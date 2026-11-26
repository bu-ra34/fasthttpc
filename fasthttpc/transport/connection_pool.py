"""
FAZ 2 — Akıllı Connection Pool
Yenilikler:
  - TTFB bazlı bağlantı sıralama (en hızlı bağlantı önce)
  - Semaphore ile concurrency limiti
  - Bağlantı ön ısıtma (pre-warming) — ThreadPoolExecutor ile paralel handshake
  - Pipelining desteği için bağlantı kilitleme (item 13)
  - TCP_NODELAY zaten vardı; TCP Fast Open eklendi (Linux)
  - SO_KEEPALIVE eklendi

İş parçacığı güvenliği (senkron ``Session`` birden çok iş parçacığından kullanılır):

  - Bir bağlantı (HTTP/1.1 ya da HTTP/2) ``acquire()`` ile ÖZEL olarak kiralanır ve
    ``release()`` edilene kadar başka hiçbir iş parçacığına verilmez. HTTP/2
    bağlantısı da senkron tarafta tek isteğe aittir (stream çoğullama AsyncSession'da).
  - Origin (ve proxy/mTLS kapsamı) başına ``max_connections`` slotluk bir semaphore,
    kiralanmış + kurulmakta olan bağlantı sayısını sınırlar. Boş bağlantı yoksa ve
    sınıra ulaşılmışsa iş parçacığı ``timeout`` (``Timeout.pool``) kadar bekler,
    sonra ``TimeoutError``. Kilit sırası tek yönlüdür (önce semaphore, sonra kısa
    süreli havuz kilidi; havuz kilidi tutulurken G/Ç yapılmaz ve başka kilit
    beklenmez), bu yüzden kilitlenme (deadlock) olmaz.
  - ``release()`` idempotenttir: aynı kiralama için ikinci çağrı semaphore'u bir daha
    artırmaz (artırsaydı sınır sessizce aşılırdı).
  - ``close()`` havuzu kalıcı kapatır: boştaki bağlantılar hemen kapanır, kiradaki
    bağlantılar iade edildiklerinde kapatılır (havuza dönmez); sonraki ``acquire()``
    ``RuntimeError`` verir. Kiradaki son bağlantı da iade edilince ``on_drained``
    geri çağrısı (ör. mTLS özel anahtarını bırakma) BİR kez çalışır.
"""
from __future__ import annotations
import socket
import threading
import collections
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any, Optional

from ..models.urls import URL
from .happy_eyeballs import connect_infos
from .proxy import (EnvProxies, ProxyConfig, connect_to_proxy, connect_via_proxy, resolve_proxy,
                    select_proxy)


from .._log import get_logger

if TYPE_CHECKING:
    from ..protocol.http2_parser import Http2Connection
    from .iotimeout import IOTimeouts

logger = get_logger("pool")

# Linux'ta istemci tarafı TCP Fast Open. Not: eski kod `TCP_FASTOPEN`
# kullanıyordu — o SUNUCU tarafı seçeneğidir (dinleme kuyruğu boyutu) ve
# istemcide hiçbir şey yapmaz. İstemci için doğru seçenek budur.
_TCP_FASTOPEN_CONNECT = getattr(socket, "TCP_FASTOPEN_CONNECT", 30)

# Havuzdaki boşta bağlantının azami yaşı. Sunucular keep-alive bağlantılarını
# genelde 5-60 sn sonra kapatır; bundan eskisini kullanıcıya vermek, ilk
# isteğin kesin başarısız olması demektir.
DEFAULT_IDLE_TIMEOUT = 30.0

POOL_CLOSED_MESSAGE = "Session kapatıldı (close()); yeni istek gönderilemez."


# Opsiyonel DNS-over-HTTPS çözücü. ConnectionPool(resolver=...) ile verilir;
# None ise işletim sisteminin çözücüsü kullanılır.
_DEFAULT_RESOLVER = None


class HTTPConnection:
    """Tek bir TCP/TLS soket bağlantısını ve durumunu sarmalayan sınıf."""

    __slots__ = (
        "origin", "socket", "is_closed", "tls_established",
        "conn_data", "ttfb_ms", "_lock", "in_use", "h2_conn", "idle_since", "pool_key",
        "leased",
    )

    def __init__(self, origin: tuple[str, str, int]):
        self.origin: tuple          = origin
        # Ham ``socket.socket``; TLS el sıkışmasından sonra ``EncryptedSocket`` (TLS 1.3)
        # ya da legacy TLS 1.2 soketi ile değiştirilir — ortak bir taban tipi yok.
        self.socket: Any            = None
        self.is_closed: bool        = True
        self.tls_established: bool  = False
        self.conn_data: dict        = {}
        self.ttfb_ms: float         = float("inf")                          
        self._lock                  = threading.Lock()
        self.in_use: bool           = False
        self.h2_conn: "Http2Connection | None" = None   # ALPN "h2" ise Http2Connection nesnesi
        self.idle_since: float      = 0.0
        self.pool_key               = origin     # rotasyonda proxy'yi de içerir
        # Havuzda boşta DEĞİLSE True: yeni oluşturulan bağlantı yaratanındır; havuza
        # dönünce False olur. release() yalnızca True iken iş yapar (çift iade koruması).
        self.leased: bool           = True

    def connect(self, timeout: float = 30.0, resolver=None,
                proxy: "ProxyConfig | None" = None, io: "IOTimeouts | None" = None) -> None:
        """Hedef sunucuya ham TCP bağlantısı kurar (IPv4 + IPv6).

        Args:
            resolver: Opsiyonel ``DoHResolver``. Verilirse host adı önce
                DNS-over-HTTPS ile çözülür; ISP/ağ seviyesindeki DNS
                gözetimini ve engellemesini atlar.
            proxy: Opsiyonel ``ProxyConfig``. Verilirse proxy'ye bağlanılıp
                hedefe tünel (CONNECT/SOCKS5) kurulur; hedef adı proxy'de
                çözülür (resolver kullanılmaz). Düz ``http://`` hedef + HTTP
                proxy'sinde tünel kurulmaz: soket proxy'nin kendisine açılır ve
                ``conn_data["forward_proxy"]`` işaretlenir (mutlak biçimli istek).
            io: Opsiyonel ``IOTimeouts``; proxy tüneli (CONNECT/SOCKS5) gönderimleri
                ``io.write`` (kalan ``total`` ile kısaltılmış) ile sınırlanır.
        """
        scheme, host, port = self.origin

        if proxy is not None:
            if scheme == "http" and proxy.scheme == "http":
                self.socket = connect_to_proxy(proxy, timeout=timeout)
                self.conn_data["forward_proxy"] = proxy
            else:
                self.socket = connect_via_proxy(proxy, host, port, timeout=timeout, io=io)
            self.is_closed = False
            return

        if resolver is not None:
            try:
                ip = resolver.resolve_one(host)
                if ip:
                    logger.debug("DoH: %s -> %s", host, ip)
                    host = ip
            except Exception as e:
                logger.debug("DoH çözümlemesi başarısız (%s), OS çözücüsüne dönülüyor: %s",
                             host, e)

        # getaddrinfo, IPv6-only ağlarda ve AAAA kaydı olan hostlarda çalışmak
        # için gerekli. Sabit AF_INET, IPv6-only bir ortamda kütüphaneyi
        # tamamen kullanılamaz kılıyordu.
        try:
            infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise ConnectionError(f"'{host}' adresi çözümlenemedi: {e}") from e

        # Happy Eyeballs (RFC 8305): adresler (AAAA + A) sırayla değil yarıştırılır;
        # ör. Windows'ta "localhost" -> ::1 reddi ~2 sn sürer, IPv4 250 ms'de kazanır.
        try:
            raw = connect_infos(infos, timeout, prepare=self._apply_socket_options)
        except PermissionError as e:
            raise ConnectionError(
                f"'{host}:{port}' adresine bağlanılamadı (İzin reddedildi / Errno 13). "
                f"Bu genellikle şunlardan kaynaklanır: (1) ağın/güvenlik duvarının giden "
                f"bağlantıyı engellemesi, (2) sandbox/container ortamının ham soket açmaya "
                f"izin vermemesi, (3) zorunlu bir proxy üzerinden geçilmesi gerektiği halde "
                f"doğrudan bağlanılmaya çalışılması. Orijinal hata: {e}"
            ) from e
        except OSError as e:
            raise ConnectionError(f"'{host}:{port}' adresine bağlanılamadı: {e}") from e
        self.socket = raw
        self.is_closed = False

    @staticmethod
    def _apply_socket_options(raw: socket.socket) -> None:
        """Soket seçeneklerini uygular; hepsi opsiyonel hızlandırmadır.

        TCP_NODELAY, SO_KEEPALIVE ve istemci tarafı TCP Fast Open. Bunların
        hiçbiri Windows/container/VPN gibi ortamlarda garanti değildir; her biri
        bağımsız olarak, sessizce atlanabilir.
        """
        for level, opt, val in (
            (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
            (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
            (socket.IPPROTO_TCP, _TCP_FASTOPEN_CONNECT, 1),
        ):
            try:
                raw.setsockopt(level, opt, val)
            except (OSError, AttributeError):
                pass

    def update_ttfb(self, ms: float) -> None:
        """Ölçülen TTFB'yi güncelle (thread-safe)."""
        with self._lock:
                                      
            if self.ttfb_ms == float("inf"):
                self.ttfb_ms = ms
            else:
                self.ttfb_ms = 0.7 * self.ttfb_ms + 0.3 * ms

    def close(self) -> None:
        target = self.socket
        if hasattr(target, "raw_socket"):
            target = target.raw_socket
        if target:
            try:
                target.close()
            except Exception:
                pass
        self.is_closed = True
        self.tls_established = False
        self.h2_conn = None
        self.in_use = False

    def __lt__(self, other: "HTTPConnection") -> bool:
        """TTFB bazlı karşılaştırma — sorted() ile sıralama için."""
        return self.ttfb_ms < other.ttfb_ms


class ConnectionPool:
    """
    Bağlantıları origin bazında saklayan akıllı havuz.

    - TTFB sıralaması: en hızlı bağlantı önce seçilir
    - Semaphore: max_connections limiti zorunlu tutulur
    - Pre-warming: paralel TLS handshake ile bağlantı önceden kurulur
    - Auto-evict: ölü bağlantılar acquire sırasında otomatik atılır
    """

    def __init__(self, max_connections: int = 10, timeout: float = 30.0,
                 idle_timeout: float = DEFAULT_IDLE_TIMEOUT, resolver=None,
                 proxy=None, tls_scope=None, env_proxies: "EnvProxies | None" = None):
        self.max_connections = max_connections
        # mTLS: istemci sertifikası kimliği; havuz anahtarına girer, böylece farklı
        # sertifikalı oturumlar (başka havuz örnekleri dahil) bağlantı paylaşmaz.
        self.tls_scope       = tls_scope
        # proxy: None | URL str | ProxyConfig | {"https": url, "all": url}
        self.proxy           = proxy
        # trust_env: ortamdan okunan proxy'ler (yalnızca ``proxy`` None iken kullanılır).
        self.env_proxies     = env_proxies
        self.timeout         = timeout
        self.idle_timeout    = idle_timeout
        self.resolver        = resolver
        self._pools: dict[tuple, list[HTTPConnection]] = collections.defaultdict(list)
        self._semaphores: dict[tuple, threading.Semaphore] = {}
        # Kısa süreli kilit: _pools/_semaphores/_in_use/_closed. Tutulurken G/Ç yapılmaz.
        self._lock = threading.Lock()
        self._in_use: set[HTTPConnection] = set()      # acquire() ile verilmiş, iade edilmemiş
        self._closed = False
        self._on_drained: list = []                     # close() sonrası, son iadede çalışır



    def _key(self, origin: tuple, proxy=None) -> tuple:
        key = origin if proxy is None else origin + (proxy,)
        if self.tls_scope:
            key += (("mtls", self.tls_scope),)
        return key

    def _semaphore_locked(self, key: tuple) -> threading.Semaphore:
        sem = self._semaphores.get(key)
        if sem is None:
            sem = self._semaphores[key] = threading.Semaphore(self.max_connections)
        return sem

    def _get_semaphore(self, origin: tuple) -> threading.Semaphore:
        with self._lock:
            return self._semaphore_locked(origin)

    @property
    def closed(self) -> bool:
        return self._closed



    def acquire(self, url: URL, block: bool = True, timeout: Optional[float] = None,
                proxy: Optional[str] = None,
                connect_timeout: Optional[float] = None,
                io: "IOTimeouts | None" = None) -> HTTPConnection:
        """
        URL için en hızlı canlı bağlantıyı döner.
        Yoksa yeni bağlantı kurar. Concurrency limiti Semaphore ile korunur.

        Dönen bağlantı çağırana ÖZELDİR (``release()`` edilene kadar başka iş
        parçacığına verilmez). Havuz kapatılmışsa ``RuntimeError``.

        ``proxy``: proxy rotasyonu için istek başına proxy URL'i (``self.proxy``'yi
        geçersiz kılar; bağlantılar proxy başına ayrı havuzlanır). ``io``: proxy
        tüneli gönderimlerinin süresi (bkz. :meth:`HTTPConnection.connect`).
        """
        if self._closed:
            raise RuntimeError(POOL_CLOSED_MESSAGE)
        origin = (url.scheme, url.host, url.port)
        key = self._key(origin, proxy)
        sem = self._get_semaphore(key)

        if block:
            acquired = sem.acquire(timeout=timeout or self.timeout)
        else:
            acquired = sem.acquire(blocking=False)
        if not acquired:
            raise TimeoutError(f"Bağlantı havuzu dolu ({self.max_connections}), zaman aşımı.")

        now = time.monotonic()
        stale: list[HTTPConnection] = []
        conn: Optional[HTTPConnection] = None
        with self._lock:
            if self._closed:
                # close() semaphore beklenirken geldi: slotu geri ver, istek başlamaz.
                sem.release()
                raise RuntimeError(POOL_CLOSED_MESSAGE)
            pool = self._pools[key]
            pool.sort()  # en düşük TTFB önce
            while pool:
                c = pool.pop(0)
                if c.is_closed or c.in_use:
                    continue
                if self.idle_timeout and (now - c.idle_since) > self.idle_timeout:
                    # Sunucu bunu çoktan kapatmış olabilir; kullanıcıya kesin
                    # başarısız olacak bir bağlantı vermektense yenisini kur.
                    stale.append(c)
                    continue
                conn = c
                break
            fresh = conn is None
            if conn is None:
                conn = HTTPConnection(origin)
                conn.pool_key = key
            conn.in_use = True
            conn.leased = True
            self._in_use.add(conn)
        for c in stale:
            logger.debug("Boşta kalma süresi aşıldı, bağlantı atılıyor: %s", origin)
            c.close()
        if not fresh:
            return conn

        try:
            conn.connect(timeout=connect_timeout or self.timeout, resolver=self.resolver,
                         proxy=(self.proxy_for(url) if proxy is None
                                else resolve_proxy(proxy, url.scheme)),
                         **({"io": io} if io is not None else {}))
        except BaseException:
            # Bağlantı kurulamadı: bu slot için hiç bağlantı verilmeyecek,
            # semaphore'u serbest bırakmazsak kalıcı olarak sızar (havuz asla
            # dolmaz gibi görünüp aslında hep dolu kalır).
            conn.close()
            self.release(conn)
            raise
        return conn

    def proxy_for(self, url: URL) -> "ProxyConfig | None":
        """Bu URL için oturum düzeyi proxy: ``proxy=``/``proxies=`` ya da ortam (NO_PROXY dahil)."""
        return select_proxy(url.scheme, url.host, url.port, self.proxy, self.env_proxies)

    def release(self, conn: HTTPConnection) -> None:
        """Bağlantıyı Keep-Alive amacıyla havuza geri koy (kapalıysa yalnızca slotu iade et).

        İdempotent: zaten iade edilmiş bağlantı için hiçbir şey yapmaz. Havuz
        kapatılmışsa bağlantı havuza konmaz, kapatılır."""
        to_close: Optional[HTTPConnection] = None
        drained: list = []
        with self._lock:
            if not conn.leased:
                return
            conn.leased = False
            conn.in_use = False
            self._in_use.discard(conn)
            origin = conn.pool_key
            sem = self._semaphore_locked(origin)
            if not conn.is_closed:
                keep = getattr(self, "max_keepalive_connections", None)
                if keep is None:
                    keep = self.max_connections
                # keepalive_expiry=0: keep-alive KAPALI (AsyncSession/httpx ile aynı);
                # None: süre sınırı yok.
                no_keepalive = self.idle_timeout is not None and self.idle_timeout <= 0
                if self._closed or no_keepalive or len(self._pools.get(origin, ())) >= keep:
                    to_close = conn
                else:
                    conn.idle_since = time.monotonic()
                    self._pools[origin].append(conn)
            if self._closed and not self._in_use and self._on_drained:
                drained, self._on_drained = self._on_drained, []
        if to_close is not None:
            to_close.close()
        sem.release()
        for cb in drained:
            cb()



    def prewarm(
        self,
        hosts: list[str],
        count: int = 2,
        tls_negotiate_fn=None,
        impersonate: str = "chrome_158",
    ) -> dict[str, int]:
        """
        Verilen host listesi için paralel TCP (+TLS) bağlantıları önceden kurar.
        tls_negotiate_fn: TLSAdapter.negotiate uyumlu callable (opsiyonel)
        Döner: {host: başarılı_bağlantı_sayısı}
        """
        if self._closed:
            raise RuntimeError(POOL_CLOSED_MESSAGE)
        results: dict[str, int] = {}

        def _make_conn(host: str, idx: int) -> tuple[str, bool]:
            url = URL(f"https://{host}/")
            origin = (url.scheme, url.host, url.port)
            conn = HTTPConnection(origin)
            try:
                conn.connect(timeout=self.timeout, resolver=self.resolver,
                             proxy=self.proxy_for(url))
                if tls_negotiate_fn:
                    conn.socket = tls_negotiate_fn(conn.socket, url.host, impersonate, port=url.port)
                    conn.tls_established = True
                conn.idle_since = time.monotonic()
                with self._lock:
                    # Havuz sınırını prewarm de aşamamalı; aksi hâlde
                    # max_connections sessizce anlamsızlaşır. Bu arada close()
                    # çağrıldıysa bağlantı havuza konmaz.
                    pkey = self._key(origin)
                    conn.pool_key = pkey
                    added = not self._closed and len(self._pools[pkey]) < self.max_connections
                    if added:
                        conn.leased = False
                        self._pools[pkey].append(conn)
                if not added:
                    conn.close()
                    return host, False
                return host, True
            except Exception as e:
                logger.debug("Ön ısıtma başarısız (%s): %s", host, e)
                conn.close()
                return host, False

        tasks = [
            (host, i)
            for host in hosts
            for i in range(count)
        ]

        with ThreadPoolExecutor(max_workers=min(len(tasks), 16)) as executor:
            futures = {executor.submit(_make_conn, h, i): (h, i) for h, i in tasks}
            for future in as_completed(futures):
                host, ok = future.result()
                results[host] = results.get(host, 0) + (1 if ok else 0)

        return results

                                                                              

    def close_all(self) -> None:
        """Boştaki bağlantıları kapatır; havuz kullanılabilir kalır (bkz. :meth:`close`)."""
        with self._lock:
            idle = [c for conns in self._pools.values() for c in conns]
            self._pools.clear()
        for c in idle:
            c.close()

    def close(self, on_drained=None) -> None:
        """Havuzu KALICI olarak kapatır (``Session.close``).

        Boştaki bağlantılar hemen kapanır; başka iş parçacıklarının kullandığı
        bağlantılar kesilmez, iade edildiklerinde kapatılır. Sonraki ``acquire()``
        (semaphore bekleyen iş parçacıkları dahil) ``RuntimeError`` verir.
        ``on_drained``: kirada bağlantı kalmayınca bir kez çağrılır (hemen ya da son
        ``release()`` içinde)."""
        with self._lock:
            self._closed = True
            idle = [c for conns in self._pools.values() for c in conns]
            self._pools.clear()
            run_now = not self._in_use
            if on_drained is not None and not run_now:
                self._on_drained.append(on_drained)
        for c in idle:
            c.close()
        if on_drained is not None and run_now:
            on_drained()

    def stats(self) -> dict:
        """Her origin için havuz istatistiği döner (``idle``: boşta, ``in_use``: kirada)."""
        with self._lock:
            grouped: dict = {}
            for (s, h, p, *_proxy), conns in self._pools.items():
                grouped.setdefault(f"{s}://{h}:{p}", []).extend(conns)
            busy: dict[str, int] = {}
            for c in self._in_use:
                s, h, p = c.pool_key[:3]
                name = f"{s}://{h}:{p}"
                busy[name] = busy.get(name, 0) + 1
                grouped.setdefault(name, [])
            return {
                name: {
                    "idle": len(conns),
                    "in_use": busy.get(name, 0),
                    "avg_ttfb_ms": round(
                        sum(c.ttfb_ms for c in conns if c.ttfb_ms != float("inf"))
                        / max(len([c for c in conns if c.ttfb_ms != float("inf")]), 1),
                        2,
                    ),
                }
                for name, conns in grouped.items()
            }
