"""
FAZ 2 — Akıllı Connection Pool
Yenilikler:
  - TTFB bazlı bağlantı sıralama (en hızlı bağlantı önce)
  - Semaphore ile concurrency limiti
  - Bağlantı ön ısıtma (pre-warming) — ThreadPoolExecutor ile paralel handshake
  - Pipelining desteği için bağlantı kilitleme (item 13)
  - TCP_NODELAY zaten vardı; TCP Fast Open eklendi (Linux)
  - SO_KEEPALIVE eklendi
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
from .proxy import ProxyConfig, connect_via_proxy, resolve_proxy


from .._log import get_logger

if TYPE_CHECKING:
    from ..protocol.http2_parser import Http2Connection

logger = get_logger("pool")

# Linux'ta istemci tarafı TCP Fast Open. Not: eski kod `TCP_FASTOPEN`
# kullanıyordu — o SUNUCU tarafı seçeneğidir (dinleme kuyruğu boyutu) ve
# istemcide hiçbir şey yapmaz. İstemci için doğru seçenek budur.
_TCP_FASTOPEN_CONNECT = getattr(socket, "TCP_FASTOPEN_CONNECT", 30)

# Havuzdaki boşta bağlantının azami yaşı. Sunucular keep-alive bağlantılarını
# genelde 5-60 sn sonra kapatır; bundan eskisini kullanıcıya vermek, ilk
# isteğin kesin başarısız olması demektir.
DEFAULT_IDLE_TIMEOUT = 30.0


# Opsiyonel DNS-over-HTTPS çözücü. ConnectionPool(resolver=...) ile verilir;
# None ise işletim sisteminin çözücüsü kullanılır.
_DEFAULT_RESOLVER = None


class HTTPConnection:
    """Tek bir TCP/TLS soket bağlantısını ve durumunu sarmalayan sınıf."""

    __slots__ = (
        "origin", "socket", "is_closed", "tls_established",
        "conn_data", "ttfb_ms", "_lock", "in_use", "h2_conn", "idle_since", "pool_key",
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

    def connect(self, timeout: float = 30.0, resolver=None,
                proxy: "ProxyConfig | None" = None) -> None:
        """Hedef sunucuya ham TCP bağlantısı kurar (IPv4 + IPv6).

        Args:
            resolver: Opsiyonel ``DoHResolver``. Verilirse host adı önce
                DNS-over-HTTPS ile çözülür; ISP/ağ seviyesindeki DNS
                gözetimini ve engellemesini atlar.
            proxy: Opsiyonel ``ProxyConfig``. Verilirse proxy'ye bağlanılıp
                hedefe tünel (CONNECT/SOCKS5) kurulur; hedef adı proxy'de
                çözülür (resolver kullanılmaz).
        """
        scheme, host, port = self.origin

        if proxy is not None:
            self.socket = connect_via_proxy(proxy, host, port, timeout=timeout)
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
                 proxy=None, tls_scope=None):
        self.max_connections = max_connections
        # mTLS: istemci sertifikası kimliği; havuz anahtarına girer, böylece farklı
        # sertifikalı oturumlar (başka havuz örnekleri dahil) bağlantı paylaşmaz.
        self.tls_scope       = tls_scope
        # proxy: None | URL str | ProxyConfig | {"https": url, "all": url}
        self.proxy           = proxy
        self.timeout         = timeout
        self.idle_timeout    = idle_timeout
        self.resolver        = resolver
        self._pools: dict[tuple, list[HTTPConnection]] = collections.defaultdict(list)
        self._semaphores: dict[tuple, threading.Semaphore] = {}
        self._lock = threading.Lock()

                                                                               

    def _key(self, origin: tuple, proxy=None) -> tuple:
        key = origin if proxy is None else origin + (proxy,)
        if self.tls_scope:
            key += (("mtls", self.tls_scope),)
        return key

    def _get_semaphore(self, origin: tuple) -> threading.Semaphore:
        with self._lock:
            if origin not in self._semaphores:
                self._semaphores[origin] = threading.Semaphore(self.max_connections)
            return self._semaphores[origin]

                                                                              

    def acquire(self, url: URL, block: bool = True, timeout: Optional[float] = None,
                proxy: Optional[str] = None,
                connect_timeout: Optional[float] = None) -> HTTPConnection:
        """
        URL için en hızlı canlı bağlantıyı döner.
        Yoksa yeni bağlantı kurar. Concurrency limiti Semaphore ile korunur.

        ``proxy``: proxy rotasyonu için istek başına proxy URL'i (``self.proxy``'yi
        geçersiz kılar; bağlantılar proxy başına ayrı havuzlanır).
        """
        origin = (url.scheme, url.host, url.port)
        key = self._key(origin, proxy)
        sem = self._get_semaphore(key)

                                                                
        acquired = sem.acquire(blocking=block, timeout=timeout or self.timeout)
        if not acquired:
            raise TimeoutError(f"Bağlantı havuzu dolu ({self.max_connections}), zaman aşımı.")

        now = time.monotonic()
        with self._lock:
            pool = self._pools[key]
            pool.sort()  # en düşük TTFB önce
            while pool:
                conn = pool.pop(0)
                if conn.is_closed or conn.in_use:
                    continue
                if self.idle_timeout and (now - conn.idle_since) > self.idle_timeout:
                    # Sunucu bunu çoktan kapatmış olabilir; kullanıcıya kesin
                    # başarısız olacak bir bağlantı vermektense yenisini kur.
                    logger.debug("Boşta kalma süresi aşıldı, bağlantı atılıyor: %s", origin)
                    conn.close()
                    continue
                conn.in_use = True
                return conn

                                              
        conn = HTTPConnection(origin)
        conn.pool_key = key
        try:
            conn.connect(timeout=connect_timeout or self.timeout, resolver=self.resolver,
                         proxy=resolve_proxy(self.proxy if proxy is None else proxy,
                                             url.scheme))
        except Exception:
            # Bağlantı kurulamadı: bu slot için hiç bağlantı verilmeyecek,
            # semaphore'u serbest bırakmazsak kalıcı olarak sızar (havuz asla
            # dolmaz gibi görünüp aslında hep dolu kalır).
            sem.release()
            raise
        conn.in_use = True
        return conn

                                                                              

    def release(self, conn: HTTPConnection) -> None:
        """Bağlantıyı Keep-Alive amacıyla havuza geri koy."""
        conn.in_use = False
        origin = conn.pool_key
        sem    = self._get_semaphore(origin)

        if not conn.is_closed:
            conn.idle_since = time.monotonic()
            with self._lock:
                pool = self._pools[origin]
                keep = getattr(self, "max_keepalive_connections", None)
                if keep is None:
                    keep = self.max_connections
                # keepalive_expiry=0: keep-alive KAPALI (AsyncSession/httpx ile aynı);
                # None: süre sınırı yok.
                no_keepalive = self.idle_timeout is not None and self.idle_timeout <= 0
                if len(pool) < keep and not no_keepalive:
                    pool.append(conn)
                else:
                    conn.close()

        sem.release()

                                                                              

    def prewarm(
        self,
        hosts: list[str],
        count: int = 2,
        tls_negotiate_fn=None,
        impersonate: str = "chrome_131",
    ) -> dict[str, int]:
        """
        Verilen host listesi için paralel TCP (+TLS) bağlantıları önceden kurar.
        tls_negotiate_fn: TLSAdapter.negotiate uyumlu callable (opsiyonel)
        Döner: {host: başarılı_bağlantı_sayısı}
        """
        results: dict[str, int] = {}

        def _make_conn(host: str, idx: int) -> tuple[str, bool]:
            url = URL(f"https://{host}/")
            origin = (url.scheme, url.host, url.port)
            conn = HTTPConnection(origin)
            try:
                conn.connect(timeout=self.timeout, resolver=self.resolver,
                             proxy=resolve_proxy(self.proxy, url.scheme))
                if tls_negotiate_fn:
                    conn.socket = tls_negotiate_fn(conn.socket, url.host, impersonate, port=url.port)
                    conn.tls_established = True
                conn.idle_since = time.monotonic()
                with self._lock:
                    # Havuz sınırını prewarm de aşamamalı; aksi hâlde
                    # max_connections sessizce anlamsızlaşır.
                    pkey = self._key(origin)
                    conn.pool_key = pkey
                    if len(self._pools[pkey]) < self.max_connections:
                        self._pools[pkey].append(conn)
                    else:
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
        with self._lock:
            for conns in self._pools.values():
                for c in conns:
                    c.close()
            self._pools.clear()

    def stats(self) -> dict:
        """Her origin için havuz istatistiği döner."""
        with self._lock:
            grouped: dict = {}
            for (s, h, p, *_proxy), conns in self._pools.items():
                grouped.setdefault(f"{s}://{h}:{p}", []).extend(conns)
            return {
                name: {
                    "idle": len(conns),
                    "avg_ttfb_ms": round(
                        sum(c.ttfb_ms for c in conns if c.ttfb_ms != float("inf"))
                        / max(len([c for c in conns if c.ttfb_ms != float("inf")]), 1),
                        2,
                    ),
                }
                for name, conns in grouped.items()
            }
