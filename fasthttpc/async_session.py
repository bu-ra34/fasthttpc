"""
FAZ 5 — Özellik 27: AsyncSession (asyncio tabanlı tam async motor)
Özellik 28: Connection pre-warming with ThreadPoolExecutor (session.pre_warm zaten var, async versiyonu)
Özellik 29: Plugin sistemi (session.use(middleware))
Özellik 30: Otomatik proxy rotasyonu
"""
from __future__ import annotations
import asyncio
import ssl
import warnings

from ._log import get_logger
from . import _api
from ._api import USE_CLIENT_DEFAULT
from .auth import resolve_auth, netrc_credentials, BasicAuth

logger = get_logger("async")
import time
import threading
from dataclasses import dataclass
from typing import Any, Callable, Optional, AsyncGenerator, Union
from .models.urls     import URL
from .models.headers  import Headers
from .fingerprint     import drop_h2_only_defaults, merge_default_headers, order_h1
from .models.response import Response, HTTPStatusError
from .metrics         import RequestMetrics
from .cache           import ResponseCache
from .cookies         import CookieJar
from .multipart       import encode_multipart
from .protocol.http1_parser import HTTP1Parser
from .models.request  import Request
from .config          import Limits, Timeout, resolve_verify
from .retry           import Retry
from .tls13 import AsyncTLSStream
from .protocol.async_h2 import AsyncHttp2Connection, H2StreamRefused
from .protocol.http2_parser import Http2ConnectionError, Http2StreamError
from .transport.proxy import ProxyConfig, async_connect_via_proxy, parse_proxy_url, resolve_proxy


                                                                               
                                  
                                                                               

def _resolve_location(base: URL, location: str) -> str:
    """Redirect Location'ı mutlak URL'ye çevirir (sync tarafla aynı kurallar)."""
    from .session import _resolve_location as _impl
    return _impl(base, location)


from .plugins import Plugin, RetryPlugin, LoggingPlugin, RateLimitPlugin, call_async  # noqa: E402,F401


async def _maybe(out):
    """Hook düz değer ya da coroutine döndürebilir."""
    import inspect
    return await out if inspect.isawaitable(out) else out


class ProxyRotator:
    """
    Proxy listesini round-robin veya TTFB bazlı rotate eder.
    Başarısız proxy'leri otomatik listeden çıkarır.
    """
    def __init__(self, proxies: list[str], strategy: str = "round_robin"):
        """
        proxies: ["http://user:pass@host:port", "socks5://host:port", ...]
        strategy: "round_robin" | "performance"
        """
        self._proxies   = list(proxies)
        self._bad:  set[str]         = set()
        self._perf: dict[str, float] = {}                             
        self._idx   = 0
        self._lock  = threading.Lock()
        self._strategy = strategy

    def next(self) -> Optional[str]:
        """Sıradaki kullanılabilir proxy'yi döner."""
        with self._lock:
            available = [p for p in self._proxies if p not in self._bad]
            if not available:
                return None
            if self._strategy == "performance" and self._perf:
                return min(available, key=lambda p: self._perf.get(p, float("inf")))
                         
            proxy = available[self._idx % len(available)]
            self._idx += 1
            return proxy

    def mark_failed(self, proxy: str) -> None:
        """Proxy'yi başarısız listesine ekle."""
        with self._lock:
            self._bad.add(proxy)
        print(f"[ProxyRotator] ✗ Başarısız proxy devre dışı: {proxy}")
        print(f"[ProxyRotator] Kalan aktif: {len(self._proxies) - len(self._bad)}")

    def update_perf(self, proxy: str, ttfb_ms: float) -> None:
        """TTFB ölçümü güncelle (EWMA)."""
        with self._lock:
            old = self._perf.get(proxy, ttfb_ms)
            self._perf[proxy] = 0.7 * old + 0.3 * ttfb_ms

    def restore(self, proxy: str) -> None:
        """Başarısız proxy'yi listeye geri ekle."""
        with self._lock:
            self._bad.discard(proxy)

    def stats(self) -> dict:
        with self._lock:
            return {
                "total":     len(self._proxies),
                "active":    len(self._proxies) - len(self._bad),
                "failed":    list(self._bad),
                "perf_ms":   dict(self._perf),
            }

    def parse_proxy_url(self, proxy_url: str) -> dict:
        """proxy URL'i bileşenlerine ayırır."""
        from urllib.parse import urlparse
        p = urlparse(proxy_url)
        return {
            "scheme":   p.scheme,
            "host":     p.hostname,
            "port":     p.port or (1080 if p.scheme == "socks5" else 8080),
            "username": p.username or "",
            "password": p.password or "",
        }


                                                                               
                                
                                                                               

@dataclass
class _Opened:
    """Yeni açılmış bağlantı + havuz slotunu geri veren ``release``."""
    reader:  Any
    writer:  Any
    alpn:    str
    release: Callable[[], None]
    key:     tuple = ()
    reused:  bool = False          # havuzdan gelen (bayat olabilir) bağlantı
    last_used: float = 0.0
    loop:    Any = None


class _StaleConn(Exception):
    """Yeniden kullanılan bağlantı, yanıttan tek bayt gelmeden koptu (güvenle yeniden denenir)."""

    def __init__(self, cause: BaseException):
        super().__init__(str(cause))
        self.cause = cause


class AsyncSession:
    """
    asyncio tabanlı async HTTP istemcisi.

    Sync Session ile aynı API — await ile kullanılır.

    Özellikler:
    - Plugin sistemi: session.use(plugin)
    - Proxy rotasyonu: session.set_proxies([...])
    - Response cache (ETag/Last-Modified)
    - Metrics (resp.metrics)
    - iter_content() streaming

    Parametreler senkron :class:`~fasthttpc.session.Session` ile aynıdır
    (``resolver`` dahil); sıra farkı: ``timeout`` ve ``max_redirects``
    ``max_connections``'tan önce gelir (isimle çağırın).

    Kullanım:
        async with AsyncSession(impersonate="chrome_131") as session:
            resp = await session.get("https://example.com")
            print(resp.status_code)

        # Paralel istekler
        tasks = [session.get(url) for url in urls]
        responses = await asyncio.gather(*tasks)
    """

    def __init__(
        self,
        impersonate:     str   = "chrome_131",
        timeout:         "Union[float, int, Timeout]" = 30.0,
        max_redirects:   int   = 10,
        max_connections: int   = 100,
        cache:           "bool | ResponseCache" = False,
        cache_ttl:       float = 300.0,
        verify:          "bool | str" = True,
        retries:         "int | Retry | None" = None,
        transport                     = None,
        limits:          "Limits | None" = None,
        proxies                       = None,
        proxy                         = None,
        resolver                      = None,
        headers                       = None,
        auth                          = None,
        hooks:           "dict | None" = None,
        event_hooks:     "dict | None" = None,
        trust_env:       bool          = True,
        params                        = None,
    ):
        # impersonate verilirse TLS, fasthttpc.tls13 çekirdeğiyle (tarayıcı
        # ClientHello'su) kurulur ve profilin ALPN'i (h2, http/1.1) kullanılır;
        # sunucu h2 seçerse HTTP/2 (multiplexing) konuşulur.
        # impersonate=None -> stdlib ssl, yalnızca HTTP/1.1.
        from .session import _proxy_spec
        self.impersonate   = impersonate
        # requests/httpx uyumu (Session ile aynı): kimlik, hook'lar, varsayılan params.
        self.auth          = auth
        self.hooks         = _api.normalize_hooks(hooks)
        self.event_hooks   = _api.normalize_event_hooks(event_hooks)
        self.trust_env     = trust_env
        self.params        = params
        # Oturum düzeyi varsayılan başlıklar (mutable; Session ile aynı öncelik:
        # profil başlıkları < headers < istek başlıkları; None değer kaldırır).
        self.headers       = Headers(headers)
        self.timeout       = Timeout.from_value(timeout)
        self.verify        = verify
        self._ca_path      = resolve_verify(verify)   # None → varsayılan güven deposu
        self.retries       = Retry.from_value(retries)
        self.transport     = transport
        self.max_redirects = max_redirects
        self.limits        = limits if limits is not None else Limits(max_connections=max_connections)
        self._proxy_spec   = _proxy_spec(proxy, proxies)
        self.resolver      = resolver      # opsiyonel DoHResolver (senkron Session ile aynı)
        self.cookie_jar    = CookieJar()
        self._plugins: list[Plugin]   = []
        self._rotator: Optional[ProxyRotator] = None
        self._sem     = asyncio.Semaphore(self.limits.max_connections)
        # HTTP/2: (host, port, proxy) -> canlı bağlantı; kaynak protokol önbelleği
        self._h2:           dict[tuple, AsyncHttp2Connection] = {}
        self._origin_proto: dict[tuple, str] = {}
        self._origin_locks: dict[tuple, asyncio.Lock] = {}
        self._bg_tasks:     set[asyncio.Task] = set()
        # HTTP/1.1 keep-alive havuzu: (host, port, proxy, impersonate-mi) -> boşta bağlantılar.
        # Boştaki bağlantı semaphore slotu TUTMAZ (slot yalnızca kullanımdayken).
        self._idle: dict[tuple, list[_Opened]] = {}

        if isinstance(cache, ResponseCache):
            self._cache: Optional[ResponseCache] = cache
        elif cache:
            self._cache = ResponseCache(default_ttl=cache_ttl)
        else:
            self._cache = None

                                                                               

    @property
    def cookies(self) -> dict[str, str]:
        """İsim->değer sözlüğü (salt okunur görünüm; yazmak için ``cookie_jar``)."""
        return self.cookie_jar.as_dict()

    def _update_cookies(self, response_headers: Headers, url: URL) -> None:
        self.cookie_jar.update_from_headers(
            response_headers.get_list("set-cookie"),
            request_host=url.host, request_path=url.path,
        )

    def _cookie_header(self, url: URL) -> str:
        return self.cookie_jar.header_for(
            host=url.host, path=url.path, secure=(url.scheme == "https"))

    def pool_stats(self) -> dict:
        """Kaynak başına boştaki keep-alive bağlantı sayısı (+ canlı h2 bağlantıları)."""
        self._idle_purge()
        stats: dict[str, dict] = {}
        for (host, port, _proxy, _imp), lst in self._idle.items():
            stats.setdefault(f"https://{host}:{port}", {"idle": 0, "h2": 0})["idle"] += len(lst)
        for (host, port, _proxy), conn in self._h2.items():
            if conn.usable:
                stats.setdefault(f"https://{host}:{port}", {"idle": 0, "h2": 0})["h2"] += 1
        return stats

    def _tmo(self) -> Timeout:
        """Etkin zaman aşımı: istek düzeyi ``timeout=`` varsa o, yoksa oturumunki."""
        return _api.effective_timeout(self, self.timeout)

    def use(self, plugin: Plugin) -> "AsyncSession":
        """Plugin ekle (``Session.use`` ile aynı arayüz; kancalar düz fonksiyon ya da coroutine).

        Zincir çağrı destekli: ``session.use(p1).use(p2)``.
        """
        self._plugins.append(plugin)
        return self

    async def _run_request_hooks(self, req: dict) -> dict:
        for plugin in self._plugins:
            req = await call_async(plugin, "on_request", req)
        return req

    async def _run_response_hooks(self, resp: Response) -> Response:
        for plugin in self._plugins:
            resp = await call_async(plugin, "on_response", resp)
        return resp

    def set_proxies(self, proxies: list[str], strategy: str = "round_robin") -> "AsyncSession":
        """Proxy listesini ayarla ve rotasyonu etkinleştir.

        Rotasyon etkinken her istek için seçilen proxy (``proxy=``/``proxies=``
        yerine) GERÇEKTEN kullanılır; URL'ler burada doğrulanır.
        """
        for url in proxies:
            parse_proxy_url(url)   # hatalı URL'i erken yakala
        self._rotator = ProxyRotator(proxies, strategy=strategy)
        return self

                                                                               

    async def pre_warm(self, hosts: list[str], count: int = 2) -> dict[str, int]:
        """
        Async pre-warming: asyncio.gather ile paralel bağlantı + TLS handshake.

        ``_connect`` ile aynı yol: ``impersonate`` verilmişse tarayıcı
        ClientHello'su (AsyncTLSStream), ``proxy``/``proxies``/rotasyon varsa
        tünel üzerinden. Kurulan HTTP/1.1 bağlantıları keep-alive havuzuna
        konur (``Limits`` uygulanır), h2 ise önbelleğe alınır; sonraki istekler
        bu bağlantıları kullanır. ``{host: başarılı bağlantı sayısı}`` döner.
        """
        results: dict[str, int] = {}

        async def _warm_one(host: str) -> tuple[str, bool]:
            try:
                u = URL(f"https://{host}")
                proxy_cfg, _ = self._select_proxy(u)
                reader, writer, alpn = await self._connect(u.host, u.port, proxy_cfg)
            except (OSError, asyncio.TimeoutError, ValueError) as e:  # ssl.SSLError ⊂ OSError
                logger.debug("Ön ısıtma başarısız %s: %s", host, e)
                return host, False
            o = _Opened(reader, writer, alpn, lambda: None, key=self._h1_key(u, proxy_cfg),
                        loop=asyncio.get_running_loop())
            try:
                key = (u.host, u.port, proxy_cfg)
                if alpn == "h2":
                    if self._h2_get(key) is None:
                        await self._start_h2(key, o)
                        return host, True
                    await self._h1_finish(o, False)      # zaten canlı h2 var
                    return host, True
                if alpn == "http/1.1":
                    self._origin_proto[key] = "h1"
                await self._h1_finish(o, True)
                return host, True
            except (OSError, asyncio.TimeoutError, ConnectionError) as e:
                logger.debug("Ön ısıtma başarısız %s: %s", host, e)
                return host, False

        tasks = [_warm_one(h) for h in hosts for _ in range(count)]
        for coro in asyncio.as_completed(tasks):
            host, ok = await coro
            results[host] = results.get(host, 0) + (1 if ok else 0)

        return results

                                                                               

    # --- proxy seçimi ve bağlantı kurulumu ---------------------------------

    def _select_proxy(self, u: URL) -> "tuple[Optional[ProxyConfig], Optional[str]]":
        """(ProxyConfig, rotator URL'i). Rotasyon açıksa o, değilse proxy=/proxies=."""
        if self._rotator is not None:
            url = self._rotator.next()
            if url:
                return parse_proxy_url(url), url
        return resolve_proxy(self._proxy_spec, u.scheme), None

    async def _connect(self, host: str, port: int, proxy: Optional[ProxyConfig], *,
                       alpn: Optional[list] = None, tls: bool = True):
        """TCP (+ varsa proxy tüneli) + TLS. ``(reader, writer, alpn)`` döner.

        impersonate: tarayıcı ClientHello'su (ALPN = profilin h2, http/1.1
        listesi; ``alpn=`` ile geçersiz kılınabilir, ör. WebSocket için
        ``["http/1.1"]``); tünel varsa TLS tünelin İÇİNDE, hedef host'a karşı
        kurulur. impersonate=None: stdlib ssl, yalnızca http/1.1.
        ``tls=False``: düz TCP (``ws://``), yine proxy tüneli üzerinden olabilir.
        """
        connect_to = self._tmo().connect
        sni = host
        if proxy is None and self.resolver is not None:
            host = await asyncio.wait_for(self._resolve(host), connect_to)   # DoH: TCP IP'ye, TLS/SNI özgün ada

        async def _go():
            if not tls:
                if proxy is None:
                    reader, writer = await asyncio.open_connection(host, port)
                else:
                    reader, writer = await async_connect_via_proxy(
                        proxy, host, port, timeout=connect_to)
                return reader, writer, ""
            if self.impersonate is not None:
                kw = {"alpn": list(alpn)} if alpn is not None else {}
                if proxy is None:
                    stream = await AsyncTLSStream.connect(
                        host, port, self.impersonate, server_hostname=sni,
                        ca_path=self._ca_path, **kw)
                else:
                    reader, writer = await async_connect_via_proxy(proxy, host, port, timeout=connect_to)
                    try:
                        stream = await AsyncTLSStream.negotiate(
                            reader, writer, sni, self.impersonate, ca_path=self._ca_path,
                            port=port, **kw)   # bilet anahtarı: proxy'nin değil hedefin portu
                    except BaseException:
                        writer.close()
                        raise
                return stream, stream, stream.conn.alpn
            ctx = ssl.create_default_context(cafile=self._ca_path)
            ctx.set_alpn_protocols(["http/1.1"])
            if proxy is None:
                reader, writer = await asyncio.open_connection(
                    host, port, ssl=ctx, server_hostname=sni)
            else:
                reader, writer = await async_connect_via_proxy(proxy, host, port, timeout=connect_to)
                try:
                    if hasattr(writer, "start_tls"):   # Python 3.11+
                        await writer.start_tls(ctx, server_hostname=sni)
                    else:
                        writer = await _start_tls_py310(reader, writer, ctx, sni)
                except BaseException:
                    writer.close()
                    raise
            return reader, writer, "http/1.1"

        return await asyncio.wait_for(_go(), connect_to)

    async def _resolve(self, host: str) -> str:
        """DoH çözücüyle (senkron, thread'de) IP'ye çevirir; hata olursa özgün ad."""
        try:
            ip = await asyncio.get_running_loop().run_in_executor(
                None, self.resolver.resolve_one, host)
        except Exception as e:
            logger.debug("DoH çözümlemesi başarısız (%s), OS çözücüsüne dönülüyor: %s", host, e)
            return host
        if ip:
            logger.debug("DoH: %s -> %s", host, ip)
            return ip
        return host

    def _slot_releaser(self) -> "Callable[[], None]":
        released = False

        def release() -> None:
            nonlocal released
            if not released:
                released = True
                self._sem.release()
        return release

    def _h1_key(self, u: URL, proxy: Optional[ProxyConfig]) -> tuple:
        return (u.host, u.port, proxy, self.impersonate is not None)

    @staticmethod
    def _conn_dead(o: "_Opened") -> bool:
        """Boştaki bağlantı kapanmış mı (EOF görüldü / transport kapanıyor)?"""
        try:
            if o.reader.at_eof():
                return True
            inner = getattr(o.writer, "writer", o.writer)   # AsyncTLSStream -> StreamWriter
            return bool(inner.is_closing())
        except (AttributeError, RuntimeError):
            return True

    @staticmethod
    def _drop_conn(o: "_Opened") -> None:
        """Bağlantıyı eşzamanlı kapatır (wait_closed beklenmez)."""
        try:
            o.writer.close()
        except (OSError, RuntimeError) as e:   # kapalı event loop vb.
            logger.debug("boştaki bağlantı kapatılamadı: %s", e)

    def _idle_expired(self, o: "_Opened", now: float) -> bool:
        exp = self.limits.keepalive_expiry
        return exp is not None and now - o.last_used >= exp

    def _idle_purge(self) -> None:
        """Süresi dolan boşta bağlantıları kapatır."""
        now = time.monotonic()
        for key in list(self._idle):
            keep = []
            for o in self._idle[key]:
                if self._idle_expired(o, now) or self._conn_dead(o):
                    self._drop_conn(o)
                else:
                    keep.append(o)
            if keep:
                self._idle[key] = keep
            else:
                del self._idle[key]

    def _idle_count(self) -> int:
        return sum(len(v) for v in self._idle.values())

    def _idle_pop(self, key: tuple) -> "Optional[_Opened]":
        self._idle_purge()
        lst = self._idle.get(key)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return None
        while lst:
            o = lst.pop()               # en son kullanılan (LIFO) en taze olandır
            if not lst:
                del self._idle[key]
            if o.loop is loop:
                return o
            self._drop_conn(o)
        return None

    async def _open(self, u: URL, proxy: Optional[ProxyConfig], metrics,
                    reuse: bool = True) -> "_Opened":
        """Havuz slotu alır; boşta uygun HTTP/1.1 bağlantısı varsa onu, yoksa yenisini
        açar. Slot ``release()`` ile geri verilir."""
        try:
            await asyncio.wait_for(self._sem.acquire(), self._tmo().pool)
        except asyncio.TimeoutError:
            raise asyncio.TimeoutError(
                f"Bağlantı havuzu {self._tmo().pool} sn içinde boşalmadı "
                f"(max_connections={self.limits.max_connections}).") from None
        release = self._slot_releaser()
        key = self._h1_key(u, proxy)

        try:
            if reuse:
                o = self._idle_pop(key)
                if o is not None:
                    o.release, o.reused = release, True
                    if metrics:
                        metrics.connection_reused = True
                        metrics.connect_start = metrics.connect_end = time.monotonic()
                    return o
            if metrics:
                metrics.connect_start = time.monotonic()
            reader, writer, alpn = await self._connect(u.host, u.port, proxy)
        except BaseException:
            release()
            raise
        if metrics:
            metrics.connect_end = time.monotonic()
            metrics.tls_end     = time.monotonic()
        return _Opened(reader, writer, alpn, release, key=key,
                       loop=asyncio.get_running_loop())

    async def _h1_finish(self, o: "_Opened", reusable: bool) -> None:
        """İstek bitti: bağlantıyı havuza koyar ya da kapatır; slot HER durumda geri verilir."""
        try:
            if reusable:
                self._idle_purge()
                o.last_used = time.monotonic()
                cap = self.limits.max_keepalive_connections
                if cap is None:
                    cap = self.limits.max_connections
                exp = self.limits.keepalive_expiry
                if self._idle_count() < cap and not (exp is not None and exp <= 0):
                    self._idle.setdefault(o.key, []).append(o)
                    return
            o.writer.close()
            try:
                await o.writer.wait_closed()
            except OSError as e:  # ssl kapanış hataları dahil
                logger.debug("wait_closed hatası yok sayıldı: %s", e)
        finally:
            o.release()

    def _h2_get(self, key: tuple) -> Optional[AsyncHttp2Connection]:
        """Kaynak için yeniden kullanılabilir canlı HTTP/2 bağlantısı (yoksa None)."""
        conn = self._h2.get(key)
        if conn is None:
            return None
        drop = False
        try:
            loop_ok = conn.loop is asyncio.get_running_loop()
        except RuntimeError:
            loop_ok = False
        expiry = self.limits.keepalive_expiry
        if not loop_ok or not conn.usable:
            drop = True
        elif expiry is not None and conn.active_streams == 0 \
                and time.monotonic() - conn.last_used > expiry:
            drop = True
        if drop:
            del self._h2[key]
            if loop_ok and not conn.closed:
                task = asyncio.ensure_future(conn.close())
                self._bg_tasks.add(task)
                task.add_done_callback(self._bg_tasks.discard)
            return None
        return conn

    async def _start_h2(self, key: tuple, opened: "_Opened") -> AsyncHttp2Connection:
        stream = opened.writer          # AsyncTLSStream: read/write/drain/close/wait_closed
        conn = AsyncHttp2Connection(
            stream, read_timeout=self._tmo().read, write_timeout=self._tmo().write,
            on_close=opened.release, profile=self.impersonate,
        )
        try:
            await asyncio.wait_for(conn.start(), self._tmo().connect)
        except BaseException:
            await conn.close()
            opened.release()
            raise
        self._h2[key] = conn
        return conn

    async def _exchange(self, method: str, u: URL, proxy: Optional[ProxyConfig],
                        req_headers: dict, raw_body: bytes, metrics):
        """Bağlantıyı bulur/kurar ve isteği h2 veya HTTP/1.1 ile yapar.

        ``(status, Headers, body_raw, send_time, http_version)`` döner.
        """
        key = (u.host, u.port, proxy)
        for attempt in (0, 1):
            conn = self._h2_get(key)
            opened = None
            if conn is not None:
                if metrics:
                    metrics.connection_reused = True
                    metrics.connect_start = metrics.connect_end = time.monotonic()
            elif self.impersonate is not None and self._origin_proto.get(key) != "h1":
                # Protokol henüz bilinmiyor: aynı kaynağa eşzamanlı gelen isteklerin
                # tek bir h2 bağlantısını paylaşabilmesi için ilk el sıkışma serileşir.
                async with self._origin_locks.setdefault(key, asyncio.Lock()):
                    conn = self._h2_get(key)
                    if conn is None:
                        opened = await self._open(u, proxy, metrics)
                        if opened.alpn == "h2":
                            conn = await self._start_h2(key, opened)
                            opened = None
                        else:
                            self._origin_proto[key] = "h1"
            else:
                opened = await self._open(u, proxy, metrics)

            if conn is not None:
                try:
                    return await self._h2_exchange(conn, method, u, req_headers, raw_body, metrics)
                except H2StreamRefused as e:
                    if attempt == 0:
                        logger.debug("h2 stream işlenmedi, yeni bağlantıda yeniden: %s", e)
                        continue
                    raise ConnectionError(f"HTTP/2 isteği başarısız: {e}") from e
            try:
                return await self._h1_exchange(opened, method, u, req_headers, raw_body, metrics)
            except _StaleConn as st:
                # Havuzdaki bağlantı sunucu tarafında kapanmıştı ve yanıttan HİÇ bayt
                # gelmedi: bir kez, taze bağlantıyla yeniden dene (zaman aşımı hariç).
                logger.debug("Bayat bağlantı, yeniden deneniyor (%s)", st.cause)
                opened = await self._open(u, proxy, metrics, reuse=False)
                if opened.alpn == "h2":     # pragma: no cover - h1 olarak bilinen kaynak
                    opened.release()
                    opened.writer.close()
                    raise ConnectionError("Beklenmeyen ALPN h2 (kaynak h1 olarak biliniyordu).") from st
                return await self._h1_exchange(opened, method, u, req_headers, raw_body, metrics)
        raise ConnectionError("Tüm bağlantı denemeleri başarısız oldu.")  # pragma: no cover

    # RFC 7540 §8.1.2.2: bağlantıya özgü başlıklar h2'de yasaktır; Host -> :authority.
    _H2_SKIP = frozenset({"host", "connection", "keep-alive", "proxy-connection",
                          "transfer-encoding", "upgrade"})

    async def _h2_exchange(self, conn: AsyncHttp2Connection, method: str, u: URL,
                           req_headers: dict, raw_body: bytes, metrics):
        h2_headers = [(k.lower(), str(v)) for k, v in req_headers.items()
                      if k.lower() not in self._H2_SKIP]
        host = f"[{u.host}]" if ":" in u.host else u.host
        authority = host if u.port == 443 else f"{host}:{u.port}"
        if metrics:
            metrics.bytes_sent = len(raw_body) + sum(len(k) + len(v) for k, v in h2_headers)
        send_time = time.monotonic()
        try:
            r = await conn.request(method, authority, u.raw_path.decode("latin-1"),
                                   h2_headers, raw_body)
        except H2StreamRefused:
            raise
        except (Http2StreamError, Http2ConnectionError) as e:
            raise ConnectionError(f"HTTP/2 isteği başarısız: {e}") from e
        if metrics:
            metrics.first_byte_time = r.first_byte_time or time.monotonic()
        headers = Headers()
        for k, v in r.headers:
            headers.add(k, v)
        return r.status, headers, r.body, send_time, "HTTP/2"

    @staticmethod
    def _h1_framing(method: str, status: int, headers: Headers) -> str:
        """"none" | "chunked" | "length" | "eof" (RFC 9112 §6.3)."""
        if method.upper() == "HEAD" or status in (204, 304) or 100 <= status < 200:
            return "none"
        if "chunked" in headers.get("transfer-encoding", "").lower():
            return "chunked"
        if headers.get("content-length", "").strip().isdigit():
            return "length"
        return "eof"

    @staticmethod
    async def _h1_read_body(reader, method: str, status: int, headers: Headers,
                            first: bytes, read_to: Optional[float]) -> "tuple[bytes, int]":
        """HTTP/1.1 gövdesi (RFC 9112 §6.3): ``(gövde, artakalan_bayt)``.

        Eksik gövde ConnectionResetError'dır. ``artakalan_bayt`` > 0 ise bağlantıda
        yanıta ait olmayan veri var demektir (bağlantı yeniden kullanılmamalı).
        """
        async def more() -> bytes:
            return await asyncio.wait_for(reader.read(4096), timeout=read_to)

        framing = AsyncSession._h1_framing(method, status, headers)
        if framing == "none":
            return b"", len(first)      # gövde YOK: bağlantıdan veri beklenmez

        buf = bytearray(first)
        if framing == "chunked":
            out = bytearray()
            pos = 0
            while True:
                nl = buf.find(b"\r\n", pos)
                while nl == -1:
                    c = await more()
                    if not c:
                        raise ConnectionResetError("Chunked gövde yarıda kesildi.")
                    buf.extend(c)
                    nl = buf.find(b"\r\n", pos)
                try:
                    sz = int(bytes(buf[pos:nl]).split(b";")[0].strip(), 16)
                except ValueError:
                    raise ConnectionError("Geçersiz chunk boyutu.") from None
                pos = nl + 2
                if sz == 0:
                    # trailer'lar (varsa) boş satıra kadar tüketilir: bağlantı temiz kalsın
                    while True:
                        nl = buf.find(b"\r\n", pos)
                        while nl == -1:
                            c = await more()
                            if not c:
                                raise ConnectionResetError("Chunked gövde yarıda kesildi.")
                            buf.extend(c)
                            nl = buf.find(b"\r\n", pos)
                        empty = nl == pos
                        pos = nl + 2
                        if empty:
                            return bytes(out), len(buf) - pos
                while len(buf) < pos + sz + 2:
                    c = await more()
                    if not c:
                        raise ConnectionResetError("Chunked gövde yarıda kesildi.")
                    buf.extend(c)
                out.extend(buf[pos:pos + sz])
                pos += sz + 2
                if pos > 65536:             # işlenmiş kısmı at
                    del buf[:pos]
                    pos = 0

        if framing == "length":
            n = int(headers.get("content-length", "").strip())
            while len(buf) < n:
                c = await more()
                if not c:
                    raise ConnectionResetError(
                        f"Yanıt gövdesi eksik: {len(buf)}/{n} bayt alındı.")
                buf.extend(c)
            return bytes(buf[:n]), len(buf) - n

        while True:                          # bağlantı kapanana kadar (HTTP/1.0)
            try:
                c = await asyncio.wait_for(reader.read(4096), timeout=2.0)
            except (ConnectionResetError, asyncio.TimeoutError):
                break
            if not c:
                break
            buf.extend(c)
        return bytes(buf), 0

    async def _h1_exchange(self, opened: "_Opened", method: str, u: URL,
                           req_headers: dict, raw_body: bytes, metrics):
        """Bağlantıda tek HTTP/1.1 isteği. Bağlantı yeniden kullanılabilirse havuza
        döner; aksi halde (Connection: close, HTTP/1.0, eof çerçeveli gövde, hata,
        iptal) kapatılır. Slot her durumda serbest bırakılır."""
        reader, writer = opened.reader, opened.writer
        read_to = self._tmo().read
        reusable = False
        finished = False
        got_bytes = False        # yanıttan en az 1 bayt geldi mi (yeniden deneme güvenliği)
        try:
            req_line = f"{method} {u.raw_path.decode()} HTTP/1.1\r\n"
            for k, v in order_h1(self.impersonate, drop_h2_only_defaults(
                    self.impersonate, list(req_headers.items()))):
                req_line += f"{k}: {v}\r\n"
            req_line += "\r\n"
            raw_request = req_line.encode("ascii") + (raw_body or b"")
            if metrics:
                metrics.bytes_sent = len(raw_request)

            writer.write(raw_request)
            await asyncio.wait_for(writer.drain(), self._tmo().write)
            send_time = time.monotonic()

            hdr_acc = bytearray()
            sep     = -1
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=read_to)
                if not chunk: break
                got_bytes = True
                if len(hdr_acc) == 0 and metrics:
                    metrics.first_byte_time = time.monotonic()
                search_from = max(0, len(hdr_acc) - 3)
                hdr_acc += chunk
                sep = hdr_acc.find(b"\r\n\r\n", search_from)
                if sep != -1:
                    break
            hdr_buf = bytes(hdr_acc)
            if sep == -1:
                raise ConnectionResetError("Sunucu yanıt başlıkları tamamlanmadan bağlantıyı kesti.")

            headers_raw      = hdr_buf[:sep]
            first_body_chunk = hdr_buf[sep + 4:]

            lines = headers_raw.split(b"\r\n")
            status_code = 0
            try:
                status_code = int(lines[0].decode("ascii", errors="ignore").split(" ", 2)[1])
            except (IndexError, ValueError):
                logger.debug("Status satırı ayrıştırılamadı: %r", lines[0][:80])

            resp_headers = Headers()
            for line in lines[1:]:
                if b":" not in line: continue
                k, _, v = line.partition(b":")
                resp_headers._list.append((k.strip(), k.strip().lower(), v.strip()))

            body_raw, extra = await self._h1_read_body(
                reader, method, status_code, resp_headers, first_body_chunk, read_to)

            conn_tokens = {t.strip() for t in resp_headers.get("connection", "").lower().split(",")}
            http10 = lines[0].upper().startswith(b"HTTP/1.0")
            req_close = any(k.lower() == "connection" and "close" in str(v).lower()
                            for k, v in req_headers.items())
            reusable = (
                status_code != 101 and extra == 0 and not req_close
                and "close" not in conn_tokens
                and (not http10 or "keep-alive" in conn_tokens)
                and self._h1_framing(method, status_code, resp_headers) != "eof"
            )
            return status_code, resp_headers, bytes(body_raw), send_time, "HTTP/1.1"
        except BaseException as e:
            if (opened.reused and not got_bytes
                    and isinstance(e, (ConnectionError, OSError))
                    and not isinstance(e, (TimeoutError, asyncio.TimeoutError))):
                # Çağıran yeniden dener; bu bağlantı kapatılır, slot bırakılır.
                finished = True
                await self._h1_finish(opened, False)
                raise _StaleConn(e) from e
            raise
        finally:
            if not finished:
                await self._h1_finish(opened, reusable)

    async def _raw_request(
        self,
        method:  str,
        url:     str,
        headers: Optional[dict]  = None,
        body:    bytes           = b"",
        metrics: Optional[RequestMetrics] = None,
    ) -> Response:
        """Tek async HTTP isteği (ALPN'e göre HTTP/2 veya HTTP/1.1)."""
        u = URL(url) if isinstance(url, str) else url

        proxy_cfg, proxy = self._select_proxy(u)

        req_dict = {"method": method, "url": url, "headers": headers or {}, "body": body}
        req_dict = await self._run_request_hooks(req_dict)

        # Profilin tarayıcı başlıkları (User-Agent, Accept-Encoding, sec-ch-ua...)
        # + kullanıcı başlıkları (geçersiz kılar); büyük/küçük harf duyarsız.
        hh = Headers(merge_default_headers(self.impersonate, req_dict.get("headers") or {}))
        if "host" not in hh:
            hh["Host"] = u.host
        if "connection" not in hh:
            hh["Connection"] = "keep-alive"
        req_headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in hh.raw}
        cookie_header = self._cookie_header(u)
        if cookie_header and not any(k.lower() == "cookie" for k in req_headers):
            req_headers["Cookie"] = cookie_header

        cache_entry = None
        if self._cache and method.upper() == "GET":
            cache_entry = self._cache.get(url, method)
            if cache_entry:
                cond = self._cache.build_conditional_headers(cache_entry)
                req_headers.update(cond)

        raw_body = req_dict.get("body", b"")
        if raw_body:
            req_headers["Content-Length"] = str(len(raw_body))

        if metrics:
            metrics.request_start = time.monotonic()

        try:
            status_code, resp_headers, body_raw, send_time, http_version = await self._exchange(
                method, u, proxy_cfg, req_headers, raw_body, metrics)

            if metrics:
                metrics.transfer_end   = time.monotonic()
                metrics.bytes_received = len(body_raw)
                metrics.total_end      = time.monotonic()

            ce  = resp_headers.get("content-encoding", "").lower()
            body_final = HTTP1Parser._decompress(bytes(body_raw), ce)

            self._update_cookies(resp_headers, u)

            resp = Response(status_code=status_code, headers=resp_headers, body=body_final)
            resp.http_version = http_version
            resp.url = str(url)
            if metrics and metrics.request_start:
                resp.elapsed = time.monotonic() - metrics.request_start

            if metrics:
                resp.metrics = metrics

            if status_code == 304 and cache_entry:
                resp = cache_entry.response

            if self._cache and method.upper() == "GET":
                self._cache.store(url, method, resp)

            if proxy and self._rotator and metrics and metrics.first_byte_time:
                ttfb = (metrics.first_byte_time - send_time) * 1000
                self._rotator.update_perf(proxy, ttfb)

            resp = await self._run_response_hooks(resp)
            return resp

        except Exception as e:
            if proxy and self._rotator:
                self._rotator.mark_failed(proxy)
            for plugin in self._plugins:
                e2 = await call_async(plugin, "on_error", e)
                if e2 is None:
                    return Response(0, body=b"")
            raise

                                                                                
    # --- Faz 5 kancaları: transport + retry -------------------------------

    async def _send(self, method, url, headers=None, body=b"", metrics=None) -> Response:
        """Tek isteği transport'a (verilmişse) ya da ağa gönderir."""
        if self.transport is None:
            return await self._raw_request(method, url, headers=headers, body=body,
                                           metrics=metrics)
        try:
            req_dict = await self._run_request_hooks(
                {"method": method, "url": url, "headers": headers or {}, "body": body}
            )
            h = {k: v for k, v in dict(req_dict.get("headers") or {}).items() if v is not None}
            cookie_header = self._cookie_header(URL(req_dict["url"]))
            if cookie_header and not any(k.lower() == "cookie" for k in h):
                h["Cookie"] = cookie_header
            req = Request(method=req_dict["method"], url=req_dict["url"], headers=h,
                          data=req_dict.get("body") or None)
            if "host" not in req.headers:
                req.headers["Host"] = req.url.host
            req.timeout = self._tmo()
            resp = await self.transport.handle_async_request(req)
            self._update_cookies(resp.headers, req.url)
            return await self._run_response_hooks(resp)
        except Exception as e:
            for plugin in self._plugins:
                if await call_async(plugin, "on_error", e) is None:
                    return Response(0, body=b"")
            raise

    async def _send_with_retries(self, method, url, **kwargs) -> Response:
        """``self.retries`` politikasına göre ``_send``'i tekrarlar."""
        retry = self.retries
        attempt = 0
        while True:
            try:
                resp = await self._send(method, url, **kwargs)
            except Exception as e:
                if not retry.should_retry_error(method, e, attempt):
                    raise
                attempt += 1
                delay = retry.get_delay(attempt)
            else:
                if not retry.should_retry_status(method, resp.status_code, attempt):
                    return resp
                attempt += 1
                delay = retry.get_delay(attempt, resp)
            logger.debug("%d. yeniden deneme %.2fs sonra", attempt, delay)
            if delay:
                await asyncio.sleep(delay)

    # --- kimlik / hook / hop ------------------------------------------------

    def _auth_for(self, auth, url_creds, host: str):
        """(Auth | None, kaynak): istek > oturum > .netrc (trust_env) > URL'deki user:pass@."""
        chosen = self.auth if auth is USE_CLIENT_DEFAULT else auth
        if chosen is not None:
            return resolve_auth(chosen), "explicit"
        if self.trust_env:
            creds = netrc_credentials(host)
            if creds:
                return BasicAuth(*creds), "netrc"
        if url_creds:
            return BasicAuth(*url_creds), "url"
        return None, None

    async def _call_hooks(self, event: str, arg, req_hooks=None, **kw):
        """Hook'ları çalıştırır. Yanıtta requests hook'u ``None`` dışı dönerse yanıt değişir."""
        if event == "request":
            for fn in _api.hook_list(self.event_hooks, "request"):
                await _maybe(fn(arg))
            return arg
        for fn in _api.hook_list(self.event_hooks, "response"):
            await _maybe(fn(arg))
        for fn in _api.hook_list(self.hooks, "response") + _api.hook_list(req_hooks, "response"):
            out = await _maybe(fn(arg, **kw))
            if out is not None:
                arg = out
        return arg

    async def _hop(self, auth, method, url, headers, body, metrics, req_hooks, hkw):
        """Tek yönlendirme adımı: auth akışı (401 yeniden denemesi dahil) + hook'lar.

        Döner: (son yanıt, ara yanıtlar). Ara yanıtlar (ör. 401 challenge) ``history``'ye girer.
        """
        has_req_hooks = bool(_api.hook_list(self.event_hooks, "request"))
        extras: list[Response] = []
        if auth is None and not has_req_hooks:
            resp = await self._send_with_retries(method, url, headers=headers, body=body, metrics=metrics)
            return await self._call_hooks("response", resp, req_hooks, **hkw), extras
        removed = [k for k, v in headers.items() if v is None]
        base = Request(method, url, data=body or None,
                       headers={k: v for k, v in headers.items() if v is not None})
        flow = auth.auth_flow(base) if auth is not None else None
        req = next(flow) if flow is not None else base
        while True:
            await self._call_hooks("request", req)
            h = {k.decode("latin-1"): v.decode("latin-1") for k, v in req.headers.raw
                 if k.lower() != b"content-length"}
            lower = {x.lower() for x in h}
            h.update({k: None for k in removed if k.lower() not in lower})
            target = url if req.url is base.url else str(req.url)
            resp = await self._send_with_retries(req.method, target, headers=h,
                                           body=req.body or b"", metrics=metrics)
            resp = await self._call_hooks("response", resp, req_hooks, **hkw)
            if flow is None:
                return resp, extras
            try:
                req = flow.send(resp)
            except StopIteration:
                return resp, extras
            extras.append(resp)

    async def request(
        self,
        method:          str,
        url:             "str | URL",
        data             = None,
        json             = None,
        headers          = None,
        files            = None,
        allow_redirects: bool = True,
        params           = None,
        cookies          = None,
        auth             = USE_CLIENT_DEFAULT,
        timeout          = USE_CLIENT_DEFAULT,
        hooks            = None,
    ) -> Response:
        """HTTP isteği. requests/httpx uyumlu ek parametreler:

        ``params`` (dict/liste/str; URL'deki sorguya eklenir), ``cookies`` (yalnızca bu
        istek için; yönlendirmede başka origin'e gitmez), ``auth`` (oturumunkini ezer;
        ``None`` oturum auth'unu kapatır), ``timeout`` (float, ``(connect, read)`` ya da
        :class:`Timeout`; ``None`` sınırsız), ``hooks`` (``{"response": [fn]}``).
        """
        url, url_creds = _api.split_userinfo(url)
        url = _api.apply_params(url, self.params, params)
        current_url    = url
        redirect_count = 0
        history: list[Response] = []
        metrics = RequestMetrics(request_start=time.monotonic())
        headers = self._merged_headers(headers)
        body = _api.encode_body(data, json, files, headers)
        req_hooks = _api.normalize_hooks(hooks)
        req_cookies = _api.parse_cookie_arg(cookies)
        tmo = _api.resolve_timeout(timeout, self.timeout)
        token = _api.set_timeout_override(self, tmo)
        hkw = _api.hook_kwargs(self, tmo or self.timeout)
        first_origin = URL(current_url).origin
        retry_plugins = [p for p in self._plugins if isinstance(p, RetryPlugin)]
        try:
            while True:
                cur = URL(current_url)
                same_origin = cur.origin == first_origin
                hop_auth, _src = self._auth_for(
                    auth if same_origin else None, url_creds if same_origin else None, cur.host)
                if not same_origin and _src == "explicit":
                    hop_auth = None
                hop_headers = dict(headers)
                if same_origin and req_cookies and not _api._has(hop_headers, "cookie"):
                    jar = self.cookie_jar.header_for(
                        host=cur.host, path=cur.path, secure=(cur.scheme == "https"))
                    hop_headers["Cookie"] = _api.merge_cookie_header(jar, req_cookies)
                attempt = 0
                while True:
                    resp, extras = await self._hop(hop_auth, method, current_url, hop_headers,
                                             body, metrics, req_hooks, hkw)
                    delay = None
                    for plugin in retry_plugins:
                        if plugin.should_retry(resp, attempt):
                            delay = plugin.delay_for(resp, attempt)
                            break
                    if delay is None:
                        break
                    if delay:
                        await asyncio.sleep(delay)
                    attempt += 1
                history.extend(extras)
                if history:
                    resp.history = list(history)

                if not allow_redirects or resp.status_code not in (301, 302, 303, 307, 308):
                    if not allow_redirects:
                        resp.next = _api.next_request(resp, method, current_url, headers, body)
                    return resp

                if redirect_count >= self.max_redirects:
                    raise ConnectionError(f"Maksimum yönlendirme sayısına ulaşıldı ({self.max_redirects}).")

                location = resp.headers.get("location", "")
                if not location:
                    return resp

                history.append(resp)
                metrics.redirect_count += 1

                base = URL(current_url) if isinstance(current_url, str) else current_url
                current_url = _resolve_location(base, location)

                # Farklı bir origin'e gidiyorsak Authorization/Cookie TAŞINMAZ;
                # aksi hâlde kimlik bilgisi üçüncü bir siteye sızar.
                new_url = URL(current_url)
                if (new_url.scheme, new_url.host, new_url.port) != base.origin and headers:
                    headers = {
                        k: v for k, v in dict(headers).items()
                        if k.lower() not in ("authorization", "cookie", "proxy-authorization")
                    }

                if resp.status_code in (301, 302, 303):
                    method = "GET"
                    body   = b""
                    headers = {k: v for k, v in headers.items()
                               if k.lower() not in ("content-type", "content-length")}

                redirect_count += 1
                logger.debug("Yönlendirme (%s) -> %s", resp.status_code, current_url)
        finally:
            _api.reset_timeout_override(token)

    def _merged_headers(self, headers) -> dict:
        """Oturum başlıkları + istek başlıkları (istek kazanır; büyük/küçük harf
        duyarsız). ``None`` değerler, varsayılanı kaldırmak için korunur."""
        merged: dict = {}
        index: dict = {}
        for src in (self.headers, headers or {}):
            for k, v in (src.items() if hasattr(src, "items") else src):
                lk = k.lower()
                if lk in index:
                    del merged[index[lk]]
                index[lk] = k
                merged[k] = v
        return merged

    async def get(self, url, headers=None, allow_redirects=True, params=None, cookies=None,
                  auth=USE_CLIENT_DEFAULT, timeout=USE_CLIENT_DEFAULT, hooks=None) -> Response:
        return await self.request("GET", url, headers=headers, allow_redirects=allow_redirects,
                                  params=params, cookies=cookies, auth=auth, timeout=timeout,
                                  hooks=hooks)

    async def post(self, url, data=None, json=None, headers=None, files=None, allow_redirects=True,
                   params=None, cookies=None, auth=USE_CLIENT_DEFAULT, timeout=USE_CLIENT_DEFAULT,
                   hooks=None) -> Response:
        return await self.request("POST", url, data=data, json=json, headers=headers, files=files,
                                  allow_redirects=allow_redirects, params=params, cookies=cookies,
                                  auth=auth, timeout=timeout, hooks=hooks)

    async def put(self, url, data=None, json=None, headers=None, files=None, allow_redirects=True,
                  params=None, cookies=None, auth=USE_CLIENT_DEFAULT, timeout=USE_CLIENT_DEFAULT,
                  hooks=None) -> Response:
        return await self.request("PUT", url, data=data, json=json, headers=headers, files=files,
                                  allow_redirects=allow_redirects, params=params, cookies=cookies,
                                  auth=auth, timeout=timeout, hooks=hooks)

    async def patch(self, url, data=None, json=None, headers=None, allow_redirects=True,
                    params=None, cookies=None, auth=USE_CLIENT_DEFAULT, timeout=USE_CLIENT_DEFAULT,
                    hooks=None) -> Response:
        return await self.request("PATCH", url, data=data, json=json, headers=headers,
                                  allow_redirects=allow_redirects, params=params, cookies=cookies,
                                  auth=auth, timeout=timeout, hooks=hooks)

    async def delete(self, url, headers=None, allow_redirects=True, params=None, cookies=None,
                     auth=USE_CLIENT_DEFAULT, timeout=USE_CLIENT_DEFAULT, hooks=None) -> Response:
        return await self.request("DELETE", url, headers=headers, allow_redirects=allow_redirects,
                                  params=params, cookies=cookies, auth=auth, timeout=timeout,
                                  hooks=hooks)

    async def head(self, url, headers=None, allow_redirects=False, params=None, cookies=None,
                   auth=USE_CLIENT_DEFAULT, timeout=USE_CLIENT_DEFAULT, hooks=None) -> Response:
        """HEAD; ``allow_redirects`` varsayılanı ``False`` (requests/httpx gibi)."""
        return await self.request("HEAD", url, headers=headers, allow_redirects=allow_redirects,
                                  params=params, cookies=cookies, auth=auth, timeout=timeout,
                                  hooks=hooks)

    async def options(self, url, headers=None, allow_redirects=True, params=None, cookies=None,
                      auth=USE_CLIENT_DEFAULT, timeout=USE_CLIENT_DEFAULT, hooks=None) -> Response:
        return await self.request("OPTIONS", url, headers=headers,
                                  allow_redirects=allow_redirects, params=params, cookies=cookies,
                                  auth=auth, timeout=timeout, hooks=hooks)

    async def gather(self, *requests: tuple) -> list[Response]:
        """
        Birden fazla isteği paralel çalıştır.
        requests: [(method, url), (method, url, {headers}), ...]
        """
        tasks = []
        for req in requests:
            if len(req) == 2:
                method, url = req; kw = {}
            else:
                method, url, kw = req
            tasks.append(self.request(method, url, **kw))
        return await asyncio.gather(*tasks)

                                                                                

    async def ws_connect(self, url: str) -> "AsyncWebSocket":
        """Async WebSocket bağlantısı açar."""
        return await AsyncWebSocket.connect(url, self)

    async def websocket(self, url: str) -> "AsyncWebSocket":
        """Senkron ``Session.websocket`` ile aynı ad (``ws_connect`` takma adı)."""
        return await self.ws_connect(url)

                                                                                

    async def close(self) -> None:
        conns, self._h2 = list(self._h2.values()), {}
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        idle = [o for lst in self._idle.values() for o in lst]
        self._idle = {}
        waits = []
        for o in idle:
            self._drop_conn(o)
            if o.loop is running:
                waits.append((o, asyncio.ensure_future(o.writer.wait_closed())))
        if waits:
            # Karşı taraf TLS close_notify'a yanıt vermezse (ssl kapanış zaman aşımı
            # 30 sn) close() takılmasın: kısa süre bekle, kalanı arka planda kapanır.
            _, pending = await asyncio.wait([t for _, t in waits], timeout=1.0)
            for o, t in waits:
                if t in pending:
                    t.cancel()
                    inner = getattr(o.writer, "writer", o.writer)
                    transport = getattr(inner, "transport", None)
                    if transport is not None:
                        transport.abort()       # TCP'yi şimdi bırak
                elif not t.cancelled() and t.exception() is not None:
                    logger.debug("wait_closed hatası yok sayıldı: %s", t.exception())
        for c in conns:
            if c.loop is running:
                await c.close()
        if self.transport is not None:
            self.transport.close()                                         

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()


                                                                               
                 
                                                                               

class AsyncWebSocket:
    """asyncio tabanlı WebSocket bağlantısı (``ws://`` ve ``wss://``).

    Bağlantı :meth:`AsyncSession._connect` ile kurulur: ``impersonate`` varsa
    tarayıcı ClientHello'su (ALPN yalnızca ``http/1.1``; WebSocket h2 üzerinden
    yükseltilemez), ``proxy``/``proxies``/rotasyon varsa proxy tüneli üzerinden.
    """

    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, reader, writer):
        self._reader = reader
        self._writer = writer
        self._buf    = bytearray()
        self._closed = False

    @classmethod
    async def connect(cls, url: str, session: AsyncSession) -> "AsyncWebSocket":
        import base64, hashlib, os
        from urllib.parse import urlparse
        from .protocol.http2_parser import _validate_ws_handshake_response
        u   = URL(url)
        tls = u.scheme in ("wss", "https")
        # URL modeli şema-varsayılan portu yalnızca http/https için bilir.
        port = urlparse(str(url)).port or (443 if tls else 80)
        key = base64.b64encode(os.urandom(16)).decode()
        expected = base64.b64encode(hashlib.sha1((key + cls.GUID).encode()).digest()).decode()

        proxy_cfg, proxy_url = session._select_proxy(u)
        try:
            reader, writer, _ = await session._connect(
                u.host, port, proxy_cfg, alpn=["http/1.1"], tls=tls)
        except Exception:
            if proxy_url and session._rotator:
                session._rotator.mark_failed(proxy_url)
            raise

        try:
            default = 443 if tls else 80
            host = f"[{u.host}]" if ":" in u.host else u.host
            hostport = host if port == default else f"{host}:{port}"
            req = (
                f"GET {u.raw_path.decode()} HTTP/1.1\r\n"
                f"Host: {hostport}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n"
            )
            writer.write(req.encode("latin-1"))
            await asyncio.wait_for(writer.drain(), session.timeout.write)

            resp = bytearray()
            while b"\r\n\r\n" not in resp:
                chunk = await asyncio.wait_for(reader.read(4096), session.timeout.read)
                if not chunk:
                    raise ConnectionError(
                        f"WebSocket Upgrade yanıtı tamamlanmadan bağlantı kapandı: {bytes(resp[:200])!r}")
                resp += chunk
                if len(resp) > 65536:
                    raise ConnectionError("WebSocket Upgrade yanıt başlığı çok büyük.")
            head, _, leftover = bytes(resp).partition(b"\r\n\r\n")
            _validate_ws_handshake_response(head, expected)
        except BaseException:
            writer.close()
            raise

        ws = cls(reader, writer)
        ws._buf += leftover          # 101'den hemen sonra gelen frame'ler kaybolmasın
        return ws

    async def send_text(self, text: str) -> None:
        from .protocol.http2_parser import WebSocketFrame
        frame = WebSocketFrame(WebSocketFrame.OP_TEXT, text.encode("utf-8"))
        self._writer.write(frame.serialize())
        await self._writer.drain()

    async def send_binary(self, data: bytes) -> None:
        from .protocol.http2_parser import WebSocketFrame
        frame = WebSocketFrame(WebSocketFrame.OP_BINARY, bytes(data))
        self._writer.write(frame.serialize())
        await self._writer.drain()

    async def recv(self) -> "tuple[int, bytes]":
        """Tek frame oku. Döner: ``(opcode, payload)``; bağlantı kapanırsa ``(OP_CLOSE, b"")``."""
        from .protocol.http2_parser import WebSocketFrame
        while True:
            frame, consumed = WebSocketFrame.parse(bytes(self._buf))
            if frame:
                del self._buf[:consumed]
                if frame.opcode == WebSocketFrame.OP_PING:
                    pong = WebSocketFrame(WebSocketFrame.OP_PONG, frame.payload)
                    self._writer.write(pong.serialize())
                    await self._writer.drain()
                    continue
                if frame.opcode == WebSocketFrame.OP_CLOSE:
                    self._closed = True
                return frame.opcode, frame.payload
            chunk = await self._reader.read(4096)
            if not chunk:
                self._closed = True
                return WebSocketFrame.OP_CLOSE, b""
            self._buf += chunk

    async def recv_text(self) -> str:
        """Sıradaki frame'in metni (kapanışta ``""``)."""
        _, payload = await self.recv()
        return payload.decode("utf-8", errors="replace")

    async def close(self) -> None:
        if not self._closed:
            from .protocol.http2_parser import WebSocketFrame
            self._closed = True
            try:
                self._writer.write(WebSocketFrame(
                    WebSocketFrame.OP_CLOSE, (1000).to_bytes(2, "big")).serialize())
                await asyncio.wait_for(self._writer.drain(), 2.0)
            except (OSError, asyncio.TimeoutError, RuntimeError) as e:
                logger.debug("WebSocket CLOSE frame'i gönderilemedi: %s", e)
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except OSError as e:
            logger.debug("WebSocket wait_closed hatası yok sayıldı: %s", e)

    async def __aenter__(self): return self
    async def __aexit__(self, *a): await self.close()


async def _start_tls_py310(reader, writer, ctx, host):
    """Python 3.10 için ``StreamWriter.start_tls`` karşılığı (3.11'de eklendi).

    Var olan (proxy tüneli) transport'u ``loop.start_tls`` ile TLS'e yükseltir ve
    aynı StreamReader'ı besleyen protokolü yeni transport'a bağlar; 3.11'deki
    ``StreamWriter.start_tls`` gövdesiyle aynı adımlar.
    """
    loop = asyncio.get_running_loop()
    protocol = writer.transport.get_protocol()
    await writer.drain()
    new_transport = await loop.start_tls(
        writer.transport, protocol, ctx, server_hostname=host)
    # StreamReaderProtocol yeni transport'u bilmeli (3.11: _replace_writer).
    protocol._transport = new_transport
    protocol._over_ssl = True
    new_writer = asyncio.StreamWriter(new_transport, protocol, reader, loop)
    protocol._stream_writer = new_writer
    return new_writer
