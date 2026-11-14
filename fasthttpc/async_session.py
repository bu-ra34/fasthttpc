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

logger = get_logger("async")
import time
import threading
from dataclasses import dataclass
from typing import Any, Callable, Optional, AsyncGenerator, Union
from .models.urls     import URL
from .models.headers  import Headers
from .models.response import Response, HTTPStatusError
from .metrics         import RequestMetrics
from .cache           import ResponseCache
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


class Plugin:
    """
    Base plugin sınıfı. Kalıtım alarak özelleştirin.
    Metodlar opsiyonel — sadece gerekli hook'ları override edin.
    """
    async def on_request(self, request: dict) -> dict:
        """İstek gönderilmeden önce çağrılır. request dict'i döndürün."""
        return request

    async def on_response(self, response: Response) -> Response:
        """Yanıt alındıktan sonra çağrılır. response döndürün."""
        return response

    async def on_error(self, error: Exception) -> Optional[Exception]:
        """Hata oluştuğunda çağrılır. None → hatayı yut; Exception → yeniden fırlat."""
        return error


class RetryPlugin(Plugin):
    """Belirli durum kodlarında isteği otomatik tekrar dener.

    Yeniden deneme, istek döngüsünün SAHİBİ olan ``AsyncSession.request``
    tarafından uygulanır; bir ``on_response`` hook'u yanıtı dönüştürebilir ama
    yeni bir istek başlatamaz. Bu yüzden plugin yalnızca politikayı bildirir,
    kararı session verir.

    Args:
        max_retries: Azami yeniden deneme sayısı (ilk istek hariç).
        retry_on:    Yeniden denenecek HTTP durum kodları.
        backoff:     Üstel bekleme taban süresi (saniye). 0 ise beklenmez.
    """

    def __init__(self, max_retries: int = 3,
                 retry_on: tuple = (429, 500, 502, 503, 504),
                 backoff: float = 0.5):
        self.max_retries = max_retries
        self.retry_on = set(retry_on)
        self.backoff = backoff

    def should_retry(self, response: Response, attempt: int) -> bool:
        return attempt < self.max_retries and response.status_code in self.retry_on

    def delay_for(self, response: Response, attempt: int) -> float:
        """Retry-After başlığına saygı duyar, yoksa üstel bekleme uygular."""
        retry_after = response.headers.get("retry-after", "")
        if retry_after:
            try:
                return max(0.0, float(retry_after.strip()))
            except ValueError:
                pass
        return self.backoff * (2 ** attempt) if self.backoff else 0.0


class LoggingPlugin(Plugin):
    """İstekleri ve yanıtları loglar."""
    def __init__(self, verbose: bool = False):
        self._verbose = verbose

    async def on_request(self, request: dict) -> dict:
        print(f"[LOG] → {request['method']} {request['url']}")
        return request

    async def on_response(self, response: Response) -> Response:
        status = response.status_code
        size   = len(response.body)
        print(f"[LOG] ← {status} ({size}B)")
        if self._verbose and hasattr(response, "metrics"):
            print(f"       ttfb={response.metrics.ttfb:.1f}ms total={response.metrics.total_time:.1f}ms")
        return response


class RateLimitPlugin(Plugin):
    """Saniyedeki istek sayısını sınırlar."""
    def __init__(self, rps: float = 10.0):
        self._interval = 1.0 / rps
        self._last_req = 0.0
        self._lock     = asyncio.Lock()

    async def on_request(self, request: dict) -> dict:
        async with self._lock:
            now   = time.monotonic()
            wait  = self._interval - (now - self._last_req)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_req = time.monotonic()
        return request


                                                                               
                                   
                                                                               

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
    ):
        # impersonate verilirse TLS, fasthttpc.tls13 çekirdeğiyle (tarayıcı
        # ClientHello'su) kurulur ve profilin ALPN'i (h2, http/1.1) kullanılır;
        # sunucu h2 seçerse HTTP/2 (multiplexing) konuşulur.
        # impersonate=None -> stdlib ssl, yalnızca HTTP/1.1.
        from .session import _proxy_spec
        self.impersonate   = impersonate
        self.timeout       = Timeout.from_value(timeout)
        self.verify        = verify
        self._ca_path      = resolve_verify(verify)   # None → varsayılan güven deposu
        self.retries       = Retry.from_value(retries)
        self.transport     = transport
        self.max_redirects = max_redirects
        self.limits        = limits if limits is not None else Limits(max_connections=max_connections)
        self._proxy_spec   = _proxy_spec(proxy, proxies)
        self.cookies:  dict[str, str] = {}
        self._plugins: list[Plugin]   = []
        self._rotator: Optional[ProxyRotator] = None
        self._sem     = asyncio.Semaphore(self.limits.max_connections)
        # HTTP/2: (host, port, proxy) -> canlı bağlantı; kaynak protokol önbelleği
        self._h2:           dict[tuple, AsyncHttp2Connection] = {}
        self._origin_proto: dict[tuple, str] = {}
        self._origin_locks: dict[tuple, asyncio.Lock] = {}
        self._bg_tasks:     set[asyncio.Task] = set()

        if isinstance(cache, ResponseCache):
            self._cache: Optional[ResponseCache] = cache
        elif cache:
            self._cache = ResponseCache(default_ttl=cache_ttl)
        else:
            self._cache = None

                                                                               

    def use(self, plugin: Plugin) -> "AsyncSession":
        """Plugin ekle. Zincir çağrı destekli: session.use(p1).use(p2)"""
        self._plugins.append(plugin)
        return self

    async def _run_request_hooks(self, req: dict) -> dict:
        for plugin in self._plugins:
            req = await plugin.on_request(req)
        return req

    async def _run_response_hooks(self, resp: Response) -> Response:
        for plugin in self._plugins:
            resp = await plugin.on_response(resp)
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
        Async pre-warming: asyncio.gather ile paralel TLS handshake.
        """
        results: dict[str, int] = {}

        async def _warm_one(host: str) -> tuple[str, bool]:
            try:
                ctx = ssl.create_default_context(cafile=self._ca_path)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, 443, ssl=ctx),
                    timeout=self.timeout.connect,
                )
                writer.close()
                await writer.wait_closed()
                return host, True
            except (OSError, asyncio.TimeoutError) as e:  # ssl.SSLError ⊂ OSError
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

    async def _connect(self, host: str, port: int, proxy: Optional[ProxyConfig]):
        """TCP (+ varsa proxy tüneli) + TLS. ``(reader, writer, alpn)`` döner.

        impersonate: tarayıcı ClientHello'su (ALPN = profilin h2, http/1.1
        listesi); tünel varsa TLS tünelin İÇİNDE, hedef host'a karşı kurulur.
        impersonate=None: stdlib ssl, yalnızca http/1.1.
        """
        connect_to = self.timeout.connect

        async def _go():
            if self.impersonate is not None:
                if proxy is None:
                    stream = await AsyncTLSStream.connect(
                        host, port, self.impersonate, ca_path=self._ca_path)
                else:
                    reader, writer = await async_connect_via_proxy(proxy, host, port, timeout=connect_to)
                    try:
                        stream = await AsyncTLSStream.negotiate(
                            reader, writer, host, self.impersonate, ca_path=self._ca_path)
                    except BaseException:
                        writer.close()
                        raise
                return stream, stream, stream.conn.alpn
            ctx = ssl.create_default_context(cafile=self._ca_path)
            ctx.set_alpn_protocols(["http/1.1"])
            if proxy is None:
                reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
            else:
                reader, writer = await async_connect_via_proxy(proxy, host, port, timeout=connect_to)
                try:
                    if hasattr(writer, "start_tls"):   # Python 3.11+
                        await writer.start_tls(ctx, server_hostname=host)
                    else:
                        writer = await _start_tls_py310(reader, writer, ctx, host)
                except BaseException:
                    writer.close()
                    raise
            return reader, writer, "http/1.1"

        return await asyncio.wait_for(_go(), connect_to)

    async def _open(self, u: URL, proxy: Optional[ProxyConfig], metrics) -> "_Opened":
        """Havuz slotu alır, bağlanır. Slot ``release()`` ile geri verilir."""
        try:
            await asyncio.wait_for(self._sem.acquire(), self.timeout.pool)
        except asyncio.TimeoutError:
            raise asyncio.TimeoutError(
                f"Bağlantı havuzu {self.timeout.pool} sn içinde boşalmadı "
                f"(max_connections={self.limits.max_connections}).") from None
        released = False

        def release() -> None:
            nonlocal released
            if not released:
                released = True
                self._sem.release()

        try:
            if metrics:
                metrics.connect_start = time.monotonic()
            reader, writer, alpn = await self._connect(u.host, u.port, proxy)
        except BaseException:
            release()
            raise
        if metrics:
            metrics.connect_end = time.monotonic()
            metrics.tls_end     = time.monotonic()
        return _Opened(reader, writer, alpn, release)

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
            stream, read_timeout=self.timeout.read, write_timeout=self.timeout.write,
            on_close=opened.release, profile=self.impersonate,
        )
        try:
            await asyncio.wait_for(conn.start(), self.timeout.connect)
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
    async def _h1_read_body(reader, method: str, status: int, headers: Headers,
                            first: bytes, read_to: Optional[float]) -> bytes:
        """HTTP/1.1 gövdesi (RFC 9112 §6.3). Eksik gövde ConnectionResetError'dır."""
        async def more() -> bytes:
            return await asyncio.wait_for(reader.read(4096), timeout=read_to)

        if method.upper() == "HEAD" or status in (204, 304) or 100 <= status < 200:
            return b""          # gövde YOK: bağlantıdan veri beklenmez

        buf = bytearray(first)
        if "chunked" in headers.get("transfer-encoding", "").lower():
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
                    return bytes(out)       # trailer'lar yok sayılır
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

        cl = headers.get("content-length", "").strip()
        if cl.isdigit():
            n = int(cl)
            while len(buf) < n:
                c = await more()
                if not c:
                    raise ConnectionResetError(
                        f"Yanıt gövdesi eksik: {len(buf)}/{n} bayt alındı.")
                buf.extend(c)
            return bytes(buf[:n])

        while True:                          # bağlantı kapanana kadar (HTTP/1.0)
            try:
                c = await asyncio.wait_for(reader.read(4096), timeout=2.0)
            except (ConnectionResetError, asyncio.TimeoutError):
                break
            if not c:
                break
            buf.extend(c)
        return bytes(buf)

    async def _h1_exchange(self, opened: "_Opened", method: str, u: URL,
                           req_headers: dict, raw_body: bytes, metrics):
        """Tek bağlantıda tek HTTP/1.1 isteği; bağlantı sonunda kapatılır."""
        reader, writer = opened.reader, opened.writer
        read_to = self.timeout.read
        try:
            req_line = f"{method} {u.raw_path.decode()} HTTP/1.1\r\n"
            for k, v in req_headers.items():
                req_line += f"{k}: {v}\r\n"
            req_line += "\r\n"
            raw_request = req_line.encode("ascii") + (raw_body or b"")
            if metrics:
                metrics.bytes_sent = len(raw_request)

            writer.write(raw_request)
            await asyncio.wait_for(writer.drain(), self.timeout.write)
            send_time = time.monotonic()

            hdr_acc = bytearray()
            sep     = -1
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=read_to)
                if not chunk: break
                if not hdr_acc and metrics:
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

            body_raw = await self._h1_read_body(reader, method, status_code, resp_headers,
                                                first_body_chunk, read_to)

            return status_code, resp_headers, bytes(body_raw), send_time, "HTTP/1.1"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError as e:  # ssl kapanış hataları dahil
                logger.debug("wait_closed hatası yok sayıldı: %s", e)
            opened.release()

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

        req_headers = {
            "Host":            u.host,
            "Connection":      "keep-alive",
            "Accept-Encoding": HTTP1Parser.supported_encodings(),
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
        }
        req_headers.update(req_dict.get("headers", {}))
        if self.cookies:
            req_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())

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

            for cs in resp_headers.get_list("set-cookie"):
                main = cs.split(";")[0].strip()
                if "=" in main:
                    k, v = main.split("=", 1)
                    self.cookies[k.strip()] = v.strip()

            resp = Response(status_code=status_code, headers=resp_headers, body=body_final)
            resp.http_version = http_version

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
                e2 = await plugin.on_error(e)
                if e2 is None:
                    return Response(0, body=b"")
            raise

                                                                                
    # --- Faz 5 kancaları: transport + retry -------------------------------

    async def _send(self, method, url, headers=None, body=b"", metrics=None) -> Response:
        """Tek isteği transport'a (verilmişse) ya da ağa gönderir."""
        if self.transport is None:
            return await self._raw_request(method, url, headers=headers, body=body,
                                           metrics=metrics)
        req_dict = await self._run_request_hooks(
            {"method": method, "url": url, "headers": headers or {}, "body": body}
        )
        h = dict(req_dict.get("headers") or {})
        if self.cookies and not any(k.lower() == "cookie" for k in h):
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        req = Request(method=req_dict["method"], url=req_dict["url"], headers=h,
                      data=req_dict.get("body") or None)
        if "host" not in req.headers:
            req.headers["Host"] = req.url.host
        resp = await self.transport.handle_async_request(req)
        for cs in resp.headers.get_list("set-cookie"):
            main = cs.split(";")[0].strip()
            if "=" in main:
                k, v = main.split("=", 1)
                self.cookies[k.strip()] = v.strip()
        return await self._run_response_hooks(resp)

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

    async def request(
        self,
        method:          str,
        url:             str,
        data:            Any  = None,
        json:            Any  = None,
        headers:         Optional[dict] = None,
        allow_redirects: bool = True,
    ) -> Response:
        import json as jsonlib

        body    = b""
        h       = dict(headers or {})

        if json is not None:
            body = jsonlib.dumps(json).encode("utf-8")
            h.setdefault("Content-Type", "application/json")
        elif isinstance(data, dict):
            from urllib.parse import urlencode
            body = urlencode(data).encode("ascii")
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(data, (bytes, bytearray)):
            body = bytes(data)

        metrics       = RequestMetrics(request_start=time.monotonic())
        current_url   = url
        redirect_cnt  = 0
        history       = []

        retry_plugins = [p for p in self._plugins if isinstance(p, RetryPlugin)]

        while True:
            attempt = 0
            while True:
                resp = await self._send_with_retries(
                    method, current_url, headers=h, body=body, metrics=metrics
                )
                retrying = False
                for plugin in retry_plugins:
                    if plugin.should_retry(resp, attempt):
                        delay = plugin.delay_for(resp, attempt)
                        logger.debug("HTTP %s alındı, %.2fs sonra tekrar denenecek",
                                     resp.status_code, delay)
                        if delay:
                            await asyncio.sleep(delay)
                        retrying = True
                        break
                if not retrying:
                    break
                attempt += 1

            if history:
                resp.history = list(history)

            if not allow_redirects or resp.status_code not in (301, 302, 303, 307, 308):
                return resp

            if redirect_cnt >= self.max_redirects:
                raise ConnectionError("Max redirect aşıldı")

            location = resp.headers.get("location", "")
            if not location:
                return resp

            history.append(resp)
            metrics.redirect_count += 1

            base = URL(current_url)
            location = _resolve_location(base, location)

            new = URL(location)
            if (new.scheme, new.host, new.port) != base.origin:
                # Farklı origin'e giderken kimlik bilgisi taşınmaz
                h = {k: v for k, v in h.items()
                     if k.lower() not in ("authorization", "cookie", "proxy-authorization")}

            current_url = location
            if resp.status_code in (301, 302, 303):
                method = "GET"
                body = b""
                h = {k: v for k, v in h.items()
                     if k.lower() not in ("content-type", "content-length")}

            redirect_cnt += 1

                                                                                

    async def get(self, url: str, headers: Optional[dict] = None, allow_redirects: bool = True) -> Response:
        return await self.request("GET", url, headers=headers, allow_redirects=allow_redirects)

    async def post(self, url: str, data=None, json=None, headers: Optional[dict] = None) -> Response:
        return await self.request("POST", url, data=data, json=json, headers=headers)

    async def put(self, url: str, data=None, json=None, headers: Optional[dict] = None) -> Response:
        return await self.request("PUT", url, data=data, json=json, headers=headers)

    async def patch(self, url: str, data=None, json=None, headers: Optional[dict] = None) -> Response:
        return await self.request("PATCH", url, data=data, json=json, headers=headers)

    async def delete(self, url: str, headers: Optional[dict] = None) -> Response:
        return await self.request("DELETE", url, headers=headers)

    async def head(self, url: str, headers: Optional[dict] = None) -> Response:
        return await self.request("HEAD", url, headers=headers, allow_redirects=False)

                                                                               

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

                                                                                

    async def close(self) -> None:
        conns, self._h2 = list(self._h2.values()), {}
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
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
    """asyncio tabanlı WebSocket bağlantısı."""

    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer
        self._buf    = b""

    @classmethod
    async def connect(cls, url: str, session: AsyncSession) -> "AsyncWebSocket":
        import base64, hashlib, os
        u   = URL(url)
        key = base64.b64encode(os.urandom(16)).decode()

        ctx = ssl.create_default_context(cafile=session._ca_path)
        reader, writer = await asyncio.open_connection(u.host, u.port, ssl=ctx)

        req = (
            f"GET {u.raw_path.decode()} HTTP/1.1\r\n"
            f"Host: {u.host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        writer.write(req.encode())
        await writer.drain()

        resp = b""
        while b"\r\n\r\n" not in resp:
            resp += await reader.read(4096)

        if b"101" not in resp:
            raise ConnectionError("WebSocket Upgrade başarısız")

        return cls(reader, writer)

    async def send_text(self, text: str) -> None:
        from .protocol.http2_parser import WebSocketFrame
        frame = WebSocketFrame(WebSocketFrame.OP_TEXT, text.encode())
        self._writer.write(frame.serialize())
        await self._writer.drain()

    async def recv_text(self) -> str:
        from .protocol.http2_parser import WebSocketFrame
        while True:
            frame, consumed = WebSocketFrame.parse(self._buf)
            if frame:
                self._buf = self._buf[consumed:]
                if frame.opcode == WebSocketFrame.OP_PING:
                    pong = WebSocketFrame(WebSocketFrame.OP_PONG, frame.payload)
                    self._writer.write(pong.serialize())
                    await self._writer.drain()
                    continue
                return frame.payload.decode("utf-8", errors="replace")
            chunk = await self._reader.read(4096)
            if not chunk:
                return ""
            self._buf += chunk

    async def close(self) -> None:
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
