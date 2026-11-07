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
from typing import Any, Callable, Optional, AsyncGenerator
from .models.urls     import URL
from .models.headers  import Headers
from .models.response import Response, HTTPStatusError
from .metrics         import RequestMetrics
from .cache           import ResponseCache
from .protocol.http1_parser import HTTP1Parser
from .models.request  import Request
from .config          import resolve_verify
from .retry           import Retry


                                                                               
                                  
                                                                               

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
        timeout:         float = 30.0,
        max_redirects:   int   = 10,
        max_connections: int   = 100,                                     
        cache:           "bool | ResponseCache" = False,
        cache_ttl:       float = 300.0,
        verify:          "bool | str" = True,
        retries:         "int | Retry | None" = None,
        transport                     = None,
    ):
        # DÜRÜSTLÜK NOTU: AsyncSession, sync Session'ın özel TLS yığınını
        # KULLANMAZ. asyncio.open_connection stdlib ssl bağlamıyla çalışır,
        # yani ClientHello Python/OpenSSL parmak izini taşır — Chrome'unkini
        # değil. Sessizce yok saymak yerine açıkça uyarıyoruz.
        if impersonate is not None:
            warnings.warn(
                "AsyncSession şu anda TLS impersonation DESTEKLEMİYOR: bağlantı "
                "stdlib ssl ile kurulur ve ClientHello Python/OpenSSL parmak izi "
                "taşır. Parmak izi gerekiyorsa senkron Session kullanın. Bu uyarıyı "
                "susturmak için impersonate=None geçin.",
                UserWarning,
                stacklevel=2,
            )
        self.impersonate   = impersonate
        self.timeout       = timeout
        self.verify        = verify
        self._ca_path      = resolve_verify(verify)   # None → varsayılan güven deposu
        self.retries       = Retry.from_value(retries)
        self.transport     = transport
        self.max_redirects = max_redirects
        self.cookies:  dict[str, str] = {}
        self._plugins: list[Plugin]   = []
        self._rotator: Optional[ProxyRotator] = None
        self._sem     = asyncio.Semaphore(max_connections)

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
        """Proxy listesini ayarla ve rotasyonu etkinleştir."""
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
                    timeout=self.timeout,
                )
                writer.close()
                await writer.wait_closed()
                return host, True
            except Exception:
                return host, False

        tasks = [_warm_one(h) for h in hosts for _ in range(count)]
        for coro in asyncio.as_completed(tasks):
            host, ok = await coro
            results[host] = results.get(host, 0) + (1 if ok else 0)

        return results

                                                                               

    async def _raw_request(
        self,
        method:  str,
        url:     str,
        headers: Optional[dict]  = None,
        body:    bytes           = b"",
        metrics: Optional[RequestMetrics] = None,
    ) -> Response:
        """Tek async HTTP/1.1 isteği."""
        u = URL(url) if isinstance(url, str) else url

                        
        proxy = self._rotator.next() if self._rotator else None

                      
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

                   
        req_line = f"{method} {u.raw_path.decode()} HTTP/1.1\r\n"
        for k, v in req_headers.items():
            req_line += f"{k}: {v}\r\n"
        req_line += "\r\n"
        raw_request = req_line.encode("ascii") + (raw_body or b"")

        if metrics:
            metrics.request_start = time.monotonic()
            metrics.bytes_sent    = len(raw_request)

                        
        ctx = ssl.create_default_context(cafile=self._ca_path)
        ctx.set_alpn_protocols(["http/1.1"])

        connect_host = u.host
        connect_port = u.port

        async with self._sem:
            try:
                if metrics: metrics.connect_start = time.monotonic()

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(connect_host, connect_port, ssl=ctx),
                    timeout=self.timeout,
                )

                if metrics:
                    metrics.connect_end = time.monotonic()
                    metrics.tls_end     = time.monotonic()

                writer.write(raw_request)
                await writer.drain()
                send_time = time.monotonic()

                            
                hdr_buf = b""
                while b"\r\n\r\n" not in hdr_buf:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                    if not chunk: break
                    if not hdr_buf and metrics:
                        metrics.first_byte_time = time.monotonic()
                    hdr_buf += chunk

                sep              = hdr_buf.find(b"\r\n\r\n")
                headers_raw      = hdr_buf[:sep]
                first_body_chunk = hdr_buf[sep + 4:]

                                  
                lines = headers_raw.split(b"\r\n")
                status_code = 0
                try:
                    status_code = int(lines[0].decode("ascii", errors="ignore").split(" ", 2)[1])
                except Exception:
                    pass

                resp_headers = Headers()
                for line in lines[1:]:
                    if b":" not in line: continue
                    k, _, v = line.partition(b":")
                    resp_headers._list.append((k.strip(), k.strip().lower(), v.strip()))

                      
                is_chunked    = "chunked" in resp_headers.get("transfer-encoding", "").lower()
                cl_str        = resp_headers.get("content-length", "")
                content_length = int(cl_str.strip()) if cl_str else None

                body_raw = bytearray(first_body_chunk)

                if is_chunked:
                    pos = 0
                    while True:
                        while b"\r\n" not in bytes(body_raw[pos:]):
                            c = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                            if not c: break
                            body_raw.extend(c)
                        nl = bytes(body_raw).find(b"\r\n", pos)
                        if nl == -1: break
                        sz = int(bytes(body_raw[pos:nl]).split(b";")[0].strip(), 16)
                        if sz == 0: break
                        pos = nl + 2
                        end = pos + sz
                        while len(body_raw) < end + 2:
                            c = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                            if not c: break
                            body_raw.extend(c)
                        pos = end + 2
                            
                    decoded = bytearray()
                    p2 = 0
                    raw_b = bytes(body_raw)
                    while p2 < len(raw_b):
                        nl2 = raw_b.find(b"\r\n", p2)
                        if nl2 == -1: break
                        try: sz2 = int(raw_b[p2:nl2].split(b";")[0].strip(), 16)
                        except: break
                        if sz2 == 0: break
                        p2 = nl2 + 2
                        decoded.extend(raw_b[p2:p2 + sz2])
                        p2 += sz2 + 2
                    body_raw = decoded

                elif content_length is not None:
                    while len(body_raw) < content_length:
                        c = await asyncio.wait_for(reader.read(min(4096, content_length - len(body_raw))), timeout=self.timeout)
                        if not c: break
                        body_raw.extend(c)
                    body_raw = body_raw[:content_length]

                else:
                    while True:
                        try:
                            c = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                            if not c: break
                            body_raw.extend(c)
                        except asyncio.TimeoutError:
                            break

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

                if metrics:
                    resp.metrics = metrics                              

                     
                if status_code == 304 and cache_entry:
                    resp = cache_entry.response

                             
                if self._cache and method.upper() == "GET":
                    self._cache.store(url, method, resp)

                                     
                if proxy and self._rotator and metrics and metrics.first_byte_time:
                    ttfb = (metrics.first_byte_time - send_time) * 1000
                    self._rotator.update_perf(proxy, ttfb)

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                              
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
        except Exception:
            pass

    async def __aenter__(self): return self
    async def __aexit__(self, *a): await self.close()
