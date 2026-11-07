"""
fasthttpc Session — FAZ 1 + FAZ 2 + düzeltmeler

Düzeltmeler:
  - TEST 6: session'da header parse artık Headers sınıfı kullanıyor
    (content-length/chunked tespiti güvenilir hale getirildi)
  - Chunked body toplama: partial marker sorununu önlemek için
    byte-level search yerine state-machine yaklaşımı
  - _read_body_stream() yardımcı metodu ile body okuma merkezileştirildi
  - Timeout objesi desteği eklendi (connect/read ayrı)
  - Multipart/form-data encoder entegre edildi
  - response.elapsed otomatik doldurulur
"""
from __future__ import annotations
import time
from typing import Union

from .models.urls     import URL
from .models.headers  import Headers
from .models.request  import Request
from .models.response import Response, HTTPStatusError
from .transport.connection_pool import ConnectionPool
from .security.tls_adapter      import TLSAdapter
from .protocol.http1_parser     import HTTP1Parser
from .protocol.http2_parser     import Http2Connection, Http2StreamError, Http2ConnectionError
from .metrics    import RequestMetrics
from .cache      import ResponseCache
from .buffer     import AdaptiveReceiver, get_pool
from .timeout    import Timeout
from .multipart  import encode_multipart
from .cookies    import CookieJar
from ._log       import get_logger

logger = get_logger("session")


def _resolve_location(base: URL, location: str) -> str:
    """Redirect ``Location`` başlığını mutlak URL'ye çevirir (RFC 9110 §10.2.2).

    Mutlak, protokol-göreli (``//host/yol``), kökten (``/yol``) ve göreli
    (``yol``) biçimlerin hepsini destekler.
    """
    location = location.strip()
    if location.startswith(("http://", "https://")):
        return location
    if location.startswith("//"):
        return f"{base.scheme}:{location}"

    default_port = 443 if base.scheme == "https" else 80
    netloc = base.host if base.port == default_port else f"{base.host}:{base.port}"
    origin = f"{base.scheme}://{netloc}"

    if location.startswith("/"):
        return origin + location

    base_dir = base.path.rsplit("/", 1)[0]
    return f"{origin}{base_dir}/{location}"


class Session:
    """
    fasthttpc senkron HTTP istemcisi.

    Args:
        impersonate:     TLS fingerprint profili. ``"chrome_131"``, ``"firefox_120"``, ``"safari_17"``
        max_connections: Connection pool boyutu.
        timeout:         Zaman aşımı — float (saniye) veya :class:`Timeout` objesi.
        max_redirects:   Maksimum redirect sayısı.
        cache:           ``True`` → yerleşik cache, ``ResponseCache`` objesi → özel cache.
        cache_ttl:       Yerleşik cache için varsayılan TTL (saniye).
        resolver:        Opsiyonel :class:`~fasthttpc.protocol.dns_over_https.DoHResolver`.
                         Verilirse host adları DNS-over-HTTPS ile çözülür.

    Örnek::

        with Session(impersonate="chrome_131", timeout=Timeout(connect=5, read=30)) as s:
            r = s.get("https://example.com")
            print(r.status_code, r.elapsed)
    """

    def __init__(
        self,
        impersonate:     str                          = "chrome_131",
        max_connections: int                          = 10,
        timeout:         Union[float, int, Timeout]   = 30.0,
        max_redirects:   int                          = 10,
        cache:           "bool | ResponseCache"       = False,
        cache_ttl:       float                        = 300.0,
        resolver                                      = None,
    ):
        self.impersonate   = impersonate
        self.timeout       = Timeout.from_value(timeout)
        self.max_redirects = max_redirects
        self.pool          = ConnectionPool(
            max_connections=max_connections,
            timeout=self.timeout.connect_timeout,
            resolver=resolver,
        )
        self.cookie_jar = CookieJar()

        if isinstance(cache, ResponseCache):
            self._cache: ResponseCache | None = cache
        elif cache:
            self._cache = ResponseCache(default_ttl=cache_ttl)
        else:
            self._cache = None

        self._receiver = AdaptiveReceiver()
        self._pool     = get_pool()

                                                                               

    # RFC 7540 §8.1.2.2 — bu header'lar HTTP/2'de yasaktır, gönderilirse
    # sunucu genellikle stream'i PROTOCOL_ERROR ile RST_STREAM eder.
    _H2_FORBIDDEN_HEADERS = frozenset({
        "connection", "keep-alive", "proxy-connection",
        "transfer-encoding", "upgrade",
    })

    def _send_h2_request(self, conn, req, metrics, cache_entry, method, url) -> Response:
        """HTTP/2 üzerinden tek bir isteği gönderir ve Response nesnesi döner."""
        # HTTP header değerleri RFC 7230 gereği ISO-8859-1 (latin-1) alfabesindedir;
        # ascii decode, Türkçe/aksanlı karakter içeren Accept-Language, Cookie vb.
        # değerlerde UnicodeDecodeError fırlatır. latin-1 hiçbir byte için başarısız olmaz.
        h2_headers = [(k.decode("latin-1").lower(), v.decode("latin-1")) for k, v in req.headers.raw]
        # HTTP/1.1'e özgü Host header'ı h2'de :authority pseudo-header'ı olarak zaten gidiyor.
        # Connection-specific header'lar da RFC 7540 gereği tamamen yasak.
        h2_headers = [
            (k, v) for k, v in h2_headers
            if k != "host" and k not in self._H2_FORBIDDEN_HEADERS
        ]

        if metrics:
            metrics.bytes_sent = len(req.body) + sum(len(k) + len(v) for k, v in h2_headers)

        try:
            status_code, resp_header_pairs, body_raw = conn.h2_conn.request(
                method=req.method,
                authority=req.url.host,
                path=req.url.raw_path.decode("latin-1"),
                headers=h2_headers,
                body=req.body,
            )
        except (Http2StreamError, Http2ConnectionError) as e:
            raise ConnectionError(f"HTTP/2 isteği başarısız: {e}") from e

        if metrics:
            metrics.first_byte_time = time.monotonic()
            metrics.transfer_end    = time.monotonic()
            metrics.bytes_received  = len(body_raw)

        resp_headers = Headers()
        for k, v in resp_header_pairs:
            resp_headers[k] = v

        ce = resp_headers.get("content-encoding", "").lower()
        body_raw = HTTP1Parser._decompress(body_raw, ce)

        resp         = Response(status_code=status_code, headers=resp_headers, body=body_raw)
        resp.request = req
        if metrics:
            metrics.total_end = time.monotonic()
            resp.metrics = metrics

        self._update_cookies(resp_headers, req.url)

        if self._cache and method.upper() == "GET":
            self._cache.store(str(url), method, resp)

        return resp

    def _read_app_data(self, conn) -> bytes:
        """Sadece Application Data döner; post-handshake handshake mesajları
        (NewSessionTicket vb.) TLS katmanında yutulur."""
        while True:
            msg, m_type = conn.socket.recv_record(skip_post_handshake=True)
            if m_type == 23:
                return msg
            elif m_type == 21:
                if msg == b"\x01\x00":  # close_notify
                    return b""
                raise ConnectionError(f"Şifreli Alert: {msg.hex()}")
            # m_type == 22 buraya artık gelmez (skip_post_handshake yuttu)

                                                                              

    def _collect_body(
        self,
        conn,
        first_body_chunk: bytes,
        headers: Headers,
        metrics: RequestMetrics | None = None,
    ) -> bytes:
        """
        Headers parse edildikten sonra body'yi güvenilir biçimde toplar.
        
        Chunked: proper chunk state-machine (TLS record boundary sorununu çözer)
        Content-Length: tam miktar okunana kadar devam et
        Bilinmiyor: bağlantı kapanana kadar oku (HTTP/1.0 compat)
        """
        te = headers.get("transfer-encoding", "").lower()
        is_chunked = "chunked" in te

        cl_str = headers.get("content-length", "")
        content_length: int | None = None
        if cl_str:
            try:
                content_length = int(cl_str.strip())
            except ValueError:
                pass

                                                                              
        if is_chunked:
            return self._collect_chunked(conn, first_body_chunk)

                                                                               
        if content_length is not None:
            body = bytearray(first_body_chunk)
            while len(body) < content_length:
                chunk = self._read_app_data(conn)
                if not chunk:
                    break
                body.extend(chunk)
            return bytes(body[:content_length])

                                                                              
        body = bytearray(first_body_chunk)
        while True:
            chunk = self._read_app_data(conn)
            if not chunk:
                break
            body.extend(chunk)
        return bytes(body)

    def _collect_chunked(self, conn, first_chunk: bytes) -> bytes:
        """
        Proper chunked state-machine.
        TLS record sınırlarından bağımsız çalışır:
        Yeterli veri olmadığında recv_record() ile daha fazla alır.
        """
        buf    = bytearray(first_chunk)
        result = bytearray()
        pos    = 0

        while True:
                                                                           
            while True:
                nl = buf.find(b"\r\n", pos)
                if nl != -1:
                    break
                                     
                more = self._read_app_data(conn)
                if not more:
                    return bytes(result)                    
                buf.extend(more)

            size_line = bytes(buf[pos:nl]).split(b";")[0].strip()
            pos = nl + 2             

            try:
                chunk_size = int(size_line, 16)
            except ValueError:
                break

            if chunk_size == 0:
                break                  

                                                                           
            end = pos + chunk_size
            while len(buf) < end + 2:                      
                more = self._read_app_data(conn)
                if not more:
                                                    
                    result.extend(buf[pos:])
                    return bytes(result)
                buf.extend(more)

            result.extend(buf[pos:end])
            pos = end + 2                      

        return bytes(result)

                                                                               

    def _raw_request(
        self,
        method:  str,
        url:     "str | URL",
        data     = None,
        json     = None,
        headers  = None,
        files    = None,
        metrics: RequestMetrics | None = None,
    ) -> Response:
        """
        Ham HTTP isteği gönderir. Redirect, cache, retry döngüsü bu metodun üzerinde yönetilir.

        Args:
            method:  HTTP metodu (GET, POST, vb.)
            url:     Hedef URL (string veya URL objesi)
            data:    Form verisi (dict veya bytes)
            json:    JSON gövdesi (dict)
            headers: Ek başlıklar
            files:   Dosya yükleme — multipart/form-data olarak encode edilir
            metrics: İstek metrikleri objesi
        """
                                         
        extra_headers: dict = {}
        if files is not None:
            mp_body, mp_ct = encode_multipart(
                fields=data if isinstance(data, dict) else None,
                files=files,
            )
            data = mp_body
            extra_headers["Content-Type"] = mp_ct
            files = None

        req = Request(method=method, url=url, data=data, json=json,
                      headers=headers, files=files)
        for k, v in extra_headers.items():
            req.headers[k] = v

                               
        if "host"       not in req.headers: req.headers["Host"]       = req.url.host
        if "connection" not in req.headers: req.headers["Connection"] = "keep-alive"
        if "accept-encoding" not in req.headers:
            req.headers["Accept-Encoding"] = "gzip, deflate"
        if "user-agent" not in req.headers:
            req.headers["User-Agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            )
        # Çerezler yalnızca domain/path/Secure kurallarına uyanlar arasından
        # seçilir; redirect başka bir host'a giderse oraya gönderilmez.
        cookie_header = self.cookie_jar.header_for(
            host=req.url.host, path=req.url.path, secure=(req.url.scheme == "https")
        )
        if cookie_header:
            req.headers["Cookie"] = cookie_header

                        
        cache_entry = None
        if self._cache and method.upper() == "GET":
            url_str = str(url)
            cache_entry = self._cache.get(url_str, method)
            if cache_entry:
                cond = self._cache.build_conditional_headers(cache_entry)
                for k, v in cond.items():
                    req.headers[k] = v

        retry_count = 0
        while retry_count < 2:
            if metrics:
                metrics.connect_start = time.monotonic()

            conn = None
            is_new_conn = False
            try:
                conn = self.pool.acquire(req.url)
                is_new_conn = not conn.tls_established
                logger.debug("conn id=%s yeni=%s tls=%s h2=%s",
                             id(conn), is_new_conn, conn.tls_established,
                             conn.h2_conn is not None)

                if metrics:
                    metrics.connection_reused = not is_new_conn
                    metrics.connect_end       = time.monotonic()

                     
                if is_new_conn:
                    if metrics: metrics.tls_start = time.monotonic()
                    logger.debug("%s profili ile TLS el sıkışması başlıyor (%s)",
                                 self.impersonate, req.url.host)
                    conn.socket = TLSAdapter.negotiate(
                        conn.socket, req.url.host, self.impersonate
                    )
                    conn.socket.raw_socket.settimeout(self.timeout.read_timeout)
                    conn.tls_established = True
                    if metrics: metrics.tls_end = time.monotonic()
                    alpn = conn.socket.state.get("alpn", "")
                    if alpn == "h2":
                        logger.debug("TLS 1.3 kuruldu (ALPN: h2)")
                        conn.h2_conn = Http2Connection(conn.socket)
                        conn.h2_conn.send_preface_and_settings()
                    else:
                        logger.debug("TLS 1.3 kuruldu (ALPN: http/1.1)")

                if conn.h2_conn is not None:
                    resp = self._send_h2_request(conn, req, metrics, cache_entry, method, url)
                    self.pool.release(conn)
                    if metrics and metrics.request_start:
                        resp.elapsed = time.monotonic() - metrics.request_start
                    return resp

                                 
                req_lines = [f"{req.method} {req.url.raw_path.decode('ascii')} HTTP/1.1"]
                for k, v in req.headers.raw:
                    req_lines.append(f"{k.decode('ascii')}: {v.decode('ascii')}")
                raw_bytes = "\r\n".join(req_lines).encode("ascii") + b"\r\n\r\n" + req.body

                if metrics: metrics.bytes_sent = len(raw_bytes)

                conn.socket.send_record(raw_bytes)
                send_time = time.monotonic()

                                                                            
                header_buf  = b""
                first_byte  = True
                while b"\r\n\r\n" not in header_buf:
                    chunk = self._read_app_data(conn)
                    if not chunk:
                        break
                    if first_byte and metrics:
                        metrics.first_byte_time = time.monotonic()
                        first_byte = False
                    header_buf += chunk

                if not header_buf:
                    raise ConnectionResetError("Sunucu yanıt vermeden bağlantıyı kesti.")

                sep              = header_buf.find(b"\r\n\r\n")
                headers_raw      = header_buf[:sep]
                first_body_chunk = header_buf[sep + 4:]

                                                                              
                resp_headers = Headers()
                lines        = headers_raw.split(b"\r\n")
                for line in lines[1:]:
                    if b":" not in line:
                        continue
                    k, _, v = line.partition(b":")
                    try:
                        k_str = k.strip().decode("latin-1")
                        v_str = v.strip().decode("latin-1")
                        resp_headers.add(k_str, v_str)
                    except (UnicodeDecodeError, ValueError) as e:
                        logger.debug("Geçersiz yanıt header'ı atlandı %r: %s", line[:80], e)

                             
                status_code = 0
                try:
                    parts = lines[0].decode("ascii", errors="ignore").split(" ", 2)
                    if len(parts) >= 2:
                        status_code = int(parts[1])
                except (ValueError, IndexError):
                    pass

                                                                           
                                                                    
                if req.method.upper() == "HEAD":
                    body_raw = b""
                else:
                    body_raw = self._collect_body(conn, first_body_chunk, resp_headers, metrics)

                if metrics:
                    metrics.transfer_end   = time.monotonic()
                    metrics.bytes_received = len(headers_raw) + 4 + len(body_raw)
                    if metrics.first_byte_time:
                        ttfb_ms = (metrics.first_byte_time - send_time) * 1000
                        conn.update_ttfb(ttfb_ms)

                                                                           
                ce       = resp_headers.get("content-encoding", "").lower()
                body_raw = HTTP1Parser._decompress(body_raw, ce)

                resp         = Response(status_code=status_code, headers=resp_headers, body=body_raw)
                resp.request = req

                if metrics:
                    metrics.total_end = time.monotonic()
                    resp.metrics = metrics                              

                self._update_cookies(resp_headers, req.url)

                                     
                if status_code == 304 and cache_entry:
                    cached          = cache_entry.response
                    cached.request  = req
                    if metrics: cached.metrics = metrics                              
                    self.pool.release(conn)
                    return cached

                             
                if self._cache and method.upper() == "GET":
                    self._cache.store(str(url), method, resp)

                if "close" in resp_headers.get("connection", "").lower():
                    conn.close()
                else:
                    self.pool.release(conn)

                if metrics and metrics.request_start:
                    resp.elapsed = time.monotonic() - metrics.request_start
                return resp

            except (ConnectionResetError, ConnectionError, TimeoutError, OSError) as e:
                # conn döngü başında None'a çekiliyor: acquire() patlarsa bir
                # ÖNCEKİ turdan kalan bayat bağlantıyı ikinci kez release edip
                # semaphore sayacını bozmuyoruz.
                if conn is not None:
                    conn.close()
                    self.pool.release(conn)  # close() semaphore'a dokunmaz
                    conn = None
                    if not is_new_conn:
                        # Yeniden kullanılan bağlantı sunucu tarafında kapanmış
                        # olabilir; bu idempotent olmayan istekler için de
                        # güvenlidir çünkü sunucu isteği hiç görmemiştir.
                        retry_count += 1
                        logger.debug("Bayat bağlantı, yeniden deneniyor (%s)", e)
                        continue
                raise
            except BaseException:
                # Beklenmeyen hata (encoding, parsing, KeyboardInterrupt vb.) — bağlantıyı havuzda
                # yarım bırakmamak için kapatıp semaphore'u serbest bırak.
                if conn is not None:
                    conn.close()
                    self.pool.release(conn)
                    conn = None
                raise

        raise ConnectionError("Tüm bağlantı denemeleri başarısız oldu.")

                                                                                

    def request(
        self,
        method:          str,
        url:             "str | URL",
        data             = None,
        json             = None,
        headers          = None,
        files            = None,
        allow_redirects: bool = True,
    ) -> Response:
        current_url    = url
        redirect_count = 0
        history: list[Response] = []
        metrics = RequestMetrics(request_start=time.monotonic())

        while True:
            resp = self._raw_request(
                method, current_url,
                data=data, json=json, headers=headers, files=files,
                metrics=metrics,
            )
            if history:
                resp.history = list(history)

            if not allow_redirects or resp.status_code not in (301, 302, 303, 307, 308):
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

            # Farklı bir origin'e gidiyorsak kullanıcı Authorization/Cookie
            # başlıklarını elle vermişse bunları TAŞIMAYIZ; aksi hâlde kimlik
            # bilgisi üçüncü bir siteye sızar.
            new_url = URL(current_url)
            if (new_url.scheme, new_url.host, new_url.port) != base.origin and headers:
                headers = {
                    k: v for k, v in dict(headers).items()
                    if k.lower() not in ("authorization", "cookie", "proxy-authorization")
                }

            if resp.status_code in (301, 302, 303):
                method = "GET"
                data   = None
                json   = None
                files  = None

            redirect_count += 1
            logger.debug("Yönlendirme (%s) -> %s", resp.status_code, current_url)

                                                                                

    def get(self, url, headers=None, allow_redirects=True) -> Response:
        return self.request("GET", url, headers=headers, allow_redirects=allow_redirects)

    def websocket(self, url: str):
        """
        WebSocket bağlantısı açar (RFC 6455 HTTP Upgrade handshake).
        'ws://' ve 'wss://' şemalarını destekler; 'wss://' TLS fingerprint
        taklidini (chrome_131 vb.) kullanır.

        Context manager olarak kullanılabilir:
            with session.websocket("wss://example.com/socket") as ws:
                ws.send_text("merhaba")
                opcode, payload = ws.recv()
        """
        from .protocol.http2_parser import WebSocketConnection
        return WebSocketConnection.handshake(self, url)

    def post(self, url, data=None, json=None, headers=None, files=None, allow_redirects=True) -> Response:
        return self.request("POST", url, data=data, json=json, headers=headers,
                            files=files, allow_redirects=allow_redirects)

    def put(self, url, data=None, json=None, headers=None, files=None, allow_redirects=True) -> Response:
        return self.request("PUT", url, data=data, json=json, headers=headers,
                            files=files, allow_redirects=allow_redirects)

    def patch(self, url, data=None, json=None, headers=None, allow_redirects=True) -> Response:
        return self.request("PATCH", url, data=data, json=json, headers=headers,
                            allow_redirects=allow_redirects)

    def delete(self, url, headers=None, allow_redirects=True) -> Response:
        return self.request("DELETE", url, headers=headers, allow_redirects=allow_redirects)

    def head(self, url, headers=None) -> Response:
        return self.request("HEAD", url, headers=headers, allow_redirects=False)

                                                                                

    def pre_warm(self, hosts: list[str], count: int = 2) -> dict[str, int]:
        return self.pool.prewarm(
            hosts, count=count,
            tls_negotiate_fn=TLSAdapter.negotiate,
            impersonate=self.impersonate,
        )

    def pool_stats(self) -> dict:
        return self.pool.stats()

                                                                                

    @property
    def cookies(self) -> dict[str, str]:
        """Geriye dönük uyumluluk için isim->değer sözlüğü (salt okunur görünüm)."""
        return self.cookie_jar.as_dict()

    def _update_cookies(self, response_headers: Headers, url: URL) -> None:
        self.cookie_jar.update_from_headers(
            response_headers.get_list("set-cookie"),
            request_host=url.host,
            request_path=url.path,
        )

                                                                                

    def close(self) -> None:
        self.pool.close_all()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
