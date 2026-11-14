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
import functools
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
from .config     import Limits, resolve_verify
from .retry      import Retry
from .multipart  import encode_multipart
from .cookies    import CookieJar
from .fingerprint import drop_h2_only_defaults, merge_default_headers, order_h1
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


def _proxy_spec(proxy, proxies):
    """proxy= (tek URL) ve proxies= (sözlük) parametrelerini birleştirir/doğrular."""
    if proxy is not None and proxies is not None:
        raise ValueError("proxy= ve proxies= birlikte verilemez.")
    spec = proxy if proxy is not None else proxies
    from .transport.proxy import resolve_proxy
    for scheme in ("https", "http"):
        resolve_proxy(spec, scheme)  # hatalı URL'i erken (Session kurulurken) yakala
    return spec


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
        verify:          ``True`` (varsayılan; certifi + sistem CA'ları) veya özel CA
                         bundle'ının PEM dosya yolu. ``False`` DESTEKLENMEZ (ValueError).
        retries:         ``int`` veya :class:`~fasthttpc.retry.Retry`. Varsayılan: kapalı.
        transport:       Opsiyonel transport (ör. :class:`~fasthttpc.transport.mock.MockTransport`);
                         verilirse istekler ağ yerine buna gönderilir.
        limits:          Opsiyonel :class:`~fasthttpc.config.Limits`; verilirse
                         ``max_connections`` parametresini geçersiz kılar.
        headers:         Oturum düzeyi varsayılan başlıklar (``s.headers`` ile
                         değiştirilebilir). Öncelik: profilin tarayıcı
                         başlıkları < ``headers`` < istek başlıkları; değeri
                         ``None`` olan başlık varsayılanı kaldırır.

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
        verify:          "bool | str"                 = True,
        retries:         "int | Retry | None"         = None,
        transport                                     = None,
        limits:          "Limits | None"              = None,
        proxies                                       = None,
        proxy                                         = None,
        headers                                       = None,
    ):
        self.impersonate   = impersonate
        # Oturum düzeyi varsayılan başlıklar (requests gibi mutable): profilin
        # tarayıcı başlıklarını geçersiz kılar, istek başlıkları bunları.
        self.headers       = Headers(headers)
        self._rotator      = None
        self.timeout       = Timeout.from_value(timeout)
        self.max_redirects = max_redirects
        self.verify        = verify
        self._ca_path      = resolve_verify(verify)
        self.retries       = Retry.from_value(retries)
        self.transport     = transport
        self.limits        = limits if limits is not None else Limits(max_connections=max_connections)
        self.pool          = ConnectionPool(
            max_connections=self.limits.max_connections,
            timeout=self.timeout.connect_timeout,
            resolver=resolver,
            proxy=_proxy_spec(proxy, proxies),
        )
        self.limits.apply_to_pool(self.pool)
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

        host = req.url.host
        if ":" in host:
            host = f"[{host}]"
        default_port = 443 if req.url.scheme == "https" else 80
        authority = host if req.url.port == default_port else f"{host}:{req.url.port}"

        try:
            status_code, resp_header_pairs, body_raw = conn.h2_conn.request(
                method=req.method,
                authority=authority,
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
            resp_headers.add(k, v)

        ce = resp_headers.get("content-encoding", "").lower()
        body_raw = HTTP1Parser._decompress(body_raw, ce)

        resp         = Response(status_code=status_code, headers=resp_headers, body=body_raw)
        resp.request = req
        resp.http_version = "HTTP/2"
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
        dl = conn.conn_data.get("deadline")
        while True:
            if dl is not None:
                kalan = dl - time.monotonic()
                if kalan <= 0:
                    raise TimeoutError("İstek toplam süre sınırını (Timeout.total) aştı.")
                conn.socket.raw_socket.settimeout(min(self.timeout.read_timeout, kalan))
            msg, m_type = conn.socket.recv_record(skip_post_handshake=True)
            if m_type == 23:
                return msg
            elif m_type == 21:
                if msg == b"\x01\x00":  # close_notify
                    return b""
                raise ConnectionError(f"Şifreli Alert: {msg.hex()}")
            # m_type == 22 buraya artık gelmez (skip_post_handshake yuttu)

                                                                              

    @staticmethod
    def _body_framing(method: str, status_code: int, headers: Headers) -> str:
        """Yanıt gövdesinin çerçevelenme biçimi (RFC 9112 §6.3).

        ``"none"`` (HEAD, 1xx, 204, 304: gövde YOK, bağlantıdan veri beklenmez),
        ``"chunked"``, ``"length"`` ya da ``"eof"`` (bağlantı kapanana kadar).
        """
        if method.upper() == "HEAD" or status_code in (204, 304) or 100 <= status_code < 200:
            return "none"
        if "chunked" in headers.get("transfer-encoding", "").lower():
            return "chunked"
        cl = headers.get("content-length", "").strip()
        if cl.isdigit():
            return "length"
        return "eof"

    def _collect_body(
        self,
        conn,
        first_body_chunk: bytes,
        headers: Headers,
        metrics: RequestMetrics | None = None,
        framing: str | None = None,
    ) -> bytes:
        """
        Headers parse edildikten sonra body'yi güvenilir biçimde toplar.

        Chunked: proper chunk state-machine (TLS record boundary sorununu çözer)
        Content-Length: tam miktar okunana kadar devam et; eksik gelirse
        ``ConnectionResetError`` (sessizce kısaltılmış gövde DÖNMEZ).
        Bilinmiyor: bağlantı kapanana kadar oku (HTTP/1.0 uyumu). Bu modda
        close_notify'sız TCP kapanışı normal sayılır (çoğu HTTP/1.0 sunucusu
        TLS'i düzgün kapatmaz; tarayıcılar/curl da böyle davranır).
        """
        if framing is None:
            framing = self._body_framing("GET", 200, headers)
        if framing == "none":
            return b""
        if framing == "chunked":
            return self._collect_chunked(conn, first_body_chunk)

        if framing == "length":
            content_length = int(headers.get("content-length", "").strip())
            body = bytearray(first_body_chunk)
            while len(body) < content_length:
                chunk = self._read_app_data(conn)
                if not chunk:
                    raise ConnectionResetError(
                        f"Yanıt gövdesi eksik: {len(body)}/{content_length} bayt alındı."
                    )
                body.extend(chunk)
            return bytes(body[:content_length])

        body = bytearray(first_body_chunk)
        while True:
            try:
                chunk = self._read_app_data(conn)
            except ConnectionResetError:
                break  # close_notify'sız EOF: bağlantı-kapanışlı gövdenin sonu
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
                    raise ConnectionResetError("Chunked gövde yarıda kesildi.")
                buf.extend(more)

            size_line = bytes(buf[pos:nl]).split(b";")[0].strip()
            pos = nl + 2             

            try:
                chunk_size = int(size_line, 16)
            except ValueError:
                raise ConnectionError(f"Geçersiz chunk boyutu: {size_line[:20]!r}") from None

            if chunk_size == 0:
                # Trailer satırlarını ve kapanış boş satırını TÜKET; aksi hâlde
                # artan baytlar keep-alive bağlantıda bir sonraki yanıtı bozar.
                while True:
                    nl = buf.find(b"\r\n", pos)
                    while nl == -1:
                        more = self._read_app_data(conn)
                        if not more:
                            raise ConnectionResetError("Chunked gövde yarıda kesildi.")
                        buf.extend(more)
                        nl = buf.find(b"\r\n", pos)
                    bos = nl == pos
                    pos = nl + 2
                    if bos:
                        break
                break

                                                                           
            end = pos + chunk_size
            while len(buf) < end + 2:                      
                more = self._read_app_data(conn)
                if not more:
                    raise ConnectionResetError("Chunked gövde yarıda kesildi.")
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

        # Profilin tarayıcı başlıkları (User-Agent, Accept-Encoding, sec-ch-ua...)
        # + kullanıcı başlıkları; kullanıcınınki varsayılanı geçersiz kılar.
        req = Request(method=method, url=url, data=data, json=json,
                      headers=merge_default_headers(self.impersonate, headers or {}),
                      files=files)
        for k, v in extra_headers.items():
            req.headers[k] = v

                               
        if "host"       not in req.headers: req.headers["Host"]       = req.url.host
        if "connection" not in req.headers: req.headers["Connection"] = "keep-alive"
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
            rot_proxy = None
            is_new_conn = False
            got_bytes = False
            try:
                rot_proxy = self._rotator.next() if self._rotator is not None else None
                acq = {"proxy": rot_proxy} if rot_proxy is not None else {}
                conn = self.pool.acquire(req.url, timeout=self.timeout.pool, **acq)
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
                        conn.socket, req.url.host, self.impersonate,
                        ca_path=self._ca_path,
                    )
                    conn.socket.raw_socket.settimeout(self.timeout.read_timeout)
                    conn.tls_established = True
                    if metrics: metrics.tls_end = time.monotonic()
                    alpn = conn.socket.state.get("alpn", "")
                    if alpn == "h2":
                        logger.debug("TLS 1.3 kuruldu (ALPN: h2)")
                        conn.h2_conn = Http2Connection(conn.socket, profile=self.impersonate)
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
                h1_pairs = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in req.headers.raw]
                h1_pairs = order_h1(self.impersonate,
                                    drop_h2_only_defaults(self.impersonate, h1_pairs))
                for k, v in h1_pairs:
                    req_lines.append(f"{k}: {v}")
                raw_bytes = "\r\n".join(req_lines).encode("ascii") + b"\r\n\r\n" + req.body

                if metrics: metrics.bytes_sent = len(raw_bytes)

                total = self.timeout.total
                if total is not None:
                    conn.conn_data["deadline"] = time.monotonic() + total
                conn.socket.send_record(raw_bytes)
                send_time = time.monotonic()

                                                                            
                # bytearray + kaldığı yerden arama: header'lar çok record'a bölünse
                # bile birleştirme/arama doğrusal kalır.
                header_acc  = bytearray()
                got_bytes   = False   # yanıttan en az 1 bayt geldi mi (yeniden deneme güvenliği)
                first_byte  = True
                sep         = -1
                while True:
                    chunk = self._read_app_data(conn)
                    if not chunk:
                        break
                    got_bytes = True
                    if first_byte and metrics:
                        metrics.first_byte_time = time.monotonic()
                        first_byte = False
                    search_from = max(0, len(header_acc) - 3)
                    header_acc += chunk
                    sep = header_acc.find(b"\r\n\r\n", search_from)
                    if sep != -1:
                        break
                header_buf = bytes(header_acc)

                if not header_buf:
                    raise ConnectionResetError("Sunucu yanıt vermeden bağlantıyı kesti.")

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

                                                                           
                                                                    
                framing  = self._body_framing(req.method, status_code, resp_headers)
                body_raw = self._collect_body(conn, first_body_chunk, resp_headers, metrics, framing)
                if conn.conn_data.pop("deadline", None) is not None:
                    conn.socket.raw_socket.settimeout(self.timeout.read_timeout)

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

                conn_hdr = resp_headers.get("connection", "").lower()
                http10   = lines[0].upper().startswith(b"HTTP/1.0")
                if ("close" in conn_hdr or framing == "eof"
                        or (http10 and "keep-alive" not in conn_hdr)):
                    # Yeniden kullanılamaz: kapat VE havuza iade et. release()
                    # kapalı bağlantıyı havuza koymaz ama semaphore slotunu
                    # geri verir; atlanırsa max_connections kadar "close"
                    # yanıtından sonra havuz kalıcı kilitlenir.
                    conn.close()
                    self.pool.release(conn)
                else:
                    self.pool.release(conn)

                if metrics and metrics.request_start:
                    resp.elapsed = time.monotonic() - metrics.request_start
                return resp

            except (ConnectionResetError, ConnectionError, TimeoutError, OSError) as e:
                # conn döngü başında None'a çekiliyor: acquire() patlarsa bir
                # ÖNCEKİ turdan kalan bayat bağlantıyı ikinci kez release edip
                # semaphore sayacını bozmuyoruz.
                if (conn is None and rot_proxy is not None
                        and not isinstance(e, TimeoutError)):
                    self._rotator.mark_failed(rot_proxy)   # proxy'ye bağlanılamadı
                if conn is not None:
                    conn.close()
                    self.pool.release(conn)  # close() semaphore'a dokunmaz
                    conn = None
                    if (not is_new_conn and not got_bytes
                            and not isinstance(e, TimeoutError)):
                        # Yeniden kullanılan bağlantı sunucu tarafında kapanmış
                        # olabilir; yanıttan HİÇ bayt gelmediyse ve hata zaman aşımı
                        # değilse yeniden denemek güvenlidir. Zaman aşımı (sunucu
                        # isteği işliyor olabilir) ya da yarım yanıt YENİDEN
                        # DENENMEZ: POST çift gönderilir, bekleme süresi katlanır.
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

                                                                                

    # --- Faz 5 kancaları: transport + retry -------------------------------

    def _send(self, method, url, data=None, json=None, headers=None, files=None,
              metrics: RequestMetrics | None = None) -> Response:
        """Tek bir isteği gönderir: transport verilmişse ona, yoksa ağa."""
        if self.transport is None:
            return self._raw_request(method, url, data=data, json=json,
                                     headers=headers, files=files, metrics=metrics)
        req = Request(method=method, url=url, data=data, json=json,
                      headers={k: v for k, v in dict(headers or {}).items() if v is not None},
                      files=files)
        if "host" not in req.headers:
            req.headers["Host"] = req.url.host
        cookie_header = self.cookie_jar.header_for(
            host=req.url.host, path=req.url.path, secure=(req.url.scheme == "https")
        )
        if cookie_header and "cookie" not in req.headers:
            req.headers["Cookie"] = cookie_header
        resp = self.transport.handle_request(req)
        self._update_cookies(resp.headers, req.url)
        if metrics and metrics.request_start:
            resp.elapsed = time.monotonic() - metrics.request_start
        return resp

    def _send_with_retries(self, method, url, **kwargs) -> Response:
        """``self.retries`` politikasına göre ``_send``'i tekrarlar."""
        retry = self.retries
        attempt = 0
        while True:
            try:
                resp = self._send(method, url, **kwargs)
            except Exception as e:
                if not retry.should_retry_error(method, e, attempt):
                    raise
                attempt += 1
                delay = retry.get_delay(attempt)
                logger.debug("Ağ hatası (%s), %d. yeniden deneme %.2fs sonra", e, attempt, delay)
            else:
                if not retry.should_retry_status(method, resp.status_code, attempt):
                    return resp
                attempt += 1
                delay = retry.get_delay(attempt, resp)
                logger.debug("HTTP %s, %d. yeniden deneme %.2fs sonra",
                             resp.status_code, attempt, delay)
            if delay:
                time.sleep(delay)

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
        headers = self._merged_headers(headers)

        while True:
            resp = self._send_with_retries(
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

    def options(self, url, headers=None, allow_redirects=True) -> Response:
        return self.request("OPTIONS", url, headers=headers, allow_redirects=allow_redirects)

                                                                                

    def pre_warm(self, hosts: list[str], count: int = 2) -> dict[str, int]:
        return self.pool.prewarm(
            hosts, count=count,
            tls_negotiate_fn=functools.partial(TLSAdapter.negotiate, ca_path=self._ca_path),
            impersonate=self.impersonate,
        )

    def pool_stats(self) -> dict:
        return self.pool.stats()

    def set_proxies(self, proxies: list[str], strategy: str = "round_robin") -> "Session":
        """Proxy listesini ayarla ve rotasyonu etkinleştir (``AsyncSession`` ile aynı).

        Rotasyon etkinken her istek için sıradaki proxy (``proxy=``/``proxies=``
        yerine) kullanılır; bağlantılar proxy başına ayrı havuzlanır. Bağlantı
        kurulamayan proxy devre dışı bırakılır.
        """
        from .async_session import ProxyRotator
        from .transport.proxy import parse_proxy_url
        for url in proxies:
            parse_proxy_url(url)   # hatalı URL'i erken yakala
        self._rotator = ProxyRotator(proxies, strategy=strategy)
        return self

                                                                                

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
        if self.transport is not None:
            self.transport.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
