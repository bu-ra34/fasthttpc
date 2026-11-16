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
import os
import time
from typing import (TYPE_CHECKING, Any, Generator, Iterable, Optional, TypedDict,
                    Union)

from .models.urls     import URL
from .models.headers  import Headers, check_header_field, check_request_line
from .models.request  import Request
from .models.response import Response, HTTPStatusError
from .transport.connection_pool import ConnectionPool
from .security.tls_adapter      import TLSAdapter
from .security.alerts          import describe_alert
from .protocol.http1_parser     import HTTP1Parser, MAX_RESPONSE_HEADER_BYTES, parse_chunk_size
from .protocol.http2_parser     import (Http2Connection, Http2StreamError, Http2ConnectionError,
                                         Http2RefusedError)
from .metrics    import RequestMetrics
from .cache      import ResponseCache
from .buffer     import AdaptiveReceiver, get_pool
from .timeout    import Timeout
from .config     import Limits, resolve_verify
from .security.client_cert import ClientCert
from .retry      import Retry
from .multipart  import encode_multipart
from .cookies    import CookieJar
from .fingerprint import drop_h2_only_defaults, merge_default_headers, order_h1
from ._log       import get_logger
from . import _api
from ._api       import (USE_CLIENT_DEFAULT, AuthArg, CookiesArg, HeaderDict, HeadersArg,
                          ParamsArg, TimeoutArg)
from .auth       import resolve_auth, netrc_credentials, BasicAuth
from .plugins    import Plugin, RetryPlugin, call_sync

if TYPE_CHECKING:
    from .async_session import ProxyRotator
    from .auth import Auth
    from .cache import CacheEntry
    from .http3.manager import SyncHttp3
    from .protocol.dns_over_https import DoHResolver
    from .protocol.http2_parser import H2ClientStream, WebSocketConnection
    from .transport.connection_pool import HTTPConnection
    from .transport.mock import BaseTransport
    from .transport.proxy import ProxySpec

logger = get_logger("session")

_BodyGen = Generator[bytes, None, None]


# Yalnızca gerektiğinde geçirilen isteğe bağlı anahtar kelime argümanları (varsayılan
# çağrılar bit bit aynı kalsın diye): ``**`` ile açılınca mypy anahtarları tek tek denetler.
class _AcquireKw(TypedDict, total=False):
    proxy: str
    connect_timeout: Optional[float]


class _LegacyKw(TypedDict, total=False):
    legacy_tls: bool


class _CertKw(TypedDict, total=False):
    client_cert: ClientCert


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


def _proxy_spec(proxy: "ProxySpec", proxies: "ProxySpec") -> "ProxySpec":
    """proxy= (tek URL) ve proxies= (sözlük) parametrelerini birleştirir/doğrular."""
    if proxy is not None and proxies is not None:
        raise ValueError("proxy= ve proxies= birlikte verilemez.")
    spec = proxy if proxy is not None else proxies
    from .transport.proxy import resolve_proxy
    for scheme in ("https", "http"):
        resolve_proxy(spec, scheme)  # hatalı URL'i erken (Session kurulurken) yakala
    return spec



_DISCARD_LIMIT = 65536


def _discard_stream(resp: Response) -> None:
    """Yönlendirme yanıtının gövdesini (küçükse) tüketir ki h1 bağlantısı havuza
    dönsün; büyükse/hata olursa yanıt kapatılır."""
    try:
        n = 0
        for c in resp.iter_raw():
            n += len(c)
            if n > _DISCARD_LIMIT:
                break
    except Exception as e:  # noqa: BLE001 - yönlendirme gövdesi önemsiz
        logger.debug("yönlendirme gövdesi okunamadı: %s", e)
    resp.close()


class _StreamContext:
    """``Session.stream(...)`` dönüşü: ``with`` bloğunda Response verir, çıkışta kapatır."""

    def __init__(self, session: "Session", method: str, url: "str | URL",
                 kwargs: "dict[str, Any]"):
        self._args = (session, method, url, kwargs)
        self._resp: Optional[Response] = None

    def __enter__(self) -> Response:
        session, method, url, kwargs = self._args
        self._resp = resp = session.request(method, url, stream=True, **kwargs)
        return resp

    def __exit__(self, *exc: object) -> None:
        if self._resp is not None:
            self._resp.close()


class _H1BodyStream:
    """HTTP/1.1 akış gövdesi: bağlantının sahibi. Gövde bitince bağlantı (yeniden
    kullanılabilirse) havuza döner; erken ``close()``/hata -> bağlantı kapatılır."""

    def __init__(self, session: "Session", conn: "HTTPConnection", gen: "_BodyGen",
                 reusable: bool, metrics: "RequestMetrics | None", header_bytes: int = 0):
        self._s, self._conn, self._gen = session, conn, gen
        self._reusable, self._metrics = reusable, metrics
        self._received = header_bytes
        self._done = False

    def read_chunk(self) -> bytes:
        if self._done:
            return b""
        try:
            chunk: bytes = next(self._gen)
        except StopIteration:
            self._finish(self._reusable)
            return b""
        except BaseException:
            self._finish(False)
            raise
        self._received += len(chunk)
        return chunk

    def _finish(self, reuse: bool) -> None:
        if self._done:
            return
        self._done = True
        conn = self._conn
        m = self._metrics
        if m:
            m.transfer_end = m.total_end = time.perf_counter()
            m.bytes_received = self._received
        if not reuse:
            conn.close()
        self._s.pool.release(conn)    # kapalı bağlantıyı havuza koymaz, slotu iade eder

    def close(self) -> None:
        self._gen.close()
        self._finish(False)

    def __del__(self) -> None:
        try:
            if not self._done:
                self.close()
        except Exception:  # noqa: BLE001 - yorumlayıcı kapanışı
            pass


class _H2BodyStream:
    """HTTP/2 akış gövdesi. Bitince bağlantı havuza döner (GOAWAY varsa kapatılır);
    erken ``close()`` stream'i RST_STREAM(CANCEL) ile iptal eder, bağlantı yaşar."""

    def __init__(self, session: "Session", conn: "HTTPConnection", h2_stream: "H2ClientStream",
                 metrics: "RequestMetrics | None"):
        self._s, self._conn, self._st = session, conn, h2_stream
        self._metrics, self._received = metrics, 0
        self._done = False

    def read_chunk(self) -> bytes:
        if self._done:
            return b""
        try:
            chunk: bytes = self._st.read_chunk()
        except BaseException as e:
            self._finish()
            if isinstance(e, (Http2StreamError, Http2ConnectionError)):
                raise ConnectionError(f"HTTP/2 isteği başarısız: {e}") from e
            raise
        if not chunk:
            self._finish()
            return b""
        self._received += len(chunk)
        return chunk

    def _finish(self) -> None:
        if self._done:
            return
        self._done = True
        conn, st = self._conn, self._st
        m = self._metrics
        if m:
            m.transfer_end = m.total_end = time.perf_counter()
            m.bytes_received = self._received
        if st.broken or (conn.h2_conn is not None and conn.h2_conn.goaway is not None):
            conn.close()
        self._s.pool.release(conn)

    def close(self) -> None:
        if self._done:
            return
        self._st.close()          # bitmediyse CANCEL; kilidi bırakır
        self._finish()

    def __del__(self) -> None:
        try:
            if not self._done:
                self.close()
        except Exception:  # noqa: BLE001
            pass
def _no_await(out: Any) -> Any:
    """Senkron oturumda hook coroutine döndürürse açık bir hata ver."""
    import inspect
    if inspect.isawaitable(out):
        if hasattr(out, "close"):
            out.close()
        raise TypeError("Hook coroutine döndürdü; senkron Session yalnızca düz fonksiyon "
                        "hook'larını destekler (async hook için AsyncSession kullanın).")
    return out


class _H2Refused(ConnectionError):
    """HTTP/2 isteği sunucu tarafından İŞLENMEDİ (GOAWAY); güvenle yeniden denenebilir."""

class Session:
    """
    fasthttpc senkron HTTP istemcisi.

    Args:
        impersonate:     TLS fingerprint profili: ``"chrome_158"`` (varsayılan), ``"firefox_160"``,
                         ``"safari_27"``, eski ``"chrome_131"``/``"firefox_133"``/``"safari_18"``
                         (takma adlar: ``"chrome"``, ``"firefox"``, ``"safari"`` güncel sürüme;
                         ``"firefox_120"``, ``"safari_17"``) ya da ``None`` (tarayıcı taklidi yok).
        max_connections: Origin başına en fazla bağlantı (``limits`` verilmezse).
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
        auth:            Oturum düzeyi kimlik: ``("kullanici", "parola")`` (Basic),
                         :class:`~fasthttpc.auth.BasicAuth` / ``DigestAuth`` /
                         ``BearerAuth`` ya da özel (requests ``__call__`` veya httpx
                         ``auth_flow``). ``s.auth`` ile değiştirilebilir.
        hooks:           requests tarzı ``{"response": [fn, ...]}``; ``fn(response, **kw)``
                         yeni Response döndürebilir.
        event_hooks:     httpx tarzı ``{"request": [fn], "response": [fn]}``.
        trust_env:       ``True`` iken ``.netrc`` (``NETRC`` env dahil) kimliği kullanılır.
        params:          Her isteğe eklenen varsayılan sorgu parametreleri.
        cert:            İstemci sertifikası (mTLS), YALNIZCA oturum düzeyinde: ``"client.pem"``
                         (sertifika+anahtar), ``("cert.pem", "key.pem")``, ``("cert.pem", "key.pem",
                         "parola")`` veya ``ClientCert.from_pkcs12(yol, parola)``. Bağlantı havuzu ve
                         TLS bilet önbelleği anahtarına sertifika kimliği girer.
        headers:         Oturum düzeyi varsayılan başlıklar (``s.headers`` ile
                         değiştirilebilir). Öncelik: profilin tarayıcı
                         başlıkları < ``headers`` < istek başlıkları; değeri
                         ``None`` olan başlık varsayılanı kaldırır.
        proxy / proxies: ``"http://..."`` / ``"socks5://..."`` ya da şema sözlüğü
                         (``{"https": ...}``). Ortam değişkenleri okunmaz.
        http3:           DENEYSEL, varsayılan ``False``. ``True`` (Alt-Svc keşfi, h2'ye
                         düşüş), ``"force"`` ya da ``fasthttpc.http3.Http3Options``.
                         ``fasthttpc[http3]`` (aioquic) gerektirir.
        legacy_tls:      ``True`` -> TLS 1.2 CBC / statik RSA eski sunucu modu
                         (varsayılan ``False``; TLS 1.0/1.1 hiçbir zaman).

    Örnek::

        with Session(impersonate="chrome_131", timeout=Timeout(connect=5, read=30)) as s:
            r = s.get("https://example.com")
            print(r.status_code, r.elapsed)
    """

    def __init__(
        self,
        impersonate:     str                          = "chrome_158",
        max_connections: int                          = 10,
        timeout:         Union[float, int, Timeout]   = 30.0,
        max_redirects:   int                          = 10,
        cache:           "bool | ResponseCache"       = False,
        cache_ttl:       float                        = 300.0,
        resolver:        "DoHResolver | None"         = None,
        verify:          "bool | str"                 = True,
        retries:         "int | Retry | None"         = None,
        transport:       "BaseTransport | None"       = None,
        limits:          "Limits | None"              = None,
        proxies:         "ProxySpec"                  = None,
        proxy:           "ProxySpec"                  = None,
        headers:         HeadersArg                   = None,
        http3:           "bool | str | object"        = False,
        legacy_tls:      bool                         = False,
        auth:            AuthArg                      = None,
        hooks:           "dict[str, Any] | None"      = None,
        event_hooks:     "dict[str, Any] | None"      = None,
        trust_env:       bool                         = True,
        params:          ParamsArg                    = None,
        *,
        cert:            "ClientCert | str | os.PathLike[str] | tuple[Any, ...] | None" = None,
    ) -> None:
        # Eski sunucu uyumluluk modu: YALNIZCA açıkça True verilirse TLS 1.2 CBC/statik RSA/EMS'siz
        # sunucular kabul edilir (sertifika doğrulaması ve DOWNGRD kontrolü AYNEN sürer).
        # Bkz. security/tls12_legacy.py ve README "Legacy TLS".
        from .security.tls12_legacy import normalize_legacy
        self.legacy_tls    = normalize_legacy(legacy_tls)
        self.impersonate   = impersonate
        # requests/httpx uyumu: oturum düzeyi kimlik, hook'lar ve varsayılan params.
        self.auth          = auth
        self.hooks         = _api.normalize_hooks(hooks)
        self.event_hooks   = _api.normalize_event_hooks(event_hooks)
        self.trust_env     = trust_env
        self.params        = params
        self._plugins: list[Plugin] = []
        # mTLS (oturum düzeyi): cert= yol | (cert, key) | (cert, key, parola) | ClientCert.
        # Yükleme hatası burada (kurucuda) ClientCertError(ValueError) olarak yükselir.
        self.client_cert   = ClientCert.coerce(cert)
        self._owns_cert    = self.client_cert is not None and not isinstance(cert, ClientCert)
        # Oturum düzeyi varsayılan başlıklar (requests gibi mutable): profilin
        # tarayıcı başlıklarını geçersiz kılar, istek başlıkları bunları.
        self.headers       = Headers(headers)
        self.resolver      = resolver      # opsiyonel DoHResolver (AsyncSession ile aynı ad)
        self._rotator: "ProxyRotator | None" = None
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
            tls_scope=self.client_cert.identity if self.client_cert is not None else None,
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
        # HTTP/3 (opsiyonel, aioquic): True -> Alt-Svc keşfi + h2'ye düşüş, "force" -> doğrudan h3.
        self._h3: "SyncHttp3 | None" = None
        self._has_proxy = bool(_proxy_spec(proxy, proxies))
        from .http3.options import Http3Options
        _h3opts = Http3Options.from_value(http3)
        if _h3opts is not None and self.client_cert is not None:
            # HTTP/3 yolu istemci sertifikası (mTLS) göndermez: cert= varken h3 KULLANILMAZ
            # (aksi halde istek sertifikasız bir QUIC bağlantısıyla gidebilirdi).
            if _h3opts.mode == "force":
                raise ValueError("http3='force' ile cert= (mTLS) birlikte kullanılamaz.")
            _h3opts = None
        if _h3opts is not None:
            from .http3.manager import SyncHttp3
            self._h3 = SyncHttp3(_h3opts, self._ca_path, impersonate)

                                                                               

    # RFC 7540 §8.1.2.2 — bu header'lar HTTP/2'de yasaktır, gönderilirse
    # sunucu genellikle stream'i PROTOCOL_ERROR ile RST_STREAM eder.
    _H2_FORBIDDEN_HEADERS = frozenset({
        "connection", "keep-alive", "proxy-connection",
        "transfer-encoding", "upgrade",
    })

    def _legacy_kw(self) -> _LegacyKw:
        """legacy_tls kapalıyken HİÇ kwarg geçirilmez (varsayılan çağrılar bit bit aynı kalır)."""
        return {"legacy_tls": True} if self.legacy_tls else {}

    def _cert_kw(self) -> _CertKw:
        """İstemci sertifikası yalnızca verilmişse geçirilir."""
        return {"client_cert": self.client_cert} if self.client_cert is not None else {}

    @staticmethod
    def _tls_info(conn: "HTTPConnection") -> "dict[str, Any] | None":
        from .security.tls12_legacy import tls_info
        sock = getattr(conn, "socket", None)
        state = getattr(sock, "state", None)
        return tls_info(state) if isinstance(state, dict) else None

    def _send_h2_request(self, conn: "HTTPConnection", req: Request,
                         metrics: "RequestMetrics | None", cache_entry: "CacheEntry | None",
                         method: str, url: "str | URL", stream: bool = False) -> Response:
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

        h2 = conn.h2_conn
        assert h2 is not None    # çağıran yalnızca ALPN h2 bağlantısında çağırır
        h2_stream = None
        try:
            if stream:
                h2_stream = h2.request_stream(
                    method=req.method, authority=authority,
                    path=req.url.raw_path.decode("latin-1"),
                    headers=h2_headers, body=req.body,
                )
                status_code, resp_header_pairs, body_raw = (
                    h2_stream.status, list(h2_stream.headers), b"")
            else:
                status_code, resp_header_pairs, body_raw = h2.request(
                    method=req.method,
                    authority=authority,
                    path=req.url.raw_path.decode("latin-1"),
                    headers=h2_headers,
                    body=req.body,
                )
        except Http2RefusedError as e:
            raise _H2Refused(f"HTTP/2 isteği işlenmedi: {e}") from e
        except (Http2StreamError, Http2ConnectionError) as e:
            raise ConnectionError(f"HTTP/2 isteği başarısız: {e}") from e

        if metrics:
            metrics.first_byte_time = time.perf_counter()
            metrics.transfer_end    = time.perf_counter()
            metrics.bytes_received  = len(body_raw)

        resp_headers = Headers()
        for k, v in resp_header_pairs:
            resp_headers.add(k, v)

        if h2_stream is not None:
            resp = Response(status_code=status_code, headers=resp_headers,
                            stream=_H2BodyStream(self, conn, h2_stream, metrics))
            resp.request = req
            resp.http_version = "HTTP/2"
            if metrics:
                resp.metrics = metrics
            self._update_cookies(resp_headers, req.url)
            return resp

        ce = resp_headers.get("content-encoding", "").lower()
        body_raw = HTTP1Parser._decompress(body_raw, ce)

        resp         = Response(status_code=status_code, headers=resp_headers, body=body_raw)
        resp.request = req
        resp.http_version = "HTTP/2"
        resp.tls_info = self._tls_info(conn)
        if metrics:
            metrics.total_end = time.perf_counter()
            resp.metrics = metrics

        self._update_cookies(resp_headers, req.url)

        if self._cache and method.upper() == "GET":
            self._cache.store(str(url), method, resp)

        return resp

    def _h3_attempt(self, req: Request, metrics: "RequestMetrics | None",
                    cache_entry: "CacheEntry | None", method: str,
                    url: "str | URL") -> "Response | None":
        """HTTP/3 denemesi: Response ya da None (h2/h1'e düş). Ayrıntı: fasthttpc.http3."""
        h3 = self._h3
        assert h3 is not None    # yalnızca http3= etkinken çağrılır
        if self._has_proxy or self._rotator is not None:
            # UDP bir HTTP proxy'sinden geçemez.
            if h3.state.force:
                raise ConnectionError("http3='force' bir HTTP proxy ile kullanılamaz (UDP).")
            return None
        t = self.timeout
        timeout = t.total if t.total is not None else t.read_timeout
        h3_headers = [(k.decode("latin-1").lower(), v.decode("latin-1")) for k, v in req.headers.raw]
        h3_headers = [(k, v) for k, v in h3_headers
                      if k != "host" and k not in self._H2_FORBIDDEN_HEADERS]
        if metrics:
            metrics.bytes_sent = len(req.body) + sum(len(k) + len(v) for k, v in h3_headers)
        r = h3.exchange(req.url.host, req.url.port, method,
                              req.url.raw_path.decode("latin-1"), h3_headers, req.body, timeout)
        if r is None:
            return None
        status_code: int
        resp_headers: Headers
        body: bytes
        status_code, resp_headers, body = r
        resp = Response(status_code=status_code, headers=resp_headers, body=body)
        resp.request = req
        resp.http_version = "HTTP/3"
        if metrics:
            metrics.first_byte_time = metrics.transfer_end = metrics.total_end = time.perf_counter()
            metrics.bytes_received = len(body)
            resp.metrics = metrics
            if metrics.request_start:
                resp.elapsed = time.perf_counter() - metrics.request_start
        self._update_cookies(resp_headers, req.url)
        if status_code == 304 and cache_entry:
            cached = cache_entry.response
            cached.request = req
            if metrics:
                cached.metrics = metrics
            return cached
        if self._cache and method.upper() == "GET":
            self._cache.store(str(url), method, resp)
        return resp

    def _read_app_data(self, conn: "HTTPConnection") -> bytes:
        """Sadece Application Data döner; post-handshake handshake mesajları
        (NewSessionTicket vb.) TLS katmanında yutulur."""
        dl = conn.conn_data.get("deadline")
        while True:
            if dl is not None:
                kalan = dl - time.perf_counter()
                if kalan <= 0:
                    raise TimeoutError("İstek toplam süre sınırını (Timeout.total) aştı.")
                conn.socket.raw_socket.settimeout(min(self._tmo().read_timeout, kalan))
            rec: "tuple[bytes, int]" = conn.socket.recv_record(skip_post_handshake=True)
            msg, m_type = rec
            if m_type == 23:
                return msg
            elif m_type == 21:
                if msg == b"\x01\x00":  # close_notify
                    return b""
                raise ConnectionError(f"Sunucudan şifreli TLS alert: {describe_alert(bytes(msg))}")
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
        conn: "HTTPConnection",
        first_body_chunk: bytes,
        headers: Headers,
        metrics: RequestMetrics | None = None,
        framing: str | None = None,
    ) -> bytes:
        """Gövdeyi tamamen toplar (bkz. :meth:`_iter_body`)."""
        return b"".join(self._iter_body(conn, first_body_chunk, headers, framing))

    def _iter_body(self, conn: "HTTPConnection", first_body_chunk: bytes, headers: Headers,
                   framing: str | None = None) -> _BodyGen:
        """
        Headers parse edildikten sonra body'yi PARÇA PARÇA üretir (boş parça yok).

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
            return
        if framing == "chunked":
            yield from self._iter_chunked(conn, first_body_chunk)
            return

        if framing == "length":
            content_length = int(headers.get("content-length", "").strip())
            remaining = content_length
            chunk = first_body_chunk
            while True:
                if chunk:
                    piece = chunk[:remaining]
                    remaining -= len(piece)
                    if piece:
                        yield bytes(piece)
                if remaining <= 0:
                    return
                chunk = self._read_app_data(conn)
                if not chunk:
                    raise ConnectionResetError(
                        f"Yanıt gövdesi eksik: {content_length - remaining}/{content_length} bayt alındı."
                    )

        if first_body_chunk:
            yield bytes(first_body_chunk)
        while True:
            try:
                chunk = self._read_app_data(conn)
            except ConnectionResetError:
                return  # close_notify'sız EOF: bağlantı-kapanışlı gövdenin sonu
            if not chunk:
                return
            yield chunk

    def _iter_chunked(self, conn: "HTTPConnection", first_chunk: bytes) -> _BodyGen:
        """
        Proper chunked state-machine (üreteç).
        TLS record sınırlarından bağımsız çalışır: yeterli veri olmadığında
        recv_record() ile daha fazla alır. Bellek: en çok bir chunk + bir record.
        """
        buf = bytearray(first_chunk)

        def fill() -> None:
            more = self._read_app_data(conn)
            if not more:
                raise ConnectionResetError("Chunked gövde yarıda kesildi.")
            buf.extend(more)

        while True:
            nl = buf.find(b"\r\n")
            while nl == -1:
                fill()
                nl = buf.find(b"\r\n")
            size_line = bytes(buf[:nl])
            del buf[:nl + 2]
            try:
                chunk_size = parse_chunk_size(size_line)
            except ValueError:
                raise ConnectionError(f"Geçersiz chunk boyutu: {size_line[:20]!r}") from None

            if chunk_size == 0:
                # Trailer satırlarını ve kapanış boş satırını TÜKET; aksi hâlde
                # artan baytlar keep-alive bağlantıda bir sonraki yanıtı bozar.
                while True:
                    nl = buf.find(b"\r\n")
                    while nl == -1:
                        fill()
                        nl = buf.find(b"\r\n")
                    bos = nl == 0
                    del buf[:nl + 2]
                    if bos:
                        return

            remaining = chunk_size
            while remaining > 0:
                if not buf:
                    fill()
                take = min(remaining, len(buf))
                yield bytes(buf[:take])
                del buf[:take]
                remaining -= take
            while len(buf) < 2:       # chunk sonu CRLF
                fill()
            if buf[:2] != b"\r\n":
                raise ConnectionError("Chunked gövde bozuk: chunk verisinden sonra CRLF yok.")
            del buf[:2]

                                                                               

    def _raw_request(
        self,
        method:  str,
        url:     "str | URL",
        data:    Any      = None,
        json:    Any      = None,
        headers: HeadersArg = None,
        files:   "dict[str, Any] | None" = None,
        metrics: RequestMetrics | None = None,
        stream:  bool = False,
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
            stream:  True ise gövde OKUNMADAN döner (bkz. ``Response.iter_*``)
        """
                                         
        extra_headers: dict[str, str] = {}
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

        # Telde yazılmadan (bağlantı açılmadan) ÖNCE: CR/LF/NUL içeren başlık ya da
        # bozuk metot/hedef, HTTP/1.1'de istek enjeksiyonuna yol açar (h2/h3'te malformed).
        check_request_line(req.method, req.url.raw_path.decode("latin-1"))
        for raw_k, raw_v in req.headers.raw:
            check_header_field(raw_k, raw_v)

        if self._h3 is not None:
            h3_resp = self._h3_attempt(req, metrics, cache_entry, method, url)
            if h3_resp is not None:
                return h3_resp

        retry_count = 0
        while retry_count < 2:
            if metrics:
                metrics.connect_start = time.perf_counter()

            conn: "HTTPConnection | None" = None
            rot_proxy = None
            is_new_conn = False
            got_bytes = False
            try:
                rot_proxy = self._rotator.next() if self._rotator is not None else None
                acq: _AcquireKw = {"proxy": rot_proxy} if rot_proxy is not None else {}
                if self._tmo() is not self.timeout:    # istek düzeyi timeout=
                    acq["connect_timeout"] = self._tmo().connect_timeout
                conn = self.pool.acquire(req.url, timeout=self._tmo().pool, **acq)
                is_new_conn = not conn.tls_established
                logger.debug("conn id=%s yeni=%s tls=%s h2=%s",
                             id(conn), is_new_conn, conn.tls_established,
                             conn.h2_conn is not None)

                if metrics:
                    metrics.connection_reused = not is_new_conn
                    metrics.connect_end       = time.perf_counter()

                     
                if is_new_conn:
                    if metrics: metrics.tls_start = time.perf_counter()
                    logger.debug("%s profili ile TLS el sıkışması başlıyor (%s)",
                                 self.impersonate, req.url.host)
                    conn.socket = TLSAdapter.negotiate(
                        conn.socket, req.url.host, self.impersonate,
                        ca_path=self._ca_path, port=req.url.port,
                        **self._legacy_kw(),
                        **self._cert_kw(),
                    )
                    conn.socket.raw_socket.settimeout(self._tmo().read_timeout)
                    conn.tls_established = True
                    if metrics: metrics.tls_end = time.perf_counter()
                    alpn = conn.socket.state.get("alpn", "")
                    if alpn == "h2":
                        logger.debug("TLS 1.3 kuruldu (ALPN: h2)")
                        h2 = Http2Connection(conn.socket, profile=self.impersonate)
                        conn.h2_conn = h2
                        h2.send_preface_and_settings()
                    else:
                        logger.debug("TLS 1.3 kuruldu (ALPN: http/1.1)")

                if conn.h2_conn is not None:
                    resp = self._send_h2_request(conn, req, metrics, cache_entry, method, url,
                                                 stream=stream)
                    if resp._stream is not None:
                        # Bağlantıyı akış yönetir (bitince/close'ta havuza döner).
                        if metrics and metrics.request_start:
                            resp.elapsed = time.perf_counter() - metrics.request_start
                        return resp
                    if conn.h2_conn is not None and conn.h2_conn.goaway is not None:
                        # Sunucu GOAWAY ile kapatıyor: yanıt tamam ama bağlantı
                        # yeniden kullanılmaz (RFC 9113 §6.8).
                        conn.close()
                    self.pool.release(conn)
                    if metrics and metrics.request_start:
                        resp.elapsed = time.perf_counter() - metrics.request_start
                    return resp

                                 
                req_lines = [f"{req.method} {req.url.raw_path.decode('ascii')} HTTP/1.1"]
                h1_pairs = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in req.headers.raw]
                h1_pairs = order_h1(self.impersonate,
                                    drop_h2_only_defaults(self.impersonate, h1_pairs))
                for k, v in h1_pairs:
                    req_lines.append(f"{k}: {v}")
                raw_bytes = "\r\n".join(req_lines).encode("ascii") + b"\r\n\r\n" + req.body

                if metrics: metrics.bytes_sent = len(raw_bytes)

                total = self._tmo().total
                if total is not None:
                    conn.conn_data["deadline"] = time.perf_counter() + total
                conn.socket.send_record(raw_bytes)
                send_time = time.perf_counter()

                                                                            
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
                        metrics.first_byte_time = time.perf_counter()
                        first_byte = False
                    search_from = max(0, len(header_acc) - 3)
                    header_acc += chunk
                    sep = header_acc.find(b"\r\n\r\n", search_from)
                    if sep != -1:
                        break
                    if len(header_acc) > MAX_RESPONSE_HEADER_BYTES:
                        raise ConnectionError(
                            f"Yanıt başlık bloğu {MAX_RESPONSE_HEADER_BYTES} baytı aşıyor (CRLFCRLF yok).")
                header_buf = bytes(header_acc)

                if not header_buf:
                    raise ConnectionResetError("Sunucu yanıt vermeden bağlantıyı kesti.")
                if sep == -1:
                    # CRLF CRLF görülmeden kapanış: yarım başlık bloğu yanıt SAYILMAZ
                    # (eskiden sep=-1 dilimleri çöp başlık/gövde üretip 200 dönüyordu).
                    raise ConnectionResetError(
                        "Sunucu yanıt başlıkları tamamlanmadan bağlantıyı kesti.")

                headers_raw      = header_buf[:sep]
                first_body_chunk = header_buf[sep + 4:]

                                                                              
                resp_headers = Headers()
                lines        = headers_raw.split(b"\r\n")
                for line in lines[1:]:
                    if b":" not in line:
                        continue
                    hk, _, hv = line.partition(b":")
                    try:
                        k_str = hk.strip().decode("latin-1")
                        v_str = hv.strip().decode("latin-1")
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
                conn_hdr = resp_headers.get("connection", "").lower()
                http10   = lines[0].upper().startswith(b"HTTP/1.0")
                if stream and framing != "none" and not (
                        framing == "length"
                        and int(resp_headers.get("content-length", "0").strip()) == 0):
                    # Akış: gövdeyi OKUMADAN dön. Toplam süre sınırı (deadline)
                    # akışa uygulanmaz; her okuma read_timeout ile sınırlıdır.
                    if conn.conn_data.pop("deadline", None) is not None:
                        conn.socket.raw_socket.settimeout(self.timeout.read_timeout)
                    reusable = not ("close" in conn_hdr or framing == "eof"
                                    or (http10 and "keep-alive" not in conn_hdr))
                    gen = self._iter_body(conn, first_body_chunk, resp_headers, framing)
                    resp = Response(status_code=status_code, headers=resp_headers,
                                    stream=_H1BodyStream(self, conn, gen, reusable, metrics,
                                                         len(headers_raw) + 4))
                    resp.request = req
                    if metrics:
                        metrics.transfer_end = time.perf_counter()
                        resp.metrics = metrics
                        if metrics.first_byte_time:
                            conn.update_ttfb((metrics.first_byte_time - send_time) * 1000)
                    self._update_cookies(resp_headers, req.url)
                    if metrics and metrics.request_start:
                        resp.elapsed = time.perf_counter() - metrics.request_start
                    return resp
                body_raw = self._collect_body(conn, first_body_chunk, resp_headers, metrics, framing)
                if conn.conn_data.pop("deadline", None) is not None:
                    conn.socket.raw_socket.settimeout(self._tmo().read_timeout)

                if metrics:
                    metrics.transfer_end   = time.perf_counter()
                    metrics.bytes_received = len(headers_raw) + 4 + len(body_raw)
                    if metrics.first_byte_time:
                        ttfb_ms = (metrics.first_byte_time - send_time) * 1000
                        conn.update_ttfb(ttfb_ms)

                                                                           
                ce       = resp_headers.get("content-encoding", "").lower()
                body_raw = HTTP1Parser._decompress(body_raw, ce)

                resp         = Response(status_code=status_code, headers=resp_headers, body=body_raw)
                resp.request = req
                resp.tls_info = self._tls_info(conn)

                if metrics:
                    metrics.total_end = time.perf_counter()
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
                    resp.elapsed = time.perf_counter() - metrics.request_start
                return resp

            except (ConnectionResetError, ConnectionError, TimeoutError, OSError) as e:
                # conn döngü başında None'a çekiliyor: acquire() patlarsa bir
                # ÖNCEKİ turdan kalan bayat bağlantıyı ikinci kez release edip
                # semaphore sayacını bozmuyoruz.
                if (conn is None and rot_proxy is not None and self._rotator is not None
                        and not isinstance(e, TimeoutError)):
                    self._rotator.mark_failed(rot_proxy)   # proxy'ye bağlanılamadı
                if conn is not None:
                    conn.close()
                    self.pool.release(conn)  # close() semaphore'a dokunmaz
                    conn = None
                    if isinstance(e, _H2Refused) or (
                            not is_new_conn and not got_bytes
                            and not isinstance(e, TimeoutError)):
                        # Yeniden kullanılan bağlantı sunucu tarafında kapanmış
                        # olabilir; yanıttan HİÇ bayt gelmediyse ve hata zaman aşımı
                        # değilse yeniden denemek güvenlidir. Zaman aşımı (sunucu
                        # isteği işliyor olabilir) ya da yarım yanıt YENİDEN
                        # DENENMEZ: POST çift gönderilir, bekleme süresi katlanır.
                        # GOAWAY ile işlenmediği bildirilen h2 isteği (yeni
                        # bağlantıda bile) güvenle yeniden denenir.
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

    def _tmo(self) -> Timeout:
        """Etkin zaman aşımı: istek düzeyi ``timeout=`` varsa o, yoksa oturumunki."""
        return _api.effective_timeout(self, self.timeout)

    def use(self, plugin: Plugin) -> "Session":
        """Plugin ekle (``AsyncSession.use`` ile aynı arayüz; kancalar düz fonksiyon).

        Zincir çağrı destekli: ``s.use(p1).use(p2)``.
        """
        self._plugins.append(plugin)
        return self

    def _send(self, method: str, url: "str | URL", headers: "HeaderDict | None" = None,
              body: bytes = b"",
              metrics: RequestMetrics | None = None, stream: bool = False) -> Response:
        """Tek bir isteği gönderir: plugin kancaları + transport verilmişse ona, yoksa ağa."""
        try:
            req_dict: dict[str, Any] = {"method": method, "url": url, "headers": headers or {},
                                        "body": body}
            for plugin in self._plugins:
                req_dict = call_sync(plugin, "on_request", req_dict)
            method, url = req_dict["method"], req_dict["url"]
            body = req_dict.get("body") or b""
            hdrs = req_dict.get("headers") or {}
            if self.transport is None:
                resp = self._raw_request(method, url, data=body or None, headers=hdrs,
                                         metrics=metrics, stream=stream)
                if self._h3 is not None:
                    u = URL(str(url))
                    self._h3.state.observe(u.host, u.port, resp.headers)    # Alt-Svc keşfi
            else:
                req = Request(method=method, url=url, data=body or None,
                              headers={k: v for k, v in dict(hdrs).items() if v is not None})
                if "host" not in req.headers:
                    req.headers["Host"] = req.url.host
                cookie_header = self.cookie_jar.header_for(
                    host=req.url.host, path=req.url.path, secure=(req.url.scheme == "https")
                )
                if cookie_header and "cookie" not in req.headers:
                    req.headers["Cookie"] = cookie_header
                req.timeout = self._tmo()
                resp = self.transport.handle_request(req)
                self._update_cookies(resp.headers, req.url)
                if metrics and metrics.request_start:
                    resp.elapsed = time.perf_counter() - metrics.request_start
            for plugin in self._plugins:
                resp = call_sync(plugin, "on_response", resp)
            return resp
        except Exception as e:
            for plugin in self._plugins:
                if call_sync(plugin, "on_error", e) is None:
                    return Response(0, body=b"")
            raise

    def _send_with_retries(self, method: str, url: "str | URL", **kwargs: Any) -> Response:
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
                resp.close()      # akış yanıtıysa bağlantıyı bırak
                logger.debug("HTTP %s, %d. yeniden deneme %.2fs sonra",
                             resp.status_code, attempt, delay)
            if delay:
                time.sleep(delay)

    # --- kimlik / hook / hop ------------------------------------------------

    def _auth_for(self, auth: AuthArg, url_creds: "tuple[str, str] | None",
                  host: str) -> "tuple[Auth | None, str | None]":
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

    def _call_hooks(self, event: str, arg: Any, req_hooks: "_api.HookMap | None" = None,
                    **kw: Any) -> Any:
        """Hook'ları çalıştırır. Yanıtta requests hook'u ``None`` dışı dönerse yanıt değişir."""
        if event == "request":
            for fn in _api.hook_list(self.event_hooks, "request"):
                _no_await(fn(arg))
            return arg
        for fn in _api.hook_list(self.event_hooks, "response"):
            _no_await(fn(arg))
        for fn in _api.hook_list(self.hooks, "response") + _api.hook_list(req_hooks, "response"):
            out = _no_await(fn(arg, **kw))
            if out is not None:
                arg = out
        return arg

    def _hop(self, auth: "Auth | None", method: str, url: str, headers: HeaderDict, body: bytes,
             metrics: RequestMetrics, req_hooks: "_api.HookMap", hkw: "dict[str, Any]",
             stream: bool = False) -> "tuple[Response, list[Response]]":
        """Tek yönlendirme adımı: auth akışı (401 yeniden denemesi dahil) + hook'lar.

        Döner: (son yanıt, ara yanıtlar). Ara yanıtlar (ör. 401 challenge) ``history``'ye girer.
        """
        has_req_hooks = bool(_api.hook_list(self.event_hooks, "request"))
        extras: list[Response] = []
        if auth is None and not has_req_hooks:
            resp = self._send_with_retries(method, url, headers=headers, body=body, metrics=metrics,
                                           stream=stream)
            hooked: Response = self._call_hooks("response", resp, req_hooks, **hkw)
            return hooked, extras
        removed = [k for k, v in headers.items() if v is None]
        base = Request(method, url, data=body or None,
                       headers={k: v for k, v in headers.items() if v is not None})
        flow = auth.auth_flow(base) if auth is not None else None
        req = next(flow) if flow is not None else base
        while True:
            self._call_hooks("request", req)
            h: HeaderDict = {k.decode("latin-1"): v.decode("latin-1") for k, v in req.headers.raw
                             if k.lower() != b"content-length"}
            lower = {x.lower() for x in h}
            h.update({k: None for k in removed if k.lower() not in lower})
            target = url if req.url is base.url else str(req.url)
            resp = self._send_with_retries(req.method, target, headers=h,
                                           body=req.body or b"", metrics=metrics, stream=stream)
            resp = self._call_hooks("response", resp, req_hooks, **hkw)
            if flow is None:
                return resp, extras
            try:
                req = flow.send(resp)
            except StopIteration:
                return resp, extras
            if stream:
                _discard_stream(resp)     # 401 ara yanıtı: bağlantı havuza dönsün
            extras.append(resp)

    def request(
        self,
        method:          str,
        url:             "str | URL",
        data:            Any        = None,
        json:            Any        = None,
        headers:         HeadersArg = None,
        files:           "dict[str, Any] | None" = None,
        allow_redirects: bool       = True,
        params:          ParamsArg  = None,
        cookies:         CookiesArg = None,
        auth:            AuthArg    = USE_CLIENT_DEFAULT,
        timeout:         TimeoutArg = USE_CLIENT_DEFAULT,
        hooks:           "dict[str, Any] | None" = None,
        stream:          bool       = False,
    ) -> Response:
        """HTTP isteği. requests/httpx uyumlu ek parametreler:

        ``params`` (dict/liste/str; URL'deki sorguya eklenir), ``cookies`` (yalnızca bu
        istek için; yönlendirmede başka origin'e gitmez), ``auth`` (oturumunkini ezer;
        ``None`` oturum auth'unu kapatır), ``timeout`` (float, ``(connect, read)`` ya da
        :class:`Timeout`; ``None`` sınırsız), ``hooks`` (``{"response": [fn]}``).

        ``stream=True``: gövde OKUNMADAN döner; ``r.iter_content``/``iter_lines``/
        ``iter_bytes``/``raw`` ile okunur, ``r.close()`` (ya da ``with``) ile bırakılır.
        Gövde sonuna kadar okununca bağlantı havuza döner.
        """
        url, url_creds = _api.split_userinfo(url)
        url = _api.apply_params(url, self.params, params)
        current_url    = url
        redirect_count = 0
        history: list[Response] = []
        metrics = RequestMetrics(request_start=time.perf_counter())
        merged = self._merged_headers(headers)
        body = _api.encode_body(data, json, files, merged)
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
                hop_headers = dict(merged)
                if same_origin and req_cookies and not _api._has(hop_headers, "cookie"):
                    jar = self.cookie_jar.header_for(
                        host=cur.host, path=cur.path, secure=(cur.scheme == "https"))
                    hop_headers["Cookie"] = _api.merge_cookie_header(jar, req_cookies)
                attempt = 0
                while True:
                    resp, extras = self._hop(hop_auth, method, current_url, hop_headers,
                                             body, metrics, req_hooks, hkw, stream=stream)
                    delay = None
                    for plugin in retry_plugins:
                        if plugin.should_retry(resp, attempt):
                            delay = plugin.delay_for(resp, attempt)
                            break
                    if delay is None:
                        break
                    resp.close()      # tekrar denenecek yanıt (akışsa bağlantıyı bırak)
                    if delay:
                        time.sleep(delay)
                    attempt += 1
                history.extend(extras)
                if history:
                    resp.history = list(history)

                if not allow_redirects or resp.status_code not in (301, 302, 303, 307, 308):
                    if not allow_redirects:
                        resp.next = _api.next_request(resp, method, current_url, merged, body)
                    return resp

                if redirect_count >= self.max_redirects:
                    raise ConnectionError(f"Maksimum yönlendirme sayısına ulaşıldı ({self.max_redirects}).")

                location = resp.headers.get("location", "")
                if not location:
                    return resp

                history.append(resp)
                metrics.redirect_count += 1

                if stream:
                    _discard_stream(resp)     # yönlendirme gövdesi: küçükse tüketip bağlantıyı koru
                base = URL(current_url)
                current_url = _resolve_location(base, location)

                # Farklı bir origin'e gidiyorsak Authorization/Cookie TAŞINMAZ;
                # aksi hâlde kimlik bilgisi üçüncü bir siteye sızar.
                new_url = URL(current_url)
                if (new_url.scheme, new_url.host, new_url.port) != base.origin and merged:
                    merged = {
                        k: v for k, v in dict(merged).items()
                        if k.lower() not in ("authorization", "cookie", "proxy-authorization")
                    }

                if resp.status_code in (301, 302, 303):
                    method = "GET"
                    body   = b""
                    merged = {k: v for k, v in merged.items()
                              if k.lower() not in ("content-type", "content-length")}

                redirect_count += 1
                logger.debug("Yönlendirme (%s) -> %s", resp.status_code, current_url)
        finally:
            _api.reset_timeout_override(token)

    def _merged_headers(self, headers: HeadersArg) -> HeaderDict:
        """Oturum başlıkları + istek başlıkları (istek kazanır; büyük/küçük harf
        duyarsız). ``None`` değerler, varsayılanı kaldırmak için korunur."""
        merged: HeaderDict = {}
        index: dict[str, str] = {}
        # Duck-typed (requests uyumu): ``items()`` olan her nesne ya da (ad, değer) çiftleri.
        sources: "tuple[Any, ...]" = (self.headers, headers or {})
        for src in sources:
            pairs: "Iterable[tuple[str, str | None]]" = (
                src.items() if hasattr(src, "items") else src)
            for k, v in pairs:
                lk = k.lower()
                if lk in index:
                    del merged[index[lk]]
                index[lk] = k
                merged[k] = v
        return merged

    def stream(self, method: str, url: "str | URL", **kwargs: Any) -> _StreamContext:
        """httpx tarzı: ``with s.stream("GET", url) as r:`` — gövde akıtılır, çıkışta kapanır."""
        return _StreamContext(self, method, url, kwargs)

    def get(self, url: "str | URL", headers: HeadersArg = None, allow_redirects: bool = True,
            params: ParamsArg = None, cookies: CookiesArg = None,
            auth: AuthArg = USE_CLIENT_DEFAULT, timeout: TimeoutArg = USE_CLIENT_DEFAULT,
            hooks: "dict[str, Any] | None" = None, stream: bool = False) -> Response:
        return self.request("GET", url, headers=headers, allow_redirects=allow_redirects,
                            params=params, cookies=cookies, auth=auth, timeout=timeout, hooks=hooks,
                            stream=stream)

    def websocket(self, url: str) -> "WebSocketConnection":
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

    def post(self, url: "str | URL", data: Any = None, json: Any = None, headers: HeadersArg = None,
             files: "dict[str, Any] | None" = None, allow_redirects: bool = True,
             params: ParamsArg = None, cookies: CookiesArg = None,
             auth: AuthArg = USE_CLIENT_DEFAULT, timeout: TimeoutArg = USE_CLIENT_DEFAULT,
             hooks: "dict[str, Any] | None" = None, stream: bool = False) -> Response:
        return self.request("POST", url, data=data, json=json, headers=headers, files=files,
                            allow_redirects=allow_redirects, params=params, cookies=cookies,
                            auth=auth, timeout=timeout, hooks=hooks,
                            stream=stream)

    def put(self, url: "str | URL", data: Any = None, json: Any = None, headers: HeadersArg = None,
            files: "dict[str, Any] | None" = None, allow_redirects: bool = True,
            params: ParamsArg = None, cookies: CookiesArg = None,
            auth: AuthArg = USE_CLIENT_DEFAULT, timeout: TimeoutArg = USE_CLIENT_DEFAULT,
            hooks: "dict[str, Any] | None" = None, stream: bool = False) -> Response:
        return self.request("PUT", url, data=data, json=json, headers=headers, files=files,
                            allow_redirects=allow_redirects, params=params, cookies=cookies,
                            auth=auth, timeout=timeout, hooks=hooks,
                            stream=stream)

    def patch(self, url: "str | URL", data: Any = None, json: Any = None,
              headers: HeadersArg = None, allow_redirects: bool = True, params: ParamsArg = None,
              cookies: CookiesArg = None, auth: AuthArg = USE_CLIENT_DEFAULT,
              timeout: TimeoutArg = USE_CLIENT_DEFAULT, hooks: "dict[str, Any] | None" = None,
              stream: bool = False) -> Response:
        return self.request("PATCH", url, data=data, json=json, headers=headers,
                            allow_redirects=allow_redirects, params=params, cookies=cookies,
                            auth=auth, timeout=timeout, hooks=hooks,
                            stream=stream)

    def delete(self, url: "str | URL", headers: HeadersArg = None, allow_redirects: bool = True,
               params: ParamsArg = None, cookies: CookiesArg = None,
               auth: AuthArg = USE_CLIENT_DEFAULT, timeout: TimeoutArg = USE_CLIENT_DEFAULT,
               hooks: "dict[str, Any] | None" = None, stream: bool = False) -> Response:
        return self.request("DELETE", url, headers=headers, allow_redirects=allow_redirects,
                            params=params, cookies=cookies, auth=auth, timeout=timeout, hooks=hooks,
                            stream=stream)

    def head(self, url: "str | URL", headers: HeadersArg = None, allow_redirects: bool = False,
             params: ParamsArg = None, cookies: CookiesArg = None,
             auth: AuthArg = USE_CLIENT_DEFAULT, timeout: TimeoutArg = USE_CLIENT_DEFAULT,
             hooks: "dict[str, Any] | None" = None) -> Response:
        """HEAD; ``allow_redirects`` varsayılanı ``False`` (requests/httpx gibi)."""
        return self.request("HEAD", url, headers=headers, allow_redirects=allow_redirects,
                            params=params, cookies=cookies, auth=auth, timeout=timeout, hooks=hooks)

    def options(self, url: "str | URL", headers: HeadersArg = None, allow_redirects: bool = True,
                params: ParamsArg = None, cookies: CookiesArg = None,
                auth: AuthArg = USE_CLIENT_DEFAULT, timeout: TimeoutArg = USE_CLIENT_DEFAULT,
                hooks: "dict[str, Any] | None" = None, stream: bool = False) -> Response:
        return self.request("OPTIONS", url, headers=headers, allow_redirects=allow_redirects,
                            params=params, cookies=cookies, auth=auth, timeout=timeout, hooks=hooks,
                            stream=stream)

    def pre_warm(self, hosts: list[str], count: int = 2) -> dict[str, int]:
        return self.pool.prewarm(
            hosts, count=count,
            tls_negotiate_fn=functools.partial(TLSAdapter.negotiate, ca_path=self._ca_path,
                                               **self._legacy_kw(),
                                               client_cert=self.client_cert),
            impersonate=self.impersonate,
        )

    def pool_stats(self) -> "dict[str, Any]":
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
        if self._h3 is not None:
            self._h3.close()
        self.pool.close_all()
        if self.client_cert is not None and self._owns_cert:
            self.client_cert.close()          # özel anahtar referansını bırak
        if self.transport is not None:
            self.transport.close()

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
