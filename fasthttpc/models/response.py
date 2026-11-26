"""
fasthttpc — Response modeli

HTTP yanıtını temsil eder. status_code, headers, body, elapsed,
history ve links özelliklerini içerir.
"""
from __future__ import annotations

import codecs
import http
import io
import json as jsonlib
import re
import time
from typing import (
    TYPE_CHECKING, Any, AsyncIterable, AsyncIterator, Callable, Iterable, Iterator,
    List, Optional, Protocol, TypeVar,
)
from .headers import Headers
from ..streaming import (
    DEFAULT_MAX_DECOMPRESSED_SIZE, IncrementalDecoder, LineSplitter, Rechunker, TextRechunker,
    StreamConsumed, StreamClosed, ResponseNotRead,
)

if TYPE_CHECKING:
    from typing_extensions import Buffer   # yalnızca tip: collections.abc.Buffer 3.12+

    from .request import Request
    from ..metrics import RequestMetrics

_T = TypeVar("_T")


class _Chunker(Protocol[_T]):
    """``Rechunker`` (bytes) / ``TextRechunker`` (str) ortak arayüzü."""

    def feed(self, data: _T) -> "list[_T]": ...
    def flush(self) -> "list[_T]": ...


class BodyStream(Protocol):
    """Senkron akış gövdesi kaynağı (session ``_H1BodyStream``/``_H2BodyStream``)."""

    def read_chunk(self) -> bytes: ...
    def close(self) -> None: ...


class AsyncBodyStream(Protocol):
    """Async akış gövdesi kaynağı (async_session ``_AsyncH1Stream``/``_AsyncH2Stream``)."""

    async def read_chunk(self) -> bytes: ...
    def close_nowait(self) -> None: ...
    async def aclose(self) -> None: ...


_CHARSET_RE = re.compile(r"""charset\s*=\s*["']?([^\s;"']+)""", re.IGNORECASE)


_LINK_RE = re.compile(r'<([^>]*)>((?:\s*;\s*[^;,"\s=]+(?:\s*=\s*(?:"[^"]*"|[^;,\s]*))?)*)')
_LINK_PARAM_RE = re.compile(r'[;\s]*([^;,"\s=]+)(?:\s*=\s*(?:"([^"]*)"|([^;,\s]*)))?')


class _Text(str):
    """``Response.text`` değeri: hem ``str`` (requests/httpx uyumu: ``r.text``)
    hem çağrılabilir (eski API: ``r.text()``, ``r.text(encoding="latin-1")``)."""

    _body: bytes

    def __new__(cls, value: str, body: bytes = b"") -> "_Text":
        self = super().__new__(cls, value)
        self._body = body
        return self

    def __call__(self, encoding: Optional[str] = None, errors: str = "replace") -> str:
        if encoding is None:
            return str(self)
        return self._body.decode(encoding, errors=errors)

    def __reduce__(self) -> "tuple[type[_Text], tuple[str, bytes]]":
        return (_Text, (str(self), self._body))


class _Elapsed(float):
    """Saniye cinsinden float; requests'teki ``timedelta.total_seconds()`` ile uyumlu."""

    def total_seconds(self) -> float:
        return float(self)


class HTTPStatusError(Exception):
    """4xx veya 5xx HTTP hatalarında fırlatılır."""
    def __init__(self, message: str, response: "Response"):
        super().__init__(message)
        self.response = response


def _reason(status: int) -> str:
    try:
        return http.HTTPStatus(status).phrase
    except ValueError:
        return ""


class Response:
    """
    Bir HTTP yanıtını temsil eder.

    Attributes:
        status_code: HTTP durum kodu (200, 404, vb.)
        headers:     Yanıt başlıkları (Headers objesi)
        body:        Ham yanıt gövdesi (bytes)
        request:     Bu yanıtı oluşturan istek objesi
        history:     Redirect zinciri (önceki Response listesi)
        elapsed:     İsteğin toplam süresi (saniye cinsinden float)
        http_version: Yanıtın taşındığı protokol ("HTTP/1.1" veya "HTTP/2")
    """

    # İstek metrikleri: yalnızca ağ yolunda atanır (mock/transport yanıtında YOK;
    # ``hasattr(r, "metrics")`` ile denetlenir), bu yüzden sınıfta varsayılanı yoktur.
    metrics: "RequestMetrics"

    # Akış gövdesi açılırken üst sınır (``Limits.max_decompressed_size``); oturum kendi
    # ayarını akış yanıtına yazar. Aşılınca iter_*/content DecompressedSizeError verir.
    _max_decompressed_size: Optional[int] = DEFAULT_MAX_DECOMPRESSED_SIZE

    def __init__(
        self,
        status_code: int,
        headers: "dict[str, str] | list[tuple[str, str]] | Headers | None" = None,
        body: bytes = b"",
        request: "Request | None" = None,
        elapsed: float = 0.0,
        stream: "BodyStream | None" = None,
        astream: "AsyncBodyStream | None" = None,
    ):
        self.status_code: int              = status_code
        self.headers: Headers              = headers if isinstance(headers, Headers) else Headers(headers)
        # Akış modu: ``stream`` (senkron) / ``astream`` (async) HAM gövde kaynağıdır;
        # ``_body`` ilk ``content``/``body`` erişiminde doldurulur.
        self._stream                       = stream
        self._astream                      = astream
        self._body: Optional[bytes]        = None if (stream or astream) else body
        self._consumed                     = False
        self._closed                       = False
        self._decoder: Optional[IncrementalDecoder] = None
        self._raw_iter: Optional[_RawReader] = None
        self.request: "Request | None"     = request
        self.history: List["Response"]     = []
        self.next: "Request | None"        = None   # allow_redirects=False: izlenecek istek (requests ``r.next``)
        self.elapsed                       = elapsed
        self._reason: str                  = ""
        self._url: Optional[str]           = None
        self._encoding: Optional[str]      = None
        self.http_version: str             = "HTTP/1.1"   # "HTTP/2" ise h2 üzerinden geldi
        # TLS el sıkışması özeti (sürüm, suite, EMS/EtM/güvenli renegotiation görünürlüğü); düz
        # HTTP/mock taşıma ise None. Bkz. security/tls12_legacy.tls_info.
        self.tls_info: Optional[dict[str, Any]] = None

                                                                              

    @property
    def body(self) -> bytes:
        """Gövde (bytes). Akış modunda ilk erişimde KALAN gövdeyi okur ve açar."""
        if self._body is None:
            self._load()
        assert self._body is not None   # _load ya doldurur ya da fırlatır
        return self._body

    @body.setter
    def body(self, value: bytes) -> None:
        self._body = value

    @property
    def encoding(self) -> str:
        """Gövde kodlaması: atanmışsa o, yoksa Content-Type charset'i, yoksa ``utf-8``."""
        if self._encoding:
            return self._encoding
        m = _CHARSET_RE.search(self.headers.get("content-type", "") or "")
        return m.group(1) if m else "utf-8"

    @encoding.setter
    def encoding(self, value: Optional[str]) -> None:
        self._encoding = value

    @property
    def text(self) -> str:
        """
        Yanıt gövdesi (``str``); kodlama :attr:`encoding`'den gelir (hatalı
        byte'lar ``replace`` ile). Eski kullanım ``r.text()`` ve
        ``r.text(encoding="latin-1", errors="strict")`` da çalışır.
        """
        try:
            s = self.body.decode(self.encoding, errors="replace")
        except LookupError:            # bilinmeyen charset adı
            s = self.body.decode("utf-8", errors="replace")
        return _Text(s, self.body)

    @property
    def elapsed(self) -> float:
        """İstek süresi (saniye); ``.total_seconds()`` de desteklenir."""
        return self._elapsed

    @elapsed.setter
    def elapsed(self, value: float) -> None:
        self._elapsed = _Elapsed(value or 0.0)

    @property
    def url(self) -> str:
        """İsteğin (yönlendirmeler sonrası) URL'i."""
        if self._url is not None:
            return self._url
        return str(self.request.url) if self.request is not None else ""

    @url.setter
    def url(self, value: object) -> None:
        self._url = None if value is None else str(value)

    @property
    def ok(self) -> bool:
        """Durum kodu 400'den küçükse True (requests ile aynı)."""
        return self.status_code < 400

    @property
    def reason(self) -> str:
        """Durum ifadesi ("OK", "Not Found"); atanmadıysa standart ifade."""
        return self._reason or _reason(self.status_code)

    @reason.setter
    def reason(self, value: str) -> None:
        self._reason = value or ""

    # ------------------------------------------------------------ akış
    @property
    def is_stream_consumed(self) -> bool:
        """Akış gövdesi sonuna kadar okundu mu (akışsız yanıtta her zaman True)."""
        return self._consumed or (self._stream is None and self._astream is None)

    @property
    def is_closed(self) -> bool:
        return self._closed

    def _load(self) -> None:
        """Akış gövdesinin kalanını okuyup ``_body``'ye koyar (senkron)."""
        if self._astream is not None:
            raise ResponseNotRead(
                "Akış yanıtı: gövdeyi okumak için 'await r.aread()' ya da aiter_* kullanın.")
        if self._consumed:
            raise StreamConsumed("Gövde iter_* ile zaten tüketildi; content yok.")
        if self._closed:
            raise StreamClosed("Yanıt gövde okunmadan kapatıldı.")
        self._body = b"".join(self._decoded())

    def _check_sync(self) -> None:
        if self._astream is not None:
            raise RuntimeError("Async akış yanıtı: aiter_*/aread kullanın.")

    def _get_decoder(self) -> IncrementalDecoder:
        if self._decoder is None:
            self._decoder = IncrementalDecoder(self.headers.get("content-encoding", "") or "",
                                               self._max_decompressed_size)
        return self._decoder

    def _raw_chunks(self) -> Iterator[bytes]:
        """Akıştan HAM (Content-Encoding açılmamış) parçalar; senkron üreteç."""
        self._check_sync()
        if self._body is not None and self._stream is None:
            if self._body:
                yield self._body
            return
        if self._consumed:
            raise StreamConsumed("Akış gövdesi zaten tüketildi.")
        if self._closed:
            raise StreamClosed("Yanıt gövde okunmadan kapatıldı.")
        st = self._stream
        assert st is not None   # _body None ise akış modundayız
        while True:
            c = st.read_chunk()
            if not c:
                self._consumed = True
                return
            yield c

    def _decoded(self) -> Iterator[bytes]:
        """Açılmış parçalar (senkron üreteç). Her parça sınırlıdır (~64 KiB); açıcıda
        bekleyen çıktı (yarıda bırakılmış önceki okuma) önce verilir."""
        if self._body is not None:
            if self._body:
                yield self._body
            return
        dec = self._get_decoder()
        yield from dec.decode_iter(b"")
        for c in self._raw_chunks():
            yield from dec.decode_iter(c)
        yield from dec.flush_iter()

    @staticmethod
    def _drive(gen: Iterable[_T], rc: _Chunker[_T]) -> Iterator[_T]:
        for c in gen:
            yield from rc.feed(c)
        yield from rc.flush()

    def iter_raw(self, chunk_size: "int | None" = None) -> Iterator[bytes]:
        """HAM (sıkıştırması açılmamış) gövde parçaları. Akışsız yanıtta gövde
        zaten açılmış olduğundan olduğu gibi döner."""
        return self._drive(self._raw_chunks(), Rechunker(chunk_size))

    def iter_bytes(self, chunk_size: "int | None" = None) -> Iterator[bytes]:
        """Content-Encoding açılmış gövde parçaları (``chunk_size=None``: geldiği gibi)."""
        return self._drive(self._decoded(), Rechunker(chunk_size))

    def iter_content(self, chunk_size: "int | None" = 1,
                     decode_unicode: bool = False) -> "Iterator[bytes] | Iterator[str]":
        """requests uyumlu: açılmış bayt (``decode_unicode=True`` ise ``str``) parçaları."""
        if decode_unicode:
            return self.iter_text(chunk_size)
        return self.iter_bytes(chunk_size)

    def _text_decoder(self) -> codecs.IncrementalDecoder:
        try:
            return codecs.getincrementaldecoder(self.encoding)(errors="replace")
        except LookupError:
            return codecs.getincrementaldecoder("utf-8")(errors="replace")

    def iter_text(self, chunk_size: "int | None" = None) -> Iterator[str]:
        """Gövde ``str`` parçaları (çok baytlı karakterler parça sınırında bölünmez)."""
        def gen() -> Iterator[str]:
            dec = self._text_decoder()
            for c in self._decoded():
                t = dec.decode(c)
                if t:
                    yield t
            t = dec.decode(b"", final=True)
            if t:
                yield t
        return self._drive(gen(), TextRechunker(chunk_size))

    def iter_lines(self, chunk_size: int = 512, decode_unicode: bool = False,
                   delimiter: "bytes | None" = None) -> "Iterator[bytes | str]":
        """Satır satır gövde; tamamlanan her satır gövdenin kalanı beklenmeden
        HEMEN verilir (SSE). ``chunk_size`` yalnızca uyumluluk içindir.
        ``decode_unicode=True`` -> ``str``."""
        splitter = LineSplitter(delimiter)
        conv = self._line_conv(decode_unicode)
        for c in self._decoded():
            for ln in splitter.feed(c):
                yield conv(ln)
        for ln in splitter.flush():
            yield conv(ln)

    def _line_conv(self, decode_unicode: bool) -> "Callable[[bytes], bytes | str]":
        if not decode_unicode:
            return lambda b: b
        enc = self.encoding
        try:
            codecs.lookup(enc)
        except LookupError:
            enc = "utf-8"
        return lambda b: b.decode(enc, errors="replace")

    @property
    def raw(self) -> "_RawReader":
        """Okunabilir HAM gövde (``read(n)``, ``readinto``, ``close``)."""
        if self._raw_iter is None:
            self._raw_iter = _RawReader(self)
        return self._raw_iter

    def read(self) -> bytes:
        """Gövdenin kalanını okuyup döner (httpx uyumu)."""
        return self.content

    def close(self) -> None:
        """Akış yanıtını kapatır: tamamen okunduysa bağlantı zaten havuzdadır;
        okunmadıysa h1'de bağlantı kapatılır, h2'de stream CANCEL ile iptal edilir."""
        if self._closed:
            return
        self._closed = True
        if self._stream is not None:
            self._stream.close()
        elif self._astream is not None:
            self._astream.close_nowait()

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- async ---------------------------------------------------------
    def _acheck(self) -> None:
        if self._stream is not None:
            raise RuntimeError("Senkron akış yanıtı: iter_* kullanın.")

    async def _araw_chunks(self) -> AsyncIterator[bytes]:
        self._acheck()
        if self._astream is None:
            if self._body:
                yield self._body
            return
        if self._consumed:
            raise StreamConsumed("Akış gövdesi zaten tüketildi.")
        if self._closed:
            raise StreamClosed("Yanıt gövde okunmadan kapatıldı.")
        st = self._astream
        while True:
            c = await st.read_chunk()
            if not c:
                self._consumed = True
                return
            yield c

    async def _adecoded(self) -> AsyncIterator[bytes]:
        if self._body is not None:
            if self._body:
                yield self._body
            return
        dec = self._get_decoder()
        for out in dec.decode_iter(b""):
            yield out
        async for c in self._araw_chunks():
            for out in dec.decode_iter(c):
                yield out
        for out in dec.flush_iter():
            yield out

    @staticmethod
    async def _adrive(agen: AsyncIterable[_T], rc: _Chunker[_T]) -> AsyncIterator[_T]:
        async for c in agen:
            for o in rc.feed(c):
                yield o
        for o in rc.flush():
            yield o

    async def aread(self) -> bytes:
        """Gövdenin kalanını okur (açılmış) ve ``content``'e koyar."""
        if self._body is None:
            if self._consumed:
                raise StreamConsumed("Gövde aiter_* ile zaten tüketildi; content yok.")
            if self._closed:
                raise StreamClosed("Yanıt gövde okunmadan kapatıldı.")
            parts = []
            async for c in self._adecoded():
                parts.append(c)
            self._body = b"".join(parts)
        return self._body

    def aiter_raw(self, chunk_size: "int | None" = None) -> AsyncIterator[bytes]:
        return self._adrive(self._araw_chunks(), Rechunker(chunk_size))

    def aiter_bytes(self, chunk_size: "int | None" = None) -> AsyncIterator[bytes]:
        return self._adrive(self._adecoded(), Rechunker(chunk_size))

    def aiter_text(self, chunk_size: "int | None" = None) -> AsyncIterator[str]:
        async def gen() -> AsyncIterator[str]:
            dec = self._text_decoder()
            async for c in self._adecoded():
                t = dec.decode(c)
                if t:
                    yield t
            t = dec.decode(b"", final=True)
            if t:
                yield t
        return self._adrive(gen(), TextRechunker(chunk_size))

    async def aiter_lines(self, decode_unicode: bool = True,
                          delimiter: "bytes | None" = None) -> "AsyncIterator[bytes | str]":
        """Satır satır (async). httpx gibi varsayılan ``str``; ``decode_unicode=False`` -> bytes."""
        splitter = LineSplitter(delimiter)
        conv = self._line_conv(decode_unicode)
        async for c in self._adecoded():
            for ln in splitter.feed(c):
                yield conv(ln)
        for ln in splitter.flush():
            yield conv(ln)

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._astream is not None:
            await self._astream.aclose()
        elif self._stream is not None:
            self._stream.close()

    async def __aenter__(self) -> "Response":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    def json(self, **kwargs: Any) -> Any:
        """
        Yanıt gövdesini JSON olarak parse eder ve döner.

        Args:
            **kwargs: json.loads'a iletilir.

        Raises:
            json.JSONDecodeError: Geçersiz JSON formatı.
        """
        return jsonlib.loads(self.body, **kwargs)

    @property
    def content(self) -> bytes:
        """Yanıt gövdesi (body ile aynı). Akış modunda ilk erişimde kalanı okur."""
        return self.body

                                                                               

    @property
    def links(self) -> dict[str, dict[str, str]]:
        """
        ``Link`` başlığını parse ederek sözlük döner.

        Örnek::

            # Link: <https://api.github.com/repos?page=2>; rel="next"
            response.links
            # {"next": {"url": "https://...", "rel": "next"}}
        """
        link_header = self.headers.get("link", "")
        result: dict[str, dict[str, str]] = {}
        # RFC 8288: <uri>; param=değer; ... ; URI içindeki virgül ve tırnaklı
        # değerler (``title="a, b"``) bölmeyi bozmaz.
        for m in _LINK_RE.finditer(link_header):
            params: dict[str, str] = {"url": m.group(1)}
            for pm in _LINK_PARAM_RE.finditer(m.group(2) or ""):
                key = pm.group(1).lower()
                if key not in params or key == "url":
                    params[key] = pm.group(2) if pm.group(2) is not None else (pm.group(3) or "")
            result[params.get("rel", params["url"])] = params
        return result

                                                                               

    @property
    def is_success(self) -> bool:
        """2xx yanıtı mı?"""
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        """Redirect yanıtı mı? (301/302/303/307/308 VE ``Location`` başlığı var; requests/httpx gibi)"""
        return self.status_code in (301, 302, 303, 307, 308) and "location" in self.headers

    @property
    def is_permanent_redirect(self) -> bool:
        """301/308 + ``Location`` (requests uyumu)."""
        return self.status_code in (301, 308) and "location" in self.headers

    @property
    def is_client_error(self) -> bool:
        """4xx istemci hatası mı?"""
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        """5xx sunucu hatası mı?"""
        return 500 <= self.status_code < 600

    def raise_for_status(self) -> "Response":
        """
        4xx veya 5xx ise HTTPStatusError fırlatır, aksi hâlde self döner.

        Raises:
            HTTPStatusError: HTTP hata kodu alındığında.
        """
        if self.is_client_error or self.is_server_error:
            raise HTTPStatusError(
                f"HTTP {self.status_code} hatası: {self.url}",
                response=self,
            )
        return self

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}] elapsed={self.elapsed:.3f}s>"


class _RawReader(io.RawIOBase):
    """``Response.raw``: HAM gövde üzerinde dosya benzeri okuyucu."""

    def __init__(self, resp: "Response"):
        super().__init__()
        self._it = resp._raw_chunks()
        self._left = b""
        self._resp = resp

    def readable(self) -> bool:
        return True

    def readinto(self, b: "Buffer") -> int:
        if not self._left:
            try:
                self._left = next(self._it)
            except StopIteration:
                return 0
        mv = memoryview(b).cast("B")
        n = min(len(mv), len(self._left))
        mv[:n] = self._left[:n]
        self._left = self._left[n:]
        return n

    def close(self) -> None:
        if not self.closed:
            self._resp.close()
        super().close()
