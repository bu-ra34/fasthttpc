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
from typing import Optional, List
from .headers import Headers
from ..streaming import (
    IncrementalDecoder, LineSplitter, Rechunker, TextRechunker,
    StreamConsumed, StreamClosed, ResponseNotRead,
)

_CHARSET_RE = re.compile(r"""charset\s*=\s*["']?([^\s;"']+)""", re.IGNORECASE)


class _Text(str):
    """``Response.text`` değeri: hem ``str`` (requests/httpx uyumu: ``r.text``)
    hem çağrılabilir (eski API: ``r.text()``, ``r.text(encoding="latin-1")``)."""

    def __new__(cls, value: str, body: bytes = b""):
        self = super().__new__(cls, value)
        self._body = body
        return self

    def __call__(self, encoding: Optional[str] = None, errors: str = "replace") -> str:
        if encoding is None:
            return str(self)
        return self._body.decode(encoding, errors=errors)

    def __reduce__(self):
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

    def __init__(
        self,
        status_code: int,
        headers: "dict | Headers | None" = None,
        body: bytes = b"",
        request=None,
        elapsed: float = 0.0,
        stream=None,
        astream=None,
    ):
        self.status_code: int              = status_code
        self.headers: Headers              = headers if isinstance(headers, Headers) else Headers(headers)
        # Akış modu: ``stream`` (senkron) / ``astream`` (async) HAM gövde kaynağıdır;
        # ``_body`` ilk ``content``/``body`` erişiminde doldurulur.
        self._stream                       = stream
        self._astream                      = astream
        self._body                         = None if (stream or astream) else body
        self._consumed                     = False
        self._closed                       = False
        self._decoder                      = None
        self._raw_iter                     = None
        self.request                       = request
        self.history: List["Response"]     = []
        self.elapsed                       = elapsed
        self._reason: str                  = ""
        self._url: Optional[str]           = None
        self._encoding: Optional[str]      = None
        self.http_version: str             = "HTTP/1.1"   # "HTTP/2" ise h2 üzerinden geldi
        # TLS el sıkışması özeti (sürüm, suite, EMS/EtM/güvenli renegotiation görünürlüğü); düz
        # HTTP/mock taşıma ise None. Bkz. security/tls12_legacy.tls_info.
        self.tls_info: Optional[dict]      = None

                                                                              

    @property
    def body(self) -> bytes:
        """Gövde (bytes). Akış modunda ilk erişimde KALAN gövdeyi okur ve açar."""
        if self._body is None:
            self._load()
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
    def url(self, value) -> None:
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
            self._decoder = IncrementalDecoder(self.headers.get("content-encoding", "") or "")
        return self._decoder

    def _raw_chunks(self):
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
        while True:
            c = st.read_chunk()
            if not c:
                self._consumed = True
                return
            yield c

    def _decoded(self):
        """Açılmış parçalar (senkron üreteç)."""
        if self._body is not None:
            if self._body:
                yield self._body
            return
        dec = self._get_decoder()
        for c in self._raw_chunks():
            out = dec.decode(c)
            if out:
                yield out
        tail = dec.flush()
        if tail:
            yield tail

    @staticmethod
    def _drive(gen, rc):
        for c in gen:
            yield from rc.feed(c)
        yield from rc.flush()

    def iter_raw(self, chunk_size: "int | None" = None):
        """HAM (sıkıştırması açılmamış) gövde parçaları. Akışsız yanıtta gövde
        zaten açılmış olduğundan olduğu gibi döner."""
        return self._drive(self._raw_chunks(), Rechunker(chunk_size))

    def iter_bytes(self, chunk_size: "int | None" = None):
        """Content-Encoding açılmış gövde parçaları (``chunk_size=None``: geldiği gibi)."""
        return self._drive(self._decoded(), Rechunker(chunk_size))

    def iter_content(self, chunk_size: "int | None" = 1, decode_unicode: bool = False):
        """requests uyumlu: açılmış bayt (``decode_unicode=True`` ise ``str``) parçaları."""
        if decode_unicode:
            return self.iter_text(chunk_size)
        return self.iter_bytes(chunk_size)

    def _text_decoder(self):
        try:
            return codecs.getincrementaldecoder(self.encoding)(errors="replace")
        except LookupError:
            return codecs.getincrementaldecoder("utf-8")(errors="replace")

    def iter_text(self, chunk_size: "int | None" = None):
        """Gövde ``str`` parçaları (çok baytlı karakterler parça sınırında bölünmez)."""
        def gen():
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
                   delimiter: "bytes | None" = None):
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

    def _line_conv(self, decode_unicode: bool):
        if not decode_unicode:
            return lambda b: b
        enc = self.encoding
        try:
            codecs.lookup(enc)
        except LookupError:
            enc = "utf-8"
        return lambda b: b.decode(enc, errors="replace")

    @property
    def raw(self):
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

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- async ---------------------------------------------------------
    def _acheck(self) -> None:
        if self._stream is not None:
            raise RuntimeError("Senkron akış yanıtı: iter_* kullanın.")

    async def _araw_chunks(self):
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

    async def _adecoded(self):
        if self._body is not None:
            if self._body:
                yield self._body
            return
        dec = self._get_decoder()
        async for c in self._araw_chunks():
            out = dec.decode(c)
            if out:
                yield out
        tail = dec.flush()
        if tail:
            yield tail

    @staticmethod
    async def _adrive(agen, rc):
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

    def aiter_raw(self, chunk_size: "int | None" = None):
        return self._adrive(self._araw_chunks(), Rechunker(chunk_size))

    def aiter_bytes(self, chunk_size: "int | None" = None):
        return self._adrive(self._adecoded(), Rechunker(chunk_size))

    def aiter_text(self, chunk_size: "int | None" = None):
        async def gen():
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
                          delimiter: "bytes | None" = None):
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

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.aclose()

    def json(self, **kwargs):
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
        if not link_header:
            return {}

        result: dict[str, dict[str, str]] = {}
        for part in link_header.split(","):
            part = part.strip()
            if not part:
                continue
            segments = [s.strip() for s in part.split(";")]
            if not segments:
                continue
            url_part = segments[0]
            if url_part.startswith("<") and url_part.endswith(">"):
                url = url_part[1:-1]
            else:
                continue
            params: dict[str, str] = {"url": url}
            for seg in segments[1:]:
                if "=" in seg:
                    k, _, v = seg.partition("=")
                    params[k.strip()] = v.strip().strip('"')
            rel = params.get("rel", url)
            result[rel] = params
        return result

                                                                               

    @property
    def is_success(self) -> bool:
        """2xx yanıtı mı?"""
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        """Redirect yanıtı mı? (301, 302, 303, 307, 308)"""
        return self.status_code in (301, 302, 303, 307, 308)

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

    def readinto(self, b) -> int:
        if not self._left:
            try:
                self._left = next(self._it)
            except StopIteration:
                return 0
        n = min(len(b), len(self._left))
        b[:n] = self._left[:n]
        self._left = self._left[n:]
        return n

    def close(self) -> None:
        if not self.closed:
            self._resp.close()
        super().close()
