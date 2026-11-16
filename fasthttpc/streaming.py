"""
fasthttpc — akış (streaming) yanıt yardımcıları

Senkron ve async yanıt akışlarının ortak parçaları: artımlı Content-Encoding
açıcı, satır bölücü, sabit boyutlu parça birleştirici ve akış hataları.
G/Ç yok; yalnızca bayt -> bayt dönüşümleri vardır.
"""
from __future__ import annotations

import importlib
import zlib
from types import ModuleType
from typing import Any

from ._log import get_logger

logger = get_logger("streaming")


def _optional_module(name: str) -> ModuleType | None:
    """Opsiyonel bağımlılık (http1_parser ile aynı): kurulu değilse ``None``.
    ``importlib`` ile yüklenir; böylece stub'ı olmayan/kurulu olmayan modül
    tip denetimini ortama göre değiştirmez."""
    try:
        return importlib.import_module(name)
    except ImportError:  # pragma: no cover
        return None


# PyPy'de ``brotli`` yerine aynı API'li ``brotlicffi`` kullanılır.
_brotli = _optional_module("brotli") or _optional_module("brotlicffi")
_zstd = _optional_module("zstandard")

#: Content-Encoding -> (denenecek modüller, kurulacak paket, fasthttpc extra'sı)
_DECODER_PACKAGES: dict[str, tuple[tuple[str, ...], str, str]] = {
    "br":   (("brotli", "brotlicffi"), "brotli", "brotli"),
    "zstd": (("zstandard",), "zstandard", "zstd"),
}


class StreamConsumed(RuntimeError):
    """Akış gövdesi zaten tüketildi (bir kez okunabilir; ``content`` önbelleğe alınmadıysa)."""


class StreamClosed(RuntimeError):
    """Gövde okunmadan yanıt kapatıldı; artık okunamaz."""


class ResponseNotRead(RuntimeError):
    """Akış yanıtında gövde henüz okunmadı: ``await r.aread()`` ya da ``iter_*`` kullanın."""


class DecodeError(ValueError):
    """Content-Encoding açılamadı (bozuk sıkıştırılmış veri ya da eksik açıcı)."""


class MissingDecoderError(DecodeError):
    """Yanıt, açıcı paketi kurulu olmayan bir kodlamayla (``br``/``zstd``) geldi.

    Gövde ASLA sıkıştırılmış haliyle sessizce döndürülmez. Öznitelikler:
    ``encoding`` (ör. ``"br"``) ve kurulması gereken ``package`` (ör. ``"brotli"``).
    Ham baytlar gerekiyorsa ``stream=True`` ile ``iter_raw()`` kullanılabilir.
    """

    def __init__(self, encoding: str, package: str, extra: str):
        self.encoding = encoding
        self.package = package
        self.extra = extra
        super().__init__(
            f"Yanıt gövdesi 'Content-Encoding: {encoding}' ile sıkıştırılmış ama açıcı paket "
            f"'{package}' kurulu değil (ya da yüklenemedi). Kurmak için: "
            f"pip install {package}  (veya: pip install 'fasthttpc[{extra}]')")


def _decoder_module(enc: str) -> ModuleType:
    """``br``/``zstd`` açıcı modülü; yoksa :class:`MissingDecoderError`.

    Her çağrıda ``importlib`` ile bakılır (``sys.modules`` önbelleği sayesinde ucuz);
    böylece paket kaldırılmış/engellenmişse durum doğru yansır."""
    modules, package, extra = _DECODER_PACKAGES[enc]
    for name in modules:
        try:
            return importlib.import_module(name)
        except ImportError:
            continue
    raise MissingDecoderError(enc, package, extra)


_DECODE_ERRORS: tuple[type[BaseException], ...] = (zlib.error, ValueError, EOFError)
if _brotli is not None:
    _DECODE_ERRORS += (getattr(_brotli, "error", ValueError),)
if _zstd is not None:
    _DECODE_ERRORS += (_zstd.ZstdError,)


class _OneDecoder:
    """Tek bir kodlama için artımlı açıcı. İlk parça açılamazsa (sunucu başlıkta
    yalan söylüyor) ham veriye geçer — akışsız yolun (``_decompress``) davranışı;
    sonraki hatalar ``DecodeError`` olur."""

    def __init__(self, enc: str):
        self.enc = enc
        # zlib/brotli/zstandard açıcıları ortak bir tip paylaşmaz (brotli ``process``,
        # diğerleri ``decompress``); ``_run`` kodlamaya göre doğru yöntemi çağırır.
        self._obj: Any
        self._passthrough = False
        self._started = False
        # Bilinen ama açıcısı kurulu olmayan kodlama: ilk BOŞ OLMAYAN parçada hata
        # (gövdesiz yanıtlar -- HEAD/204/304 -- hata vermez).
        self._missing: "MissingDecoderError | None" = None
        try:
            self._obj = self._make(enc)
        except MissingDecoderError as e:
            self._obj, self._missing = None, e
            return
        if self._obj is None:
            self._passthrough = True        # bilinmeyen kodlama: olduğu gibi

    @staticmethod
    def _make(enc: str, raw_deflate: bool = False) -> Any:
        if enc in ("gzip", "x-gzip"):
            return zlib.decompressobj(zlib.MAX_WBITS | 16)
        if enc == "deflate":
            return zlib.decompressobj(-zlib.MAX_WBITS if raw_deflate else zlib.MAX_WBITS)
        if enc == "br":
            return _decoder_module("br").Decompressor()
        if enc == "zstd":
            return _decoder_module("zstd").ZstdDecompressor().decompressobj()
        return None

    def _run(self, chunk: bytes) -> bytes:
        o = self._obj
        out: bytes = o.process(chunk) if self.enc == "br" else o.decompress(chunk)
        return out

    def decode(self, chunk: bytes) -> bytes:
        if self._passthrough or not chunk:
            return chunk
        if self._missing is not None:
            m = self._missing
            raise MissingDecoderError(m.encoding, m.package, m.extra)
        first = not self._started
        self._started = True
        try:
            return self._run(chunk)
        except _DECODE_ERRORS as e:
            if first and self.enc == "deflate":
                self._obj = self._make("deflate", raw_deflate=True)   # ham deflate (RFC 1951)
                try:
                    return self._run(chunk)
                except _DECODE_ERRORS:
                    pass
            if first:
                logger.warning("Akış açılamadı (%s), ham veri döndürülüyor: %s", self.enc, e)
                self._passthrough = True
                return chunk
            raise DecodeError(f"{self.enc} gövdesi açılamadı: {e}") from e

    def flush(self) -> bytes:
        if self._passthrough or self._obj is None:
            return b""
        try:
            if self.enc == "br":
                return b""
            tail: bytes = self._obj.flush() if hasattr(self._obj, "flush") else b""
            return tail
        except _DECODE_ERRORS as e:
            logger.warning("Akış flush hatası (%s): %s", self.enc, e)
            return b""


class IncrementalDecoder:
    """``Content-Encoding`` değerini (virgüllü zincir dahil: ``"gzip, br"``) parça
    parça açar. Bilinmeyen/``identity`` kodlamalar geçirilir."""

    def __init__(self, content_encoding: str = ""):
        encs = [e.strip().lower() for e in (content_encoding or "").split(",")]
        # Uygulanma sırasının TERSİ ile açılır.
        self._chain = [_OneDecoder(e) for e in reversed(encs) if e and e != "identity"]

    @property
    def active(self) -> bool:
        return any(not d._passthrough for d in self._chain)

    def decode(self, chunk: bytes) -> bytes:
        for d in self._chain:
            chunk = d.decode(chunk)
            if not chunk:
                break
        return chunk

    def flush(self) -> bytes:
        out = b""
        for i, d in enumerate(self._chain):
            tail = d.flush()
            for d2 in self._chain[i + 1:]:
                tail = d2.decode(tail)
            out += tail
        return out


def decode_body(data: bytes, content_encoding: str) -> bytes:
    """Tüm gövdeyi açar. Akışlı yolla (:class:`IncrementalDecoder`) AYNI davranış:
    virgüllü zincirler, bozuk ilk parçada ham geçiş, eksik açıcıda
    :class:`MissingDecoderError`."""
    if not data or not content_encoding:
        return data
    d = IncrementalDecoder(content_encoding)
    return d.decode(data) + d.flush()


class LineSplitter:
    """Parça akışını satırlara böler. Satır sonu ``\\n``, ``\\r\\n`` veya ``\\r``;
    ``delimiter`` verilirse yalnızca o. Tamamlanan satırlar HEMEN döner (SSE)."""

    def __init__(self, delimiter: "bytes | None" = None):
        self._delim = delimiter
        self._pending = b""

    def feed(self, data: bytes) -> "list[bytes]":
        pending = self._pending + data if self._pending else data
        if self._delim:
            parts = pending.split(self._delim)
            self._pending = parts.pop()
            return parts
        lines = pending.splitlines(True)
        # Sonu \n ile bitmeyen son parça: eksik satır ya da \r\n'in ilk yarısı olabilir.
        if lines and not lines[-1].endswith(b"\n"):
            self._pending = lines.pop()
        else:
            self._pending = b""
        return [ln[:-2] if ln.endswith(b"\r\n") else ln[:-1] for ln in lines]

    def flush(self) -> "list[bytes]":
        rest, self._pending = self._pending, b""
        if not rest:
            return []
        if self._delim:
            return [rest]
        return [rest.rstrip(b"\r")] if rest.endswith(b"\r") else [rest]


class Rechunker:
    """Gelen parçaları ``size`` boyutlu parçalara çevirir (``None``/0: olduğu gibi)."""

    def __init__(self, size: "int | None"):
        self._size = size if size and size > 0 else None
        self._buf = bytearray()

    def feed(self, data: bytes) -> "list[bytes]":
        if self._size is None:
            return [data]
        buf, size = self._buf, self._size
        buf += data
        if len(buf) < size:
            return []
        n = len(buf) - len(buf) % size
        out = [bytes(buf[i:i + size]) for i in range(0, n, size)]
        del buf[:n]
        return out

    def flush(self) -> "list[bytes]":
        if self._size is None or not self._buf:
            return []
        out = [bytes(self._buf)]
        self._buf.clear()
        return out


class TextRechunker:
    """``Rechunker``'ın ``str`` karşılığı."""

    def __init__(self, size: "int | None"):
        self._size = size if size and size > 0 else None
        self._buf = ""

    def feed(self, text: str) -> "list[str]":
        if self._size is None:
            return [text]
        self._buf += text
        n = len(self._buf) - len(self._buf) % self._size
        out = [self._buf[i:i + self._size] for i in range(0, n, self._size)]
        self._buf = self._buf[n:]
        return out

    def flush(self) -> "list[str]":
        out, self._buf = ([self._buf] if self._buf else []), ""
        return out
