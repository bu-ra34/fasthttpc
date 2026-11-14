"""
fasthttpc — akış (streaming) yanıt yardımcıları

Senkron ve async yanıt akışlarının ortak parçaları: artımlı Content-Encoding
açıcı, satır bölücü, sabit boyutlu parça birleştirici ve akış hataları.
G/Ç yok; yalnızca bayt -> bayt dönüşümleri vardır.
"""
from __future__ import annotations

import zlib

from ._log import get_logger

logger = get_logger("streaming")

try:  # opsiyonel bağımlılıklar (http1_parser ile aynı)
    import brotli as _brotli
except ImportError:  # pragma: no cover
    _brotli = None
try:
    import zstandard as _zstd
except ImportError:  # pragma: no cover
    _zstd = None


class StreamConsumed(RuntimeError):
    """Akış gövdesi zaten tüketildi (bir kez okunabilir; ``content`` önbelleğe alınmadıysa)."""


class StreamClosed(RuntimeError):
    """Gövde okunmadan yanıt kapatıldı; artık okunamaz."""


class ResponseNotRead(RuntimeError):
    """Akış yanıtında gövde henüz okunmadı: ``await r.aread()`` ya da ``iter_*`` kullanın."""


class DecodeError(ValueError):
    """Akış ortasında Content-Encoding açılamadı (bozuk sıkıştırılmış veri)."""


_DECODE_ERRORS: tuple = (zlib.error, ValueError, EOFError)
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
        self._passthrough = False
        self._started = False
        self._obj = self._make(enc)
        if self._obj is None:
            self._passthrough = True

    @staticmethod
    def _make(enc: str, raw_deflate: bool = False):
        if enc in ("gzip", "x-gzip"):
            return zlib.decompressobj(zlib.MAX_WBITS | 16)
        if enc == "deflate":
            return zlib.decompressobj(-zlib.MAX_WBITS if raw_deflate else zlib.MAX_WBITS)
        if enc == "br" and _brotli is not None:
            return _brotli.Decompressor()
        if enc == "zstd" and _zstd is not None:
            return _zstd.ZstdDecompressor().decompressobj()
        return None

    def _run(self, chunk: bytes) -> bytes:
        o = self._obj
        if self.enc == "br":
            return o.process(chunk)
        return o.decompress(chunk)

    def decode(self, chunk: bytes) -> bytes:
        if self._passthrough or not chunk:
            return chunk
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
            return self._obj.flush() if hasattr(self._obj, "flush") else b""
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
        self._buf = bytearray() if self._size else None

    def feed(self, data):
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

    def flush(self):
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

    def feed(self, text: str):
        if self._size is None:
            return [text]
        self._buf += text
        n = len(self._buf) - len(self._buf) % self._size
        out = [self._buf[i:i + self._size] for i in range(0, n, self._size)]
        self._buf = self._buf[n:]
        return out

    def flush(self):
        out, self._buf = ([self._buf] if self._buf else []), ""
        return out
