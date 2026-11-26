"""
fasthttpc — akış (streaming) yanıt yardımcıları

Senkron ve async yanıt akışlarının ortak parçaları: artımlı Content-Encoding
açıcı, satır bölücü, sabit boyutlu parça birleştirici ve akış hataları.
G/Ç yok; yalnızca bayt -> bayt dönüşümleri vardır.
"""
from __future__ import annotations

import importlib
import itertools
import zlib
from collections import deque
from types import ModuleType
from typing import Any, Iterator

from ._log import get_logger

logger = get_logger("streaming")

#: ``Limits.max_decompressed_size`` varsayılanı (256 MiB): açılmış (Content-Encoding
#: çözülmüş) gövde için üst sınır. Sıradan bir HTML/JSON yanıtının binlerce katı; ama
#: akışsız yanıtta gövde tek bir ``bytes`` olarak bellekte durduğundan GB mertebesindeki
#: bir değer, ~1 MB'lık gzip (ya da ~100 baytlık brotli) bombasının tipik bir kapsayıcının
#: belleğini bitirmesine izin verirdi. Bkz. docs/timeouts-limits-retries.md.
DEFAULT_MAX_DECOMPRESSED_SIZE = 256 * 1024 * 1024

#: Bir açıcının tek adımda ürettiği en büyük parça (brotli tampon büyümesi yüzünden en
#: çok ~1.5 katı). Akışta verilen her açılmış parça bununla sınırlıdır.
_PIECE = 64 * 1024
#: Açıcıya tek seferde verilen girdi dilimi: zlib/brotli tüketilmeyen girdiyi her
#: çağrıda kopyalar (``unconsumed_tail``); dilim bu kopyayı sınırlar.
_IN_SLICE = 64 * 1024
#: zstd'de ``max_length`` yok: çıktı geri çağırmada parça parça gelir ve sınır orada
#: denetlenir. Girdi küçük dilimlerle verilir ki tek adımın çıktısı birkaç MiB'ı geçmesin
#: (bir blok en çok 128 KiB'a açılır ve en az 4 bayttır).
_ZSTD_SLICE = 256
#: brotli < 1.2 (``output_buffer_limit`` yok) için girdi dilimi (yedek yol).
_BR_LEGACY_SLICE = 32
#: Content-Encoding zincirinde en fazla bu kadar kodlama açılır (urllib3 ile aynı).
MAX_CONTENT_CODINGS = 5

_KNOWN_CODINGS = frozenset({"gzip", "x-gzip", "deflate", "br", "zstd"})


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


class DecompressedSizeError(DecodeError):
    """Açılmış yanıt gövdesi ``Limits.max_decompressed_size`` sınırını aştı.

    Sıkıştırma bombasına karşı koruma: küçük bir gzip/deflate/br/zstd gövdesi
    gigabaytlarca veriye açılabilir. Açma artımlıdır ve sınır aşıldığı anda bu hata
    yükselir (``stream=True`` iken de, toplam açılmış bayt üzerinden); gövde ASLA
    sessizce kısaltılmaz. Öznitelikler: ``limit`` (bayt) ve ``encoding`` (sınırı aşan
    kodlama, ör. ``"gzip"``). Büyük sıkıştırılmış gövde bekleniyorsa
    ``Limits(max_decompressed_size=...)`` ile sınır artırılır ya da ``None`` ile kapatılır.
    """

    def __init__(self, limit: int, encoding: str):
        self.limit = limit
        self.encoding = encoding
        super().__init__(
            f"Açılmış yanıt gövdesi {limit} bayt sınırını aşıyor ('{encoding}' kodlaması; olası "
            f"sıkıştırma bombası). Büyük sıkıştırılmış gövde bekleniyorsa "
            f"Limits(max_decompressed_size=...) ile sınırı artırın ya da None verin.")

    def __reduce__(self) -> "tuple[type[DecompressedSizeError], tuple[int, str]]":
        return (DecompressedSizeError, (self.limit, self.encoding))


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


class _ZstdSink:
    """zstd ``stream_writer`` çıktısını parça parça (en çok ``_PIECE``) alır ve her
    parçada sınırı denetler: ``zstandard``'ın açıcısında ``max_length`` yoktur."""

    __slots__ = ("_dec",)

    def __init__(self, dec: "_OneDecoder"):
        self._dec = dec

    def write(self, data: bytes) -> int:
        self._dec._emit(bytes(data))
        return len(data)


class _OneDecoder:
    """Tek bir kodlama için artımlı ve ÇIKTISI SINIRLI açıcı.

    ``feed(veri)`` girdiyi alır; ``read()`` sıradaki açılmış parçayı (en çok ~``_PIECE``
    bayt) ya da yeni girdi gerektiğinde ``b""`` döner. Açıcılar çıktı sınırıyla
    çağrılır (zlib ``max_length``, brotli ``output_buffer_limit``, zstd küçük girdi
    dilimleri + parça geri çağırması); bellek, sınır denetiminden önce büyümez. Toplam
    çıktı ``max_size``'ı aşarsa :class:`DecompressedSizeError`. Bütün durum nesnededir:
    tüketici yarıda bırakıp sonra devam ederse veri kaybolmaz.

    İlk parça hiç çıktı üretmeden açılamazsa (sunucu başlıkta yalan söylüyor) ham veriye
    geçer -- akışsız yolun eski davranışı; ``strict=True`` iken bu da ``DecodeError``
    olur. Sonraki hatalar her zaman ``DecodeError``'dır.
    """

    def __init__(self, enc: str, max_size: "int | None" = None, strict: bool = False):
        self.enc = enc
        self._limit = max_size
        self._strict = strict
        self._total = 0                     # üretilen (açılmış) bayt
        self._out: "deque[bytes]" = deque()  # verilmeyi bekleyen parçalar
        self._buf = b""                     # açıcıya henüz verilmemiş girdi
        self._pos = 0
        self._tail = b""                    # zlib: unconsumed_tail
        self._more = False                  # açıcıda bekleyen çıktı olabilir (sınıra takıldı)
        self._fed = 0                       # verilen (boş olmayan) parça sayısı
        self._first = b""                   # ilk parça (ham geçiş için)
        self._raw_retry = False
        # zlib/brotli/zstandard açıcıları ortak bir tip paylaşmaz; ``_step`` kodlamaya
        # göre doğru yöntemi çağırır.
        self._obj: Any = None
        self._passthrough = False
        self._br_bounded = False
        # Bilinen ama açıcısı kurulu olmayan kodlama: ilk BOŞ OLMAYAN parçada hata
        # (gövdesiz yanıtlar -- HEAD/204/304 -- hata vermez).
        self._missing: "MissingDecoderError | None" = None
        if enc not in _KNOWN_CODINGS:
            self._passthrough = True        # bilinmeyen kodlama: olduğu gibi
            return
        try:
            self._obj = self._make(enc)
        except MissingDecoderError as e:
            self._missing = e
            return
        # brotli >= 1.2 / brotlicffi >= 1.2: process(..., output_buffer_limit=...)
        self._br_bounded = enc == "br" and hasattr(self._obj, "can_accept_more_data")

    def _make(self, enc: str, raw_deflate: bool = False) -> Any:
        if enc in ("gzip", "x-gzip"):
            return zlib.decompressobj(zlib.MAX_WBITS | 16)
        if enc == "deflate":
            return zlib.decompressobj(-zlib.MAX_WBITS if raw_deflate else zlib.MAX_WBITS)
        if enc == "br":
            return _decoder_module("br").Decompressor()
        # zstd: çerçeve başlığında içerik boyutu olmayan (akış sıkıştırıcısıyla üretilmiş)
        # gövdeler ve art arda çerçeveler de açılır (RFC 8878 §3.1).
        return _decoder_module("zstd").ZstdDecompressor().stream_writer(
            _ZstdSink(self), write_size=_PIECE, closefd=False)

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        if self._passthrough:
            self._out.append(chunk)
            return
        if self._missing is not None:
            m = self._missing
            raise MissingDecoderError(m.encoding, m.package, m.extra)
        self._fed += 1
        if self._fed == 1:
            self._first = chunk
        else:
            self._first = b""
        if self._pos < len(self._buf):      # tüketici yarıda bıraktı: kalan girdi önce
            chunk = self._buf[self._pos:] + chunk
        self._buf, self._pos = chunk, 0

    def read(self) -> bytes:
        """Sıradaki açılmış parça (boş değil); ``b""`` -> yeni girdi gerekiyor."""
        while not self._out:
            if not (self._more or self._tail or self._pos < len(self._buf)):
                return b""
            try:
                self._step()
            except DecodeError:
                raise
            except _DECODE_ERRORS as e:
                self._failed(e)
        return self._out.popleft()

    def finish(self) -> None:
        """Girdi bitti (``read()`` ``b""`` döndükten sonra): açıcıda kalan çıktı sıraya."""
        if self._passthrough or self._obj is None or self.enc not in ("gzip", "x-gzip", "deflate"):
            return
        try:
            self._emit(self._obj.flush())
        except DecodeError:
            raise
        except _DECODE_ERRORS as e:
            logger.warning("Akış flush hatası (%s): %s", self.enc, e)

    def _take(self, n: int) -> bytes:
        b, p = self._buf, self._pos
        if p == 0 and len(b) <= n:
            self._buf = b""
            return b
        piece = b[p:p + n]
        self._pos = p + len(piece)
        if self._pos >= len(b):
            self._buf, self._pos = b"", 0
        return piece

    def _step(self) -> None:
        o = self._obj
        if self.enc == "zstd":
            o.write(self._take(_ZSTD_SLICE))      # çıktı _ZstdSink -> _emit
            return
        if self.enc == "br":
            if not self._br_bounded:               # brotli < 1.2: yalnızca girdi dilimi
                self._emit(o.process(self._take(_BR_LEGACY_SLICE)))
                return
            # Sınıra takılınca (çıktı >= _PIECE ya da tüketilmemiş girdi) yeni girdi
            # verilmeden boş girdiyle devam edilir (brotli 1.2 API sözleşmesi).
            data = b"" if self._more else self._take(_IN_SLICE)
            out: bytes = o.process(data, output_buffer_limit=_PIECE)
            self._more = len(out) >= _PIECE or not o.can_accept_more_data()
            if not out and not data:
                self._more = False                 # ilerleme yok: döngüye girme
            self._emit(out)
            return
        data = self._tail if (self._tail or self._more) else self._take(_IN_SLICE)
        out = o.decompress(data, _PIECE)
        self._tail = o.unconsumed_tail
        self._more = len(out) >= _PIECE
        self._emit(out)

    def _emit(self, out: bytes) -> None:
        if not out:
            return
        self._total += len(out)
        if self._limit is not None and self._total > self._limit:
            raise DecompressedSizeError(self._limit, self.enc)
        self._out.append(out)

    def _failed(self, e: BaseException) -> None:
        if self._fed == 1 and self._total == 0:
            if self.enc == "deflate" and not self._raw_retry:
                # zlib sarmalı yok: ham deflate (RFC 1951) dene
                self._raw_retry = True
                self._obj = self._make("deflate", raw_deflate=True)
                self._buf, self._pos, self._tail, self._more = self._first, 0, b"", False
                return
            if not self._strict:
                logger.warning("Akış açılamadı (%s), ham veri döndürülüyor: %s", self.enc, e)
                self._passthrough = True
                self._out.append(self._first)
                self._buf, self._pos, self._tail, self._more = b"", 0, b"", False
                self._first = b""
                return
        raise DecodeError(f"{self.enc} gövdesi açılamadı: {e}") from e


class IncrementalDecoder:
    """``Content-Encoding`` değerini (virgüllü zincir dahil: ``"gzip, br"``) parça
    parça açar. Bilinmeyen/``identity`` kodlamalar geçirilir.

    Her açılmış parça en çok ~64 KiB'tır ve zincirin her aşamasının toplam çıktısı
    ``max_size`` bayt ile sınırlıdır (``None``: sınırsız); aşılınca
    :class:`DecompressedSizeError`. ``decode_iter``/``flush_iter`` parçaları tembel
    üretir (akış yolu); ``decode``/``flush`` aynı çıktıyı tek ``bytes`` olarak döner.
    """

    def __init__(self, content_encoding: str = "",
                 max_size: "int | None" = DEFAULT_MAX_DECOMPRESSED_SIZE, *, strict: bool = False):
        encs = [e.strip().lower() for e in (content_encoding or "").split(",")]
        encs = [e for e in encs if e and e != "identity"]
        # Her açıcı kendi penceresini ayırır (brotli 16 MiB'a kadar): kodlama sayısı sınırlı.
        self._too_many = sum(e in _KNOWN_CODINGS for e in encs) > MAX_CONTENT_CODINGS
        # Uygulanma sırasının TERSİ ile açılır.
        self._chain = [] if self._too_many else [
            _OneDecoder(e, max_size, strict) for e in reversed(encs)]

    @property
    def active(self) -> bool:
        return self._too_many or any(not d._passthrough for d in self._chain)

    def _pull(self, i: int) -> bytes:
        """``i``. aşamanın sıradaki parçası; gerekirse önceki aşamadan çekip besler."""
        d = self._chain[i]
        while True:
            out = d.read()
            if out or i == 0:
                return out
            up = self._pull(i - 1)
            if not up:
                return b""
            d.feed(up)

    def _drain(self) -> Iterator[bytes]:
        last = len(self._chain) - 1
        while last >= 0:
            out = self._pull(last)
            if not out:
                return
            yield out

    def decode_iter(self, chunk: bytes) -> Iterator[bytes]:
        """``chunk``'ı açar; açılmış parçaları (boş parça yok) tembel üretir."""
        if chunk and self._too_many:
            raise DecodeError(
                f"Content-Encoding zinciri {MAX_CONTENT_CODINGS} kodlamadan uzun; reddedildi.")
        if not self._chain:
            if chunk:
                yield chunk
            return
        self._chain[0].feed(chunk)
        yield from self._drain()

    def flush_iter(self) -> Iterator[bytes]:
        """Girdi bitti: her aşamada kalan çıktıyı sırayla verir."""
        for d in self._chain:
            yield from self._drain()
            d.finish()
        yield from self._drain()

    def decode(self, chunk: bytes) -> bytes:
        return b"".join(self.decode_iter(chunk))

    def flush(self) -> bytes:
        return b"".join(self.flush_iter())


def decode_body(data: bytes, content_encoding: str,
                max_size: "int | None" = DEFAULT_MAX_DECOMPRESSED_SIZE, *,
                strict: bool = False) -> bytes:
    """Tüm gövdeyi açar. Akışlı yolla (:class:`IncrementalDecoder`) AYNI davranış:
    virgüllü zincirler, bozuk ilk parçada ham geçiş (``strict=False``), eksik açıcıda
    :class:`MissingDecoderError`, ``max_size`` aşılınca :class:`DecompressedSizeError`
    (açma artımlıdır: sınırı aşan çıktı hiçbir zaman belleğe alınmaz)."""
    if not data or not content_encoding:
        return data
    d = IncrementalDecoder(content_encoding, max_size, strict=strict)
    return b"".join(itertools.chain(d.decode_iter(data), d.flush_iter()))


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
