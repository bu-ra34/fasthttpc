"""
FAZ 1 — HTTP/1.1 Parser
Yenilikler:
  - Brotli + Zstandard decompress (optional import)
  - Zero-copy ZeroCopyReader kullanımı
  - Chunked decoder iyileştirildi
"""
from __future__ import annotations
from typing import NamedTuple
from ..models.headers import Headers
from ..models.response import Response
from ..buffer import ZeroCopyReader
from .._log import get_logger
from ..streaming import (_DECODER_PACKAGES, DEFAULT_MAX_DECOMPRESSED_SIZE, DecodeError,
                         DecompressedSizeError, MissingDecoderError, decode_body)

logger = get_logger("http1")

# brotli ve zstandard varsayılan bağımlılıklardır (PyPy'de brotli yerine brotlicffi);
# yine de kurulu değilse sıkıştırılmış gövde sessizce ham dönmez: MissingDecoderError.
try:
    import brotli as _brotli
    _BROTLI = True
except ImportError:
    try:
        import brotlicffi as _brotli
        _BROTLI = True
    except ImportError:
        _BROTLI = False

try:
    import zstandard as _zstd
    _ZSTD = True
except ImportError:
    _ZSTD = False


def _missing(enc: str) -> MissingDecoderError:
    _mods, package, extra = _DECODER_PACKAGES[enc]
    return MissingDecoderError(enc, package, extra)


_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")

#: Yanıt başlık bloğu (status satırı + başlıklar) için üst sınır. Kötü niyetli ya da
#: bozuk bir sunucu CRLFCRLF göndermeden sınırsız veri akıtarak belleği tüketemesin
#: (HTTP/2 tarafındaki HPACK_MAX_HEADER_LIST_SIZE ile aynı mertebe).
MAX_RESPONSE_HEADER_BYTES = 256 * 1024


def parse_chunk_size(line: "bytes | bytearray") -> int:
    """``chunk-size [; chunk-ext]`` satırını KATI biçimde ayrıştırır (RFC 9112 §7.1).

    Python'un ``int(x, 16)``'sı ``0x10``, ``+1``, ``-1``, ``1_0`` ve çevreleyen boşlukları da
    kabul eder; böyle gevşek ayrıştırma, aynı baytları farklı okuyan bir aracı (proxy) ile
    çerçeveleme uyuşmazlığına (response splitting / desync) zemin hazırlar. Yalnızca
    1-16 onaltılık rakam kabul edilir; aksi halde ``ValueError``.
    """
    size = bytes(line).split(b";", 1)[0].rstrip(b" \t")
    if not size or len(size) > 16 or any(c not in _HEX_DIGITS for c in size):
        raise ValueError(f"Geçersiz chunk boyutu: {bytes(line)[:20]!r}")
    return int(size, 16)


#: Yanıtta çözebildiğimiz aktarım kodlamaları (RFC 9112 §7; ``chunked`` ayrıca ele
#: alınır). ``compress``/``x-compress`` (LZW) ve kayıtlı olmayan adlar hata verir.
_TRANSFER_CODINGS = frozenset({"gzip", "x-gzip", "deflate"})
_DIGITS = frozenset("0123456789")


class BodyFraming(NamedTuple):
    """HTTP/1.1 yanıt gövdesinin çerçevelenmesi (bkz. :func:`response_framing`)."""

    #: ``"none"`` (gövde yok), ``"chunked"``, ``"length"`` ya da ``"eof"`` (kapanışa kadar).
    kind: str
    #: ``kind == "length"`` iken gövde uzunluğu.
    length: int = 0
    #: ``chunked`` dışında, gövdeye uygulanmış (açılacak) aktarım kodlamaları, uygulanma sırasıyla.
    codings: "tuple[str, ...]" = ()
    #: Yanıttan sonra bağlantı YENİDEN KULLANILMAZ (çelişkili/bozuk çerçeveleme riski).
    close: bool = False


def _framing_error(msg: str) -> ConnectionError:
    return ConnectionError(f"Yanıt çerçevelemesi geçersiz: {msg}")


def response_framing(method: str, status: int, headers: Headers,
                     http10: bool = False) -> BodyFraming:
    """Yanıt gövdesinin uzunluğu, RFC 9112 §6.1-6.3'e harfiyen uyarak.

    * HEAD, 1xx, 204, 304 -> gövde yok (diğer başlıklara bakılmaz).
    * ``Transfer-Encoding`` varsa ``Content-Length``'i GEÇERSİZ KILAR (§6.3 madde 3).
      İkisi birlikte gelmişse yanıt işlenir ama bağlantı yeniden kullanılmaz: bu ikili
      request smuggling / response splitting işareti olabilir; bağlantıda kalan baytlar
      bir sonraki yanıt sanılmamalı. Son kodlama ``chunked`` ise chunked okunur; değilse
      gövde bağlantı kapanana kadar okunur (§6.3 madde 4). ``chunked``'dan SONRA başka
      kodlama ya da bilinmeyen kodlama -> hata.
    * HTTP/1.0 yanıtında ``Transfer-Encoding``: çerçeveleme bozuk sayılır (§6.1);
      ``Content-Length`` dahil güvenilmez, gövde kapanışa kadar okunur, bağlantı kapatılır.
    * ``Content-Length`` (TE yoksa): virgüllü liste ve tekrarlanan satırlar, hepsi aynı
      geçerli değerse kabul edilir (``5, 5``); farklı değerler ya da geçersiz değer
      kurtarılamaz çerçeveleme hatasıdır (§6.3 madde 5) -> :class:`ConnectionError`.
    * Hiçbiri yoksa gövde kapanışa kadar okunur (§6.3 madde 8).
    """
    if method.upper() == "HEAD" or status in (204, 304) or 100 <= status < 200:
        return BodyFraming("none")
    te_values = headers.get_list("transfer-encoding")
    cl_values = headers.get_list("content-length")
    if te_values:
        if http10:
            return BodyFraming("eof", close=True)
        codings = [c.split(";", 1)[0].strip().lower()
                   for v in te_values for c in v.split(",")]
        codings = [c for c in codings if c and c != "identity"]   # identity: eski no-op
        for c in codings:
            if c != "chunked" and c not in _TRANSFER_CODINGS:
                raise _framing_error(f"desteklenmeyen Transfer-Encoding {c!r}.")
        chunked = "chunked" in codings
        if chunked:
            first = codings.index("chunked")
            # Yinelenen "chunked" (aynı başlığın iki satırı) tek sayılır; chunked'dan
            # sonra uygulanmış başka bir kodlama çerçevelemeyi anlamsız kılar (curl de reddeder).
            if any(c != "chunked" for c in codings[first:]):
                raise _framing_error("'chunked' son aktarım kodlaması değil.")
        others = tuple(c for c in codings if c != "chunked")
        return BodyFraming("chunked" if chunked else "eof", codings=others,
                           close=bool(cl_values) or not chunked)
    if not cl_values:
        return BodyFraming("eof")
    lengths = set()
    for v in cl_values:
        for item in v.split(","):
            item = item.strip()
            if not item:
                continue
            if not set(item) <= _DIGITS or len(item) > 19:
                raise _framing_error(f"geçersiz Content-Length {v!r}.")
            lengths.add(int(item))
    if len(lengths) != 1:
        raise _framing_error(
            f"birbiriyle çelişen ya da boş Content-Length değerleri {cl_values!r}.")
    return BodyFraming("length", length=lengths.pop())


class HTTP1Parser:
    """Ham HTTP/1.1 bayt akışını Response nesnesine dönüştüren protokol ayrıştırıcısı."""

    @staticmethod
    def parse(raw: bytes, max_decompressed_size: "int | None" = DEFAULT_MAX_DECOMPRESSED_SIZE,
              method: str = "GET") -> Response:
        """Tam bir yanıtı (bellekteki ham baytlar) ayrıştırır. Çerçeveleme
        :func:`response_framing` ile (RFC 9112 §6.3); geçersiz çerçevelemede
        :class:`ConnectionError`."""
        reader = ZeroCopyReader(raw)

                               
        sep = reader.find(b"\r\n\r\n")
        if sep == -1:
            header_raw = bytes(reader.peek(len(raw)))
            body_raw   = b""
        else:
            header_raw = bytes(reader.read(sep))
            reader.skip(4)                                        
            body_raw   = bytes(reader.read(reader.remaining))

        lines = header_raw.split(b"\r\n")
        if not lines or not lines[0]:
            return Response(status_code=0, body=b"")

                         
        status_code = 0
        try:
            parts = lines[0].decode("ascii", errors="ignore").split(" ", 2)
            if len(parts) >= 2:
                status_code = int(parts[1])
        except (IndexError, ValueError):
            pass

                                                              
        headers = Headers()
        for line in lines[1:]:
            if b":" not in line:
                continue
            k, _, v = line.partition(b":")
            headers._list.append((k.strip(), k.strip().lower(), v.strip()))

                              
        framing = response_framing(method, status_code, headers,
                                   http10=lines[0].upper().startswith(b"HTTP/1.0"))
        if framing.kind == "none":
            body_raw = b""
        elif framing.kind == "chunked":
            body_raw = HTTP1Parser._decode_chunked(body_raw)
        elif framing.kind == "length":
            body_raw = body_raw[:framing.length]
        if framing.codings:          # aktarım kodlaması (gzip/deflate): aynı sınırla açılır
            body_raw = decode_body(body_raw, ", ".join(framing.codings), max_decompressed_size,
                                   strict=True)

        body_raw = HTTP1Parser._decompress(
            body_raw,
            headers.get("content-encoding", "").lower(),
            max_decompressed_size,
        )

        return Response(status_code=status_code, headers=headers, body=body_raw)

                                                                              

    _DECODER_NAMES = {"gzip": "Gzip", "deflate": "Deflate", "br": "Brotli", "zstd": "Zstd"}

    @staticmethod
    def _decompress(data: bytes, encoding: str,
                    max_size: "int | None" = DEFAULT_MAX_DECOMPRESSED_SIZE) -> bytes:
        """Tek kodlamayı (gzip > deflate > br > zstd önceliğiyle) açar; açılamazsa ham
        gövde döner. Açma artımlıdır ve ``max_size`` aşılınca
        :class:`~fasthttpc.streaming.DecompressedSizeError` yükselir (FHC-07)."""
        if not data or not encoding:
            return data
        enc = next((e for e in ("gzip", "deflate", "br", "zstd") if e in encoding), None)
        if enc is None:
            return data
        if enc == "br" and not _BROTLI:
            raise _missing("br")      # ham (sıkıştırılmış) gövde sessizce dönmez
        if enc == "zstd" and not _ZSTD:
            raise _missing("zstd")
        try:
            return decode_body(data, enc, max_size, strict=True)
        except (DecompressedSizeError, MissingDecoderError):
            raise
        except DecodeError as e:
            logger.warning("%s açılamadı, ham gövde döndürülüyor: %s",
                           HTTP1Parser._DECODER_NAMES[enc], e)
            return data

                                                                              

    @staticmethod
    def _decode_chunked(data: bytes) -> bytes:
        result = bytearray()
        reader = ZeroCopyReader(data)

        while reader.remaining > 0:
                                
            nl = reader.find(b"\r\n")
            if nl == -1:
                break
            size_line = bytes(reader.read(nl - reader.pos))
            reader.skip(2)        

                                            
            try:
                chunk_size = parse_chunk_size(size_line)
            except ValueError:
                break

            if chunk_size == 0:
                break

            result += reader.read(chunk_size)
            reader.skip(2)                 

        return bytes(result)

                                                                              

    @staticmethod
    def supported_encodings() -> str:
        """
        Kurulu kütüphanelere göre Accept-Encoding header değeri üretir.
        Sadece decode edebildiğimiz encoding'leri reklam ederiz —
        aksi hâlde sunucu decode edemediğimiz bir format gönderir.
        """
        encodings = ["gzip", "deflate"]
        if _BROTLI:
            encodings.insert(0, "br")
        if _ZSTD:
            encodings.insert(0, "zstd")
        return ", ".join(encodings)
