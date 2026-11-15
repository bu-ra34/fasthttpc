"""
FAZ 1 — HTTP/1.1 Parser
Yenilikler:
  - Brotli + Zstandard decompress (optional import)
  - Zero-copy ZeroCopyReader kullanımı
  - Chunked decoder iyileştirildi
"""
from __future__ import annotations
import zlib
from ..models.headers import Headers
from ..models.response import Response
from ..buffer import ZeroCopyReader
from .._log import get_logger

logger = get_logger("http1")

                              
try:
    import brotli as _brotli
    _BROTLI = True
except ImportError:
    _BROTLI = False

try:
    import zstandard as _zstd
    _ZSTD = True
    _zstd_dctx = _zstd.ZstdDecompressor()
except ImportError:
    _ZSTD = False

# Bozuk sıkıştırılmış veride beklenen hata tipleri (gerisi yukarı yükselir).
_DECOMPRESS_ERRORS: tuple = (zlib.error, ValueError, EOFError)
if _BROTLI:
    _DECOMPRESS_ERRORS += (getattr(_brotli, "error", ValueError),)
if _ZSTD:
    _DECOMPRESS_ERRORS += (_zstd.ZstdError,)


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


class HTTP1Parser:
    """Ham HTTP/1.1 bayt akışını Response nesnesine dönüştüren protokol ayrıştırıcısı."""

    @staticmethod
    def parse(raw: bytes) -> Response:
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

                              
        te = headers.get("transfer-encoding", "")
        if "chunked" in te.lower():
            body_raw = HTTP1Parser._decode_chunked(body_raw)
        else:
            cl = headers.get("content-length", "")
            if cl:
                try:
                    body_raw = body_raw[:int(cl)]
                except ValueError:
                    pass

                                                                     
        body_raw = HTTP1Parser._decompress(
            body_raw,
            headers.get("content-encoding", "").lower()
        )

        return Response(status_code=status_code, headers=headers, body=body_raw)

                                                                              

    @staticmethod
    def _decompress(data: bytes, encoding: str) -> bytes:
        if not data or not encoding:
            return data

        if "gzip" in encoding:
            try:
                return zlib.decompress(data, zlib.MAX_WBITS | 16)
            except zlib.error:
                return data

        if "deflate" in encoding:
            try:
                return zlib.decompress(data)
            except zlib.error:
                try:
                    return zlib.decompress(data, -zlib.MAX_WBITS)
                except zlib.error:
                    return data

        if "br" in encoding:
            if not _BROTLI:
                                                                         
                                                                             
                return data
            if _BROTLI:
                try:
                    return _brotli.decompress(data)
                except _DECOMPRESS_ERRORS as e:
                    logger.warning("Brotli açılamadı, ham gövde döndürülüyor: %s", e)
                    return data
                                                      
            return data

        if "zstd" in encoding:
            if not _ZSTD:
                return data
            if _ZSTD:
                try:
                    return _zstd_dctx.decompress(data)
                except _DECOMPRESS_ERRORS as e:
                    logger.warning("Zstd açılamadı, ham gövde döndürülüyor: %s", e)
                    return data
            return data

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
