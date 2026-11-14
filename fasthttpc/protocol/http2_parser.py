"""
FAZ 4 — Özellik 23+24: HTTP/2 Pasif Algılama + Frame Parser
Özellik 25: WebSocket desteği
Özellik 26: Streaming decompress + iter_content()

HTTP/2 ALPN "h2" müzakeresi tespit edilir.
Frame parser: DATA, HEADERS, SETTINGS, PING, GOAWAY, RST_STREAM, WINDOW_UPDATE
HPACK: static table decode (basit, tam HPACK için hpack kütüphanesi önerilir)
"""
from __future__ import annotations
import struct
import zlib
import socket
import threading
from enum import IntEnum
from typing import Iterator, Optional, Generator

                                        
try:
    import brotli as _brotli; _BROTLI = True
except ImportError:
    _BROTLI = False
try:
    import zstandard as _zstd; _ZSTD = True; _zstd_dctx = _zstd.ZstdDecompressor()
except ImportError:
    _ZSTD = False

from .._log import get_logger
logger = get_logger("http2")

# Bozuk sıkıştırılmış veride beklenen hata tipleri (gerisi yukarı yükselir).
_DECOMPRESS_ERRORS: tuple = (zlib.error, ValueError, EOFError)
if _BROTLI:
    _DECOMPRESS_ERRORS += (getattr(_brotli, "error", ValueError),)
if _ZSTD:
    _DECOMPRESS_ERRORS += (_zstd.ZstdError,)


                                                                               
                      
                                                                               

class FrameType(IntEnum):
    DATA          = 0x0
    HEADERS       = 0x1
    PRIORITY      = 0x2
    RST_STREAM    = 0x3
    SETTINGS      = 0x4
    PUSH_PROMISE  = 0x5
    PING          = 0x6
    GOAWAY        = 0x7
    WINDOW_UPDATE = 0x8
    CONTINUATION  = 0x9


class FrameFlags(IntEnum):
    END_STREAM  = 0x1
    END_HEADERS = 0x4
    PADDED      = 0x8
    PRIORITY    = 0x20


                                                                               
              
                                                                               

def _strip_headers_frame_fields(frame: "HTTP2Frame") -> bytes:
    """HEADERS payload'ından pad-length, padding ve priority alanlarını çıkarır.

    RFC 7540 §6.2. Sıra: [Pad Length(1, PADDED ise)] [Priority(5, PRIORITY ise)]
    [header block fragment] [Padding(PADDED ise)]. Geriye sadece header block
    fragment kalmalıdır; aksi halde HPACK decode çöp üretir.
    """
    payload = frame.payload
    pad_len = 0
    start = 0
    if frame.flags & FrameFlags.PADDED:
        if not payload:
            return b""
        pad_len = payload[0]
        start = 1
    if frame.flags & FrameFlags.PRIORITY:
        start += 5  # 4 byte stream dependency + 1 byte weight
    end = len(payload) - pad_len
    if start > end:
        # Bozuk frame; boş dön ki HPACK durumunu zehirlemeyelim.
        return b""
    return payload[start:end]


def _strip_data_frame_padding(frame: "HTTP2Frame") -> bytes:
    """DATA payload'ından pad-length ve padding'i çıkarır (RFC 7540 §6.1)."""
    payload = frame.payload
    if not (frame.flags & FrameFlags.PADDED):
        return payload
    if not payload:
        return b""
    pad_len = payload[0]
    end = len(payload) - pad_len
    if end < 1:
        return b""
    return payload[1:end]


class HTTP2Frame:
    """Tek bir HTTP/2 frame'i temsil eder."""
    __slots__ = ("length", "type", "flags", "stream_id", "payload")

    HEADER_SIZE = 9                                                      

    def __init__(self, length: int, ftype: int, flags: int, stream_id: int, payload: bytes):
        self.length    = length
        self.type      = ftype
        self.flags     = flags
        self.stream_id = stream_id
        self.payload   = payload

    @classmethod
    def parse(cls, data: bytes) -> Optional["HTTP2Frame"]:
        """9-byte header + payload'dan frame oluştur."""
        if len(data) < cls.HEADER_SIZE:
            return None
        length    = struct.unpack("!I", b"\x00" + data[0:3])[0]
        ftype     = data[3]
        flags     = data[4]
        stream_id = struct.unpack("!I", data[5:9])[0] & 0x7FFFFFFF
        payload   = data[9:9 + length]
        return cls(length, ftype, flags, stream_id, payload)

    def serialize(self) -> bytes:
        """Frame'i wire format'a çevir."""
        header = (
            struct.pack("!I", self.length)[1:]                  
            + struct.pack("!B", self.type)
            + struct.pack("!B", self.flags)
            + struct.pack("!I", self.stream_id & 0x7FFFFFFF)
        )
        return header + self.payload

    @property
    def end_stream(self) -> bool:
        return bool(self.flags & FrameFlags.END_STREAM)

    @property
    def end_headers(self) -> bool:
        return bool(self.flags & FrameFlags.END_HEADERS)

    def __repr__(self) -> str:
        try:
            name = FrameType(self.type).name
        except ValueError:
            name = f"0x{self.type:02X}"
        return f"<HTTP2Frame {name} stream={self.stream_id} len={self.length} flags=0x{self.flags:02X}>"


                                                                               
                                          
                                                                               

                                                                              
                                                                          
# RFC 7541 Appendix B Huffman decode trie (otomatik uretildi)
# Her node: (child0, child1). child = None | int(node_index) | ('L', symbol)
HPACK_HUFFMAN_TRIE = [
    (1, 22),
    (2, 9),
    (3, 6),
    (4, 5),
    (('L', 48), ('L', 49)),
    (('L', 50), ('L', 97)),
    (7, 8),
    (('L', 99), ('L', 101)),
    (('L', 105), ('L', 111)),
    (10, 15),
    (11, 12),
    (('L', 115), ('L', 116)),
    (13, 14),
    (('L', 32), ('L', 37)),
    (('L', 45), ('L', 46)),
    (16, 19),
    (17, 18),
    (('L', 47), ('L', 51)),
    (('L', 52), ('L', 53)),
    (20, 21),
    (('L', 54), ('L', 55)),
    (('L', 56), ('L', 57)),
    (23, 40),
    (24, 31),
    (25, 28),
    (26, 27),
    (('L', 61), ('L', 65)),
    (('L', 95), ('L', 98)),
    (29, 30),
    (('L', 100), ('L', 102)),
    (('L', 103), ('L', 104)),
    (32, 35),
    (33, 34),
    (('L', 108), ('L', 109)),
    (('L', 110), ('L', 112)),
    (36, 37),
    (('L', 114), ('L', 117)),
    (38, 39),
    (('L', 58), ('L', 66)),
    (('L', 67), ('L', 68)),
    (41, 56),
    (42, 49),
    (43, 46),
    (44, 45),
    (('L', 69), ('L', 70)),
    (('L', 71), ('L', 72)),
    (47, 48),
    (('L', 73), ('L', 74)),
    (('L', 75), ('L', 76)),
    (50, 53),
    (51, 52),
    (('L', 77), ('L', 78)),
    (('L', 79), ('L', 80)),
    (54, 55),
    (('L', 81), ('L', 82)),
    (('L', 83), ('L', 84)),
    (57, 64),
    (58, 61),
    (59, 60),
    (('L', 85), ('L', 86)),
    (('L', 87), ('L', 89)),
    (62, 63),
    (('L', 106), ('L', 107)),
    (('L', 113), ('L', 118)),
    (65, 68),
    (66, 67),
    (('L', 119), ('L', 120)),
    (('L', 121), ('L', 122)),
    (69, 72),
    (70, 71),
    (('L', 38), ('L', 42)),
    (('L', 44), ('L', 59)),
    (73, 74),
    (('L', 88), ('L', 90)),
    (75, 78),
    (76, 77),
    (('L', 33), ('L', 34)),
    (('L', 40), ('L', 41)),
    (79, 81),
    (('L', 63), 80),
    (('L', 39), ('L', 43)),
    (82, 84),
    (('L', 124), 83),
    (('L', 35), ('L', 62)),
    (85, 88),
    (86, 87),
    (('L', 0), ('L', 36)),
    (('L', 64), ('L', 91)),
    (89, 90),
    (('L', 93), ('L', 126)),
    (91, 92),
    (('L', 94), ('L', 125)),
    (93, 94),
    (('L', 60), ('L', 96)),
    (('L', 123), 95),
    (96, 110),
    (97, 101),
    (98, 99),
    (('L', 92), ('L', 195)),
    (('L', 208), 100),
    (('L', 128), ('L', 130)),
    (102, 105),
    (103, 104),
    (('L', 131), ('L', 162)),
    (('L', 184), ('L', 194)),
    (106, 107),
    (('L', 224), ('L', 226)),
    (108, 109),
    (('L', 153), ('L', 161)),
    (('L', 167), ('L', 172)),
    (111, 133),
    (112, 119),
    (113, 116),
    (114, 115),
    (('L', 176), ('L', 177)),
    (('L', 179), ('L', 209)),
    (117, 118),
    (('L', 216), ('L', 217)),
    (('L', 227), ('L', 229)),
    (120, 126),
    (121, 123),
    (('L', 230), 122),
    (('L', 129), ('L', 132)),
    (124, 125),
    (('L', 133), ('L', 134)),
    (('L', 136), ('L', 146)),
    (127, 130),
    (128, 129),
    (('L', 154), ('L', 156)),
    (('L', 160), ('L', 163)),
    (131, 132),
    (('L', 164), ('L', 169)),
    (('L', 170), ('L', 173)),
    (134, 153),
    (135, 142),
    (136, 139),
    (137, 138),
    (('L', 178), ('L', 181)),
    (('L', 185), ('L', 186)),
    (140, 141),
    (('L', 187), ('L', 189)),
    (('L', 190), ('L', 196)),
    (143, 146),
    (144, 145),
    (('L', 198), ('L', 228)),
    (('L', 232), ('L', 233)),
    (147, 150),
    (148, 149),
    (('L', 1), ('L', 135)),
    (('L', 137), ('L', 138)),
    (151, 152),
    (('L', 139), ('L', 140)),
    (('L', 141), ('L', 143)),
    (154, 169),
    (155, 162),
    (156, 159),
    (157, 158),
    (('L', 147), ('L', 149)),
    (('L', 150), ('L', 151)),
    (160, 161),
    (('L', 152), ('L', 155)),
    (('L', 157), ('L', 158)),
    (163, 166),
    (164, 165),
    (('L', 165), ('L', 166)),
    (('L', 168), ('L', 174)),
    (167, 168),
    (('L', 175), ('L', 180)),
    (('L', 182), ('L', 183)),
    (170, 180),
    (171, 174),
    (172, 173),
    (('L', 188), ('L', 191)),
    (('L', 197), ('L', 231)),
    (175, 177),
    (('L', 239), 176),
    (('L', 9), ('L', 142)),
    (178, 179),
    (('L', 144), ('L', 145)),
    (('L', 148), ('L', 159)),
    (181, 190),
    (182, 185),
    (183, 184),
    (('L', 171), ('L', 206)),
    (('L', 215), ('L', 225)),
    (186, 187),
    (('L', 236), ('L', 237)),
    (188, 189),
    (('L', 199), ('L', 207)),
    (('L', 234), ('L', 235)),
    (191, 207),
    (192, 199),
    (193, 196),
    (194, 195),
    (('L', 192), ('L', 193)),
    (('L', 200), ('L', 201)),
    (197, 198),
    (('L', 202), ('L', 205)),
    (('L', 210), ('L', 213)),
    (200, 203),
    (201, 202),
    (('L', 218), ('L', 219)),
    (('L', 238), ('L', 240)),
    (204, 205),
    (('L', 242), ('L', 243)),
    (('L', 255), 206),
    (('L', 203), ('L', 204)),
    (208, 223),
    (209, 216),
    (210, 213),
    (211, 212),
    (('L', 211), ('L', 212)),
    (('L', 214), ('L', 221)),
    (214, 215),
    (('L', 222), ('L', 223)),
    (('L', 241), ('L', 244)),
    (217, 220),
    (218, 219),
    (('L', 245), ('L', 246)),
    (('L', 247), ('L', 248)),
    (221, 222),
    (('L', 250), ('L', 251)),
    (('L', 252), ('L', 253)),
    (224, 238),
    (225, 231),
    (226, 228),
    (('L', 254), 227),
    (('L', 2), ('L', 3)),
    (229, 230),
    (('L', 4), ('L', 5)),
    (('L', 6), ('L', 7)),
    (232, 235),
    (233, 234),
    (('L', 8), ('L', 11)),
    (('L', 12), ('L', 14)),
    (236, 237),
    (('L', 15), ('L', 16)),
    (('L', 17), ('L', 18)),
    (239, 246),
    (240, 243),
    (241, 242),
    (('L', 19), ('L', 20)),
    (('L', 21), ('L', 23)),
    (244, 245),
    (('L', 24), ('L', 25)),
    (('L', 26), ('L', 27)),
    (247, 250),
    (248, 249),
    (('L', 28), ('L', 29)),
    (('L', 30), ('L', 31)),
    (251, 252),
    (('L', 127), ('L', 220)),
    (('L', 249), 253),
    (254, 255),
    (('L', 10), ('L', 13)),
    (('L', 22), ('L', 256)),
]


class HpackDecodingError(ValueError):
    """HPACK çözme hatası — HTTP/2 COMPRESSION_ERROR (RFC 7540 §4.3) karşılığı.

    Bağlantı-seviyesi bir hatadır: HPACK durumu artık senkron değildir, bağlantı
    yeniden kullanılmamalıdır.
    """
    error_code = 0x9  # COMPRESSION_ERROR


# HPACK güvenlik sınırları
HPACK_MAX_INT = 2 ** 32                     # integer decode üst sınırı
HPACK_MAX_HEADER_LIST_SIZE = 256 * 1024     # toplam header list boyutu (RFC 7540 §6.5.2 tanımıyla)
HPACK_DEFAULT_TABLE_SIZE = 4096             # SETTINGS_HEADER_TABLE_SIZE varsayılanı


def _hpack_huffman_decode(data: bytes) -> bytes:
    """
    RFC 7541 Appendix B Huffman kod tablosuna göre decode eder.
    HPACK_HUFFMAN_TRIE üzerinde bit-bit gezinerek çalışır. Sunucudan gelen
    header value'ları (örn. Set-Cookie) neredeyse her zaman Huffman-encoded
    gelir; bu decode edilmeden ham bit dizisi metin sanılırsa çöp veri üretilir
    (ki önceki implementasyonun hatası tam buydu).

    RFC 7541 §5.2: sondaki padding 7 bitten uzun olamaz ve EOS'un en anlamlı
    bitlerine (tamamı 1) eşit olmalıdır; aksi hâlde decoding error.
    Hata: HpackDecodingError.
    """
    out = bytearray()
    trie = HPACK_HUFFMAN_TRIE
    node = 0
    pad_bits = 0          # son sembolden beri okunan bit sayısı
    pad_all_ones = True   # bu bitlerin tamamı 1 mi
    for byte in data:
        for shift in (7, 6, 5, 4, 3, 2, 1, 0):
            bit = (byte >> shift) & 1
            child = trie[node][bit]
            if child is None:
                raise HpackDecodingError("Geçersiz Huffman kod dizisi.")
            pad_bits += 1
            pad_all_ones = pad_all_ones and bit == 1
            if isinstance(child, tuple):
                symbol = child[1]
                if symbol == 256:
                    raise HpackDecodingError("EOS sembolü veri içinde beklenmiyordu.")
                out.append(symbol)
                node = 0
                pad_bits = 0
                pad_all_ones = True
            else:
                node = child
    if pad_bits > 7:
        raise HpackDecodingError("Huffman padding 7 bitten uzun.")
    if not pad_all_ones:
        raise HpackDecodingError("Huffman padding EOS önekiyle (tümü 1) eşleşmiyor.")
    return bytes(out)


HPACK_STATIC_TABLE = [
    None,                       
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
]


class HpackDecoder:
    """
    HPACK decoder (RFC 7541) — static + dynamic table, Huffman.

    Güvenlik sınırları: integer'lar HPACK_MAX_INT ile, toplam header list
    boyutu max_header_list_size ile sınırlıdır; dynamic table size update
    ilan edilen (SETTINGS_HEADER_TABLE_SIZE) değeri aşamaz ve yalnızca blok
    başında gelebilir. Kesik/bozuk girdi HpackDecodingError fırlatır.
    """
    def __init__(self, max_table_size: int = HPACK_DEFAULT_TABLE_SIZE,
                 max_header_list_size: int = HPACK_MAX_HEADER_LIST_SIZE):
        self._dynamic: list[tuple[str, str]] = []
        self._dynamic_size = 0
        # Bizim SETTINGS ile ilan ettiğimiz üst sınır; sunucunun size update'i bunu aşamaz.
        self._max_allowed = max_table_size
        # Karşı taraf size update gönderene kadar RFC varsayılanı (4096) geçerlidir.
        self._max_size = min(max_table_size, HPACK_DEFAULT_TABLE_SIZE)
        self.max_header_list_size = max_header_list_size

    def _table_get(self, idx: int) -> tuple[str, str]:
        if 1 <= idx <= len(HPACK_STATIC_TABLE) - 1:
            return HPACK_STATIC_TABLE[idx]
        dyn_idx = idx - len(HPACK_STATIC_TABLE)
        if 0 <= dyn_idx < len(self._dynamic):
            return self._dynamic[dyn_idx]
        raise HpackDecodingError(f"Geçersiz HPACK tablo indeksi: {idx}.")

    def _evict(self) -> None:
        while self._dynamic_size > self._max_size and self._dynamic:
            n, v = self._dynamic.pop()
            self._dynamic_size -= len(n) + len(v) + 32

    def _add_dynamic(self, name: str, value: str) -> None:
        entry_size = len(name) + len(value) + 32
        if entry_size > self._max_size:
            # RFC 7541 §4.4: tablodan büyük giriş tabloyu boşaltır, eklenmez.
            self._dynamic.clear()
            self._dynamic_size = 0
            return
        self._dynamic.insert(0, (name, value))
        self._dynamic_size += entry_size
        self._evict()

    @staticmethod
    def _decode_int(data: bytes, pos: int, prefix_bits: int) -> tuple[int, int]:
        """RFC 7541 §5.1 integer; pos önek byte'ını gösterir."""
        if pos >= len(data):
            raise HpackDecodingError("HPACK integer kesik.")
        mask = (1 << prefix_bits) - 1
        value = data[pos] & mask
        pos += 1
        if value < mask:
            return value, pos
        m = 0
        while True:
            if pos >= len(data):
                raise HpackDecodingError("HPACK integer kesik (devam byte'ı eksik).")
            bb = data[pos]
            pos += 1
            value += (bb & 0x7F) << m
            m += 7
            if value > HPACK_MAX_INT:
                raise HpackDecodingError("HPACK integer üst sınırı (2^32) aşıldı.")
            if not (bb & 0x80):
                return value, pos

    def decode(self, data: bytes) -> list[tuple[str, str]]:
        """HPACK encoded bytes → (name, value) listesi. Hata: HpackDecodingError."""
        headers: list[tuple[str, str]] = []
        pos = 0
        n = len(data)
        list_size = 0
        size_update_allowed = True

        while pos < n:
            b = data[pos]

            if b & 0x80:                       # §6.1 Indexed Header Field
                idx, pos = self._decode_int(data, pos, 7)
                if idx == 0:
                    raise HpackDecodingError("Indexed header field indeksi 0 olamaz.")
                name, value = self._table_get(idx)
                add = False
            elif b & 0x40:                     # §6.2.1 Literal with Incremental Indexing
                idx, pos = self._decode_int(data, pos, 6)
                name, value, pos = self._decode_literal(data, pos, idx)
                add = True
            elif b & 0x20:                     # §6.3 Dynamic Table Size Update
                if not size_update_allowed:
                    raise HpackDecodingError(
                        "Dynamic table size update header bloğunun başında olmalı."
                    )
                new_size, pos = self._decode_int(data, pos, 5)
                if new_size > self._max_allowed:
                    raise HpackDecodingError(
                        f"Dynamic table size update ({new_size}) ilan edilen üst sınırı "
                        f"({self._max_allowed}) aşıyor."
                    )
                self._max_size = new_size
                self._evict()
                continue
            else:                              # §6.2.2 / §6.2.3 without / never indexed
                idx, pos = self._decode_int(data, pos, 4)
                name, value, pos = self._decode_literal(data, pos, idx)
                add = False

            size_update_allowed = False
            list_size += len(name) + len(value) + 32
            if list_size > self.max_header_list_size:
                raise HpackDecodingError(
                    f"Header list boyutu sınırı ({self.max_header_list_size} byte) aşıldı."
                )
            if add:
                self._add_dynamic(name, value)
            headers.append((name, value))

        return headers

    def _decode_literal(self, data: bytes, pos: int, idx: int) -> tuple[str, str, int]:
        if idx == 0:
            name, pos = self._decode_string(data, pos)
        else:
            name, _ = self._table_get(idx)
        value, pos = self._decode_string(data, pos)
        return name, value, pos

    def _decode_string(self, data: bytes, pos: int) -> tuple[str, int]:
        """Huffman veya literal string decode. Kesik veri HpackDecodingError."""
        if pos >= len(data):
            raise HpackDecodingError("HPACK string uzunluğu eksik.")
        huffman = bool(data[pos] & 0x80)
        length, pos = self._decode_int(data, pos, 7)
        if length > self.max_header_list_size:
            raise HpackDecodingError("HPACK string uzunluğu sınırı aşıyor.")
        if pos + length > len(data):
            raise HpackDecodingError(
                f"HPACK string kesik (beklenen {length}, kalan {len(data) - pos})."
            )
        raw = data[pos:pos + length]
        pos += length
        if huffman:
            raw = _hpack_huffman_decode(raw)
        return raw.decode("latin-1"), pos


                                                                               
                                           
                                                                               

class HpackEncoder:
    """
    Basit HPACK encoder — literal header encode (Huffman'sız, "never indexed" değil).
    Karşı taraf her zaman literal'i doğru okur; sıkıştırma oranı Huffman kadar
    yüksek olmasa da protokol açısından tamamen geçerlidir.
    RFC 7541 §6.2.2 (Literal Header Field without Indexing) kullanılır — basit ve güvenli.
    """
    # (name) statik tabloda birebir varsa index'ini bulmak için ad->ilk index haritası
    _NAME_INDEX = {}
    for _i, _entry in enumerate(HPACK_STATIC_TABLE):
        if _entry and _entry[0] not in _NAME_INDEX:
            _NAME_INDEX[_entry[0]] = _i

    def __init__(self):
        self._dynamic: list[tuple[str, str]] = []
        self._max_size = 4096

    @staticmethod
    def _encode_int(value: int, prefix_bits: int, prefix_val: int = 0) -> bytes:
        max_prefix = (1 << prefix_bits) - 1
        if value < max_prefix:
            return bytes([prefix_val | value])
        out = bytearray([prefix_val | max_prefix])
        value -= max_prefix
        while value >= 128:
            out.append((value % 128) + 128)
            value //= 128
        out.append(value)
        return bytes(out)

    @classmethod
    def _encode_string(cls, s: str) -> bytes:
        # latin-1: header decode tarafıyla (session.py, latin-1) simetrik —
        # orijinal byte dizisi bozulmadan geri üretilir. utf-8 kullanılırsa
        # latin-1'de decode edilmiş çok-byte karakterler (örn. 0xFC -> 'ü')
        # tekrar encode edilirken farklı bir byte dizisine döner ve bütünlük bozulur.
        try:
            raw = s.encode("latin-1")
        except UnicodeEncodeError:
            # latin-1'e sığmayan (gerçek Unicode, örn. emoji) bir str geldiyse
            # (örn. kullanıcı elle unicode bir header value verdiyse) utf-8'e düş.
            raw = s.encode("utf-8")
        # Huffman kullanmıyoruz (0x80 biti kapalı) — literal, doğrudan uyumlu.
        return cls._encode_int(len(raw), 7, 0x00) + raw

    def _add_dynamic(self, name: str, value: str) -> None:
        entry_size = len(name) + len(value) + 32
        self._dynamic.insert(0, (name, value))
        total = sum(len(n) + len(v) + 32 for n, v in self._dynamic)
        while total > self._max_size and self._dynamic:
            n, v = self._dynamic.pop()
            total -= len(n) + len(v) + 32

    def encode(self, headers: list[tuple[str, str]]) -> bytes:
        """(name, value) listesini HPACK bytes'a çevirir. Header adları küçük harf olmalı (h2 zorunluluğu)."""
        out = bytearray()
        for name, value in headers:
            name = name.lower()
            idx = self._NAME_INDEX.get(name)
            # Not: karşı taraftaki basit decoder, "literal with indexed name" alanında
            # 4-bit prefix continuation byte'ını desteklemiyor (idx <= 15 olmalı).
            # Bu yüzden 15'i aşan statik index'ler için de literal isim gönderiyoruz —
            # biraz daha fazla byte ama her decoder ile (bizimki dahil) kesin uyumlu.
            if idx and idx <= 15:
                # İsim statik tabloda var → indexed name, literal value, indexlemeden (0x00 prefix)
                out += self._encode_int(idx, 4, 0x00)
            else:
                out += bytes([0x00])       # yeni isim, indexlemeden
                out += self._encode_string(name)
            out += self._encode_string(value)
        return bytes(out)


                                                                               
                             
                                                                               

# ---------------------------------------------------------------------------
# Profil bazlı HTTP/2 parmak izi: önsöz/SETTINGS/WINDOW_UPDATE/PRIORITY,
# HEADERS (PRIORITY alanı), pseudo-header ve başlık sırası. Değerler
# fingerprint.PROFILES[...]["h2"]'den gelir; senkron ve async bağlantı AYNI
# fonksiyonları kullanır.
# ---------------------------------------------------------------------------

def _frame_bytes(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return HTTP2Frame(len(payload), ftype, flags, stream_id, payload).serialize()


def _priority_payload(dep: int, exclusive: bool, weight: int) -> bytes:
    """5 baytlık PRIORITY alanı: E+bağımlılık (4) ve ağırlık-1 (1). ``weight`` 1..256."""
    return struct.pack("!IB", (dep & 0x7FFFFFFF) | (0x80000000 if exclusive else 0), weight - 1)


def h2_for_profile(profile) -> dict:
    """Profil adı / profil sözlüğü / None -> h2 parmak izi sözlüğü."""
    from ..fingerprint import get_profile
    if isinstance(profile, dict) and "h2" in profile:
        return profile["h2"]
    return get_profile(profile)["h2"]


def build_client_preface(h2: dict) -> bytes:
    """Bağlantı ön eki + SETTINGS + (varsa) WINDOW_UPDATE + PRIORITY frame'leri.

    Chrome/Firefox/Safari bunu TEK yazımda gönderir; sıra: PRI preface,
    SETTINGS, bağlantı WINDOW_UPDATE'i, PRIORITY frame'leri.
    """
    payload = b"".join(struct.pack("!HI", i, v) for i, v in h2["settings"])
    out = HTTP2Detector.H2_PREFACE + _frame_bytes(FrameType.SETTINGS, 0, 0, payload)
    if h2.get("window_update"):
        out += _frame_bytes(FrameType.WINDOW_UPDATE, 0, 0, struct.pack("!I", h2["window_update"]))
    for sid, dep, excl, weight in h2.get("priority_frames", ()):
        out += _frame_bytes(FrameType.PRIORITY, 0, sid, _priority_payload(dep, excl, weight))
    return out


def h2_setting(h2: dict, ident: int, default: int) -> int:
    """Profilin ilan ettiği SETTINGS değeri (ilan etmiyorsa RFC varsayılanı)."""
    for i, v in h2["settings"]:
        if i == ident:
            return v
    return default


def h2_request_headers(h2: dict, method: str, authority: str, scheme: str, path: str,
                       headers: "list[tuple[str, str]]") -> "list[tuple[str, str]]":
    """Pseudo-header'lar profil sırasında, ardından başlıklar profil sırasında.

    Profildeki ``header_order``'da olan başlıklar o sırada gelir; olmayanlar
    orijinal göreli sıralarıyla SONA eklenir. Pseudo'lar her zaman öne
    (RFC 7540 §8.1.2.1).
    """
    values = {":method": method.upper(), ":authority": authority,
              ":scheme": scheme, ":path": path}
    pseudo = [(k, values[k]) for k in h2["pseudo_header_order"]]
    rest = [(k, v) for k, v in headers if not k.startswith(":")]
    order = h2.get("header_order") or []
    if order:
        rank = {name: i for i, name in enumerate(order)}
        indexed = list(enumerate(rest))
        indexed.sort(key=lambda t: (rank.get(t[1][0].lower(), len(rank)),
                                    t[0] if t[1][0].lower() not in rank else 0))
        rest = [kv for _, kv in indexed]
    return pseudo + rest


def h2_headers_priority_field(h2: dict) -> bytes:
    """HEADERS frame'inin 5 baytlık PRIORITY alanı (yoksa b"")."""
    hp = h2.get("headers_priority")
    return _priority_payload(*hp) if hp else b""



class Http2StreamError(Exception):
    """Tek bir HTTP/2 stream seviyesinde hata (RST_STREAM vb.)."""
    pass


class Http2ConnectionError(Exception):
    """Bağlantı seviyesinde HTTP/2 hatası (GOAWAY vb.)."""
    pass


class Http2RefusedError(Http2ConnectionError):
    """Sunucu isteği İŞLEMEDİ (GOAWAY last_stream_id < stream, RFC 9113 §6.8).

    İstek sunucuya hiç ulaşmamış sayılır; POST dahil yeni bir bağlantıda
    yeniden denemek güvenlidir.
    """
    pass


class Http2Connection:
    """
    Tek bir TCP/TLS bağlantısı üzerinde çalışan, gerçek istek/yanıt akışını
    yürüten minimal ama işlevsel HTTP/2 client.

    Desteklenenler:
      - Connection preface + SETTINGS alışverişi
      - HEADERS (+ CONTINUATION birleştirme) ile request gönderme
      - DATA frame'leriyle response body toplama
      - Connection + stream flow control (WINDOW_UPDATE)
      - RST_STREAM / GOAWAY hata yönetimi
      - Tek TLS bağlantısı üzerinden ardışık (sıralı) istekler — her istek
        kendi stream_id'sini alır, aynı bağlantı yeniden kullanılır.

    Desteklenmeyenler (kapsam dışı, ileride eklenebilir):
      - Gerçek eşzamanlı multiplexing (aynı anda birden fazla açık stream)
      - Sunucu PUSH_PROMISE
      - HPACK Huffman ENCODE (decode destekleniyor; gönderimde literal
        kullanılıyor — protokolde geçerli ama Chrome huffman kodladığı için
        h2 parmak izinde küçük bir sapma yaratır)
    """

    DEFAULT_WINDOW = 65535

    def __init__(self, encrypted_socket, initial_settings: Optional[dict] = None, debug: bool = False,
                 profile=None):
        """``profile``: TLS/HTTP2 profil adı (ör. "chrome_131") veya profil sözlüğü;
        SETTINGS/WINDOW_UPDATE/PRIORITY/pseudo-header sırası ondan gelir.
        None -> ``default`` profili (eski sabit davranış)."""
        self.sock = encrypted_socket
        self._h2 = h2_for_profile(profile)
        self._next_stream_id = 1
        # Dinamik tablo üst sınırı = ilan ettiğimiz SETTINGS_HEADER_TABLE_SIZE
        # (ilan edilmediyse RFC varsayılanı 4096).
        self._decoder = HpackDecoder(max_table_size=h2_setting(self._h2, 0x1, HPACK_DEFAULT_TABLE_SIZE),
                                     max_header_list_size=HPACK_MAX_HEADER_LIST_SIZE)
        self._encoder = HpackEncoder()
        self._recv_buf = bytearray()
        self._conn_window_send = self.DEFAULT_WINDOW      # bizim gönderebileceğimiz (server bize izin verdikçe artar)
        self._conn_window_recv = self.DEFAULT_WINDOW      # server'ın bize gönderebileceği (biz WINDOW_UPDATE yolladıkça artar)
        self._peer_settings = {"max_frame_size": 16384, "initial_window_size": self.DEFAULT_WINDOW}
        self._stream_windows: dict[int, int] = {}
        # GOAWAY alındıysa (last_stream_id, error_code); bağlantı artık yeni
        # stream açmak için kullanılmaz (RFC 9113 §6.8).
        self.goaway: Optional[tuple[int, int]] = None
        self._pending_frames: list[HTTP2Frame] = []
        self._lock = threading.Lock()
        self._foreign_hblock = bytearray()
        self.debug = debug or __import__("os").environ.get("FASTHTTPC_H2_DEBUG") == "1"

    def _dbg(self, msg: str) -> None:
        if self.debug:
            print(f"[H2-DEBUG] {msg}")

    # -- El sıkışma -----------------------------------------------------

    def send_preface_and_settings(self) -> None:
        """Preface + SETTINGS gönderir.

        Gönderilen SETTINGS kümesi ve sırası, HTTP/2 parmak izinin (Akamai
        "h2 fingerprint") ilk bileşenidir. ENABLE_PUSH=0 ayrıca gerekli:
        bu istemci PUSH_PROMISE işlemiyor, açık bırakmak sunucunun bize
        işleyemeyeceğimiz stream'ler açmasına yol açar.

        İçerik profilden gelir (``fingerprint.PROFILES[ad]["h2"]``): SETTINGS
        sırası/değerleri, bağlantı WINDOW_UPDATE'i ve PRIORITY frame'leri.
        Büyük INITIAL_WINDOW_SIZE ilan etmek güvenlidir: alım tarafı her DATA
        için hemen WINDOW_UPDATE döner, yani pencere hiç daralmaz.
        """
        self.sock.send_record(build_client_preface(self._h2), content_type=0x17)

    def _send_goaway(self, error_code: int) -> None:
        """En iyi çabayla GOAWAY gönderir (bağlantı zaten bozuksa hata yutulur)."""
        payload = struct.pack("!II", 0, error_code)
        try:
            self.sock.send_record(HTTP2Frame(len(payload), FrameType.GOAWAY, 0, 0, payload).serialize())
        except OSError as e:
            self._dbg(f"GOAWAY gönderilemedi: {e}")

    def _read_frame(self) -> HTTP2Frame:
        # Gövde gönderirken pencere beklerken okunmuş ama işlenmemiş frame'ler
        if self._pending_frames:
            return self._pending_frames.pop(0)
        while len(self._recv_buf) < HTTP2Frame.HEADER_SIZE:
            msg, m_type = self.sock.recv_record(skip_post_handshake=True)
            if m_type != 23:
                continue
            if not msg:
                raise Http2ConnectionError("Bağlantı beklenmedik şekilde kapandı.")
            self._recv_buf += msg

        length = struct.unpack("!I", b"\x00" + bytes(self._recv_buf[0:3]))[0]
        while len(self._recv_buf) < HTTP2Frame.HEADER_SIZE + length:
            msg, m_type = self.sock.recv_record(skip_post_handshake=True)
            if m_type != 23:
                continue
            if not msg:
                raise Http2ConnectionError("Frame gövdesi okunurken bağlantı kapandı.")
            self._recv_buf += msg

        raw = bytes(self._recv_buf[:HTTP2Frame.HEADER_SIZE + length])
        del self._recv_buf[:HTTP2Frame.HEADER_SIZE + length]
        return HTTP2Frame.parse(raw)

    def _handle_settings(self, frame: HTTP2Frame) -> None:
        if frame.flags & 0x1:          # ACK
            return
        payload = frame.payload
        for i in range(0, len(payload) - 5, 6):
            ident, value = struct.unpack("!HI", payload[i:i + 6])
            if ident == 0x4:
                self._peer_settings["initial_window_size"] = value
            elif ident == 0x5:
                self._peer_settings["max_frame_size"] = value
        # ACK dön
        ack = HTTP2Frame(0, FrameType.SETTINGS, 0x1, 0, b"")
        self.sock.send_record(ack.serialize())

    def _handle_window_update(self, frame: HTTP2Frame) -> None:
        increment = struct.unpack("!I", frame.payload[:4])[0] & 0x7FFFFFFF
        if frame.stream_id == 0:
            self._conn_window_send += increment
        else:
            # Yalnızca bilinen (şu an açık) stream'ler: bitmiş bir stream için geç
            # gelen WINDOW_UPDATE sözlüğe sonsuza dek kalacak bir girdi eklemesin.
            if frame.stream_id in self._stream_windows:
                self._stream_windows[frame.stream_id] += increment

    # -- İstek gönderme ---------------------------------------------------

    def _next_id(self) -> int:
        sid = self._next_stream_id
        self._next_stream_id += 2
        # İstekler bağlantı kilidi altında ardışık işlenir; önceki stream'ler
        # bitmiştir. Temizlenmezse uzun ömürlü bağlantıda istek başına bir
        # girdi sızar (soak testinde ~70 bayt/istek).
        self._stream_windows.clear()
        self._stream_windows[sid] = self._peer_settings["initial_window_size"]
        return sid

    def _send_headers(self, stream_id: int, headers: list[tuple[str, str]], end_stream: bool) -> None:
        block = self._encoder.encode(headers)
        max_frame = self._peer_settings.get("max_frame_size", 16384)
        prio = h2_headers_priority_field(self._h2)
        first = True
        offset = 0
        while offset < len(block) or first:
            # İlk HEADERS'ta PRIORITY alanı (5 bayt) frame yükünün parçasıdır.
            room = max_frame - (len(prio) if first else 0)
            chunk = block[offset: offset + room]
            offset += len(chunk)
            is_last = offset >= len(block)
            flags = 0
            if end_stream and is_last:
                flags |= FrameFlags.END_STREAM
            if is_last:
                flags |= FrameFlags.END_HEADERS
            if first and prio:
                flags |= FrameFlags.PRIORITY
            ftype = FrameType.HEADERS if first else FrameType.CONTINUATION
            payload = (prio + chunk) if first else chunk
            frame = HTTP2Frame(len(payload), ftype, flags, stream_id, payload)
            self.sock.send_record(frame.serialize())
            first = False
            if not block:
                break

    def _on_goaway(self, frame: "HTTP2Frame", stream_id: int) -> None:
        """GOAWAY'i işler (RFC 9113 §6.8).

        last_stream_id >= stream_id ise sunucu bu stream'i işleyecek: yanıtı
        okumaya devam edilir, bağlantı yalnızca yeniden kullanılmaz (sunucu
        bakım/boşta kapatma için error_code=NO_ERROR ile gönderir). Aksi halde
        istek işlenmedi -> Http2RefusedError (güvenle yeniden denenebilir).
        """
        p = frame.payload
        if len(p) < 8:
            raise Http2ConnectionError(f"Bozuk GOAWAY frame'i: {p!r}")
        last_sid = struct.unpack("!I", p[:4])[0] & 0x7FFFFFFF
        err = struct.unpack("!I", p[4:8])[0]
        if self.goaway is None or last_sid < self.goaway[0]:
            self.goaway = (last_sid, err)
        if stream_id > last_sid:
            raise Http2RefusedError(
                f"Sunucu GOAWAY ile bağlantıyı kapatıyor (last_stream_id={last_sid}, "
                f"error_code={err}); stream {stream_id} işlenmedi."
            )
        self._dbg(f"GOAWAY (last_stream_id={last_sid}, error={err}); stream {stream_id} tamamlanacak")

    def _await_window(self, stream_id: int, needed: int) -> None:
        """Gönderim penceresi açılana kadar sunucudan frame okur.

        Akış kontrolü YOK SAYILAMAZ: başlangıç penceresi 65535 byte'tır ve
        bundan büyük bir gövdeyi tek seferde göndermek sunucudan
        FLOW_CONTROL_ERROR / GOAWAY almakla sonuçlanır.
        """
        while min(self._conn_window_send, self._stream_windows.get(stream_id, 0)) < needed:
            frame = self._read_frame()
            if frame.type == FrameType.WINDOW_UPDATE:
                self._handle_window_update(frame)
            elif frame.type == FrameType.SETTINGS:
                self._handle_settings(frame)
            elif frame.type == FrameType.PING and not (frame.flags & 0x1):
                pong = HTTP2Frame(len(frame.payload), FrameType.PING, 0x1, 0, frame.payload)
                self.sock.send_record(pong.serialize())
            elif frame.type == FrameType.GOAWAY:
                self._on_goaway(frame, stream_id)
            elif frame.type == FrameType.RST_STREAM:
                raise Http2StreamError(f"Stream {frame.stream_id} gövde gönderilirken sıfırlandı.")
            else:
                # Yanıt bizden önce gelmeye başlamış olabilir; sonra işlenmek
                # üzere sakla (yarı-kapalı stream'de bu tamamen geçerlidir).
                self._pending_frames.append(frame)

    def _send_data(self, stream_id: int, body: bytes) -> None:
        if not body:
            frame = HTTP2Frame(0, FrameType.DATA, FrameFlags.END_STREAM, stream_id, b"")
            self.sock.send_record(frame.serialize())
            return

        max_frame = self._peer_settings.get("max_frame_size", 16384)
        offset = 0
        while offset < len(body):
            chunk = body[offset: offset + max_frame]
            self._await_window(stream_id, len(chunk))

            offset += len(chunk)
            is_last = offset >= len(body)
            flags = FrameFlags.END_STREAM if is_last else 0
            frame = HTTP2Frame(len(chunk), FrameType.DATA, flags, stream_id, chunk)
            self.sock.send_record(frame.serialize())

            self._conn_window_send -= len(chunk)
            self._stream_windows[stream_id] -= len(chunk)

    def request_stream(
        self,
        method: str,
        authority: str,
        path: str,
        headers: list[tuple[str, str]],
        body: bytes = b"",
        scheme: str = "https",
    ) -> "H2ClientStream":
        """İsteği gönderir, yanıt BAŞLIKLARI gelene kadar bekler ve gövdeyi isteğe
        bağlı (parça parça) okuyan bir :class:`H2ClientStream` döner.

        Bağlantı, akış bitene/``close()`` edilene kadar bu akışa aittir (kilit
        tutulur): bu minimal istemcide aynı anda tek stream vardır. Geri basınç:
        DATA frame'leri yalnızca tüketici ``read_chunk()`` çağırdıkça okunur ve
        WINDOW_UPDATE o anda gönderilir; okunmayan veri sınırsız tamponlanmaz.
        """
        self._lock.acquire()
        try:
            if self.goaway is not None:
                raise Http2RefusedError(
                    f"Bağlantı GOAWAY almış (last_stream_id={self.goaway[0]}); yeni stream açılmaz.")
            stream_id = self._next_id()
            self._dbg(f"--- REQUEST stream_id={stream_id} {method} {path} ---")

            # Pseudo-header ve başlık SIRASI birer parmak izidir; profilden gelir
            # (Chrome m,a,s,p; Firefox m,p,a,s; Safari m,s,a,p).
            full_headers = h2_request_headers(self._h2, method, authority, scheme, path, headers)
            self._dbg(f"giden headers: {full_headers}")

            self._send_headers(stream_id, full_headers, end_stream=(len(body) == 0))
            if body:
                self._send_data(stream_id, body)

            st = H2ClientStream(self, stream_id)
            while not st.headers_done and not st.ended:
                early = self._step(st)
                if early:
                    st._early += early
            return st
        except BaseException:
            self._lock.release()
            raise

    def request(
        self,
        method: str,
        authority: str,
        path: str,
        headers: list[tuple[str, str]],
        body: bytes = b"",
        scheme: str = "https",
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        """
        Tek bir HTTP/2 isteği gönderir ve tam yanıtı bekler.
        Döner: (status_code, header_listesi, body_bytes)
        Aynı bağlantı üzerinde ardışık çağrılabilir (her çağrı yeni stream_id alır).
        """
        st = self.request_stream(method, authority, path, headers, body, scheme)
        out = bytearray()
        try:
            while True:
                c = st.read_chunk()
                if not c:
                    break
                out += c
        except BaseException:
            st._release()
            raise
        return st.status, st.headers, bytes(out)

    _ERR_NAMES = {
        0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR",
        3: "FLOW_CONTROL_ERROR", 4: "SETTINGS_TIMEOUT", 5: "STREAM_CLOSED",
        6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM", 8: "CANCEL",
        9: "COMPRESSION_ERROR", 10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM",
        12: "INADEQUATE_SECURITY", 13: "HTTP_1_1_REQUIRED",
    }

    def _send_window_updates(self, stream_id: int, n: int, stream: bool = True) -> None:
        self.sock.send_record(HTTP2Frame(4, FrameType.WINDOW_UPDATE, 0, 0,
                                         struct.pack("!I", n)).serialize())
        if stream:
            self.sock.send_record(HTTP2Frame(4, FrameType.WINDOW_UPDATE, 0, stream_id,
                                             struct.pack("!I", n)).serialize())

    def _foreign_frame(self, frame: HTTP2Frame) -> None:
        """Bizim stream'imize ait olmayan frame (ör. CANCEL ile bırakılan eski stream).

        HPACK durumu bağlantı genelinde olduğundan başlık blokları yine de
        decode edilir; DATA'nın bağlantı penceresi geri açılır (yoksa her iptal
        bağlantı penceresini kalıcı daraltırdı)."""
        if frame.type in (FrameType.HEADERS, FrameType.CONTINUATION):
            if frame.type == FrameType.HEADERS:
                self._foreign_hblock = bytearray(_strip_headers_frame_fields(frame))
            else:
                self._foreign_hblock += frame.payload
            if frame.end_headers:
                blk, self._foreign_hblock = bytes(self._foreign_hblock), bytearray()
                try:
                    self._decoder.decode(blk)
                except HpackDecodingError as e:
                    self._send_goaway(HpackDecodingError.error_code)
                    raise Http2ConnectionError(f"COMPRESSION_ERROR: {e}") from e
        elif frame.type == FrameType.DATA and frame.payload:
            self._send_window_updates(frame.stream_id, len(frame.payload), stream=False)

    def _step(self, st: "H2ClientStream") -> bytes:
        """Bir frame okur/işler; DATA ise (padding'siz) gövde baytlarını döner."""
        frame = self._read_frame()
        self._dbg(f"gelen frame: {frame!r}")
        stream_id = st.stream_id

        if frame.stream_id != 0 and frame.stream_id != stream_id:
            self._dbg(f"  -> beklenmeyen stream_id, yutuluyor (bizim stream={stream_id})")
            self._foreign_frame(frame)
            return b""

        if frame.type == FrameType.SETTINGS:
            self._handle_settings(frame)
        elif frame.type == FrameType.WINDOW_UPDATE:
            self._handle_window_update(frame)
        elif frame.type == FrameType.PING:
            if not (frame.flags & 0x1):
                pong = HTTP2Frame(len(frame.payload), FrameType.PING, 0x1, 0, frame.payload)
                self.sock.send_record(pong.serialize())
        elif frame.type == FrameType.GOAWAY:
            self._on_goaway(frame, stream_id)
        elif frame.type == FrameType.RST_STREAM:
            err_code = struct.unpack("!I", frame.payload[:4])[0] if len(frame.payload) >= 4 else -1
            err_name = self._ERR_NAMES.get(err_code, f"UNKNOWN({err_code})")
            raise Http2StreamError(
                f"Stream {stream_id} sıfırlandı (RST_STREAM), error_code={err_code} [{err_name}]."
            )
        elif frame.type in (FrameType.HEADERS, FrameType.CONTINUATION):
            # HEADERS frame'i PADDED (0x8) ve/veya PRIORITY (0x20) flag'leri
            # taşıyabilir; bu alanlar AYIKLANMADAN HPACK'e verilirse header bloğu
            # bozulur (Cloudflare/Google kullanır). CONTINUATION'da yoktur.
            if frame.type == FrameType.HEADERS:
                st._hblock += _strip_headers_frame_fields(frame)
            else:
                st._hblock += frame.payload
            if len(st._hblock) > HPACK_MAX_HEADER_LIST_SIZE:
                self._send_goaway(0xB)  # ENHANCE_YOUR_CALM
                raise Http2ConnectionError(
                    "Sıkıştırılmış header bloğu sınırı aşıldı (HEADERS/CONTINUATION seli)."
                )
            if frame.end_headers:
                try:
                    decoded = self._decoder.decode(bytes(st._hblock))
                except HpackDecodingError as e:
                    self._send_goaway(HpackDecodingError.error_code)
                    raise Http2ConnectionError(f"COMPRESSION_ERROR: {e}") from e
                # HPACK durumu bağlantı genelinde: her blok TAM BİR KEZ decode
                # edilmeli ve tampon sıfırlanmalı (1xx ara yanıtlar, trailer'lar).
                st._hblock = bytearray()
                block_status = 0
                block_headers = []
                for k, v in decoded:
                    if k == ":status":
                        block_status = int(v)
                    else:
                        block_headers.append((k, v))
                if 100 <= block_status < 200:
                    self._dbg(f"  -> ara yanıt {block_status}, yok sayılıyor")
                elif st.headers_done:
                    st.headers.extend(block_headers)      # trailer
                else:
                    st.headers_done = True
                    st.status = block_status
                    st.headers.extend(block_headers)
            if frame.type == FrameType.HEADERS and frame.end_stream:
                st.ended = True
        elif frame.type == FrameType.DATA:
            # DATA da PADDED olabilir; pencere HAM uzunluk (padding dahil) üzerinden açılır.
            raw_len = len(frame.payload)
            data = _strip_data_frame_padding(frame)
            if frame.end_stream:
                st.ended = True
            if raw_len > 0:
                # Tüketici bu veriyi isteyince (frame ancak o zaman okunur) pencere açılır.
                self._send_window_updates(stream_id, raw_len)
            return data
        # PRIORITY, PUSH_PROMISE vb. bu minimal modelde yok sayılır
        return b""


class H2ClientStream:
    """:meth:`Http2Connection.request_stream` dönüşü: yanıt başlıkları hazır,
    gövde ``read_chunk()`` ile parça parça okunur (``b""`` = akış bitti).

    Akış bitince (ya da ``close()``/hata) bağlantı kilidi serbest kalır.
    ``close()`` bitmemiş akışı RST_STREAM(CANCEL) ile iptal eder; bağlantı yaşar.
    """

    def __init__(self, conn: Http2Connection, stream_id: int):
        self._conn = conn
        self.stream_id = stream_id
        self.status = 0
        self.headers: list[tuple[str, str]] = []
        self.headers_done = False
        self.ended = False
        self.cancelled = False
        self.broken = False           # g/ç hatası: bağlantı yeniden kullanılmamalı
        self._hblock = bytearray()
        self._early = bytearray()
        self._released = False

    def _release(self) -> None:
        if not self._released:
            self._released = True
            self._conn._lock.release()

    def read_chunk(self) -> bytes:
        if self._early:
            data, self._early = bytes(self._early), bytearray()
            return data
        try:
            while not self.ended:
                data = self._conn._step(self)
                if data:
                    return data
        except BaseException:
            self.broken = True
            self._release()
            raise
        self._release()
        return b""

    def close(self) -> None:
        """Bitmediyse stream'i iptal eder (CANCEL) ve bağlantıyı serbest bırakır."""
        if self._released:
            return
        if not self.ended:
            try:
                self._conn.sock.send_record(HTTP2Frame(
                    4, FrameType.RST_STREAM, 0, self.stream_id, struct.pack("!I", 8)).serialize())
                self.cancelled = True
            except OSError:
                self.broken = True
        self._release()


class HTTP2Detector:
    """
    ALPN müzakere sonucuna göre bağlantının HTTP/2 mi HTTP/1.1 mi
    kullandığını tespit eder.
    TLSAdapter ile entegre: negotiate() sonrası crypto_state kontrol edilir.
    """
    H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    @staticmethod
    def is_http2(crypto_state: dict) -> bool:
        """ALPN'de 'h2' müzakere edildi mi?"""
        alpn = crypto_state.get("alpn", "")
        return alpn == "h2"

    @staticmethod
    def send_preface(sock) -> None:
        """HTTP/2 client connection preface gönder."""
        sock.send_record(HTTP2Detector.H2_PREFACE)

    @staticmethod
    def build_settings_frame() -> bytes:
        """Boş SETTINGS frame (client → server)."""
        frame = HTTP2Frame(
            length=0, ftype=FrameType.SETTINGS,
            flags=0, stream_id=0, payload=b""
        )
        return frame.serialize()

    @staticmethod
    def build_settings_ack() -> bytes:
        """SETTINGS ACK frame."""
        frame = HTTP2Frame(
            length=0, ftype=FrameType.SETTINGS,
            flags=0x1, stream_id=0, payload=b""
        )
        return frame.serialize()


                                                                               
                                     
                                                                               

import base64, hashlib, os as _os

class _PlainSocketAdapter:
    """
    'ws://' (TLS'siz) bağlantılar için EncryptedSocket.send_record/recv_record
    arayüzüyle uyumlu ince sarmalayıcı — WebSocketFrame gönderim/alım kodu
    TLS olsun olmasın aynı şekilde çalışabilsin diye.
    """
    def __init__(self, raw_socket):
        self.raw_socket = raw_socket

    def send_record(self, data: bytes, content_type: int = 0x17, use_app_keys: bool = True) -> None:
        self.raw_socket.sendall(data)

    def recv_record(self, skip_post_handshake: bool = False) -> tuple[bytes, int]:
        try:
            chunk = self.raw_socket.recv(16384)
        except (OSError, socket.timeout):
            return b"", 23
        return chunk, 23                                        


class WebSocketFrame:
    """RFC 6455 WebSocket frame."""
    OP_CONTINUATION = 0x0
    OP_TEXT         = 0x1
    OP_BINARY       = 0x2
    OP_CLOSE        = 0x8
    OP_PING         = 0x9
    OP_PONG         = 0xA

    def __init__(self, opcode: int, payload: bytes, fin: bool = True, mask: bool = True):
        self.opcode  = opcode
        self.payload = payload
        self.fin     = fin
        self.mask    = mask

    def serialize(self) -> bytes:
        """Frame'i wire bytes'a çevir (client→server: maskelenmiş)."""
        b0 = (0x80 if self.fin else 0) | (self.opcode & 0x0F)
        pl = self.payload
        n  = len(pl)

        if self.mask:
            masking_key = _os.urandom(4)
            masked      = bytes(b ^ masking_key[i % 4] for i, b in enumerate(pl))
        else:
            masking_key = b""
            masked      = pl

        mask_bit = 0x80 if self.mask else 0

        if n < 126:
            header = bytes([b0, mask_bit | n])
        elif n < 65536:
            header = bytes([b0, mask_bit | 126]) + struct.pack("!H", n)
        else:
            header = bytes([b0, mask_bit | 127]) + struct.pack("!Q", n)

        return header + masking_key + masked

    @classmethod
    def parse(cls, data: bytes) -> tuple[Optional["WebSocketFrame"], int]:
        """
        Wire bytes'tan frame parse et.
        Döner: (frame, consumed_bytes) veya (None, 0) yetersiz veri ise
        """
        if len(data) < 2:
            return None, 0

        b0     = data[0]; b1 = data[1]
        fin    = bool(b0 & 0x80)
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        pl_len = b1 & 0x7F
        pos    = 2

        if pl_len == 126:
            if len(data) < pos + 2: return None, 0
            pl_len = struct.unpack("!H", data[pos:pos+2])[0]; pos += 2
        elif pl_len == 127:
            if len(data) < pos + 8: return None, 0
            pl_len = struct.unpack("!Q", data[pos:pos+8])[0]; pos += 8

        if masked:
            if len(data) < pos + 4: return None, 0
            mk  = data[pos:pos+4]; pos += 4
        else:
            mk  = b""

        if len(data) < pos + pl_len:
            return None, 0

        payload = bytes(data[pos:pos + pl_len])
        if masked:
            payload = bytes(b ^ mk[i % 4] for i, b in enumerate(payload))

        return cls(opcode, payload, fin=fin, mask=False), pos + pl_len


def _validate_ws_handshake_response(head: bytes, expected_accept: str) -> None:
    """RFC 6455 §4.1 — sunucunun Upgrade yanıtını doğrular.

    head: status satırı + header'lar (\r\n\r\n hariç). Status kodu TAM
    OLARAK 101 olmalı; Upgrade: websocket, Connection: upgrade ve doğru
    Sec-WebSocket-Accept zorunludur. Aksi hâlde ConnectionError.
    """
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1", errors="replace")
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/1.") or not parts[1].isdigit():
        raise ConnectionError(f"WebSocket Upgrade yanıtı geçersiz status satırı: {status_line[:100]!r}")
    if int(parts[1]) != 101:
        raise ConnectionError(
            f"WebSocket Upgrade başarısız: sunucu {parts[1]} döndü (101 bekleniyordu): "
            f"{status_line[:100]!r}"
        )
    hdrs: dict[str, list[str]] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        k, _, v = line.partition(b":")
        hdrs.setdefault(k.strip().lower().decode("latin-1"), []).append(
            v.strip().decode("latin-1")
        )
    if [v.lower() for v in hdrs.get("upgrade", [])] != ["websocket"]:
        raise ConnectionError("WebSocket Upgrade yanıtında 'Upgrade: websocket' yok.")
    conn_tokens = {t.strip().lower() for v in hdrs.get("connection", []) for t in v.split(",")}
    if "upgrade" not in conn_tokens:
        raise ConnectionError("WebSocket Upgrade yanıtında 'Connection: Upgrade' yok.")
    accepts = hdrs.get("sec-websocket-accept", [])
    if not accepts:
        raise ConnectionError("WebSocket Upgrade yanıtında Sec-WebSocket-Accept yok — reddedildi.")
    if len(accepts) != 1 or accepts[0] != expected_accept:
        raise ConnectionError("WebSocket Accept anahtarı hatalı — MITM şüphesi!")


class WebSocketConnection:
    """
    HTTP Upgrade → WebSocket bağlantısı.
    Senkron mesaj gönderme/alma desteği.
    """
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, conn, url: str, wire=None, session=None):
        self._conn    = conn
        self._url     = url
        self._buf     = bytearray()
        self._closed  = False
        self._session = session
        # wire: send_record/recv_record arayüzüne sahip nesne (EncryptedSocket
        # ya da _PlainSocketAdapter). Geriye dönük uyumluluk için verilmezse
        # conn.socket kullanılır (eski çağıranlar için).
        self._wire    = wire if wire is not None else conn.socket

    @classmethod
    def handshake(cls, session, url: str) -> "WebSocketConnection":
        """
        HTTP Upgrade handshake gerçekleştirir, WebSocketConnection döner.
        Hem 'wss://' (TLS üzerinden, fingerprint taklidiyle) hem 'ws://'
        (düz TCP) şemalarını destekler.
        """
        from ..models.urls import URL as FURL
        u = FURL(url) if isinstance(url, str) else url
        use_tls = u.scheme in ("wss", "https")

        key      = base64.b64encode(_os.urandom(16)).decode()
        expected = base64.b64encode(
            hashlib.sha1((key + cls.GUID).encode()).digest()
        ).decode()

        conn = session.pool.acquire(u)
        try:
            if use_tls:
                if not conn.tls_established:
                    from ..security.tls_adapter import TLSAdapter
                    conn.socket = TLSAdapter.negotiate(conn.socket, u.host, session.impersonate)
                    conn.socket.raw_socket.settimeout(session.timeout)
                    conn.tls_established = True
                wire = conn.socket
            else:
                # 'ws://' — düz TCP, TLS katmanı yok. conn.socket burada ham
                # socket.socket nesnesidir; EncryptedSocket'ın send_record/
                # recv_record arayüzüyle uyumlu ince bir sarmalayıcı kullanıyoruz
                # ki WebSocketFrame gönderim/alım kodu değişmeden çalışsın.
                conn.socket.settimeout(session.timeout)
                wire = _PlainSocketAdapter(conn.socket)

            req = (
                f"GET {u.raw_path.decode()} HTTP/1.1\r\n"
                f"Host: {u.host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n"
            )
            wire.send_record(req.encode("latin-1"))

            # Yanıt başlığını oku (101'den hemen sonra gelen frame'ler kaybolmasın).
            resp_raw = b""
            while b"\r\n\r\n" not in resp_raw:
                msg, mt = wire.recv_record(skip_post_handshake=True)
                if not msg:
                    raise ConnectionError(
                        f"WebSocket Upgrade yanıtı tamamlanmadan bağlantı kapandı: {resp_raw[:200]!r}"
                    )
                if mt == 23:
                    resp_raw += msg
                if len(resp_raw) > 65536:
                    raise ConnectionError("WebSocket Upgrade yanıt başlığı çok büyük.")

            head, _, leftover = resp_raw.partition(b"\r\n\r\n")
            _validate_ws_handshake_response(head, expected)
        except BaseException:
            # Handshake başarısız olduysa (KeyboardInterrupt dahil) bağlantıyı havuzda kilitli/yarım
            # bırakmamak için kapatıp semaphore'u serbest bırakıyoruz.
            conn.close()
            session.pool.release(conn)
            raise

        ws = cls(conn, url, wire, session=session)
        ws._buf += leftover
        return ws

    def send_text(self, text: str) -> None:
        frame = WebSocketFrame(WebSocketFrame.OP_TEXT, text.encode("utf-8"))
        self._wire.send_record(frame.serialize())

    def send_binary(self, data: bytes) -> None:
        frame = WebSocketFrame(WebSocketFrame.OP_BINARY, data)
        self._wire.send_record(frame.serialize())

    def recv(self) -> tuple[int, bytes]:
        """Tek frame oku. Döner: (opcode, payload)"""
        while True:
            frame, consumed = WebSocketFrame.parse(self._buf)
            if frame:
                del self._buf[:consumed]
                if frame.opcode == WebSocketFrame.OP_PING:
                    pong = WebSocketFrame(WebSocketFrame.OP_PONG, frame.payload)
                    self._wire.send_record(pong.serialize())
                    continue
                return frame.opcode, frame.payload

            msg, mt = self._wire.recv_record(skip_post_handshake=True)
            if mt == 23:
                self._buf += msg
            elif not msg:
                self._closed = True
                return WebSocketFrame.OP_CLOSE, b""

    def recv_text(self) -> str:
        _, payload = self.recv()
        return payload.decode("utf-8", errors="replace")

    def close(self) -> None:
        if not self._closed:
            frame = WebSocketFrame(WebSocketFrame.OP_CLOSE, struct.pack("!H", 1000))
            try:
                self._wire.send_record(frame.serialize())
            except OSError as e:  # ConnectionError dahil — karşı taraf zaten kapatmış olabilir
                logger.debug("WebSocket CLOSE frame'i gönderilemedi: %s", e)
            self._closed = True
        # WebSocket bağlantısı artık HTTP keep-alive için yeniden kullanılamaz
        # (protokol Upgrade edildi) — soketi kapatıp havuzdaki semaphore'u
        # serbest bırakıyoruz. release() olmadan bu bağlantı slotu kalıcı
        # sızar (daha önce HTTP/2 tarafında düzelttiğimiz sorunla aynı kalıp).
        self._conn.close()
        if self._session is not None:
            self._session.pool.release(self._conn)

    def __enter__(self): return self
    def __exit__(self, *a): self.close()


                                                                               
                                                         
                                                                               

class StreamingDecompressor:
    """
    Brotli + Zstandard + gzip streaming decompress.
    iter_content() ile chunk-by-chunk decode için.
    """
    def __init__(self, encoding: str):
        self._enc = encoding.lower()
        self._obj = None
        self._init_decompressor()

    def _init_decompressor(self) -> None:
        if "gzip" in self._enc:
            self._obj = zlib.decompressobj(zlib.MAX_WBITS | 16)
        elif "deflate" in self._enc:
            self._obj = zlib.decompressobj(-zlib.MAX_WBITS)
        elif "br" in self._enc and _BROTLI:
            import brotli
            self._obj = brotli.Decompressor()
        elif "zstd" in self._enc and _ZSTD:
            self._obj = _zstd.ZstdDecompressor().stream_reader(b"")
                                    

    def decompress(self, chunk: bytes) -> bytes:
        if not self._obj or not chunk:
            return chunk
        try:
            obj_type = type(self._obj).__name__
                                                      
            if obj_type == "Decompress":
                return self._obj.decompress(chunk)
                                 
            if hasattr(self._obj, 'process'):
                return self._obj.process(chunk)
                                
            if hasattr(self._obj, 'read'):
                import io
                buf = io.BytesIO(chunk)
                self._obj = _zstd.ZstdDecompressor().stream_reader(buf)
                return self._obj.read()
        except _DECOMPRESS_ERRORS as e:
            logger.warning("Akış açılamadı (%s), ham chunk döndürülüyor: %s", self._enc, e)
            return chunk
        return chunk

    def flush(self) -> bytes:
        if isinstance(self._obj, zlib.Decompress):
            try:
                return self._obj.flush()
            except zlib.error as e:
                logger.warning("Akış flush hatası (%s): %s", self._enc, e)
                return b""
        return b""


def iter_content(
    session,
    method: str,
    url: str,
    chunk_size: int = 8192,
    **kwargs,
) -> Generator[bytes, None, None]:
    """
    Büyük response'ları belleğe yüklemeden chunk'lar halinde üretir (açılmış
    gövde). ``session.request(..., stream=True)`` üzerine kuruludur: h1/h2,
    chunked/Content-Length, yönlendirme ve bağlantı havuzu aynen geçerlidir.

    Kullanım:
        for chunk in iter_content(session, "GET", "https://example.com/bigfile"):
            process(chunk)
    """
    with session.request(method, url, stream=True, **kwargs) as r:
        yield from r.iter_bytes(chunk_size)
