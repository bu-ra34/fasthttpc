"""
FAZ 4 — Özellik 23+24: HTTP/2 Pasif Algılama + Frame Parser
Özellik 25: WebSocket desteği
Özellik 26: Streaming decompress + iter_content()

HTTP/2 ALPN "h2" müzakeresi tespit edilir.
Frame parser: DATA, HEADERS, SETTINGS, PING, GOAWAY, RST_STREAM, WINDOW_UPDATE
HPACK: tam çözücü (statik + dinamik tablo, Huffman) ve tarayıcıya özgü kodlayıcı
(HpackPolicy: Huffman, dinamik tablo, cookie parçalama, tablo boyutu güncellemesi)
"""
from __future__ import annotations
import collections
import functools
import struct
import socket
import time
import threading
from dataclasses import dataclass
from enum import IntEnum
from typing import Iterable, Iterator, Optional, Generator

from .._log import get_logger
from ..transport.iotimeout import (IOTimeouts, is_attributed, send_all, total_timeout_error,
                                  write_timeout_error)
# Content-Encoding açma tek yerde: fasthttpc.streaming (çıktısı sınırlı açıcı, FHC-07).
from ..streaming import DEFAULT_MAX_DECOMPRESSED_SIZE, IncrementalDecoder
logger = get_logger("http2")


                                                                               
                      
                                                                               

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


# ---------------------------------------------------------------------------
# RFC 7541 Appendix B — Huffman KODLAMA tablosu. Ayrı bir kopya tutulmaz: decode
# trie'sinden türetilir (sembol -> (kod, bit uzunluğu)). tests/test_hpack_kodlayici.py
# tabloyu RFC metninden aktarılmış Appendix B tablosuyla ve ``hpack`` paketinin
# tablosuyla 257 sembolün tamamında birebir karşılaştırır.
# ---------------------------------------------------------------------------

def _huffman_codes_from_trie(trie: list) -> "list[tuple[int, int]]":
    codes: "list[tuple[int, int]]" = [(0, 0)] * 257
    stack = [(0, 0, 0)]                      # (düğüm, kod, uzunluk)
    while stack:
        node, code, length = stack.pop()
        for bit in (0, 1):
            child = trie[node][bit]
            if child is None:
                continue
            c, n = (code << 1) | bit, length + 1
            if isinstance(child, tuple):
                codes[child[1]] = (c, n)
            else:
                stack.append((child, c, n))
    return codes


#: Sembol (0..255, 256 = EOS) -> (kod, bit uzunluğu); RFC 7541 Appendix B.
HPACK_HUFFMAN_CODES: "list[tuple[int, int]]" = _huffman_codes_from_trie(HPACK_HUFFMAN_TRIE)
# Tablo güdümlü kodlama: bayt başına kodun bit dizisi ('0'/'1' metni) ve uzunluk
# tablosu. Bit bit Python döngüsü yok: birleştirme (str.join + map), sayma
# (bytes.translate + sum) ve ikiliden bayta çevirme (int(.., 2).to_bytes) C'de.
_HUFF_BITS: "list[str]" = [format(c, "0%db" % n) for c, n in HPACK_HUFFMAN_CODES[:256]]
_HUFF_LEN_TABLE = bytes(n for _, n in HPACK_HUFFMAN_CODES[:256])   # bytes.translate tablosu


def hpack_huffman_size(data: bytes) -> int:
    """``data``'nın Huffman kodlu uzunluğu (bayt; QUICHE ``HuffmanSize`` karşılığı)."""
    return (sum(data.translate(_HUFF_LEN_TABLE)) + 7) >> 3


def hpack_huffman_encode(data: bytes) -> bytes:
    """RFC 7541 §5.2 Huffman kodlama; son bayt EOS'un en anlamlı bitleriyle (1) doldurulur."""
    if not data:
        return b""
    bits = "".join(map(_HUFF_BITS.__getitem__, data))
    n = len(bits)
    pad = -n % 8
    return int(bits + "1" * pad, 2).to_bytes((n + pad) >> 3, "big")


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


# ---------------------------------------------------------------------------
# HPACK KODLAYICI (RFC 7541): Huffman + dinamik tablo + tablo boyutu güncellemesi.
# RFC'nin serbest bıraktığı her seçim (Huffman ne zaman, hangi başlık tabloya
# girer, ad referansı hangi indeksten, cookie nasıl bölünür, size update ne
# zaman yazılır) tarayıcıya özgüdür ve HEADERS frame'inin baytlarını belirler.
# Bu seçimler HpackPolicy'dedir; profil değerleri ``fingerprint.PROFILES[ad]
# ["h2"]["hpack"]``'ten gelir (kaynaklar orada ve docs/http2.md'de).
# ---------------------------------------------------------------------------

#: Kodlayıcının tutacağı dinamik tablo üst sınırı (bayt). Eş daha büyük bir
#: SETTINGS_HEADER_TABLE_SIZE ilan ederse tablo ve size update bu değerde kalır
#: (QUICHE ``HpackEncoder::SetHeaderTableSizeBound`` ile aynı mekanizma). Gerçek
#: sunucular 4096 / 65536 ilan eder; sınır yalnızca saçma büyük değerlerde (bellek
#: koruması) devreye girer.
HPACK_ENCODER_MAX_TABLE_SIZE = 1 << 24

# Statik tablo aramaları (bayt anahtarlı): tam eşleşme, adın İLK ve SON indeksi.
_STATIC_EXACT: "dict[tuple[bytes, bytes], int]" = {}
_STATIC_NAME_FIRST: "dict[bytes, int]" = {}
_STATIC_NAME_LAST: "dict[bytes, int]" = {}
for _i, _entry in enumerate(HPACK_STATIC_TABLE):
    if _entry is not None:
        _sn, _sv = _entry[0].encode("latin-1"), _entry[1].encode("latin-1")
        _STATIC_EXACT.setdefault((_sn, _sv), _i)
        _STATIC_NAME_FIRST.setdefault(_sn, _i)
        _STATIC_NAME_LAST[_sn] = _i
del _i, _entry, _sn, _sv
_STATIC_COUNT = len(HPACK_STATIC_TABLE) - 1      # 61; dinamik indeksler 62'den başlar


def _hpack_int(value: int, prefix_bits: int, prefix: int) -> bytes:
    """RFC 7541 §5.1 tamsayı; ``prefix`` önek baytının üst (opcode) bitleri."""
    mask = (1 << prefix_bits) - 1
    if value < mask:
        return bytes((prefix | value,))
    out = bytearray((prefix | mask,))
    value -= mask
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _hpack_bytes(s: str) -> bytes:
    # latin-1: header decode tarafıyla (session.py, latin-1) simetrik — orijinal
    # bayt dizisi bozulmadan geri üretilir. latin-1'e sığmayan gerçek Unicode
    # (ör. kullanıcının elle verdiği emoji) utf-8'e düşer.
    try:
        return s.encode("latin-1")
    except UnicodeEncodeError:
        return s.encode("utf-8")


def _crumbs_chromium(v: bytes) -> "list[bytes]":
    """QUICHE ``HpackEncoder::CookieToCrumbs``: baş/son ' '/'\\t' kırpılır, her ';'
    bir sınırdır, ';'dan sonraki TEK boşluk atlanır (boş parçalar korunur)."""
    v = v.strip(b" \t")
    out = []
    pos = 0
    while True:
        end = v.find(b";", pos)
        if end < 0:
            out.append(v[pos:])
            return out
        out.append(v[pos:end])
        pos = end + 1
        if pos != len(v) and v[pos] == 0x20:
            pos += 1


def _crumbs_firefox(v: bytes) -> "list[bytes]":
    """Firefox ``Http2Compressor::EncodeHeaderBlock``: yalnızca "; " ayırıcıdır."""
    return v.split(b"; ")


# -- dize literal'leri (RFC 7541 §5.2): H biti + uzunluk + veri ----------------

def _str_shorter(raw: bytes) -> bytes:
    """QUICHE ``EmitString``: Huffman yalnızca KESİN kısaysa (eşitse ham)."""
    n = hpack_huffman_size(raw)
    if n < len(raw):
        return _hpack_int(n, 7, 0x80) + hpack_huffman_encode(raw)
    return _hpack_int(len(raw), 7, 0x00) + raw


def _str_always(raw: bytes) -> bytes:
    """Firefox ``HuffmanAppend``: her zaman Huffman (daha uzun olsa bile)."""
    enc = hpack_huffman_encode(raw)
    return _hpack_int(len(enc), 7, 0x80) + enc


def _str_raw(raw: bytes) -> bytes:
    return _hpack_int(len(raw), 7, 0x00) + raw


# Aynı dizeler (User-Agent, Accept, sec-ch-ua, :authority...) her YENİ bağlantının
# ilk isteğinde yeniden kodlanır (dinamik tablo bağlantı başınadır). Kısa dizelerin
# kodlanmış hâli süreç genelinde LRU önbellekte tutulur; uzun/tekil değerler
# (büyük cookie'ler, uzun yollar) önbelleğe girmez. Bellek: <= 2 x 1024 x ~2 x 256 B.
_STR_CACHE_MAX_LEN = 256
_str_shorter_cached = functools.lru_cache(maxsize=1024)(_str_shorter)
_str_always_cached = functools.lru_cache(maxsize=1024)(_str_always)


def _hpack_str_shorter(raw: bytes) -> bytes:
    return _str_shorter_cached(raw) if len(raw) <= _STR_CACHE_MAX_LEN else _str_shorter(raw)


def _hpack_str_always(raw: bytes) -> bytes:
    return _str_always_cached(raw) if len(raw) <= _STR_CACHE_MAX_LEN else _str_always(raw)


_HPACK_STRING_ENCODERS = {"shorter": _hpack_str_shorter, "always": _hpack_str_always,
                          "never": _str_raw}

_CRUMBLERS = {None: None, "chromium": _crumbs_chromium, "firefox": _crumbs_firefox}
_HPACK_ENUMS = {
    "huffman": ("shorter", "always", "never"),
    "name_ref": ("first", "last"),
    "cookie_crumbs": tuple(_CRUMBLERS),
    "size_update": ("on_change", "on_setting"),
}


@dataclass(frozen=True)
class HpackPolicy:
    """Bir tarayıcının HPACK kodlayıcı davranışı. Varsayılanlar Chromium/QUICHE'dir.

    Alanlar (``fingerprint.PROFILES[ad]["h2"]["hpack"]`` anahtarlarıyla aynı):

    ``huffman``
        ``"shorter"``: Huffman yalnızca ham dizeden KESİN kısaysa (QUICHE
        ``HpackEncoder::EmitString``); ``"always"``: her dize (Firefox
        ``Http2Compressor::HuffmanAppend``); ``"never"``: hiç.
    ``name_ref``
        Literal'in ad referansı. ``"first"``: statik tablodaki İLK eşleşme, yoksa
        dinamik tablodaki EN YENİ (QUICHE ``HpackHeaderTable::GetByName``).
        ``"last"``: tablo (statik, sonra dinamik en yeniden en eskiye) taranır, tam
        eşleşmede durulur, yoksa SON ad eşleşmesi (Firefox ``ProcessHeader``).
    ``index_pseudo``
        Dinamik tabloya eklenebilen pseudo-header'lar (``None`` = hepsi).
        Chromium ``DefaultPolicy``: yalnızca ``:authority``.
    ``always_literal``
        Tam eşleşme olsa bile "literal without indexing" (0x00) gönderilen adlar
        (Firefox ``:path``: ``noLocalIndex``).
    ``never_index``
        "Literal never indexed" (0x10) gönderilen adlar (Firefox ``authorization``).
    ``cookie_crumbs``
        Cookie'nin RFC 9113 §8.2.3 parçalara bölünmesi: ``"chromium"``,
        ``"firefox"`` ya da ``None`` (bölünmez); bkz. ``_crumbs_*``.
    ``cookie_never_index_below``
        Bu uzunluktan (bayt) kısa cookie parçaları never-indexed (Firefox: 20).
    ``index_max_entry_divisor``
        >0 ise boyutu ``tablo_sınırı // bölen``'i aşan giriş tabloya eklenmez
        (Firefox: 2).
    ``index_min_table_size``
        Tablo sınırı bundan küçükse hiçbir giriş eklenmez (Firefox: 128).
    ``size_update``
        Eşin SETTINGS_HEADER_TABLE_SIZE'ı geldiğinde: ``"on_change"`` yalnızca
        değer mevcut sınırdan farklıysa (QUICHE ``ApplyHeaderTableSizeSetting``);
        ``"on_setting"`` her seferinde, aynı değer olsa bile (Firefox
        ``SetMaxBufferSize``). Güncelleme sonraki başlık bloğunun başına yazılır;
        arada daha küçük bir değer görüldüyse önce o, sonra güncel değer.
    """

    huffman: str = "shorter"
    name_ref: str = "first"
    index_pseudo: "Optional[frozenset[str]]" = frozenset({":authority"})
    always_literal: "frozenset[str]" = frozenset()
    never_index: "frozenset[str]" = frozenset()
    cookie_crumbs: Optional[str] = "chromium"
    cookie_never_index_below: int = 0
    index_max_entry_divisor: int = 0
    index_min_table_size: int = 0
    size_update: str = "on_change"

    def __post_init__(self) -> None:
        for key, allowed in _HPACK_ENUMS.items():
            if getattr(self, key) not in allowed:
                raise ValueError(f"Geçersiz HPACK politikası: {key}={getattr(self, key)!r} "
                                 f"(izinli: {', '.join(map(repr, allowed))}).")
        for key in ("cookie_never_index_below", "index_max_entry_divisor", "index_min_table_size"):
            if not isinstance(getattr(self, key), int) or getattr(self, key) < 0:
                raise ValueError(f"Geçersiz HPACK politikası: {key} negatif olmayan tamsayı olmalı.")


_DEFAULT_HPACK_POLICY = HpackPolicy()


def hpack_policy(spec: "HpackPolicy | dict | None" = None) -> HpackPolicy:
    """Profil sözlüğündeki ``"hpack"`` değerini (ya da None -> Chromium) doğrulanmış
    :class:`HpackPolicy`'ye çevirir. Bilinmeyen anahtar/değer ValueError'dır: sessiz
    varsayılana düşüş, baytları yanlış ama isteği başarılı bir parmak izi üretirdi."""
    if spec is None:
        return _DEFAULT_HPACK_POLICY
    if isinstance(spec, HpackPolicy):
        return spec
    if not isinstance(spec, dict):
        raise TypeError(f"HPACK politikası sözlük olmalı, {type(spec).__name__} verildi.")
    unknown = set(spec) - set(HpackPolicy.__dataclass_fields__)
    if unknown:
        raise ValueError(f"Bilinmeyen HPACK politika anahtarı: {', '.join(sorted(unknown))}.")
    kw = dict(spec)
    for key in ("always_literal", "never_index", "index_pseudo"):
        if kw.get(key) is not None:
            kw[key] = frozenset(str(x).lower() for x in kw[key])
    return HpackPolicy(**kw)


class HpackEncoder:
    """HPACK kodlayıcı (RFC 7541): statik + dinamik tablo, Huffman, dinamik tablo
    boyutu güncellemeleri; temsil seçimleri ``policy``'den (:class:`HpackPolicy`;
    profil sözlüğü, politika ya da None = Chromium).

    Durum BAĞLANTI BAŞINADIR ve eşin çözücüsüyle birebir senkron kalmalıdır: her
    başlık bloğu, telde gönderileceği SIRAYLA ve tam bir kez kodlanmalı (kodlanıp
    gönderilmeyen blok tabloyu kaydırır); eşin SETTINGS_HEADER_TABLE_SIZE'ı
    :meth:`set_peer_table_size` ile bildirilmelidir.
    """

    #: Bkz. HPACK_ENCODER_MAX_TABLE_SIZE.
    max_table_size_cap = HPACK_ENCODER_MAX_TABLE_SIZE

    def __init__(self, policy: "HpackPolicy | dict | None" = None):
        p = self.policy = hpack_policy(policy)
        self._name_last = p.name_ref == "last"
        self._index_pseudo = (None if p.index_pseudo is None
                              else frozenset(n.encode("latin-1") for n in p.index_pseudo))
        self._always_literal = frozenset(n.encode("latin-1") for n in p.always_literal)
        self._never = frozenset(n.encode("latin-1") for n in p.never_index)
        self._cookie_never_below = p.cookie_never_index_below
        self._crumbs = _CRUMBLERS[p.cookie_crumbs]
        self._string = _HPACK_STRING_ENCODERS[p.huffman]
        # Dinamik tablo: en eski solda. Her girişin sıra numarası (``_insertions``
        # sayacı) indeksi verir: indeks = 61 + _insertions - sıra (en yeni = 62).
        self._entries: "collections.deque[tuple[bytes, bytes, int]]" = collections.deque()
        self._size = 0
        self._insertions = 0
        self._dyn_exact: "dict[tuple[bytes, bytes], int]" = {}       # (ad, değer) -> en yeni sıra
        self._dyn_names: "dict[bytes, collections.deque[int]]" = {}  # ad -> sıralar (eskiden yeniye)
        # Tablo boyutu: eşin son SETTINGS_HEADER_TABLE_SIZE'ı ve etkin sınır.
        self._settings_bound = HPACK_DEFAULT_TABLE_SIZE
        self._max_size = HPACK_DEFAULT_TABLE_SIZE
        self._update_pending = False
        self._pending_min: Optional[int] = None

    # -- durum (testler / hata ayıklama) ---------------------------------
    @property
    def max_table_size(self) -> int:
        """Etkin dinamik tablo üst sınırı (eşin çözücüsünün bildiği değer)."""
        return self._max_size

    @property
    def table_size(self) -> int:
        return self._size

    @property
    def dynamic_table(self) -> "list[tuple[str, str]]":
        """Dinamik tablo, en yeni (indeks 62) başta — HpackDecoder._dynamic ile aynı düzen."""
        return [(n.decode("latin-1"), v.decode("latin-1")) for n, v, _ in reversed(self._entries)]

    # -- tablo boyutu ------------------------------------------------------
    def set_peer_table_size(self, value: int) -> None:
        """Eşin SETTINGS_HEADER_TABLE_SIZE değeri geldi (RFC 9113 §6.5.2, RFC 7541 §4.2).

        Yeni sınır hemen uygulanır (gerekirse tahliye); size update sonraki blokta."""
        cap = self.max_table_size_cap
        if self.policy.size_update == "on_change":
            # QUICHE ApplyHeaderTableSizeSetting: aynı değer -> hiçbir şey; küçülme
            # en küçük değer olarak hatırlanır.
            if value == self._settings_bound and value <= cap:
                return
            if value < self._settings_bound:
                self._pending_min = value if self._pending_min is None else min(self._pending_min, value)
        elif not self._update_pending or self._pending_min is None or value < self._pending_min:
            # Firefox SetMaxBufferSize: bekleyen güncelleme yoksa ya da daha küçükse.
            self._pending_min = value
        self._settings_bound = value
        self._max_size = min(value, cap)
        while self._entries and self._size > self._max_size:
            self._evict()
        self._update_pending = True

    # -- dinamik tablo -----------------------------------------------------
    def _evict(self) -> None:
        name, value, size = self._entries.popleft()
        seq = self._insertions - len(self._entries) - 1
        self._size -= size
        key = (name, value)
        if self._dyn_exact.get(key) == seq:
            del self._dyn_exact[key]
        seqs = self._dyn_names[name]
        seqs.popleft()                  # tahliye her zaman en eskiden: adın da en eskisi
        if not seqs:
            del self._dyn_names[name]

    def _insert(self, name: bytes, value: bytes, size: int) -> None:
        # RFC 7541 §4.4: önce yer açılır; tablodan büyük giriş tabloyu boşaltır, eklenmez.
        while self._entries and self._size + size > self._max_size:
            self._evict()
        if size > self._max_size:
            return
        seq = self._insertions
        self._insertions = seq + 1
        self._entries.append((name, value, size))
        self._size += size
        self._dyn_exact[(name, value)] = seq
        seqs = self._dyn_names.get(name)
        if seqs is None:
            self._dyn_names[name] = collections.deque((seq,))
        else:
            seqs.append(seq)

    def _exact(self, name: bytes, value: bytes) -> int:
        """Tam eşleşme: önce statik, sonra dinamikteki en yeni; yoksa 0."""
        idx = _STATIC_EXACT.get((name, value))
        if idx is not None:
            return idx
        seq = self._dyn_exact.get((name, value))
        return 0 if seq is None else _STATIC_COUNT + self._insertions - seq

    def _name_ref(self, name: bytes, value: "Optional[bytes]") -> int:
        if self._name_last:
            # Firefox: statik + dinamik (en yeniden en eskiye) taranır; tam
            # eşleşmede durulur, yoksa SON ad eşleşmesi kalır.
            if value is not None:
                idx = self._exact(name, value)
                if idx:
                    return idx
            seqs = self._dyn_names.get(name)
            if seqs:
                return _STATIC_COUNT + self._insertions - seqs[0]
            return _STATIC_NAME_LAST.get(name, 0)
        idx = _STATIC_NAME_FIRST.get(name)
        if idx is not None:
            return idx
        seqs = self._dyn_names.get(name)
        return _STATIC_COUNT + self._insertions - seqs[-1] if seqs else 0

    # -- kodlama ------------------------------------------------------------
    def _field(self, out: bytearray, name: bytes, value: bytes, crumb: bool) -> None:
        string = self._string
        if name in self._never or (crumb and len(value) < self._cookie_never_below):
            ref = self._name_ref(name, value)
            out += _hpack_int(ref, 4, 0x10)                  # §6.2.3 never indexed
        elif name in self._always_literal:
            ref = self._name_ref(name, value)
            out += _hpack_int(ref, 4, 0x00)                  # §6.2.2 without indexing
        else:
            idx = self._exact(name, value)
            if idx:
                out += _hpack_int(idx, 7, 0x80)              # §6.1 indexed
                return
            ref = self._name_ref(name, None)
            size = len(name) + len(value) + 32
            ip = self._index_pseudo
            p = self.policy
            if ((ip is not None and name[:1] == b":" and name not in ip)
                    or (p.index_max_entry_divisor and size > self._max_size // p.index_max_entry_divisor)
                    or self._max_size < p.index_min_table_size):
                out += _hpack_int(ref, 4, 0x00)              # §6.2.2 without indexing
            else:
                out += _hpack_int(ref, 6, 0x40)              # §6.2.1 incremental indexing
                if not ref:
                    out += string(name)
                out += string(value)
                # Ad referansı EKLEMEDEN ÖNCE hesaplandı: çözücü de adı tahliyeden
                # önce okur (RFC 7541 §4.4).
                self._insert(name, value, size)
                return
        if not ref:
            out += string(name)
        out += string(value)

    def encode(self, headers: "Iterable[tuple[str, str]]") -> bytes:
        """(ad, değer) listesini HPACK başlık bloğuna çevirir (adlar küçük harfe).

        Bekleyen tablo boyutu güncellemesi bloğun başına yazılır (RFC 7541 §4.2).
        Sıra korunur; cookie politika gereği parçalara bölünebilir."""
        out = bytearray()
        if self._update_pending:
            pmin, target = self._pending_min, self._max_size
            if pmin is not None and pmin < target:
                out += _hpack_int(pmin, 5, 0x20)
            out += _hpack_int(target, 5, 0x20)
            self._update_pending = False
            self._pending_min = None
        field = self._field
        crumbs = self._crumbs
        for name, value in headers:
            n = _hpack_bytes(name.lower())
            v = _hpack_bytes(value)
            if crumbs is not None and n == b"cookie":
                for c in crumbs(v):
                    field(out, n, c, True)
            else:
                field(out, n, v, False)
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


# Alım tarafı WINDOW_UPDATE toplama eşiğinin üst sınırı. Bkz. h2_wu_thresholds.
WU_BATCH_MAX = 32768


def _wu_threshold(window: int) -> int:
    return 1 if window <= Http2Connection.DEFAULT_WINDOW else min(window // 2, WU_BATCH_MAX)


def h2_wu_thresholds(h2: dict) -> "tuple[int, int]":
    """(bağlantı, stream) için WINDOW_UPDATE gönderme eşiği (tüketilmiş, henüz geri
    verilmemiş bayt).

    Tarayıcılar her DATA frame'i için WINDOW_UPDATE göndermez: Chromium, geri
    verilmemiş kredi pencerenin yarısını aşınca gönderir. İlan ettiğimiz pencere
    RFC varsayılanından (65535) büyükse aynı şekilde toplarız; eşik
    ``min(pencere // 2, WU_BATCH_MAX)``. Üst sınır, SETTINGS'imizi yok sayıp
    pencereyi 65535 sanan uyumsuz bir eşin bile kilitlenmemesi içindir (eşik
    65535'in altında kaldıkça o eş tükenmeden kredi alır). Varsayılan 65535
    pencerede (``default`` profili) davranış eskisiyle aynıdır: her DATA'da hemen.
    İlan edilen başlangıç değerleri (parmak izi) DEĞİŞMEZ; yalnızca kredinin
    hangi sıklıkla geri verildiği değişir. Geri basınç korunur: kredi yalnızca
    tüketilen veri için verilir.
    """
    stream_win = h2_setting(h2, 0x4, Http2Connection.DEFAULT_WINDOW)
    conn_win = Http2Connection.DEFAULT_WINDOW + (h2.get("window_update") or 0)
    return _wu_threshold(conn_win), _wu_threshold(stream_win)


def _window_update_frame(stream_id: int, increment: int) -> bytes:
    return (b"\x00\x00\x04\x08\x00" + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
            + increment.to_bytes(4, "big"))



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

      - HPACK kodlama profilin tarayıcısı gibi (Huffman, dinamik tablo, cookie
        parçalama; bkz. HpackPolicy) ve sunucunun SETTINGS_HEADER_TABLE_SIZE'ına
        göre dinamik tablo boyutu güncellemesi

    Desteklenmeyenler (kapsam dışı, ileride eklenebilir):
      - Gerçek eşzamanlı multiplexing (aynı anda birden fazla açık stream)
      - Sunucu PUSH_PROMISE
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
        # Kodlayıcı bağlantı başınadır; davranışı profilin tarayıcısınınki.
        self._encoder = HpackEncoder(self._h2.get("hpack"))
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
        # İstek başına zaman aşımı (Session._arm_timeouts her istekte ayarlar):
        # okuma/yazma süresi ve Timeout.total'ın bitiş anı (perf_counter; None = yok).
        # write_timeout gövde gönderirken akış kontrolü (WINDOW_UPDATE) beklemesini de
        # sınırlar; frame gönderimlerinin kendisi soket sarmalayıcısının ``io``'suyla sınırlıdır.
        self.read_timeout: Optional[float] = None
        self.write_timeout: Optional[float] = None
        self.deadline: Optional[float] = None
        self._send_wait = False      # True: gövde gönderilirken pencere bekleniyor (write süresi)
        self.debug = debug or __import__("os").environ.get("FASTHTTPC_H2_DEBUG") == "1"
        # Alım tarafı akış kontrolü: tüketilmiş ama henüz WINDOW_UPDATE ile geri
        # verilmemiş bayt (bağlantı düzeyi) ve eşikler (bkz. h2_wu_thresholds).
        self._conn_unacked = 0
        self._wu_conn_threshold, self._wu_stream_threshold = h2_wu_thresholds(self._h2)

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

    def _recv_record(self) -> tuple[bytes, int]:
        """``sock.recv_record``; istek başına toplam süre sınırı (``deadline``,
        ``time.perf_counter`` cinsinden; Session ayarlar) varsa soketin zaman
        aşımı her okumadan önce kalan süreye kısaltılır. Gövde gönderilirken
        akış kontrolü beklemesinde (``_send_wait``) temel süre ``write_timeout``'tur."""
        dl = self.deadline
        if self._send_wait:
            base = self.write_timeout
        elif dl is None:
            rec0: tuple[bytes, int] = self.sock.recv_record(skip_post_handshake=True)
            return rec0
        else:
            base = self.read_timeout
        # Zaman aşımının nedeni süre KURULURKEN belirlenir (total kısalttı mı?); hata
        # sonrası saati yeniden okumak kaba çözünürlüklü saatlerde yanlış nedene götürür.
        by_total = False
        if dl is not None:
            left = dl - time.perf_counter()
            if left <= 0:
                raise total_timeout_error()
            if base is None or left < base:
                base, by_total = left, True
        if base is not None or dl is not None:
            raw = self.sock.raw_socket
            if raw.gettimeout() != base:
                raw.settimeout(base)
        try:
            rec: tuple[bytes, int] = self.sock.recv_record(skip_post_handshake=True)
        except TimeoutError as e:
            if is_attributed(e):
                raise                  # ör. okuma sırasında yapılan gönderimin yazma hatası
            if by_total:
                raise total_timeout_error() from None
            if self._send_wait:
                raise write_timeout_error(
                    self.write_timeout,
                    "HTTP/2 akış kontrolü penceresi (WINDOW_UPDATE) gelmediğinden gövde") from None
            raise
        return rec

    def _read_frame(self) -> HTTP2Frame:
        # Gövde gönderirken pencere beklerken okunmuş ama işlenmemiş frame'ler
        if self._pending_frames:
            return self._pending_frames.pop(0)
        while len(self._recv_buf) < HTTP2Frame.HEADER_SIZE:
            msg, m_type = self._recv_record()
            if m_type != 23:
                continue
            if not msg:
                raise Http2ConnectionError("Bağlantı beklenmedik şekilde kapandı.")
            self._recv_buf += msg

        buf = self._recv_buf
        length = (buf[0] << 16) | (buf[1] << 8) | buf[2]
        total = HTTP2Frame.HEADER_SIZE + length
        while len(buf) < total:
            msg, m_type = self._recv_record()
            if m_type != 23:
                continue
            if not msg:
                raise Http2ConnectionError("Frame gövdesi okunurken bağlantı kapandı.")
            buf += msg

        # Başlık alanları doğrudan tampondan; yük TEK kopyayla (eskiden frame önce
        # bytes'a, sonra parse() içinde yeniden dilimleniyordu).
        ftype, flags = buf[3], buf[4]
        stream_id = ((buf[5] << 24) | (buf[6] << 16) | (buf[7] << 8) | buf[8]) & 0x7FFFFFFF
        with memoryview(buf) as mv:
            payload = mv[HTTP2Frame.HEADER_SIZE:total].tobytes()
        del buf[:total]
        return HTTP2Frame(length, ftype, flags, stream_id, payload)

    def _handle_settings(self, frame: HTTP2Frame) -> None:
        if frame.flags & 0x1:          # ACK
            return
        payload = frame.payload
        for i in range(0, len(payload) - 5, 6):
            ident, value = struct.unpack("!HI", payload[i:i + 6])
            if ident == 0x1:
                # Sunucunun çözücü tablosu: kodlayıcı sınırı hemen uygular, size
                # update'i sonraki HEADERS bloğunun başına yazar (RFC 7541 §4.2).
                self._encoder.set_peer_table_size(value)
            elif ident == 0x4:
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
        # Bağlantı kilidi altında: bloklar telde gidecekleri sırayla kodlanır
        # (HPACK dinamik tablosu sunucunun çözücüsüyle senkron kalır).
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
        if min(self._conn_window_send, self._stream_windows.get(stream_id, 0)) >= needed:
            return
        # Bekleme bir GÖNDERİM aşamasıdır: süre ``write_timeout`` (+ kalan total). Okuma
        # süresi (soketin önceki zaman aşımı) bekleme bitince geri yüklenir.
        timed = self.write_timeout is not None or self.deadline is not None
        prev = self.sock.raw_socket.gettimeout() if timed else None
        self._send_wait = True
        try:
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
        # Zaman aşımları nedeniyle birlikte yükselir: pencere beklemesi _recv_record'da,
        # araya giren gönderimler (PONG, SETTINGS ACK) send_all'da total/write olarak işaretlenir.
        finally:
            self._send_wait = False
            if timed:
                try:
                    if self.sock.raw_socket.gettimeout() != prev:
                        self.sock.raw_socket.settimeout(prev)
                except OSError:
                    pass

    def _send_data(self, stream_id: int, body: "bytes | Iterable[bytes]") -> None:
        """Gövdeyi DATA frame'leriyle gönderir; END_STREAM SON frame'dedir.

        ``body``: bayt ya da bayt parçaları üreten iterable (akış gövdesi; belleğe
        alınmaz). Frame'ler ``max_frame_size``'ı ve bağlantı + stream gönderim pencerelerini
        aşmaz (pencere kapalıysa WINDOW_UPDATE beklenir, bkz. :meth:`_await_window`). Son
        frame'in hangisi olduğu ancak kaynak bitince bilindiğinden bir parça geride
        tutulur. Her frame gönderimi soket sarmalayıcısının ``io``'suyla (``Timeout.write``,
        kalan ``total``) sınırlıdır."""
        parts: "Iterable[bytes]" = (body,) if isinstance(body, (bytes, bytearray, memoryview)) else body
        pending: "Optional[memoryview]" = None
        for chunk in parts:
            if not chunk:
                continue
            max_frame = self._peer_settings.get("max_frame_size", 16384)
            mv = memoryview(chunk)
            for off in range(0, len(mv), max_frame):
                if pending is not None:
                    self._send_data_frame(stream_id, pending, end_stream=False)
                pending = mv[off:off + max_frame]
        self._send_data_frame(stream_id, pending if pending is not None else memoryview(b""),
                              end_stream=True)

    def _send_data_frame(self, stream_id: int, data: memoryview, end_stream: bool) -> None:
        """En çok bir frame'lik veri; pencere yetmiyorsa pencereye sığan parçalara bölünür."""
        off, n = 0, len(data)
        while True:
            take = n - off
            if take:
                self._await_window(stream_id, 1)
                take = min(take, self._conn_window_send, self._stream_windows.get(stream_id, 0))
            last = off + take >= n
            flags = FrameFlags.END_STREAM if (end_stream and last) else 0
            self.sock.send_record(_frame_bytes(FrameType.DATA, flags, stream_id,
                                               data[off:off + take].tobytes()))
            self._conn_window_send -= take
            self._stream_windows[stream_id] -= take
            off += take
            if last:
                return

    def request_stream(
        self,
        method: str,
        authority: str,
        path: str,
        headers: list[tuple[str, str]],
        body: "bytes | Iterable[bytes]" = b"",
        scheme: str = "https",
    ) -> "H2ClientStream":
        """İsteği gönderir, yanıt BAŞLIKLARI gelene kadar bekler ve gövdeyi isteğe
        bağlı (parça parça) okuyan bir :class:`H2ClientStream` döner.

        ``body`` bayt ya da bayt parçaları üreten iterable olabilir (akış gövdesi:
        DATA frame'leriyle parça parça gönderilir, bkz. :meth:`_send_data`).

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
            if self.debug:
                self._dbg(f"--- REQUEST stream_id={stream_id} {method} {path} ---")

            # Pseudo-header ve başlık SIRASI birer parmak izidir; profilden gelir
            # (Chrome m,a,s,p; Firefox m,p,a,s; Safari m,s,a,p).
            full_headers = h2_request_headers(self._h2, method, authority, scheme, path, headers)
            if self.debug:
                self._dbg(f"giden headers: {full_headers}")

            in_memory = isinstance(body, (bytes, bytearray, memoryview))
            self._send_headers(stream_id, full_headers, end_stream=in_memory and not body)
            if not in_memory or body:
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
        body: "bytes | Iterable[bytes]" = b"",
        scheme: str = "https",
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        """
        Tek bir HTTP/2 isteği gönderir ve tam yanıtı bekler.
        Döner: (status_code, header_listesi, body_bytes)
        Aynı bağlantı üzerinde ardışık çağrılabilir (her çağrı yeni stream_id alır).
        """
        st = self.request_stream(method, authority, path, headers, body, scheme)
        parts: list[bytes] = []
        try:
            while True:
                c = st.read_chunk()
                if not c:
                    break
                parts.append(c)
        except BaseException:
            st._release()
            raise
        # Tek kopya (bytearray'e ekleyip sonra bytes() almak büyümeler + bir kopya daha).
        return st.status, st.headers, b"".join(parts)

    _ERR_NAMES = {
        0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR",
        3: "FLOW_CONTROL_ERROR", 4: "SETTINGS_TIMEOUT", 5: "STREAM_CLOSED",
        6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM", 8: "CANCEL",
        9: "COMPRESSION_ERROR", 10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM",
        12: "INADEQUATE_SECURITY", 13: "HTTP_1_1_REQUIRED",
    }

    def _credit(self, st: "Optional[H2ClientStream]", n: int, end_stream: bool) -> None:
        """Tüketilen ``n`` baytlık DATA için kredi; eşiğe ulaşınca WINDOW_UPDATE.

        Bağlantı kredisi stream bittiğinde de tamamen geri verilir (pencere sızmaz).
        ``st`` None ise (yabancı/iptal edilmiş stream) yalnızca bağlantı kredisi."""
        self._conn_unacked += n
        out = b""
        if self._conn_unacked >= self._wu_conn_threshold or (end_stream and self._conn_unacked):
            out = _window_update_frame(0, self._conn_unacked)
            self._conn_unacked = 0
        if st is not None:
            st._unacked += n
            # Toplama modunda END_STREAM'den sonra stream kredisi anlamsız: gönderme.
            if st._unacked >= self._wu_stream_threshold and not (
                    end_stream and self._wu_stream_threshold > 1):
                out += _window_update_frame(st.stream_id, st._unacked)
                st._unacked = 0
        if out:
            self.sock.send_record(out)

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
            self._credit(None, len(frame.payload), end_stream=False)

    def _step(self, st: "H2ClientStream") -> bytes:
        """Bir frame okur/işler; DATA ise (padding'siz) gövde baytlarını döner."""
        frame = self._read_frame()
        if self.debug:      # f-string/repr her frame'de boşuna değerlendirilmesin
            self._dbg(f"gelen frame: {frame!r}")
        stream_id = st.stream_id

        if frame.type == FrameType.PUSH_PROMISE:
            # ENABLE_PUSH=0 ilan ettik: PUSH_PROMISE bağlantı hatasıdır
            # (RFC 9113 §6.6, §8.4). Başlık bloğu decode edilmeden yutulsaydı
            # HPACK dinamik tablosu sunucuyla senkronunu yitirirdi.
            self._send_goaway(1)
            raise Http2ConnectionError("PROTOCOL_ERROR: ENABLE_PUSH=0 iken PUSH_PROMISE alındı")

        if frame.stream_id != 0 and frame.stream_id != stream_id:
            if self.debug:
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
                if self._conn_unacked:       # trailer ile biten akış: bağlantı kredisini geri ver
                    self._credit(None, 0, end_stream=True)
        elif frame.type == FrameType.DATA:
            # DATA da PADDED olabilir; pencere HAM uzunluk (padding dahil) üzerinden açılır.
            raw_len = len(frame.payload)
            data = _strip_data_frame_padding(frame)
            if frame.end_stream:
                st.ended = True
            if raw_len > 0:
                # Tüketici bu veriyi isteyince (frame ancak o zaman okunur) pencere açılır.
                self._credit(st, raw_len, frame.end_stream)
            elif frame.end_stream and self._conn_unacked:
                self._credit(None, 0, end_stream=True)
            return data
        # PRIORITY ve bilinmeyen frame türleri yok sayılır (RFC 9113 §4.1)
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
        self._unacked = 0             # tüketilmiş, WINDOW_UPDATE ile geri verilmemiş bayt

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
        self.io: Optional[IOTimeouts] = None     # bkz. transport.iotimeout

    def send_record(self, data: bytes, content_type: int = 0x17, use_app_keys: bool = True) -> None:
        send_all(self.raw_socket, data, self.io)

    def recv_record(self, skip_post_handshake: bool = False) -> tuple[bytes, int]:
        try:
            chunk = self.raw_socket.recv(16384)
        except socket.timeout:
            # Okuma zaman aşımı "bağlantı kapandı" DEĞİLDİR: wss:// yolundaki
            # (EncryptedSocket) davranışla aynı şekilde çağırana yükseltilir.
            raise
        except OSError:
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

        # session.timeout bir Timeout nesnesidir; settimeout() float/None ister.
        # Bağlantı/TLS el sıkışması pool'un connect zaman aşımıyla yapılır,
        # sonrasındaki okumalar (Upgrade yanıtı + frame'ler) read zaman aşımıyla.
        tmo = session._tmo() if hasattr(session, "_tmo") else session.timeout
        read_timeout = getattr(tmo, "read_timeout", tmo)
        write_timeout = getattr(tmo, "write_timeout", read_timeout)

        conn = session.pool.acquire(u)
        try:
            if use_tls:
                if not conn.tls_established:
                    from ..security.tls_adapter import TLSAdapter
                    # Profilin ALPN'i "h2, http/1.1"; sunucu h2 seçerse HTTP/1.1
                    # Upgrade yapılamaz — async yol gibi yalnızca http/1.1 öneriyoruz.
                    conn.socket = TLSAdapter.negotiate(conn.socket, u.host, session.impersonate,
                                                      alpn=["http/1.1"],
                                                      **_tls_kw(session, u.port))
                    conn.tls_established = True
                alpn = (getattr(conn.socket, "state", None) or {}).get("alpn", "")
                if alpn not in ("", "http/1.1") or getattr(conn, "h2_conn", None) is not None:
                    raise ConnectionError(
                        f"WebSocket için sunucu ALPN {alpn!r} seçti; yalnızca 'http/1.1' "
                        "önerilmişti (WebSocket Upgrade HTTP/2 üzerinden yapılamaz)."
                    )
                conn.socket.raw_socket.settimeout(read_timeout)
                wire = conn.socket
            else:
                # 'ws://' — düz TCP, TLS katmanı yok. conn.socket burada ham
                # socket.socket nesnesidir; EncryptedSocket'ın send_record/
                # recv_record arayüzüyle uyumlu ince bir sarmalayıcı kullanıyoruz
                # ki WebSocketFrame gönderim/alım kodu değişmeden çalışsın.
                conn.socket.settimeout(read_timeout)
                wire = _PlainSocketAdapter(conn.socket)
            # Gönderimler (Upgrade isteği, frame'ler) Timeout.write ile sınırlı.
            wire.io = IOTimeouts(read_timeout, write_timeout)

            default_port = 443 if use_tls else 80
            host = f"[{u.host}]" if ":" in u.host else u.host
            hostport = host if u.port == default_port else f"{host}:{u.port}"
            req = (
                f"GET {u.raw_path.decode()} HTTP/1.1\r\n"
                f"Host: {hostport}\r\n"
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
    Geriye dönük uyumluluk: chunk-by-chunk açıcı. Artık
    :class:`fasthttpc.streaming.IncrementalDecoder` üzerine ince bir sarmalayıcıdır;
    böylece Session/AsyncSession ile AYNI, çıktısı sınırlı açıcıyı kullanır (gzip,
    deflate, br, zstd, virgüllü zincir). Toplam açılmış çıktı ``max_size``'ı aşarsa
    :class:`~fasthttpc.streaming.DecompressedSizeError` (FHC-07).
    """
    def __init__(self, encoding: str, max_size: Optional[int] = DEFAULT_MAX_DECOMPRESSED_SIZE):
        self._enc = encoding.lower()
        self._dec = IncrementalDecoder(self._enc, max_size)

    def decompress(self, chunk: bytes) -> bytes:
        return self._dec.decode(chunk)

    def flush(self) -> bytes:
        return self._dec.flush()


def _tls_kw(session, port) -> dict:
    """Oturumun TLS ayarlarını (özel CA, hedef port, legacy_tls, istemci sertifikası)
    doğrudan TLSAdapter.negotiate çağıran yollara taşır. Eskiden WebSocket yolu
    ``verify="ca.pem"``'i YOK SAYIYORDU (varsayılan güven deposu kullanılıyordu)."""
    kw = {"ca_path": getattr(session, "_ca_path", None), "port": port}
    if getattr(session, "legacy_tls", False):
        kw["legacy_tls"] = True
    cc = getattr(session, "client_cert", None)
    if cc is not None:
        kw["client_cert"] = cc
    return kw


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
