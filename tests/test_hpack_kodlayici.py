"""HPACK kodlayıcı testleri: RFC 7541 Huffman kodlama + tarayıcıya özgü kodlama politikaları.

Tarayıcı davranışlarının kaynakları ``fasthttpc/fingerprint.py``'deki [QH] (Chromium/QUICHE
``quiche/http2/hpack/hpack_encoder.cc``), [FH] (Firefox ``netwerk/protocol/http/
Http2Compression.cpp``) ve [SC] (Safari yakalaması) notlarındadır; beklenen baytlar o
kaynaklardaki kurallardan türetildi ve her alan için yorumda gerekçesi yazılıdır.
"""
from __future__ import annotations

import random
import struct

import pytest

from fasthttpc.fingerprint import PROFILES, get_profile
from fasthttpc.protocol.http2_parser import (
    HPACK_ENCODER_MAX_TABLE_SIZE,
    HPACK_HUFFMAN_CODES,
    FrameFlags,
    FrameType,
    HpackDecoder,
    HpackEncoder,
    HpackPolicy,
    HTTP2Frame,
    Http2Connection,
    _hpack_huffman_decode,
    hpack_huffman_encode,
    hpack_huffman_size,
    hpack_policy,
)

CHROME = PROFILES["chrome_158"]["h2"]["hpack"]
FIREFOX = PROFILES["firefox_160"]["h2"]["hpack"]
SAFARI = PROFILES["safari_27"]["h2"]["hpack"]


def _hex(*parts: str) -> bytes:
    return bytes.fromhex("".join(parts))


# ============================================================ Huffman tablosu
# RFC 7541 Appendix B, sembol 0..256 (EOS) için (kod, bit uzunluğu); RFC metninden
# (rfc-editor.org/rfc/rfc7541.txt) "hex" ve "[len]" sütunları aktarıldı.
RFC7541_APPENDIX_B = [
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28), (0xfffffe4, 28), (0xfffffe5, 28),
    (0xfffffe6, 28), (0xfffffe7, 28), (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
    (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28), (0xfffffed, 28), (0xfffffee, 28),
    (0xfffffef, 28), (0xffffff0, 28), (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28), (0xffffff8, 28), (0xffffff9, 28),
    (0xffffffa, 28), (0xffffffb, 28), (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
    (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11), (0x3fa, 10), (0x3fb, 10),
    (0xf9, 8), (0x7fb, 11), (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6), (0x1a, 6), (0x1b, 6),
    (0x1c, 6), (0x1d, 6), (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
    (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10), (0x1ffa, 13), (0x21, 6),
    (0x5d, 7), (0x5e, 7), (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7), (0x67, 7), (0x68, 7),
    (0x69, 7), (0x6a, 7), (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
    (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7), (0xfc, 8), (0x73, 7),
    (0xfd, 8), (0x1ffb, 13), (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
    (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5), (0x24, 6), (0x5, 5),
    (0x25, 6), (0x26, 6), (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
    (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5), (0x2b, 6), (0x76, 7),
    (0x2c, 6), (0x8, 5), (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15), (0x7fc, 11), (0x3ffd, 14),
    (0x1ffd, 13), (0xffffffc, 28), (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),
    (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23), (0x3fffd6, 22), (0x7fffda, 23),
    (0x7fffdb, 23), (0x7fffdc, 23), (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
    (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23), (0xffffee, 24), (0x7fffe1, 23),
    (0x7fffe2, 23), (0x7fffe3, 23), (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
    (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24), (0x3fffda, 22), (0x1fffdd, 21),
    (0xfffe9, 20), (0x3fffdb, 22), (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
    (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24), (0x1fffdf, 21), (0x3fffdf, 22),
    (0x7fffeb, 23), (0x7fffec, 23), (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
    (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23), (0xfffea, 20), (0x3fffe2, 22),
    (0x3fffe3, 22), (0x3fffe4, 22), (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
    (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19), (0x3fffe7, 22), (0x7ffff2, 23),
    (0x3fffe8, 22), (0x1ffffec, 25), (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27),
    (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25), (0x7fff2, 19), (0x1fffe3, 21),
    (0x3ffffe6, 26), (0x7ffffe0, 27), (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
    (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26), (0xffffffd, 28), (0x7ffffe3, 27),
    (0x7ffffe4, 27), (0x7ffffe5, 27), (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21),
    (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23), (0x3fffea, 22), (0x3fffeb, 22),
    (0x1ffffee, 25), (0x1ffffef, 25), (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26), (0x7ffffe7, 27), (0x7ffffe8, 27),
    (0x7ffffe9, 27), (0x7ffffea, 27), (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),
    (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26), (0x3fffffff, 30),
]


def test_huffman_kod_tablosu_rfc_appendix_b_ile_ayni():
    """Kodlama tablosu decode trie'sinden türetilir; RFC tablosuyla 257 sembolde birebir."""
    assert len(RFC7541_APPENDIX_B) == 257
    assert HPACK_HUFFMAN_CODES == RFC7541_APPENDIX_B


def test_huffman_kod_tablosu_hpack_paketiyle_ayni():
    consts = pytest.importorskip("hpack.huffman_constants")
    assert [c for c, _ in HPACK_HUFFMAN_CODES] == list(consts.REQUEST_CODES)
    assert [n for _, n in HPACK_HUFFMAN_CODES] == list(consts.REQUEST_CODES_LENGTH)


# RFC 7541 Appendix C.4 / C.6'daki Huffman kodlu dizeler.
RFC_HUFFMAN_ORNEKLERI = [
    (b"www.example.com", "f1e3c2e5f23a6ba0ab90f4ff"),                       # C.4.1
    (b"no-cache", "a8eb10649cbf"),                                          # C.4.2
    (b"custom-key", "25a849e95ba97d7f"),                                    # C.4.3
    (b"custom-value", "25a849e95bb8e8b4bf"),                                # C.4.3
    (b"302", "6402"),                                                       # C.6.1
    (b"private", "aec3771a4b"),                                             # C.6.1
    (b"Mon, 21 Oct 2013 20:13:21 GMT", "d07abe941054d444a8200595040b8166e082a62d1bff"),
    (b"https://www.example.com", "9d29ad171863c78f0b97c8e9ae82ae43d3"),     # C.6.1
    (b"307", "640eff"),                                                     # C.6.2
    (b"Mon, 21 Oct 2013 20:13:22 GMT", "d07abe941054d444a8200595040b8166e084a62d1bff"),
    (b"gzip", "9bd9ab"),                                                    # C.6.3
    (b"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
     "94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007"),
]


@pytest.mark.parametrize("raw,beklenen", RFC_HUFFMAN_ORNEKLERI)
def test_huffman_kodlama_rfc_ornekleri(raw, beklenen):
    enc = hpack_huffman_encode(raw)
    assert enc.hex() == beklenen
    assert hpack_huffman_size(raw) == len(enc)
    assert _hpack_huffman_decode(enc) == raw


def test_huffman_gidip_gelme_tum_baytlar_ve_rastgele():
    rnd = random.Random(7541)
    samples = [b"", bytes(range(256)), bytes(range(255, -1, -1)) * 3]
    samples += [bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 300))) for _ in range(300)]
    samples += [bytes(rnd.choice(b"abcdefghijklmnop0123456789-=;, /") for _ in range(rnd.randrange(1, 64)))
                for _ in range(300)]
    for s in samples:
        enc = hpack_huffman_encode(s)
        assert len(enc) == hpack_huffman_size(s)
        assert _hpack_huffman_decode(enc) == s


def test_huffman_kodlama_hpack_paketiyle_ayni():
    huffman = pytest.importorskip("hpack.huffman")
    consts = pytest.importorskip("hpack.huffman_constants")
    ref = huffman.HuffmanEncoder(consts.REQUEST_CODES, consts.REQUEST_CODES_LENGTH)
    rnd = random.Random(1)
    for _ in range(300):
        s = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 200)))
        assert hpack_huffman_encode(s) == ref.encode(s)


# ============================================================ RFC 7541 Appendix C blokları
def test_rfc7541_c4_istek_ornekleri_huffman_dinamik_tablo():
    """C.4 (Huffman'lı istekler) Chromium politikasıyla bayt bayt: :authority ve
    cache-control/custom-key tabloya girer, 2. ve 3. istek onlara indeksle başvurur."""
    enc = HpackEncoder(CHROME)
    assert enc.encode([(":method", "GET"), (":scheme", "http"), (":path", "/"),
                       (":authority", "www.example.com")]) == _hex("828684418cf1e3c2e5f23a6ba0ab90f4ff")
    assert enc.encode([(":method", "GET"), (":scheme", "http"), (":path", "/"),
                       (":authority", "www.example.com"), ("cache-control", "no-cache")]
                      ) == _hex("828684be5886a8eb10649cbf")
    assert enc.encode([(":method", "GET"), (":scheme", "https"), (":path", "/index.html"),
                       (":authority", "www.example.com"), ("custom-key", "custom-value")]
                      ) == _hex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf")
    assert enc.dynamic_table == [("custom-key", "custom-value"), ("cache-control", "no-cache"),
                                 (":authority", "www.example.com")]
    assert enc.table_size == 164


def test_rfc7541_c6_yanit_ornekleri_tahliye_ile():
    """C.6 (Huffman'lı yanıtlar, tablo 256 bayt): tahliyeler dahil bayt bayt. RFC
    örnekleri her dizeyi Huffman'lar ve :status'u da indeksler -> huffman="always",
    index_pseudo=None. Tablo boyutu SETTINGS ile geldiği için ilk bloğun başında
    size update (256 = 3f e1 01) vardır; RFC örneğinde bu bant dışıdır."""
    enc = HpackEncoder(HpackPolicy(huffman="always", index_pseudo=None))
    enc.set_peer_table_size(256)
    b1 = enc.encode([(":status", "302"), ("cache-control", "private"),
                     ("date", "Mon, 21 Oct 2013 20:13:21 GMT"), ("location", "https://www.example.com")])
    assert b1[:3] == _hex("3fe101")
    assert b1[3:] == _hex("488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff"
                          "6e919d29ad171863c78f0b97c8e9ae82ae43d3")
    assert enc.table_size == 222
    b2 = enc.encode([(":status", "307"), ("cache-control", "private"),
                     ("date", "Mon, 21 Oct 2013 20:13:21 GMT"), ("location", "https://www.example.com")])
    assert b2 == _hex("4883640effc1c0bf")
    b3 = enc.encode([(":status", "200"), ("cache-control", "private"),
                     ("date", "Mon, 21 Oct 2013 20:13:22 GMT"), ("location", "https://www.example.com"),
                     ("content-encoding", "gzip"),
                     ("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1")])
    assert b3 == _hex("88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2"
                      "e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007")
    assert enc.dynamic_table == [
        ("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
        ("content-encoding", "gzip"), ("date", "Mon, 21 Oct 2013 20:13:22 GMT")]
    assert enc.table_size == 215


# ============================================================ Chrome
UA_CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
             "Chrome/158.0.0.0 Safari/537.36")
CHROME_ISTEK = [
    (":method", "GET"), (":authority", "www.example.com"), (":scheme", "https"), (":path", "/"),
    ("sec-ch-ua", '"Chromium";v="158", "Google Chrome";v="158", "Not)A;Brand";v="8"'),
    ("sec-ch-ua-mobile", "?0"), ("sec-ch-ua-platform", '"Windows"'),
    ("upgrade-insecure-requests", "1"), ("user-agent", UA_CHROME),
    ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
               "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
    ("sec-fetch-site", "none"), ("sec-fetch-mode", "navigate"), ("sec-fetch-user", "?1"),
    ("sec-fetch-dest", "document"), ("accept-encoding", "gzip, deflate, br, zstd"),
    ("accept-language", "en-US,en;q=0.9"), ("cookie", "sid=31d4d96e407aad42; lang=en-US"),
    ("priority", "u=0, i"),
]

# [QH] hpack_encoder.cc: tam eşleşme (statik önce) -> EmitIndex; DefaultPolicy (pseudo'lardan
# yalnızca :authority; diğer her ad) -> EmitIndexedLiteral (0x40|ad); aksi EmitNonIndexedLiteral
# (0x00|ad). Ad indeksi GetByName: statik İLK, sonra en yeni dinamik. EmitString: Huffman
# yalnızca KESİN kısaysa. CookieToCrumbs: "; " parçaları ayrı alanlar.
CHROME_ISTEK_1 = _hex(
    "82",                                           # :method GET = statik 2
    "41" "8c" "f1e3c2e5f23a6ba0ab90f4ff",           # :authority: indexing, ad 1, Huffman 12<15
    "87",                                           # :scheme https = statik 7
    "84",                                           # :path / = statik 4 (pseudo ama tam eşleşme)
    "40" "87" "4148b1275ad1ff"                      # sec-ch-ua: yeni ad, indexing, Huffman ad
    "b8" "fe6f4f61e935b4ff3f7de0fe42dbdfcfd29fce239e6a0aa5e9ec3d25fe7efbc1fc85b7bf9fa53f9d274ff70fddd"
    "b07549fcfdf783f97bf9f",
    "40" "8b" "4148b1275ad1ad49e33505" "02" "3f30",  # sec-ch-ua-mobile: "?0" Huffman 2 = 2 -> HAM
    "40" "8d" "4148b1275ad1ad5d034ca7b29f88" "fe" "791aa90fe11fcf",  # sec-ch-ua-platform
    "40" "92" "b6b9ac1c8558d520a4b6c2ad617b5a54251f" "01" "31",       # upgrade-insecure-requests: "1" ham
    "7a" "d5" "d07f66a281b0dae053fae46aa43f8429a77a8102e0fb5391aa71afb53cb8d7f6a435d74179163cc64b0db2"
    "eaecb8a7f59b1efd19fe94a0dd4aa62293a9ffb52f4f61e92b016de5c0b817029b8728ec330db2eaecb9",
    # ^ user-agent: indexing, statik ad 58 (0x40|58 = 7a)
    "53" "e5" "497ca589d34d1f43aeba0c41a4c7a98f33a69a3fdf9a68fa1d75d0620d263d4c79a68fbed00177fe8d48e6"
    "2b03ee697e8d48e62b1e0b1d7f46a4731581d754df5f2c7cfdf6800bbdf43aeba0c41a4c7a9841a6a8b22c5f249c754c"
    "5fbef046cfdf6800bbbf",                         # accept: statik ad 19 (0x53)
    "40" "8a" "4148b4a549275906497f" "83" "a8f517",  # sec-fetch-site: none
    "40" "8a" "4148b4a549275a93c85f" "86" "a87dcd30d25f",  # sec-fetch-mode: navigate
    "40" "8a" "4148b4a549275ad416cf" "02" "3f31",   # sec-fetch-user: "?1" ham
    "40" "8a" "4148b4a549275a42a13f" "86" "90e4b692d49f",  # sec-fetch-dest: document
    "50" "92" "9bd9abfa5242cb40d25fa523b3e94f684c9f",  # accept-encoding: statik ad 16 (İLK eşleşme)
    "51" "8b" "2d4b70ddf45abefb4005df",             # accept-language: statik ad 17
    "60" "8e" "41a48190c8d48fb85680e8c72342",       # cookie parça 1 (sid=...): statik ad 32
    "60" "88" "a0754d016a5b86ef",                   # cookie parça 2 (lang=en-US): yine statik 32
    "40" "86" "aec31ec327d7" "85" "b6007d286f",     # priority: u=0, i
)
# 2. istek: :path dışında her şey dinamik tablodan tek bayt (16 giriş; en yeni = 62).
CHROME_ISTEK_2 = _hex(
    "82", "cd", "87",                               # :authority en eski giriş = 62+15 = 77
    "04" "8c" "61051d849ffced04f58c9d7f",           # :path /search?q=hpack: indekslemesiz, ad 4
    "cc cb ca c9 c8 c7 c6 c5 c4 c3 c2 c1",          # sec-ch-ua .. accept-language
    "c0 bf",                                        # cookie parçaları
    "be",                                           # priority (en yeni = 62)
)


def test_chrome_tipik_istek_baytlari_ve_ikinci_istek_dinamik_tablo():
    enc = HpackEncoder(CHROME)
    assert enc.encode(CHROME_ISTEK) == CHROME_ISTEK_1
    istek2 = [(k, "/search?q=hpack" if k == ":path" else v) for k, v in CHROME_ISTEK]
    assert enc.encode(istek2) == CHROME_ISTEK_2
    assert len(CHROME_ISTEK_1) == 477 and len(CHROME_ISTEK_2) == 32


def test_chrome_151_yakalamasi_ile_ayni_parcalar():
    """Bağımsız doğrulama: httpcloak 8a8f2be1e7 commit'inde ham TLS+ALPN h2 sunucusuyla
    alınan gerçek Chrome 151 header_block_fragment'ları ([QH])."""
    def ilk(h):
        return HpackEncoder(CHROME).encode([h])
    assert ilk((":path", "/fi/matkat")) == _hex("048762533148d3d469")
    assert ilk((":method", "PUT")) == _hex("0203505554")
    assert ilk((":method", "DELETE")) == _hex("020644454c455445")
    assert ilk((":method", "PATCH")) == _hex("02055041544348")
    assert ilk(("cookie", "alpha=one")) == _hex("60871d15ce380f517f")
    enc = HpackEncoder(CHROME)
    assert enc.encode([(":authority", "example.org")])[0] == 0x41
    assert enc.encode([(":authority", "example.org")]) == b"\xbe"      # 2. istekten itibaren tek bayt
    enc.set_peer_table_size(65536)
    assert enc.encode([(":method", "GET")]) == _hex("3fe1ff03") + b"\x82"   # 0. ofsette size update


def test_chrome_cookie_crumbs_quiche_kurallari():
    """CookieToCrumbs: dış ' '/'\\t' kırpılır, her ';' ayırır, ardından TEK boşluk atlanır."""
    def parcalar(v):
        return [val for _, val in HpackDecoder().decode(HpackEncoder(CHROME).encode([("cookie", v)]))]
    assert parcalar("a=1; b=2") == ["a=1", "b=2"]
    assert parcalar("a=1;b=2") == ["a=1", "b=2"]
    assert parcalar("  a=1;  b=2 \t") == ["a=1", " b=2"]
    assert parcalar("a=1;;b=2;") == ["a=1", "", "b=2", ""]
    assert parcalar(" \t ") == [""]


# ============================================================ Firefox
UA_FIREFOX = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) Gecko/20100101 Firefox/160.0"
FIREFOX_ISTEK = [
    (":method", "GET"), (":path", "/"), (":authority", "www.example.com"), (":scheme", "https"),
    ("user-agent", UA_FIREFOX),
    ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("accept-language", "en-US,en;q=0.5"), ("accept-encoding", "gzip, deflate, br, zstd"),
    ("upgrade-insecure-requests", "1"), ("sec-fetch-dest", "document"),
    ("sec-fetch-mode", "navigate"), ("sec-fetch-site", "none"), ("sec-fetch-user", "?1"),
    ("cookie", "sid=31d4d96e407aad42; lang=en-US"), ("priority", "u=0, i"), ("te", "trailers"),
]

# [FH] Http2Compression.cpp: EncodeHeaderBlock (:path noLocalIndex; cookie "; " ile bölünür,
# <20 bayt parça neverIndex; te: trailers sonda), ProcessHeader (tablo taraması: tam eşleşmede
# dur, yoksa SON ad eşleşmesi; tam eşleşme -> kIndex, değilse kIndexedLiteral), HuffmanAppend
# (her dize Huffman, daha uzun ya da eşit olsa bile).
FIREFOX_ISTEK_1 = _hex(
    "82",                                           # :method GET = statik 2
    "04" "81" "63",                                 # :path /: noLocalIndex -> literal (tam eşleşme 4), Huffman
    "41" "8c" "f1e3c2e5f23a6ba0ab90f4ff",           # :authority: kIndexedLiteral, ad 1
    "87",                                           # :scheme https
    "7a" "bc" "d07f66a281b0dae053fae46aa43f8429a77a8102e0fb5391aa71afb53cb8d7da9677b81700b83fb531149d"
    "4ec0801000200a984d61653f9602e01707",           # user-agent: ad 58
    "53" "b0" "497ca589d34d1f43aeba0c41a4c7a98f33a69a3fdf9a68fa1d75d0620d263d4c79a68fbed00177febe58f9"
    "fbed00177b",                                   # accept: ad 19
    "51" "8b" "2d4b70ddf45abefb4005db",             # accept-language: ad 17
    "50" "92" "9bd9abfa5242cb40d25fa523b3e94f684c9f",  # accept-encoding: ad 16 (tek statik ad)
    "40" "92" "b6b9ac1c8558d520a4b6c2ad617b5a54251f" "81" "0f",  # "1" -> Huffman 1 bayt (Chrome: ham)
    "40" "8a" "4148b4a549275a42a13f" "86" "90e4b692d49f",        # sec-fetch-dest
    "40" "8a" "4148b4a549275a93c85f" "86" "a87dcd30d25f",        # sec-fetch-mode
    "40" "8a" "4148b4a549275906497f" "83" "a8f517",              # sec-fetch-site
    "40" "8a" "4148b4a549275ad416cf" "82" "ff03",   # sec-fetch-user "?1" -> Huffman (Chrome: 02 3f31)
    "60" "8e" "41a48190c8d48fb85680e8c72342",       # cookie "sid=..." 20 bayt -> indexing, ad 32
    "1f2f" "88" "a0754d016a5b86ef",                 # cookie "lang=en-US" <20 -> never indexed (0x10),
    #                                                 ad = SON eşleşme: az önce eklenen dinamik 62
    "40" "86" "aec31ec327d7" "85" "b6007d286f",     # priority
    "40" "82" "497f" "86" "4d833505b11f",           # te: trailers (yeni ad, indexing)
)
FIREFOX_ISTEK_2 = _hex(
    "82",
    "05" "8c" "61051d849ffced04f58c9d7f",           # :path: SON statik :path eşleşmesi = 5 (/index.html)
    "ca", "87",                                     # :authority (13 girişin en eskisi = 74)
    "c9 c8 c7 c6 c5 c4 c3 c2 c1",                   # user-agent .. sec-fetch-user
    "c0",                                           # cookie sid=... tam eşleşme
    "1f31" "88" "a0754d016a5b86ef",                 # cookie lang=en-US: yine never indexed, ad 64
    "bf", "be",                                     # priority, te
)


def test_firefox_tipik_istek_baytlari_ve_ikinci_istek_dinamik_tablo():
    enc = HpackEncoder(FIREFOX)
    assert enc.encode(FIREFOX_ISTEK) == FIREFOX_ISTEK_1
    istek2 = [(k, "/search?q=hpack" if k == ":path" else v) for k, v in FIREFOX_ISTEK]
    assert enc.encode(istek2) == FIREFOX_ISTEK_2
    assert len(FIREFOX_ISTEK_1) == 307 and len(FIREFOX_ISTEK_2) == 40


def test_firefox_ozel_kurallar():
    # authorization: never indexed (0x10), ad statik 23 -> 4 bit önek: 1f 08
    assert HpackEncoder(FIREFOX).encode([("authorization", "Bearer x")])[:2] == _hex("1f08")
    # Chrome authorization'ı indeksler (0x40|23 = 0x57)
    assert HpackEncoder(CHROME).encode([("authorization", "Bearer x")])[0] == 0x57
    # :method PUT: SON statik :method (3 = POST) adıyla, Huffman (3 bayt = ham, yine de
    # Huffman), tabloya eklenir; ikinci kez tek bayt indeks. Chrome: 02 03 505554, eklemez.
    enc = HpackEncoder(FIREFOX)
    assert enc.encode([(":method", "PUT")]) == _hex("43" "83" "d7c37f")
    assert enc.encode([(":method", "PUT")]) == b"\xbe"
    # Tablonun yarısından büyük giriş indekslenmez (literal 0x00).
    blk = HpackEncoder(FIREFOX).encode([("x-buyuk", "v" * 2100)])
    assert blk[0] == 0x00
    # Firefox cookie bölmesi yalnızca "; " ile.
    vals = [v for _, v in HpackDecoder().decode(HpackEncoder(FIREFOX).encode([("cookie", "a=1;b=2; c=3")]))]
    assert vals == ["a=1;b=2", "c=3"]


# ============================================================ Safari
def test_safari_yakalamasi_277_bayt():
    """[SC] Safari 26.6.1 iOS (tls.peet.ws): HEADERS yükü 277 bayt. Profil politikası
    bu başlık listesinden tam 277 bayt üretir (Huffman'sız 359, indekslemesiz 281)."""
    ua = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 "
          "(KHTML, like Gecko) Version/26.6.1 Mobile/15E148 Safari/604.1")
    hdrs = [(":method", "GET"), (":scheme", "https"), (":authority", "tls.peet.ws"),
            (":path", "/api/all"), ("sec-fetch-dest", "document"), ("user-agent", ua),
            ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
            ("sec-fetch-site", "none"), ("sec-fetch-mode", "navigate"),
            ("accept-language", "en-AU,en;q=0.9"), ("priority", "u=0, i"),
            ("accept-encoding", "gzip, deflate, br, zstd")]
    assert len(HpackEncoder(SAFARI).encode(hdrs)) == 277
    # Ayırt edicilik: Huffman'sız 359; statik adı >= 15 olan 4 başlık (user-agent 58,
    # accept 19, accept-language 17, accept-encoding 16) indekslenmeseydi (4 bit önek) 281.
    assert len(HpackEncoder({**SAFARI, "huffman": "never"}).encode(hdrs)) == 359
    yok = {**SAFARI, "never_index": ["user-agent", "accept", "accept-language", "accept-encoding"]}
    assert len(HpackEncoder(yok).encode(hdrs)) == 281


def test_safari_cookie_tek_alan():
    blk = HpackEncoder(SAFARI).encode([("cookie", "a=1; b=2")])
    assert HpackDecoder().decode(blk) == [("cookie", "a=1; b=2")]


# ============================================================ tablo boyutu güncellemesi
def test_chrome_ayni_deger_guncelleme_yazmaz_firefox_yazar():
    c, f = HpackEncoder(CHROME), HpackEncoder(FIREFOX)
    c.set_peer_table_size(4096)
    f.set_peer_table_size(4096)
    assert c.encode([(":method", "GET")]) == b"\x82"            # QUICHE: değişiklik yok
    assert f.encode([(":method", "GET")]) == _hex("3fe11f82")   # Firefox: her SETTINGS'te
    assert f.encode([(":method", "GET")]) == b"\x82"            # yalnızca bir kez


def test_kuculme_sonra_buyume_once_en_kucuk_sonra_guncel():
    for pol in (CHROME, FIREFOX):
        enc = HpackEncoder(pol)
        enc.set_peer_table_size(1024)
        enc.set_peer_table_size(8192)
        assert enc.encode([]) == _hex("3fe107" "3fe13f")         # 1024, 8192


def test_ara_buyume_quiche_ve_firefox_farki():
    """4096 -> 6000 -> 8192: QUICHE küçülme görmediği için yalnızca 8192; Firefox
    bekleyen en küçük değeri (6000) de yazar."""
    c, f = HpackEncoder(CHROME), HpackEncoder(FIREFOX)
    for e in (c, f):
        e.set_peer_table_size(6000)
        e.set_peer_table_size(8192)
    assert c.encode([]) == _hex("3fe13f")
    assert f.encode([]) == _hex("3fd12e" "3fe13f")


def test_kuculmede_tahliye_ve_cozucu_senkron():
    enc, dec = HpackEncoder(CHROME), HpackDecoder(max_table_size=4096)
    hdrs = [(f"x-h{i}", "v" * 40) for i in range(20)]
    assert dec.decode(enc.encode(hdrs)) == hdrs
    assert enc.dynamic_table == dec._dynamic
    enc.set_peer_table_size(200)
    assert enc.table_size <= 200
    blk = enc.encode(hdrs[-3:])
    assert blk.startswith(_hex("3fa901"))                       # 200
    assert dec.decode(blk) == hdrs[-3:]
    assert enc.dynamic_table == dec._dynamic and dec._dynamic_size == enc.table_size


def test_sifir_tablo_chrome_yine_0x40_yazar_firefox_0x00():
    c, f = HpackEncoder(CHROME), HpackEncoder(FIREFOX)
    for e in (c, f):
        e.set_peer_table_size(0)
    bc = c.encode([("x-a", "b")])
    bf = f.encode([("x-a", "b")])
    assert bc[:2] == b"\x20\x40" and c.dynamic_table == []      # TryAddEntry eklemez
    assert bf[:2] == b"\x20\x00" and f.dynamic_table == []      # mMaxBuffer < 128
    assert HpackDecoder().decode(bc) == [("x-a", "b")] == HpackDecoder().decode(bf)


def test_sacma_buyuk_tablo_ust_siniri():
    enc = HpackEncoder(CHROME)
    enc.set_peer_table_size(2 ** 32 - 1)
    assert enc.max_table_size == HPACK_ENCODER_MAX_TABLE_SIZE
    blk = enc.encode([])
    d = HpackDecoder(max_table_size=2 ** 32 - 1)
    d.decode(blk)
    assert d._max_size == HPACK_ENCODER_MAX_TABLE_SIZE


@pytest.mark.parametrize("pol,seed", [(CHROME, 1), (FIREFOX, 2), (SAFARI, 3)],
                         ids=["chrome", "firefox", "safari"])
def test_rastgele_istekler_ve_ayar_degisiklikleri_cozuculerle_senkron(pol, seed):
    """Çok istek + rastgele SETTINGS_HEADER_TABLE_SIZE değişiklikleri: kodlayıcının tablosu
    bizim çözücümüzle ve (kuruluysa) hpack paketinin çözücüsüyle her blokta aynı kalır."""
    try:
        from hpack import Decoder as RefDecoder
    except ImportError:          # hpack yalnızca karşılaştırma için
        RefDecoder = None
    rnd = random.Random(seed)
    enc = HpackEncoder(pol)
    dec = HpackDecoder(max_table_size=2 ** 20)
    ref = RefDecoder() if RefDecoder else None
    if ref is not None:
        ref.max_allowed_table_size = 2 ** 20
    names = ["x-a", "x-b", "user-agent", "accept", "cookie", "authorization", ":path", ":method",
             ":authority", "referer", "x-uzun"]
    for i in range(300):
        if rnd.random() < 0.1:
            enc.set_peer_table_size(rnd.choice([0, 64, 100, 256, 1024, 4096, 8192, 65536]))
        hdrs = []
        for _ in range(rnd.randrange(1, 12)):
            n = rnd.choice(names)
            v = ("v%d" % rnd.randrange(8)) * rnd.choice([1, 1, 3, 40])
            if n == "cookie":
                v = "; ".join(f"c{j}={rnd.randrange(4)}" * rnd.choice([1, 8]) for j in range(rnd.randrange(1, 4)))
            hdrs.append((n, v))
        blk = enc.encode(hdrs)
        got = dec.decode(blk)
        if pol.get("cookie_crumbs"):
            # parçalar ardışık "cookie" alanlarıdır; "; " ile birleştirince özgün değer
            joined, k = [], 0
            while k < len(got):
                if got[k][0] == "cookie":
                    parts = [got[k][1]]
                    while k + 1 < len(got) and got[k + 1][0] == "cookie":
                        k += 1
                        parts.append(got[k][1])
                    joined.append(("cookie", "; ".join(parts)))
                else:
                    joined.append(got[k])
                k += 1
            merged, prev = [], None
            for n, v in hdrs:
                if n == "cookie" and prev == "cookie":
                    merged[-1] = ("cookie", merged[-1][1] + "; " + v)
                else:
                    merged.append((n, v))
                prev = n
            assert joined == merged, i
        else:
            assert got == hdrs, i
        assert enc.dynamic_table == dec._dynamic, i
        assert enc.table_size == dec._dynamic_size and enc.max_table_size == dec._max_size, i
        if ref is not None:
            assert [(k.decode() if isinstance(k, bytes) else k, v.decode() if isinstance(v, bytes) else v)
                    for k, v in ref.decode(blk)] == got, i


# ============================================================ politika doğrulama
def test_profillerin_hpack_politikalari_gecerli():
    for name in PROFILES:
        pol = hpack_policy(get_profile(name)["h2"]["hpack"])
        assert isinstance(pol, HpackPolicy)
    assert hpack_policy(CHROME) == HpackPolicy()              # Chromium = varsayılan
    assert hpack_policy(FIREFOX).name_ref == "last"


def test_bilinmeyen_politika_anahtari_ve_degeri_hata():
    with pytest.raises(ValueError, match="Bilinmeyen HPACK"):
        HpackEncoder({"hufman": "always"})
    with pytest.raises(ValueError, match="huffman"):
        HpackEncoder({"huffman": "bazen"})
    with pytest.raises(ValueError, match="size_update"):
        HpackEncoder({"size_update": "asla"})
    with pytest.raises(TypeError):
        HpackEncoder("chrome")


# ============================================================ bağlantı düzeyi (senkron)
class _Soket:
    def __init__(self):
        self.gelen = bytearray()
        self.giden = bytearray()

    def send_record(self, data, content_type=0x17, use_app_keys=True):
        self.giden += data

    def recv_record(self, skip_post_handshake=False):
        if not self.gelen:
            raise ConnectionError("veri bitti")
        v, self.gelen = bytes(self.gelen), bytearray()
        return v, 23

    def header_bloklari(self):
        buf = bytes(self.giden)
        if buf.startswith(b"PRI * HTTP/2.0"):
            buf = buf[24:]
        out, pos = [], 0
        while pos + 9 <= len(buf):
            f = HTTP2Frame.parse(buf[pos:])
            pos += 9 + f.length
            if f.type == FrameType.HEADERS:
                out.append(f.payload[5:] if f.flags & FrameFlags.PRIORITY else f.payload)
        return out


def _yanit(sid, *on):
    blk = b"\x88"
    return b"".join(on) + HTTP2Frame(len(blk), FrameType.HEADERS, 0x5, sid, blk).serialize()


@pytest.mark.parametrize("profil,guncelleme", [("chrome_158", "3fe1ff03"), ("firefox_160", "3fe1ff03"),
                                               ("safari_27", "3fe1ff03")])
def test_senkron_baglanti_settings_header_table_size_sonraki_blokta(profil, guncelleme):
    sock = _Soket()
    conn = Http2Connection(sock, profile=profil)
    ayar = struct.pack("!HI", 1, 65536)
    sock.gelen += _yanit(1, HTTP2Frame(6, FrameType.SETTINGS, 0, 0, ayar).serialize())
    hdrs = [("user-agent", "UA"), ("cookie", "a=1; bbbbbbbbbbbbbbbbbbbbbbbbbbbbb=2")]
    assert conn.request("GET", "a.example", "/", hdrs)[0] == 200
    sock.gelen += _yanit(3)
    assert conn.request("GET", "a.example", "/x", hdrs)[0] == 200
    b1, b2 = sock.header_bloklari()
    assert not b1.startswith(b"\x3f")                # ilk istek sunucu SETTINGS'inden önce gitti
    assert b2.startswith(bytes.fromhex(guncelleme))
    assert len(b2) < len(b1) // 2                    # dinamik tablo yeniden kullanıldı
    dec = HpackDecoder(max_table_size=65536)
    dec.decode(b1)
    dec.decode(b2)
    assert dec._max_size == 65536


def test_senkron_baglanti_ayni_tablo_boyutu_firefox_yazar_chrome_yazmaz():
    for profil, bas in (("chrome_158", b"\x82"), ("firefox_160", _hex("3fe11f82"))):
        sock = _Soket()
        conn = Http2Connection(sock, profile=profil)
        sock.gelen += _yanit(1, HTTP2Frame(6, FrameType.SETTINGS, 0, 0, struct.pack("!HI", 1, 4096)).serialize())
        conn.request("GET", "a.example", "/", [])
        sock.gelen += _yanit(3)
        conn.request("GET", "a.example", "/", [])
        assert sock.header_bloklari()[1].startswith(bas), profil
