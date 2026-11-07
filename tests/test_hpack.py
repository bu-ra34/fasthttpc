"""HPACK kodlayıcı/çözücü testleri (RFC 7541)."""
import pytest

from fasthttpc.protocol.http2_parser import HpackDecoder, HpackEncoder, _hpack_huffman_decode


def _gidip_gel(headers):
    return HpackDecoder().decode(HpackEncoder().encode(headers))


def test_basit_gidip_gelme():
    headers = [(":method", "GET"), (":path", "/"), ("accept", "text/html")]
    assert _gidip_gel(headers) == headers


def test_pseudo_header_sirasi_korunur():
    """Sıra bir parmak izidir; kodlayıcı onu yeniden düzenlememeli."""
    headers = [(":method", "GET"), (":authority", "a.com"),
               (":scheme", "https"), (":path", "/")]
    assert [k for k, _ in _gidip_gel(headers)] == [
        ":method", ":authority", ":scheme", ":path"
    ]


def test_uzun_deger_gidip_geliyor():
    headers = [("cookie", "x" * 5000)]
    assert _gidip_gel(headers) == headers


def test_bos_deger():
    assert _gidip_gel([("x-bos", "")]) == [("x-bos", "")]


def test_dinamik_tablo_bagimsiz_kodlayici_cozucu_arasinda_tutarli():
    enc, dec = HpackEncoder(), HpackDecoder()
    for i in range(5):
        headers = [(":method", "GET"), ("x-sayac", str(i))]
        assert dec.decode(enc.encode(headers)) == headers


def test_huffman_cozme():
    """RFC 7541 Ek C.4.1 — 'www.example.com' huffman kodlu hâli."""
    kodlu = bytes.fromhex("f1e3c2e5f23a6ba0ab90f4ff")
    assert _hpack_huffman_decode(kodlu) == b"www.example.com"


def test_statik_tablo_ortak_headerlar():
    headers = [(":method", "GET"), (":scheme", "https"), (":status", "200")]
    assert _gidip_gel(headers) == headers


# ---- Sağlamlaştırma (bozuk/kötü niyetli girdi) -------------------------------
from fasthttpc.protocol.http2_parser import HpackDecodingError, HPACK_MAX_HEADER_LIST_SIZE


def test_rfc7541_c4_huffman_istek_ornegi():
    d = HpackDecoder()
    assert d.decode(bytes.fromhex("828684418cf1e3c2e5f23a6ba0ab90f4ff")) == [
        (":method", "GET"), (":scheme", "http"), (":path", "/"),
        (":authority", "www.example.com"),
    ]
    assert d._dynamic == [(":authority", "www.example.com")]


def test_huffman_padding_7_bitten_uzunsa_hata():
    # 'www.example.com' + tamamı 1 olan ek bir byte -> padding 8+ bit
    with pytest.raises(HpackDecodingError, match="padding"):
        _hpack_huffman_decode(bytes.fromhex("f1e3c2e5f23a6ba0ab90f4ff") + b"\xff")


def test_huffman_padding_sifir_bitlerse_hata():
    # '0' sembolü 5 bit (00000) + 3 bit padding '000' (1 olmalıydı)
    with pytest.raises(HpackDecodingError, match="padding"):
        _hpack_huffman_decode(b"\x00")


def test_huffman_eos_veri_icinde_hata():
    # EOS: 30 bit tamamı 1 -> 4 byte 0xff ile EOS'a ulaşılır
    with pytest.raises(HpackDecodingError):
        _hpack_huffman_decode(b"\xff\xff\xff\xff")


def test_bozuk_huffman_decode_icinde_hata_firlatir():
    blok = b"\x00\x81\x00" + b"\x81\xff"  # isim huffman '0'+000 padding
    with pytest.raises(HpackDecodingError):
        HpackDecoder().decode(blok)


def test_integer_ust_siniri():
    blok = b"\xff" + b"\xff" * 6 + b"\x01"
    with pytest.raises(HpackDecodingError, match="2\\^32"):
        HpackDecoder().decode(blok)


def test_kesik_integer_hata():
    with pytest.raises(HpackDecodingError, match="kesik"):
        HpackDecoder().decode(b"\xff\x80")


def test_kesik_string_hata():
    # literal without indexing, yeni isim, isim uzunluğu 10 ama 3 byte var
    with pytest.raises(HpackDecodingError, match="kesik"):
        HpackDecoder().decode(b"\x00\x0aabc")


def test_eksik_deger_stringi_hata():
    # isim indeksli (4=:path), değer hiç yok
    with pytest.raises(HpackDecodingError, match="eksik"):
        HpackDecoder().decode(b"\x04")


def test_gecersiz_indeks_ve_sifir_indeks_hata():
    with pytest.raises(HpackDecodingError, match="indeks"):
        HpackDecoder().decode(b"\xbe")   # 62: dinamik tablo boş
    with pytest.raises(HpackDecodingError, match="0 olamaz"):
        HpackDecoder().decode(b"\x80")


def test_header_list_boyut_siniri():
    d = HpackDecoder(max_header_list_size=1000)
    v = "a" * 120
    enc = HpackEncoder()
    blok = enc.encode([("x-h%d" % i, v) for i in range(10)])
    with pytest.raises(HpackDecodingError, match="Header list"):
        d.decode(blok)
    assert HPACK_MAX_HEADER_LIST_SIZE == 256 * 1024


def test_varsayilan_header_list_siniri_256kb():
    enc = HpackEncoder()
    blok = enc.encode([("x-h%d" % i, "b" * 60000) for i in range(5)])
    with pytest.raises(HpackDecodingError, match="Header list"):
        HpackDecoder().decode(blok)


def test_dynamic_table_size_update_siniri():
    d = HpackDecoder(max_table_size=4096)
    d.decode(b"\x3f\xe1\x1f")          # 4096'ya güncelle — izinli
    d.decode(b"\x20")                  # 0 — izinli, tablo boşalır
    with pytest.raises(HpackDecodingError, match="aşıyor"):
        d.decode(b"\x3f\xe2\x1f")      # 4097


def test_dynamic_table_size_update_blok_basinda_olmali():
    with pytest.raises(HpackDecodingError, match="başında"):
        HpackDecoder().decode(b"\x82\x20")


def test_size_update_tabloyu_bosaltir():
    d = HpackDecoder()
    d.decode(bytes.fromhex("828684418cf1e3c2e5f23a6ba0ab90f4ff"))
    assert d._dynamic
    d.decode(b"\x20")
    assert d._dynamic == [] and d._dynamic_size == 0
    with pytest.raises(HpackDecodingError):
        d.decode(b"\xbe")


def test_size_update_eskiden_literal_saniliyordu():
    """Regresyon: 001xxxxx önekli size update literal gibi ayrıştırılıyordu."""
    d = HpackDecoder(max_table_size=65536)
    assert d.decode(b"\x3f\xe1\x1f\x88") == [(":status", "200")]


def test_http2_baglantisi_compression_error_firlatir():
    import struct
    from fasthttpc.protocol.http2_parser import Http2Connection, Http2ConnectionError

    def h2f(ftype, flags, sid, payload):
        return (struct.pack("!I", len(payload))[1:] + bytes([ftype, flags]) +
                struct.pack("!I", sid) + payload)

    class Sock:
        def __init__(self):
            self.recs = [h2f(0x4, 0, 0, b""), h2f(0x1, 0x5, 1, b"\x00\x0aabc")]
            self.sent = bytearray()

        def send_record(self, data, content_type=0x17, use_app_keys=True):
            self.sent += data

        def recv_record(self, skip_post_handshake=False):
            if not self.recs:
                raise ConnectionError("bitti")
            return self.recs.pop(0), 23

    s = Sock()
    with pytest.raises(Http2ConnectionError, match="COMPRESSION_ERROR"):
        Http2Connection(s).request("GET", "example.com", "/", [])
    # GOAWAY(COMPRESSION_ERROR=0x9) gönderildi
    assert b"\x07\x00\x00\x00\x00\x00" + b"\x00\x00\x00\x00\x00\x00\x00\x09" in bytes(s.sent)
