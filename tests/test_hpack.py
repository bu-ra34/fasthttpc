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
