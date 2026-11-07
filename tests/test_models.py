"""URL ve Headers modellerinin testleri."""
import pytest

from fasthttpc.models.headers import Headers
from fasthttpc.models.urls import URL


# --- Headers ---------------------------------------------------------------

def test_add_coklu_degeri_korur():
    """Regresyon: __setitem__ ile parse etmek Set-Cookie'lerin hepsini eziyordu."""
    h = Headers()
    h.add("Set-Cookie", "a=1; Path=/")
    h.add("Set-Cookie", "b=2; Path=/")
    h.add("Set-Cookie", "c=3")
    assert h.get_list("set-cookie") == ["a=1; Path=/", "b=2; Path=/", "c=3"]


def test_setitem_onceki_degerleri_siler():
    h = Headers()
    h.add("X-Test", "1")
    h.add("X-Test", "2")
    h["X-Test"] = "3"
    assert h.get_list("x-test") == ["3"]


def test_setitem_sirayi_korur():
    """Header sırası bir parmak izidir; güncelleme onu sona atmamalı."""
    h = Headers()
    h["A"] = "1"
    h["B"] = "2"
    h["C"] = "3"
    h["A"] = "yeni"
    assert [k for k in h] == ["a", "b", "c"]


def test_buyuk_kucuk_harf_duyarsiz():
    h = Headers({"Content-Type": "text/html"})
    assert h["content-type"] == h["CONTENT-TYPE"] == "text/html"


def test_latin1_disi_karakterler_patlatmaz():
    h = Headers()
    h["Accept-Language"] = "tr-TR, Türkçe"
    assert "Accept-Language" in dict(h.items()) or "accept-language" in h


def test_getitem_coklu_degeri_virgulle_birlestirir():
    h = Headers()
    h.add("Accept", "text/html")
    h.add("Accept", "application/json")
    assert h["accept"] == "text/html, application/json"


# --- URL -------------------------------------------------------------------

def test_query_string_yeniden_kodlanmaz():
    """Regresyon: parse_qs->urlencode turu '?foo' -> '?foo=' yapıyordu."""
    assert URL("https://x.com/a?foo").raw_path == b"/a?foo"
    assert URL("https://x.com/a?b=1%2F2").raw_path == b"/a?b=1%2F2"
    assert URL("https://x.com/a?z=1&a=2").raw_path == b"/a?z=1&a=2"


def test_parametre_sirasi_korunur():
    url = "https://x.com/api?ts=1&sig=abc&nonce=9"
    assert URL(url).raw_path.decode() == "/api?ts=1&sig=abc&nonce=9"


def test_hostsuz_url_acik_hata_verir():
    with pytest.raises(ValueError, match="host içermiyor"):
        URL("/sadece/yol")


def test_idn_punycode_e_cevrilir():
    assert URL("https://köşe.example/x").host == "xn--ke-fka43b.example"


def test_varsayilan_portlar():
    assert URL("https://a.com/").port == 443
    assert URL("http://a.com/").port == 80
    assert URL("https://a.com:8443/").port == 8443


def test_str_donusu_yeniden_ayristirilabilir():
    for u in ("https://a.com/x?q=1", "http://b.org:8080/y"):
        assert str(URL(str(URL(u)))) == str(URL(u))


def test_bos_yol_koke_cevrilir():
    assert URL("https://a.com").path == "/"
