"""
Cookie jar testleri.

Eski sürüm çerezleri düz bir dict'te tutuyordu; bu, oturum token'ının
redirect üzerinden üçüncü bir siteye gönderilmesi demekti. Buradaki testler
o sızıntının geri gelmesini engeller.
"""
from fasthttpc.cookies import CookieJar, parse_set_cookie


def _jar(*values, host="example.com", path="/"):
    jar = CookieJar()
    jar.update_from_headers(values, request_host=host, request_path=path)
    return jar


def test_cerez_baska_domaine_gonderilmez():
    """En kritik test: a.com'un oturumu b.com'a sızmamalı."""
    jar = _jar("session=gizli", host="a.com")
    assert jar.header_for("a.com", "/", secure=True) == "session=gizli"
    assert jar.header_for("b.com", "/", secure=True) == ""


def test_alt_alan_adi_domain_belirtilmeden_eslesmez():
    """Domain verilmemişse çerez host-only'dir (RFC 6265 §5.3)."""
    jar = _jar("a=1", host="example.com")
    assert jar.header_for("sub.example.com", "/", secure=True) == ""


def test_domain_belirtilirse_alt_alan_adi_eslesir():
    jar = _jar("a=1; Domain=example.com", host="example.com")
    assert jar.header_for("sub.example.com", "/", secure=True) == "a=1"


def test_sunucu_baska_domain_icin_cerez_koyamaz():
    """evil.com, bank.com için Set-Cookie gönderemez."""
    jar = _jar("a=1; Domain=bank.com", host="evil.com")
    assert jar.header_for("bank.com", "/", secure=True) == ""


def test_secure_cerez_duz_http_ile_gonderilmez():
    jar = _jar("token=abc; Secure", host="a.com")
    assert jar.header_for("a.com", "/", secure=True) == "token=abc"
    assert jar.header_for("a.com", "/", secure=False) == ""


def test_path_eslesmesi():
    jar = _jar("a=1; Path=/admin", host="x.com")
    assert jar.header_for("x.com", "/admin", secure=True) == "a=1"
    assert jar.header_for("x.com", "/admin/panel", secure=True) == "a=1"
    assert jar.header_for("x.com", "/public", secure=True) == ""


def test_path_kismi_eslesme_yanlis_pozitif_vermez():
    """'/adminpanel' '/admin' çerezini ALMAMALI."""
    jar = _jar("a=1; Path=/admin", host="x.com")
    assert jar.header_for("x.com", "/adminpanel", secure=True) == ""


def test_suresi_gecmis_cerez_silinir():
    jar = _jar("a=1", host="x.com")
    assert jar.header_for("x.com", "/", secure=True) == "a=1"
    jar.update_from_headers(
        ["a=; Max-Age=0"], request_host="x.com", request_path="/"
    )
    assert jar.header_for("x.com", "/", secure=True) == ""


def test_max_age_expires_i_ezer():
    c = parse_set_cookie(
        "a=1; Expires=Wed, 01 Jan 2020 00:00:00 GMT; Max-Age=3600", "x.com", "/"
    )
    assert not c.is_expired()


def test_uzun_path_once_gonderilir():
    """RFC 6265 §5.4 sıralama kuralı."""
    jar = CookieJar()
    jar.update_from_headers(["genel=1; Path=/"], "x.com", "/")
    jar.update_from_headers(["ozel=2; Path=/a/b"], "x.com", "/a/b")
    assert jar.header_for("x.com", "/a/b", secure=True) == "ozel=2; genel=1"


def test_ayni_isim_farkli_path_ayri_saklanir():
    jar = CookieJar()
    jar.update_from_headers(["id=kok; Path=/"], "x.com", "/")
    jar.update_from_headers(["id=alt; Path=/app"], "x.com", "/app")
    assert len(jar) == 2


def test_bozuk_set_cookie_yok_sayilir():
    jar = _jar("", "sadece-metin", "=degersiz")
    assert len(jar) == 0


def test_httponly_ve_samesite_patlatmaz():
    jar = _jar("a=1; HttpOnly; SameSite=Lax; Secure", host="x.com")
    assert jar.header_for("x.com", "/", secure=True) == "a=1"
