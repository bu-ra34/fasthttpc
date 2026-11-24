"""Güvenlik denetimi (docs/security-audit.md) bulgularının regresyon testleri.

Her test, düzeltmeden ÖNCEKİ kodda başarısız olur. Ağ gerektirmez (yalnızca loopback).
"""
import asyncio
import datetime
import ipaddress
import struct
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from fasthttpc import AsyncSession, MockTransport, Response, Session
from fasthttpc.cookies import CookieJar
from fasthttpc.models.urls import URL
from fasthttpc.models.headers import check_header_field, check_request_line
from fasthttpc.protocol.http1_parser import HTTP1Parser, parse_chunk_size
from fasthttpc.security.cert_validator import CertificateValidationError, validate_server_certificate
from saha.yerel_sunucu import YerelSunucu


# ---------------------------------------------------------------------------
# PKI yardımcıları
# ---------------------------------------------------------------------------
def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    ca = (
        x509.CertificateBuilder()
        .subject_name(_name("Audit CA")).issuer_name(_name("Audit CA"))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    path = tmp_path_factory.mktemp("pki") / "ca.pem"
    path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    return key, ca, str(path)


def _leaf(pki, sans):
    ca_key, ca, _ = pki
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(_name("leaf")).issuer_name(ca.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=10))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )


def _cert_msg(cert, ctx=b"", trailing=b""):
    der = cert.public_bytes(serialization.Encoding.DER)
    entries = struct.pack("!I", len(der))[1:] + der + b"\x00\x00"
    body = bytes([len(ctx)]) + ctx + struct.pack("!I", len(entries))[1:] + entries + trailing
    return b"\x0b" + struct.pack("!I", len(body))[1:] + body


# ---------------------------------------------------------------------------
# F1 — IP literal'i host'lar iPAddress SAN ile eşleşmeli, dNSName ile DEĞİL
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("ip", ["127.0.0.1", "::1"])
def test_ip_host_rejects_dnsname_san_spelling_the_ip(pki, ip):
    leaf = _leaf(pki, [x509.DNSName(ip)])
    with pytest.raises(CertificateValidationError):
        validate_server_certificate(_cert_msg(leaf), ip, ca_path=pki[2])


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1"])
def test_ip_host_accepts_ipaddress_san(pki, ip):
    leaf = _leaf(pki, [x509.IPAddress(ipaddress.ip_address(ip))])
    assert validate_server_certificate(_cert_msg(leaf), ip, ca_path=pki[2]) is not None


def test_ip_host_rejects_other_ip(pki):
    leaf = _leaf(pki, [x509.IPAddress(ipaddress.ip_address("10.0.0.1"))])
    with pytest.raises(CertificateValidationError):
        validate_server_certificate(_cert_msg(leaf), "10.0.0.2", ca_path=pki[2])


def test_dns_host_still_validated_normally(pki):
    leaf = _leaf(pki, [x509.DNSName("audit.example")])
    assert validate_server_certificate(_cert_msg(leaf), "audit.example", ca_path=pki[2]) is not None
    with pytest.raises(CertificateValidationError):
        validate_server_certificate(_cert_msg(leaf), "other.example", ca_path=pki[2])


# ---------------------------------------------------------------------------
# F6 — Certificate mesajı katı ayrıştırılır
# ---------------------------------------------------------------------------
def test_certificate_message_with_request_context_rejected(pki):
    leaf = _leaf(pki, [x509.DNSName("audit.example")])
    with pytest.raises(CertificateValidationError, match="request_context"):
        validate_server_certificate(_cert_msg(leaf, ctx=b"\x01\x02"), "audit.example", ca_path=pki[2])


def test_certificate_message_with_trailing_bytes_rejected(pki):
    leaf = _leaf(pki, [x509.DNSName("audit.example")])
    with pytest.raises(CertificateValidationError, match="uzunlu"):
        validate_server_certificate(_cert_msg(leaf, trailing=b"\x00junk"), "audit.example", ca_path=pki[2])


# ---------------------------------------------------------------------------
# F2 — giden başlıklarda CR/LF/NUL (istek enjeksiyonu) reddedilir
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name,value", [
    ("X-Test", "a\r\nInjected: 1"),
    ("X-Test", "a\nInjected: 1"),
    ("X-Test", "a\x00b"),
    ("X-Te st", "v"),
    ("X-Test\r\nInjected", "v"),
    ("", "v"),
])
def test_check_header_field_rejects(name, value):
    with pytest.raises(ValueError):
        check_header_field(name, value)


def test_check_header_field_accepts_normal():
    check_header_field("X-Test", "değer; a=b, \t c")      # latin-1, sekme, virgül: geçerli
    check_header_field(":path", "/x?y=1")
    check_header_field(b"Cookie", b"a=b")


@pytest.mark.parametrize("method,target", [
    ("GET /x HTTP/1.1\r\nX:", "/"),
    ("GE T", "/"),
    ("GET", "/a\r\nX-Injected: 1"),
    ("GET", "/a\x00"),
])
def test_check_request_line_rejects(method, target):
    with pytest.raises(ValueError):
        check_request_line(method, target)


# Port 1 üzerinde dinleyen yok: düzeltmeden önce istek bağlantı aşamasına ulaşıp
# ConnectionError veriyordu; şimdi telde hiçbir şey yazılmadan ValueError.
_DEAD = "https://127.0.0.1:1/"


@pytest.mark.parametrize("kw", [
    {"headers": {"X-Test": "a\r\nInjected: 1"}},
    {"headers": {"X-Test\r\nInjected": "1"}},
    {"cookies": {"sid": "a\r\nInjected: 1"}},
])
def test_session_rejects_crlf_before_connecting(kw):
    with Session(timeout=2) as s:
        with pytest.raises(ValueError):
            s.get(_DEAD, **kw)


def test_session_rejects_bad_method_before_connecting():
    with Session(timeout=2) as s:
        with pytest.raises(ValueError):
            s.request("GET / HTTP/1.1\r\nX-Injected: 1\r\n\r\nGET", _DEAD)


@pytest.mark.parametrize("kw", [
    {"headers": {"X-Test": "a\r\nInjected: 1"}},
    {"cookies": {"sid": "a\nInjected: 1"}},
])
def test_async_session_rejects_crlf_before_connecting(kw):
    async def main():
        async with AsyncSession(timeout=2) as s:
            with pytest.raises(ValueError):
                await s.get(_DEAD, **kw)
    asyncio.run(main())


# ---------------------------------------------------------------------------
# F3 — çerez Domain= özniteliği genel soneke / IP'ye yayılamaz
# ---------------------------------------------------------------------------
def test_cookie_domain_tld_is_rejected():
    jar = CookieJar()
    jar.update_from_headers(["sid=evil; Domain=com; Path=/"], "attacker.com", "/")
    assert jar.header_for("bank.com", "/", True) == ""
    # FHC-08'den beri (RFC 6265 §5.3 adım 5) genel sonek Domain'li çerez host-only
    # kalmaz, tümden yok sayılır.
    assert jar.header_for("attacker.com", "/", True) == ""


def test_cookie_domain_dot_tld_is_rejected():
    jar = CookieJar()
    jar.update_from_headers(["sid=evil; Domain=.com"], "www.attacker.com", "/")
    assert jar.header_for("bank.com", "/", True) == ""
    assert jar.header_for("www.attacker.com", "/", True) == ""


@pytest.mark.parametrize("host,domain,other", [
    ("10.0.0.1", "0.0.1", "9.0.0.1"),
    ("10.0.0.1", "10.0.0.2", "10.0.0.2"),
    ("10.0.0.1", "example.com", "example.com"),
    ("::1", "::1", "::2"),          # IPv6 öznitelik köşeli parantezsiz: tarayıcılar da reddeder
    ("::1", "[::2]", "::2"),
])
def test_cookie_domain_on_ip_host_is_rejected(host, domain, other):
    # FHC-03'te host-only kalıyordu; Chromium/Firefox gibi artık tümden yok sayılır
    # (bkz. fasthttpc/cookies.py _domain_attr_verdict).
    jar = CookieJar()
    jar.update_from_headers([f"sid=x; Domain={domain}"], host, "/")
    assert len(jar) == 0
    assert jar.header_for(other, "/", True) == ""
    assert jar.header_for(host, "/", True) == ""


@pytest.mark.parametrize("host,domain,other", [
    ("10.0.0.1", "10.0.0.1", "9.0.0.1"),
    ("10.0.0.1", ".10.0.0.1", "10.0.0.10"),
    ("::1", "[::1]", "::2"),
    ("[::1]", "[::1]", "[::2]"),
])
def test_cookie_domain_equal_to_ip_host_is_host_only(host, domain, other):
    jar = CookieJar()
    jar.update_from_headers([f"sid=x; Domain={domain}"], host, "/")
    assert jar.header_for(host, "/", True) == "sid=x"
    assert jar.header_for(other, "/", True) == ""


@pytest.mark.parametrize("host,domain", [
    ("evil.com", "bank.com"),
    ("example.com", "a.example.com"),           # öznitelik host'un alt alanı
    ("notexample.com", "example.com"),          # sonek ama etiket sınırında değil
    ("a.example.com", "b.example.com"),
])
def test_cookie_domain_not_matching_host_is_rejected(host, domain):
    """RFC 6265 §5.3 adım 6: host özniteliği domain-match etmiyorsa çerez yok sayılır."""
    jar = CookieJar()
    jar.update_from_headers([f"sid=evil; Domain={domain}"], host, "/")
    assert len(jar) == 0
    assert jar.header_for(domain, "/", True) == ""
    assert jar.header_for(host, "/", True) == ""


def test_cookie_registrable_domain_still_shared():
    jar = CookieJar()
    jar.update_from_headers(["sid=ok; Domain=example.com"], "a.example.com", "/")
    assert jar.header_for("b.example.com", "/", True) == "sid=ok"
    assert jar.header_for("example.org", "/", True) == ""


# ---------------------------------------------------------------------------
# F8 — Public Suffix List: Domain= genel sonek olamaz (RFC 6265 §5.3 adım 5)
# ---------------------------------------------------------------------------
def _jar_from(host, *set_cookies):
    jar = CookieJar()
    jar.update_from_headers(set_cookies, URL(f"https://{host}/").host, "/")
    return jar


def _sent(jar, host):
    return jar.header_for(URL(f"https://{host}/").host, "/", True)


@pytest.mark.parametrize("host,domain,sibling", [
    ("example.co.uk", "co.uk", "victim.co.uk"),
    ("evil.co.uk", ".CO.UK.", "victim.co.uk"),
    ("foo.github.io", "github.io", "bar.github.io"),        # PRIVATE bölümü
    ("app.herokuapp.com", "herokuapp.com", "bank.herokuapp.com"),
    ("a.b.test.ck", "test.ck", "c.test.ck"),                 # joker *.ck
    ("x.c.kobe.jp", "c.kobe.jp", "y.c.kobe.jp"),             # joker *.kobe.jp
    ("пример.рф", "рф", "сайт.рф"),                          # IDN, Unicode öznitelik
    ("пример.рф", "xn--p1ai", "сайт.рф"),                    # IDN, A-label öznitelik
    ("食狮.公司.cn", "公司.cn", "shishi.公司.cn"),
    ("xn--85x722f.xn--55qx5d.cn", "公司.cn", "shishi.xn--55qx5d.cn"),
])
def test_cookie_domain_public_suffix_is_ignored(host, domain, sibling):
    jar = _jar_from(host, f"sid=evil; Domain={domain}; Path=/")
    assert len(jar) == 0
    assert _sent(jar, sibling) == ""
    assert _sent(jar, host) == ""


def test_cookie_last_domain_attribute_wins():
    jar = _jar_from("example.co.uk", "sid=evil; Domain=example.co.uk; Domain=co.uk")
    assert len(jar) == 0
    jar = _jar_from("example.co.uk", "sid=ok; Domain=co.uk; Domain=example.co.uk")
    assert _sent(jar, "www.example.co.uk") == "sid=ok"


@pytest.mark.parametrize("host,domain,shared_with,not_sent_to", [
    ("example.co.uk", "example.co.uk", "www.example.co.uk", "other.co.uk"),
    ("login.foo.github.io", "foo.github.io", "foo.github.io", "bar.github.io"),
    ("x.www.ck", "www.ck", "y.www.ck", "z.ck"),                          # istisna !www.ck
    ("www.city.kobe.jp", "city.kobe.jp", "city.kobe.jp", "x.kobe.jp"),   # istisna !city.kobe.jp
    ("a.b.test.ck", "b.test.ck", "c.b.test.ck", "c.test.ck"),
    ("сайт.пример.рф", "пример.рф", "пример.рф", "другой.рф"),
    ("сайт.пример.рф", "XN--E1AFMKFD.XN--P1AI", "www.пример.рф", "другой.рф"),
    ("www.食狮.公司.cn", "食狮.公司.cn", "xn--85x722f.xn--55qx5d.cn", "shishi.公司.cn"),
])
def test_cookie_registrable_domain_under_public_suffix_accepted(host, domain, shared_with, not_sent_to):
    jar = _jar_from(host, f"sid=ok; Domain={domain}")
    assert _sent(jar, host) == "sid=ok"
    assert _sent(jar, shared_with) == "sid=ok"
    assert _sent(jar, not_sent_to) == ""


@pytest.mark.parametrize("host,child", [
    ("github.io", "foo.github.io"),
    ("co.uk", "example.co.uk"),
    ("test.ck", "b.test.ck"),
    ("рф", "пример.рф"),
])
def test_cookie_domain_equal_to_public_suffix_host_is_host_only(host, child):
    jar = _jar_from(host, f"sid=x; Domain={host}")
    assert _sent(jar, host) == "sid=x"
    assert _sent(jar, child) == ""


def _psl_handler(request):
    host = request.url.host
    if host == "evil.co.uk":
        return Response(302, headers=[
            ("Location", "https://victim.co.uk/"),
            ("Set-Cookie", "toss=evil; Domain=co.uk; Path=/"),
            ("Set-Cookie", "own=1; Domain=evil.co.uk; Path=/"),
        ])
    if host == "foo.github.io":
        return Response(200, headers={"Set-Cookie": "toss=gh; Domain=github.io; Path=/"})
    if host == "login.example.co.uk":
        return Response(302, headers=[
            ("Location", "https://www.example.co.uk/"),
            ("Set-Cookie", "sid=ok; Domain=example.co.uk; Path=/"),
        ])
    return Response(200)


def _cookie_of(request):
    return request.headers.get("cookie") or ""


def _check_psl_session_requests(t):
    reqs = {}
    for r in t.requests:
        reqs.setdefault(r.url.host, []).append(_cookie_of(r))
    assert reqs["victim.co.uk"] == [""]             # yönlendirme ara yanıtındaki çerez
    assert reqs["www.evil.co.uk"] == ["own=1"]
    assert reqs["bar.github.io"] == [""]
    assert reqs["foo.github.io"] == ["", ""]        # yok sayılan çerez host-only da kalmaz
    assert reqs["www.example.co.uk"] == ["sid=ok"]  # meşru alan-geneli çerez yönlendirmede
    assert reqs["other.co.uk"] == [""]


_PSL_URLS = ["https://evil.co.uk/", "https://www.evil.co.uk/", "https://foo.github.io/",
             "https://bar.github.io/", "https://foo.github.io/", "https://login.example.co.uk/",
             "https://other.co.uk/"]


def test_sync_session_public_suffix_cookie_not_sent_to_sibling_sites():
    t = MockTransport(_psl_handler)
    with Session(transport=t) as s:
        for url in _PSL_URLS:
            s.get(url)
    _check_psl_session_requests(t)


def test_async_session_public_suffix_cookie_not_sent_to_sibling_sites():
    t = MockTransport(_psl_handler)

    async def main():
        async with AsyncSession(transport=t) as s:
            for url in _PSL_URLS:
                await s.get(url)
    asyncio.run(main())
    _check_psl_session_requests(t)


# ---------------------------------------------------------------------------
# F4 — chunk-size katı ayrıştırılır, chunk sonu CRLF zorunlu
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("line", [b"0x5", b"+5", b"-1", b"1_0", b"", b" ", b"5 5", b"1" * 17, b"\xb2"])
def test_parse_chunk_size_rejects(line):
    with pytest.raises(ValueError):
        parse_chunk_size(line)


@pytest.mark.parametrize("line,n", [(b"0", 0), (b"1a", 26), (b"1A;ext=1", 26), (b"ff ", 255)])
def test_parse_chunk_size_accepts(line, n):
    assert parse_chunk_size(line) == n


def test_buffered_parser_stops_on_lenient_chunk_size():
    raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0x5\r\nhello\r\n0\r\n\r\n"
    assert HTTP1Parser.parse(raw).content == b""


@pytest.fixture(scope="module")
def sv():
    with YerelSunucu() as s:
        yield s


@pytest.mark.parametrize("path", ["/chunk0x", "/chunknocrlf"])
def test_sync_rejects_malformed_chunking(sv, path):
    with Session(verify=sv.ca_path, timeout=3) as s:
        with pytest.raises(ConnectionError, match="[Cc]hunk"):
            s.get(sv.url + path)


@pytest.mark.parametrize("path", ["/chunk0x", "/chunknocrlf"])
def test_async_rejects_malformed_chunking(sv, path):
    async def main():
        async with AsyncSession(verify=sv.ca_path, timeout=3) as s:
            with pytest.raises(ConnectionError, match="[Cc]hunk"):
                await s.get(sv.url + path)
    asyncio.run(main())


# ---------------------------------------------------------------------------
# F5 — yanıt başlık bloğu sınırlı (CRLF CRLF gelmeden sınırsız biriktirme yok)
# ---------------------------------------------------------------------------
def test_sync_response_header_block_is_bounded(sv):
    with Session(verify=sv.ca_path, timeout=10) as s:
        t = time.monotonic()
        with pytest.raises(ConnectionError, match="aşıyor"):
            s.get(sv.url + "/hdrflood")
        assert time.monotonic() - t < 3          # sunucunun 3 sn beklemesini beklemeden


def test_async_response_header_block_is_bounded(sv):
    async def main():
        async with AsyncSession(verify=sv.ca_path, timeout=10) as s:
            t = time.monotonic()
            with pytest.raises(ConnectionError, match="aşıyor"):
                await s.get(sv.url + "/hdrflood")
            assert time.monotonic() - t < 3
    asyncio.run(main())
