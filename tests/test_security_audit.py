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


# ---------------------------------------------------------------------------
# F7 — açılmış gövde sınırı (sıkıştırma bombası): Limits.max_decompressed_size
# ---------------------------------------------------------------------------
import gzip as _gzip                                    # noqa: E402
import tracemalloc                                      # noqa: E402
import zlib as _zlib                                    # noqa: E402

import fasthttpc                                        # noqa: E402
from fasthttpc import DecodeError, DecompressedSizeError, Limits  # noqa: E402
from fasthttpc import streaming                         # noqa: E402
from fasthttpc.models.headers import Headers            # noqa: E402
from fasthttpc.protocol.http1_parser import response_framing  # noqa: E402
from fasthttpc.protocol.http2_parser import FrameType, StreamingDecompressor  # noqa: E402
from fasthttpc.streaming import DEFAULT_MAX_DECOMPRESSED_SIZE, IncrementalDecoder, decode_body  # noqa: E402

from async_fakes import start_h2                        # noqa: E402
from test_streaming_h2 import _Sunucu                   # noqa: E402
from tls13_fakeserver import PKI                        # noqa: E402

LIMIT = 100 * 1024
MB = 1024 * 1024
#: Akışta verilen bir parçanın üst sınırı (brotli tamponu ~1.5 x _PIECE büyüyebilir).
PARCA_MAX = 2 * streaming._PIECE
ENCS = ["gzip", "deflate", "br", "zstd", "gzip,br", "br,gzip"]


def _bomba(enc, n=MB):
    return YerelSunucu._sikistir(enc, bytes(n))


def _ic_kodlama(enc):
    """Genişlemenin olduğu (ilk uygulanan) kodlama: sınırı o aşar."""
    return enc.split(",")[0]


def _ce(enc):
    return enc.replace(",", ", ")


def _limitli(**kw):
    return Limits(max_decompressed_size=LIMIT, **kw)


def _akis_sinirli_ve_hata(parcalar, enc):
    """Akış: hata yükselene kadar verilen her parça sınırlı, toplam <= LIMIT."""
    boyutlar = []
    with pytest.raises(DecompressedSizeError) as ei:
        for c in parcalar:
            boyutlar.append(len(c))
    assert sum(boyutlar) <= LIMIT and max(boyutlar, default=0) <= PARCA_MAX
    assert (ei.value.limit, ei.value.encoding) == (LIMIT, _ic_kodlama(enc))


def test_limits_max_decompressed_size_varsayilan_ve_dogrulama():
    assert Limits().max_decompressed_size == DEFAULT_MAX_DECOMPRESSED_SIZE == 256 * MB
    assert Limits(max_decompressed_size=None).max_decompressed_size is None
    assert Session().limits.max_decompressed_size == 256 * MB
    for bad in (0, -1, True, 1.5, "1"):
        with pytest.raises(ValueError):
            Limits(max_decompressed_size=bad)
    assert Limits(max_decompressed_size=5) != Limits()
    assert "max_decompressed_size=5" in repr(Limits(max_decompressed_size=5))
    assert fasthttpc.DecompressedSizeError is DecompressedSizeError
    assert issubclass(DecompressedSizeError, DecodeError)


@pytest.mark.parametrize("enc", ENCS)
def test_decode_body_bomba_sinirlanir(enc):
    z = _bomba(enc)
    with pytest.raises(DecompressedSizeError) as ei:
        decode_body(z, _ce(enc), LIMIT)
    assert (ei.value.limit, ei.value.encoding) == (LIMIT, _ic_kodlama(enc))
    assert decode_body(_bomba(enc, LIMIT), _ce(enc), LIMIT) == bytes(LIMIT)   # tam sınırda
    assert decode_body(z, _ce(enc), None) == bytes(MB)                        # None: kapalı


@pytest.mark.parametrize("enc", ENCS)
def test_artimli_acici_parcalari_sinirli_ve_toplam_sinir(enc):
    z = _bomba(enc)
    d = IncrementalDecoder(_ce(enc), LIMIT)
    _akis_sinirli_ve_hata((p for i in range(0, len(z), 5) for p in d.decode_iter(z[i:i + 5])), enc)
    d = IncrementalDecoder(_ce(enc), None)
    parcalar = list(d.decode_iter(z)) + list(d.flush_iter())
    assert b"".join(parcalar) == bytes(MB) and max(map(len, parcalar)) <= PARCA_MAX


@pytest.mark.parametrize("enc", ["gzip", "br", "zstd"])
def test_bomba_bellek_sinirin_otesine_buyumez(enc):
    """512 MiB'a açılan bomba, 1 MiB sınırla: tepe bellek birkaç MiB (açma artımlı)."""
    if enc == "gzip":
        z = _gzip.compress(bytes(64 * MB), compresslevel=1)
    elif enc == "br":
        z = streaming._decoder_module("br").compress(bytes(512 * MB), quality=1)
    else:
        z = streaming._decoder_module("zstd").ZstdCompressor(level=1).compress(bytes(512 * MB))
    tracemalloc.start()
    try:
        with pytest.raises(DecompressedSizeError):
            decode_body(z, enc, MB)
        _, tepe = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert tepe < 8 * MB, tepe


def test_kodlama_zinciri_uzunlugu_sinirli():
    with pytest.raises(DecodeError, match="zinciri"):
        decode_body(b"x", ", ".join(["gzip"] * 6))
    z = _bomba("gzip")
    for _ in range(4):
        z = _gzip.compress(z)
    assert decode_body(z, ", ".join(["gzip"] * 5), None) == bytes(MB)


def test_eski_brotli_yedek_yolu_da_sinirli(monkeypatch):
    """brotli < 1.2 (output_buffer_limit yok): girdi dilimlenir, toplam sınır yine geçerli."""
    br = streaming._decoder_module("br")
    gercek = br.Decompressor

    class EskiDecompressor:
        def __init__(self):
            self._d = gercek()

        def process(self, data):
            return self._d.process(data)

    monkeypatch.setattr(br, "Decompressor", EskiDecompressor)
    with pytest.raises(DecompressedSizeError):
        decode_body(_bomba("br", 4 * MB), "br", LIMIT)
    assert decode_body(_bomba("br", LIMIT), "br", LIMIT) == bytes(LIMIT)


def test_eski_yardimcilar_da_sinirli():
    with pytest.raises(DecompressedSizeError):
        HTTP1Parser._decompress(_bomba("gzip"), "gzip", LIMIT)
    z = _bomba("br")
    raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: %d\r\n\r\n" % len(z) + z
    with pytest.raises(DecompressedSizeError):
        HTTP1Parser.parse(raw, LIMIT)
    assert HTTP1Parser.parse(raw, None).content == bytes(MB)
    with pytest.raises(DecompressedSizeError):
        StreamingDecompressor("zstd", LIMIT).decompress(_bomba("zstd"))


# --- HTTP/1.1 (yerel TLS sunucusu), sync/async, akışsız/akışlı ------------------------
@pytest.mark.parametrize("enc", ENCS)
def test_sync_h1_bomba(sv, enc):
    with Session(verify=sv.ca_path, timeout=10, limits=_limitli(max_connections=1)) as s:
        u = f"{sv.url}/bomb?enc={enc}&n={MB}"
        with pytest.raises(DecompressedSizeError):
            s.get(u)
        with s.get(u, stream=True) as r:
            _akis_sinirli_ve_hata(r.iter_bytes(), enc)
        with s.get(u, stream=True) as r:
            with pytest.raises(DecompressedSizeError):
                r.content
        assert s.get(f"{sv.url}/bomb?enc={enc}&n={LIMIT}").content == bytes(LIMIT)
        with s.get(f"{sv.url}/bomb?enc={enc}&n={LIMIT}", stream=True) as r:
            assert b"".join(r.iter_bytes()) == bytes(LIMIT)
        assert s.get(sv.url + "/id?i=sonra").content == b"sonra"     # havuz slotu sızmadı
    with Session(verify=sv.ca_path, timeout=10, limits=Limits(max_decompressed_size=None)) as s:
        assert s.get(f"{sv.url}/bomb?enc={enc}&n={MB}").content == bytes(MB)


@pytest.mark.parametrize("enc", ENCS)
def test_async_h1_bomba(sv, enc):
    async def main():
        async with AsyncSession(verify=sv.ca_path, timeout=10, limits=_limitli(max_connections=1)) as s:
            u = f"{sv.url}/bomb?enc={enc}&n={MB}"
            with pytest.raises(DecompressedSizeError):
                await s.get(u)
            r = await s.get(u, stream=True)
            boyutlar = []
            with pytest.raises(DecompressedSizeError):
                async for c in r.aiter_bytes():
                    boyutlar.append(len(c))
            await r.aclose()
            assert sum(boyutlar) <= LIMIT and max(boyutlar, default=0) <= PARCA_MAX
            r = await s.get(u, stream=True)
            with pytest.raises(DecompressedSizeError):
                await r.aread()
            await r.aclose()
            assert (await s.get(f"{sv.url}/bomb?enc={enc}&n={LIMIT}")).content == bytes(LIMIT)
            assert (await s.get(sv.url + "/id?i=sonra")).content == b"sonra"
        async with AsyncSession(verify=sv.ca_path, timeout=10,
                                limits=Limits(max_decompressed_size=None)) as s:
            assert (await s.get(f"{sv.url}/bomb?enc={enc}&n={MB}")).content == bytes(MB)
    asyncio.run(main())


# --- HTTP/2 (sahte h2 sunucusu), sync/async, akışsız/akışlı ---------------------------
async def _h2_bomba(c):
    """GET /bomb/<enc>/<n> -> n sıfır baytın sıkıştırılmışı, 1000 baytlık DATA frame'leri."""
    await c.handshake()
    while True:
        f = await c.next_frame()
        if f is None:
            return
        if f.type != FrameType.HEADERS or not c.requests[f.stream_id]["ended"]:
            continue
        sid = f.stream_id
        _, _, enc, n = dict(c.requests[sid]["headers"])[":path"].split("/")
        z = YerelSunucu._sikistir(enc, bytes(int(n)))
        c.send(c.response_headers(sid, 200, [("content-encoding", _ce(enc))]))
        for i in range(0, len(z), 1000):
            c.send(c.data(sid, z[i:i + 1000], end=i + 1000 >= len(z)))
        await c.flush()


@pytest.fixture(scope="module")
def h2pki():
    return PKI("localhost")


@pytest.fixture(scope="module")
def h2ca(h2pki, tmp_path_factory):
    p = tmp_path_factory.mktemp("h2ca") / "ca.pem"
    p.write_bytes(h2pki.ca_pem())
    return str(p)


@pytest.fixture(scope="module")
def h2sv(h2pki):
    s = _Sunucu(h2pki, _h2_bomba)
    yield s
    s.stop()


@pytest.mark.parametrize("enc", ENCS)
def test_sync_h2_bomba(h2sv, h2ca, enc):
    base = f"https://localhost:{h2sv.port}/bomb/{enc}"
    with Session(impersonate="chrome_131", verify=h2ca, timeout=10, limits=_limitli()) as s:
        with pytest.raises(DecompressedSizeError):
            s.get(f"{base}/{MB}")
        with s.get(f"{base}/{MB}", stream=True) as r:
            assert r.http_version == "HTTP/2"
            _akis_sinirli_ve_hata(r.iter_bytes(), enc)
        r = s.get(f"{base}/{LIMIT}")
        assert r.http_version == "HTTP/2" and r.content == bytes(LIMIT)
        with s.get(f"{base}/{LIMIT}", stream=True) as r:
            assert b"".join(r.iter_bytes()) == bytes(LIMIT)
    with Session(impersonate="chrome_131", verify=h2ca, timeout=10,
                 limits=Limits(max_decompressed_size=None)) as s:
        assert s.get(f"{base}/{MB}").content == bytes(MB)


@pytest.mark.parametrize("enc", ENCS)
def test_async_h2_bomba(h2pki, h2ca, enc):
    async def main():
        srv, port, _ = await start_h2(h2pki, _h2_bomba)
        base = f"https://localhost:{port}/bomb/{enc}"
        async with srv:
            async with AsyncSession(impersonate="chrome_131", verify=h2ca, timeout=10,
                                    limits=_limitli()) as s:
                with pytest.raises(DecompressedSizeError):
                    await s.get(f"{base}/{MB}")
                r = await s.get(f"{base}/{MB}", stream=True)
                assert r.http_version == "HTTP/2"
                boyutlar = []
                with pytest.raises(DecompressedSizeError):
                    async for c in r.aiter_bytes():
                        boyutlar.append(len(c))
                await r.aclose()
                assert sum(boyutlar) <= LIMIT and max(boyutlar, default=0) <= PARCA_MAX
                assert (await s.get(f"{base}/{LIMIT}")).content == bytes(LIMIT)
            async with AsyncSession(impersonate="chrome_131", verify=h2ca, timeout=10,
                                    limits=Limits(max_decompressed_size=None)) as s:
                assert (await s.get(f"{base}/{MB}")).content == bytes(MB)
    asyncio.run(asyncio.wait_for(main(), 30))


# ---------------------------------------------------------------------------
# F9 — Transfer-Encoding / Content-Length çerçevelemesi (RFC 9112 §6.1-6.3)
# ---------------------------------------------------------------------------
def _h(*pairs):
    h = Headers()
    for k, v in pairs:
        h.add(k, v)
    return h


@pytest.mark.parametrize("pairs,http10,beklenen", [
    ([("Transfer-Encoding", "chunked"), ("Content-Length", "3")], False, ("chunked", 0, (), True)),
    ([("Transfer-Encoding", "gzip, chunked")], False, ("chunked", 0, ("gzip",), False)),
    ([("Transfer-Encoding", "gzip")], False, ("eof", 0, ("gzip",), True)),
    ([("Transfer-Encoding", "identity"), ("Content-Length", "5")], False, ("eof", 0, (), True)),
    ([("Transfer-Encoding", "chunked"), ("Transfer-Encoding", "chunked")], False,
     ("chunked", 0, (), False)),
    ([("Transfer-Encoding", "Chunked")], False, ("chunked", 0, (), False)),
    ([("Transfer-Encoding", "chunked"), ("Content-Length", "1")], True, ("eof", 0, (), True)),
    ([("Content-Length", "5, 5")], False, ("length", 5, (), False)),
    ([("Content-Length", "5"), ("Content-Length", "5")], False, ("length", 5, (), False)),
    ([("Content-Length", "007")], False, ("length", 7, (), False)),
    ([("Content-Length", "0")], False, ("length", 0, (), False)),
    ([], False, ("eof", 0, (), False)),
])
def test_response_framing(pairs, http10, beklenen):
    assert tuple(response_framing("GET", 200, _h(*pairs), http10)) == beklenen


@pytest.mark.parametrize("pairs", [
    [("Content-Length", "5"), ("Content-Length", "6")],
    [("Content-Length", "5, 6")],
    [("Content-Length", "abc")],
    [("Content-Length", "-1")],
    [("Content-Length", "+5")],
    [("Content-Length", "5.0")],
    [("Content-Length", "")],
    [("Content-Length", "١")],              # Unicode rakam: isdigit() True ama DIGIT değil
    [("Content-Length", "9" * 25)],
    [("Transfer-Encoding", "compress, chunked")],
    [("Transfer-Encoding", "br")],
    [("Transfer-Encoding", "chunked, gzip")],
    [("Transfer-Encoding", "foo")],
])
def test_response_framing_hatalari(pairs):
    with pytest.raises(ConnectionError, match="çerçeveleme"):
        response_framing("GET", 200, _h(*pairs))


def test_govdesiz_yanitta_cerceveleme_basliklari_yok_sayilir():
    bozuk = _h(("Transfer-Encoding", "foo"), ("Content-Length", "x"))
    assert response_framing("HEAD", 200, bozuk).kind == "none"
    assert response_framing("GET", 304, bozuk).kind == "none"
    assert response_framing("GET", 204, bozuk).kind == "none"


def _sync_get(sv, c, **kw):
    """(gövde, açılan yeni bağlantı sayısı) -- ardından gelen ikinci istek dahil."""
    with Session(verify=sv.ca_path, timeout=5, max_connections=1) as s:
        b0 = sv.kabul_edilen_baglanti
        r = s.get(f"{sv.url}/frame?c={c}", **kw)
        body = r.content
        r.close()
        assert s.get(sv.url + "/id?i=sonra").content == b"sonra"
        return body, sv.kabul_edilen_baglanti - b0


@pytest.mark.parametrize("stream", [False, True])
def test_sync_te_ve_cl_birlikte_te_kazanir_baglanti_yeniden_kullanilmaz(sv, stream):
    body, yeni = _sync_get(sv, "tecl", stream=stream)
    assert body == b"hello"
    assert yeni == 2          # ikinci istek YENİ bağlantıda (TE+CL'li bağlantı kapatıldı)


def test_sync_ayni_cl_tekrari_kabul_ve_baglanti_yeniden_kullanilir(sv):
    assert _sync_get(sv, "clsame") == (b"hello", 1)


@pytest.mark.parametrize("c,beklenen,yeni", [
    ("tegzip", b"te-gzip-govde", 1),
    ("tegzipclose", b"kapanisa-kadar", 2),
    ("http10te", b"2\r\nab\r\n0\r\n\r\n", 2),
])
def test_sync_aktarim_kodlamalari(sv, c, beklenen, yeni):
    assert _sync_get(sv, c) == (beklenen, yeni)


@pytest.mark.parametrize("c", ["cldiff", "clinvalid", "teunknown", "techunkedgzip"])
def test_sync_gecersiz_cerceveleme_hata(sv, c):
    with Session(verify=sv.ca_path, timeout=5, max_connections=1) as s:
        with pytest.raises(ConnectionError, match="çerçeveleme"):
            s.get(f"{sv.url}/frame?c={c}")
        assert s.get(sv.url + "/id?i=sonra").content == b"sonra"     # slot sızmadı


def test_sync_aktarim_kodlamasi_bombasi_da_sinirli(sv):
    with Session(verify=sv.ca_path, timeout=5, limits=_limitli()) as s:
        with pytest.raises(DecompressedSizeError):
            s.get(f"{sv.url}/frame?c=tebomb")
        with s.get(f"{sv.url}/frame?c=tebomb", stream=True) as r:
            with pytest.raises(DecompressedSizeError):
                b"".join(r.iter_raw())


async def _async_get(sv, c, **kw):
    async with AsyncSession(verify=sv.ca_path, timeout=5, max_connections=1) as s:
        b0 = sv.kabul_edilen_baglanti
        r = await s.get(f"{sv.url}/frame?c={c}", **kw)
        body = await r.aread()
        await r.aclose()
        assert (await s.get(sv.url + "/id?i=sonra")).content == b"sonra"
        return body, sv.kabul_edilen_baglanti - b0


@pytest.mark.parametrize("stream", [False, True])
def test_async_te_ve_cl_birlikte_te_kazanir_baglanti_yeniden_kullanilmaz(sv, stream):
    assert asyncio.run(_async_get(sv, "tecl", stream=stream)) == (b"hello", 2)


def test_async_ayni_cl_tekrari_kabul_ve_baglanti_yeniden_kullanilir(sv):
    assert asyncio.run(_async_get(sv, "clsame")) == (b"hello", 1)


@pytest.mark.parametrize("c,beklenen,yeni", [
    ("tegzip", b"te-gzip-govde", 1),
    ("tegzipclose", b"kapanisa-kadar", 2),
    ("http10te", b"2\r\nab\r\n0\r\n\r\n", 2),
])
def test_async_aktarim_kodlamalari(sv, c, beklenen, yeni):
    assert asyncio.run(_async_get(sv, c)) == (beklenen, yeni)


@pytest.mark.parametrize("c", ["cldiff", "clinvalid", "teunknown", "techunkedgzip"])
def test_async_gecersiz_cerceveleme_hata(sv, c):
    async def main():
        async with AsyncSession(verify=sv.ca_path, timeout=5, max_connections=1) as s:
            with pytest.raises(ConnectionError, match="çerçeveleme"):
                await s.get(f"{sv.url}/frame?c={c}")
            assert (await s.get(sv.url + "/id?i=sonra")).content == b"sonra"
    asyncio.run(main())


def test_async_aktarim_kodlamasi_bombasi_da_sinirli(sv):
    async def main():
        async with AsyncSession(verify=sv.ca_path, timeout=5, limits=_limitli()) as s:
            with pytest.raises(DecompressedSizeError):
                await s.get(f"{sv.url}/frame?c=tebomb")
            r = await s.get(f"{sv.url}/frame?c=tebomb", stream=True)
            with pytest.raises(DecompressedSizeError):
                [c async for c in r.aiter_raw()]
            await r.aclose()
    asyncio.run(main())


def test_buffered_parser_cerceveleme():
    ok = HTTP1Parser.parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\nhelloXX")
    assert ok.content == b"hello"
    te = HTTP1Parser.parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n"
                           b"5\r\nhello\r\n0\r\n\r\n")
    assert te.content == b"hello"
    with pytest.raises(ConnectionError):
        HTTP1Parser.parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!")
    r = HTTP1Parser.parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: deflate\r\n\r\n"
                          + _zlib.compress(b"deflate-te"))
    assert r.content == b"deflate-te"


# ---------------------------------------------------------------------------
# F18 — CompressedCertificate (RFC 8879) açma sınırı: doğrulamadan ÖNCE bomba yok
# ---------------------------------------------------------------------------
from fasthttpc.security import cert_validator as _cv     # noqa: E402
from fasthttpc.security.cert_validator import (         # noqa: E402
    MAX_UNCOMPRESSED_CERTIFICATE, CertificateDecompressionError, decompress_certificate_message,
)
from fasthttpc.tls13 import TLSClientConnection         # noqa: E402

from async_fakes import start_tls13                     # noqa: E402
from tls_fakes import FakeSocket, FakeTLSServer, split_records, unseal  # noqa: E402

_CERT_ALGS = {"zlib": 1, "br": 2, "zstd": 3}


def _sikistir_cert(alg, data):
    if alg == "zlib":
        return _zlib.compress(data)
    if alg == "br":
        return streaming._decoder_module("br").compress(data)
    return streaming._decoder_module("zstd").ZstdCompressor().compress(data)   # içerik boyutu başlıkta


def _ccert(alg, comp, ilan, ek=b""):
    """CompressedCertificate (hs 25): algorithm, uncompressed_length=ilan, compressed data."""
    body = (struct.pack("!H", _CERT_ALGS.get(alg, alg) if isinstance(alg, str) else alg)
            + ilan.to_bytes(3, "big") + len(comp).to_bytes(3, "big") + comp + ek)
    return bytes([25]) + len(body).to_bytes(3, "big") + body


def _cert_body(n=3000):
    return b"\x00" + (n - 4).to_bytes(3, "big") + bytes(range(256)) * ((n - 4) // 256) + b"x" * ((n - 4) % 256)


@pytest.mark.parametrize("alg", ["zlib", "br", "zstd"])
def test_sikistirilmis_sertifika_tam_uzunlukta_acilir(alg):
    body = _cert_body()
    out = decompress_certificate_message(_ccert(alg, _sikistir_cert(alg, body), len(body)))
    assert out == b"\x0b" + len(body).to_bytes(3, "big") + body


@pytest.mark.parametrize("alg", ["zlib", "br", "zstd"])
@pytest.mark.parametrize("fark", [-1, +1])
def test_sikistirilmis_sertifika_uzunluk_uyusmazligi_bad_certificate(alg, fark):
    body = _cert_body()
    with pytest.raises(CertificateDecompressionError, match="uyuşmuyor") as ei:
        decompress_certificate_message(_ccert(alg, _sikistir_cert(alg, body), len(body) + fark))
    assert ei.value.alert == 42                           # RFC 8879 §4: bad_certificate
    assert isinstance(ei.value, CertificateValidationError)


@pytest.mark.parametrize("alg", ["zlib", "br", "zstd"])
def test_sertifika_bombasi_hizli_ve_sinirli_bellekle_reddedilir(alg):
    """Küçük girdi, devasa çıktı; ilan edilen uzunluk 4096. Düzeltmeden önce zlib/brotli
    sınırsız açıyordu, zstd de başlıktaki içerik boyutu kadar (64 MiB) ayırıyordu."""
    n = 512 * MB if alg == "br" else 64 * MB
    if alg == "br":
        comp = streaming._decoder_module("br").compress(bytes(n), quality=1)
    else:
        comp = _sikistir_cert(alg, bytes(n))
    assert len(comp) < MB
    tracemalloc.start()
    t = time.monotonic()
    try:
        with pytest.raises(CertificateDecompressionError) as ei:
            decompress_certificate_message(_ccert(alg, comp, 4096))
        _, tepe = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert ei.value.alert == 42
    assert tepe < 2 * MB, tepe
    assert time.monotonic() - t < 2


def test_uncompressed_length_ust_siniri_acmadan_reddedilir(monkeypatch):
    assert MAX_UNCOMPRESSED_CERTIFICATE == 100 * 1024       # BoringSSL SSL_MAX_CERT_LIST_DEFAULT

    def acma_yok(*a, **kw):
        raise AssertionError("sınırı aşan mesaj açılmamalı")

    monkeypatch.setattr(_cv, "_decompress_bounded", acma_yok)
    for ilan in (MAX_UNCOMPRESSED_CERTIFICATE + 1, 2 ** 24 - 1):
        with pytest.raises(CertificateDecompressionError, match="sınırı") as ei:
            decompress_certificate_message(_ccert("zlib", b"\x78\x9c\x03\x00", ilan))
        assert ei.value.alert == 47                       # illegal_parameter (BoringSSL ile aynı)


@pytest.mark.parametrize("msg,alert", [
    (_ccert("zlib", _zlib.compress(b"abc"), 3, ek=b"\x00"), 50),        # mesajın sonunda fazladan bayt
    (_ccert("zlib", b"", 3), 50),                                        # boş compressed data
    (_ccert(4, b"\x00\x01", 3), 47),                                     # bilinmeyen algoritma
    (_ccert("zlib", _zlib.compress(b"abc")[:-3], 3), 42),                # kesik zlib akışı
    (_ccert("zlib", _zlib.compress(b"abc") + b"zz", 3), 42),             # akıştan sonra çöp
    (_ccert("br", b"\xff\xff\xff\xff", 3), 42),                          # açılamayan brotli
    (b"\x19\x00\x00\x03\x00\x01\x00", 50),                               # çok kısa
])
def test_bozuk_sikistirilmis_sertifika_alertleri(msg, alert):
    with pytest.raises(CertificateDecompressionError) as ei:
        decompress_certificate_message(msg)
    assert ei.value.alert == alert


# El sıkışma testlerinde bomba tek TLS kaydına sığmalı (sahte sunucular mesajı bölmez):
# 12 MiB sıfırın zlib'i ~12 KB, 64 MiB'ın brotli'si ~100 bayt.
_BOMBA = {"zlib": lambda: _zlib.compress(bytes(12 * MB), 9),
          "br": lambda: streaming._decoder_module("br").compress(bytes(64 * MB), quality=1)}


def _bomba_cert(alg):
    comp = _BOMBA[alg]()
    assert len(comp) < 16000

    def f(cert_msg):
        return _ccert(alg, comp, len(cert_msg) - 4)
    return f


def _gecerli_cert(alg):
    def f(cert_msg):
        return _ccert(alg, _sikistir_cert(alg, cert_msg[4:]), len(cert_msg) - 4)
    return f


def _sansio_el_sikisma(conn, server):
    to_server = conn.initiate()
    for _ in range(10):
        to_client = server.receive(to_server) if to_server else b""
        conn.receive_data(to_client)
        to_server = conn.data_to_send()
        if conn.handshake_complete and not to_server:
            return


@pytest.mark.parametrize("alg", ["zlib", "br"])
def test_sansio_cekirdek_gecerli_sikistirilmis_sertifika(h2pki, h2ca, alg):
    from tls13_fakeserver import FakeTLS13Server
    conn = TLSClientConnection("localhost", "chrome_131", ca_path=h2ca)
    _sansio_el_sikisma(conn, FakeTLS13Server(h2pki, compress_cert=_gecerli_cert(alg)))
    assert conn.handshake_complete and conn.peer_certificate is not None


@pytest.mark.parametrize("alg", ["zlib", "br"])
def test_sansio_cekirdek_bomba_bad_certificate_alert_gonderir(h2pki, h2ca, alg):
    from fasthttpc.tls13.errors import TLSError
    from tls13_fakeserver import FakeTLS13Server
    conn = TLSClientConnection("localhost", "chrome_131", ca_path=h2ca)
    server = FakeTLS13Server(h2pki, compress_cert=_bomba_cert(alg))
    to_client = server.receive(conn.initiate())
    with pytest.raises(TLSError, match="Sıkıştırılmış sertifika"):
        conn.receive_data(to_client)
    server.receive(conn.data_to_send())              # istemci handshake anahtarıyla şifreli alert
    assert server.alerts == [b"\x02\x2a"]            # fatal bad_certificate (RFC 8879 §4)


@pytest.mark.parametrize("alg", ["zlib", "br"])
def test_async_oturum_bomba_sertifika_reddedilir_ve_alert_gider(h2pki, h2ca, alg):
    async def main():
        srv, port, servers = await start_tls13(h2pki, compress_cert=_bomba_cert(alg))
        async with srv:
            async with AsyncSession(impersonate="chrome_131", verify=h2ca, timeout=5) as s:
                with pytest.raises(ConnectionError, match="Sıkıştırılmış sertifika"):
                    await s.get(f"https://localhost:{port}/")
            for _ in range(100):
                if servers and servers[0].alerts:
                    break
                await asyncio.sleep(0.02)
            assert servers[0].alerts == [b"\x02\x2a"]
    asyncio.run(asyncio.wait_for(main(), 20))


@pytest.fixture
def _no_pki(monkeypatch):
    from fasthttpc.security import tls_adapter as ta
    monkeypatch.setattr(ta, "validate_server_certificate", lambda payload, host, **kw: "LEAF")
    monkeypatch.setattr(ta, "verify_certificate_verify", lambda payload, leaf, th, **kw: 0x0804)


@pytest.mark.parametrize("alg", ["zlib", "br"])
def test_sync_tlsadapter_gecerli_ve_bomba_sikistirilmis_sertifika(_no_pki, alg):
    from fasthttpc.security.tls_adapter import TLSAdapter
    body = _cert_body()
    ok = _ccert("zlib", _zlib.compress(body), len(body))
    srv = FakeTLSServer(flight=[("hs", 8), ("msg", ok), ("hs", 15), ("hs", 20)])
    es = TLSAdapter.negotiate(FakeSocket(on_send=srv), "example.com", None)
    assert es.state["using_app_keys"]

    bomba = _ccert(alg, _BOMBA[alg](), 4096)
    srv = FakeTLSServer(flight=[("hs", 8), ("msg", bomba), ("hs", 15), ("hs", 20)])
    sock = FakeSocket(on_send=srv)
    with pytest.raises(ConnectionError, match="Sıkıştırılmış sertifika"):
        TLSAdapter.negotiate(sock, "example.com", None)
    st = srv.state
    rec = split_records(sock.sends[-1])[0]
    assert unseal(st["ck"], st["civ"], 0, rec, st["name"]) == (b"\x02\x2a", 21)
