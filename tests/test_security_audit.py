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

from fasthttpc import AsyncSession, Session
from fasthttpc.cookies import CookieJar
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
def test_cookie_domain_tld_is_host_only():
    jar = CookieJar()
    jar.update_from_headers(["sid=evil; Domain=com; Path=/"], "attacker.com", "/")
    assert jar.header_for("bank.com", "/", True) == ""
    assert jar.header_for("attacker.com", "/", True) == "sid=evil"


def test_cookie_domain_dot_tld_is_host_only():
    jar = CookieJar()
    jar.update_from_headers(["sid=evil; Domain=.com"], "www.attacker.com", "/")
    assert jar.header_for("bank.com", "/", True) == ""


def test_cookie_domain_on_ip_host_is_host_only():
    jar = CookieJar()
    jar.update_from_headers(["sid=x; Domain=0.0.1"], "10.0.0.1", "/")
    assert jar.header_for("9.0.0.1", "/", True) == ""
    assert jar.header_for("10.0.0.1", "/", True) == "sid=x"


def test_cookie_registrable_domain_still_shared():
    jar = CookieJar()
    jar.update_from_headers(["sid=ok; Domain=example.com"], "a.example.com", "/")
    assert jar.header_for("b.example.com", "/", True) == "sid=ok"
    assert jar.header_for("example.org", "/", True) == ""


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
# FHC-11 / FHC-12 — TLS 1.3 uyumluluk CCS'i: el sıkışmadan sonra değil, en fazla bir kez
# ---------------------------------------------------------------------------
class _CcsSock:
    def __init__(self, data):
        self.data = data

    def recv(self, n):
        out, self.data = self.data[:n], self.data[n:]
        return out


_CCS = b"\x14\x03\x03\x00\x01\x01"


def _es(**state):
    from fasthttpc.security.tls_adapter import EncryptedSocket
    st = {"is_tls13": True, "using_app_keys": False}
    st.update(state)
    return EncryptedSocket(_CcsSock(_CCS), st)


def test_fhc11_ccs_after_handshake_rejected():
    from fasthttpc.security.tls_adapter import TLSProtocolError
    with pytest.raises(TLSProtocolError, match="unexpected_message: el sıkışma bittikten sonra"):
        _es(using_app_keys=True).recv_record()


def test_fhc12_second_compat_ccs_rejected():
    from fasthttpc.security.tls_adapter import TLSProtocolError
    with pytest.raises(TLSProtocolError, match="unexpected_message: ikinci change_cipher_spec"):
        _es(ccs_seen=True).recv_record()
