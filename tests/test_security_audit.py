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
