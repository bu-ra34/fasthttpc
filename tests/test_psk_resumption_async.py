"""Async sans-IO çekirdekte (fasthttpc.tls13) TLS 1.3 PSK resumption.

* Gerçek OpenSSL (127.0.0.1, Python ssl) sunucusuna AsyncTLSStream ile ikinci
  bağlantıda resumption (sunucu tarafı session_reused=True).
* Bayrak kapalıyken PSK gönderilmez; ca_path/port bilet önbelleğini ayırır.
* Sahte sunucuyla: PSK'da Certificate/CV reddi, HRR sonrası PSK seçimi, hash
  uyumsuzluğu, tek kullanımlık bilet, özel cert_validator'da resumption yok.
"""
import asyncio
import datetime
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from fasthttpc.security import session_tickets as st
from fasthttpc.tls13 import AsyncTLSStream, TLSClientConnection, TLSError
from test_trust_store_cache import _make_ca
from test_tls13_core import handshake
from tls13_fakeserver import PKI, FakeTLS13Server

EXT_PSK = st.EXT_PRE_SHARED_KEY


@pytest.fixture(autouse=True)
def _clean_cache():
    st.default_cache.clear()
    yield
    st.default_cache.clear()
    st.enable_resumption(False)


# ------------------------------------------------------ gerçek OpenSSL sunucusu
@pytest.fixture
def tls_server(tmp_path):
    ca_key, ca = _make_ca()
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca.subject).public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "leaf.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "leaf.key").write_bytes(leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(tmp_path / "leaf.pem"), str(tmp_path / "leaf.key"))
    ctx.num_tickets = 2

    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(8)
    port = lsock.getsockname()[1]
    results, stop = [], threading.Event()

    def serve():
        lsock.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = lsock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                c.settimeout(5)
                s = ctx.wrap_socket(c, server_side=True)
                data = s.recv(1024)
                results.append(s.session_reused)
                s.sendall(b"echo:" + data)
                s.close()
            except Exception as e:  # pragma: no cover - teşhis
                results.append(e)
                c.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield port, str(ca_path), results
    stop.set()
    t.join(2)
    lsock.close()


async def _roundtrip(port, ca_path, payload=b"ping"):
    stream = await AsyncTLSStream.connect("127.0.0.1", port, "chrome_131",
                                          server_hostname="localhost", ca_path=ca_path)
    try:
        await stream.send_record(payload)
        data, _ = await stream.recv_record(skip_post_handshake=True)
        return stream, data
    finally:
        stream.writer.close()


def test_async_resumption_gercek_sunucuda(tls_server):
    port, ca_path, results = tls_server
    st.enable_resumption(True)

    async def run():
        s1, d1 = await _roundtrip(port, ca_path, b"one")
        assert d1 == b"echo:one" and not s1.state["resumed"]
        assert len(st.default_cache) >= 1
        s2, d2 = await _roundtrip(port, ca_path, b"two")
        return s1, s2, d2

    s1, s2, d2 = asyncio.run(run())
    assert d2 == b"echo:two"
    assert s2.state["resumed"] is True
    assert s2.conn.peer_certificate is s1.conn.peer_certificate   # kimlik biletten
    assert results == [False, True]                                # OpenSSL: session_reused


def test_bilet_tek_kullanimlik(tls_server):
    """Bir bilet teklif edilince önbellekten çıkar; aynı PSK ikinci kez gönderilmez."""
    port, ca_path, results = tls_server
    st.enable_resumption(True)
    asyncio.run(_roundtrip(port, ca_path))
    key = st.cache_key("localhost", port, ca_path)
    first = st.default_cache.pop(key)
    st.default_cache.put(first)
    s, _ = asyncio.run(_roundtrip(port, ca_path))
    assert s.state["resumed"] is True
    ids = []
    while True:
        t = st.default_cache.pop(key)
        if t is None:
            break
        ids.append(t.ticket)
    assert first.ticket not in ids                 # en yeni bilet tüketildi, geri konmadı
    assert len(ids) == len(set(ids))


def test_bayrak_kapaliyken_psk_gonderilmez(tls_server):
    port, ca_path, results = tls_server

    async def run():
        s1, _ = await _roundtrip(port, ca_path)
        s2, _ = await _roundtrip(port, ca_path)
        return s1, s2

    s1, s2 = asyncio.run(run())
    for s in (s1, s2):
        assert EXT_PSK not in st.client_hello_extension_types(s.conn._ch1)
        assert s.conn._rms is None and not s.state["resumed"]
    assert len(st.default_cache) == 0
    assert results == [False, False]


def test_bayrak_kapaliyken_mevcut_bilet_kullanilmaz(tls_server):
    port, ca_path, results = tls_server
    st.enable_resumption(True)
    asyncio.run(_roundtrip(port, ca_path))
    n = len(st.default_cache)
    assert n >= 1
    st.enable_resumption(False)
    s, _ = asyncio.run(_roundtrip(port, ca_path))
    assert EXT_PSK not in st.client_hello_extension_types(s.conn._ch1)
    assert len(st.default_cache) == n          # dokunulmadı
    assert results[-1] is False


def test_farkli_ca_path_veya_port_bileti_paylasmaz(tls_server):
    port, ca_path, _ = tls_server
    st.enable_resumption(True)
    asyncio.run(_roundtrip(port, ca_path))
    assert len(st.default_cache) >= 1

    def hello_ext_types(**kw):
        c = TLSClientConnection("localhost", "chrome_131", **kw)
        return st.client_hello_extension_types(c.initiate())

    assert EXT_PSK not in hello_ext_types(ca_path="/baska/ca.pem", port=port)
    assert EXT_PSK not in hello_ext_types(ca_path=ca_path, port=port + 1)
    assert EXT_PSK not in hello_ext_types(ca_path=None, port=port)
    assert EXT_PSK not in hello_ext_types(ca_path=ca_path, port=port,
                                          cert_validator=lambda m, h: None)   # özel doğrulayıcı
    # bunların hiçbiri bileti tüketmedi
    assert st.default_cache.pop(st.cache_key("localhost", port, ca_path)) is not None


def test_senkron_ve_async_ayni_onbellegi_paylasir(tls_server, monkeypatch):
    """Senkron yoldan alınan bilet aynı (host, port, ca_path) için async'te kullanılır."""
    from fasthttpc.security import tls_adapter
    from fasthttpc.security.cert_validator import validate_server_certificate
    port, ca_path, results = tls_server
    monkeypatch.setattr(
        tls_adapter, "validate_server_certificate",
        lambda payload, host, *a, **k: validate_server_certificate(payload, host, ca_path=ca_path))
    st.enable_resumption(True)
    # senkron: ca_path=ca_path ile (anahtar async ile aynı olsun)
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    es = tls_adapter.TLSAdapter.negotiate(raw, "localhost", "chrome_131", ca_path=ca_path)
    es.send_record(b"sync")
    es.recv_record(skip_post_handshake=True)
    raw.close()
    s, d = asyncio.run(_roundtrip(port, ca_path, b"async"))
    assert d == b"echo:async" and s.state["resumed"] is True
    assert results == [False, True]


# ------------------------------------------------------------- sahte sunucu
HOST = "example.com"


@pytest.fixture(scope="module")
def pki():
    return PKI(HOST)


@pytest.fixture
def trust(pki, tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_bytes(pki.ca_pem())
    return {"ca_path": str(ca), "port": 443}


def _full(pki, trust, store, **srv_kw):
    conn = TLSClientConnection(HOST, "chrome_131", **trust)
    server = FakeTLS13Server(pki, psk_store=store, **srv_kw)
    handshake(conn, server)
    return conn, server


def test_sahte_sunucuda_resumption_ve_binder(pki, trust):
    st.enable_resumption(True)
    store = {}
    c1, s1 = _full(pki, trust, store, tickets=2)
    assert c1.handshake_complete and not c1.resumed and len(st.default_cache) == 2
    c2, s2 = _full(pki, trust, store)                      # binder sunucuda doğrulanır
    assert c2.handshake_complete and c2.resumed and s2.resumed
    assert c2.peer_certificate is c1.peer_certificate
    assert c2.crypto_state()["resumed"] is True
    # uygulama verisi çalışıyor
    out = c2.send_application_data(b"x")
    assert s2.read.open(out[:5], out[5:])[0] == b"x"
    # c2 yeni biletler bıraktı (resumption zinciri)
    assert len(st.default_cache) >= 1


def test_psk_modunda_sertifika_gelirse_reddedilir(pki, trust):
    st.enable_resumption(True)
    store = {}
    _full(pki, trust, store)
    with pytest.raises(TLSError, match="unexpected_message"):
        _full(pki, trust, store, tamper={"psk_with_cert"})


def test_psk_hash_uyumsuzlugu_reddedilir(pki, trust):
    """Bilet sha256 (0x1301) paketine ait; sunucu PSK'yı kabul edip sha384 (0x1302) seçerse red."""
    st.enable_resumption(True)
    store = {}
    _full(pki, trust, store)
    conn = TLSClientConnection(HOST, "chrome_131", **trust)
    server = FakeTLS13Server(pki, suite=0x1302, tamper={"force_psk"})
    with pytest.raises(TLSError, match="hash"):
        handshake(conn, server)


def test_hrr_sonrasi_psk_secimi_protokol_ihlali(pki, trust, monkeypatch):
    from test_tls13_core import _HRRImpersonator
    from fasthttpc.tls13 import connection as core_mod
    monkeypatch.setattr(core_mod, "_supported_groups", lambda: (0x001D, 0x0017))
    st.enable_resumption(True)
    store = {}
    _full(pki, trust, store)
    srv = FakeTLS13Server(pki, hrr_group=0x0017, tamper={"force_psk"})
    conn = TLSClientConnection(HOST, "chrome_131", impersonator=_HRRImpersonator(HOST, profile="chrome_131"),
                               **trust)
    with pytest.raises(TLSError, match="HRR sonrası"):
        handshake(conn, srv)


def test_teklif_edilmemis_psk_reddedilir(pki, trust):
    """Bayrak kapalı, PSK teklif etmedik; sunucu yine de pre_shared_key seçerse protokol ihlali."""
    st.enable_resumption(False)
    conn = TLSClientConnection(HOST, "chrome_131", **trust)
    with pytest.raises(TLSError, match="teklif etmediğimiz"):
        handshake(conn, FakeTLS13Server(pki, tamper={"force_psk"}))


def test_check_psk_selection_saf_fonksiyon():
    t = st.SessionTicket(HOST, b"t", b"p" * 32, 0x1301, 0, 100)
    assert st.check_psk_selection(t, None, 0x1301, False) is False
    assert st.check_psk_selection(t, 0, 0x1301, False) is True
    for args in ((None, 0, 0x1301, False), (t, 1, 0x1301, False), (t, 0, 0x1302, False), (t, 0, 0x1301, True)):
        with pytest.raises(st.PskViolation):
            st.check_psk_selection(*args)


def test_ticket_tek_kullanimlik_sahte(pki, trust):
    st.enable_resumption(True)
    store = {}
    _full(pki, trust, store, tickets=1)
    assert len(st.default_cache) == 1
    c2, s2 = _full(pki, trust, store, tickets=1)
    assert c2.resumed
    # c2'nin kendi bileti var; ilk bilet tüketildi, aynı PSK tekrar teklif edilmez
    ids_seen = [ch["exts"][EXT_PSK][4:28] for ch in s2.client_hellos]
    c3, s3 = _full(pki, trust, store, tickets=1)
    assert s3.client_hellos[0]["exts"][EXT_PSK][4:28] != ids_seen[0]


def test_ozel_cert_validator_resumption_yapmaz(pki, trust):
    st.enable_resumption(True)
    store = {}
    _full(pki, trust, store)
    n = len(st.default_cache)
    from fasthttpc.security import cert_validator as cv
    conn = TLSClientConnection(HOST, "chrome_131", port=443, ca_path=trust["ca_path"],
                               cert_validator=lambda m, h: cv.validate_server_certificate(
                                   m, h, ca_path=trust["ca_path"]))
    server = FakeTLS13Server(pki, psk_store=store, tickets=2)
    handshake(conn, server)
    assert not conn.resumed and EXT_PSK not in server.client_hellos[0]["exts"]
    assert len(st.default_cache) == n            # ne tüketti ne sakladı


def test_bayrak_kapaliyken_sahte_sunucu_psk_gormez(pki, trust):
    st.enable_resumption(False)
    store = {}
    conn, server = _full(pki, trust, store)
    assert EXT_PSK not in server.client_hellos[0]["exts"]
    assert len(st.default_cache) == 0 and conn._rms is None

