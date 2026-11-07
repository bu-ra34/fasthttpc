"""PSK resumption uçtan uca testi: yerel Python ssl (OpenSSL) TLS 1.3 sunucusu.
Ağ gerekmez — 127.0.0.1 üzerinde geçici bir sunucu ve geçici bir CA kullanılır."""
import socket
import ssl
import threading

import pytest
from cryptography.hazmat.primitives import serialization

from fasthttpc.security import session_tickets, tls_adapter
from fasthttpc.security.cert_validator import validate_server_certificate
from tests.test_trust_store_cache import _make_ca


@pytest.fixture
def tls_server(tmp_path, monkeypatch):
    ca_key, ca = _make_ca()
    # _make_leaf özel anahtarı dönmediği için sunucu leaf'ini burada üretiyoruz.
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
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
    cert_path = tmp_path / "leaf.pem"
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path = tmp_path / "leaf.key"
    key_path.write_bytes(leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(cert_path), str(key_path))
    ctx.num_tickets = 2

    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(8)
    port = lsock.getsockname()[1]
    results = []
    stop = threading.Event()

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
            except Exception as e:  # pragma: no cover - teşhis için
                results.append(e)
                c.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()

    monkeypatch.setattr(
        tls_adapter, "validate_server_certificate",
        lambda payload, host, *a, **k: validate_server_certificate(payload, host, ca_path=str(ca_path)),
    )
    session_tickets.default_cache.clear()
    yield port, results
    stop.set()
    t.join(2)
    lsock.close()
    session_tickets.default_cache.clear()
    session_tickets.enable_resumption(False)


def _roundtrip(port, payload=b"ping", profile="chrome_131"):
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    es = tls_adapter.TLSAdapter.negotiate(raw, "localhost", profile)
    es.send_record(payload)
    data, _ = es.recv_record(skip_post_handshake=True)
    raw.close()
    return es, data


def test_full_handshake_without_flag_stores_nothing(tls_server):
    port, results = tls_server
    session_tickets.enable_resumption(False)
    es, data = _roundtrip(port)
    assert data == b"echo:ping"
    assert "resumption_master_secret" not in es.state
    assert len(session_tickets.default_cache) == 0
    assert results == [False]


def test_psk_resumption_roundtrip(tls_server):
    port, results = tls_server
    session_tickets.enable_resumption(True)
    es1, d1 = _roundtrip(port, b"one")
    assert d1 == b"echo:one" and not es1.state.get("resumed")
    assert len(session_tickets.default_cache) >= 1
    peer = es1.state["peer_certificate"]

    es2, d2 = _roundtrip(port, b"two")
    assert d2 == b"echo:two"
    assert es2.state.get("resumed") is True
    assert es2.state["peer_certificate"] is peer
    assert results[0] is False and results[1] is True


def test_corrupt_ticket_falls_back_to_full_handshake(tls_server):
    port, results = tls_server
    session_tickets.enable_resumption(True)
    _roundtrip(port, b"one")
    t = session_tickets.default_cache.pop(session_tickets.cache_key("localhost", port))
    t.ticket = b"\x00" * len(t.ticket)  # sunucu bunu çözemez -> PSK reddedilir
    session_tickets.default_cache.clear()
    session_tickets.default_cache.put(t)
    es, d = _roundtrip(port, b"x")
    assert d == b"echo:x" and not es.state.get("resumed")
    assert results[-1] is False


def test_wrong_psk_rejected_by_server(tls_server):
    """Bilet geçerli ama PSK yanlışsa binder doğrulanamaz; sunucu bağlantıyı reddetmeli."""
    port, _results = tls_server
    session_tickets.enable_resumption(True)
    _roundtrip(port, b"one")
    t = session_tickets.default_cache.pop(session_tickets.cache_key("localhost", port))
    t.psk = bytes(len(t.psk))
    session_tickets.default_cache.clear()
    session_tickets.default_cache.put(t)
    with pytest.raises((ConnectionError, OSError)):
        _roundtrip(port, b"x")


def test_ticket_not_shared_across_trust_roots(tls_server):
    """ca_path farklıysa (farklı güven kökü) bilet kullanılmamalı."""
    port, _results = tls_server
    session_tickets.enable_resumption(True)
    _roundtrip(port, b"one")
    assert session_tickets.default_cache.pop(session_tickets.cache_key("localhost", port, "/other/ca.pem")) is None
    assert session_tickets.default_cache.pop(session_tickets.cache_key("localhost", port + 1)) is None
    assert session_tickets.default_cache.pop(session_tickets.cache_key("localhost", port)) is not None


def test_negotiate_passes_ca_path(tls_server, monkeypatch):
    port, _results = tls_server
    seen = []
    orig = tls_adapter.validate_server_certificate
    monkeypatch.setattr(tls_adapter, "validate_server_certificate",
                        lambda p, h, ca_path=None: (seen.append(ca_path), orig(p, h))[1])
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    tls_adapter.TLSAdapter.negotiate(raw, "localhost", "chrome_131", ca_path="/x/ca.pem")
    raw.close()
    assert seen == ["/x/ca.pem"]


def test_default_profile_without_psk_modes_skips_resumption(tls_server):
    port, results = tls_server
    session_tickets.enable_resumption(True)
    _roundtrip(port, b"one", profile="default")
    es, _ = _roundtrip(port, b"two", profile="default")
    assert not es.state.get("resumed")
