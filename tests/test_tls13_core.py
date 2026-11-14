"""sans-IO TLS 1.3 çekirdeği (fasthttpc.tls13) uçtan uca testleri.

Sunucu tarafı tests/tls13_fakeserver.py içinde yalnızca `cryptography` ile
simüle edilir; ağ yok. Sertifika doğrulaması GERÇEK cert_validator ile yapılır
(test CA'sı güven deposuna enjekte edilir).
"""
import hashlib
import inspect
import struct

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from fasthttpc.crypto_math import PureCryptoEngine as P
from fasthttpc.security import cert_validator as cv
from fasthttpc.tls_crafter import TLSImpersonator
from fasthttpc.tls13 import (
    TLSClientConnection, TLSError, TLSAlertError,
    HandshakeComplete, ApplicationData, NewSessionTicket, KeyUpdateReceived,
    AlertReceived, ConnectionClosed, application_traffic_secrets,
)
from fasthttpc.tls13 import connection as core_mod

from tls13_fakeserver import PKI, FakeTLS13Server, parse_client_hello, ext

HOST = "example.com"


@pytest.fixture(scope="module")
def pki():
    return PKI(HOST)


@pytest.fixture
def trust(pki, tmp_path, monkeypatch):
    """Test CA'sını güven deposuna ekler; TLSClientConnection kwargs döner.

    cert_validator ca_path parametresini destekliyorsa (faz4/faz5 sonrası) onu
    kullanır; değilse certifi.where()'i test CA'sına yönlendirir.
    """
    ca = tmp_path / "ca.pem"
    ca.write_bytes(pki.ca_pem())
    if "ca_path" in inspect.signature(cv.validate_server_certificate).parameters:
        return {"ca_path": str(ca)}

    class _Certifi:
        @staticmethod
        def where():
            return str(ca)

    monkeypatch.setattr(cv, "certifi", _Certifi)
    return {}


def handshake(conn, server, chunk=None):
    """İki sans-IO uç arasında byte taşır; istemci olaylarını döner."""
    events = []
    to_server = conn.initiate()
    for _ in range(20):
        to_client = server.receive(to_server) if to_server else b""
        if chunk:
            for i in range(0, len(to_client), chunk):
                events += conn.receive_data(to_client[i:i + chunk])
        else:
            events += conn.receive_data(to_client)
        to_server = conn.data_to_send()
        if conn.handshake_complete and not to_server:
            break
    return events


# --------------------------------------------------------------- mutlu yol
@pytest.mark.parametrize("suite", [0x1301, 0x1302, 0x1303])
def test_tam_handshake_ve_uygulama_verisi(pki, trust, suite):
    server = FakeTLS13Server(pki, suite=suite, alpn="h2")
    conn = TLSClientConnection(HOST, "chrome_131", **trust)
    events = handshake(conn, server)

    hc = [e for e in events if isinstance(e, HandshakeComplete)]
    assert len(hc) == 1 and hc[0].cipher_suite == suite and hc[0].alpn == "h2"
    assert hc[0].signature_scheme == 0x0403
    assert conn.peer_certificate.subject == pki.cert.subject
    assert server.state == "CONNECTED"
    assert conn.crypto_state()["alpn"] == "h2"
    assert conn.crypto_state()["using_app_keys"] is True

    # NewSessionTicket ApplicationData'dan ayrı olay olarak gelir
    evs = conn.receive_data(server.send_app(b"merhaba", pad=5))
    assert any(isinstance(e, NewSessionTicket) for e in events + evs)
    assert [e.data for e in evs if isinstance(e, ApplicationData)] == [b"merhaba"]

    server.receive(conn.send_application_data(b"GET / HTTP/1.1\r\n\r\n"))
    assert server.app_in == [b"GET / HTTP/1.1\r\n\r\n"]


def test_client_hello_profil_parmak_izini_tasir(pki, trust):
    """ClientHello eski yoldaki TLSImpersonator ile üretilir — JA3 sırası korunur."""
    conn = TLSClientConnection(HOST, "chrome_131", **trust)
    rec = conn.initiate()
    ch = parse_client_hello(rec[5:])
    ref = parse_client_hello(TLSImpersonator(HOST, "chrome_131").build_client_hello()[0][5:])
    grease = lambda xs: [x for x in xs if (x & 0x0F0F) != 0x0A0A]
    assert sorted(grease(ch["order"])) == sorted(grease(ref["order"]))   # Chrome sırayı karıştırır
    assert grease(ch["suites"]) == grease(ref["suites"])
    assert ch["alpn"] == ["h2", "http/1.1"]


def test_alpn_override(pki, trust):
    conn = TLSClientConnection(HOST, "chrome_131", alpn=["http/1.1"], **trust)
    assert parse_client_hello(conn.initiate()[5:])["alpn"] == ["http/1.1"]


@pytest.mark.parametrize("chunk", [1, 7, 333])
def test_parca_parca_gelen_veri(pki, trust, chunk):
    server = FakeTLS13Server(pki)
    conn = TLSClientConnection(HOST, "chrome_131", **trust)
    handshake(conn, server, chunk=chunk)
    assert conn.handshake_complete


@pytest.mark.parametrize("mode", ["coalesce", "split_records", "no_ccs"])
def test_record_sinirlari_ve_handshake_birlestirme(pki, trust, mode):
    server = FakeTLS13Server(pki, tamper={mode})
    conn = TLSClientConnection(HOST, "chrome_131", **trust)
    handshake(conn, server)
    assert conn.handshake_complete and server.state == "CONNECTED"


def test_buyuk_veri_record_lara_bolunur(pki, trust):
    server = FakeTLS13Server(pki)
    conn = TLSClientConnection(HOST, "chrome_131", **trust)
    handshake(conn, server)
    data = bytes(range(256)) * 200  # 51200 byte
    server.receive(conn.send_application_data(data))
    assert b"".join(server.app_in) == data
    assert all(len(p) <= 2 ** 14 for p in server.app_in)


def test_anahtar_takvimi_eski_yolla_ayni():
    """application_traffic_secrets, crypto_math.derive_application_keys ile tutarlı."""
    for h, kl in ((hashlib.sha256, 16), (hashlib.sha384, 32)):
        hs_secret, th = h(b"hs").digest(), h(b"t").digest()
        c, s = application_traffic_secrets(hs_secret, th, h)
        res = P.derive_application_keys(hs_secret, th, kl, hash_alg=h)
        ck, civ, sk, siv = res[:4]
        if len(res) == 6:  # faz1 sonrası secret'lar da dönüyor
            assert res[4:] == (c, s)
        assert P.tls13_hkdf_expand_label(c, "key", b"", kl, hash_alg=h) == ck
        assert P.tls13_hkdf_expand_label(s, "iv", b"", 12, hash_alg=h) == siv


# ------------------------------------------------------ post-handshake
def test_sunucu_keyupdate_istegi_yanitlanir(pki, trust):
    server = FakeTLS13Server(pki)
    conn = TLSClientConnection(HOST, "chrome_131", **trust)
    handshake(conn, server)

    evs = conn.receive_data(server.send_key_update(request=True) + server.send_app(b"yeni anahtar"))
    ku = [e for e in evs if isinstance(e, KeyUpdateReceived)]
    assert ku and ku[0].update_requested
    assert [e.data for e in evs if isinstance(e, ApplicationData)] == [b"yeni anahtar"]

    # istemcinin KeyUpdate yanıtı + yeni anahtarlı veri sunucuda çözülebilmeli
    server.receive(conn.send_application_data(b"istemci yeni anahtar"))
    assert server.key_updates_received == 1
    assert server.app_in == [b"istemci yeni anahtar"]


def test_istemci_kaynakli_keyupdate(pki, trust):
    server = FakeTLS13Server(pki)
    conn = TLSClientConnection(HOST, "chrome_131", **trust)
    handshake(conn, server)
    reply = server.receive(conn.update_keys(request_peer=True))
    evs = conn.receive_data(reply + server.send_app(b"ok"))
    assert [e.data for e in evs if isinstance(e, ApplicationData)] == [b"ok"]
    server.receive(conn.send_application_data(b"x"))
    assert server.app_in == [b"x"]


def test_close_notify_ve_alert(pki, trust):
    server = FakeTLS13Server(pki)
    conn = TLSClientConnection(HOST, "chrome_131", **trust)
    handshake(conn, server)
    evs = conn.receive_data(server.send_alert(1, 0))
    assert any(isinstance(e, ConnectionClosed) for e in evs) and conn.closed

    server2 = FakeTLS13Server(pki)
    conn2 = TLSClientConnection(HOST, "chrome_131", **trust)
    handshake(conn2, server2)
    evs = conn2.receive_data(server2.send_alert(2, 80))
    assert any(isinstance(e, AlertReceived) and e.description == 80 for e in evs)

    server3 = FakeTLS13Server(pki)
    conn3 = TLSClientConnection(HOST, "chrome_131", **trust)
    handshake(conn3, server3)
    server3.receive(conn3.close())
    assert server3.alerts == [b"\x01\x00"]


# --------------------------------------------- güvenlik: reddedilmeli
@pytest.mark.parametrize("tamper,match", [
    ("bad_cv_sig", "kimlik doğrulaması"),
    ("wrong_key_cv", "kimlik doğrulaması"),
    ("bad_finished", "Finished"),
    ("skip_cv", "unexpected_message|CertificateVerify"),
    ("skip_cert", "unexpected_message|Certificate"),
    ("tls12", "TLS 1.3"),
    ("wrong_session_id", "session_id"),
    ("cert_request", "CertificateRequest|unexpected"),
    ("early_app_data", "unexpected_message"),
])
def test_saldiri_senaryolari_reddedilir(pki, trust, tamper, match):
    server = FakeTLS13Server(pki, tamper={tamper})
    conn = TLSClientConnection(HOST, "chrome_131", **trust)
    with pytest.raises(TLSError, match=match):
        handshake(conn, server)
    assert conn.closed and not conn.handshake_complete


def test_guvenilmeyen_ca_reddedilir(pki, trust):
    """Başka bir CA'nın imzaladığı (MITM) sertifika."""
    server = FakeTLS13Server(PKI(HOST))
    conn = TLSClientConnection(HOST, "chrome_131", **trust)
    with pytest.raises(TLSError, match="sertifika doğrulaması"):
        handshake(conn, server)


def test_hostname_uyusmazligi_reddedilir(pki, trust):
    server = FakeTLS13Server(pki)
    conn = TLSClientConnection("baska.example.org", "chrome_131", **trust)
    with pytest.raises(TLSError, match="sertifika doğrulaması"):
        handshake(conn, server)


def test_bozulmus_record_reddedilir(pki, trust):
    server = FakeTLS13Server(pki)
    conn = TLSClientConnection(HOST, "chrome_131", **trust)
    handshake(conn, server)
    rec = bytearray(server.send_app(b"veri"))
    rec[-1] ^= 1
    with pytest.raises(TLSError, match="bad_record_mac"):
        conn.receive_data(bytes(rec))


def test_buyuk_record_reddedilir(pki, trust):
    conn = TLSClientConnection(HOST, "chrome_131", **trust)
    conn.initiate()
    with pytest.raises(TLSError, match="record_overflow"):
        conn.receive_data(struct.pack("!BHH", 22, 0x0303, 2 ** 14 + 257))


def test_acik_alert_handshake_sirasinda(pki, trust):
    conn = TLSClientConnection(HOST, "chrome_131", **trust)
    conn.initiate()
    with pytest.raises(TLSAlertError) as ei:
        conn.receive_data(b"\x15\x03\x03\x00\x02\x02\x28")
    assert ei.value.description == 40


def test_handshake_oncesi_gonderim_reddedilir():
    conn = TLSClientConnection(HOST, "chrome_131")
    conn.initiate()
    with pytest.raises(TLSError):
        conn.send_application_data(b"x")


# ------------------------------------------------------------- HRR
class _P256Shares:
    def __init__(self, group):
        self.groups = [group]
        self.priv = ec.generate_private_key(ec.SECP256R1())

    def public(self):
        return self.priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    def shared_secret(self, group, peer):
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer)
        return self.priv.exchange(ec.ECDH(), pub)


class _HRRImpersonator(TLSImpersonator):
    """faz2'nin build_retry_client_hello sözleşmesini taklit eden test çifti."""

    def build_retry_client_hello(self, group, cookie=None):
        self.key_shares = _P256Shares(group)
        msg = self.last_client_hello[5:]
        b = msg[4:]
        off = 35 + b[34]
        off += 2 + struct.unpack("!H", b[off:off + 2])[0]
        off += 1 + b[off]
        head, exts_raw = b[:off], b[off + 2:]
        out, p = b"", 0
        pub = self.key_shares.public()
        while p < len(exts_raw):
            t, l = struct.unpack("!HH", exts_raw[p:p + 4])
            body = exts_raw[p + 4:p + 4 + l]
            if t == 51:
                entry = struct.pack("!HH", group, len(pub)) + pub
                body = struct.pack("!H", len(entry)) + entry
            if t == 21:  # padding'i atla (uzunluk değişti)
                p += 4 + l
                continue
            out += ext(t, body)
            p += 4 + l
        if cookie:
            out += ext(44, struct.pack("!H", len(cookie)) + cookie)
        body = head + struct.pack("!H", len(out)) + out
        m = b"\x01" + len(body).to_bytes(3, "big") + body
        return struct.pack("!BHH", 22, 0x0303, len(m)) + m


@pytest.mark.parametrize("cookie", [None, b"cerez123"])
def test_hello_retry_request_p256(pki, trust, monkeypatch, cookie):
    monkeypatch.setattr(core_mod, "_supported_groups", lambda: (0x001D, 0x0017))
    server = FakeTLS13Server(pki, hrr_group=0x0017, hrr_cookie=cookie)
    imp = _HRRImpersonator(HOST, profile="chrome_131")
    conn = TLSClientConnection(HOST, "chrome_131", impersonator=imp, **trust)
    handshake(conn, server)
    assert conn.handshake_complete and server.state == "CONNECTED"
    assert len(server.client_hellos) == 2


def test_hrr_desteklenmeyen_grup_reddedilir(pki, trust):
    server = FakeTLS13Server(pki, hrr_group=0x0017)
    imp = _HRRImpersonator(HOST, profile="chrome_131")
    conn = TLSClientConnection(HOST, "chrome_131", impersonator=imp, **trust)
    # Baseline'da (faz2 merge öncesi) P-256 desteklenmiyor -> illegal_parameter;
    # faz2 sonrası desteklenir ve handshake tamamlanır.
    try:
        handshake(conn, server)
    except TLSError as e:
        assert "illegal_parameter" in str(e)
    else:
        assert 0x0017 in core_mod._supported_groups()


def test_hrr_zaten_teklif_edilen_grup_reddedilir(pki, trust):
    server = FakeTLS13Server(pki, hrr_group=0x001D)
    imp = _HRRImpersonator(HOST, profile="chrome_131")
    conn = TLSClientConnection(HOST, "chrome_131", impersonator=imp, **trust)
    with pytest.raises(TLSError, match="illegal_parameter"):
        handshake(conn, server)


@pytest.mark.skipif(not hasattr(TLSImpersonator, "build_retry_client_hello"),
                    reason="faz2 (HRR crafter) henüz birleştirilmedi")
def test_hrr_gercek_impersonator_ile(pki, trust):
    """faz2 merge sonrası: gerçek TLSImpersonator.build_retry_client_hello yolu."""
    imp = TLSImpersonator(HOST, profile="chrome_131")
    offered = core_mod._offered_groups(imp)
    candidates = [g for g in core_mod._supported_groups() if g not in offered and g in (0x0017, 0x0018)]
    if not candidates:
        pytest.skip("teklif edilmemiş desteklenen grup yok")
    server = FakeTLS13Server(pki, hrr_group=candidates[0], hrr_cookie=b"c00k")
    conn = TLSClientConnection(HOST, "chrome_131", impersonator=imp, **trust)
    handshake(conn, server)
    assert conn.handshake_complete and len(server.client_hellos) == 2
