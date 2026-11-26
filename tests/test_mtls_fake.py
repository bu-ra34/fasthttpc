"""mTLS: sahte sunucularla (ağsız/loopback) protokol davranışı.

Sıra dışı/tekrar CertificateRequest, uyumsuz imza şeması listesi (BOŞ Certificate gönderilmeli),
post-handshake CertificateRequest reddi, CertificateVerify bağlamı/transcript noktası, TLS 1.2'de
EMS session_hash'in CertificateVerify'dan önce alınması.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import socket
import struct
import sys
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fasthttpc.security import mtls  # noqa: E402
from fasthttpc.security.client_cert import ClientCert  # noqa: E402
from fasthttpc.security.tls_adapter import HandshakeOrderValidator, TLSAdapter, TLSProtocolError  # noqa: E402
from fasthttpc.tls13 import AsyncTLSStream, HandshakeComplete, TLSClientConnection, TLSError  # noqa: E402
from interop import pki as ipki  # noqa: E402
from test_tls13_core import HOST, handshake, pki, trust  # noqa: E402,F401
from netutil import start_server  # noqa: E402
from tls12_servers import Fake12Server, PKI12, serve_fake_in_thread  # noqa: E402
from tls13_fakeserver import FakeTLS13Server, expand_label, sync_serve  # noqa: E402

CR_ALL = None


def _ext(t, d):
    return struct.pack("!HH", t, len(d)) + d


def _sa(vals):
    d = b"".join(struct.pack("!H", v) for v in vals)
    return struct.pack("!H", len(d)) + d


def cr13(sigs, cas=(), cert_sigs=None):
    e = _ext(13, _sa(sigs))
    if cert_sigs is not None:
        e += _ext(50, _sa(cert_sigs))
    if cas:
        d = b"".join(struct.pack("!H", len(x)) + x for x in cas)
        e += _ext(47, struct.pack("!H", len(d)) + d)
    return b"\x00" + struct.pack("!H", len(e)) + e


def cr12(types, sigs, cas=()):
    d = b"".join(struct.pack("!H", len(x)) + x for x in cas)
    return bytes([len(types)]) + bytes(types) + _sa(sigs) + struct.pack("!H", len(d)) + d


@pytest.fixture(scope="module")
def pki12():
    return PKI12()


@pytest.fixture(scope="module")
def files(pki12, tmp_path_factory):
    return pki12.write(tmp_path_factory.mktemp("mtls12"))


@pytest.fixture(scope="module")
def cca():
    return ipki.make_cert("Fake Client CA", None, "p256", ca=True)


def mk_client(cca, kind="p256"):
    c = ipki.make_cert("fake-client", cca, kind, server_auth=False, sans=[])
    return ClientCert([c.cert.public_bytes(serialization.Encoding.DER)], c.key), c


# ----------------------------------------------------------------- sunucu (TLS 1.3, istemci kimlik doğrulamalı)
class MtlsFake13(FakeTLS13Server):
    """İstemci Certificate/CertificateVerify'ı kaydeder ve doğrular (transcript'e katılır)."""

    def __init__(self, *a, cr_body, **kw):
        super().__init__(*a, tamper={"cert_request"}, **kw)
        self.cr_body = cr_body
        self.client_ders = None
        self.cv_ok = None
        self.cv_scheme = None
        self.order = []

    def _on_encrypted(self, content, ctype):
        if self.state == "WAIT_FINISHED" and ctype == 22 and content[0] in (11, 15):
            self.order.append(content[0])
            if content[0] == 11:
                body = content[4:]
                assert body[0] == 0, "Certificate certificate_request_context boş olmalı"
                ln = int.from_bytes(body[1:4], "big")
                ders, p = [], 4
                while p < 4 + ln:
                    n = int.from_bytes(body[p:p + 3], "big")
                    ders.append(body[p + 3:p + 3 + n])
                    el = struct.unpack("!H", body[p + 3 + n:p + 5 + n])[0]
                    assert el == 0
                    p += 5 + n + el
                self.client_ders = ders
            else:
                assert self.client_ders, "boş Certificate sonrası CertificateVerify gönderilmemeli"
                scheme, sl = struct.unpack("!HH", content[4:8])
                sig = content[8:8 + sl]
                self.cv_scheme = scheme
                pub = x509.load_der_x509_certificate(self.client_ders[0]).public_key()
                signed = b"\x20" * 64 + b"TLS 1.3, client CertificateVerify\x00" + self.th()
                try:
                    if scheme == 0x0403:
                        pub.verify(sig, signed, ec.ECDSA(hashes.SHA256()))
                    elif scheme == 0x0503:
                        pub.verify(sig, signed, ec.ECDSA(hashes.SHA384()))
                    elif scheme == 0x0804:
                        pub.verify(sig, signed, padding.PSS(padding.MGF1(hashes.SHA256()), 32), hashes.SHA256())
                    elif scheme == 0x0807:
                        pub.verify(sig, signed)
                    else:
                        raise AssertionError(f"beklenmeyen şema {scheme:#x}")
                    self.cv_ok = True
                except Exception:
                    self.cv_ok = False
            self.transcript += content
            return b""
        return super()._on_encrypted(content, ctype)


def _serve_sync(server):
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)

    def run():
        c, _ = ls.accept()
        sync_serve(server, c)
        ls.close()
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return ls.getsockname()[1], t


def _core(server, cert, trust_kw):
    conn = TLSClientConnection(HOST, "chrome_131", client_cert=cert, **trust_kw)
    events = handshake(conn, server)
    return conn, events


@pytest.mark.parametrize("kind,scheme", [("p256", 0x0403), ("p384", 0x0503), ("ed25519", 0x0807),
                                         ("rsa2048", 0x0804)])
def test_13_gecerli_istek_sertifika_ve_cv(pki, trust, cca, kind, scheme):
    cc, c = mk_client(cca, kind)
    srv = MtlsFake13(pki, cr_body=cr13([0x0401, scheme, 0x0403 if kind == "p384" else 0x0807]))
    conn, events = _core(srv, cc, trust)
    assert any(isinstance(e, HandshakeComplete) for e in events)
    assert srv.client_ders == cc.chain_der and srv.cv_ok is True and srv.cv_scheme == scheme
    assert srv.order == [11, 15]                      # Certificate -> CertificateVerify -> Finished
    assert conn.client_cert_sent and conn.client_signature_scheme == scheme
    # Finished MAC'i sunucuda doğrulandı (transcript Certificate+CV'yi kapsıyor): state CONNECTED
    assert srv.state == "CONNECTED"


def test_13_uyumsuz_sema_listesi_bos_certificate(pki, trust, cca):
    cc, _ = mk_client(cca, "p256")
    srv = MtlsFake13(pki, cr_body=cr13([0x0401, 0x0201, 0x0807]))   # PKCS1 / SHA-1 / ed25519: p256'ya uymaz
    conn, events = _core(srv, cc, trust)
    assert any(isinstance(e, HandshakeComplete) for e in events)
    assert srv.client_ders == [] and srv.order == [11] and srv.cv_ok is None
    assert not conn.client_cert_sent and srv.state == "CONNECTED"


def test_13_pkcs1_asla_rsa_anahtar_icin_bile(pki, trust, cca):
    cc, _ = mk_client(cca, "rsa2048")
    srv = MtlsFake13(pki, cr_body=cr13([0x0401, 0x0501, 0x0601]))
    conn, _ = _core(srv, cc, trust)
    assert srv.client_ders == [] and srv.order == [11]


def test_13_sertifikasiz_istemci_bos_certificate(pki, trust):
    srv = MtlsFake13(pki, cr_body=cr13([0x0403]))
    conn, events = _core(srv, None, trust)
    assert any(isinstance(e, HandshakeComplete) for e in events)
    assert srv.client_ders == [] and srv.order == [11] and srv.state == "CONNECTED"


def test_13_ca_uyusmazligi_bos_certificate(pki, trust, cca):
    cc, _ = mk_client(cca, "p256")
    other = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Hic Alakasiz CA")]).public_bytes()
    srv = MtlsFake13(pki, cr_body=cr13([0x0403], cas=[other]))
    _core(srv, cc, trust)
    assert srv.client_ders == [] and srv.order == [11]
    ok = MtlsFake13(pki, cr_body=cr13([0x0403], cas=[other, cca.cert.subject.public_bytes()]))
    _core(ok, cc, trust)
    assert ok.client_ders == cc.chain_der and ok.cv_ok


def test_13_cert_sigalgs_kisiti_bos_certificate(pki, trust, cca):
    cc, _ = mk_client(cca, "p256")          # zincir ECDSA-SHA256 ile imzalı
    srv = MtlsFake13(pki, cr_body=cr13([0x0403], cert_sigs=[0x0804, 0x0805]))
    _core(srv, cc, trust)
    assert srv.client_ders == []


@pytest.mark.parametrize("body,needle", [
    (b"\x00\x00\x00", "signature_algorithms"),                       # zorunlu uzantı yok
    (b"\x01\xaa" + struct.pack("!H", 0), "context"),                 # bağlam boş değil
    (cr13([0x0403]) + b"\x00", "uzunluğu"),
])
def test_13_bozuk_certificate_request_reddedilir(pki, trust, body, needle):
    srv = MtlsFake13(pki, cr_body=body)
    conn = TLSClientConnection(HOST, "chrome_131", **trust)
    with pytest.raises(TLSError, match=needle):
        handshake(conn, srv)
    assert conn.closed


def test_13_sunucu_sertifikasi_dogrulamasi_mtls_te_de_zorunlu(cca, trust):
    from tls13_fakeserver import PKI
    srv = MtlsFake13(PKI(HOST), cr_body=cr13([0x0403]))      # güvenilmeyen CA'lı sunucu
    cc, _ = mk_client(cca)
    conn = TLSClientConnection(HOST, "chrome_131", client_cert=cc, **trust)
    with pytest.raises(TLSError, match="sertifika doğrulaması"):
        handshake(conn, srv)


def test_13_post_handshake_certificate_request_reddedilir(pki, trust, cca):
    cc, _ = mk_client(cca)
    srv = FakeTLS13Server(pki)
    conn = TLSClientConnection(HOST, "chrome_131", client_cert=cc, **trust)
    handshake(conn, srv)
    assert conn.handshake_complete
    msg = b"\x0d" + len(cr13([0x0403])).to_bytes(3, "big") + cr13([0x0403])
    with pytest.raises(TLSError, match="unexpected_message.*CertificateRequest"):
        conn.receive_data(srv.write.seal(msg, 22))
    assert conn.closed
    out = conn.data_to_send()
    h, payload = out[:5], out[5:]
    content, ctype = srv.read.open(h, payload)
    assert (ctype, content) == (21, b"\x02\x0a")             # fatal unexpected_message


def test_post_handshake_auth_ilan_edilmez():
    from fasthttpc.fingerprint import PROFILES  # noqa: F401
    from fasthttpc.tls_crafter import TLSImpersonator
    import fasthttpc.fingerprint as fp
    names = [n for n in dir(fp) if n.endswith("PROFILES") or n == "PROFILES"]
    assert names
    profs = getattr(fp, "PROFILES")
    for name in list(profs):
        rec, _p, _r = TLSImpersonator("example.com", profile=name).build_client_hello()
        body = rec[5 + 4:]
        p = 2 + 32
        p += 1 + body[p]
        p += 2 + struct.unpack("!H", body[p:p + 2])[0]
        p += 1 + body[p]
        el = struct.unpack("!H", body[p:p + 2])[0]
        p += 2
        end = p + el
        while p < end:
            et, ln = struct.unpack("!HH", body[p:p + 4])
            assert et != 49, f"{name}: post_handshake_auth (49) ilan ediliyor"
            p += 4 + ln


def test_validator_psk_devaminda_certificate_request_yok():
    v = HandshakeOrderValidator()
    v.expect(2)
    v.psk_accepted = True
    v.expect(8)
    with pytest.raises(TLSProtocolError, match="unexpected_message"):
        v.expect(13)


def test_validator_certificate_request_tek_ve_yalniz_ee_sonrasi():
    v = HandshakeOrderValidator()
    v.expect(2)
    with pytest.raises(TLSProtocolError):
        v.expect(13)                     # EE'den önce
    v = HandshakeOrderValidator()
    for t in (2, 8, 13):
        v.expect(t)
    with pytest.raises(TLSProtocolError):
        v.expect(13)                     # tekrar
    v.expect(11)
    v.expect(15)
    v.expect(20)
    with pytest.raises(TLSProtocolError):
        v.expect(13)                     # bağlandıktan sonra


# ------------------------------------------------ senkron TLSAdapter yolu (aynı pure mantık)
def test_sync_13_cv_ve_bos_certificate(pki, trust, cca):
    cc, _ = mk_client(cca, "p256")
    for sigs, want_cert in (([0x0403], True), ([0x0401], False)):
        srv = MtlsFake13(pki, cr_body=cr13(sigs))
        port, t = _serve_sync(srv)
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        es = TLSAdapter.negotiate(sock, HOST, "chrome_131", ca_path=trust["ca_path"], port=port,
                                  client_cert=cc)
        assert es.state["client_cert_sent"] is want_cert
        sock.close()
        t.join(5)
        assert srv.state == "CONNECTED"
        assert (srv.client_ders == cc.chain_der) is want_cert and (srv.cv_ok is True) is want_cert


def test_sync_13_sertifikasiz_ve_post_handshake_reddi(pki, trust, cca):
    srv = MtlsFake13(pki, cr_body=cr13([0x0403]))
    port, t = _serve_sync(srv)
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    TLSAdapter.negotiate(sock, HOST, "chrome_131", ca_path=trust["ca_path"], port=port)
    sock.close()
    t.join(5)
    assert srv.client_ders == [] and srv.state == "CONNECTED"

    # post-handshake CertificateRequest
    plain = FakeTLS13Server(pki)
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)

    def run():
        c, _ = ls.accept()
        try:
            while plain.state != "CONNECTED":
                c.sendall(plain.receive(c.recv(65536)) or b"")
            body = cr13([0x0403])
            c.sendall(plain.write.seal(b"\x0d" + len(body).to_bytes(3, "big") + body, 22))
            c.settimeout(5)
            data = c.recv(65536)
            plain.receive(data)
        except OSError:
            pass
        finally:
            c.close()
            ls.close()
    th = threading.Thread(target=run, daemon=True)
    th.start()
    s2 = socket.create_connection(("127.0.0.1", ls.getsockname()[1]), timeout=10)
    es = TLSAdapter.negotiate(s2, HOST, "chrome_131", ca_path=trust["ca_path"])
    with pytest.raises(TLSProtocolError, match="unexpected_message"):
        es.recv_record(skip_post_handshake=True)
    th.join(5)
    s2.close()
    assert plain.alerts and plain.alerts[0] == b"\x02\x0a"


# --------------------------------------------------------------------------- async akış
def test_async_13_stream(pki, trust, cca):
    cc, _ = mk_client(cca, "ed25519")
    srv = MtlsFake13(pki, cr_body=cr13([0x0807]))

    async def main():
        async def handler(reader, writer):
            try:
                while True:
                    d = await reader.read(65536)
                    if not d:
                        break
                    out = srv.receive(d)
                    if out:
                        writer.write(out)
                        await writer.drain()
            finally:
                writer.close()
        server = await start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        st = await AsyncTLSStream.connect("127.0.0.1", port, "chrome_131", server_hostname=HOST,
                                          ca_path=trust["ca_path"], client_cert=cc)
        assert st.conn.client_cert_sent
        for _ in range(100):
            if srv.state == "CONNECTED":
                break
            await asyncio.sleep(0.02)
        st.writer.close()
        server.close()
    asyncio.run(asyncio.wait_for(main(), 20))
    assert srv.cv_ok and srv.cv_scheme == 0x0807


# ------------------------------------------------------------------------------- TLS 1.2
def _verify12(srv, scheme_expect=None):
    cv = srv.client_cv_msg
    scheme, sl = struct.unpack("!HH", cv[4:8])
    sig = cv[8:8 + sl]
    pub = x509.load_der_x509_certificate(srv.client_ders_leaf).public_key()
    data = srv.client_cv_transcript
    if scheme in (0x0403, 0x0503):
        pub.verify(sig, data, ec.ECDSA(hashes.SHA256() if scheme == 0x0403 else hashes.SHA384()))
    elif scheme == 0x0804:
        pub.verify(sig, data, padding.PSS(padding.MGF1(hashes.SHA256()), 32), hashes.SHA256())
    elif scheme == 0x0401:
        pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
    elif scheme == 0x0807:
        pub.verify(sig, data)
    else:
        raise AssertionError(hex(scheme))
    if scheme_expect is not None:
        assert scheme == scheme_expect


def _negotiate12(srv_obj, files, cert):
    port, t, ls = serve_fake_in_thread(srv_obj)
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        es = TLSAdapter.negotiate(sock, "localhost", "chrome_131", ca_path=files[0], port=port,
                                  client_cert=cert)
        return es
    finally:
        sock.close()
        t.join(5)


@pytest.mark.parametrize("kind,types,sigs,expect", [
    ("p256", [64], [0x0804, 0x0403], 0x0403),
    ("p384", [64], [0x0503], 0x0503),
    ("rsa2048", [1], [0x0401, 0x0804], 0x0804),          # PSS tercih
    ("rsa2048", [1], [0x0401], 0x0401),                  # TLS 1.2'de PKCS#1 serbest
    ("ed25519", [64], [0x0807], 0x0807),
])
def test_12_certificate_ve_cv(pki12, files, cca, kind, types, sigs, expect):
    cc, c = mk_client(cca, kind)
    srv = Fake12Server(pki12, cr_body=cr12(types, sigs, cas=[cca.cert.subject.public_bytes()]),
                       suite=0xC02F if kind == "rsa2048" else 0xC02B)
    es = _negotiate12(srv, files, cc)
    assert srv.finished_ok, "Finished doğrulanamadı: transcript sırası (Cert, CKE, CV) bozuk"
    assert srv.client_cert_ders == cc.chain_der
    srv.client_ders_leaf = srv.client_cert_ders[0]
    _verify12(srv, expect)                  # imza CKE DAHİL, CV HARİÇ transcript üzerinde
    assert es.state.get("client_cert_sent", True)


@pytest.mark.parametrize("kind,types,sigs", [
    ("p256", [1], [0x0403]),                 # sertifika türü uymuyor (rsa_sign)
    ("p256", [64], [0x0401, 0x0201]),        # şema kesişimi boş
    ("rsa2048", [64], [0x0804]),
    ("ed25519", [1], [0x0807]),
])
def test_12_uyumsuz_bos_certificate(pki12, files, cca, kind, types, sigs):
    cc, _ = mk_client(cca, kind)
    srv = Fake12Server(pki12, cr_body=cr12(types, sigs))
    _negotiate12(srv, files, cc)
    assert srv.finished_ok and srv.client_cert_ders == [] and srv.client_cv_ok is None


def test_12_ca_uyusmazligi_ve_sertifikasiz(pki12, files, cca):
    cc, _ = mk_client(cca, "p256")
    other = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Alakasiz")]).public_bytes()
    srv = Fake12Server(pki12, cr_body=cr12([64], [0x0403], cas=[other]))
    _negotiate12(srv, files, cc)
    assert srv.finished_ok and srv.client_cert_ders == []
    srv2 = Fake12Server(pki12, cr_body=cr12([64], [0x0403]))
    _negotiate12(srv2, files, None)
    assert srv2.finished_ok and srv2.client_cert_ders == []


@pytest.mark.parametrize("body,needle", [
    (b"\x00" + _sa([0x0403]) + b"\x00\x00", "CertificateRequest"),     # certificate_types boş
    (b"\x01\x40" + b"\x00\x00\x00\x00", "CertificateRequest"),         # sigalgs boş
    (cr12([64], [0x0403]) + b"\x00", "CertificateRequest"),            # fazla bayt
])
def test_12_bozuk_certificate_request(pki12, files, body, needle):
    srv = Fake12Server(pki12, cr_body=body)
    port, t, ls = serve_fake_in_thread(srv)
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    with pytest.raises(Exception, match=needle):
        TLSAdapter.negotiate(sock, "localhost", "chrome_131", ca_path=files[0], port=port)
    sock.close()
    t.join(5)
    ls.close()


def test_12_async_cert(pki12, files, cca):
    cc, _ = mk_client(cca, "p256")
    srv = Fake12Server(pki12, cr_body=cr12([64], [0x0403]), suite=0xC02B)
    port, t, ls = serve_fake_in_thread(srv)

    async def main():
        st = await AsyncTLSStream.connect("127.0.0.1", port, "chrome_131", server_hostname="localhost",
                                          ca_path=files[0], client_cert=cc)
        assert st.conn.client_cert_sent and st.conn.client_signature_scheme == 0x0403
        await asyncio.sleep(0.2)
        st.writer.close()
    asyncio.run(asyncio.wait_for(main(), 20))
    t.join(5)
    assert srv.finished_ok and srv.client_cert_ders == cc.chain_der
