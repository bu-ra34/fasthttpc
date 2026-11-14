"""Gerçek mTLS: openssl s_server (-Verify 1 -verify_return_error) karşısında sync + async Session.

TLS 1.3 ve 1.2; RSA / ECDSA P-256,P-384 / Ed25519 istemci anahtarları; şifreli anahtar; PKCS#12;
sertifikasız ve yanlış CA'lı istemcinin reddi; PSK/bilet izolasyonu.
"""
from __future__ import annotations

import asyncio
import os
import socket
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fasthttpc import AsyncSession, Session  # noqa: E402
from fasthttpc.security import session_tickets  # noqa: E402
from fasthttpc.security.client_cert import ClientCert  # noqa: E402
from fasthttpc.security.tls_adapter import TLSAdapter  # noqa: E402
from interop import pki  # noqa: E402
from interop.openssl_server import OPENSSL, SServer  # noqa: E402
from test_interop_openssl import _rejects  # noqa: E402

pytestmark = [pytest.mark.interop, pytest.mark.skipif(OPENSSL is None, reason="openssl CLI yok")]

MODES = ["sync", "async"]
CLIENT_KEYS = ["rsa2048", "p256", "p384", "ed25519"]
VERSIONS = {"tls13": ["-tls1_3"], "tls12": ["-tls1_2"]}


class MEnv:
    def __init__(self, d):
        self.dir = d
        self.server_ca = pki.make_cert("Server CA", None, "p256", ca=True)
        self.server_ca_path = pki.write_ca(d, "server_ca", self.server_ca)
        self.srv = pki.write(d, "srv", pki.make_cert("localhost", self.server_ca, "p256"))
        self.client_ca = pki.make_cert("Client CA", None, "p256", ca=True)
        self.client_ca_path = pki.write_ca(d, "client_ca", self.client_ca)
        self.rogue_ca = pki.make_cert("Rogue CA", None, "p256", ca=True)
        self.clients = {}
        for k in CLIENT_KEYS:
            c = pki.make_cert(f"client-{k}", self.client_ca, k, server_auth=False, sans=[])
            cp, kp = pki.write(d, f"cl_{k}", c)
            os.chmod(kp, 0o600)
            self.clients[k] = (c, cp, kp)
        self.rogue = pki.make_cert("rogue-client", self.rogue_ca, "p256", server_auth=False, sans=[])
        self.rogue_files = pki.write(d, "rogue", self.rogue)
        os.chmod(self.rogue_files[1], 0o600)
        (d / "index.html").write_text("mtls tamam")

    def server(self, version, *extra):
        cert, key = self.srv
        return SServer("-cert", cert, "-key", key, *VERSIONS[version], "-WWW",
                       "-Verify", "1", "-verify_return_error", "-CAfile", self.client_ca_path,
                       *extra, cwd=str(self.dir))


@pytest.fixture(scope="module")
def menv(tmp_path_factory):
    return MEnv(tmp_path_factory.mktemp("mtls"))


@pytest.fixture(autouse=True)
def _reset_tickets():
    session_tickets.default_cache.clear()
    session_tickets.enable_resumption(False)
    yield
    session_tickets.default_cache.clear()
    session_tickets.enable_resumption(False)


def _get(mode, port, ca, cert=None, profile="chrome_131"):
    url = f"https://localhost:{port}/index.html"
    if mode == "sync":
        with Session(impersonate=profile, verify=ca, timeout=15, cert=cert) as s:
            return s.get(url)

    async def run():
        async with AsyncSession(impersonate=profile, verify=ca, timeout=15, cert=cert) as s:
            return await s.get(url)
    return asyncio.run(run())


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key", CLIENT_KEYS)
@pytest.mark.parametrize("version", list(VERSIONS))
def test_mtls_matris(menv, version, key, mode):
    _c, cp, kp = menv.clients[key]
    with menv.server(version) as s:
        r = _get(mode, s.port, menv.server_ca_path, (cp, kp))
    assert r.status_code == 200 and r.content == b"mtls tamam"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("version", list(VERSIONS))
def test_tek_pem_dosyasi(menv, tmp_path, version, mode):
    c, _cp, _kp = menv.clients["p256"]
    f = tmp_path / "all.pem"
    f.write_bytes(c.pem + pki.pem_key(c.key))
    os.chmod(f, 0o600)
    with menv.server(version) as s:
        r = _get(mode, s.port, menv.server_ca_path, str(f))
    assert r.status_code == 200


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("version", list(VERSIONS))
@pytest.mark.parametrize("key", ["rsa2048", "p256", "ed25519"])
def test_sifreli_anahtar_ve_pkcs12(menv, tmp_path, key, version, mode):
    c, cp, _kp = menv.clients[key]
    enc = tmp_path / f"enc_{key}.key"
    enc.write_bytes(c.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.BestAvailableEncryption(b"parola")))
    p12 = tmp_path / f"id_{key}.p12"
    p12.write_bytes(pkcs12.serialize_key_and_certificates(
        b"id", c.key, c.cert, None, serialization.BestAvailableEncryption(b"p12parola")))
    with menv.server(version) as s:
        assert _get(mode, s.port, menv.server_ca_path, (cp, str(enc), "parola")).status_code == 200
        assert _get(mode, s.port, menv.server_ca_path,
                    ClientCert.from_pkcs12(str(p12), "p12parola")).status_code == 200


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("version", list(VERSIONS))
def test_sertifikasiz_istemci_reddedilir(menv, version, mode):
    with menv.server(version) as s:
        _rejects(lambda: _get(mode, s.port, menv.server_ca_path, None),
                 r"alert|handshake|certificate|reset|closed|kapat|sertifika", allowed=Exception)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("version", list(VERSIONS))
def test_yanlis_ca_istemci_sertifikasi_reddedilir(menv, version, mode):
    with menv.server(version) as s:
        _rejects(lambda: _get(mode, s.port, menv.server_ca_path, menv.rogue_files),
                 r"alert|handshake|certificate|reset|closed|kapat|sertifika|unknown", allowed=Exception)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("version", list(VERSIONS))
def test_sunucu_dogrulamasi_mtls_te_de_zorunlu(menv, version, mode):
    """İstemci sertifikası verilse bile sunucu sertifikası güvenilmezse bağlantı REDDEDİLİR."""
    _c, cp, kp = menv.clients["p256"]
    with menv.server(version) as s:
        # server_ca yerine istemci CA'sını güven deposu yap: sunucu sertifikası doğrulanamaz
        _rejects(lambda: _get(mode, s.port, menv.client_ca_path, (cp, kp)),
                 r"sertifika|certificate|doğrulama|verify|MITM", allowed=Exception)


@pytest.mark.parametrize("version", list(VERSIONS))
def test_oturumlar_cert_kimligine_gore_ayri_havuz(menv, version):
    """Farklı sertifikalı iki oturum aynı sunucuya bağlanır; ikisi de kendi kimliğiyle."""
    _c1, cp1, kp1 = menv.clients["p256"]
    _c2, cp2, kp2 = menv.clients["rsa2048"]
    with menv.server(version) as s:
        url = f"https://localhost:{s.port}/index.html"
        with Session(impersonate="chrome_131", verify=menv.server_ca_path, cert=(cp1, kp1)) as a, \
                Session(impersonate="chrome_131", verify=menv.server_ca_path, cert=(cp2, kp2)) as b:
            assert a.get(url).status_code == 200 and b.get(url).status_code == 200
            assert a.get(url).status_code == 200            # a'nın bağlantısı yeniden kullanılır
            ka, kb = list(a.pool._pools), list(b.pool._pools)
            assert ka and kb and not set(ka) & set(kb)
            assert a.client_cert.identity != b.client_cert.identity


# ----------------------------------------------------------- PSK / bilet izolasyonu
def _raw_get(port, ca, cert):
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    es = TLSAdapter.negotiate(sock, "localhost", "chrome_131", ca_path=ca, port=port,
                              **({"client_cert": cert} if cert is not None else {}))
    resumed = bool(es.state.get("resumed"))
    es.send_record(b"GET /index.html HTTP/1.0\r\n\r\n")
    body = b""
    try:
        while True:
            data, ct = es.recv_record(skip_post_handshake=True)
            if ct != 23:
                break
            body += data
    except Exception:
        pass
    sock.close()
    return resumed, body


def test_psk_devaminda_sertifika_gonderilmez_ve_bilet_cert_kimligine_bagli(menv):
    _c, cp, kp = menv.clients["p256"]
    cc = ClientCert.coerce((cp, kp))
    session_tickets.enable_resumption(True)
    with menv.server("tls13") as s:
        r1, b1 = _raw_get(s.port, menv.server_ca_path, cc)
        assert not r1 and b"mtls tamam" in b1
        assert session_tickets.default_cache._data, "bilet önbelleğe alınmadı"
        # Aynı kimlik -> PSK ile devam; istemci sertifikası yeniden gönderilmez (RFC 8446 §4.6.1/§4.4.2)
        r2, b2 = _raw_get(s.port, menv.server_ca_path, cc)
        assert r2 and b"mtls tamam" in b2
        # Sertifikasız oturum, sertifikalı oturumun biletini KULLANAMAZ: tam handshake -> sunucu cert ister
        n_before = sum(len(v) for v in session_tickets.default_cache._data.values())
        assert n_before >= 1
        r3, b3 = _raw_get(s.port, menv.server_ca_path, None)
        assert not r3, "sertifikasız oturum, sertifikalı oturumun biletiyle PSK devam etti"
        assert b"mtls tamam" not in b3, "sunucu sertifikasız istemciyi kabul etti"
        # cert'li oturumun bileti hâlâ önbellekte (cert'siz oturum onu tüketmedi)
        assert sum(len(v) for v in session_tickets.default_cache._data.values()) >= 1
