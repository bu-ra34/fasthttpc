"""tlslite-ng (saf Python, ikinci bağımsız TLS uygulaması) sunucusu karşısında TLS 1.3 testleri +
sunucu tarafı kontrollü bozma senaryoları (imza şeması ihlalleri vb.).

openssl s_server'ın yapamadığı şeyler: sertifika sıkıştırma (RFC 8879), record_size_limit (RFC 8449),
sunucu tarafı record dolgusu, çok sayıda NewSessionTicket, imza şeması ihlali.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tlslite import tlsconnection  # noqa: E402
from tlslite.api import HandshakeSettings  # noqa: E402

from interop import pki  # noqa: E402
from interop.tlslite_server import TlsliteServer  # noqa: E402
from test_interop_openssl import MODES, _get, _rejects  # noqa: E402,F401

pytestmark = pytest.mark.interop


@pytest.fixture(scope="module")
def tenv(tmp_path_factory):
    d = tmp_path_factory.mktemp("tlslite")
    ca = pki.make_cert("tlslite Root", None, "p256", ca=True)
    e = type("E", (), {})()
    e.dir, e.ca_path = d, pki.write_ca(d, "ca", ca)
    e.certs = {k: pki.write(d, k, pki.make_cert("localhost", ca, k)) for k in ("rsa2048", "p256", "p384")}
    return e


def _settings(**kw):
    s = HandshakeSettings()
    s.minVersion = s.maxVersion = (3, 4)
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def _srv(tenv, key="p256", settings=None, **kw):
    c, k = tenv.certs[key]
    return TlsliteServer(c, k, settings or _settings(), **kw)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("cipher,suite", [("aes128gcm", 0x1301), ("aes256gcm", 0x1302), ("chacha20-poly1305", 0x1303)])
@pytest.mark.parametrize("key", ["rsa2048", "p256"])
def test_tlslite_suite_ve_sertifika(tenv, key, cipher, suite, mode):
    with _srv(tenv, key, _settings(cipherNames=[cipher])) as s:
        r = _get(mode, s.port, tenv.ca_path)
    assert r.status_code == 200 and r.content == b"tlslite merhaba", s.errors
    assert s.sessions[0][0] == (3, 4) and s.sessions[0][1] == suite


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("alg,profile", [
    ("zlib", "safari_18"), ("brotli", "chrome_131"), ("zlib", "firefox_133"),
    ("zlib", "safari_27"), ("brotli", "chrome_158"), ("brotli", "firefox_160"), ("zstd", "firefox_160"),
])
def test_sertifika_sikistirma(tenv, alg, profile, mode):
    """Sunucu CompressedCertificate (RFC 8879) gönderir; istemci açıp doğrular."""
    with _srv(tenv, "rsa2048", _settings(certificate_compression_send=[alg],
                                          certificate_compression_receive=[alg])) as s:
        r = _get(mode, s.port, tenv.ca_path, profile=profile)
    assert r.status_code == 200 and r.content == b"tlslite merhaba", s.errors


@pytest.mark.parametrize("mode", MODES)
def test_server_record_dolgusu(tenv, mode):
    """Sunucu her şifreli record'a rastgele boyutta TLS 1.3 dolgusu (RFC 8446 §5.4) ekler."""
    with _srv(tenv, "p256", _settings(padding_cb=lambda length, ctype, maxlen: min(97, maxlen - length))) as s:
        r = _get(mode, s.port, tenv.ca_path)
    assert r.content == b"tlslite merhaba", s.errors


@pytest.mark.parametrize("mode", MODES)
def test_cok_sayida_session_ticket(tenv, mode):
    with _srv(tenv, "p256", _settings(ticket_count=6)) as s:
        r = _get(mode, s.port, tenv.ca_path)
    assert r.content == b"tlslite merhaba", s.errors


@pytest.mark.parametrize("mode", MODES)
def test_sunucu_record_size_limit_istemci_gonderimine_uyulur(tenv, mode):
    """Sunucu record_size_limit=1024 ilan eder (RFC 8449). İstemci 40 KB gövdeyi bundan büyük
    record'larla göndermemeli; tlslite büyük record alırsa record_overflow ile kapatır."""
    body = os.urandom(40_000)
    with _srv(tenv, "p256", _settings(record_size_limit=1024), body=None) as s:
        if mode == "sync":
            from fasthttpc import Session
            with Session(impersonate="firefox_133", verify=tenv.ca_path, timeout=15) as se:
                r = se.post(f"https://localhost:{s.port}/", data=body)
        else:
            import asyncio

            from fasthttpc import AsyncSession

            async def run():
                async with AsyncSession(impersonate="firefox_133", verify=tenv.ca_path, timeout=15) as se:
                    return await se.post(f"https://localhost:{s.port}/", data=body)
            r = asyncio.run(run())
    assert s.received and s.received[0] == body, s.errors
    assert r.content == b"len=40000"


# ----------------------------------------------------------- sunucu tarafı bozma (imza şeması ihlalleri)

def _force_scheme(monkeypatch, scheme_name):
    """tlslite sunucusunun CertificateVerify'da seçtiği imza şemasını (istemcinin teklif listesinden bağımsız)
    zorla değiştirir."""
    orig = tlsconnection.TLSConnection._serverTLS13Handshake

    def patched(self, settings, clientHello, cipherSuite, privateKey, serverCertChain, version, scheme,
                srv_alpns, reqCert):
        return orig(self, settings, clientHello, cipherSuite, privateKey, serverCertChain, version,
                    scheme_name, srv_alpns, reqCert)
    scheme_name = scheme_name
    monkeypatch.setattr(tlsconnection.TLSConnection, "_serverTLS13Handshake", patched)


@pytest.mark.parametrize("mode", MODES)
def test_rsa_pkcs1_certificateverify_tls13te_yasak(tenv, monkeypatch, mode):
    """TLS 1.3'te CertificateVerify rsa_pkcs1_* ile imzalanamaz (RFC 8446 §4.2.3)."""
    _force_scheme(monkeypatch, "rsa_pkcs1_sha256")
    with _srv(tenv, "rsa2048") as s:
        _rejects(lambda: _get(mode, s.port, tenv.ca_path), r"imza|signature|şema|scheme|CertificateVerify|pkcs|kimlik")


@pytest.mark.parametrize("mode", MODES)
def test_ecdsa_egri_sema_uyusmazligi(tenv, monkeypatch, mode):
    """P-384 anahtarlı sunucu CertificateVerify'ı ecdsa_secp256r1_sha256 şemasıyla işaretler;
    şema eğriyle eşleşmediği için (RFC 8446 §4.2.3) reddedilmeli."""
    _force_scheme(monkeypatch, "ecdsa_secp256r1_sha256")
    with _srv(tenv, "p384") as s:
        _rejects(lambda: _get(mode, s.port, tenv.ca_path), r"imza|signature|şema|scheme|CertificateVerify|eğri|curve|kimlik")


@pytest.mark.parametrize("mode", MODES)
def test_istemcinin_teklif_etmedigi_imza_semasi(tenv, monkeypatch, mode):
    """Sunucu, ClientHello.signature_algorithms'ta olmayan rsa_pss_pss_sha256 ile imzalar
    (RFC 8446 §4.4.3: teklif edilmeyen şema kabul edilmemeli)."""
    _force_scheme(monkeypatch, "rsa_pss_pss_sha256")
    with _srv(tenv, "rsa2048") as s:
        _rejects(lambda: _get(mode, s.port, tenv.ca_path), r"imza|signature|şema|scheme|CertificateVerify|teklif|offered|kimlik")
