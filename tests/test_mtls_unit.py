"""mTLS birim testleri (ağsız): ClientCert yükleme/imza ve saf protokol fonksiyonları."""
import logging
import os
import pickle
import struct

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from interop import pki  # noqa: E402

from fasthttpc.security import mtls  # noqa: E402
from fasthttpc.security.client_cert import ClientCert, ClientCertError  # noqa: E402


@pytest.fixture(scope="module")
def ca():
    return pki.make_cert("Test CA", None, "p256", ca=True)


def _client(ca, kind, cn="client1"):
    return pki.make_cert(cn, ca, kind, server_auth=False, sans=[])


def _enc_pem(key, pw: bytes) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.BestAvailableEncryption(pw))


KINDS = ["rsa2048", "p256", "p384", "ed25519"]


@pytest.mark.parametrize("kind", KINDS)
def test_tek_pem_ve_tuple(ca, tmp_path, kind):
    c = _client(ca, kind)
    combined = tmp_path / "client.pem"
    combined.write_bytes(c.pem + pki.pem_key(c.key))
    os.chmod(combined, 0o600)
    a = ClientCert.coerce(str(combined))
    cp, kp = pki.write(tmp_path, "c", c)
    os.chmod(kp, 0o600)
    b = ClientCert.coerce((cp, kp))
    assert a.identity == b.identity and a.key_kind == b.key_kind
    assert len(a.chain_der) == 1


def test_zincir_sirasi_leaf_otomatik(ca, tmp_path):
    c = _client(ca, "p256")
    f = tmp_path / "chain.pem"
    f.write_bytes(ca.pem + c.pem + pki.pem_key(c.key))   # leaf ortada
    cc = ClientCert.coerce(str(f))
    ders = cc.chain_der
    assert x509.load_der_x509_certificate(ders[0]).subject == c.cert.subject
    assert len(ders) == 2


def test_sifreli_pem_ve_parola(ca, tmp_path):
    c = _client(ca, "rsa2048")
    (tmp_path / "c.pem").write_bytes(c.pem)
    (tmp_path / "c.key").write_bytes(_enc_pem(c.key, b"gizli"))
    cp, kp = str(tmp_path / "c.pem"), str(tmp_path / "c.key")
    assert ClientCert.coerce((cp, kp, "gizli")).identity
    assert ClientCert.coerce((cp, kp, b"gizli")).identity
    with pytest.raises(ClientCertError, match="parola verilmedi"):
        ClientCert.coerce((cp, kp))
    with pytest.raises(ClientCertError) as ei:
        ClientCert.coerce((cp, kp, "yanlis"))
    assert "yanlis" not in str(ei.value) and "gizli" not in str(ei.value)


def test_eski_sifreli_pem_traditional(ca, tmp_path):
    c = _client(ca, "p256")
    (tmp_path / "c.pem").write_bytes(c.pem)
    (tmp_path / "c.key").write_bytes(c.key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.BestAvailableEncryption(b"pw")))
    assert ClientCert.coerce((str(tmp_path / "c.pem"), str(tmp_path / "c.key"), "pw")).key_kind == "ec"


@pytest.mark.parametrize("kind", ["rsa2048", "p256", "ed25519"])
def test_pkcs12(ca, tmp_path, kind):
    c = _client(ca, kind)
    p = tmp_path / "id.p12"
    p.write_bytes(pkcs12.serialize_key_and_certificates(
        b"x", c.key, c.cert, [ca.cert], serialization.BestAvailableEncryption(b"p12pw")))
    cc = ClientCert.from_pkcs12(str(p), "p12pw")
    assert len(cc.chain_der) == 2
    with pytest.raises(ClientCertError, match="PKCS#12"):
        ClientCert.from_pkcs12(str(p), "yanlis")
    with pytest.raises(ClientCertError, match="PKCS#12"):
        ClientCert.from_pkcs12(str(p), None)


def test_anahtar_sertifika_uyumsuz(ca, tmp_path):
    a, b = _client(ca, "p256", "a"), _client(ca, "p256", "b")
    cp = tmp_path / "a.pem"
    cp.write_bytes(a.pem)
    kp = tmp_path / "b.key"
    kp.write_bytes(pki.pem_key(b.key))
    with pytest.raises(ClientCertError, match="eşleşen"):
        ClientCert.coerce((str(cp), str(kp)))


def test_anahtarsiz_pem_ve_yok_dosya(ca, tmp_path):
    c = _client(ca, "p256")
    (tmp_path / "only.pem").write_bytes(c.pem)
    with pytest.raises(ClientCertError, match="özel anahtar"):
        ClientCert.coerce(str(tmp_path / "only.pem"))
    with pytest.raises(ClientCertError, match="okunamadı"):
        ClientCert.coerce(str(tmp_path / "yok.pem"))
    with pytest.raises(ClientCertError):
        ClientCert.coerce(123)


def test_desteklenmeyen_anahtarlar(ca, tmp_path):
    p521 = pki.Cert(None, ec.generate_private_key(ec.SECP521R1()))
    leaf = pki.make_cert("x", ca, "p256", server_auth=False, sans=[])
    with pytest.raises(ClientCertError, match="eğri"):
        ClientCert([leaf.cert.public_bytes(serialization.Encoding.DER)], p521.key)
    small = rsa.generate_private_key(65537, 1024)
    with pytest.raises(ClientCertError, match="kısa"):
        ClientCert([leaf.cert.public_bytes(serialization.Encoding.DER)], small)


def test_izin_uyarisi(ca, tmp_path, caplog):
    c = _client(ca, "p256")
    cp, kp = pki.write(tmp_path, "w", c)
    os.chmod(kp, 0o644)
    with caplog.at_level(logging.WARNING, logger="fasthttpc.security.client_cert"):
        ClientCert.coerce((cp, kp))
    assert any("izinleri geniş" in r.message for r in caplog.records)
    caplog.clear()
    os.chmod(kp, 0o600)
    os.chmod(cp, 0o644)   # yalnız sertifika dosyası geniş: ayrıca uyarı (aynı yardımcı); anahtar 600
    with caplog.at_level(logging.WARNING, logger="fasthttpc.security.client_cert"):
        ClientCert.coerce((cp, kp))
    # ayrı sertifika dosyası herkese açık olabilir (gizli değil): hiç uyarı olmamalı
    assert not caplog.records


def test_kapat_kopyalama_pickle_repr(ca, tmp_path):
    c = _client(ca, "p256")
    cp, kp = pki.write(tmp_path, "z", c)
    os.chmod(kp, 0o600)
    cc = ClientCert.coerce((cp, kp))
    assert "PRIVATE" not in repr(cc)
    with pytest.raises(TypeError):
        pickle.dumps(cc)
    import copy
    with pytest.raises(TypeError):
        copy.deepcopy(cc)
    cc.close()
    assert cc.closed
    with pytest.raises(ClientCertError, match="kapat"):
        cc.sign(0x0403, b"x")


def test_parola_ve_dosya_tamponlari_sifirlanir(ca, tmp_path, monkeypatch):
    """Yükleme sonrası değiştirilebilir tamponlar (dosya baytları, parola) sıfırlanmış olmalı."""
    from fasthttpc.security import client_cert as m
    seen = []
    orig = m._zero

    def spy(buf):
        orig(buf)
        if buf is not None:
            seen.append(bytes(buf))
    monkeypatch.setattr(m, "_zero", spy)
    c = _client(ca, "p256")
    (tmp_path / "c.pem").write_bytes(c.pem)
    (tmp_path / "c.key").write_bytes(_enc_pem(c.key, b"gizli"))
    ClientCert.coerce((str(tmp_path / "c.pem"), str(tmp_path / "c.key"), "gizli"))
    assert len(seen) == 3 and all(set(b) == {0} for b in seen)


# ------------------------------------------------------------------ imzalar
def _verify(pub, scheme, sig, data):
    h = {0x0401: hashes.SHA256, 0x0501: hashes.SHA384, 0x0601: hashes.SHA512,
         0x0403: hashes.SHA256, 0x0503: hashes.SHA384, 0x0603: hashes.SHA512,
         0x0804: hashes.SHA256, 0x0805: hashes.SHA384, 0x0806: hashes.SHA512}.get(scheme)
    if scheme == 0x0807:
        pub.verify(sig, data)
    elif scheme in (0x0403, 0x0503, 0x0603):
        pub.verify(sig, data, ec.ECDSA(h()))
    elif scheme in (0x0401, 0x0501, 0x0601):
        pub.verify(sig, data, padding.PKCS1v15(), h())
    else:
        pub.verify(sig, data, padding.PSS(padding.MGF1(h()), h().digest_size), h())


@pytest.mark.parametrize("kind", KINDS)
def test_tum_semalar_dogru_imzalar(ca, kind):
    c = _client(ca, kind)
    cc = ClientCert([c.cert.public_bytes(serialization.Encoding.DER)], c.key)
    for tls12 in (False, True):
        for sch in cc.schemes(tls12):
            _verify(c.key.public_key(), sch, cc.sign(sch, b"veri", tls12=tls12), b"veri")


def test_tls13_pkcs1_asla(ca):
    c = _client(ca, "rsa2048")
    cc = ClientCert([c.cert.public_bytes(serialization.Encoding.DER)], c.key)
    assert not {0x0401, 0x0501, 0x0601} & set(cc.schemes(tls12=False))
    assert {0x0401, 0x0501, 0x0601} <= set(cc.schemes(tls12=True))
    with pytest.raises(ClientCertError):
        cc.sign(0x0401, b"x", tls12=False)


# ------------------------------------------------------- CertificateRequest 1.3
def _ext(t, d):
    return struct.pack("!HH", t, len(d)) + d


def _sa(vals):
    d = b"".join(struct.pack("!H", v) for v in vals)
    return struct.pack("!H", len(d)) + d


def _cas(dns):
    d = b"".join(struct.pack("!H", len(x)) + x for x in dns)
    return struct.pack("!H", len(d)) + d


def _cr13(exts=None, ctx=b""):
    e = b"".join(exts or [])
    body = bytes([len(ctx)]) + ctx + struct.pack("!H", len(e)) + e
    return b"\x0d" + len(body).to_bytes(3, "big") + body


def test_cr13_ayristirma_tam():
    dn = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "CA")]).public_bytes()
    r = mtls.parse_certificate_request_13(_cr13([
        _ext(13, _sa([0x0403, 0x0804])), _ext(50, _sa([0x0403])), _ext(47, _cas([dn])),
        _ext(0x1234, b"bilinmeyen")]))
    assert r.sigalgs == [0x0403, 0x0804] and r.cert_sigalgs == [0x0403] and r.cas == [dn]


@pytest.mark.parametrize("msg,alert,needle", [
    (_cr13([]), 109, "signature_algorithms"),                                  # zorunlu extension yok
    (_cr13([_ext(13, _sa([0x0403]))], ctx=b"\x01"), 47, "context"),            # bağlam boş olmalı
    (_cr13([_ext(13, _sa([0x0403])), _ext(13, _sa([0x0403]))]), 47, "tekrarlanan"),
    (_cr13([_ext(13, struct.pack("!H", 3) + b"\x04\x03\x01")]), 50, "uzunluğu"),   # tek sayıda bayt
    (_cr13([_ext(13, struct.pack("!H", 0))]), 50, "uzunluğu"),                 # boş liste
    (_cr13([_ext(13, _sa([0x0403])), _ext(47, struct.pack("!H", 0))]), 50, "boş"),
    (_cr13([_ext(13, _sa([0x0403])), _ext(47, _cas([b""]))]), 50, "DN"),
    (_cr13([_ext(13, _sa([0x0403]))])[:-1], 50, "uzunluğu"),
    (b"\x0d\x00\x00\x00", 50, "boş"),
])
def test_cr13_bozuk(msg, alert, needle):
    with pytest.raises(mtls.MtlsProtocolError) as ei:
        mtls.parse_certificate_request_13(msg)
    assert ei.value.alert == alert and needle in str(ei.value) and "CertificateRequest" in str(ei.value)


def test_cr13_ext_sonrasi_fazla_bayt():
    m = _cr13([_ext(13, _sa([0x0403]))]) + b"\x00"
    m = m[:1] + (len(m) - 4).to_bytes(3, "big") + m[4:]
    with pytest.raises(mtls.MtlsProtocolError):
        mtls.parse_certificate_request_13(m)


def _cc(ca, kind, chain=()):
    c = _client(ca, kind)
    ders = [c.cert.public_bytes(serialization.Encoding.DER)] + [x.cert.public_bytes(serialization.Encoding.DER) for x in chain]
    return ClientCert(ders, c.key), c


def test_secim_13_sunucu_sirasi_ve_kesisim(ca):
    cc, _ = _cc(ca, "rsa2048")
    R = mtls.CertRequest13
    assert mtls.select_scheme_13(cc, R(b"", [0x0403, 0x0806, 0x0804])) == 0x0806      # ilk uyumlu
    assert mtls.select_scheme_13(cc, R(b"", [0x0401, 0x0403, 0x0807])) is None        # PKCS1 1.3'te asla
    assert mtls.select_scheme_13(None, R(b"", [0x0804])) is None
    ec_, _ = _cc(ca, "p384")
    assert mtls.select_scheme_13(ec_, R(b"", [0x0403, 0x0503])) == 0x0503
    assert mtls.select_scheme_13(ec_, R(b"", [0x0403])) is None                         # eğri bağlı
    ed, _ = _cc(ca, "ed25519")
    assert mtls.select_scheme_13(ed, R(b"", [0x0807])) == 0x0807


def test_secim_13_ca_ve_cert_sigalgs(ca):
    cc, _ = _cc(ca, "p256", chain=[ca])
    issuer_dn = ca.cert.subject.public_bytes()
    other = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Baska")]).public_bytes()
    R = mtls.CertRequest13
    assert mtls.select_scheme_13(cc, R(b"", [0x0403], None, [issuer_dn])) == 0x0403
    assert mtls.select_scheme_13(cc, R(b"", [0x0403], None, [other])) is None          # CA uyuşmuyor
    assert mtls.select_scheme_13(cc, R(b"", [0x0403], [0x0403])) == 0x0403             # ecdsa+sha256 zincir
    assert mtls.select_scheme_13(cc, R(b"", [0x0403], [0x0804])) is None               # zincir imzası listede yok


def test_flight13_imza_ve_baglam(ca):
    cc, c = _cc(ca, "p256")
    req = mtls.CertRequest13(b"", [0x0403])
    tr = b"transcript-oncesi"
    msgs, sch = mtls.client_auth_flight_13(cc, req, __import__("hashlib").sha256, tr)
    assert sch == 0x0403 and [m[0] for m in msgs] == [11, 15]
    import hashlib
    th = hashlib.sha256(tr + msgs[0]).digest()          # Certificate DAHİL
    content = b"\x20" * 64 + b"TLS 1.3, client CertificateVerify\x00" + th
    sig = msgs[1][8:]
    c.key.public_key().verify(sig, content, ec.ECDSA(hashes.SHA256()))
    # sunucu bağlamıyla doğrulanamaz
    bad = b"\x20" * 64 + b"TLS 1.3, server CertificateVerify\x00" + th
    with pytest.raises(Exception):
        c.key.public_key().verify(sig, bad, ec.ECDSA(hashes.SHA256()))


def test_flight13_bos_sertifika():
    import hashlib
    req = mtls.CertRequest13(b"", [0x0401])
    for cert in (None,):
        msgs, sch = mtls.client_auth_flight_13(cert, req, hashlib.sha256, b"x")
        assert sch is None and msgs == [b"\x0b\x00\x00\x04\x00\x00\x00\x00"]


# ---------------------------------------------------------------- 1.2
def _cr12(types, sigs, dns=()):
    d = b"".join(struct.pack("!H", len(x)) + x for x in dns)
    body = bytes([len(types)]) + bytes(types) + _sa(sigs) + struct.pack("!H", len(d)) + d
    return b"\x0d" + len(body).to_bytes(3, "big") + body


def test_cr12_ayristirma_ve_bozuk():
    r = mtls.parse_certificate_request_12(_cr12([1, 64], [0x0401, 0x0403]))
    assert r.types == [1, 64] and r.sigalgs == [0x0401, 0x0403] and r.cas == []
    for bad in (_cr12([], [0x0401]), _cr12([1], []), _cr12([1], [0x0401])[:-1], _cr12([1], [0x0401]) + b"\x00",
                b"\x0d\x00\x00\x00"):
        with pytest.raises(mtls.MtlsProtocolError):
            mtls.parse_certificate_request_12(bad)


def test_secim_12(ca):
    R = mtls.CertRequest12
    rsa_cc, _ = _cc(ca, "rsa2048")
    assert mtls.select_scheme_12(rsa_cc, R([1], [0x0401, 0x0804])) == 0x0804           # PSS tercih
    assert mtls.select_scheme_12(rsa_cc, R([1], [0x0601])) == 0x0601                   # PKCS1 1.2'de serbest
    assert mtls.select_scheme_12(rsa_cc, R([64], [0x0804])) is None                    # tür uyuşmuyor
    assert mtls.select_scheme_12(rsa_cc, R([1], [0x0403])) is None
    ec_cc, _ = _cc(ca, "p256")
    assert mtls.select_scheme_12(ec_cc, R([64], [0x0503, 0x0403])) == 0x0403           # eğri eşleşmesi
    assert mtls.select_scheme_12(ec_cc, R([64], [0x0503])) == 0x0503                   # 1.2'de eğri bağlı değil
    assert mtls.select_scheme_12(ec_cc, R([1], [0x0403])) is None
    ed, _ = _cc(ca, "ed25519")
    assert mtls.select_scheme_12(ed, R([64], [0x0807])) == 0x0807


def test_cert_ve_cv_12_bicimi(ca):
    cc, c = _cc(ca, "p256")
    m = mtls.build_certificate_12(cc)
    der = cc.chain_der[0]
    assert m == b"\x0b" + (6 + len(der)).to_bytes(3, "big") + (3 + len(der)).to_bytes(3, "big") + len(der).to_bytes(3, "big") + der
    assert mtls.build_certificate_12(None) == b"\x0b\x00\x00\x03\x00\x00\x00"
    cv = mtls.build_certificate_verify_12(cc, 0x0403, b"hs-messages")
    assert cv[0] == 15 and struct.unpack("!H", cv[4:6])[0] == 0x0403
    c.key.public_key().verify(cv[8:], b"hs-messages", ec.ECDSA(hashes.SHA256()))


def test_bilet_anahtari_cert_kimligi():
    from fasthttpc.security import session_tickets as st
    a = st.cache_key("h", 443, None)
    b = st.cache_key("h", 443, None, "cert:abc")
    c = st.cache_key("h", 443, None, "cert:def")
    assert a == "h|443|" and len({a, b, c}) == 3
