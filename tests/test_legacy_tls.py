"""legacy_tls=True (eski sunucu uyumluluk modu) testleri — AĞSIZ (yalnızca loopback).

Güvenlik sözleşmesi:
  * legacy_tls=False (varsayılan): ClientHello ve kabul kuralları DEĞİŞMEZ; aynı sunucular reddedilir.
  * legacy_tls=True: CBC, statik RSA, EMS/renegotiation_info'suz sunucu, SHA-1 SKE kabul edilir; AMA
    sertifika doğrulaması ve DOWNGRD kontrolü sürer; TLS 1.0/1.1 AÇILMAZ.
"""
from __future__ import annotations

import hashlib
import os
import socket
import struct
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fasthttpc.security import tls12, tls12_legacy as lg  # noqa: E402
from fasthttpc.security.tls_adapter import TLSAdapter  # noqa: E402
from fasthttpc.tls_crafter import TLSImpersonator  # noqa: E402
from interop.openssl_server import OPENSSL, SServer  # noqa: E402
from interop.relay import Relay  # noqa: E402
from interop.tlslite_server import TlsliteServer  # noqa: E402
from test_interop_openssl import MODES, _get, _rejects  # noqa: E402,F401
from test_interop_openssl import env  # noqa: E402,F401  (fixture)
from tlslite.api import HandshakeSettings  # noqa: E402
from tls12_servers import Fake12Server, PKI12, serve_fake_in_thread  # noqa: E402

needs_openssl = pytest.mark.skipif(OPENSSL is None, reason="openssl CLI yok")


# ============================================================ birim: bayrak ve ClientHello
def test_bayrak_dogrulamasi():
    assert lg.normalize_legacy(True) is True and lg.normalize_legacy(False) is False
    for bad in ("tls1.0", "tls1.1", "TLS1.0"):
        with pytest.raises(ValueError, match="TLS 1.0/1.1"):
            lg.normalize_legacy(bad)
    for bad in (1, None, "yes"):
        with pytest.raises(TypeError):
            lg.normalize_legacy(bad)


def test_session_varsayilan_kapali_ve_tls10_reddi():
    from fasthttpc import AsyncSession, Session
    assert Session().legacy_tls is False and AsyncSession().legacy_tls is False
    assert Session(legacy_tls=True).legacy_tls is True
    with pytest.raises(ValueError):
        Session(legacy_tls="tls1.0")
    with pytest.raises(ValueError):
        AsyncSession(legacy_tls="tls1.0")


def _hello(profile, legacy):
    imp = TLSImpersonator("example.com", profile=profile, legacy_tls=legacy)
    rec, _, _ = imp.build_client_hello()
    return tls12.parse_client_hello(rec[5:]), imp


def test_varsayilan_clienthello_degismez():
    ch, imp = _hello("chrome_131", False)
    assert 0x0016 not in ch.ext_types
    assert 0x0201 not in ch.sigalgs and 0x0203 not in ch.sigalgs
    prof = [c for c in imp.profile["cipher_suites"] if isinstance(c, int)]
    assert [c for c in ch.suites if c in prof] == prof and len(ch.suites) == len(prof) + 1  # +GREASE
    assert 0xC009 not in ch.suites and 0x003C not in ch.suites


@pytest.mark.parametrize("profile", ["chrome_131", "firefox_133", "safari_18", None])
def test_legacy_clienthello_eksikleri_sona_ekler(profile):
    nogrease = lambda l: [c for c in l if c & 0x0F0F != 0x0A0A]  # noqa: E731
    base, _ = _hello(profile, False)
    ch, _ = _hello(profile, True)
    b0, c0 = nogrease(base.suites), nogrease(ch.suites)
    added = [c for c in lg.LEGACY_OFFER_ORDER if c not in b0]
    assert c0 == b0 + added                     # profil sırası aynen; eksikler SONA, sırayla
    for need in lg.LEGACY_OFFER_ORDER:
        assert need in ch.suites
    assert 0x0016 in ch.ext_types                       # encrypt_then_mac ilanı
    assert 0x0201 in ch.sigalgs and 0x0203 in ch.sigalgs
    assert 0x0017 in ch.ext_types and 0xFF01 in ch.ext_types   # EMS/renegotiation_info hâlâ ilan
    assert 0x0303 in ch.versions


def test_chrome_zaten_olan_suiteler_tekrarlanmaz():
    ch, _ = _hello("chrome_131", True)
    assert len(ch.suites) == len(set(ch.suites))        # GREASE tek, tekrar yok


# ============================================================ birim: CBC kayıt katmanı
CBC_IDS = [i for i, s in lg.LEGACY_SUITES.items() if s.mode == "CBC"]


def _pair(sid, etm):
    suite = lg.LEGACY_SUITES[sid]
    key, mk = os.urandom(suite.key_len), os.urandom(suite.mac_len)
    return lg.CBCRecordCipher(suite, key, mk, etm), lg.CBCRecordCipher(suite, key, mk, etm)


@pytest.mark.parametrize("etm", [False, True])
@pytest.mark.parametrize("sid", CBC_IDS)
def test_cbc_gidis_donus(sid, etm):
    w, r = _pair(sid, etm)
    for n in (0, 1, 15, 16, 17, 255, 1000, 2 ** 14):
        pt = os.urandom(n)
        body = w.seal(23, pt)
        assert r.open(23, b"\x03\x03", body) == pt
    assert w.seq == r.seq == 8


def test_cbc_acik_iv_her_kayitta_farkli():
    w, _ = _pair(0xC013, False)
    a, b = w.seal(23, b"x" * 40), w.seal(23, b"x" * 40)
    assert a[:16] != b[:16] and a[16:] != b[16:]


def test_cbc_mte_bilinen_vektor():
    """Elle (cryptography ile) inşa edilen MtE kaydı açılmalı: format RFC 5246 §6.2.3.2."""
    import hmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    suite = lg.LEGACY_SUITES[0x002F]
    key, mk, iv = bytes(range(16)), bytes(range(20)), bytes(range(16, 32))
    pt = b"merhaba"
    mac = hmac.new(mk, struct.pack("!Q", 0) + b"\x17\x03\x03" + struct.pack("!H", len(pt)) + pt,
                   hashlib.sha1).digest()
    data = pt + mac
    n = (-(len(data) + 1)) % 16
    data += bytes([n]) * (n + 1)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    body = iv + enc.update(data) + enc.finalize()
    assert lg.CBCRecordCipher(suite, key, mk, False).open(23, b"\x03\x03", body) == pt


def _forge_mte(c, ctype, pt, *, pad=None, mac_flip=False, ver=b"\x03\x03"):
    """Anahtarı bilen saldırgan-simülasyonu: MtE kaydı; padding veya MAC kasten bozulur."""
    import hmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    seq8 = c.seq.to_bytes(8, "big")
    mac = hmac.new(c.mac_key, seq8 + bytes([ctype]) + ver + struct.pack("!H", len(pt)) + pt,
                   c.suite.mac_hash).digest()
    if mac_flip:
        mac = bytes([mac[0] ^ 1]) + mac[1:]
    data = pt + mac
    data += pad if pad is not None else bytes([(-(len(data) + 1)) % 16]) * ((-(len(data) + 1)) % 16 + 1)
    assert len(data) % 16 == 0
    iv = os.urandom(16)
    enc = Cipher(algorithms.AES(c.key), modes.CBC(iv)).encryptor()
    return iv + enc.update(data) + enc.finalize()


def _err_of(fn):
    with pytest.raises(tls12.TLS12Error) as ei:
        fn()
    return ei.value


@pytest.mark.parametrize("sid", [0x002F, 0xC013, 0xC023, 0xC024, 0x003D])
def test_cbc_mte_padding_ve_mac_hatasi_ayni_alert_ve_mesaj(sid):
    """Lucky13 azaltımı: padding hatası, MAC hatası, yapısal hata -> AYNI alert, AYNI mesaj, AYNI sınıf."""
    mk = lambda: _pair(sid, False)  # noqa: E731
    pt = b"gizli veri " * 5
    cases = {}

    w, r = mk()
    cases["iyi_ama_mac_bozuk"] = _forge_mte(r, 23, pt, mac_flip=True)
    w, r = mk()
    # padding: son bayt 5 ama önceki baytlar 5 değil
    L = len(pt) + r.suite.mac_len
    padn = (-(L + 1)) % 16
    bad_pad = bytes([1] * padn + [padn]) if padn else bytes([7])  # tutarsız
    if padn == 0:
        bad_pad = bytes([0xFF] * 15 + [15])
    cases["padding_tutarsiz_mac_dogru"] = _forge_mte(r, 23, pt, pad=bad_pad if padn else None)
    w, r = mk()
    cases["padlen_cok_buyuk"] = _forge_mte(r, 23, pt, pad=b"\xff" * (((-(L + 1)) % 16) + 1))
    w, r = mk()
    cases["bit_cevirme"] = bytes(w.seal(23, pt)[:-1]) + bytes([w.seal(23, pt)[-1] ^ 1])
    cases["kisa"] = os.urandom(20)
    cases["blok_hizasiz"] = os.urandom(16 + 33)
    cases["bos"] = b""

    errs = {}
    for name, body in cases.items():
        _, r = mk()
        # her vaka kendi anahtarıyla üretildiği için aynı r'yi paylaşmak yerine yeniden üret
        r2 = r
        errs[name] = _err_of(lambda b=body, rr=r2: rr.open(23, b"\x03\x03", b))
    # NOT: yukarıdaki vakalar farklı anahtarlarla üretildi -> hepsi MAC/padding hatası olarak düşmeli
    msgs = {str(e) for e in errs.values()}
    alerts = {e.alert for e in errs.values()}
    types = {type(e) for e in errs.values()}
    assert alerts == {tls12.AL_BAD_RECORD_MAC}, alerts
    assert len(msgs) == 1, msgs
    assert len(types) == 1


@pytest.mark.parametrize("etm", [False, True])
def test_cbc_dogru_anahtarla_tek_hata_yolu(etm):
    """Aynı anahtarla: MtE'de yalnızca padding bozuk / yalnızca MAC bozuk -> özdeş hata."""
    suite_id = 0xC013
    w, r = _pair(suite_id, etm)
    pt = b"A" * 33
    if etm:
        good = w.seal(23, pt)
        body_mac = good[:-1] + bytes([good[-1] ^ 1])             # MAC bozuk
        body_ct = bytearray(good)
        body_ct[20] ^= 1                                         # şifreli metin bozuk (MAC tutmaz)
        e1 = _err_of(lambda: r.open(23, b"\x03\x03", body_mac))
        _, r2 = _pair(suite_id, etm)
        r2.key, r2.mac_key = r.key, r.mac_key
        e2 = _err_of(lambda: r2.open(23, b"\x03\x03", bytes(body_ct)))
    else:
        e1 = _err_of(lambda: r.open(23, b"\x03\x03", _forge_mte(r, 23, pt, mac_flip=True)))
        r2 = lg.CBCRecordCipher(r.suite, r.key, r.mac_key, False)
        L = len(pt) + r.suite.mac_len
        n = (-(L + 1)) % 16
        e2 = _err_of(lambda: r2.open(23, b"\x03\x03", _forge_mte(
            r2, 23, pt, pad=bytes([n ^ 0x55] * n + [n]) if n else bytes([0x77] * 15 + [15]))))
    assert (type(e1), e1.alert, str(e1)) == (type(e2), e2.alert, str(e2))
    assert e1.alert == tls12.AL_BAD_RECORD_MAC


def test_cbc_mte_mac_her_zaman_tam_hesaplanir(monkeypatch):
    """Padding hatalı kayıtta da HMAC çalışır (erken çıkış yok): hmac.new çağrı sayısı geçerli kayıtla aynı."""
    import fasthttpc.security.tls12_legacy as mod
    w, r = _pair(0xC013, False)
    r2 = lg.CBCRecordCipher(r.suite, r.key, r.mac_key, False)
    pt = b"B" * 30
    good = w.seal(23, pt)
    n = (-(len(pt) + r.suite.mac_len + 1)) % 16
    bad = _forge_mte(r2, 23, pt, pad=bytes([n ^ 1] * n + [n]) if n else bytes([9] * 15 + [15]))
    calls = []
    real = mod.hmac.new

    def counting(*a, **k):
        calls.append(1)
        return real(*a, **k)

    monkeypatch.setattr(mod.hmac, "new", counting)
    r.open(23, b"\x03\x03", good)
    n_good = len(calls)
    calls.clear()
    with pytest.raises(tls12.TLS12Error):
        r2.open(23, b"\x03\x03", bad)
    assert len(calls) == n_good == 2     # gerçek HMAC + sahte HMAC (süre normalleştirme)


def test_cbc_seq_dogrulamasi():
    w, r = _pair(0x002F, True)
    b1, b2 = w.seal(23, b"bir"), w.seal(23, b"iki")
    with pytest.raises(tls12.TLS12Error):
        r.open(23, b"\x03\x03", b2)          # sıra dışı: seq MAC'e girdiği için reddedilir


def test_statik_rsa_pms_surumu_ve_sifreleme():
    from cryptography.hazmat.primitives.asymmetric import padding
    p = PKI12()
    body, pms = lg.rsa_client_key_exchange(p.rsa_cert, 0x0303)
    assert len(pms) == 48 and pms[:2] == b"\x03\x03"
    n = struct.unpack("!H", body[:2])[0]
    assert n == len(body) - 2
    assert p.rsa_key.decrypt(body[2:], padding.PKCS1v15()) == pms
    body2, pms2 = lg.rsa_client_key_exchange(p.rsa_cert, 0x0303)
    assert pms2 != pms and body2 != body                    # taze rastgelelik
    with pytest.raises(tls12.TLS12Error, match="RSA"):
        lg.rsa_client_key_exchange(p.ec_cert, 0x0303)


# ============================================================ openssl s_server uyumluluğu
CBC_MATRIX = [
    ("rsa2048", "ECDHE-RSA-AES128-SHA", 0xC013),
    ("rsa2048", "ECDHE-RSA-AES256-SHA", 0xC014),
    ("rsa2048", "ECDHE-RSA-AES128-SHA256", 0xC027),
    ("rsa2048", "ECDHE-RSA-AES256-SHA384", 0xC028),
    ("p256", "ECDHE-ECDSA-AES128-SHA", 0xC009),
    ("p256", "ECDHE-ECDSA-AES256-SHA", 0xC00A),
    ("p256", "ECDHE-ECDSA-AES128-SHA256", 0xC023),
    ("p256", "ECDHE-ECDSA-AES256-SHA384", 0xC024),
]
RSA_MATRIX = [
    ("rsa2048", "AES128-GCM-SHA256", 0x009C),
    ("rsa2048", "AES256-GCM-SHA384", 0x009D),
    ("rsa2048", "AES128-SHA", 0x002F),
    ("rsa2048", "AES256-SHA", 0x0035),
    ("rsa2048", "AES128-SHA256", 0x003C),
    ("rsa2048", "AES256-SHA256", 0x003D),
]


def _ossl(env, key, cipher, *extra):
    cert, k = env.leaf[key]
    return SServer("-cert", cert, "-key", k, "-tls1_2", "-cipher", cipher + ":@SECLEVEL=0", *extra,
                   "-WWW", cwd=str(env.dir))


@needs_openssl
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key,cipher,sid", CBC_MATRIX + RSA_MATRIX)
def test_legacy_openssl_suite_matrisi(env, key, cipher, sid, mode):
    with _ossl(env, key, cipher) as s:
        r = _get(mode, s.port, env.ca_path, legacy_tls=True)
    assert r.status_code == 200 and r.content == b"merhaba interop"
    assert r.tls_info["cipher_suite"] == sid and r.tls_info["version"] == "TLSv1.2"
    assert r.tls_info["legacy_tls"] is True
    assert r.tls_info["forward_secret"] is (sid in {i for _, _, i in CBC_MATRIX})
    assert r.tls_info["extended_master_secret"] is True       # openssl EMS sunar


@needs_openssl
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key,cipher,sid", CBC_MATRIX + RSA_MATRIX)
def test_legacy_kapaliyken_ayni_sunucular_reddedilir(env, key, cipher, sid, mode):
    with _ossl(env, key, cipher) as s:
        _rejects(lambda: _get(mode, s.port, env.ca_path),
                 r"CBC|statik RSA|insufficient_security|handshake_failure|cipher|alert")


@needs_openssl
@pytest.mark.parametrize("mode", MODES)
def test_legacy_etm_tercih_edilir(env, mode):
    with _ossl(env, "rsa2048", "ECDHE-RSA-AES128-SHA") as s:
        r = _get(mode, s.port, env.ca_path, legacy_tls=True)
    assert r.tls_info["encrypt_then_mac"] is True


@needs_openssl
@pytest.mark.parametrize("mode", MODES)
def test_legacy_etm_yoksa_mte(env, mode):
    with _ossl(env, "rsa2048", "ECDHE-RSA-AES128-SHA", "-no_etm") as s:
        r = _get(mode, s.port, env.ca_path, legacy_tls=True)
    assert r.status_code == 200 and r.tls_info["encrypt_then_mac"] is False


@needs_openssl
@pytest.mark.parametrize("mode", MODES)
def test_legacy_buyuk_yanit_cbc(env, mode):
    with _ossl(env, "rsa2048", "ECDHE-RSA-AES256-SHA") as s:
        r = _get(mode, s.port, env.ca_path, path="/big.bin", legacy_tls=True)
    assert hashlib.sha256(r.content).digest() == hashlib.sha256(env.big).digest()


@needs_openssl
@pytest.mark.parametrize("mode", MODES)
def test_legacy_aead_ecdhe_normal_sunucu_bagli_ve_bilgi_dogru(env, mode):
    """Legacy açıkken modern sunucular da (ECDHE+GCM) eskisi gibi çalışır."""
    with _ossl(env, "p256", "ECDHE-ECDSA-AES128-GCM-SHA256") as s:
        r = _get(mode, s.port, env.ca_path, legacy_tls=True)
    assert r.status_code == 200 and r.tls_info["cipher_suite"] == 0xC02B


@needs_openssl
@pytest.mark.parametrize("mode", MODES)
def test_legacy_sertifika_dogrulamasi_aynen_zorunlu(env, mode):
    """Legacy modda yanlış CA / yanlış host HÂLÂ reddedilir (CBC ve statik RSA dahil)."""
    for cipher in ("ECDHE-RSA-AES128-SHA", "AES128-SHA"):
        with _ossl(env, "rsa2048", cipher) as s:
            _rejects(lambda: _get(mode, s.port, env.other_ca_path, legacy_tls=True),
                     r"sertifika|certificate|doğrulama")
        with _ossl(env, "rsa2048", cipher) as s:
            _rejects(lambda: _get(mode, s.port, env.ca_path, host="127.0.0.1", legacy_tls=True),
                     r"sertifika|certificate|doğrulama|host")


@needs_openssl
@pytest.mark.parametrize("mode", MODES)
def test_legacy_tls10_11_sunucusu_hala_reddedilir(env, mode):
    cert, k = env.leaf["rsa2048"]
    for flag in ("-tls1", "-tls1_1"):
        try:
            with SServer("-cert", cert, "-key", k, flag, "-cipher", "AES128-SHA:@SECLEVEL=0", "-WWW",
                         cwd=str(env.dir)) as s:
                _rejects(lambda: _get(mode, s.port, env.ca_path, legacy_tls=True),
                         r"protocol_version|TLS 1\.[01]|desteklen|alert|sürüm|version")
        except RuntimeError:
            pytest.skip("openssl bu s_server bayrağını desteklemiyor")


@needs_openssl
@pytest.mark.parametrize("mode", MODES)
def test_legacy_downgrd_openssl_araci_reddedilir(env, mode):
    """TLS 1.3 sunucusunun TLS 1.2'ye zorlanması (DOWNGRD) legacy modda da RED."""
    from test_interop_tls12 import _strip_supported_versions
    cert, k = env.leaf["p256"]
    with SServer("-cert", cert, "-key", k, "-WWW", cwd=str(env.dir)) as s, \
            Relay(s.port, c2s=_strip_supported_versions) as rl:
        _rejects(lambda: _get(mode, rl.port, env.ca_path, legacy_tls=True), r"downgrad|DOWNGRD")


# ============================================================ tlslite: EMS'siz / EtM'siz sunucu
def _tl(env, tmp, *, ems, etm=True, cipher="aes128", key="rsa2048"):
    from interop import pki
    c, k = pki.write(tmp, "tl_" + key, pki.make_cert("localhost", env.ca, key))
    hs = HandshakeSettings()
    hs.minVersion = hs.maxVersion = (3, 3)
    hs.useExtendedMasterSecret = ems
    hs.requireExtendedMasterSecret = False
    hs.useEncryptThenMAC = etm
    hs.cipherNames = [cipher]
    hs.macNames = ["sha", "sha256", "aead"]
    return TlsliteServer(c, k, hs)


@pytest.mark.parametrize("mode", MODES)
def test_legacy_ems_yok_kabul_ama_gorunur(env, mode, tmp_path, caplog):
    import logging
    with caplog.at_level(logging.WARNING, logger="fasthttpc"):
        with _tl(env, tmp_path, ems=False) as s:
            r = _get(mode, s.port, env.ca_path, legacy_tls=True)
    assert r.status_code == 200 and r.content == b"tlslite merhaba", s.errors
    assert r.tls_info["extended_master_secret"] is False
    assert any("Extended Master Secret" in m for m in caplog.messages), caplog.messages
    assert s.sessions[0][2] is False                      # sunucu da EMS'siz oturum görüyor


@pytest.mark.parametrize("mode", MODES)
def test_legacy_ems_var_gorunur(env, mode, tmp_path):
    with _tl(env, tmp_path, ems=True) as s:
        r = _get(mode, s.port, env.ca_path, legacy_tls=True)
    assert r.status_code == 200 and r.tls_info["extended_master_secret"] is True


@pytest.mark.parametrize("mode", MODES)
def test_legacy_kapaliyken_ems_siz_sunucu_reddedilir(env, mode, tmp_path):
    with _tl(env, tmp_path, ems=False, cipher="aes128gcm") as s:
        _rejects(lambda: _get(mode, s.port, env.ca_path), r"extended.?master|\bEMS\b|7627")


@pytest.mark.parametrize("mode", MODES)
def test_legacy_tlslite_cbc_etm_ve_mte(env, mode, tmp_path):
    for etm in (True, False):
        with _tl(env, tmp_path, ems=True, etm=etm) as s:
            r = _get(mode, s.port, env.ca_path, legacy_tls=True)
        assert r.status_code == 200, s.errors
        assert r.tls_info["encrypt_then_mac"] is etm


# ============================================================ sahte sunucu: DOWNGRD, SHA-1, sıra
@pytest.fixture(scope="module")
def fpki():
    return PKI12()


def _fake_connect(fpki, tmp_path, tamper, legacy, suite=0xC02F, **kw):
    srv = Fake12Server(fpki, suite=suite, tamper=tamper, **kw)
    port, t, ls = serve_fake_in_thread(srv)
    ca = tmp_path / "fca.pem"
    ca.write_bytes(fpki.ca_pem())
    return srv, TLSAdapter.negotiate(socket.create_connection(("127.0.0.1", port), 5),
                                     "localhost", "chrome_131", ca_path=str(ca), legacy_tls=legacy)


@pytest.mark.parametrize("tamper", [{"downgrd"}, {"downgrd0"}])
def test_legacy_downgrd_sahte_sunucu_reddedilir(fpki, tmp_path, tamper):
    for legacy in (False, True):
        with pytest.raises(ConnectionError, match="DOWNGRD"):
            _fake_connect(fpki, tmp_path, tamper, legacy)


@pytest.mark.parametrize("suite,key", [(0xC02F, "rsa"), (0xC02B, "ec")])
def test_legacy_sha1_ske_yalnizca_legacyde(fpki, tmp_path, suite, key):
    with pytest.raises(ConnectionError, match="SHA-1"):
        _fake_connect(fpki, tmp_path, {"sha1_sig"}, False, suite=suite)
    srv, es = _fake_connect(fpki, tmp_path, {"sha1_sig"}, True, suite=suite)
    assert es.state["is_tls12"] and es.state["cipher_suite"] == suite
    es.close()


def test_legacy_sha1_ske_gecersiz_imza_yine_reddedilir(fpki, tmp_path):
    with pytest.raises(ConnectionError, match="GEÇERSİZ|imza"):
        _fake_connect(fpki, tmp_path, {"sha1_sig", "bad_ske_sig"}, True)


def test_legacy_ems_reneg_sahte_sunucu(fpki, tmp_path):
    for t in ({"no_ems"}, {"no_reneg"}, {"no_ems", "no_reneg"}):
        with pytest.raises(ConnectionError, match="Extended Master|renegotiation"):
            _fake_connect(fpki, tmp_path, t, False)
    # bozuk (boş olmayan) renegotiation_info legacy'de de RED: yalnızca YOKLUK gevşer
    with pytest.raises(ConnectionError, match="renegotiation_info"):
        _fake_connect(fpki, tmp_path, {"bad_reneg"}, True)


@pytest.mark.parametrize("tamper,pat", [
    ({"bad_finished"}, "Finished"),
    ({"bad_cert_host"}, "sertifika"),
    ({"out_of_order"}, "unexpected_message|beklenmeyen"),
    ({"tls13_suite"}, "TLS 1.3"),
    ({"extra_ext"}, "extension"),
])
def test_legacy_diger_denetimler_sürer(fpki, tmp_path, tamper, pat):
    with pytest.raises(ConnectionError, match=pat):
        _fake_connect(fpki, tmp_path, tamper, True)


def test_legacy_ilan_edilmeyen_suite_reddedilir(fpki, tmp_path):
    """Sunucu ilan etmediğimiz bir suite seçerse (ör. 0xC013 ama profil+legacy dışı bir id) RED."""
    srv = Fake12Server(fpki, tamper=set())
    srv.suite = 0x000A      # 3DES: legacy'de de YOK
    srv.suite_info = srv.suite_info
    port, t, ls = serve_fake_in_thread(srv)
    with pytest.raises(ConnectionError, match="desteklenmeyen|insufficient|handshake_failure"):
        TLSAdapter.negotiate(socket.create_connection(("127.0.0.1", port), 5), "localhost", "chrome_131",
                             legacy_tls=True)
