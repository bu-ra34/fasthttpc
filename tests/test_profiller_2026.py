"""2026-11 tarayıcı profilleri: chrome_158 / firefox_160 / safari_27 (ağsız).

Beklenen değerlerin kaynakları fasthttpc/fingerprint.py başındaki KAYNAKLAR
bloğundadır ([CR] Chromium 158 kaynağı, [BS] BoringSSL, [FF] Firefox 160/NSS
kaynağı, [CI2] curl-impersonate yakalamaları, [CAP] bu depoda gerçek Chrome for
Testing 153 ile yapılan yerel yakalama). JA4/Akamai dizeleri profilin telde
ürettiği baytlardan hesaplanır (profil sözlüğünden değil).
"""
import struct

import pytest

from fasthttpc import fingerprint as fp
from fasthttpc.fingerprint import (
    PROFILES, akamai_h2_hash, akamai_h2_string, chrome_sec_ch_ua, default_headers,
    extension_ids_from_client_hello, get_profile, ja4_from_client_hello,
)
from fasthttpc.protocol.http2_parser import (
    FrameType, HpackDecoder, Http2Connection, build_client_preface, h2_request_headers,
)
from fasthttpc.security import keyshare as KS
from fasthttpc.security.cert_validator import (
    CertificateValidationError, decompress_certificate_message,
)
from fasthttpc.tls13 import TLSClientConnection
from fasthttpc.tls_crafter import (
    EXT_ALPS, EXT_ALPS_NEW, HAVE_MLDSA, TLSImpersonator, alps_accepted,
    build_client_encrypted_extensions, encrypted_extensions_types,
)

from fake_tls_server import parse_client_hello
from tls13_fakeserver import PKI, FakeTLS13Server, ext, hs
from test_tls13_core import handshake, trust  # noqa: F401  (fixture)
from test_parmakizi_profilleri import _Sok, _frames, _settings

YENI = ("chrome_158", "firefox_160", "safari_27")
GREASE = {(i << 4 | 0xA) << 8 | (i << 4 | 0xA) for i in range(16)}

BEKLENEN_AKAMAI = {
    "chrome_158": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    "firefox_160": "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
    "safari_27": "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p",
}
BEKLENEN_AKAMAI_HASH = {
    "chrome_158": "52d84b11737d980aef856699f885ca86",
    "firefox_160": "6ea73faa8fc5aac76bded7bd238f6433",
    "safari_27": "c52879e43202aeb92740be6e8c86ea96",
}
# ML-KEM varsa (Safari'de padding olmaz) ve ML-DSA ilan edilebiliyorsa geçerli.
BEKLENEN_JA4 = {
    "chrome_158": "t13d1517h2_8daaf6152771_cb7bf5808d99",
    "firefox_160": "t13d1517h2_8daaf6152771_3cbfd9057e0d",
    "safari_27": "t13d2013h2_a09f3c656075_7f0f34a4126d",
}
# [CAP] Gerçek Google Chrome for Testing 153.0.8010.12 ClientHello'sunun JA4'ü
# (--disable-field-trial-config; host-resolver-rules nedeniyle ECH GREASE yok).
CHROME_153_YAKALAMA_JA4 = "t13d1516h2_8daaf6152771_447d952d5833"
# [CAP] aynı yakalamadaki trust_anchors (0xca34) gövdesi (186 bayt).
CHROME_153_TAI_GOVDESI = bytes.fromhex(
    "00b804d679090a04d679090d08839a648c9b2d010808839a648c9b2d011308839a648c9b2d010d"
    "08839a648c9b2d010c04d679090f04d679090604d679090c08839a648c9b2d010a0582df130213"
    "0582df13020604d679090b0582df1302010582df13020e08839a648c9b2d010704d67909070582"
    "df13020d08839a648c9b2d010b0582df13020f0582df13021204d679090804d67909050582df13"
    "021408839a648c9b2d011204d679090104d679090408839a648c9b2d0109")

pq_gerekli = pytest.mark.skipif(not (KS.HAVE_MLKEM and HAVE_MLDSA),
                                reason="cryptography ML-KEM/ML-DSA sunmuyor")


def _hello(ad, host="example.com"):
    return TLSImpersonator(host, profile=ad).build_client_hello()[0]


def _exts(ch):
    return dict(parse_client_hello(ch[5:])["exts"])


def _u16(b):
    return [struct.unpack("!H", b[i:i + 2])[0] for i in range(0, len(b), 2)]


def _tai_listesi(govde):
    n = struct.unpack("!H", govde[:2])[0]
    assert n == len(govde) - 2
    out, i = [], 2
    while i < len(govde):
        out.append(govde[i + 1:i + 1 + govde[i]])
        i += 1 + govde[i]
    return out


# ------------------------------------------------------------ takma adlar

def test_takma_adlar_guncel_surumlere_gider():
    assert get_profile("chrome")["_name"] == "chrome_158"
    assert get_profile("firefox")["_name"] == "firefox_160"
    assert get_profile("safari")["_name"] == "safari_27"
    for eski in ("chrome_131", "firefox_133", "safari_18"):   # geriye dönük uyumluluk
        assert get_profile(eski)["_name"] == eski


def test_session_varsayilani_guncel_chrome():
    import inspect
    from fasthttpc import AsyncSession, Session
    for cls in (Session, AsyncSession):
        assert inspect.signature(cls.__init__).parameters["impersonate"].default == "chrome_158"


# ------------------------------------------------------------ HTTP/2

@pytest.mark.parametrize("ad", YENI)
def test_akamai(ad):
    assert akamai_h2_string(ad) == BEKLENEN_AKAMAI[ad]
    assert akamai_h2_hash(ad) == BEKLENEN_AKAMAI_HASH[ad]


def test_safari_27_h2_safari_18den_farkli():
    """Gerçek Safari 26/27: SETTINGS_ENABLE_CONNECT_PROTOCOL (8) yok; HEADERS'ta
    PRIORITY bayrağı yok [CI2]."""
    frames = _frames(build_client_preface(PROFILES["safari_27"]["h2"])[24:])
    assert [i for i, _ in _settings(frames[0])] == [2, 3, 4, 9]
    sok = _Sok()
    c = Http2Connection(sok, profile="safari_27")
    c._send_headers(1, h2_request_headers(c._h2, "GET", "example.com", "https", "/", []), True)
    f = next(f for f in _frames(b"".join(sok.out)) if f.type == FrameType.HEADERS)
    assert not f.flags & 0x20
    pairs = HpackDecoder().decode(f.payload)
    assert [k for k, _ in pairs if k.startswith(":")] == [":method", ":scheme", ":authority", ":path"]


def test_chrome_158_headers_priority_ve_pseudo():
    sok = _Sok()
    c = Http2Connection(sok, profile="chrome_158")
    c._send_headers(1, h2_request_headers(c._h2, "GET", "example.com", "https", "/", []), True)
    f = next(f for f in _frames(b"".join(sok.out)) if f.type == FrameType.HEADERS)
    assert f.flags & 0x20
    dep, w = struct.unpack("!IB", f.payload[:5])
    assert dep == 0x80000000 and w == 255                  # [CAP]: excl=1 dep=0 w=256


# ------------------------------------------------------------ başlıklar

def test_sec_ch_ua_algoritmasi_yakalamalarla_dogrulanir():
    assert chrome_sec_ch_ua(152) == '"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"'
    assert chrome_sec_ch_ua(150) == '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"'
    assert chrome_sec_ch_ua(153, None) == '"Chromium";v="153", "Not_A Brand";v="8"'      # [CAP]
    assert chrome_sec_ch_ua(158) == '"Chromium";v="158", "Not.A/Brand";v="24", "Google Chrome";v="158"'


def test_varsayilan_basliklar():
    c = dict(default_headers("chrome_158"))
    assert c["sec-ch-ua"] == chrome_sec_ch_ua(158)
    assert "Chrome/158.0.0.0" in c["User-Agent"]
    f = dict(default_headers("firefox_160"))
    assert f["User-Agent"].endswith("rv:160.0) Gecko/20100101 Firefox/160.0")
    assert f["Accept"] == "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    assert f["Accept-Language"] == "en-US,en;q=0.5"
    s = default_headers("safari_27")
    assert "Version/27.2 Safari/605.1.15" in dict(s)["User-Agent"]
    assert "Upgrade-Insecure-Requests" not in dict(s)          # Safari 18.0+ göndermez
    assert [k for k, _ in s][:2] == ["Sec-Fetch-Dest", "User-Agent"]


# ------------------------------------------------------------ TLS: Chrome 158

@pq_gerekli
@pytest.mark.parametrize("ad", YENI)
def test_ja4(ad):
    assert ja4_from_client_hello(_hello(ad)) == BEKLENEN_JA4[ad]


@pq_gerekli
def test_chrome_158_ja4_gercek_chrome_yakalamasiyla_ayni(monkeypatch):
    """ECH GREASE kapalıyken (yakalama koşulu) JA4 gerçek Chrome 153 ile BİREBİR."""
    monkeypatch.setenv("FASTHTTPC_NO_ECH_GREASE", "1")
    assert ja4_from_client_hello(_hello("chrome_158")) == CHROME_153_YAKALAMA_JA4


def test_ja4_imza_listesindeki_greasei_yok_sayar():
    ch = _hello("chrome_158")
    sig = _u16(_exts(ch)[13][2:])
    assert sig[0] in GREASE
    ja4_c = ja4_from_client_hello(ch).split("_")[2]
    import hashlib
    ext_part = ",".join(f"{t:04x}" for t in sorted(
        t for t in extension_ids_from_client_hello(ch) if t not in GREASE and t not in (0, 16)))
    src = ext_part + "_" + ",".join(f"{a:04x}" for a in sig[1:])
    assert ja4_c == hashlib.sha256(src.encode()).hexdigest()[:12]


def test_chrome_158_extension_kumesi():
    beklenen = sorted([0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51,
                       17613, 0xCA34, 65037, 65281])
    sirala = set()
    for _ in range(6):
        ids = extension_ids_from_client_hello(_hello("chrome_158"))
        assert ids[0] in GREASE and ids[-1] in GREASE and ids[0] != ids[-1]
        assert sorted(i for i in ids if i not in GREASE) == beklenen
        assert EXT_ALPS not in ids and 0x15 not in ids and 4832 not in ids
        sirala.add(tuple(ids[1:-1]))
    assert len(sirala) > 1                                  # permütasyon


@pytest.mark.skipif(not HAVE_MLDSA, reason="ML-DSA yok")
def test_chrome_158_imza_algoritmalari():
    imp = TLSImpersonator("example.com", profile="chrome_158")
    ch = imp.build_client_hello()[0]
    sig = _u16(_exts(ch)[13][2:])
    assert sig[0] == imp._grease_sigalg and sig[0] in GREASE
    assert sig[1:] == [0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503,
                       0x0805, 0x0501, 0x0806, 0x0601]
    # HRR sonrası 2. ClientHello aynı GREASE şemasını taşır.
    ch2 = imp.build_retry_client_hello(KS.GROUP_SECP256R1)
    assert _u16(_exts(ch2)[13][2:]) == sig


def test_chrome_158_trust_anchors_gercek_chrome_kumesi():
    govde = _exts(_hello("chrome_158"))[0xCA34]
    assert len(govde) == len(CHROME_153_TAI_GOVDESI) == 186
    assert sorted(_tai_listesi(govde)) == sorted(_tai_listesi(CHROME_153_TAI_GOVDESI))
    # Sıra süreç başına sabit (Chrome gibi): aynı süreçte iki bağlantı aynı sırayı taşır.
    assert _exts(_hello("chrome_158"))[0xCA34] == govde


def test_chrome_158_alps_yeni_kod_noktasi():
    e = _exts(_hello("chrome_158"))
    assert e[EXT_ALPS_NEW] == b"\x00\x03\x02h2" and EXT_ALPS not in e
    assert TLSImpersonator("x.com", profile="chrome_158").alps_codepoint == 17613
    assert TLSImpersonator("x.com", profile="chrome_131").alps_codepoint == 17513


def test_chrome_158_gruplar_ve_key_share():
    p = parse_client_hello(_hello("chrome_158")[5:])
    pq = [0x11EC] if KS.HAVE_MLKEM else []
    assert [g for g in p["groups"] if g not in GREASE] == pq + [0x1D, 0x17, 0x18]
    assert [g for g in p["key_shares"] if g not in GREASE] == pq + [0x1D]
    assert _u16(_exts(_hello("chrome_158"))[27][1:]) in ([2], [1])


def test_chrome_158_ech_grease_boringssl_bicimi():
    ech = _exts(_hello("chrome_158"))[65037]
    assert ech[0] == 0 and struct.unpack("!HH", ech[1:5])[0] == 1
    assert struct.unpack("!HH", ech[1:5])[1] in (1, 3)
    plen = struct.unpack("!H", ech[40:42])[0]
    assert plen in (144, 176, 208, 240) and len(ech) == 42 + plen


# ------------------------------------------------------------ TLS: Firefox 160

def test_firefox_160_clienthello():
    ch = _hello("firefox_160")
    assert extension_ids_from_client_hello(ch) == [
        0, 23, 65281, 10, 11, 35, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 65037]
    p = parse_client_hello(ch[5:])
    e = _exts(ch)
    pq = [0x11EC] if KS.HAVE_MLKEM else []
    assert p["groups"] == pq + [0x1D, 0x17, 0x18, 0x19]      # ffdhe YOK [FF]
    assert list(p["key_shares"]) == pq + [0x1D, 0x17]
    sig = _u16(e[13][2:])
    assert sig == [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
                   0x0401, 0x0501, 0x0601, 0x0203, 0x0201]
    assert not set(sig) & {0x0904, 0x0905, 0x0906}           # security.tls.enable_mldsa=false
    assert _u16(e[34][2:]) == [0x0403, 0x0503, 0x0603, 0x0203]
    assert e[28] == b"\x40\x01"
    ech = e[65037]
    assert struct.unpack("!H", ech[3:5])[0] in (1, 3)        # NSS: AEAD 1 ya da 3
    assert (struct.unpack("!H", ech[40:42])[0] - 16) % 32 == 0


def test_firefox_160_suite_listesi():
    from fasthttpc.fingerprint import ja3_string_from_client_hello
    assert ja3_string_from_client_hello(_hello("firefox_160")).split(",")[1] == (
        "4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53")


# ------------------------------------------------------------ TLS: Safari 27

def test_safari_27_clienthello():
    ch = _hello("safari_27")
    ids = extension_ids_from_client_hello(ch)
    beklenen = [None, 0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, None]
    if not KS.HAVE_MLKEM:
        beklenen.append(21)                                  # küçük CH -> BoringSSL padding
    assert [None if i in GREASE else i for i in ids] == beklenen
    p = parse_client_hello(ch[5:])
    assert p["suites"][0] in GREASE and p["suites"][1:4] == [0x1302, 0x1303, 0x1301]
    assert len(p["suites"]) == 21
    pq = [0x11EC] if KS.HAVE_MLKEM else []
    assert [g for g in p["groups"] if g not in GREASE] == pq + [0x1D, 0x17, 0x18, 0x19]
    e = _exts(ch)
    vers = _u16(e[43][1:])
    assert vers[0] in GREASE and vers[1:] == [0x0304, 0x0303]
    assert _u16(e[13][2:]) == [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805,
                               0x0501, 0x0806, 0x0601, 0x0201]
    assert 65037 not in e                                    # Safari ECH GREASE göndermez


# ------------------------------------------------------------ el sıkışmaları

@pytest.fixture(scope="module")
def pki():
    return PKI("example.com")


def test_chrome_158_alps_17613_kabulunde_istemci_ee(pki, trust):
    server = FakeTLS13Server(pki, alpn="h2", tamper={"alps_new"})
    conn = TLSClientConnection("example.com", "chrome_158", **trust)
    handshake(conn, server)
    assert conn.handshake_complete and server.state == "CONNECTED"
    assert encrypted_extensions_types(server.client_ee) == [17613]


def test_alps_baska_kod_noktasiyla_kabul_sayilmaz():
    ee = hs(8, struct.pack("!H", 6) + ext(EXT_ALPS, b"\x00\x00"))
    assert alps_accepted(True, ee, "h2", EXT_ALPS)
    assert not alps_accepted(True, ee, "h2", EXT_ALPS_NEW)
    assert encrypted_extensions_types(build_client_encrypted_extensions(codepoint=17613)) == [17613]


def test_trust_anchors_sunucu_yaniti_tolere_edilir(pki, trust):
    """Sunucu EE'de trust_anchors listesi ve CertificateEntry'de trust_anchors
    döndürür; istemci yok sayar, doğrulama aynen yapılır."""
    server = FakeTLS13Server(pki, alpn="h2", tamper={"trust_anchors"})
    conn = TLSClientConnection("example.com", "chrome_158", **trust)
    handshake(conn, server)
    assert conn.handshake_complete


@pytest.mark.skipif(not HAVE_MLDSA, reason="ML-DSA yok")
@pytest.mark.parametrize("anahtar,sema", [("mldsa44", 0x0904), ("mldsa65", 0x0905),
                                          ("mldsa87", 0x0906)])
def test_mldsa_certificate_verify_gercekten_dogrulanir(tmp_path, anahtar, sema):
    p = PKI("example.com", leaf_key=anahtar)
    ca = tmp_path / "ca.pem"
    ca.write_bytes(p.ca_pem())
    conn = TLSClientConnection("example.com", "chrome_158", ca_path=str(ca))
    handshake(conn, FakeTLS13Server(p, alpn="h2"))
    assert conn.handshake_complete and conn.signature_scheme == sema


@pytest.mark.skipif(not HAVE_MLDSA, reason="ML-DSA yok")
def test_mldsa_bozuk_imza_reddedilir(tmp_path):
    p = PKI("example.com", leaf_key="mldsa65")
    ca = tmp_path / "ca.pem"
    ca.write_bytes(p.ca_pem())
    conn = TLSClientConnection("example.com", "chrome_158", ca_path=str(ca))
    with pytest.raises(Exception, match="GEÇERSİZ|CertificateVerify"):
        handshake(conn, FakeTLS13Server(p, alpn="h2", tamper={"bad_cv_sig"}))
    assert not conn.handshake_complete


@pytest.mark.skipif(not HAVE_MLDSA, reason="ML-DSA yok")
def test_mldsa_teklif_etmeyen_profilde_reddedilir(tmp_path):
    """Firefox 160 ML-DSA ilan etmez; sunucu yine de kullanırsa RFC 8446 §4.4.3 ihlali."""
    p = PKI("example.com", leaf_key="mldsa65")
    ca = tmp_path / "ca.pem"
    ca.write_bytes(p.ca_pem())
    conn = TLSClientConnection("example.com", "firefox_160", ca_path=str(ca))
    with pytest.raises(Exception, match="teklif etmediğimiz"):
        handshake(conn, FakeTLS13Server(p, alpn="h2"))


@pytest.mark.parametrize("ad", YENI)
def test_yeni_profillerle_tam_el_sikisma(pki, trust, ad):
    conn = TLSClientConnection("example.com", ad, **trust)
    handshake(conn, FakeTLS13Server(pki, alpn="h2"))
    assert conn.handshake_complete


# ------------------------------------------------------------ zstd sertifika sıkıştırma

def test_zstd_sertifika_acilir_ve_boyut_denetlenir():
    zstandard = pytest.importorskip("zstandard")
    cert_msg_body = b"\x00" + (5).to_bytes(3, "big") + b"abcde"
    comp = zstandard.ZstdCompressor().compress(cert_msg_body)
    def msg(ilan):
        body = struct.pack("!H", 3) + ilan.to_bytes(3, "big") + len(comp).to_bytes(3, "big") + comp
        return hs(25, body)
    out = decompress_certificate_message(msg(len(cert_msg_body)))
    assert out[0] == 11 and out[4:] == cert_msg_body
    with pytest.raises(CertificateValidationError):
        decompress_certificate_message(msg(len(cert_msg_body) - 1))   # ilan edilenden büyük


def test_profillerin_hepsi_kurulabiliyor_ve_ja3_benzersiz():
    hashes = {ad: fp.ja3_for_profile(ad)[1] for ad in YENI}
    assert len(set(hashes.values())) == 3
