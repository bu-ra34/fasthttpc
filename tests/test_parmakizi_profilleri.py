"""Profil başına HTTP/2 + TLS parmak izi testleri (ağsız).

Beklenen değerlerin kaynakları fasthttpc/fingerprint.py başındaki KAYNAKLAR
bloğunda ve NOTES3'tedir. Chrome JA4'ü (02713d6af862) gerçek Chrome 120-131
yakalamasıyla yayımlanmış değerdir; Firefox/Safari JA4 ve Akamai hash'leri
bu depodaki profilin kendi çıktısına sabitlenmiş regresyon değerleridir
(tls.peet.ws canlı ölçümüyle eşleşir; gerçek tarayıcıyla birebirlik NOTES3'te).
"""
import asyncio
import hashlib
import struct

import pytest

from fasthttpc.fingerprint import (
    PROFILES, akamai_h2_hash, akamai_h2_string, extension_ids_from_client_hello,
    ja4_from_client_hello, ja3_string_from_client_hello,
)
from fasthttpc.protocol.async_h2 import AsyncHttp2Connection, client_preface_bytes
from fasthttpc.protocol.http2_parser import (
    HTTP2Frame, FrameType, HpackDecoder, Http2Connection, build_client_preface,
    h2_request_headers,
)
from fasthttpc.security import keyshare as KS
from fasthttpc.tls13 import TLSClientConnection
from fasthttpc.tls_crafter import (
    TLSImpersonator, build_client_encrypted_extensions, encrypted_extensions_types,
)

from tls13_fakeserver import PKI, FakeTLS13Server
from fake_tls_server import parse_client_hello
from test_tls13_core import handshake, trust  # noqa: F401  (fixture)

PROFIL_ADLARI = ("chrome_131", "firefox_133", "safari_18")

BEKLENEN_AKAMAI = {
    "chrome_131": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    "firefox_133": "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
    "safari_18": "2:0;3:100;4:2097152;8:1;9:1|10420225|0|m,s,a,p",
}
BEKLENEN_AKAMAI_HASH = {
    "chrome_131": "52d84b11737d980aef856699f885ca86",
    "firefox_133": "6ea73faa8fc5aac76bded7bd238f6433",
    "safari_18": "d4a2dcbfde511b5040ed5a5190a8d78b",
}
BEKLENEN_JA4 = {
    "chrome_131": "t13d1516h2_8daaf6152771_02713d6af862",
    "firefox_133": "t13d1717h2_5b57614c22b0_3cbfd9057e0d",
    "safari_18": "t13d2014h2_a09f3c656075_14788d8d241b",
}
GREASE = {(i << 4 | 0xA) << 8 | (i << 4 | 0xA) for i in range(16)}


def _hello(profil):
    return TLSImpersonator("example.com", profile=profil).build_client_hello()[0]


def _frames(buf):
    pos, out = 0, []
    while pos + 9 <= len(buf):
        n = int.from_bytes(buf[pos:pos + 3], "big")
        out.append(HTTP2Frame.parse(buf[pos:pos + 9 + n]))
        pos += 9 + n
    assert pos == len(buf)
    return out


def _settings(frame):
    p = frame.payload
    return [struct.unpack("!HI", p[i:i + 6]) for i in range(0, len(p), 6)]


# --------------------------------------------------------------- HTTP/2

@pytest.mark.parametrize("ad", PROFIL_ADLARI)
def test_akamai_dizesi_ve_hash(ad):
    assert akamai_h2_string(ad) == BEKLENEN_AKAMAI[ad]
    assert akamai_h2_hash(ad) == BEKLENEN_AKAMAI_HASH[ad]


def test_uc_profilin_h2_hashleri_farkli():
    assert len({akamai_h2_hash(a) for a in PROFIL_ADLARI}) == 3


@pytest.mark.parametrize("ad", PROFIL_ADLARI)
def test_onsoz_baytlari_profile_gore(ad):
    buf = client_preface_bytes(ad)
    assert buf.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    frames = _frames(buf[24:])
    h2 = PROFILES[ad]["h2"]
    assert frames[0].type == FrameType.SETTINGS and frames[0].stream_id == 0
    assert _settings(frames[0]) == h2["settings"]          # SIRA dahil birebir
    assert frames[1].type == FrameType.WINDOW_UPDATE
    assert struct.unpack("!I", frames[1].payload)[0] == h2["window_update"]
    assert len(frames) == 2 + len(h2["priority_frames"])


def test_priority_frameleri_onsoze_yazilir():
    h2 = {"settings": [(4, 1000)], "window_update": 77,
          "priority_frames": [(3, 0, False, 201), (9, 7, True, 1)],
          "pseudo_header_order": [":method"], "headers_priority": None}
    frames = _frames(build_client_preface(h2)[24:])
    assert [f.type for f in frames] == [FrameType.SETTINGS, FrameType.WINDOW_UPDATE,
                                        FrameType.PRIORITY, FrameType.PRIORITY]
    assert frames[2].stream_id == 3 and frames[2].payload == struct.pack("!IB", 0, 200)
    assert frames[3].stream_id == 9 and frames[3].payload == struct.pack("!IB", 0x80000007, 0)


def test_default_profil_eski_davranisla_ayni():
    """default: WINDOW_UPDATE yok, SETTINGS 1:65536;2:0;4:65535;6:262144."""
    frames = _frames(client_preface_bytes(None)[24:])
    assert [f.type for f in frames] == [FrameType.SETTINGS]
    assert _settings(frames[0]) == [(1, 65536), (2, 0), (4, 65535), (6, 262144)]


class _Sok:
    def __init__(self):
        self.out = []

    def send_record(self, data, content_type=0x17, use_app_keys=True):
        self.out.append(bytes(data))


@pytest.mark.parametrize("ad", PROFIL_ADLARI)
def test_async_onsoz_senkronla_ayni(ad):
    sok = _Sok()
    Http2Connection(sok, profile=ad).send_preface_and_settings()
    assert b"".join(sok.out) == client_preface_bytes(ad) == build_client_preface(PROFILES[ad]["h2"])


def _headers_frame(buf):
    return next(f for f in _frames(buf) if f.type == FrameType.HEADERS)


@pytest.mark.parametrize("ad,sira", [
    ("chrome_131", [":method", ":authority", ":scheme", ":path"]),
    ("firefox_133", [":method", ":path", ":authority", ":scheme"]),
    ("safari_18", [":method", ":scheme", ":authority", ":path"]),
])
def test_senkron_headers_pseudo_sirasi_ve_priority(ad, sira):
    sok = _Sok()
    c = Http2Connection(sok, profile=ad)
    c._send_headers(1, h2_request_headers(c._h2, "get", "example.com", "https", "/x",
                                          [("user-agent", "ua"), ("accept", "*/*")]), True)
    f = _headers_frame(b"".join(sok.out))
    hp = PROFILES[ad]["h2"]["headers_priority"]
    assert f.flags & 0x20                                   # PRIORITY bayrağı
    dep_excl, w = struct.unpack("!IB", f.payload[:5])
    assert (dep_excl >> 31 == 1) == hp[1] and (dep_excl & 0x7FFFFFFF) == hp[0] and w + 1 == hp[2]
    pairs = HpackDecoder().decode(f.payload[5:])
    assert [k for k, _ in pairs if k.startswith(":")] == sira


def test_header_order_profil_sirasini_uygular():
    h2 = PROFILES["chrome_131"]["h2"]
    out = h2_request_headers(h2, "GET", "a.com", "https", "/", [
        ("accept-language", "tr"), ("x-ozel", "1"), ("user-agent", "u"), ("accept", "*/*")])
    assert [k for k, _ in out[4:]] == ["user-agent", "accept", "accept-language", "x-ozel"]


class _AkisSahte:
    """AsyncHttp2Connection için bellek içi akış: yazılanları toplar, okuma bekler."""
    def __init__(self):
        self.out = bytearray()
        self._ev = asyncio.Event()

    def write(self, b):
        self.out += b

    async def drain(self):
        pass

    def close(self):
        self._ev.set()

    async def wait_closed(self):
        pass

    async def read(self, n):
        await self._ev.wait()
        return b""


@pytest.mark.parametrize("ad", PROFIL_ADLARI)
def test_async_baglanti_profil_degerlerini_telde_kullanir(ad):
    async def main():
        s = _AkisSahte()
        c = AsyncHttp2Connection(s, profile=ad)
        await c.start()
        t = asyncio.ensure_future(c.request("GET", "example.com", "/p", [("user-agent", "u")]))
        await asyncio.sleep(0.05)
        wire = bytes(s.out)
        t.cancel()
        await c.close()
        return wire
    wire = asyncio.run(main())
    assert wire.startswith(client_preface_bytes(ad))
    f = _headers_frame(wire[len(client_preface_bytes(ad)):])
    hp = PROFILES[ad]["h2"]["headers_priority"]
    assert f.flags & 0x20 and struct.unpack("!IB", f.payload[:5])[1] + 1 == hp[2]
    pairs = HpackDecoder().decode(f.payload[5:])
    assert [k for k, _ in pairs if k.startswith(":")] == PROFILES[ad]["h2"]["pseudo_header_order"]


def test_buyuk_pencere_ilan_edilince_alim_akis_kontrolu_bozulmaz():
    """Chrome 6 MiB pencere + 15 MiB bağlantı artışı ilan eder; alım tarafı her
    DATA için WINDOW_UPDATE döner, 300 KB'lık gövde eksiksiz gelir."""
    gövde = bytes(range(256)) * 1200                      # 307200 bayt
    frames = [HTTP2Frame(0, FrameType.SETTINGS, 0, 0, b"").serialize(),
              HTTP2Frame(1, FrameType.HEADERS, 0x4, 1, b"\x88").serialize()]
    for i in range(0, len(gövde), 16384):
        parca = gövde[i:i + 16384]
        son = i + 16384 >= len(gövde)
        frames.append(HTTP2Frame(len(parca), FrameType.DATA, 0x1 if son else 0, 1, parca).serialize())

    class Esock(_Sok):
        def __init__(self):
            super().__init__()
            self.kayit = [(f, 23) for f in frames]

        def recv_record(self, skip_post_handshake=False):
            return self.kayit.pop(0)

    sok = Esock()
    c = Http2Connection(sok, profile="chrome_131")
    c.send_preface_and_settings()
    status, _h, body = c.request("GET", "example.com", "/", [])
    assert status == 200 and body == gövde
    wu = [f for f in _frames_after_preface(sok.out[1:]) if f.type == FrameType.WINDOW_UPDATE]
    assert sum(struct.unpack("!I", f.payload)[0] for f in wu if f.stream_id == 0) == len(gövde)


def _frames_after_preface(chunks):
    out = []
    for ch in chunks:
        out += _frames(ch) if len(ch) >= 9 else []
    return out


# ------------------------------------------------------------------ TLS

@pytest.mark.parametrize("ad", PROFIL_ADLARI)
def test_ja4_beklenen(ad):
    assert ja4_from_client_hello(_hello(ad)) == BEKLENEN_JA4[ad]


def test_chrome_ja4_gercek_tarayici_degeri():
    """Chrome 120-131 gerçek JA4'ü (yayımlanmış): extension kümesi (ALPS 17513,
    ECH 65037 dahil, padding YOK), şifre listesi ve imza algoritmaları eşleşir."""
    assert ja4_from_client_hello(_hello("chrome_131")) == "t13d1516h2_8daaf6152771_02713d6af862"


CHROME_EXT_KUMESI = sorted([0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17513, 65037, 65281])


def test_chrome_extension_kumesi_ve_grease_uclari():
    for _ in range(5):                                      # karıştırma her seferinde farklı
        ids = extension_ids_from_client_hello(_hello("chrome_131"))
        assert ids[0] in GREASE and ids[-1] in GREASE and ids[0] != ids[-1]
        assert sorted(i for i in ids if i not in GREASE) == CHROME_EXT_KUMESI
        assert 0x15 not in ids                              # Chrome padding göndermez


def test_chrome_extension_sirasi_baglanti_basina_karisir():
    sirali = {tuple(i for i in extension_ids_from_client_hello(_hello("chrome_131"))
                    if i not in GREASE) for _ in range(8)}
    assert len(sirali) > 1


FIREFOX_EXT = [0, 23, 65281, 10, 11, 35, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 65037]
SAFARI_EXT = [None, 0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, None, 21]   # None = GREASE


def test_firefox_extension_listesi_tam_sira():
    for _ in range(3):
        assert extension_ids_from_client_hello(_hello("firefox_133")) == FIREFOX_EXT


def test_safari_extension_listesi_tam_sira():
    ids = extension_ids_from_client_hello(_hello("safari_18"))
    assert [None if i in GREASE else i for i in ids] == SAFARI_EXT


def _ja3_alanlari(ad):
    ja3 = ja3_string_from_client_hello(_hello(ad)).split(",")
    return ja3[1], ja3[3]


def test_cipher_ve_grup_listeleri():
    assert _ja3_alanlari("firefox_133")[0] == (
        "4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53")
    assert _ja3_alanlari("chrome_131")[0] == (
        "4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53")
    assert _ja3_alanlari("safari_18")[0].count("-") + 1 == 20
    pq = "4588-" if KS.HAVE_MLKEM else ""
    assert _ja3_alanlari("chrome_131")[1] == pq + "29-23-24"
    assert _ja3_alanlari("firefox_133")[1] == pq + "29-23-24-25-256-257"
    assert _ja3_alanlari("safari_18")[1] == "29-23-24-25"


def _ext_payload(ch, tip):
    p = parse_client_hello(ch[5:])
    return dict(p["exts"])[tip]


def test_imza_algoritmalari():
    def sig(ad):
        d = _ext_payload(_hello(ad), 13)
        return [struct.unpack("!H", d[2 + i:4 + i])[0] for i in range(0, len(d) - 2, 2)]
    assert sig("chrome_131") == [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    assert sig("firefox_133") == [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
                                  0x0401, 0x0501, 0x0601, 0x0203, 0x0201]


def test_alps_ve_ech_grease_yapisi():
    ch = _hello("chrome_131")
    assert _ext_payload(ch, 17513) == b"\x00\x03\x02h2"
    ech = _ext_payload(ch, 65037)
    assert ech[0] == 0                                      # outer
    kdf, aead = struct.unpack("!HH", ech[1:5])
    assert kdf == 1 and aead in (1, 3)
    assert struct.unpack("!H", ech[6:8])[0] == 32           # enc = X25519 boyutu
    plen = struct.unpack("!H", ech[8 + 32:10 + 32])[0]
    assert plen in (144, 176, 208, 240) and len(ech) == 10 + 32 + plen


def test_ikinci_grease_extension_bir_bayt_tasir():
    imp = TLSImpersonator("example.com", profile="chrome_131")
    ch = imp.build_client_hello()[0]
    greases = [(t, p) for t, p in parse_client_hello(ch[5:])["exts"] if t in GREASE]
    assert len(greases) == 2 and len({t for t, _ in greases}) == 2
    assert [len(p) for _, p in greases] == [0, 1]


def test_sertifika_sikistirma_yalniz_acabildiklerimiz():
    def algs(ad):
        d = _ext_payload(_hello(ad), 27)
        return [struct.unpack("!H", d[1 + i:3 + i])[0] for i in range(0, d[0], 2)]
    try:
        import brotli  # noqa: F401
        brotli_var = True
    except ImportError:
        brotli_var = False
    # brotli kurulu değilse ilan edilmez (sunucu seçerse sertifikayı açamazdık)
    assert algs("chrome_131") == ([2] if brotli_var else [1])
    assert algs("safari_18") == [1]                         # zlib
    assert algs("firefox_133") == ([1, 2] if brotli_var else [1])   # zstd (3) HİÇ ilan edilmez


def test_key_share_grease_ve_hibrit():
    imp = TLSImpersonator("example.com", profile="chrome_131")
    p = parse_client_hello(imp.build_client_hello()[0][5:])
    assert imp._grease_group in p["key_shares"] and p["key_shares"][imp._grease_group] == b"\x00"
    assert p["key_shares"][0x001D] and len(p["key_shares"][0x001D]) == 32
    if KS.HAVE_MLKEM:
        assert len(p["key_shares"][0x11EC]) == 1184 + 32
        assert 0x11EC in p["groups"]
    else:                               # desteklenmeyeni ilan etme (HRR ile handshake'i kırar)
        assert 0x11EC not in p["groups"] and 0x11EC not in p["key_shares"]


def test_mlkem_hibrit_paylasilan_sir():
    """X25519MLKEM768: sunucu payı ct(1088)||x25519(32), sır = mlkem_ss||x25519_ss."""
    if not KS.HAVE_MLKEM:
        with pytest.raises(ValueError):
            KS.generate_key_share(KS.GROUP_X25519MLKEM768)
        return
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
    ks = KS.KeyShareSet([KS.GROUP_X25519MLKEM768])
    pub = ks.public(KS.GROUP_X25519MLKEM768)
    ek, xpub = pub[:1184], pub[1184:]
    ss_kem, ct = mlkem.MLKEM768PublicKey.from_public_bytes(ek).encapsulate()
    sx = x25519.X25519PrivateKey.generate()
    ss_x = sx.exchange(x25519.X25519PublicKey.from_public_bytes(xpub))
    spub = sx.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert ks.shared_secret(KS.GROUP_X25519MLKEM768, ct + spub) == ss_kem + ss_x
    with pytest.raises(ValueError):
        ks.shared_secret(KS.GROUP_X25519MLKEM768, ct)       # kısa pay reddedilir


def test_safari_padding_512ye_tamamlar_chrome_firefox_eklemez():
    assert len(_hello("safari_18")) - 5 == 512
    assert 0x15 not in extension_ids_from_client_hello(_hello("firefox_133"))


def test_ech_grease_kacis_kapisi(monkeypatch):
    monkeypatch.setenv("FASTHTTPC_NO_ECH_GREASE", "1")
    assert 65037 not in extension_ids_from_client_hello(_hello("chrome_131"))
    assert 65037 not in extension_ids_from_client_hello(_hello("firefox_133"))


def test_hrr_sonrasi_chrome_sirasi_korunur():
    imp = TLSImpersonator("example.com", profile="chrome_131")
    ch1 = imp.build_client_hello()[0]
    ch2 = imp.build_retry_client_hello(KS.GROUP_SECP256R1)
    t1 = [t for t in extension_ids_from_client_hello(ch1)]
    t2 = [t for t in extension_ids_from_client_hello(ch2) if t != 0x2C]
    assert t1 == t2
    assert list(parse_client_hello(ch2[5:])["key_shares"]) == [KS.GROUP_SECP256R1]   # GREASE girdisi yok


def test_istemci_encrypted_extensions_bicimi():
    m = build_client_encrypted_extensions()
    assert m[0] == 8 and int.from_bytes(m[1:4], "big") == len(m) - 4
    assert encrypted_extensions_types(m) == [17513]


def test_alps_kabul_edilince_istemci_ee_gonderir_ve_handshake_tamamlanir(pki, trust):
    server = FakeTLS13Server(pki, alpn="h2", tamper={"alps"})
    conn = TLSClientConnection("example.com", "chrome_131", **trust)
    handshake(conn, server)
    assert conn.handshake_complete and server.state == "CONNECTED"
    assert server.client_ee[0] == 8


def test_alps_kabul_edilmezse_ee_gonderilmez(pki, trust):
    server = FakeTLS13Server(pki, alpn="h2")
    conn = TLSClientConnection("example.com", "chrome_131", **trust)
    handshake(conn, server)
    assert conn.handshake_complete and not hasattr(server, "client_ee")


@pytest.fixture(scope="module")
def pki():
    return PKI("example.com")


@pytest.mark.parametrize("ad", PROFIL_ADLARI)
def test_hash_md5_tutarli(ad):
    assert hashlib.md5(BEKLENEN_AKAMAI[ad].encode()).hexdigest() == BEKLENEN_AKAMAI_HASH[ad]
