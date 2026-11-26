"""secp521r1 / x448 / ffdhe2048 / ffdhe3072 anahtar değişimi (ağsız: yalnızca loopback).

* Saf yardımcılar: RFC 7919 asalları (formülden bağımsız türetilir), gidiş-dönüş, geçersiz karşı
  değerler (eğri dışı / yanlış uzunluk / sıkıştırılmış nokta, x448 sıfır sır, ffdhe Y=0/1/p-1/>=p),
  ffdhe paylaşılan sırrının ve public değerinin p uzunluğuna soldan sıfırla doldurulması
  (deterministik vakalar).
* ClientHello sabitleme: her profilin supported_groups / key_share baytları 0.7.0 ile AYNI; yeni
  gruplar yalnızca HelloRetryRequest ve TLS 1.2 ServerKeyExchange yoluyla kullanılır.
* HelloRetryRequest (senkron TLSAdapter + sans-IO çekirdek): ilan edilmiş yeni gruba geçiş başarılı;
  ilan edilmemiş grup, zaten pay gönderilmiş grup ve ikinci HRR reddedilir (RFC 8446 §4.1.4).
* TLS 1.2 ECDHE (RFC 8422): secp521r1 ve x448 ServerKeyExchange kabul; geçersiz nokta, ilan
  edilmemiş eğri, ffdhe ve hibrit "eğri" reddedilir.

Bağımsız `openssl s_server` karşısında uyumluluk: tests/test_interop_kex_groups.py.
"""
import hashlib
import socket
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric import dh

import fake_tls_server as fts
import tls13_fakeserver as sansio
from fasthttpc.fingerprint import PROFILES, _parse_client_hello_fields
from fasthttpc.security import keyshare as KS
from fasthttpc.security.tls_adapter import TLSAdapter
from fasthttpc.tls13 import TLSClientConnection, TLSError
from fasthttpc.tls_crafter import TLSImpersonator
from test_hrr_keyshare import _connect, _roundtrip, trust_leaf  # noqa: F401  (trust_leaf: fixture)
from test_tls13_core import handshake
from tls12_servers import HOST as HOST12, PKI12, Fake12Server, serve_fake_in_thread

HOST = "example.com"
P521, X448, FF2048, FF3072 = KS.GROUP_SECP521R1, KS.GROUP_X448, KS.GROUP_FFDHE2048, KS.GROUP_FFDHE3072
NEW_GROUPS = [P521, X448, FF2048, FF3072]
FFDHE = [FF2048, FF3072]
PUB_LEN = {P521: 133, X448: 56, FF2048: 256, FF3072: 384}
SECRET_LEN = {P521: 66, X448: 56, FF2048: 256, FF3072: 384}
X448_P = 2 ** 448 - 2 ** 224 - 1


def _need(group):
    """Kurulu `cryptography` grubu sunmuyorsa (ör. BoringSSL/LibreSSL derlemesinde X448 yok) atla."""
    if group not in KS.SUPPORTED_GROUPS:
        pytest.skip(f"kurulu cryptography {KS.group_name(group)} sunmuyor (platform kısıtı)")


@pytest.fixture
def x448_profili(monkeypatch):
    """Hiçbir yerleşik profil x448 ilan etmez (gerçek tarayıcılar da etmez); x448 yalnızca onu
    supported_groups'ta ilan eden bir profille kullanılabilir. Test için böyle bir profil."""
    prof = dict(PROFILES["default"])
    prof["supported_groups"] = [0x001D, 0x0017, 0x0018, X448]
    monkeypatch.setitem(PROFILES, "test_x448", prof)
    return "test_x448"


def _profil(request, name):
    if name == "test_x448":
        request.getfixturevalue("x448_profili")
    return name


# ============================================================ saf yardımcılar

def _e_olcekli(bits: int, guard: int = 64) -> int:
    """floor(2^bits * e), yalnızca tamsayı aritmetiğiyle (sum floor(2^m / k!))."""
    s, term, k = 0, 1 << (bits + guard), 0
    while term:
        s += term
        k += 1
        term //= k
    return s >> guard


@pytest.mark.parametrize("group,b,X", [(FF2048, 2048, 560316), (FF3072, 3072, 2625351)])
def test_rfc7919_asallari_formulle_ayni(group, b, X):
    """RFC 7919 §A: p = 2^b - 2^{b-64} + {[2^{b-130} e] + X} * 2^64 - 1, g = 2."""
    p = 2 ** b - 2 ** (b - 64) + (_e_olcekli(b - 130) + X) * 2 ** 64 - 1
    assert KS.FFDHE_PRIMES[group] == p
    assert KS.FFDHE_GENERATOR == 2 and KS.ffdhe_prime_len(group) == b // 8
    assert pow(2, (p - 1) // 2, p) == 1      # g, q = (p-1)/2 mertebeli alt grubu üretir


def test_grup_adlari_tutarli():
    for g in KS.SUPPORTED_GROUPS:
        assert KS.GROUP_NAMES[g] == KS.group_name(g)
    assert [KS.group_name(g) for g in NEW_GROUPS] == ["secp521r1", "x448", "ffdhe2048", "ffdhe3072"]
    assert KS.ECDHE_GROUPS <= set(KS.SUPPORTED_GROUPS)
    assert not KS.ECDHE_GROUPS & {FF2048, FF3072, KS.GROUP_X25519MLKEM768}


@pytest.mark.parametrize("group", NEW_GROUPS, ids=KS.group_name)
def test_gidis_donus(group):
    _need(group)
    a_priv, a_pub = KS.generate_key_share(group)
    b_priv, b_pub = KS.generate_key_share(group)
    assert len(a_pub) == len(b_pub) == PUB_LEN[group]
    s1 = KS.compute_shared_secret(group, a_priv, b_pub)
    assert s1 == KS.compute_shared_secret(group, b_priv, a_pub)
    assert len(s1) == SECRET_LEN[group]
    ks = KS.KeyShareSet([group])
    assert ks.shared_secret(group, b_pub) == KS.compute_shared_secret(group, b_priv, ks.public(group))
    if group == P521:
        assert a_pub[0] == 0x04
    if group in FFDHE:   # bağımsız modüler üs ile çapraz kontrol
        p = KS.FFDHE_PRIMES[group]
        y_b = int.from_bytes(b_pub, "big")
        assert 1 < y_b < p - 1
        assert s1 == pow(y_b, a_priv.private_numbers().x, p).to_bytes(len(s1), "big")


# ---- secp521r1

def test_p521_gecersiz_noktalar_reddedilir():
    priv, _ = KS.generate_key_share(P521)
    _, other = KS.generate_key_share(P521)
    egri_disi = other[:-1] + bytes([other[-1] ^ 1])      # aralıkta ama eğri üzerinde değil
    for val in (egri_disi, b"\x04" + b"\xff" * 132, b"\x04" + bytes(132)):
        with pytest.raises(ValueError, match="eğri üzerinde değil"):
            KS.compute_shared_secret(P521, priv, val)
    bicimsiz = [
        bytes([2 + (other[-1] & 1)]) + other[1:67],      # sıkıştırılmış nokta
        b"\x06" + other[1:], b"\x07" + other[1:],        # hibrit biçim
        other[:-1], other + b"\x00",                      # yanlış uzunluk
        b"\x00",                                          # sonsuzdaki nokta
        KS.generate_key_share(KS.GROUP_SECP384R1)[1],     # başka eğrinin noktası
    ]
    for val in bicimsiz:
        with pytest.raises(ValueError, match="133 byte uncompressed"):
            KS.compute_shared_secret(P521, priv, val)


# ---- x448

@pytest.mark.parametrize("n", [0, 32, 55, 57, 133])
def test_x448_yanlis_uzunluk_reddedilir(n):
    _need(X448)
    priv, _ = KS.generate_key_share(X448)
    with pytest.raises(ValueError, match="56 byte"):
        KS.compute_shared_secret(X448, priv, bytes([9]) * n)


@pytest.mark.parametrize("u", [0, 1, X448_P - 1, X448_P], ids=["u=0", "u=1", "u=p-1", "u=p"])
def test_x448_kucuk_alt_grup_noktalari_reddedilir(u):
    """Küçük mertebeli noktalar tamamen sıfır paylaşılan sır verir (RFC 7748 §6.2)."""
    _need(X448)
    priv, _ = KS.generate_key_share(X448)
    with pytest.raises(ValueError, match="x448"):
        KS.compute_shared_secret(X448, priv, u.to_bytes(56, "little"))


def test_x448_sifir_sir_kendi_kontrolumuzle_reddedilir():
    """Backend sıfır sonucu kendisi reddetmese bile (RFC 8422 §5.11) bizim kontrolümüz yakalar."""
    _need(X448)

    class _SifirDonen:
        def exchange(self, peer):
            return bytes(56)
    _, pub = KS.generate_key_share(X448)
    with pytest.raises(ValueError, match="x448 paylaşılan sırrı sıfır"):
        KS.compute_shared_secret(X448, _SifirDonen(), pub)


# ---- ffdhe

@pytest.mark.parametrize("group", FFDHE, ids=KS.group_name)
@pytest.mark.parametrize("ad", ["Y=0", "Y=1", "Y=p-1", "Y=p", "Y=p+1", "Y=2^n-1"])
def test_ffdhe_aralik_disi_Y_reddedilir(group, ad):
    _need(group)
    p, plen = KS.FFDHE_PRIMES[group], KS.ffdhe_prime_len(group)
    y = {"Y=0": 0, "Y=1": 1, "Y=p-1": p - 1, "Y=p": p, "Y=p+1": p + 1, "Y=2^n-1": 2 ** (8 * plen) - 1}[ad]
    priv, _ = KS.generate_key_share(group)
    with pytest.raises(ValueError, match=r"1 < Y < p-1"):
        KS.compute_shared_secret(group, priv, y.to_bytes(plen, "big"))


@pytest.mark.parametrize("group", FFDHE, ids=KS.group_name)
def test_ffdhe_yanlis_uzunluk_reddedilir(group):
    _need(group)
    plen = KS.ffdhe_prime_len(group)
    priv, pub = KS.generate_key_share(group)
    _, peer = KS.generate_key_share(group)
    kisa = int.from_bytes(peer, "big").to_bytes(plen - 1, "big") if peer[0] == 0 else peer[1:]
    for val in (b"", b"\x02", kisa, peer + b"\x00", b"\x00" + peer,
                (2).to_bytes(plen - 1, "big"),            # dolgusuz (kısa) küçük değer
                KS.generate_key_share(FF3072 if group == FF2048 else FF2048)[1]):
        with pytest.raises(ValueError, match=f"{plen} byte olmalı"):
            KS.compute_shared_secret(group, priv, val)


@pytest.mark.parametrize("group", FFDHE, ids=KS.group_name)
def test_ffdhe_Y_2_sinirda_kabul_edilir(group):
    """1 < Y kesin: Y = 2 (üreteç, 255/383 sıfır baytla doldurulmuş) geçerlidir."""
    _need(group)
    p, plen = KS.FFDHE_PRIMES[group], KS.ffdhe_prime_len(group)
    priv, _ = KS.generate_key_share(group)
    out = KS.compute_shared_secret(group, priv, (2).to_bytes(plen, "big"))
    assert out == pow(2, priv.private_numbers().x, p).to_bytes(plen, "big")


def _sabit_ozel_anahtar(group, etiket: bytes, kosul):
    """Deterministik: sha256(etiket)'ten başlayıp ``kosul(x)`` sağlanana dek x'i artırır."""
    p = KS.FFDHE_PRIMES[group]
    base = int.from_bytes(hashlib.sha256(etiket).digest(), "big")
    x = next(base + i for i in range(1 << 13) if kosul(base + i))
    pn = dh.DHParameterNumbers(p, 2, (p - 1) // 2)
    return x, dh.DHPrivateNumbers(x, dh.DHPublicNumbers(pow(2, x, p), pn)).private_key()


@pytest.mark.filterwarnings("ignore::cryptography.utils.CryptographyDeprecationWarning")
@pytest.mark.parametrize("group", FFDHE, ids=KS.group_name)
def test_ffdhe_paylasilan_sir_soldan_sifirla_doldurulur(group):
    """RFC 8446 §7.4.1: Z, p uzunluğuna soldan sıfırla doldurulur. Baştaki baytı sıfır olan bir Z
    deterministik olarak seçilir (sabit eş değeri + sabit başlangıçtan aranan özel üs)."""
    _need(group)
    p, plen = KS.FFDHE_PRIMES[group], KS.ffdhe_prime_len(group)
    y_es = pow(2, int.from_bytes(hashlib.sha256(b"fasthttpc ffdhe es").digest(), "big"), p)
    x, priv = _sabit_ozel_anahtar(group, b"fasthttpc ffdhe istemci",
                                  lambda x: pow(y_es, x, p) < 1 << (8 * (plen - 1)))
    z = pow(y_es, x, p)
    assert z.bit_length() <= 8 * (plen - 1)                  # gerçekten baştaki bayt sıfır
    out = KS.compute_shared_secret(group, priv, y_es.to_bytes(plen, "big"))
    assert len(out) == plen and out[0] == 0
    assert out == z.to_bytes(plen, "big")

    class _KisaDonen:            # backend baştaki sıfırları atsa bile sonuç doldurulmalı
        def exchange(self, peer):
            return priv.exchange(peer).lstrip(b"\x00")
    assert len(_KisaDonen().exchange(priv.public_key())) <= plen
    assert KS.compute_shared_secret(group, _KisaDonen(), y_es.to_bytes(plen, "big")) == out


@pytest.mark.filterwarnings("ignore::cryptography.utils.CryptographyDeprecationWarning")
@pytest.mark.parametrize("group", FFDHE, ids=KS.group_name)
def test_ffdhe_public_deger_soldan_sifirla_doldurulur(group, monkeypatch):
    """RFC 8446 §4.2.8.1: key_share'deki Y baştaki sıfırlarla birlikte tam p uzunluğundadır."""
    _need(group)
    p, plen = KS.FFDHE_PRIMES[group], KS.ffdhe_prime_len(group)
    x, priv = _sabit_ozel_anahtar(group, b"fasthttpc ffdhe public",
                                  lambda x: pow(2, x, p) < 1 << (8 * (plen - 1)))

    class _SabitParametre:      # generate_key_share'in ürettiği özel anahtarı sabitle
        def parameters(self):
            return self

        def generate_private_key(self):
            return priv
    monkeypatch.setitem(KS._FFDHE_PARAMS, group, _SabitParametre())
    got_priv, pub = KS.generate_key_share(group)
    assert got_priv is priv
    assert len(pub) == plen and pub[0] == 0
    assert int.from_bytes(pub, "big") == pow(2, x, p)


# ============================================================ ClientHello sabitleme

G = "GREASE"
_PQ = [KS.GROUP_X25519MLKEM768] if KS.HAVE_MLKEM else []
_PQ_KS = [(KS.GROUP_X25519MLKEM768, 1184 + 32)] if KS.HAVE_MLKEM else []
#: profil -> (supported_groups, [(key_share grubu, pay uzunluğu)]) — 0.7.0 ile bayt bayt aynı.
#: secp521r1/ffdhe yalnızca ilan edilir (Firefox/Safari, gerçek tarayıcılar gibi), ilk key_share
#: hiçbir profilde bu gruplar için değildir; Chrome ve default onları hiç ilan etmez; x448'i kimse.
CH_GROUPS = {
    "chrome_131": ([G, *_PQ, 0x001D, 0x0017, 0x0018], [(G, 1), *_PQ_KS, (0x001D, 32)]),
    "chrome_158": ([G, *_PQ, 0x001D, 0x0017, 0x0018], [(G, 1), *_PQ_KS, (0x001D, 32)]),
    "firefox_133": ([*_PQ, 0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101],
                    [*_PQ_KS, (0x001D, 32), (0x0017, 65)]),
    "firefox_160": ([*_PQ, 0x001D, 0x0017, 0x0018, 0x0019], [*_PQ_KS, (0x001D, 32), (0x0017, 65)]),
    "safari_18": ([G, 0x001D, 0x0017, 0x0018, 0x0019], [(G, 1), (0x001D, 32)]),
    "safari_27": ([G, *_PQ, 0x001D, 0x0017, 0x0018, 0x0019], [(G, 1), *_PQ_KS, (0x001D, 32)]),
    "default": ([0x001D, 0x0017, 0x0018], [(0x001D, 32)]),
}


def test_sabitleme_tum_profilleri_kapsar():
    assert set(CH_GROUPS) == set(PROFILES)


def _ext(ch: bytes, etype: int) -> bytes:
    found = [p for t, p in _parse_client_hello_fields(ch)[1] if t == etype]
    assert len(found) == 1, (hex(etype), len(found))
    return found[0]


def _key_share_entries(payload: bytes) -> list:
    total = struct.unpack("!H", payload[:2])[0]
    assert total == len(payload) - 2
    out, off = [], 2
    while off < len(payload):
        g, n = struct.unpack("!HH", payload[off:off + 4])
        out.append((g, payload[off + 4:off + 4 + n]))
        off += 4 + n
    assert off == len(payload)
    return out


@pytest.mark.parametrize("legacy", [False, True], ids=["normal", "legacy_tls"])
@pytest.mark.parametrize("name", sorted(CH_GROUPS))
def test_clienthello_grup_ve_key_share_baytlari_degismedi(name, legacy):
    groups, shares = CH_GROUPS[name]
    imp = TLSImpersonator(HOST, profile=name, legacy_tls=legacy)
    ch = imp.build_client_hello()[0]
    gv = imp._grease_group
    wire = [gv if g == G else g for g in groups]
    raw = b"".join(struct.pack("!H", g) for g in wire)
    assert _ext(ch, 0x000A) == struct.pack("!H", len(raw)) + raw          # supported_groups: tam bayt
    entries = _key_share_entries(_ext(ch, 0x0033))
    assert [(G if g == gv else g, len(pub)) for g, pub in entries] == shares
    for g, pub in entries:
        if g == gv:
            assert pub == b"\x00"                                          # RFC 8701 GREASE payı
    assert imp.advertised_groups() == [g for g in wire if g != gv]
    assert not {g for g, _ in entries} & set(NEW_GROUPS)


def test_hrr_grubu_ilan_edilmemisse_ikinci_clienthello_uretilmez():
    imp = TLSImpersonator(HOST, profile="chrome_131")
    imp.build_client_hello()
    for g in NEW_GROUPS:
        with pytest.raises(ValueError, match="ilan edilmedi"):
            imp.build_retry_client_hello(g)


# ============================================================ HRR: senkron TLSAdapter yolu

HRR_OK = [("firefox_133", P521), ("firefox_133", FF2048), ("firefox_133", FF3072),
          ("firefox_160", P521), ("safari_18", P521), ("safari_27", P521), ("test_x448", X448)]


@pytest.mark.parametrize("profile,group", HRR_OK)
def test_hrr_ile_yeni_gruba_gecis_senkron(trust_leaf, request, profile, group):  # noqa: F811
    _need(group)
    srv = fts.FakeTLS13Server(hrr_group=group)
    esock = _connect(srv, _profil(request, profile))
    assert esock.state["hello_retry"] is True and esock.state["key_share_group"] == group
    assert _roundtrip(esock).startswith(b"HTTP/1.1 200")
    srv.done.wait(5)
    assert srv.error is None, srv.error
    ch1, ch2 = srv.client_hellos
    assert group in ch1["groups"] and group not in ch1["key_shares"]
    assert list(ch2["key_shares"]) == [group] and len(ch2["key_shares"][group]) == PUB_LEN[group]
    assert ch2["groups"] == ch1["groups"]                 # supported_groups CH2'de aynen korunur
    srv.close()


@pytest.mark.parametrize("profile,group", [
    ("chrome_131", P521), ("chrome_158", P521), ("chrome_158", FF2048), ("firefox_160", FF2048),
    ("firefox_160", FF3072), ("safari_27", FF2048), ("default", X448), ("default", P521),
])
def test_hrr_ilan_edilmemis_grup_reddedilir_senkron(trust_leaf, profile, group):  # noqa: F811
    srv = fts.FakeTLS13Server(hrr_group=group)
    with pytest.raises(ConnectionError, match="ilan etmediğimiz grubu.*illegal_parameter"):
        _connect(srv, profile)
    srv.done.wait(5)
    assert len(srv.client_hellos) == 1                      # 2. ClientHello GÖNDERİLMEDİ
    srv.close()


def test_hrr_zaten_pay_gonderilen_grup_reddedilir_senkron(trust_leaf):  # noqa: F811
    srv = fts.FakeTLS13Server(hrr_group=KS.GROUP_SECP256R1)     # firefox ilk CH'de P-256 payı yollar
    with pytest.raises(ConnectionError, match="zaten key_share gönderdiğimiz.*illegal_parameter"):
        _connect(srv, "firefox_133")
    srv.close()


@pytest.mark.parametrize("group", [P521, FF2048])
def test_hrr_ikinci_kez_gelirse_reddedilir_senkron(trust_leaf, group):  # noqa: F811
    srv = fts.FakeTLS13Server(hrr_group=group, double_hrr=True)
    with pytest.raises(ConnectionError, match="ikinci bir HelloRetryRequest"):
        _connect(srv, "firefox_133")
    srv.close()


# ============================================================ HRR: sans-IO çekirdek (async yolu)

@pytest.fixture(scope="module")
def pki13():
    return sansio.PKI(HOST)


@pytest.fixture
def trust13(pki13, tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_bytes(pki13.ca_pem())
    return {"ca_path": str(ca)}


@pytest.mark.parametrize("profile,group", HRR_OK)
def test_hrr_ile_yeni_gruba_gecis_sansio(pki13, trust13, request, profile, group):
    _need(group)
    server = sansio.FakeTLS13Server(pki13, hrr_group=group)
    conn = TLSClientConnection(HOST, _profil(request, profile), **trust13)
    handshake(conn, server)
    assert conn.handshake_complete and server.state == "CONNECTED"
    ch1, ch2 = server.client_hellos
    assert group not in ch1["shares"]
    assert list(ch2["shares"]) == [group] and len(ch2["shares"][group]) == PUB_LEN[group]


@pytest.mark.parametrize("profile,group", [("chrome_131", P521), ("chrome_158", FF3072),
                                           ("firefox_160", FF2048), ("default", X448)])
def test_hrr_ilan_edilmemis_grup_reddedilir_sansio(pki13, trust13, profile, group):
    server = sansio.FakeTLS13Server(pki13, hrr_group=group)
    conn = TLSClientConnection(HOST, profile, **trust13)
    with pytest.raises(TLSError, match="illegal_parameter.*ilan edilmedi"):
        handshake(conn, server)
    assert len(server.client_hellos) == 1


def test_hrr_zaten_pay_gonderilen_grup_reddedilir_sansio(pki13, trust13):
    server = sansio.FakeTLS13Server(pki13, hrr_group=KS.GROUP_SECP256R1)
    conn = TLSClientConnection(HOST, "firefox_160", **trust13)
    with pytest.raises(TLSError, match="illegal_parameter.*zaten teklif"):
        handshake(conn, server)


def test_hrr_ikinci_kez_gelirse_reddedilir_sansio(pki13, trust13):
    server = sansio.FakeTLS13Server(pki13, hrr_group=P521, tamper={"double_hrr"})
    conn = TLSClientConnection(HOST, "firefox_160", **trust13)
    with pytest.raises(TLSError, match="unexpected_message: ikinci HelloRetryRequest"):
        handshake(conn, server)
    assert len(server.client_hellos) == 2


# ============================================================ TLS 1.2 ECDHE ServerKeyExchange

@pytest.fixture(scope="module")
def pki12():
    return PKI12()


@pytest.fixture(scope="module")
def ca12(pki12, tmp_path_factory):
    return pki12.write(tmp_path_factory.mktemp("kex12"))[0]


def _connect12(srv, ca, profile):
    port, t, ls = serve_fake_in_thread(srv)
    s = socket.create_connection(("127.0.0.1", port), timeout=8)
    try:
        return TLSAdapter.negotiate(s, HOST12, profile, ca_path=ca), t
    except BaseException:
        s.close()
        ls.close()
        t.join(5)
        raise


@pytest.mark.parametrize("suite", [0xC02B, 0xC02F])
@pytest.mark.parametrize("profile,group", [("firefox_160", P521), ("firefox_133", P521),
                                           ("test_x448", X448)])
def test_tls12_ecdhe_yeni_egriler(pki12, ca12, request, profile, group, suite):
    _need(group)
    srv = Fake12Server(pki12, group=group, suite=suite)
    es, t = _connect12(srv, ca12, _profil(request, profile))
    assert es.state["cipher_suite"] == suite
    es.send_record(b"x")
    assert es.recv_record(skip_post_handshake=True) == (b"echo:x", 23)
    es.close()
    t.join(3)
    assert srv.finished_ok and srv.error is None, srv.error   # sunucu istemci Finished'ını doğruladı
    assert len(srv.cke_pub) == PUB_LEN[group]
    if group == P521:
        assert srv.cke_pub[0] == 0x04


@pytest.mark.parametrize("profile,group", [("firefox_160", P521), ("test_x448", X448)])
def test_tls12_gecersiz_ecdhe_noktasi_reddedilir(pki12, ca12, request, profile, group):
    _need(group)
    srv = Fake12Server(pki12, group=group, tamper={"bad_pub"})
    with pytest.raises(ConnectionError, match="illegal_parameter.*ECDHE anahtarı geçersiz"):
        _connect12(srv, ca12, _profil(request, profile))
    assert not srv.cke_seen, "geçersiz sunucu anahtarında ClientKeyExchange GÖNDERİLMEMELİ"


@pytest.mark.parametrize("profile,group,match", [
    ("chrome_131", P521, "ilan etmediğimiz eğri"),          # Chrome secp521r1 ilan etmez
    ("chrome_158", X448, "ilan etmediğimiz eğri"),
    ("default", P521, "ilan etmediğimiz eğri"),
    ("firefox_133", FF2048, "desteklenmeyen eğri"),         # ffdhe bir ECDHE eğrisi değildir
    ("firefox_133", FF3072, "desteklenmeyen eğri"),
    ("firefox_160", KS.GROUP_X25519MLKEM768, "desteklenmeyen eğri"),   # hibrit grup yalnızca TLS 1.3
])
def test_tls12_ilan_edilmemis_veya_ecdhe_olmayan_grup_reddedilir(pki12, ca12, profile, group, match):
    srv = Fake12Server(pki12, group=group)
    with pytest.raises(ConnectionError, match=f"illegal_parameter.*{match}"):
        _connect12(srv, ca12, profile)
    assert not srv.cke_seen
