"""
TLS parmak izi testleri.

Buradaki testlerin ortak fikri: iddiayı PROFİL SÖZLÜĞÜNDEN değil, telde
gerçekten gönderilen ClientHello byte'larından doğrulamak. Eski ja3_hash()
profili okuyordu, dolayısıyla kodun profili filtrelediğini fark edemiyordu.
"""
import pytest

from fasthttpc.fingerprint import (
    PROFILES,
    available_profiles,
    get_profile,
    ja3_for_profile,
    ja3_string_from_client_hello,
    extension_ids_from_client_hello,
)
from fasthttpc.tls_crafter import TLSImpersonator


def _client_hello(profile="chrome_131"):
    return TLSImpersonator("example.com", profile=profile).build_client_hello()[0]


def test_bilinmeyen_profil_sessizce_dusmez():
    """Eski davranış default'a düşüp UA'yı 'fasthttpc' yapıyordu."""
    with pytest.raises(ValueError, match="Bilinmeyen TLS profili"):
        get_profile("opera_99")


def test_hata_mesaji_kullanilabilir_profilleri_listeler():
    with pytest.raises(ValueError) as exc:
        get_profile("yok_boyle")
    for name in available_profiles():
        assert name in str(exc.value)


@pytest.mark.parametrize("alias,canonical", [
    ("firefox_120", "firefox_133"),
    ("safari_17", "safari_18"),
    ("chrome", "chrome_158"),
    ("firefox", "firefox_160"),
    ("safari", "safari_27"),
    ("safari_27_2", "safari_27"),
    ("chrome_131", "chrome_131"),
])
def test_takma_adlar_dogru_profile_gider(alias, canonical):
    assert get_profile(alias)["_name"] == canonical


def test_chrome_tls12_suitelerini_de_reklam_eder():
    """Regresyon: filtre yalnızca 0x1301-3 bırakıyordu, JA3 tanınmaz oluyordu."""
    ja3 = ja3_string_from_client_hello(_client_hello("chrome_131"))
    ciphers = ja3.split(",")[1].split("-")
    assert "49195" in ciphers   # 0xC02B ECDHE-ECDSA-AES128-GCM
    assert "52393" in ciphers   # 0xCCA9 ECDHE-ECDSA-CHACHA20
    assert len(ciphers) >= 15, f"Chrome 15+ suite reklam eder, {len(ciphers)} bulundu"


def test_tls13_suiteleri_her_zaman_var():
    for name in ("chrome_131", "firefox_133", "safari_18", "chrome_158", "firefox_160", "safari_27"):
        ciphers = ja3_string_from_client_hello(_client_hello(name)).split(",")[1].split("-")
        assert "4865" in ciphers  # 0x1301


def test_client_random_zaman_damgasi_icermiyor():
    """gmt_unix_time prefix'i TLS 1.2 kalıntısıdır; tek başına bot sinyali verir."""
    import time
    now = int(time.time())
    for _ in range(5):
        body = _client_hello()[5 + 4:]
        prefix = int.from_bytes(body[2:6], "big")
        assert abs(prefix - now) > 86400, "client_random zaman damgası taşıyor gibi"


def test_padding_boringssl_kurali():
    """BoringSSL: handshake mesajı 256..511 bayt ise 512'ye tamamlanır, aksi halde
    padding YOK. Safari profili padding ister (JA4'teki 21), Chrome ister değil."""
    for host in ("a.com", "cok-daha-uzun-bir-alan-adi.example.org", "x.io"):
        ch = TLSImpersonator(host, profile="safari_18").build_client_hello()[0]
        assert len(ch) - 5 == 512, f"{host}: handshake {len(ch) - 5} byte"
        assert 0x15 in extension_ids_from_client_hello(ch)
        ch = TLSImpersonator(host, profile="chrome_131").build_client_hello()[0]
        assert 0x15 not in extension_ids_from_client_hello(ch)


def test_profiller_farkli_ja3_uretir():
    adlar = ("chrome_131", "firefox_133", "safari_18", "chrome_158", "firefox_160", "safari_27")
    hashes_ = {p: ja3_for_profile(p)[1] for p in adlar}
    assert len(set(hashes_.values())) == len(adlar)


def test_ja3_grease_degerlerini_disarida_birakir():
    """JA3 tanımı gereği GREASE değerleri elenir; yoksa hash her seferinde değişir."""
    # Chrome extension sırasını bağlantı başına karıştırır (gerçek davranış):
    # JA3 METNİ değişir ama extension KÜMESİ/şifre/grup alanları sabittir.
    a = ja3_string_from_client_hello(_client_hello()).split(",")
    b = ja3_string_from_client_hello(_client_hello()).split(",")
    assert a[1] == b[1] and a[3:] == b[3:]
    assert sorted(a[2].split("-")) == sorted(b[2].split("-"))
    # Karıştırmayan profillerde JA3 birebir kararlıdır.
    for ad in ("firefox_133", "safari_18"):
        assert ja3_string_from_client_hello(_client_hello(ad)) == \
            ja3_string_from_client_hello(_client_hello(ad))


def test_sni_hedef_hostu_tasiyor():
    ch = TLSImpersonator("test.example.org", profile="chrome_131").build_client_hello()[0]
    assert b"test.example.org" in ch


def test_alpn_h2_iceriyor():
    assert b"h2" in _client_hello("chrome_131")


def test_tum_profillerde_client_hello_kurulabiliyor():
    for name in available_profiles():
        assert len(_client_hello(name)) > 100


def test_supported_versions_grease_iceriyor():
    """Regresyon: GREASE'siz supported_versions nginx gibi katı sunucularda
    protocol_version alert'ine yol açıyordu. Chrome GREASE+0304 gönderir."""
    import struct
    from fasthttpc.tls_crafter import TLSImpersonator
    from fasthttpc.fingerprint import _GREASE_VALUES

    ch = TLSImpersonator("example.com", profile="chrome_131").build_client_hello()[0]
    body = ch[9:]
    pos = 2 + 32
    sid = body[pos]; pos += 1 + sid
    cs = struct.unpack("!H", body[pos:pos + 2])[0]; pos += 2 + cs
    comp = body[pos]; pos += 1 + comp
    ext_total = struct.unpack("!H", body[pos:pos + 2])[0]; pos += 2
    end = pos + ext_total
    bulundu = False
    while pos + 4 <= end:
        et, el = struct.unpack("!HH", body[pos:pos + 4]); pos += 4
        payload = body[pos:pos + el]; pos += el
        if et == 0x2B:
            bulundu = True
            list_len = payload[0]
            versions = [struct.unpack("!H", payload[1 + i:3 + i])[0]
                        for i in range(0, list_len, 2)]
            assert 0x0304 in versions, "TLS 1.3 (0x0304) listede olmalı"
            assert any(v in _GREASE_VALUES for v in versions), \
                f"supported_versions GREASE içermeli, bulunan: {[hex(v) for v in versions]}"
    assert bulundu, "supported_versions extension'ı yok"
