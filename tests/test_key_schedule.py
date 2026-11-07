"""
TLS 1.3 anahtar türetme (key schedule) testleri.

Kritik nokta: HKDF hash'i müzakere edilen cipher suite'e bağlıdır.
SHA-256'ya sabitlemek, TLS_AES_256_GCM_SHA384 (0x1302) seçildiğinde
SESSİZCE yanlış anahtar üretir — bağlantı "sebepsiz" kopar.
"""
import hashlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from fasthttpc.crypto_math import PureCryptoEngine as P, PureAESGCM


@pytest.mark.parametrize("hash_alg,ch", [
    (hashlib.sha256, hashes.SHA256()),
    (hashlib.sha384, hashes.SHA384()),
])
def test_hkdf_extract_bagimsiz_implementasyonla_uyusuyor(hash_alg, ch):
    salt, ikm = b"tuz" * 5, b"anahtar malzemesi"
    bizim = P.hkdf_extract(salt, ikm, hash_alg=hash_alg)
    onlarin = HKDF(algorithm=ch, length=ch.digest_size, salt=salt, info=None)._extract(ikm)
    assert bizim == onlarin


@pytest.mark.parametrize("hash_alg,ch", [
    (hashlib.sha256, hashes.SHA256()),
    (hashlib.sha384, hashes.SHA384()),
])
def test_hkdf_expand_bagimsiz_implementasyonla_uyusuyor(hash_alg, ch):
    prk = hash_alg(b"prk").digest()
    info, length = b"bilgi", 42
    bizim = P.hkdf_expand(prk, info, length, hash_alg=hash_alg)
    onlarin = HKDFExpand(algorithm=ch, length=length, info=info).derive(prk)
    assert bizim == onlarin


def test_expand_label_rfc8446_formatinda():
    """HkdfLabel: length(2) + len("tls13 "+label)(1) + label + len(ctx)(1) + ctx"""
    secret = b"\x01" * 32
    out = P.tls13_hkdf_expand_label(secret, "key", b"", 16)
    beklenen_info = (
        (16).to_bytes(2, "big") + bytes([len(b"tls13 key")]) + b"tls13 key" + b"\x00"
    )
    assert out == P.hkdf_expand(secret, beklenen_info, 16)


def test_sha384_suite_dogru_uzunlukta_secret_uretir():
    """0x1302 (AES_256_GCM_SHA384) 48 byte'lık traffic secret gerektirir."""
    t = hashlib.sha384(b"transcript").digest()
    _, ck, civ, sk, siv, c_hts, s_hts = P.derive_tls13_keys(
        b"\x02" * 32, t, 32, hash_alg=hashlib.sha384
    )
    assert len(c_hts) == 48 and len(s_hts) == 48
    assert len(ck) == 32 and len(sk) == 32
    assert len(civ) == 12 and len(siv) == 12


def test_sha256_suite_32_byte_secret_uretir():
    t = hashlib.sha256(b"transcript").digest()
    _, ck, _, _, _, c_hts, s_hts = P.derive_tls13_keys(b"\x02" * 32, t, 16)
    assert len(c_hts) == 32 and len(s_hts) == 32
    assert len(ck) == 16


def test_istemci_ve_sunucu_secretlari_farkli():
    """c_hts == s_hts olsaydı iki yön aynı anahtarı kullanırdı — ciddi hata."""
    t = hashlib.sha256(b"x").digest()
    _, _, _, _, _, c_hts, s_hts = P.derive_tls13_keys(b"\x03" * 32, t, 16)
    assert c_hts != s_hts


def test_aes192_acikca_reddedilir():
    """Eski kod 24 byte anahtara 14 tur uyguluyordu — sessizce yanlış sonuç."""
    with pytest.raises(ValueError, match="AES-128 ve AES-256"):
        PureAESGCM(b"\x00" * 24)


@pytest.mark.parametrize("key_size", [16, 32])
def test_saf_python_aes_gcm_gidip_geliyor(key_size):
    aead = PureAESGCM(b"\x07" * key_size)
    nonce, pt, aad = b"\x01" * 12, b"gizli mesaj", b"ek veri"
    ct, tag = aead.encrypt_gcm(nonce, pt, aad)
    assert aead.decrypt_gcm(nonce, ct, aad, tag) == pt


def test_bozulmus_tag_reddedilir():
    aead = PureAESGCM(b"\x07" * 16)
    nonce, pt = b"\x01" * 12, b"gizli"
    ct, tag = aead.encrypt_gcm(nonce, pt, b"")
    with pytest.raises(ValueError, match="tag mismatch"):
        aead.decrypt_gcm(nonce, ct, b"", bytes(16))
