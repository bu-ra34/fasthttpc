"""
CertificateVerify doğrulamasının testleri.

Bu dosya projedeki en kritik güvenlik düzeltmesini koruma altına alır:
TLS 1.3'te sunucunun sertifikadaki özel anahtara sahip olduğunun tek kanıtı
CertificateVerify imzasıdır. Bu kontrol kaldırılırsa/bozulursa MITM mümkün
hâle gelir, o yüzden testler hem "geçerli imzayı kabul et" hem de
"her türlü sahte imzayı reddet" tarafını kapsar.

Ağ gerektirmez: sertifikalar ve imzalar test içinde üretilir.
"""
import datetime
import struct

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, ed25519
from cryptography.x509.oid import NameOID

from fasthttpc.security.cert_validator import (
    CertificateValidationError,
    build_certificate_verify_content,
    verify_certificate_verify,
)


def _make_cert(private_key, host="example.com"):
    """Test için kendinden imzalı sertifika üretir."""
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.datetime.now(datetime.timezone.utc)
    # Ed25519/Ed448 kendi hash'ini içerir; ayrı algoritma verilemez.
    algo = None if isinstance(private_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .sign(private_key, algo)
    )


def _wrap(scheme: int, signature: bytes) -> bytes:
    """Ham imzayı CertificateVerify handshake mesajı formatına sarar."""
    body = struct.pack("!HH", scheme, len(signature)) + signature
    return b"\x0f" + struct.pack("!I", len(body))[1:] + body


TRANSCRIPT = hashes.Hash(hashes.SHA256())
TRANSCRIPT.update(b"sahte transcript")
TRANSCRIPT_HASH = TRANSCRIPT.finalize()


# --- Geçerli imzalar kabul edilmeli ---------------------------------------

def test_ecdsa_p256_gecerli_imza_kabul_edilir():
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _make_cert(key)
    content = build_certificate_verify_content(TRANSCRIPT_HASH)
    sig = key.sign(content, ec.ECDSA(hashes.SHA256()))

    assert verify_certificate_verify(_wrap(0x0403, sig), cert, TRANSCRIPT_HASH) == 0x0403


def test_rsa_pss_gecerli_imza_kabul_edilir():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _make_cert(key)
    content = build_certificate_verify_content(TRANSCRIPT_HASH)
    sig = key.sign(
        content,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )

    assert verify_certificate_verify(_wrap(0x0804, sig), cert, TRANSCRIPT_HASH) == 0x0804


def test_ed25519_gecerli_imza_kabul_edilir():
    key = ed25519.Ed25519PrivateKey.generate()
    cert = _make_cert(key)
    content = build_certificate_verify_content(TRANSCRIPT_HASH)
    sig = key.sign(content)

    assert verify_certificate_verify(_wrap(0x0807, sig), cert, TRANSCRIPT_HASH) == 0x0807


# --- Saldırı senaryoları reddedilmeli --------------------------------------

def test_baska_anahtarla_imzalanmis_mesaj_reddedilir():
    """Klasik MITM: saldırgan gerçek sertifikayı iletir ama kendi anahtarıyla imzalar."""
    gercek_key = ec.generate_private_key(ec.SECP256R1())
    gercek_cert = _make_cert(gercek_key)

    saldirgan_key = ec.generate_private_key(ec.SECP256R1())
    content = build_certificate_verify_content(TRANSCRIPT_HASH)
    sahte_sig = saldirgan_key.sign(content, ec.ECDSA(hashes.SHA256()))

    with pytest.raises(CertificateValidationError, match="GEÇERSİZ"):
        verify_certificate_verify(_wrap(0x0403, sahte_sig), gercek_cert, TRANSCRIPT_HASH)


def test_farkli_transcript_uzerine_imza_reddedilir():
    """İmza geçerli ama BAŞKA bir handshake'e ait — replay saldırısı."""
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _make_cert(key)

    eski_transcript = b"\xaa" * 32
    sig = key.sign(
        build_certificate_verify_content(eski_transcript), ec.ECDSA(hashes.SHA256())
    )

    with pytest.raises(CertificateValidationError, match="GEÇERSİZ"):
        verify_certificate_verify(_wrap(0x0403, sig), cert, TRANSCRIPT_HASH)


def test_bozulmus_imza_reddedilir():
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _make_cert(key)
    sig = bytearray(key.sign(
        build_certificate_verify_content(TRANSCRIPT_HASH), ec.ECDSA(hashes.SHA256())
    ))
    sig[-1] ^= 0xFF

    with pytest.raises(CertificateValidationError):
        verify_certificate_verify(_wrap(0x0403, bytes(sig)), cert, TRANSCRIPT_HASH)


def test_rsa_pkcs1_semasi_reddedilir():
    """RFC 8446 §4.4.3: rsa_pkcs1_* TLS 1.3 CertificateVerify'da YASAKTIR."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _make_cert(key)
    sig = key.sign(
        build_certificate_verify_content(TRANSCRIPT_HASH), padding.PKCS1v15(), hashes.SHA256()
    )

    with pytest.raises(CertificateValidationError, match="yasak|Desteklenmeyen"):
        verify_certificate_verify(_wrap(0x0401, sig), cert, TRANSCRIPT_HASH)


def test_anahtar_tipi_uyusmazligi_reddedilir():
    """Sertifikada RSA var ama ECDSA şeması bildirilmiş."""
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _make_cert(rsa_key)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    sig = ec_key.sign(
        build_certificate_verify_content(TRANSCRIPT_HASH), ec.ECDSA(hashes.SHA256())
    )

    with pytest.raises(CertificateValidationError, match="EC değil"):
        verify_certificate_verify(_wrap(0x0403, sig), cert, TRANSCRIPT_HASH)


def test_kesilmis_mesaj_reddedilir():
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _make_cert(key)
    # 500 byte imza vaat edip 4 byte gönder
    bozuk = b"\x0f\x00\x00\x08" + struct.pack("!HH", 0x0403, 500) + b"\x01\x02\x03\x04"

    with pytest.raises(CertificateValidationError, match="kesilmiş"):
        verify_certificate_verify(bozuk, cert, TRANSCRIPT_HASH)


# --- İmzalanan içeriğin biçimi RFC'ye uymalı --------------------------------

def test_imzalanan_icerik_rfc8446_formatinda():
    content = build_certificate_verify_content(TRANSCRIPT_HASH)
    assert content[:64] == b"\x20" * 64
    assert content[64:64 + 33] == b"TLS 1.3, server CertificateVerify"
    assert content[97] == 0x00
    assert content[98:] == TRANSCRIPT_HASH
