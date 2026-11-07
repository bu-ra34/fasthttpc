"""validate_server_certificate(..., ca_path=...) — özel CA bundle testleri (ağsız)."""
import datetime
import struct

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from fasthttpc.security.cert_validator import (
    CertificateValidationError,
    validate_server_certificate,
)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("Kurumsal Test CA")).issuer_name(_name("Kurumsal Test CA"))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_leaf(ca_key, ca_cert, host):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(_name(host)).issuer_name(ca_cert.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=10))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, hashes.SHA256())
    )


def _certificate_msg(*certs):
    entries = b""
    for c in certs:
        der = c.public_bytes(serialization.Encoding.DER)
        entries += struct.pack("!I", len(der))[1:] + der + b"\x00\x00"
    body = b"\x00" + struct.pack("!I", len(entries))[1:] + entries
    return b"\x0b" + struct.pack("!I", len(body))[1:] + body


@pytest.fixture
def pki(tmp_path):
    ca_key, ca_cert = _make_ca()
    leaf = _make_leaf(ca_key, ca_cert, "intranet.example")
    pem = tmp_path / "kurumsal-ca.pem"
    pem.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return str(pem), _certificate_msg(leaf)


def test_ozel_ca_ile_zincir_kabul_edilir(pki):
    ca_path, msg = pki
    leaf = validate_server_certificate(msg, "intranet.example", ca_path=ca_path)
    assert leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "intranet.example"


def test_varsayilan_store_ozel_ca_yi_tanimaz(pki):
    _, msg = pki
    with pytest.raises(CertificateValidationError):
        validate_server_certificate(msg, "intranet.example")


def test_ozel_ca_ile_hostname_uyusmazligi_reddedilir(pki):
    ca_path, msg = pki
    with pytest.raises(CertificateValidationError):
        validate_server_certificate(msg, "baska.example", ca_path=ca_path)


def test_olmayan_ca_dosyasi_hata_verir(pki, tmp_path):
    _, msg = pki
    with pytest.raises(CertificateValidationError):
        validate_server_certificate(msg, "intranet.example", ca_path=str(tmp_path / "yok.pem"))
