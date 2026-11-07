"""cert_validator güven deposu önbelleği ve ca_path testleri (ağsız)."""
import datetime
import os
import struct
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from fasthttpc.security import cert_validator as cv
from fasthttpc.security.cert_validator import (
    CertificateValidationError,
    clear_trust_store_cache,
    load_trust_store,
    validate_server_certificate,
)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _make_ca(cn="Test Root CA"):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn)).issuer_name(_name(cn))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_leaf(ca_key, ca_cert, host, not_before_days=-1, not_after_days=30):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(host)).issuer_name(ca_cert.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=not_before_days))
        .not_valid_after(now + datetime.timedelta(days=not_after_days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return cert


def _cert_msg(*certs):
    entries = b""
    for c in certs:
        der = c.public_bytes(serialization.Encoding.DER)
        entries += struct.pack("!I", len(der))[1:] + der + b"\x00\x00"
    body = b"\x00" + struct.pack("!I", len(entries))[1:] + entries
    return b"\x0b" + struct.pack("!I", len(body))[1:] + body


@pytest.fixture
def ca_pem(tmp_path):
    key, cert = _make_ca()
    p = tmp_path / "ca.pem"
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert, str(p)


def test_custom_ca_accepted(ca_pem):
    key, ca, path = ca_pem
    leaf = _make_leaf(key, ca, "example.test")
    out = validate_server_certificate(_cert_msg(leaf), "example.test", ca_path=path)
    assert out.serial_number == leaf.serial_number


def test_custom_ca_rejected_by_default_store(ca_pem):
    key, ca, _path = ca_pem
    leaf = _make_leaf(key, ca, "example.test")
    with pytest.raises(CertificateValidationError, match="doğrulanamadı"):
        validate_server_certificate(_cert_msg(leaf), "example.test")


def test_hostname_mismatch(ca_pem):
    key, ca, path = ca_pem
    leaf = _make_leaf(key, ca, "example.test")
    with pytest.raises(CertificateValidationError, match="doğrulanamadı"):
        validate_server_certificate(_cert_msg(leaf), "other.test", ca_path=path)


def test_expired_message_preserved(ca_pem):
    key, ca, path = ca_pem
    leaf = _make_leaf(key, ca, "example.test", not_before_days=-30, not_after_days=-1)
    with pytest.raises(CertificateValidationError, match="süresi dolmuş"):
        validate_server_certificate(_cert_msg(leaf), "example.test", ca_path=path)


def test_not_yet_valid_message_preserved(ca_pem):
    key, ca, path = ca_pem
    leaf = _make_leaf(key, ca, "example.test", not_before_days=2, not_after_days=30)
    with pytest.raises(CertificateValidationError, match="henüz geçerli değil"):
        validate_server_certificate(_cert_msg(leaf), "example.test", ca_path=path)


def test_store_is_cached_per_path(ca_pem):
    _key, _ca, path = ca_pem
    clear_trust_store_cache()
    s1 = load_trust_store(path)
    s2 = load_trust_store(path)
    assert s1 is s2
    d1 = load_trust_store()
    assert d1 is load_trust_store()
    assert d1 is not s1
    info = cv._build_store.cache_info()
    assert info.misses == 2 and info.hits == 2


def test_cache_invalidated_when_file_changes(ca_pem, tmp_path):
    _key, _ca, path = ca_pem
    s1 = load_trust_store(path)
    key2, ca2 = _make_ca("Second CA")
    with open(path, "wb") as f:
        f.write(ca2.public_bytes(serialization.Encoding.PEM))
    st = os.stat(path)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000))
    s2 = load_trust_store(path)
    assert s1 is not s2
    leaf = _make_leaf(key2, ca2, "two.test")
    validate_server_certificate(_cert_msg(leaf), "two.test", ca_path=path)


def test_missing_ca_file():
    with pytest.raises(CertificateValidationError, match="CA bundle yüklenemedi"):
        load_trust_store("/nonexistent/ca.pem")


def test_cached_load_is_fast():
    clear_trust_store_cache()
    t0 = time.perf_counter()
    load_trust_store()
    cold = time.perf_counter() - t0
    t0 = time.perf_counter()
    for _ in range(100):
        load_trust_store()
    warm = (time.perf_counter() - t0) / 100
    assert warm < cold
