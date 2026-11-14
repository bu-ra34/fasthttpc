"""Test PKI üreticisi: CA, ara CA ve çeşitli anahtar türlerinde yaprak sertifikalar.

Her şey `cryptography` ile bellekte üretilir ve dosyaya yazılır; openssl CLI gerekmez.
"""
from __future__ import annotations

import datetime
import ipaddress
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_NOW = datetime.datetime.now(datetime.timezone.utc)


def gen_key(kind: str):
    if kind == "rsa2048":
        return rsa.generate_private_key(65537, 2048)
    if kind == "rsa4096":
        return rsa.generate_private_key(65537, 4096)
    if kind == "p256":
        return ec.generate_private_key(ec.SECP256R1())
    if kind == "p384":
        return ec.generate_private_key(ec.SECP384R1())
    if kind == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError(kind)


def _sign_hash(key):
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return None
    if isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.name == "secp384r1":
        return hashes.SHA384()
    return hashes.SHA256()


def pem_cert(c: x509.Certificate) -> bytes:
    return c.public_bytes(serialization.Encoding.PEM)


def pem_key(k) -> bytes:
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())


@dataclass
class Cert:
    cert: x509.Certificate
    key: object

    @property
    def pem(self) -> bytes:
        return pem_cert(self.cert)


def make_cert(cn: str, issuer: "Cert | None", key_kind: str = "p256", *, ca: bool = False,
              sans: "list[str] | None" = None, not_before=None, not_after=None,
              server_auth: bool = True, path_len=None) -> Cert:
    key = gen_key(key_kind)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer_name = issuer.cert.subject if issuer else name
    signer = issuer.key if issuer else key
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(not_before or _NOW - datetime.timedelta(days=1))
         .not_valid_after(not_after or _NOW + datetime.timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=path_len if ca else None), critical=True))
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                            critical=True)
    else:
        if server_auth:
            b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        gn = []
        for s in (sans if sans is not None else [cn]):
            try:
                gn.append(x509.IPAddress(ipaddress.ip_address(s)))
            except ValueError:
                gn.append(x509.DNSName(s))
        if gn:
            b = b.add_extension(x509.SubjectAlternativeName(gn), critical=False)
    b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    if issuer:
        b = b.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()), critical=False)
    return Cert(b.sign(signer, _sign_hash(signer)), key)


def write(dirpath: Path, name: str, c: Cert, *extra_chain: Cert) -> "tuple[str, str]":
    """Yaprak + (isteğe bağlı) zincir sertifikalarını `name.pem`, anahtarı `name.key` olarak yazar."""
    cp, kp = dirpath / f"{name}.pem", dirpath / f"{name}.key"
    cp.write_bytes(c.pem + b"".join(x.pem for x in extra_chain))
    kp.write_bytes(pem_key(c.key))
    return str(cp), str(kp)


def write_ca(dirpath: Path, name: str, *cas: Cert) -> str:
    p = dirpath / f"{name}.pem"
    p.write_bytes(b"".join(c.pem for c in cas))
    return str(p)
