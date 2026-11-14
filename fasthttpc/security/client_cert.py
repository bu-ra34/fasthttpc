"""İstemci sertifikası (mTLS) yükleme ve imzalama.

Kabul edilen girdiler (requests uyumlu)::

    ClientCert.coerce("client.pem")                      # sertifika + anahtar tek PEM
    ClientCert.coerce(("cert.pem", "key.pem"))
    ClientCert.coerce(("cert.pem", "key.pem", "parola"))  # şifreli PEM / PKCS#8
    ClientCert.from_pkcs12("kimlik.p12", "parola")

Anahtar türleri: RSA (>= 2048 bit; PSS ve TLS 1.2'de PKCS#1 v1.5), ECDSA P-256 /
P-384, Ed25519. Diğer türler (DSA, Ed448, P-521, küçük RSA) AÇIK hatayla reddedilir.

Güvenlik notları (ayrıntı için security/mtls.py ve rapor):
  * Dosya baytları ve parola yalnızca yükleme süresince bellekte tutulur; ayrıştırma
    sonrası değiştirilebilir tamponlar sıfırlanır. Nesne yalnızca ayrıştırılmış anahtar
    nesnesini ve sertifika DER'lerini saklar (PEM metni / parola SAKLANMAZ).
    Python'da anahtar belleğini kesin silmek mümkün değildir: ``close()`` referansı
    bırakır, OpenSSL nesne serbest kalınca anahtar malzemesini temizler.
  * Anahtar dosyası grup/diğer tarafından okunabiliyorsa (POSIX, ``mode & 0o077``)
    uyarı loglanır (yükleme yine de yapılır; yalnızca uyarı).
  * Nesne pickle/kopyalanamaz ve repr'ı anahtar bilgisi içermez.
"""
from __future__ import annotations

import hashlib
import logging
import os
import stat
import threading
from typing import Iterable, Optional

logger = logging.getLogger("fasthttpc.security.client_cert")

# SignatureScheme sabitleri (RFC 8446 §4.2.3)
RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512 = 0x0401, 0x0501, 0x0601
ECDSA_P256_SHA256, ECDSA_P384_SHA384, ECDSA_P521_SHA512 = 0x0403, 0x0503, 0x0603
RSA_PSS_RSAE_SHA256, RSA_PSS_RSAE_SHA384, RSA_PSS_RSAE_SHA512 = 0x0804, 0x0805, 0x0806
ED25519 = 0x0807

_HASH_OF = {
    RSA_PKCS1_SHA256: "SHA256", RSA_PKCS1_SHA384: "SHA384", RSA_PKCS1_SHA512: "SHA512",
    ECDSA_P256_SHA256: "SHA256", ECDSA_P384_SHA384: "SHA384", ECDSA_P521_SHA512: "SHA512",
    RSA_PSS_RSAE_SHA256: "SHA256", RSA_PSS_RSAE_SHA384: "SHA384", RSA_PSS_RSAE_SHA512: "SHA512",
}

MIN_RSA_BITS = 2048


class ClientCertError(ValueError):
    """İstemci sertifikası/anahtarı yüklenemedi (mesaj anahtar/parola içermez)."""


def _zero(buf) -> None:
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


def _read_secret_file(path, secret: bool = True) -> bytearray:
    """Dosyayı okur; izinleri aynı fd üzerinden denetler (TOCTOU yok). Sıfırlanabilir tampon döner."""
    p = os.fspath(path)
    try:
        with open(p, "rb") as f:
            try:
                mode = os.fstat(f.fileno()).st_mode
            except OSError:
                mode = None
            if secret and mode is not None and os.name == "posix" and (mode & 0o077):
                logger.warning(
                    "İstemci anahtar/sertifika dosyasının izinleri geniş (%s, mod %s): "
                    "yalnızca sahibi okuyabilmeli (chmod 600).",
                    p, oct(stat.S_IMODE(mode)))
            data = bytearray(f.read())
    except OSError as e:
        raise ClientCertError(f"İstemci sertifika dosyası okunamadı: {p}: {e.strerror or e}") from e
    return data


def _pw(password) -> "Optional[bytearray]":
    if password is None:
        return None
    if isinstance(password, str):
        return bytearray(password.encode("utf-8"))
    if isinstance(password, (bytes, bytearray)):
        return bytearray(password)
    raise ClientCertError("Anahtar parolası str veya bytes olmalı.")


class ClientCert:
    """Yüklenmiş istemci kimliği: sertifika zinciri (leaf ilk) + özel anahtar."""

    __slots__ = ("_chain", "_key", "_kind", "_curve", "_lock", "identity",
                 "_issuer_dns", "_chain_sigs")

    def __init__(self, chain_der: "list[bytes]", private_key, *, _validated: bool = False):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

        if not chain_der:
            raise ClientCertError("İstemci sertifika zinciri boş.")
        leaf = x509.load_der_x509_certificate(chain_der[0])
        if isinstance(private_key, rsa.RSAPrivateKey):
            if private_key.key_size < MIN_RSA_BITS:
                raise ClientCertError(
                    f"RSA istemci anahtarı çok kısa ({private_key.key_size} bit); en az {MIN_RSA_BITS} gerekir.")
            kind, curve = "rsa", None
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            if private_key.curve.name not in ("secp256r1", "secp384r1"):
                raise ClientCertError(
                    f"Desteklenmeyen EC eğrisi {private_key.curve.name!r}; yalnızca P-256 ve P-384.")
            kind, curve = "ec", private_key.curve.name
        elif isinstance(private_key, ed25519.Ed25519PrivateKey):
            kind, curve = "ed25519", None
        else:
            raise ClientCertError(
                f"Desteklenmeyen istemci anahtar türü {type(private_key).__name__}; "
                f"RSA, ECDSA (P-256/P-384) veya Ed25519 olmalı.")
        spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        if private_key.public_key().public_bytes(*spki) != leaf.public_key().public_bytes(*spki):
            raise ClientCertError("Özel anahtar, istemci sertifikasının (leaf) açık anahtarıyla eşleşmiyor.")

        self._chain = [bytes(d) for d in chain_der]
        self._key = private_key
        self._kind = kind
        self._curve = curve
        self._lock = threading.Lock()
        self.identity = "cert:" + hashlib.sha256(self._chain[0]).hexdigest()
        # CA filtresi için: zincirdeki her sertifikanın issuer ve subject DN'leri (DER)
        dns: list = []
        sigs: list = []
        for i, der in enumerate(self._chain):
            c = x509.load_der_x509_certificate(der)
            dns.append(c.issuer.public_bytes())
            dns.append(c.subject.public_bytes())
            if c.issuer != c.subject:           # kendinden imzalı kök için imza şeması sınırı uygulanmaz
                sigs.append(_cert_sig_schemes(c))
        self._issuer_dns = frozenset(dns)
        self._chain_sigs = sigs
        try:
            import datetime
            now = datetime.datetime.now(datetime.timezone.utc)
            nb = getattr(leaf, "not_valid_after_utc", None) or leaf.not_valid_after.replace(
                tzinfo=datetime.timezone.utc)
            if nb < now:
                logger.warning("İstemci sertifikasının süresi dolmuş (%s).", nb.isoformat())
        except Exception:  # pragma: no cover - yalnızca bilgi amaçlı
            pass

    # ------------------------------------------------------------ yükleyiciler
    @classmethod
    def from_pem(cls, cert, key=None, password=None) -> "ClientCert":
        """``cert`` PEM yolu (+ isteğe bağlı ayrı ``key`` yolu ve ``password``).

        key verilmezse anahtar ``cert`` dosyasının içinde aranır. Zincirde leaf, anahtarla
        eşleşen sertifika olarak otomatik seçilir (sıra önemli değil); kalanlar verilen sırayla
        zincir olarak gönderilir.
        """
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        cert_data = _read_secret_file(cert, secret=key is None)   # ayrı key varsa sertifika gizli değil
        key_data = _read_secret_file(key) if key is not None else None
        pw = _pw(password)
        try:
            try:
                certs = x509.load_pem_x509_certificates(bytes(cert_data))
            except ValueError as e:
                raise ClientCertError(f"PEM sertifika okunamadı ({os.fspath(cert)}): geçerli CERTIFICATE bulunamadı.") from e
            src = key_data if key_data is not None else cert_data
            if b"PRIVATE KEY" not in bytes(src):
                raise ClientCertError(
                    "PEM içinde özel anahtar bulunamadı; cert=(cert.pem, key.pem) biçimini kullanın.")
            try:
                priv = load_pem_private_key(bytes(src), bytes(pw) if pw is not None else None)
            except TypeError as e:
                raise ClientCertError("Özel anahtar şifreli ama parola verilmedi.") from e
            except ValueError as e:
                raise ClientCertError(
                    "Özel anahtar çözülemedi (parola yanlış veya anahtar bozuk/desteklenmeyen biçimde).") from e
            except Exception as e:  # UnsupportedAlgorithm vb.
                raise ClientCertError(f"Özel anahtar çözülemedi: {type(e).__name__}") from e
            return cls._from_objects(certs, priv)
        finally:
            _zero(cert_data)
            _zero(key_data)
            _zero(pw)

    @classmethod
    def from_pkcs12(cls, path, password=None) -> "ClientCert":
        """PKCS#12 (.p12/.pfx) dosyasından yükler (anahtar + leaf + varsa ara sertifikalar)."""
        from cryptography.hazmat.primitives.serialization import pkcs12

        data = _read_secret_file(path)
        pw = _pw(password)
        try:
            try:
                key, cert, extra = pkcs12.load_key_and_certificates(
                    bytes(data), bytes(pw) if pw is not None else None)
            except ValueError as e:
                raise ClientCertError("PKCS#12 çözülemedi (parola yanlış veya dosya bozuk).") from e
            except Exception as e:
                raise ClientCertError(f"PKCS#12 çözülemedi: {type(e).__name__}") from e
            if key is None or cert is None:
                raise ClientCertError("PKCS#12 dosyası anahtar ve sertifika içermiyor.")
            return cls._from_objects([cert, *(extra or [])], key)
        finally:
            _zero(data)
            _zero(pw)

    @classmethod
    def _from_objects(cls, certs, priv) -> "ClientCert":
        from cryptography.hazmat.primitives import serialization
        spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        want = priv.public_key().public_bytes(*spki)
        leaf = next((c for c in certs if c.public_key().public_bytes(*spki) == want), None)
        if leaf is None:
            raise ClientCertError("Özel anahtarla eşleşen sertifika bulunamadı.")
        ders = [leaf.public_bytes(serialization.Encoding.DER)]
        ders += [c.public_bytes(serialization.Encoding.DER) for c in certs if c is not leaf]
        return cls(ders, priv)

    @classmethod
    def coerce(cls, value) -> "Optional[ClientCert]":
        """``Session(cert=...)`` değerini ClientCert'e çevirir (None -> None)."""
        if value is None or isinstance(value, ClientCert):
            return value
        if isinstance(value, (str, bytes, os.PathLike)):
            return cls.from_pem(value)
        if isinstance(value, (tuple, list)) and 1 <= len(value) <= 3:
            return cls.from_pem(*value)
        raise ClientCertError(
            "cert= bir yol, (cert, key), (cert, key, parola) veya ClientCert olmalı.")

    # ----------------------------------------------------------------- sorgular
    @property
    def chain_der(self) -> "list[bytes]":
        return list(self._chain)

    @property
    def closed(self) -> bool:
        return self._key is None

    def matches_cas(self, cas: "Iterable[bytes]") -> bool:
        """certificate_authorities listesi (DER DN'ler) zincirle örtüşüyor mu?  Boş liste = kısıt yok."""
        cas = list(cas)
        return not cas or any(dn in self._issuer_dns for dn in cas)

    def chain_allows(self, cert_sigalgs: "Optional[Iterable[int]]") -> bool:
        """signature_algorithms_cert verilmişse zincirdeki imzaların hepsi listede olmalı."""
        if not cert_sigalgs:
            return True
        allowed = set(cert_sigalgs)
        return all((not s) or (s & allowed) for s in self._chain_sigs)

    def schemes(self, tls12: bool = False) -> "list[int]":
        """Anahtarın üretebildiği SignatureScheme'ler (tercih sırasıyla)."""
        if self._kind == "rsa":
            s = [RSA_PSS_RSAE_SHA256, RSA_PSS_RSAE_SHA384, RSA_PSS_RSAE_SHA512]
            if tls12:   # PKCS#1 v1.5 yalnızca TLS 1.2'de geçerli (TLS 1.3 CertificateVerify'da YASAK)
                s += [RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512]
            return s
        if self._kind == "ec":
            own = ECDSA_P256_SHA256 if self._curve == "secp256r1" else ECDSA_P384_SHA384
            if not tls12:      # TLS 1.3'te şema eğriyi bağlar
                return [own]
            return [own] + [x for x in (ECDSA_P256_SHA256, ECDSA_P384_SHA384, ECDSA_P521_SHA512) if x != own]
        return [ED25519]

    @property
    def cert_type_12(self) -> int:
        """TLS 1.2 ClientCertificateType: rsa_sign=1, ecdsa_sign=64 (Ed25519 de ecdsa_sign, RFC 8422 §5.5)."""
        return 1 if self._kind == "rsa" else 64

    @property
    def key_kind(self) -> str:
        return self._kind

    # ------------------------------------------------------------------- imza
    def sign(self, scheme: int, data: bytes, *, tls12: bool = False) -> bytes:
        """``data``'yı ``scheme`` ile imzalar. Anahtarın desteklemediği şema -> ClientCertError."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding

        key = self._key
        if key is None:
            raise ClientCertError("İstemci sertifikası kapatılmış (close()).")
        if scheme not in self.schemes(tls12):
            raise ClientCertError(f"Anahtar 0x{scheme:04x} imza şemasını desteklemiyor.")
        if scheme == ED25519:
            return key.sign(data)
        h = getattr(hashes, _HASH_OF[scheme])()
        if scheme in (ECDSA_P256_SHA256, ECDSA_P384_SHA384, ECDSA_P521_SHA512):
            return key.sign(data, ec.ECDSA(h))
        if scheme in (RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512):
            return key.sign(data, padding.PKCS1v15(), h)
        return key.sign(data, padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h)

    # ---------------------------------------------------------------- yaşam döngüsü
    def close(self) -> None:
        """Özel anahtar referansını bırakır (ardından sign() başarısız olur)."""
        with self._lock:
            self._key = None

    def __repr__(self) -> str:
        return f"<ClientCert {self._kind} {self.identity[:17]}…{' closed' if self._key is None else ''}>"

    def __reduce__(self):
        raise TypeError("ClientCert pickle/kopyalanamaz (özel anahtar sızıntısını önlemek için).")

    def __copy__(self):
        raise TypeError("ClientCert kopyalanamaz.")

    def __deepcopy__(self, memo):
        raise TypeError("ClientCert kopyalanamaz.")


def _cert_sig_schemes(cert) -> frozenset:
    """Sertifikanın kendi imzasına karşılık gelen SignatureScheme kümesi (boş = bilinmiyor)."""
    from cryptography.x509 import oid

    try:
        sa = cert.signature_algorithm_oid
        h = cert.signature_hash_algorithm
    except Exception:
        return frozenset()
    if sa == oid.SignatureAlgorithmOID.ED25519:
        return frozenset({ED25519})
    if h is None:
        return frozenset()
    name = h.name
    ecdsa = {"sha256": ECDSA_P256_SHA256, "sha384": ECDSA_P384_SHA384, "sha512": ECDSA_P521_SHA512,
             "sha1": 0x0203}
    pkcs1 = {"sha256": RSA_PKCS1_SHA256, "sha384": RSA_PKCS1_SHA384, "sha512": RSA_PKCS1_SHA512,
             "sha1": 0x0201}
    pss = {"sha256": (RSA_PSS_RSAE_SHA256, 0x0809), "sha384": (RSA_PSS_RSAE_SHA384, 0x080A),
           "sha512": (RSA_PSS_RSAE_SHA512, 0x080B)}
    if sa == oid.SignatureAlgorithmOID.RSASSA_PSS:
        return frozenset(pss.get(name, ()))
    if name in ecdsa and sa.dotted_string.startswith("1.2.840.10045.4"):
        return frozenset({ecdsa[name]})
    if name in pkcs1 and sa.dotted_string.startswith("1.2.840.113549.1.1"):
        return frozenset({pkcs1[name]})
    return frozenset()
