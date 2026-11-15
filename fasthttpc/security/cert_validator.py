"""
TLS 1.3 sunucu sertifikası doğrulama.

Bu modül, tls_adapter.py tarafından alınan ham Certificate handshake
mesajını parse eder ve sertifika zincirini + hostname eşleşmesini
`cryptography` kütüphanesinin denetlenmiş (Rust tabanlı) x509.verification
API'si ile doğrular. Güven kökü olarak `certifi` paketinin CA bundle'ı
kullanılır (aynı sistem requests/httpx/curl'ün kullandığı kaynak).

Pure-Python imza doğrulama / ASN.1 parser YAZILMAMIŞTIR — bu kasıtlıdır.
Sertifika doğrulama, hata payı en düşük olması gereken güvenlik
kritik bir işlemdir; bu yüzden mevcut, denetlenmiş kütüphaneye devredilir.
"""
from __future__ import annotations

import os
import struct
import functools
import datetime
import ipaddress
import warnings

# cryptography import'undan ÖNCE (bkz. __init__.py'deki açıklama).
os.environ.setdefault("CRYPTOGRAPHY_OPENSSL_NO_LEGACY", "1")

try:
    import certifi
    from cryptography import x509
    from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
    _CERT_VALIDATION_AVAILABLE = True
except ImportError as _e:
    _CERT_VALIDATION_AVAILABLE = False
    _IMPORT_ERROR = _e


class CertificateValidationError(Exception):
    """Sunucu sertifikası doğrulanamadığında fırlatılır (MITM şüphesi dahil)."""
    pass


def decompress_certificate_message(hs_payload: bytes) -> bytes:
    """
    TLS 1.3 CompressedCertificate handshake mesajını (RFC 8879, hs_type=25) açar
    ve normal bir Certificate handshake mesajı (hs_type=11) formatında döner.

    Format (hs_type/hs_len 4 byte'lık header'dan sonraki body, RFC 8879 §4):
        algorithm                      (2 byte)  — 1=zlib, 2=brotli, 3=zstd
        uncompressed_length             (3 byte)
        compressed_certificate_message  (3 byte uzunluk prefix'i + o kadar byte veri)
    """
    body = hs_payload[4:]
    if len(body) < 8:
        raise CertificateValidationError("CompressedCertificate mesajı çok kısa.")

    algorithm = struct.unpack("!H", body[0:2])[0]
    uncompressed_length = struct.unpack("!I", b"\x00" + body[2:5])[0]

    # compressed_certificate_message alanının kendi 3-byte uzunluk prefix'i var (RFC 8879 §4,
    # opaque<1..2^24-1>). Bu prefix'i sıkıştırılmış veriye dahil etmemek gerekiyor —
    # aksi halde decoder'lar (özellikle brotli) bozuk stream görüp hata verir.
    comp_len = struct.unpack("!I", b"\x00" + body[5:8])[0]
    compressed_data = body[8:8 + comp_len]

    if len(compressed_data) != comp_len:
        raise CertificateValidationError(
            f"CompressedCertificate mesajı kesilmiş (beklenen={comp_len} byte, "
            f"alınan={len(compressed_data)} byte)."
        )

    if algorithm == 1:  # zlib
        import zlib
        try:
            decompressed = zlib.decompress(compressed_data)
        except zlib.error as e:
            raise CertificateValidationError(f"zlib ile sertifika açılamadı: {e}") from e
    elif algorithm == 2:  # brotli
        try:
            import brotli
        except ImportError as e:
            raise CertificateValidationError(
                "Sunucu brotli-sıkıştırılmış sertifika gönderdi ancak 'brotli' paketi "
                "kurulu değil. Kurmak için: pip install brotli"
            ) from e
        try:
            decompressed = brotli.decompress(compressed_data)
        except Exception as e:
            raise CertificateValidationError(f"brotli ile sertifika açılamadı: {e}") from e
    else:
        raise CertificateValidationError(
            f"Desteklenmeyen sertifika sıkıştırma algoritması: {algorithm} "
            f"(sadece zlib=1 ve brotli=2 destekleniyor)."
        )

    if len(decompressed) != uncompressed_length:
        raise CertificateValidationError(
            f"Açılan sertifika boyutu beklenenle uyuşmuyor "
            f"(beklenen={uncompressed_length}, alınan={len(decompressed)}) — "
            f"veri bozulmuş veya değiştirilmiş olabilir."
        )

    # Normal bir Certificate handshake mesajı gibi paketle: hs_type=11 + 3-byte uzunluk + body
    return b"\x0b" + struct.pack("!I", len(decompressed))[1:] + decompressed


def _parse_tls13_certificate_message(hs_payload: bytes) -> list[bytes]:
    """
    TLS 1.3 Certificate handshake mesajını (RFC 8446 §4.4.2) parse eder.
    hs_payload: hs_type (1 byte) + hs_len (3 byte) dahil ham handshake mesajı.
    Döner: DER-encoded sertifikaların listesi (ilk eleman leaf/end-entity sertifikadır).
    """
    body = hs_payload[4:]  # hs_type + hs_len'i atla

    if len(body) < 1:
        raise CertificateValidationError("Certificate mesajı boş.")

    cert_request_ctx_len = body[0]
    if cert_request_ctx_len != 0:
        # RFC 8446 §4.4.2: sunucu kimlik doğrulamasında certificate_request_context BOŞ olmalı.
        raise CertificateValidationError("Certificate mesajında boş olmayan certificate_request_context.")
    offset = 1 + cert_request_ctx_len

    if len(body) < offset + 3:
        raise CertificateValidationError("Certificate mesajı bozuk (cert_list_len okunamadı).")

    cert_list_len = struct.unpack("!I", b"\x00" + body[offset:offset + 3])[0]
    offset += 3
    cert_list_end = offset + cert_list_len
    if cert_list_end != len(body):
        raise CertificateValidationError("Certificate listesi uzunluğu mesajla uyuşmuyor.")

    certs: list[bytes] = []
    while offset < cert_list_end:
        if offset + 3 > len(body):
            raise CertificateValidationError("Certificate listesi bozuk.")
        cert_len = struct.unpack("!I", b"\x00" + body[offset:offset + 3])[0]
        offset += 3
        cert_der = body[offset:offset + cert_len]
        if len(cert_der) != cert_len:
            raise CertificateValidationError("Certificate uzunluğu uyuşmuyor (kesilmiş mesaj).")
        certs.append(cert_der)
        offset += cert_len

        if offset + 2 > len(body):
            raise CertificateValidationError("Certificate extensions uzunluğu okunamadı.")
        ext_len = struct.unpack("!H", body[offset:offset + 2])[0]
        offset += 2 + ext_len
        if offset > cert_list_end:
            raise CertificateValidationError("Certificate extensions alanı listenin dışına taşıyor.")

    if not certs:
        raise CertificateValidationError("Sunucu hiç sertifika göndermedi.")

    return certs


# ---------------------------------------------------------------------------
# Güven deposu (trust store) önbelleği
#
# certifi + sistem bundle'ı (~200 kök CA) okumak, PEM'i parse etmek ve Store
# kurmak handshake başına onlarca ms tutuyordu. Store değiştirilemez (immutable)
# ve thread-safe olduğundan modül düzeyinde bir kez kurulup paylaşılabilir.
# Önbellek anahtarı (dosya yolu, mtime_ns, boyut) üçlüleridir: aynı yoldaki
# dosya değişirse (ör. testlerde yeniden yazılan ca.pem) yeniden yüklenir.
# ---------------------------------------------------------------------------

_SYSTEM_CA_PATHS = ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt")


def _default_ca_paths() -> tuple:
    """certifi bundle'ı + bulunan ilk sistem bundle'ı (curl/requests benzeri birleşim)."""
    paths = [certifi.where()]
    for sys_ca_path in _SYSTEM_CA_PATHS:
        if os.path.isfile(sys_ca_path):
            paths.append(sys_ca_path)
            break
    return tuple(paths)


def _file_fingerprint(path: str) -> tuple:
    try:
        st = os.stat(path)
        return (os.path.abspath(path), st.st_mtime_ns, st.st_size)
    except OSError:
        # Dosya yoksa da anahtar üret; yükleme sırasında anlamlı hata fırlatılır.
        return (os.path.abspath(path), None, None)


@functools.lru_cache(maxsize=16)
def _build_store(file_keys: tuple):
    """(yol, mtime, boyut) üçlülerinden Store kurar. lru_cache kendi içinde thread-safe'tir;
    yarış durumunda en kötü ihtimalle aynı Store iki kez kurulur (doğruluk etkilenmez)."""
    pem = b""
    for path, _mtime, _size in file_keys:
        with open(path, "rb") as f:
            pem += f.read() + b"\n"
    with warnings.catch_warnings():
        # Bazı eski (ama hâlâ geçerli ve yaygın kullanılan) kök CA sertifikaları
        # RFC 5280'in serial-number pozitiflik kuralına tam uymuyor; bu sadece
        # bir uyarı, güvenlik açığı değil — CA'nın kendisi hâlâ geçerli.
        warnings.simplefilter("ignore")
        certs = x509.load_pem_x509_certificates(pem)
    return Store(certs)


def load_trust_store(ca_path: str | None = None):
    """Güven deposunu (önbellekli) döner.

    ca_path=None -> certifi + sistem CA bundle'ı.
    ca_path="ca.pem" -> YALNIZCA o PEM dosyası (requests'in verify="ca.pem" semantiği).
    """
    if not _CERT_VALIDATION_AVAILABLE:
        raise CertificateValidationError(
            f"Sertifika doğrulama için gerekli kütüphaneler eksik "
            f"('cryptography' ve 'certifi' paketleri gerekli): {_IMPORT_ERROR}"
        )
    paths = _default_ca_paths() if ca_path is None else (os.fspath(ca_path),)
    try:
        return _build_store(tuple(_file_fingerprint(p) for p in paths))
    except Exception as e:
        raise CertificateValidationError(f"CA bundle yüklenemedi ({', '.join(paths)}): {e}") from e


# faz5 dalıyla uyumluluk için takma ad.
_load_trust_store = load_trust_store


def clear_trust_store_cache() -> None:
    """Önbelleğe alınmış tüm güven depolarını atar (test/benchmark için)."""
    _build_store.cache_clear()


def _validity_error(leaf) -> str | None:
    now = datetime.datetime.now(datetime.timezone.utc)
    if now < leaf.not_valid_before_utc:
        return f"Sertifika henüz geçerli değil (not_valid_before={leaf.not_valid_before_utc})."
    if now > leaf.not_valid_after_utc:
        return f"Sertifikanın süresi dolmuş (not_valid_after={leaf.not_valid_after_utc})."
    return None


def _subject_for(hostname: str):
    """Doğrulanacak sunucu kimliği: IP literal'i ise ``IPAddress``, değilse ``DNSName``.

    RFC 9525 §6.2 / RFC 5280 §4.2.1.6: IP adresiyle bağlanılan sunucu, sertifikanın
    iPAddress SAN'ıyla eşleşmelidir. IP'yi DNSName olarak doğrulamak hem doğru IP SAN'lı
    sertifikaları reddeder hem de dNSName="1.2.3.4" içeren (kurallara aykırı) bir
    sertifikayı kabul ederdi.
    """
    host = hostname[1:-1] if hostname.startswith("[") and hostname.endswith("]") else hostname
    try:
        return x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        return x509.DNSName(hostname)


def validate_server_certificate(hs_payload: bytes, hostname: str, ca_path: str | None = None):
    """
    Sunucudan gelen TLS 1.3 Certificate mesajını doğrular:
      1. Zincir, güvenilir bir CA'ya (certifi + sistem bundle'ı, ya da ca_path) kadar
         kurulabiliyor mu?
      2. Sertifika süresi geçerli mi (expired/not-yet-valid değil mi)?
      3. Hostname, sertifikanın SAN alanıyla eşleşiyor mu?

    Süre kontrolünü (2) zincirdeki TÜM sertifikalar için cryptography'nin
    verifier'ı yapar; elle yapılan leaf kontrolü yalnızca doğrulama başarısız
    olduğunda daha açıklayıcı bir hata mesajı üretmek için kullanılır.

    Başarısız olursa CertificateValidationError fırlatır — bu durumda
    çağıran taraf bağlantıyı DERHAL kapatmalı, hiçbir veri alışverişine
    devam etmemelidir.

    Döner: doğrulanmış leaf sertifika (cryptography x509.Certificate objesi).
    """
    if not _CERT_VALIDATION_AVAILABLE:
        raise CertificateValidationError(
            f"Sertifika doğrulama için gerekli kütüphaneler eksik "
            f"('cryptography' ve 'certifi' paketleri gerekli): {_IMPORT_ERROR}"
        )

    der_certs = _parse_tls13_certificate_message(hs_payload)

    try:
        chain = [x509.load_der_x509_certificate(der) for der in der_certs]
    except Exception as e:
        raise CertificateValidationError(f"Sertifika parse edilemedi (bozuk DER): {e}") from e

    leaf = chain[0]
    intermediates = chain[1:]

    trust_store = load_trust_store(ca_path)

    try:
        builder = PolicyBuilder().store(trust_store).max_chain_depth(32)
        verifier = builder.build_server_verifier(_subject_for(hostname))
        verifier.verify(leaf, intermediates)
    except VerificationError as e:
        validity = _validity_error(leaf)
        if validity:
            raise CertificateValidationError(validity) from e
        raise CertificateValidationError(
            f"Sertifika zinciri '{hostname}' için doğrulanamadı (güvenilmeyen CA, "
            f"hostname uyuşmazlığı veya süresi dolmuş ara sertifika olabilir): {e}"
        ) from e
    except Exception as e:
        raise CertificateValidationError(f"Sertifika doğrulama sırasında beklenmeyen hata: {e}") from e

    return leaf


# ---------------------------------------------------------------------------
# CertificateVerify doğrulaması (RFC 8446 §4.4.3)
#
# TLS 1.3'te sunucunun sertifikadaki özel anahtara SAHİP OLDUĞUNUN TEK KANITI
# bu imzadır. Sertifika zincirini doğrulamak tek başına YETMEZ: sertifika
# herkese açık veridir, araya giren biri gerçek sunucunun sertifikasını aynen
# iletip kendi key_share'ini gönderebilir. CertificateVerify kontrol edilmezse
# istemci saldırganla anahtar türetir ve bunu asla fark etmez.
# ---------------------------------------------------------------------------

_CV_CONTEXT_STRING = b"TLS 1.3, server CertificateVerify"
_CV_PREFIX = b"\x20" * 64

# SignatureScheme -> (tip, hash) eşlemesi. RFC 8446 §4.2.3.
# TLS 1.3 CertificateVerify'da rsa_pkcs1_* şemaları YASAKTIR (yalnızca
# sertifika imzalarında geçerlidir); bu yüzden kasıtlı olarak listede yok.
_SIG_SCHEMES = {
    0x0403: ("ecdsa", "sha256"),
    0x0503: ("ecdsa", "sha384"),
    0x0603: ("ecdsa", "sha512"),
    0x0804: ("rsa_pss_rsae", "sha256"),
    0x0805: ("rsa_pss_rsae", "sha384"),
    0x0806: ("rsa_pss_rsae", "sha512"),
    0x0809: ("rsa_pss_pss", "sha256"),
    0x080A: ("rsa_pss_pss", "sha384"),
    0x080B: ("rsa_pss_pss", "sha512"),
    0x0807: ("ed25519", None),
    0x0808: ("ed448", None),
}


_ECDSA_SCHEME_CURVE = {0x0403: "secp256r1", 0x0503: "secp384r1", 0x0603: "secp521r1"}


def build_certificate_verify_content(transcript_hash: bytes) -> bytes:
    """RFC 8446 §4.4.3'teki imzalanan içeriği kurar.

    64 byte 0x20 + context string + 0x00 + Transcript-Hash(... Certificate'a kadar)
    """
    return _CV_PREFIX + _CV_CONTEXT_STRING + b"\x00" + transcript_hash


def verify_certificate_verify(
    hs_payload: bytes,
    leaf_cert,
    transcript_hash: bytes,
    offered_schemes=None,
) -> int:
    """Sunucunun CertificateVerify mesajını doğrular.

    Args:
        hs_payload:      Ham handshake mesajı (hs_type=15 + 3 byte uzunluk dahil).
        leaf_cert:       Doğrulanmış leaf sertifika (x509.Certificate).
        transcript_hash: Certificate mesajı DAHİL, CertificateVerify HARİÇ
                         handshake transcript'inin hash'i.
        offered_schemes: ClientHello.signature_algorithms'ta teklif ettiğimiz şemalar;
                         verilirse dışındaki bir şema reddedilir (RFC 8446 §4.4.3).

    Returns:
        Kullanılan SignatureScheme değeri.

    Raises:
        CertificateValidationError: İmza geçersizse veya şema desteklenmiyorsa.
    """
    if not _CERT_VALIDATION_AVAILABLE:
        raise CertificateValidationError(
            "CertificateVerify doğrulaması için 'cryptography' paketi gerekli."
        )

    from cryptography.hazmat.primitives import hashes as _h
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, ed25519, ed448
    from cryptography.exceptions import InvalidSignature

    body = hs_payload[4:]
    if len(body) < 4:
        raise CertificateValidationError("CertificateVerify mesajı çok kısa.")

    scheme = struct.unpack("!H", body[0:2])[0]
    sig_len = struct.unpack("!H", body[2:4])[0]
    signature = body[4:4 + sig_len]
    if len(signature) != sig_len:
        raise CertificateValidationError(
            f"CertificateVerify imzası kesilmiş (beklenen={sig_len}, alınan={len(signature)})."
        )

    if scheme not in _SIG_SCHEMES:
        raise CertificateValidationError(
            f"Desteklenmeyen veya TLS 1.3'te yasak SignatureScheme: 0x{scheme:04x}. "
            f"(rsa_pkcs1_* şemaları TLS 1.3 CertificateVerify'da kullanılamaz.)"
        )

    if offered_schemes is not None and scheme not in {a for a in offered_schemes if isinstance(a, int)}:
        raise CertificateValidationError(
            f"Sunucu CertificateVerify'da teklif etmediğimiz SignatureScheme 0x{scheme:04x} kullandı "
            f"(RFC 8446 §4.4.3)."
        )

    kind, hash_name = _SIG_SCHEMES[scheme]
    content = build_certificate_verify_content(transcript_hash)
    pubkey = leaf_cert.public_key()

    try:
        if kind == "ecdsa":
            if not isinstance(pubkey, ec.EllipticCurvePublicKey):
                raise CertificateValidationError(
                    f"Sunucu ECDSA şeması (0x{scheme:04x}) bildirdi ama sertifikadaki "
                    f"anahtar EC değil ({type(pubkey).__name__})."
                )
            # RFC 8446 §4.2.3: TLS 1.3'te ECDSA şeması eğriye bağlıdır.
            want_curve = _ECDSA_SCHEME_CURVE[scheme]
            if pubkey.curve.name != want_curve:
                raise CertificateValidationError(
                    f"ECDSA şeması 0x{scheme:04x} {want_curve} eğrisi gerektirir ama sertifika anahtarı "
                    f"{pubkey.curve.name} (RFC 8446 §4.2.3)."
                )
            pubkey.verify(signature, content, ec.ECDSA(getattr(_h, hash_name.upper())()))

        elif kind in ("rsa_pss_rsae", "rsa_pss_pss"):
            if not isinstance(pubkey, rsa.RSAPublicKey):
                raise CertificateValidationError(
                    f"Sunucu RSA şeması (0x{scheme:04x}) bildirdi ama sertifikadaki "
                    f"anahtar RSA değil ({type(pubkey).__name__})."
                )
            algo = getattr(_h, hash_name.upper())()
            pubkey.verify(
                signature,
                content,
                padding.PSS(mgf=padding.MGF1(algo), salt_length=algo.digest_size),
                algo,
            )

        elif kind == "ed25519":
            if not isinstance(pubkey, ed25519.Ed25519PublicKey):
                raise CertificateValidationError("Ed25519 şeması bildirildi ama anahtar Ed25519 değil.")
            pubkey.verify(signature, content)

        elif kind == "ed448":
            if not isinstance(pubkey, ed448.Ed448PublicKey):
                raise CertificateValidationError("Ed448 şeması bildirildi ama anahtar Ed448 değil.")
            pubkey.verify(signature, content)

    except InvalidSignature as e:
        raise CertificateValidationError(
            "CertificateVerify imzası GEÇERSİZ — sunucu sertifikadaki özel anahtara "
            "sahip olduğunu kanıtlayamadı. Bu güçlü bir MITM göstergesidir; "
            "bağlantı reddedildi."
        ) from e
    except CertificateValidationError:
        raise
    except Exception as e:
        raise CertificateValidationError(
            f"CertificateVerify doğrulanırken beklenmeyen hata: {type(e).__name__}: {e}"
        ) from e

    return scheme
