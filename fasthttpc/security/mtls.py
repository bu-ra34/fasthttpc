"""İstemci kimlik doğrulaması (mTLS) için SAF protokol fonksiyonları.

Senkron (security/tls_adapter.py), async sans-IO çekirdek (tls13/connection.py) ve
TLS 1.2 çekirdeği (security/tls12.py) AYNI fonksiyonları kullanır; soket/durum yok.

TLS 1.3 (RFC 8446):  §4.3.2 CertificateRequest, §4.4.2 Certificate, §4.4.3 CertificateVerify.
TLS 1.2 (RFC 5246):  §7.4.4 CertificateRequest, §7.4.6 Certificate, §7.4.8 CertificateVerify.

Kararlar:
  * Uygun sertifika/şema yoksa (CA uyuşmuyor, imza şeması kesişimi boş, sertifika türü
    uymuyor, istemcide sertifika yok) BOŞ Certificate gönderilir ve CertificateVerify
    GÖNDERİLMEZ; sunucu devam edip etmeyeceğine kendisi karar verir (RFC 8446 §4.4.2,
    RFC 5246 §7.4.6). Sunucu sertifikası doğrulaması bundan bağımsız, aynen zorunludur.
  * TLS 1.3'te PKCS#1 v1.5 şemaları asla seçilmez (§4.2.3 / §4.4.3).
  * Hata: ``MtlsProtocolError.alert`` RFC alert numarasını taşır.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from .client_cert import ClientCert, ClientCertError  # noqa: F401

AL_UNEXPECTED_MESSAGE = 10
AL_ILLEGAL_PARAMETER = 47
AL_DECODE_ERROR = 50
AL_MISSING_EXTENSION = 109

HS_CERTIFICATE = 11
HS_CERTIFICATE_REQUEST = 13
HS_CERTIFICATE_VERIFY = 15

EXT_SIGNATURE_ALGORITHMS = 13
EXT_CERTIFICATE_AUTHORITIES = 47
EXT_SIGNATURE_ALGORITHMS_CERT = 50

#: RFC 8446 §4.4.3: CertificateVerify imza bağlamı (istemci)
CLIENT_CV_CONTEXT = b"TLS 1.3, client CertificateVerify"


class MtlsProtocolError(ValueError):
    def __init__(self, msg: str, alert: int):
        super().__init__(msg)
        self.alert = alert


def _decode(msg: str) -> MtlsProtocolError:
    return MtlsProtocolError(f"decode_error: {msg}", AL_DECODE_ERROR)


def _illegal(msg: str) -> MtlsProtocolError:
    return MtlsProtocolError(f"illegal_parameter: {msg}", AL_ILLEGAL_PARAMETER)


def _check_header(msg: bytes, name: str) -> memoryview:
    if len(msg) < 4 or msg[0] != HS_CERTIFICATE_REQUEST:
        raise _decode(f"{name} başlığı bozuk.")
    if int.from_bytes(msg[1:4], "big") != len(msg) - 4:
        raise _decode(f"{name} uzunluğu mesajla uyuşmuyor.")
    return memoryview(msg)[4:]


def _u16_list(data: bytes, what: str) -> "list[int]":
    if len(data) < 2 or len(data) % 2:
        raise _decode(f"{what} uzunluğu geçersiz.")
    return [struct.unpack_from("!H", data, i)[0] for i in range(0, len(data), 2)]


def _dn_list(data: bytes, what: str) -> "list[bytes]":
    out, cur = [], 0
    while cur < len(data):
        if cur + 2 > len(data):
            raise _decode(f"{what} DN başlığı kesik.")
        n = struct.unpack_from("!H", data, cur)[0]
        cur += 2
        if n == 0 or cur + n > len(data):
            raise _decode(f"{what} DN uzunluğu geçersiz.")
        out.append(bytes(data[cur:cur + n]))
        cur += n
    return out


# ---------------------------------------------------------------------------
# TLS 1.3 CertificateRequest
# ---------------------------------------------------------------------------
@dataclass
class CertRequest13:
    context: bytes
    sigalgs: "list[int]"
    cert_sigalgs: "Optional[list[int]]" = None
    cas: "list[bytes]" = field(default_factory=list)


def parse_certificate_request_13(msg: bytes) -> CertRequest13:
    try:
        return _parse_cr13(msg)
    except MtlsProtocolError as e:
        raise MtlsProtocolError(f"{e} (CertificateRequest)", e.alert) from None


def _parse_cr13(msg: bytes) -> CertRequest13:
    """CertificateRequest (4 bayt başlık dahil), KATI ayrıştırma (RFC 8446 §4.3.2).

    * el sıkışma sırasında certificate_request_context sıfır uzunlukta olmalı
    * signature_algorithms ZORUNLU (yoksa missing_extension)
    * tekrarlanan extension -> illegal_parameter; gövde tam tüketilmeli
    """
    body = bytes(_check_header(msg, "CertificateRequest"))
    if not body:
        raise _decode("CertificateRequest gövdesi boş.")
    clen = body[0]
    if 1 + clen + 2 > len(body):
        raise _decode("CertificateRequest context/extension başlığı kesik.")
    ctx = body[1:1 + clen]
    if ctx:
        raise _illegal("el sıkışma CertificateRequest'inde certificate_request_context boş olmalı "
                       "(RFC 8446 §4.3.2).")
    elen = struct.unpack_from("!H", body, 1 + clen)[0]
    cur = 3 + clen
    if cur + elen != len(body):
        raise _decode("CertificateRequest extension uzunluğu tutarsız.")
    exts: "dict[int, bytes]" = {}
    while cur < len(body):
        if cur + 4 > len(body):
            raise _decode("CertificateRequest extension başlığı kesik.")
        et, el = struct.unpack_from("!HH", body, cur)
        cur += 4
        if cur + el > len(body):
            raise _decode("CertificateRequest extension gövdesi kesik.")
        if et in exts:
            raise _illegal(f"CertificateRequest'te tekrarlanan extension {et}.")
        exts[et] = body[cur:cur + el]
        cur += el

    def vec16(ext: int, what: str) -> bytes:
        d = exts[ext]
        if len(d) < 2 or struct.unpack_from("!H", d)[0] != len(d) - 2:
            raise _decode(f"{what} vektör uzunluğu tutarsız.")
        return d[2:]

    if EXT_SIGNATURE_ALGORITHMS not in exts:
        raise MtlsProtocolError("missing_extension: CertificateRequest signature_algorithms içermiyor "
                                "(RFC 8446 §4.3.2).", AL_MISSING_EXTENSION)
    sigalgs = _u16_list(vec16(EXT_SIGNATURE_ALGORITHMS, "signature_algorithms"), "signature_algorithms")
    cert_sigs = None
    if EXT_SIGNATURE_ALGORITHMS_CERT in exts:
        cert_sigs = _u16_list(vec16(EXT_SIGNATURE_ALGORITHMS_CERT, "signature_algorithms_cert"),
                              "signature_algorithms_cert")
    cas: "list[bytes]" = []
    if EXT_CERTIFICATE_AUTHORITIES in exts:
        raw = vec16(EXT_CERTIFICATE_AUTHORITIES, "certificate_authorities")
        if not raw:
            raise _decode("certificate_authorities boş olamaz.")
        cas = _dn_list(raw, "certificate_authorities")
    return CertRequest13(bytes(ctx), sigalgs, cert_sigs, cas)


def select_scheme_13(cert: "Optional[ClientCert]", req: CertRequest13) -> "Optional[int]":
    """Sertifikamızla uyumlu ve sunucunun izin verdiği ilk şema (sunucu tercih sırası); yoksa None."""
    if cert is None or cert.closed:
        return None
    if req.cas and not cert.matches_cas(req.cas):
        return None
    if not cert.chain_allows(req.cert_sigalgs):
        return None
    ours = set(cert.schemes(tls12=False))
    for s in req.sigalgs:
        if s in ours:
            return s
    return None


def build_certificate_13(context: bytes, cert: "Optional[ClientCert]") -> bytes:
    """İstemci Certificate (RFC 8446 §4.4.2). cert None -> boş liste."""
    entries = b""
    if cert is not None:
        entries = b"".join(len(d).to_bytes(3, "big") + d + b"\x00\x00" for d in cert.chain_der)
    body = bytes([len(context)]) + context + len(entries).to_bytes(3, "big") + entries
    return bytes([HS_CERTIFICATE]) + len(body).to_bytes(3, "big") + body


def certificate_verify_content_13(transcript_hash: bytes) -> bytes:
    return b"\x20" * 64 + CLIENT_CV_CONTEXT + b"\x00" + transcript_hash


def build_certificate_verify_13(cert: ClientCert, scheme: int, transcript_hash: bytes) -> bytes:
    sig = cert.sign(scheme, certificate_verify_content_13(transcript_hash))
    body = struct.pack("!HH", scheme, len(sig)) + sig
    return bytes([HS_CERTIFICATE_VERIFY]) + len(body).to_bytes(3, "big") + body


def client_auth_flight_13(cert: "Optional[ClientCert]", req: CertRequest13, hash_alg,
                          transcript: bytes) -> "tuple[list[bytes], Optional[int]]":
    """Sunucu Finished'tan SONRAKİ istemci kimlik mesajları: ([Certificate, (CertificateVerify)], şema).

    ``transcript``: ClientHello .. sunucu Finished (varsa istemci EncryptedExtensions dahil).
    CertificateVerify, Certificate mesajı DAHİL transcript'in hash'ini imzalar (§4.4.3); çağıran
    dönen mesajları sırayla gönderip transcript'e ekler, ardından Finished'ı hesaplar.
    Şema None ise yalnızca boş Certificate döner.
    """
    scheme = select_scheme_13(cert, req)
    if scheme is None:
        return [build_certificate_13(req.context, None)], None
    cmsg = build_certificate_13(req.context, cert)
    th = hash_alg(transcript + cmsg).digest()
    return [cmsg, build_certificate_verify_13(cert, scheme, th)], scheme


# ---------------------------------------------------------------------------
# TLS 1.2
# ---------------------------------------------------------------------------
@dataclass
class CertRequest12:
    types: "list[int]"
    sigalgs: "list[int]"
    cas: "list[bytes]" = field(default_factory=list)


def parse_certificate_request_12(msg: bytes) -> CertRequest12:
    try:
        return _parse_cr12(msg)
    except MtlsProtocolError as e:
        raise MtlsProtocolError(f"{e} (CertificateRequest)", e.alert) from None


def _parse_cr12(msg: bytes) -> CertRequest12:
    """TLS 1.2 CertificateRequest (RFC 5246 §7.4.4), TLS 1.2 biçimi (signature_algorithms dahil)."""
    body = bytes(_check_header(msg, "CertificateRequest"))
    try:
        tn = body[0]
        if tn == 0:
            raise _decode("certificate_types boş olamaz.")
        types = list(body[1:1 + tn])
        cur = 1 + tn
        if len(types) != tn:
            raise _decode("certificate_types kesik.")
        sl = struct.unpack_from("!H", body, cur)[0]
        cur += 2
        sig_raw = body[cur:cur + sl]
        if len(sig_raw) != sl:
            raise _decode("supported_signature_algorithms kesik.")
        sigalgs = _u16_list(sig_raw, "supported_signature_algorithms")
        cur += sl
        cl = struct.unpack_from("!H", body, cur)[0]
        cur += 2
        if cur + cl != len(body):
            raise _decode("certificate_authorities uzunluğu gövdeyle tutarsız.")
        cas = _dn_list(body[cur:cur + cl], "certificate_authorities")
    except (IndexError, struct.error) as e:
        raise _decode("CertificateRequest kesik.") from e
    return CertRequest12(types, sigalgs, cas)


def select_scheme_12(cert: "Optional[ClientCert]", req: CertRequest12) -> "Optional[int]":
    if cert is None or cert.closed:
        return None
    if cert.cert_type_12 not in req.types:
        return None
    if req.cas and not cert.matches_cas(req.cas):
        return None
    ours = cert.schemes(tls12=True)
    offered = set(req.sigalgs)
    for s in ours:                 # önce anahtarın kendi tercihi (eğri eşleşmesi, PSS > PKCS#1)
        if s in offered:
            return s
    return None


def build_certificate_12(cert: "Optional[ClientCert]") -> bytes:
    """İstemci Certificate (RFC 5246 §7.4.6). cert None -> sıfır sertifikalı liste."""
    entries = b"" if cert is None else b"".join(len(d).to_bytes(3, "big") + d for d in cert.chain_der)
    body = len(entries).to_bytes(3, "big") + entries
    return bytes([HS_CERTIFICATE]) + len(body).to_bytes(3, "big") + body


def build_certificate_verify_12(cert: ClientCert, scheme: int, handshake_messages: bytes) -> bytes:
    """RFC 5246 §7.4.8: imza, ClientHello'dan CertificateVerify'a kadar (ClientKeyExchange DAHİL)
    tüm handshake mesajlarının KENDİSİ üzerinedir (şemanın hash'i uygulanır; ed25519 ham)."""
    sig = cert.sign(scheme, handshake_messages, tls12=True)
    body = struct.pack("!HH", scheme, len(sig)) + sig
    return bytes([HS_CERTIFICATE_VERIFY]) + len(body).to_bytes(3, "big") + body
