"""QUIC el sıkışmasında sunucu sertifikası doğrulaması: fasthttpc'nin cert_validator'ı AYNEN."""
from __future__ import annotations

import struct

from ..security.cert_validator import CertificateValidationError, validate_server_certificate


def _u24(n: int) -> bytes:
    return struct.pack("!I", n)[1:]


def validate_peer_chain(der_chain: "list[bytes]", hostname: str, ca_path: "str | None"):
    """DER zincirini (leaf önde) TLS 1.3 Certificate mesajı olarak paketleyip
    ``validate_server_certificate``'e verir: TCP yoluyla aynı zincir/süre/hostname kuralları."""
    if not der_chain:
        raise CertificateValidationError("Sunucu hiç sertifika göndermedi.")
    entries = b"".join(_u24(len(d)) + d + b"\x00\x00" for d in der_chain)
    body = b"\x00" + _u24(len(entries)) + entries
    msg = b"\x0b" + _u24(len(body)) + body
    return validate_server_certificate(msg, hostname, ca_path)
