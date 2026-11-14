"""TLS alert açıklamaları (RFC 8446 §6) ve kullanıcıya dönük ipuçları."""
from __future__ import annotations

ALERT_NAMES = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    22: "record_overflow", 40: "handshake_failure", 42: "bad_certificate",
    43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired",
    46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
    49: "access_denied", 50: "decode_error", 51: "decrypt_error",
    70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
    86: "inappropriate_fallback", 90: "user_canceled", 100: "no_renegotiation", 109: "missing_extension",
    110: "unsupported_extension", 112: "unrecognized_name",
    113: "bad_certificate_status_response", 115: "unknown_psk_identity",
    116: "certificate_required", 120: "no_application_protocol",
}

_HINTS = {
    70: ("Sunucu ortak bir TLS sürümü bulamadı. En olası neden: sunucu TLS 1.3 "
         "veya güvenli TLS 1.2 alt kümesini (ECDHE + AEAD + Extended Master Secret) "
         "desteklemiyor; TLS 1.1 ve altı reddedilir (README)."),
    40: ("Sunucu teklif edilen parametrelerden (cipher suite / grup / imza "
         "algoritması) hiçbirini kabul etmedi."),
    47: "Sunucu ClientHello'daki bir alanı geçersiz buldu.",
    71: "Sunucu daha güçlü parametreler istiyor.",
    109: "Sunucu ClientHello'da zorunlu bir extension'ı bulamadı.",
    112: "Sunucu SNI'daki host adını tanımıyor.",
    120: "Sunucu ALPN listesindeki protokollerin hiçbirini desteklemiyor.",
}


def describe_alert(payload: bytes) -> str:
    """Ham alert payload'ını (level, description) okunur bir metne çevirir."""
    if len(payload) < 2:
        return f"bozuk alert ({payload.hex()})"
    level, desc = payload[0], payload[1]
    name = ALERT_NAMES.get(desc, "bilinmiyor")
    text = f"{'fatal' if level == 2 else 'warning'} alert {desc} ({name})"
    hint = _HINTS.get(desc)
    return f"{text} — {hint}" if hint else text
