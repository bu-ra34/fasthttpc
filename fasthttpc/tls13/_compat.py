"""Paylaşılan saf (soket-bağımsız) TLS yardımcıları.

Mantığın iki kez yazılıp kaymaması için çekirdek, faz1'in
(security/tls_adapter.py: ServerHello ayrıştırma, KeyUpdate, sıra doğrulama,
record sınırları) ve faz2'nin (security/keyshare.py: HRR, P-256/P-384) saf
fonksiyonlarını kullanır. Bu dallar henüz birleştirilmediyse AYNI İMZALI
yerel yedekler devreye girer; birleştirme sonrası import otomatik olarak
paylaşılan sürüme geçer ve yedekler ölü kod olur (koordinatör silebilir).

`USING_SHARED_*` bayrakları hangi yolun aktif olduğunu gösterir (testler ve
teşhis için).
"""
from __future__ import annotations

import hashlib
import struct

from ..crypto_math import PureCryptoEngine as _P

try:  # pragma: no cover - faz1 merge edilince
    from ..security.tls_adapter import TLSProtocolError
except ImportError:
    class TLSProtocolError(ConnectionError):  # type: ignore[no-redef]
        pass

# --------------------------------------------------------------------------
# faz1: record sınırları, ServerHello, KeyUpdate, sıra doğrulayıcı
# --------------------------------------------------------------------------
try:  # pragma: no cover - faz1 merge edilince
    from ..security.tls_adapter import (  # type: ignore
        MAX_PLAINTEXT,
        MAX_CIPHERTEXT,
        parse_server_hello,
        suite_params,
        next_traffic_secret,
        traffic_key_iv,
        build_key_update,
        parse_key_update,
        HandshakeOrderValidator,
    )
    USING_SHARED_FAZ1 = True
except ImportError:
    USING_SHARED_FAZ1 = False

    MAX_PLAINTEXT = 2 ** 14
    MAX_CIPHERTEXT = 2 ** 14 + 256

    HRR_RANDOM = bytes.fromhex(
        "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
    )

    def suite_params(cipher_suite: int):
        if cipher_suite == 0x1301:
            return "AES", 16, hashlib.sha256
        if cipher_suite == 0x1302:
            return "AES", 32, hashlib.sha384
        if cipher_suite == 0x1303:
            return "CHACHA20-POLY1305", 32, hashlib.sha256
        raise TLSProtocolError(
            f"Sunucu desteklenmeyen bir cipher suite seçti: 0x{cipher_suite:04x}. "
            f"Bu istemci yalnızca TLS 1.3 suite'lerini destekler."
        )

    def parse_server_hello(sh_msg: bytes, sent_session_id: bytes | None = None) -> dict:
        """ServerHello / HelloRetryRequest ayrıştırır (4 byte hs header dahil)."""
        if len(sh_msg) < 4 or sh_msg[0] != 2:
            raise TLSProtocolError("ServerHello beklenirken farklı bir handshake mesajı geldi.")
        body = sh_msg[4:]
        try:
            if len(body) < 38:
                raise TLSProtocolError("ServerHello mesajı bozuk (çok kısa).")
            random = body[2:34]
            sid_len = body[34]
            off = 35 + sid_len
            session_id = body[35:off]
            if len(body) < off + 5:
                raise TLSProtocolError("ServerHello mesajı bozuk (cipher suite okunamadı).")
            cipher_suite = struct.unpack("!H", body[off:off + 2])[0]
            if body[off + 2] != 0:
                raise TLSProtocolError("ServerHello sıkıştırma yöntemi null değil.")
            ext_len = struct.unpack("!H", body[off + 3:off + 5])[0]
            cur, end = off + 5, off + 5 + ext_len
            if end != len(body):
                raise TLSProtocolError("ServerHello extension uzunluğu tutarsız.")
            is_hrr = random == HRR_RANDOM
            res = {
                "random": random, "session_id": session_id,
                "cipher_suite": cipher_suite, "selected_version": None,
                "selected_group": None, "server_pub": None,
                "is_hrr": is_hrr, "cookie": None, "extensions": {},
            }
            while cur < end:
                if cur + 4 > end:
                    raise TLSProtocolError("ServerHello extension başlığı kesilmiş.")
                et, el = struct.unpack("!HH", body[cur:cur + 4])
                cur += 4
                data = body[cur:cur + el]
                if len(data) != el:
                    raise TLSProtocolError("ServerHello extension gövdesi kesilmiş.")
                if et in res["extensions"]:
                    raise TLSProtocolError(f"ServerHello'da tekrarlanan extension: {et}")
                res["extensions"][et] = data
                cur += el
                if et == 43 and el == 2:
                    res["selected_version"] = struct.unpack("!H", data)[0]
                elif et == 51:
                    if is_hrr:
                        if el != 2:
                            raise TLSProtocolError("HRR key_share bozuk.")
                        res["selected_group"] = struct.unpack("!H", data)[0]
                    else:
                        if el < 4:
                            raise TLSProtocolError("ServerHello key_share bozuk.")
                        g, kl = struct.unpack("!HH", data[:4])
                        if kl != el - 4:
                            raise TLSProtocolError("ServerHello key_share uzunluğu tutarsız.")
                        res["selected_group"], res["server_pub"] = g, data[4:]
                elif et == 44 and el >= 2:
                    cl = struct.unpack("!H", data[:2])[0]
                    res["cookie"] = data[2:2 + cl]
        except (struct.error, IndexError) as e:
            raise TLSProtocolError(f"ServerHello ayrıştırılamadı: {e}") from e
        if res["selected_version"] != 0x0304:
            raise TLSProtocolError(
                "Sunucu TLS 1.3 (supported_versions=0x0304) müzakere etmedi. Bu istemci "
                "TLS 1.2 ve altını desteklemez; downgrade kabul edilmiyor."
            )
        if sent_session_id is not None and session_id != sent_session_id:
            raise TLSProtocolError("ServerHello legacy_session_id_echo gönderilenle eşleşmiyor.")
        suite_params(cipher_suite)  # desteklenmeyen suite -> hata
        return res

    def next_traffic_secret(secret: bytes, hash_alg) -> bytes:
        return _P.tls13_hkdf_expand_label(
            secret, "traffic upd", b"", hash_alg().digest_size, hash_alg=hash_alg
        )

    def traffic_key_iv(secret: bytes, key_len: int, hash_alg):
        key = _P.tls13_hkdf_expand_label(secret, "key", b"", key_len, hash_alg=hash_alg)
        iv = _P.tls13_hkdf_expand_label(secret, "iv", b"", 12, hash_alg=hash_alg)
        return key, iv

    def build_key_update(request_update: bool) -> bytes:
        return b"\x18\x00\x00\x01" + (b"\x01" if request_update else b"\x00")

    def parse_key_update(msg: bytes) -> bool:
        if len(msg) != 5 or msg[0] != 24 or msg[1:4] != b"\x00\x00\x01" or msg[4] > 1:
            raise TLSProtocolError("KeyUpdate mesajı bozuk.")
        return msg[4] == 1

    class HandshakeOrderValidator:
        """RFC 8446 §A.1 istemci durum makinesi (sertifikalı, PSK'sız)."""

        _NEXT = {
            "WAIT_SH": {2: "WAIT_EE"},
            "WAIT_EE": {8: "WAIT_CERT"},
            "WAIT_CERT": {11: "WAIT_CV", 25: "WAIT_CV"},
            "WAIT_CV": {15: "WAIT_FINISHED"},
            "WAIT_FINISHED": {20: "CONNECTED"},
        }

        def __init__(self):
            self.state = "WAIT_SH"
            self.hrr_seen = False

        def expect(self, hs_type: int, is_hrr: bool = False) -> None:
            if is_hrr:
                if self.state != "WAIT_SH" or hs_type != 2 or self.hrr_seen:
                    raise TLSProtocolError("unexpected_message: beklenmeyen/ikinci HelloRetryRequest")
                self.hrr_seen = True
                return
            nxt = self._NEXT.get(self.state, {}).get(hs_type)
            if nxt is None:
                raise TLSProtocolError(
                    f"unexpected_message: durum={self.state}, gelen hs_type={hs_type}"
                )
            self.state = nxt

        @property
        def done(self) -> bool:
            return self.state == "CONNECTED"

# --------------------------------------------------------------------------
# faz2: key share grupları, HRR yardımcıları
# --------------------------------------------------------------------------
try:  # pragma: no cover - faz2 merge edilince
    from ..security.keyshare import compute_shared_secret, message_hash  # type: ignore
    USING_SHARED_FAZ2 = True
except ImportError:
    USING_SHARED_FAZ2 = False

    def compute_shared_secret(group: int, priv_obj, peer_public: bytes) -> bytes:
        if group != 0x001D:
            raise ValueError(f"Desteklenmeyen key_share grubu 0x{group:04x} (yalnızca x25519).")
        if len(peer_public) != 32:
            raise ValueError("x25519 açık anahtarı 32 byte olmalı.")
        shared = _P.x25519(priv_obj, peer_public)
        if shared == b"\x00" * 32:
            raise ValueError("x25519 paylaşılan sırrı sıfır (küçük alt grup noktası).")
        return shared

    def message_hash(hash_alg, ch1_handshake_msg: bytes) -> bytes:
        d = hash_alg(ch1_handshake_msg).digest()
        return b"\xfe\x00\x00" + bytes([len(d)]) + d


def client_shared_secret(impersonator, group: int, peer_public: bytes) -> bytes:
    """ClientHello'yu üreten TLSImpersonator'ın özel anahtar(lar)ıyla sır hesaplar.

    faz2 sonrası impersonator birden çok key_share tutabilir (`key_shares`);
    baseline'da yalnızca x25519 `private_key` vardır.
    """
    ks = getattr(impersonator, "key_shares", None)
    if ks is not None and hasattr(ks, "shared_secret"):
        return ks.shared_secret(group, peer_public)
    return compute_shared_secret(group, impersonator.private_key, peer_public)
