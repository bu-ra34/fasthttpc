"""
fasthttpc — TLS 1.3 key_share grupları ve HelloRetryRequest yardımcıları.

Bu modül SAF (soket-bağımsız) fonksiyonlar içerir; hem ``TLSAdapter.negotiate``
hem de sans-IO TLS çekirdeği (fasthttpc/tls13/) tarafından kullanılır.

Desteklenen (EC)DHE grupları:
  - x25519     (0x001D)  RFC 7748, 32 byte public key
  - secp256r1  (0x0017)  uncompressed nokta, 65 byte (0x04 || X || Y)
  - secp384r1  (0x0018)  uncompressed nokta, 97 byte

RFC 8446 §4.2.8.2: ECDHE paylaşılan sırrı yalnızca X koordinatıdır (cryptography
``ECDH`` exchange'i tam olarak bunu döner). Karşı tarafın noktası eğri üzerinde
olmalıdır; ``from_encoded_point`` bunu doğrular ve geçersiz noktada hata verir.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives import serialization

GROUP_X25519 = 0x001D
GROUP_SECP256R1 = 0x0017
GROUP_SECP384R1 = 0x0018

#: Bu istemcinin gerçekten key exchange yapabildiği gruplar.
SUPPORTED_GROUPS = (GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1)

GROUP_NAMES = {
    GROUP_X25519: "x25519",
    GROUP_SECP256R1: "secp256r1",
    GROUP_SECP384R1: "secp384r1",
    0x0019: "secp521r1",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x11EC: "X25519MLKEM768",
    0x6399: "X25519Kyber768Draft00",
}

_EC_CURVES = {
    GROUP_SECP256R1: (ec.SECP256R1, 65),
    GROUP_SECP384R1: (ec.SECP384R1, 97),
}

#: RFC 8446 §4.1.3 — SHA-256("HelloRetryRequest")
HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
)

#: RFC 8446 §4.4.1 — sentetik handshake mesaj tipi
HS_MESSAGE_HASH = 254

EXT_KEY_SHARE = 0x0033
EXT_COOKIE = 0x002C
EXT_SUPPORTED_VERSIONS = 0x002B


def group_name(group: int) -> str:
    return GROUP_NAMES.get(group, f"0x{group:04x}")


def is_supported_group(group: int) -> bool:
    return group in SUPPORTED_GROUPS


def generate_key_share(group: int):
    """Grup için (özel_anahtar_nesnesi, telde_gönderilecek_public_bytes) döner."""
    if group == GROUP_X25519:
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return priv, pub
    if group in _EC_CURVES:
        curve_cls, _ = _EC_CURVES[group]
        priv = ec.generate_private_key(curve_cls())
        pub = priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return priv, pub
    raise ValueError(f"key_share grubu desteklenmiyor: {group_name(group)}")


def compute_shared_secret(group: int, private_key, peer_public: bytes) -> bytes:
    """(EC)DHE paylaşılan sırrı. Geçersiz/bozuk karşı anahtarda ValueError."""
    if group == GROUP_X25519:
        if len(peer_public) != 32:
            raise ValueError("x25519 public key 32 byte olmalı.")
        if isinstance(private_key, (bytes, bytearray)):
            private_key = x25519.X25519PrivateKey.from_private_bytes(bytes(private_key))
        shared = private_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))
        # RFC 8446 §7.4.2: tamamen sıfır sonuç (küçük-alt-grup noktası) reddedilmeli.
        if shared == b"\x00" * 32:
            raise ValueError("x25519 paylaşılan sırrı sıfır — geçersiz karşı anahtar.")
        return shared
    if group in _EC_CURVES:
        curve_cls, size = _EC_CURVES[group]
        # RFC 8446 §4.2.8.2: yalnızca uncompressed (0x04) format geçerlidir.
        if len(peer_public) != size or peer_public[0] != 0x04:
            raise ValueError(
                f"{group_name(group)} public key {size} byte uncompressed nokta olmalı."
            )
        try:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(curve_cls(), peer_public)
        except ValueError as e:
            raise ValueError(f"{group_name(group)} noktası eğri üzerinde değil: {e}") from e
        return private_key.exchange(ec.ECDH(), peer)
    raise ValueError(f"key_share grubu desteklenmiyor: {group_name(group)}")


def encode_key_share_entry(group: int, public: bytes) -> bytes:
    return struct.pack("!HH", group, len(public)) + public


class KeyShareSet:
    """ClientHello'da gönderilen key_share'lerin özel anahtarlarını tutar."""

    def __init__(self, groups=(GROUP_X25519,)):
        self._keys: dict[int, tuple[object, bytes]] = {}
        for g in groups:
            self.add(g)

    def add(self, group: int) -> bytes:
        priv, pub = generate_key_share(group)
        self._keys[group] = (priv, pub)
        return pub

    @property
    def groups(self) -> list[int]:
        return list(self._keys)

    def public(self, group: int) -> bytes:
        return self._keys[group][1]

    def private(self, group: int):
        return self._keys[group][0]

    def entries(self) -> bytes:
        """KeyShareClientHello.client_shares gövdesi (uzunluk prefix'i HARİÇ)."""
        return b"".join(encode_key_share_entry(g, pub) for g, (_p, pub) in self._keys.items())

    def shared_secret(self, group: int, peer_public: bytes) -> bytes:
        if group not in self._keys:
            raise ValueError(
                f"Sunucu {group_name(group)} grubunu seçti ama bu grup için key_share "
                f"göndermedik (gönderilenler: {', '.join(group_name(g) for g in self._keys)})."
            )
        return compute_shared_secret(group, self._keys[group][0], peer_public)


def is_hello_retry_request(server_random: bytes) -> bool:
    return bytes(server_random) == HRR_RANDOM


@dataclass
class HRRInfo:
    cipher_suite: int
    selected_group: Optional[int]
    cookie: Optional[bytes]
    session_id: bytes
    selected_version: Optional[int]


def parse_hrr(sh_body: bytes) -> HRRInfo:
    """HelloRetryRequest gövdesini (4 byte handshake başlığı HARİÇ) parse eder.

    Bozuk mesajda ValueError fırlatır. key_share uzantısı HRR'de yalnızca
    2 byte'lık ``selected_group`` içerir (RFC 8446 §4.2.8).
    """
    if len(sh_body) < 38:
        raise ValueError("HelloRetryRequest çok kısa.")
    if sh_body[2:34] != HRR_RANDOM:
        raise ValueError("Mesaj bir HelloRetryRequest değil.")
    sid_len = sh_body[34]
    off = 35 + sid_len
    if len(sh_body) < off + 5:
        raise ValueError("HelloRetryRequest bozuk (session_id/cipher).")
    session_id = sh_body[35:off]
    cipher_suite = struct.unpack("!H", sh_body[off:off + 2])[0]
    if sh_body[off + 2] != 0:
        raise ValueError("HelloRetryRequest legacy_compression_method 0 değil.")
    ext_len = struct.unpack("!H", sh_body[off + 3:off + 5])[0]
    cur = off + 5
    end = cur + ext_len
    if end != len(sh_body):
        raise ValueError("HelloRetryRequest extension uzunluğu tutarsız.")

    selected_group = cookie = selected_version = None
    seen = set()
    while cur < end:
        if cur + 4 > end:
            raise ValueError("HelloRetryRequest extension başlığı kesik.")
        etype, elen = struct.unpack("!HH", sh_body[cur:cur + 4])
        cur += 4
        data = sh_body[cur:cur + elen]
        if len(data) != elen:
            raise ValueError("HelloRetryRequest extension gövdesi kesik.")
        cur += elen
        if etype in seen:
            raise ValueError(f"HelloRetryRequest'te tekrarlanan extension: {etype}")
        seen.add(etype)
        if etype == EXT_KEY_SHARE:
            if elen != 2:
                raise ValueError("HRR key_share yalnızca 2 byte selected_group içermeli.")
            selected_group = struct.unpack("!H", data)[0]
        elif etype == EXT_COOKIE:
            if elen < 3:
                raise ValueError("HRR cookie extension'ı boş/bozuk.")
            clen = struct.unpack("!H", data[:2])[0]
            if clen == 0 or clen != elen - 2:
                raise ValueError("HRR cookie uzunluğu tutarsız.")
            cookie = data[2:]
        elif etype == EXT_SUPPORTED_VERSIONS:
            if elen != 2:
                raise ValueError("HRR supported_versions 2 byte olmalı.")
            selected_version = struct.unpack("!H", data)[0]
    return HRRInfo(cipher_suite, selected_group, cookie, session_id, selected_version)


def message_hash(hash_alg, client_hello1: bytes) -> bytes:
    """RFC 8446 §4.4.1 sentetik ``message_hash`` handshake mesajı.

    client_hello1: 4 byte handshake başlığı DAHİL ilk ClientHello mesajı
    (record başlığı HARİÇ). Dönüş: 254 || uint24(Hash.len) || Hash(CH1).
    HRR sonrası transcript = message_hash || HRR || CH2 || ServerHello || ...
    """
    digest = hash_alg(client_hello1).digest()
    return bytes([HS_MESSAGE_HASH]) + struct.pack("!I", len(digest))[1:] + digest
