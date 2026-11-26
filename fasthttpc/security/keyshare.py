"""
fasthttpc — TLS 1.3 key_share grupları ve HelloRetryRequest yardımcıları.

Bu modül SAF (soket-bağımsız) fonksiyonlar içerir; hem ``TLSAdapter.negotiate``
hem de sans-IO TLS çekirdeği (fasthttpc/tls13/) tarafından kullanılır.

Desteklenen (EC)DHE grupları:
  - x25519     (0x001D)  RFC 7748, 32 byte public key
  - x448       (0x001E)  RFC 7748, 56 byte public key
  - secp256r1  (0x0017)  uncompressed nokta, 65 byte (0x04 || X || Y)
  - secp384r1  (0x0018)  uncompressed nokta, 97 byte
  - secp521r1  (0x0019)  uncompressed nokta, 133 byte
  - ffdhe2048  (0x0100)  RFC 7919; Y, p uzunluğuna (256 byte) soldan sıfırla doldurulur
  - ffdhe3072  (0x0101)  RFC 7919; 384 byte
  - X25519MLKEM768 (0x11EC) yalnızca ``cryptography`` ML-KEM sunuyorsa

RFC 8446 §4.2.8.2: ECDHE paylaşılan sırrı yalnızca X koordinatıdır (cryptography
``ECDH`` exchange'i tam olarak bunu döner). Karşı tarafın noktası eğri üzerinde
olmalıdır; ``from_encoded_point`` bunu doğrular ve geçersiz noktada hata verir.
x25519/x448'de tamamen sıfır paylaşılan sır reddedilir (RFC 8446 §7.4.2,
RFC 8422 §5.11). ffdhe'de karşı değer 1 < Y < p-1 olmalıdır (RFC 7919 §5.1) ve
paylaşılan sır p uzunluğuna soldan sıfırla doldurulur (RFC 8446 §7.4.1).

TLS 1.2 ECDHE (RFC 8422) yalnızca eliptik eğri gruplarını kullanabilir
(``ECDHE_GROUPS``); ffdhe ve hibrit gruplar burada yalnızca TLS 1.3 içindir.
"""
from __future__ import annotations

import os
import re
import struct
import warnings
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives import serialization

GROUP_X25519 = 0x001D
GROUP_SECP256R1 = 0x0017
GROUP_SECP384R1 = 0x0018
GROUP_SECP521R1 = 0x0019
GROUP_X448 = 0x001E
GROUP_FFDHE2048 = 0x0100
GROUP_FFDHE3072 = 0x0101
GROUP_X25519MLKEM768 = 0x11EC

try:  # cryptography >= 47: ML-KEM (FIPS 203); eski sürümlerde yok
    from cryptography.hazmat.primitives.asymmetric import mlkem as _mlkem
    _mlkem.MLKEM768PrivateKey.generate()          # backend gerçekten destekliyor mu?
    HAVE_MLKEM = True
except Exception:  # noqa: BLE001 - ImportError/UnsupportedAlgorithm/AttributeError
    _mlkem = None
    HAVE_MLKEM = False

_MLKEM768_EK = 1184   # ML-KEM-768 encapsulation key
_MLKEM768_CT = 1088   # ML-KEM-768 ciphertext

try:  # X448: BoringSSL/LibreSSL tabanlı cryptography derlemelerinde olmayabilir
    from cryptography.hazmat.primitives.asymmetric import x448 as _x448
    _x448.X448PrivateKey.generate()               # backend gerçekten destekliyor mu?
    HAVE_X448 = True
except Exception:  # noqa: BLE001 - ImportError/UnsupportedAlgorithm
    _x448 = None
    HAVE_X448 = False

# RFC 7919 Ek A.1 / A.2 — sabit asallar (g = 2, q = (p-1)/2). Parametre çalışma
# anında ÜRETİLMEZ. Değerler RFC'deki p = 2^b - 2^{b-64} + {[2^{b-130} e] + X} * 2^64 - 1
# formülüyle ve OpenSSL'in yerleşik ffdhe2048/ffdhe3072 gruplarıyla aynıdır
# (tests/test_kex_groups.py ikisini de doğrular).
_FFDHE2048_P = int(
    "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695"
    "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A"
    "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
    "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A"
    "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4"
    "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
    "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005"
    "C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF", 16)
_FFDHE3072_P = int(
    "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695"
    "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A"
    "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
    "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A"
    "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4"
    "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
    "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005"
    "C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035B"
    "BC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
    "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF"
    "5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E"
    "0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF", 16)
FFDHE_PRIMES = {GROUP_FFDHE2048: _FFDHE2048_P, GROUP_FFDHE3072: _FFDHE3072_P}
FFDHE_GENERATOR = 2

# cryptography sonlu cisim DH'yi (FFDH) kullanımdan kaldırılmış sayar ve
# DHParameterNumbers/DHPublicNumbers kurulurken CryptographyDeprecationWarning
# (UserWarning) basar. Kullanıcı buna göre davranamaz; uyarı YALNIZCA bu modülün
# çağrıları için (mesaj + kategori + modül adıyla dar bir filtre) susturulur.
# Destek bir gün kaldırılırsa HAVE_FFDHE False olur ve ffdhe grupları
# SUPPORTED_GROUPS'tan düşer: profiller onları ilan etmeyi sürdürür (parmak izi
# değişmez), HelloRetryRequest ile istenirlerse açık hata verilir.
_FFDH_MSG = r"Diffie-Hellman over finite fields"
_FFDH_MODULE = re.escape(__name__) + r"\Z"
try:
    from cryptography.utils import CryptographyDeprecationWarning as _CDW
except ImportError:  # pragma: no cover - eski cryptography
    _CDW = None


def _ffdh_uyarisini_sustur() -> None:
    """Dar filtreyi yoksa (yeniden) ekler. İçe aktarmada bir kez eklenir; bir
    ``warnings.catch_warnings()`` bloğu (ör. pytest) onu geri aldıysa FFDH
    çağrısından hemen önce tekrar eklenir. Filtre varsa küresel durum DEĞİŞMEZ."""
    if _CDW is None:
        return
    for f in warnings.filters:
        if (f[0] == "ignore" and f[2] is _CDW and f[1] is not None and f[1].pattern == _FFDH_MSG
                and f[3] is not None and f[3].pattern == _FFDH_MODULE):
            return
    warnings.filterwarnings("ignore", message=_FFDH_MSG, category=_CDW, module=_FFDH_MODULE)


_ffdh_uyarisini_sustur()

try:
    from cryptography.hazmat.primitives.asymmetric import dh as _dh
    _FFDHE_PARAMS = {
        g: _dh.DHParameterNumbers(p, FFDHE_GENERATOR, (p - 1) // 2) for g, p in FFDHE_PRIMES.items()
    }
    _FFDHE_PARAMS[GROUP_FFDHE2048].parameters()   # backend gerçekten destekliyor mu?
    HAVE_FFDHE = True
except Exception:  # noqa: BLE001 - ImportError/UnsupportedAlgorithm/AttributeError
    _dh = None
    _FFDHE_PARAMS = {}
    HAVE_FFDHE = False

#: Bu istemcinin gerçekten key exchange yapabildiği gruplar. X25519MLKEM768
#: (draft-kwiatkowski-tls-ecdhe-mlkem; Chrome 131+/Firefox 132+ varsayılanı)
#: yalnızca kurulu ``cryptography`` ML-KEM sunuyorsa listelenir.
#:
#: Bu küme ClientHello'yu DEĞİŞTİRMEZ: supported_groups ve ilk key_share'ler
#: profilden gelir (tls_crafter; hiçbir profil secp521r1/x448/ffdhe için ilk
#: key_share istemez). Buradaki bir grup yalnızca (a) profil onu ilan ediyor ve
#: sunucu HelloRetryRequest ile istiyorsa, (b) TLS 1.2'de ServerKeyExchange
#: ilan edilmiş bir ECDHE_GROUPS eğrisini seçtiyse kullanılır.
SUPPORTED_GROUPS = (
    (GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1, GROUP_SECP521R1)
    + ((GROUP_X448,) if HAVE_X448 else ())
    + ((GROUP_FFDHE2048, GROUP_FFDHE3072) if HAVE_FFDHE else ())
    + ((GROUP_X25519MLKEM768,) if HAVE_MLKEM else ())
)

#: TLS 1.2 ECDHE ServerKeyExchange'te (RFC 8422 named_curve) kabul edilen gruplar:
#: yalnızca eliptik eğriler. ffdhe (RFC 7919) TLS 1.2'de DHE suite'leri içindir ve
#: DHE her zaman reddedilir; X25519MLKEM768 yalnızca TLS 1.3'tür.
ECDHE_GROUPS = frozenset(
    g for g in SUPPORTED_GROUPS
    if g in (GROUP_X25519, GROUP_X448, GROUP_SECP256R1, GROUP_SECP384R1, GROUP_SECP521R1)
)

GROUP_NAMES = {
    GROUP_X25519: "x25519",
    GROUP_SECP256R1: "secp256r1",
    GROUP_SECP384R1: "secp384r1",
    GROUP_SECP521R1: "secp521r1",
    GROUP_X448: "x448",
    GROUP_FFDHE2048: "ffdhe2048",
    GROUP_FFDHE3072: "ffdhe3072",
    0x0102: "ffdhe4096",
    0x0103: "ffdhe6144",
    0x0104: "ffdhe8192",
    GROUP_X25519MLKEM768: "X25519MLKEM768",
    0x6399: "X25519Kyber768Draft00",
}

_EC_CURVES = {
    GROUP_SECP256R1: (ec.SECP256R1, 65),
    GROUP_SECP384R1: (ec.SECP384R1, 97),
    GROUP_SECP521R1: (ec.SECP521R1, 133),
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


def supported_group_names() -> str:
    """Hata mesajları için desteklenen grupların virgülle ayrılmış adları."""
    return ", ".join(group_name(g) for g in SUPPORTED_GROUPS)


def ffdhe_prime_len(group: int) -> int:
    """ffdhe grubunda p'nin byte uzunluğu: public değer ve paylaşılan sır tam bu uzunluktadır."""
    return (FFDHE_PRIMES[group].bit_length() + 7) // 8


def generate_key_share(group: int):
    """Grup için (özel_anahtar_nesnesi, telde_gönderilecek_public_bytes) döner."""
    if group == GROUP_X25519:
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return priv, pub
    if group == GROUP_X448 and HAVE_X448:
        xpriv = _x448.X448PrivateKey.generate()
        return xpriv, xpriv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    if group in _FFDHE_PARAMS:
        # Sabit RFC 7919 parametreleri (çalışma anında parametre üretimi YOK); özel
        # üs OpenSSL'in adlandırılmış grup uzunluğunda üretilir. RFC 8446 §4.2.8.1:
        # Y big-endian, p uzunluğuna soldan sıfırla doldurulur.
        dpriv = _FFDHE_PARAMS[group].parameters().generate_private_key()
        y = dpriv.public_key().public_numbers().y
        return dpriv, y.to_bytes(ffdhe_prime_len(group), "big")
    if group in _EC_CURVES:
        curve_cls, _ = _EC_CURVES[group]
        priv = ec.generate_private_key(curve_cls())
        pub = priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return priv, pub
    if group == GROUP_X25519MLKEM768 and HAVE_MLKEM:
        # Hibrit: ML-KEM-768 encapsulation key (1184) || x25519 public (32).
        kem = _mlkem.MLKEM768PrivateKey.generate()
        xpriv = x25519.X25519PrivateKey.generate()
        xpub = xpriv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return (kem, xpriv), kem.public_key().public_bytes_raw() + xpub
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
    if group == GROUP_X448 and HAVE_X448:
        if len(peer_public) != 56:
            raise ValueError("x448 public key 56 byte olmalı.")
        try:
            shared = private_key.exchange(_x448.X448PublicKey.from_public_bytes(bytes(peer_public)))
        except ValueError as e:      # OpenSSL küçük-alt-grup sonucunu kendisi de reddedebilir
            raise ValueError(f"x448 paylaşılan sırrı hesaplanamadı — geçersiz karşı anahtar: {e}") from e
        # RFC 8422 §5.11 / RFC 8446 §7.4.2: tamamen sıfır sonuç reddedilmeli.
        if shared == b"\x00" * 56:
            raise ValueError("x448 paylaşılan sırrı sıfır — geçersiz karşı anahtar.")
        return shared
    if group in _FFDHE_PARAMS:
        p = FFDHE_PRIMES[group]
        plen = ffdhe_prime_len(group)
        # RFC 8446 §4.2.8.1: Y, p uzunluğuna soldan sıfırla doldurulmuş big-endian tamsayıdır.
        if len(peer_public) != plen:
            raise ValueError(
                f"{group_name(group)} public değeri {plen} byte olmalı (gelen: {len(peer_public)})."
            )
        y = int.from_bytes(peer_public, "big")
        # RFC 7919 §5.1 / RFC 8446 §4.2.8.1: 1 < Y < p-1. p güvenli asal olduğundan
        # bu kontrol yeterlidir (Y = 1 / p-1 karşıyı 2 elemanlı alt gruba zorlar).
        if not 1 < y < p - 1:
            raise ValueError(f"{group_name(group)} public değeri aralık dışında (1 < Y < p-1 olmalı).")
        _ffdh_uyarisini_sustur()
        try:
            z = private_key.exchange(_dh.DHPublicNumbers(y, _FFDHE_PARAMS[group]).public_key())
        except ValueError as e:
            raise ValueError(f"{group_name(group)} paylaşılan sırrı hesaplanamadı: {e}") from e
        if not z or len(z) > plen:
            raise ValueError(f"{group_name(group)} paylaşılan sırrı beklenmeyen uzunlukta.")
        # RFC 8446 §7.4.1: Z big-endian, p uzunluğuna soldan sıfırla doldurulur.
        return bytes(z).rjust(plen, b"\x00")
    if group == GROUP_X25519MLKEM768 and HAVE_MLKEM:
        # Sunucu payı: ML-KEM ciphertext (1088) || x25519 public (32);
        # sır = mlkem_ss (32) || x25519_ss (32) (bu sırayla).
        if len(peer_public) != _MLKEM768_CT + 32:
            raise ValueError("X25519MLKEM768 sunucu payı 1120 byte olmalı.")
        kem, xpriv = private_key
        mlkem_ss = kem.decapsulate(bytes(peer_public[:_MLKEM768_CT]))
        x_ss = compute_shared_secret(GROUP_X25519, xpriv, peer_public[_MLKEM768_CT:])
        return bytes(mlkem_ss) + x_ss
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
