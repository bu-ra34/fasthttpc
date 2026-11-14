"""
fasthttpc — güvenli TLS 1.2 alt kümesi (RFC 5246 + RFC 7627 + RFC 5746 + RFC 7905).

Bu modül SOKET-BAĞIMSIZ (sans-IO) bir TLS 1.2 istemci durum makinesi ve saf
yardımcı fonksiyonlar içerir. İki yol da aynı mantığı kullanır:

  * senkron : ``TLSAdapter.negotiate`` ServerHello 0x0303 seçilince
              ``negotiate_tls12`` ile buraya dallanır; dönen nesne
              ``EncryptedSocket`` ile aynı ``send_record/recv_record`` yüzeyini sunar.
  * async   : ``tls13.connection.TLSClientConnection`` aynı dallanmayı yapar ve
              ``TLS12ClientConnection``'a devreder.

KAPSAM — yalnızca modern ve güvenli alt küme; gerisi AÇIK HATAYLA reddedilir:

  Anahtar değişimi : yalnızca ECDHE (x25519, secp256r1, secp384r1).
                     Statik RSA, DHE, PSK, anonim, export: YOK.
  Suite'ler        : ECDHE-{ECDSA,RSA}-AES128-GCM-SHA256 (0xC02B/0xC02F),
                     ECDHE-{ECDSA,RSA}-AES256-GCM-SHA384 (0xC02C/0xC030),
                     ECDHE-{ECDSA,RSA}-CHACHA20-POLY1305 (0xCCA9/0xCCA8).
                     CBC suite'leri KABUL EDİLMEZ.
  Zorunlu          : Extended Master Secret (RFC 7627) ve güvenli renegotiation
                     uzantısı (RFC 5746). Sunucu birini göndermezse bağlantı REDDEDİLİR.
  Desteklenmeyen   : renegotiation (HelloRequest -> no_renegotiation), oturum
                     devamı/bilet kullanımı (NewSessionTicket yalnızca parse edilir),
                     sıkıştırma (yalnızca null), istemci sertifikası.

GÜVENLİK — sunucu kimliği ve bütünlüğü şu kontrollerle sağlanır (hepsi zorunlu):

  1. Certificate        : zincir + hostname + süre (cert_validator, ca_path destekli).
  2. ServerKeyExchange  : client_random || server_random || ECDH parametreleri
                          üzerindeki imza, sertifika anahtarıyla doğrulanır; imza
                          algoritması ClientHello'da ilan ettiklerimizden biri olmalı,
                          sertifika anahtar türüyle ve suite ile uyumlu olmalı
                          (SHA-1/MD5/SHA-224 reddedilir).
  3. Finished           : sunucunun verify_data'sı SABİT ZAMANLI karşılaştırılır.
  4. DOWNGRD sentinel   : ServerHello.random sonunda DOWNGRD\\x01/\\x00 varsa
                          (TLS 1.3 ilan ettik) saldırı varsayılıp REDDEDİLİR
                          (RFC 8446 §4.1.3).
  5. El sıkışma sırası  : ServerHello -> Certificate -> (CertificateStatus) ->
                          ServerKeyExchange -> ServerHelloDone; sonra
                          (NewSessionTicket) -> ChangeCipherSpec -> Finished.
                          Sıra dışı/tekrar mesaj ``unexpected_message`` ile reddedilir.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Callable, Optional

from ..crypto_math import FastAESGCM, FastChaCha20Poly1305
from . import cert_validator as _cv
from .._log import get_logger
from .alerts import describe_alert
from .cert_validator import CertificateValidationError
from .keyshare import (
    SUPPORTED_GROUPS,
    compute_shared_secret,
    generate_key_share,
    group_name,
)
from . import mtls as _mtls
from .tls_adapter import TLSProtocolError
from ..tls13.events import (
    ApplicationData,
    AlertReceived,
    ConnectionClosed,
    Event,
    HandshakeComplete,
)

# --------------------------------------------------------------------------
# Sabitler
# --------------------------------------------------------------------------
_log = get_logger("tls12")

VERSION_TLS12 = 0x0303

CT_CHANGE_CIPHER_SPEC = 20
CT_ALERT = 21
CT_HANDSHAKE = 22
CT_APPLICATION_DATA = 23

HS_HELLO_REQUEST = 0
HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_NEW_SESSION_TICKET = 4
HS_CERTIFICATE = 11
HS_SERVER_KEY_EXCHANGE = 12
HS_CERTIFICATE_REQUEST = 13
HS_SERVER_HELLO_DONE = 14
HS_CLIENT_KEY_EXCHANGE = 16
HS_FINISHED = 20
HS_CERTIFICATE_STATUS = 22

# Alert açıklamaları (RFC 5246 §7.2)
AL_UNEXPECTED_MESSAGE = 10
AL_BAD_RECORD_MAC = 20
AL_RECORD_OVERFLOW = 22
AL_HANDSHAKE_FAILURE = 40
AL_BAD_CERTIFICATE = 42
AL_UNSUPPORTED_CERTIFICATE = 43
AL_ILLEGAL_PARAMETER = 47
AL_DECODE_ERROR = 50
AL_DECRYPT_ERROR = 51
AL_PROTOCOL_VERSION = 70
AL_INSUFFICIENT_SECURITY = 71
AL_INTERNAL_ERROR = 80
AL_NO_RENEGOTIATION = 100
AL_MISSING_EXTENSION = 109
AL_UNSUPPORTED_EXTENSION = 110

# RFC 5246 §6.2.1 / §6.2.3 — record boyut sınırları
MAX_PLAINTEXT = 2 ** 14
MAX_CIPHERTEXT = 2 ** 14 + 2048
# Bir handshake mesajı için üst sınır (sertifika zincirleri büyük olabilir).
MAX_HANDSHAKE_MESSAGE = 1 << 18
# RFC 5246 §6.1: sequence number 2^64-1'i AŞAMAZ ve sarmaz; sınıra gelince kapat.
SEQ_LIMIT = 2 ** 64 - 1
MAX_CERT_CHAIN = 16
# Güvenli renegotiation'ı desteklemediğimiz için HelloRequest'lere en fazla bu kadar
# uyarıyla (no_renegotiation) yanıt verilir; aşılırsa bağlantı kapatılır.
MAX_HELLO_REQUESTS = 3

EXT_SERVER_NAME = 0x0000
EXT_STATUS_REQUEST = 0x0005
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_SCT = 0x0012
EXT_EXTENDED_MASTER_SECRET = 0x0017
EXT_RECORD_SIZE_LIMIT = 0x001C
EXT_ENCRYPT_THEN_MAC = 0x0016      # RFC 7366; yalnızca legacy_tls
EXT_SESSION_TICKET = 0x0023
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_RENEGOTIATION_INFO = 0xFF01

#: ServerHello'da (TLS 1.2) görülmesine izin verilen extension'lar. Bunun dışındaki
#: her şey (TLS 1.3'e özgü olanlar dahil) reddedilir.
_SH_ALLOWED_EXTS = frozenset({
    EXT_SERVER_NAME, EXT_STATUS_REQUEST, EXT_SUPPORTED_GROUPS, EXT_EC_POINT_FORMATS,
    EXT_ALPN, EXT_SCT, EXT_EXTENDED_MASTER_SECRET, EXT_RECORD_SIZE_LIMIT,
    EXT_SESSION_TICKET, EXT_RENEGOTIATION_INFO,
})

#: RFC 8446 §4.1.3 — TLS 1.3 destekleyen sunucu daha düşük sürüm seçerse
#: ServerHello.random'un SON 8 baytına bunu koyar.
DOWNGRD_TLS12 = b"DOWNGRD\x01"
DOWNGRD_TLS11 = b"DOWNGRD\x00"


class TLS12Error(TLSProtocolError):
    """TLS 1.2 protokol/doğrulama hatası. ``alert`` karşı tarafa gönderilecek alert kodudur."""

    def __init__(self, msg: str, alert: int = AL_HANDSHAKE_FAILURE):
        super().__init__(msg)
        self.alert = alert


class TLS12AlertError(TLS12Error):
    """Sunucudan gelen fatal alert (karşıya alert GÖNDERİLMEZ)."""

    def __init__(self, level: int, description: int, msg: str = ""):
        super().__init__(msg or f"Sunucudan TLS alert alındı (level={level}, description={description})",
                         description)
        self.level = level
        self.description = description


def _err(alert: int, name: str, detail: str) -> TLS12Error:
    return TLS12Error(f"{name}: {detail}", alert)


def _unexpected(detail: str) -> TLS12Error:
    return _err(AL_UNEXPECTED_MESSAGE, "unexpected_message", detail)


def _illegal(detail: str) -> TLS12Error:
    return _err(AL_ILLEGAL_PARAMETER, "illegal_parameter", detail)


def _decode(detail: str) -> TLS12Error:
    return _err(AL_DECODE_ERROR, "decode_error", detail)


# --------------------------------------------------------------------------
# Cipher suite'ler
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Suite:
    id: int
    name: str
    auth: str            # "ECDSA" | "RSA"  (sertifika anahtar türü)
    cipher: str          # "AES" | "CHACHA20-POLY1305"
    key_len: int
    fixed_iv_len: int    # GCM: 4 (salt), ChaCha: 12 (RFC 7905)
    hash_alg: Callable   # PRF / transcript hash'i
    # --- yalnızca legacy_tls (tls12_legacy.py): varsayılanlar AEAD+ECDHE'dir, mevcut tablo değişmez ---
    kx: str = "ECDHE"    # "ECDHE" | "RSA" (statik RSA; yalnızca legacy)
    mode: str = "AEAD"   # "AEAD" | "CBC" (yalnızca legacy)
    mac_hash: Optional[Callable] = None
    mac_len: int = 0


SUITES: dict[int, Suite] = {
    0xC02B: Suite(0xC02B, "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDSA", "AES", 16, 4, hashlib.sha256),
    0xC02F: Suite(0xC02F, "ECDHE-RSA-AES128-GCM-SHA256", "RSA", "AES", 16, 4, hashlib.sha256),
    0xC02C: Suite(0xC02C, "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDSA", "AES", 32, 4, hashlib.sha384),
    0xC030: Suite(0xC030, "ECDHE-RSA-AES256-GCM-SHA384", "RSA", "AES", 32, 4, hashlib.sha384),
    0xCCA9: Suite(0xCCA9, "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDSA", "CHACHA20-POLY1305", 32, 12, hashlib.sha256),
    0xCCA8: Suite(0xCCA8, "ECDHE-RSA-CHACHA20-POLY1305", "RSA", "CHACHA20-POLY1305", 32, 12, hashlib.sha256),
}

_CBC_SUITES = frozenset({
    0xC009, 0xC00A, 0xC013, 0xC014, 0xC023, 0xC024, 0xC027, 0xC028,
    0x002F, 0x0035, 0x003C, 0x003D, 0x000A, 0x0033, 0x0039, 0x0067, 0x006B,
})
_STATIC_RSA_SUITES = frozenset({0x009C, 0x009D, 0x002F, 0x0035, 0x003C, 0x003D, 0x000A})


def reject_suite_message(cs: int) -> TLS12Error:
    """Kabul edilmeyen bir suite için anlamlı Türkçe hata."""
    if cs in (0x1301, 0x1302, 0x1303):
        return _illegal(
            f"Sunucu TLS 1.2 ServerHello'sunda TLS 1.3 cipher suite'i (0x{cs:04x}) seçti — "
            f"TLS 1.3 değil TLS 1.2 müzakere edilmiş olamaz; protokol ihlali."
        )
    if cs in _CBC_SUITES:
        return _err(
            AL_INSUFFICIENT_SECURITY, "insufficient_security",
            f"Sunucu CBC modlu bir cipher suite (0x{cs:04x}) seçti; CBC reddedilir "
            f"(padding-oracle/Lucky13 sınıfı saldırılar). Yalnızca AEAD (AES-GCM, "
            f"ChaCha20-Poly1305) ve ECDHE kabul edilir."
        )
    if cs in (0x009C, 0x009D):
        return _err(
            AL_INSUFFICIENT_SECURITY, "insufficient_security",
            f"Sunucu statik RSA anahtar değişimli bir suite (0x{cs:04x}) seçti; ileri gizlilik "
            f"yok, reddedilir. Yalnızca ECDHE kabul edilir."
        )
    return _err(
        AL_HANDSHAKE_FAILURE, "handshake_failure",
        f"Sunucu desteklenmeyen bir TLS 1.2 cipher suite'i (0x{cs:04x}) seçti. İzin verilenler: "
        + ", ".join(f"0x{s.id:04x} ({s.name})" for s in SUITES.values()) + "."
    )


# --------------------------------------------------------------------------
# PRF ve anahtar türetme (RFC 5246 §5, §6.3, §7.4.9; RFC 7627 §4)
# --------------------------------------------------------------------------
def prf(hash_alg, secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    """TLS 1.2 PRF = P_hash(secret, label || seed)  (RFC 5246 §5)."""
    seed = label + seed
    a = seed
    out = bytearray()
    while len(out) < length:
        a = hmac.new(secret, a, hash_alg).digest()
        out += hmac.new(secret, a + seed, hash_alg).digest()
    return bytes(out[:length])


def extended_master_secret(hash_alg, pre_master: bytes, session_hash: bytes) -> bytes:
    """RFC 7627 §4: PRF(pms, "extended master secret", session_hash)[0..47].

    session_hash = Hash(ClientHello .. ClientKeyExchange handshake mesajları).
    """
    return prf(hash_alg, pre_master, b"extended master secret", session_hash, 48)


def derive_key_block(suite: Suite, master: bytes, server_random: bytes, client_random: bytes):
    """(client_write_key, server_write_key, client_write_iv, server_write_iv).

    AEAD suite'lerde MAC anahtarı yoktur (RFC 5288 §3 / RFC 7905 §2).
    """
    n = 2 * suite.key_len + 2 * suite.fixed_iv_len
    kb = prf(suite.hash_alg, master, b"key expansion", server_random + client_random, n)
    k = suite.key_len
    i = suite.fixed_iv_len
    return kb[:k], kb[k:2 * k], kb[2 * k:2 * k + i], kb[2 * k + i:2 * k + 2 * i]


def finished_verify_data(suite: Suite, master: bytes, label: bytes, transcript: bytes) -> bytes:
    """RFC 5246 §7.4.9: PRF(master, label, Hash(handshake_messages))[0..11]."""
    return prf(suite.hash_alg, master, label, suite.hash_alg(transcript).digest(), 12)


# --------------------------------------------------------------------------
# Record koruması (AEAD)
# --------------------------------------------------------------------------
class RecordCipher:
    """Tek yön için TLS 1.2 AEAD record koruması + sequence number.

    GCM (RFC 5288): nonce = 4 bayt salt || 8 bayt açık explicit nonce. explicit nonce
    olarak sequence number kullanılır (benzersizlik garantisi). Alırken telde gelen
    explicit nonce kullanılır.
    ChaCha20-Poly1305 (RFC 7905): nonce = 12 bayt IV XOR (0^4 || seq64), açık nonce yok.
    AAD (RFC 5246 §6.2.3.3) = seq_num(8) || type(1) || version(2) || plaintext_length(2).
    """

    __slots__ = ("suite", "iv", "seq", "aead", "is_aes")

    def __init__(self, suite: Suite, key: bytes, iv: bytes):
        self.suite = suite
        self.iv = iv
        self.seq = 0
        self.is_aes = suite.cipher == "AES"
        self.aead = FastAESGCM(key) if self.is_aes else FastChaCha20Poly1305(key)

    @property
    def overhead(self) -> int:
        return (8 + 16) if self.is_aes else 16

    def _check_seq(self) -> None:
        if self.seq >= SEQ_LIMIT:
            raise _err(AL_INTERNAL_ERROR, "internal_error",
                       "Sequence number 2^64-1'e ulaştı — bağlantı kapatılmalı (RFC 5246 §6.1).")

    def seal(self, content_type: int, plaintext: bytes, version: int = VERSION_TLS12) -> bytes:
        """Record GÖVDESİNİ (header HARİÇ) döner."""
        self._check_seq()
        seq8 = self.seq.to_bytes(8, "big")
        aad = seq8 + struct.pack("!BHH", content_type, version, len(plaintext))
        if self.is_aes:
            ct, tag = self.aead.encrypt_gcm(self.iv + seq8, plaintext, aad)
            body = seq8 + ct + tag
        else:
            nonce = bytes(a ^ b for a, b in zip(self.iv, b"\x00\x00\x00\x00" + seq8))
            ct, tag = self.aead.encrypt_aead(nonce, plaintext, aad)
            body = ct + tag
        self.seq += 1
        return body

    def open(self, content_type: int, version: bytes, body: bytes) -> bytes:
        self._check_seq()
        if len(body) < self.overhead:
            raise _err(AL_BAD_RECORD_MAC, "bad_record_mac", "şifreli record AEAD için fazla kısa.")
        seq8 = self.seq.to_bytes(8, "big")
        if self.is_aes:
            explicit, ct, tag = body[:8], body[8:-16], body[-16:]
            aad = seq8 + bytes([content_type]) + version + struct.pack("!H", len(ct))
            nonce = self.iv + explicit
            decrypt = self.aead.decrypt_gcm
        else:
            ct, tag = body[:-16], body[-16:]
            aad = seq8 + bytes([content_type]) + version + struct.pack("!H", len(ct))
            nonce = bytes(a ^ b for a, b in zip(self.iv, b"\x00\x00\x00\x00" + seq8))
            decrypt = self.aead.decrypt_aead
        try:
            pt = decrypt(nonce, ct, aad, tag)
        except ValueError as e:
            raise _err(AL_BAD_RECORD_MAC, "bad_record_mac", f"TLS record'u doğrulanamadı ({e})") from e
        self.seq += 1
        return pt


# --------------------------------------------------------------------------
# ClientHello / ServerHello ayrıştırma
# --------------------------------------------------------------------------
@dataclass
class ClientHelloInfo:
    """Kendi gönderdiğimiz ClientHello'nun, ServerHello'yu doğrulamak için gereken özeti."""
    random: bytes
    session_id: bytes
    suites: list
    ext_types: set
    versions: list
    sigalgs: list
    groups: list
    alpn: list


def parse_client_hello(msg: bytes) -> ClientHelloInfo:
    """ClientHello handshake mesajını (4 bayt başlık DAHİL) ayrıştırır."""
    try:
        if msg[0] != HS_CLIENT_HELLO:
            raise ValueError("ClientHello değil")
        body = msg[4:]
        random = body[2:34]
        sl = body[34]
        sid = body[35:35 + sl]
        off = 35 + sl
        csl = struct.unpack("!H", body[off:off + 2])[0]
        suites = [struct.unpack("!H", body[off + 2 + i:off + 4 + i])[0] for i in range(0, csl, 2)]
        off += 2 + csl
        off += 1 + body[off]
        el = struct.unpack("!H", body[off:off + 2])[0]
        off += 2
        end = off + el
        exts = {}
        while off < end:
            t, ln = struct.unpack("!HH", body[off:off + 4])
            exts[t] = body[off + 4:off + 4 + ln]
            off += 4 + ln
    except (IndexError, struct.error, ValueError) as e:
        raise TLS12Error(f"internal_error: ClientHello ayrıştırılamadı: {e}", AL_INTERNAL_ERROR) from e

    def u16_list(data: bytes, prefix: int) -> list:
        if prefix == 1:
            raw = data[1:1 + data[0]] if data else b""
        else:
            raw = data[2:2 + struct.unpack("!H", data[:2])[0]] if len(data) >= 2 else b""
        return [struct.unpack("!H", raw[i:i + 2])[0] for i in range(0, len(raw) - 1, 2)]

    alpn = []
    d = exts.get(EXT_ALPN, b"")
    p = 2
    while p < len(d):
        ln = d[p]
        alpn.append(d[p + 1:p + 1 + ln].decode("ascii", "ignore"))
        p += 1 + ln
    return ClientHelloInfo(
        random=bytes(random), session_id=bytes(sid), suites=suites, ext_types=set(exts),
        versions=u16_list(exts.get(EXT_SUPPORTED_VERSIONS, b""), 1),
        sigalgs=u16_list(exts.get(EXT_SIGNATURE_ALGORITHMS, b""), 2),
        groups=u16_list(exts.get(EXT_SUPPORTED_GROUPS, b""), 2),
        alpn=alpn,
    )


def is_tls12_server_hello(sh_msg: bytes) -> bool:
    """ServerHello (başlık dahil) TLS 1.2 mi seçiyor? (legacy_version == 0x0303 ve
    supported_versions ≠ 0x0304 ve HelloRetryRequest değil.)

    Bozuk/anlaşılmaz mesajlarda False döner; hata mesajını TLS 1.3 yolu üretir.
    """
    try:
        if len(sh_msg) < 4 + 35 or sh_msg[0] != HS_SERVER_HELLO:
            return False
        body = sh_msg[4:]
        if body[:2] != b"\x03\x03":
            return False
        if body[2:34] == bytes.fromhex(
            "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
        ):
            return False
        off = 35 + body[34]
        off += 3                      # cipher_suite(2) + compression(1)
        if off == len(body):
            return True               # extension'sız -> TLS 1.2
        total = struct.unpack("!H", body[off:off + 2])[0]
        cur = off + 2
        if cur + total != len(body):
            return False
        while cur + 4 <= len(body):
            et, el = struct.unpack("!HH", body[cur:cur + 4])
            if et == EXT_SUPPORTED_VERSIONS and body[cur + 4:cur + 4 + el] == b"\x03\x04":
                return False
            cur += 4 + el
        return True
    except (IndexError, struct.error):
        return False


@dataclass
class ServerHello12:
    random: bytes
    session_id: bytes
    suite: Suite
    alpn: str
    ticket_ext: bool
    status_ext: bool
    record_size_limit: Optional[int]
    # legacy_tls: sunucu bunları sunmayabilir (varsayılan modda sunmamak RED olduğundan hep True/False).
    ems: bool = True
    etm: bool = False
    secure_renegotiation: bool = True


def check_downgrade_sentinel(server_random: bytes) -> None:
    """RFC 8446 §4.1.3 — DOWNGRD sentinel'i varsa downgrade saldırısı: REDDET."""
    tail = bytes(server_random[24:32])
    if tail in (DOWNGRD_TLS12, DOWNGRD_TLS11):
        raise _err(
            AL_ILLEGAL_PARAMETER, "illegal_parameter",
            "ServerHello.random DOWNGRD sentinel'i taşıyor (RFC 8446 §4.1.3): sunucu TLS 1.3 "
            "destekliyor ama bize TLS 1.2 (veya altını) dayatılıyor — olası DOWNGRADE SALDIRISI "
            "(araya giren biri ClientHello'yu değiştirmiş olabilir). Bağlantı reddedildi."
        )


def parse_server_hello_12(sh_msg: bytes, ch: ClientHelloInfo, legacy: bool = False) -> ServerHello12:
    """TLS 1.2 ServerHello'yu (4 bayt başlık dahil) ayrıştırır ve KATI biçimde doğrular.

    ``legacy=True`` (yalnızca ``legacy_tls``): CBC/statik-RSA suite'leri kabul edilir, EMS ve
    renegotiation_info yokluğu RED yerine ``ems=False`` / ``secure_renegotiation=False`` olarak
    raporlanır (+ log uyarısı). DOWNGRD kontrolü ve diğer tüm denetimler AYNEN sürer.
    """
    if len(sh_msg) < 4 or sh_msg[0] != HS_SERVER_HELLO:
        raise _unexpected("ServerHello bekleniyordu.")
    if int.from_bytes(sh_msg[1:4], "big") != len(sh_msg) - 4:
        raise _decode("ServerHello uzunluk alanı mesajla uyuşmuyor.")
    body = sh_msg[4:]
    if len(body) < 38:
        raise _decode("ServerHello çok kısa.")
    version = struct.unpack("!H", body[:2])[0]
    random = bytes(body[2:34])

    # DOWNGRD kontrolü en önce: başka hata mesajlarının arkasında kalmasın.
    check_downgrade_sentinel(random)

    sid_len = body[34]
    if sid_len > 32:
        raise _decode("ServerHello session_id 32 bayttan uzun.")
    off = 35 + sid_len
    if len(body) < off + 3:
        raise _decode("ServerHello kesik (cipher suite/compression).")
    session_id = bytes(body[35:off])
    cs = struct.unpack("!H", body[off:off + 2])[0]
    comp = body[off + 2]
    off += 3

    if version < VERSION_TLS12:
        raise _err(AL_PROTOCOL_VERSION, "protocol_version",
                   f"Sunucu TLS 0x{version:04x} (TLS 1.1 veya altı / SSL) seçti; desteklenmiyor"
                   + (" (legacy_tls=True TLS 1.0/1.1'i AÇMAZ: BEAST, MD5+SHA-1 PRF, RFC 8996)"
                      if legacy else "")
                   + ". Yalnızca TLS 1.3 ve TLS 1.2 (güvenli alt küme) desteklenir.")
    if version != VERSION_TLS12:
        raise _illegal(f"ServerHello.server_version 0x{version:04x} geçersiz.")
    if VERSION_TLS12 not in ch.versions:
        raise _err(AL_PROTOCOL_VERSION, "protocol_version",
                   "Sunucu TLS 1.2 seçti ama ClientHello'da (supported_versions) TLS 1.2 ilan "
                   "etmemiştik; bu profil TLS 1.2 konuşmaz.")
    if comp != 0:
        raise _illegal("Sunucu null dışında bir sıkıştırma yöntemi seçti (compression yalnızca null).")

    exts: dict[int, bytes] = {}
    if off < len(body):
        if len(body) < off + 2:
            raise _decode("ServerHello extension uzunluğu kesik.")
        total = struct.unpack("!H", body[off:off + 2])[0]
        cur = off + 2
        if cur + total != len(body):
            raise _decode("ServerHello extension uzunluğu mesajla uyuşmuyor.")
        while cur < len(body):
            if cur + 4 > len(body):
                raise _decode("ServerHello extension başlığı kesik.")
            et, el = struct.unpack("!HH", body[cur:cur + 4])
            cur += 4
            if cur + el > len(body):
                raise _decode("ServerHello extension gövdesi kesik.")
            if et in exts:
                raise _illegal(f"ServerHello'da extension 0x{et:04x} tekrarlandı.")
            exts[et] = bytes(body[cur:cur + el])
            cur += el

    if legacy:
        from . import tls12_legacy as _lg
        suite = SUITES.get(cs) or _lg.LEGACY_SUITES.get(cs)
    else:
        suite = SUITES.get(cs)
    if suite is None:
        raise reject_suite_message(cs)
    if cs not in ch.suites:
        raise _illegal(f"Sunucu ClientHello'da ilan etmediğimiz suite'i (0x{cs:04x}) seçti.")

    allowed_exts = _SH_ALLOWED_EXTS
    if legacy:
        allowed_exts = _SH_ALLOWED_EXTS | {EXT_ENCRYPT_THEN_MAC}
    for et in exts:
        if et not in allowed_exts:
            raise _err(AL_UNSUPPORTED_EXTENSION, "unsupported_extension",
                       f"ServerHello TLS 1.2'de izin verilmeyen extension içeriyor: 0x{et:04x}.")
        if et not in ch.ext_types:
            raise _err(AL_UNSUPPORTED_EXTENSION, "unsupported_extension",
                       f"Sunucu istemediğimiz bir extension gönderdi: 0x{et:04x} (RFC 5246 §7.4.1.4).")

    # --- Güvenli renegotiation (RFC 5746) — varsayılanda ZORUNLU, legacy'de TERCİH ---
    secure_reneg = True
    if EXT_RENEGOTIATION_INFO not in ch.ext_types:
        if not legacy:
            raise _err(AL_HANDSHAKE_FAILURE, "handshake_failure",
                       "ClientHello'da renegotiation_info ilan edilmediği için TLS 1.2 güvenli biçimde "
                       "kurulamaz (RFC 5746).")
        secure_reneg = False
    else:
        ri = exts.get(EXT_RENEGOTIATION_INFO)
        if ri is None:
            if not legacy:
                raise _err(AL_HANDSHAKE_FAILURE, "handshake_failure",
                           "Sunucu renegotiation_info (RFC 5746) göndermedi: güvenli renegotiation "
                           "desteklenmiyor, olası renegotiation (Marsh Ray) saldırısına açık sunucu. "
                           "Bağlantı reddedildi.")
            secure_reneg = False
            _log.warning("legacy_tls: sunucu renegotiation_info (RFC 5746) sunmuyor — güvenli "
                         "renegotiation YOK; renegotiation zaten desteklenmiyor (HelloRequest reddedilir).")
        elif ri != b"\x00":
            raise _err(AL_HANDSHAKE_FAILURE, "handshake_failure",
                       "Sunucunun renegotiation_info değeri geçersiz (ilk el sıkışmada boş "
                       "renegotiated_connection beklenir) — bağlantı reddedildi.")

    # --- Extended Master Secret (RFC 7627) — varsayılanda ZORUNLU, legacy'de TERCİH ---
    ems_on = True
    if EXT_EXTENDED_MASTER_SECRET not in ch.ext_types:
        if not legacy:
            raise _err(AL_HANDSHAKE_FAILURE, "handshake_failure",
                       "ClientHello'da Extended Master Secret (RFC 7627) ilan edilmediği için TLS 1.2 "
                       "güvenli biçimde kurulamaz.")
        ems_on = False
    else:
        ems = exts.get(EXT_EXTENDED_MASTER_SECRET)
        if ems is None:
            if not legacy:
                raise _err(AL_HANDSHAKE_FAILURE, "handshake_failure",
                           "Sunucu Extended Master Secret (RFC 7627) kabul etmedi: master secret oturuma "
                           "bağlı değil, triple-handshake saldırısına açık. Bağlantı reddedildi.")
            ems_on = False
            _log.warning("legacy_tls: sunucu Extended Master Secret (RFC 7627) sunmuyor — master secret "
                         "oturum transcript'ine bağlı DEĞİL (triple-handshake saldırısına açık); "
                         "yalnızca eski sunucu uyumluluğu için kabul edildi.")
        elif ems != b"":
            raise _decode("extended_master_secret extension'ı boş olmalı.")

    # --- Encrypt-then-MAC (RFC 7366) — yalnızca legacy ---
    etm_on = False
    if legacy and EXT_ENCRYPT_THEN_MAC in exts:
        if exts[EXT_ENCRYPT_THEN_MAC] != b"":
            raise _decode("encrypt_then_mac extension'ı boş olmalı.")
        if suite.mode != "CBC":
            # RFC 7366 §3: AEAD/akış suite'inde sunucu EtM yanıtı GÖNDERMEMELİ.
            raise _illegal("Sunucu AEAD suite'i ile encrypt_then_mac gönderdi (RFC 7366 §3 ihlali).")
        etm_on = True
    if legacy and suite.mode == "CBC" and not etm_on:
        _log.warning("legacy_tls: sunucu Encrypt-then-MAC sunmuyor — CBC için MAC-then-encrypt "
                     "(Lucky13 azaltımı best-effort).")

    # --- diğer extension'lar --------------------------------------------------------
    alpn = ""
    if EXT_ALPN in exts:
        d = exts[EXT_ALPN]
        if len(d) < 3 or struct.unpack("!H", d[:2])[0] != len(d) - 2 or d[2] != len(d) - 3 or d[2] == 0:
            raise _decode("ALPN extension'ı bozuk (tek protokol adı olmalı).")
        alpn = d[3:].decode("ascii", "ignore")
        if alpn not in ch.alpn:
            raise _illegal(f"Sunucu ilan etmediğimiz ALPN protokolünü seçti: {alpn!r}.")
    if EXT_EC_POINT_FORMATS in exts:
        d = exts[EXT_EC_POINT_FORMATS]
        if not d or d[0] != len(d) - 1 or 0 not in d[1:]:
            raise _illegal("ec_point_formats uncompressed (0) biçimini içermiyor.")
    if EXT_SESSION_TICKET in exts and exts[EXT_SESSION_TICKET] != b"":
        raise _decode("ServerHello session_ticket extension'ı boş olmalı.")
    if EXT_STATUS_REQUEST in exts and exts[EXT_STATUS_REQUEST] != b"":
        raise _decode("ServerHello status_request extension'ı boş olmalı.")
    if EXT_SERVER_NAME in exts and exts[EXT_SERVER_NAME] != b"":
        raise _decode("ServerHello server_name extension'ı boş olmalı.")
    rsl = None
    if EXT_RECORD_SIZE_LIMIT in exts:
        d = exts[EXT_RECORD_SIZE_LIMIT]
        if len(d) != 2:
            raise _decode("record_size_limit 2 bayt olmalı.")
        rsl = struct.unpack("!H", d)[0]
        if rsl < 64:
            raise _illegal("record_size_limit 64'ten küçük.")

    return ServerHello12(random, session_id, suite, alpn,
                         EXT_SESSION_TICKET in exts, EXT_STATUS_REQUEST in exts, rsl,
                         ems=ems_on, etm=etm_on, secure_renegotiation=secure_reneg)


# --------------------------------------------------------------------------
# Certificate / CertificateStatus / SKE
# --------------------------------------------------------------------------
def parse_certificate_chain(msg: bytes) -> list:
    """TLS 1.2 Certificate mesajı (başlık dahil) -> [DER, ...]  (leaf ilk). KATI uzunluk kontrolü."""
    body = msg[4:]
    if len(body) < 3:
        raise _decode("Certificate mesajı çok kısa.")
    total = int.from_bytes(body[:3], "big")
    if total != len(body) - 3:
        raise _decode("Certificate liste uzunluğu mesajla uyuşmuyor.")
    certs = []
    cur = 3
    while cur < len(body):
        if cur + 3 > len(body):
            raise _decode("Certificate girdisi kesik.")
        ln = int.from_bytes(body[cur:cur + 3], "big")
        cur += 3
        if ln == 0 or cur + ln > len(body):
            raise _decode("Certificate uzunluğu hatalı.")
        certs.append(bytes(body[cur:cur + ln]))
        cur += ln
        if len(certs) > MAX_CERT_CHAIN:
            raise _illegal(f"Sertifika zinciri {MAX_CERT_CHAIN} sertifikadan uzun.")
    if not certs:
        raise _err(AL_BAD_CERTIFICATE, "bad_certificate", "Sunucu hiç sertifika göndermedi.")
    return certs


def to_tls13_certificate_message(ders: list) -> bytes:
    """TLS 1.2 zincirini, cert_validator'ın beklediği TLS 1.3 Certificate biçimine
    (boş request_context + sertifika başına boş extensions) çevirir."""
    entries = b"".join(len(d).to_bytes(3, "big") + d + b"\x00\x00" for d in ders)
    body = b"\x00" + len(entries).to_bytes(3, "big") + entries
    return bytes([HS_CERTIFICATE]) + len(body).to_bytes(3, "big") + body


def parse_certificate_status(msg: bytes) -> None:
    """CertificateStatus (OCSP stapling) yapısını doğrular. İçerik DOĞRULANMAZ (iptal
    kontrolü bu kütüphanenin kapsamında değil); yalnızca bozuk yapı reddedilir."""
    body = msg[4:]
    if len(body) < 4 or body[0] != 1:
        raise _decode("CertificateStatus bozuk (yalnızca ocsp status_type=1).")
    if int.from_bytes(body[1:4], "big") != len(body) - 4 or len(body) == 4:
        raise _decode("CertificateStatus uzunluğu tutarsız.")


_HASH_NAMES = {1: "MD5", 2: "SHA-1", 3: "SHA-224"}

#: TLS 1.2'de kabul edilen imza algoritmaları: (tür, hash adı).
SIG_ALGS = {
    0x0403: ("ecdsa", "SHA256"), 0x0503: ("ecdsa", "SHA384"), 0x0603: ("ecdsa", "SHA512"),
    0x0804: ("pss", "SHA256"), 0x0805: ("pss", "SHA384"), 0x0806: ("pss", "SHA512"),
    0x0401: ("pkcs1", "SHA256"), 0x0501: ("pkcs1", "SHA384"), 0x0601: ("pkcs1", "SHA512"),
}


@dataclass
class ServerKeyExchange:
    group: int
    public: bytes
    sigalg: int
    params: bytes
    signature: bytes


def parse_server_key_exchange(msg: bytes) -> ServerKeyExchange:
    """ECDHE ServerKeyExchange (RFC 8422 §5.4) — başlık dahil mesaj. Gövde TAMAMEN tüketilmeli."""
    body = msg[4:]
    try:
        if body[0] != 3:
            raise _illegal(f"ServerKeyExchange curve_type={body[0]}: yalnızca named_curve (3) kabul edilir "
                           f"(açık eğri parametreleri/DHE reddedilir).")
        group = struct.unpack("!H", body[1:3])[0]
        plen = body[3]
        public = bytes(body[4:4 + plen])
        if plen == 0 or len(public) != plen:
            raise _decode("ServerKeyExchange public anahtarı bozuk.")
        params_end = 4 + plen
        sigalg = struct.unpack("!H", body[params_end:params_end + 2])[0]
        slen = struct.unpack("!H", body[params_end + 2:params_end + 4])[0]
        sig = bytes(body[params_end + 4:params_end + 4 + slen])
        if slen == 0 or len(sig) != slen or params_end + 4 + slen != len(body):
            raise _decode("ServerKeyExchange imza uzunluğu/gövde uzunluğu tutarsız.")
    except (IndexError, struct.error) as e:
        raise _decode("ServerKeyExchange kesik.") from e
    return ServerKeyExchange(group, public, sigalg, bytes(body[:params_end]), sig)


def verify_server_key_exchange(ske: ServerKeyExchange, client_random: bytes, server_random: bytes,
                               leaf, suite: Suite, offered_sigalgs: list, offered_groups: list,
                               legacy: bool = False) -> int:
    """SKE imzasını ve parametrelerini doğrular. Döner: kullanılan SignatureScheme.

    ``legacy=True`` yalnızca SHA-1 imzaları (rsa_pkcs1_sha1/ecdsa_sha1) ek olarak kabul eder.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes as _h
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    if ske.group not in SUPPORTED_GROUPS:
        raise _illegal(f"Sunucu desteklenmeyen eğri seçti: {group_name(ske.group)} "
                       f"(desteklenenler: x25519, secp256r1, secp384r1).")
    if ske.group not in offered_groups:
        raise _illegal(f"Sunucu supported_groups'ta ilan etmediğimiz eğriyi ({group_name(ske.group)}) seçti.")

    alg = ske.sigalg
    hname = _HASH_NAMES.get(alg >> 8)
    sig_algs = SIG_ALGS
    if legacy:
        from .tls12_legacy import LEGACY_SIG_ALGS
        sig_algs = {**SIG_ALGS, **LEGACY_SIG_ALGS}
    if alg not in sig_algs:
        extra = f" ({hname} zayıf bir hash, reddedilir)" if hname else ""
        raise _err(AL_INSUFFICIENT_SECURITY, "insufficient_security",
                   f"ServerKeyExchange imza algoritması 0x{alg:04x} kabul edilmiyor{extra}. "
                   f"İzinli: ecdsa/rsa_pss/rsa_pkcs1 + SHA-256/384/512.")
    if alg not in offered_sigalgs:
        raise _illegal(f"Sunucu ClientHello'da ilan etmediğimiz imza algoritmasını (0x{alg:04x}) kullandı.")

    kind, hash_name = sig_algs[alg]
    pub = leaf.public_key()
    is_ec = isinstance(pub, ec.EllipticCurvePublicKey)
    is_rsa = isinstance(pub, rsa.RSAPublicKey)
    # Suite <-> sertifika anahtar türü <-> imza algoritması tutarlılığı
    if suite.auth == "ECDSA" and not is_ec:
        raise _err(AL_BAD_CERTIFICATE, "bad_certificate",
                   f"{suite.name} suite'i ECDSA sertifikası gerektirir ama anahtar {type(pub).__name__}.")
    if suite.auth == "RSA" and not is_rsa:
        raise _err(AL_BAD_CERTIFICATE, "bad_certificate",
                   f"{suite.name} suite'i RSA sertifikası gerektirir ama anahtar {type(pub).__name__}.")
    if (kind == "ecdsa") != is_ec:
        raise _illegal(f"İmza algoritması 0x{alg:04x} sertifika anahtarıyla ({type(pub).__name__}) uyumsuz.")

    signed = client_random + server_random + ske.params
    algo = getattr(_h, hash_name)()
    try:
        if kind == "ecdsa":
            pub.verify(ske.signature, signed, ec.ECDSA(algo))
        elif kind == "pss":
            pub.verify(ske.signature, signed,
                       padding.PSS(mgf=padding.MGF1(algo), salt_length=algo.digest_size), algo)
        else:
            pub.verify(ske.signature, signed, padding.PKCS1v15(), algo)
    except InvalidSignature as e:
        raise _err(AL_DECRYPT_ERROR, "decrypt_error",
                   "ServerKeyExchange imzası GEÇERSİZ — sunucu sertifikadaki özel anahtara sahip "
                   "olduğunu kanıtlayamadı (ECDHE parametreleri değiştirilmiş olabilir). Güçlü bir "
                   "MITM göstergesidir; bağlantı reddedildi.") from e
    except Exception as e:  # beklenmeyen kütüphane hatası da RED sayılır
        raise _err(AL_DECRYPT_ERROR, "decrypt_error",
                   f"ServerKeyExchange imzası doğrulanamadı: {type(e).__name__}: {e}") from e
    return alg


# --------------------------------------------------------------------------
# Handshake sıra doğrulayıcı (RFC 5246 §7.3)
# --------------------------------------------------------------------------
class HandshakeOrder12:
    """İstemci tarafı TLS 1.2 (ECDHE, tam el sıkışma) mesaj sırası.

      WAIT_SH -> ServerHello -> WAIT_CERT -> Certificate -> AFTER_CERT
      AFTER_CERT -> [CertificateStatus] -> ServerKeyExchange -> WAIT_SHD
      WAIT_SHD -> ServerHelloDone -> WAIT_TAIL      (istemci uçuşu gönderilir)
      WAIT_TAIL -> [NewSessionTicket] -> ChangeCipherSpec(kayıt katmanı) -> WAIT_FIN
      WAIT_FIN  -> Finished -> CONNECTED

    mTLS (RFC 5246 §7.3): CertificateRequest YALNIZCA ServerKeyExchange'ten sonra, ServerHelloDone'dan
    önce ve en fazla bir kez geçerlidir (durum WAIT_SHD'de kalır); başka konumda/tekrar -> unexpected_message.
    """

    _NAMES = {
        0: "HelloRequest", 1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
        11: "Certificate", 12: "ServerKeyExchange", 13: "CertificateRequest",
        14: "ServerHelloDone", 15: "CertificateVerify", 16: "ClientKeyExchange",
        20: "Finished", 22: "CertificateStatus",
    }

    def __init__(self, ticket_ok: bool = False, status_ok: bool = False, static_rsa: bool = False):
        self.state = "WAIT_SH"
        self.ticket_ok = ticket_ok
        self.status_ok = status_ok
        # legacy_tls statik RSA: ServerKeyExchange YOKTUR (Certificate -> ServerHelloDone).
        self.static_rsa = static_rsa
        self.ticket_seen = False
        self.cert_request_seen = False

    @property
    def done(self) -> bool:
        return self.state == "CONNECTED"

    def _name(self, t: int) -> str:
        return self._NAMES.get(t, f"tip {t}")

    def expect(self, hs_type: int) -> str:
        st = self.state
        if hs_type == HS_CERTIFICATE_REQUEST and not self.cert_request_seen:
            # RFC 5246 §7.3: ... ServerKeyExchange, CertificateRequest, ServerHelloDone.
            # legacy_tls statik RSA'da SKE yoktur: CR, Certificate (ya da CertificateStatus)
            # ardından gelir; sonrasında yalnızca ServerHelloDone kabul edilir.
            if st == "WAIT_SHD" or (self.static_rsa and st in ("AFTER_CERT", "WAIT_SKE")):
                self.cert_request_seen = True
                self.state = "WAIT_SHD"
                return self.state
        nxt = None
        if st == "WAIT_SH" and hs_type == HS_SERVER_HELLO:
            nxt = "WAIT_CERT"
        elif st == "WAIT_CERT" and hs_type == HS_CERTIFICATE:
            nxt = "AFTER_CERT"
        elif st == "AFTER_CERT":
            if hs_type == HS_CERTIFICATE_STATUS and self.status_ok:
                nxt = "WAIT_SKE"
            elif hs_type == HS_SERVER_KEY_EXCHANGE and not self.static_rsa:
                nxt = "WAIT_SHD"
            elif hs_type == HS_SERVER_HELLO_DONE and self.static_rsa:
                nxt = "WAIT_TAIL"
        elif st == "WAIT_SKE" and hs_type == HS_SERVER_KEY_EXCHANGE and not self.static_rsa:
            nxt = "WAIT_SHD"
        elif st == "WAIT_SKE" and hs_type == HS_SERVER_HELLO_DONE and self.static_rsa:
            nxt = "WAIT_TAIL"
        elif st == "WAIT_SHD" and hs_type == HS_SERVER_HELLO_DONE:
            nxt = "WAIT_TAIL"
        elif st == "WAIT_TAIL" and hs_type == HS_NEW_SESSION_TICKET and self.ticket_ok \
                and not self.ticket_seen:
            self.ticket_seen = True
            return st
        elif st == "WAIT_FIN" and hs_type == HS_FINISHED:
            nxt = "CONNECTED"
        if nxt is None:
            extra = ""
            if st == "WAIT_TAIL" and hs_type == HS_FINISHED:
                extra = " (ChangeCipherSpec olmadan şifresiz Finished)"
            elif hs_type == HS_NEW_SESSION_TICKET and not self.ticket_ok:
                extra = " (session_ticket extension'ını kabul etmemişti)"
            raise _unexpected(f"{st} durumunda beklenmeyen handshake mesajı: {self._name(hs_type)}.{extra}")
        self.state = nxt
        return nxt

    def check(self, hs_type: int) -> None:
        """``expect`` ile aynı denetim, ama durumu DEĞİŞTİRMEDEN."""
        probe = HandshakeOrder12(self.ticket_ok, self.status_ok, self.static_rsa)
        probe.state, probe.ticket_seen = self.state, self.ticket_seen
        probe.cert_request_seen = self.cert_request_seen
        probe.expect(hs_type)

    def on_ccs(self) -> None:
        if self.state != "WAIT_TAIL":
            raise _unexpected(f"{self.state} durumunda beklenmeyen ChangeCipherSpec.")
        self.state = "WAIT_FIN"


# --------------------------------------------------------------------------
# sans-IO istemci bağlantısı
# --------------------------------------------------------------------------
ST_WAIT_SH = "WAIT_SH"
ST_HANDSHAKE = "HANDSHAKE"
ST_CONNECTED = "CONNECTED"
ST_CLOSED = "CLOSED"


def _hs(t: int, body: bytes) -> bytes:
    return bytes([t]) + len(body).to_bytes(3, "big") + body


def _record(ctype: int, body: bytes) -> bytes:
    return struct.pack("!BHH", ctype, VERSION_TLS12, len(body)) + body


class TLS12ClientConnection:
    """sans-IO TLS 1.2 istemcisi (ECDHE + AEAD + EMS; yukarıdaki güvenlik modeli).

    Kullanım (ServerHello zaten okunmuş):
        conn = TLS12ClientConnection(host, client_hello_msg, ca_path=...)
        events = conn.start(server_hello_msg, trailing_handshake_bytes)
        send(conn.data_to_send())
        while not conn.handshake_complete: events = conn.receive_data(recv()); send(conn.data_to_send())

    client_hello_msg: gönderdiğimiz ClientHello handshake mesajı (record başlığı HARİÇ).
    Hatada TLS12Error fırlatılır, bağlantı CLOSED olur ve (uygunsa) fatal alert
    ``data_to_send()`` ile alınabilir.
    """

    def __init__(self, host: str, client_hello_msg: bytes, *, ca_path: Optional[str] = None,
                 cert_validator: Optional[Callable] = None, legacy_tls: bool = False,
                 client_cert=None):
        self.host = host
        # Eski sunucu uyumluluk modu (yalnızca açıkça istenirse; bkz. tls12_legacy.py).
        self._legacy = bool(legacy_tls)
        self.ems = True
        self.etm = False
        self.secure_renegotiation = True
        self._client_cert = client_cert
        self._cert_req: "Optional[_mtls.CertRequest12]" = None
        self.client_cert_sent = False
        self.client_signature_scheme: Optional[int] = None
        self.ca_path = ca_path
        self._cert_validator = cert_validator
        self._ch_msg = bytes(client_hello_msg)
        self._ch = parse_client_hello(self._ch_msg)
        self.state = ST_WAIT_SH

        self.suite: Optional[Suite] = None
        self.alpn = ""
        self.peer_certificate = None
        self.signature_scheme: Optional[int] = None

        self._transcript = bytearray(self._ch_msg)
        self._inbuf = bytearray()
        self._hsbuf = bytearray()
        self._out = bytearray()
        self._read: Optional[RecordCipher] = None
        self._pending_read: Optional[RecordCipher] = None
        self._write: Optional[RecordCipher] = None
        self._order: Optional[HandshakeOrder12] = None
        self._sh: Optional[ServerHello12] = None
        self._ske: Optional[ServerKeyExchange] = None
        self._master: Optional[bytes] = None
        self._max_send = MAX_PLAINTEXT
        self._hello_requests = 0
        self._close_sent = False
        self._alert_sent = False
        self._write_active = False

    # ------------------------------------------------------------- özellikler
    @property
    def handshake_complete(self) -> bool:
        return self.state == ST_CONNECTED

    @property
    def closed(self) -> bool:
        return self.state == ST_CLOSED

    @property
    def cipher_suite(self) -> Optional[int]:
        return self.suite.id if self.suite else None

    @property
    def cipher_name(self) -> str:
        return self.suite.cipher if self.suite else "CHACHA20-POLY1305"

    @property
    def key_len(self) -> int:
        return self.suite.key_len if self.suite else 32

    def crypto_state(self) -> dict:
        return {
            "is_tls13": False,
            "is_tls12": True,
            "tls_version": VERSION_TLS12,
            "using_app_keys": self.state == ST_CONNECTED,
            "cipher_name": self.cipher_name,
            "cipher_suite": self.cipher_suite,
            "key_len": self.key_len,
            "alpn": self.alpn,
            "peer_certificate": self.peer_certificate,
            "extended_master_secret": self.ems,
            "encrypt_then_mac": self.etm,
            "secure_renegotiation": self.secure_renegotiation,
            "forward_secret": self.suite is None or self.suite.kx == "ECDHE",
            "legacy_tls": self._legacy,
            "suite_name": self.suite.name if self.suite else "",
        }

    # ------------------------------------------------------------------- API
    def data_to_send(self) -> bytes:
        out = bytes(self._out)
        self._out.clear()
        return out

    def start(self, server_hello_msg: bytes, trailing: bytes = b"") -> list:
        """Okunmuş ServerHello'yu (ve aynı record'daki artık handshake baytlarını) işler."""
        if self.state != ST_WAIT_SH:
            raise TLS12Error("internal_error: start() yalnızca bir kez çağrılabilir.", AL_INTERNAL_ERROR)
        events: list = []
        try:
            self._on_server_hello(bytes(server_hello_msg))
            if trailing:
                self._feed_handshake(trailing, events)
        except TLS12Error as e:
            self._fail(e)
            raise
        return events

    def receive_data(self, data: bytes) -> list:
        if self.state == ST_WAIT_SH:
            raise TLS12Error("internal_error: receive_data() start()'tan önce çağrıldı.", AL_INTERNAL_ERROR)
        if self.state == ST_CLOSED:
            return []
        self._inbuf += data
        events: list = []
        try:
            while self.state != ST_CLOSED and len(self._inbuf) >= 5:
                rtype = self._inbuf[0]
                ver = bytes(self._inbuf[1:3])
                rlen = (self._inbuf[3] << 8) | self._inbuf[4]
                if ver[0] != 3 or ver[1] not in (1, 2, 3):
                    raise _err(AL_PROTOCOL_VERSION, "protocol_version",
                               f"record sürümü geçersiz: 0x{ver.hex()}.")
                limit = MAX_CIPHERTEXT if self._read is not None else MAX_PLAINTEXT
                if rlen > limit:
                    raise _err(AL_RECORD_OVERFLOW, "record_overflow",
                               f"TLS record uzunluğu {rlen} > {limit}.")
                if len(self._inbuf) < 5 + rlen:
                    break
                payload = bytes(self._inbuf[5:5 + rlen])
                del self._inbuf[:5 + rlen]
                self._handle_record(rtype, ver, payload, events)
        except TLS12Error as e:
            self._fail(e)
            raise
        return events

    def send_record(self, data: bytes, content_type: int = CT_APPLICATION_DATA) -> None:
        """Uygulama verisini şifreli record(lar)a çevirip çıkış tamponuna koyar."""
        if self.state == ST_CLOSED:
            raise TLS12Error("Bağlantı kapalı.", AL_INTERNAL_ERROR)
        if content_type == CT_APPLICATION_DATA and self.state != ST_CONNECTED:
            raise TLS12Error("Handshake tamamlanmadan application data gönderilemez.", AL_INTERNAL_ERROR)
        if self._write is None:
            raise TLS12Error("Yazma anahtarı yok — handshake tamamlanmadı.", AL_INTERNAL_ERROR)
        if not data:
            return
        step = self._max_send
        for i in range(0, len(data), step):
            self._out += _record(content_type, self._write.seal(content_type, data[i:i + step]))

    def send_application_data(self, data: bytes) -> bytes:
        self.send_record(data, CT_APPLICATION_DATA)
        return self.data_to_send()

    def update_keys(self, request_peer: bool = True) -> bytes:
        raise TLS12Error("TLS 1.2'de KeyUpdate yoktur (renegotiation da desteklenmez).", AL_INTERNAL_ERROR)

    def close(self) -> bytes:
        """close_notify alert'i üretir (handshake sonrası, şifreli)."""
        if self._write is not None and not self._close_sent and not self._alert_sent \
                and self.state in (ST_CONNECTED, ST_CLOSED):
            self._out += _record(CT_ALERT, self._write.seal(CT_ALERT, b"\x01\x00"))
            self._close_sent = True
        self.state = ST_CLOSED
        return self.data_to_send()

    # -------------------------------------------------------------- dahili
    def _queue_alert(self, level: int, desc: int) -> None:
        body = bytes([level, desc])
        if self._write is not None and self._write_active:
            self._out += _record(CT_ALERT, self._write.seal(CT_ALERT, body))
        else:
            self._out += _record(CT_ALERT, body)

    def _fail(self, e: TLS12Error) -> None:
        """Fatal hata: (sunucudan gelen alert değilse) alert kuyruğa al ve kapat."""
        if not isinstance(e, TLS12AlertError) and not self._alert_sent and self.state != ST_CLOSED:
            try:
                self._queue_alert(2, e.alert)
            except TLS12Error:
                pass
            self._alert_sent = True
        self.state = ST_CLOSED
        self._master = None

    def _handle_record(self, rtype: int, ver: bytes, payload: bytes, events: list) -> None:
        if rtype == CT_CHANGE_CIPHER_SPEC:
            if self._read is not None:
                raise _unexpected("ikinci ChangeCipherSpec alındı.")
            if payload != b"\x01":
                raise _illegal("ChangeCipherSpec içeriği 0x01 değil.")
            if self._hsbuf:
                raise _unexpected("handshake mesajı tamamlanmadan ChangeCipherSpec geldi.")
            if self._order is None:
                raise _unexpected("ChangeCipherSpec ServerHello'dan önce geldi.")
            self._order.on_ccs()
            self._read = self._pending_read
            self._pending_read = None
            return
        if rtype not in (CT_ALERT, CT_HANDSHAKE, CT_APPLICATION_DATA):
            raise _unexpected(f"beklenmeyen record tipi {rtype}.")

        if self._read is not None:
            pt = self._read.open(rtype, ver, payload)
            if len(pt) > MAX_PLAINTEXT:
                raise _err(AL_RECORD_OVERFLOW, "record_overflow", "çözülmüş düz metin 2^14 baytı aşıyor.")
        else:
            pt = payload

        if rtype == CT_APPLICATION_DATA:
            if self.state != ST_CONNECTED:
                raise _unexpected("handshake bitmeden application data alındı.")
            if self._hsbuf:
                raise _unexpected("yarım handshake mesajı arasında application data.")
            if pt:
                events.append(ApplicationData(pt))
            return
        if not pt:
            raise _decode("sıfır uzunluklu handshake/alert record'u.")
        if rtype == CT_ALERT:
            self._on_alert(pt, events)
            return
        self._feed_handshake(pt, events)

    def _on_alert(self, data: bytes, events: list) -> None:
        if len(data) != 2:
            raise _decode("bozuk alert.")
        level, desc = data[0], data[1]
        if desc == 0:                                   # close_notify
            if self.state != ST_CONNECTED:
                self.state = ST_CLOSED
                raise TLS12AlertError(level, desc, "Sunucu el sıkışma tamamlanmadan bağlantıyı kapattı "
                                                   "(close_notify).")
            self.state = ST_CLOSED
            events.append(ConnectionClosed(bytes(data)))
            return
        if level == 1 and desc != 0:
            # Uyarı seviyesi (ör. no_renegotiation, user_canceled): bağlantı sürer.
            return
        was_connected = self.state == ST_CONNECTED
        self.state = ST_CLOSED
        if was_connected:
            events.append(AlertReceived(level, desc))
            return
        raise TLS12AlertError(level, desc, f"Sunucu el sıkışmayı reddetti: {describe_alert(data)}")

    # ---- handshake akışı --------------------------------------------------
    def _feed_handshake(self, data: bytes, events: list) -> None:
        self._hsbuf += data
        while len(self._hsbuf) >= 4 and self.state != ST_CLOSED:
            if self._order is not None and self._hsbuf[0] != HS_HELLO_REQUEST:
                self._order.check(self._hsbuf[0])      # tip, sıraya uymuyorsa gövdeyi beklemeden reddet
            hs_len = int.from_bytes(self._hsbuf[1:4], "big")
            if hs_len > MAX_HANDSHAKE_MESSAGE:
                raise _illegal(f"handshake mesajı çok büyük ({hs_len} bayt).")
            if len(self._hsbuf) < 4 + hs_len:
                break
            msg = bytes(self._hsbuf[:4 + hs_len])
            del self._hsbuf[:4 + hs_len]
            self._handle_handshake(msg, events)

    def _handle_handshake(self, msg: bytes, events: list) -> None:
        t = msg[0]
        if t == HS_HELLO_REQUEST:
            self._on_hello_request(msg)
            return
        if self._order is None:
            raise _unexpected("ServerHello alınmadan handshake mesajı.")
        self._order.expect(t)
        if t == HS_NEW_SESSION_TICKET:
            self._transcript += msg
            self._on_new_session_ticket(msg)
        elif t == HS_CERTIFICATE:
            self._transcript += msg
            self._on_certificate(msg)
        elif t == HS_CERTIFICATE_STATUS:
            self._transcript += msg
            parse_certificate_status(msg)
        elif t == HS_SERVER_KEY_EXCHANGE:
            self._transcript += msg
            self._on_server_key_exchange(msg)
        elif t == HS_CERTIFICATE_REQUEST:
            self._transcript += msg
            try:
                self._cert_req = _mtls.parse_certificate_request_12(msg)
            except _mtls.MtlsProtocolError as e:
                raise TLS12Error(str(e), e.alert) from e
        elif t == HS_SERVER_HELLO_DONE:
            self._transcript += msg
            if len(msg) != 4:
                raise _decode("ServerHelloDone gövdesi boş olmalı.")
            if self._hsbuf:
                raise _unexpected("ServerHelloDone sonrasında aynı record'da ek handshake verisi.")
            self._send_client_flight()
        elif t == HS_FINISHED:
            self._on_server_finished(msg, events)
        else:  # pragma: no cover - HandshakeOrder12 bunu zaten engeller
            raise _unexpected(f"handshake tipi {t}.")

    def _on_hello_request(self, msg: bytes) -> None:
        if len(msg) != 4:
            raise _decode("HelloRequest gövdesi boş olmalı.")
        if self.state != ST_CONNECTED:
            # RFC 5246 §7.4.1.1: el sıkışma sürerken HelloRequest yok sayılır (transcript'e girmez).
            return
        # Renegotiation DESTEKLENMEZ: uyarı alert'i (RFC 5746 §4.2) ile reddet.
        self._hello_requests += 1
        if self._hello_requests > MAX_HELLO_REQUESTS:
            raise _err(AL_NO_RENEGOTIATION, "no_renegotiation",
                       "Sunucu tekrar tekrar renegotiation (HelloRequest) istedi; renegotiation "
                       "desteklenmiyor — bağlantı kapatıldı.")
        self._queue_alert(1, AL_NO_RENEGOTIATION)

    def _on_server_hello(self, msg: bytes) -> None:
        sh = parse_server_hello_12(msg, self._ch, self._legacy)
        self._sh = sh
        self.suite = sh.suite
        self.ems, self.etm, self.secure_renegotiation = sh.ems, sh.etm, sh.secure_renegotiation
        self.alpn = sh.alpn
        if sh.record_size_limit is not None:
            self._max_send = min(MAX_PLAINTEXT, sh.record_size_limit)
        self._order = HandshakeOrder12(ticket_ok=sh.ticket_ext, status_ok=sh.status_ext,
                                       static_rsa=sh.suite.kx == "RSA")
        self._order.expect(HS_SERVER_HELLO)
        self._transcript += msg
        self.state = ST_HANDSHAKE

    def _validate_cert(self, msg13: bytes):
        if self._cert_validator is not None:
            return self._cert_validator(msg13, self.host)
        if self.ca_path is not None:
            return _cv.validate_server_certificate(msg13, self.host, ca_path=self.ca_path)
        return _cv.validate_server_certificate(msg13, self.host)

    def _on_certificate(self, msg: bytes) -> None:
        ders = parse_certificate_chain(msg)
        try:
            self.peer_certificate = self._validate_cert(to_tls13_certificate_message(ders))
        except CertificateValidationError as e:
            raise _err(AL_BAD_CERTIFICATE, "bad_certificate",
                       f"TLS sertifika doğrulaması başarısız — bağlantı güvenli değil, "
                       f"olası MITM saldırısı: {e}") from e

    def _on_server_key_exchange(self, msg: bytes) -> None:
        ske = parse_server_key_exchange(msg)
        self.signature_scheme = verify_server_key_exchange(
            ske, self._ch.random, self._sh.random, self.peer_certificate, self.suite,
            self._ch.sigalgs, self._ch.groups, self._legacy,
        )
        self._ske = ske

    def _on_new_session_ticket(self, msg: bytes) -> None:
        """Bilet YAPISI doğrulanır, KULLANILMAZ (oturum devamı desteklenmez)."""
        body = msg[4:]
        if len(body) < 6:
            raise _decode("NewSessionTicket çok kısa.")
        tlen = struct.unpack("!H", body[4:6])[0]
        if tlen != len(body) - 6:
            raise _decode("NewSessionTicket bilet uzunluğu tutarsız.")

    def _send_client_flight(self) -> None:
        suite, ske = self.suite, self._ske
        # mTLS (RFC 5246 §7.4.6): istemci Certificate, ClientKeyExchange'ten ÖNCE gider. Uygun
        # sertifika/şema yoksa sıfır sertifikalı Certificate (sunucu karar verir).
        cert_msg = cv_scheme = None
        if self._cert_req is not None:
            cv_scheme = _mtls.select_scheme_12(self._client_cert, self._cert_req)
            cert_msg = _mtls.build_certificate_12(self._client_cert if cv_scheme is not None else None)
            self._transcript += cert_msg
        if suite.kx == "RSA":
            # legacy_tls: statik RSA — PMS sunucu sertifikası anahtarına şifrelenir (ileri gizlilik YOK).
            from . import tls12_legacy as _lg
            body, pms = _lg.rsa_client_key_exchange(
                self.peer_certificate, struct.unpack("!H", self._ch_msg[4:6])[0])
            cke = _hs(HS_CLIENT_KEY_EXCHANGE, body)
        else:
            if ske is None:  # pragma: no cover - sıra doğrulayıcı SKE'siz SHD'ye izin vermez
                raise _unexpected("ServerKeyExchange olmadan ServerHelloDone.")
            try:
                priv, my_pub = generate_key_share(ske.group)
                pms = compute_shared_secret(ske.group, priv, ske.public)
            except ValueError as e:
                raise _illegal(f"sunucunun ECDHE anahtarı geçersiz ({group_name(ske.group)}): {e}") from e
            cke = _hs(HS_CLIENT_KEY_EXCHANGE, bytes([len(my_pub)]) + my_pub)
        self._transcript += cke
        if self.ems:
            # RFC 7627 §3: session_hash ClientKeyExchange'e KADAR (CertificateVerify HARİÇ) alınır.
            session_hash = suite.hash_alg(bytes(self._transcript)).digest()
            master = extended_master_secret(suite.hash_alg, pms, session_hash)
        else:  # yalnızca legacy_tls: sunucu EMS sunmadı (parse_server_hello_12 varsayılanda reddeder)
            from . import tls12_legacy as _lg
            master = _lg.master_secret(suite.hash_alg, pms, self._ch.random, self._sh.random)
        cv_msg = None
        if cv_scheme is not None:
            # RFC 5246 §7.4.8: imza, CKE dahil önceki tüm handshake mesajları üzerinedir; Finished
            # transcript'i CertificateVerify'ı da kapsar.
            try:
                cv_msg = _mtls.build_certificate_verify_12(
                    self._client_cert, cv_scheme, bytes(self._transcript))
            except _mtls.ClientCertError as e:
                raise TLS12Error(f"internal_error: istemci CertificateVerify imzalanamadı: {e}",
                                 AL_INTERNAL_ERROR) from e
            self._transcript += cv_msg
            self.client_signature_scheme = cv_scheme
            self.client_cert_sent = True
        if suite.mode == "CBC":
            from . import tls12_legacy as _lg
            cmac, smac, ckey, skey = _lg.derive_cbc_keys(suite, master, self._sh.random, self._ch.random)
            self._pending_read = _lg.CBCRecordCipher(suite, skey, smac, self.etm)
            write = _lg.CBCRecordCipher(suite, ckey, cmac, self.etm)
        else:
            ckey, skey, civ, siv = derive_key_block(suite, master, self._sh.random, self._ch.random)
            self._pending_read = RecordCipher(suite, skey, siv)
            write = RecordCipher(suite, ckey, civ)

        verify = finished_verify_data(suite, master, b"client finished", bytes(self._transcript))
        fin = _hs(HS_FINISHED, verify)
        self._transcript += fin
        self._master = master

        if cert_msg is not None:
            self._out += _record(CT_HANDSHAKE, cert_msg)
        self._out += _record(CT_HANDSHAKE, cke)
        if cv_msg is not None:
            self._out += _record(CT_HANDSHAKE, cv_msg)
        self._out += _record(CT_CHANGE_CIPHER_SPEC, b"\x01")
        self._write = write                    # CCS'ten sonra: Finished şifreli gider
        self._write_active = True
        self._out += _record(CT_HANDSHAKE, write.seal(CT_HANDSHAKE, fin))

    def _on_server_finished(self, msg: bytes, events: list) -> None:
        if self._read is None:  # pragma: no cover - CCS olmadan WAIT_FIN'e girilemez
            raise _unexpected("şifresiz Finished.")
        if len(msg) != 4 + 12:
            raise _decode("Finished verify_data 12 bayt olmalı.")
        expected = finished_verify_data(self.suite, self._master, b"server finished",
                                        bytes(self._transcript))
        if not hmac.compare_digest(expected, msg[4:]):
            raise _err(AL_DECRYPT_ERROR, "decrypt_error",
                       "Sunucunun Finished verify_data'sı uyuşmuyor — handshake transcript'i "
                       "üzerinde anlaşamadık. Bu, araya girme veya veri değiştirme göstergesidir; "
                       "bağlantı reddedildi.")
        if self._hsbuf:
            raise _unexpected("Finished sonrasında aynı record'da ek handshake verisi.")
        self._transcript += msg
        self._master = None
        self.state = ST_CONNECTED
        events.append(HandshakeComplete(
            cipher_suite=self.suite.id, alpn=self.alpn,
            peer_certificate=self.peer_certificate, signature_scheme=self.signature_scheme,
        ))


# --------------------------------------------------------------------------
# Senkron yol
# --------------------------------------------------------------------------
def negotiate_tls12(raw_socket, host: str, client_hello_record: bytes, server_hello_msg: bytes,
                    trailing: bytes = b"", *, ca_path: Optional[str] = None, legacy_tls: bool = False,
                    client_cert=None):
    """TLS 1.2 el sıkışmasını tamamlar ve EncryptedSocket arayüzlü bir nesne döner.

    ``client_hello_record``: gönderdiğimiz ClientHello (5 bayt record başlığı DAHİL).
    ``server_hello_msg``: okunmuş ServerHello handshake mesajı; ``trailing``: aynı
    record'da ServerHello'yu izleyen ek handshake baytları.
    """
    from ..tls13.sync_socket import SyncTLSSocket

    conn = TLS12ClientConnection(host, client_hello_record[5:], ca_path=ca_path, legacy_tls=legacy_tls,
                                 client_cert=client_cert)
    sock = SyncTLSSocket(raw_socket, conn)

    def flush() -> None:
        out = conn.data_to_send()
        if out:
            raw_socket.sendall(out)

    def flush_quiet() -> None:
        try:
            flush()
        except OSError:
            pass

    try:
        sock._records.extend(conn.start(server_hello_msg, trailing))
        flush()
        while not conn.handshake_complete:
            data = raw_socket.recv(65536)
            if not data:
                raise ConnectionResetError("TLS 1.2 handshake sırasında sunucu bağlantıyı kapattı.")
            sock._records.extend(conn.receive_data(data))
            flush()
    except TLS12Error:
        flush_quiet()          # fatal alert (varsa) best-effort gönder
        raise
    return sock
