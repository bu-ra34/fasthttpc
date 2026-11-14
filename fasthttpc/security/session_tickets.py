"""
TLS 1.3 PSK session resumption (RFC 8446 §4.6.1, §4.2.11, §7.1).

Bu modül saf (I/O içermeyen) yardımcılar sunar:

  * NewSessionTicket ayrıştırma
  * resumption_master_secret -> PSK türetme
  * host başına, thread-safe, tek-kullanımlık bilet önbelleği
  * ClientHello için pre_shared_key uzantısı + binder hesaplama
  * PSK'lı (psk_dhe_ke) handshake anahtar takvimi

Handshake entegrasyonu (tls_adapter.negotiate) bir bayrak arkasındadır ve
VARSAYILAN OLARAK KAPALIDIR. Açmak için:

    from fasthttpc.security import session_tickets
    session_tickets.enable_resumption(True)

ya da ortam değişkeni FASTHTTPC_TLS_RESUMPTION=1.

Yalnızca psk_dhe_ke modu kullanılır (her bağlantıda yine taze ECDHE; ileri
gizlilik korunur). 0-RTT (early data) BİLEREK desteklenmez — replay'e açıktır.

Senkron / async paylaşımı (KARAR): senkron yol (tls_adapter.negotiate) ve async
sans-IO çekirdek (tls13/connection.py) AYNI süreç içi `default_cache`'i ve
AYNI saf fonksiyonları (begin_resumption, check_psk_selection,
store_new_session_tickets) kullanır. Bir bilet yalnızca anahtarı birebir
eşleşen bağlantıda geçerlidir: (host, port, ca_path) — yani aynı güven kökünde
doğrulanmış aynı hedef. Senkron alınan bilet bu yüzden async'te (ve tersi)
kullanılabilir; bilet tek kullanımlık olduğundan iki yol aynı PSK'yı asla iki
kez göndermez. İstisna: async çekirdeğe ÖZEL `cert_validator` verildiyse
resumption hiç teklif edilmez ve bilet saklanmaz (kimliğin hangi güven
kökünden geldiği bilinemez). Profil/ALPN anahtara girmez: sunucu ALPN'yi
resumption'da yeniden seçer (EE) ve parmak izi güvenlik sınırı değildir.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Optional

from ..crypto_math import PureCryptoEngine

_expand_label = PureCryptoEngine.tls13_hkdf_expand_label
_extract = PureCryptoEngine.hkdf_extract

EXT_PRE_SHARED_KEY = 41
EXT_PSK_KEY_EXCHANGE_MODES = 45
EXT_EARLY_DATA = 42
PSK_DHE_KE = 1

# RFC 8446 §4.6.1: ticket_lifetime 7 günü aşamaz.
MAX_TICKET_LIFETIME = 7 * 24 * 3600

_SUITE_HASH = {0x1301: hashlib.sha256, 0x1302: hashlib.sha384, 0x1303: hashlib.sha256}

# ---------------------------------------------------------------------------
# Bayrak
# ---------------------------------------------------------------------------
_enabled = os.environ.get("FASTHTTPC_TLS_RESUMPTION", "").strip().lower() in ("1", "true", "yes", "on")


def enable_resumption(on: bool = True) -> None:
    """PSK resumption'ı süreç genelinde açar/kapatır (varsayılan: kapalı)."""
    global _enabled
    _enabled = bool(on)


def resumption_enabled() -> bool:
    return _enabled


class TicketError(ValueError):
    """Bozuk NewSessionTicket veya ClientHello."""


# ---------------------------------------------------------------------------
# NewSessionTicket (RFC 8446 §4.6.1)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class NewSessionTicket:
    lifetime: int
    age_add: int
    nonce: bytes
    ticket: bytes
    max_early_data: int = 0


def parse_new_session_ticket(msg: bytes) -> NewSessionTicket:
    """hs_type(1)+len(3) başlığı DAHİL ham NewSessionTicket mesajını ayrıştırır.

        uint32 ticket_lifetime; uint32 ticket_age_add;
        opaque ticket_nonce<0..255>; opaque ticket<1..2^16-1>;
        Extension extensions<0..2^16-2>;
    """
    if len(msg) < 4 or msg[0] != 4:
        raise TicketError("NewSessionTicket değil (hs_type != 4).")
    body_len = int.from_bytes(msg[1:4], "big")
    body = msg[4:4 + body_len]
    if len(body) != body_len:
        raise TicketError("NewSessionTicket kesilmiş.")
    try:
        lifetime, age_add = struct.unpack_from("!II", body, 0)
        pos = 8
        nlen = body[pos]; pos += 1
        nonce = bytes(body[pos:pos + nlen]); pos += nlen
        if len(nonce) != nlen:
            raise TicketError("ticket_nonce kesilmiş.")
        tlen = struct.unpack_from("!H", body, pos)[0]; pos += 2
        ticket = bytes(body[pos:pos + tlen]); pos += tlen
        if tlen == 0 or len(ticket) != tlen:
            raise TicketError("ticket alanı boş veya kesilmiş.")
        elen = struct.unpack_from("!H", body, pos)[0]; pos += 2
        ext_end = pos + elen
        if ext_end != len(body):
            raise TicketError("NewSessionTicket uzantı uzunluğu tutarsız.")
        max_early = 0
        while pos + 4 <= ext_end:
            etype, el = struct.unpack_from("!HH", body, pos); pos += 4
            if pos + el > ext_end:
                raise TicketError("NewSessionTicket uzantısı kesilmiş.")
            if etype == EXT_EARLY_DATA and el == 4:
                max_early = struct.unpack_from("!I", body, pos)[0]
            pos += el
        if pos != ext_end:
            raise TicketError("NewSessionTicket uzantıları bozuk.")
    except (struct.error, IndexError) as e:
        raise TicketError(f"NewSessionTicket bozuk: {e}") from e
    return NewSessionTicket(lifetime, age_add, nonce, ticket, max_early)


# ---------------------------------------------------------------------------
# Anahtar takvimi
# ---------------------------------------------------------------------------
def derive_master_secret(handshake_secret: bytes, hash_alg=hashlib.sha256) -> bytes:
    hl = hash_alg().digest_size
    derived = _expand_label(handshake_secret, "derived", hash_alg(b"").digest(), hl, hash_alg=hash_alg)
    return _extract(derived, b"\x00" * hl, hash_alg=hash_alg)


def derive_resumption_master_secret(handshake_secret: bytes, transcript_hash: bytes,
                                    hash_alg=hashlib.sha256) -> bytes:
    """resumption_master_secret = Derive-Secret(master_secret, "res master",
    ClientHello...client Finished). transcript_hash client Finished DAHİL olmalı."""
    ms = derive_master_secret(handshake_secret, hash_alg)
    return _expand_label(ms, "res master", transcript_hash, hash_alg().digest_size, hash_alg=hash_alg)


def derive_psk(resumption_master_secret: bytes, ticket_nonce: bytes, hash_alg=hashlib.sha256) -> bytes:
    """PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)."""
    return _expand_label(resumption_master_secret, "resumption", ticket_nonce,
                         hash_alg().digest_size, hash_alg=hash_alg)


def derive_early_secret(psk: Optional[bytes], hash_alg=hashlib.sha256) -> bytes:
    hl = hash_alg().digest_size
    return _extract(b"\x00" * hl, psk if psk is not None else b"\x00" * hl, hash_alg=hash_alg)


def compute_binder(psk: bytes, transcript_hash: bytes, hash_alg=hashlib.sha256) -> bytes:
    """Resumption PSK binder'ı: HMAC(finished_key(binder_key), Transcript-Hash(truncated CH))."""
    hl = hash_alg().digest_size
    early = derive_early_secret(psk, hash_alg)
    binder_key = _expand_label(early, "res binder", hash_alg(b"").digest(), hl, hash_alg=hash_alg)
    finished_key = _expand_label(binder_key, "finished", b"", hl, hash_alg=hash_alg)
    return hmac.new(finished_key, transcript_hash, hash_alg).digest()


def derive_handshake_keys_psk(psk: Optional[bytes], shared_secret: bytes, handshake_hash: bytes,
                              key_len: int, hash_alg=hashlib.sha256):
    """PureCryptoEngine.derive_tls13_keys ile aynı dönüş, ama early_secret PSK'dan türetilir.

    Döner: (handshake_secret, c_key, c_iv, s_key, s_iv, c_hts, s_hts)
    psk=None ise derive_tls13_keys ile birebir aynı sonucu verir.
    """
    hl = hash_alg().digest_size
    early = derive_early_secret(psk, hash_alg)
    derived = _expand_label(early, "derived", hash_alg(b"").digest(), hl, hash_alg=hash_alg)
    hs = _extract(derived, shared_secret, hash_alg=hash_alg)
    c_hts = _expand_label(hs, "c hs traffic", handshake_hash, hl, hash_alg=hash_alg)
    s_hts = _expand_label(hs, "s hs traffic", handshake_hash, hl, hash_alg=hash_alg)
    return (
        hs,
        _expand_label(c_hts, "key", b"", key_len, hash_alg=hash_alg),
        _expand_label(c_hts, "iv", b"", 12, hash_alg=hash_alg),
        _expand_label(s_hts, "key", b"", key_len, hash_alg=hash_alg),
        _expand_label(s_hts, "iv", b"", 12, hash_alg=hash_alg),
        c_hts, s_hts,
    )


# ---------------------------------------------------------------------------
# Bilet + önbellek
# ---------------------------------------------------------------------------
@dataclass
class SessionTicket:
    host: str  # önbellek anahtarı: cache_key(host, port, ca_path) ya da düz host adı
    ticket: bytes
    psk: bytes
    cipher_suite: int
    age_add: int
    lifetime: int
    received_at: float = field(default_factory=time.time)
    max_early_data: int = 0
    peer_certificate: object = None

    @property
    def hash_alg(self):
        return _SUITE_HASH[self.cipher_suite]

    def is_expired(self, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        return now - self.received_at >= min(self.lifetime, MAX_TICKET_LIFETIME) or now < self.received_at

    def obfuscated_age(self, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now
        age_ms = int((now - self.received_at) * 1000)
        return (age_ms + self.age_add) & 0xFFFFFFFF


def ticket_from_message(host: str, nst: NewSessionTicket, resumption_master_secret: bytes,
                        cipher_suite: int, peer_certificate=None,
                        now: Optional[float] = None) -> Optional[SessionTicket]:
    """NewSessionTicket + resumption secret'tan önbelleğe konabilir SessionTicket üretir.
    lifetime 0 ise (sunucu 'saklama' diyor) veya suite bilinmiyorsa None döner."""
    if nst.lifetime == 0 or cipher_suite not in _SUITE_HASH:
        return None
    hash_alg = _SUITE_HASH[cipher_suite]
    return SessionTicket(
        host=host.lower(),
        ticket=nst.ticket,
        psk=derive_psk(resumption_master_secret, nst.nonce, hash_alg),
        cipher_suite=cipher_suite,
        age_add=nst.age_add,
        lifetime=min(nst.lifetime, MAX_TICKET_LIFETIME),
        received_at=time.time() if now is None else now,
        max_early_data=nst.max_early_data,
        peer_certificate=peer_certificate,
    )


def cache_key(host: str, port=None, ca_path=None, client_id: Optional[str] = None) -> str:
    """Bilet önbelleği anahtarı.

    Resumption'da sertifika YENİDEN doğrulanmaz; kimlik bileti veren handshake'ten
    devralınır. Bu yüzden anahtar, o handshake'i doğrulayan güven kökünü (ca_path)
    ve hedef portu içermelidir — aksi halde verify="kurumsal-ca.pem" ile açılan bir
    oturum, başka bir güven deposuyla doğrulanmış bağlantının biletini kullanabilir.

    mTLS: ``client_id`` (ClientCert.identity) anahtara girer. Sunucu bileti, bileti alan
    handshake'teki istemci kimliğine bağlayabilir; sertifikasız (veya başka sertifikalı) bir
    oturum, sertifikalı oturumun biletiyle onun yetkilerine PSK üzerinden devam EDEMEZ.
    Sertifikasız anahtar biçimi eskisiyle aynıdır.
    """
    ca = os.path.abspath(os.fspath(ca_path)) if ca_path is not None else ""
    key = f"{host.lower()}|{port if port is not None else ''}|{ca}"
    return key if not client_id else f"{key}|{client_id}"


class TicketCache:
    """Host başına bilet önbelleği. Thread-safe; biletler TEK KULLANIMLIKTIR
    (RFC 8446 Ek C.4: aynı bileti tekrar kullanmak bağlantıların ilişkilendirilmesine
    yol açar). Host sayısı LRU ile sınırlıdır."""

    def __init__(self, max_hosts: int = 256, max_per_host: int = 4):
        self.max_hosts = max_hosts
        self.max_per_host = max_per_host
        self._lock = threading.Lock()
        self._data: "OrderedDict[str, deque]" = OrderedDict()

    def put(self, ticket: SessionTicket) -> None:
        key = ticket.host.lower()
        with self._lock:
            q = self._data.get(key)
            if q is None:
                q = deque(maxlen=self.max_per_host)
                self._data[key] = q
            self._data.move_to_end(key)
            q.append(ticket)
            while len(self._data) > self.max_hosts:
                self._data.popitem(last=False)

    def pop(self, host: str, now: Optional[float] = None) -> Optional[SessionTicket]:
        """Host için en yeni, süresi dolmamış bileti çıkarıp döner."""
        key = host.lower()
        with self._lock:
            q = self._data.get(key)
            while q:
                t = q.pop()
                if not t.is_expired(now):
                    if not q:
                        del self._data[key]
                    return t
            self._data.pop(key, None)
            return None

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        with self._lock:
            return sum(len(q) for q in self._data.values())


default_cache = TicketCache()


# ---------------------------------------------------------------------------
# ClientHello yardımcıları
# ---------------------------------------------------------------------------
def build_pre_shared_key_extension(identity: bytes, obfuscated_age: int, hash_len: int) -> bytes:
    """Tek kimlikli pre_shared_key uzantısı (binder sıfır baytlarla yer tutucu).
    ClientHello'nun SON uzantısı olmalıdır."""
    identities = struct.pack("!H", len(identity)) + identity + struct.pack("!I", obfuscated_age)
    binders = bytes([hash_len]) + b"\x00" * hash_len
    body = struct.pack("!H", len(identities)) + identities + struct.pack("!H", len(binders)) + binders
    return struct.pack("!HH", EXT_PRE_SHARED_KEY, len(body)) + body


def _locate_extensions(hello_msg: bytes) -> tuple[int, int]:
    """ClientHello handshake mesajında (hs başlığı dahil) uzantı bloğunun
    (ext_len alanının ofseti, uzantıların bitiş ofseti) değerini döner."""
    if len(hello_msg) < 4 or hello_msg[0] != 1:
        raise TicketError("ClientHello değil.")
    try:
        pos = 4 + 2 + 32
        pos += 1 + hello_msg[pos]
        pos += 2 + struct.unpack_from("!H", hello_msg, pos)[0]
        pos += 1 + hello_msg[pos]
        ext_len = struct.unpack_from("!H", hello_msg, pos)[0]
    except (struct.error, IndexError) as e:
        raise TicketError(f"ClientHello bozuk: {e}") from e
    if pos + 2 + ext_len != len(hello_msg):
        raise TicketError("ClientHello uzantı uzunluğu tutarsız.")
    return pos, pos + 2 + ext_len


def client_hello_extension_types(record_or_msg: bytes) -> list[int]:
    msg = record_or_msg[5:] if record_or_msg[:1] == b"\x16" else record_or_msg
    ext_off, end = _locate_extensions(msg)
    pos, out = ext_off + 2, []
    while pos + 4 <= end:
        t, ln = struct.unpack_from("!HH", msg, pos)
        out.append(t)
        pos += 4 + ln
    return out


def append_tail_extension(record: bytes, ext: bytes) -> bytes:
    """ClientHello record'unun sonuna bir uzantı ekler ve uzunluk alanlarını düzeltir.
    (tls_crafter'ın extra_tail_extensions kancası yoksa kullanılan geri dönüş yolu.)"""
    msg = bytearray(record[5:])
    ext_off, _end = _locate_extensions(bytes(msg))
    msg += ext
    struct.pack_into("!H", msg, ext_off, struct.unpack_from("!H", msg, ext_off)[0] + len(ext))
    msg[1:4] = (len(msg) - 4).to_bytes(3, "big")
    return record[:3] + struct.pack("!H", len(msg)) + bytes(msg)


def finalize_binder(record: bytes, psk: bytes, hash_alg=hashlib.sha256, prior_transcript: bytes = b"") -> bytes:
    """Sonu sıfır binder'lı pre_shared_key ile biten ClientHello record'unda binder'ı
    hesaplayıp yerine yazar. prior_transcript: HRR durumunda message_hash+HRR."""
    hl = hash_alg().digest_size
    tail = 2 + 1 + hl  # binders_len + binder_len + binder
    msg = record[5:]
    if client_hello_extension_types(msg)[-1:] != [EXT_PRE_SHARED_KEY]:
        raise TicketError("pre_shared_key ClientHello'nun son uzantısı değil.")
    truncated = msg[:-tail]
    binder = compute_binder(psk, hash_alg(prior_transcript + truncated).digest(), hash_alg)
    return record[:-hl] + binder


def build_resumption_client_hello(impersonator, ticket: SessionTicket, now: Optional[float] = None):
    """Bilet ile PSK'lı ClientHello üretir. Döner: (record, priv_key, client_random)
    ya da profil psk_key_exchange_modes içermiyorsa None (o zaman tam handshake)."""
    hl = ticket.hash_alg().digest_size
    ext = build_pre_shared_key_extension(ticket.ticket, ticket.obfuscated_age(now), hl)
    try:
        record, priv, rand = impersonator.build_client_hello(extra_tail_extensions=ext)
    except TypeError:
        record, priv, rand = impersonator.build_client_hello()
        if EXT_PSK_KEY_EXCHANGE_MODES not in client_hello_extension_types(record):
            return None
        record = append_tail_extension(record, ext)
    if EXT_PSK_KEY_EXCHANGE_MODES not in client_hello_extension_types(record):
        return None
    record = finalize_binder(record, ticket.psk, ticket.hash_alg)
    impersonator.last_client_hello = record
    return record, priv, rand


# ---------------------------------------------------------------------------
# Senkron (tls_adapter.negotiate) ve async sans-IO çekirdek (tls13/connection.py)
# ORTAK saf mantık. İki yol da yalnızca bunları kullanır; PSK kuralları tek yerde.
# ---------------------------------------------------------------------------
class PskViolation(ValueError):
    """Sunucunun PSK davranışı protokol ihlali (çağıran uygun hata tipine çevirir)."""


def resumption_key(host: str, port=None, ca_path=None, client_id: Optional[str] = None) -> Optional[str]:
    """Bayrak açıksa cache_key, kapalıysa None (None = bu bağlantıda resumption yok)."""
    return cache_key(host, port, ca_path, client_id) if _enabled else None


def begin_resumption(impersonator, key: Optional[str]):
    """ClientHello'yu kurar; key verilmiş ve önbellekte bilet varsa PSK'lı kurar.

    Döner: (record, priv_key, client_random, ticket_or_None). Bilet TÜKETİLİR
    (tek kullanımlık); profil PSK modlarını desteklemiyorsa bilet yine tüketilir
    ve düz ClientHello kurulur. key=None -> düz ClientHello, önbelleğe dokunulmaz.
    """
    ticket = default_cache.pop(key) if key is not None else None
    hello = build_resumption_client_hello(impersonator, ticket) if ticket is not None else None
    if hello is None:
        record, priv, rand = impersonator.build_client_hello()
        return record, priv, rand, None
    record, priv, rand = hello
    return record, priv, rand, ticket


def check_psk_selection(ticket: Optional[SessionTicket], selected_identity: Optional[int],
                        cipher_suite: int, hello_retry: bool) -> bool:
    """ServerHello pre_shared_key kararını doğrular. True = PSK kabul edildi.

    PskViolation: HRR sonrası PSK seçimi (CH2'de PSK teklif edilmez), teklif
    edilmemiş kimlik (bilet yok ya da selected_identity != 0), ya da biletin
    hash'iyle uyumsuz cipher suite (RFC 8446 §4.2.11).
    """
    if selected_identity is None:
        return False
    if hello_retry:
        raise PskViolation("Sunucu HRR sonrası teklif edilmemiş bir PSK'yı seçti — protokol ihlali.")
    if ticket is None or selected_identity != 0:
        raise PskViolation("Sunucu teklif etmediğimiz bir PSK kimliğini seçti — protokol ihlali.")
    if _SUITE_HASH.get(cipher_suite) is not ticket.hash_alg:
        raise PskViolation("Sunucu PSK'yı kabul etti ama biletin hash'iyle uyumsuz bir cipher suite seçti.")
    return True


def store_new_session_tickets(key: Optional[str], messages: bytes, resumption_master_secret: Optional[bytes],
                              cipher_suite: int, peer_certificate=None) -> int:
    """Ham NewSessionTicket mesaj(lar)ını (art arda olabilir, hs başlığı dahil)
    ayrıştırıp önbelleğe koyar. Bozuk bilet sessizce bırakılır (resumption bir
    optimizasyondur; bağlantı düşmez). Döner: saklanan bilet sayısı."""
    if not resumption_master_secret or not key:
        return 0
    pos = stored = 0
    while pos + 4 <= len(messages) and messages[pos] == 4:
        end = pos + 4 + int.from_bytes(messages[pos + 1:pos + 4], "big")
        try:
            nst = parse_new_session_ticket(messages[pos:end])
        except TicketError:
            break
        ticket = ticket_from_message(key, nst, resumption_master_secret, cipher_suite,
                                     peer_certificate=peer_certificate)
        if ticket is not None:
            default_cache.put(ticket)
            stored += 1
        pos = end
    return stored
