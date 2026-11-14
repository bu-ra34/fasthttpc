"""
fasthttpc — ESKİ SUNUCU UYUMLULUK MODU (``legacy_tls=True``), YALNIZCA AÇIKÇA İSTENİRSE.

Varsayılan davranış (``legacy_tls=False``) DEĞİŞMEZ: bu modüldeki hiçbir tablo/ayar
varsayılan yolda kullanılmaz. Buradaki her gevşetme bilinçli, dar ve belgelidir:

  GEVŞETİLEN (yalnızca legacy_tls=True)
    * TLS 1.2 CBC suite'leri: ECDHE-{ECDSA,RSA}-AES{128,256}-CBC-{SHA,SHA256,SHA384}
      (0xC009 0xC00A 0xC013 0xC014 0xC023 0xC024 0xC027 0xC028).
    * Statik RSA anahtar değişimi (ileri gizlilik YOK): 0x009C 0x009D (GCM) ve
      0x002F 0x0035 0x003C 0x003D (CBC).
    * Extended Master Secret ve renegotiation_info TERCİH edilir; sunucu desteklemiyorsa
      bağlantı kabul edilir ama log uyarısı verilir ve ``tls_info``/state'te
      ``extended_master_secret=False`` / ``secure_renegotiation=False`` görünür.
    * ServerKeyExchange'te SHA-1 imzalar (rsa_pkcs1_sha1 0x0201, ecdsa_sha1 0x0203).

  GEVŞETİLMEYEN (legacy modda da AYNEN geçerli)
    * Sertifika zinciri/hostname/süre doğrulaması.
    * DOWNGRD sentinel kontrolü (TLS 1.3 teklif ettiğimiz halde TLS 1.2 dayatılıyorsa RED).
    * ServerKeyExchange imzası doğrulaması, Finished doğrulaması, sıra doğrulaması.
    * TLS 1.0/1.1 ve SSLv3 HÂLÂ REDDEDİLİR (bkz. README "Legacy TLS" ve NOTES4).
    * RC4/3DES/export/anonim/DHE/PSK: yok.

CBC kayıt katmanı:
  * TLS 1.1+ açık (rastgele, kayıt başına) IV.
  * Sunucu Encrypt-then-MAC (RFC 7366) kabul ederse EtM (ClientHello'da ilan edilir;
    tercih edilen). Aksi halde MAC-then-encrypt.
  * MtE'de Lucky13 azaltımı (BEST-EFFORT; saf Python gerçek sabit-zamanlı OLAMAZ):
    padding hatası ``padlen=0`` sayılır ve MAC HER ZAMAN tam hesaplanır, hash edilen
    toplam bayt miktarı padding'e bağlı kalmasın diye artan kısım için sahte HMAC
    çalıştırılır; padding hatası ile MAC hatası TEK bir yoldan, aynı ``bad_record_mac``
    alert'i ve aynı mesajla raporlanır. EtM'de MAC önce doğrulanır (oracle yok).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import Optional

from .tls12 import (
    AL_BAD_CERTIFICATE,
    AL_BAD_RECORD_MAC,
    AL_INTERNAL_ERROR,
    EXT_ENCRYPT_THEN_MAC,
    SEQ_LIMIT,
    VERSION_TLS12,
    Suite,
    _err,
    prf,
)

#: Legacy modda ClientHello'ya (listede yoksa) SONA eklenen suite'ler — bu sırayla.
#: Profilde zaten olanlar tekrarlanmaz (yalnızca kabul tarafı açılır).
LEGACY_OFFER_ORDER = (
    0xC009, 0xC00A, 0xC013, 0xC014, 0xC023, 0xC024, 0xC027, 0xC028,
    0x009C, 0x009D, 0x002F, 0x0035, 0x003C, 0x003D,
)

#: Legacy modda ClientHello signature_algorithms SONUNA eklenenler.
LEGACY_SIGALGS = (0x0201, 0x0203)
#: Legacy modda kabul edilen EK ServerKeyExchange imza algoritmaları: (tür, hash adı).
LEGACY_SIG_ALGS = {
    0x0201: ("pkcs1", "SHA1"),
    0x0203: ("ecdsa", "SHA1"),
}


def _cbc(id_, name, auth, key_len, mac, prf_hash, kx="ECDHE"):
    return Suite(id_, name, auth, "AES-CBC", key_len, 0, prf_hash,
                 kx=kx, mode="CBC", mac_hash=mac, mac_len=mac().digest_size)


_S1, _S256, _S384 = hashlib.sha1, hashlib.sha256, hashlib.sha384

LEGACY_SUITES: dict[int, Suite] = {
    0xC009: _cbc(0xC009, "ECDHE-ECDSA-AES128-SHA", "ECDSA", 16, _S1, _S256),
    0xC00A: _cbc(0xC00A, "ECDHE-ECDSA-AES256-SHA", "ECDSA", 32, _S1, _S256),
    0xC013: _cbc(0xC013, "ECDHE-RSA-AES128-SHA", "RSA", 16, _S1, _S256),
    0xC014: _cbc(0xC014, "ECDHE-RSA-AES256-SHA", "RSA", 32, _S1, _S256),
    0xC023: _cbc(0xC023, "ECDHE-ECDSA-AES128-SHA256", "ECDSA", 16, _S256, _S256),
    0xC024: _cbc(0xC024, "ECDHE-ECDSA-AES256-SHA384", "ECDSA", 32, _S384, _S384),
    0xC027: _cbc(0xC027, "ECDHE-RSA-AES128-SHA256", "RSA", 16, _S256, _S256),
    0xC028: _cbc(0xC028, "ECDHE-RSA-AES256-SHA384", "RSA", 32, _S384, _S384),
    0x009C: Suite(0x009C, "AES128-GCM-SHA256", "RSA", "AES", 16, 4, _S256, kx="RSA"),
    0x009D: Suite(0x009D, "AES256-GCM-SHA384", "RSA", "AES", 32, 4, _S384, kx="RSA"),
    0x002F: _cbc(0x002F, "AES128-SHA", "RSA", 16, _S1, _S256, kx="RSA"),
    0x0035: _cbc(0x0035, "AES256-SHA", "RSA", 32, _S1, _S256, kx="RSA"),
    0x003C: _cbc(0x003C, "AES128-SHA256", "RSA", 16, _S256, _S256, kx="RSA"),
    0x003D: _cbc(0x003D, "AES256-SHA256", "RSA", 32, _S256, _S256, kx="RSA"),
}


def normalize_legacy(value) -> bool:
    """``legacy_tls`` bayrağını doğrular. Yalnızca bool; TLS 1.0/1.1 AÇIKÇA desteklenmez."""
    if value is True or value is False:
        return value
    if isinstance(value, str) and value.lower() in ("tls1.0", "tls1.1", "tls1", "ssl3"):
        raise ValueError(
            f"legacy_tls={value!r}: TLS 1.0/1.1 ve SSLv3 DESTEKLENMİYOR (BEAST/implicit IV, "
            f"MD5+SHA-1 PRF, RFC 8996 ile kullanımdan kaldırıldı). legacy_tls=True yalnızca "
            f"TLS 1.2'nin CBC/statik-RSA/EMS'siz eski sunucularını açar."
        )
    raise TypeError(f"legacy_tls bool olmalı (True/False), verilen: {value!r}")


# --------------------------------------------------------------------------
# Anahtar türetme (CBC)
# --------------------------------------------------------------------------
def master_secret(hash_alg, pre_master: bytes, client_random: bytes, server_random: bytes) -> bytes:
    """RFC 5246 §8.1 (EMS YOKSA): PRF(pms, "master secret", client_random + server_random)[0..47]."""
    return prf(hash_alg, pre_master, b"master secret", client_random + server_random, 48)


def derive_cbc_keys(suite: Suite, master: bytes, server_random: bytes, client_random: bytes):
    """(client_mac, server_mac, client_key, server_key). TLS 1.1+ CBC: sabit IV YOK (RFC 5246 §6.3)."""
    m, k = suite.mac_len, suite.key_len
    kb = prf(suite.hash_alg, master, b"key expansion", server_random + client_random, 2 * m + 2 * k)
    return kb[:m], kb[m:2 * m], kb[2 * m:2 * m + k], kb[2 * m + k:2 * m + 2 * k]


# --------------------------------------------------------------------------
# CBC kayıt koruması
# --------------------------------------------------------------------------
def _bad_mac() -> "object":
    # TEK mesaj/TEK alert: padding hatası, MAC hatası ve yapısal hata birbirinden ayırt edilemez.
    return _err(AL_BAD_RECORD_MAC, "bad_record_mac", "TLS record'u doğrulanamadı.")


class CBCRecordCipher:
    """Tek yön için TLS 1.2 AES-CBC + HMAC kayıt koruması (MtE veya EtM). ``RecordCipher`` ile aynı yüzey."""

    __slots__ = ("suite", "key", "mac_key", "etm", "seq")

    def __init__(self, suite: Suite, key: bytes, mac_key: bytes, etm: bool):
        self.suite = suite
        self.key = key
        self.mac_key = mac_key
        self.etm = etm
        self.seq = 0

    @property
    def overhead(self) -> int:
        return 16 + self.suite.mac_len + 1

    def _check_seq(self) -> None:
        if self.seq >= SEQ_LIMIT:
            raise _err(AL_INTERNAL_ERROR, "internal_error",
                       "Sequence number 2^64-1'e ulaştı — bağlantı kapatılmalı (RFC 5246 §6.1).")

    def _mac(self, seq8: bytes, ctype: int, version: bytes, data: bytes) -> bytes:
        h = hmac.new(self.mac_key, digestmod=self.suite.mac_hash)
        h.update(seq8 + bytes([ctype]) + version + struct.pack("!H", len(data)))
        h.update(data)
        return h.digest()

    def _aes(self, iv: bytes):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        return Cipher(algorithms.AES(self.key), modes.CBC(iv))

    def seal(self, content_type: int, plaintext: bytes, version: int = VERSION_TLS12) -> bytes:
        """Record GÖVDESİNİ (header HARİÇ) döner: IV || CBC(...) [|| MAC (EtM)]."""
        self._check_seq()
        seq8 = self.seq.to_bytes(8, "big")
        ver = struct.pack("!H", version)
        iv = os.urandom(16)
        if self.etm:
            padded = _pad(plaintext)
            enc = self._aes(iv).encryptor()
            ct = enc.update(padded) + enc.finalize()
            body = iv + ct
            body += self._mac(seq8, content_type, ver, body)
        else:
            padded = _pad(plaintext + self._mac(seq8, content_type, ver, plaintext))
            enc = self._aes(iv).encryptor()
            body = iv + enc.update(padded) + enc.finalize()
        self.seq += 1
        return body

    def open(self, content_type: int, version: bytes, body: bytes) -> bytes:
        self._check_seq()
        seq8 = self.seq.to_bytes(8, "big")
        pt = self._open_etm(seq8, content_type, version, body) if self.etm \
            else self._open_mte(seq8, content_type, version, body)
        self.seq += 1
        return pt

    def _decrypt(self, iv: bytes, ct: bytes) -> bytes:
        dec = self._aes(iv).decryptor()
        return dec.update(ct) + dec.finalize()

    def _open_etm(self, seq8: bytes, ctype: int, version: bytes, body: bytes) -> bytes:
        m = self.suite.mac_len
        # yapısal koşullar: IV(16) + en az 1 blok + MAC; blok hizalı
        if len(body) < 16 + 16 + m or (len(body) - 16 - m) % 16:
            raise _bad_mac()
        signed, tag = body[:-m], body[-m:]
        # RFC 7366 §3: MAC, şifreli metin (IV dahil) üzerinden ve ÖNCE doğrulanır.
        if not hmac.compare_digest(self._mac(seq8, ctype, version, signed), tag):
            raise _bad_mac()
        plain = self._decrypt(signed[:16], signed[16:])
        return _unpad_strict(plain)

    def _open_mte(self, seq8: bytes, ctype: int, version: bytes, body: bytes) -> bytes:
        m = self.suite.mac_len
        if len(body) < 16 + 16 or (len(body) - 16) % 16 or len(body) - 16 < m + 1:
            raise _bad_mac()
        plain = self._decrypt(body[:16], body[16:])
        n = len(plain)
        padlen = plain[-1]
        ok = padlen + 1 + m <= n
        eff = padlen if ok else 0                    # geçersizse "padding yok" gibi devam
        bad = 0 if ok else 1
        for i in range(min(256, n)):                 # SABİT iterasyon: erken çıkış yok
            bad |= (plain[n - 1 - i] ^ eff) * (i <= eff)
        msg_len = n - 1 - eff - m
        mac_rx = plain[msg_len:msg_len + m]
        h = hmac.new(self.mac_key, digestmod=self.suite.mac_hash)
        h.update(seq8 + bytes([ctype]) + version + struct.pack("!H", msg_len))
        h.update(plain[:msg_len])
        mac_ok = hmac.compare_digest(h.digest(), mac_rx)
        # Hash edilen toplam miktarı (n - m) sabit tut: artan kısım için sahte HMAC.
        hmac.new(self.mac_key, plain[msg_len + m:], self.suite.mac_hash).digest()
        if bad or not mac_ok:
            raise _bad_mac()
        return plain[:msg_len]


def _pad(data: bytes) -> bytes:
    n = (-(len(data) + 1)) % 16
    return data + bytes([n]) * (n + 1)


def _unpad_strict(plain: bytes) -> bytes:
    """EtM (MAC zaten doğrulandı): padding yine de KATI doğrulanır; hata = aynı bad_record_mac."""
    if not plain:
        raise _bad_mac()
    n = plain[-1]
    if n + 1 > len(plain) or plain[-(n + 1):] != bytes([n]) * (n + 1):
        raise _bad_mac()
    return plain[:-(n + 1)]


# --------------------------------------------------------------------------
# Statik RSA anahtar değişimi (istemci tarafı)
# --------------------------------------------------------------------------
def rsa_client_key_exchange(leaf, client_version: int) -> "tuple[bytes, bytes]":
    """(ClientKeyExchange gövdesi, pre_master_secret).

    RFC 5246 §7.4.7.1: PMS = client_version(2) || 46 rastgele bayt; RSAES-PKCS1-v1_5 ile
    sunucu sertifikasının anahtarına şifrelenir. ``client_version`` ClientHello'daki
    client_version alanıdır (0x0303: TLS 1.3'ü supported_versions ile ilan etsek de
    legacy_version sabit 0x0303'tür; sunucu bu değeri PMS'te doğrular). Bleichenbacher
    ŞİFRE ÇÖZEN tarafı etkiler (sunucu); istemci yalnızca şifreler.
    """
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509 import KeyUsage
    from cryptography.x509.oid import ExtensionOID
    from cryptography import x509

    pub = leaf.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        raise _err(AL_BAD_CERTIFICATE, "bad_certificate",
                   f"Statik RSA suite'i RSA sertifikası gerektirir ama anahtar {type(pub).__name__}.")
    try:
        ku = leaf.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if isinstance(ku, KeyUsage) and not ku.key_encipherment:
            raise _err(AL_BAD_CERTIFICATE, "bad_certificate",
                       "Sertifika KeyUsage'ı keyEncipherment içermiyor; statik RSA için kullanılamaz.")
    except x509.ExtensionNotFound:
        pass
    pms = struct.pack("!H", client_version) + os.urandom(46)
    enc = pub.encrypt(pms, padding.PKCS1v15())
    return struct.pack("!H", len(enc)) + enc, pms


# --------------------------------------------------------------------------
# Görünürlük
# --------------------------------------------------------------------------
def tls_info(state: Optional[dict]) -> dict:
    """``crypto_state()``/``socket.state`` sözlüğünden kullanıcıya dönük ``Response.tls_info``."""
    st = state or {}
    if st.get("is_tls12"):
        ver = "TLSv1.2"
    elif st.get("is_tls13"):
        ver = "TLSv1.3"
    else:
        ver = "unknown"
    return {
        "version": ver,
        "cipher_suite": st.get("cipher_suite"),
        "cipher_name": st.get("suite_name") or st.get("cipher_name"),
        "extended_master_secret": st.get("extended_master_secret", True),
        "encrypt_then_mac": st.get("encrypt_then_mac", False),
        "secure_renegotiation": st.get("secure_renegotiation", True),
        "forward_secret": st.get("forward_secret", True),
        "legacy_tls": st.get("legacy_tls", False),
    }
