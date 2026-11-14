"""
fasthttpc — TLS 1.3 handshake adapter.

Bu modül tam bir TLS 1.3 istemci handshake'i yürütür ve şifreli bir soket döner.

GÜVENLİK NOTU — sunucu kimliği üç ayrı kontrolle doğrulanır ve üçü de zorunludur:

  1. Certificate      : zincir güvenilir bir CA'ya kadar kuruluyor mu, hostname
                        eşleşiyor mu, süresi geçerli mi?  (cert_validator)
  2. CertificateVerify: sunucu sertifikadaki özel anahtara sahip olduğunu
                        imzayla kanıtlıyor mu?  (RFC 8446 §4.4.3)
  3. Finished         : sunucu handshake anahtarlarını gerçekten türetebildi mi,
                        yani transcript üzerinde anlaşıyor muyuz? (§4.4.4)

Yalnızca (1) yapılırsa bağlantı MITM'e AÇIKTIR: sertifika herkese açık veridir,
araya giren biri onu aynen iletip kendi key_share'ini gönderebilir. (2) olmadan
istemci bunu ayırt edemez. Üçünden biri eksikse handshake reddedilir.
"""
from __future__ import annotations

import struct
import socket
import hashlib
import hmac

from ..crypto_math import (
    PureCryptoEngine,
    FastChaCha20Poly1305 as PureChaCha20Poly1305,
    FastAESGCM as PureAESGCM,
)
from ..tls_crafter import (
    TLSImpersonator, alps_accepted, build_client_encrypted_extensions,
)
from .._log import get_logger
from .alerts import describe_alert
from .keyshare import (
    is_hello_retry_request,
    parse_hrr,
    message_hash,
    group_name,
    is_supported_group,
)
from . import session_tickets
from . import mtls
from .cert_validator import (
    validate_server_certificate,
    verify_certificate_verify,
    decompress_certificate_message,
    CertificateValidationError,
)

logger = get_logger("tls")

# RFC 8446 §4.1.3 — ServerHello.random bu değere eşitse mesaj aslında bir
# HelloRetryRequest'tir: SHA-256("HelloRetryRequest")
_HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
)

# Handshake mesaj tipleri
_HS_SERVER_HELLO = 2
_HS_NEW_SESSION_TICKET = 4
_HS_ENCRYPTED_EXTENSIONS = 8
_HS_CERTIFICATE = 11
_HS_CERTIFICATE_REQUEST = 13
_HS_CERTIFICATE_VERIFY = 15
_HS_FINISHED = 20
_HS_KEY_UPDATE = 24
_HS_COMPRESSED_CERTIFICATE = 25

# RFC 8446 §5.1 / §5.2 — record boyut sınırları
MAX_PLAINTEXT = 2 ** 14
MAX_CIPHERTEXT = 2 ** 14 + 256
# RFC 8446 §5.3 — sequence number 64 bit; taşmadan önce bağlantı kapatılmalı
_MAX_SEQ_NUM = 2 ** 64 - 1
# ServerHello için makul üst sınır (birden fazla record'a bölünmüş olabilir)
_MAX_SERVER_HELLO = 64 * 1024


class TLSProtocolError(ConnectionError):
    """TLS protokol ihlali (RFC 8446 alert türü mesajın başında yer alır)."""


def _unexpected(detail: str) -> TLSProtocolError:
    return TLSProtocolError(f"unexpected_message: {detail}")


def _recv_all(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            raise ConnectionResetError(
                f"Sunucu aniden bağlantıyı kesti! (Beklenen: {length}, Alınan: {len(data)})"
            )
        data.extend(packet)
    return bytes(data)


# ---------------------------------------------------------------------------
# Soket bağımsız (sans-IO) yardımcılar — fasthttpc/tls13 de bunları kullanır.
# ---------------------------------------------------------------------------

def suite_params(cipher_suite: int):
    """TLS 1.3 cipher suite -> (cipher_name, key_len, hash_func)."""
    if cipher_suite == 0x1301:
        return "AES", 16, hashlib.sha256
    if cipher_suite == 0x1302:
        return "AES", 32, hashlib.sha384
    if cipher_suite == 0x1303:
        return "CHACHA20-POLY1305", 32, hashlib.sha256
    raise TLSProtocolError(
        f"illegal_parameter: Sunucu desteklenmeyen bir cipher suite seçti: 0x{cipher_suite:04x}. "
        f"Bu istemci yalnızca TLS 1.3 suite'lerini destekler."
    )


def parse_server_hello(sh_msg: bytes, sent_session_id: bytes | None = None) -> dict:
    """ServerHello (4 byte handshake başlığı DAHİL) mesajını ayrıştırır ve doğrular.

    Döner: {random, session_id, cipher_suite, selected_version, selected_group,
            server_pub, is_hrr, cookie, selected_identity, extensions}
    selected_identity: pre_shared_key (ext 41) kabul edildiyse u16, yoksa None.
    HRR'de key_share yalnızca grup içerir -> server_pub=None.
    Grup/anahtar uzunluğu kontrolü çağırana bırakılır.
    Hata: TLSProtocolError.
    """
    if len(sh_msg) < 4:
        raise TLSProtocolError("decode_error: ServerHello başlığı eksik.")
    if sh_msg[0] != _HS_SERVER_HELLO:
        raise _unexpected(f"ServerHello (2) beklenirken handshake tipi {sh_msg[0]} geldi.")
    hs_len = int.from_bytes(sh_msg[1:4], "big")
    if hs_len != len(sh_msg) - 4:
        raise TLSProtocolError("decode_error: ServerHello uzunluk alanı mesajla uyuşmuyor.")
    body = sh_msg[4:]
    if len(body) < 35:
        raise TLSProtocolError("decode_error: ServerHello mesajı bozuk (çok kısa).")

    random = body[2:34]
    is_hrr = random == _HELLO_RETRY_REQUEST_RANDOM
    sid_len = body[34]
    if sid_len > 32:
        raise TLSProtocolError("decode_error: legacy_session_id_echo 32 byte'tan uzun.")
    offset = 35 + sid_len
    if len(body) < offset + 5:
        raise TLSProtocolError("decode_error: ServerHello mesajı bozuk (cipher suite okunamadı).")
    session_id = body[35:offset]

    cipher_suite = struct.unpack("!H", body[offset:offset + 2])[0]
    if body[offset + 2] != 0:
        raise TLSProtocolError("illegal_parameter: legacy_compression_method sıfır değil.")
    ext_total = struct.unpack("!H", body[offset + 3:offset + 5])[0]
    curr = offset + 5
    if curr + ext_total != len(body):
        raise TLSProtocolError("decode_error: ServerHello extension uzunluğu mesajla uyuşmuyor.")

    extensions: list[tuple[int, bytes]] = []
    seen: set[int] = set()
    while curr < len(body):
        if curr + 4 > len(body):
            raise TLSProtocolError("decode_error: ServerHello extension başlığı kesik.")
        ext_type, ext_len = struct.unpack("!HH", body[curr:curr + 4])
        curr += 4
        if curr + ext_len > len(body):
            raise TLSProtocolError("decode_error: ServerHello extension gövdesi kesik.")
        if ext_type in seen:
            raise TLSProtocolError(
                f"illegal_parameter: ServerHello'da extension 0x{ext_type:04x} tekrarlandı."
            )
        seen.add(ext_type)
        extensions.append((ext_type, body[curr:curr + ext_len]))
        curr += ext_len

    selected_version = selected_group = selected_identity = None
    server_pub = cookie = None
    for ext_type, data in extensions:
        if ext_type == 43:
            if len(data) != 2:
                raise TLSProtocolError("decode_error: supported_versions uzunluğu hatalı.")
            selected_version = struct.unpack("!H", data)[0]
        elif ext_type == 51:
            if is_hrr:
                if len(data) != 2:
                    raise TLSProtocolError("decode_error: HRR key_share uzunluğu hatalı.")
                selected_group = struct.unpack("!H", data)[0]
            else:
                if len(data) < 4:
                    raise TLSProtocolError("decode_error: key_share uzunluğu hatalı.")
                selected_group, klen = struct.unpack("!HH", data[:4])
                if klen != len(data) - 4 or klen == 0:
                    raise TLSProtocolError("decode_error: key_share anahtar uzunluğu hatalı.")
                server_pub = data[4:]
        elif ext_type == 41:
            if is_hrr or len(data) != 2:
                raise TLSProtocolError("illegal_parameter: pre_shared_key extension hatalı.")
            selected_identity = struct.unpack("!H", data)[0]
        elif ext_type == 44:
            if len(data) < 2 or struct.unpack("!H", data[:2])[0] != len(data) - 2:
                raise TLSProtocolError("decode_error: cookie extension bozuk.")
            cookie = data[2:]

    if selected_version != 0x0304:
        hint = ""
        if random[24:32] in (b"DOWNGRD\x01", b"DOWNGRD\x00"):
            hint = " ServerHello.random DOWNGRD işareti taşıyor — olası downgrade saldırısı."
        raise TLSProtocolError(
            "protocol_version: Sunucu TLS 1.3 (supported_versions=0x0304) müzakere etmedi ve TLS 1.2 "
            "(0x0303) de seçmedi. Bu istemci yalnızca TLS 1.3 ve güvenli TLS 1.2 alt kümesini "
            "destekler; TLS 1.1 ve altı reddedilir." + hint
        )
    # Sürüm kontrolünden SONRA: TLS 1.2 ServerHello'su session_id'mizi geri
    # göndermek zorunda değildir; önce kontrol edilirse kullanıcı TLS 1.2
    # yerine yanıltıcı bir "session_id eşleşmiyor" hatası görür.
    if sent_session_id is not None and session_id != sent_session_id:
        raise TLSProtocolError(
            "illegal_parameter: ServerHello legacy_session_id_echo gönderilen session_id ile eşleşmiyor."
        )

    return {
        "random": random,
        "session_id": session_id,
        "cipher_suite": cipher_suite,
        "selected_version": selected_version,
        "selected_group": selected_group,
        "server_pub": server_pub,
        "is_hrr": is_hrr,
        "cookie": cookie,
        "selected_identity": selected_identity,
        "extensions": extensions,
    }


def _client_hello_session_id(record_bytes: bytes) -> bytes | None:
    """ClientHello record'u (5 byte record + 4 byte hs başlığı dahil) içinden session_id."""
    pos = 5 + 4 + 2 + 32
    if len(record_bytes) <= pos:
        return None
    sid_len = record_bytes[pos]
    if sid_len > 32 or len(record_bytes) < pos + 1 + sid_len:
        return None
    return bytes(record_bytes[pos + 1:pos + 1 + sid_len])


def next_traffic_secret(secret: bytes, hash_alg) -> bytes:
    """RFC 8446 §7.2: application_traffic_secret_N+1."""
    return PureCryptoEngine.tls13_hkdf_expand_label(
        secret, "traffic upd", b"", hash_alg().digest_size, hash_alg=hash_alg
    )


def traffic_key_iv(secret: bytes, key_len: int, hash_alg) -> tuple[bytes, bytes]:
    """Trafik secret'ından (write_key, write_iv) türetir (RFC 8446 §7.3)."""
    key = PureCryptoEngine.tls13_hkdf_expand_label(secret, "key", b"", key_len, hash_alg=hash_alg)
    iv = PureCryptoEngine.tls13_hkdf_expand_label(secret, "iv", b"", 12, hash_alg=hash_alg)
    return key, iv


def build_key_update(request_update: bool) -> bytes:
    """KeyUpdate handshake mesajı (4 byte başlık dahil)."""
    return bytes([_HS_KEY_UPDATE, 0, 0, 1, 1 if request_update else 0])


def parse_key_update(msg: bytes) -> bool:
    """KeyUpdate mesajını (başlık dahil) ayrıştırır; update_requested döner."""
    if len(msg) != 5 or msg[0] != _HS_KEY_UPDATE or msg[1:4] != b"\x00\x00\x01":
        raise TLSProtocolError("decode_error: KeyUpdate mesajı bozuk.")
    if msg[4] not in (0, 1):
        raise TLSProtocolError("illegal_parameter: KeyUpdate request_update değeri geçersiz.")
    return msg[4] == 1


class HandshakeOrderValidator:
    """İstemci tarafı TLS 1.3 handshake mesaj sırası (RFC 8446 §A.1).

    ServerHello -> EncryptedExtensions -> [CertificateRequest] ->
    (Certificate | CompressedCertificate) -> CertificateVerify -> Finished.  Sonrasında yalnızca NewSessionTicket ve
    KeyUpdate kabul edilir. psk_accepted=True ise EE -> Finished.
    Tek bir HelloRetryRequest'e izin verilir:
    expect(2, is_hrr=True) sonrası ikinci bir ServerHello beklenir.
    Sıra dışı/tekrar mesaj -> TLSProtocolError("unexpected_message ...").
    """

    _NAMES = {
        2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions",
        11: "Certificate", 13: "CertificateRequest", 15: "CertificateVerify",
        20: "Finished", 24: "KeyUpdate", 25: "CompressedCertificate",
    }
    _TRANSITIONS = {
        "WAIT_SH": {2: "WAIT_EE"},
        "WAIT_EE": {8: "WAIT_CERT"},
        "WAIT_CERT": {11: "WAIT_CV", 25: "WAIT_CV"},
        "WAIT_CV": {15: "WAIT_FIN"},
        "WAIT_FIN": {20: "CONNECTED"},
        "CONNECTED": {4: "CONNECTED", 24: "CONNECTED"},
    }

    def __init__(self, psk_accepted: bool = False):
        self.state = "WAIT_SH"
        self.hrr_seen = False
        # RFC 8446 §4.3.2: EncryptedExtensions ile Certificate arasında EN FAZLA bir
        # CertificateRequest (mTLS). PSK devamında hiç gelmez (WAIT_FIN'de reddedilir).
        self.cert_request_seen = False
        # PSK resumption kabul edildiyse (ServerHello ext 41) sıra:
        # EE -> Finished (Certificate/CertificateVerify gönderilmez).
        # ServerHello işlendikten sonra da set edilebilir.
        self.psk_accepted = psk_accepted

    @property
    def done(self) -> bool:
        return self.state == "CONNECTED"

    def expect(self, hs_type: int, *, is_hrr: bool = False) -> str:
        if is_hrr:
            if self.state != "WAIT_SH" or hs_type != _HS_SERVER_HELLO:
                raise _unexpected("HelloRetryRequest yalnızca ilk ServerHello yerine gelebilir.")
            if self.hrr_seen:
                raise _unexpected("ikinci HelloRetryRequest alındı.")
            self.hrr_seen = True
            return self.state
        if self.psk_accepted and self.state == "WAIT_EE" and hs_type == _HS_ENCRYPTED_EXTENSIONS:
            self.state = "WAIT_FIN"
            return self.state
        if hs_type == _HS_CERTIFICATE_REQUEST and self.state == "WAIT_CERT" and not self.cert_request_seen:
            self.cert_request_seen = True     # durum aynı kalır: Certificate hâlâ beklenir
            return self.state
        nxt = self._TRANSITIONS[self.state].get(hs_type)
        if nxt is None:
            name = self._NAMES.get(hs_type, f"tip {hs_type}")
            raise _unexpected(f"{self.state} durumunda beklenmeyen handshake mesajı: {name}.")
        self.state = nxt
        return nxt


def _nonce(iv: bytes, seq: int) -> bytes:
    return bytes(a ^ b for a, b in zip(iv, b"\x00" * 4 + seq.to_bytes(8, "big")))


class EncryptedSocket:
    """TLS 1.3 record katmanı. AEAD şifreleme/çözme ve sequence number yönetimi."""

    def __init__(self, raw_socket: socket.socket, crypto_state: dict):
        self.raw_socket = raw_socket
        self.state = crypto_state
        # Okuma tamponu: bytearray + okuma ofseti. `bytes += chunk` ve her record'da
        # dilimleyerek yeni bytes üretmek büyük indirmelerde O(n^2) kopyalamaya yol açıyordu.
        self.read_buffer = bytearray()
        self._rbuf_off = 0
        # AEAD nesneleri anahtar başına bir kez kurulur (OpenSSL context kurulumu
        # record başına tekrarlanmaz). Anahtar bytes'ı önbellek anahtarı olduğundan
        # anahtar değişince (handshake->app, KeyUpdate) otomatik olarak yeni nesne oluşur.
        self._cipher_cache: dict = {}
        self._post_hs_buffer = b""

    def _cipher(self, key: bytes):
        is_aes = self.state["cipher_name"].startswith("AES")
        cached = self._cipher_cache.get(key)
        if cached is None or cached[1] != is_aes:
            if len(self._cipher_cache) >= 4:
                self._cipher_cache.clear()
            cached = (PureAESGCM(key) if is_aes else PureChaCha20Poly1305(key), is_aes)
            self._cipher_cache[key] = cached
        return cached

    def _invalidate_cipher_cache(self) -> None:
        """Anahtar değiştiğinde (KeyUpdate) eski AEAD nesnelerini bırakır."""
        self._cipher_cache.clear()

    def _fill(self, need: int, eof_msg: str) -> None:
        """Tamponda okunmamış en az `need` bayt olana kadar soketten okur."""
        buf = self.read_buffer
        while len(buf) - self._rbuf_off < need:
            chunk = self.raw_socket.recv(16384)
            if not chunk:
                raise ConnectionResetError(eof_msg)
            buf += chunk

    def _read_raw_record(self) -> tuple[int, bytes, bytes]:
        """Telden bir ham TLS record'u okur: (rec_type, 5 baytlık header, payload)."""
        self._fill(5, "TLS şifreli paket beklenirken bağlantı koptu!")
        off = self._rbuf_off
        buf = self.read_buffer
        record_header = bytes(buf[off:off + 5])
        rec_type = record_header[0]
        rec_len = (record_header[3] << 8) | record_header[4]
        if rec_len > MAX_CIPHERTEXT:
            self.close()
            raise TLSProtocolError(
                f"record_overflow: TLS record uzunluğu {rec_len} > {MAX_CIPHERTEXT} (2^14+256)."
            )

        self._fill(5 + rec_len, "TLS paket gövdesi okunurken koptu.")
        off = self._rbuf_off
        payload = bytes(self.read_buffer[off + 5:off + 5 + rec_len])
        off += 5 + rec_len
        if off == len(self.read_buffer):
            self.read_buffer.clear()
            off = 0
        elif off > 65536:
            # Tüketilmiş baştaki kısmı ara sıra at (amortize O(1)).
            del self.read_buffer[:off]
            off = 0
        self._rbuf_off = off
        return rec_type, record_header, payload

    def send_record(self, data: bytes, content_type: int = 0x17, use_app_keys: bool = True) -> None:
        if not self.state.get("is_tls13"):
            raise ConnectionError("Yalnızca TLS 1.3 desteklenmektedir.")
        # RFC 8446 §5.1: TLSPlaintext.length <= 2^14 — büyük veriyi böl.
        limit = self.state.get("send_limit", MAX_PLAINTEXT)  # sunucunun record_size_limit'i (RFC 8449)
        if len(data) > limit:
            for i in range(0, len(data), limit):
                self._send_one_record(data[i:i + limit], content_type, use_app_keys)
            return
        self._send_one_record(data, content_type, use_app_keys)

    def _send_one_record(self, data: bytes, content_type: int, use_app_keys: bool) -> None:
        key = self.state["app_client_write_key"] if use_app_keys else self.state["client_write_key"]
        iv = self.state["app_client_write_iv"] if use_app_keys else self.state["client_write_iv"]
        seq_name = "app_client_seq_num" if use_app_keys else "client_seq_num"
        seq = self.state[seq_name]
        if seq > _MAX_SEQ_NUM:
            self.close()
            raise TLSProtocolError(
                "Gönderim sequence number'ı 2^64-1'i aştı — bağlantı kapatıldı (RFC 8446 §5.3)."
            )

        inner = data + struct.pack("!B", content_type)
        nonce = _nonce(iv, seq)
        header = struct.pack("!BHH", 0x17, 0x0303, len(inner) + 16)

        cipher, is_aes = self._cipher(key)
        if is_aes:
            ct, tag = cipher.encrypt_gcm(nonce, inner, header)
        else:
            ct, tag = cipher.encrypt_aead(nonce, inner, header)

        self.state[seq_name] = seq + 1
        self.raw_socket.sendall(header + ct + tag)

    def close(self) -> None:
        try:
            self.raw_socket.close()
        except OSError as e:
            logger.debug("Soket kapatılırken hata yok sayıldı: %s", e)

    def recv_record(self, skip_post_handshake: bool = False) -> tuple[bytes, int]:
        """Bir TLS record'u şifresini çözerek döner.

        Args:
            skip_post_handshake: Geriye uyumluluk için korunur. Application
                anahtarları devredeyken gelen handshake-tipi record'lar
                (NewSessionTicket, KeyUpdate) her zaman burada işlenir/yutulur
                ve bir sonraki record döner — KeyUpdate işlenmezse sonraki
                record'lar çözülemez.

        TLS 1.3'te handshake biter bitmez sunucu genelde bir NewSessionTicket
        (hs_type=4) gönderir; bu, application anahtarlarıyla ŞİFRELİ bir
        handshake record'udur (content_type=22). HTTP katmanı bunu bir HTTP/2
        frame ya da HTTP/1.1 yanıtı sanarsa tüm akış bozulur — length alanı
        saçmalar, "invalid literal for int" gibi hatalar çıkar. Bu yüzden
        application verisi beklerken handshake record'ları burada yutulmalıdır.
        """
        while True:
            rec_type, record_header, payload = self._read_raw_record()

            if rec_type == 20:  # change_cipher_spec — TLS 1.3'te uyumluluk için, yok say
                # RFC 8446 §5: yalnızca tek byte 0x01 geçerli (el sıkışma sonrası CCS'in tolere edilmesi
                # test_record_layer_perf tarafından bilinçli olarak korunuyor).
                if payload != b"\x01":
                    raise _unexpected("beklenmeyen/geçersiz change_cipher_spec record'u.")
                continue
            if rec_type == 21:  # açık (şifresiz) alert
                raise ConnectionError(f"Açık (şifresiz) TLS alert alındı: {describe_alert(payload)}")
            if rec_type != 23:
                raise _unexpected(f"şifreli bağlantıda beklenmeyen record tipi {rec_type}.")

            if not self.state.get("is_tls13"):
                raise ConnectionError("Yalnızca TLS 1.3 desteklenmektedir.")

            if len(payload) < 17:
                raise ConnectionError("TLS record'u AEAD tag'i için fazla kısa — bozuk veri.")

            using_app = self.state.get("using_app_keys")
            key = self.state["app_server_write_key"] if using_app else self.state["server_write_key"]
            iv = self.state["app_server_write_iv"] if using_app else self.state["server_write_iv"]
            seq_name = "app_server_seq_num" if using_app else "server_seq_num"
            seq = self.state[seq_name]
            if seq > _MAX_SEQ_NUM:
                self.close()
                raise TLSProtocolError(
                    "Alım sequence number'ı 2^64-1'i aştı — bağlantı kapatıldı (RFC 8446 §5.3)."
                )

            nonce = _nonce(iv, seq)
            ct, tag = payload[:-16], payload[-16:]

            # AAD, telde GELEN record header'ının birebir kendisidir (RFC 8446 §5.2).
            # Sabit 0x17/0x0303 varsaymak, farklı legacy_record_version gönderen
            # sunucularda tag doğrulamasını hatalı biçimde başarısız kılar.
            cipher, is_aes = self._cipher(key)
            if is_aes:
                pt = cipher.decrypt_gcm(nonce, ct, record_header, tag)
            else:
                pt = cipher.decrypt_aead(nonce, ct, record_header, tag)

            self.state[seq_name] = seq + 1

            if len(pt) > MAX_PLAINTEXT + 1:
                self.close()
                raise TLSProtocolError("record_overflow: çözülmüş TLSInnerPlaintext 2^14+1'i aşıyor.")

            # TLSInnerPlaintext: content || content_type || zero-padding
            idx = len(pt) - 1
            while idx >= 0 and pt[idx] == 0:
                idx -= 1
            if idx < 0:
                raise ConnectionError(
                    "TLS record'u yalnızca padding içeriyor, content_type yok — protokol hatası."
                )
            inner = pt[:idx]
            inner_type = pt[idx]

            # Application aşamasında gelen post-handshake handshake
            # mesajlarını (NewSessionTicket=4, KeyUpdate=24) işle/yut.
            if using_app and inner_type == 22:
                self._process_post_handshake_record(inner)
                continue
            if using_app and self._post_hs_buffer:
                raise _unexpected("bölünmüş handshake mesajı tamamlanmadan başka record geldi.")

            return inner, inner_type

    def _process_post_handshake_record(self, data: bytes) -> None:
        """Bir handshake record'unu mesajlara böler; KeyUpdate record sınırında bitmeli."""
        buf = self._post_hs_buffer + data
        while len(buf) >= 4:
            hs_len = int.from_bytes(buf[1:4], "big")
            if len(buf) < 4 + hs_len:
                break
            msg, buf = buf[:4 + hs_len], buf[4 + hs_len:]
            if msg[0] == _HS_KEY_UPDATE and buf:
                raise _unexpected("KeyUpdate record sınırında bitmiyor.")
            self._handle_post_handshake(msg)
        self._post_hs_buffer = buf

    def _handle_post_handshake(self, msg: bytes) -> None:
        """Application aşamasında gelen tek bir handshake mesajını işler."""
        if not msg:
            return
        hs_type = msg[0]
        if hs_type == 4:      # NewSessionTicket
            self._on_new_session_ticket(msg)
            return
        if hs_type == _HS_CERTIFICATE_REQUEST:
            # Post-handshake auth desteklenmiyor; post_handshake_auth extension'ı İLAN EDİLMEZ
            # (RFC 8446 §4.2.6) -> unexpected_message alert'i ile kapat (§4.6.2).
            try:
                self.send_record(b"\x02\x0a", content_type=0x15, use_app_keys=True)
            except Exception:  # best-effort
                pass
            raise _unexpected("handshake sonrası CertificateRequest — post_handshake_auth ilan edilmedi.")
        if hs_type == _HS_KEY_UPDATE:
            self._handle_key_update(msg)
            return
        raise _unexpected(f"handshake sonrası beklenmeyen mesaj hs_type={hs_type}.")

    # ---- KeyUpdate (RFC 8446 §4.6.3, §7.2) ---------------------------------
    def _handle_key_update(self, msg: bytes) -> None:
        update_requested = parse_key_update(msg)
        st = self.state
        hash_func, key_len = st["hash_func"], st["key_len"]

        st["server_ats"] = next_traffic_secret(st["server_ats"], hash_func)
        st["app_server_write_key"], st["app_server_write_iv"] = traffic_key_iv(
            st["server_ats"], key_len, hash_func
        )
        st["app_server_seq_num"] = 0
        st["key_updates_received"] = st.get("key_updates_received", 0) + 1
        self._invalidate_cipher_cache()
        logger.debug("Sunucu KeyUpdate işlendi (update_requested=%s)", update_requested)

        if update_requested:
            self.send_key_update(request_update=False)

    def send_key_update(self, request_update: bool = False) -> None:
        """Kendi KeyUpdate'imizi ESKİ anahtarla gönderir, sonra c_ats'yi yeniler."""
        st = self.state
        self.send_record(build_key_update(request_update), content_type=0x16, use_app_keys=True)
        hash_func, key_len = st["hash_func"], st["key_len"]
        st["client_ats"] = next_traffic_secret(st["client_ats"], hash_func)
        st["app_client_write_key"], st["app_client_write_iv"] = traffic_key_iv(
            st["client_ats"], key_len, hash_func
        )
        st["app_client_seq_num"] = 0
        self._invalidate_cipher_cache()


    def _on_new_session_ticket(self, msg: bytes) -> None:
        """NewSessionTicket'ları PSK resumption önbelleğine yazar (faz4).

        Yalnızca resumption bayrağı açık bir handshake'te resumption_master_secret
        türetilmişse çalışır; aksi halde bilet eskisi gibi yutulur. Bozuk bilet
        bağlantıyı düşürmez (resumption bir optimizasyondur), yalnızca loglanır.
        Bir record'da birden fazla NewSessionTicket art arda gelebilir.
        """
        session_tickets.store_new_session_tickets(
            self.state.get("ticket_cache_key"), msg, self.state.get("resumption_master_secret"),
            self.state.get("cipher_suite", 0), peer_certificate=self.state.get("peer_certificate"),
        )


def _parse_record_size_limit(hs_payload: bytes) -> int:
    """EncryptedExtensions içindeki record_size_limit (ext 28, RFC 8449); yoksa 0."""
    try:
        total = struct.unpack("!H", hs_payload[4:6])[0]
        cur, end = 6, min(6 + total, len(hs_payload))
        while cur + 4 <= end:
            et, el = struct.unpack("!HH", hs_payload[cur:cur + 4])
            cur += 4
            if et == 28:
                if el != 2:
                    raise _unexpected("decode_error: bozuk record_size_limit uzantısı.")
                return struct.unpack("!H", hs_payload[cur:cur + 2])[0]
            cur += el
    except (struct.error, IndexError):
        pass
    return 0


def _parse_alpn_from_encrypted_extensions(hs_payload: bytes) -> str:
    """EncryptedExtensions (hs_type=8) içinden ALPN sonucunu çıkarır."""
    try:
        if len(hs_payload) < 6:
            return ""
        ext_total_len = struct.unpack("!H", hs_payload[4:6])[0]
        curr = 6
        end = min(6 + ext_total_len, len(hs_payload))
        while curr + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", hs_payload[curr:curr + 4])
            curr += 4
            if ext_type == 16 and ext_len >= 3:
                proto_len = hs_payload[curr + 2]
                return hs_payload[curr + 3: curr + 3 + proto_len].decode("ascii", errors="ignore")
            curr += ext_len
    except (struct.error, IndexError):
        pass
    return ""


def _read_server_hello(raw_socket: socket.socket, allow_ccs: bool = True) -> bytes:
    """Düz (şifresiz) handshake record'larından tam ServerHello mesajını toplar.

    TLS 1.3'te ServerHello sonrasında aynı düz record'da veri kalması protokol
    ihlalidir; bu sarmalayıcı onu reddeder (TLS 1.2 için bkz. ``_read_server_hello_ex``).
    """
    msg, trailing = _read_server_hello_ex(raw_socket, allow_ccs)
    if trailing:
        raise _unexpected("ServerHello sonrasında şifresiz handshake verisi.")
    return msg


def _read_server_hello_ex(raw_socket: socket.socket, allow_ccs: bool = True) -> tuple[bytes, bytes]:
    """(ServerHello, aynı record'da onu izleyen handshake baytları). Ayrıntı: ``_read_server_hello``.

    TLS 1.2 sunucuları ServerHello'yu Certificate/ServerKeyExchange ile AYNI record'a
    koyabilir; TLS 1.2 yolu bu artık baytları devralır.

    ServerHello birden fazla record'a bölünebilir (RFC 8446 §5.1). Mesajdan
    sonra aynı düz record'da artık veri kalırsa (şifresiz EE vb.) reddedilir.
    allow_ccs: mesaj başlamadan önce gelen TEK bir uyumluluk CCS'si (0x01)
    yok sayılır — HRR -> CCS -> ServerHello2 akışı için (RFC 8446 §D.4).
    """
    buf = b""
    ccs_seen = False
    while True:
        header = _recv_all(raw_socket, 5)
        rec_type, _ver, rec_len = struct.unpack("!BHH", header)
        if header[:4] == b"HTTP":
            raise TLSProtocolError("Sunucu TLS yerine düz HTTP ile yanıt verdi (bu port TLS konuşmuyor olabilir).")
        if rec_len > MAX_PLAINTEXT:
            raise TLSProtocolError(
                f"record_overflow: düz record uzunluğu {rec_len} > {MAX_PLAINTEXT}."
            )
        payload = _recv_all(raw_socket, rec_len)
        if rec_type == 20 and allow_ccs and not ccs_seen and not buf and payload == b"\x01":
            ccs_seen = True
            continue
        if rec_type == 21:
            raise ConnectionError(f"Sunucu el sıkışmayı reddetti: {describe_alert(payload)}")
        if rec_type != 22:
            raise _unexpected(f"ServerHello beklenirken beklenmeyen record tipi: {rec_type}")
        if not payload:
            raise TLSProtocolError("decode_error: boş handshake record'u.")
        buf += payload
        if len(buf) >= 4:
            if buf[0] != _HS_SERVER_HELLO:
                raise _unexpected(f"ServerHello (2) beklenirken handshake tipi {buf[0]} geldi.")
            total = 4 + int.from_bytes(buf[1:4], "big")
            if total > _MAX_SERVER_HELLO:
                raise TLSProtocolError("decode_error: ServerHello makul boyutu aşıyor.")
            if len(buf) == total:
                return buf, b""
            if len(buf) > total:
                return buf[:total], buf[total:]


_SUITE_HASH = {0x1301: hashlib.sha256, 0x1302: hashlib.sha384, 0x1303: hashlib.sha256}


def _recv_handshake_message(raw_socket: socket.socket, what: str) -> bytes:
    """Şifresiz handshake record'larından TEK bir handshake mesajı okur.

    CCS record'larını (TLS 1.3 uyumluluk) atlar, alert'te hata verir ve
    birden çok record'a bölünmüş mesajı birleştirir.
    """
    buf = b""
    ccs_seen = False
    while True:
        header = _recv_all(raw_socket, 5)
        rec_type, _ver, rec_len = struct.unpack("!BHH", header)
        if rec_len > 16384:
            raise ConnectionError(f"record_overflow: düz record uzunluğu {rec_len} > 16384.")
        payload = _recv_all(raw_socket, rec_len)
        if rec_type == 20:
            # HRR'den sonra sunucu sahte CCS gönderebilir (RFC 8446 §D.4).
            if payload != b"\x01" or ccs_seen:
                raise ConnectionError("unexpected_message: geçersiz/tekrarlanan change_cipher_spec.")
            ccs_seen = True
            continue
        if rec_type == 21:
            raise ConnectionError(f"Sunucu el sıkışmayı reddetti: {describe_alert(payload)}")
        if rec_type != 22:
            raise ConnectionError(f"{what} beklenirken beklenmeyen record tipi: {rec_type}")
        if not payload:
            raise ConnectionError("decode_error: boş handshake record'u.")
        buf += payload
        if len(buf) >= 4:
            hs_len = struct.unpack("!I", b"\x00" + buf[1:4])[0]
            if len(buf) >= 4 + hs_len:
                if len(buf) > 4 + hs_len:
                    raise ConnectionError(f"{what} ile aynı record'da beklenmeyen ek veri.")
                return buf


def _handle_hrr(raw_socket: socket.socket, impersonator: TLSImpersonator,
                client_hello1: bytes, hrr_msg: bytes):
    """HelloRetryRequest'i işler (RFC 8446 §4.1.4) ve 2. ServerHello'yu döner.

    Args:
        client_hello1: ilk ClientHello handshake mesajı (record başlığı HARİÇ).
        hrr_msg: HRR handshake mesajı (4 byte başlık DAHİL).

    Döner: (server_hello2_msg, transcript_bytes, hrr_info). transcript_bytes
    = message_hash(CH1) || HRR || CH2 || ServerHello2 — §4.4.1.
    """
    if hrr_msg[0] != 2:
        raise ConnectionError("HelloRetryRequest handshake tipi ServerHello (2) değil.")
    try:
        hrr = parse_hrr(hrr_msg[4:])
    except ValueError as e:
        raise ConnectionError(f"Bozuk HelloRetryRequest: {e}") from e

    if hrr.selected_version != 0x0304:
        raise ConnectionError("HelloRetryRequest TLS 1.3 (supported_versions) seçmedi.")
    hash_func = _SUITE_HASH.get(hrr.cipher_suite)
    if hash_func is None:
        raise ConnectionError(
            f"HelloRetryRequest desteklenmeyen cipher suite seçti: 0x{hrr.cipher_suite:04x}"
        )
    group = hrr.selected_group
    if group is None and hrr.cookie is None:
        # §4.1.4: CH1'de hiçbir değişikliğe yol açmayacak HRR → illegal_parameter
        raise ConnectionError("HelloRetryRequest ne key_share grubu ne cookie içeriyor.")
    if group is None:
        # Yalnızca cookie istendi: aynı key_share'lerle tekrar dene.
        groups = impersonator.key_shares.groups
        group = groups[0]
        if len(groups) != 1:
            raise ConnectionError("Yalnızca cookie içeren HRR, çoklu key_share ile desteklenmiyor.")
    else:
        if group in impersonator.key_shares.groups:
            raise ConnectionError(
                f"HelloRetryRequest zaten key_share gönderdiğimiz grubu ({group_name(group)}) "
                f"istedi — protokol ihlali (illegal_parameter)."
            )
        if group not in impersonator.advertised_groups():
            raise ConnectionError(
                f"HelloRetryRequest supported_groups'ta ilan etmediğimiz grubu istedi: "
                f"{group_name(group)}"
            )
        if not is_supported_group(group):
            raise ConnectionError(
                f"Sunucu HelloRetryRequest ile {group_name(group)} grubunu istedi; bu grup "
                f"profilde ilan ediliyor ama bu istemci tarafından implemente edilmedi "
                f"(desteklenenler: x25519, secp256r1, secp384r1)."
            )

    ch2_record = impersonator.build_retry_client_hello(group, hrr.cookie)
    # Middlebox uyumluluk modu (RFC 8446 §D.4): Chrome 2. ClientHello'dan hemen
    # önce sahte bir change_cipher_spec gönderir.
    raw_socket.sendall(b"\x14\x03\x03\x00\x01\x01" + ch2_record)

    sh2 = _recv_handshake_message(raw_socket, "2. ServerHello")
    if sh2[0] != 2 or len(sh2) < 4 + 35:
        raise ConnectionError("HRR sonrası ServerHello bekleniyordu.")
    if is_hello_retry_request(sh2[6:38]):
        raise ConnectionError(
            "Sunucu ikinci bir HelloRetryRequest gönderdi — RFC 8446 §4.1.4 gereği "
            "handshake sonlandırıldı (unexpected_message)."
        )
    transcript = message_hash(hash_func, client_hello1) + hrr_msg + ch2_record[5:] + sh2
    return sh2, transcript, hrr


class TLSAdapter:
    @staticmethod
    def negotiate(raw_socket: socket.socket, host: str, profile_name: str, *,
                  ca_path: str | None = None, port: int | None = None,
                  legacy_tls: bool = False, client_cert=None) -> EncryptedSocket:
        """ca_path: None -> certifi + sistem CA'ları; aksi halde YALNIZCA o PEM dosyası.

        legacy_tls: eski sunucu uyumluluk modu (varsayılan False = davranış değişmez);
        bkz. security/tls12_legacy.py.

        client_cert: security.client_cert.ClientCert (mTLS). CertificateRequest gelirse
        Certificate + CertificateVerify gönderilir (uygun şema yoksa boş Certificate).
        Kimliği PSK bilet önbelleği anahtarına girer.
        """
        impersonator = TLSImpersonator(host, profile=profile_name, legacy_tls=legacy_tls)

        # PSK resumption (faz4) — VARSAYILAN KAPALI; bkz. session_tickets.enable_resumption.
        ticket_key = None
        if session_tickets.resumption_enabled():
            # Hedef port: proxy tünelinde getpeername() PROXY'nin portunu verir; bu
            # yüzden çağıran hedef portu ``port=`` ile geçirmeli (bilet anahtarı).
            peer_port = port
            if peer_port is None:
                try:
                    peer_port = raw_socket.getpeername()[1]
                except (OSError, IndexError, TypeError):
                    peer_port = None
            ticket_key = session_tickets.resumption_key(
                host, peer_port, ca_path,
                *((client_cert.identity,) if client_cert is not None else ()))
        resumption_on = ticket_key is not None
        record_bytes, priv_key, _c_rand, ticket = session_tickets.begin_resumption(
            impersonator, ticket_key)
        sent_session_id = _client_hello_session_id(record_bytes)

        raw_socket.sendall(record_bytes)

        state = {
            "is_tls13": False,
            "using_app_keys": False,
            "client_seq_num": 0,
            "server_seq_num": 0,
            "app_client_seq_num": 0,
            "app_server_seq_num": 0,
            "handshake_messages": record_bytes[5:],
            "cipher_name": "CHACHA20-POLY1305",
            "key_len": 32,
            "alpn": "",
        }
        esock = EncryptedSocket(raw_socket, state)
        order = HandshakeOrderValidator()

        # ---- ServerHello ---------------------------------------------------
        server_hello_payload, sh_trailing = _read_server_hello_ex(raw_socket)

        # TLS 1.2 seçildiyse (legacy_version 0x0303, supported_versions ≠ 0x0304)
        # güvenli TLS 1.2 alt kümesine dallan (bkz. security/tls12.py).
        from . import tls12
        if tls12.is_tls12_server_hello(server_hello_payload):
            return tls12.negotiate_tls12(
                raw_socket, host, record_bytes, server_hello_payload, sh_trailing, ca_path=ca_path,
                legacy_tls=legacy_tls,
                client_cert=client_cert,
            )
        if sh_trailing:
            raise _unexpected("ServerHello sonrasında şifresiz handshake verisi.")
        sh = parse_server_hello(server_hello_payload, sent_session_id)

        hrr = None
        if sh["is_hrr"]:
            order.expect(_HS_SERVER_HELLO, is_hrr=True)
            server_hello_payload, transcript, hrr = _handle_hrr(
                raw_socket, impersonator, record_bytes[5:], server_hello_payload
            )
            sh = parse_server_hello(server_hello_payload, sent_session_id)
            order.expect(_HS_SERVER_HELLO)
            state["handshake_messages"] = transcript
        else:
            order.expect(_HS_SERVER_HELLO)
            state["handshake_messages"] += server_hello_payload

        cipher_suite = sh["cipher_suite"]
        state["cipher_name"], state["key_len"], hash_func = suite_params(cipher_suite)
        state["hash_func"] = hash_func

        if hrr is not None and cipher_suite != hrr.cipher_suite:
            raise ConnectionError(
                "HRR sonrası ServerHello farklı bir cipher suite seçti — protokol ihlali."
            )
        psk_selected = sh["selected_identity"]
        selected_group = sh["selected_group"]
        server_pub = sh["server_pub"]
        if not server_pub or selected_group is None:
            raise ConnectionError(
                "ServerHello geçerli bir key_share içermiyor — handshake tamamlanamaz."
            )
        if hrr is not None and hrr.selected_group is not None and selected_group != hrr.selected_group:
            raise ConnectionError(
                "HRR sonrası ServerHello, HRR'de istenen gruptan farklı bir grup seçti."
            )

        try:
            psk_accepted = session_tickets.check_psk_selection(
                ticket, psk_selected, cipher_suite, hrr is not None)
        except session_tickets.PskViolation as e:
            raise ConnectionError(str(e)) from e
        order.psk_accepted = psk_accepted

        state["is_tls13"] = True
        state["key_share_group"] = selected_group
        state["hello_retry"] = hrr is not None

        # ---- Handshake anahtarları ------------------------------------------
        try:
            shared = impersonator.key_shares.shared_secret(selected_group, server_pub)
        except ValueError as e:
            raise ConnectionError(f"key_share işlenemedi ({group_name(selected_group)}): {e}") from e
        t_hash = hash_func(state["handshake_messages"]).digest()
        if psk_accepted:
            hs, ck, civ, sk, siv, c_hts, s_hts = session_tickets.derive_handshake_keys_psk(
                ticket.psk, shared, t_hash, state["key_len"], hash_alg=hash_func
            )
            state["peer_certificate"] = ticket.peer_certificate
            state["resumed"] = True
            logger.debug("PSK resumption kabul edildi: host=%s", host)
        else:
            hs, ck, civ, sk, siv, c_hts, s_hts = PureCryptoEngine.derive_tls13_keys(
                shared, t_hash, state["key_len"], hash_alg=hash_func
            )
        state.update({
            "client_write_key": ck, "client_write_iv": civ,
            "server_write_key": sk, "server_write_iv": siv,
            "client_hts": c_hts, "server_hts": s_hts,
            "handshake_secret": hs,
        })

        # ---- Şifreli handshake akışı -----------------------------------------
        # Sıra HandshakeOrderValidator ile zorunlu kılınır:
        # EE -> (Certificate | CompressedCertificate) -> CertificateVerify -> Finished
        handshake_buffer = b""
        leaf_cert = None
        send_client_ee = False
        cert_req = None

        while not order.done:
            msg, m_type = esock.recv_record()
            if m_type == 21:
                raise ConnectionError(f"Sunucudan Şifreli TLS Alert: {msg.hex()}")
            if m_type != 22:
                raise _unexpected(
                    f"handshake tamamlanmadan content_type={m_type} record'u alındı."
                )

            handshake_buffer += msg
            while len(handshake_buffer) >= 4 and not order.done:
                hs_type = handshake_buffer[0]
                hs_len = struct.unpack("!I", b"\x00" + handshake_buffer[1:4])[0]
                if len(handshake_buffer) < 4 + hs_len:
                    break
                hs_payload = handshake_buffer[:4 + hs_len]
                handshake_buffer = handshake_buffer[4 + hs_len:]

                # Sıra kontrolü — mesaj işlenmeden ÖNCE.
                order.expect(hs_type)

                # ÖNEMLİ: transcript hash'i bu mesaj EKLENMEDEN önce alınmalı.
                # CertificateVerify kendisinden ÖNCEKİ transcript'i imzalar;
                # Finished da kendisinden öncekinin MAC'ini taşır.
                transcript_before = hash_func(state["handshake_messages"]).digest()
                state["handshake_messages"] += hs_payload

                if hs_type == _HS_ENCRYPTED_EXTENSIONS:
                    state["alpn"] = _parse_alpn_from_encrypted_extensions(hs_payload)
                    send_client_ee = alps_accepted(
                        impersonator.alps_advertised, hs_payload, state["alpn"])
                    rsl = _parse_record_size_limit(hs_payload)
                    if rsl:
                        if rsl < 64:  # RFC 8449 §4
                            raise TLSProtocolError(f"illegal_parameter: record_size_limit={rsl} < 64")
                        # TLS 1.3'te sınır içerik tipi baytını da kapsar
                        state["send_limit"] = min(MAX_PLAINTEXT, rsl - 1)

                elif hs_type == _HS_CERTIFICATE_REQUEST:
                    # RFC 8446 §4.3.2 (sıra/tekrar order.expect ile zaten denetlendi)
                    try:
                        cert_req = mtls.parse_certificate_request_13(hs_payload)
                    except mtls.MtlsProtocolError as e:
                        raise TLSProtocolError(str(e)) from e

                elif hs_type in (_HS_CERTIFICATE, _HS_COMPRESSED_CERTIFICATE, _HS_CERTIFICATE_VERIFY) \
                        and psk_accepted:
                    raise ConnectionError(
                        "PSK ile devam edilen oturumda sunucu Certificate/CertificateVerify "
                        "gönderdi — protokol ihlali (RFC 8446 §4.4.2)."
                    )

                elif hs_type in (_HS_CERTIFICATE, _HS_COMPRESSED_CERTIFICATE):
                    if hs_type == _HS_COMPRESSED_CERTIFICATE:
                        try:
                            effective_payload = decompress_certificate_message(hs_payload)
                        except CertificateValidationError as e:
                            raise ConnectionError(f"Sıkıştırılmış sertifika açılamadı: {e}") from e
                    else:
                        effective_payload = hs_payload

                    try:
                        leaf_cert = validate_server_certificate(effective_payload, host, ca_path=ca_path)
                    except CertificateValidationError as e:
                        raise ConnectionError(
                            f"TLS sertifika doğrulaması başarısız — bağlantı güvenli değil, "
                            f"olası MITM saldırısı: {e}"
                        ) from e
                    state["peer_certificate"] = leaf_cert

                elif hs_type == _HS_CERTIFICATE_VERIFY:
                    try:
                        scheme = verify_certificate_verify(
                            hs_payload, leaf_cert, transcript_before,
                            offered_schemes=impersonator.profile.get("signature_algorithms"))
                    except CertificateValidationError as e:
                        raise ConnectionError(f"TLS kimlik doğrulaması başarısız: {e}") from e
                    logger.debug("CertificateVerify doğrulandı (scheme=0x%04x)", scheme)

                elif hs_type == _HS_FINISHED:
                    # RFC 8446 §4.4.4 — server Finished doğrulaması
                    hash_len = hash_func().digest_size
                    s_fin_key = PureCryptoEngine.tls13_hkdf_expand_label(
                        state["server_hts"], "finished", b"", hash_len, hash_alg=hash_func
                    )
                    expected = hmac.new(s_fin_key, transcript_before, hash_func).digest()
                    if not hmac.compare_digest(expected, hs_payload[4:]):
                        raise ConnectionError(
                            "Sunucunun Finished MAC'i uyuşmuyor — handshake transcript'i üzerinde "
                            "anlaşamadık. Bu, araya girme veya veri değiştirme göstergesidir; "
                            "bağlantı reddedildi."
                        )
                    logger.debug("Server Finished doğrulandı")

            if order.done and handshake_buffer:
                # Finished anahtar değişiminden önce record sınırında bitmeli (§5.1).
                raise _unexpected("Finished sonrasında aynı record'da ek handshake verisi.")

        # ---- Client EncryptedExtensions (ALPS) + Client Finished ----------------
        hash_len = hash_func().digest_size
        # Application secret'lar transcript'i SERVER Finished'a kadar kapsar.
        t_hash = hash_func(state["handshake_messages"]).digest()
        if send_client_ee:
            # Sunucu ALPS'i kabul etti: istemci EE'yi Finished'tan önce yollar
            # (transcript'e girer; Finished MAC'i onu da kapsar).
            client_ee = build_client_encrypted_extensions()
            esock.send_record(client_ee, content_type=0x16, use_app_keys=False)
            state["handshake_messages"] += client_ee
        if cert_req is not None:
            # RFC 8446 §4.4.2-4.4.3: Certificate [+ CertificateVerify], Finished'tan ÖNCE.
            # Uygun sertifika/şema yoksa boş Certificate (sunucu karar verir). Mantık saf
            # fonksiyonlarda (security/mtls.py); async çekirdekle ortak.
            auth_msgs, auth_scheme = mtls.client_auth_flight_13(
                client_cert, cert_req, hash_func, state["handshake_messages"])
            for m in auth_msgs:
                esock.send_record(m, content_type=0x16, use_app_keys=False)
                state["handshake_messages"] += m
            state["client_signature_scheme"] = auth_scheme
            state["client_cert_sent"] = auth_scheme is not None
        f_key = PureCryptoEngine.tls13_hkdf_expand_label(
            state["client_hts"], "finished", b"", hash_len, hash_alg=hash_func
        )
        mac = hmac.new(f_key, hash_func(state["handshake_messages"]).digest(), hash_func).digest()
        finished_msg = b"\x14" + struct.pack("!I", len(mac))[1:] + mac

        esock.send_record(finished_msg, content_type=0x16, use_app_keys=False)

        if resumption_on:
            state["resumption_master_secret"] = session_tickets.derive_resumption_master_secret(
                state["handshake_secret"],
                hash_func(state["handshake_messages"] + finished_msg).digest(),
                hash_alg=hash_func,
            )
            state["cipher_suite"] = cipher_suite
            state["ticket_cache_key"] = ticket_key

        # ---- Application anahtarları -------------------------------------------
        ak, aiv, ask_key, asiv, c_ats, s_ats = PureCryptoEngine.derive_application_keys(
            state["handshake_secret"], t_hash, state["key_len"], hash_alg=hash_func
        )
        state.update({
            "app_client_write_key": ak, "app_client_write_iv": aiv,
            "app_server_write_key": ask_key, "app_server_write_iv": asiv,
            "client_ats": c_ats, "server_ats": s_ats,
            "key_updates_received": 0,
            "using_app_keys": True,
        })

        logger.debug(
            "TLS 1.3 handshake tamam: host=%s suite=0x%04x alpn=%r",
            host, cipher_suite, state["alpn"],
        )
        return esock
