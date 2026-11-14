"""sans-IO TLS 1.3 istemci durum makinesi.

Soket yok, I/O yok: çağıran taraf byte'ları taşır.

    conn = TLSClientConnection("example.com", "chrome_131")
    sock.sendall(conn.initiate())                 # ClientHello
    while not conn.handshake_complete:
        events = conn.receive_data(sock.recv(65536))
        sock.sendall(conn.data_to_send())         # client Finished vb.
    sock.sendall(conn.send_application_data(b"GET / HTTP/1.1\\r\\n..."))

Güvenlik: eski TLSAdapter.negotiate ile birebir aynı üç kontrol zorunludur —
(1) sertifika zinciri + hostname (cert_validator.validate_server_certificate),
(2) CertificateVerify imzası (cert_validator.verify_certificate_verify),
(3) sunucu Finished MAC'i. Biri eksikse/başarısızsa TLSError fırlatılır ve
bağlantı kullanılamaz hâle gelir.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Callable, Optional

from ..crypto_math import (
    PureCryptoEngine as _P,
    FastAESGCM as _AESGCM,
    FastChaCha20Poly1305 as _ChaCha,
)
from ..tls_crafter import (
    TLSImpersonator, alps_accepted, build_client_encrypted_extensions,
)
from ..security import cert_validator as _cv
from ..security import session_tickets as _st
from ..security.cert_validator import CertificateValidationError
from . import _compat as C
from .errors import TLSError, TLSAlertError
from .events import (
    Event,
    HandshakeComplete,
    ApplicationData,
    NewSessionTicket,
    KeyUpdateReceived,
    AlertReceived,
    ConnectionClosed,
)

# Record content type'ları
CT_CHANGE_CIPHER_SPEC = 20
CT_ALERT = 21
CT_HANDSHAKE = 22
CT_APPLICATION_DATA = 23

# Handshake mesaj tipleri
HS_SERVER_HELLO = 2
HS_NEW_SESSION_TICKET = 4
HS_ENCRYPTED_EXTENSIONS = 8
HS_CERTIFICATE = 11
HS_CERTIFICATE_REQUEST = 13
HS_CERTIFICATE_VERIFY = 15
HS_FINISHED = 20
HS_KEY_UPDATE = 24
HS_COMPRESSED_CERTIFICATE = 25

# Bir handshake mesajı için üst sınır (sertifika zincirleri büyük olabilir).
MAX_HANDSHAKE_MESSAGE = 1 << 18

# Durumlar
ST_IDLE = "IDLE"
ST_WAIT_SH = "WAIT_SH"
ST_WAIT_ENCRYPTED = "WAIT_ENCRYPTED"   # EE..Finished
ST_CONNECTED = "CONNECTED"
ST_CLOSED = "CLOSED"


def parse_alpn(ee_msg: bytes) -> str:
    """EncryptedExtensions (4 byte hs header dahil) içinden seçilen ALPN."""
    try:
        if len(ee_msg) < 6:
            return ""
        total = struct.unpack("!H", ee_msg[4:6])[0]
        cur, end = 6, min(6 + total, len(ee_msg))
        while cur + 4 <= end:
            et, el = struct.unpack("!HH", ee_msg[cur:cur + 4])
            cur += 4
            if et == 16 and el >= 3:
                plen = ee_msg[cur + 2]
                return ee_msg[cur + 3:cur + 3 + plen].decode("ascii", errors="ignore")
            cur += el
    except (struct.error, IndexError):
        pass
    return ""


class _Direction:
    """Tek yön için AEAD durumu: anahtar, IV, sequence, traffic secret."""

    __slots__ = ("secret", "key", "iv", "seq", "aead", "is_aes")

    def __init__(self, secret: bytes, key: bytes, iv: bytes, cipher_name: str):
        self.secret = secret
        self.key = key
        self.iv = iv
        self.seq = 0
        self.is_aes = cipher_name.startswith("AES")
        # Cipher nesnesi anahtar değişene kadar önbellekte tutulur.
        self.aead = _AESGCM(key) if self.is_aes else _ChaCha(key)

    def nonce(self) -> bytes:
        seq = self.seq.to_bytes(12, "big")
        return bytes(a ^ b for a, b in zip(self.iv, seq))

    def seal(self, inner: bytes, header: bytes) -> bytes:
        if self.seq >= (1 << 64) - 1:
            raise TLSError("Sequence number taştı; KeyUpdate gerekli.")
        n = self.nonce()
        if self.is_aes:
            ct, tag = self.aead.encrypt_gcm(n, inner, header)
        else:
            ct, tag = self.aead.encrypt_aead(n, inner, header)
        self.seq += 1
        return ct + tag

    def open(self, payload: bytes, header: bytes) -> bytes:
        n = self.nonce()
        ct, tag = payload[:-16], payload[-16:]
        try:
            if self.is_aes:
                pt = self.aead.decrypt_gcm(n, ct, header, tag)
            else:
                pt = self.aead.decrypt_aead(n, ct, header, tag)
        except ValueError as e:
            raise TLSError(f"bad_record_mac: TLS record'u doğrulanamadı ({e})") from e
        self.seq += 1
        return pt


class TLSClientConnection:
    """sans-IO TLS 1.3 istemcisi (tarayıcı parmak izi taklitli ClientHello).

    Args:
        host: SNI ve sertifika hostname doğrulaması için ad.
        profile: fingerprint profili (ör. "chrome_131"); None -> varsayılan.
        alpn: Profilin ALPN listesini geçersiz kılar (ör. ["http/1.1"]).
            Verilmezse profilinki aynen kullanılır (parmak izi korunur).
        ca_path: Ek/özel CA bundle yolu (cert_validator destekliyorsa iletilir).
        cert_validator: (cert_msg, host) -> x509.Certificate çağrılabilir;
            None ise security.cert_validator.validate_server_certificate.
            Özel doğrulayıcı verilirse PSK resumption KULLANILMAZ (biletin
            devraldığı kimliğin hangi güven kökünden geldiği bilinemez).
        port: Hedef port; PSK bilet önbelleği anahtarının (host+port+ca_path)
            parçasıdır. Bilinmiyorsa boş port ile anahtarlanır.
    """

    def __init__(
        self,
        host: str,
        profile: Optional[str] = None,
        *,
        alpn: Optional[list[str]] = None,
        ca_path: Optional[str] = None,
        cert_validator: Optional[Callable] = None,
        impersonator: Optional[TLSImpersonator] = None,
        port: Optional[int] = None,
    ):
        self.host = host
        self.port = port
        self.profile = profile
        self.ca_path = ca_path
        self._cert_validator = cert_validator
        self._imp = impersonator or TLSImpersonator(host, profile=profile)
        if alpn is not None:
            self._imp.profile = dict(self._imp.profile, alpn=list(alpn))

        self.state = ST_IDLE
        self.cipher_suite: Optional[int] = None
        self.cipher_name = "CHACHA20-POLY1305"
        self.key_len = 32
        self.alpn = ""
        self.peer_certificate = None
        self.signature_scheme: Optional[int] = None

        self._hash = hashlib.sha256
        self._transcript = b""
        self._inbuf = bytearray()
        self._outbuf = bytearray()
        self._hs_buf = b""            # handshake mesajı birleştirme tamponu
        self._hs_buf_epoch = None     # tampon hangi anahtar döneminden
        self._read: Optional[_Direction] = None
        self._epoch = 0               # her okuma anahtarı değişiminde artar
        self._write: Optional[_Direction] = None
        self._hs_secret = b""
        self._c_hts = b""
        self._s_hts = b""
        self._order = C.HandshakeOrderValidator()
        self._session_id = b""
        self._ch1 = b""               # ilk ClientHello (hs mesajı, header dahil)
        self._hrr: Optional[dict] = None
        self._cert_seen = False
        self._cv_ok = False
        # PSK resumption (security/session_tickets; varsayılan KAPALI). Senkron yolla
        # AYNI önbelleği ve aynı saf fonksiyonları paylaşır.
        self._ticket = None            # teklif edilen SessionTicket
        self._ticket_key: Optional[str] = None
        self._rms: Optional[bytes] = None
        self.resumed = False
        self._close_sent = False
        # ServerHello TLS 1.2 seçerse (security/tls12.py) tüm iş buna devredilir.
        self._t12 = None

    # ------------------------------------------------------------------ API
    @property
    def handshake_complete(self) -> bool:
        return self.state == ST_CONNECTED

    @property
    def closed(self) -> bool:
        return self.state == ST_CLOSED

    def initiate(self) -> bytes:
        """ClientHello record'unu üretir ve döner (ayrıca tampona koymaz)."""
        if self.state != ST_IDLE:
            raise TLSError("initiate() yalnızca bir kez çağrılabilir.")
        if self._cert_validator is None:
            self._ticket_key = _st.resumption_key(self.host, self.port, self.ca_path)
        record, _priv, _rand, self._ticket = _st.begin_resumption(self._imp, self._ticket_key)
        self._ch1 = record[5:]
        self._session_id = self._ch1[4 + 2 + 32 + 1:4 + 2 + 32 + 1 + self._ch1[4 + 2 + 32]]
        self._transcript = self._ch1
        self.state = ST_WAIT_SH
        return record

    def data_to_send(self) -> bytes:
        """Gönderilmeyi bekleyen tüm byte'ları döner ve tamponu boşaltır."""
        out = bytes(self._outbuf)
        self._outbuf.clear()
        if self._t12 is not None:
            out += self._t12.data_to_send()
        return out

    def send_application_data(self, data: bytes) -> bytes:
        """Uygulama verisini şifreli record(lar)a çevirir.

        Önce bekleyen çıktıyı (ör. KeyUpdate yanıtı) döner — sıra önemlidir,
        çünkü yeni anahtarla şifrelenen record'lar ondan sonra gelmelidir.
        """
        if self.state != ST_CONNECTED:
            raise TLSError("Handshake tamamlanmadan application data gönderilemez.")
        self.send_record(data, CT_APPLICATION_DATA)
        return self.data_to_send()

    def send_record(self, data: bytes, content_type: int = CT_APPLICATION_DATA) -> None:
        """Veriyi mevcut yazma anahtarıyla şifreleyip çıkış tamponuna ekler.

        MAX_PLAINTEXT'ten büyük veri birden çok record'a bölünür.
        """
        if self._t12 is not None:
            self._t12_call(self._t12.send_record, data, content_type)
            return
        if self._write is None:
            raise TLSError("Yazma anahtarı yok — handshake başlamadı.")
        if self.state == ST_CLOSED:
            raise TLSError("Bağlantı kapalı.")
        mp = C.MAX_PLAINTEXT
        if not data:
            self._seal(b"", content_type)
            return
        for i in range(0, len(data), mp):
            self._seal(data[i:i + mp], content_type)

    def update_keys(self, request_peer: bool = True) -> bytes:
        """İstemci kaynaklı KeyUpdate gönderir; yazma anahtarını döndürür."""
        if self.state != ST_CONNECTED:
            raise TLSError("KeyUpdate yalnızca handshake sonrası gönderilebilir.")
        if self._t12 is not None:
            raise TLSError("TLS 1.2'de KeyUpdate yoktur.")
        self._seal(C.build_key_update(request_peer), CT_HANDSHAKE)
        self._rotate_write()
        return self.data_to_send()

    def close(self) -> bytes:
        """close_notify alert'i üretir (şifreli, handshake sonrası)."""
        if self._t12 is not None:
            out = self._t12.close()
            self.state = ST_CLOSED
            return out
        if self._write is not None and not self._close_sent and self.state != ST_CLOSED:
            self._seal(b"\x01\x00", CT_ALERT)
            self._close_sent = True
        self.state = ST_CLOSED
        return self.data_to_send()

    def crypto_state(self) -> dict:
        """EncryptedSocket.state ile uyumlu (salt-okunur) özet."""
        if self._t12 is not None:
            return self._t12.crypto_state()
        return {
            "is_tls13": self.cipher_suite is not None,
            "using_app_keys": self.state == ST_CONNECTED,
            "cipher_name": self.cipher_name,
            "cipher_suite": self.cipher_suite,
            "key_len": self.key_len,
            "alpn": self.alpn,
            "peer_certificate": self.peer_certificate,
            "resumed": self.resumed,
        }

    def receive_data(self, data: bytes) -> list[Event]:
        """Gelen byte'ları işler; oluşan olayları döner.

        Eksik record'lar tamponda bekletilir. Protokol veya doğrulama
        hatasında TLSError fırlatılır ve bağlantı CLOSED olur.
        """
        if self.state == ST_IDLE:
            raise TLSError("receive_data() initiate()'den önce çağrıldı.")
        if self.state == ST_CLOSED:
            return []
        if self._t12 is not None:
            return self._t12_call(self._t12.receive_data, data)
        self._inbuf += data
        events: list[Event] = []
        try:
            while self.state != ST_CLOSED and len(self._inbuf) >= 5:
                rtype = self._inbuf[0]
                rlen = struct.unpack("!H", self._inbuf[3:5])[0]
                if rlen > C.MAX_CIPHERTEXT:
                    raise TLSError(f"record_overflow: record uzunluğu {rlen} > {C.MAX_CIPHERTEXT}")
                if len(self._inbuf) < 5 + rlen:
                    break
                header = bytes(self._inbuf[:5])
                payload = bytes(self._inbuf[5:5 + rlen])
                del self._inbuf[:5 + rlen]
                self._handle_record(rtype, header, payload, events)
                if self._t12 is not None:
                    # ServerHello TLS 1.2 seçti: kalan baytlar TLS 1.2 çekirdeğinindir.
                    rest = bytes(self._inbuf)
                    self._inbuf.clear()
                    if rest:
                        events.extend(self._t12_call(self._t12.receive_data, rest))
                    break
        except TLSError:
            self.state = ST_CLOSED
            raise
        return events

    # ------------------------------------------------------------ internals
    def _seal(self, content: bytes, content_type: int) -> None:
        inner = content + bytes([content_type])
        header = struct.pack("!BHH", CT_APPLICATION_DATA, 0x0303, len(inner) + 16)
        self._outbuf += header + self._write.seal(inner, header)

    def _handle_record(self, rtype: int, header: bytes, payload: bytes, events: list) -> None:
        if rtype == CT_CHANGE_CIPHER_SPEC:
            # TLS 1.3 uyumluluk CCS'i: yalnızca handshake sırasında, tek byte 0x01.
            if self.state == ST_CONNECTED or payload != b"\x01":
                raise TLSError("unexpected_message: beklenmeyen change_cipher_spec record'u")
            return

        if self._read is None:
            # Henüz şifreleme yok: yalnızca ServerHello/HRR (handshake) veya alert.
            if rtype == CT_ALERT:
                self._raise_alert(payload)
            if rtype != CT_HANDSHAKE:
                raise TLSError(f"ServerHello beklenirken beklenmeyen record tipi: {rtype}")
            if len(payload) > C.MAX_PLAINTEXT:
                raise TLSError("record_overflow: düz metin record'u çok büyük")
            self._feed_handshake(payload, events, epoch=self._epoch)
            return

        if rtype == CT_ALERT and self.state != ST_CONNECTED:
            # Bazı sunucular handshake ortasında şifresiz alert gönderebilir.
            self._raise_alert(payload)
        if rtype != CT_APPLICATION_DATA:
            raise TLSError(f"unexpected_message: şifreli aşamada record tipi {rtype}")
        if len(payload) < 17:
            raise TLSError("TLS record'u AEAD tag'i için fazla kısa — bozuk veri.")

        pt = self._read.open(payload, header)
        idx = len(pt) - 1
        while idx >= 0 and pt[idx] == 0:
            idx -= 1
        if idx < 0:
            raise TLSError("unexpected_message: record yalnızca padding içeriyor, content_type yok")
        inner, itype = pt[:idx], pt[idx]
        if len(inner) > C.MAX_PLAINTEXT:
            raise TLSError("record_overflow: çözülmüş düz metin 2^14 byte'ı aşıyor")

        if itype == CT_HANDSHAKE:
            if not inner:
                raise TLSError("unexpected_message: boş handshake record'u")
            self._feed_handshake(inner, events, epoch=self._epoch)
        elif itype == CT_APPLICATION_DATA:
            if self.state != ST_CONNECTED:
                raise TLSError("unexpected_message: handshake bitmeden application data")
            if self._hs_buf:
                raise TLSError("unexpected_message: yarım handshake mesajı arasında application data")
            events.append(ApplicationData(inner))
        elif itype == CT_ALERT:
            if len(inner) != 2:
                raise TLSError("decode_error: bozuk alert")
            level, desc = inner[0], inner[1]
            was_connected = self.state == ST_CONNECTED
            self.state = ST_CLOSED
            if desc == 0:
                events.append(ConnectionClosed(bytes(inner)))
            elif was_connected:
                events.append(AlertReceived(level, desc))
            else:
                raise TLSAlertError(level, desc, f"Sunucudan Şifreli TLS Alert: {inner.hex()}")
        else:
            raise TLSError(f"unexpected_message: bilinmeyen iç content type {itype}")

    def _raise_alert(self, payload: bytes) -> None:
        level = payload[0] if len(payload) > 0 else 2
        desc = payload[1] if len(payload) > 1 else 0
        raise TLSAlertError(level, desc, f"Sunucu el sıkışmayı reddetti (alert): {payload.hex()}")

    def _feed_handshake(self, data: bytes, events: list, epoch) -> None:
        # Handshake mesajları anahtar değişimi sınırını aşamaz (RFC 8446 §5.1).
        if self._hs_buf and self._hs_buf_epoch != epoch:
            raise TLSError("unexpected_message: handshake mesajı anahtar değişimi sınırını aştı")
        self._hs_buf += data
        self._hs_buf_epoch = epoch
        while len(self._hs_buf) >= 4:
            hs_len = int.from_bytes(self._hs_buf[1:4], "big")
            if hs_len > MAX_HANDSHAKE_MESSAGE:
                raise TLSError(f"Handshake mesajı çok büyük ({hs_len} byte)")
            if len(self._hs_buf) < 4 + hs_len:
                break
            msg = self._hs_buf[:4 + hs_len]
            self._hs_buf = self._hs_buf[4 + hs_len:]
            self._handle_handshake(msg, events)
            if self._t12 is not None:
                break                      # kalan baytlar _begin_tls12'de devredildi
            # ServerHello/Finished sonrası anahtar değişir; tamponda kalan veri
            # eski anahtarla gelmiş demektir -> protokol ihlali.
            if self._hs_buf and self._hs_buf_epoch != self._epoch:
                raise TLSError("unexpected_message: handshake mesajı anahtar değişimi sınırını aştı")

    def _handle_handshake(self, msg: bytes, events: list) -> None:
        hs_type = msg[0]
        if self.state == ST_WAIT_SH:
            self._on_server_hello(msg, events)
            return
        if self.state == ST_WAIT_ENCRYPTED:
            self._on_encrypted_handshake(msg, events)
            return
        if self.state == ST_CONNECTED:
            self._on_post_handshake(msg, events)
            return
        raise TLSError(f"unexpected_message: durum={self.state}, hs_type={hs_type}")

    # ------------------------------------------------------- ServerHello / HRR
    def _begin_tls12(self, msg: bytes, events: list) -> None:
        """ServerHello TLS 1.2 seçti: güvenli TLS 1.2 alt kümesine devret (security/tls12.py).

        HRR sonrası TLS 1.2 seçimi protokol ihlalidir (sunucu 1.3'ü kabul etmişti).
        """
        from ..security import tls12 as _t12mod
        if self._hrr is not None:
            raise TLSError("unexpected_message: HelloRetryRequest'ten sonra sunucu TLS 1.2 seçti — "
                           "protokol ihlali / olası downgrade.")
        trailing = bytes(self._hs_buf)        # ServerHello'yla aynı record'daki artık handshake baytları
        self._hs_buf = b""
        try:
            self._t12 = _t12mod.TLS12ClientConnection(
                self.host, self._ch1, ca_path=self.ca_path, cert_validator=self._cert_validator,
            )
        except _t12mod.TLS12Error as e:
            raise TLSError(str(e)) from e
        self.state = ST_WAIT_ENCRYPTED
        events.extend(self._t12_call(self._t12.start, msg, trailing))

    def _t12_call(self, fn, *args):
        """TLS 1.2 çekirdeğini çağırır; hatayı TLSError'a çevirir, durumu senkronlar."""
        from ..security import tls12 as _t12mod
        try:
            res = fn(*args)
        except _t12mod.TLS12AlertError as e:
            self.state = ST_CLOSED
            self._sync_t12()
            raise TLSAlertError(e.level, e.description, str(e)) from e
        except _t12mod.TLS12Error as e:
            self.state = ST_CLOSED
            self._sync_t12()
            raise TLSError(str(e)) from e
        self._sync_t12()
        return res

    def _sync_t12(self) -> None:
        t = self._t12
        self.cipher_suite, self.cipher_name, self.key_len = t.cipher_suite, t.cipher_name, t.key_len
        self.alpn = t.alpn
        self.peer_certificate = t.peer_certificate
        self.signature_scheme = t.signature_scheme
        if t.closed:
            self.state = ST_CLOSED
        elif t.handshake_complete:
            self.state = ST_CONNECTED

    def _on_server_hello(self, msg: bytes, events: Optional[list] = None) -> None:
        if msg[0] != HS_SERVER_HELLO:
            raise TLSError(f"unexpected_message: ServerHello beklenirken hs_type={msg[0]}")
        from ..security import tls12 as _t12mod
        if _t12mod.is_tls12_server_hello(msg):
            self._begin_tls12(msg, events if events is not None else [])
            return
        try:
            sh = C.parse_server_hello(msg, self._session_id)
        except C.TLSProtocolError as e:
            raise TLSError(str(e)) from e

        if sh["is_hrr"]:
            self._on_hello_retry_request(msg, sh)
            return

        try:
            self._order.expect(HS_SERVER_HELLO)
        except C.TLSProtocolError as e:
            raise TLSError(str(e)) from e
        if self._hrr is not None:
            if sh["cipher_suite"] != self._hrr["cipher_suite"]:
                raise TLSError("illegal_parameter: ServerHello cipher suite HRR'dekinden farklı")
            if sh["selected_group"] != self._hrr["selected_group"]:
                raise TLSError("illegal_parameter: ServerHello grubu HRR'de istenenden farklı")

        self._set_suite(sh["cipher_suite"])
        try:
            psk_accepted = _st.check_psk_selection(
                self._ticket, sh.get("selected_identity"), sh["cipher_suite"], self._hrr is not None)
        except _st.PskViolation as e:
            raise TLSError(f"illegal_parameter: {e}") from e
        if not sh["server_pub"] or sh["selected_group"] is None:
            raise TLSError("ServerHello geçerli bir key_share içermiyor — handshake tamamlanamaz.")
        try:
            shared = C.client_shared_secret(self._imp, sh["selected_group"], sh["server_pub"])
        except ValueError as e:
            raise TLSError(f"illegal_parameter: key_share geçersiz: {e}") from e

        self._transcript += msg
        th = self._hash(self._transcript).digest()
        if psk_accepted:
            # Resumption: kimlik bileti veren handshake'ten devralınır; Certificate/CV gelmez.
            self._order.psk_accepted = True
            self.resumed = True
            self.peer_certificate = self._ticket.peer_certificate
            hs, ck, civ, sk, siv, c_hts, s_hts = _st.derive_handshake_keys_psk(
                self._ticket.psk, shared, th, self.key_len, hash_alg=self._hash
            )
        else:
            hs, ck, civ, sk, siv, c_hts, s_hts = _P.derive_tls13_keys(
                shared, th, self.key_len, hash_alg=self._hash
            )
        self._hs_secret, self._c_hts, self._s_hts = hs, c_hts, s_hts
        self._write = _Direction(c_hts, ck, civ, self.cipher_name)
        self._read = _Direction(s_hts, sk, siv, self.cipher_name)
        self._epoch += 1
        self.state = ST_WAIT_ENCRYPTED

    def _on_hello_retry_request(self, msg: bytes, sh: dict) -> None:
        if self._hrr is not None:
            raise TLSError("unexpected_message: ikinci HelloRetryRequest")
        retry = getattr(self._imp, "build_retry_client_hello", None)
        if retry is None:
            raise TLSError(
                "Sunucu HelloRetryRequest gönderdi; bu kurulumda HRR desteklenmiyor "
                "(TLSImpersonator.build_retry_client_hello yok)."
            )
        group = sh["selected_group"]
        if group is None:
            raise TLSError("illegal_parameter: HRR key_share grubu içermiyor")
        if group not in _supported_groups() or group in _offered_groups(self._imp):
            raise TLSError(
                f"illegal_parameter: HRR grubu 0x{group:04x} desteklenmiyor veya zaten teklif edilmişti"
            )
        try:
            self._order.expect(HS_SERVER_HELLO, is_hrr=True)
        except C.TLSProtocolError as e:
            raise TLSError(str(e)) from e
        self._set_suite(sh["cipher_suite"])
        self._hrr = sh
        # RFC 8446 §4.4.1: transcript = message_hash(CH1) || HRR || CH2
        record = retry(group, cookie=sh.get("cookie"))
        self._transcript = C.message_hash(self._hash, self._ch1) + msg + record[5:]
        self._outbuf += record

    def _set_suite(self, suite: int) -> None:
        try:
            self.cipher_name, self.key_len, self._hash = C.suite_params(suite)
        except C.TLSProtocolError as e:
            raise TLSError(str(e)) from e
        self.cipher_suite = suite

    # ------------------------------------------------ EE / Cert / CV / Finished
    def _on_encrypted_handshake(self, msg: bytes, events: list) -> None:
        hs_type = msg[0]
        if hs_type == HS_CERTIFICATE_REQUEST:
            raise TLSError("Sunucu istemci sertifikası istedi (CertificateRequest) — desteklenmiyor.")
        try:
            self._order.expect(hs_type)
        except C.TLSProtocolError as e:
            raise TLSError(str(e)) from e

        # Transcript hash bu mesaj EKLENMEDEN önce alınır: CertificateVerify ve
        # Finished kendilerinden ÖNCEKİ transcript'i kapsar.
        transcript_before = self._hash(self._transcript).digest()
        self._transcript += msg

        if hs_type == HS_ENCRYPTED_EXTENSIONS:
            self.alpn = parse_alpn(msg)
            self._send_client_ee = alps_accepted(
                getattr(self._imp, "alps_advertised", False), msg, self.alpn)

        elif hs_type in (HS_CERTIFICATE, HS_COMPRESSED_CERTIFICATE, HS_CERTIFICATE_VERIFY) and self.resumed:
            raise TLSError(
                "unexpected_message: PSK ile devam edilen oturumda sunucu Certificate/CertificateVerify "
                "gönderdi — protokol ihlali (RFC 8446 §4.4.2)."
            )

        elif hs_type in (HS_CERTIFICATE, HS_COMPRESSED_CERTIFICATE):
            if hs_type == HS_COMPRESSED_CERTIFICATE:
                try:
                    msg = _cv.decompress_certificate_message(msg)
                except CertificateValidationError as e:
                    raise TLSError(f"Sıkıştırılmış sertifika açılamadı: {e}") from e
            try:
                self.peer_certificate = self._validate_cert(msg)
            except CertificateValidationError as e:
                raise TLSError(
                    f"TLS sertifika doğrulaması başarısız — bağlantı güvenli değil, "
                    f"olası MITM saldırısı: {e}"
                ) from e
            self._cert_seen = True

        elif hs_type == HS_CERTIFICATE_VERIFY:
            if not self._cert_seen or self.peer_certificate is None:
                raise TLSError("Sunucu Certificate göndermeden CertificateVerify gönderdi — protokol ihlali.")
            try:
                self.signature_scheme = _cv.verify_certificate_verify(
                    msg, self.peer_certificate, transcript_before
                )
            except CertificateValidationError as e:
                raise TLSError(f"TLS kimlik doğrulaması başarısız: {e}") from e
            self._cv_ok = True

        elif hs_type == HS_FINISHED:
            if not self.resumed and not self._cert_seen:
                raise TLSError("Handshake Finished'a ulaştı ama sunucu sertifikası hiç doğrulanmadı.")
            if not self.resumed and not self._cv_ok:
                raise TLSError("Sunucu CertificateVerify göndermedi veya doğrulanamadı.")
            hlen = self._hash().digest_size
            fkey = _P.tls13_hkdf_expand_label(self._s_hts, "finished", b"", hlen, hash_alg=self._hash)
            expected = hmac.new(fkey, transcript_before, self._hash).digest()
            if not hmac.compare_digest(expected, msg[4:]):
                raise TLSError(
                    "Sunucunun Finished MAC'i uyuşmuyor — handshake transcript'i üzerinde "
                    "anlaşamadık; bağlantı reddedildi."
                )
            self._finish_handshake(events)

        else:  # pragma: no cover - validator bunu zaten engeller
            raise TLSError(f"unexpected_message: hs_type={hs_type}")

    def _validate_cert(self, cert_msg: bytes):
        if self._cert_validator is not None:
            return self._cert_validator(cert_msg, self.host)
        if self.ca_path is not None:
            return _cv.validate_server_certificate(cert_msg, self.host, ca_path=self.ca_path)
        return _cv.validate_server_certificate(cert_msg, self.host)

    def _finish_handshake(self, events: list) -> None:
        # Server Finished dahil transcript -> application secret'lar
        th_sf = self._hash(self._transcript).digest()
        hlen = self._hash().digest_size
        if getattr(self, "_send_client_ee", False):
            # ALPS kabul edildi: istemci EncryptedExtensions Finished'tan ÖNCE
            # gider, transcript'e girer (application secret'lar ise SERVER
            # Finished'a kadar olan th_sf'ten türer).
            cee = build_client_encrypted_extensions()
            self._seal(cee, CT_HANDSHAKE)
            self._transcript += cee
        fkey = _P.tls13_hkdf_expand_label(self._c_hts, "finished", b"", hlen, hash_alg=self._hash)
        mac = hmac.new(fkey, self._hash(self._transcript).digest(), self._hash).digest()
        finished = bytes([HS_FINISHED]) + len(mac).to_bytes(3, "big") + mac
        self._seal(finished, CT_HANDSHAKE)          # handshake anahtarıyla
        self._transcript += finished
        if self._ticket_key is not None:
            # resumption_master_secret: transcript client Finished DAHİL.
            self._rms = _st.derive_resumption_master_secret(
                self._hs_secret, self._hash(self._transcript).digest(), self._hash)

        c_ats, s_ats = application_traffic_secrets(self._hs_secret, th_sf, self._hash)
        ck, civ = C.traffic_key_iv(c_ats, self.key_len, self._hash)
        sk, siv = C.traffic_key_iv(s_ats, self.key_len, self._hash)
        self._write = _Direction(c_ats, ck, civ, self.cipher_name)
        self._read = _Direction(s_ats, sk, siv, self.cipher_name)
        self._epoch += 1
        self.state = ST_CONNECTED
        events.append(HandshakeComplete(
            cipher_suite=self.cipher_suite, alpn=self.alpn,
            peer_certificate=self.peer_certificate,
            signature_scheme=self.signature_scheme,
        ))

    # --------------------------------------------------------- post-handshake
    def _on_post_handshake(self, msg: bytes, events: list) -> None:
        hs_type = msg[0]
        if hs_type == HS_NEW_SESSION_TICKET:
            _st.store_new_session_tickets(
                self._ticket_key, msg, self._rms, self.cipher_suite or 0,
                peer_certificate=self.peer_certificate)
            events.append(NewSessionTicket(msg))
        elif hs_type == HS_KEY_UPDATE:
            try:
                requested = C.parse_key_update(msg)
            except C.TLSProtocolError as e:
                raise TLSError(str(e)) from e
            self._rotate_read()
            if requested:
                # Yanıt ESKİ yazma anahtarıyla gider, sonra yazma anahtarı döner.
                self._seal(C.build_key_update(False), CT_HANDSHAKE)
                self._rotate_write()
            events.append(KeyUpdateReceived(msg, requested))
        else:
            raise TLSError(f"unexpected_message: handshake sonrası hs_type={hs_type}")

    def _rotate_read(self) -> None:
        s = C.next_traffic_secret(self._read.secret, self._hash)
        k, iv = C.traffic_key_iv(s, self.key_len, self._hash)
        self._read = _Direction(s, k, iv, self.cipher_name)
        self._epoch += 1

    def _rotate_write(self) -> None:
        s = C.next_traffic_secret(self._write.secret, self._hash)
        k, iv = C.traffic_key_iv(s, self.key_len, self._hash)
        self._write = _Direction(s, k, iv, self.cipher_name)


def application_traffic_secrets(hs_secret: bytes, transcript_hash: bytes, hash_alg):
    """(client_application_traffic_secret_0, server_application_traffic_secret_0)."""
    hlen = hash_alg().digest_size
    derived = _P.tls13_hkdf_expand_label(
        hs_secret, "derived", hash_alg(b"").digest(), hlen, hash_alg=hash_alg
    )
    master = _P.hkdf_extract(derived, b"\x00" * hlen, hash_alg=hash_alg)
    c = _P.tls13_hkdf_expand_label(master, "c ap traffic", transcript_hash, hlen, hash_alg=hash_alg)
    s = _P.tls13_hkdf_expand_label(master, "s ap traffic", transcript_hash, hlen, hash_alg=hash_alg)
    return c, s


def _supported_groups() -> tuple:
    try:
        from ..security.keyshare import SUPPORTED_GROUPS  # type: ignore
        return tuple(SUPPORTED_GROUPS)
    except ImportError:
        return (0x001D,)


def _offered_groups(imp) -> set:
    ks = getattr(imp, "key_shares", None)
    if ks is None:
        return {0x001D}
    groups = getattr(ks, "groups", None)
    if groups is None and hasattr(ks, "entries"):
        groups = [e[0] if isinstance(e, tuple) else e for e in ks.entries()]
    return set(groups or ())
