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
from ..tls_crafter import TLSImpersonator
from .._log import get_logger
from .alerts import describe_alert
from .keyshare import (
    is_hello_retry_request,
    parse_hrr,
    message_hash,
    group_name,
    is_supported_group,
)
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
_HS_NEW_SESSION_TICKET = 4
_HS_ENCRYPTED_EXTENSIONS = 8
_HS_CERTIFICATE = 11
_HS_CERTIFICATE_VERIFY = 15
_HS_FINISHED = 20
_HS_COMPRESSED_CERTIFICATE = 25


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


class EncryptedSocket:
    """TLS 1.3 record katmanı. AEAD şifreleme/çözme ve sequence number yönetimi."""

    def __init__(self, raw_socket: socket.socket, crypto_state: dict):
        self.raw_socket = raw_socket
        self.state = crypto_state
        self.read_buffer = b""

    def _cipher(self, key: bytes):
        if self.state["cipher_name"].startswith("AES"):
            return PureAESGCM(key), True
        return PureChaCha20Poly1305(key), False

    def send_record(self, data: bytes, content_type: int = 0x17, use_app_keys: bool = True) -> None:
        if not self.state.get("is_tls13"):
            raise ConnectionError("Yalnızca TLS 1.3 desteklenmektedir.")

        key = self.state["app_client_write_key"] if use_app_keys else self.state["client_write_key"]
        iv = self.state["app_client_write_iv"] if use_app_keys else self.state["client_write_iv"]
        seq = self.state["app_client_seq_num"] if use_app_keys else self.state["client_seq_num"]

        inner = data + struct.pack("!B", content_type)
        nonce = bytes(a ^ b for a, b in zip(iv, b"\x00" * 4 + seq.to_bytes(8, "big")))
        header = struct.pack("!BHH", 0x17, 0x0303, len(inner) + 16)

        cipher, is_aes = self._cipher(key)
        if is_aes:
            ct, tag = cipher.encrypt_gcm(nonce, inner, header)
        else:
            ct, tag = cipher.encrypt_aead(nonce, inner, header)

        if use_app_keys:
            self.state["app_client_seq_num"] += 1
        else:
            self.state["client_seq_num"] += 1

        self.raw_socket.sendall(header + ct + tag)

    def recv_record(self, skip_post_handshake: bool = False) -> tuple[bytes, int]:
        """Bir TLS record'u şifresini çözerek döner.

        Args:
            skip_post_handshake: True ise (HTTP katmanı çağırdığında),
                application aşamasında gelen handshake-tipi record'lar
                (NewSessionTicket, KeyUpdate) HTTP katmanına iletilmez —
                yutulur ve bir sonraki application_data record'u döner.

        TLS 1.3'te handshake biter bitmez sunucu genelde bir NewSessionTicket
        (hs_type=4) gönderir; bu, application anahtarlarıyla ŞİFRELİ bir
        handshake record'udur (content_type=22). HTTP katmanı bunu bir HTTP/2
        frame ya da HTTP/1.1 yanıtı sanarsa tüm akış bozulur — length alanı
        saçmalar, "invalid literal for int" gibi hatalar çıkar. Bu yüzden
        application verisi beklerken handshake record'ları burada yutulmalıdır.
        """
        while True:
            while len(self.read_buffer) < 5:
                chunk = self.raw_socket.recv(16384)
                if not chunk:
                    raise ConnectionResetError("TLS şifreli paket beklenirken bağlantı koptu!")
                self.read_buffer += chunk

            record_header = self.read_buffer[:5]
            rec_type = record_header[0]
            rec_len = struct.unpack("!H", record_header[3:5])[0]

            while len(self.read_buffer) < 5 + rec_len:
                chunk = self.raw_socket.recv(16384)
                if not chunk:
                    raise ConnectionResetError("TLS paket gövdesi okunurken koptu.")
                self.read_buffer += chunk

            payload = self.read_buffer[5:5 + rec_len]
            self.read_buffer = self.read_buffer[5 + rec_len:]

            if rec_type == 20:  # change_cipher_spec — TLS 1.3'te uyumluluk için, yok say
                continue
            if rec_type == 21:  # açık (şifresiz) alert
                raise ConnectionError(f"Açık TLS Alert Alındı: {payload.hex()}")

            if not self.state.get("is_tls13"):
                raise ConnectionError("Yalnızca TLS 1.3 desteklenmektedir.")

            if len(payload) < 17:
                raise ConnectionError("TLS record'u AEAD tag'i için fazla kısa — bozuk veri.")

            using_app = self.state.get("using_app_keys")
            key = self.state["app_server_write_key"] if using_app else self.state["server_write_key"]
            iv = self.state["app_server_write_iv"] if using_app else self.state["server_write_iv"]
            seq = self.state["app_server_seq_num"] if using_app else self.state["server_seq_num"]

            nonce = bytes(a ^ b for a, b in zip(iv, b"\x00" * 4 + seq.to_bytes(8, "big")))
            ct, tag = payload[:-16], payload[-16:]

            # AAD, telde GELEN record header'ının birebir kendisidir (RFC 8446 §5.2).
            # Sabit 0x17/0x0303 varsaymak, farklı legacy_record_version gönderen
            # sunucularda tag doğrulamasını hatalı biçimde başarısız kılar.
            cipher, is_aes = self._cipher(key)
            if is_aes:
                pt = cipher.decrypt_gcm(nonce, ct, record_header, tag)
            else:
                pt = cipher.decrypt_aead(nonce, ct, record_header, tag)

            if using_app:
                self.state["app_server_seq_num"] += 1
            else:
                self.state["server_seq_num"] += 1

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

            # HTTP katmanı application verisi beklerken gelen post-handshake
            # handshake mesajlarını (NewSessionTicket=4, KeyUpdate=24) yut.
            if skip_post_handshake and inner_type == 22:
                self._handle_post_handshake(inner)
                continue

            return inner, inner_type

    def _handle_post_handshake(self, msg: bytes) -> None:
        """Application aşamasında gelen handshake mesajlarını işler/yutar."""
        if not msg:
            return
        hs_type = msg[0]
        if hs_type == 4:      # NewSessionTicket — resumption yok, yok say
            return
        if hs_type == 24:     # KeyUpdate
            # Doğru yanıt anahtarları döndürmektir; bu basit istemci key update
            # implemente etmediğinden, sunucu update_requested gönderirse sonraki
            # record'lar çözülemez. Şimdilik yok sayıyoruz (nadir bir durum).
            logger.debug("KeyUpdate alındı ama işlenmiyor (implemente edilmedi)")
            return
        logger.debug("Bilinmeyen post-handshake mesajı hs_type=%d, yok sayıldı", hs_type)


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


def _tls12_hint(sh_body: bytes) -> str:
    """TLS 1.2 ServerHello'su için açıklayıcı ek mesaj (TLS 1.2 kapsam dışı)."""
    if sh_body[:2] != b"\x03\x03":
        return ""
    if sh_body[26:34] in (b"DOWNGRD\x01", b"DOWNGRD\x00"):
        # RFC 8446 §4.1.3: TLS 1.3 destekleyen sunucu daha düşük sürüm seçerse
        # random'un son 8 byte'ına bu işareti koyar → aktif downgrade saldırısı.
        return (" UYARI: ServerHello.random downgrade işareti (DOWNGRD) taşıyor — sunucu "
                "TLS 1.3 destekliyor ama araya giren biri sürümü düşürmüş olabilir.")
    return (" Sunucu TLS 1.2 ile yanıt verdi; TLS 1.3 desteklemiyor görünüyor. "
            "TLS 1.2 bilinçli olarak kapsam dışıdır (README).")


_SUITE_HASH = {0x1301: hashlib.sha256, 0x1302: hashlib.sha384, 0x1303: hashlib.sha256}


def _recv_handshake_message(raw_socket: socket.socket, what: str) -> bytes:
    """Şifresiz handshake record'larından TEK bir handshake mesajı okur.

    CCS record'larını (TLS 1.3 uyumluluk) atlar, alert'te hata verir ve
    birden çok record'a bölünmüş mesajı birleştirir.
    """
    buf = b""
    while True:
        header = _recv_all(raw_socket, 5)
        rec_type, _ver, rec_len = struct.unpack("!BHH", header)
        payload = _recv_all(raw_socket, rec_len)
        if rec_type == 20:
            continue
        if rec_type == 21:
            raise ConnectionError(f"Sunucu el sıkışmayı reddetti: {describe_alert(payload)}")
        if rec_type != 22:
            raise ConnectionError(f"{what} beklenirken beklenmeyen record tipi: {rec_type}")
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
    def negotiate(raw_socket: socket.socket, host: str, profile_name: str) -> EncryptedSocket:
        impersonator = TLSImpersonator(host, profile=profile_name)
        record_bytes, _priv_key, _c_rand = impersonator.build_client_hello()

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

        # ---- ServerHello ---------------------------------------------------
        header = _recv_all(raw_socket, 5)
        rec_type, _ver, rec_len = struct.unpack("!BHH", header)
        server_hello_payload = _recv_all(raw_socket, rec_len)

        if rec_type == 21:
            raise ConnectionError(
                f"Sunucu el sıkışmayı reddetti: {describe_alert(server_hello_payload)}"
            )
        if rec_type != 22:
            raise ConnectionError(f"ServerHello beklenirken beklenmeyen record tipi: {rec_type}")

        state["handshake_messages"] += server_hello_payload

        sh_body = server_hello_payload[4:]
        if len(sh_body) < 35:
            raise ConnectionError("ServerHello mesajı bozuk (çok kısa).")

        hrr = None
        if is_hello_retry_request(sh_body[2:34]):
            server_hello_payload, state["handshake_messages"], hrr = _handle_hrr(
                raw_socket, impersonator, record_bytes[5:], server_hello_payload
            )
            sh_body = server_hello_payload[4:]

        sess_id_len = sh_body[34]
        offset = 35 + sess_id_len
        if len(sh_body) < offset + 5:
            raise ConnectionError("ServerHello mesajı bozuk (cipher suite okunamadı).")

        cipher_suite = struct.unpack("!H", sh_body[offset:offset + 2])[0]
        if cipher_suite == 0x1301:
            state["cipher_name"], state["key_len"], hash_func = "AES", 16, hashlib.sha256
        elif cipher_suite == 0x1302:
            state["cipher_name"], state["key_len"], hash_func = "AES", 32, hashlib.sha384
        elif cipher_suite == 0x1303:
            state["cipher_name"], state["key_len"], hash_func = "CHACHA20-POLY1305", 32, hashlib.sha256
        else:
            raise ConnectionError(
                f"Sunucu desteklenmeyen bir cipher suite seçti: 0x{cipher_suite:04x}. "
                f"Bu istemci yalnızca TLS 1.3 suite'lerini destekler."
                + _tls12_hint(sh_body)
            )
        if hrr is not None and cipher_suite != hrr.cipher_suite:
            raise ConnectionError(
                "HRR sonrası ServerHello farklı bir cipher suite seçti — protokol ihlali."
            )

        extensions_len = struct.unpack("!H", sh_body[offset + 3:offset + 5])[0]
        curr = offset + 5
        ext_end = min(curr + extensions_len, len(sh_body))
        is_tls13, server_pub, selected_group = False, None, None

        while curr + 4 <= ext_end:
            ext_type, ext_len = struct.unpack("!HH", sh_body[curr:curr + 4])
            curr += 4
            if ext_type == 43 and ext_len >= 2:
                if struct.unpack("!H", sh_body[curr:curr + 2])[0] == 0x0304:
                    is_tls13 = True
            elif ext_type == 51 and ext_len > 2:
                selected_group, key_len_val = struct.unpack("!HH", sh_body[curr:curr + 4])
                server_pub = sh_body[curr + 4:curr + 4 + key_len_val]
            curr += ext_len

        if not is_tls13:
            raise ConnectionError(
                "Sunucu TLS 1.3 (supported_versions=0x0304) müzakere etmedi. Bu istemci "
                "TLS 1.2 ve altını desteklemez; downgrade kabul edilmiyor."
            )
        if not server_pub or selected_group is None:
            raise ConnectionError(
                "ServerHello geçerli bir key_share içermiyor — handshake tamamlanamaz."
            )
        if hrr is not None and hrr.selected_group is not None and selected_group != hrr.selected_group:
            raise ConnectionError(
                "HRR sonrası ServerHello, HRR'de istenen gruptan farklı bir grup seçti."
            )

        state["is_tls13"] = True
        state["key_share_group"] = selected_group
        state["hello_retry"] = hrr is not None

        # ---- Handshake anahtarları ------------------------------------------
        try:
            shared = impersonator.key_shares.shared_secret(selected_group, server_pub)
        except ValueError as e:
            raise ConnectionError(f"key_share işlenemedi ({group_name(selected_group)}): {e}") from e
        t_hash = hash_func(state["handshake_messages"]).digest()
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
        finished_received = False
        handshake_buffer = b""
        certificate_seen = False
        cert_verify_ok = False
        leaf_cert = None

        while not finished_received:
            msg, m_type = esock.recv_record()
            if m_type == 21:
                raise ConnectionError(f"Sunucudan Şifreli TLS Alert: {msg.hex()}")
            if m_type != 22:
                continue  # handshake bitmeden application_data beklemiyoruz

            handshake_buffer += msg
            while len(handshake_buffer) >= 4:
                hs_type = handshake_buffer[0]
                hs_len = struct.unpack("!I", b"\x00" + handshake_buffer[1:4])[0]
                if len(handshake_buffer) < 4 + hs_len:
                    break
                hs_payload = handshake_buffer[:4 + hs_len]
                handshake_buffer = handshake_buffer[4 + hs_len:]

                # ÖNEMLİ: transcript hash'i bu mesaj EKLENMEDEN önce alınmalı.
                # CertificateVerify kendisinden ÖNCEKİ transcript'i imzalar;
                # Finished da kendisinden öncekinin MAC'ini taşır.
                transcript_before = hash_func(state["handshake_messages"]).digest()
                state["handshake_messages"] += hs_payload

                if hs_type == _HS_NEW_SESSION_TICKET:
                    # PSK/0-RTT resumption implemente edilmedi; mesaj yalnızca
                    # handshake akışını bozmamak için okunup yutuluyor.
                    continue

                if hs_type == _HS_ENCRYPTED_EXTENSIONS:
                    state["alpn"] = _parse_alpn_from_encrypted_extensions(hs_payload)

                elif hs_type in (_HS_CERTIFICATE, _HS_COMPRESSED_CERTIFICATE):
                    if hs_type == _HS_COMPRESSED_CERTIFICATE:
                        try:
                            effective_payload = decompress_certificate_message(hs_payload)
                        except CertificateValidationError as e:
                            raise ConnectionError(f"Sıkıştırılmış sertifika açılamadı: {e}") from e
                    else:
                        effective_payload = hs_payload

                    try:
                        leaf_cert = validate_server_certificate(effective_payload, host)
                    except CertificateValidationError as e:
                        raise ConnectionError(
                            f"TLS sertifika doğrulaması başarısız — bağlantı güvenli değil, "
                            f"olası MITM saldırısı: {e}"
                        ) from e
                    state["peer_certificate"] = leaf_cert
                    certificate_seen = True

                elif hs_type == _HS_CERTIFICATE_VERIFY:
                    if not certificate_seen:
                        raise ConnectionError(
                            "Sunucu Certificate göndermeden CertificateVerify gönderdi — protokol ihlali."
                        )
                    try:
                        scheme = verify_certificate_verify(hs_payload, leaf_cert, transcript_before)
                    except CertificateValidationError as e:
                        raise ConnectionError(f"TLS kimlik doğrulaması başarısız: {e}") from e
                    logger.debug("CertificateVerify doğrulandı (scheme=0x%04x)", scheme)
                    cert_verify_ok = True

                elif hs_type == _HS_FINISHED:
                    if not certificate_seen:
                        raise ConnectionError(
                            "Handshake Finished'a ulaştı ama sunucu sertifikası hiç doğrulanmadı — "
                            "bağlantı reddedildi."
                        )
                    if not cert_verify_ok:
                        raise ConnectionError(
                            "Sunucu CertificateVerify göndermedi veya doğrulanamadı — sertifikadaki "
                            "özel anahtara sahip olduğunu kanıtlayamadı. Bağlantı reddedildi."
                        )

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
                    finished_received = True
                    break

        # ---- Client Finished --------------------------------------------------
        hash_len = hash_func().digest_size
        t_hash = hash_func(state["handshake_messages"]).digest()
        f_key = PureCryptoEngine.tls13_hkdf_expand_label(
            state["client_hts"], "finished", b"", hash_len, hash_alg=hash_func
        )
        mac = hmac.new(f_key, t_hash, hash_func).digest()
        finished_msg = b"\x14" + struct.pack("!I", len(mac))[1:] + mac

        esock.send_record(finished_msg, content_type=0x16, use_app_keys=False)

        # ---- Application anahtarları -------------------------------------------
        ak, aiv, ask_key, asiv = PureCryptoEngine.derive_application_keys(
            state["handshake_secret"], t_hash, state["key_len"], hash_alg=hash_func
        )
        state.update({
            "app_client_write_key": ak, "app_client_write_iv": aiv,
            "app_server_write_key": ask_key, "app_server_write_iv": asiv,
            "using_app_keys": True,
        })

        logger.debug(
            "TLS 1.3 handshake tamam: host=%s suite=0x%04x alpn=%r",
            host, cipher_suite, state["alpn"],
        )
        return esock
