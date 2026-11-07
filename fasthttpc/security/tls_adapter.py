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
from . import session_tickets
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
        # Okuma tamponu: bytearray + okuma ofseti. `bytes += chunk` ve her record'da
        # dilimleyerek yeni bytes üretmek büyük indirmelerde O(n^2) kopyalamaya yol açıyordu.
        self.read_buffer = bytearray()
        self._rbuf_off = 0
        # AEAD nesneleri anahtar başına bir kez kurulur (OpenSSL context kurulumu
        # record başına tekrarlanmaz). Anahtar bytes'ı önbellek anahtarı olduğundan
        # anahtar değişince (handshake->app, KeyUpdate) otomatik olarak yeni nesne oluşur.
        self._cipher_cache: dict = {}

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
            rec_type, record_header, payload = self._read_raw_record()

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
        if hs_type == 4:      # NewSessionTicket
            self._on_new_session_ticket(msg)
            return
        if hs_type == 24:     # KeyUpdate
            # Doğru yanıt anahtarları döndürmektir; bu basit istemci key update
            # implemente etmediğinden, sunucu update_requested gönderirse sonraki
            # record'lar çözülemez. Şimdilik yok sayıyoruz (nadir bir durum).
            logger.debug("KeyUpdate alındı ama işlenmiyor (implemente edilmedi)")
            return
        logger.debug("Bilinmeyen post-handshake mesajı hs_type=%d, yok sayıldı", hs_type)


    def _on_new_session_ticket(self, msg: bytes) -> None:
        """NewSessionTicket'ları PSK resumption önbelleğine yazar (faz4).

        Yalnızca resumption bayrağı açık bir handshake'te resumption_master_secret
        türetilmişse çalışır; aksi halde bilet eskisi gibi yutulur. Bozuk bilet
        bağlantıyı düşürmez (resumption bir optimizasyondur), yalnızca loglanır.
        Bir record'da birden fazla NewSessionTicket art arda gelebilir.
        """
        rms = self.state.get("resumption_master_secret")
        host = self.state.get("ticket_host")
        if not rms or not host:
            return
        pos = 0
        while pos + 4 <= len(msg) and msg[pos] == 4:
            end = pos + 4 + int.from_bytes(msg[pos + 1:pos + 4], "big")
            try:
                nst = session_tickets.parse_new_session_ticket(msg[pos:end])
            except session_tickets.TicketError as e:
                logger.debug("NewSessionTicket ayrıştırılamadı, yok sayıldı: %s", e)
                return
            ticket = session_tickets.ticket_from_message(
                host, nst, rms, self.state.get("cipher_suite", 0),
                peer_certificate=self.state.get("peer_certificate"),
            )
            if ticket is not None:
                session_tickets.default_cache.put(ticket)
                logger.debug("Oturum bileti önbelleğe alındı: host=%s lifetime=%ds", host, ticket.lifetime)
            pos = end


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


class TLSAdapter:
    @staticmethod
    def negotiate(raw_socket: socket.socket, host: str, profile_name: str) -> EncryptedSocket:
        impersonator = TLSImpersonator(host, profile=profile_name)

        # PSK resumption (faz4) — VARSAYILAN KAPALI; bkz. session_tickets.enable_resumption.
        resumption_on = session_tickets.resumption_enabled()
        ticket = session_tickets.default_cache.pop(host) if resumption_on else None
        psk_hello = (
            session_tickets.build_resumption_client_hello(impersonator, ticket) if ticket else None
        )
        if psk_hello is None:
            ticket = None
            record_bytes, priv_key, _c_rand = impersonator.build_client_hello()
        else:
            record_bytes, priv_key, _c_rand = psk_hello

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
                f"Sunucu el sıkışmayı reddetti (alert): {server_hello_payload.hex()}"
            )
        if rec_type != 22:
            raise ConnectionError(f"ServerHello beklenirken beklenmeyen record tipi: {rec_type}")

        state["handshake_messages"] += server_hello_payload

        sh_body = server_hello_payload[4:]
        if len(sh_body) < 35:
            raise ConnectionError("ServerHello mesajı bozuk (çok kısa).")

        if sh_body[2:34] == _HELLO_RETRY_REQUEST_RANDOM:
            raise ConnectionError(
                "Sunucu HelloRetryRequest gönderdi — teklif ettiğimiz key_share grubunu "
                "(x25519) kabul etmedi. Bu istemci şu an yalnızca tek turlu handshake "
                "destekliyor; HRR implemente edilmedi."
            )

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
            )

        extensions_len = struct.unpack("!H", sh_body[offset + 3:offset + 5])[0]
        curr = offset + 5
        ext_end = min(curr + extensions_len, len(sh_body))
        is_tls13, server_pub = False, None
        psk_selected = None

        while curr + 4 <= ext_end:
            ext_type, ext_len = struct.unpack("!HH", sh_body[curr:curr + 4])
            curr += 4
            if ext_type == 43 and ext_len >= 2:
                if struct.unpack("!H", sh_body[curr:curr + 2])[0] == 0x0304:
                    is_tls13 = True
            elif ext_type == 51 and ext_len > 2:
                group, key_len_val = struct.unpack("!HH", sh_body[curr:curr + 4])
                if group != 0x001D:
                    raise ConnectionError(
                        f"Sunucu x25519 dışında bir grup seçti (0x{group:04x}); desteklenmiyor."
                    )
                server_pub = sh_body[curr + 4:curr + 4 + key_len_val]
            elif ext_type == session_tickets.EXT_PRE_SHARED_KEY and ext_len == 2:
                psk_selected = struct.unpack("!H", sh_body[curr:curr + 2])[0]
            curr += ext_len

        if not is_tls13:
            raise ConnectionError(
                "Sunucu TLS 1.3 (supported_versions=0x0304) müzakere etmedi. Bu istemci "
                "TLS 1.2 ve altını desteklemez; downgrade kabul edilmiyor."
            )
        if not server_pub or len(server_pub) != 32:
            raise ConnectionError(
                "ServerHello geçerli bir x25519 key_share içermiyor — handshake tamamlanamaz."
            )

        psk_accepted = psk_selected is not None
        if psk_accepted:
            if ticket is None or psk_selected != 0:
                raise ConnectionError(
                    "Sunucu teklif etmediğimiz bir PSK kimliğini seçti — protokol ihlali."
                )
            if session_tickets._SUITE_HASH.get(cipher_suite) is not ticket.hash_alg:
                raise ConnectionError(
                    "Sunucu PSK'yı kabul etti ama biletin hash'iyle uyumsuz bir cipher suite seçti."
                )

        state["is_tls13"] = True

        # ---- Handshake anahtarları ------------------------------------------
        shared = PureCryptoEngine.x25519(priv_key, server_pub)
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
                    # PSK resumption'da kimlik, bileti veren orijinal (tam doğrulanmış)
                    # handshake'ten devralınır; Certificate/CertificateVerify gelmez.
                    if not psk_accepted and not certificate_seen:
                        raise ConnectionError(
                            "Handshake Finished'a ulaştı ama sunucu sertifikası hiç doğrulanmadı — "
                            "bağlantı reddedildi."
                        )
                    if not psk_accepted and not cert_verify_ok:
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

        if resumption_on:
            state["resumption_master_secret"] = session_tickets.derive_resumption_master_secret(
                state["handshake_secret"],
                hash_func(state["handshake_messages"] + finished_msg).digest(),
                hash_alg=hash_func,
            )
            state["cipher_suite"] = cipher_suite
            state["ticket_host"] = host

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
