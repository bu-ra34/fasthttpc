"""
Testler için minimal sahte TLS 1.3 sunucusu (ağ gerektirmez, 127.0.0.1).

Yalnızca istemcinin handshake yolunu sınamak için yazıldı; gerçek bir sunucu
DEĞİLDİR. Desteklenenler: fasthttpc.security.keyshare'in tüm (EC)DHE grupları
(x25519, x448, secp256r1/384r1/521r1, ffdhe2048/3072) key_share,
HelloRetryRequest (grup + cookie), ikinci HRR (hata testi), AES-128-GCM
(0x1301) ve AES-256-GCM (0x1302), ECDSA-P256 CertificateVerify, Finished.
Handshake sonrası tek bir HTTP/1.1 isteğine sabit yanıt döner.

Sertifika doğrulaması (CA zinciri) testlerde ``trust_leaf`` fixture'ı ile
devre dışı bırakılır; CertificateVerify ve Finished GERÇEKTEN doğrulanır.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import os
import socket
import struct
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

from fasthttpc.crypto_math import PureCryptoEngine
from fasthttpc.security.keyshare import (
    HRR_RANDOM, generate_key_share, compute_shared_secret, message_hash,
)

HTTP_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

_KEY = ec.generate_private_key(ec.SECP256R1())


def make_cert(host="example.com"):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .sign(_KEY, hashes.SHA256())
    )


def _hs(t, body):
    return bytes([t]) + struct.pack("!I", len(body))[1:] + body


def _ext(t, data):
    return struct.pack("!HH", t, len(data)) + data


def _rec(t, payload):
    return struct.pack("!BHH", t, 0x0303, len(payload)) + payload


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


def recv_record(sock):
    hdr = recv_exact(sock, 5)
    return hdr, recv_exact(sock, struct.unpack("!H", hdr[3:5])[0])


def parse_client_hello(msg):
    """msg: handshake mesajı (4 byte başlık dahil). Dönüş: dict."""
    assert msg[0] == 1
    b = msg[4:]
    pos = 2
    random = b[pos:pos + 32]
    pos += 32
    sid = b[pos + 1:pos + 1 + b[pos]]
    pos += 1 + b[pos]
    cs_len = struct.unpack("!H", b[pos:pos + 2])[0]
    suites = [struct.unpack("!H", b[pos + 2 + i:pos + 4 + i])[0] for i in range(0, cs_len, 2)]
    pos += 2 + cs_len
    pos += 1 + b[pos]
    ext_total = struct.unpack("!H", b[pos:pos + 2])[0]
    pos += 2
    end = pos + ext_total
    exts = []
    while pos < end:
        t, l = struct.unpack("!HH", b[pos:pos + 4])
        exts.append((t, b[pos + 4:pos + 4 + l]))
        pos += 4 + l
    shares = {}
    cookie = None
    groups = []
    for t, d in exts:
        if t == 0x0033:
            p = 2
            while p < len(d):
                g, l = struct.unpack("!HH", d[p:p + 4])
                shares[g] = d[p + 4:p + 4 + l]
                p += 4 + l
        elif t == 0x002C:
            cookie = d[2:]
        elif t == 0x000A:
            groups = [struct.unpack("!H", d[2 + i:4 + i])[0] for i in range(0, len(d) - 2, 2)]
    return {"random": random, "session_id": sid, "suites": suites, "exts": exts,
            "key_shares": shares, "cookie": cookie, "groups": groups}


class FakeTLS13Server:
    """Tek bağlantı kabul eden sahte TLS 1.3 sunucusu (arka plan thread'i)."""

    def __init__(self, host="example.com", group=None, hrr_group=None, cookie=None,
                 double_hrr=False, suite=0x1301, hrr_suite=None, sh_group_override=None):
        self.host = host
        self.group = group            # ServerHello'da seçilecek grup (None: ilk key_share)
        self.hrr_group = hrr_group    # verilirse önce HRR gönderilir
        self.cookie = cookie
        self.double_hrr = double_hrr
        self.suite = suite
        self.hrr_suite = hrr_suite or suite
        self.sh_group_override = sh_group_override
        self.client_hellos: list[dict] = []
        self.raw_client_hellos: list[bytes] = []
        self.ccs_before_ch2 = False
        self.error: Exception | None = None
        self.done = threading.Event()
        self.lsock = socket.socket()
        self.lsock.bind(("127.0.0.1", 0))
        self.lsock.listen(5)
        self.port = self.lsock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self):
        self.lsock.close()

    # ---- sunucu mantığı --------------------------------------------------
    def _read_ch(self, sock):
        while True:
            hdr, payload = recv_record(sock)
            if hdr[0] == 20:
                self.ccs_before_ch2 = True
                continue
            assert hdr[0] == 22
            self.raw_client_hellos.append(payload)
            ch = parse_client_hello(payload)
            self.client_hellos.append(ch)
            return payload, ch

    def _hrr(self, ch, group):
        exts = _ext(0x002B, b"\x03\x04") + _ext(0x0033, struct.pack("!H", group))
        if self.cookie:
            exts += _ext(0x002C, struct.pack("!H", len(self.cookie)) + self.cookie)
        body = (b"\x03\x03" + HRR_RANDOM + bytes([len(ch["session_id"])]) + ch["session_id"]
                + struct.pack("!H", self.hrr_suite) + b"\x00"
                + struct.pack("!H", len(exts)) + exts)
        return _hs(2, body)

    def _serve(self):
        try:
            sock, _ = self.lsock.accept()
            sock.settimeout(5)
            self.conn = sock
            self._handshake(sock)
        except Exception as e:  # noqa: BLE001 — test teşhisi için saklanır
            self.error = e
        finally:
            self.done.set()

    def _handshake(self, sock):
        hash_alg = hashlib.sha384 if self.suite == 0x1302 else hashlib.sha256
        key_len = 32 if self.suite == 0x1302 else 16
        ch1, ch = self._read_ch(sock)
        transcript = ch1
        if self.hrr_group is not None:
            hrr = self._hrr(ch, self.hrr_group)
            # RFC 8446 §D.4: sunucu (OpenSSL gibi) ilk handshake mesajından —
            # burada HRR — hemen sonra sahte CCS gönderir; istemci bunu
            # 2. ServerHello'yu beklerken atlamalı.
            sock.sendall(_rec(22, hrr) + _rec(20, b"\x01"))
            transcript = message_hash(hash_alg, ch1) + hrr
            try:
                ch2, ch = self._read_ch(sock)
            except ConnectionError:
                return
            transcript += ch2
            if self.cookie is not None:
                assert ch["cookie"] == self.cookie, "cookie geri gönderilmedi"
            if self.double_hrr:
                sock.sendall(_rec(22, self._hrr(ch, self.hrr_group)))
                try:
                    sock.recv(10)
                except OSError:
                    pass
                return

        if self.group is not None:
            group = self.group
        elif self.hrr_group is not None:
            group = self.hrr_group          # HRR sonrası: istenen grubun payı (CH2'de tek pay)
        else:
            group = next(g for g in ch["key_shares"] if g in (0x001D, 0x0017, 0x0018))  # GREASE/PQ'yu atla
        peer = ch["key_shares"][group]
        priv, pub = generate_key_share(group)
        shared = compute_shared_secret(group, priv, peer)
        sh_group = self.sh_group_override or group
        exts = _ext(0x002B, b"\x03\x04") + _ext(0x0033, struct.pack("!HH", sh_group, len(pub)) + pub)
        sh = _hs(2, b"\x03\x03" + os.urandom(32) + bytes([len(ch["session_id"])]) + ch["session_id"]
                 + struct.pack("!H", self.suite) + b"\x00" + struct.pack("!H", len(exts)) + exts)
        transcript += sh
        sock.sendall(_rec(22, sh) + (b"" if self.hrr_group is not None else _rec(20, b"\x01")))

        hs_secret, ck, civ, sk, siv, c_hts, s_hts = PureCryptoEngine.derive_tls13_keys(
            shared, hash_alg(transcript).digest(), key_len, hash_alg=hash_alg)
        s_seq = [0]

        def send_enc(content, ctype, key, iv, seq):
            inner = content + bytes([ctype])
            hdr = struct.pack("!BHH", 23, 0x0303, len(inner) + 16)
            nonce = bytes(a ^ b for a, b in zip(iv, b"\x00" * 4 + seq[0].to_bytes(8, "big")))
            seq[0] += 1
            sock.sendall(hdr + AESGCM(key).encrypt(nonce, inner, hdr))

        def recv_enc(key, iv, seq):
            while True:
                hdr, payload = recv_record(sock)
                if hdr[0] == 20:
                    continue
                nonce = bytes(a ^ b for a, b in zip(iv, b"\x00" * 4 + seq[0].to_bytes(8, "big")))
                seq[0] += 1
                pt = AESGCM(key).decrypt(nonce, payload, hdr).rstrip(b"\x00")
                return pt[:-1], pt[-1]

        ee = _hs(8, b"\x00\x00")
        transcript += ee
        send_enc(ee, 22, sk, siv, s_seq)

        cert_der = make_cert(self.host).public_bytes(serialization.Encoding.DER)
        entry = struct.pack("!I", len(cert_der))[1:] + cert_der + b"\x00\x00"
        cert_msg = _hs(11, b"\x00" + struct.pack("!I", len(entry))[1:] + entry)
        transcript += cert_msg
        send_enc(cert_msg, 22, sk, siv, s_seq)

        content = b"\x20" * 64 + b"TLS 1.3, server CertificateVerify\x00" + hash_alg(transcript).digest()
        sig = _KEY.sign(content, ec.ECDSA(hashes.SHA256()))
        cv = _hs(15, struct.pack("!HH", 0x0403, len(sig)) + sig)
        transcript += cv
        send_enc(cv, 22, sk, siv, s_seq)

        hlen = hash_alg().digest_size
        fk = PureCryptoEngine.tls13_hkdf_expand_label(s_hts, "finished", b"", hlen, hash_alg=hash_alg)
        fin = _hs(20, hmac.new(fk, hash_alg(transcript).digest(), hash_alg).digest())
        transcript += fin
        send_enc(fin, 22, sk, siv, s_seq)

        app_hash = hash_alg(transcript).digest()
        c_seq = [0]
        cfin, _t = recv_enc(ck, civ, c_seq)
        cfk = PureCryptoEngine.tls13_hkdf_expand_label(c_hts, "finished", b"", hlen, hash_alg=hash_alg)
        assert hmac.compare_digest(cfin[4:], hmac.new(cfk, app_hash, hash_alg).digest()), \
            "client Finished geçersiz"

        # [:4] — faz1 dönüşe trafik secret'larını da ekliyor (KeyUpdate için).
        ak, aiv, ask, asiv = PureCryptoEngine.derive_application_keys(
            hs_secret, app_hash, key_len, hash_alg=hash_alg)[:4]
        self.handshake_ok = True
        try:
            req, _t = recv_enc(ak, aiv, [0])
        except (ConnectionError, OSError):
            return
        self.request = req
        send_enc(HTTP_RESPONSE, 23, ask, asiv, [0])
