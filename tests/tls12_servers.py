"""TLS 1.2 test sunucuları (ağsız: yalnızca loopback).

* ``PKI12``          : kendi CA + ECDSA(P-256/P-384) ve RSA(2048) leaf sertifikaları.
* ``StdlibTLS12``    : Python ``ssl`` ile TLS 1.2-ONLY gerçek sunucu (bağımsız doğrulama).
* ``Fake12Server``   : SAHTE sunucu; el sıkışmayı elle yürütür ve ``tamper`` ile tek tek
                       güvenlik kontrollerini bozar. Kriptosu fasthttpc'den BAĞIMSIZDIR
                       (yalnızca ``cryptography`` + kendi PRF'i).
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import os
import socket
import ssl
import struct
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x448, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HOST = "localhost"
# ECDHE ServerKeyExchange'te kullanılabilen NIST eğrileri (RFC 8422 named_curve)
_EC_CURVES = {0x0017: ec.SECP256R1, 0x0018: ec.SECP384R1, 0x0019: ec.SECP521R1}


# ---------------------------------------------------------------- PKI
class PKI12:
    def __init__(self, host: str = HOST):
        now = datetime.datetime.now(datetime.timezone.utc)
        self.host = host
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fasthttpc tls12 test CA")])
        ski = x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key())
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name).issuer_name(ca_name)
            .public_key(self.ca_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=2))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(ski, critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )
        self._ski = ski
        self.ec_key = ec.generate_private_key(ec.SECP256R1())
        self.ec384_key = ec.generate_private_key(ec.SECP384R1())
        self.rsa_key = rsa.generate_private_key(65537, 2048)
        self.ec_cert = self._leaf(self.ec_key, host)
        self.ec384_cert = self._leaf(self.ec384_key, host)
        self.rsa_cert = self._leaf(self.rsa_key, host)
        self.wrong_host_cert = self._leaf(self.ec_key, "baska.example")

    def _leaf(self, key, host):
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_name = self.ca_cert.subject
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=10))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(self._ski),
                           critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )

    def ca_pem(self) -> bytes:
        return self.ca_cert.public_bytes(serialization.Encoding.PEM)

    def write(self, tmp_path):
        """ca.pem + {ec,rsa}.pem (zincir+anahtar) yazar; (ca, ec_pem, rsa_pem, ec384_pem) döner."""
        ca = tmp_path / "ca.pem"
        ca.write_bytes(self.ca_pem())
        out = []
        for name, cert, key in (("ec", self.ec_cert, self.ec_key), ("rsa", self.rsa_cert, self.rsa_key),
                                ("ec384", self.ec384_cert, self.ec384_key)):
            p = tmp_path / f"{name}.pem"
            p.write_bytes(
                cert.public_bytes(serialization.Encoding.PEM)
                + key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
            out.append(str(p))
        return (str(ca), *out)


# ---------------------------------------------------------- stdlib sunucu
class StdlibTLS12:
    """ssl ile TLS 1.2-only sunucu; her bağlantıda ``handler(conn)`` çalıştırır."""

    def __init__(self, certfile: str, ciphers: str, *, alpn=None, curve=None, handler=None):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers(ciphers)
        ctx.load_cert_chain(certfile)
        if alpn:
            ctx.set_alpn_protocols(alpn)
        if curve:
            ctx.set_ecdh_curve(curve)
        self.ctx = ctx
        self.handler = handler or http1_handler(b"merhaba tls12")
        self.ls = socket.socket()
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(8)
        self.port = self.ls.getsockname()[1]
        self.errors = []
        self.negotiated = []
        self._stop = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self._stop:
            try:
                raw, _ = self.ls.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(raw,), daemon=True).start()

    def _one(self, raw):
        try:
            raw.settimeout(10)
            conn = self.ctx.wrap_socket(raw, server_side=True)
            self.negotiated.append((conn.version(), conn.cipher()[0], conn.selected_alpn_protocol()))
            self.handler(conn)
        except Exception as e:  # noqa: BLE001 - testte hata listesi
            self.errors.append(e)
        finally:
            try:
                raw.close()
            except OSError:
                pass

    def close(self):
        self._stop = True
        try:
            self.ls.close()
        except OSError:
            pass


def http1_handler(body: bytes):
    def handle(conn):
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = conn.recv(65536)
            if not d:
                return
            buf += d
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
        try:
            conn.unwrap()
        except (ssl.SSLError, OSError):
            pass
    return handle


def h2_handler(body: bytes):
    """h2 kütüphanesiyle sunucu tarafı: her isteğe 200 + body."""
    def handle(conn):
        import h2.config
        import h2.connection
        import h2.events
        c = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False))
        c.initiate_connection()
        conn.sendall(c.data_to_send())
        done = False
        while not done:
            d = conn.recv(65536)
            if not d:
                return
            for ev in c.receive_data(d):
                if isinstance(ev, h2.events.RequestReceived):
                    c.send_headers(ev.stream_id, [(":status", "200"), ("content-length", str(len(body)))])
                    c.send_data(ev.stream_id, body, end_stream=True)
                    done = True
            conn.sendall(c.data_to_send())
        # istemci akışı bitirene dek biraz bekle
        conn.settimeout(1)
        try:
            while conn.recv(65536):
                pass
        except (OSError, ssl.SSLError):
            pass
    return handle


# ------------------------------------------------------------ sahte sunucu
def prf(h, secret, label, seed, n):
    seed = label + seed
    a, out = seed, b""
    while len(out) < n:
        a = hmac.new(secret, a, h).digest()
        out += hmac.new(secret, a + seed, h).digest()
    return out[:n]


def hs(t, body):
    return bytes([t]) + len(body).to_bytes(3, "big") + body


def ext(t, body):
    return struct.pack("!HH", t, len(body)) + body


def rec(t, body, ver=0x0303):
    return struct.pack("!BHH", t, ver, len(body)) + body


_SUITES = {  # id: (hash, key_len, iv_len, aead_cls, key_type)
    0xC02B: (hashlib.sha256, 16, 4, AESGCM, "ec"),
    0xC02F: (hashlib.sha256, 16, 4, AESGCM, "rsa"),
    0xC02C: (hashlib.sha384, 32, 4, AESGCM, "ec"),
    0xC030: (hashlib.sha384, 32, 4, AESGCM, "rsa"),
    0xCCA9: (hashlib.sha256, 32, 12, ChaCha20Poly1305, "ec"),
    0xCCA8: (hashlib.sha256, 32, 12, ChaCha20Poly1305, "rsa"),
}

_SIGHASH = {0x0403: hashes.SHA256, 0x0503: hashes.SHA384, 0x0603: hashes.SHA512,
            0x0804: hashes.SHA256, 0x0805: hashes.SHA384, 0x0806: hashes.SHA512,
            0x0401: hashes.SHA256, 0x0501: hashes.SHA384, 0x0601: hashes.SHA512,
            0x0201: hashes.SHA1, 0x0203: hashes.SHA1}


def parse_client_hello(msg):
    b = msg[4:]
    sid = b[35:35 + b[34]]
    off = 35 + b[34]
    csl = struct.unpack("!H", b[off:off + 2])[0]
    suites = [struct.unpack("!H", b[off + 2 + i:off + 4 + i])[0] for i in range(0, csl, 2)]
    off += 2 + csl
    off += 1 + b[off]
    el = struct.unpack("!H", b[off:off + 2])[0]
    off += 2
    exts = {}
    end = off + el
    while off < end:
        t, ln = struct.unpack("!HH", b[off:off + 4])
        exts[t] = b[off + 4:off + 4 + ln]
        off += 4 + ln
    alpn = []
    d = exts.get(16, b"")
    p = 2
    while p < len(d):
        alpn.append(d[p + 1:p + 1 + d[p]].decode())
        p += 1 + d[p]
    return {"random": b[2:34], "session_id": sid, "suites": suites, "exts": exts, "alpn": alpn}


class Fake12Server:
    """Elle yürütülen TLS 1.2 sunucusu. ``tamper`` kümesi:

    no_ems, no_reneg, bad_reneg, downgrd, downgrd0, bad_ske_sig, bad_finished, cbc_suite, static_rsa,
    tls13_suite, out_of_order (SKE'den önce SHD), cert_request, sha1_sig, unoffered_sig, wrong_key_type,
    no_ccs, plain_finished, bad_curve, unoffered_curve, bad_pub, hello_request, hello_request_flood,
    bad_cert_host, untrusted, extra_ext, unsolicited_ticket, tls11, null_cmp_not, zero_len_rec,
    ccs_in_hs, replay_sha384, bad_record_mac, oversize_record, trailing_after_finished,
    unoffered_alpn, close_after_hello, alert_in_hs, ske_curve_type_explicit, status
    """

    def __init__(self, pki, *, suite=0xC02F, sigalg=None, group=0x001D, tamper=(), alpn=None,
                 split_flight=False, ticket=True, key=None, handler=None, cr_body=None):
        # cr_body: verilirse (bayt) GEÇERLİ bir CertificateRequest gövdesi gönderilir ve istemci
        # Certificate/CertificateVerify mesajları alınıp kaydedilir (client_cert_ders, client_cv_ok).
        self.cr_body = cr_body
        self.client_cert_ders = None
        self.client_cv_ok = None
        self.pki, self.suite, self.group = pki, suite, group
        self.tamper = set(tamper)
        self.alpn = alpn
        self.split_flight = split_flight
        self.ticket = ticket
        self.keykind = key or _SUITES.get(suite, (0, 0, 0, 0, "ec"))[4]
        self.sigalg = sigalg or (0x0403 if self.keykind == "ec" else 0x0804)
        self.handler = handler
        self.received = []          # istemcinin gönderdiği uygulama verisi
        self.alerts = []
        self.error = None
        self.client_hello = None
        self.finished_ok = False
        self.cke_seen = False
        self.cke_pub = None         # istemcinin ClientKeyExchange'teki ECDHE public değeri
        self.suite_info = _SUITES.get(suite, _SUITES[0xC02F])

    # --- kayıt katmanı ---
    def _read_rec(self, sock):
        h = self._recvn(sock, 5)
        t, _v, ln = struct.unpack("!BHH", h)
        return t, h, self._recvn(sock, ln)

    @staticmethod
    def _recvn(sock, n):
        buf = b""
        while len(buf) < n:
            d = sock.recv(n - len(buf))
            if not d:
                raise ConnectionError("istemci kapattı")
            buf += d
        return buf

    def _seal(self, key, iv, seq, t, pt):
        hlen, klen, ivlen, cls, _k = self.suite_info
        seq8 = struct.pack("!Q", seq)
        aad = seq8 + struct.pack("!BHH", t, 0x0303, len(pt))
        if cls is AESGCM:
            ex = seq8
            return ex + AESGCM(key).encrypt(iv + ex, pt, aad)
        nonce = bytes(a ^ b for a, b in zip(iv, b"\x00" * 4 + seq8))
        return ChaCha20Poly1305(key).encrypt(nonce, pt, aad)

    def _open(self, key, iv, seq, t, body):
        hlen, klen, ivlen, cls, _k = self.suite_info
        seq8 = struct.pack("!Q", seq)
        if cls is AESGCM:
            ex, ct = body[:8], body[8:]
            aad = seq8 + struct.pack("!BHH", t, 0x0303, len(ct) - 16)
            return AESGCM(key).decrypt(iv + ex, ct, aad)
        aad = seq8 + struct.pack("!BHH", t, 0x0303, len(body) - 16)
        nonce = bytes(a ^ b for a, b in zip(iv, b"\x00" * 4 + seq8))
        return ChaCha20Poly1305(key).decrypt(nonce, body, aad)

    # --- sunucu akışı ---
    def serve(self, sock):
        try:
            sock.settimeout(8)
            self._serve(sock)
        except Exception as e:  # noqa: BLE001
            self.error = e
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _serve(self, sock):
        T = self.tamper
        t, _h, body = self._read_rec(sock)
        assert t == 22
        while len(body) < 4 + int.from_bytes(body[1:4], "big"):
            t2, _h, more = self._read_rec(sock)
            body += more
        ch_msg = body
        self.client_hello = ch = parse_client_hello(ch_msg)
        transcript = bytearray(ch_msg)
        hash_alg = self.suite_info[0]

        if "close_after_hello" in T:
            return
        if "alert_in_hs" in T:
            sock.sendall(rec(21, b"\x02\x28"))     # handshake_failure
            return

        # ---- ServerHello ----
        random = os.urandom(32)
        if "downgrd" in T:
            random = os.urandom(24) + b"DOWNGRD\x01"
        if "downgrd0" in T:
            random = os.urandom(24) + b"DOWNGRD\x00"
        suite = self.suite
        if "cbc_suite" in T:
            suite = 0xC013
        if "static_rsa" in T:
            suite = 0x009C
        if "tls13_suite" in T:
            suite = 0x1301
        exts = b""
        if "no_reneg" not in T:
            exts += ext(0xFF01, b"\x01\x00" if "bad_reneg" in T else b"\x00")
        if "no_ems" not in T:
            exts += ext(0x0017, b"")
        exts += ext(0x000B, b"\x01\x00")
        if self.ticket:
            exts += ext(0x0023, b"")
        if "status" in T:
            exts += ext(0x0005, b"")
        if self.alpn:
            a = self.alpn.encode()
            exts += ext(0x0010, struct.pack("!HB", len(a) + 1, len(a)) + a)
        if "unoffered_alpn" in T:
            exts += ext(0x0010, b"\x00\x06\x05bogus")
        if "extra_ext" in T:
            exts += ext(0x0033, b"\x00\x1d\x00\x00")         # key_share: TLS 1.2 ServerHello'sunda yasak
        sid = os.urandom(32)
        ver = b"\x03\x01" if "tls11" in T else b"\x03\x03"
        sh_body = ver + random + bytes([len(sid)]) + sid + struct.pack("!HB", suite, 1 if "null_cmp_not" in T else 0) \
            + struct.pack("!H", len(exts)) + exts
        sh = hs(2, sh_body)

        msgs = [sh]
        # ---- Certificate ----
        cert = {"ec": self.pki.ec_cert, "rsa": self.pki.rsa_cert}[self.keykind]
        if self.keykind == "ec" and "ec384" in T:
            cert = self.pki.ec384_cert
        if "bad_cert_host" in T:
            cert = self.pki.wrong_host_cert
        der = cert.public_bytes(serialization.Encoding.DER)
        entry = len(der).to_bytes(3, "big") + der
        cert_msg = hs(11, len(entry).to_bytes(3, "big") + entry)
        key = {"ec": self.pki.ec_key, "rsa": self.pki.rsa_key}[self.keykind]
        if "ec384" in T:
            key = self.pki.ec384_key
        if "wrong_key_type" in T:
            # sertifika ECDSA ama suite RSA beklerken: anahtar türünü ters çevir
            flip_to_ec = self.keykind == "rsa"
            cert = self.pki.ec_cert if flip_to_ec else self.pki.rsa_cert
            key = self.pki.ec_key if flip_to_ec else self.pki.rsa_key
            self.sigalg = 0x0403 if flip_to_ec else 0x0804
            der = cert.public_bytes(serialization.Encoding.DER)
            entry = len(der).to_bytes(3, "big") + der
            cert_msg = hs(11, len(entry).to_bytes(3, "big") + entry)
        if "skip_cert" not in T:
            msgs.append(cert_msg)
        if "dup_cert" in T:
            msgs.append(cert_msg)
        if "status" in T:
            msgs.append(hs(22, b"\x01" + (3).to_bytes(3, "big") + b"ocs"))

        # ---- ServerKeyExchange ----
        group = self.group
        if "bad_curve" in T:
            group = 0x001A        # brainpoolP256r1: istemci desteklemiyor
        if "unoffered_curve" in T:
            group = 0x001E        # x448: chrome profili ilan etmiyor
        if group == 0x001D:
            priv = x25519.X25519PrivateKey.generate()
            pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        elif group == 0x001E:
            priv = x448.X448PrivateKey.generate()
            pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        elif group in _EC_CURVES:
            priv = ec.generate_private_key(_EC_CURVES[group]())
            pub = priv.public_key().public_bytes(serialization.Encoding.X962,
                                                 serialization.PublicFormat.UncompressedPoint)
        else:
            priv, pub = None, os.urandom(32)
        if "bad_pub" in T:
            if group in (0x001D, 0x001E):
                pub = bytes(len(pub))                      # u = 0: paylaşılan sır tamamen sıfır
            else:
                pub = pub[:-1] + bytes([pub[-1] ^ 1])      # Y'nin son biti: aralıkta ama eğri dışı
        params = bytes([3]) + struct.pack("!H", group) + bytes([len(pub)]) + pub
        if "ske_curve_type_explicit" in T:
            params = bytes([1]) + struct.pack("!H", group) + bytes([len(pub)]) + pub
        sigalg = self.sigalg
        if "sha1_sig" in T:
            sigalg = 0x0203 if self.keykind == "ec" else 0x0201
        if "unoffered_sig" in T:
            sigalg = 0x0603                       # ecdsa_secp521r1_sha512: chrome profili ilan ETMİYOR
        signed = ch["random"] + random + params
        hcls = _SIGHASH.get(sigalg, hashes.SHA256)
        if sigalg in (0x0403, 0x0503, 0x0603, 0x0203):
            sig = key.sign(signed, ec.ECDSA(hcls()))
        elif sigalg in (0x0804, 0x0805, 0x0806):
            sig = key.sign(signed, padding.PSS(mgf=padding.MGF1(hcls()), salt_length=hcls().digest_size), hcls())
        elif sigalg in (0x0401, 0x0501, 0x0601, 0x0201):
            sig = key.sign(signed, padding.PKCS1v15(), hcls())
        else:
            sig = os.urandom(64)
        if "bad_ske_sig" in T:
            sig = bytes([sig[0] ^ 1]) + sig[1:]
        ske = hs(12, params + struct.pack("!HH", sigalg, len(sig)) + sig)
        shd = hs(14, b"")
        if "out_of_order" in T:
            msgs += [shd, ske]
        else:
            msgs.append(ske)
            if self.cr_body is not None:
                msgs.append(hs(13, self.cr_body))
            elif "cert_request" in T:
                msgs.append(hs(13, b"\x01\x01\x00\x00\x00"))
            msgs.append(shd)
        for m in msgs:
            transcript += m
        if "early_ccs" in T:
            sock.sendall(rec(22, sh) + rec(20, b"\x01"))
            msgs = msgs[1:]
        if self.split_flight:
            sock.sendall(rec(22, b"".join(msgs)))
        else:
            for m in msgs:
                sock.sendall(rec(22, m))

        # ---- istemci uçuşu ----
        t, _h, cke_rec = self._read_rec(sock)
        if t == 21:
            self.alerts.append(cke_rec)
            return
        if self.cr_body is not None:
            assert t == 22 and cke_rec[0] == 11, "CertificateRequest sonrası istemci Certificate bekleniyordu"
            body = cke_rec[4:]
            ln = int.from_bytes(body[:3], "big")
            assert ln == len(body) - 3
            ders, p = [], 3
            while p < len(body):
                n = int.from_bytes(body[p:p + 3], "big")
                ders.append(body[p + 3:p + 3 + n])
                p += 3 + n
            self.client_cert_ders = ders
            transcript += cke_rec
            t, _h, cke_rec = self._read_rec(sock)
        assert t == 22, f"CKE bekleniyordu, tip {t}"
        self.cke_seen = True
        cke = cke_rec
        assert cke[0] == 16
        cpub = cke[5:5 + cke[4]]
        transcript += cke
        self.cke_pub = bytes(cpub)
        if group == 0x001D:
            pms = priv.exchange(x25519.X25519PublicKey.from_public_bytes(cpub))
        elif group == 0x001E:
            pms = priv.exchange(x448.X448PublicKey.from_public_bytes(cpub))
        else:
            pms = priv.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(_EC_CURVES[group](), cpub))
        session_hash = hash_alg(bytes(transcript)).digest()
        master = prf(hash_alg, pms, b"extended master secret", session_hash, 48)
        _h, klen, ivlen, _cls, _kt = self.suite_info
        kb = prf(hash_alg, master, b"key expansion", random + ch["random"], 2 * klen + 2 * ivlen)
        ckey, skey = kb[:klen], kb[klen:2 * klen]
        civ, siv = kb[2 * klen:2 * klen + ivlen], kb[2 * klen + ivlen:]

        if self.client_cert_ders:
            # RFC 5246 §7.4.8: CertificateVerify, CKE'den sonra; imza CKE dahil transcript üzerinde
            t, _h, cv_rec = self._read_rec(sock)
            assert t == 22 and cv_rec[0] == 15, f"CertificateVerify bekleniyordu, tip {t}"
            self.client_cv_msg = cv_rec
            self.client_cv_transcript = bytes(transcript)
            transcript += cv_rec
        t, _h, ccs = self._read_rec(sock)
        assert t == 20 and ccs == b"\x01", f"CCS bekleniyordu, tip {t}"
        t, _h, fin_rec = self._read_rec(sock)
        assert t == 22
        fin = self._open(ckey, civ, 0, 22, fin_rec)
        expect = prf(hash_alg, master, b"client finished", hash_alg(bytes(transcript)).digest(), 12)
        assert fin == hs(20, expect), "istemci Finished verify_data HATALI"
        self.finished_ok = True
        transcript += fin

        out = b""
        if "unsolicited_ticket" in T or self.ticket:
            nst = hs(4, struct.pack("!IH", 3600, 4) + b"tick")
            transcript += nst
            out += rec(22, nst)
        wseq = 0
        if "no_ccs" not in T:
            out += rec(20, b"\x01")
        vd = prf(hash_alg, master, b"server finished", hash_alg(bytes(transcript)).digest(), 12)
        if "bad_finished" in T:
            vd = bytes([vd[0] ^ 1]) + vd[1:]
        sfin = hs(20, vd)
        if "plain_finished" in T:
            out += rec(22, sfin)
        else:
            out += rec(22, self._seal(skey, siv, wseq, 22, sfin + (b"\x00" if "trailing_after_finished" in T else b"")))
            wseq += 1
        sock.sendall(out)
        if "no_ccs" in T or "bad_finished" in T or "plain_finished" in T:
            try:
                t, _h, b = self._read_rec(sock)
                if t == 21:
                    self.alerts.append(b)
            except Exception:  # noqa: BLE001
                pass
            return

        rseq = 1
        if "hello_request" in T or "hello_request_flood" in T:
            # Sel: tam olarak eşik+1 HelloRequest — istemci sonuncusunda kapatır ve alım
            # tamponunda okunmamış veri kalmaz (kalırsa close() RST üretir ve RST,
            # sunucunun henüz okumadığı alert'leri siler: testte yarış).
            n = 4 if "hello_request_flood" in T else 1   # istemci eşiği (3) + 1
            for _ in range(n):
                sock.sendall(rec(22, self._seal(skey, siv, wseq, 22, hs(0, b""))))
                wseq += 1
        if "bad_record_mac" in T:
            body = bytearray(self._seal(skey, siv, wseq, 23, b"hello"))
            body[-1] ^= 1
            sock.sendall(rec(23, bytes(body)))
            return
        if "oversize_record" in T:
            sock.sendall(struct.pack("!BHH", 23, 0x0303, 2 ** 14 + 2049) + b"\x00" * (2 ** 14 + 2049))
            return

        # ---- uygulama ----
        while True:
            t, _h, body = self._read_rec(sock)
            if t == 21:
                try:
                    pt = self._open(ckey, civ, rseq, 21, body)
                except Exception:  # noqa: BLE001
                    pt = body
                self.alerts.append(pt)
                rseq += 1
                if pt == b"\x01\x00":
                    sock.sendall(rec(21, self._seal(skey, siv, wseq, 21, b"\x01\x00")))
                    return
                continue
            pt = self._open(ckey, civ, rseq, t, body)
            rseq += 1
            self.received.append(pt)
            if self.handler:
                for chunk in self.handler(pt):
                    for i in range(0, len(chunk), 16384):
                        sock.sendall(rec(23, self._seal(skey, siv, wseq, 23, chunk[i:i + 16384])))
                        wseq += 1
            else:
                sock.sendall(rec(23, self._seal(skey, siv, wseq, 23, b"echo:" + pt)))
                wseq += 1
            if b"CLOSE" in pt:
                sock.sendall(rec(21, self._seal(skey, siv, wseq, 21, b"\x01\x00")))
                return


def serve_fake_in_thread(server: Fake12Server):
    """Loopback'te dinler; (port, thread) döner. TEK bağlantı kabul eder."""
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)

    def run():
        try:
            c, _ = ls.accept()
        except OSError:
            return
        server.serve(c)
        ls.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return ls.getsockname()[1], t, ls
