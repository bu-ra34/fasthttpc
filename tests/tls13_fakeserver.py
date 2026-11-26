"""Testler için sahte TLS 1.3 sunucusu (sans-IO).

İstemci çekirdeğinden BAĞIMSIZ olsun diye anahtar türetme, AEAD ve imzalar
yalnızca `cryptography` ile yapılır (fasthttpc.crypto_math kullanılmaz).
Testler `tamper` seçenekleriyle tek tek güvenlik kontrollerini bozabilir.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import os
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

_SUITES = {
    0x1301: (hashlib.sha256, hashes.SHA256(), 16, AESGCM),
    0x1302: (hashlib.sha384, hashes.SHA384(), 32, AESGCM),
    0x1303: (hashlib.sha256, hashes.SHA256(), 32, ChaCha20Poly1305),
}


# ----------------------------------------------------------------- PKI
class PKI:
    """Kök CA + ondan imzalı leaf (varsayılan ECDSA P-256; ``leaf_key="mldsa44"`` /
    ``"mldsa65"`` / ``"mldsa87"`` ile ML-DSA leaf — CA yine ECDSA)."""

    def __init__(self, host: str = "example.com", *, expired: bool = False,
                 leaf_key: str = "p256"):
        now = datetime.datetime.now(datetime.timezone.utc)
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fasthttpc test CA")])
        ca_ski = x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key())
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name).issuer_name(ca_name)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=2))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(ca_ski, critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )
        self.leaf_key = leaf_key
        if leaf_key.startswith("mldsa"):
            from cryptography.hazmat.primitives.asymmetric import mldsa
            self.key = getattr(mldsa, f"MLDSA{leaf_key[5:]}PrivateKey").generate()
        else:
            self.key = ec.generate_private_key(ec.SECP256R1())
        nb, na = (now - datetime.timedelta(days=10), now - datetime.timedelta(days=1)) if expired \
            else (now - datetime.timedelta(days=1), now + datetime.timedelta(days=10))
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(ca_name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(nb).not_valid_after(na)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
                           critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()),
                           critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )

    def ca_pem(self) -> bytes:
        return self.ca_cert.public_bytes(serialization.Encoding.PEM)

    def chain_der(self) -> list[bytes]:
        return [self.cert.public_bytes(serialization.Encoding.DER)]


# ------------------------------------------------------- crypto helpers
def expand_label(h, secret: bytes, label: str, ctx: bytes, length: int) -> bytes:
    full = b"tls13 " + label.encode()
    info = struct.pack("!H", length) + bytes([len(full)]) + full + bytes([len(ctx)]) + ctx
    return HKDFExpand(algorithm=h, length=length, info=info).derive(secret)


def hkdf_extract(hlib, salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hlib).digest()


def hs(t: int, body: bytes) -> bytes:
    return bytes([t]) + len(body).to_bytes(3, "big") + body


def ext(t: int, body: bytes) -> bytes:
    return struct.pack("!HH", t, len(body)) + body


def parse_client_hello(msg: bytes) -> dict:
    """ClientHello handshake mesajı (header dahil)."""
    assert msg[0] == 1
    b = msg[4:]
    random = b[2:34]
    sl = b[34]
    sid = b[35:35 + sl]
    off = 35 + sl
    csl = struct.unpack("!H", b[off:off + 2])[0]
    suites = [struct.unpack("!H", b[off + 2 + i:off + 4 + i])[0] for i in range(0, csl, 2)]
    off += 2 + csl
    off += 1 + b[off]
    el = struct.unpack("!H", b[off:off + 2])[0]
    off += 2
    exts = {}
    order = []
    end = off + el
    while off < end:
        t, l = struct.unpack("!HH", b[off:off + 4])
        exts[t] = b[off + 4:off + 4 + l]
        order.append(t)
        off += 4 + l
    shares = {}
    if 51 in exts:
        d = exts[51]
        p = 2
        while p < len(d):
            g, l = struct.unpack("!HH", d[p:p + 4])
            shares[g] = d[p + 4:p + 4 + l]
            p += 4 + l
    alpn = []
    if 16 in exts:
        d = exts[16]
        p = 2
        while p < len(d):
            l = d[p]
            alpn.append(d[p + 1:p + 1 + l].decode())
            p += 1 + l
    return {"random": random, "session_id": sid, "suites": suites, "exts": exts,
            "order": order, "shares": shares, "alpn": alpn}


class _Dir:
    def __init__(self, aead_cls, key, iv, secret):
        self.aead = aead_cls(key)
        self.iv = iv
        self.seq = 0
        self.secret = secret

    def nonce(self):
        return bytes(a ^ b for a, b in zip(self.iv, self.seq.to_bytes(12, "big")))

    def seal(self, content: bytes, ctype: int, pad: int = 0) -> bytes:
        inner = content + bytes([ctype]) + b"\x00" * pad
        header = struct.pack("!BHH", 23, 0x0303, len(inner) + 16)
        ct = self.aead.encrypt(self.nonce(), inner, header)
        self.seq += 1
        return header + ct

    def open(self, header: bytes, payload: bytes) -> tuple[bytes, int]:
        pt = self.aead.decrypt(self.nonce(), payload, header)
        self.seq += 1
        pt = pt.rstrip(b"\x00")
        return pt[:-1], pt[-1]


# ------------------------------------------------------------- server
class FakeTLS13Server:
    """Tek bağlantılık sahte TLS 1.3 sunucusu.

    tamper anahtarları:
      bad_cv_sig, bad_finished, skip_cv, skip_cert, wrong_key_cv,
      split_records (handshake'i 1'er byte'lık değil, küçük record'lara böl),
      coalesce (tüm şifreli handshake'i tek record'a koy), no_ccs,
      tls12 (supported_versions göndermeme), wrong_session_id, oversize_record,
      cert_request, early_app_data, psk_with_cert (PSK kabulünden sonra yine de
      Certificate/CertificateVerify gönder), force_psk (ClientHello'da PSK
      olmasa/HRR sonrası bile ServerHello'da pre_shared_key seç), double_hrr
      (2. ClientHello'ya da HelloRetryRequest ile yanıt ver — RFC 8446 §4.1.4 ihlali)

    psk_store: dict verilirse sunucu PSK resumption destekler: tam handshake
    sonrası gerçek (benzersiz) biletler verir ve ticket->PSK kaydını bu sözlükte
    tutar; ClientHello'da tanıdığı bir kimlik + doğru binder varsa PSK'yı kabul
    eder (self.resumed=True). Yanlış binder -> AssertionError.
    """

    def __init__(self, pki: PKI, *, suite: int = 0x1301, alpn: str | None = "http/1.1",
                 hrr_group: int | None = None, hrr_cookie: bytes | None = None,
                 tamper: set | None = None, tickets: int = 1,
                 psk_store: dict | None = None, compress_cert=None):
        # compress_cert(cert_msg) -> CompressedCertificate (hs 25) mesajı (RFC 8879) ya da None
        self.compress_cert = compress_cert
        self.psk_store = psk_store
        self.resumed = False
        self.pki = pki
        self.suite = suite
        self.alpn = alpn
        self.hrr_group = hrr_group
        self.hrr_cookie = hrr_cookie
        self.tamper = tamper or set()
        self.tickets = tickets
        self.hlib, self.h, self.key_len, self.aead_cls = _SUITES[suite]
        self.inbuf = b""
        self.transcript = b""
        self.state = "WAIT_CH"
        self.read = None
        self.write = None
        self.app_in: list[bytes] = []
        self.alerts: list[bytes] = []
        self.key_updates_received = 0
        self.client_hellos: list[dict] = []

    # -- yardımcılar
    def th(self) -> bytes:
        return self.hlib(self.transcript).digest()

    def _traffic(self, secret):
        k = expand_label(self.h, secret, "key", b"", self.key_len)
        iv = expand_label(self.h, secret, "iv", b"", 12)
        return _Dir(self.aead_cls, k, iv, secret)

    def _records(self, data: bytes):
        self.inbuf += data
        while len(self.inbuf) >= 5:
            l = struct.unpack("!H", self.inbuf[3:5])[0]
            if len(self.inbuf) < 5 + l:
                return
            rec = self.inbuf[:5 + l]
            self.inbuf = self.inbuf[5 + l:]
            yield rec[:5], rec[5:]

    # -- giriş noktası
    def receive(self, data: bytes) -> bytes:
        out = b""
        for header, payload in self._records(data):
            rtype = header[0]
            if rtype == 22 and self.state in ("WAIT_CH", "WAIT_CH2"):
                out += self._on_client_hello(payload)
            elif rtype == 20:
                continue
            elif rtype == 23:
                content, ctype = self.read.open(header, payload)
                out += self._on_encrypted(content, ctype)
            else:
                raise AssertionError(f"sunucu: beklenmeyen record {rtype}")
        return out

    def _on_client_hello(self, msg: bytes) -> bytes:
        ch = parse_client_hello(msg)
        self.client_hellos.append(ch)
        sid = ch["session_id"]
        if self.hrr_group is not None and (
                self.state == "WAIT_CH" or (self.state == "WAIT_CH2" and "double_hrr" in self.tamper)):
            # HelloRetryRequest
            exts = ext(43, b"\x03\x04") + ext(51, struct.pack("!H", self.hrr_group))
            if self.hrr_cookie:
                exts += ext(44, struct.pack("!H", len(self.hrr_cookie)) + self.hrr_cookie)
            body = (b"\x03\x03" + HRR_RANDOM + bytes([len(sid)]) + sid +
                    struct.pack("!HB", self.suite, 0) + struct.pack("!H", len(exts)) + exts)
            hrr = hs(2, body)
            d = self.hlib(msg).digest()
            self.transcript = b"\xfe\x00\x00" + bytes([len(d)]) + d + hrr
            self.state = "WAIT_CH2"
            return struct.pack("!BHH", 22, 0x0303, len(hrr)) + hrr

        self.transcript += msg
        if self.state == "WAIT_CH2" and self.hrr_cookie:
            assert ch["exts"].get(44) == struct.pack("!H", len(self.hrr_cookie)) + self.hrr_cookie

        if self.hrr_group is not None:
            group = self.hrr_group
        else:
            group = 0x001D
        peer = ch["shares"][group]
        if group == 0x001D:
            priv = x25519.X25519PrivateKey.generate()
            shared = priv.exchange(x25519.X25519PublicKey.from_public_bytes(peer))
            pub = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                                 serialization.PublicFormat.Raw)
        elif group in (0x0017, 0x0018):
            curve = {0x0017: ec.SECP256R1(), 0x0018: ec.SECP384R1()}[group]
            priv = ec.generate_private_key(curve)
            shared = priv.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(curve, peer))
            pub = priv.public_key().public_bytes(serialization.Encoding.X962,
                                                 serialization.PublicFormat.UncompressedPoint)
        else:   # secp521r1 / x448 / ffdhe: HRR ile istenen grup için sunucu payı
            from fasthttpc.security.keyshare import compute_shared_secret, generate_key_share
            priv, pub = generate_key_share(group)
            shared = compute_shared_secret(group, priv, peer)

        psk = None
        if "force_psk" in self.tamper:           # teklif edilmemiş PSK'yı seçen kötü niyetli sunucu
            psk = b"\x07" * self.h.digest_size
        elif self.psk_store is not None and 41 in ch["exts"]:
            psk = self._select_psk(ch, msg)
        exts = b""
        if "tls12" not in self.tamper:
            exts += ext(43, b"\x03\x04")
        exts += ext(51, struct.pack("!HH", group, len(pub)) + pub)
        if psk is not None:
            exts += ext(41, b"\x00\x00")
            self.resumed = True
        echo = os.urandom(32) if "wrong_session_id" in self.tamper else sid
        body = (b"\x03\x03" + os.urandom(32) + bytes([len(echo)]) + echo +
                struct.pack("!HB", self.suite, 0) + struct.pack("!H", len(exts)) + exts)
        sh = hs(2, body)
        self.transcript += sh
        out = struct.pack("!BHH", 22, 0x0303, len(sh)) + sh
        if "no_ccs" not in self.tamper:
            out += b"\x14\x03\x03\x00\x01\x01"

        # key schedule
        hl = self.h.digest_size
        zero = b"\x00" * hl
        early = hkdf_extract(self.hlib, zero, psk if psk is not None else zero)
        derived = expand_label(self.h, early, "derived", self.hlib(b"").digest(), hl)
        hs_secret = hkdf_extract(self.hlib, derived, shared)
        th = self.th()
        self.c_hts = expand_label(self.h, hs_secret, "c hs traffic", th, hl)
        self.s_hts = expand_label(self.h, hs_secret, "s hs traffic", th, hl)
        self.hs_secret = hs_secret
        self.read = self._traffic(self.c_hts)
        self.write = self._traffic(self.s_hts)

        msgs = []
        ee_ext = b""
        if self.alpn:
            p = self.alpn.encode()
            lst = bytes([len(p)]) + p
            ee_ext += ext(16, struct.pack("!H", len(lst)) + lst)
        if "alps" in self.tamper:
            ee_ext += ext(17513, b"\x00\x00")          # ALPS kabul (sunucu ayarları boş)
        if "alps_new" in self.tamper:
            ee_ext += ext(17613, b"\x00\x00")          # ALPS yeni kod noktası (Chrome 133+)
        if "trust_anchors" in self.tamper:
            # draft-ietf-tls-trust-anchor-ids: sunucunun sunabildiği anchor listesi (EE).
            ids = b"\x04\xd6\x79\x09\x01" + b"\x03\x82\x01\x02"
            ee_ext += ext(0xCA34, struct.pack("!H", len(ids)) + ids)
        msgs.append(hs(8, struct.pack("!H", len(ee_ext)) + ee_ext))
        if "cert_request" in self.tamper:
            msgs.append(hs(13, getattr(self, "cr_body", None) or b"\x00\x00\x00"))
        for m in msgs:
            self.transcript += m
        send_cert = psk is None or "psk_with_cert" in self.tamper
        if "skip_cert" not in self.tamper and send_cert:
            # trust_anchors: CertificateEntry'de boş extension = "seçilen zincir eşleşti".
            entry_ext = ext(0xCA34, b"") if "trust_anchors" in self.tamper else b""
            certs = b"".join(len(d).to_bytes(3, "big") + d
                             + struct.pack("!H", len(entry_ext)) + entry_ext
                             for d in self.pki.chain_der())
            cert_msg = hs(11, b"\x00" + len(certs).to_bytes(3, "big") + certs)
            if self.compress_cert is not None:
                cert_msg = self.compress_cert(cert_msg)
            self.transcript += cert_msg
            msgs.append(cert_msg)
        if "skip_cv" not in self.tamper and send_cert:
            content = b"\x20" * 64 + b"TLS 1.3, server CertificateVerify\x00" + self.th()
            if self.pki.leaf_key.startswith("mldsa"):
                # draft-ietf-tls-mldsa: saf ML-DSA, boş bağlam; şema = parametre kümesi.
                scheme = {"mldsa44": 0x0904, "mldsa65": 0x0905, "mldsa87": 0x0906}[self.pki.leaf_key]
                sig = self.pki.key.sign(content)
            else:
                scheme = 0x0403
                signer = ec.generate_private_key(ec.SECP256R1()) if "wrong_key_cv" in self.tamper \
                    else self.pki.key
                sig = signer.sign(content, ec.ECDSA(hashes.SHA256()))
            if "bad_cv_sig" in self.tamper:
                sig = sig[:-1] + bytes([sig[-1] ^ 1])
            cv = hs(15, struct.pack("!HH", scheme, len(sig)) + sig)
            self.transcript += cv
            msgs.append(cv)
        fkey = expand_label(self.h, self.s_hts, "finished", b"", hl)
        mac = hmac.new(fkey, self.th(), self.hlib).digest()
        if "bad_finished" in self.tamper:
            mac = bytes([mac[0] ^ 1]) + mac[1:]
        fin = hs(20, mac)
        self.transcript += fin
        msgs.append(fin)

        flight = b"".join(msgs)
        if "coalesce" in self.tamper:
            out += self.write.seal(flight, 22, pad=7)
        elif "split_records" in self.tamper:
            for i in range(0, len(flight), 50):
                out += self.write.seal(flight[i:i + 50], 22)
        else:
            for i, m in enumerate(msgs):
                out += self.write.seal(m, 22)
                if i == 0 and "early_app_data" in self.tamper:
                    out += self.write.seal(b"erken", 23)   # Finished'tan önce

        # application secrets (server Finished dahil)
        th_sf = self.th()
        d2 = expand_label(self.h, hs_secret, "derived", self.hlib(b"").digest(), hl)
        master = hkdf_extract(self.hlib, d2, zero)
        self.master = master
        self.c_ats = expand_label(self.h, master, "c ap traffic", th_sf, hl)
        self.s_ats = expand_label(self.h, master, "s ap traffic", th_sf, hl)
        self.app_write = self._traffic(self.s_ats)
        self.state = "WAIT_FINISHED"
        return out

    def _select_psk(self, ch: dict, msg: bytes):
        """pre_shared_key uzantısı: tanınan ilk kimliğin PSK'sı (binder doğrulanır) ya da None."""
        d = ch["exts"][41]
        assert ch["order"][-1] == 41, "pre_shared_key son uzantı olmalı"
        ilen = struct.unpack("!H", d[:2])[0]
        ids, p = [], 2
        while p < 2 + ilen:
            n = struct.unpack("!H", d[p:p + 2])[0]
            ids.append(d[p + 2:p + 2 + n])
            p += 2 + n + 4
        binders_blob = d[p:]
        blen = struct.unpack("!H", binders_blob[:2])[0]
        binders, q = [], 2
        while q < 2 + blen:
            binders.append(binders_blob[q + 1:q + 1 + binders_blob[q]])
            q += 1 + binders_blob[q]
        for idx, ident in enumerate(ids):
            psk = self.psk_store.get(ident)
            if psk is None:
                continue
            hl = self.h.digest_size
            early = hkdf_extract(self.hlib, b"\x00" * hl, psk)
            bkey = expand_label(self.h, early, "res binder", self.hlib(b"").digest(), hl)
            fkey = expand_label(self.h, bkey, "finished", b"", hl)
            trunc = msg[:len(msg) - len(binders_blob)]
            want = hmac.new(fkey, self.hlib(trunc).digest(), self.hlib).digest()
            assert hmac.compare_digest(want, binders[idx]), "PSK binder hatalı"
            return psk
        return None

    def _on_encrypted(self, content: bytes, ctype: int) -> bytes:
        if ctype == 21:                  # istemcinin (şifreli) alert'i: kaydet
            self.alerts.append(content)
            return b""
        alps = "alps" in self.tamper or "alps_new" in self.tamper
        if self.state == "WAIT_FINISHED" and alps and content[:1] == b"\x08":
            # ALPS: istemci EncryptedExtensions'ı Finished'tan ÖNCE gelir ve transcript'e girer.
            assert ctype == 22
            self.client_ee = content
            self.transcript += content
            return b""
        if self.state == "WAIT_FINISHED":
            if alps:
                assert getattr(self, "client_ee", None), "ALPS kabul edildi ama istemci EE yollamadı"
            assert ctype == 22 and content[0] == 20, "client Finished bekleniyordu"
            hl = self.h.digest_size
            fkey = expand_label(self.h, self.c_hts, "finished", b"", hl)
            expected = hmac.new(fkey, self.th(), self.hlib).digest()
            assert hmac.compare_digest(content[4:], expected), "client Finished MAC hatalı"
            self.transcript += content
            self.read = self._traffic(self.c_ats)
            self.write = self.app_write
            self.state = "CONNECTED"
            out = b""
            if self.psk_store is not None:
                rms = expand_label(self.h, self.master, "res master", self.th(), self.h.digest_size)
            for i in range(self.tickets):
                if self.psk_store is None:
                    nst = hs(4, struct.pack("!IIB", 7200, 1, 0) + b"\x00\x04tick" + b"\x00\x00")
                else:
                    tick, nonce = os.urandom(24), bytes([i])
                    self.psk_store[tick] = expand_label(self.h, rms, "resumption", nonce, self.h.digest_size)
                    nst = hs(4, struct.pack("!IIB", 7200, 1, len(nonce)) + nonce +
                             struct.pack("!H", len(tick)) + tick + b"\x00\x00")
                out += self.write.seal(nst, 22)
            return out
        if ctype == 23:
            self.app_in.append(content)
            return b""
        if ctype == 21:
            self.alerts.append(content)
            return b""
        if ctype == 22 and content[0] == 24:
            self.key_updates_received += 1
            s = expand_label(self.h, self.read.secret, "traffic upd", b"", self.h.digest_size)
            self.read = self._traffic(s)
            out = b""
            if content[4] == 1:
                out += self.write.seal(hs(24, b"\x00"), 22)
                self._rotate_write()
            return out
        raise AssertionError(f"sunucu: beklenmeyen iç tip {ctype}")

    # -- uygulama aşaması API'si
    def send_app(self, data: bytes, pad: int = 0) -> bytes:
        return b"".join(self.write.seal(data[i:i + 2 ** 14], 23, pad=pad)
                        for i in range(0, max(len(data), 1), 2 ** 14))

    def send_alert(self, level: int, desc: int) -> bytes:
        return self.write.seal(bytes([level, desc]), 21)

    def _rotate_write(self):
        s = expand_label(self.h, self.write.secret, "traffic upd", b"", self.h.digest_size)
        self.write = self._traffic(s)

    def send_key_update(self, request: bool) -> bytes:
        out = self.write.seal(hs(24, b"\x01" if request else b"\x00"), 22)
        self._rotate_write()
        return out


# ------------------------------------------------- I/O sürücüleri (testler için)
def http_responder(body: bytes = b"merhaba dunya", extra: bytes = b""):
    """İstek başlığı tamamlanınca bir HTTP/1.1 yanıtı üreten basit işleyici."""
    def handle(server: "FakeTLS13Server") -> bytes:
        buf = b"".join(server.app_in)
        if b"\r\n\r\n" not in buf:
            return b""
        server.app_in.clear()
        server.requests = getattr(server, "requests", []) + [buf]
        resp = (b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() +
                b"\r\nContent-Type: text/plain\r\nSet-Cookie: s=1\r\n\r\n" + body)
        return extra + server.send_app(resp)
    return handle


async def async_serve(server: "FakeTLS13Server", reader, writer, handler=None):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            out = server.receive(data)
            if handler and server.state == "CONNECTED":
                out += handler(server)
            if out:
                writer.write(out)
                await writer.drain()
    finally:
        writer.close()


def sync_serve(server: "FakeTLS13Server", sock, handler=None):
    try:
        while True:
            data = sock.recv(65536)
            if not data:
                break
            out = server.receive(data)
            if handler and server.state == "CONNECTED":
                out += handler(server)
            if out:
                sock.sendall(out)
    except OSError:
        pass
    finally:
        sock.close()
