"""TLS testleri için ağsız sahte soket/sunucu yardımcıları."""
from __future__ import annotations

import hashlib
import hmac
import os
import struct

from fasthttpc.crypto_math import PureCryptoEngine as P, FastAESGCM, FastChaCha20Poly1305
from fasthttpc.security import tls_adapter as ta


class FakeSocket:
    """recv() önceden yüklenmiş tampondan okur; sendall() çıktıyı biriktirir.

    on_send verilirse, her sendall'da çağrılır ve dönen bytes alım tamponuna eklenir.
    """

    def __init__(self, incoming: bytes = b"", on_send=None, chunk: int = 16384):
        self.incoming = bytearray(incoming)
        self.sent = bytearray()
        self.sends: list[bytes] = []
        self.on_send = on_send
        self.chunk = chunk
        self.closed = False

    def feed(self, data: bytes) -> None:
        self.incoming += data

    def recv(self, n: int) -> bytes:
        n = min(n, self.chunk)
        out = bytes(self.incoming[:n])
        del self.incoming[:n]
        return out

    def sendall(self, data: bytes) -> None:
        self.sent += data
        self.sends.append(bytes(data))
        if self.on_send:
            reply = self.on_send(bytes(data))
            if reply:
                self.incoming += reply

    def settimeout(self, t):
        pass

    def close(self):
        self.closed = True


def seal(key: bytes, iv: bytes, seq: int, content: bytes, content_type: int,
         cipher_name: str = "AES", pad: int = 0) -> bytes:
    inner = content + bytes([content_type]) + b"\x00" * pad
    header = struct.pack("!BHH", 0x17, 0x0303, len(inner) + 16)
    nonce = ta._nonce(iv, seq)
    if cipher_name.startswith("AES"):
        ct, tag = FastAESGCM(key).encrypt_gcm(nonce, inner, header)
    else:
        ct, tag = FastChaCha20Poly1305(key).encrypt_aead(nonce, inner, header)
    return header + ct + tag


def unseal(key: bytes, iv: bytes, seq: int, record: bytes, cipher_name: str = "AES"):
    header, body = record[:5], record[5:]
    nonce = ta._nonce(iv, seq)
    if cipher_name.startswith("AES"):
        pt = FastAESGCM(key).decrypt_gcm(nonce, body[:-16], header, body[-16:])
    else:
        pt = FastChaCha20Poly1305(key).decrypt_aead(nonce, body[:-16], header, body[-16:])
    pt = pt.rstrip(b"\x00")
    return pt[:-1], pt[-1]


def split_records(data: bytes) -> list[bytes]:
    out, i = [], 0
    while i + 5 <= len(data):
        ln = struct.unpack("!H", data[i + 3:i + 5])[0]
        out.append(data[i:i + 5 + ln])
        i += 5 + ln
    return out


def app_state(cipher_suite: int = 0x1301) -> dict:
    """Handshake sonrası (application anahtarları devrede) bir state üretir."""
    name, key_len, h = ta.suite_params(cipher_suite)
    c_ats = os.urandom(h().digest_size)
    s_ats = os.urandom(h().digest_size)
    ck, civ = ta.traffic_key_iv(c_ats, key_len, h)
    sk, siv = ta.traffic_key_iv(s_ats, key_len, h)
    return {
        "is_tls13": True, "using_app_keys": True, "cipher_name": name, "key_len": key_len,
        "hash_func": h, "client_ats": c_ats, "server_ats": s_ats,
        "app_client_write_key": ck, "app_client_write_iv": civ,
        "app_server_write_key": sk, "app_server_write_iv": siv,
        "app_client_seq_num": 0, "app_server_seq_num": 0,
        "client_seq_num": 0, "server_seq_num": 0,
    }


# ---------------------------------------------------------------------------
# Sahte TLS 1.3 sunucusu (negotiate testleri için)
# ---------------------------------------------------------------------------

def hs(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def ext(t: int, data: bytes) -> bytes:
    return struct.pack("!HH", t, len(data)) + data


def parse_client_hello(record_bytes: bytes) -> dict:
    body = record_bytes[9:]
    pos = 2 + 32
    sid_len = body[pos]
    sid = body[pos + 1:pos + 1 + sid_len]
    pos += 1 + sid_len
    cs_len = struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 2 + cs_len
    pos += 1 + body[pos]
    ext_len = struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 2
    end = pos + ext_len
    pub = None
    while pos < end:
        t, ln = struct.unpack("!HH", body[pos:pos + 4])
        data = body[pos + 4:pos + 4 + ln]
        if t == 51:
            p = 2
            while p < len(data):
                g, kl = struct.unpack("!HH", data[p:p + 4])
                if g == 0x001D:
                    pub = data[p + 4:p + 4 + kl]
                p += 4 + kl
        pos += 4 + ln
    return {"session_id": sid, "x25519_pub": pub}


def server_hello(session_id: bytes, server_pub: bytes, cipher_suite: int = 0x1301,
                 extra_exts: bytes = b"", random: bytes | None = None) -> bytes:
    random = random if random is not None else os.urandom(32)
    exts = ext(43, b"\x03\x04") + ext(51, struct.pack("!HH", 0x001D, len(server_pub)) + server_pub)
    exts += extra_exts
    body = (b"\x03\x03" + random + bytes([len(session_id)]) + session_id
            + struct.pack("!H", cipher_suite) + b"\x00" + struct.pack("!H", len(exts)) + exts)
    return hs(2, body)


def plain_records(msg: bytes, sizes: list[int] | None = None) -> bytes:
    """Düz handshake verisini (isteğe bağlı) parçalara bölünmüş record'lara sarar."""
    out, i = b"", 0
    sizes = list(sizes or [])
    while i < len(msg):
        n = sizes.pop(0) if sizes else len(msg) - i
        part = msg[i:i + n]
        out += struct.pack("!BHH", 22, 0x0303, len(part)) + part
        i += n
    return out


class FakeTLSServer:
    """ClientHello'yu görünce ServerHello + şifreli uçuşu üreten sahte sunucu.

    flight: şifreli handshake uçuşunun öğeleri; her öğe ("hs", tip) — standart
    mesaj üretilir (20=Finished doğru MAC'le), ("raw", ct, bytes) — ham içerik,
    ("msg", bytes) — hazır handshake mesajı (transcript'e girer),
    ("record", [öğeler]) — birden fazla mesaj tek record'da.
    """

    def __init__(self, cipher_suite=0x1301, flight=None, session_id_override=None,
                 sh_split=None, sh_extra_exts=b"", after_finished=b""):
        self.cipher_suite = cipher_suite
        self.flight = flight if flight is not None else [("hs", 8), ("hs", 11), ("hs", 15), ("hs", 20)]
        self.session_id_override = session_id_override
        self.sh_split = sh_split
        self.sh_extra_exts = sh_extra_exts
        self.after_finished = after_finished
        self.state = None
        self.client_finished = None

    def __call__(self, data: bytes) -> bytes:
        if self.state is None:
            return self._on_client_hello(data)
        if self.client_finished is None:
            self.client_finished = data
            return self.after_finished_records()
        return b""

    def after_finished_records(self) -> bytes:
        return self.after_finished(self) if callable(self.after_finished) else self.after_finished

    def _on_client_hello(self, ch: bytes) -> bytes:
        info = parse_client_hello(ch)
        name, key_len, h = ta.suite_params(self.cipher_suite)
        priv = os.urandom(32)
        pub = P.x25519(priv, (9).to_bytes(32, "little"))
        shared = P.x25519(priv, info["x25519_pub"])
        sid = info["session_id"] if self.session_id_override is None else self.session_id_override
        sh = server_hello(sid, pub, self.cipher_suite, self.sh_extra_exts)
        transcript = ch[5:] + sh
        hs_secret, ck, civ, sk, siv, c_hts, s_hts = P.derive_tls13_keys(
            shared, h(transcript).digest(), key_len, hash_alg=h)
        self.state = dict(name=name, key_len=key_len, h=h, sk=sk, siv=siv, seq=0, hs_secret=hs_secret,
                          ck=ck, civ=civ)

        out = plain_records(sh, self.sh_split)
        out += struct.pack("!BHH", 20, 0x0303, 1) + b"\x01"  # uyumluluk CCS

        def make(item):
            nonlocal transcript
            if item[0] == "raw":
                return item[2], item[1]
            if item[0] == "msg":             # hazır handshake mesajı (transcript'e girer)
                transcript += item[1]
                return item[1], 22
            t = item[1]
            if t == 20:
                fk = P.tls13_hkdf_expand_label(s_hts, "finished", b"", h().digest_size, hash_alg=h)
                m = hs(20, hmac.new(fk, h(transcript).digest(), h).digest())
            elif t == 8:
                m = hs(8, b"\x00\x00")
            else:
                m = hs(t, b"\x00" * 8)
            transcript += m
            return m, 22

        for item in self.flight:
            if item[0] == "record":
                content = b"".join(make(x)[0] for x in item[1])
                ct = 22
            else:
                content, ct = make(item)
            out += seal(sk, siv, self.state["seq"], content, ct, name)
            self.state["seq"] += 1

        self.state["transcript"] = transcript
        self.state["c_hts"] = c_hts
        return out

    def app_keys(self):
        """İstemci Finished alındıktan sonra application anahtarlarını türetir."""
        st = self.state
        h = st["h"]
        # Application anahtarları sunucu Finished'a kadarki transcript'ten türetilir.
        return P.derive_application_keys(st["hs_secret"], h(st["transcript"]).digest(),
                                         st["key_len"], hash_alg=h)
