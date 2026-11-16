"""Sıcak yol performans regresyon testleri (zamanlama YOK: sistem çağrısı, TLS
record'u ve frame sayıları ile algoritmik davranış ölçülür; bkz. docs/performance.md)."""
import os
import struct

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from fasthttpc.models.headers import Headers
from fasthttpc.protocol.http2_parser import (
    WU_BATCH_MAX, FrameType, HTTP2Frame, Http2Connection, h2_for_profile, h2_wu_thresholds,
)
from fasthttpc.security.tls_adapter import EncryptedSocket, _nonce


# ------------------------------------------------------------------ record katmanı
class _Sock:
    def __init__(self, data=b""):
        self.data, self.pos, self.recv_calls, self.sent = data, 0, 0, []

    def recv(self, n):
        self.recv_calls += 1
        out = self.data[self.pos:self.pos + n]
        self.pos += len(out)
        return out

    def sendall(self, b):
        self.sent.append(bytes(b))


def _state():
    k, iv = os.urandom(16), os.urandom(12)
    return {"is_tls13": True, "using_app_keys": True, "cipher_name": "AES",
            "app_server_write_key": k, "app_server_write_iv": iv,
            "app_client_write_key": k, "app_client_write_iv": iv,
            "app_server_seq_num": 0, "app_client_seq_num": 0}


def test_nonce_rfc8446_ile_ayni():
    iv = os.urandom(12)
    for seq in (0, 1, 255, 2 ** 32 + 7, 2 ** 64 - 1):
        eski = bytes(a ^ b for a, b in zip(iv, b"\x00" * 4 + seq.to_bytes(8, "big")))
        assert _nonce(iv, seq) == eski


def test_tam_boy_recordlar_az_sistem_cagrisiyla_okunur():
    """16 KiB'lik okuma her tam boy record'u iki recv()'e bölüyordu; artık
    toplam/64 KiB civarı çağrı yeter (O(veri/recv_boyu))."""
    st = _state()
    aead = AESGCM(st["app_server_write_key"])
    n, size = 64, 16384
    wire = bytearray()
    for seq in range(n):
        inner = bytes([seq % 256]) * size + b"\x17"
        h = struct.pack("!BHH", 0x17, 0x0303, len(inner) + 16)
        wire += h + aead.encrypt(_nonce(st["app_server_write_iv"], seq), inner, h)
    sock = _Sock(bytes(wire))
    es = EncryptedSocket(sock, st)
    for seq in range(n):
        assert es.recv_record() == (bytes([seq % 256]) * size, 0x17)
    assert sock.recv_calls <= len(wire) // EncryptedSocket._RECV_SIZE + 2
    assert len(es.read_buffer) == 0


def test_send_record_tek_sendall_ve_dogru_sifreli():
    st = _state()
    sock = _Sock()
    es = EncryptedSocket(sock, st)
    es.send_record(b"merhaba")
    assert len(sock.sent) == 1
    rec = sock.sent[0]
    pt = AESGCM(st["app_client_write_key"]).decrypt(_nonce(st["app_client_write_iv"], 0), rec[5:], rec[:5])
    assert pt == b"merhaba\x17"


# ------------------------------------------------------------------ HTTP/2 akış kontrolü
class _Rec:
    """send_record'ları ayrı ayrı kaydeden, verilen frame'leri teker teker döndüren soket."""

    def __init__(self, frames):
        self.incoming = [f.serialize() for f in frames]
        self.out: list[bytes] = []

    def send_record(self, data, content_type=0x17, use_app_keys=True):
        self.out.append(bytes(data))

    def recv_record(self, skip_post_handshake=False):
        return self.incoming.pop(0), 23


def _parse(buf):
    pos, out = 0, []
    while pos + 9 <= len(buf):
        n = int.from_bytes(buf[pos:pos + 3], "big")
        out.append(HTTP2Frame.parse(buf[pos:pos + 9 + n]))
        pos += 9 + n
    assert pos == len(buf)
    return out


def _download(profile, body):
    frames = [HTTP2Frame(0, FrameType.SETTINGS, 0, 0, b""), HTTP2Frame(1, FrameType.HEADERS, 0x4, 1, b"\x88")]
    for i in range(0, len(body), 16384):
        p = body[i:i + 16384]
        frames.append(HTTP2Frame(len(p), FrameType.DATA, 1 if i + 16384 >= len(body) else 0, 1, p))
    sock = _Rec(frames)
    conn = Http2Connection(sock, profile=profile)
    status, _h, got = conn.request("GET", "x", "/", [])
    assert status == 200 and got == body
    wu_records = [r for r in sock.out if _parse(r) and all(f.type == FrameType.WINDOW_UPDATE for f in _parse(r))]
    wus = [(f.stream_id, struct.unpack("!I", f.payload)[0]) for r in wu_records for f in _parse(r)]
    return len(frames) - 2, wu_records, wus


def test_varsayilan_profil_her_data_icin_tek_record():
    """65535 pencerede davranış aynı (her DATA'da kredi), ama bağlantı + stream
    WINDOW_UPDATE'i iki ayrı record yerine TEK record'da gider."""
    body = os.urandom(200_000)
    n_data, recs, wus = _download(None, body)
    assert len(recs) == n_data
    assert sum(n for sid, n in wus if sid == 0) == len(body)
    assert all(len(_parse(r)) == 2 for r in recs)


@pytest.mark.parametrize("profile", ["chrome_131", "firefox_133", "safari_18"])
def test_buyuk_pencerede_window_update_toplanir(profile):
    """Tarayıcı profillerinde kredi eşikte toplu verilir: record sayısı frame
    sayısıyla değil, veri/eşik ile orantılı; bağlantı kredisi eksiksiz geri verilir."""
    body = os.urandom(1 << 20)
    n_data, recs, wus = _download(profile, body)
    t_conn, t_stream = h2_wu_thresholds(h2_for_profile(profile))
    assert 1 < t_stream <= WU_BATCH_MAX and 1 < t_conn <= WU_BATCH_MAX
    assert len(recs) <= len(body) // min(t_conn, t_stream) + 1
    assert len(recs) < n_data
    assert sum(n for sid, n in wus if sid == 0) == len(body)


def test_varsayilan_profil_esigi_bir():
    assert h2_wu_thresholds(h2_for_profile(None)) == (1, 1)


# ------------------------------------------------------------------ Headers
def test_headers_listeden_kurulum_dogrusal(monkeypatch):
    """Kurulum her başlık için listeyi baştan kuran __setitem__'ı çağırmaz (O(n^2) idi)."""
    calls = []
    orig = Headers.__setitem__
    monkeypatch.setattr(Headers, "__setitem__", lambda self, k, v: (calls.append(k), orig(self, k, v)))
    items = [(f"X-H{i}", str(i)) for i in range(500)] + [("x-h3", "son")]
    h = Headers(items)
    assert calls == []
    assert len(h) == 500 and h["X-H3"] == "son" and list(h)[3] == "x-h3"
    assert Headers(dict(items[:3]))["x-h1"] == "1"
