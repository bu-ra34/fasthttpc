"""EncryptedSocket okuma tamponu ve cipher önbelleği testleri (ağsız, sahte soket)."""
import os
import struct

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from fasthttpc.security.tls_adapter import EncryptedSocket


class FakeSock:
    def __init__(self, data: bytes, chunk: int = 7):
        self.data = data
        self.pos = 0
        self.chunk = chunk
        self.sent = bytearray()
        self.recv_calls = 0

    def recv(self, n):
        self.recv_calls += 1
        out = self.data[self.pos:self.pos + min(n, self.chunk)]
        self.pos += len(out)
        return out

    def sendall(self, b):
        self.sent += b


def _nonce(iv, seq):
    return bytes(a ^ b for a, b in zip(iv, b"\x00" * 4 + seq.to_bytes(8, "big")))


def _seal(aead, iv, seq, content, ctype=0x17, pad=0):
    inner = content + bytes([ctype]) + b"\x00" * pad
    header = struct.pack("!BHH", 0x17, 0x0303, len(inner) + 16)
    return header + aead.encrypt(_nonce(iv, seq), inner, header)


def _state(cipher_name, key_len):
    return {
        "is_tls13": True, "using_app_keys": True, "cipher_name": cipher_name,
        "app_server_write_key": os.urandom(key_len), "app_server_write_iv": os.urandom(12),
        "app_client_write_key": os.urandom(key_len), "app_client_write_iv": os.urandom(12),
        "app_server_seq_num": 0, "app_client_seq_num": 0,
        "server_seq_num": 0, "client_seq_num": 0,
    }


@pytest.mark.parametrize("name,klen,cls", [("AES", 16, AESGCM), ("AES", 32, AESGCM),
                                            ("CHACHA20-POLY1305", 32, ChaCha20Poly1305)])
@pytest.mark.parametrize("chunk", [1, 5, 13, 16384])
def test_recv_many_records_chunked(name, klen, cls, chunk):
    st = _state(name, klen)
    aead = cls(st["app_server_write_key"])
    msgs = [os.urandom(n) for n in (0 + 1, 100, 16000, 3, 777)]
    wire = b"".join(_seal(aead, st["app_server_write_iv"], i, m, pad=i) for i, m in enumerate(msgs))
    # Araya change_cipher_spec record'u (yok sayılmalı)
    wire = b"\x14\x03\x03\x00\x01\x01" + wire
    es = EncryptedSocket(FakeSock(wire, chunk), st)
    for m in msgs:
        data, t = es.recv_record()
        assert t == 0x17 and data == m
    assert st["app_server_seq_num"] == len(msgs)
    assert len(es.read_buffer) == 0 and es._rbuf_off == 0


def test_post_handshake_skipped_and_buffer_offset():
    st = _state("AES", 16)
    aead = AESGCM(st["app_server_write_key"])
    iv = st["app_server_write_iv"]
    nst = b"\x04\x00\x00\x05" + b"\x00" * 5
    wire = _seal(aead, iv, 0, nst, ctype=22) + _seal(aead, iv, 1, b"hello")
    es = EncryptedSocket(FakeSock(wire, 16384), st)
    assert es.recv_record(skip_post_handshake=True) == (b"hello", 0x17)


def test_cipher_object_reused_and_invalidated():
    st = _state("AES", 16)
    es = EncryptedSocket(FakeSock(b""), st)
    k = st["app_client_write_key"]
    c1, _ = es._cipher(k)
    c2, _ = es._cipher(k)
    assert c1 is c2
    # Farklı anahtar (ör. KeyUpdate) -> farklı nesne
    c3, _ = es._cipher(os.urandom(16))
    assert c3 is not c1
    es._invalidate_cipher_cache()
    assert es._cipher(k)[0] is not c1


def test_send_record_roundtrip_with_cached_cipher():
    st = _state("CHACHA20-POLY1305", 32)
    sock = FakeSock(b"")
    es = EncryptedSocket(sock, st)
    for i in range(3):
        es.send_record(b"x" * i)
    aead = ChaCha20Poly1305(st["app_client_write_key"])
    buf, seq = bytes(sock.sent), 0
    while buf:
        ln = struct.unpack("!H", buf[3:5])[0]
        pt = aead.decrypt(_nonce(st["app_client_write_iv"], seq), buf[5:5 + ln], buf[:5])
        assert pt == b"x" * seq + b"\x17"
        buf, seq = buf[5 + ln:], seq + 1
    assert seq == 3


def test_tampered_record_rejected():
    st = _state("AES", 16)
    aead = AESGCM(st["app_server_write_key"])
    rec = bytearray(_seal(aead, st["app_server_write_iv"], 0, b"data"))
    rec[-1] ^= 1
    es = EncryptedSocket(FakeSock(bytes(rec), 16384), st)
    with pytest.raises(ValueError):
        es.recv_record()


def test_truncated_stream_raises():
    st = _state("AES", 16)
    aead = AESGCM(st["app_server_write_key"])
    rec = _seal(aead, st["app_server_write_iv"], 0, b"data")[:-3]
    es = EncryptedSocket(FakeSock(rec, 16384), st)
    with pytest.raises(ConnectionResetError):
        es.recv_record()


def test_large_buffer_compaction():
    st = _state("AES", 16)
    aead = AESGCM(st["app_server_write_key"])
    iv = st["app_server_write_iv"]
    n = 40
    wire = b"".join(_seal(aead, iv, i, bytes([i % 256]) * 16000) for i in range(n))
    sock = FakeSock(wire, 10 ** 9)  # her şeyi tek recv'de ver
    es = EncryptedSocket(sock, st)
    for i in range(n):
        data, _ = es.recv_record()
        assert data == bytes([i % 256]) * 16000
        assert es._rbuf_off <= 65536 + 16021
    assert len(es.read_buffer) == 0
