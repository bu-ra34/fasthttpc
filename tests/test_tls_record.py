"""EncryptedSocket record katmanı: KeyUpdate, record sınırları, seq taşması."""
import struct

import pytest

from fasthttpc.security import tls_adapter as ta
from fasthttpc.security.tls_adapter import EncryptedSocket, TLSProtocolError
from tls_fakes import FakeSocket, seal, unseal, split_records, app_state


def _server_rec(st, content, ct=23, seq=None, key=None, iv=None, pad=0):
    seq = st["_srv_seq"] if seq is None else seq
    st["_srv_seq"] = seq + 1
    return seal(key or st["app_server_write_key"], iv or st["app_server_write_iv"],
                seq, content, ct, st["cipher_name"], pad)


@pytest.fixture(params=[0x1301, 0x1302, 0x1303])
def st(request):
    s = app_state(request.param)
    s["_srv_seq"] = 0
    return s


def test_normal_record_cozulur_ve_padding_atilir(st):
    sock = FakeSocket(_server_rec(st, b"merhaba", pad=7))
    es = EncryptedSocket(sock, st)
    assert es.recv_record(skip_post_handshake=True) == (b"merhaba", 23)
    assert st["app_server_seq_num"] == 1


def test_keyupdate_sonrasi_veri_yeni_anahtarla_cozulur(st):
    old_key, old_iv, old_secret = st["app_server_write_key"], st["app_server_write_iv"], st["server_ats"]
    h, kl = st["hash_func"], st["key_len"]
    new_secret = ta.next_traffic_secret(old_secret, h)
    new_key, new_iv = ta.traffic_key_iv(new_secret, kl, h)

    data = _server_rec(st, b"once", seq=0)
    data += _server_rec(st, ta.build_key_update(False), ct=22, seq=1)
    data += seal(new_key, new_iv, 0, b"sonra", 23, st["cipher_name"])  # seq sıfırlanır
    data += seal(new_key, new_iv, 1, b"daha sonra", 23, st["cipher_name"])

    es = EncryptedSocket(FakeSocket(data), st)
    assert es.recv_record(True) == (b"once", 23)
    assert es.recv_record(True) == (b"sonra", 23)
    assert es.recv_record(True) == (b"daha sonra", 23)
    assert st["server_ats"] == new_secret != old_secret
    assert st["app_server_write_key"] == new_key != old_key
    assert st["app_server_write_iv"] == new_iv != old_iv
    assert st["app_server_seq_num"] == 2
    assert st["key_updates_received"] == 1
    # update_not_requested -> biz KeyUpdate göndermeyiz
    assert es.raw_socket.sent == b""


def test_keyupdate_update_requested_kendi_keyupdateimizi_gonderir(st):
    h, kl = st["hash_func"], st["key_len"]
    old_ck, old_civ, old_c = st["app_client_write_key"], st["app_client_write_iv"], st["client_ats"]
    st["app_client_seq_num"] = 5
    new_s = ta.next_traffic_secret(st["server_ats"], h)
    nsk, nsiv = ta.traffic_key_iv(new_s, kl, h)

    data = _server_rec(st, ta.build_key_update(True), ct=22)
    data += seal(nsk, nsiv, 0, b"veri", 23, st["cipher_name"])
    sock = FakeSocket(data)
    es = EncryptedSocket(sock, st)
    assert es.recv_record(True) == (b"veri", 23)

    recs = split_records(bytes(sock.sent))
    assert len(recs) == 1
    # Bizim KeyUpdate'imiz ESKİ istemci anahtarıyla ve eski seq ile şifrelenir.
    content, ct = unseal(old_ck, old_civ, 5, recs[0], st["cipher_name"])
    assert ct == 22 and content == ta.build_key_update(False)

    new_c = ta.next_traffic_secret(old_c, h)
    nck, nciv = ta.traffic_key_iv(new_c, kl, h)
    assert st["client_ats"] == new_c
    assert st["app_client_write_key"] == nck and st["app_client_seq_num"] == 0

    # Sonraki gönderim yeni anahtarla, seq=0'dan.
    es.send_record(b"istek")
    rec = split_records(bytes(sock.sent))[1]
    assert unseal(nck, nciv, 0, rec, st["cipher_name"]) == (b"istek", 23)


def test_keyupdate_skip_false_iken_de_islenir(st):
    h, kl = st["hash_func"], st["key_len"]
    nsk, nsiv = ta.traffic_key_iv(ta.next_traffic_secret(st["server_ats"], h), kl, h)
    data = _server_rec(st, ta.build_key_update(False), ct=22)
    data += seal(nsk, nsiv, 0, b"x", 23, st["cipher_name"])
    es = EncryptedSocket(FakeSocket(data), st)
    assert es.recv_record() == (b"x", 23)


def test_keyupdate_record_sinirinda_bitmezse_hata(st):
    data = _server_rec(st, ta.build_key_update(False) + b"\x04\x00\x00\x00", ct=22)
    es = EncryptedSocket(FakeSocket(data), st)
    with pytest.raises(TLSProtocolError, match="unexpected_message"):
        es.recv_record(True)


def test_bozuk_keyupdate_reddedilir(st):
    data = _server_rec(st, b"\x18\x00\x00\x01\x02", ct=22)
    es = EncryptedSocket(FakeSocket(data), st)
    with pytest.raises(TLSProtocolError, match="illegal_parameter"):
        es.recv_record(True)


def test_new_session_ticket_yutulur_bolunmus_olsa_bile(st):
    nst = b"\x04" + (10).to_bytes(3, "big") + b"\x00" * 10
    data = _server_rec(st, nst[:6], ct=22) + _server_rec(st, nst[6:], ct=22)
    data += _server_rec(st, b"veri")
    es = EncryptedSocket(FakeSocket(data), st)
    assert es.recv_record(True) == (b"veri", 23)


def test_bilinmeyen_post_handshake_mesaji_reddedilir(st):
    data = _server_rec(st, b"\x0d\x00\x00\x00", ct=22)  # CertificateRequest
    es = EncryptedSocket(FakeSocket(data), st)
    with pytest.raises(TLSProtocolError, match="unexpected_message"):
        es.recv_record(True)


def test_cok_buyuk_sifreli_record_reddedilir(st):
    header = struct.pack("!BHH", 0x17, 0x0303, ta.MAX_CIPHERTEXT + 1)
    sock = FakeSocket(header + b"\x00" * 100)
    es = EncryptedSocket(sock, st)
    with pytest.raises(TLSProtocolError, match="record_overflow"):
        es.recv_record(True)
    assert sock.closed


def test_sinirdaki_record_kabul_edilir(st):
    content = b"a" * ta.MAX_PLAINTEXT
    es = EncryptedSocket(FakeSocket(_server_rec(st, content)), st)
    assert es.recv_record(True) == (content, 23)


def test_cozulmus_plaintext_siniri_asarsa_reddedilir(st):
    # 2^14 içerik + tip + 200 byte padding: ciphertext sınırı içinde ama plaintext fazla
    rec = _server_rec(st, b"a" * ta.MAX_PLAINTEXT, pad=200)
    es = EncryptedSocket(FakeSocket(rec), st)
    with pytest.raises(TLSProtocolError, match="record_overflow"):
        es.recv_record(True)


def test_beklenmeyen_record_tipi_reddedilir(st):
    es = EncryptedSocket(FakeSocket(struct.pack("!BHH", 0x18, 0x0303, 20) + b"\x00" * 20), st)
    with pytest.raises(TLSProtocolError, match="unexpected_message"):
        es.recv_record(True)


def test_alim_seq_tasmasinda_kapatir(st):
    st["app_server_seq_num"] = 2 ** 64
    sock = FakeSocket(seal(st["app_server_write_key"], st["app_server_write_iv"], 0, b"x", 23,
                           st["cipher_name"]))
    es = EncryptedSocket(sock, st)
    with pytest.raises(TLSProtocolError, match="2\\^64-1"):
        es.recv_record(True)
    assert sock.closed


def test_gonderim_seq_tasmasinda_kapatir(st):
    sock = FakeSocket()
    es = EncryptedSocket(sock, st)
    st["app_client_seq_num"] = 2 ** 64 - 1  # son geçerli değer
    es.send_record(b"son")
    assert st["app_client_seq_num"] == 2 ** 64
    with pytest.raises(TLSProtocolError, match="2\\^64-1"):
        es.send_record(b"bir fazla")
    assert sock.closed


def test_buyuk_veri_gonderimde_bolunur(st):
    sock = FakeSocket()
    es = EncryptedSocket(sock, st)
    payload = bytes(range(256)) * 200  # 51200 byte
    es.send_record(payload)
    recs = split_records(bytes(sock.sent))
    assert len(recs) == 4
    got = b""
    for i, r in enumerate(recs):
        assert len(r) - 5 <= ta.MAX_CIPHERTEXT
        c, t = unseal(st["app_client_write_key"], st["app_client_write_iv"], i, r, st["cipher_name"])
        got += c
    assert got == payload
