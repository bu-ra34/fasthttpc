"""ServerHello sağlamlaştırma ve handshake sıra durum makinesi."""
import os
import struct

import pytest

from fasthttpc.security import tls_adapter as ta
from fasthttpc.security.tls_adapter import (
    TLSProtocolError, HandshakeOrderValidator, parse_server_hello, TLSAdapter,
)
from tls_fakes import (
    FakeSocket, FakeTLSServer, server_hello, plain_records, ext, hs, seal, split_records, unseal,
)

SID = bytes(range(32))
PUB = b"\x09" * 32


# ---- parse_server_hello ----------------------------------------------------

def test_gecerli_server_hello():
    sh = parse_server_hello(server_hello(SID, PUB, 0x1302), SID)
    assert sh["cipher_suite"] == 0x1302
    assert sh["selected_group"] == 0x001D and sh["server_pub"] == PUB
    assert sh["selected_version"] == 0x0304 and not sh["is_hrr"]
    assert sh["session_id"] == SID


def test_hs_type_2_degilse_reddedilir():
    msg = bytearray(server_hello(SID, PUB))
    msg[0] = 1
    with pytest.raises(TLSProtocolError, match="unexpected_message"):
        parse_server_hello(bytes(msg))


def test_session_id_echo_uyusmazsa_reddedilir():
    with pytest.raises(TLSProtocolError, match="session_id"):
        parse_server_hello(server_hello(b"\x01" * 32, PUB), SID)


def test_tekrarlanan_extension_reddedilir():
    with pytest.raises(TLSProtocolError, match="tekrarlandı"):
        parse_server_hello(server_hello(SID, PUB, extra_exts=ext(43, b"\x03\x04")), SID)


def test_tls13_degilse_reddedilir():
    body = (b"\x03\x03" + os.urandom(32) + b"\x20" + SID + b"\x13\x01\x00"
            + struct.pack("!H", 0))
    with pytest.raises(TLSProtocolError, match="TLS 1.3"):
        parse_server_hello(hs(2, body), SID)


def test_uzunluk_tutarsizligi_ve_kesik_extension():
    msg = server_hello(SID, PUB)
    with pytest.raises(TLSProtocolError, match="decode_error"):
        parse_server_hello(msg + b"\x00")
    with pytest.raises(TLSProtocolError, match="decode_error"):
        parse_server_hello(hs(2, msg[4:-3]))


def test_sifir_olmayan_compression_reddedilir():
    msg = bytearray(server_hello(SID, PUB))
    msg[4 + 2 + 32 + 1 + 32 + 2] = 1
    with pytest.raises(TLSProtocolError, match="compression"):
        parse_server_hello(bytes(msg))


def test_hrr_ayristirilir():
    exts = ext(43, b"\x03\x04") + ext(51, b"\x00\x17") + ext(44, b"\x00\x03abc")
    body = (b"\x03\x03" + ta._HELLO_RETRY_REQUEST_RANDOM + b"\x20" + SID + b"\x13\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    sh = parse_server_hello(hs(2, body), SID)
    assert sh["is_hrr"] and sh["selected_group"] == 0x0017
    assert sh["server_pub"] is None and sh["cookie"] == b"abc"


def test_client_hello_session_id_cikarilir():
    from fasthttpc.tls_crafter import TLSImpersonator
    rec, _, _ = TLSImpersonator("example.com").build_client_hello()
    sid = ta._client_hello_session_id(rec)
    assert sid is not None and len(sid) == 32 and sid in rec


def test_birden_fazla_recorda_bolunmus_server_hello():
    msg = server_hello(SID, PUB)
    sock = FakeSocket(plain_records(msg, [3, 1, 40, 10]))
    assert ta._read_server_hello(sock) == msg


def test_server_hello_sonrasi_duz_veri_reddedilir():
    msg = server_hello(SID, PUB)
    sock = FakeSocket(plain_records(msg + hs(8, b"\x00\x00")))
    with pytest.raises(TLSProtocolError, match="unexpected_message"):
        ta._read_server_hello(sock)


def test_server_hello_yerine_application_data():
    sock = FakeSocket(struct.pack("!BHH", 23, 0x0303, 3) + b"abc")
    with pytest.raises(TLSProtocolError, match="unexpected_message"):
        ta._read_server_hello(sock)


# ---- HandshakeOrderValidator -------------------------------------------------

def test_dogru_sira_ve_compressed_cert():
    for cert in (11, 25):
        v = HandshakeOrderValidator()
        for t in (2, 8, cert, 15, 20):
            assert not v.done
            v.expect(t)
        assert v.done
        v.expect(4)
        v.expect(24)


@pytest.mark.parametrize("seq", [
    (8,), (2, 11), (2, 8, 15), (2, 8, 11, 20), (2, 8, 8), (2, 8, 11, 11),
    (2, 8, 11, 15, 15), (2, 4), (2, 8, 11, 15, 4), (2, 8, 11, 13), (2, 8, 13, 13), (2, 8, 13, 15), (2, 2), (2, 8, 11, 15, 20, 20),
])
def test_sira_disi_veya_tekrar_mesaj_reddedilir(seq):
    v = HandshakeOrderValidator()
    for t in seq[:-1]:
        v.expect(t)
    with pytest.raises(TLSProtocolError, match="unexpected_message"):
        v.expect(seq[-1])


def test_tek_hrr_izinli():
    v = HandshakeOrderValidator()
    v.expect(2, is_hrr=True)
    with pytest.raises(TLSProtocolError, match="unexpected_message"):
        v.expect(2, is_hrr=True)
    v.expect(2)
    with pytest.raises(TLSProtocolError, match="unexpected_message"):
        v.expect(2, is_hrr=True)


# ---- Uçtan uca negotiate (sahte sunucu) ---------------------------------------

@pytest.fixture
def no_pki(monkeypatch):
    monkeypatch.setattr(ta, "validate_server_certificate", lambda payload, host, **kw: "LEAF")
    monkeypatch.setattr(ta, "verify_certificate_verify", lambda payload, leaf, th, **kw: 0x0804)


def _negotiate(server, chunk=16384):
    sock = FakeSocket(on_send=server, chunk=chunk)
    return TLSAdapter.negotiate(sock, "example.com", None), sock


@pytest.mark.parametrize("suite", [0x1301, 0x1302, 0x1303])
def test_negotiate_basarili_ve_keyupdate(no_pki, suite):
    srv = FakeTLSServer(cipher_suite=suite, sh_split=[5, 20])
    es, sock = _negotiate(srv, chunk=7)
    st = es.state
    assert st["using_app_keys"] and st["hash_func"] is ta.suite_params(suite)[2]
    ck, civ, sk, siv, c_ats, s_ats = srv.app_keys()
    assert st["client_ats"] == c_ats and st["server_ats"] == s_ats

    # Sunucu: NST + KeyUpdate(update_requested) + yeni anahtarla veri
    name, kl, h = ta.suite_params(suite)
    nst = hs(4, b"\x00" * 12)
    data = seal(sk, siv, 0, nst, 22, name) + seal(sk, siv, 1, ta.build_key_update(True), 22, name)
    nsk, nsiv = ta.traffic_key_iv(ta.next_traffic_secret(s_ats, h), kl, h)
    data += seal(nsk, nsiv, 0, b"HTTP/1.1 200 OK\r\n\r\n", 23, name)
    sock.feed(data)
    assert es.recv_record(skip_post_handshake=True) == (b"HTTP/1.1 200 OK\r\n\r\n", 23)

    recs = split_records(sock.sends[-1])
    assert unseal(ck, civ, 0, recs[0], name) == (ta.build_key_update(False), 22)


def test_negotiate_session_id_uyusmazligi(no_pki):
    with pytest.raises(TLSProtocolError, match="session_id"):
        _negotiate(FakeTLSServer(session_id_override=b"\x00" * 32))


def test_negotiate_tekrar_extension(no_pki):
    with pytest.raises(TLSProtocolError, match="tekrarlandı"):
        _negotiate(FakeTLSServer(sh_extra_exts=ext(51, b"\x00\x1d\x00\x01\x00")))


@pytest.mark.parametrize("flight,needle", [
    ([("hs", 11), ("hs", 15), ("hs", 20)], "Certificate"),                 # EE yok
    ([("hs", 8), ("hs", 15), ("hs", 20)], "CertificateVerify"),            # Cert yok
    ([("hs", 8), ("hs", 11), ("hs", 20)], "Finished"),                     # CV yok
    ([("hs", 8), ("hs", 8), ("hs", 11), ("hs", 15), ("hs", 20)], "EncryptedExtensions"),
    ([("hs", 8), ("hs", 11), ("hs", 11), ("hs", 15), ("hs", 20)], "Certificate"),
    ([("hs", 8), ("hs", 11), ("hs", 4), ("hs", 15), ("hs", 20)], "NewSessionTicket"),
    ([("hs", 8), ("hs", 11), ("hs", 15), ("hs", 4), ("hs", 20)], "NewSessionTicket"),
    ([("hs", 8), ("raw", 23, b"GET"), ("hs", 11), ("hs", 15), ("hs", 20)], "content_type=23"),
    ([("hs", 8), ("hs", 11), ("hs", 13), ("hs", 15), ("hs", 20)], "CertificateRequest"),
    ([("hs", 8), ("hs", 11), ("hs", 15), ("record", [("hs", 20), ("hs", 4)])], "Finished sonrasında"),
])
def test_negotiate_sira_disi_mesajlar(no_pki, flight, needle):
    with pytest.raises(TLSProtocolError, match="unexpected_message") as ei:
        _negotiate(FakeTLSServer(flight=flight))
    assert needle in str(ei.value)


def test_negotiate_tek_recordda_birden_fazla_mesaj(no_pki):
    flight = [("record", [("hs", 8), ("hs", 11)]), ("record", [("hs", 15), ("hs", 20)])]
    es, _ = _negotiate(FakeTLSServer(flight=flight))
    assert es.state["using_app_keys"]


def test_psk_modunda_sertifikasiz_sira():
    v = HandshakeOrderValidator()
    v.expect(2)
    v.psk_accepted = True
    v.expect(8)
    v.expect(20)
    assert v.done
    v2 = HandshakeOrderValidator(psk_accepted=True)
    v2.expect(2)
    v2.expect(8)
    with pytest.raises(TLSProtocolError, match="unexpected_message"):
        v2.expect(11)


def test_server_hello_oncesi_tek_ccs_yok_sayilir():
    msg = server_hello(SID, PUB)
    ccs = struct.pack("!BHH", 20, 0x0303, 1) + b"\x01"
    assert ta._read_server_hello(FakeSocket(ccs + plain_records(msg))) == msg
    with pytest.raises(TLSProtocolError, match="unexpected_message"):
        ta._read_server_hello(FakeSocket(ccs + ccs + plain_records(msg)))
    with pytest.raises(TLSProtocolError, match="unexpected_message"):
        ta._read_server_hello(FakeSocket(ccs + plain_records(msg)), allow_ccs=False)


def _ccs_yerlestir(server, at):
    """FakeTLSServer çıktısındaki uyumluluk CCS'ini kaldırıp ``at``ıncı record'dan önce koyar."""
    def responder(data):
        out = server(data)
        recs, i = [], 0
        while i < len(out):
            n = struct.unpack("!H", out[i + 3:i + 5])[0]
            recs.append(out[i:i + 5 + n])
            i += 5 + n
        if not recs or recs[0][0] != 22:      # ServerHello uçuşu değil (ör. NST): dokunma
            return out
        recs = [r for r in recs if r[0] != 20]
        recs.insert(at, CCS_REC)
        return b"".join(recs)
    return responder


CCS_REC = struct.pack("!BHH", 20, 0x0303, 1) + b"\x01"


def test_senkron_ikinci_ccs_reddedilir(no_pki):
    srv = FakeTLSServer()
    orig = srv._on_client_hello

    def iki_ccs(ch):
        out = orig(ch)
        sh_len = struct.unpack("!H", out[3:5])[0]
        j = 5 + sh_len + len(CCS_REC)              # ServerHello + uyumluluk CCS'i
        return out[:j] + CCS_REC + out[j:]
    srv._on_client_hello = iki_ccs
    with pytest.raises(TLSProtocolError, match="unexpected_message: ikinci change_cipher_spec"):
        _negotiate(srv)


def test_senkron_ccs_handshake_parcalari_arasinda_reddedilir(no_pki):
    msg = hs(11, b"\x00" * 40)
    flight = [("hs", 8), ("raw", 22, msg[:10]), ("raw", 22, msg[10:]), ("hs", 15), ("hs", 20)]
    srv = FakeTLSServer(flight=flight)
    # Kayıtlar: ServerHello, EE, Cert[:10], Cert[10:] ... -> CCS'i Cert parçaları arasına koy.
    with pytest.raises(TLSProtocolError, match="unexpected_message: change_cipher_spec, bölünmüş"):
        _negotiate(_ccs_yerlestir(srv, 3))


def test_senkron_el_sikisma_sonrasi_ccs_reddedilir(no_pki):
    srv = FakeTLSServer(after_finished=CCS_REC)
    es, _ = _negotiate(srv)
    with pytest.raises(TLSProtocolError, match="unexpected_message: el sıkışma bittikten sonra"):
        es.recv_record()


def test_senkron_ikinci_server_hello_tipi_ve_boyutu():
    """HRR sonrası 2. ServerHello: tip uzunluktan önce, uzunluk gövdeden önce denetlenir."""
    with pytest.raises(TLSProtocolError, match=r"unexpected_message: 2. ServerHello \(2\) beklenirken"):
        ta._recv_handshake_message(FakeSocket(plain_records(b"\x08\xff\xff\xff")), "2. ServerHello",
                                   expect_type=2)
    with pytest.raises(TLSProtocolError, match="decode_error: 2. ServerHello makul boyutu"):
        ta._recv_handshake_message(FakeSocket(plain_records(b"\x02\xff\xff\xff")), "2. ServerHello",
                                   expect_type=2)
    # HRR'den önce görülmüş CCS ile birlikte ikinci CCS reddedilir (el sıkışma boyunca tek CCS).
    st = {"ccs_seen": True}
    with pytest.raises(TLSProtocolError, match="ikinci change_cipher_spec"):
        ta._recv_handshake_message(FakeSocket(CCS_REC + plain_records(server_hello(SID, PUB))),
                                   "2. ServerHello", st, expect_type=2)


def test_downgrd_isareti_mesajda():
    rnd = os.urandom(24) + b"DOWNGRD\x01"
    body = b"\x03\x03" + rnd + b"\x20" + SID + b"\xc0\x2f\x00" + struct.pack("!H", 0)
    with pytest.raises(TLSProtocolError, match="downgrade saldırısı"):
        parse_server_hello(hs(2, body), SID)


def test_pre_shared_key_selected_identity():
    sh = parse_server_hello(server_hello(SID, PUB, extra_exts=ext(41, b"\x00\x00")), SID)
    assert sh["selected_identity"] == 0
    assert parse_server_hello(server_hello(SID, PUB), SID)["selected_identity"] is None
    with pytest.raises(TLSProtocolError, match="pre_shared_key"):
        parse_server_hello(server_hello(SID, PUB, extra_exts=ext(41, b"\x00")), SID)


def test_tls12_server_hello_gives_version_error_not_session_id_error():
    """Canlı testte bulundu (nginx.org): TLS 1.2 ServerHello'su session_id'mizi
    geri göndermez; kullanıcı 'session_id eşleşmiyor' yerine sürüm hatası görmeli."""
    import os as _os
    import pytest as _pytest
    from fasthttpc.security.tls_adapter import parse_server_hello, TLSProtocolError
    sid_sent = _os.urandom(32)
    body = (b"\x03\x03" + _os.urandom(32) + b"\x20" + _os.urandom(32)
            + b"\xc0\x2f" + b"\x00" + b"\x00\x00")
    msg = b"\x02" + len(body).to_bytes(3, "big") + body
    with _pytest.raises(TLSProtocolError, match="protocol_version"):
        parse_server_hello(msg, sid_sent)
