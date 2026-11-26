"""Güvenli TLS 1.2 alt kümesi testleri (ağsız: yalnızca loopback).

* RFC 5246 PRF test vektörleri (SHA-256 / SHA-384)
* Python ``ssl`` ile TLS 1.2-ONLY gerçek sunucu: her izinli suite, ECDSA ve RSA, h2 ALPN
* Sahte sunucu: EMS/renegotiation_info yokluğu, DOWNGRD, bozuk SKE imzası/Finished,
  CBC/statik RSA suite'i, sıra dışı mesaj, CertificateRequest, SHA-1 imza, vb. REDDEDİLMELİ
* Senkron (TLSAdapter.negotiate) ve async (AsyncTLSStream) yollar
"""
import asyncio
import hashlib
import socket
import ssl
import struct

import pytest

from fasthttpc.security import tls12
from fasthttpc.security.tls_adapter import TLSAdapter, TLSProtocolError
from fasthttpc.tls13 import AsyncTLSStream, TLSError

from tls12_servers import (
    HOST, Fake12Server, PKI12, StdlibTLS12, h2_handler, http1_handler, serve_fake_in_thread,
)


@pytest.fixture(scope="module")
def pki():
    return PKI12()


@pytest.fixture(scope="module")
def files(pki, tmp_path_factory):
    return pki.write(tmp_path_factory.mktemp("tls12"))


# ----------------------------------------------------------------- PRF vektörleri
def test_prf_sha256_vektoru():
    """TLS WG (RFC 5246 PRF) yaygın test vektörü: SHA-256, 100 bayt."""
    secret = bytes.fromhex("9bbe436ba940f017b17652849a71db35")
    seed = bytes.fromhex("a0ba9f936cda311827a6f796ffd5198c")
    out = tls12.prf(hashlib.sha256, secret, b"test label", seed, 100)
    assert out.hex() == (
        "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a"
        "6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab"
        "4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701"
        "87347b66")


def test_prf_sha384_vektoru():
    secret = bytes.fromhex("b80b733d6ceefcdc71566ea48e5567df")
    seed = bytes.fromhex("cd665cf6a8447dd6ff8b27555edb7465")
    out = tls12.prf(hashlib.sha384, secret, b"test label", seed, 148)
    assert out.hex().startswith("7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cd")
    assert out.hex().endswith("a3be85e0990703d73e56f")
    # kısa çıktı uzun çıktının öneki olmalı (P_hash akış özelliği)
    assert tls12.prf(hashlib.sha384, secret, b"test label", seed, 20) == out[:20]


def test_ems_ve_key_block_boyutlari():
    suite = tls12.SUITES[0xCCA8]
    ck, sk, civ, siv = tls12.derive_key_block(suite, b"m" * 48, b"s" * 32, b"c" * 32)
    assert (len(ck), len(sk), len(civ), len(siv)) == (32, 32, 12, 12)
    suite = tls12.SUITES[0xC02B]
    ck, sk, civ, siv = tls12.derive_key_block(suite, b"m" * 48, b"s" * 32, b"c" * 32)
    assert (len(ck), len(sk), len(civ), len(siv)) == (16, 16, 4, 4)
    # EMS, session_hash'e bağlıdır: farklı hash -> farklı master
    a = tls12.extended_master_secret(hashlib.sha256, b"p" * 32, b"\x01" * 32)
    b = tls12.extended_master_secret(hashlib.sha256, b"p" * 32, b"\x02" * 32)
    assert len(a) == 48 and a != b


# ------------------------------------------------------- record katmanı (birim)
@pytest.mark.parametrize("suite_id", sorted(tls12.SUITES))
def test_record_cipher_roundtrip_ve_nonce(suite_id):
    suite = tls12.SUITES[suite_id]
    key, iv = b"\x11" * suite.key_len, b"\x22" * suite.fixed_iv_len
    w, r = tls12.RecordCipher(suite, key, iv), tls12.RecordCipher(suite, key, iv)
    for i in range(3):
        body = w.seal(23, b"veri%d" % i)
        if suite.cipher == "AES":
            assert body[:8] == struct.pack("!Q", i)       # açık explicit nonce = seq
        assert r.open(23, b"\x03\x03", body) == b"veri%d" % i
    # AAD seq'e bağlı: tekrar oynatma (replay) reddedilir
    body = w.seal(23, b"x")
    r.open(23, b"\x03\x03", body)
    r2 = tls12.RecordCipher(suite, key, iv)
    r2.seq = 99
    with pytest.raises(tls12.TLS12Error, match="bad_record_mac"):
        r2.open(23, b"\x03\x03", body)
    # içerik tipi AAD'de: farklı tip reddedilir
    r3 = tls12.RecordCipher(suite, key, iv)
    r3.seq = w.seq - 1
    with pytest.raises(tls12.TLS12Error, match="bad_record_mac"):
        r3.open(22, b"\x03\x03", body)


def test_record_cipher_chacha_nonce_xor():
    """RFC 7905: nonce = iv XOR (0^4 || seq)."""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    suite = tls12.SUITES[0xCCA9]
    key, iv = bytes(range(32)), bytes(range(100, 112))
    w = tls12.RecordCipher(suite, key, iv)
    w.seq = 5
    body = w.seal(23, b"abc")
    nonce = bytes(a ^ b for a, b in zip(iv, b"\x00" * 4 + struct.pack("!Q", 5)))
    aad = struct.pack("!Q", 5) + struct.pack("!BHH", 23, 0x0303, 3)
    assert ChaCha20Poly1305(key).decrypt(nonce, body, aad) == b"abc"


def test_record_cipher_gcm_nonce_ve_aad():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    suite = tls12.SUITES[0xC02F]
    key, iv = b"\x01" * 16, b"\xaa\xbb\xcc\xdd"
    w = tls12.RecordCipher(suite, key, iv)
    w.seq = 7
    body = w.seal(22, b"hs-data")
    aad = struct.pack("!Q", 7) + struct.pack("!BHH", 22, 0x0303, 7)
    assert AESGCM(key).decrypt(iv + struct.pack("!Q", 7), body[8:], aad) == b"hs-data"


@pytest.mark.parametrize("suite_id", [0xC02F, 0xCCA8])
def test_sequence_number_tasmasi_reddedilir(suite_id):
    suite = tls12.SUITES[suite_id]
    c = tls12.RecordCipher(suite, b"\x00" * suite.key_len, b"\x00" * suite.fixed_iv_len)
    c.seq = tls12.SEQ_LIMIT - 1
    c.seal(23, b"son")                      # 2^64-2 hâlâ geçerli
    assert c.seq == tls12.SEQ_LIMIT
    with pytest.raises(tls12.TLS12Error, match="Sequence number"):
        c.seal(23, b"fazla")
    with pytest.raises(tls12.TLS12Error, match="Sequence number"):
        c.open(23, b"\x03\x03", b"\x00" * 40)


# ----------------------------------------------------- sıra doğrulayıcı (birim)
def test_handshake_order_normal_akis():
    o = tls12.HandshakeOrder12(ticket_ok=True, status_ok=True)
    for t in (2, 11, 22, 12, 14, 4):
        o.expect(t)
    o.on_ccs()
    o.expect(20)
    assert o.done


@pytest.mark.parametrize("seq,match", [
    ([11], "WAIT_SH"),
    ([2, 12], "WAIT_CERT"),
    ([2, 11, 14], "AFTER_CERT"),
    ([2, 11, 12, 12], "WAIT_SHD"),
    ([2, 11, 22], "AFTER_CERT"),                  # status_request kabul edilmemişti
    ([2, 11, 12, 14, 4], "NewSessionTicket"),     # session_ticket kabul edilmemişti
    ([2, 11, 12, 14, 20], "ChangeCipherSpec olmadan"),
    ([2, 11, 13], "CertificateRequest"),          # SKE'den önce
    ([2, 11, 12, 13, 13], "CertificateRequest"),  # tekrar
    ([2, 11, 12, 13, 14, 13], "CertificateRequest"),
    ([2, 2], "WAIT_CERT"),
])
def test_handshake_order_sira_disi_reddedilir(seq, match):
    o = tls12.HandshakeOrder12()
    with pytest.raises(tls12.TLS12Error, match=match):
        for t in seq:
            o.expect(t)


def test_handshake_order_ccs_ve_tekrar_ticket():
    o = tls12.HandshakeOrder12(ticket_ok=True)
    with pytest.raises(tls12.TLS12Error, match="ChangeCipherSpec"):
        o.on_ccs()
    for t in (2, 11, 12, 14, 4):
        o.expect(t)
    with pytest.raises(tls12.TLS12Error, match="NewSessionTicket"):
        o.expect(4)                                 # ikinci bilet
    o.on_ccs()
    with pytest.raises(tls12.TLS12Error, match="ChangeCipherSpec"):
        o.on_ccs()                                  # ikinci CCS


def test_certificate_zinciri_katı_ayrıştırma():
    der = b"\x30\x03abc"
    ok = tls12.to_tls13_certificate_message([der, der])
    assert ok[0] == 11 and ok[4] == 0                # boş request_context
    msg = b"\x0b" + (3 + 3 + len(der)).to_bytes(3, "big") + (3 + len(der)).to_bytes(3, "big") \
        + len(der).to_bytes(3, "big") + der
    assert tls12.parse_certificate_chain(msg) == [der]
    bad = bytearray(msg)
    bad[4:7] = (3 + len(der) + 1).to_bytes(3, "big")     # liste uzunluğu uyuşmuyor
    with pytest.raises(tls12.TLS12Error, match="decode_error"):
        tls12.parse_certificate_chain(bytes(bad))
    with pytest.raises(tls12.TLS12Error, match="hiç sertifika"):
        tls12.parse_certificate_chain(b"\x0b\x00\x00\x03\x00\x00\x00")


def test_is_tls12_server_hello_ayirimi():
    def sh(version=b"\x03\x03", exts=b"", suite=0xC02F, rnd=b"r" * 32):
        body = version + rnd + b"\x00" + struct.pack("!HB", suite, 0)
        if exts is not None:
            body += struct.pack("!H", len(exts)) + exts
        return b"\x02" + len(body).to_bytes(3, "big") + body
    assert tls12.is_tls12_server_hello(sh())
    assert tls12.is_tls12_server_hello(sh(exts=b""))
    assert not tls12.is_tls12_server_hello(sh(version=b"\x03\x01"))
    assert not tls12.is_tls12_server_hello(sh(exts=b"\x00\x2b\x00\x02\x03\x04"))
    hrr = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
    assert not tls12.is_tls12_server_hello(sh(rnd=hrr))
    assert not tls12.is_tls12_server_hello(b"\x02\x00\x00\x02\x03\x03")     # bozuk


# ------------------------------------------------------ yardımcılar (sync/async)
def _connect(port, ca, profile="chrome_131", host=HOST):
    s = socket.create_connection(("127.0.0.1", port), timeout=8)
    try:
        return TLSAdapter.negotiate(s, host, profile, ca_path=ca)
    except BaseException:
        s.close()
        raise


def _get(esock, path=b"/"):
    esock.send_record(b"GET " + path + b" HTTP/1.1\r\nHost: localhost\r\n\r\n")
    data = b""
    while b"merhaba" not in data:
        msg, mt = esock.recv_record(skip_post_handshake=True)
        assert mt == 23
        data += msg
    return data


SUITE_MATRIX = [
    # (OpenSSL adı, sertifika anahtarı, suite id)
    ("ECDHE-ECDSA-AES128-GCM-SHA256", "ec", 0xC02B),
    ("ECDHE-RSA-AES128-GCM-SHA256", "rsa", 0xC02F),
    ("ECDHE-ECDSA-AES256-GCM-SHA384", "ec", 0xC02C),
    ("ECDHE-RSA-AES256-GCM-SHA384", "rsa", 0xC030),
    ("ECDHE-ECDSA-CHACHA20-POLY1305", "ec", 0xCCA9),
    ("ECDHE-RSA-CHACHA20-POLY1305", "rsa", 0xCCA8),
]


def _cert_for(files, kind):
    ca, ec, rsa_, _ec384 = files
    return ca, (ec if kind == "ec" else rsa_)


# ----------------------------------------- gerçek (ssl) TLS 1.2-only sunucu: sync
@pytest.mark.parametrize("cipher,kind,sid", SUITE_MATRIX)
def test_stdlib_sunucu_her_suite_sync(files, cipher, kind, sid):
    ca, cert = _cert_for(files, kind)
    srv = StdlibTLS12(cert, cipher, alpn=["http/1.1"])
    try:
        es = _connect(srv.port, ca)
        st = es.state
        assert st["is_tls13"] is False and st["is_tls12"] and st["cipher_suite"] == sid
        assert st["alpn"] == "http/1.1" and st["peer_certificate"] is not None
        assert es.raw_socket is not None
        assert b"merhaba tls12" in _get(es)
        es.close()
    finally:
        srv.close()
    assert srv.negotiated[0][0] == "TLSv1.2" and srv.negotiated[0][1] == cipher
    assert not srv.errors, srv.errors


@pytest.mark.parametrize("curve", ["X25519", "prime256v1", "secp384r1"])
def test_stdlib_sunucu_ecdhe_gruplari(files, curve):
    ca, cert = _cert_for(files, "ec")
    # X25519: set_ecdh_curve eski Python'larda yalnızca NIST eğri adlarını kabul eder;
    # OpenSSL 3 varsayılan olarak zaten x25519'u tercih eder.
    srv = StdlibTLS12(cert, "ECDHE-ECDSA-AES128-GCM-SHA256", curve=None if curve == "X25519" else curve)
    try:
        es = _connect(srv.port, ca)
        assert b"merhaba" in _get(es)
        es.close()
    finally:
        srv.close()


@pytest.mark.parametrize("profile", ["chrome_131", "firefox_133", "safari_18"])
def test_stdlib_sunucu_profiller(files, profile):
    ca, cert = _cert_for(files, "rsa")
    srv = StdlibTLS12(cert, "ECDHE-RSA-AES256-GCM-SHA384")
    try:
        es = _connect(srv.port, ca, profile)
        assert b"merhaba" in _get(es)
        es.close()
    finally:
        srv.close()


def test_stdlib_sunucu_buyuk_veri_ve_bolunmus_record(files):
    ca, cert = _cert_for(files, "ec")
    big = b"x" * 100_000

    def handler(conn):
        conn.recv(65536)
        conn.sendall(big)
        conn.unwrap()

    srv = StdlibTLS12(cert, "ECDHE-ECDSA-CHACHA20-POLY1305", handler=handler)
    try:
        es = _connect(srv.port, ca)
        es.send_record(b"y" * 50_000)            # 2^14'ten büyük: bölünerek gider
        got = b""
        while len(got) < len(big):
            msg, mt = es.recv_record(skip_post_handshake=True)
            assert mt == 23
            got += msg
        assert got == big
        es.close()
    finally:
        srv.close()


def test_stdlib_sunucu_close_notify(files):
    ca, cert = _cert_for(files, "ec")
    srv = StdlibTLS12(cert, "ECDHE-ECDSA-AES128-GCM-SHA256", handler=http1_handler(b"merhaba"))
    try:
        es = _connect(srv.port, ca)
        assert b"merhaba" in _get(es)
        msg, mt = es.recv_record(skip_post_handshake=True)       # sunucu unwrap -> close_notify
        assert (msg, mt) == (b"\x01\x00", 21)
        es.close()
    finally:
        srv.close()


def test_stdlib_sunucu_guvenilmeyen_ca_reddedilir(files, tmp_path):
    ca, cert = _cert_for(files, "ec")
    other = PKI12()
    other_ca = tmp_path / "other.pem"
    other_ca.write_bytes(other.ca_pem())
    srv = StdlibTLS12(cert, "ECDHE-ECDSA-AES128-GCM-SHA256")
    try:
        with pytest.raises(ConnectionError, match="sertifika doğrulaması"):
            _connect(srv.port, str(other_ca))
    finally:
        srv.close()


def test_stdlib_sunucu_yanlis_hostname_reddedilir(files):
    ca, cert = _cert_for(files, "ec")
    srv = StdlibTLS12(cert, "ECDHE-ECDSA-AES128-GCM-SHA256")
    try:
        with pytest.raises(ConnectionError, match="sertifika doğrulaması"):
            _connect(srv.port, ca, host="baska.example")
    finally:
        srv.close()


def test_stdlib_sunucu_cbc_only_reddedilir(files):
    """Sunucu yalnızca CBC biliyorsa: ya sunucu uyarısı ya istemci reddi — asla CBC ile bağlanma."""
    ca, cert = _cert_for(files, "rsa")
    ctx_ciphers = "ECDHE-RSA-AES128-SHA"
    try:
        srv = StdlibTLS12(cert, ctx_ciphers)
    except ssl.SSLError:
        pytest.skip("OpenSSL CBC suite'lerini devre dışı bırakmış")   # ortam kısıtı, istemci davranışı değil
    try:
        with pytest.raises(ConnectionError, match="CBC|insufficient_security|handshake_failure"):
            _connect(srv.port, ca)
    finally:
        srv.close()


# --------------------------------------------------------- tam yığın (Session)
def test_session_http11_tls12(files):
    from fasthttpc import Session
    ca, cert = _cert_for(files, "rsa")
    srv = StdlibTLS12(cert, "ECDHE-RSA-AES128-GCM-SHA256", alpn=["http/1.1"])
    try:
        with Session(impersonate="chrome_131", verify=ca) as s:
            r = s.get(f"https://localhost:{srv.port}/")
        assert r.status_code == 200 and r.content == b"merhaba tls12"
    finally:
        srv.close()


def test_session_h2_tls12(files):
    from fasthttpc import Session
    ca, cert = _cert_for(files, "ec")
    srv = StdlibTLS12(cert, "ECDHE-ECDSA-AES256-GCM-SHA384", alpn=["h2", "http/1.1"],
                      handler=h2_handler(b"h2 uzerinden tls12"))
    try:
        with Session(impersonate="chrome_131", verify=ca) as s:
            r = s.get(f"https://localhost:{srv.port}/")
        assert r.status_code == 200 and r.content == b"h2 uzerinden tls12"
        assert srv.negotiated[0][2] == "h2" and srv.negotiated[0][0] == "TLSv1.2"
    finally:
        srv.close()


# ------------------------------------------------------ sahte sunucu: kabul yolları
def _run_fake(pki, files, profile="chrome_131", **kw):
    srv = Fake12Server(pki, **kw)
    port, t, ls = serve_fake_in_thread(srv)
    try:
        es = _connect(port, files[0], profile)
    except BaseException:
        ls.close()
        raise
    return srv, es, t


@pytest.mark.parametrize("suite", sorted(tls12.SUITES))
def test_fake_her_suite_ve_dogrulanmis_client_finished(pki, files, suite):
    srv, es, t = _run_fake(pki, files, suite=suite)
    assert es.state["cipher_suite"] == suite
    es.send_record(b"ping")
    assert es.recv_record(skip_post_handshake=True) == (b"echo:ping", 23)
    es.close()
    t.join(3)
    assert srv.finished_ok and srv.error is None, srv.error     # sunucu, istemci Finished'ını doğruladı
    assert srv.alerts[-1] == b"\x01\x00"


@pytest.mark.parametrize("sigalg,key,profile", [
    (0x0403, "ec", "chrome_131"), (0x0503, "ec", "chrome_131"), (0x0603, "ec", "firefox_133"),
    (0x0804, "rsa", "chrome_131"), (0x0805, "rsa", "chrome_131"), (0x0806, "rsa", "chrome_131"),
    (0x0401, "rsa", "chrome_131"), (0x0501, "rsa", "chrome_131"), (0x0601, "rsa", "chrome_131"),
])
def test_fake_imza_algoritmalari(pki, files, sigalg, key, profile):
    suite = 0xC02B if key == "ec" else 0xC02F
    srv, es, t = _run_fake(pki, files, profile, suite=suite, sigalg=sigalg)
    es.send_record(b"x")
    assert es.recv_record()[0] == b"echo:x"
    assert es.conn.signature_scheme == sigalg
    es.close()
    t.join(3)


@pytest.mark.parametrize("group", [0x001D, 0x0017, 0x0018])
def test_fake_ecdhe_gruplari(pki, files, group):
    srv, es, t = _run_fake(pki, files, group=group)
    es.send_record(b"x")
    assert es.recv_record()[0] == b"echo:x"
    es.close()
    t.join(3)
    assert srv.finished_ok


def test_fake_ec384_sertifikasi_ve_p256_hash(pki, files):
    srv, es, t = _run_fake(pki, files, suite=0xC02C, tamper={"ec384"}, sigalg=0x0503)
    es.close()
    t.join(3)
    assert srv.finished_ok


def test_fake_servertlshello_ile_sertifika_ayni_recordda(pki, files):
    srv, es, t = _run_fake(pki, files, split_flight=True)
    es.send_record(b"a")
    assert es.recv_record()[0] == b"echo:a"
    es.close()
    t.join(3)
    assert srv.finished_ok


def test_fake_alpn_h2_ve_ticket_ve_status(pki, files):
    srv, es, t = _run_fake(pki, files, alpn="h2", tamper={"status"})
    assert es.state["alpn"] == "h2"
    es.close()
    t.join(3)


def test_fake_ticket_yok(pki, files):
    srv, es, t = _run_fake(pki, files, ticket=False)
    es.send_record(b"z")
    assert es.recv_record()[0] == b"echo:z"
    es.close()
    t.join(3)


def test_fake_hello_request_no_renegotiation_uyarisi(pki, files):
    srv, es, t = _run_fake(pki, files, tamper={"hello_request"})
    es.send_record(b"hala calisiyor")
    assert es.recv_record(skip_post_handshake=True) == (b"echo:hala calisiyor", 23)
    es.close()
    t.join(3)
    assert srv.alerts[0] == b"\x01\x64"          # warning no_renegotiation (100)
    assert srv.alerts[-1] == b"\x01\x00"


def test_fake_hello_request_seli_kapatir(pki, files):
    """Renegotiation seli bağlantıyı no_renegotiation ile kapatmalı.

    Sel, sunucunun Finished'ı ile AYNI TCP okumasında gelebilir (macOS'ta CI'da
    görüldü): istemci o zaman reddi daha negotiate() içinde verir. İki zamanlama da
    doğru davranıştır; test ikisini de kabul eder ama sonucu (red + alert'ler) aynı
    sıkılıkla doğrular.
    """
    srv = Fake12Server(pki, tamper={"hello_request_flood"})
    port, t, ls = serve_fake_in_thread(srv)
    es = None
    try:
        with pytest.raises(ConnectionError, match="no_renegotiation|renegotiation"):
            es = _connect(port, files[0], "chrome_131")
            # Uygulama verisi GÖNDERİLMEZ: sunucunun yanıtı (echo) istemci kapandıktan
            # sonra gelirse RST oluşur ve sunucu alert'leri okuyamadan kaybedebilir.
            for _ in range(tls12.MAX_HELLO_REQUESTS + 2):
                es.recv_record(skip_post_handshake=True)
    finally:
        if es is not None:
            es.close()
        else:
            ls.close()
    t.join(5)
    assert srv.alerts.count(b"\x01\x64") == 3 and srv.alerts[-1] == bytes([2, tls12.AL_NO_RENEGOTIATION])


# ----------------------------------------------- sahte sunucu: REDDEDİLMELİ
# (tamper, beklenen mesaj regex'i, sunucu kwargs, istemci akışı gönderilmeden (CKE'den önce) mi reddedilmeli)
REJECT = [
    ("no_ems", "Extended Master Secret", {}, True),
    ("no_reneg", "renegotiation_info", {}, True),
    ("bad_reneg", "renegotiation_info", {}, True),
    ("downgrd", "DOWNGRD", {}, True),
    ("downgrd0", "DOWNGRD", {}, True),
    ("bad_ske_sig", "ServerKeyExchange imzası GEÇERSİZ", {}, True),
    ("cbc_suite", "CBC", {}, True),
    ("static_rsa", "statik RSA", {}, True),
    ("tls13_suite", "TLS 1.3 cipher suite", {}, True),
    ("out_of_order", "unexpected_message", {}, True),
    ("skip_cert", "unexpected_message", {}, True),
    ("dup_cert", "unexpected_message", {}, True),
    ("early_ccs", "unexpected_message", {}, True),
    ("cert_request", "CertificateRequest", {}, True),
    ("sha1_sig", "SHA-1", {"suite": 0xC02F}, True),
    ("sha1_sig", "SHA-1", {"suite": 0xC02B}, True),
    ("unoffered_sig", "ilan etmediğimiz imza", {"suite": 0xC02B}, True),
    ("bad_curve", "desteklenmeyen eğri", {}, True),
    ("unoffered_curve", "ilan etmediğimiz eğri|desteklenmeyen eğri", {}, True),
    ("extra_ext", "izin verilmeyen extension", {}, True),
    ("unoffered_alpn", "ALPN", {}, True),
    ("null_cmp_not", "sıkıştırma", {}, True),
    ("tls11", "protocol_version", {}, True),
    ("bad_cert_host", "sertifika doğrulaması", {}, True),
    ("ske_curve_type_explicit", "named_curve", {}, True),
    ("alert_in_hs", "handshake_failure", {}, True),
    ("close_after_hello", "aniden bağlantıyı kesti", {}, True),
    # istemci uçuşu gönderildikten SONRA yakalananlar
    ("bad_finished", "decrypt_error.*Finished", {}, False),
    # CCS'siz şifreli Finished: hem AES-GCM (8 bayt sıfır explicit nonce) hem ChaCha20-Poly1305
    # (açık nonce yok) her koşuda denenir — alert şifreli metnin baytlarına bağlı olmamalı.
    ("no_ccs", "unexpected_message", {"suite": 0xC02F}, False),
    ("no_ccs", "unexpected_message", {"suite": 0xCCA8}, False),
    ("plain_finished", "bad_record_mac", {}, False),
    ("trailing_after_finished", "unexpected_message", {}, False),
]


@pytest.mark.parametrize("tamper,match,kw,pre_flight", REJECT)
def test_fake_saldiri_ve_hatali_sunucular_reddedilir(pki, files, tamper, match, kw, pre_flight):
    srv = Fake12Server(pki, tamper={tamper}, **kw)
    port, t, ls = serve_fake_in_thread(srv)
    with pytest.raises(ConnectionError, match=match):
        _connect(port, files[0])
    t.join(5)
    ls.close()
    if pre_flight:
        assert not srv.cke_seen, "doğrulama başarısızken istemci ClientKeyExchange GÖNDERMEMELİ"


def test_fake_ccs_olmadan_sifresiz_finished_reddedilir(pki, files):
    srv = Fake12Server(pki, tamper={"no_ccs", "plain_finished"})
    port, t, ls = serve_fake_in_thread(srv)
    with pytest.raises(ConnectionError, match="ChangeCipherSpec olmadan"):
        _connect(port, files[0])
    t.join(5)


# CCS'siz şifreli Finished; her iki AEAD türü. ``ct_hello_request``: sunucu nonce seçerek
# şifreli gövdeyi düz metin olarak "HelloRequest, uzunluk > 2^18" gibi gösterir — düzeltmeden
# önce CI'da 1/256 olasılıkla görülen ``illegal_parameter: handshake mesajı çok büyük`` hatasını
# DETERMİNİSTİK üretir. ticket=False: NewSessionTicket hiç yok, record doğrudan CCS yerine gelir.
NO_CCS_SUITES = [pytest.param(0xC02F, id="aes128gcm"), pytest.param(0xCCA8, id="chacha20")]
NO_CCS_VARIANTS = [
    pytest.param(True, (), id="nst"),
    pytest.param(True, ("ct_hello_request",), id="nst-ct_hello_request"),
    pytest.param(False, (), id="bilet_yok"),
]


@pytest.mark.parametrize("ticket,extra", NO_CCS_VARIANTS)
@pytest.mark.parametrize("suite", NO_CCS_SUITES)
def test_fake_ccs_atlanirsa_alert_sifreli_metne_bagli_degil(pki, files, suite, ticket, extra):
    srv = Fake12Server(pki, suite=suite, ticket=ticket, tamper={"no_ccs", *extra})
    port, t, ls = serve_fake_in_thread(srv)
    with pytest.raises(ConnectionError, match=r"unexpected_message: ChangeCipherSpec beklenirken handshake"):
        _connect(port, files[0])
    t.join(5)
    ls.close()
    assert srv.finished_ok
    assert srv.alerts == [bytes([2, tls12.AL_UNEXPECTED_MESSAGE])]


@pytest.mark.parametrize("tamper,match,alert", [
    # session_ticket kabul edildi ama NST yok: CCS erken (RFC 5077 §3.3)
    ("no_nst", r"unexpected_message: NewSessionTicket beklenirken ChangeCipherSpec",
     tls12.AL_UNEXPECTED_MESSAGE),
    # NST'den sonra CCS yerine HelloRequest: bu pencerede yok SAYILMAZ
    ("hello_request_tail", r"unexpected_message: ChangeCipherSpec beklenirken handshake",
     tls12.AL_UNEXPECTED_MESSAGE),
    # CCS'ten sonra, Finished'tan önce application_data: ŞİFRESİ ÇÖZÜLMEDEN reddedilir
    # (önceden rastgele gövde bad_record_mac'e düşüyordu)
    ("garbage_appdata_before_fin", r"unexpected_message: handshake bitmeden",
     tls12.AL_UNEXPECTED_MESSAGE),
    # doğru pencerede ama içeriği 0x01 olmayan CCS
    ("ccs_payload_02", r"illegal_parameter: ChangeCipherSpec içeriği", tls12.AL_ILLEGAL_PARAMETER),
])
def test_fake_sunucu_ucusu_kayit_tipi_durum_makinesi(pki, files, tamper, match, alert):
    srv = Fake12Server(pki, tamper={tamper})
    port, t, ls = serve_fake_in_thread(srv)
    with pytest.raises(ConnectionError, match=match):
        _connect(port, files[0])
    t.join(5)
    ls.close()
    assert srv.alerts == [bytes([2, alert])]


def test_fake_erken_ccs_icerigi_bozuk_olsa_da_unexpected_message(pki, files):
    """Yanlış durumda gelen CCS, içeriği (0x02) ne olursa olsun önce DURUM yüzünden reddedilir."""
    srv = Fake12Server(pki, tamper={"early_ccs", "ccs_payload_02"})
    port, t, ls = serve_fake_in_thread(srv)
    with pytest.raises(ConnectionError, match=r"unexpected_message: WAIT_CERT durumunda beklenmeyen"):
        _connect(port, files[0])
    t.join(5)
    ls.close()
    assert not srv.cke_seen


def test_tls12_server_hello_oncesi_ccs_reddedilir(pki, files):
    """TLS 1.3 uyumluluk CCS'i ServerHello'dan önce atlanabilir; ama sunucu TLS 1.2 seçerse
    bu CCS TLS 1.2'de geçersizdir (CCS yalnızca istemci uçuşundan sonra) — reddedilir."""
    for use_async in (False, True):
        srv = Fake12Server(pki, tamper={"ccs_before_sh"})
        port, t, ls = serve_fake_in_thread(srv)
        with pytest.raises(ConnectionError, match="unexpected_message: TLS 1.2 ServerHello'dan önce"):
            if use_async:
                async def main():
                    await _async_negotiate(port, files[0])
                asyncio.run(asyncio.wait_for(main(), 15))
            else:
                _connect(port, files[0])
        t.join(5)
        ls.close()
        assert not srv.cke_seen


def test_wait_tail_kayit_tipi_birim():
    """İstemci uçuşundan sonraki pencere (WAIT_TAIL): NST zorunlu, sonra YALNIZCA CCS."""
    order = tls12.HandshakeOrder12(ticket_ok=True)
    order.state = "WAIT_TAIL"
    assert order.nst_pending and not order.awaiting_ccs
    with pytest.raises(tls12.TLS12Error, match="NewSessionTicket beklenirken ChangeCipherSpec"):
        order.check_ccs()
    with pytest.raises(tls12.TLS12Error, match="HelloRequest"):
        order.check(tls12.HS_HELLO_REQUEST)
    order.expect(tls12.HS_NEW_SESSION_TICKET)
    assert order.awaiting_ccs
    order.check_ccs()
    order.on_ccs()
    assert order.state == "WAIT_FIN"
    with pytest.raises(tls12.TLS12Error, match="WAIT_FIN durumunda beklenmeyen ChangeCipherSpec"):
        order.check_ccs()


def test_fake_wrong_key_type_rsa_suite_ec_cert(pki, files):
    srv = Fake12Server(pki, suite=0xC02F, tamper={"wrong_key_type"})
    port, t, ls = serve_fake_in_thread(srv)
    with pytest.raises(ConnectionError, match="RSA sertifikası gerektirir"):
        _connect(port, files[0])
    t.join(5)


def test_fake_wrong_key_type_ecdsa_suite_rsa_cert(pki, files):
    srv = Fake12Server(pki, suite=0xC02B, tamper={"wrong_key_type"})
    port, t, ls = serve_fake_in_thread(srv)
    with pytest.raises(ConnectionError, match="ECDSA sertifikası gerektirir"):
        _connect(port, files[0])
    t.join(5)


@pytest.mark.parametrize("group", [0x001D, 0x0017])
def test_fake_gecersiz_ecdhe_noktasi_reddedilir(pki, files, group):
    srv = Fake12Server(pki, group=group, tamper={"bad_pub"})
    port, t, ls = serve_fake_in_thread(srv)
    with pytest.raises(ConnectionError, match="illegal_parameter"):
        _connect(port, files[0])
    t.join(5)


def test_fake_reddedilen_baglantida_fatal_alert_gonderilir(pki, files):
    """İstemci doğrulama hatasında sunucuya fatal alert yollar (sessizce kapatmaz)."""
    srv = Fake12Server(pki, tamper={"bad_ske_sig"})
    port, t, ls = serve_fake_in_thread(srv)
    with pytest.raises(ConnectionError):
        _connect(port, files[0])
    t.join(5)
    assert srv.alerts and srv.alerts[0] == bytes([2, tls12.AL_DECRYPT_ERROR])


def test_fake_guvenilmeyen_ca(pki, files, tmp_path):
    srv = Fake12Server(pki)
    port, t, ls = serve_fake_in_thread(srv)
    other = tmp_path / "other.pem"
    other.write_bytes(PKI12().ca_pem())
    with pytest.raises(ConnectionError, match="olası MITM"):
        _connect(port, str(other))
    t.join(5)


@pytest.mark.parametrize("tamper,match", [("bad_record_mac", "bad_record_mac"),
                                          ("oversize_record", "record_overflow")])
def test_fake_bozuk_record_mac_ve_asiri_buyuk_record(pki, files, tamper, match):
    """Bozuk bir record, el sıkışma biter bitmez gelse de (aynı TCP okumasında) reddedilir."""
    srv = Fake12Server(pki, tamper={tamper})
    port, t, ls = serve_fake_in_thread(srv)
    with pytest.raises(ConnectionError, match=match):
        es = _connect(port, files[0])
        try:
            es.recv_record(skip_post_handshake=True)
        finally:
            es.close()
    t.join(3)


def test_tls12_hatalari_tlsprotocolerror_alt_sinifi(pki, files):
    srv = Fake12Server(pki, tamper={"no_ems"})
    port, t, ls = serve_fake_in_thread(srv)
    with pytest.raises(TLSProtocolError):
        _connect(port, files[0])


def test_default_profil_fake_sunucuyla_tls12(pki, files):
    """'default' profil (impersonate=None) EMS/renegotiation_info/0x0303 ilan eder."""
    srv, es, t = _run_fake(pki, files, profile=None)
    assert es.state["is_tls12"] and not es.state["is_tls13"]
    es.close()
    t.join(5)


@pytest.mark.parametrize("cipher,kind,sid", SUITE_MATRIX)
def test_default_profil_stdlib_tls12_her_suite(files, cipher, kind, sid):
    ca, cert = _cert_for(files, kind)
    srv = StdlibTLS12(cert, cipher, alpn=["http/1.1"])
    try:
        es = _connect(srv.port, ca, profile=None)
        assert es.state["is_tls12"] and es.state["cipher_suite"] == sid
        assert b"merhaba tls12" in _get(es)
        es.close()
    finally:
        srv.close()
    assert srv.negotiated[0][0] == "TLSv1.2" and srv.negotiated[0][1] == cipher
    assert not srv.errors, srv.errors


def test_default_profil_clienthello_tls12_uzantilari():
    from fasthttpc.fingerprint import extension_ids_from_client_hello
    from fasthttpc.tls_crafter import TLSImpersonator
    ch, _, _ = TLSImpersonator("example.com", profile=None).build_client_hello()
    exts = extension_ids_from_client_hello(ch)
    assert 0x0017 in exts and 0xFF01 in exts      # EMS, renegotiation_info
    assert ch[9:11] == b"\x03\x03"                  # client_version 0x0303 (legacy)
    from fasthttpc.fingerprint import ja3_string_from_client_hello
    suites = ja3_string_from_client_hello(ch).split(",")[1].split("-")
    assert {"49195", "49199", "52393"} <= set(suites)


# ------------------------------------------------------------------ async yol
def _async_negotiate(port, ca, profile="chrome_131", host=HOST):
    async def run():
        return await AsyncTLSStream.connect("127.0.0.1", port, profile, server_hostname=host, ca_path=ca)
    return run()


@pytest.mark.parametrize("cipher,kind,sid", SUITE_MATRIX)
def test_async_stdlib_sunucu_her_suite(files, cipher, kind, sid):
    ca, cert = _cert_for(files, kind)
    srv = StdlibTLS12(cert, cipher, alpn=["http/1.1"])

    async def main():
        st = await _async_negotiate(srv.port, ca)
        try:
            assert st.conn.cipher_suite == sid and st.state["is_tls12"]
            assert st.get_extra_info("alpn") == "http/1.1"
            st.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await st.drain()
            data = b""
            while b"merhaba" not in data:
                data += await st.read(65536)
            return data
        finally:
            st.close()

    try:
        data = asyncio.run(asyncio.wait_for(main(), 15))
    finally:
        srv.close()
    assert b"merhaba tls12" in data and not srv.errors


def test_async_session_http11_ve_h2(files):
    from fasthttpc.async_session import AsyncSession
    ca, cert = _cert_for(files, "ec")
    srv1 = StdlibTLS12(cert, "ECDHE-ECDSA-CHACHA20-POLY1305", alpn=["http/1.1"])
    srv2 = StdlibTLS12(cert, "ECDHE-ECDSA-AES128-GCM-SHA256", alpn=["h2", "http/1.1"],
                       handler=h2_handler(b"async h2 tls12"))

    async def main():
        async with AsyncSession(impersonate="chrome_131", verify=ca) as a:
            r1 = await a.get(f"https://localhost:{srv1.port}/")
            r2 = await a.get(f"https://localhost:{srv2.port}/")
            return r1, r2

    try:
        r1, r2 = asyncio.run(asyncio.wait_for(main(), 20))
    finally:
        srv1.close()
        srv2.close()
    assert r1.status_code == 200 and r1.content == b"merhaba tls12"
    assert r2.status_code == 200 and r2.content == b"async h2 tls12"
    assert srv2.negotiated[0][2] == "h2"


@pytest.mark.parametrize("tamper,match", [
    ("no_ems", "Extended Master Secret"),
    ("no_reneg", "renegotiation_info"),
    ("downgrd", "DOWNGRD"),
    ("bad_ske_sig", "ServerKeyExchange imzası GEÇERSİZ"),
    ("bad_finished", "Finished"),
    ("cbc_suite", "CBC"),
    ("out_of_order", "unexpected_message"),
    ("cert_request", "CertificateRequest"),
    ("sha1_sig", "SHA-1"),
    ("no_ccs", "unexpected_message"),
    ("no_nst", "unexpected_message"),
    ("hello_request_tail", "unexpected_message"),
    ("garbage_appdata_before_fin", "unexpected_message"),
])
def test_async_sahte_sunucu_reddedilir(pki, files, tamper, match):
    srv = Fake12Server(pki, tamper={tamper})
    port, t, ls = serve_fake_in_thread(srv)

    async def main():
        await _async_negotiate(port, files[0])

    with pytest.raises(TLSError, match=match):
        asyncio.run(asyncio.wait_for(main(), 15))
    t.join(5)


@pytest.mark.parametrize("ticket,extra", NO_CCS_VARIANTS)
@pytest.mark.parametrize("suite", NO_CCS_SUITES)
def test_async_ccs_atlanirsa_alert_sifreli_metne_bagli_degil(pki, files, suite, ticket, extra):
    """Senkron test_fake_ccs_atlanirsa_alert_sifreli_metne_bagli_degil'in async karşılığı."""
    srv = Fake12Server(pki, suite=suite, ticket=ticket, tamper={"no_ccs", *extra})
    port, t, ls = serve_fake_in_thread(srv)

    async def main():
        await _async_negotiate(port, files[0])

    with pytest.raises(TLSError, match=r"unexpected_message: ChangeCipherSpec beklenirken handshake"):
        asyncio.run(asyncio.wait_for(main(), 15))
    t.join(5)
    ls.close()
    assert srv.alerts == [bytes([2, tls12.AL_UNEXPECTED_MESSAGE])]


def _run_async_backend(backend, coro_fn, timeout=15):
    """``coro_fn``'i asyncio ya da trio altında (anyio zaman aşımıyla) çalıştırır."""
    if backend == "asyncio":
        return asyncio.run(asyncio.wait_for(coro_fn(), timeout))
    trio = pytest.importorskip("trio")
    anyio = pytest.importorskip("anyio")

    async def main():
        with anyio.fail_after(timeout):
            return await coro_fn()
    return trio.run(main)


@pytest.mark.parametrize("backend", ["asyncio", "trio"])
@pytest.mark.parametrize("tamper,alert", [
    ("bad_ske_sig", tls12.AL_DECRYPT_ERROR),
    ("out_of_order", tls12.AL_UNEXPECTED_MESSAGE),
    ("cbc_suite", tls12.AL_INSUFFICIENT_SECURITY),
])
def test_async_reddedilen_baglantida_fatal_alert_gonderilir(pki, files, backend, tamper, alert):
    """Senkron test_fake_reddedilen_baglantida_fatal_alert_gonderilir'in async karşılığı:
    async yol da doğrulama hatasında sunucuya (senkron yolla AYNI kodlu) fatal alert yollar."""
    srv = Fake12Server(pki, tamper={tamper})
    port, t, ls = serve_fake_in_thread(srv)

    async def main():
        await _async_negotiate(port, files[0])

    with pytest.raises(TLSError):
        _run_async_backend(backend, main)
    t.join(5)
    ls.close()
    assert srv.alerts and srv.alerts[0] == bytes([2, alert])


def test_async_ve_senkron_ayni_alert_kodunu_gonderir(pki, files):
    """Aynı hata için iki yolun gönderdiği fatal alert birebir aynı olmalı."""
    got = []
    for use_async in (False, True):
        srv = Fake12Server(pki, tamper={"bad_ske_sig"})
        port, t, ls = serve_fake_in_thread(srv)
        with pytest.raises(ConnectionError):
            if use_async:
                async def main():
                    await _async_negotiate(port, files[0])
                asyncio.run(asyncio.wait_for(main(), 15))
            else:
                _connect(port, files[0])
        t.join(5)
        ls.close()
        got.append(srv.alerts[:1])
    assert got[0] == got[1] == [bytes([2, tls12.AL_DECRYPT_ERROR])]


def test_async_sahte_sunucu_kabul_ve_hello_request(pki, files):
    srv = Fake12Server(pki, suite=0xC030, split_flight=True, tamper={"hello_request"})
    port, t, ls = serve_fake_in_thread(srv)

    async def main():
        st = await _async_negotiate(port, files[0])
        st.write(b"merhaba")
        await st.drain()
        data = await st.read(100)
        st.close()
        return data

    assert asyncio.run(asyncio.wait_for(main(), 15)) == b"echo:merhaba"
    t.join(5)
    assert srv.finished_ok and srv.alerts[0] == b"\x01\x64"


def test_async_cekirdek_tls12_durum_gecisleri(pki, files):
    """sans-IO çekirdek: TLS 1.2 seçilince crypto_state/closed/update_keys davranışı."""
    from fasthttpc.tls13 import TLSClientConnection
    srv = Fake12Server(pki)
    port, t, ls = serve_fake_in_thread(srv)
    conn = TLSClientConnection(HOST, "chrome_131", ca_path=files[0])
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(conn.initiate())
    while not conn.handshake_complete:
        conn.receive_data(s.recv(65536))
        out = conn.data_to_send()
        if out:
            s.sendall(out)
    assert conn.state == "CONNECTED" and conn.crypto_state()["is_tls12"]
    assert conn.cipher_suite == 0xC02F and conn.peer_certificate is not None
    with pytest.raises(TLSError, match="KeyUpdate"):
        conn.update_keys()
    s.sendall(conn.send_application_data(b"CLOSE"))
    ev = []
    while not conn.closed:
        ev += conn.receive_data(s.recv(65536))
    assert any(type(e).__name__ == "ConnectionClosed" for e in ev)
    s.close()
    t.join(3)


def test_default_profil_session_http11_tls12(files):
    from fasthttpc import Session
    ca, cert = _cert_for(files, "rsa")
    srv = StdlibTLS12(cert, "ECDHE-RSA-AES128-GCM-SHA256", alpn=["http/1.1"])
    try:
        with Session(impersonate=None, verify=ca) as s:
            r = s.get(f"https://localhost:{srv.port}/")
        assert r.status_code == 200 and r.content == b"merhaba tls12"
    finally:
        srv.close()


def test_default_profil_async_tls_cekirdegi_tls12(files):
    ca, cert = _cert_for(files, "rsa")
    srv = StdlibTLS12(cert, "ECDHE-RSA-AES256-GCM-SHA384", alpn=["http/1.1"])

    async def main():
        st = await _async_negotiate(srv.port, ca, profile=None)
        try:
            assert st.state["is_tls12"] and st.conn.cipher_suite == 0xC030
        finally:
            st.close()
    try:
        asyncio.run(main())
    finally:
        srv.close()
