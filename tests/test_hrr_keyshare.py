"""
Faz 2 — HelloRetryRequest ve secp256r1/secp384r1 key_share testleri.

Tümü yerel sahte TLS 1.3 sunucusuyla (tests/fake_tls_server.py) çalışır, ağ
gerektirmez. CA zinciri doğrulaması monkeypatch ile atlanır; CertificateVerify
ve Finished gerçekten doğrulanır, yani transcript (message_hash dahil) yanlış
kurulursa handshake BAŞARISIZ olur.
"""
import hashlib
import socket
import struct

import pytest
from cryptography import x509

from fasthttpc.security import tls_adapter
from fasthttpc.security.keyshare import (
    GROUP_SECP256R1, GROUP_SECP384R1, GROUP_X25519, HRR_RANDOM, KeyShareSet,
    SUPPORTED_GROUPS, compute_shared_secret, generate_key_share, is_hello_retry_request,
    message_hash, parse_hrr,
)
from fasthttpc.tls_crafter import TLSImpersonator
from fasthttpc.fingerprint import PROFILES

from fake_tls_server import FakeTLS13Server, parse_client_hello


@pytest.fixture
def trust_leaf(monkeypatch):
    def _validate(hs_payload, hostname, **_kw):
        body = hs_payload[4:]
        ctx_len = body[0]
        p = 1 + ctx_len + 3
        clen = struct.unpack("!I", b"\x00" + body[p:p + 3])[0]
        return x509.load_der_x509_certificate(body[p + 3:p + 3 + clen])
    monkeypatch.setattr(tls_adapter, "validate_server_certificate", _validate)


def _connect(srv, profile="chrome_131"):
    s = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
    try:
        return tls_adapter.TLSAdapter.negotiate(s, "example.com", profile)
    except Exception:
        s.close()
        raise


def _roundtrip(esock):
    esock.send_record(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    data, t = esock.recv_record(skip_post_handshake=True)
    esock.raw_socket.close()
    return data


# ---- Saf yardımcılar --------------------------------------------------------

@pytest.mark.parametrize("group,size", [(GROUP_X25519, 32), (GROUP_SECP256R1, 65),
                                        (GROUP_SECP384R1, 97)])
def test_ecdhe_roundtrip(group, size):
    a_priv, a_pub = generate_key_share(group)
    b_priv, b_pub = generate_key_share(group)
    assert len(a_pub) == size
    if group != GROUP_X25519:
        assert a_pub[0] == 0x04  # uncompressed
    assert compute_shared_secret(group, a_priv, b_pub) == compute_shared_secret(group, b_priv, a_pub)


def test_invalid_ec_point_rejected():
    priv, pub = generate_key_share(GROUP_SECP256R1)
    bad = b"\x04" + b"\x01" * 64  # eğri üzerinde olmayan nokta
    with pytest.raises(ValueError):
        compute_shared_secret(GROUP_SECP256R1, priv, bad)
    with pytest.raises(ValueError):  # compressed format reddedilir
        compute_shared_secret(GROUP_SECP256R1, priv, b"\x02" + pub[1:33])


def test_x25519_zero_shared_rejected():
    priv, _ = generate_key_share(GROUP_X25519)
    with pytest.raises(ValueError):
        compute_shared_secret(GROUP_X25519, priv, b"\x00" * 32)


def test_unsupported_group_raises():
    with pytest.raises(ValueError):
        generate_key_share(0x6399)      # X25519Kyber768Draft00: uygulanmadı
    with pytest.raises(ValueError, match="göndermedik"):
        KeyShareSet([GROUP_X25519]).shared_secret(GROUP_SECP256R1, b"\x04" * 65)


def test_message_hash_format():
    ch1 = b"\x01\x00\x00\x03abc"
    mh = message_hash(hashlib.sha256, ch1)
    assert mh[0] == 254 and mh[1:4] == b"\x00\x00\x20"
    assert mh[4:] == hashlib.sha256(ch1).digest()
    assert len(message_hash(hashlib.sha384, ch1)) == 4 + 48


def test_parse_hrr():
    exts = (struct.pack("!HHH", 0x2B, 2, 0x0304) + struct.pack("!HHH", 0x33, 2, 0x17)
            + struct.pack("!HHH", 0x2C, 5, 3) + b"abc")
    body = (b"\x03\x03" + HRR_RANDOM + b"\x01\xaa" + b"\x13\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    info = parse_hrr(body)
    assert info.selected_group == 0x17 and info.cookie == b"abc"
    assert info.cipher_suite == 0x1301 and info.session_id == b"\xaa"
    assert is_hello_retry_request(HRR_RANDOM)
    with pytest.raises(ValueError):
        parse_hrr(body + b"\x00")  # uzunluk tutarsız


# ---- Crafter: 2. ClientHello ------------------------------------------------

def test_retry_client_hello_preserves_fields():
    imp = TLSImpersonator("example.com", profile="chrome_131")
    ch1 = imp.build_client_hello()[0]
    ch2 = imp.build_retry_client_hello(GROUP_SECP256R1, cookie=b"COOKIE")
    p1, p2 = parse_client_hello(ch1[5:]), parse_client_hello(ch2[5:])
    assert p1["random"] == p2["random"]
    assert p1["session_id"] == p2["session_id"]
    assert p1["suites"] == p2["suites"]
    assert list(p2["key_shares"]) == [GROUP_SECP256R1]
    assert len(p2["key_shares"][GROUP_SECP256R1]) == 65
    assert p2["cookie"] == b"COOKIE"
    # cookie ve padding dışında extension tipleri ve sırası aynı (GREASE dahil)
    t1 = [t for t, _ in p1["exts"] if t != 0x15]
    t2 = [t for t, _ in p2["exts"] if t not in (0x15, 0x2C)]
    assert t1 == t2          # Chrome'un karıştırılmış sırası CH2'de aynen korunur


def test_extra_tail_extensions_last():
    imp = TLSImpersonator("example.com", profile="chrome_131")
    tail = struct.pack("!HH", 41, 4) + b"\x00\x00\x00\x00"
    ch = imp.build_client_hello(extra_tail_extensions=tail)[0]
    assert ch.endswith(tail)
    assert parse_client_hello(ch[5:])["exts"][-1][0] == 41


def imp_grease(imp):
    return {imp._grease_group}


def test_profile_key_shares_are_supported_and_advertised():
    """Profil tutarlılığı: key_share gönderilen her grup hem gerçekten
    desteklenmeli hem de supported_groups'ta ilan edilmiş olmalı."""
    for name in PROFILES:
        imp = TLSImpersonator("example.com", profile=name)
        ch = parse_client_hello(imp.build_client_hello()[0][5:])
        for g in ch["key_shares"]:
            if g in imp_grease(imp):
                continue          # RFC 8701 GREASE key_share girdisi
            assert g in SUPPORTED_GROUPS, (name, hex(g))
            assert g in ch["groups"], (name, hex(g))


def test_unsupported_key_share_group_dropped(monkeypatch):
    prof = dict(PROFILES["chrome_131"])
    prof["supported_groups"] = ["GREASE", 0x6399, 0x001D, 0x0017]
    prof["key_share_groups"] = [0x6399, 0x001D]
    monkeypatch.setitem(PROFILES, "chrome_131", prof)
    imp = TLSImpersonator("example.com", profile="chrome_131")
    ch = parse_client_hello(imp.build_client_hello()[0][5:])
    assert list(ch["key_shares"]) == [GROUP_X25519]
    # Desteklenmeyen PQ grup (uygulanmadı) ilan EDİLMEZ: sunucu HRR ile isteyip
    # handshake'i kırardı. (X25519MLKEM768 artık gerçekten desteklenir.)
    assert 0x6399 not in ch["groups"]


# ---- Uçtan uca handshake ----------------------------------------------------

@pytest.mark.parametrize("group", [GROUP_X25519, GROUP_SECP256R1])
def test_direct_handshake_firefox_groups(trust_leaf, group):
    srv = FakeTLS13Server(group=group)
    esock = _connect(srv, "firefox_133")
    assert esock.state["key_share_group"] == group
    assert not esock.state["hello_retry"]
    assert _roundtrip(esock).startswith(b"HTTP/1.1 200")
    srv.close()


@pytest.mark.parametrize("hrr_group,suite", [(GROUP_SECP256R1, 0x1301),
                                             (GROUP_SECP384R1, 0x1302)])
def test_hrr_handshake(trust_leaf, hrr_group, suite):
    srv = FakeTLS13Server(hrr_group=hrr_group, suite=suite)
    esock = _connect(srv)
    assert esock.state["hello_retry"] is True
    assert esock.state["key_share_group"] == hrr_group
    assert _roundtrip(esock).startswith(b"HTTP/1.1 200")
    srv.done.wait(5)
    assert srv.error is None, srv.error
    assert len(srv.client_hellos) == 2
    assert srv.ccs_before_ch2
    srv.close()


def test_hrr_with_cookie(trust_leaf):
    srv = FakeTLS13Server(hrr_group=GROUP_SECP256R1, cookie=b"\x99" * 40)
    esock = _connect(srv)
    assert _roundtrip(esock).startswith(b"HTTP/1.1 200")
    srv.done.wait(5)
    assert srv.error is None, srv.error
    assert srv.client_hellos[1]["cookie"] == b"\x99" * 40
    srv.close()


def test_second_hrr_rejected(trust_leaf):
    srv = FakeTLS13Server(hrr_group=GROUP_SECP256R1, double_hrr=True)
    with pytest.raises(ConnectionError, match="ikinci bir HelloRetryRequest"):
        _connect(srv)
    srv.close()


def test_hrr_for_already_offered_group_rejected(trust_leaf):
    srv = FakeTLS13Server(hrr_group=GROUP_X25519)
    with pytest.raises(ConnectionError, match="illegal_parameter"):
        _connect(srv)
    srv.close()


def test_hrr_for_unimplemented_group_clear_error(trust_leaf):
    # firefox_133 secp521r1'i ilan eder ama implemente etmiyoruz
    srv = FakeTLS13Server(hrr_group=0x0019)
    with pytest.raises(ConnectionError, match="implemente edilmedi"):
        _connect(srv, "firefox_133")
    srv.close()


def test_hrr_then_different_group_rejected(trust_leaf):
    srv = FakeTLS13Server(hrr_group=GROUP_SECP256R1, sh_group_override=GROUP_SECP384R1)
    with pytest.raises(ConnectionError):
        _connect(srv)
    srv.close()


def test_hrr_then_different_suite_rejected(trust_leaf):
    srv = FakeTLS13Server(hrr_group=GROUP_SECP256R1, suite=0x1302, hrr_suite=0x1301)
    with pytest.raises(ConnectionError, match="cipher suite"):
        _connect(srv)
    srv.close()
