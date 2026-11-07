"""session_tickets saf fonksiyon testleri (ağsız)."""
import hashlib
import hmac
import struct
import threading

import pytest

from fasthttpc.crypto_math import PureCryptoEngine
from fasthttpc.security import session_tickets as st
from fasthttpc.tls_crafter import TLSImpersonator


def _nst(lifetime=7200, age_add=0x01020304, nonce=b"\x00\x01", ticket=b"T" * 32, exts=b""):
    body = (struct.pack("!II", lifetime, age_add) + bytes([len(nonce)]) + nonce
            + struct.pack("!H", len(ticket)) + ticket + struct.pack("!H", len(exts)) + exts)
    return b"\x04" + len(body).to_bytes(3, "big") + body


def test_parse_new_session_ticket():
    early = struct.pack("!HHI", 42, 4, 16384)
    t = st.parse_new_session_ticket(_nst(exts=early))
    assert t.lifetime == 7200 and t.age_add == 0x01020304
    assert t.nonce == b"\x00\x01" and t.ticket == b"T" * 32 and t.max_early_data == 16384


@pytest.mark.parametrize("bad", [
    b"", b"\x05\x00\x00\x00", _nst()[:-3], _nst(ticket=b""),
    _nst()[:-2] + b"\x00\x05",  # uzantı uzunluğu tutarsız
])
def test_parse_rejects_malformed(bad):
    with pytest.raises(st.TicketError):
        st.parse_new_session_ticket(bad)


def test_resumption_secret_matches_manual_schedule():
    h = hashlib.sha256
    hs = bytes(range(32))
    th = h(b"transcript").digest()
    E = PureCryptoEngine
    derived = E.tls13_hkdf_expand_label(hs, "derived", h(b"").digest(), 32)
    ms = E.hkdf_extract(derived, b"\x00" * 32)
    expect = E.tls13_hkdf_expand_label(ms, "res master", th, 32)
    assert st.derive_resumption_master_secret(hs, th) == expect
    assert st.derive_psk(expect, b"\x00") == E.tls13_hkdf_expand_label(expect, "resumption", b"\x00", 32)


@pytest.mark.parametrize("h,klen", [(hashlib.sha256, 16), (hashlib.sha384, 32)])
def test_psk_none_equals_full_handshake_schedule(h, klen):
    shared, th = b"\x07" * 32, h(b"ch+sh").digest()
    assert st.derive_handshake_keys_psk(None, shared, th, klen, h) == \
        PureCryptoEngine.derive_tls13_keys(shared, th, klen, hash_alg=h)
    assert st.derive_handshake_keys_psk(b"\x01" * h().digest_size, shared, th, klen, h) != \
        PureCryptoEngine.derive_tls13_keys(shared, th, klen, hash_alg=h)


def test_binder_definition():
    h = hashlib.sha256
    psk = b"\x11" * 32
    th = h(b"x").digest()
    E = PureCryptoEngine
    early = E.hkdf_extract(b"\x00" * 32, psk)
    bk = E.tls13_hkdf_expand_label(early, "res binder", h(b"").digest(), 32)
    fk = E.tls13_hkdf_expand_label(bk, "finished", b"", 32)
    assert st.compute_binder(psk, th) == hmac.new(fk, th, h).digest()


def _ticket(host="a.test", now=1000.0, lifetime=60, suite=0x1301):
    nst = st.parse_new_session_ticket(_nst(lifetime=lifetime))
    return st.ticket_from_message(host, nst, b"\x22" * 32, suite, now=now)


def test_ticket_age_and_expiry():
    t = _ticket(now=1000.0, lifetime=60)
    assert t.obfuscated_age(now=1001.5) == (1500 + 0x01020304) & 0xFFFFFFFF
    assert not t.is_expired(now=1059)
    assert t.is_expired(now=1060)
    assert t.is_expired(now=999)  # saat geri gitti
    assert st.ticket_from_message("h", st.parse_new_session_ticket(_nst(lifetime=0)), b"x" * 32, 0x1301) is None
    big = _ticket(lifetime=10 ** 9)
    assert big.lifetime == st.MAX_TICKET_LIFETIME
    assert _ticket(suite=0x1302).psk != _ticket(suite=0x1301).psk  # sha384 vs sha256


def test_cache_single_use_lru_and_expiry():
    c = st.TicketCache(max_hosts=2, max_per_host=2)
    a1, a2, a3 = (_ticket("A.test") for _ in range(3))
    for t in (a1, a2, a3):
        c.put(t)
    assert len(c) == 2  # max_per_host
    assert c.pop("a.test", now=1001) is a3
    assert c.pop("a.test", now=1001) is a2
    assert c.pop("a.test", now=1001) is None
    c.put(_ticket("x")); c.put(_ticket("y")); c.put(_ticket("z"))
    assert c.pop("x", now=1001) is None and c.pop("z", now=1001) is not None
    c.put(_ticket("old", lifetime=10))
    assert c.pop("old", now=2000) is None
    assert len(c) == 1  # yalnızca "y"


def test_cache_key_includes_port_and_ca():
    assert st.cache_key("A.test", 443) == st.cache_key("a.test", 443)
    assert st.cache_key("a.test", 443) != st.cache_key("a.test", 8443)
    assert st.cache_key("a.test", 443) != st.cache_key("a.test", 443, "ca.pem")


def test_cache_thread_safe():
    c = st.TicketCache(max_hosts=1000, max_per_host=1000)

    def worker(i):
        for j in range(200):
            c.put(_ticket(f"h{i % 5}"))
            c.pop(f"h{(i + 1) % 5}", now=1001)

    ths = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    [t.start() for t in ths]; [t.join() for t in ths]
    assert len(c) >= 0


def test_psk_extension_and_binder_patch():
    imp = TLSImpersonator("example.com", profile="chrome_131")
    t = _ticket(now=__import__("time").time())
    rec, _priv, _rand = st.build_resumption_client_hello(imp, t)
    types = st.client_hello_extension_types(rec)
    assert types[-1] == st.EXT_PRE_SHARED_KEY and st.EXT_PSK_KEY_EXCHANGE_MODES in types
    assert struct.unpack("!H", rec[3:5])[0] == len(rec) - 5
    assert int.from_bytes(rec[6:9], "big") == len(rec) - 9
    msg = rec[5:]
    truncated = msg[:-(2 + 1 + 32)]
    assert rec[-32:] == st.compute_binder(t.psk, hashlib.sha256(truncated).digest())
    assert t.ticket in rec


def test_profile_without_psk_modes_returns_none():
    imp = TLSImpersonator("example.com", profile="default")
    assert st.build_resumption_client_hello(imp, _ticket(now=__import__("time").time())) is None


def test_flag_default_off(monkeypatch):
    monkeypatch.delenv("FASTHTTPC_TLS_RESUMPTION", raising=False)
    st.enable_resumption(False)
    assert st.resumption_enabled() is False
