"""TLS 1.2 istemci desteği uyumluluk matrisi (openssl s_server -tls1_2, tlslite-ng, DOWNGRD aracısı).

DURUM: TLS 1.2 istemcisi `tls12` dalında yazılıyor; bu dosya o dala AİT BEKLENTİLERİ şimdiden tanımlar.
Mevcut kod TLS 1.2'yi bilinçli reddettiği için olumlu testler `xfail(strict=True)` ile işaretlidir.
Birleştirmede müdür xfail işaretlerini kaldırır (XPASS strict hata verir, böylece unutulmaz).
"""
from __future__ import annotations

import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tlslite.api import HandshakeSettings  # noqa: E402

from interop.relay import Relay  # noqa: E402
from interop.tlslite_server import TlsliteServer  # noqa: E402
from test_interop_openssl import MODES, _get, _rejects  # noqa: E402,F401
from test_interop_openssl import env  # noqa: E402,F401  (fixture)

pytestmark = pytest.mark.interop

TLS12_PENDING = pytest.mark.xfail(
    strict=True, reason="TLS 1.2 istemci desteği tls12 dalında; birleştirmede bu işaret kaldırılacak (NOTES3)")

SUITES12 = [
    ("p256", "ECDHE-ECDSA-AES128-GCM-SHA256"),
    ("p256", "ECDHE-ECDSA-AES256-GCM-SHA384"),
    ("p256", "ECDHE-ECDSA-CHACHA20-POLY1305"),
    ("rsa2048", "ECDHE-RSA-AES128-GCM-SHA256"),
    ("rsa2048", "ECDHE-RSA-AES256-GCM-SHA384"),
    ("rsa2048", "ECDHE-RSA-CHACHA20-POLY1305"),
]


@TLS12_PENDING
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key,suite", SUITES12)
def test_tls12_openssl_suite_matrisi(env, key, suite, mode):
    cert, k = env.leaf[key]
    from interop.openssl_server import SServer
    with SServer("-cert", cert, "-key", k, "-tls1_2", "-cipher", suite, "-WWW", cwd=str(env.dir)) as s:
        r = _get(mode, s.port, env.ca_path)
    assert r.status_code == 200 and r.content == b"merhaba interop"


@TLS12_PENDING
@pytest.mark.parametrize("mode", MODES)
def test_tls12_buyuk_yanit(env, mode):
    import hashlib
    cert, k = env.leaf["p256"]
    from interop.openssl_server import SServer
    with SServer("-cert", cert, "-key", k, "-tls1_2", "-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256", "-WWW",
                 cwd=str(env.dir)) as s:
        r = _get(mode, s.port, env.ca_path, path="/big.bin")
    assert hashlib.sha256(r.content).digest() == hashlib.sha256(env.big).digest()


def _tl12(env, ems: bool, tmp):
    from interop import pki
    c, k = pki.write(tmp, "tl12", pki.make_cert("localhost", env.ca, "rsa2048"))
    hs = HandshakeSettings()
    hs.minVersion = hs.maxVersion = (3, 3)
    hs.useExtendedMasterSecret = ems
    hs.requireExtendedMasterSecret = False
    hs.cipherNames = ["aes128gcm"]
    return TlsliteServer(c, k, hs)


@TLS12_PENDING
@pytest.mark.parametrize("mode", MODES)
def test_tls12_tlslite_ems_acik(env, mode, tmp_path):
    with _tl12(env, True, tmp_path) as s:
        r = _get(mode, s.port, env.ca_path)
    assert r.status_code == 200 and s.sessions[0][0] == (3, 3) and s.sessions[0][2] is True, s.errors


@TLS12_PENDING
@pytest.mark.parametrize("mode", MODES)
def test_tls12_ems_kapali_sunucu_reddedilmeli(env, mode, tmp_path):
    """extended_master_secret (RFC 7627) sunmayan TLS 1.2 sunucusu: triple-handshake saldırısına açıktır;
    istemci reddetmeli ve nedenini EMS olarak söylemeli (sürüm hatası DEĞİL)."""
    with _tl12(env, False, tmp_path) as s:
        _rejects(lambda: _get(mode, s.port, env.ca_path), r"extended.?master|\bEMS\b|master.?secret|7627")


def _strip_supported_versions(i, t, rec):
    """ClientHello'daki supported_versions (43) uzantı tipini aynı uzunlukta bilinmeyen bir tiple değiştirir:
    sunucu istemciyi yalnızca TLS 1.2 konuşuyor sanır, ama TLS 1.3 desteklediği için ServerHello.random'a
    DOWNGRD sentinel'i koyar (RFC 8446 §4.1.3)."""
    if i != 0 or t != 22:
        return rec
    b = bytearray(rec)
    p = 5 + 4 + 2 + 32
    p += 1 + b[p]                               # session_id
    p += 2 + struct.unpack("!H", b[p:p + 2])[0]  # cipher suites
    p += 1 + b[p]                               # compression
    end = p + 2 + struct.unpack("!H", b[p:p + 2])[0]
    p += 2
    n = 0
    while p + 4 <= end:
        et, el = struct.unpack("!HH", b[p:p + 4])
        if et == 43:
            b[p:p + 2] = b"\xff\x77"
            n += 1
        p += 4 + el
    assert n == 1, "supported_versions bulunamadı"
    return bytes(b)


@pytest.mark.parametrize("mode", MODES)
def test_tls12_downgrd_sentinel_reddedilmeli(env, mode):
    """TLS 1.3 destekleyen sunucu, istemci TLS 1.3'ü ilan etmediği için (aracı sildi) TLS 1.2 seçer ve
    ServerHello.random sonuna 'DOWNGRD\\x01' koyar. İstemci TLS 1.3 teklif ettiği için bunu bir
    downgrade saldırısı sayıp reddetmeli (RFC 8446 §4.1.3)."""
    from interop.openssl_server import SServer
    cert, k = env.leaf["p256"]
    with SServer("-cert", cert, "-key", k, "-WWW", cwd=str(env.dir)) as s, \
            Relay(s.port, c2s=_strip_supported_versions) as rl:
        # Bugün de (TLS 1.2 yok) tls12 dalı birleşince de geçmeli: ret nedeni DOWNGRD olarak anılmalı.
        _rejects(lambda: _get(mode, rl.port, env.ca_path), r"downgrad|DOWNGRD")
