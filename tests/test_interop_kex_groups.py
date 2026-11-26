"""secp521r1 / x448 / ffdhe2048 / ffdhe3072: bağımsız `openssl s_server` karşısında uyumluluk.

Sunucu YALNIZCA tek bir grubu kabul eder (``-groups``). TLS 1.3'te tarayıcı profilleri bu gruplar
için ilk ClientHello'da key_share göndermez (gerçek tarayıcılar gibi); sunucu HelloRetryRequest ile
ister, istemci 2. ClientHello'da o grubun payını yollar. TLS 1.2'de grup ECDHE ServerKeyExchange'te
seçilir; ffdhe TLS 1.2'de kullanılmaz (DHE her zaman reddedilir). x448'i hiçbir yerleşik profil
ilan etmez, bu yüzden x448 onu ilan eden bir test profiliyle sınanır. Yerel openssl bir grubu
tanımıyorsa (gerçek platform kısıtı) test açık gerekçeyle atlanır. Senkron `Session` (TLSAdapter)
ve `AsyncSession` (sans-IO çekirdek) ikisi de sürülür.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fasthttpc.fingerprint import PROFILES  # noqa: E402
from interop.openssl_server import OPENSSL, SServer, s_server_supports_group  # noqa: E402
from test_interop_openssl import MODES, _get, _rejects  # noqa: E402
from test_interop_openssl import env  # noqa: E402,F401  (fixture)

pytestmark = [pytest.mark.interop, pytest.mark.skipif(OPENSSL is None, reason="openssl CLI yok")]


@pytest.fixture
def x448_profili(monkeypatch):
    prof = dict(PROFILES["default"])
    prof["supported_groups"] = [0x001D, 0x0017, 0x0018, 0x001E]
    monkeypatch.setitem(PROFILES, "test_x448", prof)
    return "test_x448"


def _grup_sunucusu(env, group: str, version: str, *extra: str) -> SServer:
    if not s_server_supports_group(group):
        pytest.skip(f"yerel openssl s_server '{group}' grubunu tanımıyor (platform kısıtı)")
    cert, key = env.leaf["p256"]
    return SServer("-cert", cert, "-key", key, version, "-groups", group, "-msg", *extra, "-WWW",
                   cwd=str(env.dir))


def _profil(request, name):
    if name == "test_x448":
        request.getfixturevalue("x448_profili")
    return name


TLS13 = [("secp521r1", "firefox_160"), ("secp521r1", "firefox_133"), ("secp521r1", "safari_18"),
         ("secp521r1", "safari_27"), ("ffdhe2048", "firefox_133"), ("ffdhe3072", "firefox_133"),
         ("X448", "test_x448")]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("group,profile", TLS13)
def test_tls13_hrr_ile_grup(env, request, group, profile, mode):
    with _grup_sunucusu(env, group, "-tls1_3") as s:
        r = _get(mode, s.port, env.ca_path, profile=_profil(request, profile))
        log = s.wait_count("ClientHello", 2)
    assert r.status_code == 200 and r.content == b"merhaba interop"
    # Profil bu grup için ilk payı göndermez: sunucu HRR istedi ve iki ClientHello okudu.
    assert log.count("ClientHello") >= 2, "HRR yolu tetiklenmedi: " + log[:600]


TLS12 = [("secp521r1", "firefox_160"), ("secp521r1", "firefox_133"), ("X448", "test_x448")]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("group,profile", TLS12)
def test_tls12_ecdhe_grup(env, request, group, profile, mode):
    with _grup_sunucusu(env, group, "-tls1_2", "-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256") as s:
        r = _get(mode, s.port, env.ca_path, profile=_profil(request, profile))
        log = s.wait_count("ServerKeyExchange", 1)
    assert r.status_code == 200 and r.content == b"merhaba interop"
    assert "ServerKeyExchange" in log and log.count("ClientHello") == 1


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("group,profile", [("secp521r1", "chrome_158"), ("ffdhe2048", "firefox_160"),
                                           ("ffdhe3072", "chrome_158"), ("X448", "firefox_160")])
def test_tls13_ilan_edilmeyen_grup_istenmez(env, group, profile, mode):
    """Profil grubu ilan etmiyor (parmak izi): ortak grup yok, bağlantı açık hatayla kurulamaz."""
    with _grup_sunucusu(env, group, "-tls1_3") as s:
        _rejects(lambda: _get(mode, s.port, env.ca_path, profile=profile),
                 r"grup|group|alert|handshake|40|uyumlu|ortak")


@pytest.mark.parametrize("mode", MODES)
def test_tls12_ffdhe_kullanilmaz(env, mode):
    """TLS 1.2'de ffdhe yalnızca DHE suite'leriyle kullanılır; DHE teklif edilmez ve her zaman
    reddedilir. Yalnızca ffdhe2048 kabul eden TLS 1.2 sunucusuyla ortak ECDHE eğrisi yoktur."""
    with _grup_sunucusu(env, "ffdhe2048", "-tls1_2") as s:
        _rejects(lambda: _get(mode, s.port, env.ca_path, profile="firefox_133"),
                 r"grup|group|alert|handshake|40|cipher|suite|DHE")
