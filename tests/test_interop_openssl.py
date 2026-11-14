"""Bağımsız `openssl s_server` karşısında TLS 1.3 uyumluluk matrisi + negatif testler.

Bağlantı gerçekten 127.0.0.1 üzerinde yapılır; sunucu OpenSSL'dir (fasthttpc'nin kendi TLS yığınına
dokunmayan, olgun bir uygulama). Senkron `Session` ve `AsyncSession(impersonate=...)` ikisi de sürülür.
Yavaş sayıldığı için `interop` marker'ı taşır ama varsayılan çalıştırmada da koşar.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import socket
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fasthttpc import AsyncSession, Session  # noqa: E402
from fasthttpc.security import session_tickets  # noqa: E402
from interop import pki  # noqa: E402
from interop.openssl_server import OPENSSL, SServer  # noqa: E402

pytestmark = [pytest.mark.interop, pytest.mark.skipif(OPENSSL is None, reason="openssl CLI yok")]

SUITES = ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
GROUPS = ["X25519", "P-256", "P-384"]
KEYS = ["rsa2048", "rsa4096", "p256", "p384"]
PROFILES = ["chrome_131", "firefox_133", "safari_18"]


# --------------------------------------------------------------------------- yardımcılar

class Env:
    """Oturum boyunca paylaşılan PKI (RSA-4096 üretimi yavaş olduğu için bir kez)."""

    def __init__(self, d):
        self.dir = d
        self.ca = pki.make_cert("Interop Root CA", None, "p256", ca=True)
        self.ca_path = pki.write_ca(d, "ca", self.ca)
        self.other_ca = pki.make_cert("Baska CA", None, "p256", ca=True)
        self.other_ca_path = pki.write_ca(d, "other_ca", self.other_ca)
        self.leaf = {}
        for k in KEYS:
            self.leaf[k] = pki.write(d, f"leaf_{k}", pki.make_cert("localhost", self.ca, k))
        self.leaf["ed25519"] = pki.write(d, "leaf_ed25519", pki.make_cert("localhost", self.ca, "ed25519"))
        self.p256 = self.leaf["p256"]
        # ara sertifikalı zincir: kök(p256) -> ara(rsa2048) -> yaprak(p384)
        self.inter = pki.make_cert("Interop Ara CA", self.ca, "rsa2048", ca=True)
        self.chain_leaf = pki.make_cert("localhost", self.inter, "p384")
        self.chain_cert, self.chain_key = pki.write(d, "chain_leaf", self.chain_leaf)
        self.chain_file = pki.write_ca(d, "chain_inter", self.inter)
        (d / "index.html").write_text("merhaba interop")
        self.big = os.urandom(3 * 1024 * 1024 + 17)
        (d / "big.bin").write_bytes(self.big)

    def server(self, key="p256", *args, www="-WWW", chain=None):
        cert, k = self.leaf[key]
        extra = ["-cert_chain", chain] if chain else []
        return SServer("-cert", cert, "-key", k, "-tls1_3", *extra, www, *args, cwd=str(self.dir))


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    return Env(tmp_path_factory.mktemp("interop"))


@pytest.fixture(autouse=True)
def _reset_tickets():
    session_tickets.default_cache.clear()
    session_tickets.enable_resumption(False)
    yield
    session_tickets.default_cache.clear()
    session_tickets.enable_resumption(False)


def _get(mode, port, ca, path="/index.html", profile="chrome_131", host="localhost", **kw):
    url = f"https://{host}:{port}{path}"
    if mode == "sync":
        with Session(impersonate=profile, verify=ca, timeout=15, **kw) as s:
            return s.get(url)

    async def run():
        async with AsyncSession(impersonate=profile, verify=ca, timeout=15, **kw) as s:
            return await s.get(url)
    return asyncio.run(run())


MODES = ["sync", "async"]


def _rejects(fn, pattern=r".", *, allowed=(ConnectionError, OSError, ValueError)):
    """Bağlantı REDDEDİLMELİ; hata sınıfı beklenen aileden ve mesaj anlamlı olmalı."""
    with pytest.raises(Exception) as ei:
        fn()
    e = ei.value
    msg = f"{type(e).__name__}: {e}"
    if os.environ.get("INTEROP_SHOW"):
        print("\nREJ>", msg[:300])
    assert isinstance(e, allowed) or type(e).__name__.endswith(("Error", "Exception")), msg
    assert re.search(pattern, msg, re.I | re.S), f"hata mesajı anlamsız/yanlış: {msg}"
    assert len(str(e)) > 15, f"hata mesajı çok kısa: {msg}"
    return msg


# --------------------------------------------------------------------------- TLS 1.3 matris: suite × grup

@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("group", GROUPS)
@pytest.mark.parametrize("suite", SUITES)
def test_suite_grup_matrisi(env, suite, group, mode):
    with env.server("p256", "-ciphersuites", suite, "-groups", group) as s:
        r = _get(mode, s.port, env.ca_path)
    assert r.status_code == 200 and r.content == b"merhaba interop"


@pytest.mark.parametrize("mode", MODES)
def test_sadece_p256_sunan_sunucu_hrr_yolu(env, mode):
    """İstemci ilk ClientHello'da x25519 payı yollar; P-256-only sunucu HelloRetryRequest ister."""
    with env.server("p256", "-groups", "P-256", "-msg") as s:
        r = _get(mode, s.port, env.ca_path)
        s.wait_line("HelloRetryRequest|Retry", 3) if False else None
        log = "".join(s.log)
    assert r.status_code == 200 and r.content == b"merhaba interop"
    # HRR gerçekten yaşandı mı: sunucu iki ClientHello okudu
    assert log.count("ClientHello") >= 2, "HRR yolu tetiklenmedi: " + log[:600]


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("group", ["X25519", "P-256"])
def test_profil_matrisi(env, profile, group):
    with env.server("p256", "-groups", group) as s:
        r = _get("sync", s.port, env.ca_path, profile=profile)
    assert r.status_code == 200


# --------------------------------------------------------------------------- sertifika matrisi

@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key", KEYS)
def test_sertifika_turleri(env, key, mode):
    with env.server(key) as s:
        r = _get(mode, s.port, env.ca_path)
    assert r.status_code == 200 and r.content == b"merhaba interop"


@pytest.mark.parametrize("mode", MODES)
def test_ara_sertifikali_zincir(env, mode):
    cert, key = env.chain_cert, env.chain_key
    with SServer("-cert", cert, "-key", key, "-cert_chain", env.chain_file, "-tls1_3", "-WWW",
                 cwd=str(env.dir)) as s:
        r = _get(mode, s.port, env.ca_path)
    assert r.status_code == 200


@pytest.mark.parametrize("sigalg", ["rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512"])
def test_rsa_pss_varyantlari(env, sigalg):
    with env.server("rsa2048", "-sigalgs", sigalg) as s:
        r = _get("sync", s.port, env.ca_path)
    assert r.status_code == 200


@pytest.mark.parametrize("mode", MODES)
def test_ed25519_sertifika_tarayici_profili_gibi_reddedilir(env, mode):
    """Chrome/Firefox/Safari signature_algorithms'ta ed25519 ilan etmez; Ed25519-only sunucu
    handshake_failure ile reddedilir (gerçek tarayıcılarla aynı davranış, anlamlı alert metniyle)."""
    with env.server("ed25519") as s:
        _rejects(lambda: _get(mode, s.port, env.ca_path), r"handshake_failure|alert 40")


# --------------------------------------------------------------------------- ALPN

@pytest.mark.parametrize("mode", MODES)
def test_alpn_http11(env, mode):
    with env.server("p256", "-alpn", "http/1.1") as s:
        r = _get(mode, s.port, env.ca_path)
    assert r.status_code == 200 and r.content == b"merhaba interop"


@pytest.mark.parametrize("mode", MODES)
def test_alpn_yok_http11e_duser(env, mode):
    with env.server("p256") as s:  # sunucu ALPN uzantısına yanıt vermez
        r = _get(mode, s.port, env.ca_path)
    assert r.status_code == 200


def _h2_server(env, stop):
    """Python ssl (OpenSSL) + h2 kütüphanesi: ALPN=h2 seçen bağımsız HTTP/2 sunucusu."""
    import ssl

    import h2.config
    import h2.connection
    import h2.events
    cert, key = env.p256
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["h2"])
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(8)
    ls.settimeout(0.2)
    seen = []

    def handle(c):
        try:
            c.settimeout(5)
            tc = ctx.wrap_socket(c, server_side=True)
            seen.append(tc.selected_alpn_protocol())
            conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False))
            conn.initiate_connection()
            tc.sendall(conn.data_to_send())
            while True:
                data = tc.recv(65535)
                if not data:
                    return
                for ev in conn.receive_data(data):
                    if isinstance(ev, h2.events.RequestReceived):
                        conn.send_headers(ev.stream_id, [(":status", "200"), ("content-type", "text/plain")])
                        conn.send_data(ev.stream_id, b"h2 interop", end_stream=True)
                tc.sendall(conn.data_to_send())
        except Exception:
            pass
        finally:
            c.close()

    def loop():
        while not stop.is_set():
            try:
                c, _ = ls.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=handle, args=(c,), daemon=True).start()
        ls.close()

    threading.Thread(target=loop, daemon=True).start()
    return ls.getsockname()[1], seen



# --------------------------------------------------------------------------- büyük yanıt / record bölme

@pytest.mark.parametrize("mode", MODES)
def test_buyuk_yanit_record_bolme(env, mode):
    with env.server("p256", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256") as s:
        r = _get(mode, s.port, env.ca_path, path="/big.bin")
    assert r.status_code == 200 and len(r.content) == len(env.big)
    assert hashlib.sha256(r.content).digest() == hashlib.sha256(env.big).digest()


@pytest.mark.parametrize("suite", SUITES[:2])
def test_buyuk_yanit_aes(env, suite):
    with env.server("p256", "-ciphersuites", suite) as s:
        r = _get("sync", s.port, env.ca_path, path="/big.bin")
    assert hashlib.sha256(r.content).digest() == hashlib.sha256(env.big).digest()


# --------------------------------------------------------------------------- KeyUpdate

def _keyupdate_server(env):
    # -www/-WWW KeyUpdate komutunu okumaz; etkileşimli kipte yanıtı biz stdin'den yazarız.
    cert, key = env.p256
    return SServer("-cert", cert, "-key", key, "-tls1_3", "-crlf", "-msg")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("cmd", ["k", "K"])
def test_keyupdate_sunucudan(env, cmd, mode):
    """k: yalnızca sunucu anahtarı döner; K: istemciden de karşı güncelleme istenir."""
    with _keyupdate_server(env) as s:
        res = {}

        def client():
            try:
                res["r"] = _get(mode, s.port, env.ca_path)
            except Exception as e:  # pragma: no cover
                res["e"] = e

        t = threading.Thread(target=client)
        t.start()
        s.wait_line("GET /index.html", 10)
        # s_server stdin'i satır satır komut sayar; yazımlar birleşmesin diye aralara bekleme koyuyoruz.
        for line in ("HTTP/1.0 200 OK\nContent-Type: text/plain\n\nbirinci", cmd, "ikinci", cmd, "ucuncu", "q"):
            s.send(line + "\n")
            time.sleep(0.15)
        t.join(15)
        assert "e" not in res, res.get("e")
    log = "".join(s.log)
    assert log.count("KeyUpdate") >= (4 if cmd == "K" else 2), "KeyUpdate gerçekten yapılmadı: " + log[-600:]
    if cmd == "K":  # istemci de karşılık verdi: sunucu gelen (<<<) KeyUpdate gördü
        assert re.search(r"<<<.*KeyUpdate", log), "istemci KeyUpdate yanıtı yok"
    body = res["r"].content.decode()
    assert res["r"].status_code == 200
    assert body.replace("\r", "").split() == ["birinci", "ikinci", "ucuncu"]


# --------------------------------------------------------------------------- session ticket / resumption

@pytest.mark.parametrize("mode", [
    "sync",
    pytest.param("async", marks=pytest.mark.xfail(
        strict=True, reason="AsyncSession (tls13 çekirdeği) NewSessionTicket'ı saklamıyor/PSK kullanmıyor; "
                            "resumption yalnızca senkron TLSAdapter yolunda (NOTES3: uyum -> asyncson)")),
])
def test_session_ticket_resumption(env, mode):
    session_tickets.enable_resumption(True)
    with env.server("p256", www="-www") as s:
        r1 = _get(mode, s.port, env.ca_path, path="/")
        assert r1.status_code == 200 and b"New, TLSv1.3" in r1.content
        assert len(session_tickets.default_cache) >= 1
        r2 = _get(mode, s.port, env.ca_path, path="/")
    assert r2.status_code == 200
    assert b"Reused, TLSv1.3" in r2.content, r2.content[:600]


def test_resumption_bayragi_kapaliyken_ticket_saklanmaz(env):
    with env.server("p256", www="-www") as s:
        _get("sync", s.port, env.ca_path, path="/")
        r2 = _get("sync", s.port, env.ca_path, path="/")
    assert len(session_tickets.default_cache) == 0
    assert b"New, TLSv1.3" in r2.content


# --------------------------------------------------------------------------- NEGATİF: sertifika

def _srv_cert(env, cert, key, *extra, chain=None):
    a = ["-cert", cert, "-key", key, "-tls1_3", "-WWW"]
    if chain:
        a += ["-cert_chain", chain]
    return SServer(*a, *extra, cwd=str(env.dir))


@pytest.mark.parametrize("mode", MODES)
def test_suresi_dolmus_sertifika(env, mode):
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    leaf = pki.make_cert("localhost", env.ca, "p256", not_before=now - dt.timedelta(days=30),
                         not_after=now - dt.timedelta(days=1))
    c, k = pki.write(env.dir, "expired", leaf)
    with _srv_cert(env, c, k) as s:
        _rejects(lambda: _get(mode, s.port, env.ca_path), r"expir|süre|geçerlilik|valid|not.?after")


@pytest.mark.parametrize("mode", MODES)
def test_henuz_gecerli_olmayan_sertifika(env, mode):
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    leaf = pki.make_cert("localhost", env.ca, "p256", not_before=now + dt.timedelta(days=2),
                         not_after=now + dt.timedelta(days=9))
    c, k = pki.write(env.dir, "future", leaf)
    with _srv_cert(env, c, k) as s:
        _rejects(lambda: _get(mode, s.port, env.ca_path), r"not.?yet|henüz|valid|geçerli|not.?before")


@pytest.mark.parametrize("mode", MODES)
def test_yanlis_hostname(env, mode):
    leaf = pki.make_cert("baska.example", env.ca, "p256")
    c, k = pki.write(env.dir, "wronghost", leaf)
    with _srv_cert(env, c, k) as s:
        _rejects(lambda: _get(mode, s.port, env.ca_path), r"host|ad[ıi]|name|SAN|eşleş|match")


@pytest.mark.parametrize("mode", MODES)
def test_ip_ile_baglanma_san_ip_yoksa(env, mode):
    """Sertifikada yalnızca DNS SAN var; 127.0.0.1 ile bağlanınca reddedilmeli."""
    with env.server("p256") as s:
        _rejects(lambda: _get(mode, s.port, env.ca_path, host="127.0.0.1"), r"host|ad[ıi]|name|SAN|IP|match")


@pytest.mark.parametrize("mode", MODES)
def test_guvenilmeyen_ca(env, mode):
    with env.server("p256") as s:
        _rejects(lambda: _get(mode, s.port, env.other_ca_path), r"CA|güven|trust|chain|zincir|issuer|verify|imza")


@pytest.mark.parametrize("mode", MODES)
def test_kendinden_imzali(env, mode):
    leaf = pki.make_cert("localhost", None, "p256")
    c, k = pki.write(env.dir, "selfsigned", leaf)
    with _srv_cert(env, c, k) as s:
        _rejects(lambda: _get(mode, s.port, env.ca_path), r"self|kendinden|CA|güven|trust|chain|zincir|verify|imza")


@pytest.mark.parametrize("mode", MODES)
def test_zincirde_eksik_ara_sertifika(env, mode):
    with _srv_cert(env, env.chain_cert, env.chain_key) as s:  # ara sertifika gönderilmiyor
        _rejects(lambda: _get(mode, s.port, env.ca_path), r"CA|güven|trust|chain|zincir|issuer|ara|verify|imza")


@pytest.mark.parametrize("mode", MODES)
def test_ca_olmayan_sertifikayla_imzalanmis_yaprak(env, mode):
    """Yaprak sertifika, bir başka yaprak tarafından imzalanmış (BasicConstraints CA=false)."""
    fake_ca = pki.make_cert("sahte ara", env.ca, "p256", ca=False, sans=["sahte"])
    leaf = pki.make_cert("localhost", fake_ca, "p256")
    c, k = pki.write(env.dir, "badca_leaf", leaf)
    with _srv_cert(env, c, k, chain=pki.write_ca(env.dir, "badca_inter", fake_ca)) as s:
        _rejects(lambda: _get(mode, s.port, env.ca_path), r"CA|basic|constraint|chain|zincir|verify|issuer|güven")


@pytest.mark.parametrize("mode", MODES)
def test_istemci_sertifikasi_isteyen_sunucu(env, mode):
    """-Verify: sunucu mTLS ister; fasthttpc sertifika sunamaz -> sessizce başarılı sayılmamalı."""
    with env.server("p256", "-Verify", "1", "-CAfile", env.ca_path) as s:
        _rejects(lambda: _get(mode, s.port, env.ca_path), r"alert|sertifika|certificate|required|handshake|kapat|closed|reset")


# --------------------------------------------------------------------------- NEGATİF: protokol/parametre

def _plain_server(env, *args, www="-WWW"):
    cert, key = env.p256
    return SServer("-cert", cert, "-key", key, www, *args, cwd=str(env.dir))


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("flag", ["-tls1", "-tls1_1"])
def test_tls10_11_sunucu(env, flag, mode):
    with _plain_server(env, flag, "-cipher", "DEFAULT:@SECLEVEL=0") as s:
        _rejects(lambda: _get(mode, s.port, env.ca_path), r"1\.3|sürüm|version|alert|protocol")


@pytest.mark.parametrize("mode", MODES)
def test_sadece_ffdhe2048_grubu(env, mode):
    with env.server("p256", "-groups", "ffdhe2048") as s:
        _rejects(lambda: _get(mode, s.port, env.ca_path), r"grup|group|alert|handshake|40|uyumlu|ortak")


@pytest.mark.parametrize("mode", MODES)
def test_tls12_sadece_cbc(env, mode):
    with _plain_server(env, "-tls1_2", "-cipher", "AES128-SHA:ECDHE-RSA-AES128-SHA:AES256-SHA") as s:
        _rejects(lambda: _get(mode, s.port, env.ca_path), r"1\.[23]|sürüm|version|alert|protocol|suite|cipher|CBC|handshake")


@pytest.mark.parametrize("mode", MODES)
def test_sunucu_hic_tls_konusmuyor(env, mode):
    """TLS olmayan düz TCP sunucu (HTTP cevaplıyor): net hata, takılma yok."""
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(2)
    port = ls.getsockname()[1]

    def srv():
        c, _ = ls.accept()
        c.recv(4096)
        c.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        c.close()

    threading.Thread(target=srv, daemon=True).start()
    try:
        _rejects(lambda: _get(mode, port, env.ca_path), r"TLS|record|alert|handshake|protocol|kayıt|beklenmeyen|unexpected")
    finally:
        ls.close()
