"""Gerçek OpenSSL sunucusu ile istemci arasına record düzeyinde hata enjekte eden aracı (interop.relay):
kesilen bağlantılar, bozulan/tekrarlanan/enjekte edilen record'lar.

Beklenti: HER durumda istemci (senkron ve async) kısa sürede anlamlı bir hata verir; eksik/bozuk yanıtı
başarıyla dönmez, takılmaz.
"""
from __future__ import annotations

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from interop.relay import Relay  # noqa: E402
from test_interop_openssl import MODES, Env, _get, _rejects  # noqa: E402,F401
from test_interop_openssl import env  # noqa: E402,F401  (fixture)

pytestmark = pytest.mark.interop


@pytest.fixture(scope="module", autouse=True)
def _cl_file(env):
    """`s_server -WWW` yanıtlarında Content-Length yok (bağlantı-kapanışlı gövde: close_notify'sız EOF bilinçli
    olarak tolere edilir). Truncation testleri için başlıkları dosyada olan (-HTTP) bir yanıt hazırla."""
    body = env.big
    head = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n" % len(body)
    (env.dir / "big_cl.http").write_bytes(head + body)
    (env.dir / "small_cl.http").write_bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")


def _run(env, mode, s2c=None, c2s=None, path="/index.html", expect=None, **srv_args):
    """s_server + Relay kurar; istemci Relay portuna bağlanır. `expect`: hata regex'i ya da None (başarı)."""
    with env.server("p256", *srv_args.get("args", ())) as srv, Relay(srv.port, s2c=s2c, c2s=c2s) as rl:
        t0 = time.time()
        if expect is None:
            r = _get(mode, rl.port, env.ca_path, path=path)
            return r, rl
        msg = _rejects(lambda: _get(mode, rl.port, env.ca_path, path=path), expect)
        assert time.time() - t0 < 12, "hata geç/takılarak geldi"
        return msg, rl


GENERIC = r"."


# -------------------------------------------------------------- handshake sırasında kesinti

@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("cut_at", [0, 1, 2, 3, 4])
def test_handshake_ortasinda_baglanti_kesilir(env, mode, cut_at):
    """Sunucudan gelen cut_at. record'tan önce TCP FIN (alert yok): hata, takılma yok."""
    def s2c(i, t, rec):
        return Relay.CUT if i >= cut_at else rec
    _run(env, mode, s2c=s2c, expect=GENERIC)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("idx", [0, 1, 2, 3, 4, 5])
def test_handshake_record_bit_cevirme(env, mode, idx):
    """Sunucudan gelen idx. record'un ortasında 1 bit çevrilir: ServerHello (transcript/anahtar) veya
    şifreli handshake (AEAD etiketi) bozulur -> reddedilmeli."""
    def s2c(i, t, rec):
        if i != idx:
            return rec
        pos = 5 + (len(rec) - 5) // 2
        return rec[:pos] + bytes([rec[pos] ^ 0x01]) + rec[pos + 1:]
    _run(env, mode, s2c=s2c, expect=GENERIC)


@pytest.mark.parametrize("mode", MODES)
def test_server_hello_random_degisirse(env, mode):
    """ServerHello.random'ın 1 bitini çevir: türetilen trafik anahtarları farklı olur."""
    def s2c(i, t, rec):
        if i == 0 and t == 22:
            pos = 5 + 4 + 2 + 5
            return rec[:pos] + bytes([rec[pos] ^ 0x80]) + rec[pos + 1:]
        return rec
    _run(env, mode, s2c=s2c, expect=GENERIC)


# -------------------------------------------------------------- uygulama verisi aşaması

@pytest.mark.parametrize("mode", MODES)
def test_yanit_ortasinda_close_notify_olmadan_kesilirse(env, mode):
    """Truncation saldırısı: 3 MB'lık yanıt yarıda TCP FIN ile biter (close_notify yok).
    İstemci eksik gövdeyi tamam diye döndürmemeli."""
    state = {"data": 0}

    def s2c(i, t, rec):
        if t == 23:
            state["data"] += 1
            if state["data"] > 12:       # el sıkışma + bilet + birkaç yüz KB sonrası
                return Relay.CUT
        return rec
    with env.server("p256", www="-HTTP") as srv, Relay(srv.port, s2c=s2c) as rl:
        try:
            r = _get(mode, rl.port, env.ca_path, path="/big_cl.http")
        except Exception as e:  # beklenen: hata
            assert len(str(e)) > 10
            return
        pytest.fail(f"kesik yanıt başarıyla döndü: {r.status_code} {len(r.content)} bayt / {len(env.big)}")


@pytest.mark.parametrize("mode", MODES)
def test_uygulama_record_bit_cevirme(env, mode):
    """Yanıt verisi taşıyan bir record'ta 1 bit çevrilir -> bad_record_mac, içerik teslim edilmez."""
    state = {"n": 0}

    def s2c(i, t, rec):
        if t == 23:
            state["n"] += 1
            if state["n"] == 7:
                pos = len(rec) - 20
                return rec[:pos] + bytes([rec[pos] ^ 0x40]) + rec[pos + 1:]
        return rec
    with env.server("p256", www="-HTTP") as srv, Relay(srv.port, s2c=s2c) as rl:
        try:
            r = _get(mode, rl.port, env.ca_path, path="/big_cl.http")
        except Exception as e:
            assert len(str(e)) > 10
            return
        pytest.fail(f"bozuk record kabul edildi ({len(r.content)} bayt)")


@pytest.mark.parametrize("mode", MODES)
def test_tekrarlanan_record_reddedilir(env, mode):
    """Aynı şifreli record iki kez iletilir (replay): sıra numarası kayar -> bad_record_mac."""
    state = {"n": 0}

    def s2c(i, t, rec):
        if t == 23:
            state["n"] += 1
            if state["n"] == 7:
                return rec + rec
        return rec
    with env.server("p256", www="-HTTP") as srv, Relay(srv.port, s2c=s2c) as rl:
        try:
            r = _get(mode, rl.port, env.ca_path, path="/big_cl.http")
        except Exception as e:
            assert len(str(e)) > 10
            return
        pytest.fail(f"tekrarlanan record kabul edildi ({len(r.content)} bayt)")


@pytest.mark.parametrize("mode", MODES)
def test_record_sirasi_degisirse(env, mode):
    """İki ardışık uygulama record'u yer değiştirir -> bad_record_mac."""
    held = {}

    def s2c(i, t, rec):
        if t == 23:
            held["n"] = held.get("n", 0) + 1
            if held["n"] == 7:
                held["rec"] = rec
                return b""
            if held["n"] == 8 and "rec" in held:
                return rec + held.pop("rec")
        return rec
    with env.server("p256", www="-HTTP") as srv, Relay(srv.port, s2c=s2c) as rl:
        try:
            r = _get(mode, rl.port, env.ca_path, path="/big_cl.http")
        except Exception as e:
            assert len(str(e)) > 10
            return
        pytest.fail(f"sırası bozulan record'lar kabul edildi ({len(r.content)} bayt)")


@pytest.mark.parametrize("mode", MODES)
def test_enjekte_edilen_duz_alert_yanittan_once(env, mode):
    """Handshake bittikten sonra, yanıttan hemen önce araya şifresiz bir close_notify alert record'u
    enjekte edilir (kimliği doğrulanmamış kapatma): istemci bunu sessizce 'boş yanıt' saymamalı."""
    state = {"n": 0}

    def s2c(i, t, rec):
        if t == 23:
            state["n"] += 1
            if state["n"] == 7:      # 4 handshake + 2 bilet = 6; 7. = yanıtın ilk record'u
                return b"\x15\x03\x03\x00\x02\x01\x00" + rec
        return rec
    with env.server("p256", www="-HTTP") as srv, Relay(srv.port, s2c=s2c) as rl:
        try:
            r = _get(mode, rl.port, env.ca_path, path="/small_cl.http")
        except Exception as e:
            assert len(str(e)) > 10
            return
        # Yanıt yine de gelmişse bile enjekte edilen alert'in sonrasında geçerli veri alınmış olamaz
        assert r.content == b"hello", "şifresiz alert sonrası boş ama 'başarılı' yanıt"
