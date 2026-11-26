"""Saha testlerinde bulunan hataların regresyon testleri.

Yerel (loopback) TLS 1.3 sunucusuna karşı çalışır (saha/yerel_sunucu.py);
dış ağ gerekmez.
"""
import time

import pytest

from fasthttpc import Session
from fasthttpc.models.headers import Headers
from saha.yerel_sunucu import YerelSunucu


@pytest.fixture(scope="module")
def sv():
    with YerelSunucu() as s:
        yield s


@pytest.fixture
def sess(sv):
    with Session(verify=sv.ca_path, timeout=3, max_connections=2) as s:
        yield s


@pytest.mark.parametrize("yol,kod", [("/s204", 204), ("/s304", 304)])
def test_govdesiz_durum_kodlari_takilmaz(sv, sess, yol, kod):
    """204/304 Content-Length'siz yanıtta eskiden EOF beklenip zaman aşımı oluyordu."""
    t = time.monotonic()
    r = sess.get(sv.url + yol)
    assert r.status_code == kod and r.content == b""
    assert time.monotonic() - t < 2
    # bağlantı yeniden kullanılabilir kaldı
    assert sess.get(sv.url + "/id?i=ok").content == b"ok"


def test_connection_close_havuzu_sizdirmaz(sv, sess):
    """'Connection: close' yanıtı semaphore slotunu iade etmiyordu: N istek sonra kilit."""
    for _ in range(6):  # max_connections=2'den fazla
        assert sess.get(sv.url + "/close").content == b"kapanis"
    assert sess.get(sv.url + "/id?i=sonra").content == b"sonra"


def test_http10_kapanisla_biten_govde_closenotifysiz(sv, sess):
    """HTTP/1.0 + close_notify'sız EOF: gövde geçerli, hata fırlatılmamalı."""
    for _ in range(4):  # havuz sızıntısı da olmasın
        r = sess.get(sv.url + "/http10")
        assert r.status_code == 200 and r.content == b"http10-govde"


@pytest.mark.parametrize("yol", ["/cut", "/cutn"])
def test_eksik_content_length_govdesi_hata_verir(sv, sess, yol):
    """Content-Length'ten kısa gövde sessizce kısaltılıp başarı sayılmamalı."""
    with pytest.raises(ConnectionError):
        sess.get(sv.url + yol)
    assert sess.get(sv.url + "/id?i=x").content == b"x"  # havuz sağlam


def test_baslik_blogu_tamamlanmadan_kapanis_hata_verir(sv, sess):
    """Başlıklar CRLF CRLF ile bitmeden bağlantı kapanırsa yanıt GEÇERSİZDİR.

    Eskiden senkron yol bu yarım bloğu (sep=-1) yanıt sayıp ``200`` + çöp gövde dönüyordu
    (Windows CI'da openssl s_server dosyayı metin kipinde okuyup CRLF'leri LF yaptığında
    yakalandı). Async yol zaten hata veriyordu."""
    with pytest.raises(ConnectionError, match="başlık"):
        sess.get(sv.url + "/hdrcut")
    assert sess.get(sv.url + "/id?i=x").content == b"x"


def test_baslik_blogu_tamamlanmadan_kapanis_hata_verir_async(sv):
    import asyncio

    from fasthttpc import AsyncSession

    async def main():
        async with AsyncSession(verify=sv.ca_path, timeout=3) as s:
            with pytest.raises(ConnectionError, match="başlık"):
                await s.get(sv.url + "/hdrcut")
    asyncio.run(main())


def test_zaman_asimi_yeniden_denenmez(sv):
    """Yeniden kullanılan bağlantıda read timeout eskiden isteği ikinci kez gönderiyordu."""
    with Session(verify=sv.ca_path, timeout=1, max_connections=2) as s:
        s.get(sv.url + "/id?i=isin")          # bağlantı havuzda, yeniden kullanılacak
        n0 = sv.istek_sayisi
        t = time.monotonic()
        with pytest.raises(TimeoutError):
            s.post(sv.url + "/sleep?d=3&i=p", data=b"x")
        assert time.monotonic() - t < 2.5    # 2 x timeout değil
        assert sv.istek_sayisi - n0 == 1     # POST tek kez gitti


def test_chunked_trailer_tuketilir_ve_baglanti_temiz_kalir(sv):
    with Session(verify=sv.ca_path, timeout=3, max_connections=1) as s:
        r = s.get(sv.url + "/trailer")
        assert r.content == b"hello"
        b0 = sv.kabul_edilen_baglanti
        # trailer artığı bir sonraki yanıtın başına karışmamalı
        r2 = s.get(sv.url + "/id?i=sonraki")
        assert r2.status_code == 200 and r2.content == b"sonraki"
        assert sv.kabul_edilen_baglanti == b0   # bağlantı yeniden kullanıldı (bozulup yenilenmedi)


@pytest.mark.parametrize("metot,kod,hdr,beklenen", [
    ("GET", 200, {"content-length": "5"}, "length"),
    ("GET", 200, {"transfer-encoding": "chunked"}, "chunked"),
    ("GET", 200, {}, "eof"),
    ("GET", 204, {}, "none"),
    ("GET", 304, {}, "none"),
    ("GET", 101, {}, "none"),
    ("HEAD", 200, {"content-length": "5"}, "none"),
])
def test_body_framing(metot, kod, hdr, beklenen):
    h = Headers()
    for k, v in hdr.items():
        h[k] = v
    assert Session._body_framing(metot, kod, h) == beklenen


def test_body_framing_gecersiz_content_length_hatadir():
    # RFC 9112 §6.3 madde 5: geçersiz Content-Length kurtarılamaz çerçeveleme hatası
    # (eskiden sessizce "kapanışa kadar oku"ya düşülüyordu; bkz. FHC-09).
    h = Headers()
    h["content-length"] = "abc"
    with pytest.raises(ConnectionError, match="Content-Length"):
        Session._body_framing("GET", 200, h)


def test_timeout_total_damla_damla_sunucuyu_keser(sv):
    """read timeout her recv için ayrı işler; damla damla yanıt Timeout.total ile kesilmeli."""
    from fasthttpc import Timeout
    with Session(verify=sv.ca_path, timeout=Timeout(2, total=1.5), max_connections=2) as s:
        t = time.monotonic()
        with pytest.raises(TimeoutError):
            s.get(sv.url + "/drip?n=6&d=1")   # her parça 1 sn < read=2, toplam 6 sn
        assert time.monotonic() - t < 3
        # sınır istek başınadır: sonraki hızlı istek etkilenmez
        assert s.get(sv.url + "/id?i=hizli").content == b"hizli"


def test_timeout_total_yapilandirma():
    from fasthttpc import Timeout
    assert Timeout(5).total is None
    assert Timeout(5, total=2).total == 2.0
    assert Timeout(Timeout(5, total=2), read=1).total == 2.0   # kopyada korunur
    assert Timeout(5, total=2) != Timeout(5)
    with pytest.raises(ValueError):
        Timeout(5, total=0)


def test_ortak_session_coklu_thread_yanit_karismaz(sv):
    """20 thread ortak Session: her yanıt kendi isteğinin kimliğini taşımalı;
    çerez kavanozuna eşzamanlı yazım hata vermemeli; havuz kilitlenmemeli."""
    import threading
    hatalar = []

    with Session(verify=sv.ca_path, timeout=10, max_connections=5) as s:
        def is_(t):
            for j in range(15):
                kimlik = f"t{t}j{j}"
                try:
                    r = s.get(f"{sv.url}/setcookie?i={kimlik}")
                    r2 = s.post(f"{sv.url}/id?i={kimlik}", data=b"+p")
                    if r.content != kimlik.encode() or r2.content != (kimlik + "+p").encode():
                        hatalar.append((kimlik, r.content, r2.content))
                except Exception as e:  # noqa: BLE001
                    hatalar.append((kimlik, repr(e)))

        ths = [threading.Thread(target=is_, args=(t,), daemon=True) for t in range(20)]
        for t in ths:
            t.start()
        for t in ths:
            t.join(60)
        assert not any(t.is_alive() for t in ths), "deadlock"
        assert hatalar == []
        assert len(s.cookie_jar) == 20 * 15


def test_h2_stream_pencere_tablosu_sizdirmaz():
    """Uzun ömürlü h2 bağlantısında her istek _stream_windows'a bir girdi bırakıyordu."""
    from fasthttpc.protocol.http2_parser import (
        FrameFlags, FrameType, HTTP2Frame, Http2Connection, HpackEncoder,
    )
    import struct

    class Soket:
        def __init__(self):
            self.gelen = bytearray()
            self.gonderilen = bytearray()

        def send_record(self, data, content_type=0x17, use_app_keys=True):
            self.gonderilen += data

        def recv_record(self, skip_post_handshake=False):
            if not self.gelen:
                raise ConnectionError("veri bitti")
            v, self.gelen = bytes(self.gelen), bytearray()
            return v, 23

    sock = Soket()
    conn = Http2Connection(sock)
    enc = HpackEncoder()
    for i in range(50):
        sid = 1 + 2 * i
        blok = enc.encode([(":status", "200")])
        sock.gelen += HTTP2Frame(len(blok), FrameType.HEADERS, FrameFlags.END_HEADERS, sid, blok).serialize()
        sock.gelen += HTTP2Frame(2, FrameType.DATA, FrameFlags.END_STREAM, sid, b"ok").serialize()
        # bitmiş stream için geç gelen WINDOW_UPDATE de girdi bırakmamalı
        sock.gelen += HTTP2Frame(4, FrameType.WINDOW_UPDATE, 0, sid, struct.pack("!I", 10)).serialize()
        durum, _, govde = conn.request("GET", "a.example", "/", [])
        assert (durum, govde) == (200, b"ok")
    conn._handle_window_update(HTTP2Frame(4, FrameType.WINDOW_UPDATE, 0, 1, struct.pack("!I", 5)))
    assert len(conn._stream_windows) <= 1
