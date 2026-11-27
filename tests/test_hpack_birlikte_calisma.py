"""HPACK kodlayıcı: bağımsız HTTP/2 uygulamalarıyla birlikte-çalışma ve bağlantı düzeyi davranış.

* Bağımsız sunucu: Python ``ssl`` (OpenSSL TLS 1.3) + ``h2`` kütüphanesi (kendi ``hpack``
  çözücüsüyle). Senkron ``Session`` ve ``AsyncSession`` aynı bağlantıda çok istek gönderir;
  sunucu ortadaki istekte SETTINGS_HEADER_TABLE_SIZE'ı küçültüp sonra büyütür. Her
  isteğin başlıkları sunucunun çözdüğü hâliyle geri döner ve ham HEADERS blokları
  sunucu tarafında (çözmeden önce) kaydedilir: dinamik tablo yeniden kullanımı ve size
  update'in hangi blokta, hangi baytla gittiği doğrudan görülür.
* Sahte ham-frame sunucusu (bağımlılıksız): AsyncSession'ın EŞZAMANLI stream'lerinde
  başlık bloklarının telde kodlandıkları sırayla gittiği (sunucunun tek çözücüsü
  bozulmadan çözer).
"""
from __future__ import annotations

import asyncio
import json
import socket
import ssl
import threading

import pytest

from fasthttpc import AsyncSession, Session
from fasthttpc.protocol.http2_parser import FrameType, HTTP2Frame, _strip_headers_frame_fields

from async_fakes import start_h2
from interop import pki as ipki
from netutil import listen_dual
from tls13_fakeserver import PKI

h2 = pytest.importorskip("h2", reason="h2 kütüphanesi kurulu değil (pip install h2)")

PROFILLER = ["chrome_158", "firefox_160", "safari_27"]
KUCULT, BUYUT = 4, 8            # bu sıradaki yanıttan ÖNCE sunucu tablo boyutunu değiştirir
N_ISTEK = 12


# ---------------------------------------------------------------- bağımsız h2 sunucusu
class H2LibSunucu:
    """OpenSSL TLS + h2: her isteğe çözdüğü başlıkları JSON olarak döner."""

    def __init__(self, cert: str, key: str, degisimler: "dict[int, int] | None" = None):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ctx.load_cert_chain(cert, key)
        self.ctx.set_alpn_protocols(["h2"])
        self.degisimler = degisimler or {}       # yanıt sırası -> yeni HEADER_TABLE_SIZE
        self.bloklar: "list[bytes]" = []         # ham HEADERS blokları, telde geliş sırasıyla
        self.baglantilar = 0
        self.hatalar: "list[BaseException]" = []
        self._dur = threading.Event()
        self._dinleyiciler, self.port = listen_dual(8)    # paralel süreçlerde port yarışına dayanıklı
        for s in self._dinleyiciler:
            s.settimeout(0.2)

    def __enter__(self):
        for s in self._dinleyiciler:
            threading.Thread(target=self._kabul, args=(s,), daemon=True).start()
        return self

    def __exit__(self, *exc):
        self._dur.set()

    def _kabul(self, ls):
        while not self._dur.is_set():
            try:
                c, _ = ls.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._isle, args=(c,), daemon=True).start()
        ls.close()

    def _isle(self, c):
        from h2.config import H2Configuration
        from h2.connection import H2Connection
        from h2.events import RequestReceived, StreamEnded
        from h2.settings import SettingCodes
        tc = None
        try:
            c.settimeout(10)
            tc = self.ctx.wrap_socket(c, server_side=True)    # c'yi devralır (detach)
            self.baglantilar += 1
            conn = H2Connection(H2Configuration(client_side=False, header_encoding=None))
            conn.initiate_connection()
            tc.sendall(conn.data_to_send())
            istekler: dict = {}
            sira = 0
            ham = b""
            preface = False
            parca = bytearray()
            while not self._dur.is_set():
                data = tc.recv(65536)
                if not data:
                    return
                # Ham HEADERS bloklarını h2 çözmeden ÖNCE kaydet.
                ham += data
                if not preface and len(ham) >= 24:
                    ham, preface = ham[24:], True
                while preface and len(ham) >= 9:
                    ln = int.from_bytes(ham[:3], "big")
                    if len(ham) < 9 + ln:
                        break
                    f = HTTP2Frame.parse(ham[:9 + ln])
                    ham = ham[9 + ln:]
                    if f.type == FrameType.HEADERS:
                        parca = bytearray(_strip_headers_frame_fields(f))
                    elif f.type == FrameType.CONTINUATION:
                        parca += f.payload
                    if f.type in (FrameType.HEADERS, FrameType.CONTINUATION) and f.flags & 0x4:
                        self.bloklar.append(bytes(parca))
                for ev in conn.receive_data(data):
                    if isinstance(ev, RequestReceived):
                        istekler[ev.stream_id] = [(k.decode("latin-1"), v.decode("latin-1"))
                                                  for k, v in ev.headers]
                    elif isinstance(ev, StreamEnded):
                        sira += 1
                        if sira in self.degisimler:
                            # Yanıttan ÖNCE: istemci bunu yanıtı almadan işler.
                            conn.update_settings({SettingCodes.HEADER_TABLE_SIZE: self.degisimler[sira]})
                        body = json.dumps(istekler.pop(ev.stream_id)).encode()
                        conn.send_headers(ev.stream_id, [(":status", "200"),
                                                         ("content-length", str(len(body)))])
                        conn.send_data(ev.stream_id, body, end_stream=True)
                tc.sendall(conn.data_to_send())
        except Exception as e:  # noqa: BLE001 - test iş parçacığı: hatayı teste taşı
            if not self._dur.is_set():
                self.hatalar.append(e)
        finally:
            (tc or c).close()


@pytest.fixture(scope="module")
def sertifikalar(tmp_path_factory):
    d = tmp_path_factory.mktemp("hpack_interop")
    ca = ipki.make_cert("HPACK Test CA", None, "p256", ca=True)
    cert, key = ipki.write(d, "leaf", ipki.make_cert("localhost", ca, "p256"))
    return cert, key, ipki.write_ca(d, "ca", ca)


def _istek(i: int) -> "tuple[str, dict]":
    # Her istekte değişen değerler (yol, x-sira, bir cookie parçası) + sabitler.
    return (f"/p{i}?q={'x' * (i % 5)}",
            {"X-Sira": str(i), "X-Sabit": "-".join(["ayni deger"] * 4),
             "Cookie": f"oturum=a1b2c3d4e5f6a7b8c9d0e1f2; sayac={i}; tema=koyu"})


def _cozulen_kontrol(profil: str, i: int, cozulen: "list[list[str]]", birlesik: bool = True) -> None:
    path, hdrs = _istek(i)
    d = dict((k, v) for k, v in cozulen if k != "cookie")
    assert d[":path"] == path and d[":method"] == "GET" and d[":scheme"] == "https"
    assert d["x-sira"] == str(i) and d["x-sabit"] == hdrs["X-Sabit"]
    assert d["user-agent"].startswith("Mozilla/5.0")
    # h2, parçalanmış cookie alanlarını uygulamaya vermeden birleştirir (RFC 9113 §8.2.3;
    # parça sayısı _blok_kontrol'de ham bloklardan denetlenir). Ham çözücü parçaları görür.
    parcalar = _cookie_parcalari(i)
    beklenen = ["; ".join(parcalar)] if birlesik or profil.startswith("safari") else parcalar
    assert [v for k, v in cozulen if k == "cookie"] == beklenen


def _cookie_parcalari(i: int) -> "list[str]":
    return ["oturum=a1b2c3d4e5f6a7b8c9d0e1f2", f"sayac={i}", "tema=koyu"]


def _blok_kontrol(profil: str, bloklar: "list[bytes]") -> None:
    from hpack import Decoder
    assert len(bloklar) == N_ISTEK
    # Ham blokları bağımsız bir çözücüyle (hpack paketi) sırayla çöz: Chrome/Firefox cookie'yi
    # parçalara böler, Safari profili bölmez.
    dec = Decoder()
    dec.max_allowed_table_size = 65536
    for i, b in enumerate(bloklar):
        cookies = [v.decode() for k, v in dec.decode(b, raw=True) if k == b"cookie"]
        p = _cookie_parcalari(i)
        assert cookies == (["; ".join(p)] if profil.startswith("safari") else p), i
    # Dinamik tablo: 4096'lık tabloda sonraki istekler ilkinin küçük bir kesri (sabit
    # başlıklar tek bayt). 256 bayta küçülünce User-Agent vb. sığmaz -> bloklar yeniden
    # büyür; 65536'ya büyüyünce ilk blok yeniden ekler, sonrakiler yine küçüktür.
    uz = [len(b) for b in bloklar]
    kucuk = list(range(1, KUCULT)) + list(range(BUYUT + 1, N_ISTEK))
    assert all(uz[i] < uz[0] // 3 for i in kucuk), uz
    assert all(uz[i] > uz[0] // 2 for i in range(KUCULT, BUYUT + 1)), uz
    guncellemeli = [i for i, b in enumerate(bloklar) if b[0] & 0xE0 == 0x20]
    if profil.startswith("firefox"):
        # h2'nin ilk SETTINGS'indeki HEADER_TABLE_SIZE=4096 bile Firefox'ta güncelleme yazdırır
        # (SetMaxBufferSize); ilk ya da ikinci blokta (SETTINGS'in ne zaman işlendiğine bağlı).
        ilk = guncellemeli.pop(0)
        assert ilk in (0, 1) and bloklar[ilk].startswith(bytes.fromhex("3fe11f"))
    # Sunucu KUCULT. yanıttan önce 256, BUYUT. yanıttan önce 65536 ilan etti: güncelleme
    # tam bir sonraki istekte, bloğun başında.
    assert guncellemeli == [KUCULT, BUYUT]
    assert bloklar[KUCULT].startswith(bytes.fromhex("3fe101"))        # 256
    assert bloklar[BUYUT].startswith(bytes.fromhex("3fe1ff03"))       # 65536


@pytest.mark.parametrize("profil", PROFILLER)
def test_senkron_h2lib_cok_istek_tablo_boyutu_degisimi(sertifikalar, profil):
    cert, key, ca = sertifikalar
    with H2LibSunucu(cert, key, {KUCULT: 256, BUYUT: 65536}) as srv:
        with Session(impersonate=profil, verify=ca, timeout=10) as s:
            for i in range(N_ISTEK):
                path, hdrs = _istek(i)
                r = s.get(f"https://localhost:{srv.port}{path}", headers=hdrs)
                assert r.status_code == 200
                _cozulen_kontrol(profil, i, r.json())
    assert not srv.hatalar, srv.hatalar
    assert srv.baglantilar == 1
    _blok_kontrol(profil, srv.bloklar)


@pytest.mark.parametrize("profil", PROFILLER)
def test_async_h2lib_cok_istek_tablo_boyutu_degisimi(sertifikalar, profil):
    cert, key, ca = sertifikalar

    async def main(port):
        async with AsyncSession(impersonate=profil, verify=ca, timeout=10) as s:
            for i in range(N_ISTEK):
                path, hdrs = _istek(i)
                r = await s.get(f"https://localhost:{port}{path}", headers=hdrs)
                assert r.status_code == 200
                _cozulen_kontrol(profil, i, r.json())

    with H2LibSunucu(cert, key, {KUCULT: 256, BUYUT: 65536}) as srv:
        asyncio.run(asyncio.wait_for(main(srv.port), 60))
    assert not srv.hatalar, srv.hatalar
    assert srv.baglantilar == 1
    _blok_kontrol(profil, srv.bloklar)


@pytest.mark.parametrize("profil", PROFILLER)
def test_async_h2lib_eszamanli_streamler_kucuk_tabloyla(sertifikalar, profil):
    """Eşzamanlı istekler + küçük tablo (sürekli tahliye): h2'nin çözücüsü her bloğu
    doğru çözer, yani bloklar telde kodlandıkları sırayla gitti."""
    cert, key, ca = sertifikalar

    async def main(port):
        async with AsyncSession(impersonate=profil, verify=ca, timeout=10) as s:
            await s.get(f"https://localhost:{port}/isinma")          # SETTINGS işlensin
            rs = await asyncio.gather(*[
                s.get(f"https://localhost:{port}{_istek(i)[0]}", headers=_istek(i)[1])
                for i in range(30)])
            for i, r in enumerate(rs):
                _cozulen_kontrol(profil, i, r.json())

    with H2LibSunucu(cert, key, {1: 300}) as srv:
        asyncio.run(asyncio.wait_for(main(srv.port), 60))
    assert not srv.hatalar, srv.hatalar
    assert srv.baglantilar == 1


# ---------------------------------------------------------------- sahte ham-frame sunucusu
@pytest.fixture(scope="module")
def sahte_pki():
    return PKI("localhost")


def test_async_eszamanli_bloklar_tel_sirasinda_kodlanir(sahte_pki, tmp_path):
    """Sunucunun TEK çözücüsü blokları telde geliş sırasıyla çözer; istemci kodlama
    sırası tel sırasından saparsa değerler karışır ya da çözme hata verir."""
    ca = tmp_path / "ca.pem"
    ca.write_bytes(sahte_pki.ca_pem())

    async def script(c):
        await c.handshake(header_table=512, max_streams=100)
        while True:
            f = await c.next_frame()
            if f is None:
                return
            if f.type == FrameType.HEADERS and f.end_stream:
                body = json.dumps(c.requests[f.stream_id]["headers"]).encode()
                c.respond(f.stream_id, 200, [("content-type", "application/json")], body)
                await c.flush()

    async def main():
        srv, port, conns = await start_h2(sahte_pki, script)
        async with srv:
            async with AsyncSession(impersonate="chrome_158", verify=str(ca), timeout=10) as s:
                await s.get(f"https://localhost:{port}/isinma")
                for tur in range(2):
                    rs = await asyncio.gather(*[
                        s.get(f"https://localhost:{port}{_istek(i)[0]}", headers=_istek(i)[1])
                        for i in range(40)])
                    for i, r in enumerate(rs):
                        _cozulen_kontrol("chrome_158", i, r.json(), birlesik=False)
            assert len(conns) == 1
            # 512 baytlık tablo ilan edildi: istemci size update gönderdi, çözücü onu uyguladı.
            assert conns[0].decoder._max_size == 512

    asyncio.run(asyncio.wait_for(main(), 60))
