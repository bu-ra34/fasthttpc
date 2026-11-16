"""Yeniden kullanılan bağlantıda zaman aşımı (yerel sunucular, ağsız).

Hata: aynı sunucuya ikinci istek, açık kalan HTTP/2 (ya da keep-alive HTTP/1.1)
bağlantısından gittiğinde istek düzeyi ``timeout=`` ve ``Timeout.total``
uygulanmıyordu; soketin/bağlantının zaman aşımı İLK isteğinkinde kalıyordu
(async h2'de ilk istek ``timeout=None`` ise sonsuza dek bekleniyordu).

Sunucular ilk isteği yanıtlar, sonrakinde takılır (ya da damla damla gönderir);
ikinci istek yapılandırılan süre civarında kütüphanenin zaman aşımı hatasıyla
bitmelidir. Süre sınırları bilerek geniştir (yük altındaki CI için).
"""
import asyncio
import time

import pytest

from fasthttpc import AsyncSession, Session, Timeout
from fasthttpc.protocol.http2_parser import FrameType
from saha.yerel_sunucu import YerelSunucu

from async_fakes import RawH2Conn, start_h2
from test_streaming_h2 import _Sunucu
from tls13_fakeserver import PKI

HOST = "localhost"
TAKILMA = 30          # sunucunun takılı kaldığı süre (istemci bundan çok önce vazgeçmeli)
SINIR = 8             # 1-1.5 sn'lik zaman aşımı için cömert üst sınır

# asyncio.TimeoutError 3.11+'da yerleşik TimeoutError ile aynı; 3.10'da değil.
ZAMAN_ASIMI = (TimeoutError, asyncio.TimeoutError)


@pytest.fixture(scope="module")
def pki():
    return PKI(HOST)


@pytest.fixture
def ca(pki, tmp_path):
    p = tmp_path / "ca.pem"
    p.write_bytes(pki.ca_pem())
    return str(p)


@pytest.fixture(scope="module")
def sv():
    with YerelSunucu() as s:
        yield s


def run(coro, timeout=25):
    return asyncio.run(asyncio.wait_for(coro, timeout))


async def _damla(c: RawH2Conn, sid: int):
    try:
        for i in range(40):
            await c.flush()
            await asyncio.sleep(0.25)
            c.send(c.data(sid, b"x", end=(i == 39)))
        await c.flush()
    except (OSError, RuntimeError):
        pass


async def _ilk_yanit_sonra_takil(c: RawH2Conn):
    """h2: ilk isteği yanıtlar. Sonrakiler: ``/stall`` -> hiç yanıt yok;
    ``/stallbody`` -> başlıklar gider, gövde gelmez; ``/drip`` -> 0.25 sn arayla
    40 DATA frame'i (toplam ~10 sn)."""
    await c.handshake()
    yanitlanan = 0
    gorevler = set()          # arka planda damlatan görevler (betik okumayı sürdürür)
    while True:
        try:
            f = await c.next_frame(timeout=TAKILMA)
        except asyncio.TimeoutError:
            return
        if f is None:
            return
        if f.type != FrameType.HEADERS or not c.requests[f.stream_id]["ended"]:
            continue
        sid = f.stream_id
        yol = dict(c.requests[sid]["headers"])[":path"]
        if yanitlanan == 0 or yol == "/ok":
            c.respond(sid, 200, [("content-type", "text/plain")], b"ilk")
        elif yol == "/stallbody":
            c.send(c.response_headers(sid, 200, [("content-type", "text/plain")]))
        elif yol == "/drip":
            c.send(c.response_headers(sid, 200, [("content-type", "text/plain")]))
            gorevler.add(asyncio.ensure_future(_damla(c, sid)))
        # "/stall": yanıt YOK
        yanitlanan += 1
        await c.flush()


# ------------------------------------------------------------------ senkron HTTP/2
@pytest.fixture
def h2sv(pki):
    s = _Sunucu(pki, _ilk_yanit_sonra_takil)
    yield s
    s.stop()


def test_sync_h2_yeniden_kullanilan_baglantida_istek_timeout(h2sv, ca):
    with Session(impersonate="chrome_131", verify=ca, timeout=20) as s:
        url = f"https://localhost:{h2sv.port}"
        assert s.get(url + "/ok").content == b"ilk"
        t = time.monotonic()
        with pytest.raises(ZAMAN_ASIMI):
            s.get(url + "/stall", timeout=1)
        assert time.monotonic() - t < SINIR
        assert len(h2sv.conns) == 1          # ikinci istek aynı h2 bağlantısından gitti


def test_sync_h2_yeniden_kullanilan_baglantida_oturum_timeout(h2sv, ca):
    """İlk istek uzun ``timeout=`` ile bağlantıyı kurar; ikincisi oturumunkine (1 sn) uymalı."""
    with Session(impersonate="chrome_131", verify=ca, timeout=1) as s:
        url = f"https://localhost:{h2sv.port}"
        assert s.get(url + "/ok", timeout=20).content == b"ilk"
        t = time.monotonic()
        with pytest.raises(ZAMAN_ASIMI):
            s.get(url + "/stall")
        assert time.monotonic() - t < SINIR


def test_sync_h2_yeniden_kullanilan_baglantida_total(h2sv, ca):
    with Session(impersonate="chrome_131", verify=ca, timeout=Timeout(5, total=1.5)) as s:
        url = f"https://localhost:{h2sv.port}"
        assert s.get(url + "/ok").content == b"ilk"
        t = time.monotonic()
        with pytest.raises(ZAMAN_ASIMI):
            s.get(url + "/drip")              # her parça 0.25 sn < read=5, toplam ~10 sn
        assert time.monotonic() - t < SINIR


def test_sync_h2_akis_yeniden_kullanilan_baglantida_istek_timeout(h2sv, ca):
    with Session(impersonate="chrome_131", verify=ca, timeout=20) as s:
        url = f"https://localhost:{h2sv.port}"
        assert s.get(url + "/ok").content == b"ilk"
        r = s.get(url + "/stallbody", stream=True, timeout=1)
        assert r.status_code == 200
        t = time.monotonic()
        with pytest.raises(ZAMAN_ASIMI):
            b"".join(r.iter_bytes())
        assert time.monotonic() - t < SINIR
        r.close()


# ------------------------------------------------------------------ senkron HTTP/1.1
def test_sync_h1_keepalive_yeniden_kullanimda_istek_timeout(sv):
    with Session(verify=sv.ca_path, timeout=20, max_connections=1) as s:
        assert s.get(sv.url + "/id?i=a").content == b"a"
        b0 = sv.kabul_edilen_baglanti
        t = time.monotonic()
        with pytest.raises(ZAMAN_ASIMI):
            s.get(sv.url + "/sleep?d=6&i=b", timeout=1)
        assert time.monotonic() - t < 4
        assert sv.kabul_edilen_baglanti == b0     # aynı keep-alive bağlantısı


def test_sync_h1_keepalive_yeniden_kullanimda_oturum_timeout(sv):
    with Session(verify=sv.ca_path, timeout=1, max_connections=1) as s:
        assert s.get(sv.url + "/id?i=a", timeout=20).content == b"a"
        t = time.monotonic()
        with pytest.raises(ZAMAN_ASIMI):
            s.get(sv.url + "/sleep?d=6&i=b")
        assert time.monotonic() - t < 4


def test_sync_h1_akis_istek_timeout_total_ile(sv):
    """stream=True + istek düzeyi Timeout(read=1, total=...): akış okumaları
    oturumun read süresine (20 sn) değil isteğinkine (1 sn) uymalı."""
    with Session(verify=sv.ca_path, timeout=20, max_connections=1) as s:
        r = s.get(sv.url + "/lines?n=4&d=4", stream=True, timeout=Timeout(1, total=60))
        t = time.monotonic()
        with pytest.raises(ZAMAN_ASIMI):
            for _ in r.iter_lines():
                pass
        assert time.monotonic() - t < 4
        r.close()


def test_sync_h1_akis_yeniden_kullanimda_istek_timeout(sv):
    with Session(verify=sv.ca_path, timeout=20, max_connections=1) as s:
        assert s.get(sv.url + "/id?i=a").content == b"a"
        r = s.get(sv.url + "/lines?n=4&d=4", stream=True, timeout=1)
        t = time.monotonic()
        with pytest.raises(ZAMAN_ASIMI):
            for _ in r.iter_lines():
                pass
        assert time.monotonic() - t < 4
        r.close()


# ------------------------------------------------------------------ async HTTP/2
def _asess(ca, **kw):
    return AsyncSession(impersonate="chrome_131", verify=ca, **kw)


def test_async_h2_ilk_istek_timeout_none_sonra_istek_timeout(pki, ca):
    """İlk istek ``timeout=None`` ile h2 bağlantısını kurunca bağlantının okuma süresi
    None kalıyor, sonraki istekler (timeout=1 olsa da) sonsuza dek bekliyordu."""
    async def main():
        srv, port, conns = await start_h2(pki, _ilk_yanit_sonra_takil)
        async with srv:
            async with _asess(ca, timeout=20) as s:
                url = f"https://localhost:{port}"
                assert (await s.get(url + "/ok", timeout=None)).content == b"ilk"
                t = time.monotonic()
                with pytest.raises(ZAMAN_ASIMI):
                    await s.get(url + "/stall", timeout=1)
                assert time.monotonic() - t < SINIR
                assert len(conns) == 1
    run(main())


def test_async_h2_yeniden_kullanilan_baglantida_oturum_timeout(pki, ca):
    async def main():
        srv, port, conns = await start_h2(pki, _ilk_yanit_sonra_takil)
        async with srv:
            async with _asess(ca, timeout=1) as s:
                url = f"https://localhost:{port}"
                assert (await s.get(url + "/ok", timeout=20)).content == b"ilk"
                t = time.monotonic()
                with pytest.raises(ZAMAN_ASIMI):
                    await s.get(url + "/stall")
                assert time.monotonic() - t < SINIR
    run(main())


def test_async_h2_yeniden_kullanilan_baglantida_total(pki, ca):
    async def main():
        srv, port, conns = await start_h2(pki, _ilk_yanit_sonra_takil)
        async with srv:
            async with _asess(ca, timeout=Timeout(5, total=1.5)) as s:
                url = f"https://localhost:{port}"
                assert (await s.get(url + "/ok")).content == b"ilk"
                t = time.monotonic()
                with pytest.raises(ZAMAN_ASIMI):
                    await s.get(url + "/drip")
                assert time.monotonic() - t < SINIR
                # sınır istek başınadır: bağlantı/oturum kullanılabilir kalır
                assert (await s.get(url + "/ok")).content == b"ilk"
    run(main())


def test_async_h2_akis_yeniden_kullanilan_baglantida_istek_timeout(pki, ca):
    async def main():
        srv, port, conns = await start_h2(pki, _ilk_yanit_sonra_takil)
        async with srv:
            async with _asess(ca, timeout=20) as s:
                url = f"https://localhost:{port}"
                assert (await s.get(url + "/ok")).content == b"ilk"
                r = await s.get(url + "/stallbody", stream=True, timeout=1)
                assert r.status_code == 200
                t = time.monotonic()
                with pytest.raises(ZAMAN_ASIMI):
                    async for _ in r.aiter_bytes():
                        pass
                assert time.monotonic() - t < SINIR
                await r.aclose()
    run(main())


# ------------------------------------------------------------------ async HTTP/1.1
def test_async_h1_total_damla_damla_sunucuyu_keser(sv):
    async def main():
        async with AsyncSession(verify=sv.ca_path, timeout=Timeout(5, total=1.5)) as s:
            assert (await s.get(sv.url + "/id?i=a")).content == b"a"
            t = time.monotonic()
            with pytest.raises(ZAMAN_ASIMI):
                await s.get(sv.url + "/drip?n=8&d=1")    # her parça 1 sn < read=5
            assert time.monotonic() - t < 5
            assert (await s.get(sv.url + "/id?i=b")).content == b"b"
    run(main())


def test_async_h1_keepalive_yeniden_kullanimda_istek_timeout(sv):
    async def main():
        async with AsyncSession(verify=sv.ca_path, timeout=20) as s:
            assert (await s.get(sv.url + "/id?i=a")).content == b"a"
            t = time.monotonic()
            with pytest.raises(ZAMAN_ASIMI):
                await s.get(sv.url + "/sleep?d=6&i=b", timeout=1)
            assert time.monotonic() - t < 4
    run(main())
