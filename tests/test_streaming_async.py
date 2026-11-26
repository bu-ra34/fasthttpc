"""AsyncSession akış testleri (yerel TLS 1.3 h1 sunucusu; ağsız)."""
import asyncio
import gzip
import time
import tracemalloc

import pytest

from fasthttpc import AsyncSession
from fasthttpc.streaming import ResponseNotRead, StreamClosed
from saha.yerel_sunucu import YerelSunucu, govde_uret


@pytest.fixture(scope="module")
def sv():
    with YerelSunucu() as s:
        yield s


def run(coro, timeout=60):
    return asyncio.run(asyncio.wait_for(coro, timeout))


def S(sv, **kw):
    kw.setdefault("timeout", 5)
    return AsyncSession(verify=sv.ca_path, **kw)


def test_async_stream_okumadan_doner_ve_aiter_bytes(sv):
    async def main():
        async with S(sv) as s:
            t = time.monotonic()
            r = await s.get(sv.url + "/lines?n=3&d=0.3", stream=True)
            assert time.monotonic() - t < 0.25
            with pytest.raises(ResponseNotRead):
                r.content
            data = b"".join([c async for c in r.aiter_bytes()])
            assert data == b"satir-0\nsatir-1\nsatir-2\n"
            await r.aclose()
    run(main())


def test_async_aread_text_lines_raw(sv):
    async def main():
        async with S(sv) as s:
            async with s.stream("GET", sv.url + "/chunked?i=Q") as r:
                assert await r.aread() == b"parca1-parca2-Q"
                assert r.text == "parca1-parca2-Q"
            async with s.stream("GET", sv.url + "/gzlines?n=3") as r:
                assert [ln async for ln in r.aiter_lines()] == ["satir-0", "satir-1", "satir-2"]
            async with s.stream("GET", sv.url + "/gzlines?n=3") as r:
                ham = b"".join([c async for c in r.aiter_raw()])
                assert gzip.decompress(ham) == b"satir-0\nsatir-1\nsatir-2\n"
            async with s.stream("GET", sv.url + "/chunked?i=Q") as r:
                assert "".join([t async for t in r.aiter_text()]) == "parca1-parca2-Q"
    run(main())


def test_async_havuz_gevri_doner_yarida_kapatinca_kapanir(sv):
    async def main():
        async with S(sv, ) as s:
            once = sv.kabul_edilen_baglanti
            for _ in range(3):
                async with s.stream("GET", sv.url + "/big?n=200000") as r:
                    assert b"".join([c async for c in r.aiter_bytes()]) == govde_uret(200000)
            assert sv.kabul_edilen_baglanti - once == 1        # tek bağlantı
            r = await s.get(sv.url + "/big?n=5000000", stream=True)
            it = r.aiter_bytes()
            await it.__anext__()
            await r.aclose()
            with pytest.raises(StreamClosed):
                await r.aread()
            assert (await s.get(sv.url + "/id?i=ok")).body == b"ok"
            assert sv.kabul_edilen_baglanti - once == 2        # kapatılan yeniden kullanılmadı
    run(main())


def test_async_slot_sizmaz(sv):
    async def main():
        async with S(sv, max_connections=2) as s:
            for _ in range(6):
                r = await s.get(sv.url + "/big?n=100000", stream=True)
                await r.aclose()
            assert (await s.get(sv.url + "/id?i=z")).body == b"z"
    run(main())


def test_async_kesik_govde_hatasi(sv):
    async def main():
        async with S(sv) as s:
            r = await s.get(sv.url + "/cut", stream=True)
            with pytest.raises(ConnectionError):
                [c async for c in r.aiter_bytes()]
            assert (await s.get(sv.url + "/id?i=x")).body == b"x"
    run(main())


def test_async_iter_lines_ilk_satir_govde_bitmeden(sv):
    async def main():
        async with S(sv) as s:
            t0 = time.monotonic()
            zamanlar = []
            async with s.stream("GET", sv.url + "/lines?n=4&d=0.4") as r:
                async for ln in r.aiter_lines():
                    zamanlar.append(time.monotonic() - t0)
            assert len(zamanlar) == 4 and zamanlar[0] < 0.35 and zamanlar[-1] > 1.2
    run(main())


def test_async_bellek_sabit_50mb(sv):
    async def main():
        n = 50 * 1024 * 1024
        async with S(sv) as s:
            for yol in ("/gen", "/chunkgen"):
                tracemalloc.start()
                toplam = 0
                async with s.stream("GET", f"{sv.url}{yol}?n={n}") as r:
                    async for c in r.aiter_bytes(chunk_size=65536):
                        toplam += len(c)
                _, tepe = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                assert toplam == n and tepe < 10 * 1024 * 1024, f"{yol}: {tepe / 1e6:.1f} MB"
    run(main())


@pytest.mark.parametrize("kind", ["raw", "bytes", "text", "lines"])
def test_async_aclose_yarida_birakilan_iteratoru_kapatir(sv, kind):
    """aclose() yarıda bırakılmış aiter_* üretecini (ve iç üreteçlerini) kapatır: çöp
    toplayıcıya kalan üreteç trio'da ResourceWarning olurdu, asyncio'da sonlandırması döngü
    kapandıktan sonraya kalabilirdi."""
    async def main():
        async with S(sv) as s:
            r = await s.get(sv.url + "/lines?n=5&d=0.05", stream=True)
            it = {"raw": r.aiter_raw, "bytes": r.aiter_bytes, "text": r.aiter_text,
                  "lines": r.aiter_lines}[kind]()
            assert await it.__anext__()
            await r.aclose()
            assert it.ag_frame is None                   # üreteç bitti (kapatıldı)
            with pytest.raises(StopAsyncIteration):
                await it.__anext__()
    run(main())
