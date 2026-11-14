"""Response.elapsed yüksek çözünürlüklü saatle ölçülür.

Windows'ta (Python < 3.13) ``time.monotonic()`` GetTickCount64 tabanlıdır ve
çözünürlüğü ~15,6 ms'dir: yerel bir isteğin elapsed'i 0.0 çıkar, kısa süre
farkları ölçülemez. ``time.perf_counter()`` her platformda yüksek çözünürlüklüdür.
Test, kaba saati taklit ederek bunu Linux'ta yeniden üretir.
"""
import time

import pytest

from fasthttpc import AsyncSession, Response, Session, Timeout
from fasthttpc.transport.mock import MockTransport

from test_async_pool import H1Server, ca, pki, run  # noqa: E402,F401  (fixture'lar)

TICK = 0.0156


@pytest.fixture
def kaba_monotonic(monkeypatch):
    gercek = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: (gercek() // TICK) * TICK)


def _handler(request):
    time.sleep(0.002)
    return Response(200, body=b"x")


def test_sync_elapsed_kaba_monotonic_saatte_de_sifirdan_buyuk(kaba_monotonic):
    with Session(transport=MockTransport(_handler)) as s:
        r = s.get("https://example.test/")
    assert r.elapsed > 0
    assert r.elapsed < TICK * 4


def test_async_elapsed_kaba_monotonic_saatte_de_sifirdan_buyuk(kaba_monotonic, pki, ca, tmp_path):
    async def main():
        srv = await H1Server(pki, tmp_path).start()
        async with AsyncSession(verify=ca, impersonate=None, timeout=Timeout(5, read=3)) as s:
            r = await s.get(f"{srv.base}/u")
        await srv.stop()
        return r
    r = run(main())
    assert r.elapsed > 0
    assert r.elapsed < 1
