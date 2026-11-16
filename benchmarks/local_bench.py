"""fasthttpc yerel (ağsız) uçtan uca benchmark'ı.

Kullanım::

    python benchmarks/local_bench.py                    # tüm senaryolar
    python benchmarks/local_bench.py --mb 64 --only h1_download,h2_download
    python benchmarks/local_bench.py --json sonuc.json  # makinece okunur çıktı
    python benchmarks/local_bench.py --profile h2_download   # cProfile (tottime) ilk 25

Sunucular ayrı süreçte çalışır (bkz. ``_servers.py``); bu yüzden raporlanan
**istemci CPU** süresi (``time.process_time``) yalnızca fasthttpc'nin işidir.
Duvar saati süresine sunucunun (stdlib ``ssl`` + saf Python ``h2``) hızı da
karışır: sunucu darboğaz olduğunda istemci iyileşmesi duvar saatinde tam
görünmez — asıl karşılaştırma ölçütü ``cpu`` sütunudur.

Senaryolar:
  h1_download     TLS 1.3 + HTTP/1.1, Content-Length gövde (``/gen``)
  h1_chunked      TLS 1.3 + HTTP/1.1, chunked gövde (``/chunkgen``)
  h1_stream       aynı, ``stream=True`` + ``iter_bytes()``
  h2_download     TLS 1.3 + HTTP/2, tek büyük gövde
  h2_stream       HTTP/2, ``stream=True`` + ``iter_bytes()``
  h1_small        keep-alive bağlantıda ardışık küçük istekler
  h2_small        tek HTTP/2 bağlantısında ardışık küçük istekler
  handshake       her seferinde yeni bağlantı: TCP + TLS 1.3 tam handshake + 1 istek
  async_h1        AsyncSession, eşzamanlı küçük istekler (HTTP/1.1 havuzu)
  async_h2        AsyncSession, tek HTTP/2 bağlantısında eşzamanlı küçük istekler
  async_h2_download  AsyncSession, HTTP/2 büyük gövde
"""
from __future__ import annotations

import argparse
import asyncio
import cProfile
import json
import os
import pstats
import statistics
import sys
import time
from typing import Callable

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Önce/sonra karşılaştırması: FASTHTTPC_BENCH_SRC=<dizin> verilirse istemci paketi
# (fasthttpc) oradan yüklenir, ör. `git archive <rev> fasthttpc | tar -x -C /tmp/eski`.
if os.environ.get("FASTHTTPC_BENCH_SRC"):
    sys.path.insert(0, os.environ["FASTHTTPC_BENCH_SRC"])

from _servers import ServerProcess, h2_available  # noqa: E402

from fasthttpc import AsyncSession, Session  # noqa: E402


class Ctx:
    def __init__(self, h1: "tuple[int, str]", h2: "tuple[int, str] | None", mb: int, n_small: int):
        self.h1_url = f"https://localhost:{h1[0]}"
        self.h1_ca = h1[1]
        self.h2_url = f"https://localhost:{h2[0]}" if h2 else None
        self.h2_ca = h2[1] if h2 else None
        self.nbytes = mb * 1024 * 1024
        self.n_small = n_small


def _measure(fn: Callable[[], object], repeat: int) -> "tuple[float, float]":
    """(en iyi duvar süresi, o koşunun istemci CPU süresi)."""
    best = (float("inf"), 0.0)
    for _ in range(repeat):
        w0, c0 = time.perf_counter(), time.process_time()
        fn()
        w, c = time.perf_counter() - w0, time.process_time() - c0
        if w < best[0]:
            best = (w, c)
    return best


# ------------------------------------------------------------------ senaryolar
def _download(url: str, ca: str, n: int, stream: bool) -> Callable[[], object]:
    s = Session(verify=ca, timeout=60)
    s.get(url.replace("/gen?n=", "/id?i=w").replace("/chunkgen?n=", "/id?i=w").split("&")[0])  # ısınma

    def run() -> None:
        if stream:
            got = 0
            with s.stream("GET", url) as r:
                for c in r.iter_bytes():
                    got += len(c)
        else:
            got = len(s.get(url).content)
        assert got == n, (got, n)
    return run


def sc_h1_download(c: Ctx):
    return _download(f"{c.h1_url}/gen?n={c.nbytes}", c.h1_ca, c.nbytes, False), c.nbytes, "MB/s"


def sc_h1_chunked(c: Ctx):
    return _download(f"{c.h1_url}/chunkgen?n={c.nbytes}", c.h1_ca, c.nbytes, False), c.nbytes, "MB/s"


def sc_h1_stream(c: Ctx):
    return _download(f"{c.h1_url}/gen?n={c.nbytes}", c.h1_ca, c.nbytes, True), c.nbytes, "MB/s"


def sc_h2_download(c: Ctx):
    assert c.h2_url
    return _download(f"{c.h2_url}/gen?n={c.nbytes}", c.h2_ca, c.nbytes, False), c.nbytes, "MB/s"


def sc_h2_stream(c: Ctx):
    assert c.h2_url
    return _download(f"{c.h2_url}/gen?n={c.nbytes}", c.h2_ca, c.nbytes, True), c.nbytes, "MB/s"


def _small(url: str, ca: str, n: int):
    s = Session(verify=ca, timeout=10)
    s.get(f"{url}/id?i=w")

    def run() -> None:
        for i in range(n):
            r = s.get(f"{url}/id?i={i}")
            assert r.content == str(i).encode()
    return run, n, "istek/s"


def sc_h1_small(c: Ctx):
    return _small(c.h1_url, c.h1_ca, c.n_small)


def sc_h2_small(c: Ctx):
    assert c.h2_url
    return _small(c.h2_url, c.h2_ca, c.n_small)


def sc_handshake(c: Ctx):
    n = 30

    def run() -> None:
        times = []
        for i in range(n):
            t0 = time.perf_counter()
            with Session(verify=c.h1_ca, timeout=10) as s:
                assert s.get(f"{c.h1_url}/id?i={i}").status_code == 200
            times.append(time.perf_counter() - t0)
        run.median_ms = statistics.median(times) * 1000  # type: ignore[attr-defined]
    return run, n, "bağlantı/s"


def _async_small(url: str, ca: str, n: int, conc: int):
    async def main() -> None:
        async with AsyncSession(verify=ca, timeout=20, max_connections=conc) as s:
            await s.get(f"{url}/id?i=w")
            sem = asyncio.Semaphore(conc)

            async def one(i: int) -> None:
                async with sem:
                    r = await s.get(f"{url}/id?i={i}")
                    assert r.content == str(i).encode()
            await asyncio.gather(*(one(i) for i in range(n)))

    def run() -> None:
        asyncio.run(main())
    return run, n, "istek/s"


def sc_async_h1(c: Ctx):
    return _async_small(c.h1_url, c.h1_ca, c.n_small, 16)


def sc_async_h2(c: Ctx):
    assert c.h2_url
    return _async_small(c.h2_url, c.h2_ca, c.n_small, 32)


def sc_async_h2_download(c: Ctx):
    assert c.h2_url
    url = f"{c.h2_url}/gen?n={c.nbytes}"

    async def main() -> None:
        async with AsyncSession(verify=c.h2_ca, timeout=60) as s:
            r = await s.get(url)
            assert len(r.content) == c.nbytes

    def run() -> None:
        asyncio.run(main())
    return run, c.nbytes, "MB/s"


SCENARIOS = {
    "h1_download": sc_h1_download,
    "h1_chunked": sc_h1_chunked,
    "h1_stream": sc_h1_stream,
    "h2_download": sc_h2_download,
    "h2_stream": sc_h2_stream,
    "h1_small": sc_h1_small,
    "h2_small": sc_h2_small,
    "handshake": sc_handshake,
    "async_h1": sc_async_h1,
    "async_h2": sc_async_h2,
    "async_h2_download": sc_async_h2_download,
}
_NEEDS_H2 = {"h2_download", "h2_stream", "h2_small", "async_h2", "async_h2_download"}


def main(argv: "list[str] | None" = None) -> dict:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mb", type=int, default=64, help="büyük indirme boyutu (MiB)")
    ap.add_argument("--small", type=int, default=500, help="küçük istek sayısı")
    ap.add_argument("--repeat", type=int, default=3, help="tekrar (en iyi koşu raporlanır)")
    ap.add_argument("--only", default="", help="virgülle ayrılmış senaryo adları")
    ap.add_argument("--json", default="", help="sonuçları bu JSON dosyasına yaz")
    ap.add_argument("--profile", default="", help="bu senaryoyu cProfile ile bir kez çalıştır")
    args = ap.parse_args(argv)

    names = [n for n in (args.only.split(",") if args.only else SCENARIOS) if n]
    if args.profile:
        names = [args.profile]
    has_h2 = h2_available()
    results: dict = {}
    with ServerProcess("h1") as h1:
        h2cm = ServerProcess("h2") if has_h2 else None
        h2 = h2cm.__enter__() if h2cm else None
        try:
            ctx = Ctx(h1, h2, args.mb, args.small)
            import fasthttpc
            print(f"fasthttpc: {os.path.dirname(fasthttpc.__file__)}  python {sys.version.split()[0]}"
                  f"  büyük gövde {args.mb} MiB, küçük istek {args.small}, en iyi {args.repeat} koşu")
            print(f"{'senaryo':20s} {'duvar':>9s} {'cpu':>9s} {'oran':>14s} {'cpu-oranı':>14s}")
            for name in names:
                if name in _NEEDS_H2 and not has_h2:
                    print(f"{name:20s} atlandı (h2 paketi kurulu değil)")
                    continue
                run, units, label = SCENARIOS[name](ctx)
                if args.profile:
                    pr = cProfile.Profile()
                    pr.enable()
                    run()
                    pr.disable()
                    pstats.Stats(pr).sort_stats(os.environ.get("BENCH_SORT", "tottime")).print_stats(int(os.environ.get("BENCH_TOP", "25")))
                    continue
                wall, cpu = _measure(run, args.repeat)
                scale = 1e6 if label == "MB/s" else 1
                rate, cpu_rate = units / scale / wall, units / scale / max(cpu, 1e-9)
                extra = ""
                if hasattr(run, "median_ms"):
                    extra = f"  medyan {run.median_ms:.2f} ms/bağlantı"
                print(f"{name:20s} {wall:8.3f}s {cpu:8.3f}s {rate:9.1f} {label:<9s}"
                      f"{cpu_rate:9.1f} {label}{extra}")
                results[name] = {"wall_s": wall, "cpu_s": cpu, "rate": rate, "cpu_rate": cpu_rate,
                                 "unit": label, **({"median_ms": run.median_ms} if extra else {})}
        finally:
            if h2cm:
                h2cm.__exit__(None, None, None)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"python": sys.version.split()[0], "mb": args.mb, "small": args.small,
                       "results": results}, f, indent=2)
    return results


if __name__ == "__main__":
    main()
