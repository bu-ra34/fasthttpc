#!/usr/bin/env python3
"""Canlı uzun soak: 3 profil x ~15 site, döngüsel istek (senkron + async karışık).

Ölçer: hata oranı (hata tipine göre), gecikme dağılımı (p50/p90/p99), RSS, açık fd, thread sayısı.
Çıktı: interop/canli_soak_sonuc.json ve (--rapor ile) Markdown özet.

Kullanım:
  python3 interop/canli_soak.py --dakika 30 --proxy "$HTTPS_PROXY" --ca /root/.ccr/ca-bundle.crt
"""
from __future__ import annotations

import argparse
import asyncio
import collections
import json
import os
import statistics
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from fasthttpc import AsyncSession, Session  # noqa: E402

PROFILES = ["chrome_131", "firefox_133", "safari_18"]
SITES = [
    "https://example.com/", "https://httpbin.org/get", "https://www.cloudflare.com/cdn-cgi/trace",
    "https://www.google.com/", "https://nginx.org/", "https://www.wikipedia.org/", "https://github.com/",
    "https://www.python.org/", "https://pypi.org/", "https://www.mozilla.org/", "https://www.apache.org/",
    "https://www.kernel.org/", "https://duckduckgo.com/", "https://www.bing.com/", "https://www.debian.org/",
]


def rss_mb() -> float:
    with open("/proc/self/status") as f:
        for ln in f:
            if ln.startswith("VmRSS:"):
                return int(ln.split()[1]) / 1024
    return 0.0


def fd_count() -> int:
    return len(os.listdir("/proc/self/fd"))


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.lat = collections.defaultdict(list)   # (profil, mod) -> [ms]
        self.ok = collections.Counter()
        self.err = collections.Counter()
        self.tls12 = collections.Counter()
        self.err_kinds = collections.Counter()
        self.err_examples = {}
        self.per_site = collections.defaultdict(lambda: [0, 0])
        self.samples = []

    def add(self, prof, mode, url, ms, exc=None, status=None):
        with self.lock:
            k = (prof, mode)
            site = url.split("/")[2]
            if exc is None and status is not None and status < 500:
                self.ok[k] += 1
                self.lat[k].append(ms)
                self.per_site[site][0] += 1
            elif exc is not None and "protocol_version" in str(exc):
                self.tls12[k] += 1     # TLS 1.2-yalnız site: bugün beklenen ret, hata oranına katılmaz
                self.per_site[site][1] += 0
            else:
                self.err[k] += 1
                self.per_site[site][1] += 1
                kind = f"{type(exc).__name__}" if exc else f"HTTP {status}"
                self.err_kinds[kind] += 1
                self.err_examples.setdefault(kind + "|" + site, str(exc)[:200] if exc else f"status {status}")


def pct(v, p):
    s = sorted(v)
    return s[min(len(s) - 1, int(len(s) * p))] if s else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dakika", type=float, default=30)
    ap.add_argument("--proxy", default=os.environ.get("HTTPS_PROXY"))
    ap.add_argument("--ca", default="/root/.ccr/ca-bundle.crt")
    ap.add_argument("--bekleme", type=float, default=0.5, help="istekler arası saniye")
    ap.add_argument("--cikti", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "canli_soak_sonuc.json"))
    a = ap.parse_args()
    kw = {"verify": a.ca, "timeout": 20}
    if a.proxy:
        kw["proxy"] = a.proxy
    st = Stats()
    t_end = time.time() + a.dakika * 60
    t0 = time.time()
    stop = threading.Event()

    def sampler():
        while not stop.wait(30):
            st.samples.append({"t": round(time.time() - t0), "rss_mb": round(rss_mb(), 1), "fd": fd_count(),
                               "threads": threading.active_count()})
    st.samples.append({"t": 0, "rss_mb": round(rss_mb(), 1), "fd": fd_count(), "threads": threading.active_count()})
    threading.Thread(target=sampler, daemon=True).start()

    async def async_fetch(sess, prof, url):
        t = time.perf_counter()
        try:
            r = await sess.get(url)
            st.add(prof, "async", url, (time.perf_counter() - t) * 1000, status=r.status_code)
        except Exception as e:  # noqa: BLE001
            st.add(prof, "async", url, (time.perf_counter() - t) * 1000, exc=e)

    async def async_batch(prof, urls):
        async with AsyncSession(impersonate=prof, **kw) as s:
            await asyncio.gather(*(async_fetch(s, prof, u) for u in urls))

    cycle = 0
    syncs = {p: Session(impersonate=p, **kw) for p in PROFILES}
    while time.time() < t_end:
        cycle += 1
        for prof in PROFILES:
            # her turda siteleri sırayla böl: çift index senkron, tek index async (3'lü paket)
            sites = SITES[cycle % 2::2]
            asyncs = SITES[(cycle + 1) % 2::2]
            for u in sites:
                if time.time() >= t_end:
                    break
                t = time.perf_counter()
                try:
                    r = syncs[prof].get(u)
                    st.add(prof, "sync", u, (time.perf_counter() - t) * 1000, status=r.status_code)
                except Exception as e:  # noqa: BLE001
                    st.add(prof, "sync", u, (time.perf_counter() - t) * 1000, exc=e)
                time.sleep(a.bekleme)
            if time.time() < t_end:
                asyncio.run(async_batch(prof, asyncs[:4]))
        if cycle % 10 == 0:    # havuz ömrünü sınamak için oturumları yenile
            for s in syncs.values():
                s.close()
            syncs = {p: Session(impersonate=p, **kw) for p in PROFILES}
    stop.set()
    st.samples.append({"t": round(time.time() - t0), "rss_mb": round(rss_mb(), 1), "fd": fd_count(),
                       "threads": threading.active_count()})
    out = {"dakika": round((time.time() - t0) / 60, 1), "dongu": cycle, "proxy": bool(a.proxy), "profiller": {},
           "hata_tipleri": dict(st.err_kinds), "hata_ornekleri": st.err_examples,
           "site": {k: {"ok": v[0], "hata": v[1]} for k, v in st.per_site.items()}, "ornekler": st.samples}
    for k in sorted(set(st.ok) | set(st.err) | set(st.tls12)):
        lat = st.lat[k]
        out["profiller"]["%s/%s" % k] = {
            "ok": st.ok[k], "hata": st.err[k], "tls12_yalniz_ret": st.tls12[k],
            "hata_orani": round(st.err[k] / max(1, st.ok[k] + st.err[k]), 4),
            "p50_ms": round(statistics.median(lat)) if lat else 0, "p90_ms": round(pct(lat, 0.9)),
            "p99_ms": round(pct(lat, 0.99)), "max_ms": round(max(lat)) if lat else 0}
    with open(a.cikti, "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
