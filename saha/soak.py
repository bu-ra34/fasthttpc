"""Uzun süreli kullanım (soak): tek Session ile çok sayıda ardışık istek.

Ağsız (varsayılan): yerel TLS 1.3 sunucusuna N istek; keep-alive yeniden
kullanımı, gövde bütünlüğü, açık fd/soket, havuz boyutu, tracemalloc.
    python -m saha.soak [--n 2000] [--json cikti.json]
Canlı (proxy üstünden): python -m saha.soak --canli https://example.com/ --n 500
"""
from __future__ import annotations

import argparse
import gc
import gzip
import hashlib
import json
import os
import sys
import time
import tracemalloc

from fasthttpc import Session
from saha.yerel_sunucu import YerelSunucu, govde_uret


def fd_sayisi() -> int:
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return -1


def rss_kb() -> int:
    try:
        with open("/proc/self/statm") as f:
            return int(f.read().split()[1]) * (os.sysconf("SC_PAGE_SIZE") // 1024)
    except OSError:
        return -1


def yerel(n: int, buyuk_mb: int = 10) -> dict:
    sonuc: dict = {"n": n}
    with YerelSunucu() as sv:
        with Session(verify=sv.ca_path, timeout=30, max_connections=10) as s:
            # --- 1. ardışık kısa istekler (karışık yol türleri) -------------------
            yollar = ["/id", "/chunked", "/gzip", "/br"]
            tracemalloc.start()
            fd0 = fd_sayisi()
            hatalar = 0
            gc.collect()
            snap_baslangic = None
            t0 = time.perf_counter()
            for i in range(n):
                y = yollar[i % len(yollar)]
                kimlik = f"r{i}"
                try:
                    r = s.get(f"{sv.url}{y}?i={kimlik}")
                    if y == "/id":
                        ok = r.content == kimlik.encode()
                    elif y == "/chunked":
                        ok = r.content == b"parca1-parca2-" + kimlik.encode()
                    else:
                        ok = r.json()["id"] == kimlik
                    hatalar += 0 if ok and r.status_code == 200 else 1
                except Exception as e:  # noqa: BLE001
                    hatalar += 1
                    print("hata", i, type(e).__name__, e, file=sys.stderr)
                if i == min(200, n // 5):  # ısınma sonrası referans
                    gc.collect()
                    snap_baslangic = tracemalloc.take_snapshot()
                    cur0 = tracemalloc.get_traced_memory()[0]
            sure = time.perf_counter() - t0
            gc.collect()
            cur1 = tracemalloc.get_traced_memory()[0]
            snap_son = tracemalloc.take_snapshot()
            tracemalloc.stop()
            fark = snap_son.compare_to(snap_baslangic, "lineno")[:5]
            sonuc["kisa"] = {
                "istek": n, "hata": hatalar, "sure_s": round(sure, 2), "istek_per_s": round(n / sure),
                "sunucuya_tcp_baglanti": sv.kabul_edilen_baglanti,
                "sunucu_istek": sv.istek_sayisi,
                "fd_once": fd0, "fd_sonra": fd_sayisi(),
                "havuz": s.pool_stats(),
                "tracemalloc_isinma_sonrasi_KB": round(cur0 / 1024, 1),
                "tracemalloc_son_KB": round(cur1 / 1024, 1),
                "tracemalloc_buyume_KB": round((cur1 - cur0) / 1024, 1),
                "buyume_per_istek_bayt": round((cur1 - cur0) / max(n - min(200, n // 5), 1)),
                "en_buyuk_farklar": [str(d) for d in fark[:3]],
            }
            # --- 2. büyük gövde ------------------------------------------------
            n_bayt = buyuk_mb * 1024 * 1024
            t = time.perf_counter()
            r = s.get(f"{sv.url}/big?n={n_bayt}")
            dt = time.perf_counter() - t
            sonuc["buyuk"] = {
                "boyut_MB": buyuk_mb, "sure_s": round(dt, 2), "MB_per_s": round(buyuk_mb / dt, 1),
                "dogru": r.content == govde_uret(n_bayt) and r.status_code == 200,
                "sha256": hashlib.sha256(r.content).hexdigest()[:16],
            }
            del r
            # büyük indirmeden sonra bağlantı hâlâ sağlam mı + 5 kez tekrar (bellek)
            gc.collect()
            rss_a = rss_kb()
            for _ in range(5):
                s.get(f"{sv.url}/big?n={n_bayt}")
            gc.collect()
            sonuc["buyuk"]["rss_5_indirme_sonrasi_artis_MB"] = round((rss_kb() - rss_a) / 1024, 1)
            sonuc["buyuk"]["sonraki_istek_ok"] = s.get(f"{sv.url}/id?i=z").content == b"z"
            sonuc["toplam_tcp_baglanti"] = sv.kabul_edilen_baglanti
    sonuc["sunucu_acik_baglanti_kapanista"] = None
    return sonuc


def canli(url: str, n: int, proxy: str, ca: str) -> dict:
    gc.collect()
    tracemalloc.start()
    fd0 = fd_sayisi()
    hata = 0
    durumlar: dict = {}
    t0 = time.perf_counter()
    yeniden = 0
    with Session(proxy=proxy, verify=ca, timeout=20) as s:
        for i in range(n):
            try:
                r = s.get(url)
                durumlar[r.status_code] = durumlar.get(r.status_code, 0) + 1
                if r.metrics is not None and r.metrics.connection_reused:
                    yeniden += 1
            except Exception as e:  # noqa: BLE001
                hata += 1
                print("hata", i, type(e).__name__, e, file=sys.stderr)
            if i == 20:
                gc.collect()
                cur0 = tracemalloc.get_traced_memory()[0]
        sure = time.perf_counter() - t0
        gc.collect()
        cur1 = tracemalloc.get_traced_memory()[0]
        out = {"url": url, "n": n, "hata": hata, "durumlar": durumlar, "sure_s": round(sure, 1),
               "istek_per_s": round(n / sure, 1), "baglanti_yeniden_kullanimi": yeniden,
               "fd_once": fd0, "fd_sonra": fd_sayisi(), "havuz": s.pool_stats(),
               "tracemalloc_buyume_KB": round((cur1 - cur0) / 1024, 1)}
    tracemalloc.stop()
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--buyuk-mb", type=int, default=10)
    ap.add_argument("--canli")
    ap.add_argument("--proxy", default=os.environ.get("HTTPS_PROXY"))
    ap.add_argument("--ca", default="/root/.ccr/ca-bundle.crt")
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    sonuc = canli(a.canli, a.n, a.proxy, a.ca) if a.canli else yerel(a.n, a.buyuk_mb)
    txt = json.dumps(sonuc, indent=1, ensure_ascii=False)
    print(txt)
    if a.json:
        with open(a.json, "w") as f:
            f.write(txt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
