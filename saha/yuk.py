"""Eşzamanlılık ve hata-enjeksiyonu testleri (yerel TLS 1.3 sunucusu).

1. ortak Session, T thread, her biri K istek; her yanıt kendi isteğinin kimliğini
   taşımalı (karışma/yarış tespiti); deadlock için watchdog.
2. zaman aşımı / yarıda kesen sunucu / RST / yanıtsız kapanış davranışı.
    python -m saha.yuk [--threads 50] [--per-thread 40] [--json cikti.json]
"""
from __future__ import annotations

import argparse
import json
import threading
import time

from fasthttpc import Session, Timeout
from saha.soak import fd_sayisi
from saha.yerel_sunucu import YerelSunucu


def ortak_session_yuku(sv, n_thread: int, k: int, max_conn: int) -> dict:
    hatalar: list[str] = []
    karisma: list[str] = []
    sayac = {"ok": 0}
    kilit = threading.Lock()
    gecikmeler: list[float] = []

    with Session(verify=sv.ca_path, timeout=Timeout(20, pool=60), max_connections=max_conn) as s:
        def is_parcacigi(t: int) -> None:
            for j in range(k):
                kimlik = f"t{t}-i{j}-{(t * 7919 + j * 104729) % 1000003}"
                tur = j % 5
                t0 = time.perf_counter()
                try:
                    if tur == 0:
                        r = s.get(f"{sv.url}/id?i={kimlik}")
                        ok = r.content == kimlik.encode() and r.headers.get("x-id") == kimlik
                    elif tur == 1:
                        r = s.post(f"{sv.url}/id?i={kimlik}", data=f"-govde-{kimlik}".encode())
                        ok = r.content == f"{kimlik}-govde-{kimlik}".encode()
                    elif tur == 2:
                        r = s.get(f"{sv.url}/chunked?i={kimlik}")
                        ok = r.content == b"parca1-parca2-" + kimlik.encode()
                    elif tur == 3:
                        r = s.get(f"{sv.url}/gzip?i={kimlik}")
                        ok = r.json()["id"] == kimlik
                    else:
                        r = s.get(f"{sv.url}/sleep?d=0.02&i={kimlik}")
                        ok = r.content == kimlik.encode()
                    dt = time.perf_counter() - t0
                    with kilit:
                        gecikmeler.append(dt)
                        if ok and r.status_code == 200:
                            sayac["ok"] += 1
                        else:
                            karisma.append(f"{kimlik}: beklenmeyen yanıt {r.status_code} {r.content[:40]!r}")
                except Exception as e:  # noqa: BLE001
                    with kilit:
                        hatalar.append(f"{kimlik}: {type(e).__name__}: {str(e)[:80]}")

        t0 = time.perf_counter()
        ths = [threading.Thread(target=is_parcacigi, args=(i,), daemon=True) for i in range(n_thread)]
        for t in ths:
            t.start()
        deadline = time.monotonic() + 120
        for t in ths:
            t.join(max(0.1, deadline - time.monotonic()))
        takili = sum(t.is_alive() for t in ths)
        sure = time.perf_counter() - t0
        havuz = s.pool_stats()
    gecikmeler.sort()
    top = n_thread * k
    return {
        "thread": n_thread, "toplam_istek": top, "max_connections": max_conn,
        "basarili": sayac["ok"], "hata": len(hatalar), "karisan_yanit": len(karisma),
        "takili_thread(deadlock)": takili, "sure_s": round(sure, 2), "istek_per_s": round(top / sure),
        "p50_ms": round(gecikmeler[len(gecikmeler) // 2] * 1000, 1) if gecikmeler else None,
        "p99_ms": round(gecikmeler[int(len(gecikmeler) * 0.99)] * 1000, 1) if gecikmeler else None,
        "sunucuya_tcp_baglanti": sv.kabul_edilen_baglanti, "havuz": havuz,
        "ornek_hatalar": (hatalar + karisma)[:5],
    }


def _zaman(fn):
    t = time.perf_counter()
    try:
        r = fn()
        return {"sonuc": f"HTTP {r.status_code} ({len(r.content)}B)", "sure_s": round(time.perf_counter() - t, 2)}
    except Exception as e:  # noqa: BLE001
        return {"sonuc": f"{type(e).__name__}: {str(e)[:70]}", "sure_s": round(time.perf_counter() - t, 2)}


def hata_enjeksiyonu(sv) -> dict:
    out = {}
    with Session(verify=sv.ca_path, timeout=Timeout(2, connect=2), max_connections=3) as s:
        out["yavas_sunucu_/sleep?d=5 (timeout=2)"] = _zaman(lambda: s.get(f"{sv.url}/sleep?d=5"))
        out["damla_damla_/drip n=6,d=1 (timeout=2; toplam 6s)"] = _zaman(lambda: s.get(f"{sv.url}/drip?n=6&d=1"))
        out["yari_kesen_/cut (close_notify'siz)"] = _zaman(lambda: s.get(f"{sv.url}/cut"))
        out["yari_kesen_/cutn (temiz kapanis)"] = _zaman(lambda: s.get(f"{sv.url}/cutn"))
        out["RST_/rst"] = _zaman(lambda: s.get(f"{sv.url}/rst"))
        out["yanitsiz_kapanis_/noreply"] = _zaman(lambda: s.get(f"{sv.url}/noreply"))
        # tüm hatalardan sonra havuz sağlam mı
        out["sonra_normal_istek"] = _zaman(lambda: s.get(f"{sv.url}/id?i=ok"))
        out["havuz_bos_mu(5 sonra)"] = {"sonuc": str(s.pool_stats()), "sure_s": 0}
        # bayat keep-alive: sunucu bağlantıyı kapatır (/once), ardından aynı Session ile istek
        s.get(f"{sv.url}/once?i=a")
        out["bayat_keepalive_sonrasi_istek"] = _zaman(lambda: s.get(f"{sv.url}/id?i=b"))
    # havuz tükenmesi: max_connections=2, 4 yavaş istek, pool timeout kısa
    with Session(verify=sv.ca_path, timeout=Timeout(10, pool=1), max_connections=2) as s:
        sonuc = []

        def yavas():
            sonuc.append(_zaman(lambda: s.get(f"{sv.url}/sleep?d=2")))

        ths = [threading.Thread(target=yavas) for _ in range(4)]
        for t in ths:
            t.start()
        for t in ths:
            t.join(15)
        out["havuz_tukenmesi (2 baglanti, 4 istek, pool=1s)"] = {
            "sonuc": " | ".join(x["sonuc"][:40] for x in sonuc), "sure_s": max(x["sure_s"] for x in sonuc)}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--threads", type=int, default=50)
    ap.add_argument("--per-thread", type=int, default=40)
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    sonuc = {}
    with YerelSunucu() as sv:
        fd0 = fd_sayisi()
        sonuc["yuk"] = []
        for nt, mc in ((20, 10), (a.threads, 10), (a.threads, 50), (a.threads, 2)):
            sonuc["yuk"].append(ortak_session_yuku(sv, nt, a.per_thread, mc))
        sonuc["fd"] = {"once": fd0, "sonra": fd_sayisi()}
        sonuc["hata_enjeksiyonu"] = hata_enjeksiyonu(sv)
    txt = json.dumps(sonuc, indent=1, ensure_ascii=False)
    print(txt)
    if a.json:
        with open(a.json, "w") as f:
            f.write(txt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
