"""~40 popüler siteye üç profille senkron GET; requests ile karşılaştırma.

Kullanım:
    python -m saha.canli_siteler [--json cikti.json] [--md cikti.md] [--workers 8]

Proxy/CA: HTTPS_PROXY ve /root/.ccr/ca-bundle.crt (ya da --proxy/--ca).
UYARI: Proxy arkasında TLS çoğu sitede PROXY'DE sonlanır (fasthttpc ↔ proxy
arası bizim TLS 1.3 yığınımız + proxy'nin yeniden imzaladığı sertifika; proxy ↔
site arası proxy'nin kendi yığını). Bu yüzden parmak izi/ALPN sonuçları
sitenin gerçek davranışını DEĞİL proxy'nin davranışını yansıtabilir.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from fasthttpc import Session

PROFILES = ("chrome_131", "firefox_133", "safari_18")

SITES = {
    # CDN / altyapı
    "cloudflare": "https://www.cloudflare.com/",
    "cf-trace": "https://www.cloudflare.com/cdn-cgi/trace",
    "cdnjs": "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js",
    "akamai": "https://www.akamai.com/",
    "fastly": "https://www.fastly.com/",
    "jsdelivr": "https://cdn.jsdelivr.net/npm/lodash/package.json",
    "unpkg": "https://unpkg.com/react/package.json",
    # Büyük platformlar
    "google": "https://www.google.com/",
    "google-204": "https://www.google.com/generate_204",
    "youtube": "https://www.youtube.com/",
    "microsoft": "https://www.microsoft.com/",
    "bing": "https://www.bing.com/",
    "amazon": "https://www.amazon.com/",
    "apple": "https://www.apple.com/",
    "github": "https://github.com/",
    "github-api": "https://api.github.com/",
    "wikipedia": "https://en.wikipedia.org/wiki/HTTP",
    "wikipedia-tr": "https://tr.wikipedia.org/",
    "reddit": "https://www.reddit.com/",
    "stackoverflow": "https://stackoverflow.com/",
    "twitter-x": "https://x.com/",
    "linkedin": "https://www.linkedin.com/",
    "netflix": "https://www.netflix.com/",
    "python-org": "https://www.python.org/",
    "pypi": "https://pypi.org/",
    "npm": "https://www.npmjs.com/",
    "httpbin": "https://httpbin.org/get",
    "example": "https://example.com/",
    "nginx": "https://nginx.org/",
    # Haber
    "bbc": "https://www.bbc.com/",
    "cnn": "https://www.cnn.com/",
    "nytimes": "https://www.nytimes.com/",
    "guardian": "https://www.theguardian.com/",
    # Türk siteleri
    "hurriyet": "https://www.hurriyet.com.tr/",
    "milliyet": "https://www.milliyet.com.tr/",
    "sabah": "https://www.sabah.com.tr/",
    "trendyol": "https://www.trendyol.com/",
    "hepsiburada": "https://www.hepsiburada.com/",
    "sahibinden": "https://www.sahibinden.com/",
    "turkiye-gov": "https://www.turkiye.gov.tr/",
    "ntv": "https://www.ntv.com.tr/",
    "sozcu": "https://www.sozcu.com.tr/",
}


def tls_sonlanma(url: str, proxy: str, ca: str) -> str:
    """CONNECT tüneli açıp sunucu sertifikasının düzenleyicisine bakar.

    Düzenleyici proxy CA'sı ("Anthropic") ise TLS proxy'de sonlanmıştır; aksi
    hâlde tünel uçtan uca geçmiştir ve fasthttpc gerçek siteyle konuşmuştur.
    """
    host = urlsplit(url).hostname
    try:
        pu = urlsplit(proxy)
        s = socket.create_connection((pu.hostname, pu.port), 10)
        s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
        s.recv(4096)
        t = ssl.create_default_context(cafile=ca).wrap_socket(s, server_hostname=host)
        org = dict(x[0] for x in t.getpeercert()["issuer"]).get("organizationName", "?")
        ver = t.version()
        t.close()
    except Exception as e:  # noqa: BLE001
        return f"? ({type(e).__name__})"
    return f"proxy'de sonlandı ({ver})" if "anthropic" in org.lower() else f"uçtan uca: {org} ({ver})"


def siniflandir(durum, hata: str | None) -> str:
    """Sonuçları (a) beklenen / (b) fasthttpc hatası / ok olarak etiketle."""
    if hata is None:
        if durum in (401, 403, 429, 503) or (isinstance(durum, int) and durum >= 400):
            return "a:bot-engeli/istemci-durumu"
        return "ok"
    h = hata.lower()
    if "tls 1.2" in h or "protocol_version" in h or "supported_versions" in h:
        return "a:TLS1.2-only"
    if "403" in h or "forbidden" in h or "proxy" in h and "refus" in h:
        return "a:proxy/bot-engeli"
    return "b:fasthttpc-hatasi?"


def fasthttpc_dene(url, profil, proxy, ca, timeout):
    t = time.perf_counter()
    try:
        with Session(impersonate=profil, proxy=proxy, verify=ca, timeout=timeout) as s:
            r = s.get(url)
        return {"durum": r.status_code, "ms": round((time.perf_counter() - t) * 1000),
                "surum": r.http_version, "bayt": len(r.content), "hata": None,
                "yonlendirme": len(r.history)}
    except Exception as e:  # noqa: BLE001 — rapor amaçlı
        return {"durum": None, "ms": round((time.perf_counter() - t) * 1000), "surum": "-",
                "bayt": 0, "hata": f"{type(e).__name__}: {str(e)[:140]}", "yonlendirme": 0}


def requests_dene(url, proxy, ca, timeout):
    try:
        import requests
    except ImportError:
        return {"durum": None, "ms": 0, "hata": "requests yok"}
    t = time.perf_counter()
    try:
        r = requests.get(url, timeout=timeout, proxies={"https": proxy, "http": proxy},
                         verify=ca, headers={"User-Agent": "Mozilla/5.0"})
        return {"durum": r.status_code, "ms": round((time.perf_counter() - t) * 1000),
                "bayt": len(r.content), "hata": None}
    except Exception as e:  # noqa: BLE001
        return {"durum": None, "ms": round((time.perf_counter() - t) * 1000),
                "hata": f"{type(e).__name__}: {str(e)[:140]}"}


def bir_site(args):
    ad, url, proxy, ca, timeout = args
    sonuc = {"site": ad, "url": url, "tls": tls_sonlanma(url, proxy, ca),
             "requests": requests_dene(url, proxy, ca, timeout)}
    for p in PROFILES:
        r = fasthttpc_dene(url, p, proxy, ca, timeout)
        r["sinif"] = siniflandir(r["durum"], r["hata"])
        sonuc[p] = r
    return sonuc


def markdown(sonuclar) -> str:
    satir = ["| site | requests | " + " | ".join(PROFILES) + " |", "|---|---|" + "---|" * len(PROFILES)]
    for s in sonuclar:
        rq = s["requests"]
        rq_t = f"{rq['durum']} {rq['ms']}ms" if rq["durum"] else f"HATA {rq['hata'][:40]}"
        hucre = []
        for p in PROFILES:
            r = s[p]
            if r["durum"]:
                hucre.append(f"{r['durum']} {r['ms']}ms {r['surum'].replace('HTTP/', 'h')} [{r['sinif']}]")
            else:
                hucre.append(f"HATA {r['hata'][:50]} [{r['sinif']}]")
        satir.append(f"| {s['site']} | {rq_t} | " + " | ".join(hucre) + " |")
    satir += ["", "| site | TLS nerede sonlandı |", "|---|---|"]
    satir += [f"| {s['site']} | {s['tls']} |" for s in sonuclar]
    return "\n".join(satir)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy", default=os.environ.get("HTTPS_PROXY"))
    ap.add_argument("--ca", default="/root/.ccr/ca-bundle.crt")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--json")
    ap.add_argument("--md")
    ap.add_argument("--only", help="virgülle ayrılmış site adları")
    a = ap.parse_args(argv)
    sec = SITES if not a.only else {k: v for k, v in SITES.items() if k in a.only.split(",")}
    isler = [(k, v, a.proxy, a.ca, a.timeout) for k, v in sec.items()]
    print(f"{len(isler)} site x {len(PROFILES)} profil; proxy={'var' if a.proxy else 'yok'}; "
          f"openssl={ssl.OPENSSL_VERSION}", file=sys.stderr)
    with ThreadPoolExecutor(a.workers) as ex:
        sonuclar = list(ex.map(bir_site, isler))
    md = markdown(sonuclar)
    print(md)
    if a.json:
        with open(a.json, "w") as f:
            json.dump(sonuclar, f, indent=1, ensure_ascii=False)
    if a.md:
        with open(a.md, "w") as f:
            f.write(md + "\n")
    b = [(s["site"], p, s[p]["hata"]) for s in sonuclar for p in PROFILES if s[p]["sinif"].startswith("b")]
    print(f"\n(b) fasthttpc hata adayı: {len(b)}", file=sys.stderr)
    for x in b:
        print("  ", x, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
