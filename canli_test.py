"""
Canlı (gerçek internet) test betiği — yayın öncesi son kontrol.

Kullanım:  python canli_test.py
Proxy arkasındaysanız:  python canli_test.py --proxy http://host:port --ca yol/ca.pem

Kontroller:
  1. Her profil ile birkaç gerçek siteye senkron istek (status, süre)
  2. tls.peet.ws ile parmak izi (JA3/JA4/Akamai) — gerçek tarayıcıyla karşılaştırın
  3. AsyncSession + impersonate ile istek
  4. TLS 1.2-only sunucuda net hata mesajı
"""
import argparse
import asyncio
import time

from fasthttpc import AsyncSession, Session

PROFILES = ("chrome_131", "firefox_133", "safari_18")
URLS = (
    "https://httpbin.org/get",
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://www.google.com/",
    "https://example.com/",
    "https://nginx.org/",
)


def _kw(args):
    kw = {}
    if args.proxy:
        kw["proxy"] = args.proxy
    if args.ca:
        kw["verify"] = args.ca
    return kw


def sync_tests(args) -> int:
    fails = 0
    print("== 1. Senkron istekler")
    for prof in PROFILES:
        for url in URLS:
            t = time.perf_counter()
            try:
                with Session(impersonate=prof, **_kw(args)) as s:
                    r = s.get(url)
                ms = (time.perf_counter() - t) * 1000
                print(f"  {prof:12} {url:45} {r.status_code}  {len(r.content):7}B  {ms:6.0f}ms")
            except Exception as e:  # noqa: BLE001 — rapor amaçlı
                print(f"  {prof:12} {url:45} HATA {type(e).__name__}: {str(e)[:120]}")
                fails += 1
    return fails


def fingerprint(args) -> int:
    print("\n== 2. Parmak izi (tls.peet.ws)")
    fails = 0
    for prof in PROFILES:
        try:
            with Session(impersonate=prof, **_kw(args)) as s:
                d = s.get("https://tls.peet.ws/api/all").json()
            tls = d.get("tls", {})
            print(f"  {prof:12} ja3_hash={tls.get('ja3_hash')}  ja4={tls.get('ja4')}"
                  f"  http={d.get('http_version')}  akamai={d.get('http2', {}).get('akamai_fingerprint_hash')}")
        except Exception as e:  # noqa: BLE001
            print(f"  {prof:12} HATA {type(e).__name__}: {str(e)[:120]}")
            fails += 1
    return fails


async def async_test(args) -> int:
    print("\n== 3. AsyncSession (impersonate)")
    try:
        async with AsyncSession(impersonate="chrome_131", **_kw(args)) as s:
            r = await s.get("https://httpbin.org/get")
        print(f"  chrome_131 async  {r.status_code}")
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"  HATA {type(e).__name__}: {str(e)[:120]}")
        return 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy")
    ap.add_argument("--ca")
    args = ap.parse_args()
    fails = sync_tests(args) + fingerprint(args) + asyncio.run(async_test(args))
    print(f"\nToplam hata: {fails}  (nginx.org TLS 1.2 sunuyorsa net 'protocol_version' "
          f"hatası BEKLENEN davranıştır)")


if __name__ == "__main__":
    main()
