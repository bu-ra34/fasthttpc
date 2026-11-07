"""
Örnek 1 — Basit GET isteği
"""
from fasthttpc import Session

with Session(impersonate="chrome_131") as s:
    r = s.get("https://httpbin.org/get")
    print(f"Durum  : {r.status_code}")
    print(f"Süre   : {r.elapsed:.3f}s")
    print(f"Body   : {r.text()[:200]}")
