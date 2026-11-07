"""
Örnek 3 — Timeout objesi (connect/read ayrı)
"""
from fasthttpc import Session, Timeout

timeout = Timeout(connect=5.0, read=30.0)

with Session(timeout=timeout) as s:
    r = s.get("https://httpbin.org/delay/2")
    print(f"Yanıt: {r.status_code} — {r.elapsed:.3f}s")
