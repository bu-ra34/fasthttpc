"""
Örnek 7 — Response özellikleri (elapsed, history, links)
"""
from fasthttpc import Session

with Session() as s:
                      
    r = s.get("https://httpbin.org/redirect/2")
    print(f"Son URL     : {r.request.url if r.request else '?'}")
    print(f"Redirect    : {len(r.history)} adım")
    print(f"Toplam süre : {r.elapsed:.3f}s")

                 
    r2 = s.get("https://api.github.com/repos/python/cpython/issues?per_page=1")
    print(f"Links       : {list(r2.links.keys())}")
