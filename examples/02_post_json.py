"""
Örnek 2 — JSON POST isteği
"""
from fasthttpc import Session

with Session() as s:
    r = s.post(
        "https://httpbin.org/post",
        json={"kullanici": "bugra", "proje": "fasthttpc"},
    )
    r.raise_for_status()
    data = r.json()
    print("Gönderilen JSON:", data["json"])
