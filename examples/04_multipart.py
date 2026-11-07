"""
Örnek 4 — Multipart dosya yükleme
"""
from fasthttpc import Session

with Session() as s:
    r = s.post(
        "https://httpbin.org/post",
        files={
            "rapor": ("rapor.txt", b"fasthttpc test verisi", "text/plain"),
        },
        data={"aciklama": "test yukleme"},
    )
    print(r.json()["files"])
