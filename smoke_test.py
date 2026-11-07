"""
fasthttpc — AĞ GEREKTİREN duman testi (smoke test).

Bu dosya bir birim test paketi DEĞİLDİR: internet bağlantısı ister, gerçek
sitelere istek atar ve assert yerine ekrana ✅/❌ basar. CI'da koşturulamaz.

Gerçek, ağsız ve assert'li test paketi ``tests/`` altındadır::

    pip install -e ".[dev]"
    pytest

Bu script yalnızca elle doğrulama içindir::

    python3 smoke_test.py
"""
from fasthttpc.session import Session
from fasthttpc.models.response import HTTPStatusError
from fasthttpc.fingerprint import ja3_for_profile
from fasthttpc.tls_crafter import clear_ticket_cache
import io

def section(title):
    print(f"\n{'='*60}\n  {title}\n{'='*60}")

def ok(msg):  print(f"  ✅ {msg}")
def fail(msg): print(f"  ❌ {msg}")
def info(msg): print(f"  [+] {msg}")

                                                                               
section("PRE — JA3 / JA3N Parmak İzi")
                                                                               
profiles = ["chrome_131", "firefox_133", "safari_18"]
ja3s = {}
for p in profiles:
    # ja3_for_profile ClientHello'yu gerçekten derleyip byte'ları parse eder;
    # yani telde ne varsa onu raporlar.
    _, ja3s[p] = ja3_for_profile(p)
    info(f"{p:15s}  JA3={ja3s[p]}")

if len(set(ja3s.values())) == len(profiles):
    ok("Tüm profiller farklı JA3 hash üretiyor")
else:
    fail("JA3 çakışması var!")



                                                                               
section("TEST 1 — Cloudflare TLS 1.3")
                                                                               
with Session(impersonate="chrome_131", timeout=15.0) as s:
    try:
        r = s.get("https://www.cloudflare.com/cdn-cgi/trace")
        info(f"Status: {r.status_code}")
        info(r.text()[:120])
        ok("TEST 1 BAŞARILI") if r.is_success else fail("TEST 1: beklenen 200 değil")
    except Exception as e:
        fail(f"TEST 1: {e}")

                                                                               
section("TEST 2 — HTTP POST Form Data")
                                                                               
with Session(impersonate="chrome_131", timeout=15.0) as s:
    try:
        r = s.post("https://httpbingo.org/post", data={"user": "fasthttpc", "v": "3"})
        info(f"Status: {r.status_code}")
        ok("TEST 2 BAŞARILI") if r.is_success else fail("TEST 2 başarısız")
    except Exception as e:
        fail(f"TEST 2: {e}")

                                                                               
section("TEST 3 — Redirect Takibi + history")
                                                                               
with Session(impersonate="chrome_131", timeout=15.0) as s:
    try:
        r = s.get("https://httpbingo.org/redirect/3")
        info(f"Son status: {r.status_code}  |  History uzunluğu: {len(r.history)}")
        if r.is_success and len(r.history) == 3:
            ok("TEST 3 BAŞARILI: 3 redirect takip edildi, history doğru")
        else:
            fail(f"TEST 3: status={r.status_code} history={len(r.history)}")
    except Exception as e:
        fail(f"TEST 3: {e}")

                                                                               
section("TEST 4 — Timeout")
                                                                               
with Session(impersonate="chrome_131", timeout=1.0) as s:
    try:
        s.get("https://httpbingo.org/delay/5")
        fail("TEST 4: Timeout tetiklenmedi!")
    except (TimeoutError, ConnectionError, OSError) as e:
        ok(f"TEST 4 BAŞARILI: {type(e).__name__}")

                                                                               
section("TEST 5 — raise_for_status()")
                                                                               
with Session(impersonate="chrome_131", timeout=15.0) as s:
    try:
        r = s.get("https://httpbingo.org/status/404")
        r.raise_for_status()
        fail("TEST 5: Exception fırlatılmadı!")
    except HTTPStatusError as e:
        ok(f"TEST 5 BAŞARILI: HTTPStatusError yakalandı — {e}")
    except Exception as e:
        fail(f"TEST 5: {e}")

                                                                               
section("TEST 6 — Multipart Dosya Yükleme")
                                                                               
with Session(impersonate="chrome_131", timeout=15.0) as s:
    try:
        fake_file = io.BytesIO(b"fasthttpc test dosyasi 123")
        r = s.post(
            "https://httpbingo.org/post",
            files={"upload": ("test.txt", fake_file, "text/plain")},
            data={"extra_field": "merhaba"},
        )
        info(f"Status: {r.status_code}")
        body = r.text()
        if "test.txt" in body and "merhaba" in body:
            ok("TEST 6 BAŞARILI: Dosya ve form alanı sunucuya ulaştı")
        else:
            fail(f"TEST 6: Beklenen içerik yok → {body[:200]}")
    except Exception as e:
        fail(f"TEST 6: {e}")

                                                                               
section("TEST 7 — Session Ticket Cache")
                                                                               
clear_ticket_cache()
with Session(impersonate="chrome_131", timeout=15.0) as s:
    try:
        s.get("https://www.cloudflare.com/cdn-cgi/trace")                  
        from fasthttpc.tls_crafter import _ticket_cache, _ticket_lock
        with _ticket_lock:
            cached = dict(_ticket_cache)
        if cached:
            ok(f"TEST 7 BAŞARILI: {len(cached)} host için ticket cache'lendi")
        else:
            info("TEST 7: Sunucu NewSessionTicket göndermedi (bazı sunucular göndermez)")
    except Exception as e:
        fail(f"TEST 7: {e}")

                                                                               
section("TEST 8 — Firefox 133 Profili")
                                                                               
with Session(impersonate="firefox_133", timeout=15.0) as s:
    try:
        r = s.get("https://httpbingo.org/get")
        ok("TEST 8 BAŞARILI") if r.is_success else fail(f"TEST 8: {r.status_code}")
    except Exception as e:
        fail(f"TEST 8: {e}")

                                                                               
section("TEST 9 — Cookie Yönetimi")
                                                                               
with Session(impersonate="chrome_131", timeout=15.0) as s:
    try:
        s.get("https://httpbingo.org/cookies/set?tok=fasthttpc")
        r = s.get("https://httpbingo.org/cookies")
        info(f"Cookie jar: {s.cookies}")
        if "fasthttpc" in r.text():
            ok("TEST 9 BAŞARILI")
        else:
            fail("TEST 9: Cookie iletilmedi")
    except Exception as e:
        fail(f"TEST 9: {e}")

                                                                               
section("TEST 10 — HEAD ve PATCH metodları")
                                                                               
                                                                           
_HEAD_ENDPOINTS = [
    "https://www.google.com/",
    "https://www.instagram.com/",
    "https://www.cloudflare.com/",
]

with Session(impersonate="chrome_131", timeout=10.0) as s:
    _head_ok = False
    for _ep in _HEAD_ENDPOINTS:
        try:
            r_head = s.head(_ep)
            info(f"HEAD {_ep} → {r_head.status_code}  body_len: {len(r_head.body)}")
            if r_head.status_code in (200, 301, 302) and len(r_head.body) == 0:
                ok(f"HEAD doğru çalışıyor — {_ep}")
                _head_ok = True
                break
        except Exception as e:
            info(f"HEAD {_ep} → {e}, sonraki deneniyor...")
    if not _head_ok:
        fail("HEAD: Hiçbir endpoint cevap vermedi")

    try:
        r_patch = s.patch("https://httpbingo.org/patch", json={"key": "val"})
        ok("PATCH BAŞARILI") if r_patch.is_success else fail(f"PATCH: {r_patch.status_code}")
    except Exception as e:
        fail(f"PATCH: {e}")

print(f"\n{'='*60}")
print("  🏁 TÜM TESTLER TAMAMLANDI")
print(f"{'='*60}\n")
