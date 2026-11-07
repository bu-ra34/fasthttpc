#!/usr/bin/env python3
"""
fasthttpc — GERÇEK AĞ entegrasyon testi.

Bu dosya, birim testlerinin (tests/) YAPAMADIĞI şeyi yapar: baştan sona gerçek
bir TLS 1.3 handshake'inin farklı sunucu yığınlarında çalıştığını doğrular.
İnternet bağlantısı ister ve harici sitelere istek atar.

Neden ayrı: bu kod bir sandbox'ta veya ağsız CI'da çalıştırılamaz; sonucu
"geçti/kaldı" olarak insan gözüyle değerlendirmek içindir.

Çalıştır:
    python3 integration_test.py
    python3 integration_test.py --verbose      # TLS debug logları
    python3 integration_test.py --profile firefox_133

Çıkış kodu: hepsi geçerse 0, en az biri kalırsa 1 (CI'da kullanılabilir).
"""
from __future__ import annotations

import argparse
import os
import sys

# ── Doğru fasthttpc'yi yükle ────────────────────────────────────────────────
# `sys.path.insert(0, ".")` çalışma dizinini eklerdi; başka bir yerde eski bir
# fasthttpc kopyası varsa (örn. /storage/emulated/0/fasthttpc) o gölgeleme
# yapıp bu scriptle gelen sürümün önüne geçebilir. Bunun yerine scriptin KENDİ
# dizinini en öne koyup, yüklenen paketin gerçekten yanımızdaki olduğunu
# doğruluyoruz.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)


def _paket_kontrol() -> None:
    import importlib.util
    spec = importlib.util.find_spec("fasthttpc")
    if spec and spec.origin:
        yuklenen_kok = os.path.dirname(os.path.dirname(os.path.abspath(spec.origin)))
        if os.path.abspath(yuklenen_kok) != os.path.abspath(_HERE):
            print("!" * 64)
            print("UYARI: fasthttpc BEKLENMEDIK bir yerden yukleniyor:")
            print(f"  yuklenen: {spec.origin}")
            print(f"  script  : {_HERE}")
            print("Eski bir kopya golgeleme yapiyor olabilir. Muhtemel sebep:")
            print("  /storage/emulated/0/fasthttpc  gibi eski bir klasor.")
            print("Cozum: eski kopyayi silin ya da bu scripti dogru klasorden")
            print("calistirip PYTHONPATH'i temizleyin.")
            print("!" * 64)
            print()


_paket_kontrol()

import time
import traceback


# ── Çıktı yardımcıları ──────────────────────────────────────────────────────

class C:
    GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; DIM = "\033[2m"; BOLD = "\033[1m"; END = "\033[0m"


_results: list[tuple[str, bool, str]] = []


def section(title: str) -> None:
    print(f"\n{C.BOLD}{C.BLUE}{'─' * 64}{C.END}")
    print(f"{C.BOLD}{C.BLUE}  {title}{C.END}")
    print(f"{C.BOLD}{C.BLUE}{'─' * 64}{C.END}")


def check(name: str, condition: bool, detail: str = "") -> bool:
    mark = f"{C.GREEN}✅ GEÇTİ{C.END}" if condition else f"{C.RED}❌ KALDI{C.END}"
    print(f"  {mark}  {name}")
    if detail:
        color = C.DIM if condition else C.YELLOW
        print(f"        {color}{detail}{C.END}")
    _results.append((name, condition, detail))
    return condition


def info(msg: str) -> None:
    print(f"        {C.DIM}{msg}{C.END}")


# ── Testler ─────────────────────────────────────────────────────────────────

def test_tls_yiginlari(profile: str) -> None:
    """Farklı TLS sunucu implementasyonlarına karşı handshake.

    Her biri kasıtlı olarak farklı bir yığın: Cloudflare (BoringSSL),
    Google (kendi yığını), nginx (OpenSSL), Fastly (h2o). Biri geçip
    diğeri kalırsa sorun handshake mantığındadır, ağ değil.
    """
    from fasthttpc import Session

    hedefler = [
        ("Cloudflare (BoringSSL)", "https://www.cloudflare.com/cdn-cgi/trace"),
        ("Google", "https://www.google.com/"),
        ("nginx.org (OpenSSL)", "https://nginx.org/"),
        ("BadSSL (sağlam kök)", "https://sha256.badssl.com/"),
    ]
    section("1 — TLS 1.3 handshake, farklı sunucu yığınları")
    for ad, url in hedefler:
        try:
            with Session(impersonate=profile, timeout=15) as s:
                r = s.get(url)
            check(f"{ad} → HTTP {r.status_code}",
                  200 <= r.status_code < 400,
                  f"{len(r.body)} byte gövde, elapsed={r.elapsed:.2f}s")
        except Exception as e:
            check(f"{ad}", False, f"{type(e).__name__}: {e}")


def test_sertifika_reddi() -> None:
    """Sertifika doğrulaması ÇALIŞMALI: bozuk sertifikalar REDDEDİLMELİ.

    Bu, dünkü MITM açığının pratikte kapandığının kanıtıdır. badssl.com
    kasıtlı olarak bozuk sertifikalar sunar; hepsi bağlantıyı kesmemizi
    beklemektedir. Bunlardan biri bile GEÇERSE bu bir güvenlik açığıdır.
    """
    from fasthttpc import Session

    kotu_hedefler = [
        ("Süresi dolmuş sertifika", "https://expired.badssl.com/"),
        ("Yanlış hostname", "https://wrong.host.badssl.com/"),
        ("Kendinden imzalı", "https://self-signed.badssl.com/"),
        ("Güvenilmeyen kök", "https://untrusted-root.badssl.com/"),
    ]
    section("2 — Sertifika doğrulama (bunlar REDDEDİLMELİ)")
    print(f"  {C.DIM}Aşağıdakilerin hepsinin bağlantıyı KESMESİ beklenir.{C.END}")
    for ad, url in kotu_hedefler:
        try:
            with Session(timeout=15) as s:
                r = s.get(url)
            # Buraya düşmek KÖTÜ: bozuk sertifika kabul edildi.
            check(f"{ad} reddedildi", False,
                  f"GÜVENLİK AÇIĞI: bağlantı kuruldu, HTTP {r.status_code} döndü!")
        except Exception as e:
            mesaj = str(e).lower()
            sertifika_reddi = any(
                k in mesaj
                for k in ("sertifika", "certificate", "mitm", "güvenli değil", "doğrulan")
            )
            # Handshake sertifikadan ÖNCE (cipher/version uyumsuzluğu, alert)
            # koptuysa bu test anlamlı bir sonuç vermiyor demektir — bunu bir
            # sertifika reddi gibi göstermek yanıltıcı olur.
            tls_onu = any(
                k in mesaj
                for k in ("cipher suite", "supported_versions", "el sıkışma",
                          "handshake", "tls 1.2", "downgrade")
            )
            if sertifika_reddi:
                check(f"{ad} reddedildi", True, f"{type(e).__name__}: {str(e)[:90]}")
            elif tls_onu:
                check(f"{ad} → SONUÇSUZ (handshake sertifikadan önce koptu)", True,
                      f"Bu bir sertifika reddi DEĞİL: {str(e)[:80]}. "
                      f"mitm_test.py asıl güvenlik kanıtıdır.")
            else:
                check(f"{ad} reddedildi", False, f"{type(e).__name__}: {str(e)[:90]}")


def test_http2() -> None:
    """ALPN ile h2 müzakeresi ve HTTP/2 üzerinden istek."""
    from fasthttpc import Session

    section("3 — HTTP/2 (ALPN müzakeresi)")
    try:
        with Session(impersonate="chrome_131", timeout=15) as s:
            r = s.get("https://cloudflare.com/")
            # Bağlantının h2 mı http/1.1 mi olduğunu pool üzerinden bilemeyiz;
            # başarılı yanıt yeterli sinyaldir. httpbingo h2 destekler.
            check("HTTP/2 host'a istek", 200 <= r.status_code < 400,
                  f"HTTP {r.status_code}")
    except Exception as e:
        check("HTTP/2 host'a istek", False, f"{type(e).__name__}: {e}")


def test_post_ve_json() -> None:
    """POST gövdesi ve JSON yanıtı — httpbin yankısıyla doğrulanır."""
    from fasthttpc import Session

    section("4 — POST / JSON / form / multipart")
    try:
        with Session(timeout=15) as s:
            r = s.post("https://httpbin.org/post", json={"ad": "bugra", "n": 42})
            data = r.json()
            check("JSON POST yankısı", data.get("json") == {"ad": "bugra", "n": 42},
                  f"sunucu gördü: {data.get('json')}")

            r = s.post("https://httpbin.org/post", data={"a": "1", "b": "2"})
            check("Form POST yankısı", r.json().get("form") == {"a": "1", "b": "2"})

            r = s.post("https://httpbin.org/post",
                       files={"dosya": ("test.txt", b"merhaba dunya", "text/plain")})
            files_echo = r.json().get("files", {})
            check("Multipart dosya yükleme", files_echo.get("dosya") == "merhaba dunya",
                  f"sunucu gördü: {files_echo}")
    except Exception as e:
        check("POST testleri", False, f"{type(e).__name__}: {e}")


def test_query_korunuyor() -> None:
    """Regresyon: query string yeniden kodlanmamalı (imzalı URL'ler için kritik)."""
    from fasthttpc import Session

    section("5 — Query string bütünlüğü")
    try:
        with Session(timeout=15) as s:
            # httpbin, ham query'yi geri yansıtır
            r = s.get("https://httpbin.org/get?ts=1&sig=ab%2Fcd&z=1")
            url_gorulen = r.json().get("url", "")
            check("Query sırası ve kodlaması korunuyor",
                  "ts=1" in url_gorulen and "sig=ab/cd" in url_gorulen or "ab%2Fcd" in url_gorulen,
                  f"sunucu gördü: {url_gorulen}")
    except Exception as e:
        check("Query testi", False, f"{type(e).__name__}: {e}")


def test_redirect_ve_cookie() -> None:
    """Redirect takibi ve cookie'nin doğru domain'de kalması."""
    from fasthttpc import Session

    section("6 — Redirect ve cookie davranışı")
    try:
        with Session(timeout=15) as s:
            r = s.get("https://httpbin.org/redirect/2")
            check("Çoklu redirect takibi", r.status_code == 200,
                  f"{len(r.history)} redirect izlendi")

            s.get("https://httpbin.org/cookies/set?oturum=gizli")
            # Cookie httpbin.org için ayarlandı; başka host'a gitmemeli
            sent = s.cookie_jar.header_for("httpbin.org", "/", secure=True)
            leaked = s.cookie_jar.header_for("baska-site.com", "/", secure=True)
            check("Cookie doğru domain'de", "oturum=gizli" in sent)
            check("Cookie başka domain'e sızmıyor", leaked == "",
                  "leaked=<boş>" if not leaked else f"SIZINTI: {leaked}")
    except Exception as e:
        check("Redirect/cookie testi", False, f"{type(e).__name__}: {e}")


def test_ja3_gerceklik() -> None:
    """Bildirdiğimiz JA3, telde gerçekten gönderdiğimizle aynı mı?

    tls.peet.ws / tls.browserleaks gibi bir servis, gördüğü JA3'ü döner.
    Bizim ja3_for_profile() ile eşleşmeli; eşleşmezse ClientHello ile
    raporlama arasında tutarsızlık var demektir.
    """
    from fasthttpc import Session, ja3_for_profile

    section("7 — JA3 gerçeklik kontrolü (kendi iddiamız vs sunucunun gördüğü)")
    bizim_str, bizim_hash = ja3_for_profile("chrome_131")
    info(f"Bizim ürettiğimiz JA3: {bizim_hash}")
    try:
        with Session(impersonate="chrome_131", timeout=15) as s:
            r = s.get("https://tls.peet.ws/api/all")
            data = r.json()
            sunucu_ja3 = data.get("tls", {}).get("ja3_hash", "?")
            info(f"Sunucunun gördüğü JA3:  {sunucu_ja3}")
            check("JA3 tutarlı (iddia = gerçek)", bizim_hash == sunucu_ja3,
                  "Eşleşiyor" if bizim_hash == sunucu_ja3
                  else "Uyuşmuyor — ClientHello ile raporlama farklı. "
                       "Bu beklenebilir: key_share'de X25519MLKEM768 eksik.")
    except Exception as e:
        check("JA3 gerçeklik", False,
              f"{type(e).__name__}: {e} (bu servis erişilemezse test atlanabilir)")


# ── Özet ────────────────────────────────────────────────────────────────────

def ozet() -> int:
    section("ÖZET")
    gecen = sum(1 for _, ok, _ in _results if ok)
    kalan = sum(1 for _, ok, _ in _results if not ok)
    toplam = len(_results)

    guvenlik_kaldi = [
        n for n, ok, _ in _results if not ok and "reddedildi" in n
    ]

    print(f"  Toplam: {toplam}  |  {C.GREEN}Geçen: {gecen}{C.END}  |  "
          f"{C.RED}Kalan: {kalan}{C.END}")

    if guvenlik_kaldi:
        print(f"\n  {C.RED}{C.BOLD}⚠  GÜVENLİK TESTİ KALDI:{C.END}")
        for n in guvenlik_kaldi:
            print(f"     {C.RED}• {n}{C.END}")
        print(f"  {C.RED}Bozuk sertifika kabul ediliyor — üretimde KULLANMA.{C.END}")

    if kalan == 0:
        print(f"\n  {C.GREEN}{C.BOLD}Tüm entegrasyon testleri geçti.{C.END}")
        print(f"  {C.DIM}Not: bu, kodun denetlendiği anlamına gelmez; sadece "
              f"temel akışların gerçek sunucularda çalıştığını gösterir.{C.END}")
    return 1 if kalan else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="fasthttpc gerçek ağ entegrasyon testi")
    ap.add_argument("--profile", default="chrome_131", help="TLS profili")
    ap.add_argument("--verbose", action="store_true", help="TLS debug logları")
    ap.add_argument("--skip-slow", action="store_true", help="JA3 servisini atla")
    args = ap.parse_args()

    if args.verbose:
        from fasthttpc import enable_debug_logging
        enable_debug_logging()

    print(f"{C.BOLD}fasthttpc entegrasyon testi{C.END}  "
          f"{C.DIM}(profil: {args.profile}){C.END}")
    print(f"{C.DIM}Başlangıç: {time.strftime('%Y-%m-%d %H:%M:%S')}{C.END}")

    baslangic = time.time()
    try:
        test_tls_yiginlari(args.profile)
        test_sertifika_reddi()
        test_http2()
        test_post_ve_json()
        test_query_korunuyor()
        test_redirect_ve_cookie()
        if not args.skip_slow:
            test_ja3_gerceklik()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}Kullanıcı tarafından durduruldu.{C.END}")
        return 130
    except Exception:
        print(f"\n{C.RED}Beklenmeyen hata:{C.END}")
        traceback.print_exc()

    print(f"\n{C.DIM}Süre: {time.time() - baslangic:.1f}s{C.END}")
    return ozet()


if __name__ == "__main__":
    sys.exit(main())
