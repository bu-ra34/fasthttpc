"""
fasthttpc vs httpx Hız Karşılaştırma Testi
============================================

Kullanım:
    1. Bu dosyayı, "fasthttpc_clean" klasörünün YANINA koy (aynı dizin seviyesi).
       Örnek dizin yapısı:
           benchmark.py
           fasthttpc_clean/
               __init__.py
               session.py
               crypto_math.py
               ...

    2. Gerekli paketleri kur:
           pip install httpx cryptography certifi

    3. Çalıştır:
           python3 benchmark.py

Bu script iki şeyi test eder:
  A) Ham şifreleme hızı (AES-GCM): pure-Python motor vs OpenSSL
  B) Gerçek HTTP isteği süresi: fasthttpc Session vs httpx Client
     (aynı URL'lere N kez istek atıp ortalama süreyi karşılaştırır)
"""
import os
os.environ.setdefault("CRYPTOGRAPHY_OPENSSL_NO_LEGACY", "1")

import sys
import time
import statistics

# fasthttpc'i içeren dizini yola ekle (bu dosyanın yanında olduğunu varsayar)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def print_header(title: str) -> None:
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)


# ---------------------------------------------------------------------------
# BÖLÜM A: Ham şifreleme hızı (AES-GCM) — pure-Python vs OpenSSL
# ---------------------------------------------------------------------------
def benchmark_crypto():
    print_header("A) Ham AES-GCM Şifreleme Hızı")

    try:
        from fasthttpc.crypto_math import PureAESGCM, FastAESGCM
    except ImportError as e:
        print(f"[HATA] fasthttpc.crypto_math import edilemedi: {e}")
        print("       Bu dosyanın fasthttpc/ klasörünün yanında olduğundan emin ol.")
        return

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        print("[HATA] 'cryptography' paketi kurulu değil. `pip install cryptography` çalıştır.")
        return

    key = os.urandom(16)
    iv = os.urandom(12)
    data_sizes_kb = [1, 16, 64]

    for size_kb in data_sizes_kb:
        data = os.urandom(size_kb * 1024)

        # Eski pure-Python motor (artık gerçek trafik akışında KULLANILMIYOR — sadece referans)
        cipher_old = PureAESGCM(key)
        start = time.perf_counter()
        cipher_old.encrypt_gcm(iv, data, b"")
        pure_elapsed = time.perf_counter() - start

        # Gerçek pipeline: fasthttpc.security.tls_adapter'ın kullandığı motor (OpenSSL sarmalayıcı)
        cipher_new = FastAESGCM(key)
        start = time.perf_counter()
        cipher_new.encrypt_gcm(iv, data, b"")
        fasthttpc_elapsed = time.perf_counter() - start

        # OpenSSL (cryptography kütüphanesi üzerinden — httpx'in kullandığı ile aynı katman)
        aesgcm = AESGCM(key)
        start = time.perf_counter()
        aesgcm.encrypt(iv, data, None)
        openssl_elapsed = time.perf_counter() - start

        speedup_vs_old = pure_elapsed / fasthttpc_elapsed if fasthttpc_elapsed > 0 else float("inf")

        print(f"\n  {size_kb} KB veri:")
        print(f"    fasthttpc (eski pure-Python, artık kullanılmıyor) : {pure_elapsed * 1000:8.3f} ms")
        print(f"    fasthttpc (güncel, FastAESGCM/OpenSSL)            : {fasthttpc_elapsed * 1000:8.4f} ms")
        print(f"    httpx (OpenSSL, doğrudan)                         : {openssl_elapsed * 1000:8.4f} ms")
        print(f"    -> fasthttpc'nin OpenSSL geçişi eski motora göre {speedup_vs_old:,.0f}x daha hızlı")


# ---------------------------------------------------------------------------
# BÖLÜM B: Gerçek HTTP istekleri — fasthttpc Session vs httpx Client
# ---------------------------------------------------------------------------
def benchmark_http_requests(url: str = "https://example.com", n_requests: int = 20):
    print_header(f"B) Gerçek HTTP İsteği Süresi ({n_requests}x GET {url})")

    # --- fasthttpc ---
    fasthttpc_times = []
    try:
        from fasthttpc.session import Session as FastHTTPCSession

        with FastHTTPCSession(impersonate="chrome_131", timeout=15) as s:
            for i in range(n_requests):
                start = time.perf_counter()
                try:
                    r = s.get(url)
                    elapsed = time.perf_counter() - start
                    fasthttpc_times.append(elapsed)
                    print(f"  [fasthttpc] istek {i+1}: {elapsed*1000:8.2f} ms (status={r.status_code})")
                except Exception as e:
                    print(f"  [fasthttpc] istek {i+1}: HATA - {e}")
    except ImportError as e:
        print(f"[HATA] fasthttpc.session import edilemedi: {e}")

    # --- httpx ---
    httpx_times = []
    try:
        import httpx

        with httpx.Client(timeout=15) as client:
            for i in range(n_requests):
                start = time.perf_counter()
                try:
                    r = client.get(url)
                    elapsed = time.perf_counter() - start
                    httpx_times.append(elapsed)
                    print(f"  [httpx]     istek {i+1}: {elapsed*1000:8.2f} ms (status={r.status_code})")
                except Exception as e:
                    print(f"  [httpx]     istek {i+1}: HATA - {e}")
    except ImportError:
        print("[HATA] 'httpx' paketi kurulu değil. `pip install httpx` çalıştır.")

    # --- Özet ---
    print("\n  --- Özet (ortalama / medyan) ---")
    if fasthttpc_times:
        avg_fc = statistics.mean(fasthttpc_times)
        med_fc = statistics.median(fasthttpc_times)
        print(f"  fasthttpc: ort={avg_fc*1000:8.2f} ms  medyan={med_fc*1000:8.2f} ms  (min={min(fasthttpc_times)*1000:.2f}, max={max(fasthttpc_times)*1000:.2f})")
    else:
        print("  fasthttpc: ölçüm alınamadı")

    if httpx_times:
        avg_hx = statistics.mean(httpx_times)
        med_hx = statistics.median(httpx_times)
        print(f"  httpx    : ort={avg_hx*1000:8.2f} ms  medyan={med_hx*1000:8.2f} ms  (min={min(httpx_times)*1000:.2f}, max={max(httpx_times)*1000:.2f})")
    else:
        print("  httpx: ölçüm alınamadı")

    if fasthttpc_times and httpx_times:
        avg_fc = statistics.mean(fasthttpc_times)
        avg_hx = statistics.mean(httpx_times)
        med_fc = statistics.median(fasthttpc_times)
        med_hx = statistics.median(httpx_times)
        if avg_hx > 0:
            print(f"\n  -> Ortalamaya göre: httpx, fasthttpc'den {avg_fc/avg_hx:.2f}x hızlı (>1 ise httpx daha yavaş anlamına gelir; ifade kafa karıştırıcıysa medyana bak)")
        if med_hx > 0:
            print(f"  -> Medyana göre (outlier'a dayanıklı): fasthttpc/httpx oranı = {med_fc/med_hx:.2f}  (1'den küçükse fasthttpc daha hızlı)")


if __name__ == "__main__":
    print("fasthttpc vs httpx — Hız Karşılaştırma Testi")
    print("(Gerçek sonuçlar senin donanımına, ağına ve test ettiğin URL'e göre değişir)")

    benchmark_crypto()

    # URL'i istersen değiştirebilirsin. Yavaş/kısıtlı bir sunucu seçersen
    # ağ gecikmesi TLS motorundaki farkı gölgeleyebilir; hızlı, yakın bir
    # sunucu seçmek şifreleme farkını daha net gösterir.
    benchmark_http_requests(url="https://www.google.com", n_requests=20)

    print()
    print("=" * 60)
    print("Not: Bölüm A (ham şifreleme) donanımdan bağımsız, en güvenilir")
    print("karşılaştırmadır. Bölüm B (gerçek istek) ayrıca ağ gecikmesi,")
    print("sunucu yanıt süresi gibi faktörleri de içerir.")
    print("=" * 60)
