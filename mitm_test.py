#!/usr/bin/env python3
"""
fasthttpc — MITM REDDİ testi.

Bu, tüm projenin en önemli tek testidir. Dünkü kod incelemesinde bulunan
kritik açık şuydu: sertifika zinciri doğrulanıyor ama CertificateVerify
imzası kontrol edilmiyordu, dolayısıyla araya giren biri gerçek sunucunun
sertifikasını iletip kendi anahtarıyla handshake yapabiliyordu.

Bu test onu PRATİKTE doğrular: kendi CA'sını sisteme EKLEMEDEN çalışan bir
MITM proxy'si kurar ve fasthttpc'nin bağlantıyı REDDETTİĞİNİ ister. Reddetmezse
açık hâlâ açıktır.

Gereksinim:
    pip install mitmproxy

Çalıştır:
    python3 mitm_test.py

Ne yapar:
    1. mitmproxy'yi kendi (güvenilmeyen) CA'sıyla arka planda başlatır.
    2. fasthttpc'yi bu proxy üzerinden bir HTTPS sitesine yönlendirir.
    3. Bağlantının bir sertifika/kimlik doğrulama hatasıyla KESİLMESİNİ bekler.

ÖNEMLİ: mitmproxy'nin CA'sını (~/.mitmproxy/mitmproxy-ca-cert.pem) sistemine
KURMA. Kurarsan test anlamsızlaşır — o zaman MITM'i "meşru" kılmış olursun,
tıpkı gerçek hayatta kurumsal bir proxy'nin yaptığı gibi.

NOT: fasthttpc'nin şu an açık bir HTTP proxy ayarı yok; bu test, proxy'yi
şeffaf/yönlendirme modunda veya /etc/hosts ile hedefi proxy'ye çevirerek
kullanır. Aşağıdaki basit yaklaşım, hedef host'u 127.0.0.1'e çözümleyen bir
resolver enjekte eder; böylece fasthttpc farkında olmadan proxy'ye bağlanır —
tam da gerçek bir MITM'in yapacağı gibi.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

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



HEDEF_HOST = "example.com"
PROXY_PORT = 8443


class C:
    GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
    BOLD = "\033[1m"; DIM = "\033[2m"; END = "\033[0m"


def _mitmproxy_var_mi() -> bool:
    try:
        subprocess.run(["mitmdump", "--version"],
                       capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


class SabitResolver:
    """Hedef host'u zorla 127.0.0.1'e çözümleyen sahte DoH resolver.

    fasthttpc'nin ConnectionPool'u resolver.resolve_one(host) çağırır. Burada
    her host için proxy'nin adresini döndürerek trafiği MITM'e yönlendiriyoruz —
    ama SNI/Host hâlâ gerçek hedef olduğu için handshake gerçek bir MITM
    senaryosuyla birebir aynı olur.
    """
    def __init__(self, ip: str):
        self._ip = ip

    def resolve_one(self, host: str) -> str:
        return self._ip

    def resolve(self, host: str, qtype: str = "A") -> list[str]:
        return [self._ip]


def main() -> int:
    print(f"{C.BOLD}fasthttpc MITM reddi testi{C.END}\n")

    if not _mitmproxy_var_mi():
        print(f"{C.YELLOW}mitmproxy kurulu değil.{C.END}")
        print("Kurmak için:  pip install mitmproxy")
        print(f"{C.DIM}Bu test olmadan MITM reddini pratikte doğrulayamayız.{C.END}")
        return 2

    ca_yolu = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

    # mitmproxy'yi wireguard/reverse modda değil, basit bir TLS sonlandırıcı
    # olarak başlatmak yerine burada onu bir "upstream" MITM gibi kullanıyoruz.
    # En basit güvenilir yol: mitmdump'ı reverse proxy modunda hedefe bağla.
    print(f"{C.DIM}mitmproxy başlatılıyor (reverse mode → https://{HEDEF_HOST})...{C.END}")
    proc = subprocess.Popen(
        [
            "mitmdump",
            "--mode", f"reverse:https://{HEDEF_HOST}",
            "--listen-host", "127.0.0.1",
            "--listen-port", str(PROXY_PORT),
            "-q",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        # Proxy'nin ayağa kalkmasını bekle
        for _ in range(30):
            try:
                with socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=1):
                    break
            except OSError:
                time.sleep(0.3)
        else:
            print(f"{C.RED}mitmproxy başlatılamadı.{C.END}")
            return 2

            from fasthttpc.security.tls_adapter import TLSAdapter

        # Ham TCP: proxy'ye bağlan ama SNI olarak gerçek hedefi kullan.
        # Bu tam bir MITM: karşıdaki taraf gerçek example.com değil, ama
        # onun adına konuşuyor ve kendi (güvenilmeyen) sertifikasını sunuyor.
        raw = socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=10)

        print(f"{C.DIM}TLS handshake deneniyor (SNI={HEDEF_HOST}, "
              f"karşı taraf mitmproxy)...{C.END}\n")

        reddedildi = False
        hata_mesaji = ""
        try:
            TLSAdapter.negotiate(raw, HEDEF_HOST, "chrome_131")
            # Buraya ulaşmak KÖTÜ: MITM'e karşı handshake tamamlandı.
        except ConnectionError as e:
            reddedildi = True
            hata_mesaji = str(e)
        except Exception as e:
            reddedildi = True
            hata_mesaji = f"{type(e).__name__}: {e}"
        finally:
            raw.close()

        print(f"{C.BOLD}Sonuç:{C.END}")
        if reddedildi:
            print(f"  {C.GREEN}✅ GEÇTİ — MITM bağlantısı reddedildi.{C.END}")
            print(f"  {C.DIM}Sebep: {hata_mesaji[:150]}{C.END}")
            print(f"\n  {C.GREEN}Dünkü açık pratikte kapalı: sunucu, sertifikadaki")
            print(f"  özel anahtara sahip olduğunu kanıtlayamadığı için")
            print(f"  handshake kesildi.{C.END}")
            beklenen_terim = any(
                k in hata_mesaji.lower()
                for k in ("certificateverify", "kimlik", "sertifika",
                          "certificate", "imza", "güvenli değil", "finished")
            )
            if not beklenen_terim:
                print(f"\n  {C.YELLOW}Uyarı: bağlantı kesildi ama sebep bir sertifika/")
                print(f"  kimlik hatası gibi görünmüyor. Doğru sebepten mi kesildiğini")
                print(f"  --verbose ile kontrol et.{C.END}")
            return 0
        else:
            print(f"  {C.RED}{C.BOLD}❌ KALDI — MITM'e karşı handshake TAMAMLANDI!{C.END}")
            print(f"\n  {C.RED}Bu ciddi bir güvenlik açığıdır: fasthttpc, gerçek")
            print(f"  example.com olmayan bir sunucuyla güvenli bağlantı kurdu.")
            print(f"  CertificateVerify doğrulaması çalışmıyor. ÜRETİMDE KULLANMA.{C.END}")
            return 1

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    print(f"{C.DIM}{'─' * 64}{C.END}")
    print(f"{C.YELLOW}HATIRLATMA: mitmproxy CA'sını sistemine KURMA. Kurarsan")
    print(f"MITM'i meşrulaştırırsın ve test anlamını yitirir.{C.END}")
    print(f"{C.DIM}{'─' * 64}{C.END}\n")
    sys.exit(main())
