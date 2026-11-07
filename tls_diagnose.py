#!/usr/bin/env python3
"""
fasthttpc — TLS handshake teşhis aracı.

Entegrasyon testinde iki host grubu farklı davrandı:
  - tls.peet.ws: TLS 1.3 handshake TAM başarılı (JA3 doğrulandı)
  - nginx/badssl/httpbin: "cipher 0xc02f" (bir TLS 1.2 suite) hatası

Bu araç TEK bir host'a bağlanıp ServerHello'yu HAM byte olarak döker; böylece
sunucunun gerçekten TLS 1.2'ye mi düştüğünü, yoksa bizim ServerHello parse'ımızın
mı kaydığını ayırt edebiliriz. Çıktıyı geliştiriciye getir.

Çalıştır:
    python3 tls_diagnose.py nginx.org
    python3 tls_diagnose.py www.cloudflare.com
    python3 tls_diagnose.py tls.peet.ws      # çalışan referans
"""
from __future__ import annotations

import os
import socket
import struct
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



def dump(host: str, port: int = 443) -> None:
    from fasthttpc.tls_crafter import TLSImpersonator

    print(f"=== {host}:{port} ===\n")

    imp = TLSImpersonator(host, profile="chrome_131")
    client_hello, _, _ = imp.build_client_hello()
    print(f"ClientHello: {len(client_hello)} byte")

    # ClientHello'da teklif edilen cipher'ları göster
    body = client_hello[5 + 4:]
    pos = 2 + 32
    sid = body[pos]; pos += 1 + sid
    cs_len = struct.unpack("!H", body[pos:pos + 2])[0]; pos += 2
    offered = [hex(struct.unpack("!H", body[pos + i:pos + i + 2])[0]) for i in range(0, cs_len, 2)]
    print(f"Teklif edilen cipher'lar ({len(offered)}): {offered}\n")

    sock = socket.create_connection((host, port), timeout=10)
    sock.sendall(client_hello)

    # İlk record'u oku
    hdr = _recv(sock, 5)
    rec_type, ver, rec_len = struct.unpack("!BHH", hdr)
    print(f"İlk record: type={rec_type} "
          f"({'handshake' if rec_type == 22 else 'ALERT!' if rec_type == 21 else rec_type}), "
          f"legacy_version=0x{ver:04x}, len={rec_len}")

    payload = _recv(sock, rec_len)

    if rec_type == 21:
        lvl = payload[0] if payload else "?"
        desc = payload[1] if len(payload) > 1 else "?"
        alerts = {70: "protocol_version", 40: "handshake_failure",
                  47: "illegal_parameter", 50: "decode_error", 109: "missing_extension"}
        print(f"  ⚠ ALERT: level={lvl}, description={desc} "
              f"({alerts.get(desc, 'bilinmiyor')})")
        print("  → Sunucu ClientHello'muzu reddetti. Bir extension eksik/hatalı olabilir.")
        sock.close()
        return

    if rec_type != 22 or not payload or payload[0] != 2:
        print(f"  Beklenmeyen: ilk mesaj ServerHello (hs_type=2) değil. "
              f"hs_type={payload[0] if payload else '?'}")
        sock.close()
        return

    # ServerHello'yu parse et
    sh = payload[4:]
    server_ver = struct.unpack("!H", sh[0:2])[0]
    print(f"\nServerHello:")
    print(f"  legacy_version: 0x{server_ver:04x}")

    hrr = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
    is_hrr = sh[2:34] == hrr
    print(f"  HelloRetryRequest mı: {is_hrr}")

    sid_len = sh[34]
    off = 35 + sid_len
    print(f"  session_id echo uzunluğu: {sid_len}")

    chosen = struct.unpack("!H", sh[off:off + 2])[0]
    print(f"  seçilen cipher: 0x{chosen:04x} "
          f"({'TLS 1.3' if chosen in (0x1301, 0x1302, 0x1303) else 'TLS 1.2 (!)'})")

    ext_len = struct.unpack("!H", sh[off + 3:off + 5])[0]
    print(f"  extensions uzunluğu: {ext_len}")

    # supported_versions extension'ı (43) var mı, TLS 1.3 mü?
    cur = off + 5
    end = cur + ext_len
    tls13 = False
    ext_list = []
    while cur + 4 <= end:
        et, el = struct.unpack("!HH", sh[cur:cur + 4])
        cur += 4
        ext_list.append(f"0x{et:04x}")
        if et == 43 and el >= 2 and struct.unpack("!H", sh[cur:cur + 2])[0] == 0x0304:
            tls13 = True
        cur += el
    print(f"  ServerHello extension'ları: {ext_list}")
    print(f"  supported_versions=TLS1.3 mı: {tls13}")

    print("\nYORUM:")
    if not tls13 and chosen not in (0x1301, 0x1302, 0x1303):
        print("  Sunucu GERÇEKTEN TLS 1.2 seçmiş. ClientHello'muzda TLS 1.3'ü")
        print("  yeterince 'ikna edici' sunmuyoruz — büyük olasılıkla bir extension")
        print("  eksik (key_share grubu, signature_algorithms, ya da supported_versions).")
    elif tls13 and chosen in (0x1301, 0x1302, 0x1303):
        print("  Sunucu TLS 1.3 + geçerli suite seçmiş. Parse doğru; sorun başka yerde.")
    else:
        print("  Tutarsız: supported_versions ile seçilen cipher uyuşmuyor.")
        print("  Muhtemelen ServerHello parse offset'i kayıyor (session_id echo?).")

    sock.close()


def _recv(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım: python3 tls_diagnose.py <host> [port]")
        sys.exit(1)
    h = sys.argv[1]
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    try:
        dump(h, p)
    except Exception as e:
        import traceback
        print(f"HATA: {type(e).__name__}: {e}")
        traceback.print_exc()
