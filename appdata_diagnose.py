#!/usr/bin/env python3
"""
fasthttpc — application-data teşhisi.

tls_diagnose.py yalnızca ServerHello'ya kadar bakar. Bu araç bir adım öteye
gider: TAM handshake yapar, ALPN sonucunu gösterir, basit bir istek gönderir ve
ilk şifresi çözülmüş byte'ları HAM olarak döker.

Amaç, entegrasyon testindeki "invalid literal for int" / çöp-veri sorununun
kaynağını ayırt etmek:
  - İlk byte'lar "HTTP/1.1 200..." gibi okunuyorsa  → şifre çözme DOĞRU,
    sorun üst katmanda (HTTP parse).
  - İlk byte'lar çöp ise                            → application-data AEAD
    şifre çözme YANLIŞ (anahtar/nonce/transcript hatası).

Çalıştır:
    python3 appdata_diagnose.py tls.peet.ws       # çalışan referans
    python3 appdata_diagnose.py www.cloudflare.com
    python3 appdata_diagnose.py www.google.com
"""
from __future__ import annotations

import os
import socket
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)


def _paket_kontrol() -> None:
    import importlib.util
    spec = importlib.util.find_spec("fasthttpc")
    if spec and spec.origin:
        kok = os.path.dirname(os.path.dirname(os.path.abspath(spec.origin)))
        if os.path.abspath(kok) != os.path.abspath(_HERE):
            print("!" * 60)
            print(f"UYARI: fasthttpc beklenmedik yerden yukleniyor:\n  {spec.origin}")
            print(f"script: {_HERE}\nEski bir kopya golgeleme yapiyor olabilir.")
            print("!" * 60, "\n")


_paket_kontrol()


def diagnose(host: str, port: int = 443) -> None:
    from fasthttpc.security.tls_adapter import TLSAdapter

    print(f"=== {host}:{port} ===\n")
    raw = socket.create_connection((host, port), timeout=15)

    try:
        esock = TLSAdapter.negotiate(raw, host, "chrome_131")
    except Exception as e:
        import traceback
        print(f"Handshake BAŞARISIZ: {type(e).__name__}: {e}")
        traceback.print_exc()
        raw.close()
        return

    alpn = esock.state.get("alpn", "")
    cipher = esock.state.get("cipher_name", "?")
    keylen = esock.state.get("key_len", "?")
    print("Handshake BAŞARILI")
    print(f"  seçilen ALPN     : {alpn!r}  "
          f"({'HTTP/2' if alpn == 'h2' else 'HTTP/1.1' if alpn else 'yok'})")
    print(f"  cipher           : {cipher}  (key_len={keylen})")
    print(f"  peer sertifika   : {esock.state.get('peer_certificate') is not None}")

    # ALPN'e göre uygun bir istek gönder
    if alpn == "h2":
        print("\n  ALPN=h2 → HTTP/2 preface + basit GET gönderiliyor")
        print("  (h2 için ham frame'lere bakmak gerekir; aşağıdaki ilk")
        print("   application record'un içeriği bir h2 frame olmalı:")
        print("   ilk byte'lar SETTINGS frame'i = 00 00 xx 04 ... gibi görünür)")
        # HTTP/2 connection preface
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        esock.send_record(preface, content_type=0x17)
        # boş SETTINGS
        import struct
        settings = struct.pack("!I", 0)[1:] + b"\x04\x00" + b"\x00\x00\x00\x00"
        esock.send_record(settings, content_type=0x17)
    else:
        print("\n  HTTP/1.1 GET / gönderiliyor")
        req = (
            f"GET / HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: fasthttpc-diagnose\r\nAccept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        esock.send_record(req, content_type=0x17)

    # İlk application record'unu şifre çöz
    try:
        data, ctype = esock.recv_record()
    except Exception as e:
        print(f"\n  İlk yanıt okunamadı: {type(e).__name__}: {e}")
        raw.close()
        return

    print(f"\n  İlk application record: content_type={ctype}, {len(data)} byte")
    print(f"  HEX (ilk 48 byte): {data[:48].hex()}")
    print(f"  ASCII (güvenli)  : {_safe_ascii(data[:80])}")

    print("\nYORUM:")
    if ctype == 22:
        hs = data[0] if data else -1
        isim = {4: "NewSessionTicket", 24: "KeyUpdate"}.get(hs, f"handshake(0x{hs:02x})")
        print(f"  content_type=22 → bu bir POST-HANDSHAKE mesajı ({isim}).")
        print(f"  ŞİFRE ÇÖZME DOĞRU çalışıyor — okunabilir, geçerli bir TLS mesajı çıktı.")
        print(f"  Bu record HTTP verisi DEĞİL; HTTP katmanı bunu yutmalı. Eğer test")
        print(f"  'invalid literal for int' veriyorsa sebep buydu: NewSessionTicket")
        print(f"  bir HTTP/2 frame sanılıyordu. (v0.2.4'te düzeltildi.)")
    elif alpn == "h2":
        if len(data) >= 4 and data[3] <= 0x09:
            print(f"  İlk byte'lar geçerli bir h2 frame gibi görünüyor "
                  f"(frame_type=0x{data[3]:02x}). Şifre çözme doğru.")
        else:
            print("  content_type=23 ama h2 frame'e benzemiyor — h2 parser'ı incele.")
    else:
        if data[:5] == b"HTTP/":
            print("  'HTTP/' ile başlıyor → şifre çözme ve HTTP yolu doğru.")
        else:
            print("  content_type=23, HTTP/ ile başlamıyor — HTTP/1.1 parse'ı incele.")

    raw.close()


def _safe_ascii(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "·" for c in b)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım: python3 appdata_diagnose.py <host> [port]")
        sys.exit(1)
    h = sys.argv[1]
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    try:
        diagnose(h, p)
    except Exception as e:
        import traceback
        traceback.print_exc()
