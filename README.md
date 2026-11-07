# fasthttpc

Pure-Python HTTP istemcisi. TLS 1.3 handshake'i, tarayıcı parmak izi taklidi,
HTTP/2 ve async destek içerir.

> **Durum: deneysel.** TLS yığını sıfırdan yazılmıştır. v0.2.0 ile sunucu kimlik
> doğrulaması tam hâle geldi (aşağıya bakın), ama bu kod bağımsız bir güvenlik
> denetiminden geçmedi. Kritik üretim trafiği için `curl_cffi` gibi olgun bir
> alternatifi tercih edin.

## Güvenlik modeli

Her TLS 1.3 bağlantısında sunucu kimliği **üç ayrı kontrolle** doğrulanır ve
üçü de zorunludur:

| Kontrol | Neyi kanıtlar |
|---|---|
| Sertifika zinciri | Sertifikayı güvenilen bir CA imzalamış, hostname eşleşiyor, süresi geçerli |
| **CertificateVerify** | Sunucu sertifikadaki **özel anahtara sahip** (RFC 8446 §4.4.3) |
| **Server Finished** | Handshake transcript'i değiştirilmemiş (§4.4.4) |

İkincisi olmadan sertifika doğrulaması tek başına MITM'i engellemez: sertifika
herkese açık veridir, araya giren biri onu aynen iletip kendi anahtar
değişimini yapabilir. Herhangi biri başarısız olursa bağlantı reddedilir.

Güven kökü olarak `certifi` bundle'ı + varsa sistem CA deposu kullanılır.
Sertifika doğrulamayı kapatmanın bir yolu yoktur; bu kasıtlıdır.

## Kurulum

```bash
git clone https://github.com/kullanici/fasthttpc
cd fasthttpc
pip install -e ".[dev]"
pytest        # 84 test, ağ gerektirmez
```

## Hızlı başlangıç

```python
from fasthttpc import Session

with Session(impersonate="chrome_131") as s:
    r = s.get("https://httpbin.org/get")
    print(r.status_code, r.elapsed)
    print(r.json())
```

### Async

```python
import asyncio
from fasthttpc import AsyncSession

async def main():
    # impersonate=None: async tarafta TLS taklidi YOK (aşağıya bakın)
    async with AsyncSession(impersonate=None) as s:
        r = await s.get("https://httpbin.org/get")
        print(r.status_code)

asyncio.run(main())
```

### Timeout

```python
from fasthttpc import Session, Timeout

with Session(timeout=Timeout(connect=5.0, read=30.0)) as s:
    r = s.get("https://example.com")
```

### Plugin'ler

```python
from fasthttpc import AsyncSession, RetryPlugin, RateLimitPlugin

async with AsyncSession(impersonate=None) as s:
    s.use(RetryPlugin(max_retries=3, retry_on=(429, 500, 502, 503, 504)))
    s.use(RateLimitPlugin(rps=5.0))
    r = await s.get("https://example.com")
```

`RetryPlugin` `Retry-After` başlığına saygı duyar, yoksa üstel bekleme uygular.

### DNS-over-HTTPS

```python
from fasthttpc import Session, DoHResolver

with Session(resolver=DoHResolver(provider="cloudflare")) as s:
    r = s.get("https://example.com")
```

### Multipart

```python
with Session() as s:
    r = s.post("https://httpbin.org/post",
               files={"file": ("test.txt", b"merhaba", "text/plain")})
```

### Proxy

```python
from fasthttpc import Session

# HTTP CONNECT (Proxy-Authorization: Basic dahil)
with Session(proxy="http://kullanici:parola@proxy.local:3128") as s:
    r = s.get("https://example.com")

# SOCKS5 (no-auth veya kullanıcı/parola; hedef adı proxy'de çözülür)
with Session(proxies={"https": "socks5://u:p@127.0.0.1:1080"}) as s:
    r = s.get("https://example.com")
```

TLS (ve parmak izi) her zaman tünelin İÇİNDE fasthttpc'nin kendi TLS 1.3
yığınıyla kurulur; proxy yalnızca TCP baytlarını taşır.

### Logging

Kütüphane `print()` kullanmaz. Ayrıntı görmek için:

```python
from fasthttpc import enable_debug_logging
enable_debug_logging()
```

## Parmak izi doğrulama

`ja3_for_profile()` profil sözlüğünü okumaz — ClientHello'yu gerçekten derleyip
telde giden byte'ları parse eder:

```python
from fasthttpc import ja3_for_profile

ja3_str, ja3_hash = ja3_for_profile("chrome_131")
print(ja3_hash)
```

## Profiller

| Profil | Takma adlar |
|---|---|
| `chrome_131` | `chrome` |
| `firefox_133` | `firefox`, `firefox_120` |
| `safari_18` | `safari`, `safari_17` |
| `default` | — (tarayıcı taklidi yok) |

Bilinmeyen bir profil adı `ValueError` fırlatır; sessizce `default`'a düşmez.

## Bilinen sınırlar

Bunlar bilinçli olarak eksiktir, sessiz hata değildir — hepsi açık hata mesajı
verir veya belgelenmiştir:

- **AsyncSession'da TLS taklidi yok.** `asyncio.open_connection` stdlib `ssl`
  ile çalışır, yani ClientHello Python/OpenSSL parmak izi taşır.
  `impersonate` verilirse `UserWarning` çıkar. Parmak izi gerekiyorsa senkron
  `Session` kullanın.
- **HTTP/2 multiplexing yok.** İstekler aynı bağlantıda sıralı gider.
- **TLS 1.2 bilinçli olarak kapsam dışıdır.** fasthttpc yalnızca TLS 1.3
  konuşur. Profiller gerçek tarayıcılar gibi `supported_versions` içinde
  0x0303'ü ve TLS 1.2 cipher suite'lerini *ilan eder* (parmak izi doğruluğu
  için), ama sunucu TLS 1.3 dışında bir sürüm seçerse bağlantı açık bir hatayla
  reddedilir ("Sunucu TLS 1.2 ile yanıt verdi ..."). ServerHello.random'da
  `DOWNGRD` işareti varsa olası downgrade saldırısı ayrıca belirtilir. Bu bir
  downgrade yolu açmaz: TLS 1.2 handshake'i hiç implemente edilmemiştir.
  Gerekçe: TLS 1.2 (RSA/ECDHE key exchange, CBC/GCM, renegotiation, ayrı PRF,
  extended master secret) ikinci bir tam handshake yığını demektir ve saldırı
  yüzeyini ikiye katlar; günümüzde TLS 1.3 desteklemeyen sunucu oranı düşüktür.
  TLS 1.2-only sunucular için stdlib `ssl` tabanlı `AsyncSession` kullanılabilir.
- **HelloRetryRequest:** destekleniyor (RFC 8446 §4.1.4, cookie dahil); ikinci
  HRR handshake'i sonlandırır.
- **Session resumption (PSK/0-RTT) yok.** Her bağlantı tam handshake yapar.
- **HPACK huffman ENCODE yok** (decode var). Protokolde geçerli, ama h2 parmak
  izinde küçük bir sapma yaratır.
- **key_share grupları:** x25519, secp256r1, secp384r1. Hibrit/post-kuantum
  gruplar (X25519MLKEM768) ve secp521r1/ffdhe implemente edilmedi: bunlar için
  key_share *gönderilmez*; profil supported_groups'ta ilan ediyorsa ve sunucu
  HRR ile bunları isterse açık hata verilir.
- `Session` thread-safe değildir; thread başına bir tane kullanın.

## Modül yapısı

```
fasthttpc/
├── session.py          # Sync HTTP istemcisi
├── async_session.py    # Async istemci + plugin sistemi
├── cookies.py          # RFC 6265 cookie jar (domain/path/Secure)
├── tls_crafter.py      # ClientHello oluşturucu
├── tls_tools.py        # TLS yardımcıları
├── crypto_math.py      # Key schedule + saf Python crypto yedeği
├── fingerprint.py      # Tarayıcı profilleri, JA3
├── buffer.py           # Adaptif alıcı buffer
├── cache.py            # Response cache
├── metrics.py          # İstek metrikleri
├── models/             # URL, Headers, Request, Response
├── protocol/           # HTTP/1.1, HTTP/2, WebSocket, DoH
├── security/           # TLS adapter, sertifika doğrulama
└── transport/          # Connection pool
```

## Testler

```bash
pytest              # ağsız birim testler
python smoke_test.py  # ağ gerektiren elle doğrulama
```

## Lisans

MIT
