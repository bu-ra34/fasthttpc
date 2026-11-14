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

### `verify`: özel CA bundle

Kurumsal ağlarda (iç CA, TLS denetleyen proxy) kendi CA'nızı verebilirsiniz:

```python
with Session(verify="/etc/kurum/ca.pem") as s:   # yalnızca bu CA'lara güvenilir
    s.get("https://intranet.kurum.local/")
```

- `verify=True` (varsayılan): `certifi` + sistem CA deposu.
- `verify="yol/ca.pem"`: güven kökü **yalnızca** bu PEM dosyasındaki
  sertifikalardır (requests'in `verify="ca.pem"` semantiği). Dosya yoksa
  `FileNotFoundError`. CertificateVerify ve Finished kontrolleri aynen yapılır.
- `verify=False` **desteklenmez** ve `ValueError` verir. Doğrulamasız TLS,
  araya giren herkesin trafiği okuyup değiştirebildiği bir bağlantıdır; bunu
  bir bayrağa bağlamak yerine güvenmek istediğiniz CA'yı açıkça vermenizi
  istiyoruz. Kendinden imzalı bir test sunucusu için de o sertifikayı (veya
  imzalayan CA'yı) `verify=` ile verin.

`AsyncSession(verify=...)` da aynı kuralları uygular (stdlib `ssl`'e `cafile`
olarak iletilir).

## Kurulum

```bash
git clone https://github.com/cevpy/fasthttpc
cd fasthttpc
pip install -e ".[dev]"
pytest        # ağ gerektirmez
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
    # Async tarafta da tarayıcı parmak izi taklidi var (kendi TLS 1.3 yığını)
    async with AsyncSession(impersonate="chrome_131") as s:
        r = await s.get("https://httpbin.org/get")
        print(r.status_code)

asyncio.run(main())
```

### requests / httpx'ten geçiş

`Response` requests/httpx alanlarını sunar: `r.status_code`, `r.headers`,
`r.url`, `r.ok`, `r.reason`, `r.encoding`, `r.content` (bytes), `r.json()`,
`r.raise_for_status()`, `r.history`, `r.elapsed` (saniye; `r.elapsed.total_seconds()`
de çalışır).

- `r.text` bir **property**'dir (`str`), requests'teki gibi; kodlama
  Content-Type `charset`'inden gelir (yoksa `utf-8`, hatalı byte'lar `replace`),
  `r.encoding = "latin-1"` ile değiştirilebilir. Geriye uyumluluk: dönen değer
  çağrılabilir olduğundan eski `r.text()` ve `r.text(encoding="latin-1")` aynen
  çalışır.
- `r.json` requests'te olduğu gibi **metottur** (`r.json()`).
- `requests.get(...)` yerine `Session`/`AsyncSession` kullanın; `verify=False`
  desteklenmez (bkz. Güvenlik modeli), `proxies={...}` sözlüğü ve `timeout=`
  (sayı veya `Timeout`) requests ile aynı biçimdedir.

### Timeout ve Limits

httpx'e benzer `Timeout` ve `Limits` (`fasthttpc.config`):

```python
from fasthttpc import Session, Timeout, Limits

with Session(
    timeout=Timeout(10.0, connect=5.0),   # connect=5, read/write/pool=10
    limits=Limits(max_connections=20, max_keepalive_connections=5,
                  keepalive_expiry=30.0),
) as s:
    r = s.get("https://example.com")
```

| `Timeout` alanı | Anlamı |
|---|---|
| `connect` | TCP bağlantısı + TLS el sıkışması |
| `read` | Sunucudan veri bekleme |
| `write` | Veri gönderme (şimdilik senkron tarafta `read` ile aynı soket zaman aşımını paylaşır) |
| `pool` | Havuzdan boş bağlantı bekleme (verilmezse `connect`) |

Geriye dönük uyumluluk: `Session(timeout=30)` ve `Timeout(connect=5, read=30)`
eskisi gibi çalışır; `from fasthttpc.timeout import Timeout` aynı sınıftır.
`limits` verilmezse `max_connections` parametresi kullanılır.

| `Limits` alanı | Varsayılan | Anlamı |
|---|---|---|
| `max_connections` | 10 | Origin başına eşzamanlı bağlantı |
| `max_keepalive_connections` | `None` (= `max_connections`) | Havuzda boşta tutulan bağlantı |
| `keepalive_expiry` | 30.0 | Boştaki bağlantının ömrü (sn); `None` → sınırsız |

### Yeniden deneme (`retries`)

urllib3 `Retry` benzeri bir politika (`fasthttpc.retry`):

```python
from fasthttpc import Session, Retry

retry = Retry(total=5, backoff_factor=0.5, status_forcelist=(429, 502, 503, 504))
with Session(retries=retry) as s:     # Session(retries=3) == Retry(total=3)
    r = s.get("https://api.example.com/items")
```

- Varsayılan kapalıdır (`retries=None`).
- Yalnızca `allowed_methods` yeniden denenir; varsayılan idempotent metotlar
  (GET, HEAD, PUT, DELETE, OPTIONS, TRACE). POST/PATCH için
  `allowed_methods=None` vermeniz gerekir.
- Bağlantı hataları (`ConnectionError`, `TimeoutError`, `OSError`) yeniden
  denenir; sertifika doğrulama hataları **asla** yeniden denenmez.
- 413/429/503 yanıtlarındaki `Retry-After` (saniye veya HTTP-date) bekleme
  süresi olarak kullanılır (`backoff_max` ile sınırlı, varsayılan 120 sn).
- Bekleme: `backoff_factor * 2 ** (n - 1)`. Denemeler tükenince son yanıt
  döner veya son hata fırlatılır.
- Redirect zincirindeki her adım ayrı ayrı yeniden denenir.

### Ağsız test: `MockTransport`

`httpx.MockTransport` benzeri; TLS/havuz/proxy katmanlarını atlar, redirect,
çerez ve retry gibi Session davranışları aynen çalışır:

```python
from fasthttpc import Session, Response, MockTransport

def handler(request):
    if request.url.path == "/login":
        return Response(200, headers={"Set-Cookie": "sid=1"})
    return Response(200, headers={"Content-Type": "application/json"},
                    body=b'{"ok": true}')

transport = MockTransport(handler)
with Session(transport=transport) as s:
    s.get("https://api.example.com/login")
    assert s.get("https://api.example.com/me").json() == {"ok": True}
assert len(transport.requests) == 2
```

Handler'ın fırlattığı istisnalar çağırana iletilir (retry testleri için).
`AsyncSession(transport=...)` ile handler `async def` de olabilir. Kendi
transport'unuz için `fasthttpc.transport.mock.BaseTransport`'tan türetip
`handle_request(request) -> Response` yazmanız yeterli.

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

- **AsyncSession HTTP/2:** `impersonate` verilince ALPN profilin kendi listesidir
  (`h2, http/1.1`; JA3 ve JA4 senkron taraftakiyle aynı). Sunucu `h2` seçerse
  `fasthttpc.protocol.async_h2` ile gerçek multiplexing yapılır: aynı bağlantıda
  eşzamanlı çok istek (`asyncio.gather`), akış kontrolü, SETTINGS, GOAWAY (işlenmeyen
  stream'ler yeni bağlantıda yeniden denenir), RST_STREAM, PING ack. SETTINGS
  kümesi/sırası senkron taraftan türetilir; pseudo-header sırası ve HPACK
  kodlaması aynıdır. Sunucu `http/1.1` seçerse (veya `impersonate=None`, stdlib
  `ssl`) istek başına bir bağlantıyla HTTP/1.1 kullanılır; async HTTP/1.1'de
  bağlantı havuzlama (keep-alive) yoktur. `AsyncSession.pre_warm` ve async
  WebSocket hâlâ stdlib `ssl` kullanır ve proxy desteklemez.
- **AsyncSession proxy:** `proxy=` / `proxies=` senkron `Session` ile aynı
  anlamdadır (HTTP CONNECT + Basic, SOCKS5 / RFC 1929; `https://` proxy yok).
  Tünelin içinde hem `impersonate` (kendi TLS 1.3 yığını) hem stdlib `ssl`
  çalışır; stdlib `ssl` + proxy Python 3.11+ gerektirir. `set_proxies([...])`
  rotasyonu artık proxy'yi gerçekten kullanır ve `proxy=`'yi geçersiz kılar.
  `AsyncSession` ayrıca `Timeout` (connect/read/write/pool; read, hareketsizlik
  süresidir) ve `Limits` (`max_connections` = toplam eşzamanlı bağlantı,
  `keepalive_expiry` h2 bağlantıları için) kabul eder. `max_keepalive_connections`
  async tarafta uygulanmaz.
- Async HTTP/2'de sunucu PUSH_PROMISE'i protokol hatasıdır (ENABLE_PUSH=0 ilan
  edilir); öncelik (PRIORITY) gönderilmez, yok sayılır.
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
- **`verify=False` yok** (bilinçli; yukarıya bakın).
- `Timeout.write` senkron tarafta ayrı uygulanmıyor (soket `read` zaman aşımını
  kullanır); `AsyncSession` `write`'ı drain süresine uygular.

## Modül yapısı

```
fasthttpc/
├── session.py          # Sync HTTP istemcisi
├── config.py           # Timeout, Limits, verify çözümleme
├── retry.py            # Retry politikası
├── async_session.py    # Async istemci + plugin sistemi
├── cookies.py          # RFC 6265 cookie jar (domain/path/Secure)
├── tls_crafter.py      # ClientHello oluşturucu
├── tls_tools.py        # TLS yardımcıları
├── crypto_math.py      # Key schedule + OpenSSL (cryptography) AEAD/X25519 sarmalayıcıları
├── fingerprint.py      # Tarayıcı profilleri, JA3
├── buffer.py           # Adaptif alıcı buffer
├── cache.py            # Response cache
├── metrics.py          # İstek metrikleri
├── models/             # URL, Headers, Request, Response
├── protocol/           # HTTP/1.1, HTTP/2, WebSocket, DoH
├── security/           # TLS adapter, sertifika doğrulama
└── transport/          # Connection pool, MockTransport
```

## Testler

```bash
pytest              # ağsız birim testler
python smoke_test.py  # ağ gerektiren elle doğrulama
```

## Lisans

MIT
