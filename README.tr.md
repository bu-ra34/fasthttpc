# fasthttpc

[English](README.md) | **Türkçe**

Pure-Python HTTP istemcisi: kendi TLS 1.3 / TLS 1.2 yığını, tarayıcı TLS ve
HTTP/2 parmak izi taklidi (Chrome, Firefox, Safari), HTTP/2 multiplexing,
senkron ve async API (asyncio ya da anyio üzerinden trio). Deneysel HTTP/3
isteğe bağlı bir ek paket olarak gelir. Kendine ait C eklentisi yoktur: tek
derlenmiş çalışma zamanı bağımlılığı primitifler (AEAD, X25519, ML-KEM,
sertifika ayrıştırma) için `cryptography`'dir; isteğe bağlı ekler (`http3`,
`brotli`, `zstd`) kendi derlenmiş paketlerini getirir.

> **Durum: deneysel (alpha).** TLS yığını sıfırdan yazılmıştır. v0.2.0 ile sunucu
> kimlik doğrulaması tam hâle geldi (aşağıya bakın). Kod kendi içimizde bir
> güvenlik incelemesinden geçti ([docs/security-audit.md](docs/security-audit.md)),
> ama **bağımsız bir güvenlik denetimi yapılmadı**. Kritik üretim trafiği için
> `curl_cffi`, `httpx` veya `requests` gibi olgun bir alternatifi tercih edin.

## Kurulum

```bash
pip install fasthttpc
pip install "fasthttpc[brotli,zstd]"   # isteğe bağlı içerik kod çözücüleri
pip install "fasthttpc[trio]"          # AsyncSession'ı trio altında çalıştırmak için (anyio + trio)
pip install "fasthttpc[http3]"         # deneysel HTTP/3 (aioquic)
```

Python 3.10+. CI testleri Linux'ta Python 3.10 - 3.13, Windows ve macOS'ta
Python 3.12 ile çalıştırır.

Geliştirme için:

```bash
git clone https://github.com/bu-ra34/fasthttpc
cd fasthttpc
pip install -e ".[dev]"
pytest        # ağ gerektirmez (canlı testler FASTHTTPC_LIVE=1 olmadan atlanır)
```

## Özellikler

| Alan | Destek |
|---|---|
| Protokoller | HTTP/1.1 (keep-alive, chunked), HTTP/2 (akış kontrolü, GOAWAY; eşzamanlı akışlar `AsyncSession`'da), WebSocket (`ws://`, `wss://`), HTTP/3 (**deneysel**, isteğe bağlı, aşağıya bakın) |
| TLS | Kendi TLS 1.3'ümüz (HelloRetryRequest; key_share x25519, secp256r1, secp384r1 ve `cryptography` ML-KEM sunuyorsa hibrit post-kuantum X25519MLKEM768) ve TLS 1.2'nin güvenli bir alt kümesi (ECDHE + AEAD, EMS zorunlu). TLS 1.3 PSK oturum devamı var ama varsayılan kapalı; 0-RTT yok |
| Sunucu doğrulaması | Zincir + hostname, CertificateVerify, Finished, hepsi zorunlu; `verify=` ile özel CA bundle |
| İstemci sertifikası | `cert=` (mTLS): PEM, şifreli PKCS#8 veya PKCS#12; RSA >= 2048, P-256, P-384, Ed25519; TLS 1.3 ve TLS 1.2 |
| Parmak izi | `chrome_158`, `firefox_160`, `safari_27` (2026-11 itibarıyla güncel kararlı sürümler; eski `chrome_131`, `firefox_133`, `safari_18` korunur): ClientHello (JA3/JA4; Chrome'un ALPS 17613, trust anchor ID ve ML-DSA imza şemaları dahil), HTTP/2 SETTINGS, pseudo-header sırası, başlık sırası. Kaynaklar ve bilinen sapmalar: [profiller](https://bu-ra34.github.io/fasthttpc/profiles/) |
| Async | `AsyncSession` asyncio altında ya da anyio üzerinden trio altında (`fasthttpc[trio]`); aynı parmak izi ve gerçek HTTP/2 multiplexing |
| Akış | `stream=True` / `s.stream(...)`; `iter_bytes`, `iter_text`, `iter_lines`, `iter_raw` ve async `aiter_*` karşılıkları; HTTP/1.1 ve HTTP/2 |
| Auth ve hook'lar | Basic, Digest (RFC 7616), Bearer, `.netrc`, özel auth (requests veya httpx tarzı); requests tarzı `hooks=`, httpx tarzı `event_hooks=`; `Session` ve `AsyncSession`'da plugin'ler |
| Proxy | HTTP CONNECT (+Basic), SOCKS5 (RFC 1929), rotasyon; TLS her zaman tünelin içinde kurulur |
| Zaman aşımı / sınır / yeniden deneme | `Timeout` (`total` dahil), `Limits`, urllib3 tarzı `Retry` (`Retry-After` ile) |
| Çerez, cache, yönlendirme | RFC 6265 cookie jar, response cache, yönlendirme geçmişi |
| DNS | İsteğe bağlı DNS-over-HTTPS çözücü; çok adresli host'larda Happy Eyeballs (RFC 8305) |
| Eski sunucular | `legacy_tls=True` (varsayılan kapalı): TLS 1.2 CBC ve statik RSA suite'leri. TLS 1.0/1.1 hiçbir zaman desteklenmez |
| Test | `MockTransport` (senkron ve async handler) |
| Tip bilgisi | `py.typed` ile gelir |

HTTP/3 (`http3=True`: Alt-Svc keşfi ve sessizce HTTP/2'ye düşüş, ya da
`http3="force"`) **deneyseldir** ve varsayılan kapalıdır. `fasthttpc[http3]`
(aioquic) gerektirir. QUIC içindeki TLS el sıkışmasını aioquic yapar; bu yüzden
tarayıcı ClientHello parmak izi HTTP/3'te **taşınmaz**, yalnızca QUIC transport
parametreleri ve HTTP/3 SETTINGS Chrome benzeri bir profili izler. Yalnızca yerel
bir aioquic sunucusuna karşı test edildi: gerçek sunuculara karşı isteğe bağlı
canlı testler var (`tests/live/`), ama CI'da çalışmıyor.

## Karşılaştırma

Dürüst karşılaştırma; burada "olgunluk" özellikler kadar önemlidir.

| | fasthttpc | requests | httpx | curl_cffi |
|---|---|---|---|---|
| Gerçekleme | Pure Python + `cryptography` | Pure Python + urllib3 + `ssl` | Pure Python + h11/h2 + `ssl` | libcurl-impersonate (C), cffi ile |
| TLS kütüphanesi | **Kendi TLS 1.3/1.2 kodu** | `ssl` üzerinden OpenSSL | `ssl` üzerinden OpenSSL | BoringSSL |
| Tarayıcı TLS/JA3/JA4 taklidi | Evet (3 aile) | Hayır | Hayır | Evet (çok sürüm, en geniş kapsam) |
| HTTP/2 parmak izi | Evet | Hayır | Hayır | Evet |
| HTTP/2 | Evet | Hayır | Evet | Evet |
| HTTP/3 | **Deneysel**, isteğe bağlı (aioquic); QUIC'te tarayıcı TLS parmak izi yok; yalnızca yerel testler | Hayır | Hayır | Evet |
| Async | Evet (asyncio, anyio üzerinden trio) | Hayır | Evet (asyncio, anyio üzerinden trio) | Evet |
| `verify=False` | **Bilinçli olarak desteklenmez** | Evet | Evet | Evet |
| Oturum devamı / 0-RTT | TLS 1.3 PSK oturum devamı, **varsayılan kapalı**; 0-RTT yok | Evet (OpenSSL) | Evet (OpenSSL) | Evet |
| Post-kuantum anahtar değişimi | Chrome, Firefox ve `safari_27` profillerinde X25519MLKEM768, yalnızca `cryptography` >= 47 ile; HTTP/3'te yok | OpenSSL 3.5+ ile | OpenSSL 3.5+ ile | Evet |
| Post-kuantum imza (ML-DSA) | `chrome_158` ML-DSA-44/65/87 ilan eder ve doğrular (`cryptography` >= 48) | Hayır | Hayır | İlan eder (BoringSSL) |
| Olgunluk / üretim kullanımı | **Alpha, genç; yalnızca iç inceleme, bağımsız denetim yok** | Çok olgun | Olgun | Olgun |
| Gerçek dünyada sertleşme yılı | Yok | >10 | >5 | Birkaç |
| Hız | Pure Python: büyük aktarımlarda daha yavaş | Yeterince hızlı | Yeterince hızlı | En hızlı |

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
HTTP/3 bağlantıları da istek gönderilmeden önce aynı sertifika doğrulayıcısından
geçer.

Güven kökü olarak `certifi` bundle'ı + varsa sistem CA deposu kullanılır.
Sertifika doğrulamayı kapatmanın bir yolu yoktur; bu kasıtlıdır.

`AsyncSession(impersonate=None)` ve DNS-over-HTTPS çözücüsü bu yığını
kullanmaz: Python'un `ssl` modülünü `ssl.create_default_context()` ile kullanır;
orada da sertifika zinciri ve hostname her zaman doğrulanır.

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

`AsyncSession(verify=...)` da aynı kuralları uygular (`impersonate=None` ile
stdlib `ssl`'e `cafile` olarak iletilir).

## Hızlı başlangıç

```python
from fasthttpc import Session

with Session(impersonate="chrome_158") as s:
    r = s.get("https://httpbin.org/get")
    print(r.status_code, r.elapsed)
    print(r.json())
```

### Async

```python
import asyncio
from fasthttpc import AsyncSession

async def main():
    # Async tarafta da tarayıcı parmak izi taklidi var (kendi TLS yığını)
    async with AsyncSession(impersonate="chrome_158") as s:
        r = await s.get("https://httpbin.org/get")
        print(r.status_code)

asyncio.run(main())
```

Aynı `AsyncSession` `fasthttpc[trio]` kuruluysa `trio.run(main)` ile de çalışır
(HTTP/3 hariç).

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
  desteklenmez (bkz. Güvenlik modeli). `proxies={...}` sözlüğü requests ile aynı
  biçimdedir ama yalnızca oturum düzeyindedir. `timeout=`, `params=`, `auth=`,
  `cookies=`, `hooks=` ve `stream=True` istek başına da verilebilir.
- Proxy ortam değişkenleri (`HTTPS_PROXY` ...) okunmaz; `trust_env` yalnızca
  `.netrc`'yi etkiler.

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
| `pool` | Havuzdan boş bağlantı bekleme (diğer alanlar gibi ilk argümanı alır; yine de `None` ise `Session` `connect` süresini kullanır, `AsyncSession` sınırsız bekler) |
| `total` | Gövde dahil tüm isteğin süre sınırı (varsayılan `None`, sınırsız) |

Geriye dönük uyumluluk: `Session(timeout=30)` ve `Timeout(connect=5, read=30)`
eskisi gibi çalışır; `from fasthttpc.timeout import Timeout` aynı sınıftır.
`limits` verilmezse `max_connections` parametresi kullanılır.

| `Limits` alanı | Varsayılan | Anlamı |
|---|---|---|
| `max_connections` | 10 | `Session`'da origin başına, `AsyncSession`'da toplam eşzamanlı bağlantı (`AsyncSession`'ın `max_connections` varsayılanı 100) |
| `max_keepalive_connections` | `None` (= `max_connections`) | Havuzda boşta tutulan bağlantı |
| `keepalive_expiry` | 30.0 | Boştaki bağlantının ömrü (sn); `None` → sınırsız, `0` → keep-alive kapalı |

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
Aynı plugin'ler senkron `Session.use()` ile de çalışır (orada kancalar düz
fonksiyon olmalıdır).

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

TLS (ve parmak izi) her zaman tünelin İÇİNDE fasthttpc'nin kendi TLS yığınıyla
kurulur (`AsyncSession(impersonate=None)` ile stdlib `ssl`); proxy yalnızca TCP
baytlarını taşır.

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

ja3_str, ja3_hash = ja3_for_profile("chrome_158")
print(ja3_hash)
```

## Profiller

| Profil | Tarayıcı | Takma adlar |
|---|---|---|
| `chrome_158` | Chrome 158 (Windows) | `chrome` |
| `firefox_160` | Firefox 160 (Windows) | `firefox` |
| `safari_27` | Safari 27.2 (macOS) | `safari`, `safari_27_2` |
| `chrome_131` | Chrome 131 (geriye dönük uyumluluk) | — |
| `firefox_133` | Firefox 133 (geriye dönük uyumluluk) | `firefox_120` |
| `safari_18` | Safari 18.0 (geriye dönük uyumluluk) | `safari_17` |
| `default` | — (tarayıcı taklidi yok; `impersonate=None`) | — |

Bilinmeyen bir profil adı `ValueError` fırlatır; sessizce `default`'a düşmez.
`Session` ve `AsyncSession`'ın varsayılanı `"chrome_158"`'dir (0.6.2'ye kadar
`"chrome_131"`; eski parmak izi için adı açıkça verin). Ayrı bir Edge profili
yoktur: Edge'in TLS/HTTP/2 katmanı Chromium'dur, ancak Edge'in trust anchor ID
uzantısını gönderip göndermediği doğrulanamadı (bkz. docs/profiles.md).

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
  `ssl`) HTTP/1.1 kullanılır. Async HTTP/1.1'de keep-alive havuzu vardır:
  `(host, port, proxy, TLS yolu)` anahtarlı; `Connection: close`, HTTP/1.0,
  EOF çerçeveli gövde, hata/iptal sonrası bağlantı havuza dönmez (slot yine de
  serbest kalır). Havuzdan alınan bağlantı yanıttan hiç bayt gelmeden koparsa
  (ve hata zaman aşımı değilse) istek bir kez taze bağlantıyla yeniden denenir;
  zaman aşımı veya yarım yanıtta yeniden denenmez (POST çift gönderilmez).
  `AsyncSession.pre_warm` ve `ws_connect` aynı bağlantı yolunu kullanır:
  `impersonate` ile tarayıcı ClientHello'su (WebSocket'te ALPN yalnızca
  `http/1.1`), `proxy=` / `proxies=` / rotasyon ile tünel üzerinden; `ws://` ve
  `wss://` desteklenir. `pre_warm` ısıttığı HTTP/1.1 bağlantılarını keep-alive
  havuzuna, h2 bağlantısını h2 önbelleğine koyar. Senkron `Session` bir HTTP/2
  bağlantısında istekleri sırayla yürütür.
- **Senkron WebSocket:** `Session.websocket()` `ws://` ve `wss://` destekler;
  `wss://` tarayıcı ClientHello'su ile ALPN yalnızca `http/1.1` önerir, okuma
  zaman aşımı oturumun `Timeout`'undan alınır. Proxy ve eşzamanlı kullanım
  için `AsyncSession` daha kapsamlıdır.
- **AsyncSession proxy:** `proxy=` / `proxies=` senkron `Session` ile aynı
  anlamdadır (HTTP CONNECT + Basic, SOCKS5 / RFC 1929; `https://` proxy yok).
  Tünelin içinde hem `impersonate` (kendi TLS yığını) hem stdlib `ssl`
  çalışır (Python 3.10'da da). `set_proxies([...])` rotasyonu proxy'yi gerçekten
  kullanır ve `proxy=`'yi geçersiz kılar.
  `AsyncSession` ayrıca `Timeout` (connect/read/write/pool; read, hareketsizlik
  süresidir) ve `Limits` (`max_connections` = toplam eşzamanlı bağlantı,
  `max_keepalive_connections`, `keepalive_expiry`) kabul eder. `max_connections`
  kullanımdaki bağlantıları sınırlar; boştaki keep-alive bağlantılar slot
  tutmaz ve `max_keepalive_connections` (varsayılan `max_connections`) ile
  sınırlıdır. Async'te `keepalive_expiry=0` keep-alive'ı kapatır.
- Proxy ortam değişkenleri (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`) okunmaz.
- **Düz HTTP yok:** `http://` adresleri de TLS ile istenir (adreste port yoksa
  80'e), bu yüzden yalnızca düz HTTP konuşan sunuculara ulaşılamaz. `ws://`
  WebSocket'leri düz TCP kullanır.
- HTTP/2'de (senkron ve async) sunucu PUSH_PROMISE'i protokol hatasıdır (ENABLE_PUSH=0 ilan
  edilir); PRIORITY frame'i gönderilmez, gelirse yok sayılır (HEADERS'ın öncelik
  alanı profili izler).
- **TLS 1.2: varsayılan olarak yalnızca güvenli bir alt küme desteklenir**
  (`fasthttpc/security/tls12.py`, hem senkron hem async yolda). TLS 1.3 tercih
  edilir; sunucu TLS 1.2 seçerse:
  - *Desteklenen:* ECDHE (x25519, secp256r1, secp384r1) + ECDSA/RSA sertifika;
    AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 (0xC02B, 0xC02F, 0xC02C, 0xC030,
    0xCCA9, 0xCCA8); ServerKeyExchange imza algoritmaları ecdsa, rsa_pss_rsae ve
    rsa_pkcs1 (SHA-256/384/512; ClientHello'da ilan edilenlerden biri olmalı).
    CertificateRequest (mTLS) yanıtlanır: `cert=` varsa sertifika, yoksa boş
    Certificate gönderilir.
  - *Zorunlu:* Extended Master Secret (RFC 7627) ve renegotiation_info (RFC 5746);
    sunucu birini göndermezse bağlantı reddedilir. Sertifika zinciri + hostname,
    SKE imzası, Finished (sabit zamanlı), handshake mesaj sırası ve
    ServerHello.random `DOWNGRD` işareti (downgrade saldırısı) denetlenir.
  - *Reddedilen (açık hatayla):* CBC suite'leri, statik RSA, DHE, PSK, anonim/export,
    SHA-1/MD5/SHA-224 imzalar, null dışı sıkıştırma, TLS 1.1 ve altı. Renegotiation
    desteklenmez (HelloRequest'e `no_renegotiation` uyarısı verilir, tekrarlanırsa
    bağlantı kapanır). CBC, statik RSA, SHA-1 SKE imzası ve EMS'siz sunucular
    yalnızca `legacy_tls=True` ile kabul edilir; DHE, PSK ve TLS 1.0/1.1 hiçbir
    zaman.
  - *Kullanılmayan:* TLS 1.2'de NewSessionTicket yalnızca ayrıştırılır; TLS 1.2
    oturum devamı yoktur.
- **HelloRetryRequest:** destekleniyor (RFC 8446 §4.1.4, cookie dahil); ikinci
  HRR handshake'i sonlandırır.
- **TLS 1.3 PSK oturum devamı varsayılan KAPALIDIR.** Süreç genelinde
  `fasthttpc.security.session_tickets.enable_resumption(True)` ya da
  `FASTHTTPC_TLS_RESUMPTION=1` ile açılır (yalnızca `psk_dhe_ke`, biletler tek
  kullanımlık). Kapalıyken her bağlantı tam handshake yapar. 0-RTT hiç yoktur;
  HTTP/3'te oturum devamı kullanılmaz.
- **HPACK huffman ENCODE yok** (decode var). Protokolde geçerli, ama h2 parmak
  izinde küçük bir sapma yaratır.
- **key_share grupları:** x25519, secp256r1, secp384r1 ve hibrit post-kuantum
  X25519MLKEM768. X25519MLKEM768 Chrome ve Firefox profillerinde ve `safari_27`'de,
  yalnızca kurulu `cryptography` ML-KEM sunuyorsa (47 ve üstü) gönderilir; aksi
  halde supported_groups'tan da çıkarılır ve ClientHello gerçek tarayıcıdan
  ayrışır. `chrome_158`'in ML-DSA imza şemaları da `cryptography` 48+ ister. secp521r1/x448/ffdhe implemente edilmedi: bunlar için
  key_share *gönderilmez*; profil supported_groups'ta ilan ediyorsa (Firefox,
  Safari) ve sunucu HRR ile bunları isterse açık hata verilir.
- **HTTP/3 deneyseldir:** proxy üzerinden ve `cert=` ile kullanılmaz, trio
  altında kullanılmaz (`http3=True` HTTP/2'ye ya da 1.1'e düşer, `"force"` açık
  `Http3ConnectError` verir), yanıt gövdesini tamamen okur (`stream=True` ile de), QUIC
  içindeki ClientHello aioquic'indir (tarayıcı parmak izi yok). Yalnızca yerel
  aioquic sunucusuyla test edildi.
- `Session` thread-safe değildir; thread başına bir tane kullanın.
- **`verify=False` yok** (bilinçli; yukarıya bakın).
- `Timeout.write` senkron tarafta ayrı uygulanmıyor (soket `read` zaman aşımını
  kullanır); `AsyncSession` `write`'ı drain süresine uygular.
- İç güvenlik incelemesinin açık bulguları (ör. açılmış gövde boyutuna sınır
  yok, çerezlerde Public Suffix List yok) [docs/security-audit.md](docs/security-audit.md)'de.

## Modül yapısı

```
fasthttpc/
├── session.py          # Sync HTTP istemcisi
├── async_session.py    # Async istemci (asyncio / trio)
├── _backend.py         # asyncio / trio (anyio) arka uç soyutlaması
├── _api.py             # Ortak istek yardımcıları (params, timeout, hook'lar)
├── config.py           # Timeout, Limits, verify çözümleme
├── retry.py            # Retry politikası
├── auth.py             # Basic, Digest, Bearer, .netrc, özel auth
├── plugins.py          # Plugin arayüzü (Session ve AsyncSession)
├── streaming.py        # Akış gövdesi kod çözücüleri
├── cookies.py          # RFC 6265 cookie jar (domain/path/Secure)
├── tls_crafter.py      # ClientHello oluşturucu
├── tls_tools.py        # TLS yardımcıları
├── crypto_math.py      # Key schedule + OpenSSL (cryptography) AEAD/X25519 sarmalayıcıları
├── fingerprint.py      # Tarayıcı profilleri, JA3
├── buffer.py           # Adaptif alıcı buffer
├── cache.py            # Response cache
├── metrics.py          # İstek metrikleri
├── multipart.py        # multipart/form-data
├── models/             # URL, Headers, Request, Response
├── protocol/           # HTTP/1.1, HTTP/2 (sync + async), WebSocket, DoH
├── security/           # TLS 1.3/1.2 adapter, sertifika doğrulama, key_share, mTLS, oturum biletleri, legacy TLS
├── tls13/              # Sans-IO TLS 1.3 çekirdeği (async yol)
├── http3/              # Deneysel HTTP/3 (aioquic), Alt-Svc
└── transport/          # Connection pool, proxy, Happy Eyeballs, MockTransport
```

## Testler

```bash
pytest              # ağsız testler (canlı HTTP/3 testleri FASTHTTPC_LIVE=1 olmadan atlanır)
python smoke_test.py  # ağ gerektiren elle doğrulama
```

## Lisans

MIT
