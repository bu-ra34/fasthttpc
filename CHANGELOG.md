# Changelog

## [Unreleased]

## [0.6.1.post1] — 2026-11-16

Yalnızca dokümantasyon güncellemesi; kod 0.6.1 ile aynı.

### Dokümantasyon
- README, README.tr ve mkdocs sayfaları koda göre güncellendi: HTTP/3 (deneysel,
  yalnızca yerel testler), trio, TLS 1.3 PSK oturum devamı (varsayılan kapalı,
  0-RTT yok), X25519MLKEM768 (Chrome/Firefox profilleri, `cryptography` >= 47),
  mTLS, akış, auth/hook sayfaları; "yakında" bölümü kaldırıldı. Düz HTTP
  olmaması, proxy ortam değişkenlerinin okunmaması ve trio altında HTTP/3'ün
  çalışmaması bilinen sınırlara eklendi.

## [0.6.1] — 2026-11-16

Kendi içimizde yapılan güvenlik incelemesi (bağımsız denetim değildir):
bulgular ve açık maddeler `docs/security-audit.md`'de.

### Güvenlik
- IP adresiyle bağlanılan host'larda sertifika artık iPAddress SAN'ı ile
  doğrulanıyor. Eskiden IP, DNS adı gibi eşleniyordu: IP'yi dNSName olarak
  yazan sertifika kabul ediliyor, doğru IP SAN'lı sertifika reddediliyordu (FHC-01).
- Giden başlık adı/değeri, çerez değeri, metot ve istek hedefi telde
  yazılmadan önce doğrulanıyor. CR/LF/NUL içeren değer `ValueError` veriyor;
  eskiden HTTP/1.1'de başlık/istek enjeksiyonu mümkündü (FHC-02).
- Çerez `Domain=` özniteliği artık tek etiketli genel soneke (`com`) ya da
  IP host'larda yayılamıyor; böyle çerezler host-only kalıyor (FHC-03).
- Chunked gövdede chunk boyutu katı ayrıştırılıyor (`0x5`, `-1`, `+5`
  reddediliyor) ve chunk sonundaki CRLF denetleniyor (FHC-04).
- HTTP/1.1 yanıt başlık bloğu 256 KiB ile sınırlandı (FHC-05).
- TLS 1.3 Certificate mesajında boş olmayan `certificate_request_context` ve
  liste sonrası artık bayt reddediliyor (FHC-06).

### Tip denetimi
- mypy (strict) kapsamı genişletildi: `session.py`, `async_session.py`,
  `models/request.py`, `models/response.py`, `models/__init__.py`, `streaming.py`,
  `_api.py` ve `plugins.py` artık `[tool.mypy] files` listesinde. Yapılandırma
  gevşetilmedi; yeni `# type: ignore` eklenmedi.
- Akış gövdesi kaynakları için `BodyStream` / `AsyncBodyStream` Protocol'leri
  (`fasthttpc.models.response`); `Response.metrics` sınıf düzeyinde tiplendi.
- `_api` içinde ortak tip takma adları (`HeadersArg`, `HeaderDict`, `ParamsArg`,
  `AuthArg`, `TimeoutArg` ...); `AuthFlow` artık `Generator[Request, Response, None]`.
- `streaming`: opsiyonel `brotli`/`zstandard` modülleri `importlib` ile yüklenir
  (davranış aynı; stub'ı olmayan/kurulu olmayan paket tip denetimini ortama göre
  değiştirmez).

### Düzeltmeler
- **Async yolda el sıkışma hatasında TLS alert:** `AsyncTLSStream` (asyncio ve
  trio) el sıkışma başarısız olduğunda çekirdeğin kuyruğa aldığı fatal alert'i
  artık sunucuya göndermeden kapatmıyor; senkron yolla aynı alert kodları
  (ör. bozuk SKE imzası → `decrypt_error`). Gönderim best-effort'tur, asıl hatayı
  maskelemez. Ardından RST yerine FIN + kısa, sınırlı boşaltma
  (`transport.lingering.async_send_and_drain`); trio akışına `write_eof` eklendi.
- `Headers(...)` yalnızca `dict` kabul ediyordu: `Headers` nesnesi ya da başka bir
  `Mapping` (ör. `MappingProxyType`) verilince başlıklar SESSİZCE düşüyordu
  (`Session(headers=Headers({...}))` -> başlık yok). Artık her `Mapping` kabul
  edilir; `Headers` kopyası çoklu değerleri (Set-Cookie) ve sırayı korur.
- `AsyncSession.pool_stats()`: `cert=` (mTLS) ile havuz/h2 anahtarlarına sertifika
  kimliği eklendiğinden anahtar sabit uzunlukta açılırken `ValueError` fırlatıyordu.
- **HTTP/3 GOAWAY (aioquic < 1.8):** aioquic 1.3–1.7 sunucunun GOAWAY
  çerçevesini sessizce yutuyordu (Python 3.10'daki en yeni sürüm 1.3). Bağlantı
  kullanılmaya devam ediyor, sunucunun işlemediği istek zaman aşımına kadar
  bekliyordu. Artık fasthttpc bu sürümlerde GOAWAY'i kendisi ayrıştırır
  (aioquic 1.8 ile aynı denetimler: bozuk çerçeve H3_FRAME_ERROR, geçersiz ya da
  artan ID H3_ID_ERROR); işlenmemiş istek yeni bağlantıda bir kez tekrarlanır.
  Python 3.10'da atlanan GOAWAY testi artık koşuyor; gerçek GOAWAY çerçevesi
  gönderen yerel sunucuyla regresyon testleri eklendi.

### Testler ve dokümantasyon
- **Canlı HTTP/3 testleri:** `tests/live/test_http3_live.py` (`live` işareti).
  Gerçek sunuculara karşı Alt-Svc keşfi ve h3 kullanımı, gövde doğrulaması,
  h3'e ulaşılamadığında h2'ye düşüş ve sertifika doğrulaması (badssl.com,
  güvenilmeyen CA ile QUIC el sıkışması). `FASTHTTPC_LIVE=1` verilmedikçe
  atlanır; CI ve `pytest -q` ağa çıkmaz. Kullanım: docs/testing.md.

## [0.6.0] — 2026-11-15

requests/httpx'e göre kalan on eksik kapatıldı: akış, mTLS, auth, senkron
hook'lar, trio, İngilizce dokümantasyon, PyPI paketlemesi, tip bilgisi, HTTP/3
ve isteğe bağlı eski TLS modu. 953 → 1498 test; Python 3.10–3.13; CI artık
Linux, Windows ve macOS'ta.

### Yeni özellikler
- **Akış (streaming):** `stream=True`, `iter_bytes/iter_text/iter_lines/iter_raw`,
  `aiter_*`, `with s.stream(...)` bağlamı. HTTP/1.1 ve HTTP/2, senkron ve async.
  HTTP/2'de geri basınç: WINDOW_UPDATE yalnızca tüketilen veri için gönderilir.
  Yönlendirme ve 401 ara yanıtlarının gövdesi atılır, yeniden denenen yanıt kapatılır.
- **mTLS (`cert=`):** PEM, şifreli PKCS#8 ve PKCS#12; RSA ≥2048, P-256, P-384,
  Ed25519. TLS 1.3 ve 1.2 (statik RSA dahil). Uygun sertifika/şema yoksa boş
  Certificate gönderilir. Anahtar dosyası herkesçe okunabilirse uyarı (POSIX).
- **Auth:** Basic, Digest (RFC 7616; MD5, SHA-256 ve -sess
  türevleri, qop=auth/auth-int, userhash), Bearer, `.netrc`, özel auth sınıfları.
- **Hook'lar:** requests tarzı `hooks={"response": [...]}` ve httpx tarzı
  `event_hooks={"request": [...], "response": [...]}`. Eklentilerde senkron
  `on_request` ve async `async_on_request`.
- **trio:** `pip install fasthttpc[trio]` ile `AsyncSession` trio altında da
  çalışır (anyio üzerinden). asyncio yolu değişmedi.
- **HTTP/3 (deneysel):** `pip install fasthttpc[http3]` (aioquic). Alt-Svc keşfi,
  UDP engelliyse h2'ye düşüş, Chrome QUIC profili. Sertifika uygulama verisinden
  önce fasthttpc tarafından doğrulanır. `cert=` verildiğinde HTTP/3 kullanılmaz.
- **`legacy_tls=True`:** eski sunucular için CBC suite'leri (Encrypt-then-MAC
  tercihli, Lucky13 önlemi) ve statik RSA. Varsayılan kapalı; TLS 1.0/1.1
  bilinçli olarak desteklenmez.
- **Happy Eyeballs (RFC 8305):** çok adresli host'larda IPv6/IPv4 yarıştırılır
  (senkron ve async).
- Session/AsyncSession: `auth=`, `params=`, `cookies=`, istek düzeyi `timeout=`,
  `head()`, `r.next`; `Response.tls_info`.

### Paketleme ve dokümantasyon
- İngilizce README (Türkçesi `README.tr.md`), mkdocs sitesi, requests/httpx
  geçiş kılavuzları.
- SPDX lisans, `py.typed`, PyPI metadata ve extras (`http3`, `trio`, `all`);
  Trusted Publishing ile yayın iş akışı.
- mypy yapılandırması ve CI'da tip denetimi.

### Düzeltmeler
- Senkron HTTP/1: başlık bloğu CRLFCRLF'den önce kesilirse sahte 200 yanıtı
  dönüyordu; artık hata.
- WebSocket yolu `verify=` ile verilen özel CA'yı yok sayıyordu (güvenlik).
- Fatal alert sonrası bağlantı düzenli kapanır (`shutdown(SHUT_WR)` + sınırlı
  boşaltma); alert artık RST'ye kurban gitmez.
- HTTP/3: getaddrinfo adresleri sırayla denenir (IPv6'sı ölü host'larda h3
  kurulmuyordu); Windows'ta UDP ICMP reddi (WSAECONNRESET) doğru işlenir.
- Async proxy: proxy'ye bağlanma zaman aşımı da `ProxyError` (senkronla aynı).
- Süre ölçümleri `time.perf_counter` ile (Windows'ta 15 ms çözünürlük sorunu).

### Bilinen sınırlamalar
- Async TLS el sıkışma hatasında sunucuya alert gönderilmiyor.
- HTTP/3 yalnızca yerel testlerle doğrulandı; gerçek internette denenmedi.
- Bağımsız güvenlik denetimi henüz yapılmadı.

## [0.5.0] — 2026-11-14

Dört eksik kapatıldı: profil başına HTTP/2 parmak izi, güvenli TLS 1.2, async
eşitliği ve bağımsız TLS sunucularına karşı uyumluluk testleri. 785 → 953 test;
Python 3.10–3.13.

### Parmak izi
- **Profil başına HTTP/2 parmak izi:** SETTINGS (sıralı), WINDOW_UPDATE,
  HEADERS PRIORITY ve pseudo-header sırası profilden üretiliyor (sync + async).
  Akamai h2 string'leri yayımlanmış gerçek Chrome 131 / Firefox 133 / Safari 18
  değerleriyle birebir (tls.peet.ws'te canlı doğrulandı). Önceden üç profil
  aynı hash'i veriyordu.
- **ClientHello gerçek tarayıcıyla hizalandı:** ALPS (17513; sunucu kabul
  ederse istemci EncryptedExtensions), ECH GREASE (yalnızca GREASE), Chrome
  extension karıştırması, BoringSSL padding kuralı, profil suite listeleri.
  Chrome 131 JA4 yayımlanmış değerle (`t13d1516h2_8daaf6152771_02713d6af862`) eşleşiyor.
  `FASTHTTPC_NO_ECH_GREASE=1` ECH GREASE'i kapatır (TLS'i sonlandıran
  proxy'ler için).
- **X25519MLKEM768** (hibrit post-kuantum) key_share — `cryptography` ML-KEM
  destekliyorsa; Cloudflare/Google/Reddit'te canlı çalıştı.

### TLS 1.2 (güvenli alt küme)
- Yalnızca ECDHE (x25519, P-256, P-384) + AEAD (AES-GCM, ChaCha20-Poly1305).
  Extended Master Secret ve renegotiation_info ZORUNLU; DOWNGRD sentinel'i,
  CBC, statik RSA, SHA-1/MD5 imzaları, renegotiation, CertificateRequest
  açık hatayla reddedilir. Senkron ve async yol. nginx.org gibi TLS 1.2-only
  sunuculara artık bağlanılıyor.

### Async ve API
- **Profil başına tarayıcı başlıkları:** `Session`/`AsyncSession` artık profilin
  `user_agent`'ını ve gerçek tarayıcının varsayılan gezinme başlıklarını
  gönderir (Chrome: sec-ch-ua*, sec-fetch-*, priority...; Firefox/Safari kendi
  kümeleri, sec-ch-ua yok). Sıra profildeki `header_order` (h2) /
  `h1_header_order` (h1) ile aynıdır; `Accept-Encoding` yalnızca açabildiğimiz
  kodlamaları (br/zstd kuruluysa) içerir. Safari UA'sı macOS sürümünü 10_15_7
  olarak dondurur.
- **Oturum başlıkları:** `Session(headers={...})` / `s.headers` (iki sınıfta da
  mutable). Öncelik: profil < oturum < istek; değeri `None` olan başlık
  varsayılanı kaldırır.
- `impersonate=None` ("default") profili TLS 1.2 ilan eder (EMS,
  renegotiation_info, 0x0303, AEAD suite'leri).
- Senkron `Session`: `options()`, `set_proxies()`, `resolver` niteliği;
  `Limits(keepalive_expiry=0)` artık senkronda da keep-alive'ı kapatır.

- **Async HTTP/1.1 keep-alive havuzu** (Limits, keepalive_expiry, bayat
  bağlantıda güvenli tek yeniden deneme; POST çift gönderilmez).
- Async WebSocket ve `pre_warm`: proxy + tarayıcı TLS taklidi.
- **Async TLS 1.3 PSK resumption** (senkronla aynı saf fonksiyonlar, aynı bilet önbelleği).
- `Response.text` artık property (requests gibi); `r.text()` geriye uyumlu.
  `encoding`, `ok`, `reason`, `url`, `elapsed.total_seconds()`.
- Async çerezler artık CookieJar (domain/path/Secure) — önceden her host'a
  gönderiliyordu (güvenlik düzeltmesi).

### Uyumluluk testleri (`interop/`, `tests/test_interop_*.py`)
- `openssl s_server` ve tlslite-ng'ye karşı matris: TLS 1.3 suite × grup ×
  sertifika türü, HRR, KeyUpdate, büyük yanıt, resumption; TLS 1.2 suite
  matrisi; reddedilmesi gerekenler (süresi dolmuş, yanlış host, güvenilmeyen
  CA, eksik ara sertifika, mTLS isteği, TLS 1.0/1.1, EMS'siz sunucu, DOWNGRD
  aracısı); kayıt düzeyinde hata enjeksiyonu.

### Güvenlik ve hata düzeltmeleri
- CertificateVerify: ECDSA şeması sertifikanın eğrisine bağlanmıyordu
  (P-384 anahtar + ecdsa_secp256r1_sha256 kabul ediliyordu) ve ClientHello'da
  teklif edilmeyen imza şeması kabul ediliyordu — ikisi de reddediliyor.
- Sunucunun `record_size_limit`'ine (RFC 8449) uyulmuyordu (Firefox profili).
- Proxy tünelinde PSK bilet anahtarı hedef yerine proxy portunu kullanıyordu.
- Alert mesajları ham hex yerine adlandırılmış; bozuk CCS reddi.
- HelloRequest seli testi deterministik hale getirildi (RST yarışı).
- **HTTP/2 GOAWAY (RFC 9113 §6.8):** senkron yol her GOAWAY'i ölümcül sayıyordu;
  NO_ERROR ile düzgün kapanan sunucularda (canlı soak'ta www.debian.org) istek
  düşüyordu. Kapsanan stream tamamlanır, kapsanmayan istek yeni bağlantıda
  güvenle tekrarlanır, GOAWAY almış bağlantı yeniden kullanılmaz.
- Canlı soak: 20 dk, ~2000 istek, düzeltme öncesi tek hata (yukarıdaki);
  rapor `interop/CANLI_SOAK.md`.

## [0.4.0] — 2026-11-14

Tur 2: async tarafın senkronla eşitlenmesi, saha testleri ve bulunan hataların
düzeltilmesi.

### Async

- **AsyncSession proxy desteği:** HTTP CONNECT ve SOCKS5.
- **Async HTTP/2 multiplexing** (`fasthttpc/protocol/async_h2.py`): tek bağlantıda
  eşzamanlı akışlar, `MAX_CONCURRENT_STREAMS` ve akış kontrol penceresine uyum.
- AsyncSession için `Timeout` ve `Limits`.
- Async HTTP/1.1 gövde çerçevelemesi düzeltmeleri (204/304/HEAD, chunked, kesik gövde).
- AsyncSession h2 yanıtlarında `Response.http_version == "HTTP/2"`.

### Saha testleri

- `saha/` dizini (canlı site, soak, yük ve bellek betikleri) ve `saha/RAPOR.md`.
- Bulunan 7 senkron hata düzeltildi:
  1. `Connection: close` yanıtı havuz slotunu iade etmiyordu (sızıntı).
  2. 204/304/HEAD yanıtlarında gövde beklenip zaman aşımı oluyordu.
  3. `close_notify`'sız HTTP/1.0 EOF hata sayılıyordu.
  4. Kesik gövde sessizce kabul ediliyordu (artık `ConnectionResetError`).
  5. Zaman aşımında POST yeniden gönderiliyordu.
  6. h2 `_stream_windows` sızıntısı.
  7. `CookieJar` kilidi eksikti.

### API

- `Timeout(total=...)`: istek başına toplam süre sınırı.
- `Response.http_version` alanı.

### Bu turdaki düzeltmeler

- Senkron h2 yolunda `:authority` standart olmayan portta `host:port` olarak gönderiliyor.
- Senkron h2 yanıt başlıkları `Headers.add` ile okunuyor; çoklu `Set-Cookie` kaybolmuyor.
- `dev` ve `all` extras'a `h2>=4` eklendi (async h2 birlikte-çalışma testleri atlanmıyor).

## [0.3.0] — 2026-11-07

Beş paralel çalışma dalının (güvenlik, uyumluluk, sans-IO/async, performans,
API) birleştirilmesi. 92 → 418 test, hepsi ağsız.

### Güvenlik ve doğruluk

- TLS 1.2 ile yanıt veren sunucularda (canlı testte nginx.org) yanıltıcı
  "session_id eşleşmiyor" hatası yerine net `protocol_version` hatası veriliyor.
- **KeyUpdate** (RFC 8446 §4.6.3): sunucu anahtar yenilemesi işleniyor,
  `update_requested` gelirse istemci de yeniliyor. Eskiden yok sayılıyor ve
  bağlantı anlamsız bir tag hatasıyla kopuyordu.
- **Handshake sıra durum makinesi** (`HandshakeOrderValidator`):
  SH → EE → Cert → CV → Fin dışındaki her sıra `unexpected_message` ile
  reddediliyor; handshake sırasında application_data, Finished öncesi
  NewSessionTicket ve CertificateRequest artık kabul edilmiyor.
- **ServerHello sağlamlaştırma:** hs_type kontrolü, birden çok record'a
  bölünmüş ServerHello, `legacy_session_id_echo` doğrulaması, tekrarlanan
  extension reddi.
- **Record sınırları:** 2^14+256 üstü şifreli record ve sequence number taşması
  bağlantıyı kapatıyor; 2^14 üstü gönderim bölünüyor.
- **HPACK sağlamlaştırma:** bozuk Huffman, sınırsız integer, 256KB üstü header
  listesi ve geçersiz dynamic table size update artık `HpackDecodingError`
  (GOAWAY COMPRESSION_ERROR). Size update'in literal header sanılması düzeltildi.
- **WebSocket:** status satırı tam 101 olmalı, `Sec-WebSocket-Accept` zorunlu.
  ws:// yolundaki TypeError ve 101 ile aynı okumada gelen frame'lerin
  kaybolması düzeltildi.
- Geniş `except Exception: pass` blokları daraltıldı.
- Saf Python AES-GCM/ChaCha20/X25519 yedeği kaldırıldı; `cryptography` zorunlu.

### Async

- **Sans-IO TLS 1.3 çekirdeği** (`fasthttpc.tls13`): soketten bağımsız
  `TLSClientConnection`, `SyncTLSSocket`, `AsyncTLSStream`.
- **AsyncSession'da tarayıcı parmak izi:** `impersonate` verilince bağlantı
  kendi TLS yığınıyla kuruluyor (HTTP/1.1).

### Performans

- CA güven deposu önbelleğe alınıyor (handshake başına ~2.5 ms → µs düzeyi).
- Record okuma tamponu `bytearray` + ofset; AEAD nesneleri anahtar başına bir
  kez kuruluyor.
- **PSK session resumption** (varsayılan KAPALI:
  `session_tickets.enable_resumption(True)` veya `FASTHTTPC_TLS_RESUMPTION=1`).
  Bilet önbelleği host + port + `ca_path` ile ayrılıyor.
- `benchmark.py` yeniden yazıldı (ağsız mikro-benchmark + `--network` ile
  requests/httpx/curl_cffi karşılaştırması).

### API

- **`verify` parametresi** — `Session(verify="yol/ca.pem")` /
  `AsyncSession(verify=...)`: özel/kurumsal CA bundle'ı. Verilen dosya tek güven
  kökü olur. `verify=False` bilinçli olarak desteklenmez (`ValueError`).
  `validate_server_certificate(hs_payload, hostname, ca_path=None)` ve
  `TLSAdapter.negotiate(..., *, ca_path=None)` opsiyonel parametre aldı.
- **`fasthttpc.config`** — httpx benzeri `Timeout(connect, read, write, pool)` ve
  `Limits(max_connections, max_keepalive_connections, keepalive_expiry)`;
  `Session(limits=...)`. `fasthttpc.timeout.Timeout` aynı sınıfı yeniden ihraç
  eder; float timeout ve eski `Timeout(connect=, read=)` çağrıları çalışmaya devam eder.
- **`fasthttpc.retry.Retry`** — urllib3 benzeri yeniden deneme: `total`,
  `backoff_factor`, `status_forcelist`, `allowed_methods` (varsayılan idempotent),
  `Retry-After` desteği, bağlantı hatalarında yeniden deneme.
  `Session(retries=...)`, `AsyncSession(retries=...)`.
- **`fasthttpc.transport.mock.MockTransport`** — `handler(request) -> Response`
  ile ağsız test; `Session(transport=...)`, `AsyncSession(transport=...)`.
- CI: GitHub Actions (pytest, Python 3.10–3.13) + ruff (kritik kurallar).

### Düzeltildi

- `examples/05_async_session.py` yinelenen `impersonate` argümanı yüzünden
  sözdizimi hatası veriyordu.

### Uyumluluk

- **HelloRetryRequest** (RFC 8446 §4.1.4): transcript `message_hash` (254) ile
  yeniden kurulur, HRR'deki grup ve cookie ile 2. ClientHello üretilir (aynı
  random/session_id/GREASE/extension sırası). İkinci HRR, zaten teklif edilmiş
  gruba HRR, farklı suite/grup seçen 2. ServerHello reddedilir.
- **secp256r1 / secp384r1 key_share** (uncompressed nokta, nokta doğrulamalı
  ECDH). Yeni saf modül `fasthttpc/security/keyshare.py`.
- **Proxy desteği** (`fasthttpc/transport/proxy.py`): HTTP CONNECT (Basic auth)
  ve SOCKS5 (no-auth, kullanıcı/parola, domain adresleme).
  `Session(proxy=...)` / `Session(proxies={...})`.
- `TLSImpersonator.build_client_hello(extra_tail_extensions=...)` — PSK için
  son-extension kancası.
- `fasthttpc/security/alerts.py` — alert adları ve kullanıcıya ipuçları.

#### nginx.org `protocol_version` (alert 70) — analiz

Ağ testi bu ortamda anlamlı değil (çıkış trafiği TLS sonlandıran bir egress
gateway'den geçiyor), bu yüzden analiz ClientHello üzerinden yapıldı:

- record version 0x0301 / ClientHello legacy_version 0x0303: doğru.
- GREASE (cipher, groups, extensions, supported_versions): RFC 8701'e uygun;
  tekrarlanan extension yok.
- key_share/supported_groups: key_share'deki her grup supported_groups'ta
  ilan ediliyor (uyumsuzluk illegal_parameter=47 üretirdi, 70 değil).
- **Kök neden (en olası):** `supported_versions` yalnızca `GREASE, 0x0304`
  içeriyordu. OpenSSL, supported_versions varken sürümü YALNIZCA bu listeden
  seçer; TLS 1.3 sunmayan bir sunucu (v0.2.1'deki "0xc02f seçiyor" gözlemi bu
  sunucunun TLS 1.2 ile yanıt verdiğini gösteriyor) ortak sürüm bulamayınca
  tam olarak `protocol_version` (70) döner. Cloudflare/tls.peet.ws TLS 1.3
  desteklediği için etkilenmiyordu.
- **Düzeltme:** profiller artık gerçek tarayıcılar gibi 0x0303'ü de ilan ediyor
  (Chrome: GREASE,0304,0303; Firefox: 0304,0303; Safari: GREASE,0304..0301).
  TLS 1.2-only sunucuda artık anlamsız alert 70 yerine net bir
  "Sunucu TLS 1.2 ile yanıt verdi; TLS 1.2 kapsam dışı" hatası alınır;
  alert 70 gelirse de mesaj nedeni açıklar. TLS 1.2 implemente EDİLMEDİ
  (README → Bilinen sınırlar). Güvenlik: 0x0304 dışı her sürüm reddedildiği
  için ilan etmek downgrade açmaz; `DOWNGRD` işareti ayrıca raporlanır.

## [0.2.4] — 2026-09-04

`appdata_diagnose.py`'nin ham byte çıktısı, üç turdur peşinde olduğumuz
"invalid literal for int" / çöp-veri sorununun KÖK NEDENİNİ ortaya çıkardı.

### Düzeltildi

- **KRİTİK: TLS 1.3 NewSessionTicket tüm HTTP/2 trafiğini bozuyordu.**
  TLS 1.3'te handshake biter bitmez sunucu (Cloudflare, Google dahil çoğu)
  application anahtarlarıyla şifreli bir NewSessionTicket handshake mesajı
  (content_type=22) gönderir. HTTP katmanı bunu bir HTTP/2 frame ya da
  HTTP/1.1 yanıtı sanıp parse etmeye çalışıyordu: NewSessionTicket'ın ilk
  byte'ları (`04 00 00 ..`) geçersiz bir frame uzunluğu/tipi olarak okunuyor
  ve tüm akış kayıyordu ("invalid literal for int", çöp `:status`).
  Şifre çözmenin kendisi hep DOĞRUYDU — sorun record'un yanlış katmana
  verilmesiydi.
  Çözüm: `EncryptedSocket.recv_record(skip_post_handshake=True)` artık
  application aşamasında gelen handshake record'larını (NewSessionTicket=4,
  KeyUpdate=24) yutuyor; HTTP/2 ve HTTP/1.1 okuma yolları bu bayrağı kullanıyor.
  Bir regresyon testi (`test_newsessionticket_h2_akisini_bozmuyor`) araya giren
  NewSessionTicket'a rağmen doğru status okunduğunu doğruluyor.

### Değişti

- `appdata_diagnose.py` artık content_type=22'yi doğru yorumluyor: gelen şeyin
  bir post-handshake mesajı (şifre çözme başarılı) olduğunu, HTTP verisi
  olmadığını açıkça söylüyor. Önceki sürüm bunu yanlışlıkla "şifre çözme bozuk"
  diye raporluyordu.

### Hâlâ araştırılıyor

- **nginx.org `protocol_version` (alert 70) ile reddediyor.** supported_versions'a
  GREASE eklenmesi (v0.2.3) bu spesifik sunucuda yetmedi; record ve ClientHello
  legacy_version değerleri doğru (0x0301 / 0x0303). Cloudflare ve tls.peet.ws
  aynı ClientHello'yu kabul ettiğinden bu tek bir katı sunucuya özgü görünüyor;
  araştırma sürüyor. Diğer TLS 1.3 sunucularını etkilemiyor.

## [0.2.3] — 2026-09-04

Gerçek ağ testinin ikinci turu. Doğru kod artık çalıştığından (gölgeleme
düzeldi), gerçek uyumluluk sorunları görünür oldu.

### Düzeltildi

- **`supported_versions` extension'ında GREASE eksikti.** Düz `0304`
  gönderiliyordu; Cloudflare gibi hoşgörülü sunucular kabul ediyor ama
  nginx.org gibi katı yığınlar `protocol_version` (alert 70) ile reddediyordu.
  Artık Chrome gibi `GREASE + 0x0304` gönderiliyor. Bu hem uyumluluğu artırır
  hem de parmak izini gerçek Chrome'a yaklaştırır (cipher ve supported_groups
  listelerinde zaten GREASE vardı; supported_versions tutarsız kalmıştı).

### Eklendi

- `appdata_diagnose.py` — tam handshake yapıp ilk şifresi çözülmüş
  application byte'larını döken teşhis aracı. "invalid literal for int" /
  çöp-veri sorununun şifre çözmede mi yoksa HTTP/2 parse'ta mı olduğunu
  ayırt etmek için.

### Araştırılıyor

- **Cloudflare/Google'da application-data çöp görünüyor** ("invalid literal
  for int", ham byte dizileri). Handshake başarılı (ServerHello TLS 1.3),
  ama üst katman bozuk. tls.peet.ws'e tam istek (JSON dahil) çalıştığından
  sorun her bağlantıda değil — büyük olasılıkla HTTP/2 (h2) yoluna özgü.
  `appdata_diagnose.py` çıktısı kök nedeni belirleyecek.

### Ortam notları (kod sorunu değil)

- badssl.com alt alan adları test ortamında DNS ile çözülemedi/zaman aşımına
  uğradı — ağ/DNS engellemesi. Sertifika reddi testleri bu yüzden sonuç
  vermedi; bağlantı hiç kurulamadı.
- httpbin.org `0xc02f` (TLS 1.2) seçiyor olabilir; bu istemci bilerek
  TLS 1.3-only'dir, dolayısıyla TLS 1.2-only sunucular reddedilir (doğru
  davranış, ama hata mesajı yanıltıcı).

## [0.2.2] — 2026-09-03

Ortam uyumluluğu ve teşhis. Kullanıcının Pydroid3/Android testinde iki sorun
ortaya çıktı; ikisi de kodun kendisiyle değil, ÇALIŞTIRMA ORTAMIYLA ilgiliydi.

### Düzeltildi

- **Pydroid3/Android: OpenSSL 3.0 legacy provider hatası.** `cryptography`
  import'u "legacy provider failed to load" RuntimeError'ı ile ölümcül biçimde
  patlıyordu. `CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1` artık paket import edilir
  edilmez (herhangi bir cryptography alt modülünden önce) `__init__.py` ve
  `cert_validator.py` içinde ayarlanıyor. fasthttpc yalnızca modern algoritmalar
  kullandığından legacy provider'a hiç ihtiyaç yoktur; devre dışı bırakmak
  güvenlidir.
- **Yardımcı scriptlerde yanlış kopya yükleme riski.** `integration_test.py`,
  `tls_diagnose.py` ve `mitm_test.py` çalışma dizinini (`sys.path.insert(0,".")`)
  değil, artık scriptin KENDİ dizinini path'e ekliyor. Başka bir yerde
  (örn. `/storage/emulated/0/fasthttpc`) eski bir kopya varsa gölgeleme yapıp
  güncel sürümün önüne geçebiliyordu. Scriptler ayrıca yüklenen paketin gerçekten
  yanlarındaki olduğunu doğrulayıp değilse görünür bir UYARI basıyor.

### Not

- Önceki testte görülen `0xc02f` (TLS 1.2 cipher) ve "invalid literal for int"
  hataları büyük olasılıkla ESKİ bir fasthttpc kopyasının gölgelemesinden
  kaynaklanıyordu. Güncel kod, denenen sunucuların hepsine (nginx.org,
  badssl.com, httpbin.org, tls.peet.ws) TLS 1.3 + geçerli suite ile bağlanıyor;
  `0xc02f` reprodüksiyonu yok. Gölgeleme düzeltildikten sonra testin yeniden
  koşulması gerekiyor.

## [0.2.1] — 2026-09-03

Gerçek ağ entegrasyon testi sonrası düzeltmeler. (Sandbox'ta ağ olmadığı için
bu bulgular ancak kullanıcının makinesinde çalıştırılarak ortaya çıktı.)

### Düzeltildi

- **KRİTİK REGRESYON: `connect()` her gerçek bağlantıda çöküyordu.** Önceki
  turda bir düzenleme `_apply_socket_options` gövdesini bozmuş, tanımsız
  `_TCP_FASTOPEN` değişkenine ve statik metot kapsamında olmayan `timeout`/
  `host`/`port` adlarına atıfta bulunuyordu. Import sırasında görünmüyordu;
  yalnızca gerçek bir socket açılınca patlıyordu. Birim testleri socket
  açmadığı için yakalayamamıştı.
- **HTTP/2 yolu PADDED/PRIORITY frame'lerde çöp veri üretiyordu.** HEADERS ve
  DATA frame'lerinin pad-length, padding ve priority alanları ayıklanmadan
  HPACK'e/gövdeye veriliyordu; Cloudflare ve Google bu alanları kullandığı için
  `:status` bozuluyor ve "invalid literal for int" hatası veriyordu (RFC 7540
  §6.1, §6.2). tls.peet.ws bu flag'leri kullanmadığından çalışıyordu.

### Bilinen açık sorun (araştırılıyor)

- **Bazı sunucular (nginx.org, badssl.com, httpbin.org) TLS 1.2 cipher (0xc02f)
  seçiyor** ya da handshake'i `protocol_version` alert'iyle reddediyor.
  tls.peet.ws aynı ClientHello'ya TLS 1.3 verdiğinden ClientHello'nun kendisi
  büyük olasılıkla sağlam; sorun muhtemelen eksik bir extension veya bu
  sunucuların downgrade davranışı. Teşhis için `tls_diagnose.py` eklendi.

### Eklendi

- `integration_test.py` — gerçek sunuculara karşı uçtan uca test. Sertifika
  testi artık handshake'in sertifikadan ÖNCE kopmasını "sonuçsuz" olarak
  işaretliyor (önceden yanlışlıkla "güvenlik açığı" diyordu).
- `mitm_test.py` — mitmproxy ile MITM reddinin pratik kanıtı.
- `tls_diagnose.py` — tek host için ham ServerHello dökümü.

### Doğrulanan

- **JA3 parmak izi gerçek dünyada tutarlı.** tls.peet.ws'in gördüğü JA3,
  `ja3_for_profile("chrome_131")`'in ürettiğiyle birebir aynı
  (`b32309a26951912be7dba376398abc3b`). Bir TLS 1.3 handshake'i baştan sona
  başarılı tamamlandı ve JSON yanıtı düzgün parse edildi.

## [0.2.0] — 2026-09-02

Güvenlik ve doğruluk sürümü. Ayrıntılı kod incelemesi sonrası yapıldı.

### Güvenlik

- **KRİTİK: CertificateVerify doğrulaması eklendi** (RFC 8446 §4.4.3). Önceki
  sürümler sertifika zincirini doğruluyor ama sunucunun özel anahtara sahip
  olduğunu hiç kontrol etmiyordu. Bu, aktif MITM'e izin veriyordu: saldırgan
  gerçek sunucunun (herkese açık) sertifikasını aynen iletip kendi anahtar
  değişimini yapabilirdi. ECDSA, RSA-PSS, Ed25519 ve Ed448 destekleniyor;
  TLS 1.3'te yasak olan `rsa_pkcs1_*` şemaları reddediliyor.
- **KRİTİK: Server Finished MAC doğrulaması eklendi** (§4.4.4). Önceden mesaj
  görülünce doğrulanmadan kabul ediliyordu.
- **Cookie sızıntısı kapatıldı.** Çerezler artık RFC 6265 domain/path/Secure
  kurallarına göre saklanıyor ve seçiliyor. Önceden düz bir dict'te tutulup
  her isteğe ekleniyordu; `a.com` oturum token'ı redirect ile `b.com`'a
  gönderiliyordu.
- **Cross-origin redirect'te kimlik başlıkları düşürülüyor**
  (`Authorization`, `Cookie`, `Proxy-Authorization`).
- TLS downgrade artık açıkça reddediliyor; `supported_versions` 0x0304
  gelmezse bağlantı kesiliyor.
- HelloRetryRequest tespit edilip açık hata veriliyor (önceden ServerHello
  gibi ayrıştırılıp bozuk anahtar üretiyordu).
- AEAD AAD'si artık telde gelen record header'ının kendisi; sabit
  `0x17/0x0303` varsayımı kaldırıldı.

### Düzeltildi

- **SHA-384 cipher suite'leri artık çalışıyor.** Key schedule SHA-256'ya
  sabitti; `TLS_AES_256_GCM_SHA384` seçildiğinde sessizce yanlış anahtar
  üretiyordu. HKDF ve tüm türetme fonksiyonları hash-parametrik hâle getirildi.
- **JA3 artık Chrome'a benziyor.** ClientHello oluşturucu TLS 1.2 cipher
  suite'lerini eliyordu; 16 suite yerine 4 gönderiliyordu.
- **JA3 gerçek byte'lardan hesaplanıyor.** `ja3_for_profile()` /
  `ja3_from_client_hello()` eklendi. Eski `ja3_hash()` profil sözlüğünü okuyordu
  ve koddaki filtrelemeyi göremediği için olmayan bir parmak izi raporluyordu.
- **`client_random` artık 32 byte tam rastgele.** TLS 1.2 kalıntısı olan
  `gmt_unix_time` prefix'i kaldırıldı — tek başına bot sinyaliydi.
- **ClientHello padding matematiği** düzeltildi (cipher bloğu iki kez sayılıyor,
  toplam 512'nin katı olmuyordu).
- **Bilinmeyen profil adı artık `ValueError` fırlatıyor.** Sessizce `default`'a
  düşmek, kullanıcının Chrome taklit ettiğini sanırken
  `User-Agent: fasthttpc/2.0` göndermesine yol açıyordu. `firefox_120` ve
  `safari_17` takma ad olarak eklendi.
- **Query string korunuyor.** `parse_qs`→`urlencode` turu sorguyu yeniden
  yazıyordu (`?foo` → `?foo=`, parametre sırası değişiyordu); imza doğrulayan
  API'lerde 403 sebebiydi.
- **Çoklu `Set-Cookie` korunuyor.** `Headers.add()` eklendi; `__setitem__`
  aynı isimli önceki değerleri siliyor ve sırayı bozuyordu.
- **HTTP/2 gönderim akış kontrolü uygulanıyor.** `_conn_window_send`
  güncelleniyor ama okunmuyordu; 65535 byte'tan büyük gövdeler
  FLOW_CONTROL_ERROR alıyordu. Stream bazlı pencereler de takip ediliyor.
- **HTTP/2 pseudo-header sırası** Chrome ile eşleşecek şekilde `:method`,
  `:authority`, `:scheme`, `:path` yapıldı.
- **HPACK header bloğu her decode sonrası sıfırlanıyor.** 1xx ara yanıtlar ve
  trailer'lar önceki bloğa ekleniyor, HPACK durumunu bozuyordu.
- **`response.elapsed`** metrics yokken `time.monotonic()` ham değerini
  dönüyordu.
- **Bağlantı havuzu:** IPv6 desteği (`getaddrinfo`), boşta kalma süresi (TTL)
  ile bayat bağlantıların atılması, hata yolunda çift `release()` sonucu
  semaphore sayacının bozulmasının önlenmesi, `prewarm`'ın `max_connections`
  sınırına uyması.
- **TCP Fast Open** artık doğru seçenekle (`TCP_FASTOPEN_CONNECT`) isteniyor;
  önceki kod sunucu tarafı seçeneğini kullanıyordu, yani hiçbir etkisi yoktu.
- **Redirect `Location` çözümlemesi** protokol-göreli (`//host`) ve göreli
  (`dosya.html`) biçimleri de destekliyor.
- `URL` hostsuz girdide `AttributeError` yerine açık `ValueError` veriyor;
  IDN alan adları punycode'a çevriliyor.
- `PureAESGCM` 24 byte anahtarı sessizce yanlış tur sayısıyla işlemek yerine
  reddediyor.
- `FastChaCha20Poly1305` saf Python yedeğine düşerken tanımsız kalıyordu.

### Değişti

- **Kütüphane artık `print()` kullanmıyor**; `logging` altyapısına geçildi.
  `enable_debug_logging()` ile açılır.
- **`RetryPlugin` gerçekten yeniden deniyor.** Önceki hâli `return response`
  yapan boş bir gövdeydi. `Retry-After` başlığına saygı duyar.
- **`AsyncSession(impersonate=...)` artık `UserWarning` veriyor.** Async yol
  stdlib `ssl` kullanır, TLS taklidi yapmaz; sessizce yok saymak yerine
  açıkça söyleniyor.
- **DNS-over-HTTPS bağlandı.** `Session(resolver=DoHResolver(...))` ile
  kullanılabiliyor; önceden modül hiçbir yerden çağrılmıyordu.
- HTTP/2 SETTINGS kümesi Chrome'a yaklaştırıldı, `ENABLE_PUSH=0` eklendi.
- `Session.cookies` artık `CookieJar` üzerinden salt okunur bir görünüm.

### Kaldırıldı

- `compiler.py` (336 satır) — hiçbir yerden import edilmiyordu.
- `debug_h2.py` — geliştirme artığı.
- `ja3n_hash()` korunuyor ama yanlış isimlendirildiği belgelendi; literatürdeki
  JA3N normalize edilmiş varyanttır, GREASE dahil eden değil.

### Paketleme ve testler

- `pyproject.toml` paket köküne taşındı; `build-backend` düzeltildi
  (`setuptools.backends.legacy:build` diye bir backend yok), paket adı
  `fasthttpc_v3` → `fasthttpc` olarak eşitlendi. `pip install -e .` artık çalışıyor.
- **84 ağsız birim testi eklendi** (`tests/`). CertificateVerify düzeltmesi,
  MITM senaryoları dahil doğrudan test ediliyor.
- Ağ gerektiren eski `test.py`, `smoke_test.py` olarak yeniden adlandırıldı ve
  birim test paketi olmadığı açıkça belirtildi.
- `.gitignore` eklendi, `__pycache__` temizlendi.
- README'den çalışmayan özellik iddiaları çıkarıldı; "Bilinen sınırlar" bölümü
  eklendi.

## [0.1.0] — 2026-06-27

- İlk sürüm: HTTP/1.1 + HTTP/2 istemcisi, TLS 1.3 handshake, connection pool,
  TLS fingerprinting, AsyncSession, plugin sistemi, response cache, multipart.
