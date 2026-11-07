# Changelog

## [Unreleased]

### Eklendi

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
