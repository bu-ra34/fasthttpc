# Saha raporu

Dal `saha`. Araçlar: `saha/canli_siteler.py`, `saha/soak.py`, `saha/yuk.py`, `saha/yerel_sunucu.py`
(yerel TLS 1.3 sunucusu, kendi CA'mızla). Regresyon testleri: `tests/test_saha_regresyon.py` (20 test).

## Dürüstlük notu: TLS nerede sonlandı?
Ortamda dış HTTPS bir proxy üzerinden çıkıyor. `canli_siteler.py` her site için CONNECT tüneli açıp sunucu
sertifikasının düzenleyicisine bakıyor. Sonuç: 42 sitenin **yalnızca 2'sinde** (github.com, api.github.com) TLS
proxy'de sonlandı (düzenleyici proxy CA'sı). Diğer 40 sitede tünel uçtan uca geçti; fasthttpc gerçek sitenin
sertifikasıyla ve gerçek sitenin TLS/ALPN davranışıyla konuştu (h2 müzakere edildi, Google/Cloudflare/Akamai vb.).
Yani canlı tablo çoğunlukla gerçek TLS 1.3 + h2 sonucudur; yalnızca GitHub satırları proxy'nin davranışıdır
(`github.com` -> 400 "Request path could not be canonicalized" proxy'nin kendi politikası, requests de aynısını alıyor).
Yine de: tek bir çıkış IP'si ve proxy üzerinden olduğu için bot engeli sonuçları (403) normal bir ev/ofis IP'sinden
farklı olabilir; parmak izi (JA3/JA4) doğrulaması bu testin kapsamı dışındadır.

## 1. Canlı siteler (42 site x 3 profil, senkron Session, requests ile karşılaştırma)
Sınıflandırma: ok / (a) beklenen / (b) fasthttpc hatası. Sonuç: **(b) = 0**.
- (a) TLS 1.2-only: `nginx.org` (3 profilde de net hata: `protocol_version: ... downgrade kabul edilmiyor`; requests 200 alıyor, çünkü TLS 1.2 konuşuyor — tasarım gereği).
- (a) Bot engeli 403: akamai.com, stackoverflow, npm, hepsiburada, sahibinden (requests ile aynı). github 400 = proxy.
- Dikkat çekici: fasthttpc (tarayıcı profilleri) microsoft, reddit, linkedin, trendyol'da **200** alırken düz requests **403** aldı.
- amazon: tarayıcı profilleri 202 (bot challenge sayfası), requests 200.
- Tüm başarılı isteklerde ALPN h2 (github-api hariç h1.1; o proxy'de sonlandı).

| site | requests | chrome_131 | firefox_133 | safari_18 |
|---|---|---|---|---|
| cloudflare | 200 526ms | 200 1078ms h2 [ok] | 200 1229ms h2 [ok] | 200 950ms h2 [ok] |
| cf-trace | 200 464ms | 200 470ms h2 [ok] | 200 418ms h2 [ok] | 200 415ms h2 [ok] |
| cdnjs | 200 448ms | 200 567ms h2 [ok] | 200 438ms h2 [ok] | 200 399ms h2 [ok] |
| akamai | 403 490ms | 403 532ms h1.1 [a:bot-engeli/istemci-durumu] | 403 486ms h1.1 [a:bot-engeli/istemci-durumu] | 403 423ms h1.1 [a:bot-engeli/istemci-durumu] |
| fastly | 200 500ms | 200 476ms h2 [ok] | 200 490ms h2 [ok] | 200 457ms h2 [ok] |
| jsdelivr | 200 314ms | 200 420ms h2 [ok] | 200 165ms h2 [ok] | 200 578ms h2 [ok] |
| unpkg | 200 573ms | 200 570ms h2 [ok] | 200 300ms h2 [ok] | 200 514ms h2 [ok] |
| google | 200 532ms | 200 270ms h2 [ok] | 200 549ms h2 [ok] | 200 504ms h2 [ok] |
| google-204 | 204 138ms | 204 252ms h2 [ok] | 204 407ms h2 [ok] | 204 345ms h2 [ok] |
| youtube | 200 402ms | 200 624ms h2 [ok] | 200 786ms h2 [ok] | 200 806ms h2 [ok] |
| microsoft | HATA ReadTimeout: HTTPSConnectionPool(host='w | 200 394ms h2 [ok] | 200 450ms h2 [ok] | 200 475ms h2 [ok] |
| bing | 200 474ms | 200 777ms h2 [ok] | 200 435ms h2 [ok] | 200 741ms h2 [ok] |
| amazon | 202 487ms | 202 404ms h2 [ok] | 200 587ms h2 [ok] | 200 639ms h2 [ok] |
| apple | 200 571ms | 200 615ms h2 [ok] | 200 628ms h2 [ok] | 200 449ms h2 [ok] |
| github | 400 192ms | 400 326ms h1.1 [a:bot-engeli/istemci-durumu] | 400 397ms h1.1 [a:bot-engeli/istemci-durumu] | 400 358ms h1.1 [a:bot-engeli/istemci-durumu] |
| github-api | 200 266ms | 200 76ms h1.1 [ok] | 200 74ms h1.1 [ok] | 200 80ms h1.1 [ok] |
| wikipedia | 200 398ms | 200 381ms h2 [ok] | 200 472ms h2 [ok] | 200 487ms h2 [ok] |
| wikipedia-tr | 200 537ms | 200 432ms h2 [ok] | 200 467ms h2 [ok] | 200 450ms h2 [ok] |
| reddit | 403 376ms | 200 154ms h2 [ok] | 200 332ms h2 [ok] | 200 465ms h2 [ok] |
| stackoverflow | 403 522ms | 403 303ms h2 [a:bot-engeli/istemci-durumu] | 403 427ms h2 [a:bot-engeli/istemci-durumu] | 403 484ms h2 [a:bot-engeli/istemci-durumu] |
| twitter-x | 200 413ms | 200 704ms h2 [ok] | 200 524ms h2 [ok] | 200 281ms h2 [ok] |
| linkedin | 403 441ms | 200 326ms h2 [ok] | 200 674ms h2 [ok] | 200 509ms h2 [ok] |
| netflix | 200 942ms | 200 833ms h2 [ok] | 200 1013ms h2 [ok] | 200 1003ms h2 [ok] |
| python-org | 200 314ms | 200 490ms h2 [ok] | 200 444ms h2 [ok] | 200 413ms h2 [ok] |
| pypi | 200 405ms | 200 481ms h2 [ok] | 200 460ms h2 [ok] | 200 372ms h2 [ok] |
| npm | 403 207ms | 403 128ms h2 [a:bot-engeli/istemci-durumu] | 403 387ms h2 [a:bot-engeli/istemci-durumu] | 403 439ms h2 [a:bot-engeli/istemci-durumu] |
| httpbin | 200 384ms | 200 387ms h2 [ok] | 200 328ms h2 [ok] | 200 447ms h2 [ok] |
| example | 200 392ms | 200 320ms h2 [ok] | 200 334ms h2 [ok] | 200 469ms h2 [ok] |
| nginx | 200 550ms | HATA TLSProtocolError: protocol_version: Sunucu TLS 1.3 [a:TLS1.2-only] | HATA TLSProtocolError: protocol_version: Sunucu TLS 1.3 [a:TLS1.2-only] | HATA TLSProtocolError: protocol_version: Sunucu TLS 1.3 [a:TLS1.2-only] |
| bbc | 200 536ms | 200 642ms h2 [ok] | 200 581ms h2 [ok] | 200 608ms h2 [ok] |
| cnn | 200 441ms | 200 1615ms h2 [ok] | 200 1784ms h2 [ok] | 200 1805ms h2 [ok] |
| nytimes | 200 989ms | 200 684ms h2 [ok] | 200 1352ms h2 [ok] | 200 1147ms h2 [ok] |
| guardian | 200 627ms | 200 545ms h2 [ok] | 200 531ms h2 [ok] | 200 598ms h2 [ok] |
| hurriyet | 200 582ms | 200 667ms h2 [ok] | 200 443ms h2 [ok] | 200 387ms h2 [ok] |
| milliyet | 200 496ms | 200 466ms h2 [ok] | 200 445ms h2 [ok] | 200 794ms h2 [ok] |
| sabah | 200 632ms | 200 634ms h2 [ok] | 200 405ms h2 [ok] | 200 516ms h2 [ok] |
| trendyol | 403 810ms | 200 834ms h2 [ok] | 200 814ms h2 [ok] | 200 834ms h2 [ok] |
| hepsiburada | 403 216ms | 403 127ms h2 [a:bot-engeli/istemci-durumu] | 403 596ms h2 [a:bot-engeli/istemci-durumu] | 403 268ms h2 [a:bot-engeli/istemci-durumu] |
| sahibinden | 403 645ms | 403 787ms h2 [a:bot-engeli/istemci-durumu] | 403 327ms h2 [a:bot-engeli/istemci-durumu] | 403 299ms h2 [a:bot-engeli/istemci-durumu] |
| turkiye-gov | 200 824ms | 200 1022ms h2 [ok] | 200 808ms h2 [ok] | 200 749ms h2 [ok] |
| ntv | 200 662ms | 200 553ms h2 [ok] | 200 503ms h2 [ok] | 200 540ms h2 [ok] |
| sozcu | 200 559ms | 200 523ms h2 [ok] | 200 550ms h2 [ok] | 200 519ms h2 [ok] |

| site | TLS nerede sonlandı |
|---|---|
| cloudflare | uçtan uca: Google Trust Services (TLSv1.3) |
| cf-trace | uçtan uca: Google Trust Services (TLSv1.3) |
| cdnjs | uçtan uca: Google Trust Services (TLSv1.3) |
| akamai | uçtan uca: DigiCert Inc (TLSv1.3) |
| fastly | uçtan uca: Certainly (TLSv1.3) |
| jsdelivr | uçtan uca: Sectigo Limited (TLSv1.3) |
| unpkg | uçtan uca: Google Trust Services (TLSv1.3) |
| google | uçtan uca: Google Trust Services (TLSv1.3) |
| google-204 | uçtan uca: Google Trust Services (TLSv1.3) |
| youtube | uçtan uca: Google Trust Services (TLSv1.3) |
| microsoft | uçtan uca: Microsoft Corporation (TLSv1.3) |
| bing | uçtan uca: Microsoft Corporation (TLSv1.3) |
| amazon | uçtan uca: DigiCert Inc (TLSv1.3) |
| apple | uçtan uca: Apple Inc. (TLSv1.3) |
| github | proxy'de sonlandı (TLSv1.3) |
| github-api | proxy'de sonlandı (TLSv1.3) |
| wikipedia | uçtan uca: Let's Encrypt (TLSv1.3) |
| wikipedia-tr | uçtan uca: Let's Encrypt (TLSv1.3) |
| reddit | uçtan uca: DigiCert Inc (TLSv1.3) |
| stackoverflow | uçtan uca: Let's Encrypt (TLSv1.3) |
| twitter-x | uçtan uca: Let's Encrypt (TLSv1.3) |
| linkedin | uçtan uca: DigiCert Inc (TLSv1.3) |
| netflix | uçtan uca: DigiCert Inc (TLSv1.3) |
| python-org | uçtan uca: GlobalSign nv-sa (TLSv1.3) |
| pypi | uçtan uca: GlobalSign nv-sa (TLSv1.3) |
| npm | uçtan uca: Google Trust Services (TLSv1.3) |
| httpbin | uçtan uca: Let's Encrypt (TLSv1.3) |
| example | uçtan uca: SSL Corporation (TLSv1.3) |
| nginx | uçtan uca: Let's Encrypt (TLSv1.2) |
| bbc | uçtan uca: GlobalSign nv-sa (TLSv1.3) |
| cnn | uçtan uca: GlobalSign nv-sa (TLSv1.3) |
| nytimes | uçtan uca: DigiCert Inc (TLSv1.3) |
| guardian | uçtan uca: GlobalSign nv-sa (TLSv1.3) |
| hurriyet | uçtan uca: GlobalSign nv-sa (TLSv1.3) |
| milliyet | uçtan uca: GlobalSign nv-sa (TLSv1.3) |
| sabah | uçtan uca: GoDaddy.com (TLSv1.3) |
| trendyol | uçtan uca: GlobalSign nv-sa (TLSv1.3) |
| hepsiburada | uçtan uca: DigiCert Inc (TLSv1.3) |
| sahibinden | uçtan uca: DigiCert Inc (TLSv1.3) |
| turkiye-gov | uçtan uca: GlobalSign nv-sa (TLSv1.3) |
| ntv | uçtan uca: Google Trust Services (TLSv1.3) |
| sozcu | uçtan uca: Google Trust Services (TLSv1.3) |

## 2. Soak (tek Session, yerel TLS 1.3 sunucusu, `python -m saha.soak`)
- 2000 ardışık istek (id/chunked/gzip/br karışık): **0 hata**, ~930 istek/s, sunucuya **1** TCP bağlantısı (keep-alive tam yeniden kullanım),
  fd 5 -> 7 (artış yok, soket sızıntısı yok), havuzda 1 boşta bağlantı.
- tracemalloc: ısınmadan sonra 1800 istekte +5 KB (~3 bayt/istek) -> bellek büyümesi yok.
- 10 MB gövde: 0.04 s (~250 MB/s loopback), bayt-bayt doğrulandı; ardından aynı bağlantıda istek sorunsuz.
  25 ardışık 10 MB indirmede RSS 62 MB'ta sabit (sızıntı yok; ilk indirmede tepe bellek ~2x gövde).
- Canlı (proxy üstünden, example.com, h2): 500 istek, 0 hata, 499 bağlantı yeniden kullanımı, 16 istek/s (ağ gecikmesi sınırlı),
  fd 4 -> 5. tracemalloc +34 KB / 480 istek (~70 B/istek) -> kök neden h2 stream tablosu sızıntısı, düzeltildi (bulgu 6).

## 3. Yük / eşzamanlılık (`python -m saha.yuk`)
Ortak Session, her istekte benzersiz kimlik (GET/POST/chunked/gzip/yavaş karışık), yanıt kimliği doğrulanıyor.
| thread | max_conn | istek | başarılı | hata | karışan yanıt | takılı thread | istek/s | p99 |
|---|---|---|---|---|---|---|---|---|
| 20 | 10 | 800 | 800 | 0 | 0 | 0 | 1615 | 251 ms |
| 50 | 10 | 2000 | 2000 | 0 | 0 | 0 | 1800 | 595 ms |
| 50 | 50 | 2000 | 2000 | 0 | 0 | 0 | 2001 | 119 ms |
| 50 | 2 | 2000 | 2000 | 0 | 0 | 0 | 409 | 2.96 s |
Hata enjeksiyonu (zaman aşımı 2 sn):
- Yavaş sunucu: 2.05 s'de TimeoutError (düzeltme sonrası tek istek; önceki kod yeniden kullanılan bağlantıda ikinci kez gönderiyordu).
- Damla damla yanıt (6 s toplam, her parça 1 s): `timeout=2` tetiklenmez (read zaman aşımı recv başınadır) -> 6 s'de 200. `Timeout(total=...)` eklendi.
- Yarıda kesen sunucu (close_notify'lı/siz), RST, yanıtsız kapanış: hepsi anında ConnectionResetError, havuz sağlam, sonraki istek başarılı.
- Bayat keep-alive (sunucu bağlantıyı kapatmış): şeffaf yeniden bağlanma, başarılı.
- Havuz tükenmesi (2 bağlantı, 4 istek, pool=1 s): 2 istek `Bağlantı havuzu dolu` TimeoutError, 2'si başarılı; deadlock yok.

## 4. Bulgular ve düzeltmeler (hepsi ağsız regresyon testli, bkz. tests/test_saha_regresyon.py)
1. **Connection: close yanıtı havuzu kilitliyordu (fasthttpc/session.py)**. Kök neden: `conn.close()` çağrılıp `pool.release()` atlanıyordu -> semaphore slotu sızıyor; max_connections kadar "close" yanıtından sonra havuz kalıcı `Bağlantı havuzu dolu`. Düzeltme: close + release. Ayrıca HTTP/1.0 (keep-alive'sız) ve kapanışla biten gövdeler de bağlantıyı kapatıyor.
2. **204/304 (ve 1xx, HEAD) Content-Length'siz yanıtta zaman aşımına kadar takılma**. Kök neden: gövde "EOF'a kadar" okunuyordu. Düzeltme: `Session._body_framing` (RFC 9112 §6.3).
3. **HTTP/1.0 / kapanışla biten gövde, close_notify'sız TCP kapanışında ConnectionResetError**. Bu modda close_notify'sız EOF artık gövdenin sonu sayılıyor (tarayıcı/curl davranışı); Content-Length'li gövdelerde hâlâ hata.
4. **Eksik gövde sessizce başarı sayılıyordu**: Content-Length'ten kısa gövde (temiz close_notify ile) ve yarıda kesilen chunked gövde 200 olarak, kısaltılmış dönüyordu. Artık ConnectionResetError. Geçersiz chunk boyutu da artık hata (önceden sessizce kesiyordu). Chunked trailer'lar ve kapanış boş satırı tüketiliyor (artık bayt bir sonraki yanıtı bozmuyor; eskiden "bayat bağlantı" yeniden denemesi bunu gizliyordu).
5. **Yeniden kullanılan bağlantıda zaman aşımında istek ikinci kez gönderiliyordu** (POST çift gönderim, bekleme 2x). Artık yalnızca yanıttan hiç bayt gelmediyse ve hata zaman aşımı değilse yeniden denenir.
6. **h2 `_stream_windows` sızıntısı (protocol/http2_parser.py)**: her istek bir girdi bırakıyordu (~70 B/istek, uzun ömürlü bağlantıda sınırsız). Temizleniyor; geç WINDOW_UPDATE girdi yaratmıyor.
7. **CookieJar thread güvenliği (cookies.py)**: kilitsizdi; sözlük yinelenirken yazım `dictionary changed size` riski taşır. RLock + anlık kopya eklendi. DÜRÜSTÇE: yarışı tetikleyemedim (Python 3.13'te 0 hata), bu önleyici bir düzeltme; testi yarışı değil ortak kullanımı doğruluyor.
8. Eklemeler: `Response.http_version` ("HTTP/1.1"/"HTTP/2"), `Timeout(total=...)` (slow-loris sınırı; h1 yolunda, h2 yolunda uygulanmıyor), pytest `pythonpath=["."]`.
9. **AsyncSession'a (async ajanına bildirildi, düzeltmedim)**: 204/304 yanıtı ~2 sn gecikiyor; Content-Length'ten kısa gövde sessizce 200 dönüyor.

## Bilinen eksikler / test edilemeyenler
- Gerçek bir ISP/DNS/IPv6 yolu, TLS 1.3 sunucu parmak izi doğrulaması (tls.peet.ws), WebSocket ve async canlı testi yapılmadı.
- `Timeout.total` h2 yolunda uygulanmıyor; h2 yolunda yarıda kesme/yük testi yerel sunucuyla yapılamadı (Python ssl sunucusu h2 konuşmuyor; h2 yalnızca canlı soak ve birim testle kapsandı).
- Yerel sunucu yalnız HTTP/1.1; yük testleri h1.1 üzerinde.
- Canlı tablo tek çalıştırmadır; aralıklı (flaky) hatalar için tekrar yok.
- İstek başarım sayıları loopback + aynı süreçteki sunucuyla ölçüldü (sunucu da aynı GIL'i paylaşıyor), mutlak değil göreli okunmalı.
