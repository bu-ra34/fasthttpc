# Canlı soak raporu (v0.5.0)

`python3 interop/canli_soak.py --dakika 20 --proxy "$HTTPS_PROXY" --ca /root/.ccr/ca-bundle.crt`
(`FASTHTTPC_NO_ECH_GREASE=1`; ortamın egress proxy'si ECH GREASE görünce TLS'i
kendisi sonlandırıyor, bu ayarla tünel uçtan uca gerçek siteye gidiyor.)

- Süre: 20 dakika, 60 döngü, 15 site × 3 profil × sync/async
- Toplam: 2035 başarılı istek,
  1 hata
- Bellek (RSS): 36.8 MB → 46.0 MB (ısınmadan sonra sabit); açık fd sabit

| profil/yol | başarılı | hata | hata oranı | p50 ms | p90 ms | p99 ms | max ms |
|---|---|---|---|---|---|---|---|
| chrome_131/async | 236 | 0 | 0.00% | 452 | 561 | 736 | 953 |
| chrome_131/sync | 443 | 1 | 0.23% | 269 | 519 | 921 | 1509 |
| firefox_133/async | 236 | 0 | 0.00% | 450 | 543 | 818 | 1562 |
| firefox_133/sync | 442 | 0 | 0.00% | 246 | 566 | 891 | 1371 |
| safari_18/async | 236 | 0 | 0.00% | 443 | 556 | 684 | 8133 |
| safari_18/sync | 442 | 0 | 0.00% | 255 | 570 | 962 | 1295 |

## Bulunan hata ve düzeltmesi

Tek hata `www.debian.org`'da: sunucu bağlantıyı düzgün kapatmak için
`GOAWAY(last_stream_id=2^31-1, NO_ERROR)` gönderdi; senkron HTTP/2 yolu her
GOAWAY'i ölümcül hata sayıyordu. RFC 9113 §6.8'e göre düzeltildi:

- `last_stream_id` bizim stream'i kapsıyorsa yanıt tamamlanır, bağlantı yeniden
  kullanılmaz.
- Kapsamıyorsa istek işlenmemiştir: `Http2RefusedError`, Session yeni
  bağlantıda bir kez yeniden dener (POST dahil güvenli).
- GOAWAY almış bağlantıda yeni stream açılmaz.

Düzeltme sonrası `www.debian.org`'a 150 sn boyunca 71 istek: 0 hata.
Ham veri: `interop/canli_soak_sonuc.json`.
