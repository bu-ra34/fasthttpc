                          
"""
TLS parmak izi profilleri.

Her profil gerçek bir tarayıcının ClientHello yapısını taklit eder:
- Cipher suite sırası
- Extension sırası
- Supported groups
- Signature algorithms
- GREASE değerleri
- JA3 hash hesaplama (debug / doğrulama)

Kullanım:
    from fasthttpc.fingerprint import get_profile, ja3_hash
    profile = get_profile("chrome_131")
"""
import os
import struct
import hashlib


                                                                                
                                                                                 
                                                                                

_GREASE_VALUES = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
    0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
]

def _random_grease() -> int:
    return _GREASE_VALUES[os.urandom(1)[0] % len(_GREASE_VALUES)]


                                                                                
                                                                                 
                                                                                

# ---------------------------------------------------------------------------
# KAYNAKLAR (hangi değer nereden; "doğrulanmadı" = elimizde gerçek tarayıcı
# yakalaması yok, yalnızca kaynaklardan türetildi). Ayrıntılı tablo NOTES3'te.
#
#  [CI]  lexiforest/curl-impersonate bin/curl_chrome131, curl_firefox133,
#        curl_safari180 betikleri (--ciphers/--curves/--signature-hashes/
#        --http2-settings/--http2-window-update/--http2-pseudo-headers-order/
#        --http2-stream-weight/--http2-stream-exclusive/--tls-extension-order).
#  [TC]  bogdanfinn/tls-client v1.18.1 profiles/*.go (Chrome_131, Firefox_133,
#        Safari_IOS_18_0 ClientHelloSpec + h2 settings/connectionFlow/pseudo).
#  [CC]  curl_cffi docs impersonate/customize (Firefox JA3 örneği).
#  [KD]  krowdev "ja4 fingerprint t13d1516h2": Chrome 120-131 JA4 =
#        t13d1516h2_8daaf6152771_02713d6af862 (ALPS 17513 -> 17613 geçişi
#        Chrome 133'te; Chrome 131 ESKİ kod noktası 17513'ü kullanır).
#  [SW]  blog.send.win Akamai h2 yazısı (Chrome/Firefox/Safari h2 dizeleri,
#        JA4 önekleri t13d1516h2 / t13d1715h2 / t13d2014h2).
#
# 2026-11 profilleri (chrome_158 / firefox_160 / safari_27) için kaynaklar:
#  [CR]  Chromium 158.0.8127.37 kaynağı: net/socket/ssl_client_socket_impl.cc
#        (kVerifyPrefs = ML-DSA-44/65/87 + 8 klasik şema; SSL_set_permute_
#        extensions; trust anchor IDs; ECH GREASE), net/base/features.cc
#        (kUseNewAlpsCodepointHttp2 ve kTLSTrustAnchorIDs varsayılan AÇIK,
#        kAddTLSServerHandshakePadding KAPALI), net/ssl/ssl_config_service.cc,
#        net/data/ssl/chrome_root_store/root_store.textproto (28 trust anchor
#        ID'si), components/embedder_support/user_agent_utils.cc (sec-ch-ua
#        GREASE marka algoritması).
#  [BS]  BoringSSL ea9f3a34 (Chromium 158 DEPS): include/openssl/tls1.h
#        (TLSEXT_TYPE_trust_anchors 0xca34 = 51764, application_settings 17613),
#        ssl/extensions.cc (signature_algorithms başına GREASE şeması,
#        trust_anchors gövdesi), ssl/encrypted_client_hello.cc (ECH GREASE
#        uzunluğu 32*{4..7}+16, AEAD 1 veya 3).
#  [CAP] Bu depoda gerçek Google Chrome for Testing 153.0.8010.12 ile yerel
#        yakalama (--disable-field-trial-config): ClientHello (GREASE sigalg +
#        ML-DSA, 17613, 51764 / 186 bayt, X25519MLKEM768 key_share) ve h2
#        SETTINGS/WINDOW_UPDATE/HEADERS (Chrome 131 ile aynı).
#  [FF]  Firefox FIREFOX_160_0_RELEASE kaynağı (NSS 3.132):
#        security/manager/ssl/nsNSSIOLayer.cpp (gruplar, FFDHE yalnızca DHE
#        suite'leri açıksa; 3 key_share), nsNSSComponent.cpp + StaticPrefList
#        (ECDSA-CBC ve DHE suite'leri kapalı; security.tls.enable_mldsa=false
#        -> ML-DSA ClientHello'ya GİRMEZ), EnabledSignatureSchemes.h,
#        netwerk/protocol/http/nsHttpHandler.cpp (belge Accept değeri),
#        security/nss/lib/ssl/tls13ech.c (ECH GREASE AEAD 1/3, yük 32k+16).
#  [CI2] lexiforest/curl-impersonate 5b1c3542 (2026-10-29): patches/curl.patch
#        hedefleri chrome152 / firefox155 / safari270 ve tests/signatures/
#        (chrome_150.0.7871.127_macOS, safari_26.0.1_macOS gerçek yakalamaları;
#        safari270, firefox155 kısmi imzaları).
#  [WK]  webkit.org "WebKit Features for Safari 27.2" (2026-10-26): güncel
#        kararlı Safari 27.2.
# ---------------------------------------------------------------------------


def _tai(dotted: str) -> bytes:
    """Göreli OID (``1.3.6.1.4.1`` altı, noktalı) -> TrustAnchorID baytları (base-128)."""
    out = b""
    for arc in (int(a) for a in dotted.split(".")):
        enc = [arc & 0x7F]
        arc >>= 7
        while arc:
            enc.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out += bytes(reversed(enc))
    return out


# Chrome Root Store'daki 28 trust anchor ID'si [CR] root_store.textproto
# (Chromium 158 ile 153 arasında küme AYNI; [CAP] yakalaması bu kümeyi taşır).
# Chrome sırayı süreç başına değiştirir ([CAP]: farklı süreçlerde farklı sıra),
# bu yüzden sıra süreç başına bir kez karıştırılır (tls_crafter).
CHROME_TRUST_ANCHOR_IDS = [_tai(o) for o in (
    "52580.200109.1.10", "52580.200109.1.9", "11129.9.1", "11129.9.4", "44947.2.1",
    "52580.200109.1.8", "52580.200109.1.7", "44947.2.6", "52580.200109.1.19",
    "52580.200109.1.18", "52580.200109.1.11", "52580.200109.1.12", "52580.200109.1.13",
    "11129.9.5", "11129.9.6", "11129.9.7", "11129.9.8", "11129.9.10", "11129.9.11",
    "11129.9.12", "11129.9.13", "11129.9.15", "44947.2.13", "44947.2.14", "44947.2.15",
    "44947.2.18", "44947.2.19", "44947.2.20",
)]


def chrome_sec_ch_ua(major: int, brand: "str | None" = "Google Chrome") -> str:
    """Chromium'un sec-ch-ua GREASE marka algoritması [CR] user_agent_utils.cc
    (GetGreasedUserAgentBrandVersion + GetRandomOrder/ShuffleBrandList, tohum = ana
    sürüm). ``brand=None``: markasız Chromium (ör. Chrome for Testing) — 2 marka.
    Doğrulama: (152, "Google Chrome") -> curl-impersonate chrome152 değeri;
    (153, None) -> [CAP] yakalaması."""
    chars = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"]
    grease = (f"Not{chars[major % 11]}A{chars[(major + 1) % 11]}Brand",
              ["8", "99", "24"][major % 3])
    brands = [grease, ("Chromium", str(major))] + ([(brand, str(major))] if brand else [])
    if len(brands) == 2:
        order: tuple = (major % 2, (major + 1) % 2)
    else:
        order = [(0, 1, 2), (0, 2, 1), (1, 0, 2), (1, 2, 0), (2, 0, 1), (2, 1, 0)][major % 6]
    shuffled: list = [None] * len(brands)
    for i, pos in enumerate(order):
        shuffled[pos] = brands[i]
    return ", ".join(f'"{b}";v="{v}"' for b, v in shuffled)


# ---------------------------------------------------------------------------
# HPACK kodlayıcı davranışı (h2["hpack"]; alanlar: http2_parser.HpackPolicy).
# RFC 7541 Huffman'ın ne zaman kullanılacağını, hangi başlığın dinamik tabloya
# gireceğini, ad referansını, cookie bölmeyi ve tablo boyutu güncellemesini
# tarayıcıya bırakır; bunlar HEADERS frame'inin BAYTLARINI belirler.
#
#  [QH]  Chromium/QUICHE (google/quiche main): quiche/http2/hpack/hpack_encoder.cc
#        (DefaultPolicy, EmitString, EmitNonIndexedLiteral, CookieToCrumbs,
#        ApplyHeaderTableSizeSetting, MaybeEmitTableSize), hpack_header_table.cc
#        (GetByName/GetByNameAndValue: önce statik, sonra en yeni dinamik),
#        hpack_static_table.cc (aynı adlı statik girişlerde İLKİ),
#        http2/core/spdy_framer.cc (GetHpackEncoder: ENABLE_COMPRESSION, cookie
#        parçalama kapatılmaz); Chromium net/spdy/spdy_session.cc HandleSetting
#        (SETTINGS_HEADER_TABLE_SIZE -> UpdateHeaderEncoderTableSize, üst sınır yok).
#        Bağımsız doğrulama: httpcloak 8a8f2be1e7 commit'indeki gerçek Chrome 151
#        yakalamaları (":path /fi/matkat" = 048762533148d3d469, "cookie alpha=one" =
#        60871d15ce380f517f, :authority 0x41, 65536 için size update 3fe1ff03).
#  [FH]  Firefox (mozilla-firefox/firefox main) netwerk/protocol/http/
#        Http2Compression.cpp: EncodeHeaderBlock (:path noLocalIndex, cookie "; "
#        ile bölünür, <20 bayt parça never-indexed, authorization never-indexed,
#        te: trailers sonda), ProcessHeader (tablo taraması: SON ad eşleşmesi;
#        giriş > tablo/2 ya da tablo < 128 -> indekslenmez), HuffmanAppend (her dize
#        Huffman), SetMaxBufferSize (her SETTINGS_HEADER_TABLE_SIZE'da güncelleme);
#        Http2Session.cpp RecvSettings.
#  [SC]  Safari: CFNetwork kapalı kaynak. httpcloak testdata/safari-26-ios-capture.json
#        (tls.peet.ws, Safari 26.6.1 iOS) başlık listesi + PR #135'teki 277 baytlık
#        HEADERS yükü: 277 ancak Huffman AÇIK ve user-agent/accept/accept-language/
#        accept-encoding "incremental indexing" (6 bit önek) ile çıkar (Huffman'sız
#        359, indekslemesiz 281). Gerisi (Huffman "yalnızca kısaysa" mı "her zaman"
#        mı, pseudo-header indeksleme, cookie, size update) DOĞRULANMADI: Chromium
#        davranışı varsayıldı; cookie tek alan (httpcloak'ın WebKit varsayımı).
# ---------------------------------------------------------------------------

_HPACK_CHROMIUM = {
    "huffman": "shorter",              # EmitString: HuffmanSize < ham uzunluk ise
    "name_ref": "first",               # GetByName: statik ilk, sonra en yeni dinamik
    "index_pseudo": [":authority"],    # DefaultPolicy: pseudo'lardan yalnızca :authority
    "always_literal": [],
    "never_index": [],                 # QUICHE kodlayıcı 0x10 hiç üretmez
    "cookie_crumbs": "chromium",       # CookieToCrumbs (crumble_cookies_ = true)
    "cookie_never_index_below": 0,
    "index_max_entry_divisor": 0,      # TryAddEntry: sığmayan giriş tabloyu boşaltır
    "index_min_table_size": 0,
    "size_update": "on_change",        # ApplyHeaderTableSizeSetting
}

_HPACK_FIREFOX = {
    "huffman": "always",               # HuffmanAppend koşulsuz
    "name_ref": "last",                # ProcessHeader taraması
    "index_pseudo": None,              # :method/:authority/:scheme indekslenebilir
    "always_literal": [":path"],       # ProcessHeader(":path", noLocalIndex=true)
    "never_index": ["authorization"],
    "cookie_crumbs": "firefox",        # "; " ile böl
    "cookie_never_index_below": 20,    # "cookies less than 20 bytes are not indexed"
    "index_max_entry_divisor": 2,      # newSize > mMaxBuffer / 2
    "index_min_table_size": 128,       # mMaxBuffer < 128
    "size_update": "on_setting",       # SetMaxBufferSize her SETTINGS'te
}

# [SC]: Huffman + regular başlıkların indekslenmesi doğrulandı; kalanı varsayım.
_HPACK_SAFARI = dict(_HPACK_CHROMIUM, cookie_crumbs=None)

PROFILES = {

    # Chrome 131 (Windows). TLS: [CI][TC][KD]; h2: [CI][TC][SW].
    # Akamai h2: 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
    # JA4: t13d1516h2_8daaf6152771_02713d6af862 (16 extension: 0,5,10,11,13,16,
    # 18,23,27,35,43,45,51,17513,65037,65281 — PADDING YOK: gerçek Chrome PQ
    # key_share'i yüzünden ClientHello'su zaten >512 bayttır).
    # Chrome extension sırasını her bağlantıda karıştırır (GREASE uçları
    # sabit) -> JA3 her seferinde farklıdır, JA4 sabittir.
    "chrome_131": {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "cipher_suites": [
            "GREASE",
            0x1301, 0x1302, 0x1303,
            0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
            0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
        ],
        "extensions_order": [
            "GREASE", "sni", "extended_master_secret", "renegotiation_info",
            "supported_groups", "ec_point_formats", "session_ticket",
            "alpn", "status_request", "signature_algorithms",
            "signed_certificate_timestamp", "key_share",
            "psk_key_exchange_modes", "supported_versions",
            "compress_certificate", "alps", "ech_grease", "GREASE",
        ],
        "shuffle_extensions": True,
        # X25519MLKEM768 (0x11EC): cryptography ML-KEM sunuyorsa hem
        # supported_groups'ta hem key_share'te; yoksa ikisinden de çıkarılır.
        "supported_groups": ["GREASE", 0x11EC, 0x001D, 0x0017, 0x0018],
        "key_share_groups": ["GREASE", 0x11EC, 0x001D],
        "supported_versions": ["GREASE", 0x0304, 0x0303],
        "signature_algorithms": [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805,
            0x0501, 0x0806, 0x0601,
        ],
        "alpn": ["h2", "http/1.1"],
        "cert_compression": [0x0002],                # brotli
        "alps_protocols": ["h2"],
        "ech_grease": {"aead_ids": [0x0001, 0x0003], "payload_lens": [144, 176, 208, 240]},
        "h2": {
            # SETTINGS (id, değer) — gönderim sırası
            "settings": [(1, 65536), (2, 0), (4, 6291456), (6, 262144)],
            "window_update": 15663105,
            "priority_frames": [],                   # (stream, bağımlı, exclusive, ağırlık 1..256)
            "headers_priority": (0, True, 256),      # HEADERS PRIORITY: (bağımlı, exclusive, ağırlık)
            "pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
            # Gezinme (navigate) isteği başlık sırası [CI]; olmayanlar atlanır,
            # listede olmayanlar sona (orijinal sırayla) eklenir.
            "header_order": [
                "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
                "upgrade-insecure-requests", "user-agent", "accept",
                "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
                "sec-fetch-dest", "accept-encoding", "accept-language",
                "cookie", "priority",
            ],
            # HPACK kodlayıcı: Chromium/QUICHE [QH]
            "hpack": _HPACK_CHROMIUM,
        },
        # Varsayılan gezinme başlıkları [CI] curl_chrome131 betiği (başlık
        # değerleri) — Content-Length/Content-Type/Origin/Referer'in gerçek
        # Chrome'daki göreli yeri DOĞRULANMADI. Priority yalnızca h2'de.
        "http_headers": {
            "default": [
                ("sec-ch-ua", '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"'),
                ("sec-ch-ua-mobile", "?0"),
                ("sec-ch-ua-platform", '"Windows"'),
                ("Upgrade-Insecure-Requests", "1"),
                ("User-Agent", None),                # profilin user_agent'ı
                ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"
                           "image/avif,image/webp,image/apng,*/*;q=0.8,"
                           "application/signed-exchange;v=b3;q=0.7"),
                ("Sec-Fetch-Site", "none"),
                ("Sec-Fetch-Mode", "navigate"),
                ("Sec-Fetch-User", "?1"),
                ("Sec-Fetch-Dest", "document"),
                ("Accept-Encoding", None),           # kurulu kodlayıcılara göre
                ("Accept-Language", "en-US,en;q=0.9"),
                ("Priority", "u=0, i"),
            ],
            "accept_encoding": ["gzip", "deflate", "br", "zstd"],
            "h1_header_order": [
                "host", "connection", "content-length", "sec-ch-ua",
                "sec-ch-ua-mobile", "sec-ch-ua-platform",
                "upgrade-insecure-requests", "user-agent", "content-type",
                "accept", "origin", "sec-fetch-site", "sec-fetch-mode",
                "sec-fetch-user", "sec-fetch-dest", "referer",
                "accept-encoding", "accept-language", "cookie",
            ],
        },
    },

    # Firefox 133. TLS: [CC][CI][TC] (extension sırası/JA3 [CC]; sabit sıra,
    # karıştırma yok). h2 [CI][TC][SW]: PRIORITY frame'i YOK (modern Firefox).
    # Akamai h2: 1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s
    # JA4 beklenen: t13d1717h2_... (17 suite / 17 extension) — tam hash
    # doğrulanmadı. ZSTD (3) sertifika sıkıştırması ilan EDİLMEZ (açıcımız yok).
    "firefox_133": {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) "
            "Gecko/20100101 Firefox/133.0"
        ),
        "cipher_suites": [
            0x1301, 0x1303, 0x1302,
            0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C, 0xC030,
            0xC00A, 0xC009, 0xC013, 0xC014,
            0x009C, 0x009D, 0x002F, 0x0035,
        ],
        "extensions_order": [
            "sni", "extended_master_secret", "renegotiation_info",
            "supported_groups", "ec_point_formats", "session_ticket",
            "alpn", "status_request", "delegated_credentials",
            "signed_certificate_timestamp", "key_share", "supported_versions",
            "signature_algorithms", "psk_key_exchange_modes",
            "record_size_limit", "compress_certificate", "ech_grease",
        ],
        "supported_groups": [0x11EC, 0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101],
        "key_share_groups": [0x11EC, 0x001D, 0x0017],
        "supported_versions": [0x0304, 0x0303],
        "signature_algorithms": [
            0x0403, 0x0503, 0x0603,
            0x0804, 0x0805, 0x0806,
            0x0401, 0x0501, 0x0601,
            0x0203, 0x0201,
        ],
        "delegated_credentials": [0x0403, 0x0503, 0x0603, 0x0203],
        "record_size_limit": 0x4001,
        "alpn": ["h2", "http/1.1"],
        "cert_compression": [0x0001, 0x0002, 0x0003],   # zlib, brotli, zstd (ilan edilen = desteklenenle kesişim)
        "ech_grease": {"aead_ids": [0x0001, 0x0002, 0x0003], "payload_lens": [144, 239]},
        "h2": {
            "settings": [(1, 65536), (2, 0), (4, 131072), (5, 16384)],
            "window_update": 12517377,
            "priority_frames": [],
            "headers_priority": (0, False, 42),
            "pseudo_header_order": [":method", ":path", ":authority", ":scheme"],
            "header_order": [
                "user-agent", "accept", "accept-language", "accept-encoding",
                "upgrade-insecure-requests", "sec-fetch-dest", "sec-fetch-mode",
                "sec-fetch-site", "sec-fetch-user", "cookie", "priority", "te",
            ],
            # HPACK kodlayıcı: Firefox Http2Compression.cpp [FH]
            "hpack": _HPACK_FIREFOX,
        },
        # [CI] curl_firefox133 başlık değerleri (bellekten; Accept'teki
        # image/* listesi ve TE: trailers'ın h2'ye özgülüğü doğrulanmadı).
        # h1 sırası doğrulanmadı.
        "http_headers": {
            "default": [
                ("User-Agent", None),
                ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"
                           "image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8"),
                ("Accept-Language", "en-US,en;q=0.5"),
                ("Accept-Encoding", None),
                ("Upgrade-Insecure-Requests", "1"),
                ("Sec-Fetch-Dest", "document"),
                ("Sec-Fetch-Mode", "navigate"),
                ("Sec-Fetch-Site", "none"),
                ("Sec-Fetch-User", "?1"),
                ("Priority", "u=0, i"),
                ("TE", "trailers"),
            ],
            "accept_encoding": ["gzip", "deflate", "br", "zstd"],
            "h1_header_order": [
                "host", "user-agent", "accept", "accept-language",
                "accept-encoding", "content-type", "content-length", "origin",
                "referer", "cookie", "connection", "upgrade-insecure-requests",
                "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
                "sec-fetch-user",
            ],
        },
    },

    # Safari 18.0 (macOS). TLS: [TC] Safari_IOS_18_0 + [CI] curl_safari180
    # (macOS Safari 18.0 ile aynı TLS yığını varsayıldı — macOS yakalaması
    # doğrulanmadı). h2: [CI] curl_safari180.
    # Akamai h2: 2:0;3:100;4:2097152;8:1;9:1|10420225|0|m,s,a,p
    # ([SW] pseudo sırasını m,s,p,a yazıyor; iki ayrı kaynak [CI][TC] m,s,a,p
    # veriyor — onlar izlendi, ÇELİŞKİ doğrulanmadı.)
    # JA4 öneki t13d2014h2 [SW]: 20 suite / 14 extension (padding 21 dahil).
    "safari_18": {
        "user_agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/18.0 Safari/605.1.15"
        ),
        "cipher_suites": [
            "GREASE",
            0x1301, 0x1302, 0x1303,
            0xC02C, 0xC02B, 0xCCA9, 0xC030, 0xC02F, 0xCCA8,
            0xC00A, 0xC009, 0xC014, 0xC013,
            0x009D, 0x009C, 0x0035, 0x002F,
            0xC008, 0xC012, 0x000A,
        ],
        "extensions_order": [
            "GREASE", "sni", "extended_master_secret", "renegotiation_info",
            "supported_groups", "ec_point_formats", "alpn", "status_request",
            "signature_algorithms", "signed_certificate_timestamp",
            "key_share", "psk_key_exchange_modes", "supported_versions",
            "compress_certificate", "GREASE", "padding",
        ],
        "supported_groups": ["GREASE", 0x001D, 0x0017, 0x0018, 0x0019],
        "key_share_groups": ["GREASE", 0x001D],
        "supported_versions": ["GREASE", 0x0304, 0x0303, 0x0302, 0x0301],
        "signature_algorithms": [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0203,
            0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
        ],
        "alpn": ["h2", "http/1.1"],
        "cert_compression": [0x0001],                   # zlib
        "h2": {
            "settings": [(2, 0), (3, 100), (4, 2097152), (8, 1), (9, 1)],
            "window_update": 10420225,
            "priority_frames": [],
            "headers_priority": (0, False, 256),
            "pseudo_header_order": [":method", ":scheme", ":authority", ":path"],
            "header_order": [
                "sec-fetch-dest", "user-agent", "upgrade-insecure-requests",
                "accept", "sec-fetch-site", "sec-fetch-mode",
                "accept-language", "priority", "accept-encoding", "cookie",
            ],
            # HPACK kodlayıcı: Safari [SC] (kısmen doğrulandı)
            "hpack": _HPACK_SAFARI,
        },
        # [CI] curl_safari180 (bellekten). Safari UA'sı macOS sürümünü hep
        # 10_15_7 olarak dondurur. upgrade-insecure-requests'in sırası ve h1
        # sırası doğrulanmadı. Safari zstd İLAN ETMEZ.
        "http_headers": {
            "default": [
                ("Sec-Fetch-Dest", "document"),
                ("User-Agent", None),
                ("Upgrade-Insecure-Requests", "1"),
                ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                ("Sec-Fetch-Site", "none"),
                ("Sec-Fetch-Mode", "navigate"),
                ("Accept-Language", "en-US,en;q=0.9"),
                ("Priority", "u=0, i"),
                ("Accept-Encoding", None),
            ],
            "accept_encoding": ["gzip", "deflate", "br"],
            "h1_header_order": [
                "host", "sec-fetch-dest", "user-agent",
                "upgrade-insecure-requests", "accept", "content-type",
                "content-length", "origin", "sec-fetch-site",
                "sec-fetch-mode", "referer", "accept-language",
                "accept-encoding", "cookie", "connection",
            ],
        },
    },

    # Chrome 158 (Windows) — 2026-11-16 itibarıyla kararlı sürüm
    # (chromiumdash: 158.0.8127.37). TLS: [CR][BS][CAP]; h2: [CAP][CI2].
    # Chrome 131'e göre farklar: ALPS 17613 (yeni kod noktası), trust_anchors
    # (51764 = 0xca34, Trust Anchor IDs; PQ kripto DEĞİL), signature_algorithms
    # başında GREASE + ML-DSA-44/65/87. Akamai h2 Chrome 131 ile AYNI.
    # JA4: t13d1517h2_8daaf6152771_<c> (17 extension; c, ML-DSA'lı imza listesi
    # yüzünden değişir — testte sabitlenir).
    "chrome_158": {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/158.0.0.0 Safari/537.36"
        ),
        "cipher_suites": [
            "GREASE",
            0x1301, 0x1302, 0x1303,
            0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
            0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
        ],
        "extensions_order": [
            "GREASE", "sni", "extended_master_secret", "renegotiation_info",
            "supported_groups", "ec_point_formats", "session_ticket",
            "alpn", "status_request", "signature_algorithms",
            "signed_certificate_timestamp", "key_share",
            "psk_key_exchange_modes", "supported_versions",
            "compress_certificate", "alps", "trust_anchors", "ech_grease", "GREASE",
        ],
        "shuffle_extensions": True,
        "supported_groups": ["GREASE", 0x11EC, 0x001D, 0x0017, 0x0018],
        "key_share_groups": ["GREASE", 0x11EC, 0x001D],
        "supported_versions": ["GREASE", 0x0304, 0x0303],
        # [CR] kVerifyPrefs + [BS] ext_sigalgs_add_clienthello (başta GREASE).
        "signature_algorithms": [
            "GREASE", 0x0904, 0x0905, 0x0906,
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805,
            0x0501, 0x0806, 0x0601,
        ],
        "alpn": ["h2", "http/1.1"],
        "cert_compression": [0x0002],                # brotli
        "alps_protocols": ["h2"],
        "alps_codepoint": 17613,
        "trust_anchors": CHROME_TRUST_ANCHOR_IDS,
        "ech_grease": {"aead_ids": [0x0001, 0x0003], "payload_lens": [144, 176, 208, 240]},
        "h2": {
            "settings": [(1, 65536), (2, 0), (4, 6291456), (6, 262144)],
            "window_update": 15663105,
            "priority_frames": [],
            "headers_priority": (0, True, 256),
            "pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
            "header_order": [
                "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
                "upgrade-insecure-requests", "user-agent", "accept",
                "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
                "sec-fetch-dest", "accept-encoding", "accept-language",
                "cookie", "priority",
            ],
            # HPACK kodlayıcı: Chromium/QUICHE [QH]
            "hpack": _HPACK_CHROMIUM,
        },
        # [CAP] (Chrome 153 gezinme isteği, başlık sırası/değerleri) + sec-ch-ua
        # 158 için chrome_sec_ch_ua() ile hesaplandı.
        "http_headers": {
            "default": [
                ("sec-ch-ua", chrome_sec_ch_ua(158)),
                ("sec-ch-ua-mobile", "?0"),
                ("sec-ch-ua-platform", '"Windows"'),
                ("Upgrade-Insecure-Requests", "1"),
                ("User-Agent", None),
                ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"
                           "image/avif,image/webp,image/apng,*/*;q=0.8,"
                           "application/signed-exchange;v=b3;q=0.7"),
                ("Sec-Fetch-Site", "none"),
                ("Sec-Fetch-Mode", "navigate"),
                ("Sec-Fetch-User", "?1"),
                ("Sec-Fetch-Dest", "document"),
                ("Accept-Encoding", None),
                ("Accept-Language", "en-US,en;q=0.9"),
                ("Priority", "u=0, i"),
            ],
            "accept_encoding": ["gzip", "deflate", "br", "zstd"],
            "h1_header_order": [
                "host", "connection", "content-length", "sec-ch-ua",
                "sec-ch-ua-mobile", "sec-ch-ua-platform",
                "upgrade-insecure-requests", "user-agent", "content-type",
                "accept", "origin", "sec-fetch-site", "sec-fetch-mode",
                "sec-fetch-user", "sec-fetch-dest", "referer",
                "accept-encoding", "accept-language", "cookie",
            ],
        },
    },

    # Firefox 160 (Windows) — product-details LATEST_FIREFOX_VERSION=160.0
    # (2026-11-10). TLS: [FF][CI2]; h2: [CI2] firefox155 + [FF].
    # Firefox 133'e göre farklar: ECDSA-CBC suite'leri (0xC00A/0xC009) yok
    # (15 suite), ffdhe2048/3072 supported_groups'ta yok (DHE suite'leri kapalı),
    # ECH GREASE AEAD yalnızca 1/3. ML-DSA ilan EDİLMEZ (enable_mldsa=false).
    # Akamai h2: 1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s (değişmedi).
    "firefox_160": {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) "
            "Gecko/20100101 Firefox/160.0"
        ),
        "cipher_suites": [
            0x1301, 0x1303, 0x1302,
            0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C, 0xC030,
            0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
        ],
        "extensions_order": [
            "sni", "extended_master_secret", "renegotiation_info",
            "supported_groups", "ec_point_formats", "session_ticket",
            "alpn", "status_request", "delegated_credentials",
            "signed_certificate_timestamp", "key_share", "supported_versions",
            "signature_algorithms", "psk_key_exchange_modes",
            "record_size_limit", "compress_certificate", "ech_grease",
        ],
        "supported_groups": [0x11EC, 0x001D, 0x0017, 0x0018, 0x0019],
        "key_share_groups": [0x11EC, 0x001D, 0x0017],
        "supported_versions": [0x0304, 0x0303],
        "signature_algorithms": [
            0x0403, 0x0503, 0x0603,
            0x0804, 0x0805, 0x0806,
            0x0401, 0x0501, 0x0601,
            0x0203, 0x0201,
        ],
        "delegated_credentials": [0x0403, 0x0503, 0x0603, 0x0203],
        "record_size_limit": 0x4001,
        "alpn": ["h2", "http/1.1"],
        "cert_compression": [0x0001, 0x0002, 0x0003],
        # [FF] tls13ech.c: AEAD = 1 ya da 3; yük = 32'nin katına yuvarlanmış iç
        # CH (ad 100 bayta dolgulanır) + 16. 240 TAHMİNDİR (yakalama yok).
        "ech_grease": {"aead_ids": [0x0001, 0x0003], "payload_lens": [240]},
        "h2": {
            "settings": [(1, 65536), (2, 0), (4, 131072), (5, 16384)],
            "window_update": 12517377,
            "priority_frames": [],
            # Http2StreamBase::SetPriority: ağırlık = 21 - öncelik; belge = 42.
            "headers_priority": (0, False, 42),
            "pseudo_header_order": [":method", ":path", ":authority", ":scheme"],
            "header_order": [
                "user-agent", "accept", "accept-language", "accept-encoding",
                "upgrade-insecure-requests", "sec-fetch-dest", "sec-fetch-mode",
                "sec-fetch-site", "sec-fetch-user", "cookie", "priority", "te",
            ],
            # HPACK kodlayıcı: Firefox Http2Compression.cpp [FH]
            "hpack": _HPACK_FIREFOX,
        },
        # Accept: [FF] DocumentAcceptHeader (accept_include_images=false).
        # Accept-Language: en-US + en için Firefox q=0.5 üretir (PrepareAcceptLanguages).
        "http_headers": {
            "default": [
                ("User-Agent", None),
                ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                ("Accept-Language", "en-US,en;q=0.5"),
                ("Accept-Encoding", None),
                ("Upgrade-Insecure-Requests", "1"),
                ("Sec-Fetch-Dest", "document"),
                ("Sec-Fetch-Mode", "navigate"),
                ("Sec-Fetch-Site", "none"),
                ("Sec-Fetch-User", "?1"),
                ("Priority", "u=0, i"),
                ("TE", "trailers"),
            ],
            "accept_encoding": ["gzip", "deflate", "br", "zstd"],
            "h1_header_order": [
                "host", "user-agent", "accept", "accept-language",
                "accept-encoding", "content-type", "content-length", "origin",
                "referer", "cookie", "connection", "upgrade-insecure-requests",
                "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
                "sec-fetch-user",
            ],
        },
    },

    # Safari 27.2 (macOS) — [WK] güncel kararlı sürüm. TLS/h2: [CI2] safari270
    # (27.0) + safari_26.0.1_macOS gerçek yakalaması; 27.1/27.2 sürüm notlarında
    # ağ yığını değişikliği yok (UA dışında 27.0 ile aynı varsayıldı).
    # Safari 18'e göre farklar: X25519MLKEM768 (grup + key_share), TLS 1.3
    # suite sırası 1302,1303,1301, supported_versions yalnızca 1.3/1.2,
    # 0x0203 imzası yok; h2'de SETTINGS 8 (ENABLE_CONNECT_PROTOCOL) yok ve
    # HEADERS'ta PRIORITY bayrağı YOK; zstd ilan edilir; Upgrade-Insecure-
    # Requests gönderilmez.
    # Akamai h2: 2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p
    "safari_27": {
        "user_agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/27.2 Safari/605.1.15"
        ),
        "cipher_suites": [
            "GREASE",
            0x1302, 0x1303, 0x1301,
            0xC02C, 0xC02B, 0xCCA9, 0xC030, 0xC02F, 0xCCA8,
            0xC00A, 0xC009, 0xC014, 0xC013,
            0x009D, 0x009C, 0x0035, 0x002F,
            0xC008, 0xC012, 0x000A,
        ],
        "extensions_order": [
            "GREASE", "sni", "extended_master_secret", "renegotiation_info",
            "supported_groups", "ec_point_formats", "alpn", "status_request",
            "signature_algorithms", "signed_certificate_timestamp",
            "key_share", "psk_key_exchange_modes", "supported_versions",
            "compress_certificate", "GREASE", "padding",
        ],
        "supported_groups": ["GREASE", 0x11EC, 0x001D, 0x0017, 0x0018, 0x0019],
        "key_share_groups": ["GREASE", 0x11EC, 0x001D],
        "supported_versions": ["GREASE", 0x0304, 0x0303],
        "signature_algorithms": [
            0x0403, 0x0804, 0x0401, 0x0503,
            0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
        ],
        "alpn": ["h2", "http/1.1"],
        "cert_compression": [0x0001],                   # zlib
        "h2": {
            "settings": [(2, 0), (3, 100), (4, 2097152), (9, 1)],
            "window_update": 10420225,
            "priority_frames": [],
            "headers_priority": None,                   # PRIORITY bayrağı yok [CI2]
            "pseudo_header_order": [":method", ":scheme", ":authority", ":path"],
            "header_order": [
                "sec-fetch-dest", "user-agent", "accept", "referer",
                "sec-fetch-site", "sec-fetch-mode", "accept-language",
                "priority", "accept-encoding", "cookie",
            ],
            # HPACK kodlayıcı: Safari [SC] (kısmen doğrulandı)
            "hpack": _HPACK_SAFARI,
        },
        # [CI2] safari270 (sec-fetch-site doğrudan gezinme için "none":
        # safari_26.0.1 yakalamasıyla aynı).
        "http_headers": {
            "default": [
                ("Sec-Fetch-Dest", "document"),
                ("User-Agent", None),
                ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                ("Sec-Fetch-Site", "none"),
                ("Sec-Fetch-Mode", "navigate"),
                ("Accept-Language", "en-US,en;q=0.9"),
                ("Priority", "u=0, i"),
                ("Accept-Encoding", None),
            ],
            "accept_encoding": ["gzip", "deflate", "br", "zstd"],
            "h1_header_order": [
                "host", "sec-fetch-dest", "user-agent", "accept",
                "content-type", "content-length", "origin", "referer",
                "sec-fetch-site", "sec-fetch-mode", "accept-language",
                "priority", "accept-encoding", "cookie", "connection",
            ],
        },
    },

    # Tarayıcı taklidi yapmayan yalın profil: h2 değerleri ESKİ sabit
    # davranışla aynıdır (connection WINDOW_UPDATE yok, PRIORITY yok).
    # Parmak izi önemsizdir, UYUMLULUK önemlidir: TLS 1.2 sunucularla da
    # konuşabilsin diye TLS 1.2 AEAD suite'leri, EMS (RFC 7627),
    # renegotiation_info (RFC 5746), ec_point_formats, supported_versions'ta
    # 0x0303, session_ticket/status_request ve TLS 1.2 imza şemaları (RSA-PKCS1
    # dahil) ilan edilir.
    "default": {
        "user_agent": "fasthttpc/2.0",
        "cipher_suites": [
            0x1301, 0x1302, 0x1303,
            0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
        ],
        "extensions_order": [
            "sni", "extended_master_secret", "renegotiation_info",
            "supported_groups", "ec_point_formats", "session_ticket", "alpn",
            "status_request", "signature_algorithms", "supported_versions",
            "key_share",
        ],
        "supported_groups": [0x001D, 0x0017, 0x0018],
        "supported_versions": [0x0304, 0x0303],
        "signature_algorithms": [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ],
        "alpn": ["http/1.1"],
        "h2": {
            "settings": [(1, 65536), (2, 0), (4, 65535), (6, 262144)],
            "window_update": None,
            "priority_frames": [],
            "headers_priority": None,
            "pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
            "header_order": [],
            # HPACK: tarayıcı taklidi yok; Chromium politikası (Huffman + dinamik tablo)
            "hpack": _HPACK_CHROMIUM,
        },
        # Tarayıcı taklidi yok: yalnızca gerekli/zararsız başlıklar (sıra serbest).
        "http_headers": {
            "default": [
                ("User-Agent", None),
                ("Accept", "*/*"),
                ("Accept-Encoding", None),
            ],
            "accept_encoding": ["gzip", "deflate", "br", "zstd"],
            "h1_header_order": [],
        },
    },
}


# Eski/yaygın yazımlar için takma adlar. Yeni isim eklerken buraya da ekle.
PROFILE_ALIASES = {
    "chrome": "chrome_158",
    "chrome_131": "chrome_131",
    "firefox": "firefox_160",
    "firefox_120": "firefox_133",
    "safari": "safari_27",
    "safari_17": "safari_18",
    "safari_27_2": "safari_27",
}


def available_profiles() -> list[str]:
    """Kullanılabilir profil adlarını döner."""
    return sorted(PROFILES.keys())


def get_profile(name: str | None) -> dict:
    """Profil sözlüğünü döner.

    Bilinmeyen bir ad verilirse SESSİZCE ``default``'a DÜŞMEZ, ValueError
    fırlatır. Sessiz düşüş, kullanıcının Chrome taklit ettiğini sanarken
    ``User-Agent: fasthttpc`` göndermesine yol açıyordu — yani kütüphanenin
    tek işini yapmadığını gizliyordu.
    """
    if name is None:
        profile = dict(PROFILES["default"])
        profile["_name"] = "default"
        return profile

    canonical = PROFILE_ALIASES.get(name, name)
    if canonical not in PROFILES:
        raise ValueError(
            f"Bilinmeyen TLS profili: {name!r}. "
            f"Kullanılabilir profiller: {', '.join(available_profiles())}. "
            f"Takma adlar: {', '.join(sorted(PROFILE_ALIASES))}."
        )
    profile = dict(PROFILES[canonical])
    profile["_name"] = canonical
    return profile


def ja3_hash(profile_name: str | None = None, resolved_grease: int | None = None) -> str:
    """
    Verilen profil için JA3 hash'i hesaplar.
    JA3 = MD5( TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats )
    """
    profile = get_profile(profile_name)
    grease  = resolved_grease if resolved_grease is not None else 0x0A0A

    tls_version = 771                       

    ciphers = [
        str(c) for c in profile["cipher_suites"]
        if c != "GREASE" and c not in _GREASE_VALUES
    ]

    _ext_ids = {
        "sni": 0, "extended_master_secret": 23, "renegotiation_info": 65281,
        "supported_groups": 10, "ec_point_formats": 11, "session_ticket": 35,
        "alpn": 16, "status_request": 5, "signature_algorithms": 13,
        "signed_certificate_timestamp": 18, "key_share": 51,
        "psk_key_exchange_modes": 45, "supported_versions": 43,
        "compress_certificate": 27, "padding": 21,
        "delegated_credentials": 34, "record_size_limit": 28,
        "alps": profile.get("alps_codepoint", 17513), "ech_grease": 65037,
        "trust_anchors": 0xCA34,
        "GREASE": grease,
    }
    exts = [
        str(_ext_ids[e]) for e in profile["extensions_order"]
        if e in _ext_ids and _ext_ids[e] not in _GREASE_VALUES
    ]

    groups = [
        str(g) for g in profile["supported_groups"]
        if g != "GREASE" and g not in _GREASE_VALUES
    ]

    point_formats = ["0"]

    ja3_str = ",".join([
        str(tls_version),
        "-".join(ciphers),
        "-".join(exts),
        "-".join(groups),
        "-".join(point_formats),
    ])

    return hashlib.md5(ja3_str.encode()).hexdigest()


                                                                                
                                                                                
                                                                                

def ja3_string_from_client_hello(client_hello: bytes) -> str:
    """Telde GERÇEKTEN gönderilen ClientHello byte'larından JA3 string'i üretir.

    Profil sözlüğünden hesaplamak yanıltıcıdır: kod ile profil arasındaki
    herhangi bir tutarsızlık (filtreleme, sıralama, eksik extension) fark
    edilmez ve fonksiyon size olmayan bir parmak izini rapor eder. Doğrulama
    fonksiyonunun tek işi budur, o yüzden gerçek byte'ları parse ediyoruz.

    Args:
        client_hello: TLS record header'ı DAHİL ham ClientHello.
    """
    if len(client_hello) < 5 or client_hello[0] != 0x16:
        raise ValueError("Geçerli bir TLS handshake record'u değil.")

    body = client_hello[5 + 4:]  # record header + handshake header atlanır
    pos = 2 + 32                 # client_version + random
    sid_len = body[pos]
    pos += 1 + sid_len

    cs_len = struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 2
    ciphers = [
        struct.unpack("!H", body[pos + i:pos + i + 2])[0]
        for i in range(0, cs_len, 2)
    ]
    pos += cs_len

    comp_len = body[pos]
    pos += 1 + comp_len

    ext_total = struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 2
    ext_end = pos + ext_total

    ext_ids: list[int] = []
    groups: list[int] = []
    point_formats: list[int] = []

    while pos + 4 <= ext_end:
        ext_type, ext_len = struct.unpack("!HH", body[pos:pos + 4])
        pos += 4
        payload = body[pos:pos + ext_len]
        pos += ext_len
        ext_ids.append(ext_type)

        if ext_type == 0x000A and len(payload) >= 2:      # supported_groups
            glen = struct.unpack("!H", payload[0:2])[0]
            groups = [
                struct.unpack("!H", payload[2 + i:4 + i])[0]
                for i in range(0, glen, 2)
            ]
        elif ext_type == 0x000B and len(payload) >= 1:    # ec_point_formats
            plen = payload[0]
            point_formats = list(payload[1:1 + plen])

    def _strip(values):
        return [str(v) for v in values if v not in _GREASE_VALUES]

    return ",".join([
        "771",
        "-".join(_strip(ciphers)),
        "-".join(_strip(ext_ids)),
        "-".join(_strip(groups)),
        "-".join(str(p) for p in point_formats),
    ])


def ja3_from_client_hello(client_hello: bytes) -> str:
    """Gerçek ClientHello byte'larından JA3 MD5 hash'i."""
    return hashlib.md5(ja3_string_from_client_hello(client_hello).encode()).hexdigest()


def ja3_for_profile(profile_name: str | None = None) -> tuple[str, str]:
    """Profili gerçekten derleyip (JA3 string, JA3 hash) döner.

    ``ja3_hash()`` gibi profil sözlüğünü okumaz — ClientHello'yu inşa edip
    çıkan byte'ları parse eder, yani sunucunun göreceği değeri raporlar.
    """
    from .tls_crafter import TLSImpersonator

    ch, _, _ = TLSImpersonator("example.com", profile=profile_name).build_client_hello()
    ja3_str = ja3_string_from_client_hello(ch)
    return ja3_str, hashlib.md5(ja3_str.encode()).hexdigest()


def ja3n_hash(profile_name: str | None = None, resolved_grease: int | None = None) -> str:
    """JA3 varyantı: GREASE değerleri de dahil edilerek hesaplanır.

    UYARI — isimlendirme: literatürdeki "JA3N", extension listesinin
    SIRALANDIĞI (normalize edildiği) varyanttır; GREASE dahil eden bir
    varyant değildir. Bu fonksiyon adını geriye dönük uyumluluk için
    koruyor ama yaptığı iş farklıdır. Gerçek parmak izi için
    ``ja3_from_client_hello()`` kullanın.
    """
    profile = get_profile(profile_name)
    grease  = resolved_grease if resolved_grease is not None else 0x0A0A

    tls_version = 771

                                                            
    ciphers = []
    for c in profile["cipher_suites"]:
        if c == "GREASE":
            ciphers.append(str(grease))
        elif isinstance(c, int):
            ciphers.append(str(c))

    _ext_ids = {
        "sni": 0, "extended_master_secret": 23, "renegotiation_info": 65281,
        "supported_groups": 10, "ec_point_formats": 11, "session_ticket": 35,
        "alpn": 16, "status_request": 5, "signature_algorithms": 13,
        "signed_certificate_timestamp": 18, "key_share": 51,
        "psk_key_exchange_modes": 45, "supported_versions": 43,
        "compress_certificate": 27, "padding": 21,
        "delegated_credentials": 34, "record_size_limit": 28,
        "alps": profile.get("alps_codepoint", 17513), "ech_grease": 65037,
        "trust_anchors": 0xCA34,
        "GREASE": grease,
    }
                                    
    exts = [str(_ext_ids[e]) for e in profile["extensions_order"] if e in _ext_ids]

                              
    groups = []
    for g in profile["supported_groups"]:
        if g == "GREASE":
            groups.append(str(grease))
        elif isinstance(g, int):
            groups.append(str(g))

    point_formats = ["0"]

    ja3n_str = ",".join([
        str(tls_version),
        "-".join(ciphers),
        "-".join(exts),
        "-".join(groups),
        "-".join(point_formats),
    ])

    return hashlib.md5(ja3n_str.encode()).hexdigest()


# ---------------------------------------------------------------------------
# HTTP/2 (Akamai) parmak izi ve JA4 yardımcıları
# ---------------------------------------------------------------------------

def h2_config(profile_name: str | None) -> dict:
    """Profilin HTTP/2 parmak izi sözlüğünü döner (profil yoksa ``default``)."""
    return get_profile(profile_name)["h2"]


def akamai_h2_string(profile_name: str | None) -> str:
    """Profilin Akamai HTTP/2 parmak izi dizesi (tls.peet.ws'in akamai_fingerprint'i).

    Biçim: ``SETTINGS(id:değer;...)|WINDOW_UPDATE|PRIORITY frame'leri|pseudo sırası``.
    PRIORITY frame yoksa ``0``. Frame biçimi ``stream:bağımlı(exclusive ise 1):…``
    değil, Akamai'nin ``stream:exclusive:bağımlı:ağırlık`` biçimidir.
    """
    h2 = h2_config(profile_name)
    settings = ";".join(f"{i}:{v}" for i, v in h2["settings"])
    wu = h2["window_update"] or 0
    prios = ",".join(
        f"{sid}:{1 if excl else 0}:{dep}:{weight}"
        for sid, dep, excl, weight in h2["priority_frames"]
    ) or "0"
    pseudo = ",".join(p[1] for p in h2["pseudo_header_order"])
    return f"{settings}|{wu}|{prios}|{pseudo}"


def akamai_h2_hash(profile_name: str | None) -> str:
    return hashlib.md5(akamai_h2_string(profile_name).encode()).hexdigest()


def _parse_client_hello_fields(client_hello: bytes) -> tuple[list[int], list[tuple[int, bytes]]]:
    """(cipher_suites, [(ext_type, payload), ...]) — record başlığı DAHİL ham CH."""
    if len(client_hello) < 9 or client_hello[0] != 0x16:
        raise ValueError("Geçerli bir TLS handshake record'u değil.")
    body = client_hello[9:]
    pos = 34
    pos += 1 + body[pos]
    cs_len = struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 2
    ciphers = [struct.unpack("!H", body[pos + i:pos + i + 2])[0] for i in range(0, cs_len, 2)]
    pos += cs_len
    pos += 1 + body[pos]
    total = struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 2
    end = pos + total
    exts = []
    while pos + 4 <= end:
        t, ln = struct.unpack("!HH", body[pos:pos + 4])
        pos += 4
        exts.append((t, body[pos:pos + ln]))
        pos += ln
    return ciphers, exts


def extension_ids_from_client_hello(client_hello: bytes) -> list[int]:
    """Telde GERÇEKTEN gönderilen extension tip listesi (GREASE dahil, sıralı)."""
    return [t for t, _ in _parse_client_hello_fields(client_hello)[1]]


def ja4_from_client_hello(client_hello: bytes, alpn_first: str | None = None) -> str:
    """Ham ClientHello'dan JA4 (FoxIO) dizesi: ``t13d1516h2_<suite hash>_<ext hash>``.

    Yalnızca TCP/TLS (``t``) üretir. ``alpn_first`` verilmezse ALPN extension'ının
    ilk değeri kullanılır.
    """
    ciphers, exts = _parse_client_hello_fields(client_hello)
    ciphers = [c for c in ciphers if c not in _GREASE_VALUES]
    ext_types = [t for t, _ in exts if t not in _GREASE_VALUES]
    payloads = {t: p for t, p in exts}

    version = "00"
    sv = payloads.get(43)
    if sv:
        vers = [struct.unpack("!H", sv[1 + i:3 + i])[0] for i in range(0, sv[0], 2)]
        vers = [v for v in vers if v not in _GREASE_VALUES]
        names = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10"}
        if vers:
            version = names.get(max(vers), "00")
    sni = "d" if 0 in ext_types else "i"

    alpn = "00"
    ap = payloads.get(16)
    if ap and len(ap) >= 4:
        first = ap[3:3 + ap[2]].decode("latin-1")
        alpn = (first[0] + first[-1]) if first else "00"

    a = f"t{version}{sni}{len(ciphers):02d}{min(len(ext_types), 99):02d}{alpn}"
    b = hashlib.sha256(",".join(f"{c:04x}" for c in sorted(ciphers)).encode()).hexdigest()[:12]

    ext_part = ",".join(f"{t:04x}" for t in sorted(ext_types) if t not in (0, 16))
    sa = payloads.get(13)
    sig = ""
    if sa:
        n = struct.unpack("!H", sa[:2])[0]
        # JA4: GREASE "her yerde" yok sayılır (FoxIO JA4.md) — imza listesi dahil.
        algs = [struct.unpack("!H", sa[2 + i:4 + i])[0] for i in range(0, n, 2)]
        sig = ",".join(f"{a:04x}" for a in algs if a not in _GREASE_VALUES)
    c_src = ext_part + ("_" + sig if sig else "")
    c = hashlib.sha256(c_src.encode()).hexdigest()[:12]
    return f"{a}_{b}_{c}"


def ja4_for_profile(profile_name: str | None = None) -> str:
    """Profili gerçekten derleyip (ClientHello byte'ları) JA4 döner."""
    from .tls_crafter import TLSImpersonator

    ch, _, _ = TLSImpersonator("example.com", profile=profile_name).build_client_hello()
    return ja4_from_client_hello(ch)



# ---------------------------------------------------------------------------
# Profil başına varsayılan HTTP başlıkları
# ---------------------------------------------------------------------------

# h2'ye özgü: h1'de gerçek tarayıcılar göndermez (değer profil varsayılanıyla
# aynıysa h1 serileştirmesinde atılır).
H1_DROPPED_DEFAULTS = ("priority", "te")


def accept_encoding_for(profile_name: str | None) -> str:
    """Profilin Accept-Encoding değeri: yalnızca AÇABİLDİĞİMİZ kodlamalar.

    br yalnızca brotli, zstd yalnızca zstandard kuruluysa; aksi halde sunucu
    açamayacağımız bir gövde yollardı.
    """
    from .protocol.http1_parser import _BROTLI, _ZSTD
    available = {"gzip": True, "deflate": True, "br": _BROTLI, "zstd": _ZSTD}
    spec = get_profile(profile_name)["http_headers"]["accept_encoding"]
    return ", ".join(e for e in spec if available.get(e))


def default_headers(profile_name: str | None) -> list[tuple[str, str]]:
    """Profilin varsayılan (navigasyon) başlıkları, profil sırasında.

    Adlar h1 yazımındadır (h2'de küçük harfe çevrilir).
    """
    profile = get_profile(profile_name)
    out = []
    for name, value in profile["http_headers"]["default"]:
        if name == "User-Agent":
            value = profile["user_agent"]
        elif name == "Accept-Encoding":
            value = accept_encoding_for(profile_name)
        out.append((name, value))
    return out


def merge_default_headers(profile_name: str | None, headers) -> list[tuple[str, str]]:
    """Varsayılanlar < ``headers`` (kullanıcı başlıkları geçersiz kılar).

    ``headers`` bir ``Headers``/dict/(k, v) listesi olabilir; değeri ``None``
    olan başlık varsayılanı da kaldırır (requests'teki gibi). Kullanıcı
    başlığı varsayılanla aynı adsa kullanıcının yazımı ve değeri kullanılır.
    Sıralama burada yapılmaz (h2: ``h2_request_headers``, h1: ``order_h1``).
    """
    items = list(headers.items()) if hasattr(headers, "items") else list(headers or [])
    user = {k.lower(): v for k, v in items}
    out = [(k, v) for k, v in default_headers(profile_name) if k.lower() not in user]
    out.extend((k, v) for k, v in items if v is not None)
    return out


def order_h1(profile_name: str | None, pairs: "list[tuple[str, str]]") -> "list[tuple[str, str]]":
    """HTTP/1.1 başlıklarını profilin ``h1_header_order``'ına göre dizer
    (listede olmayanlar orijinal göreli sırayla sona)."""
    order = get_profile(profile_name)["http_headers"]["h1_header_order"]
    if not order:
        return list(pairs)
    rank = {n: i for i, n in enumerate(order)}
    keyed = sorted(enumerate(pairs),
                   key=lambda t: (rank.get(t[1][0].lower(), len(rank)), t[0]))
    return [kv for _, kv in keyed]


def drop_h2_only_defaults(profile_name: str | None,
                          pairs: "list[tuple[str, str]]") -> "list[tuple[str, str]]":
    """h1 için: değeri profil varsayılanı olan priority/te başlıklarını at."""
    defaults = {k.lower(): v for k, v in default_headers(profile_name)}
    return [(k, v) for k, v in pairs
            if not (k.lower() in H1_DROPPED_DEFAULTS and defaults.get(k.lower()) == v)]
