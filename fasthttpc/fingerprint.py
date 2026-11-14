                          
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
# ---------------------------------------------------------------------------

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
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) "
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
                "sec-fetch-dest", "user-agent", "accept", "sec-fetch-site",
                "sec-fetch-mode", "accept-language", "priority",
                "accept-encoding", "cookie",
            ],
        },
    },

    # Tarayıcı taklidi yapmayan yalın profil: h2 değerleri ESKİ sabit
    # davranışla aynıdır (connection WINDOW_UPDATE yok, PRIORITY yok).
    "default": {
        "user_agent": "fasthttpc/2.0",
        "cipher_suites": [0x1301, 0x1302, 0x1303],
        "extensions_order": [
            "sni", "alpn", "supported_groups",
            "signature_algorithms", "supported_versions", "key_share",
        ],
        "supported_groups": [0x001D, 0x0017],
        "signature_algorithms": [0x0403, 0x0804],
        "alpn": ["http/1.1"],
        "h2": {
            "settings": [(1, 65536), (2, 0), (4, 65535), (6, 262144)],
            "window_update": None,
            "priority_frames": [],
            "headers_priority": None,
            "pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
            "header_order": [],
        },
    },
}


# Eski/yaygın yazımlar için takma adlar. Yeni isim eklerken buraya da ekle.
PROFILE_ALIASES = {
    "chrome": "chrome_131",
    "chrome_131": "chrome_131",
    "firefox": "firefox_133",
    "firefox_120": "firefox_133",
    "safari": "safari_18",
    "safari_17": "safari_18",
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
        "alps": 17513, "ech_grease": 65037,
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
        "alps": 17513, "ech_grease": 65037,
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
        sig = ",".join(f"{struct.unpack('!H', sa[2 + i:4 + i])[0]:04x}" for i in range(0, n, 2))
    c_src = ext_part + ("_" + sig if sig else "")
    c = hashlib.sha256(c_src.encode()).hexdigest()[:12]
    return f"{a}_{b}_{c}"


def ja4_for_profile(profile_name: str | None = None) -> str:
    """Profili gerçekten derleyip (ClientHello byte'ları) JA4 döner."""
    from .tls_crafter import TLSImpersonator

    ch, _, _ = TLSImpersonator("example.com", profile=profile_name).build_client_hello()
    return ja4_from_client_hello(ch)
