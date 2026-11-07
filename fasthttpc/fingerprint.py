                          
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


                                                                                
                                                                                 
                                                                                

PROFILES = {

                                                                              
    "chrome_131": {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "cipher_suites": [
            "GREASE",
            0x1301,                           
            0x1302,                           
            0x1303,                                 
            0xC02B,                                            
            0xC02F,                                          
            0xC02C,                                            
            0xC030,                                          
            0xCCA9,                                                  
            0xCCA8,                                                
            0xC013,                                       
            0xC014,                                       
            0x009C,                                    
            0x009D,                                    
            0x002F,                                 
            0x0035,                                 
        ],
        "extensions_order": [
            "GREASE", "sni", "extended_master_secret", "renegotiation_info",
            "supported_groups", "ec_point_formats", "session_ticket",
            "alpn", "status_request", "signature_algorithms",
            "signed_certificate_timestamp", "key_share",
            "psk_key_exchange_modes", "supported_versions",
            "compress_certificate", "GREASE", "padding",
        ],
        "supported_groups": [
            "GREASE", 0x001D, 0x0017, 0x0018,
        ],
        "signature_algorithms": [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805,
            0x0501, 0x0806, 0x0601,
        ],
        "alpn": ["h2", "http/1.1"],
    },

                                                                              
                                                          
    "firefox_133": {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) "
            "Gecko/20100101 Firefox/133.0"
        ),
        "cipher_suites": [
            0x1301,                           
            0x1302,                           
            0x1303,                                 
            0xC02B,                                            
            0xC02F,                                          
            0xC02C,                                            
            0xC030,                                          
            0xCCA9,                                                  
            0xCCA8,                                                
            0xC013,                                       
            0xC014,                                       
            0x002F,                                 
            0x0035,                                 
        ],
        "extensions_order": [
            "sni", "extended_master_secret", "renegotiation_info",
            "supported_groups", "ec_point_formats", "session_ticket",
            "alpn", "status_request", "delegated_credentials",
            "signature_algorithms", "record_size_limit",
            "supported_versions", "psk_key_exchange_modes",
            "key_share", "compress_certificate",
        ],
        "supported_groups": [0x001D, 0x0017, 0x0018, 0x0019],
        # Gerçek Firefox x25519 + secp256r1 için iki key_share gönderir.
        "key_share_groups": [0x001D, 0x0017],
        "signature_algorithms": [
            0x0403, 0x0503, 0x0603,
            0x0804, 0x0805, 0x0806,
            0x0401, 0x0501, 0x0601,
        ],
        "alpn": ["h2", "http/1.1"],
    },

                                                                              
                                              
    "safari_18": {
        "user_agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/18.0 Safari/605.1.15"
        ),
        "cipher_suites": [
            "GREASE",
            0x1301,                           
            0x1302,                           
            0x1303,                                 
            0xC02B,                                            
            0xC02F,                                          
            0xC02C,                                            
            0xC030,                                          
            0xCCA9,                                                  
            0xCCA8,                                                
            0xC009,                                         
            0xC013,                                       
            0xC00A,                                         
            0xC014,                                       
            0x009C,                                    
            0x009D,                                    
            0x002F,                                 
            0x0035,                                 
            0x000A,                                  
        ],
        "extensions_order": [
            "GREASE", "sni", "extended_master_secret", "renegotiation_info",
            "supported_groups", "ec_point_formats",
            "alpn", "status_request",
            "signature_algorithms", "supported_versions",
            "psk_key_exchange_modes", "key_share", "GREASE",
        ],
        "supported_groups": [
            "GREASE", 0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101,
        ],
        "signature_algorithms": [
            0x0403, 0x0503, 0x0603,
            0x0804, 0x0805, 0x0806,
            0x0401, 0x0501, 0x0601,
            0x0302, 0x0303,
        ],
        "alpn": ["h2", "http/1.1"],
    },

                                                                              
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
