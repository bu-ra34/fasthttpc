import struct
import os
import threading
from .fingerprint import get_profile, _random_grease
import random as _random_mod
from .security.keyshare import (
    KeyShareSet, SUPPORTED_GROUPS, GROUP_X25519, group_name,
)

# ALPS (application_settings) eski kod noktası — Chrome 131 bunu kullanır
# (17613'e geçiş Chrome 133'te). RFC taslağı: draft-vvv-tls-alps.
# Profil ``alps_codepoint`` ile seçer (chrome_158: EXT_ALPS_NEW).
EXT_ALPS = 17513
EXT_ALPS_NEW = 17613     # BoringSSL TLSEXT_TYPE_application_settings
EXT_ECH = 65037          # encrypted_client_hello (yalnızca GREASE gönderiyoruz)
# Trust Anchor IDs (draft-ietf-tls-trust-anchor-ids): BoringSSL'in geçici kod
# noktası TLSEXT_TYPE_trust_anchors = 0xca34 (51764). Kripto gerektirmez; yalnızca
# sunucunun sertifika seçimine ipucudur — sertifika doğrulaması DEĞİŞMEZ.
EXT_TRUST_ANCHORS = 0xCA34
_SYS_RANDOM = _random_mod.SystemRandom()

# Chrome trust anchor ID sırasını süreç başına sabitler (farklı süreçlerde farklı
# sıra gözlendi); burada da süreç başına bir kez karıştırılır.
_TAI_ORDER: dict[int, list[bytes]] = {}


def _process_tai_order(ids: list[bytes]) -> list[bytes]:
    key = id(ids)
    order = _TAI_ORDER.get(key)
    if order is None:
        order = list(ids)
        _SYS_RANDOM.shuffle(order)
        # setdefault atomik: iki iş parçacığı aynı anda karıştırsa da süreçte TEK sıra kalır.
        order = _TAI_ORDER.setdefault(key, order)
    return order


def encrypted_extensions_types(hs_payload: bytes) -> list[int]:
    """EncryptedExtensions (4 byte handshake başlığı DAHİL) içindeki extension tipleri."""
    types: list[int] = []
    try:
        total = struct.unpack("!H", hs_payload[4:6])[0]
        cur, end = 6, min(6 + total, len(hs_payload))
        while cur + 4 <= end:
            t, ln = struct.unpack("!HH", hs_payload[cur:cur + 4])
            types.append(t)
            cur += 4 + ln
    except (struct.error, IndexError):
        pass
    return types


def build_client_encrypted_extensions(settings: bytes = b"", codepoint: int = EXT_ALPS) -> bytes:
    """İstemcinin EncryptedExtensions mesajı (hs_type=8) — yalnızca ALPS içerir.

    Sunucu EncryptedExtensions'ında application_settings döndürdüyse (ALPS
    kabul), istemci Finished'tan ÖNCE kendi ALPS'ini bu mesajla yollamak
    ZORUNDADIR (BoringSSL sunucuları bunu bekler). ``settings`` boş: Chrome
    h2 için istemci tarafı ayarı taşımaz.
    """
    ext = struct.pack("!HH", codepoint, len(settings)) + settings
    body = struct.pack("!H", len(ext)) + ext
    return b"\x08" + struct.pack("!I", len(body))[1:] + body


def alps_accepted(profile_alps: bool, ee_payload: bytes, alpn: str,
                  codepoint: int = EXT_ALPS) -> bool:
    """Sunucu ALPS'i (ilan ettiğimiz kod noktasıyla) kabul ettiyse ve ALPN h2 ise True."""
    return bool(profile_alps and alpn == "h2" and codepoint in encrypted_extensions_types(ee_payload))


def _supported_cert_compression() -> list[int]:
    """Açabildiğimiz sertifika sıkıştırma algoritmaları (zlib=1 her zaman, brotli=2 /
    zstd=3 ilgili paket kuruluysa)."""
    algs = [0x0001]
    try:
        import brotli  # noqa: F401
        algs.append(0x0002)
    except ImportError:
        pass
    try:
        import zstandard  # noqa: F401
        algs.append(0x0003)
    except ImportError:
        pass
    return algs

                                     
                             
_ticket_cache: dict[str, bytes] = {}
_ticket_lock = threading.Lock()

def _get_ticket(host: str) -> bytes:
    with _ticket_lock:
        return _ticket_cache.get(host, b"")

def _store_ticket(host: str, ticket: bytes) -> None:
    with _ticket_lock:
        _ticket_cache[host] = ticket

def clear_ticket_cache() -> None:
    """Tüm session ticket'larını temizle (test veya logout için)."""
    with _ticket_lock:
        _ticket_cache.clear()


# Yalnızca gerçekten uygulayabiliyorsak ilan edebileceğimiz (PQ/hibrit) gruplar:
# desteklenmiyorsa supported_groups'ta ilan edilirse sunucu HRR ile bunu ister
# ve handshake kırılır (bkz. keyshare.HAVE_MLKEM).
_NEEDS_SUPPORT = frozenset({0x11EC, 0x6399})

# ML-DSA imza şemaları (0x0904..0x0906) yalnızca CertificateVerify'ı gerçekten
# doğrulayabiliyorsak (cryptography >= 48 ML-DSA) ilan edilir; aksi halde
# profilden SESSİZCE düşer (parmak izi sapması docs/limits.md'de).
_MLDSA_SCHEMES = frozenset({0x0904, 0x0905, 0x0906})
try:
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa  # noqa: F401
    HAVE_MLDSA = True
except ImportError:  # pragma: no cover - eski cryptography
    HAVE_MLDSA = False


class TLSImpersonator:
    def __init__(self, target_host, profile=None, legacy_tls=False):
        # Eski sunucu uyumluluk modu: ClientHello'ya eski suite'ler/SHA-1 sigalg/EtM eklenir
        # (yalnızca True iken; False iken ClientHello bayt bayt aynıdır). Bkz. security/tls12_legacy.py.
        from .security.tls12_legacy import normalize_legacy
        self.legacy_tls = normalize_legacy(legacy_tls)
        self.target_host = target_host.encode("utf-8")
        self.host_str = target_host
        self.profile = get_profile(profile)
        self._grease_cipher = _random_grease()
        self._grease_group = _random_grease()
        self._grease_version = _random_grease()
        self._grease_sigalg = _random_grease()      # BoringSSL ssl_grease_signature_algorithm
        self._used_grease_exts = set()
        # GREASE extension tipleri bağlantı başına bir kez seçilir ve HRR
        # sonrası 2. ClientHello'da AYNEN tekrarlanır (RFC 8446 §4.1.2: CH2,
        # key_share/cookie/early_data/pre_shared_key/padding dışında CH1 ile
        # aynı olmalıdır).
        self._grease_ext_values: list[int] = []
        self._grease_ext_idx = 0
        self._key_share_grease = False
        self._ext_order: list[str] | None = None     # bağlantı başına sabitlenen (karıştırılmış) sıra
        self.key_shares = KeyShareSet(self._key_share_groups())
        self._cookie: bytes | None = None
        self._is_retry = False
        self._client_random: bytes | None = None
        self._session_id: bytes | None = None
        self.last_client_hello: bytes = b""

    def _key_share_groups(self) -> list[int]:
        """Profilin key_share olarak göndermek istediği gruplardan GERÇEKTEN
        desteklenenleri döner.

        Karar (bkz. NOTES/README): desteklemediğimiz bir grup (ör. hibrit
        X25519MLKEM768) için key_share GÖNDERİLMEZ — sahte/boş bir anahtar
        göndermek sunucunun o grubu seçip handshake'i kırmasına yol açar.
        supported_groups listesi parmak izi için olduğu gibi korunur; sunucu
        HRR ile desteklenmeyen bir grup isterse negotiate() net hata verir.
        """
        wanted = self.profile.get("key_share_groups", [GROUP_X25519])
        self._key_share_grease = "GREASE" in wanted
        groups = [g for g in wanted if isinstance(g, int) and g in SUPPORTED_GROUPS]
        if not groups:
            groups = [GROUP_X25519]
        return groups

    @property
    def private_key(self):
        """Geriye dönük uyumluluk: x25519 özel anahtarının ham 32 byte'ı (yoksa None)."""
        if GROUP_X25519 not in self.key_shares.groups:
            return None
        from cryptography.hazmat.primitives import serialization
        return self.key_shares.private(GROUP_X25519).private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    @property
    def public_key(self):
        if GROUP_X25519 not in self.key_shares.groups:
            return None
        return self.key_shares.public(GROUP_X25519)

    def advertised_groups(self) -> list[int]:
        """supported_groups uzantısında ilan edilen gruplar (GREASE hariç)."""
        return [g for g in self.profile.get("supported_groups", []) if isinstance(g, int)]

    # GREASE değerleri (RFC 8701). Profillerde "GREASE" placeholder'ı olarak
    # geçer ve her bağlantıda rastgele bir değerle doldurulur.
    _GREASE_SET = frozenset({
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    })
    _TLS13_SUITES = frozenset({0x1301, 0x1302, 0x1303})

    def _cipher_suite_list(self) -> list[int]:
        """Profildeki cipher suite listesini olduğu gibi üretir.

        ÖNEMLİ: Buradan TLS 1.2 suite'lerini ELEMEK, JA3'ü tanınmaz hâle getirir.
        Gerçek Chrome, TLS 1.3 kullanacak olsa bile listede 0xC02B, 0xC02F,
        0xCCA9 gibi suite'leri REKLAM EDER. supported_versions yalnızca 0x0304
        içerdiği için sunucu zaten TLS 1.3 seçmek zorunda kalır; dolayısıyla
        eski suite'leri listelemek bağlantıyı hiçbir şekilde düşürmez, sadece
        parmak izini gerçekçi kılar.
        """
        suites: list[int] = []
        for c in self.profile["cipher_suites"]:
            if c == "GREASE":
                suites.append(self._grease_cipher)
            elif isinstance(c, int):
                suites.append(c)

        if not any(c in self._TLS13_SUITES for c in suites):
            raise ValueError(
                f"'{self.profile.get('_name', '?')}' profili hiç TLS 1.3 cipher suite "
                f"içermiyor; bu istemci yalnızca TLS 1.3 destekler."
            )
        if self.legacy_tls:
            # Profilde olmayan eski suite'ler SONA eklenir; olanlar yerinde kalır (parmak izi).
            from .security.tls12_legacy import LEGACY_OFFER_ORDER
            suites += [c for c in LEGACY_OFFER_ORDER if c not in suites]
        return suites

    def _build_cipher_suites(self) -> bytes:
        """Cipher suite bloğunu (2 byte uzunluk + gövde) döner."""
        raw = b"".join(struct.pack("!H", s) for s in self._cipher_suite_list())
        return struct.pack("!H", len(raw)) + raw

    def _ext(self, ext_type: int, payload: bytes) -> bytes:
        return struct.pack("!HH", ext_type, len(payload)) + payload

    def _pack_grease_ext(self) -> bytes:
        if self._grease_ext_idx < len(self._grease_ext_values):
            val = self._grease_ext_values[self._grease_ext_idx]
        else:
            val = _random_grease()
            while val in self._used_grease_exts:
                val = _random_grease()
            self._used_grease_exts.add(val)
            self._grease_ext_values.append(val)
        self._grease_ext_idx += 1
        # BoringSSL: ilk GREASE extension boş, sondaki (2.) GREASE 1 byte (0x00) taşır.
        return self._ext(val, b"" if self._grease_ext_idx == 1 else b"\x00")

    def _pack_sni(self) -> bytes:
        host_len = len(self.target_host)
        server_name = struct.pack(f"!BH{host_len}s", 0x00, host_len, self.target_host)
        sn_list = struct.pack(f"!H{len(server_name)}s", len(server_name), server_name)
        return self._ext(0x0000, sn_list)

    def _pack_extended_master_secret(self) -> bytes:
        return self._ext(0x0017, b"")

    def _pack_renegotiation_info(self) -> bytes:
        return self._ext(0xFF01, b"\x00")

    def _pack_supported_groups(self) -> bytes:
        profile_groups = self.profile.get("supported_groups", [0x001D, 0x0017, 0x0018])
        groups: list[int] = []
        for g in profile_groups:
            if g == "GREASE":
                groups.append(self._grease_group)
            elif isinstance(g, int) and (g in SUPPORTED_GROUPS or g not in _NEEDS_SUPPORT):
                groups.append(g)
        if not groups:
            groups = [0x001D, 0x0017, 0x0018]
        raw = b"".join(struct.pack("!H", g) for g in groups)
        payload = struct.pack(f"!H{len(raw)}s", len(raw), raw)
        return self._ext(0x000A, payload)

    def _pack_ec_point_formats(self) -> bytes:
        return self._ext(0x000B, b"\x01\x00")

    def _pack_session_ticket(self) -> bytes:
        """
        TLS 1.3'te gerçek session resumption 'pre_shared_key' extension'ı
        (RFC 8446 §4.2.11) ile yapılır — bu extension (session_ticket, 0x0023)
        TLS 1.2'nin RFC 5077 mekanizmasıdır ve modern Chrome TLS 1.3'te bunu
        her zaman BOŞ gönderir (sadece "destekliyorum" bildirimi).

        Önceden burada 1. bağlantıdan alınan ham NewSessionTicket byte'ları
        doğrudan bu extension'a konuyordu — bu formatça yanlıştı (NewSessionTicket
        payload'ı bu extension'ın beklediği formatta değil) ve sunucunun
        ClientHello'yu anomali sayıp sonraki isteği reddetmesine yol açıyordu.
        Biz gerçek PSK/0-RTT resumption implemente etmediğimiz için bu extension
        her zaman boş gönderilir; her bağlantı tam (full) TLS 1.3 handshake yapar.
        """
        return self._ext(0x0023, b"")

    def _pack_alpn(self) -> bytes:
        protocols = self.profile.get("alpn", ["http/1.1"])
        proto_list = b"".join(
            struct.pack(f"!B{len(p)}s", len(p), p.encode())
            for p in protocols
        )
        payload = struct.pack(f"!H{len(proto_list)}s", len(proto_list), proto_list)
        return self._ext(0x0010, payload)

    def _pack_status_request(self) -> bytes:
        payload = struct.pack("!BHH", 0x01, 0x0000, 0x0000)
        return self._ext(0x0005, payload)

    def _pack_signature_algorithms(self) -> bytes:
        algs = [self._grease_sigalg if a == "GREASE" else a
                for a in self.profile.get("signature_algorithms", [0x0403, 0x0804])
                if HAVE_MLDSA or a not in _MLDSA_SCHEMES]
        if self.legacy_tls:
            from .security.tls12_legacy import LEGACY_SIGALGS
            algs += [a for a in LEGACY_SIGALGS if a not in algs]
        raw = b"".join(struct.pack("!H", a) for a in algs)
        payload = struct.pack(f"!H{len(raw)}s", len(raw), raw)
        return self._ext(0x000D, payload)

    def _pack_signed_certificate_timestamp(self) -> bytes:
        return self._ext(0x0012, b"")

    def _pack_key_share(self) -> bytes:
        entries = self.key_shares.entries()
        if self._key_share_grease and self._cookie is None and not self._is_retry:
            # RFC 8701 GREASE key_share girdisi: supported_groups'taki GREASE
            # grubuyla aynı değer, 1 byte (0x00) veri.
            entries = struct.pack("!HHB", self._grease_group, 1, 0) + entries
        ext = self._ext(0x0033, struct.pack("!H", len(entries)) + entries)
        if self._cookie is not None:
            # HRR cookie'si (RFC 8446 §4.2.2) 2. ClientHello'da aynen geri yollanır.
            ext += self._ext(0x002C, struct.pack("!H", len(self._cookie)) + self._cookie)
        return ext

    def _pack_psk_key_exchange_modes(self) -> bytes:
        return self._ext(0x002D, b"\x01\x01")

    def _pack_supported_versions(self) -> bytes:
        # Profilin "supported_versions" listesi ("GREASE" placeholder'ı
        # desteklenir). Gerçek Chrome: GREASE, 0x0304, 0x0303.
        #
        # nginx.org alert 70 analizi (bkz. CHANGELOG 0.2.5): yalnızca 0x0304
        # teklif edip TLS 1.2-only bir OpenSSL sunucusuna bağlanınca OpenSSL
        # ortak sürüm bulamaz ve protocol_version (70) alert'i döner. 0x0303'ü
        # de ilan etmek (a) gerçek tarayıcı ClientHello'su ile birebir uyum
        # sağlar, (b) böyle bir sunucuda anlamsız alert 70 yerine TLS 1.2
        # ServerHello alınmasını ve istemcinin NET bir "TLS 1.2 kapsam dışı"
        # hatası vermesini sağlar. Güvenlik: negotiate() 0x0304 dışındaki her
        # sürümü reddeder, yani 0x0303'ü ilan etmek bir downgrade yolu açmaz.
        versions = []
        for v in self.profile.get("supported_versions", ["GREASE", 0x0304]):
            if v == "GREASE":
                versions.append(self._grease_version)
            elif isinstance(v, int):
                versions.append(v)
        if self.legacy_tls and 0x0303 not in versions:
            versions.append(0x0303)       # legacy: TLS 1.2 sunucularına bağlanabilmek için ilan şart
        if 0x0304 not in versions:
            raise ValueError("Profilin supported_versions listesi 0x0304 (TLS 1.3) içermeli.")
        raw = b"".join(struct.pack("!H", v) for v in versions)
        return self._ext(0x002B, struct.pack("!B", len(raw)) + raw)

    def _pack_compress_certificate(self) -> bytes:
        wanted = self.profile.get("cert_compression", [0x0002, 0x0001])
        have = _supported_cert_compression()
        algorithms = [a for a in wanted if a in have] or [0x0001]
        raw = b"".join(struct.pack("!H", a) for a in algorithms)
        payload = struct.pack("!B", len(raw)) + raw
        return self._ext(0x001B, payload)

    def _pack_delegated_credentials(self) -> bytes:
        algs = self.profile.get("delegated_credentials", [0x0403, 0x0503, 0x0603, 0x0804])
        raw = b"".join(struct.pack("!H", a) for a in algs)
        payload = struct.pack(f"!H{len(raw)}s", len(raw), raw)
        return self._ext(0x0022, payload)

    def _pack_record_size_limit(self) -> bytes:
        return self._ext(0x001C, struct.pack("!H", self.profile.get("record_size_limit", 0x4001)))

    def _pack_alps(self) -> bytes:
        """application_settings (ALPS): desteklenen protokol listesi (Chrome: ["h2"])."""
        protos = self.profile.get("alps_protocols", ["h2"])
        raw = b"".join(struct.pack("!B", len(p)) + p.encode() for p in protos)
        return self._ext(self.alps_codepoint, struct.pack("!H", len(raw)) + raw)

    def _pack_trust_anchors(self) -> bytes:
        """trust_anchors (0xca34): u16 uzunluklu, her biri u8 uzunluklu TrustAnchorID
        listesi (BoringSSL ext_trust_anchors_add_clienthello). Sunucunun yanıtı
        (EncryptedExtensions/CertificateEntry içinde) yok sayılır; Chrome'un
        TAI yeniden deneme akışı UYGULANMAZ (bkz. docs/limits.md)."""
        ids = _process_tai_order(self.profile.get("trust_anchors", []))
        raw = b"".join(struct.pack("!B", len(i)) + i for i in ids)
        return self._ext(EXT_TRUST_ANCHORS, struct.pack("!H", len(raw)) + raw)

    def _pack_ech_grease(self) -> bytes:
        """ECH GREASE (RFC 9849 §6.2 / draft-ietf-tls-esni): GERÇEK ECH DEĞİL.

        ``outer`` ClientHelloOuter biçiminde rastgele config_id/enc/payload.
        Sunucu ECH anahtarı yoksa yok sayar; varsa (retry_configs) yanıt
        EncryptedExtensions içinde gelir ve yok sayılır.
        """
        cfg = self.profile.get("ech_grease", {})
        aead = _SYS_RANDOM.choice(cfg.get("aead_ids", [0x0001]))
        plen = _SYS_RANDOM.choice(cfg.get("payload_lens", [144, 176, 208, 240]))
        body = (
            b"\x00"                                    # ECHClientHelloType: outer
            + struct.pack("!HH", 0x0001, aead)          # HKDF-SHA256, AEAD
            + os.urandom(1)                             # config_id
            + struct.pack("!H", 32) + os.urandom(32)    # enc (X25519 boyutu)
            + struct.pack("!H", plen) + os.urandom(plen)
        )
        return self._ext(EXT_ECH, body)

    def _pack_padding(self, ext_body_len: int, tail_len: int = 0) -> bytes:
        """BoringSSL tarzı padding (RFC 7685): handshake mesajı 256..511 bayt
        ise 512'ye tamamlanır, aksi halde padding EKLENMEZ (Chrome/Safari
        davranışı). Boş döner -> extension hiç yazılmaz.

        Handshake mesajı = 4 (başlık) + 2 (sürüm) + 32 (random) + 33
        (session_id) + cipher bloğu + 2 (compression) + 2 (ext uzunluğu) +
        extension'lar.
        """
        cipher_len = len(self._build_cipher_suites())
        msg_len = 4 + 2 + 32 + 33 + cipher_len + 2 + 2 + ext_body_len + tail_len
        if 0xFF < msg_len < 0x200:
            pad = 0x200 - msg_len - 4
            return self._ext(0x0015, bytes(max(pad, 1)))
        return b""

    _EXT_BUILDERS = {
        "GREASE":                    "_pack_grease_ext",
        "sni":                       "_pack_sni",
        "extended_master_secret":    "_pack_extended_master_secret",
        "renegotiation_info":        "_pack_renegotiation_info",
        "supported_groups":          "_pack_supported_groups",
        "ec_point_formats":          "_pack_ec_point_formats",
        "session_ticket":            "_pack_session_ticket",
        "alpn":                      "_pack_alpn",
        "status_request":            "_pack_status_request",
        "signature_algorithms":      "_pack_signature_algorithms",
        "signed_certificate_timestamp": "_pack_signed_certificate_timestamp",
        "key_share":                 "_pack_key_share",
        "psk_key_exchange_modes":    "_pack_psk_key_exchange_modes",
        "supported_versions":        "_pack_supported_versions",
        "compress_certificate":      "_pack_compress_certificate",
        "delegated_credentials":     "_pack_delegated_credentials",
        "record_size_limit":         "_pack_record_size_limit",
        "alps":                      "_pack_alps",
        "ech_grease":                "_pack_ech_grease",
        "trust_anchors":             "_pack_trust_anchors",
        "encrypt_then_mac":          "_pack_encrypt_then_mac",
    }

    def _pack_encrypt_then_mac(self) -> bytes:
        """RFC 7366 — yalnızca legacy_tls: sunucu CBC seçerse EtM kullanmayı teklif eder."""
        return self._ext(0x0016, b"")

    @property
    def alps_advertised(self) -> bool:
        return "alps" in self.profile.get("extensions_order", [])

    @property
    def alps_codepoint(self) -> int:
        """ClientHello'da (ve istemci EncryptedExtensions'ında) kullanılan ALPS kod noktası."""
        return int(self.profile.get("alps_codepoint", EXT_ALPS))

    def _effective_order(self) -> list[str]:
        """Profil sırası; ``shuffle_extensions`` ise (Chrome) baştaki/sondaki
        GREASE hariç ortası bağlantı başına BİR KEZ karıştırılır ve HRR
        sonrası 2. ClientHello'da AYNEN korunur."""
        if self._ext_order is not None:
            return self._ext_order
        order = list(self.profile.get("extensions_order", []))
        if self.legacy_tls and "encrypt_then_mac" not in order:
            at = len(order) - 1 if order and order[-1] == "GREASE" else len(order)
            order.insert(at, "encrypt_then_mac")
        if os.environ.get("FASTHTTPC_NO_ECH_GREASE") == "1":
            # ECH GREASE'i tanıyıp TLS'i kendisi sonlandıran ara proxy'ler için
            # (ör. kurumsal/sandbox egress proxy'leri) kaçış kapısı. JA4'te
            # extension sayısı 1 azalır; varsayılan KAPALI (gerçek tarayıcı gibi).
            order = [e for e in order if e != "ech_grease"]
        if self.profile.get("shuffle_extensions"):
            lo = 1 if order and order[0] == "GREASE" else 0
            hi = len(order) - 1 if order and order[-1] == "GREASE" else len(order)
            mid = order[lo:hi]
            _SYS_RANDOM.shuffle(mid)
            order = order[:lo] + mid + order[hi:]
        self._ext_order = order
        return order

    def _build_extensions(self, extra_tail_extensions: bytes | None = None) -> bytes:
        order = self._effective_order()
        tail = extra_tail_extensions or b""
        self._grease_ext_idx = 0
        parts = []
        for name in order:
            if name == "padding":
                continue
            builder_name = self._EXT_BUILDERS.get(name)
            if not builder_name:
                continue
            builder = getattr(self, builder_name, None)
            if builder:
                parts.append(builder())

        ext_body = b"".join(parts)

        if "padding" in order:
            ext_body += self._pack_padding(len(ext_body), len(tail))

        # extra_tail_extensions (ör. pre_shared_key) HER ZAMAN en sonda olmalı
        # (RFC 8446 §4.2.11) — padding'den bile sonra.
        ext_body += tail
        return struct.pack("!H", len(ext_body)) + ext_body

    def build_client_hello(
        self, extra_tail_extensions: bytes | None = None
    ) -> tuple[bytes, bytes, bytes]:
        """İlk ClientHello'yu üretir.

        Döner: (record_bytes, x25519_private_raw | None, client_random).
        Tüm key_share özel anahtarları ``self.key_shares`` (KeyShareSet) içindedir.

        extra_tail_extensions: verilirse extension listesinin EN SONUNA bayt
        bayt eklenir (PSK resumption için pre_shared_key — faz4).
        """
        # RFC 8446 §4.1.2: client_random 32 byte TAM RASTGELE olmalıdır.
        # Eski TLS 1.2 pratiği ilk 4 byte'a gmt_unix_time koyardı; modern
        # tarayıcıların hiçbiri bunu yapmaz, dolayısıyla o alan tek başına
        # "bu bir tarayıcı değil" sinyali veren bir parmak izidir.
        self._client_random = os.urandom(32)
        self._session_id = os.urandom(32)
        self._cookie = None
        self._is_retry = False
        self._ext_order = None
        return self._assemble(extra_tail_extensions), self.private_key, self._client_random

    def build_retry_client_hello(
        self,
        group: int,
        cookie: bytes | None = None,
        extra_tail_extensions: bytes | None = None,
    ) -> bytes:
        """HelloRetryRequest sonrası 2. ClientHello'yu üretir (RFC 8446 §4.1.2).

        Aynı client_random, session_id, cipher listesi, GREASE değerleri ve
        extension sırası korunur; key_share yalnızca ``group`` için YENİ bir
        anahtar içerir, HRR'de cookie varsa cookie extension'ı eklenir.
        Yeni özel anahtar ``self.key_shares`` içindedir.
        """
        if self._client_random is None:
            raise RuntimeError("build_retry_client_hello, build_client_hello'dan önce çağrılamaz.")
        if group not in SUPPORTED_GROUPS:
            raise ValueError(f"HRR grubu desteklenmiyor: {group_name(group)}")
        self.key_shares = KeyShareSet([group])
        self._cookie = cookie
        self._is_retry = True
        return self._assemble(extra_tail_extensions)

    def _assemble(self, extra_tail_extensions: bytes | None) -> bytes:
        client_random = self._client_random
        session_id_payload = struct.pack("!B32s", 32, self._session_id)

        cipher_payload = self._build_cipher_suites()
        comp_payload = struct.pack("!BB", 1, 0x00)
        extensions = self._build_extensions(extra_tail_extensions)

        client_hello_body = (
            struct.pack("!H", 0x0303) +
            client_random +
            session_id_payload +
            cipher_payload +
            comp_payload +
            extensions
        )

        body_len = len(client_hello_body)
        hs_header = struct.pack("!B", 0x01) + struct.pack("!I", body_len)[1:]
        full_payload = hs_header + client_hello_body
        record_header = struct.pack("!BHH", 0x16, 0x0301, len(full_payload))

        self.last_client_hello = record_header + full_payload
        return self.last_client_hello
