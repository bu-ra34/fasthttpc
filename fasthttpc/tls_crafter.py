import struct
import os
import threading
from .crypto_math import PureCryptoEngine
from .fingerprint import get_profile, _random_grease

                                     
                             
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


class TLSImpersonator:
    def __init__(self, target_host, profile=None):
        self.target_host = target_host.encode("utf-8")
        self.host_str = target_host
        self.profile = get_profile(profile)
        self.private_key, self.public_key = PureCryptoEngine.generate_keypair()
        self._grease_cipher = _random_grease()
        self._grease_group = _random_grease()
        self._grease_version = _random_grease()
        self._used_grease_exts = set()

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
        return suites

    def _build_cipher_suites(self) -> bytes:
        """Cipher suite bloğunu (2 byte uzunluk + gövde) döner."""
        raw = b"".join(struct.pack("!H", s) for s in self._cipher_suite_list())
        return struct.pack("!H", len(raw)) + raw

    def _ext(self, ext_type: int, payload: bytes) -> bytes:
        return struct.pack("!HH", ext_type, len(payload)) + payload

    def _pack_grease_ext(self) -> bytes:
        val = _random_grease()
        while val in self._used_grease_exts:
            val = _random_grease()
        self._used_grease_exts.add(val)
        return self._ext(val, b"")

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
            elif isinstance(g, int):
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
        algs = self.profile.get("signature_algorithms", [0x0403, 0x0804])
        raw = b"".join(struct.pack("!H", a) for a in algs)
        payload = struct.pack(f"!H{len(raw)}s", len(raw), raw)
        return self._ext(0x000D, payload)

    def _pack_signed_certificate_timestamp(self) -> bytes:
        return self._ext(0x0012, b"")

    def _pack_key_share(self) -> bytes:
        key_entry = struct.pack("!HH32s", 0x001D, 32, self.public_key)
        payload = struct.pack(f"!H{len(key_entry)}s", len(key_entry), key_entry)
        return self._ext(0x0033, payload)

    def _pack_psk_key_exchange_modes(self) -> bytes:
        return self._ext(0x002D, b"\x01\x01")

    def _pack_supported_versions(self) -> bytes:
        # Gerçek Chrome bu listeye önce bir GREASE değeri, sonra TLS 1.3 (0x0304)
        # koyar. GREASE'siz düz "0304", Cloudflare gibi hoşgörülü sunucularda
        # çalışır ama nginx.org gibi katı yığınlar 'protocol_version' alert'iyle
        # reddedebilir. Cipher ve supported_groups listelerinde zaten GREASE
        # kullandığımız için burada da tutarlı olmak hem uyumluluk hem parmak
        # izi doğruluğu sağlar.
        versions = struct.pack("!HH", self._grease_version, 0x0304)
        payload = struct.pack(f"!B{len(versions)}s", len(versions), versions)
        return self._ext(0x002B, payload)

    def _pack_compress_certificate(self) -> bytes:
        algorithms = [0x0002, 0x0001]
        raw = b"".join(struct.pack("!H", a) for a in algorithms)
        payload = struct.pack("!B", len(raw)) + raw
        return self._ext(0x001B, payload)

    def _pack_delegated_credentials(self) -> bytes:
        algs = [0x0403, 0x0503, 0x0603, 0x0804]
        raw = b"".join(struct.pack("!H", a) for a in algs)
        payload = struct.pack(f"!H{len(raw)}s", len(raw), raw)
        return self._ext(0x0022, payload)

    def _pack_record_size_limit(self) -> bytes:
        return self._ext(0x001C, struct.pack("!H", 0x4001))

    def _pack_padding(self, ext_body_len: int) -> bytes:
        """
        ClientHello toplam uzunluğunu 512 byte'ın katına yuvarlayacak şekilde
        padding ekle (Chrome davranışı).

        ClientHello yapısı:
          TLS record header  : 5 byte
          Handshake header   : 4 byte
          client_version     : 2
          client_random      : 32
          session_id         : 1 + 32
          cipher_suites      : 2 + len
          compression        : 2
          extensions length  : 2
          extensions         : ext_body_len (padding hariç)
        """
        # _build_cipher_suites() zaten kendi 2 byte'lık uzunluk prefix'ini
        # içeriyor; ayrıca 2 eklemek toplamı 2 byte şişirip hedefi kaydırıyordu.
        cipher_len = len(self._build_cipher_suites())
        fixed = 5 + 4 + 2 + 32 + 33 + cipher_len + 2 + 2
        current_total = fixed + ext_body_len + 4                          
        target = ((current_total + 511) // 512) * 512
        pad_data_len = target - current_total
        if pad_data_len < 0:
            pad_data_len = 0
        return self._ext(0x0015, bytes(pad_data_len))

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
    }

    def _build_extensions(self) -> bytes:
        order = self.profile.get("extensions_order", [])
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
            pad_ext = self._pack_padding(len(ext_body))
            ext_body += pad_ext

        return struct.pack("!H", len(ext_body)) + ext_body

    def build_client_hello(self) -> tuple[bytes, bytes, bytes]:
        # RFC 8446 §4.1.2: client_random 32 byte TAM RASTGELE olmalıdır.
        # Eski TLS 1.2 pratiği ilk 4 byte'a gmt_unix_time koyardı; modern
        # tarayıcıların hiçbiri bunu yapmaz, dolayısıyla o alan tek başına
        # "bu bir tarayıcı değil" sinyali veren bir parmak izidir.
        client_random = os.urandom(32)
        session_id = os.urandom(32)
        session_id_payload = struct.pack("!B32s", 32, session_id)

        cipher_payload = self._build_cipher_suites()
        comp_payload = struct.pack("!BB", 1, 0x00)
        extensions = self._build_extensions()

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
        return self.last_client_hello, self.private_key, client_random
