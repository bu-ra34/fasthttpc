"""
FAZ 3 — TLS Derinliği

14. TLS Record Fragmentation kontrolü
15. TLS Downgrade Dedektörü (MITM tespiti)
16. Adaptif Cipher Negotiation
17. TLS Davranış Kaydedici + sunucu fingerprint DB
18. ClientHello Entropy Skoru
19. TLS Session Resumption — 0-RTT (ticket cache entegrasyonu)
20. Encrypted Client Hello (ECH) — altyapı + stub
21. TLS Record Zamanlama Analizi
"""
from __future__ import annotations
import struct
import time
import math
import hashlib
import threading
import os
from dataclasses import dataclass, field
from typing import Optional


                                                                               
                                       
                                                                               

class TLSFragmenter:
    """
    TLS ClientHello'yu birden fazla record'a böler.
    DPI (Deep Packet Inspection) sistemleri ClientHello'yu tek record olarak bekler;
    fragmentasyon bu tespiti atlatır.
    
    RFC 5246 §6.2.1: TLS record max 16384 byte — minimum sınır yok.
    """
    MIN_FRAG = 1                                                                  
    DEFAULT_SPLIT = 2                                           

    @staticmethod
    def fragment(record: bytes, first_size: int = DEFAULT_SPLIT) -> list[bytes]:
        """
        Tek TLS record'u iki parçaya böl.
        record: tam TLS record (5 byte header + payload)
        """
        if len(record) <= 5 + first_size:
            return [record]

                                                             
        rec_type    = record[0:1]
        version     = record[1:3]
        payload     = record[5:]

                      
        frag1_data  = payload[:first_size]
        frag1_hdr   = rec_type + version + struct.pack("!H", len(frag1_data))

                                         
        frag2_data  = payload[first_size:]
        frag2_hdr   = rec_type + version + struct.pack("!H", len(frag2_data))

        return [frag1_hdr + frag1_data, frag2_hdr + frag2_data]

    @staticmethod
    def send_fragmented(sock, record: bytes, first_size: int = DEFAULT_SPLIT) -> None:
        """Fragment edilmiş record'ları soket üzerinden gönder."""
        fragments = TLSFragmenter.fragment(record, first_size)
        for frag in fragments:
            sock.sendall(frag)


                                                                               
                             
                                                                               

class TLSDowngradeDetector:
    """
    MITM / TLS downgrade saldırısı tespiti.
    
    Kontroller:
    - Negotiated versiyon < TLS 1.3 → şüpheli
    - Cipher suite TLS 1.3 dışı seçildi → downgrade
    - ServerHello'da GREASE değeri varsa tarayıcı simülasyonu doğrulandı
    - Sertifika değişikliği (pinning ile birlikte)
    """
    TLS13_CIPHERS = {0x1301, 0x1302, 0x1303}

    @dataclass
    class DowngradeResult:
        is_suspicious: bool
        reasons: list[str]
        negotiated_version: str
        negotiated_cipher: Optional[int]

    @staticmethod
    def check(crypto_state: dict) -> "TLSDowngradeDetector.DowngradeResult":
        reasons = []
        
                               
        is_tls13 = crypto_state.get("is_tls13", False)
        version  = "TLS 1.3" if is_tls13 else "< TLS 1.3"
        
        if not is_tls13:
            reasons.append(f"Downgrade: TLS 1.2 veya altı müzakere edildi ({version})")

                               
        cipher_name = crypto_state.get("cipher_name", "")
        selected_cipher = None
        if "AES_128_GCM" in cipher_name:
            selected_cipher = 0x1301
        elif "AES_256_GCM" in cipher_name:
            selected_cipher = 0x1302
        elif "CHACHA20" in cipher_name:
            selected_cipher = 0x1303

        if selected_cipher and selected_cipher not in TLSDowngradeDetector.TLS13_CIPHERS:
            reasons.append(f"Zayıf cipher suite: {cipher_name}")

                                                                                   
        if not crypto_state.get("app_client_write_key"):
            reasons.append("Uygulama anahtarları türetilemedi — el sıkışma eksik")

        return TLSDowngradeDetector.DowngradeResult(
            is_suspicious       = len(reasons) > 0,
            reasons             = reasons,
            negotiated_version  = version,
            negotiated_cipher   = selected_cipher,
        )


                                                                               
                                
                                                                               

class AdaptiveCipherNegotiator:
    """
    Sunucu geçmişine göre tercih edilen cipher suite sıralamasını dinamik ayarlar.
    
    AES-NI donanım desteği varsa AES_GCM'yi, yoksa ChaCha20'yi öne alır.
    Sunucu geçmişindeki başarısız denemeler otomatik listeden çıkarılır.
    """
    
                                                                        
    _aes_ni_available: Optional[bool] = None
    _lock = threading.Lock()

    @classmethod
    def detect_aesni(cls) -> bool:
        """AES-NI donanım ivmesi var mı? Mikrobenchmark ile tahmin et."""
        if cls._aes_ni_available is not None:
            return cls._aes_ni_available
        with cls._lock:
            if cls._aes_ni_available is not None:
                return cls._aes_ni_available
            try:
                from Crypto.Cipher import AES
                import time
                key  = os.urandom(16)
                data = os.urandom(1024 * 64)         
                t0   = time.perf_counter()
                for _ in range(50):
                    c = AES.new(key, AES.MODE_ECB)
                    c.encrypt(data)
                elapsed = time.perf_counter() - t0
                                              
                cls._aes_ni_available = elapsed < 0.01
            except ImportError:
                                                          
                import platform
                cls._aes_ni_available = platform.machine() in ("x86_64", "AMD64", "x86")
        return cls._aes_ni_available

    @classmethod
    def preferred_order(cls, host: str, server_history: dict) -> list[int]:
        """
        host geçmişine göre cipher suite tercih sırası döner.
        [0x1301=AES_128_GCM, 0x1302=AES_256_GCM, 0x1303=CHACHA20]
        """
                                                            
        if host in server_history:
            last_cipher = server_history[host].get("cipher")
            if last_cipher:
                base = [0x1301, 0x1302, 0x1303]
                if last_cipher in base:
                    base.remove(last_cipher)
                    return [last_cipher] + base

                                                  
        if cls.detect_aesni():
            return [0x1301, 0x1302, 0x1303]
        else:
            return [0x1303, 0x1301, 0x1302]


                                                                               
                                                    
                                                                               

@dataclass
class ServerTLSProfile:
    """Tek bir sunucunun TLS davranış profili."""
    host:               str
    negotiated_version: str         = "unknown"
    negotiated_cipher:  str         = "unknown"
    supports_0rtt:      bool        = False
    ticket_received:    bool        = False
    ech_supported:      bool        = False
    alpn_negotiated:    str         = ""
    first_seen:         float       = field(default_factory=time.time)
    last_seen:          float       = field(default_factory=time.time)
    handshake_times_ms: list[float] = field(default_factory=list)
    extensions_seen:    list[int]   = field(default_factory=list)

    @property
    def avg_handshake_ms(self) -> float:
        if not self.handshake_times_ms:
            return 0.0
        return sum(self.handshake_times_ms) / len(self.handshake_times_ms)

    def fingerprint(self) -> str:
        """Sunucu TLS davranışının kısa parmak izi hash'i."""
        raw = f"{self.negotiated_version}:{self.negotiated_cipher}:{self.alpn_negotiated}:{sorted(self.extensions_seen)}"
        return hashlib.md5(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> dict:
        return {
            "host":               self.host,
            "version":            self.negotiated_version,
            "cipher":             self.negotiated_cipher,
            "0rtt":               self.supports_0rtt,
            "ticket":             self.ticket_received,
            "ech":                self.ech_supported,
            "alpn":               self.alpn_negotiated,
            "avg_hs_ms":          round(self.avg_handshake_ms, 2),
            "fingerprint":        self.fingerprint(),
        }


class TLSBehaviorRecorder:
    """
    Session genelinde sunucu TLS profillerini kaydeder ve sorgular.
    Session.tls_recorder olarak erişilir.
    """
    def __init__(self):
        self._db: dict[str, ServerTLSProfile] = {}
        self._lock = threading.Lock()

    def record(self, host: str, crypto_state: dict, handshake_ms: float = 0.0) -> ServerTLSProfile:
        """Yeni handshake bilgisini kaydet veya mevcut profili güncelle."""
        with self._lock:
            if host not in self._db:
                self._db[host] = ServerTLSProfile(host=host)
            prof = self._db[host]

        prof.negotiated_version = "TLS 1.3" if crypto_state.get("is_tls13") else "< TLS 1.3"
        prof.negotiated_cipher  = crypto_state.get("cipher_name", "unknown")
        prof.ticket_received    = bool(crypto_state.get("session_ticket"))
        prof.last_seen          = time.time()
        if handshake_ms:
            prof.handshake_times_ms.append(handshake_ms)
            if len(prof.handshake_times_ms) > 20:
                prof.handshake_times_ms = prof.handshake_times_ms[-20:]
        return prof

    def get(self, host: str) -> Optional[ServerTLSProfile]:
        with self._lock:
            return self._db.get(host)

    def all_profiles(self) -> list[dict]:
        with self._lock:
            return [p.to_dict() for p in self._db.values()]

    def __len__(self) -> int:
        with self._lock:
            return len(self._db)


                                                                               
                               
                                                                               

class ClientHelloEntropyScorer:
    """
    ClientHello'nun bir bot mu yoksa gerçek tarayıcı mı olduğunu ölçer.
    Yüksek skor = gerçek tarayıcıya benziyor.
    
    Ölçülen faktörler:
    - Random bytes Shannon entropy (gerçek random = ~8 bit/byte)
    - Session ID varlığı/boyutu
    - GREASE değerleri kullanımı
    - Cipher suite çeşitliliği
    - Extension sırası tipik tarayıcıya benziyor mu
    """
    
                                          
    CHROME_EXT_ORDER = [
        0x0000,       
        0x0017,                          
        0xFF01,                      
        0x000A,                    
        0x000B,                    
        0x0023,                  
        0x0010,        
        0x0005,                  
        0x0013,                         
        0x000D,                        
        0x0012,                              
        0x0033,             
        0x002D,                          
        0x002B,                      
        0x001B,                        
        0xFE0D,                                
        0x0029,                               
    ]

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        """Shannon entropy (bit/byte). Max = 8.0."""
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        return -sum((f/n) * math.log2(f/n) for f in freq if f > 0)

    @classmethod
    def score_random_bytes(cls, random_bytes: bytes) -> float:
        """ClientHello random field (32 byte) entropy skoru. Max 100."""
        if len(random_bytes) < 32:
            return 0.0
        entropy = cls.shannon_entropy(random_bytes)
        return min(entropy / 8.0 * 100, 100.0)

    @classmethod
    def score_extension_order(cls, ext_ids: list[int]) -> float:
        """Extension sırası Chrome'a ne kadar benziyor? Max 100."""
        if not ext_ids:
            return 0.0
                                
        clean = [e for e in ext_ids if e not in {
            0x0A0A,0x1A1A,0x2A2A,0x3A3A,0x4A4A,0x5A5A,
            0x6A6A,0x7A7A,0x8A8A,0x9A9A,0xAAAA,0xBABA,
            0xCACA,0xDADA,0xEAEA,0xFAFA
        }]
        ref  = [e for e in cls.CHROME_EXT_ORDER if e in clean]
        seen = [e for e in clean if e in set(cls.CHROME_EXT_ORDER)]
        if not ref:
            return 50.0
                                                
        matches = sum(1 for a, b in zip(ref, seen) if a == b)
        return (matches / len(ref)) * 100

    @classmethod
    def score_grease_presence(cls, cipher_list: list, ext_ids: list[int]) -> float:
        """GREASE değerleri kullanılıyor mu? (Gerçek Chrome GREASE kullanır). Max 100."""
        grease = {
            0x0A0A,0x1A1A,0x2A2A,0x3A3A,0x4A4A,0x5A5A,
            0x6A6A,0x7A7A,0x8A8A,0x9A9A,0xAAAA,0xBABA,
            0xCACA,0xDADA,0xEAEA,0xFAFA
        }
        cipher_grease = any(c in grease for c in cipher_list)
        ext_grease    = any(e in grease for e in ext_ids)
        return 100.0 if (cipher_grease and ext_grease) else (50.0 if cipher_grease or ext_grease else 0.0)

    @classmethod
    def total_score(
        cls,
        random_bytes: bytes,
        ext_ids:      list[int],
        cipher_list:  list,
    ) -> dict:
        """Toplam entropy skoru (0-100) ve detaylar."""
        r = cls.score_random_bytes(random_bytes)
        e = cls.score_extension_order(ext_ids)
        g = cls.score_grease_presence(cipher_list, ext_ids)
        total = r * 0.4 + e * 0.35 + g * 0.25
        return {
            "total":          round(total, 1),
            "random_entropy": round(r, 1),
            "ext_order":      round(e, 1),
            "grease":         round(g, 1),
            "verdict":        "human" if total >= 70 else ("suspicious" if total >= 40 else "bot"),
        }


                                                                               
                                              
                                                                               

class SessionResumptionManager:
    """
    TLS 1.3 Session Ticket tabanlı 0-RTT resumption yöneticisi.
    tls_crafter'daki _ticket_cache ile entegre çalışır.
    
    0-RTT: önceki session'dan alınan ticket ile yeni handshake'te
    early_data gönderilebilir → 1-RTT yerine 0-RTT bağlantı.
    """
    def __init__(self):
        self._tickets: dict[str, bytes]       = {}                       
        self._nonces:  dict[str, int]         = {}                       
        self._lock = threading.Lock()

    def store_ticket(self, host: str, ticket: bytes) -> None:
        with self._lock:
            self._tickets[host] = ticket
            self._nonces[host]  = 0

    def get_ticket(self, host: str) -> Optional[bytes]:
        with self._lock:
            return self._tickets.get(host)

    def has_ticket(self, host: str) -> bool:
        with self._lock:
            return host in self._tickets

    def next_nonce(self, host: str) -> int:
        with self._lock:
            n = self._nonces.get(host, 0)
            self._nonces[host] = n + 1
            return n

    def build_psk_extension(self, host: str, cipher_hash_len: int = 32) -> Optional[bytes]:
        """
        TLS 1.3 pre_shared_key extension (type=0x0029) oluşturur.
        Döner: extension bytes veya None (ticket yoksa)
        """
        ticket = self.get_ticket(host)
        if not ticket:
            return None

                                                               
        ticket_age = struct.pack("!I", 0)                          
        identity   = struct.pack("!H", len(ticket)) + ticket + ticket_age

                                                                            
        binder_len = cipher_hash_len
        binder     = b"\x00" * binder_len

        identities  = struct.pack("!H", len(identity)) + identity
        binders     = struct.pack("!H", binder_len + 1) + struct.pack("!B", binder_len) + binder
        payload     = identities + binders

        return struct.pack("!HH", 0x0029, len(payload)) + payload

    def clear(self, host: Optional[str] = None) -> None:
        with self._lock:
            if host:
                self._tickets.pop(host, None)
                self._nonces.pop(host, None)
            else:
                self._tickets.clear()
                self._nonces.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._tickets)


                                                                               
                                            
                                                                               

class ECHManager:
    """
    Encrypted Client Hello (RFC 9258 taslak) altyapısı.
    
    ECH: ClientHello'nun gizli kısmını (SNI dahil) sunucu public key ile şifreler.
    Ağ seviyesinde SNI gizliliği sağlar.
    
    NOT: Tam ECH implementasyonu HPKE (Hybrid Public Key Encryption) gerektirir.
    Bu sınıf: ECH availability tespiti, config parsing ve extension stub sunar.
    Gerçek şifreleme python-hpke veya harici kütüphane ile tamamlanır.
    """
    ECH_EXT_TYPE = 0xFE0D

    @staticmethod
    def build_outer_sni(public_name: str) -> bytes:
        """
        ECH outer ClientHello için SNI extension.
        Gerçek hedef SNI yerine ECH public_name kullanılır.
        """
        host = public_name.encode("ascii")
        sni_entry = struct.pack("!BH", 0, len(host)) + host
        sni_list  = struct.pack("!H", len(sni_entry)) + sni_entry
        return struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    @staticmethod
    def parse_ech_config(config_bytes: bytes) -> dict:
        """
        DNS HTTPS record'dan alınan ECH config'i parse eder.
        Döner: {version, config_id, kem_id, public_key, cipher_suites, max_name_len, public_name}
        """
        if len(config_bytes) < 8:
            return {}
        try:
            version   = struct.unpack("!H", config_bytes[0:2])[0]
            length    = struct.unpack("!H", config_bytes[2:4])[0]
            config_id = config_bytes[4]
            kem_id    = struct.unpack("!H", config_bytes[5:7])[0]
            pk_len    = struct.unpack("!H", config_bytes[7:9])[0]
            pk        = config_bytes[9:9 + pk_len]
            return {
                "version":    hex(version),
                "config_id":  config_id,
                "kem_id":     kem_id,                                              
                "public_key": pk.hex(),
                "supported":  kem_id == 0x0020,                        
            }
        except Exception:
            return {}

    @staticmethod
    def build_grease_ech() -> bytes:
        """
        GREASE ECH extension — gerçek ECH yoksa bile tarayıcı davranışını taklit eder.
        Sunucu bunu görmezden gelir ama parmak izi doğal görünür.
        """
        payload = os.urandom(128)                      
        return struct.pack("!HH", ECHManager.ECH_EXT_TYPE, len(payload)) + payload


                                                                               
                                  
                                                                               

@dataclass
class TLSTimingRecord:
    """Tek bir TLS handshake için zamanlama ölçümleri."""
    host:            str
    client_hello_ts: float = 0.0                           
    server_hello_ts: float = 0.0                       
    finished_ts:     float = 0.0                    
    app_key_ts:      float = 0.0                               

    @property
    def server_hello_latency_ms(self) -> float:
        """ClientHello → ServerHello süresi (ms). Ağ RTT'ye yakın."""
        if self.server_hello_ts and self.client_hello_ts:
            return (self.server_hello_ts - self.client_hello_ts) * 1000
        return 0.0

    @property
    def handshake_total_ms(self) -> float:
        """Toplam TLS handshake süresi (ms)."""
        if self.app_key_ts and self.client_hello_ts:
            return (self.app_key_ts - self.client_hello_ts) * 1000
        return 0.0

    @property
    def server_processing_ms(self) -> float:
        """ServerHello → Finished arası (sunucu işlem süresi tahmini)."""
        if self.finished_ts and self.server_hello_ts:
            return (self.finished_ts - self.server_hello_ts) * 1000
        return 0.0

    def to_dict(self) -> dict:
        return {
            "host":                    self.host,
            "server_hello_latency_ms": round(self.server_hello_latency_ms, 2),
            "server_processing_ms":    round(self.server_processing_ms, 2),
            "handshake_total_ms":      round(self.handshake_total_ms, 2),
        }


class TLSTimingAnalyzer:
    """
    Birden fazla handshake ölçümünü toplayarak anomali tespiti yapar.
    
    MITM proxy'leri genellikle ekstra gecikme ekler:
    - ServerHello latency: doğrudan ≈ RTT/2; MITM araya girince 2×RTT veya fazlası
    - İstatistiksel outlier tespiti ile şüpheli bağlantılar işaretlenir
    """
    def __init__(self, outlier_threshold: float = 3.0):
        self._records: list[TLSTimingRecord] = []
        self._threshold = outlier_threshold                           
        self._lock = threading.Lock()

    def record(self, timing: TLSTimingRecord) -> None:
        with self._lock:
            self._records.append(timing)
            if len(self._records) > 100:
                self._records = self._records[-100:]

    def is_anomaly(self, timing: TLSTimingRecord) -> tuple[bool, str]:
        """
        Bu timing kaydı istatistiksel outlier mı?
        Döner: (is_anomaly, reason)
        """
        with self._lock:
            latencies = [r.server_hello_latency_ms for r in self._records
                         if r.host == timing.host and r.server_hello_latency_ms > 0]

        if len(latencies) < 3:
            return False, "Yeterli veri yok"

        mean   = sum(latencies) / len(latencies)
        var    = sum((x - mean) ** 2 for x in latencies) / len(latencies)
        stddev = math.sqrt(var) if var > 0 else 0

        current = timing.server_hello_latency_ms
        if stddev > 0 and abs(current - mean) > self._threshold * stddev:
            return True, (
                f"Zamanlama anomalisi: {current:.1f}ms "
                f"(ortalama={mean:.1f}ms, σ={stddev:.1f}ms) — olası MITM"
            )
        return False, "Normal"

    def stats(self) -> dict:
        with self._lock:
            if not self._records:
                return {}
            latencies = [r.server_hello_latency_ms for r in self._records if r.server_hello_latency_ms > 0]
            if not latencies:
                return {}
            mean   = sum(latencies) / len(latencies)
            var    = sum((x - mean)**2 for x in latencies) / len(latencies)
            return {
                "count":   len(latencies),
                "mean_ms": round(mean, 2),
                "std_ms":  round(math.sqrt(var), 2),
                "min_ms":  round(min(latencies), 2),
                "max_ms":  round(max(latencies), 2),
            }
