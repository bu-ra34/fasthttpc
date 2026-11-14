"""QUIC/HTTP3 parmak izi profilleri (DÜRÜST KAPSAM için paket belgelerine/NOTES4'e bakın).

Taklit EDİLEBİLEN: QUIC transport parametreleri (akış denetim pencereleri, idle timeout,
stream sınırları, CID limiti), UDP datagram boyutu, HTTP/3 SETTINGS (değerler, sıra, GREASE
ayarı) ve QPACK dinamik tablo kapasitesi.
Taklit EDİLEMEYEN: QUIC içindeki TLS ClientHello'nun tam yapısı (uzantı sırası/GREASE/
ML-KEM key_share/ECH) aioquic'e aittir; Initial paket şifreleme/padding ayrıntıları ve
Chrome'un ``google_*`` transport parametreleri de aioquic üzerinden yazılamaz.
Değerler Chrome'un (quiche) bilinen varsayılanlarından, ağ erişimi olmadan DOĞRULANAMADAN
derlenmiştir: yaklaşık kabul edin.
"""
from __future__ import annotations

import os
import random
from dataclasses import dataclass
from typing import Optional

# HTTP/3 ayar kimlikleri
QPACK_MAX_TABLE_CAPACITY = 0x1
MAX_FIELD_SECTION_SIZE = 0x6
QPACK_BLOCKED_STREAMS = 0x7


@dataclass(frozen=True)
class QuicProfile:
    name: str
    max_data: int
    max_stream_data: int
    idle_timeout: float
    max_streams_bidi: int
    max_streams_uni: int
    active_connection_id_limit: int
    max_datagram_size: int
    qpack_table_capacity: int
    max_field_section_size: int
    # Chrome QPACK_BLOCKED_STREAMS=100 ilan eder; aioquic bloklanan akışı işleyemez
    # (pylsqpack.StreamBlocked yakalanmıyor) -> DÜRÜST değer 0; fark belgelenmiştir.
    qpack_blocked_streams: int = 0
    grease_setting: bool = True


CHROME = QuicProfile(
    name="chrome", max_data=15 * 1024 * 1024, max_stream_data=6 * 1024 * 1024,
    idle_timeout=30.0, max_streams_bidi=100, max_streams_uni=103,
    active_connection_id_limit=4, max_datagram_size=1350,
    qpack_table_capacity=65536, max_field_section_size=262144,
)
DEFAULT = QuicProfile(
    name="default", max_data=1048576, max_stream_data=1048576, idle_timeout=60.0,
    max_streams_bidi=128, max_streams_uni=128, active_connection_id_limit=8,
    max_datagram_size=1280, qpack_table_capacity=0, max_field_section_size=65536,
    grease_setting=False,
)


def profile_for(impersonate: Optional[str]) -> QuicProfile:
    """Yalnızca Chrome ailesi için gerçek bir QUIC profili var; diğerleri aioquic varsayılanı."""
    if impersonate and str(impersonate).lower().startswith("chrome"):
        return CHROME
    return DEFAULT


def h3_settings(profile: QuicProfile, rng: "random.Random | None" = None) -> dict[int, int]:
    """Sıralı HTTP/3 SETTINGS sözlüğü (Chrome sırası: 1, 6, 7, GREASE)."""
    s: dict[int, int] = {}
    if profile is DEFAULT:
        return s
    s[QPACK_MAX_TABLE_CAPACITY] = profile.qpack_table_capacity
    s[MAX_FIELD_SECTION_SIZE] = profile.max_field_section_size
    s[QPACK_BLOCKED_STREAMS] = profile.qpack_blocked_streams
    if profile.grease_setting:
        r = rng or random.Random(int.from_bytes(os.urandom(4), "big"))
        s[0x1F * r.randrange(0, 2**20) + 0x21] = r.randrange(0, 2**30)   # RFC 9114 §7.2.4.1
    return s


def apply_quic_profile(quic, profile: QuicProfile) -> dict:
    """QuicConnection'ın (özel) yerel transport parametre alanlarını ayarlar.

    aioquic özel alanlarına dokunur; sürüm değişirse sessizce atlanır ve atlananlar
    döndürülür (parmak izi iddiasını şişirmemek için). Kapsam: bağlantıdan ÖNCE çağrılmalı.
    """
    applied: dict = {}
    try:
        quic._local_active_connection_id_limit = profile.active_connection_id_limit
        applied["active_connection_id_limit"] = profile.active_connection_id_limit
        for attr, val in (("_local_max_streams_bidi", profile.max_streams_bidi),
                          ("_local_max_streams_uni", profile.max_streams_uni)):
            lim = getattr(quic, attr)
            lim.value = lim.sent = val
            applied[attr[7:]] = val
    except AttributeError:      # pragma: no cover - aioquic iç yapısı değişirse
        pass
    return applied
