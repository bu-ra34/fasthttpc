"""sans-IO TLS çekirdeğinin ürettiği olaylar.

`TLSClientConnection.receive_data()` gelen byte'ları işler ve bu sınıfların
örneklerinden oluşan bir liste döner. Olaylar telde geldikleri sırayla
listelenir; her şifreli application_data record'u ayrı bir ApplicationData
olayıdır (record sınırları korunur — EncryptedSocket.recv_record uyumluluğu
için gerekli).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


class Event:
    """Tüm olayların taban sınıfı."""


@dataclass
class HandshakeComplete(Event):
    cipher_suite: int
    alpn: str
    peer_certificate: Any = None          # cryptography x509.Certificate
    signature_scheme: Optional[int] = None


@dataclass
class ApplicationData(Event):
    data: bytes


@dataclass
class NewSessionTicket(Event):
    raw: bytes                            # 4 byte hs header dahil tam mesaj


@dataclass
class KeyUpdateReceived(Event):
    raw: bytes
    update_requested: bool


@dataclass
class AlertReceived(Event):
    """Sunucudan gelen (close_notify DIŞINDAKİ) alert. Bağlantı kapanır."""
    level: int
    description: int

    @property
    def raw(self) -> bytes:
        return bytes([self.level, self.description])


@dataclass
class ConnectionClosed(Event):
    """Sunucu close_notify gönderdi (düzenli kapanış)."""
    raw: bytes = field(default=b"\x01\x00")
