"""sans-IO TLS çekirdeğinin hata tipleri.

Hepsi ConnectionError'dan türer; böylece eski TLSAdapter yolunu yakalayan
`except ConnectionError` blokları çekirdek için de çalışır.
"""
from __future__ import annotations

try:  # faz1 tls_adapter.py'ye TLSProtocolError ekliyor; varsa ondan türet.
    from ..security.tls_adapter import TLSProtocolError as _Base  # type: ignore
except ImportError:  # pragma: no cover - baseline
    _Base = ConnectionError


class TLSError(_Base):
    """Handshake veya record katmanında protokol/doğrulama hatası."""


class TLSAlertError(TLSError):
    def __init__(self, level: int, description: int, msg: str = ""):
        self.level = level
        self.description = description
        super().__init__(msg or f"Sunucudan TLS alert alındı (level={level}, description={description})")
