"""``http3=`` parametresi seçenekleri (aioquic'siz import edilebilir)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class Http3Options:
    """HTTP/3 davranışı.

    mode:            ``"auto"``  -> ilk istek h2/h1; Alt-Svc ile keşfedilince h3, başarısızsa
                                    sessizce h2'ye düş. ``"force"`` -> doğrudan h3, düşme YOK.
    connect_timeout: QUIC el sıkışma zaman aşımı (kısa tutulur: UDP engelliyse hızlı düşüş).
    disable_for:     h3 başarısız olunca o host için h3'ün kapalı kalacağı süre (sn).
    idle_timeout:    QUIC boşta kalma zaman aşımı; bağlantı bu kadar kullanılmazsa yeniden kurulur.
    """
    mode: str = "auto"
    connect_timeout: float = 3.0
    disable_for: float = 300.0
    idle_timeout: float = 30.0

    @classmethod
    def from_value(cls, value) -> "Optional[Http3Options]":
        if value is None or value is False:
            return None
        if value is True:
            return cls()
        if isinstance(value, cls):
            if value.mode not in ("auto", "force"):
                raise ValueError(f"http3 mode 'auto' veya 'force' olmalı: {value.mode!r}")
            return value
        if value == "force":
            return cls(mode="force")
        if value == "auto":
            return cls()
        raise ValueError(f"http3 True/False, 'force' veya Http3Options olmalı: {value!r}")
