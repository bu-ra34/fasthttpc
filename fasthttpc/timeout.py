"""
fasthttpc — Timeout

Bağlantı ve okuma zaman aşımlarını ayrı ayrı kontrol etmek için kullanılır.

Örnek::

    from fasthttpc.timeout import Timeout

    # connect için 5sn, read için 30sn
    t = Timeout(connect=5.0, read=30.0)

    # Her şey için tek değer
    t = Timeout(10.0)
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Union


@dataclass
class Timeout:
    """
    HTTP istek zaman aşımı ayarları.

    Args:
        default:  connect ve read için varsayılan değer (saniye).
                  connect veya read belirtilmezse bu değer kullanılır.
        connect:  TCP + TLS handshake zaman aşımı (saniye).
        read:     Sunucudan veri okuma zaman aşımı (saniye).

    Örnekler:
        >>> Timeout(30.0)               # her şey 30sn
        >>> Timeout(connect=5, read=60) # bağlantı 5sn, okuma 60sn
        >>> Timeout(10, read=60)        # bağlantı 10sn (default), okuma 60sn
    """

    default: Optional[float] = None
    connect: Optional[float] = None
    read:    Optional[float] = None

    def __init__(
        self,
        default: Optional[float] = None,
        *,
        connect: Optional[float] = None,
        read:    Optional[float] = None,
    ) -> None:
        self.default = default
        self.connect = connect if connect is not None else default
        self.read    = read    if read    is not None else default

    @classmethod
    def from_value(cls, value: "Union[float, int, Timeout, None]") -> "Timeout":
        """
        float/int/Timeout/None'dan Timeout objesi oluşturur.
        Session.__init__ içinde kullanılır — geriye dönük uyumluluk için.

        Args:
            value: Sayı, mevcut Timeout objesi ya da None.

        Returns:
            Timeout objesi.
        """
        if isinstance(value, cls):
            return value
        if isinstance(value, (int, float)):
            return cls(float(value))
        return cls(30.0)               

    @property
    def connect_timeout(self) -> float:
        """TCP bağlantı + TLS handshake için kullanılacak timeout değeri."""
        return self.connect if self.connect is not None else 30.0

    @property
    def read_timeout(self) -> float:
        """Sunucudan veri okuma için kullanılacak timeout değeri."""
        return self.read if self.read is not None else 30.0

    def __repr__(self) -> str:
        return f"Timeout(connect={self.connect}, read={self.read})"
