"""
fasthttpc — istemci yapılandırması: :class:`Timeout` ve :class:`Limits`.

httpx'in ``Timeout``/``Limits`` arayüzüne benzer::

    from fasthttpc import Session, Timeout, Limits

    s = Session(
        timeout=Timeout(10.0, connect=5.0),           # read/write/pool = 10, connect = 5
        limits=Limits(max_connections=20, keepalive_expiry=30.0),
    )

Geriye dönük uyumluluk: ``Session(timeout=30)`` (float/int) hâlâ geçerlidir;
``Timeout.from_value()`` sayıyı tüm alanlara uygular. Eski
``Timeout(default, connect=..., read=...)`` çağrıları ve ``connect_timeout`` /
``read_timeout`` özellikleri aynen çalışır.
"""
from __future__ import annotations

import os
from typing import Optional, Union

_DEFAULT_TIMEOUT = 30.0
_UNSET = object()


class Timeout:
    """
    Zaman aşımı ayarları (saniye; ``None`` → sınırsız/varsayılan).

    Args:
        timeout: Belirtilmeyen tüm alanlar için varsayılan değer. Başka bir
                 :class:`Timeout` da verilebilir (kopyalanır).
        connect: TCP + TLS el sıkışma süresi.
        read:    Sunucudan veri okuma süresi.
        write:   Sunucuya veri yazma süresi.
        pool:    Havuzdan boş bağlantı bekleme süresi.
    """

    __slots__ = ("default", "connect", "read", "write", "pool")

    def __init__(
        self,
        timeout: "Union[float, int, Timeout, None]" = None,
        *,
        connect: object = _UNSET,
        read:    object = _UNSET,
        write:   object = _UNSET,
        pool:    object = _UNSET,
        default: object = _UNSET,
    ) -> None:
        if default is not _UNSET:  # eski timeout.Timeout(default=...) imzası
            if timeout is not None:
                raise TypeError("timeout ve default aynı anda verilemez.")
            timeout = default  # type: ignore[assignment]
        if isinstance(timeout, Timeout):
            base = timeout
            self.default = base.default
            vals = {"connect": base.connect, "read": base.read,
                    "write": base.write, "pool": base.pool}
        else:
            self.default = float(timeout) if timeout is not None else None
            vals = dict.fromkeys(("connect", "read", "write", "pool"), self.default)
        for name, given in (("connect", connect), ("read", read),
                            ("write", write), ("pool", pool)):
            if given is not _UNSET:
                vals[name] = None if given is None else float(given)  # type: ignore[arg-type]
            if vals[name] is not None and vals[name] < 0:
                raise ValueError(f"Timeout.{name} negatif olamaz: {vals[name]}")
        self.connect: Optional[float] = vals["connect"]
        self.read:    Optional[float] = vals["read"]
        self.write:   Optional[float] = vals["write"]
        self.pool:    Optional[float] = vals["pool"]

    @classmethod
    def from_value(cls, value: "Union[float, int, Timeout, None]") -> "Timeout":
        """float/int/Timeout/None → Timeout. ``None`` → 30 sn varsayılan."""
        if isinstance(value, cls):
            return value
        if isinstance(value, bool):
            raise TypeError("timeout bool olamaz; saniye (float) veya Timeout verin.")
        if isinstance(value, (int, float)):
            return cls(float(value))
        if value is None:
            return cls(_DEFAULT_TIMEOUT)
        raise TypeError(f"Geçersiz timeout değeri: {value!r}")

    # Geriye dönük uyumluluk (timeout.py API'si) -------------------------
    @property
    def connect_timeout(self) -> float:
        return self.connect if self.connect is not None else _DEFAULT_TIMEOUT

    @property
    def read_timeout(self) -> float:
        return self.read if self.read is not None else _DEFAULT_TIMEOUT

    @property
    def write_timeout(self) -> float:
        return self.write if self.write is not None else _DEFAULT_TIMEOUT

    @property
    def pool_timeout(self) -> float:
        return self.pool if self.pool is not None else _DEFAULT_TIMEOUT

    def as_dict(self) -> dict:
        return {"connect": self.connect, "read": self.read,
                "write": self.write, "pool": self.pool}

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Timeout) and self.as_dict() == other.as_dict()

    def __repr__(self) -> str:
        return (f"Timeout(connect={self.connect}, read={self.read}, "
                f"write={self.write}, pool={self.pool})")


class Limits:
    """
    Bağlantı havuzu sınırları.

    Args:
        max_connections:           Origin başına eşzamanlı en fazla bağlantı.
        max_keepalive_connections: Havuzda boşta tutulacak en fazla bağlantı
                                   (``None`` → ``max_connections``).
        keepalive_expiry:          Boştaki bağlantının kapatılmadan önce
                                   bekleyebileceği süre (saniye).
    """

    __slots__ = ("max_connections", "max_keepalive_connections", "keepalive_expiry")

    def __init__(
        self,
        *,
        max_connections:           int             = 10,
        max_keepalive_connections: Optional[int]   = None,
        keepalive_expiry:          Optional[float] = 30.0,
    ) -> None:
        for name, v in (("max_connections", max_connections),
                        ("max_keepalive_connections", max_keepalive_connections),
                        ("keepalive_expiry", keepalive_expiry)):
            if v is not None and v < 0:
                raise ValueError(f"Limits.{name} negatif olamaz: {v}")
        if not isinstance(max_connections, int) or max_connections < 1:
            raise ValueError("Limits.max_connections en az 1 olmalı.")
        self.max_connections = max_connections
        self.max_keepalive_connections = max_keepalive_connections
        self.keepalive_expiry = keepalive_expiry

    def apply_to_pool(self, pool) -> None:
        """Sınırları bir :class:`ConnectionPool` örneğine uygular."""
        pool.max_connections = self.max_connections
        pool.max_keepalive_connections = self.max_keepalive_connections
        # None → boşta kalma süresi sınırsız (havuz 0/None'ı "kontrol yok" sayar).
        pool.idle_timeout = self.keepalive_expiry

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Limits) and (
            self.max_connections, self.max_keepalive_connections, self.keepalive_expiry
        ) == (other.max_connections, other.max_keepalive_connections, other.keepalive_expiry)

    def __repr__(self) -> str:
        return (f"Limits(max_connections={self.max_connections}, "
                f"max_keepalive_connections={self.max_keepalive_connections}, "
                f"keepalive_expiry={self.keepalive_expiry})")


VERIFY_FALSE_MESSAGE = (
    "verify=False desteklenmez: fasthttpc sertifika doğrulamasını kapatmaya "
    "bilinçli olarak izin vermez (MITM'e açık bağlantı kurmak yerine hata "
    "vermeyi tercih eder). Kurumsal/özel bir CA kullanıyorsanız "
    "verify=\"/yol/ca.pem\" ile o CA bundle'ını verin."
)


def resolve_verify(verify: "bool | str | os.PathLike") -> Optional[str]:
    """``verify`` parametresini cert_validator'ın ``ca_path`` değerine çevirir.

    ``True`` → ``None`` (varsayılan güven deposu), yol → mutlak yol.
    ``False`` → :class:`ValueError` (bilinçli olarak desteklenmez).
    """
    if verify is True:
        return None
    if verify is False:
        raise ValueError(VERIFY_FALSE_MESSAGE)
    if isinstance(verify, (str, os.PathLike)):
        path = os.fspath(verify)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"verify için verilen CA bundle bulunamadı: {path!r}")
        return os.path.abspath(path)
    raise TypeError(f"verify True veya bir PEM dosya yolu olmalı, {type(verify).__name__} verildi.")
