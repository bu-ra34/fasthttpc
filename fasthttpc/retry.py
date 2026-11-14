"""
fasthttpc — yeniden deneme politikası (urllib3 ``Retry`` benzeri).

Örnek::

    from fasthttpc import Session, Retry

    retry = Retry(total=5, backoff_factor=0.5, status_forcelist=(502, 503, 504))
    with Session(retries=retry) as s:
        r = s.get("https://example.com/api")

``Session(retries=3)`` kısayolu ``Retry(total=3)`` ile eşdeğerdir.

Kurallar:
  * Yalnızca ``allowed_methods`` içindeki metotlar yeniden denenir
    (varsayılan: idempotent metotlar — GET, HEAD, PUT, DELETE, OPTIONS, TRACE).
    POST/PATCH yeniden denenmez; istenirse ``allowed_methods=None`` ile tüm
    metotlar açılabilir.
  * Bağlantı hataları (``ConnectionError``, ``TimeoutError``, ``OSError``)
    yeniden denenir; sertifika doğrulama hataları ASLA denenmez.
  * ``status_forcelist`` içindeki yanıtlarda yeniden denenir; ``Retry-After``
    başlığı (saniye veya HTTP-date) varsa bekleme süresi olarak kullanılır.
    (Kötü niyetli/hatalı sunucuya karşı ``backoff_max`` ile sınırlanır.)
  * Bekleme: ``backoff_factor * 2 ** (n - 1)`` (n = ardışık deneme sayısı),
    en fazla ``backoff_max``.
  * Denemeler tükendiğinde son yanıt döner / son hata yeniden fırlatılır.
"""
from __future__ import annotations

import email.utils
import time
from typing import Any, Iterable, Optional

DEFAULT_ALLOWED_METHODS = frozenset({"GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"})
RETRY_AFTER_STATUS_CODES = frozenset({413, 429, 503})
DEFAULT_BACKOFF_MAX = 120.0

# Yeniden denenecek ağ hataları. CertificateValidationError Exception'dan
# türer (OSError değil), dolayısıyla buraya hiç girmez.
RETRYABLE_ERRORS: tuple[type[BaseException], ...] = (ConnectionError, TimeoutError, OSError)


class Retry:
    """
    Args:
        total:            Azami yeniden deneme sayısı (ilk istek hariç).
                          ``0`` → yeniden deneme yok.
        backoff_factor:   Üstel bekleme çarpanı (saniye). ``0`` → beklemeden dene.
        backoff_max:      Tek bir bekleme süresinin üst sınırı (saniye).
        status_forcelist: Yeniden denenecek HTTP durum kodları.
        allowed_methods:  Yeniden denenebilecek metotlar; ``None`` → hepsi.
        respect_retry_after_header: ``Retry-After`` başlığını kullan.
        retry_on_connection_errors: Ağ hatalarında yeniden dene.
    """

    def __init__(
        self,
        total: int = 3,
        *,
        backoff_factor: float = 0.0,
        backoff_max: float = DEFAULT_BACKOFF_MAX,
        status_forcelist: Iterable[int] = (),
        allowed_methods: Optional[Iterable[str]] = DEFAULT_ALLOWED_METHODS,
        respect_retry_after_header: bool = True,
        retry_on_connection_errors: bool = True,
    ) -> None:
        if total < 0:
            raise ValueError("Retry.total negatif olamaz.")
        if backoff_factor < 0 or backoff_max < 0:
            raise ValueError("Retry bekleme değerleri negatif olamaz.")
        self.total = int(total)
        self.backoff_factor = float(backoff_factor)
        self.backoff_max = float(backoff_max)
        self.status_forcelist = frozenset(status_forcelist)
        self.allowed_methods = (
            None if allowed_methods is None
            else frozenset(m.upper() for m in allowed_methods)
        )
        self.respect_retry_after_header = respect_retry_after_header
        self.retry_on_connection_errors = retry_on_connection_errors

    @classmethod
    def from_value(cls, value: "Retry | int | bool | None") -> "Retry":
        """Session(retries=...) değerini normalleştirir. None/False → 0 deneme."""
        if isinstance(value, cls):
            return value
        if value is None or value is False:
            return cls(0)
        if value is True:
            return cls()
        if isinstance(value, int):
            return cls(value)
        raise TypeError(f"Geçersiz retries değeri: {value!r} (int veya Retry bekleniyor)")

    # --- kararlar --------------------------------------------------------

    def is_method_retryable(self, method: str) -> bool:
        return self.allowed_methods is None or method.upper() in self.allowed_methods

    def should_retry_status(self, method: str, status_code: int, attempt: int) -> bool:
        """``attempt``: şimdiye kadar yapılmış yeniden deneme sayısı (0'dan başlar)."""
        return (
            attempt < self.total
            and status_code in self.status_forcelist
            and self.is_method_retryable(method)
        )

    def should_retry_error(self, method: str, error: BaseException, attempt: int) -> bool:
        return (
            attempt < self.total
            and self.retry_on_connection_errors
            and isinstance(error, RETRYABLE_ERRORS)
            and self.is_method_retryable(method)
        )

    # --- bekleme ---------------------------------------------------------

    def get_backoff_time(self, attempt: int) -> float:
        """``attempt``: kaçıncı yeniden deneme (1'den başlar)."""
        if self.backoff_factor <= 0 or attempt <= 0:
            return 0.0
        return float(min(self.backoff_max, self.backoff_factor * (2 ** (attempt - 1))))

    @staticmethod
    def parse_retry_after(value: str) -> Optional[float]:
        """``Retry-After`` değerini saniyeye çevirir (delta-seconds veya HTTP-date)."""
        value = (value or "").strip()
        if not value:
            return None
        if value.isdigit():
            return float(value)
        try:
            dt = email.utils.parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError):
            return None
        if dt is None:
            return None
        return max(0.0, dt.timestamp() - time.time())

    def get_retry_after(self, response: Any) -> Optional[float]:
        if response is None or not self.respect_retry_after_header:
            return None
        if response.status_code not in RETRY_AFTER_STATUS_CODES:
            return None
        return self.parse_retry_after(response.headers.get("retry-after", ""))

    def get_delay(self, attempt: int, response: Any = None) -> float:
        """Bir sonraki denemeden önce beklenecek süre. Retry-After önceliklidir."""
        retry_after = self.get_retry_after(response)
        if retry_after is not None:
            return min(retry_after, self.backoff_max)
        return self.get_backoff_time(attempt)

    def __repr__(self) -> str:
        return (f"Retry(total={self.total}, backoff_factor={self.backoff_factor}, "
                f"status_forcelist={sorted(self.status_forcelist)})")
