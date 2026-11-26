"""Senkron soket G/Ç'si için istek başına zaman aşımları (``Timeout.read`` / ``write`` / ``total``).

Bir bağlantı (HTTP/1.1 ya da HTTP/2) senkron tarafta aynı anda yalnızca bir
iş parçacığına kiralanır. İsteği yapan iş parçacığı, bağlantıyı aldıktan sonra
kendi :class:`IOTimeouts` nesnesini bağlantının soket sarmalayıcısına koyar
(``sock.io``); o bağlantıdaki her gönderim ve okuma bu nesneye bakar. Böylece
bir isteğin süreleri başka bir isteğe (başka iş parçacığına) sızmaz ve akış
gövdesi başka bir iş parçacığında okunsa da isteğin süreleri geçerli kalır.

Gönderim kuralı (:func:`send_all`): her gönderim işlemi — en çok bir TLS
record'u ya da düz HTTP'de en çok ``SEND_CHUNK`` bayt — ``write`` saniye
içinde işletim sistemine teslim edilmeli; varsa ``total``'ın kalan süresiyle
kısaltılır. Gönderimden sonra soketin zaman aşımı eski değerine (okuma
süresine) döner, böylece okumalar ``read`` ile sınırlı kalır.
"""
from __future__ import annotations

import socket
import time
from typing import Callable, Optional, Union

__all__ = ["IOTimeouts", "SEND_CHUNK", "TOTAL_TIMEOUT_MESSAGE", "is_attributed", "send_all",
           "total_timeout_error", "write_timeout_error"]

# Düz (TLS'siz) gönderimde tek sendall() çağrısının en çok bayt sayısı: büyük bir gövde
# tek çağrıda gönderilseydi ``write`` tüm gövdenin süresi olurdu (Python 3.5+ sendall'da
# zaman aşımı toplam süredir); parça başına süre TLS'teki record başına süreyle aynı anlamı verir.
SEND_CHUNK = 65536

TOTAL_TIMEOUT_MESSAGE = "İstek toplam süre sınırını (Timeout.total) aştı."

_Data = Union[bytes, bytearray, memoryview]

# Nedeni belirlenmiş zaman aşımı hatalarına konan öznitelik ("total" | "write"). Bir üst
# katman bu hatayı yeniden yorumlamaz (ör. gönderim sırasında oluşan yazma hatası).
_KIND = "fasthttpc_timeout"


def _mark(e: TimeoutError, kind: str) -> TimeoutError:
    setattr(e, _KIND, kind)
    return e


def is_attributed(e: BaseException) -> bool:
    """Hata nedeni (total/write) zaten belirlenmiş bir zaman aşımı mı?"""
    return getattr(e, _KIND, None) is not None


def total_timeout_error() -> TimeoutError:
    """``Timeout.total`` aşıldı (``TimeoutError``)."""
    return _mark(TimeoutError(TOTAL_TIMEOUT_MESSAGE), "total")


def write_timeout_error(write: Optional[float], what: str = "veri") -> TimeoutError:
    """``Timeout.write`` aşıldığında yükseltilen hata (``TimeoutError``; async tarafla aynı sınıf)."""
    return _mark(TimeoutError(
        f"Yazma zaman aşımı: {what} Timeout.write={write} sn içinde gönderilemedi."), "write")


class IOTimeouts:
    """Bir isteğin bağlantıya uyguladığı süreler.

    ``read``/``write``: işlem başına süre (saniye; ``None`` = sınırsız).
    ``deadline``: ``Timeout.total``'ın bitiş anı (``clock`` cinsinden; ``None`` = yok).
    ``clock``: varsayılan ``time.perf_counter`` (testler kaba bir saat verebilir).

    Zaman aşımının NEDENİ, soket zaman aşımı kurulurken belirlenir (:meth:`limit`):
    süre ``total``'ın kalanıyla kısaltıldıysa total, değilse işlem süresi. Hata sonrası
    saati yeniden okuyup bitiş anıyla karşılaştırmak kaba çözünürlüklü saatlerde
    (Windows) erken okuyup yanlış nedene bağlayabilirdi.
    """

    __slots__ = ("read", "write", "deadline", "clock")

    def __init__(self, read: Optional[float], write: Optional[float],
                 deadline: Optional[float] = None,
                 clock: Callable[[], float] = time.perf_counter) -> None:
        self.read = read
        self.write = write
        self.deadline = deadline
        self.clock = clock

    def limit(self, base: Optional[float]) -> "tuple[Optional[float], bool]":
        """``(süre, total_mi)``: ``base``'in kalan ``total`` ile kısaltılmış hâli ve süreyi
        ``total``'ın belirleyip belirlemediği. Toplam süre dolmuşsa ``TimeoutError``."""
        dl = self.deadline
        if dl is None:
            return base, False
        left = dl - self.clock()
        if left <= 0:
            raise total_timeout_error()
        if base is None or left < base:
            return left, True
        return base, False

    def budget(self, base: Optional[float]) -> Optional[float]:
        """``base`` süresi, ``total``'ın kalan süresiyle kısaltılmış hâli.

        Toplam süre dolmuşsa ``TimeoutError`` (``Timeout.total`` mesajıyla)."""
        return self.limit(base)[0]

    def timeout_error(self, by_total: bool, what: str = "veri") -> TimeoutError:
        """Kurulan süre doldu: :meth:`limit`'in döndürdüğü ``total_mi``'ye göre hata."""
        return total_timeout_error() if by_total else write_timeout_error(self.write, what)

    def __repr__(self) -> str:
        return f"IOTimeouts(read={self.read}, write={self.write}, deadline={self.deadline})"


def send_all(sock: socket.socket, data: _Data, io: Optional[IOTimeouts]) -> None:
    """``sock.sendall(data)``; ``io`` verilmişse her parça ``io.write`` (kalan ``total`` ile
    kısaltılmış) içinde gönderilmeli, sonra soketin zaman aşımı okuma süresine (``io.read``)
    döner.

    Soketin gönderim dışındaki zaman aşımı her zaman ``io.read``'dir (ya da ``total`` varken
    okumadan hemen önce yeniden hesaplanan değer); bu yüzden ``gettimeout()`` çağrılmaz ve
    ``write == read`` iken (``total`` yokken) hiç ``settimeout`` sistem çağrısı yapılmaz.
    ``io`` yoksa davranış eskisiyle aynıdır (soketin o anki zaman aşımı)."""
    if io is None:
        sock.sendall(data)
        return
    prev = cur = io.read
    n = len(data)
    view = memoryview(data) if n > SEND_CHUNK else None
    try:
        off = 0
        while True:
            t, by_total = io.limit(io.write)
            if t != cur:
                sock.settimeout(t)
                cur = t
            try:
                if view is None:
                    sock.sendall(data)
                    return
                sock.sendall(view[off:off + SEND_CHUNK])
            except TimeoutError:          # socket.timeout (3.10+: TimeoutError)
                raise io.timeout_error(by_total) from None
            off += SEND_CHUNK
            if off >= n:
                return
    finally:
        if view is not None:
            view.release()
        if cur != prev:
            try:
                sock.settimeout(prev)
            except OSError:               # soket bu arada kapandı
                pass
