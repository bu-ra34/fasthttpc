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
from typing import Optional, Union

__all__ = ["IOTimeouts", "SEND_CHUNK", "TOTAL_TIMEOUT_MESSAGE", "send_all", "write_timeout_error"]

# Düz (TLS'siz) gönderimde tek sendall() çağrısının en çok bayt sayısı: büyük bir gövde
# tek çağrıda gönderilseydi ``write`` tüm gövdenin süresi olurdu (Python 3.5+ sendall'da
# zaman aşımı toplam süredir); parça başına süre TLS'teki record başına süreyle aynı anlamı verir.
SEND_CHUNK = 65536

TOTAL_TIMEOUT_MESSAGE = "İstek toplam süre sınırını (Timeout.total) aştı."

_Data = Union[bytes, bytearray, memoryview]


def write_timeout_error(write: Optional[float], what: str = "veri") -> TimeoutError:
    """``Timeout.write`` aşıldığında yükseltilen hata (``TimeoutError``; async tarafla aynı sınıf)."""
    return TimeoutError(f"Yazma zaman aşımı: {what} Timeout.write={write} sn içinde gönderilemedi.")


class IOTimeouts:
    """Bir isteğin bağlantıya uyguladığı süreler.

    ``read``/``write``: işlem başına süre (saniye; ``None`` = sınırsız).
    ``deadline``: ``Timeout.total``'ın bitiş anı (``time.perf_counter``; ``None`` = yok).
    """

    __slots__ = ("read", "write", "deadline")

    def __init__(self, read: Optional[float], write: Optional[float],
                 deadline: Optional[float] = None) -> None:
        self.read = read
        self.write = write
        self.deadline = deadline

    def budget(self, base: Optional[float]) -> Optional[float]:
        """``base`` süresi, ``total``'ın kalan süresiyle kısaltılmış hâli.

        Toplam süre dolmuşsa ``TimeoutError`` (``Timeout.total`` mesajıyla)."""
        dl = self.deadline
        if dl is None:
            return base
        left = dl - time.perf_counter()
        if left <= 0:
            raise TimeoutError(TOTAL_TIMEOUT_MESSAGE)
        return left if base is None else min(base, left)

    def expired(self) -> bool:
        dl = self.deadline
        return dl is not None and time.perf_counter() >= dl

    def timeout_error(self, what: str = "veri") -> TimeoutError:
        """Gönderim/akış kontrolü beklemesi zaman aşımına uğradı: total mı write mı?"""
        if self.expired():
            return TimeoutError(TOTAL_TIMEOUT_MESSAGE)
        return write_timeout_error(self.write, what)

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
            t = io.budget(io.write)
            if t != cur:
                sock.settimeout(t)
                cur = t
            try:
                if view is None:
                    sock.sendall(data)
                    return
                sock.sendall(view[off:off + SEND_CHUNK])
            except TimeoutError:          # socket.timeout (3.10+: TimeoutError)
                raise io.timeout_error() from None
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
