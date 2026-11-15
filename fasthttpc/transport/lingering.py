"""Fatal alert sonrası düzenli kapanış (lingering close).

Alım tamponunda OKUNMAMIŞ veri varken ``close()`` TCP FIN yerine RST gönderir. RST, karşı
tarafın henüz okumadığı verileri siler — Windows'ta henüz gönderdiğimiz fatal alert dahil
(sunucu alert'i hiç göremez, yalnızca "bağlantı sıfırlandı" görür; Linux'ta kuyruktaki veri
okunabilir kalır ama sonraki okuma ECONNRESET verir). Çözüm: alert'i gönderdikten sonra yazma
yönünü kapat (FIN) ve karşı taraf kapatana kadar — kısa, sınırlı süre — gelen veriyi boşalt.

Async yol (asyncio / trio) için eşdeğeri :func:`async_send_and_drain`'dir.
"""
from __future__ import annotations

import socket
import time
from typing import Any

#: Boşaltma için en fazla bekleme (sn). Karşı taraf fatal alert'ten sonra hemen kapatır;
#: kapatmayan (ya da yavaş) bir eş hata yolunu en fazla bu kadar uzatır.
LINGER_MAX_WAIT = 0.25
#: Boşaltırken en fazla okunacak bayt (kötü niyetli eşin akışı sonsuza uzatmasını önler).
LINGER_MAX_BYTES = 1 << 20


def shutdown_and_drain(sock: socket.socket, max_wait: float = LINGER_MAX_WAIT,
                       max_bytes: int = LINGER_MAX_BYTES) -> None:
    """``sock``'un yazma yönünü kapatır, eş EOF verene (ya da sınıra) kadar okuyup atar.

    Hata vermez (best-effort); soket kapatılmaz — çağıran kapatır. Soket zaman aşımı
    (``gettimeout``) sonunda eski değerine döner."""
    try:
        old = sock.gettimeout()
        sock.shutdown(socket.SHUT_WR)
    except OSError:
        return
    end = time.perf_counter() + max_wait
    got = 0
    try:
        while got < max_bytes:
            left = end - time.perf_counter()
            if left <= 0:
                break
            sock.settimeout(left)
            data = sock.recv(65536)
            if not data:
                break
            got += len(data)
    except OSError:
        pass
    finally:
        try:
            sock.settimeout(old)
        except OSError:
            pass


async def async_send_and_drain(reader: Any, writer: Any, data: bytes,
                               max_wait: float = LINGER_MAX_WAIT,
                               max_bytes: int = LINGER_MAX_BYTES) -> None:
    """:func:`shutdown_and_drain`'in async (asyncio StreamReader/Writer ya da trio'da
    ``AnyioStream``) karşılığı: ``data``'yı (ör. fatal alert) gönderir, yazma yönünü kapatır
    (``write_eof``, destekleniyorsa) ve eş EOF verene (ya da sınıra) kadar okuyup atar.

    Hata vermez (best-effort; iptal dışında): çağıranın asıl istisnasını maskelememeli.
    Akış kapatılmaz — çağıran kapatır. Gönderim + boşaltma toplam ``max_wait`` ile sınırlı."""
    if not data:
        return
    from .. import _backend as B

    async def go() -> None:
        writer.write(data)
        await writer.drain()
        can_eof = getattr(writer, "can_write_eof", None)
        if can_eof is None or not can_eof():
            return
        writer.write_eof()
        got = 0
        while got < max_bytes:
            chunk = await reader.read(65536)
            if not chunk:
                break
            got += len(chunk)

    try:
        if writer.is_closing():
            return
        await B.wait_for(go(), max_wait)
    except Exception:  # noqa: BLE001 - best-effort; asıl hata çağıranda yükselir
        pass
