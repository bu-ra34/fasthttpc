"""Sarmalayıcıların ortak kısmı: çekirdek olaylarını EncryptedSocket.recv_record
dönüşüne ((içerik, iç_content_type)) çevirme."""
from __future__ import annotations

from collections import deque
from typing import Optional

from .events import (
    ApplicationData, NewSessionTicket, KeyUpdateReceived,
    AlertReceived, ConnectionClosed, HandshakeComplete,
)


class RecordQueue:
    def __init__(self):
        self._q: deque = deque()

    def extend(self, events) -> None:
        self._q.extend(events)

    def pop(self, skip_post_handshake: bool) -> Optional[tuple[bytes, int]]:
        """Bir sonraki (content, type) çiftini döner; yoksa None."""
        while self._q:
            ev = self._q.popleft()
            if isinstance(ev, ApplicationData):
                return ev.data, 23
            if isinstance(ev, (NewSessionTicket, KeyUpdateReceived)):
                if skip_post_handshake:
                    continue
                return ev.raw, 22
            if isinstance(ev, (AlertReceived, ConnectionClosed)):
                return ev.raw, 21
            if isinstance(ev, HandshakeComplete):
                continue
        return None

    def pop_data(self) -> Optional[bytes]:
        """Sıradaki olay uygulama verisiyse onu döner; değilse None (olay kuyrukta kalır).

        Araya giren NewSessionTicket/KeyUpdate/HandshakeComplete atlanır
        (``pop(skip_post_handshake=True)`` ile aynı); alert/kapanış TÜKETİLMEZ ki
        okuyucu önce tampondaki veriyi teslim etsin, sonra kapanışı görsün."""
        q = self._q
        while q:
            ev = q[0]
            if isinstance(ev, ApplicationData):
                q.popleft()
                return ev.data
            if isinstance(ev, (NewSessionTicket, KeyUpdateReceived, HandshakeComplete)):
                q.popleft()
                continue
            return None
        return None
