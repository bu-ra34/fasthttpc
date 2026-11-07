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
