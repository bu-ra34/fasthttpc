"""fasthttpc.tls13 — sans-IO TLS 1.3 istemci çekirdeği ve ince I/O sarmalayıcıları.

- TLSClientConnection: soket kullanmayan durum makinesi (bytes in / events out)
- SyncTLSSocket:       socket.socket + çekirdek; EncryptedSocket arayüzü
- AsyncTLSStream:      asyncio StreamReader/Writer + çekirdek; await'li arayüz
"""
from .connection import TLSClientConnection, parse_alpn, application_traffic_secrets
from .errors import TLSError, TLSAlertError
from .events import (
    Event,
    HandshakeComplete,
    ApplicationData,
    NewSessionTicket,
    KeyUpdateReceived,
    AlertReceived,
    ConnectionClosed,
)
from .sync_socket import SyncTLSSocket
from .async_stream import AsyncTLSStream

__all__ = [
    "TLSClientConnection", "TLSError", "TLSAlertError",
    "Event", "HandshakeComplete", "ApplicationData", "NewSessionTicket",
    "KeyUpdateReceived", "AlertReceived", "ConnectionClosed",
    "SyncTLSSocket", "AsyncTLSStream", "parse_alpn", "application_traffic_secrets",
]
