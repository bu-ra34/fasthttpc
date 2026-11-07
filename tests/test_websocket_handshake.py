"""WebSocket Upgrade handshake doğrulaması (RFC 6455 §4.1)."""
import base64
import hashlib
import re

import pytest

from fasthttpc.protocol.http2_parser import (
    WebSocketConnection, WebSocketFrame, _validate_ws_handshake_response,
)
from tls_fakes import FakeSocket

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


ACC = _accept("dGhlIHNhbXBsZSBub25jZQ==")


def _head(status="HTTP/1.1 101 Switching Protocols", accept=ACC, extra=b""):
    h = status.encode() + b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
    if accept is not None:
        h += b"Sec-WebSocket-Accept: " + accept.encode() + b"\r\n"
    return h + extra


def test_rfc_ornegi_kabul_edilir():
    assert ACC == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    _validate_ws_handshake_response(_head().rstrip(b"\r\n"), ACC)


@pytest.mark.parametrize("status", [
    "HTTP/1.1 200 OK", "HTTP/1.1 1010 X", "HTTP/1.1 301 Moved 101",
    "HTTP/1.1 400 101", "garbage", "HTTP/1.1 10l X",
])
def test_101_disi_status_reddedilir(status):
    with pytest.raises(ConnectionError):
        _validate_ws_handshake_response(_head(status), ACC)


def test_accept_yoksa_reddedilir():
    with pytest.raises(ConnectionError, match="Sec-WebSocket-Accept yok"):
        _validate_ws_handshake_response(_head(accept=None), ACC)


def test_accept_hataliysa_reddedilir():
    with pytest.raises(ConnectionError, match="MITM"):
        _validate_ws_handshake_response(_head(accept="AAAA"), ACC)


def test_cift_accept_reddedilir():
    with pytest.raises(ConnectionError):
        _validate_ws_handshake_response(_head(extra=b"Sec-WebSocket-Accept: " + ACC.encode()), ACC)


def test_upgrade_ve_connection_zorunlu():
    with pytest.raises(ConnectionError, match="Upgrade: websocket"):
        _validate_ws_handshake_response(
            b"HTTP/1.1 101 X\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + ACC.encode(), ACC)
    with pytest.raises(ConnectionError, match="Connection: Upgrade"):
        _validate_ws_handshake_response(
            b"HTTP/1.1 101 X\r\nUpgrade: WebSocket\r\nConnection: keep-alive\r\n"
            b"Sec-WebSocket-Accept: " + ACC.encode(), ACC)
    # büyük/küçük harf ve token listesi
    _validate_ws_handshake_response(
        b"HTTP/1.1 101 X\r\nupgrade: WebSocket\r\nconnection: keep-alive, Upgrade\r\n"
        b"sec-websocket-accept: " + ACC.encode(), ACC)


# ---- Uçtan uca (ws://, sahte havuz) ------------------------------------------

class _Conn:
    def __init__(self, sock):
        self.socket = sock
        self.tls_established = False
        self.closed = False

    def close(self):
        self.closed = True


class _Pool:
    def __init__(self, conn):
        self.conn = conn
        self.released = False

    def acquire(self, url):
        return self.conn

    def release(self, conn):
        self.released = True


class _Session:
    timeout = 5
    impersonate = None

    def __init__(self, sock):
        self.pool = _Pool(_Conn(sock))


def _server(status=b"101 Switching Protocols", bad_accept=False, trailing=b""):
    def on_send(data):
        m = re.search(rb"Sec-WebSocket-Key: (\S+)", data)
        if not m:
            return b""
        acc = "yanlis" if bad_accept else _accept(m.group(1).decode())
        return (b"HTTP/1.1 " + status + b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: " + acc.encode() + b"\r\n\r\n" + trailing)
    return on_send


def test_handshake_basarili_ve_ardindan_gelen_frame_kaybolmaz():
    frame = WebSocketFrame(WebSocketFrame.OP_TEXT, b"selam", mask=False).serialize()
    sock = FakeSocket(on_send=_server(trailing=frame))
    ws = WebSocketConnection.handshake(_Session(sock), "ws://example.com/chat")
    assert ws.recv() == (WebSocketFrame.OP_TEXT, b"selam")


def test_handshake_200_reddedilir_ve_baglanti_birakilir():
    sock = FakeSocket(on_send=_server(status=b"200 OK"))
    sess = _Session(sock)
    with pytest.raises(ConnectionError, match="101 bekleniyordu"):
        WebSocketConnection.handshake(sess, "ws://example.com/")
    assert sess.pool.conn.closed and sess.pool.released


def test_handshake_hatali_accept_reddedilir():
    sock = FakeSocket(on_send=_server(bad_accept=True))
    with pytest.raises(ConnectionError, match="MITM"):
        WebSocketConnection.handshake(_Session(sock), "ws://example.com/")


def test_handshake_yanit_yarida_kesilirse_hata():
    sock = FakeSocket(on_send=lambda d: b"HTTP/1.1 101 Switching")
    with pytest.raises(ConnectionError, match="tamamlanmadan"):
        WebSocketConnection.handshake(_Session(sock), "ws://example.com/")


def test_buyuk_frame_parcali_gelince_dogru_birlesir():
    payload = bytes(range(256)) * 400
    frame = WebSocketFrame(WebSocketFrame.OP_BINARY, payload, mask=False).serialize()
    sock = FakeSocket(on_send=_server(trailing=frame), chunk=1000)
    ws = WebSocketConnection.handshake(_Session(sock), "ws://example.com/")
    assert ws.recv() == (WebSocketFrame.OP_BINARY, payload)
