"""Senkron ``Session.websocket`` uçtan uca (loopback, threaded sunucular).

Regresyonlar:
- ``conn.socket.settimeout(session.timeout)`` bir ``Timeout`` nesnesi alıyordu →
  her ``ws://`` bağlantısı ``TypeError`` ile düşüyordu.
- ``wss://`` el sıkışması profilin ALPN'ini (``h2, http/1.1``) öneriyordu; sunucu
  h2 seçerse HTTP/1.1 Upgrade bozuluyordu. Artık yalnızca ``http/1.1`` önerilir.
- Okuma zaman aşımı ``ws://`` yolunda sessizce "bağlantı kapandı" sayılıyordu.
"""
from __future__ import annotations

import base64
import hashlib
import socket
import ssl
import threading
import time

import pytest
from cryptography.hazmat.primitives import serialization

from fasthttpc import Session, Timeout
from fasthttpc.models.urls import URL
from fasthttpc.protocol.http2_parser import WebSocketConnection, WebSocketFrame

from tls13_fakeserver import PKI

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


@pytest.fixture(scope="module")
def pki():
    return PKI("localhost")


@pytest.fixture
def ca(pki, tmp_path):
    p = tmp_path / "ca.pem"
    p.write_bytes(pki.ca_pem())
    return str(p)


def _upgrade_response(head: bytes) -> bytes:
    key = [ln.split(b":", 1)[1].strip() for ln in head.split(b"\r\n")
           if ln.lower().startswith(b"sec-websocket-key")][0]
    acc = base64.b64encode(hashlib.sha1(key + GUID).digest())
    return (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + acc + b"\r\n\r\n")


class WSServer:
    """Threaded WebSocket echo sunucusu (düz TCP ya da stdlib ssl).

    echo=False: Upgrade'den sonra hiçbir şey göndermez (zaman aşımı testi).
    """

    def __init__(self, ctx: "ssl.SSLContext | None" = None, echo: bool = True):
        self.ctx, self.echo = ctx, echo
        self.heads: list[bytes] = []
        self.alpns: list["str | None"] = []
        self.errors: list[BaseException] = []
        self.ls = socket.socket()
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(8)
        self.port = self.ls.getsockname()[1]
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                c, _ = self.ls.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c):
        c.settimeout(10)
        s = c
        try:
            s = self.ctx.wrap_socket(c, server_side=True) if self.ctx else c   # c'yi devralır
            if self.ctx:
                self.alpns.append(s.selected_alpn_protocol())
            head = b""
            while b"\r\n\r\n" not in head:
                d = s.recv(4096)
                if not d:
                    return
                head += d
            head, _, rest = head.partition(b"\r\n\r\n")
            self.heads.append(head)
            s.sendall(_upgrade_response(head))
            buf = bytearray(rest)
            while True:
                frame, n = WebSocketFrame.parse(bytes(buf))
                if frame:
                    del buf[:n]
                    if frame.opcode == WebSocketFrame.OP_CLOSE:
                        return
                    if self.echo:
                        s.sendall(WebSocketFrame(frame.opcode, b"echo:" + frame.payload,
                                                 mask=False).serialize())
                    continue
                d = s.recv(4096)
                if not d:
                    return
                buf += d
        except (OSError, ssl.SSLError) as e:
            self.errors.append(e)
        finally:
            s.close()

    def close(self):
        self.ls.close()


def _tls_ctx(pki, tmp_path, alpn):
    cert, key = tmp_path / "ws.pem", tmp_path / "ws.key"
    cert.write_bytes(pki.cert.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(pki.key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    ctx.set_alpn_protocols(alpn)
    return ctx


def _talk(ws):
    ws.send_text("merhaba")
    assert ws.recv_text() == "echo:merhaba"
    ws.send_binary(b"\x00\x01\x02")
    assert ws.recv() == (WebSocketFrame.OP_BINARY, b"echo:\x00\x01\x02")


# ------------------------------------------------------------------ ws://
def test_ws_duz_tcp_echo():
    srv = WSServer()
    try:
        with Session(timeout=5) as s:
            with s.websocket(f"ws://127.0.0.1:{srv.port}/chat") as ws:
                _talk(ws)
        assert srv.heads[0].startswith(b"GET /chat HTTP/1.1\r\n")
        assert f"Host: 127.0.0.1:{srv.port}".encode() in srv.heads[0]
    finally:
        srv.close()


def test_ws_okuma_zaman_asimi_uygulanir():
    """Sessiz sunucuda recv(), oturumun read zaman aşımıyla TimeoutError verir
    (eskiden ya TypeError ya da sessizce 'kapandı' dönüyordu)."""
    srv = WSServer(echo=False)
    try:
        with Session(timeout=Timeout(5, read=0.5)) as s:
            with s.websocket(f"ws://127.0.0.1:{srv.port}/") as ws:
                assert ws._conn.socket.gettimeout() == pytest.approx(0.5)
                t0 = time.monotonic()
                with pytest.raises(TimeoutError):
                    ws.recv()
                assert 0.3 < time.monotonic() - t0 < 4
    finally:
        srv.close()


def test_ws_istek_duzeyi_timeout_yoksa_varsayilan_float_kullanilir():
    """Timeout(read=None) → settimeout'a Timeout nesnesi değil float gider."""
    srv = WSServer()
    try:
        with Session(timeout=Timeout(5, read=None)) as s:
            with s.websocket(f"ws://127.0.0.1:{srv.port}/") as ws:
                assert isinstance(ws._conn.socket.gettimeout(), float)
                _talk(ws)
    finally:
        srv.close()


# ------------------------------------------------------------------ wss://
def test_wss_yalnizca_http11_alpn_onerir(pki, ca, tmp_path):
    """Sunucu h2'yi tercih eder (sunucu önceliği); istemci h2 önerseydi h2 seçilir
    ve Upgrade bozulurdu. Sync yol artık yalnızca http/1.1 önermeli."""
    srv = WSServer(_tls_ctx(pki, tmp_path, ["h2", "http/1.1"]))
    try:
        with Session(impersonate="chrome_131", verify=ca, timeout=5) as s:
            with s.websocket(f"wss://localhost:{srv.port}/soket") as ws:
                _talk(ws)
                assert ws._wire.state.get("alpn") == "http/1.1"
        assert srv.alpns == ["http/1.1"]
        assert srv.heads[0].startswith(b"GET /soket HTTP/1.1\r\n")
    finally:
        srv.close()


def test_wss_clienthello_alpn_listesi(monkeypatch):
    """ClientHello'daki ALPN extension'ı yalnızca 'http/1.1' içerir."""
    from fasthttpc.security import tls_adapter

    captured: list[bytes] = []
    class _Stop(Exception):
        pass

    class CapSock:
        def sendall(self, data):
            captured.append(bytes(data))
            raise _Stop

        def getpeername(self):
            return ("127.0.0.1", 443)

    with pytest.raises(_Stop):
        tls_adapter.TLSAdapter.negotiate(CapSock(), "localhost", "chrome_131",
                                         alpn=["http/1.1"])
    from fasthttpc.security.tls12 import parse_client_hello
    assert parse_client_hello(captured[0][5:]).alpn == ["http/1.1"]   # record başlığı atlanır
    with pytest.raises(_Stop):                    # karşılaştırma: profil varsayılanı h2 içerir
        tls_adapter.TLSAdapter.negotiate(CapSock(), "localhost", "chrome_131")
    assert parse_client_hello(captured[1][5:]).alpn == ["h2", "http/1.1"]

    # Uçtan uca: WebSocketConnection.handshake negotiate'e alpn=["http/1.1"] geçirir.
    seen: dict = {}

    def fake_negotiate(sock, host, profile, **kw):
        seen.update(kw)
        raise _Stop

    monkeypatch.setattr(tls_adapter.TLSAdapter, "negotiate", staticmethod(fake_negotiate))
    sess = _FakeSession(_FakeConn(object()))
    with pytest.raises(_Stop):
        WebSocketConnection.handshake(sess, "wss://example.com/")
    assert seen["alpn"] == ["http/1.1"]
    assert sess.pool.conn.closed and sess.pool.released


class _FakeConn:
    def __init__(self, sock, tls=False):
        self.socket = sock
        self.tls_established = tls
        self.h2_conn = None
        self.closed = False

    def close(self):
        self.closed = True


class _FakePool:
    def __init__(self, conn):
        self.conn = conn
        self.released = False

    def acquire(self, url):
        return self.conn

    def release(self, conn):
        self.released = True


class _FakeSession:
    timeout = Timeout(5)
    impersonate = "chrome_131"

    def __init__(self, conn):
        self.pool = _FakePool(conn)


def test_wss_sunucu_yine_de_h2_secerse_acik_hata():
    class H2Sock:
        state = {"alpn": "h2"}

        class raw_socket:
            @staticmethod
            def settimeout(_):
                pass

        def send_record(self, *_a, **_k):
            raise AssertionError("h2 bağlantısına HTTP/1.1 Upgrade yazılmamalı")

    sess = _FakeSession(_FakeConn(H2Sock(), tls=True))
    with pytest.raises(ConnectionError, match="http/1.1"):
        WebSocketConnection.handshake(sess, "wss://example.com/")
    assert sess.pool.conn.closed and sess.pool.released


def test_wss_varsayilan_port_443():
    assert URL("wss://example.com/x").port == 443
    assert str(URL("wss://example.com/x")) == "wss://example.com/x"
    assert URL("ws://example.com/x").port == 80
