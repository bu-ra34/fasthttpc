"""SyncTLSSocket ve AsyncTLSStream sarmalayıcı testleri (yerel sahte sunucu)."""
import asyncio
import inspect
import socket
import threading

import pytest

from fasthttpc.security import cert_validator as cv
from fasthttpc.tls13 import SyncTLSSocket, AsyncTLSStream, TLSError

from tls13_fakeserver import PKI, FakeTLS13Server, async_serve, sync_serve, http_responder

HOST = "example.com"


@pytest.fixture(scope="module")
def pki():
    return PKI(HOST)


@pytest.fixture
def trust(pki, tmp_path, monkeypatch):
    ca = tmp_path / "ca.pem"
    ca.write_bytes(pki.ca_pem())
    if "ca_path" in inspect.signature(cv.validate_server_certificate).parameters:
        return {"ca_path": str(ca)}

    class _Certifi:
        @staticmethod
        def where():
            return str(ca)

    monkeypatch.setattr(cv, "certifi", _Certifi)
    return {}


# ------------------------------------------------------------------ sync
def _sync_pair(pki, handler=None, **server_kw):
    a, b = socket.socketpair()
    server = FakeTLS13Server(pki, **server_kw)
    t = threading.Thread(target=sync_serve, args=(server, b, handler), daemon=True)
    t.start()
    return a, server, t


def test_sync_socket_encryptedsocket_arayuzu(pki, trust):
    a, server, t = _sync_pair(pki, http_responder(b"selam"), alpn="h2")
    a.settimeout(5)
    s = SyncTLSSocket.negotiate(a, HOST, "chrome_131", **trust)
    assert s.state["alpn"] == "h2" and s.state["is_tls13"]
    assert s.raw_socket is a

    s.send_record(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    msg, mt = s.recv_record(skip_post_handshake=True)  # NewSessionTicket yutulur
    assert mt == 23 and msg.startswith(b"HTTP/1.1 200 OK") and msg.endswith(b"selam")
    s.close()
    t.join(2)
    assert server.alerts == [b"\x01\x00"]


def test_sync_post_handshake_mesajlari_skip_false_ise_doner(pki, trust):
    a, server, t = _sync_pair(pki, http_responder())
    a.settimeout(5)
    s = SyncTLSSocket.negotiate(a, HOST, "chrome_131", **trust)
    s.send_record(b"GET / HTTP/1.1\r\n\r\n")
    msg, mt = s.recv_record(skip_post_handshake=False)
    assert mt == 22 and msg[0] == 4          # NewSessionTicket
    msg, mt = s.recv_record(skip_post_handshake=False)
    assert mt == 23
    s.close()


def test_sync_sertifika_hatasi(pki, trust):
    a, server, t = _sync_pair(PKI(HOST))       # güvenilmeyen CA
    a.settimeout(5)
    with pytest.raises(ConnectionError, match="sertifika"):
        SyncTLSSocket.negotiate(a, HOST, "chrome_131", **trust)
    a.close()


# ----------------------------------------------------------------- async
async def _start(pki, handler=None, **server_kw):
    servers = []

    async def on_conn(r, w):
        srv = FakeTLS13Server(pki, **server_kw)
        servers.append(srv)
        await async_serve(srv, r, w, handler)

    srv = await asyncio.start_server(on_conn, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    return srv, port, servers


def test_async_stream_recv_send_record(pki, trust):
    async def main():
        srv, port, servers = await _start(pki, http_responder(b"async"), alpn="h2")
        async with srv:
            stream = await AsyncTLSStream.connect("127.0.0.1", port, "chrome_131",
                                                  server_hostname=HOST, **trust)
            assert stream.state["alpn"] == "h2"
            await stream.send_record(b"GET / HTTP/1.1\r\n\r\n")
            msg, mt = await stream.recv_record(skip_post_handshake=True)
            assert mt == 23 and msg.endswith(b"async")
            stream.close()
            await stream.wait_closed()
    asyncio.run(asyncio.wait_for(main(), 10))


def test_async_stream_reader_writer_yuzeyi(pki, trust):
    """open_connection(ssl=...) dönüşü yerine `reader = writer = stream`."""
    async def main():
        body = b"x" * 40000      # birden çok record
        srv, port, servers = await _start(pki, http_responder(body))
        async with srv:
            stream = await AsyncTLSStream.connect("127.0.0.1", port, "chrome_131",
                                                  server_hostname=HOST, alpn=["http/1.1"], **trust)
            reader = writer = stream
            writer.write(b"GET / HTTP/1.1\r\n\r\n")
            await writer.drain()
            buf = b""
            while not buf.endswith(body):
                chunk = await asyncio.wait_for(reader.read(4096), 5)
                assert chunk
                assert len(chunk) <= 4096
                buf += chunk
            assert buf.startswith(b"HTTP/1.1 200 OK")
            writer.close()
            await writer.wait_closed()
    asyncio.run(asyncio.wait_for(main(), 10))


def test_async_keyupdate_ve_close_notify(pki, trust):
    def handler(server):
        if b"\r\n\r\n" not in b"".join(server.app_in):
            return b""
        ku = server.send_key_update(request=True)
        return ku + http_responder(b"ilk")(server) + server.send_alert(1, 0)

    async def main():
        srv, port, servers = await _start(pki, handler)
        async with srv:
            stream = await AsyncTLSStream.connect("127.0.0.1", port, "chrome_131",
                                                  server_hostname=HOST, **trust)
            stream.write(b"GET / HTTP/1.1\r\n\r\n")
            await stream.drain()
            data = b""
            while True:
                c = await stream.read(1024)
                if not c:
                    break
                data += c
            assert data.endswith(b"ilk")
            assert stream.at_eof()
            stream.close()
            await asyncio.sleep(0.05)
            assert servers[0].key_updates_received == 1
    asyncio.run(asyncio.wait_for(main(), 10))


def test_async_mitm_reddedilir(pki, trust):
    async def main():
        srv, port, _ = await _start(pki, tamper={"bad_cv_sig"})
        async with srv:
            with pytest.raises(TLSError, match="kimlik doğrulaması"):
                await AsyncTLSStream.connect("127.0.0.1", port, "chrome_131",
                                             server_hostname=HOST, **trust)
    asyncio.run(asyncio.wait_for(main(), 10))
