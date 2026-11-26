"""AsyncSession.ws_connect / pre_warm: impersonate (AsyncTLSStream) + proxy desteği."""
import asyncio
import base64
import hashlib
import ssl

import pytest
from cryptography.hazmat.primitives import serialization

from fasthttpc import AsyncSession, Timeout
from fasthttpc.protocol.http2_parser import WebSocketFrame

from netutil import start_dual
from async_fakes import AsyncFakeProxy, start_tls13
from tls13_fakeserver import PKI, http_responder

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


@pytest.fixture(scope="module")
def pki():
    return PKI("localhost")


@pytest.fixture
def ca(pki, tmp_path):
    p = tmp_path / "ca.pem"
    p.write_bytes(pki.ca_pem())
    return str(p)


def run(coro, timeout=30):
    return asyncio.run(asyncio.wait_for(coro, timeout))


def target_of(proxy) -> str:
    t = proxy.targets[0]                      # http: "host:port"; socks5: (atyp, host, port)
    return t if isinstance(t, str) else f"{t[1]}:{t[2]}"


def upgrade_response(head: bytes, extra=b"", status=b"101 Switching Protocols") -> bytes:
    key = [ln.split(b":", 1)[1].strip() for ln in head.split(b"\r\n")
           if ln.lower().startswith(b"sec-websocket-key")][0]
    acc = base64.b64encode(hashlib.sha1(key + GUID.encode()).digest())
    return (b"HTTP/1.1 " + status + b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + acc + b"\r\n\r\n" + extra)


def echo_frames(buf: bytearray) -> bytes:
    """Maskeli istemci frame'lerini çözer, maskesiz 'echo:<metin>' frame'leri üretir."""
    out = b""
    while True:
        frame, n = WebSocketFrame.parse(bytes(buf))
        if not frame:
            return out
        del buf[:n]
        if frame.opcode == WebSocketFrame.OP_TEXT:
            out += WebSocketFrame(WebSocketFrame.OP_TEXT, b"echo:" + frame.payload,
                                  mask=False).serialize()


UNMASKED_HELLO = WebSocketFrame(WebSocketFrame.OP_TEXT, b"hos-geldin", mask=False).serialize()


class WSServer:
    """stdlib ssl (tls=True) ya da düz TCP WebSocket echo sunucusu."""

    def __init__(self, pki=None, tmp_path=None, tls=True, hello=True, status=b"101 Switching Protocols"):
        self.hello, self.status = hello, status
        self.heads = []
        self.ctx = None
        if tls:
            cert, key = tmp_path / "ws.pem", tmp_path / "ws.key"
            cert.write_bytes(pki.cert.public_bytes(serialization.Encoding.PEM))
            key.write_bytes(pki.key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ctx.load_cert_chain(str(cert), str(key))
            self.ctx.set_alpn_protocols(["http/1.1"])

    async def start(self):
        self.server = await start_dual(self._on_conn, ssl=self.ctx)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def _on_conn(self, r, w):
        try:
            head = await r.readuntil(b"\r\n\r\n")
            self.heads.append(head)
            # 101'in hemen ardından frame (sızıntı testi): aynı yazmada gider
            w.write(upgrade_response(head, UNMASKED_HELLO if self.hello else b"", self.status))
            await w.drain()
            buf = bytearray()
            while True:
                d = await r.read(4096)
                if not d:
                    break
                buf += d
                out = echo_frames(buf)
                if out:
                    w.write(out)
                    await w.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            w.close()

    async def stop(self):
        await self.server.aclose()


async def talk(ws):
    assert await ws.recv_text() == "hos-geldin"
    await ws.send_text("merhaba")
    assert await ws.recv_text() == "echo:merhaba"
    await ws.send_binary(b"\x00\x01")        # sunucu yok sayar
    await ws.send_text("iki")
    assert await ws.recv_text() == "echo:iki"


# -------------------------------------------------------------- stdlib ssl
def test_wss_stdlib_dogrudan(pki, ca, tmp_path):
    async def main():
        srv = await WSServer(pki, tmp_path).start()
        async with AsyncSession(impersonate=None, verify=ca, timeout=5) as s:
            async with await s.ws_connect(f"wss://localhost:{srv.port}/chat") as ws:
                await talk(ws)
        assert srv.heads[0].startswith(b"GET /chat HTTP/1.1\r\n")
        await srv.stop()
    run(main())


def test_ws_duz_tcp(pki, ca):
    async def main():
        srv = await WSServer(tls=False).start()
        async with AsyncSession(timeout=5) as s:
            async with await s.ws_connect(f"ws://127.0.0.1:{srv.port}/") as ws:
                await talk(ws)
        assert f"Host: 127.0.0.1:{srv.port}".encode() in srv.heads[0]
        await srv.stop()
    run(main())


def test_ws_101_disi_durum_reddedilir(pki, ca, tmp_path):
    async def main():
        srv = await WSServer(pki, tmp_path, status=b"200 OK").start()
        async with AsyncSession(impersonate=None, verify=ca, timeout=5) as s:
            with pytest.raises(ConnectionError, match="200"):
                await s.ws_connect(f"wss://localhost:{srv.port}/")
        await srv.stop()
    run(main())


# -------------------------------------------------------------- proxy
@pytest.mark.parametrize("kind", ["http", "socks5"])
@pytest.mark.parametrize("impersonate", [None, "chrome_131"])
def test_wss_proxy_uzerinden(kind, impersonate, pki, ca, tmp_path):
    async def main():
        srv = await WSServer(pki, tmp_path).start()
        proxy = await AsyncFakeProxy(kind, upstream_port=srv.port).start()
        async with AsyncSession(impersonate=impersonate, verify=ca, timeout=5,
                                proxy=proxy.url) as s:
            async with await s.ws_connect("wss://localhost/soket") as ws:
                await talk(ws)
        assert proxy.connections == 1
        assert target_of(proxy) == "localhost:443"
        assert srv.heads[0].startswith(b"GET /soket HTTP/1.1\r\n")
        await proxy.stop()
        await srv.stop()
    run(main())


def test_ws_duz_proxy_uzerinden(pki, ca):
    async def main():
        srv = await WSServer(tls=False).start()
        proxy = await AsyncFakeProxy("http", upstream_port=srv.port).start()
        async with AsyncSession(timeout=5, proxy=proxy.url) as s:
            async with await s.ws_connect("ws://ornek.test:8080/x") as ws:
                await talk(ws)
        assert target_of(proxy) == "ornek.test:8080"
        await proxy.stop()
        await srv.stop()
    run(main())


# -------------------------------------------------------------- impersonate (AsyncTLSStream)
def ws_tls13_handler():
    def handle(server):
        if not hasattr(server, "ws_buf"):
            server.ws_buf = bytearray()
            server.upgraded = False
        server.ws_buf += b"".join(server.app_in)
        server.app_in.clear()
        out = b""
        if not server.upgraded:
            i = server.ws_buf.find(b"\r\n\r\n")
            if i == -1:
                return b""
            head = bytes(server.ws_buf[:i + 4])
            del server.ws_buf[:i + 4]
            server.upgraded = True
            server.upgrade_head = head
            out += server.send_app(upgrade_response(head, UNMASKED_HELLO))
        echo = echo_frames(server.ws_buf)
        if echo:
            out += server.send_app(echo)
        return out
    return handle


def test_wss_impersonate_alpn_http11_ve_echo(pki, ca):
    async def main():
        server, port, servers = await start_tls13(pki, ws_tls13_handler(), alpn="http/1.1")
        async with server:
            async with AsyncSession(impersonate="chrome_131", verify=ca, timeout=5) as s:
                async with await s.ws_connect(f"wss://localhost:{port}/") as ws:
                    await talk(ws)
            ch = servers[0].client_hellos[0]
            assert ch["alpn"] == ["http/1.1"]          # h2 ilan edilmez: Upgrade h2'de yapılamaz
            assert ch["exts"]                          # tarayıcı ClientHello'su
    run(main())


def test_wss_impersonate_proxy_uzerinden(pki, ca):
    async def main():
        server, port, servers = await start_tls13(pki, ws_tls13_handler(), alpn="http/1.1")
        proxy = await AsyncFakeProxy("http", upstream_port=port).start()
        async with server:
            async with AsyncSession(impersonate="firefox_120", verify=ca, timeout=5,
                                    proxy=proxy.url) as s:
                async with await s.ws_connect("wss://localhost/") as ws:
                    await talk(ws)
            assert proxy.connections == 1
        await proxy.stop()
    run(main())


def test_ws_proxy_rotasyonu_kullanilir(pki, ca, tmp_path):
    async def main():
        srv = await WSServer(pki, tmp_path).start()
        proxy = await AsyncFakeProxy("http", upstream_port=srv.port).start()
        s = AsyncSession(impersonate=None, verify=ca, timeout=5).set_proxies([proxy.url])
        async with await s.ws_connect("wss://localhost/") as ws:
            await talk(ws)
        assert proxy.connections == 1
        await s.close()
        await proxy.stop()
        await srv.stop()
    run(main())


# -------------------------------------------------------------- pre_warm
@pytest.mark.parametrize("impersonate", [None, "chrome_131"])
def test_pre_warm_proxy_uzerinden_ve_havuza_konur(impersonate, pki, ca):
    async def main():
        server, port, servers = await start_tls13(pki, http_responder(b"sicak"), alpn="http/1.1")
        proxy = await AsyncFakeProxy("http", upstream_port=port).start()
        async with server:
            async with AsyncSession(impersonate=impersonate, verify=ca, timeout=5,
                                    proxy=proxy.url) as s:
                res = await s.pre_warm(["localhost"], count=2)
                assert res == {"localhost": 2}
                assert proxy.connections == 2 and target_of(proxy) == "localhost:443"
                if impersonate:
                    assert servers[0].client_hellos[0]["exts"]
                # ısıtılan bağlantı gerçek istekte kullanılır: yeni tünel açılmaz
                r = await s.get("https://localhost/")
                assert r.body == b"sicak" and proxy.connections == 2
    run(main())


def test_pre_warm_basarisiz_sayilmaz(ca):
    async def main():
        s = AsyncSession(impersonate="chrome_131", verify=ca, timeout=Timeout(1),
                         proxy="http://127.0.0.1:1")
        assert await s.pre_warm(["localhost"], count=2) == {"localhost": 0}
        await s.close()
    run(main())
