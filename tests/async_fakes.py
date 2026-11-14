"""AsyncSession testleri için yerel sahte sunucular (ağsız).

  * AsyncFakeProxy  : asyncio HTTP CONNECT / SOCKS5 proxy; hedefi kaydeder ve
                      her tüneli yerel bir upstream porta bağlar.
  * start_tls13     : FakeTLS13Server (fasthttpc.tls13 ile konuşan) sunucusu.
  * start_stdlib_tls: stdlib ssl sunucusu (impersonate=None yolu için).
  * RawH2Conn       : FakeTLS13Server üzerinde ham HTTP/2 frame'leriyle
                      komutlanabilir sunucu (bağımlılık yok).
"""
from __future__ import annotations

import asyncio
import base64
import socket
import ssl
import struct

from cryptography.hazmat.primitives import serialization

from fasthttpc.protocol.http2_parser import (
    FrameType, HTTP2Frame, HpackDecoder, HpackEncoder, _strip_headers_frame_fields,
)
from tls13_fakeserver import FakeTLS13Server

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


async def _pipe(r, w):
    try:
        while True:
            d = await r.read(65536)
            if not d:
                break
            w.write(d)
            await w.drain()
    except (OSError, asyncio.CancelledError):
        pass
    finally:
        try:
            w.close()
        except OSError:
            pass


class AsyncFakeProxy:
    """kind='http' | 'socks5'. Her bağlantı için hedefi ``targets`` listesine yazar."""

    def __init__(self, kind, upstream_port=None, auth=None, reply=None):
        self.kind, self.upstream_port, self.auth, self.reply = kind, upstream_port, auth, reply
        self.targets: list = []
        self.heads: list[bytes] = []
        self.connections = 0
        self.server = None
        self.port = 0

    async def start(self):
        self.server = await asyncio.start_server(self._on_conn, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()

    @property
    def url(self):
        scheme = "http" if self.kind == "http" else "socks5"
        a = f"{self.auth}@" if self.auth else ""
        return f"{scheme}://{a}127.0.0.1:{self.port}"

    async def _on_conn(self, r, w):
        self.connections += 1
        try:
            ok = await (self._http(r, w) if self.kind == "http" else self._socks(r, w))
            if not ok or self.upstream_port is None:
                w.close()
                return
            ur, uw = await asyncio.open_connection("127.0.0.1", self.upstream_port)
            await asyncio.gather(_pipe(r, uw), _pipe(ur, w))
        except (OSError, asyncio.IncompleteReadError):
            w.close()

    async def _http(self, r, w):
        head = await r.readuntil(b"\r\n\r\n")
        self.heads.append(head)
        self.targets.append(head.split(b"\r\n")[0].decode().split(" ")[1])
        if self.reply:
            w.write(self.reply)
            return False
        if self.auth:
            exp = b"Proxy-Authorization: Basic " + base64.b64encode(self.auth.encode())
            if exp not in head:
                w.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                return False
        w.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await w.drain()
        return True

    async def _socks(self, r, w):
        ver, n = await r.readexactly(2)
        methods = await r.readexactly(n)
        if self.auth:
            if 2 not in methods:
                w.write(b"\x05\xff")
                return False
            w.write(b"\x05\x02")
            _v, ul = await r.readexactly(2)
            user = await r.readexactly(ul)
            pwd = await r.readexactly((await r.readexactly(1))[0])
            if f"{user.decode()}:{pwd.decode()}" != self.auth:
                w.write(b"\x01\x01")
                return False
            w.write(b"\x01\x00")
        else:
            w.write(b"\x05\x00")
        _v, _cmd, _r, atyp = await r.readexactly(4)
        if atyp == 3:
            host = (await r.readexactly((await r.readexactly(1))[0])).decode()
        elif atyp == 1:
            host = socket.inet_ntoa(await r.readexactly(4))
        else:
            host = socket.inet_ntop(socket.AF_INET6, await r.readexactly(16))
        port = struct.unpack("!H", await r.readexactly(2))[0]
        self.targets.append((atyp, host, port))
        rep = self.reply if self.reply is not None else 0
        w.write(bytes([5, rep, 0, 1]) + b"\x7f\x00\x00\x01" + struct.pack("!H", 1080))
        await w.drain()
        return rep == 0


async def start_tls13(pki, handler=None, **server_kw):
    """-> (server, port, servers) ; servers: her bağlantı için FakeTLS13Server."""
    from tls13_fakeserver import async_serve
    servers = []

    async def on_conn(r, w):
        srv = FakeTLS13Server(pki, **server_kw)
        servers.append(srv)
        await async_serve(srv, r, w, handler)

    server = await asyncio.start_server(on_conn, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1], servers


async def start_stdlib_tls(pki, tmp_path, body=b"stdlib tamam"):
    """stdlib ssl HTTP/1.1 sunucusu (leaf: pki.cert). -> (server, port, requests)."""
    cert = tmp_path / "leaf.pem"
    key = tmp_path / "leaf.key"
    cert.write_bytes(pki.cert.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(pki.key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    ctx.set_alpn_protocols(["http/1.1"])
    requests = []

    async def on_conn(r, w):
        try:
            head = await r.readuntil(b"\r\n\r\n")
            requests.append(head)
            w.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nSet-Cookie: s=1\r\n\r\n" % len(body) + body)
            await w.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            w.close()

    server = await asyncio.start_server(on_conn, "127.0.0.1", 0, ssl=ctx)
    return server, server.sockets[0].getsockname()[1], requests


class RawH2Conn:
    """FakeTLS13Server (ALPN=h2) üzerinde ham frame'lerle komutlanan sunucu bağlantısı."""

    def __init__(self, pki, reader, writer, **server_kw):
        self.srv = FakeTLS13Server(pki, alpn="h2", **server_kw)
        self.reader, self.writer = reader, writer
        self.frames: asyncio.Queue = asyncio.Queue()
        self.encoder = HpackEncoder()
        self.decoder = HpackDecoder(max_table_size=65536)
        self.raw_in = b""
        self._buf = b""
        self._preface = False
        self.preface_ok = False
        self.eof = False
        self.requests: dict[int, dict] = {}     # sid -> {"headers": [...], "body": bytearray, "ended": bool}

    async def pump(self):
        try:
            while True:
                data = await self.reader.read(65536)
                if not data:
                    break
                out = self.srv.receive(data)
                if out:
                    self.writer.write(out)
                    await self.writer.drain()
                if self.srv.state == "CONNECTED":
                    pt = b"".join(self.srv.app_in)
                    self.srv.app_in.clear()
                    self._buf += pt
                    self.raw_in += pt
                    if not self._preface and len(self._buf) >= len(PREFACE):
                        self.preface_ok = self._buf.startswith(PREFACE)
                        self._buf = self._buf[len(PREFACE):]
                        self._preface = True
                    while self._preface and len(self._buf) >= 9:
                        ln = int.from_bytes(self._buf[:3], "big")
                        if len(self._buf) < 9 + ln:
                            break
                        f = HTTP2Frame.parse(self._buf[:9 + ln])
                        self._buf = self._buf[9 + ln:]
                        self.frames.put_nowait(f)
        except (OSError, asyncio.CancelledError):
            pass
        finally:
            self.eof = True
            self.frames.put_nowait(None)

    # -- gönderim
    def send(self, *chunks: bytes):
        data = b"".join(chunks)
        self.writer.write(self.srv.send_app(data))

    async def flush(self):
        await self.writer.drain()

    @staticmethod
    def frame(ftype, flags, sid, payload=b""):
        return HTTP2Frame(len(payload), ftype, flags, sid, payload).serialize()

    def settings(self, **kv):
        ids = {"header_table": 1, "push": 2, "max_streams": 3, "window": 4, "max_frame": 5}
        payload = b"".join(struct.pack("!HI", ids[k], v) for k, v in kv.items())
        return self.frame(FrameType.SETTINGS, 0, 0, payload)

    def settings_ack(self):
        return self.frame(FrameType.SETTINGS, 1, 0)

    def window_update(self, sid, inc):
        return self.frame(FrameType.WINDOW_UPDATE, 0, sid, struct.pack("!I", inc))

    def rst(self, sid, code):
        return self.frame(FrameType.RST_STREAM, 0, sid, struct.pack("!I", code))

    def goaway(self, last, code=0):
        return self.frame(FrameType.GOAWAY, 0, 0, struct.pack("!II", last, code))

    def ping(self, data=b"12345678", ack=False):
        return self.frame(FrameType.PING, 1 if ack else 0, 0, data)

    def response_headers(self, sid, status=200, headers=(), end=False):
        block = self.encoder.encode([(":status", str(status))] + list(headers))
        return self.frame(FrameType.HEADERS, 0x4 | (0x1 if end else 0), sid, block)

    def data(self, sid, body, end=False):
        return self.frame(FrameType.DATA, 0x1 if end else 0, sid, body)

    def respond(self, sid, status=200, headers=(), body=b""):
        out = self.response_headers(sid, status, headers, end=not body)
        if body:
            out += self.data(sid, body, end=True)
        self.send(out)

    # -- alım
    async def next_frame(self, *types, timeout=5):
        """Belirtilen tipte (yoksa herhangi) sıradaki frame; diğerleri atlanır.

        HEADERS frame'leri otomatik decode edilip ``requests``'e işlenir."""
        while True:
            f = await asyncio.wait_for(self.frames.get(), timeout)
            if f is None:
                return None
            self._track(f)
            if not types or f.type in types:
                return f

    def _track(self, f):
        if f.type == FrameType.HEADERS:
            hdrs = self.decoder.decode(_strip_headers_frame_fields(f))
            self.requests[f.stream_id] = {"headers": hdrs, "body": bytearray(),
                                          "ended": f.end_stream}
        elif f.type == FrameType.DATA and f.stream_id in self.requests:
            self.requests[f.stream_id]["body"] += f.payload
            if f.end_stream:
                self.requests[f.stream_id]["ended"] = True

    async def handshake(self, **settings):
        """TLS bitince sunucu SETTINGS'i gönderir; istemcininkini alır ve ack'ler."""
        while self.srv.state != "CONNECTED":
            await asyncio.sleep(0.005)
        self.send(self.settings(**(settings or {"max_streams": 100})))
        await self.flush()
        f = await self.next_frame(FrameType.SETTINGS)
        while f is not None and f.flags & 1:
            f = await self.next_frame(FrameType.SETTINGS)
        self.client_settings = f
        self.send(self.settings_ack())
        await self.flush()

    async def run(self, script):
        pump = asyncio.ensure_future(self.pump())
        try:
            await script(self)
        finally:
            pump.cancel()
            self.writer.close()


async def start_h2(pki, script, **server_kw):
    """Her bağlantı için RawH2Conn oluşturup ``script(conn)``'i çalıştırır.

    -> (server, port, conns)"""
    conns: list[RawH2Conn] = []

    async def on_conn(r, w):
        c = RawH2Conn(pki, r, w, **server_kw)
        conns.append(c)
        try:
            await c.run(script)
        except (OSError, asyncio.CancelledError, asyncio.TimeoutError):
            pass

    server = await asyncio.start_server(on_conn, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1], conns
