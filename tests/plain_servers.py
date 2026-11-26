"""Thread tabanlı yerel HTTP/1.1 sunucuları (düz TCP ya da stdlib ssl) ve sahte ileri proxy.

Senkron ``Session`` ve ``AsyncSession`` aynı sunucuya bağlanabilsin diye event loop
yerine thread kullanılır. Her istek ``requests`` listesine kaydedilir:
``(bağlantı_no, istek_satırı, başlık çiftleri [(ad, değer)], gövde, ilk_bayt)``.
"""
from __future__ import annotations

import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from cryptography.hazmat.primitives import serialization

from netutil import listen_dual, refused_port


@dataclass
class Req:
    conn: int
    line: str
    headers: "list[tuple[str, str]]"
    body: bytes
    first_byte: bytes = b""
    extra: dict = field(default_factory=dict)

    @property
    def method(self) -> str:
        return self.line.split(" ")[0]

    @property
    def target(self) -> str:
        return self.line.split(" ")[1]

    def header(self, name: str) -> Optional[str]:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None

    @property
    def names(self) -> "list[str]":
        return [k.lower() for k, _ in self.headers]


def ok(body: bytes = b"ok", extra: bytes = b"") -> bytes:
    return b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n%s\r\n" % (len(body), extra) + body


Handler = Callable[[Req], "bytes | tuple[bytes] | list[bytes]"]


def tls_context(pki, tmp_path) -> ssl.SSLContext:
    cert, key = tmp_path / "srv-leaf.pem", tmp_path / "srv-leaf.key"
    cert.write_bytes(pki.cert.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(pki.key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


class ThreadedHTTPServer:
    """Keep-alive HTTP/1.1 sunucusu. ``handler(req)`` -> yanıt baytı | ``(bayt,)`` (yanıttan
    sonra kapat) | ``[parça, ...]`` (parçalar arasında kısa bekleme; chunked sınama için).
    ``ssl_ctx`` verilirse TLS (stdlib ssl), yoksa düz TCP. 127.0.0.1 ve ::1'de aynı port."""

    def __init__(self, handler: Optional[Handler] = None, ssl_ctx: Optional[ssl.SSLContext] = None,
                 scheme_host: str = "localhost"):
        self.handler = handler or (lambda r: ok(r.target.encode()))
        self.ssl_ctx = ssl_ctx
        self.requests: "list[Req]" = []
        self.conns = 0
        self.errors: "list[BaseException]" = []
        self._lock = threading.Lock()
        self._socks, self.port = listen_dual(16)
        scheme = "https" if ssl_ctx is not None else "http"
        self.base = f"{scheme}://{scheme_host}:{self.port}"
        self._stop = False
        for s in self._socks:
            threading.Thread(target=self._accept, args=(s,), daemon=True).start()

    def close(self) -> None:
        self._stop = True
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass

    def __enter__(self) -> "ThreadedHTTPServer":
        return self

    def __exit__(self, *a: object) -> None:
        self.close()

    def _accept(self, ls: socket.socket) -> None:
        while not self._stop:
            try:
                c, _ = ls.accept()
            except OSError:
                return
            threading.Thread(target=self._conn, args=(c,), daemon=True).start()

    def _conn(self, c: socket.socket) -> None:
        with self._lock:
            self.conns += 1
            no = self.conns
        try:
            c.settimeout(10)
            first = c.recv(1, socket.MSG_PEEK)
            if self.ssl_ctx is not None:
                c = self.ssl_ctx.wrap_socket(c, server_side=True)
            buf = b""
            while True:
                while b"\r\n\r\n" not in buf:
                    d = c.recv(65536)
                    if not d:
                        return
                    buf += d
                head, _, buf = buf.partition(b"\r\n\r\n")
                lines = head.decode("latin-1").split("\r\n")
                hdrs = [(k, v.strip()) for k, _, v in (ln.partition(":") for ln in lines[1:] if ln)]
                n = 0
                for k, v in hdrs:
                    if k.lower() == "content-length":
                        n = int(v)
                while len(buf) < n:
                    d = c.recv(65536)
                    if not d:
                        return
                    buf += d
                body, buf = buf[:n], buf[n:]
                req = Req(no, lines[0], hdrs, body, first)
                with self._lock:
                    self.requests.append(req)
                out = self.handler(req)
                if isinstance(out, list):
                    for part in out:
                        c.sendall(part)
                        time.sleep(0.02)
                    continue
                close_after = isinstance(out, tuple)
                c.sendall(out[0] if close_after else out)   # type: ignore[index,arg-type]
                if close_after:
                    return
        except (OSError, ssl.SSLError) as e:
            if not self._stop:
                self.errors.append(e)
        finally:
            try:
                c.close()
            except OSError:
                pass


class ForwardProxy(ThreadedHTTPServer):
    """Sahte ileri (forward) HTTP proxy'si: mutlak biçimli istekleri kaydeder ve kendisi
    yanıtlar (``via-proxy <hedef>``). CONNECT gelirse 405 döner (test hatayı görür)."""

    def __init__(self, require_auth: Optional[str] = None):
        def handler(r: Req) -> bytes:
            if r.method == "CONNECT":
                return (b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n",)  # type: ignore[return-value]
            if require_auth is not None and r.header("proxy-authorization") != require_auth:
                return b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"
            return ok(b"via-proxy " + r.target.encode())
        super().__init__(handler, scheme_host="127.0.0.1")

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


def closed_port() -> int:
    """Bağlantıyı reddeden port (bkz. netutil.refused_port: paralel süreçlerde yarışsız)."""
    return refused_port()
