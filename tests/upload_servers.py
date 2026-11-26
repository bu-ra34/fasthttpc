"""İstek gövdesi (yükleme) testleri için yerel sunucular (ağsız): HTTP/1.1 (düz ya da TLS)
ve HTTP/2 (stdlib ``ssl`` + ``h2``). Her istek ``requests`` listesine :class:`Got` olarak
kaydedilir: başlıklar, alınan gövde (ya da büyük gövdede yalnızca SHA-256 + uzunluk) ve
çerçeve bilgisi (HTTP/1.1: chunked mı, chunk boyutları; HTTP/2: DATA frame boyutları ve
END_STREAM bayrağı).

Yollar: ``/echo`` (200, gövde = alınan bayt sayısı), ``/big`` (gövde saklanmaz, özetlenir),
``/r307`` ``/r308`` ``/r303`` (``Location: /echo``), ``/s503`` (ilk istek 503, sonra 200),
``/drop`` (gövdeyi okur, yanıt vermeden bağlantıyı kapatır), ``/digest`` (Authorization
yoksa Digest 401 challenge'ı), ``/close`` (200 + ``Connection: close``).
"""
from __future__ import annotations

import hashlib
import socket
from dataclasses import dataclass, field
from typing import Optional

from thread_servers import _Base

DIGEST_CHALLENGE = 'Digest realm="r", nonce="n1", qop="auth", algorithm=MD5'


@dataclass
class Got:
    method: str
    path: str
    headers: "dict[str, str]"
    body: bytes = b""
    length: int = 0
    sha256: str = ""
    chunked: bool = False
    chunk_sizes: "list[int]" = field(default_factory=list)
    frames: "list[tuple[int, bool]]" = field(default_factory=list)   # h2: (len, END_STREAM)


class _Hasher:
    def __init__(self, keep: bool) -> None:
        self.keep = keep
        self.buf = bytearray()
        self.h = hashlib.sha256()
        self.n = 0

    def add(self, data: bytes) -> None:
        self.n += len(data)
        self.h.update(data)
        if self.keep:
            self.buf += data

    def fill(self, got: Got) -> None:
        got.body, got.length, got.sha256 = bytes(self.buf), self.n, self.h.hexdigest()


def _route(srv: "_UploadMixin", got: Got) -> "tuple[int, list[tuple[str, str]], bytes, bool]":
    """(status, ek başlıklar, gövde, yanıtsız kapat)."""
    p = got.path
    if p in ("/r307", "/r308", "/r303"):
        return int(p[2:]), [("location", "/echo")], b"", False
    if p == "/s503":
        with srv.lock:
            srv.hits503 += 1
            first = srv.hits503 == 1
        if first:
            return 503, [], b"busy", False
    if p == "/drop":
        return 0, [], b"", True
    if p == "/digest" and "authorization" not in got.headers:
        return 401, [("www-authenticate", DIGEST_CHALLENGE)], b"", False
    if p == "/close":
        return 200, [("connection", "close")], str(got.length).encode(), False
    return 200, [], str(got.length).encode(), False


class _UploadMixin:
    lock: "object"

    def _init_upload(self) -> None:
        self.requests: "list[Got]" = []
        self.hits503 = 0


class H1UploadServer(_UploadMixin, _Base):
    """Keep-alive HTTP/1.1; ``Content-Length`` ve ``chunked`` gövdeleri ayrıştırır."""

    def __init__(self, tls: bool = True) -> None:
        self._init_upload()
        super().__init__(["http/1.1"], tls=tls)

    def _serve(self, s: socket.socket) -> None:
        f = s.makefile("rb")
        while True:
            line = f.readline()
            if not line:
                return
            method, target, _ = line.decode("latin-1").split(" ", 2)
            headers: dict[str, str] = {}
            while True:
                h = f.readline()
                if h in (b"\r\n", b"\n", b""):
                    break
                k, _, v = h.decode("latin-1").partition(":")
                headers[k.strip().lower()] = v.strip()
            got = Got(method, target, headers)
            hs = _Hasher(keep=target != "/big")
            if "chunked" in headers.get("transfer-encoding", "").lower():
                got.chunked = True
                while True:
                    size = int(f.readline().split(b";")[0].strip(), 16)
                    if size == 0:
                        while f.readline() not in (b"\r\n", b"\n", b""):
                            pass
                        break
                    got.chunk_sizes.append(size)
                    left = size
                    while left:
                        d = f.read(min(left, 65536))
                        if not d:
                            return
                        hs.add(d)
                        left -= len(d)
                    assert f.read(2) == b"\r\n"
            else:
                left = int(headers.get("content-length", "0"))
                while left:
                    d = f.read(min(left, 65536))
                    if not d:
                        return
                    hs.add(d)
                    left -= len(d)
            hs.fill(got)
            with self.lock:
                self.requests.append(got)
            status, extra, body, drop = _route(self, got)
            if drop:
                return
            head = f"HTTP/1.1 {status} X\r\nContent-Length: {len(body)}\r\n"
            head += "".join(f"{k}: {v}\r\n" for k, v in extra) + "\r\n"
            s.sendall(head.encode() + body)
            if ("connection", "close") in extra:
                return


class H2UploadServer(_UploadMixin, _Base):
    """HTTP/2 (``h2``); stream penceresi varsayılan 65535: istemci WINDOW_UPDATE bekler."""

    def __init__(self) -> None:
        self._init_upload()
        super().__init__(["h2"])

    def _serve(self, s: socket.socket) -> None:
        import h2.config
        import h2.connection
        import h2.events

        conn = h2.connection.H2Connection(
            h2.config.H2Configuration(client_side=False, validate_inbound_headers=False))
        conn.initiate_connection()
        s.sendall(conn.data_to_send())
        streams: "dict[int, tuple[Got, _Hasher]]" = {}
        while not self._stop.is_set():
            data = s.recv(65536)
            if not data:
                return
            for ev in conn.receive_data(data):
                if isinstance(ev, h2.events.RequestReceived):
                    hd = {(k.decode() if isinstance(k, bytes) else k):
                          (v.decode() if isinstance(v, bytes) else v) for k, v in ev.headers}
                    got = Got(hd.get(":method", ""), hd.get(":path", ""), hd)
                    streams[ev.stream_id] = (got, _Hasher(keep=got.path != "/big"))
                elif isinstance(ev, h2.events.DataReceived):
                    st = streams.get(ev.stream_id)
                    if st is not None:
                        st[1].add(ev.data)
                        st[0].frames.append((len(ev.data), ev.stream_ended is not None))
                    if ev.flow_controlled_length:
                        conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, h2.events.StreamEnded):
                    st = streams.pop(ev.stream_id, None)
                    if st is not None:
                        got, hs = st
                        hs.fill(got)
                        with self.lock:
                            self.requests.append(got)
                        status, extra, body, drop = _route(self, got)
                        if drop:
                            return
                        conn.send_headers(ev.stream_id, [(":status", str(status)),
                                                         ("content-length", str(len(body)))]
                                          + [(k, v) for k, v in extra if k != "connection"],
                                          end_stream=not body)
                        if body:
                            conn.send_data(ev.stream_id, body, end_stream=True)
                elif isinstance(ev, h2.events.StreamReset):
                    streams.pop(ev.stream_id, None)
                elif isinstance(ev, h2.events.ConnectionTerminated):
                    return
            out = conn.data_to_send()
            if out:
                s.sendall(out)


def make_server(kind: str) -> "H1UploadServer | H2UploadServer":
    if kind == "plain":
        return H1UploadServer(tls=False)
    if kind == "h1":
        return H1UploadServer(tls=True)
    return H2UploadServer()


def ca(srv: "H1UploadServer | H2UploadServer") -> Optional[str]:
    return srv.ca_path
