"""İş parçacığı güvenliği ve ``Timeout.write`` testleri için yerel sunucular (ağsız).

* :class:`H2ThreadServer` — stdlib ``ssl`` (TLS 1.3, ALPN ``h2``) + ``h2`` kütüphanesi,
  bağlantı başına bir iş parçacığı. Yollar: ``/id?i=X`` (gövde ``X``; POST'ta ``X`` +
  istek gövdesi), ``/setcookie?i=X`` (``Set-Cookie: cX=vX``), ``/sleep?d=SN&i=X``.
  Bağlantı sayısı, aynı anda açık bağlantı ve bir bağlantıda aynı anda açık stream
  sayısının tepe değerlerini kaydeder.
* :class:`StallServer` — bağlantıyı kabul eder (istenirse TLS el sıkışmasını yapar,
  ``preamble`` gönderir), sonra HİÇ okumaz: istemcinin gönderimi soket tamponları
  dolunca bloklanır (``Timeout.write`` testi), küçük istekte yanıt hiç gelmez
  (``Timeout.read`` testi).

Sunucular 127.0.0.1 ve (varsa) ::1'de aynı portu dinler (bkz. netutil).
"""
from __future__ import annotations

import socket
import ssl
import tempfile
import threading
import time
from typing import Optional
from urllib.parse import parse_qs, urlsplit

from netutil import listen_dual
from saha.yerel_sunucu import pki_uret


class _Base:
    def __init__(self, alpn: "list[str] | None", tls: bool = True, rcvbuf: Optional[int] = None):
        self._tmp = tempfile.TemporaryDirectory(prefix="fasthttpc-thr-")
        self.ca_path, cert, key = pki_uret(self._tmp.name, "localhost")
        self.ctx: Optional[ssl.SSLContext] = None
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.load_cert_chain(cert, key)
            if alpn:
                ctx.set_alpn_protocols(alpn)
            self.ctx = ctx
        self.lock = threading.Lock()
        self.accepted = 0
        self.open = 0
        self.peak_open = 0
        self.errors: list[BaseException] = []
        self._stop = threading.Event()
        self._conns: set = set()
        self._listeners, self.port = listen_dual(64, rcvbuf)   # paralel süreçlerde port yarışına dayanıklı
        for ls in self._listeners:
            threading.Thread(target=self._accept, args=(ls,), daemon=True).start()

    @property
    def base(self) -> str:
        return f"{'https' if self.ctx is not None else 'http'}://localhost:{self.port}"

    def _accept(self, ls: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = ls.accept()
            except OSError:
                return
            threading.Thread(target=self._wrap, args=(raw,), daemon=True).start()

    def _wrap(self, raw: socket.socket) -> None:
        with self.lock:
            self.accepted += 1
            self.open += 1
            self.peak_open = max(self.peak_open, self.open)
            self._conns.add(raw)
        s = raw
        try:
            raw.settimeout(30)
            if self.ctx is not None:
                # wrap_socket ham soketi DEVRALIR (raw detach edilir): bundan sonra kapatılacak
                # ve close()'un keseceği soket s'dir; raw.close() hiçbir şeyi kapatmaz.
                s = self.ctx.wrap_socket(raw, server_side=True)
                with self.lock:
                    self._conns.discard(raw)
                    self._conns.add(s)
                if self._stop.is_set():     # close() sarma sırasında koştu
                    return
            self._serve(s)
        except (OSError, ssl.SSLError) as e:
            if not self._stop.is_set():
                self.errors.append(e)
        finally:
            with self.lock:
                self.open -= 1
                self._conns.discard(raw)
                self._conns.discard(s)
            try:
                s.close()
            except OSError:
                pass

    def _serve(self, s: socket.socket) -> None:  # pragma: no cover - alt sınıflar
        raise NotImplementedError

    def close(self) -> None:
        self._stop.set()
        for ls in self._listeners:
            try:
                ls.close()
            except OSError:
                pass
        with self.lock:
            conns = list(self._conns)
        for c in conns:
            try:
                c.close()
            except OSError:
                pass
        self._tmp.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *a: object) -> None:
        self.close()


class H2ThreadServer(_Base):
    def __init__(self) -> None:
        self.requests = 0
        self.max_streams_per_conn = 0     # bir bağlantıda aynı anda açık en çok stream
        super().__init__(["h2"])

    def _serve(self, s: socket.socket) -> None:
        import h2.config
        import h2.connection
        import h2.events

        conn = h2.connection.H2Connection(
            h2.config.H2Configuration(client_side=False, validate_inbound_headers=False))
        conn.initiate_connection()
        conn.increment_flow_control_window(2 ** 30)
        s.sendall(conn.data_to_send())
        streams: dict[int, dict] = {}
        while not self._stop.is_set():
            data = s.recv(65536)
            if not data:
                return
            for ev in conn.receive_data(data):
                if isinstance(ev, h2.events.RequestReceived):
                    hdrs = {(k.decode() if isinstance(k, bytes) else k):
                            (v.decode() if isinstance(v, bytes) else v) for k, v in ev.headers}
                    streams[ev.stream_id] = {"h": hdrs, "body": bytearray()}
                    with self.lock:
                        self.max_streams_per_conn = max(self.max_streams_per_conn, len(streams))
                elif isinstance(ev, h2.events.DataReceived):
                    if ev.stream_id in streams:
                        streams[ev.stream_id]["body"] += ev.data
                    conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, h2.events.StreamEnded):
                    req = streams.pop(ev.stream_id, None)
                    if req is not None:
                        self._respond(conn, ev.stream_id, req)
                elif isinstance(ev, h2.events.StreamReset):
                    streams.pop(ev.stream_id, None)
                elif isinstance(ev, h2.events.ConnectionTerminated):
                    return
            out = conn.data_to_send()
            if out:
                s.sendall(out)

    def _respond(self, conn, sid: int, req: dict) -> None:
        with self.lock:
            self.requests += 1
        u = urlsplit(req["h"].get(":path", "/"))
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        i = q.get("i", "")
        extra: list[tuple[str, str]] = []
        body = i.encode()
        if u.path == "/id" and req["h"].get(":method") == "POST":
            body += bytes(req["body"])
        elif u.path == "/setcookie":
            extra.append(("set-cookie", f"c{i}=v{i}; Path=/"))
        elif u.path == "/sleep":
            time.sleep(float(q.get("d", "1")))
        conn.send_headers(sid, [(":status", "200"), ("content-length", str(len(body))),
                                ("x-id", i)] + extra, end_stream=not body)
        if body:
            conn.send_data(sid, body, end_stream=True)


class StallServer(_Base):
    """Kabul eder, (TLS ise) el sıkışır, ``preamble``'ı gönderir ve bir daha OKUMAZ."""

    def __init__(self, tls: bool = True, alpn: "list[str] | None" = None,
                 rcvbuf: Optional[int] = None, preamble: bytes = b"") -> None:
        self.preamble = preamble
        super().__init__(alpn, tls=tls, rcvbuf=rcvbuf)

    def _serve(self, s: socket.socket) -> None:
        if self.preamble:
            s.sendall(self.preamble)
        self._stop.wait(60)          # okumadan bekle (istemci zaman aşımıyla vazgeçer)
