"""Yerel benchmark sunucuları (ağsız, 127.0.0.1).

Sunucular istemciyle GIL paylaşmasın diye AYRI bir süreçte çalışır
(``multiprocessing``, ``spawn``). Böylece ölçülen istemci CPU süresi
(``time.process_time``) yalnızca fasthttpc'ye aittir.

* ``h1``: ``saha.yerel_sunucu.YerelSunucu`` (stdlib ``ssl``, TLS 1.3, HTTP/1.1).
* ``h2``: stdlib ``ssl`` + ``h2`` kütüphanesi (dev bağımlılığı) ile küçük bir
  HTTP/2 sunucusu, ALPN ``h2``. Yollar: ``/gen?n=BAYT`` (n bayt gövde, akış
  kontrolüne uyarak), ``/id?i=X`` (gövde ``X``).
"""
from __future__ import annotations

import multiprocessing as mp
import os
import socket
import ssl
import sys
import tempfile
import threading
from urllib.parse import parse_qs, urlsplit

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ----------------------------------------------------------------- HTTP/2
def _h2_conn(raw: socket.socket, ctx: ssl.SSLContext) -> None:
    import h2.config
    import h2.connection
    import h2.events

    try:
        s = ctx.wrap_socket(raw, server_side=True)
    except (OSError, ssl.SSLError):
        raw.close()
        return
    conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False, validate_inbound_headers=False))
    conn.initiate_connection()
    # Bağlantı penceresini büyüt (gerçek sunucular da yapar; aksi hâlde istemcinin
    # büyük gövde YÜKLEMESİ 64 KiB'te tıkanır — bu benchmark yüklemeyi ölçmez).
    conn.increment_flow_control_window(2 ** 30)
    s.sendall(conn.data_to_send())
    blok = bytes(range(256)) * 256          # 64 KiB
    pending: dict[int, int] = {}            # stream_id -> kalan bayt

    def pump() -> None:
        for sid in list(pending):
            kalan = pending[sid]
            while kalan > 0:
                win = min(conn.local_flow_control_window(sid), conn.max_outbound_frame_size, kalan)
                if win <= 0:
                    break
                conn.send_data(sid, blok[:win], end_stream=(win == kalan))
                kalan -= win
            if kalan == 0:
                del pending[sid]
            else:
                pending[sid] = kalan
        out = conn.data_to_send()
        if out:
            s.sendall(out)

    try:
        while True:
            data = s.recv(262144)
            if not data:
                return
            for ev in conn.receive_data(data):
                if isinstance(ev, h2.events.RequestReceived):
                    hdrs = {k.decode() if isinstance(k, bytes) else k: v.decode() if isinstance(v, bytes) else v
                            for k, v in ev.headers}
                    u = urlsplit(hdrs.get(":path", "/"))
                    q = {k: v[0] for k, v in parse_qs(u.query).items()}
                    if u.path == "/gen":
                        n = int(q.get("n", "0"))
                        conn.send_headers(ev.stream_id, [(":status", "200"), ("content-length", str(n)),
                                                         ("content-type", "application/octet-stream")],
                                          end_stream=(n == 0))
                        if n:
                            pending[ev.stream_id] = n
                    else:
                        body = q.get("i", "ok").encode()
                        conn.send_headers(ev.stream_id, [(":status", "200"), ("content-length", str(len(body))),
                                                         ("x-id", q.get("i", ""))])
                        conn.send_data(ev.stream_id, body, end_stream=True)
                elif isinstance(ev, h2.events.DataReceived):
                    conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, h2.events.ConnectionTerminated):
                    return
            pump()
    except (OSError, ssl.SSLError, Exception):  # noqa: BLE001 - benchmark sunucusu
        return
    finally:
        try:
            s.close()
        except OSError:
            pass


def _h2_server_main(q: "mp.Queue") -> None:
    sys.path.insert(0, _ROOT)
    from saha.yerel_sunucu import pki_uret

    tmp = tempfile.mkdtemp(prefix="bench-h2-")
    ca, cert, key = pki_uret(tmp, "localhost")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["h2"])
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", 0))
    ls.listen(256)
    q.put((ls.getsockname()[1], ca))
    while True:
        raw, _ = ls.accept()
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=_h2_conn, args=(raw, ctx), daemon=True).start()


# ----------------------------------------------------------------- HTTP/1.1
def _h1_server_main(q: "mp.Queue") -> None:
    sys.path.insert(0, _ROOT)
    from saha.yerel_sunucu import YerelSunucu

    class _NoDelay(YerelSunucu):
        # Test sunucusu TCP_NODELAY koymaz: TLS 1.3 bilet(ler)inden sonra yanıt Nagle
        # yüzünden istemcinin gecikmeli ACK'ini (~40 ms) bekler. Gerçek sunucular
        # (nginx, Caddy, ...) NODELAY kullanır; handshake ölçümü bu yapayla bozulmasın.
        def _baglanti(self, raw: socket.socket) -> None:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            super()._baglanti(raw)

    sv = _NoDelay()
    q.put((sv.port, sv.ca_path))
    threading.Event().wait()


class ServerProcess:
    """``kind`` = ``"h1"`` | ``"h2"``; ``with ServerProcess("h1") as (port, ca): ...``"""

    def __init__(self, kind: str):
        target = {"h1": _h1_server_main, "h2": _h2_server_main}[kind]
        ctx = mp.get_context("spawn")
        self._q = ctx.Queue()
        self._p = ctx.Process(target=target, args=(self._q,), daemon=True)

    def __enter__(self) -> "tuple[int, str]":
        self._p.start()
        port, ca = self._q.get(timeout=30)
        return port, ca

    def __exit__(self, *exc: object) -> None:
        self._p.terminate()
        self._p.join(5)


def h2_available() -> bool:
    try:
        import h2  # noqa: F401
    except ImportError:
        return False
    return True
