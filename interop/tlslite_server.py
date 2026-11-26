"""tlslite-ng tabanlı (saf Python, ikinci bağımsız uygulama) TLS sunucusu.

Ayarlar `HandshakeSettings` üzerinden verilir; `patch` ile sunucu tarafı bilerek bozulabilir.
"""
from __future__ import annotations

import re
import socket
import threading
from pathlib import Path

from tlslite.api import HandshakeSettings, TLSConnection, X509CertChain, parsePEMKey


class TlsliteServer:
    def __init__(self, cert_pem: str, key_pem: str, settings: "HandshakeSettings", *, body=b"tlslite merhaba",
                 alpn=None, chunks=None, hs_kwargs=None):
        self.settings = settings
        self.body = body
        self.alpn = alpn if alpn is not None else [b"http/1.1"]
        self.hs_kwargs = hs_kwargs or {}
        chain = X509CertChain()
        chain.parsePemList(Path(cert_pem).read_text())
        self.chain = chain
        self.key = parsePEMKey(Path(key_pem).read_text(), private=True)
        self.ls = socket.socket()
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(8)
        self.ls.settimeout(0.2)
        self.port = self.ls.getsockname()[1]
        self.stop = threading.Event()
        self.errors: list = []
        self.received: list = []
        self.sessions: list = []      # her başarılı el sıkışma için (version, cipherName, ems, resumed)
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.stop.set()
        self.thread.join(3)
        self.ls.close()

    def _loop(self):
        while not self.stop.is_set():
            try:
                c, _ = self.ls.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _handle(self, c):
        try:
            c.settimeout(10)
            tc = TLSConnection(c)
            tc.handshakeServer(certChain=self.chain, privateKey=self.key, settings=self.settings,
                               alpn=self.alpn, **self.hs_kwargs)
            self.sessions.append((tc.version, tc.session.cipherSuite, getattr(tc.session, "extendedMasterSecret", None),
                                  tc.session.getCipherName() if hasattr(tc.session, "getCipherName") else None))
            data = b""
            while b"\r\n\r\n" not in data:
                d = tc.recv(4096)
                if not d:
                    return
                data += d
            head, _, rest = data.partition(b"\r\n\r\n")
            m = re.search(rb"content-length:\s*(\d+)", head, re.I)
            need = int(m.group(1)) if m else 0
            while len(rest) < need:
                d = tc.recv(65536)
                if not d:
                    break
                rest += d
            self.received.append(rest)
            body = self.body if self.body is not None else b"len=%d" % len(rest)
            tc.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
                       + b"\r\nConnection: close\r\n\r\n" + body)
            tc.close()
        except Exception as e:  # noqa: BLE001
            self.errors.append(repr(e))
        finally:
            c.close()
