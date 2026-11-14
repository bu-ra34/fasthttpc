"""Kayıt (record) düzeyinde hata enjekte eden TCP aracısı: istemci <-> Relay <-> gerçek sunucu.

`s2c` / `c2s` callback'leri her TLS record'u için `(idx, rtype, record_bytes)` alır ve iletilecek
bayt dizisini döner; `Relay.CUT` döndürülürse bağlantı close_notify OLMADAN (TCP FIN) kapatılır.
"""
from __future__ import annotations

import socket
import struct
import threading


class Relay:
    CUT = object()

    def __init__(self, target_port: int, s2c=None, c2s=None):
        self.target_port = target_port
        self.s2c, self.c2s = s2c, c2s
        self.ls = socket.socket()
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(4)
        self.ls.settimeout(0.2)
        self.port = self.ls.getsockname()[1]
        self.stop = threading.Event()
        self.records = {"s2c": [], "c2s": []}
        self.cut = False
        threading.Thread(target=self._accept, daemon=True).start()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.stop.set()
        self.ls.close()

    def _accept(self):
        while not self.stop.is_set():
            try:
                c, _ = self.ls.accept()
            except (socket.timeout, OSError):
                continue
            try:
                s = socket.create_connection(("127.0.0.1", self.target_port), timeout=5)
            except OSError:
                c.close()
                continue
            for src, dst, hook, name in ((c, s, self.c2s, "c2s"), (s, c, self.s2c, "s2c")):
                threading.Thread(target=self._pump, args=(src, dst, hook, name, c, s), daemon=True).start()

    def _pump(self, src, dst, hook, name, c, s):
        buf = b""
        idx = 0
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                buf += data
                while len(buf) >= 5:
                    n = struct.unpack("!H", buf[3:5])[0]
                    if len(buf) < 5 + n:
                        break
                    rec, buf = buf[:5 + n], buf[5 + n:]
                    self.records[name].append(rec)
                    out = hook(idx, rec[0], rec) if hook else rec
                    idx += 1
                    if out is Relay.CUT:
                        self.cut = True
                        raise OSError("cut")
                    if out:
                        dst.sendall(out)
        except OSError:
            pass
        finally:
            for x in (c, s):
                try:
                    x.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                x.close()
