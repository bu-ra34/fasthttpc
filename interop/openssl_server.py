"""`openssl s_server` alt süreç yönetimi (rastgele port, hazır olana kadar bekleme)."""
from __future__ import annotations

import os
import queue
import shutil
import socket
import subprocess
import threading
import time

OPENSSL = shutil.which("openssl")


def openssl_text(*args: str) -> str:
    return subprocess.run([OPENSSL, *args], capture_output=True, text=True, timeout=20).stdout


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def s_server_supports(flag: str) -> bool:
    out = subprocess.run([OPENSSL, "s_server", "-help"], capture_output=True, text=True).stderr
    return flag in out


class SServer:
    """Kullanım: with SServer("-cert", c, "-key", k, "-WWW", cwd=dir) as s: s.port ..."""

    def __init__(self, *args: str, cwd: "str | None" = None):
        self.args = list(args)
        self.cwd = cwd
        self.proc: "subprocess.Popen | None" = None
        self.port = 0
        self.lines: "queue.Queue[str]" = queue.Queue()
        self.log: "list[str]" = []

    def __enter__(self) -> "SServer":
        for _ in range(5):
            self.port = free_port()
            self.proc = subprocess.Popen(
                [OPENSSL, "s_server", "-accept", f"127.0.0.1:{self.port}", *self.args],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                cwd=self.cwd, env={**os.environ, "OPENSSL_CONF": "/dev/null"})
            threading.Thread(target=self._pump, daemon=True).start()
            if self._wait_ready():
                return self
            self.close()
        raise RuntimeError("s_server başlatılamadı: " + "".join(self.log)[-500:])

    def _pump(self):
        for raw in iter(self.proc.stdout.readline, b""):
            line = raw.decode("utf-8", "replace")
            self.log.append(line)
            self.lines.put(line)

    def _wait_ready(self, timeout=8.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            if self.proc.poll() is not None:
                return False
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return True
            except OSError:
                time.sleep(0.02)
        return False

    def send(self, text: str):
        self.proc.stdin.write(text.encode())
        self.proc.stdin.flush()

    def wait_line(self, needle: str, timeout=10.0) -> str:
        end = time.time() + timeout
        while time.time() < end:
            for ln in self.log:
                if needle in ln:
                    return ln
            time.sleep(0.02)
        raise TimeoutError(f"s_server çıktısında {needle!r} yok: {''.join(self.log)[-800:]}")

    def close(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(5)
        for f in (self.proc.stdin, self.proc.stdout) if self.proc else ():
            try:
                f.close()
            except Exception:
                pass

    def __exit__(self, *exc):
        self.close()
