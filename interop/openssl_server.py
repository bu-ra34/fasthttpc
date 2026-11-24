"""`openssl s_server` alt süreç yönetimi (rastgele port, hazır olana kadar bekleme)."""
from __future__ import annotations

import functools
import os
import queue
import shutil
import socket
import subprocess
import sys
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


@functools.lru_cache(maxsize=None)
def s_server_supports_group(group: str) -> bool:
    """Yerel `openssl s_server` bu TLS grubunu (``-groups``) ayarlayabiliyor mu?

    Tanımadığı grupta s_server başlarken ``SSL_CONF_cmd(-groups, ...)`` hatasıyla çıkar;
    tanıyorsa dinlemeye başlar (``ACCEPT`` satırı). ``-nocert``: yalnızca yoklama, sertifika gerekmez.
    """
    if OPENSSL is None:
        return False
    proc = subprocess.Popen(
        [OPENSSL, "s_server", "-accept", "127.0.0.1:0", "-nocert", "-groups", group],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={**os.environ, "OPENSSL_CONF": os.devnull})
    killer = threading.Timer(15, proc.kill)      # takılırsa (beklenmez) yoklamayı sonlandır
    killer.start()
    try:
        return any(raw.startswith(b"ACCEPT") for raw in iter(proc.stdout.readline, b""))
    finally:
        killer.cancel()
        if proc.poll() is None:
            proc.kill()
        proc.wait(5)
        proc.stdout.close()


_HTTP_MODES = ("-WWW", "-HTTP")


def http_binmode_supported() -> bool:
    """OpenSSL 3.x: `-http_server_binmode` (-WWW/-HTTP dosyalarını ikili kipte aç)."""
    return OPENSSL is not None and s_server_supports("-http_server_binmode")


def text_mode_files() -> bool:
    """True: dosyalar Windows C çalışma zamanının METİN kipinde okunacak (0x1A = EOF, CRLF -> LF).

    apps/s_server.c: ``opmode = (http_server_binmode == 1) ? "rb" : "r"``. Windows'ta bayrak
    desteklenmiyorsa (OpenSSL < 3) test verisi bu kipe dayanıklı üretilmelidir."""
    return sys.platform == "win32" and not http_binmode_supported()


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
            extra = []
            if sys.platform == "win32" and any(a in _HTTP_MODES for a in self.args) \
                    and http_binmode_supported():
                extra = ["-http_server_binmode"]   # aksi hâlde ikili dosyalar 0x1A'da kesilir
            self.proc = subprocess.Popen(
                [OPENSSL, "s_server", "-accept", f"127.0.0.1:{self.port}", *extra, *self.args],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                cwd=self.cwd, env={**os.environ, "OPENSSL_CONF": os.devnull})
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
