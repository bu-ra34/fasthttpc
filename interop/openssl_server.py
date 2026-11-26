"""`openssl s_server` alt süreç yönetimi (rastgele port, hazır olana kadar bekleme)."""
from __future__ import annotations

import functools
import os
import queue
import re
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


# s_server dinlemeye başlayınca "ACCEPT 127.0.0.1:44321" ("[::1]:port") yazar (OpenSSL 1.1.0+).
_ACCEPT_RE = re.compile(r"^ACCEPT(?:\s+\S*:(\d+))?\s*$")


class SServer:
    """Kullanım: with SServer("-cert", c, "-key", k, "-WWW", cwd=dir) as s: s.port ...

    Port seçimi yarışsızdır: s_server ``-accept 127.0.0.1:0`` ile çekirdekten port alır ve
    gerçek portu ``ACCEPT`` satırından okuruz. (Eski yol — boş port seç, kapat, s_server'a
    ver — paralel test süreçlerinde yarışır: araya giren başka bir sunucu portu kapar,
    s_server bağlanamayıp çıkar ama hazır olma yoklaması o yabancı sunucuya bağlanıp
    "hazır" sanabilir.) ACCEPT satırı port içermeyen bir openssl'de boş port seçilir; hazır
    olma yine ``ACCEPT`` satırıyla (yalnızca bizim sürecimizin çıktısı) anlaşılır.
    """

    def __init__(self, *args: str, cwd: "str | None" = None):
        self.args = list(args)
        self.cwd = cwd
        self.proc: "subprocess.Popen | None" = None
        self.port = 0
        self.lines: "queue.Queue[str]" = queue.Queue()
        self.log: "list[str]" = []
        self._pump_thread: "threading.Thread | None" = None
        self._accepted = threading.Event()
        self._accept_port: "int | None" = None

    def __enter__(self) -> "SServer":
        fixed_port = False                 # True: bu openssl ACCEPT satırında port bildirmiyor
        for _ in range(5):
            port = free_port() if fixed_port else 0
            if self._start(port):
                self.port = self._accept_port if self._accept_port is not None else port
                if self.port:
                    return self
                fixed_port = True          # dinliyor ama portu bilmiyoruz: boş portla yeniden
            self.close()
        raise RuntimeError("s_server başlatılamadı: " + "".join(self.log)[-500:])

    def _start(self, port: int) -> bool:
        extra = []
        if sys.platform == "win32" and any(a in _HTTP_MODES for a in self.args) \
                and http_binmode_supported():
            extra = ["-http_server_binmode"]   # aksi hâlde ikili dosyalar 0x1A'da kesilir
        self.log = []
        self.lines = queue.Queue()
        self._accepted = threading.Event()
        self._accept_port = None
        self.proc = subprocess.Popen(
            [OPENSSL, "s_server", "-accept", f"127.0.0.1:{port}", *extra, *self.args],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=self.cwd, env={**os.environ, "OPENSSL_CONF": os.devnull})
        # Pompa kendi sürecinin borusunu alır (self.proc yeniden denemede değişir).
        self._pump_thread = threading.Thread(target=self._pump, args=(self.proc.stdout,), daemon=True)
        self._pump_thread.start()
        return self._wait_ready()

    def _pump(self, stream):
        for raw in iter(stream.readline, b""):
            line = raw.decode("utf-8", "replace")
            self.log.append(line)
            self.lines.put(line)
            if not self._accepted.is_set():
                m = _ACCEPT_RE.match(line.strip())
                if m:
                    self._accept_port = int(m.group(1)) if m.group(1) else None
                    self._accepted.set()

    def _wait_ready(self, timeout=20.0) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self._accepted.wait(0.02):
                return True
            if self.proc.poll() is not None:     # bind/argüman hatası: süreç çıktı
                return self._accepted.is_set()
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

    def wait_count(self, needle: str, n: int, timeout=10.0) -> str:
        """Çıktıda ``needle`` en az ``n`` kez görünene (ya da süre dolana) kadar bekler; tüm
        çıktıyı döner. ``-msg`` satırları pompa iş parçacığıyla eşzamansız gelir: istemci yanıtı
        aldığı anda okunan günlük, sunucunun o el sıkışmaya ait satırlarını henüz içermeyebilir
        (yüklü makinede/paralel koşuda aralıklı düşen denetimler)."""
        end = time.time() + timeout
        while time.time() < end:
            log = "".join(self.log)
            if log.count(needle) >= n:
                return log
            time.sleep(0.02)
        return "".join(self.log)

    def close(self):
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(10)
        # Pompa iş parçacığı boruyu okurken boruyu kapatmak yarıştır: kapanan bir
        # BufferedReader üzerinde readline() yapan iş parçacığı ValueError alır ("I/O
        # operation on closed file" / "PyMemoryView_FromBuffer(): info->buf must not be
        # NULL") ve PytestUnhandledThreadExceptionWarning olur. Süreç öldüğü için boru EOF
        # verir: önce pompanın bitmesini bekleyip sonra boruları kapatırız.
        if self._pump_thread is not None:
            self._pump_thread.join(10)
            assert not self._pump_thread.is_alive(), "s_server çıktı pompası bitmedi"
        for f in (self.proc.stdin, self.proc.stdout):
            if f is not None:
                try:
                    f.close()
                except OSError:          # stdin: süreç öldü, tampondaki veri gönderilemedi
                    pass

    def __exit__(self, *exc):
        self.close()
