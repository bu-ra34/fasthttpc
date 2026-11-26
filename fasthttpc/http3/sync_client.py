"""Senkron HTTP/3 istemcisi: aioquic'in sans-IO çekirdeğini doğrudan UDP soketiyle sürer
(thread/olay döngüsü yok). Bağlantı başına bir kilit: sync Session thread-safe kalır."""
from __future__ import annotations

import select
import socket
import threading
import time
from typing import Optional

from ..security.cert_validator import CertificateValidationError
from .core import (H3Core, Http3ConnectError, Http3Error, Http3RequestRefused, address_probe_window,
                   authority_for)
from .options import Http3Options


class SyncH3Connection:
    def __init__(self, host: str, port: int, connect_host: str, connect_port: int, *,
                 ca_path, impersonate, opts: Http3Options):
        self.origin = (host, port)
        self._target = (connect_host, connect_port)
        self._opts = opts
        self._ca_path, self._impersonate = ca_path, impersonate
        self._lock = threading.RLock()
        self._sock: "Optional[socket.socket]" = None
        self.core: "Optional[H3Core]" = None

    # -- IO ---------------------------------------------------------------------
    def _flush(self) -> None:
        for data, _addr in self.core.transmit():
            try:
                self._sock.send(data)
            except (BlockingIOError, InterruptedError):
                pass    # QUIC kaybı kendi kurtarır
            except OSError as e:
                raise Http3Error(f"UDP gönderim hatası: {e}") from e

    def _run(self, done, deadline: float, what: str) -> None:
        core = self.core
        while not done():
            self._flush()
            if done():
                break
            now = time.monotonic()
            if now >= deadline:
                raise TimeoutError(f"HTTP/3 {what} zaman aşımı")
            t = core.timer()
            wait = deadline - now if t is None else min(deadline, t) - now
            r, _, _ = select.select([self._sock], [], [], max(0.0, min(wait, 1.0)))
            if r:
                for _ in range(64):
                    try:
                        data = self._sock.recv(65535)
                    except (BlockingIOError, InterruptedError):
                        break
                    except (ConnectionRefusedError, ConnectionResetError):
                        # Linux: ECONNREFUSED. Windows: önceki gönderime ICMP port unreachable
                        # gelince SONRAKİ recv WSAECONNRESET (10054, ConnectionResetError) verir
                        # (SIO_UDP_CONNRESET). İkisi de aynı: eş bu porta dinlemiyor.
                        raise Http3Error("UDP: bağlantı reddedildi (ICMP port unreachable)") from None
                    core.receive(data, self._target)
            core.handle_timer()
        self._flush()

    def connect(self) -> None:
        """getaddrinfo sonuçlarını sırayla dener (Happy Eyeballs benzeri); toplam süre
        ``connect_timeout``. ICMP reddi/hata anında, son olmayan adresten
        ``address_probe_window`` içinde hiç yanıt gelmezse sonraki adrese geçilir; yanıt veren
        adresin el sıkışması kalan sürenin tamamını kullanır. Sertifika hatasında DURULUR."""
        o = self._opts
        try:
            infos = socket.getaddrinfo(self._target[0], self._target[1], type=socket.SOCK_DGRAM)
        except OSError as e:
            raise Http3ConnectError(f"DNS çözümlenemedi: {e}", e) from e
        addrs, seen = [], set()
        for family, _, _, _, addr in infos:
            if addr not in seen:
                seen.add(addr)
                addrs.append((family, addr))
        if not addrs:
            raise Http3ConnectError("UDP için adres bulunamadı")
        deadline = time.monotonic() + o.connect_timeout
        last: "Exception | None" = None
        for i, (family, addr) in enumerate(addrs):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                self._attempt(family, addr, deadline, address_probe_window(remaining, len(addrs) - i))
                return
            except Http3ConnectError as e:
                last = e
                if isinstance(getattr(e, "cause", None), CertificateValidationError):
                    raise
        raise last or Http3ConnectError("QUIC el sıkışması zaman aşımı")

    def _attempt(self, family, addr, deadline: float, probe: "Optional[float]") -> None:
        o = self._opts
        host, port = self.origin
        try:
            self._sock = socket.socket(family, socket.SOCK_DGRAM)
            self._sock.setblocking(False)
            self._sock.connect(addr)
        except OSError as e:
            if self._sock is not None:
                self._sock.close()
                self._sock = None
            raise Http3ConnectError(f"UDP soketi açılamadı: {e}", e) from e
        self.core = H3Core(host, port, ca_path=self._ca_path, impersonate=self._impersonate,
                           idle_timeout=o.idle_timeout, clock=time.monotonic)
        self._target = addr
        self.core.connect(addr)
        core = self.core
        try:
            if probe is not None:
                try:
                    self._run(lambda: core.handshake_done or core.closed or core.datagrams_received > 0,
                              min(deadline, time.monotonic() + probe), "el sıkışma")
                except TimeoutError:
                    if core.datagrams_received == 0:
                        raise TimeoutError(f"HTTP/3 el sıkışma: {probe:.2f} sn içinde yanıt yok") from None
            self._run(lambda: core.handshake_done or core.closed, deadline, "el sıkışma")
        except (TimeoutError, Http3Error) as e:
            err = self.core.error
            self.close()
            raise (err if isinstance(err, Http3ConnectError) else
                   Http3ConnectError(f"QUIC el sıkışması başarısız: {e}", e)) from e
        if not self.core.handshake_done:
            err = self.core.error
            self.close()
            raise err or Http3ConnectError("QUIC el sıkışması başarısız")

    @property
    def usable(self) -> bool:
        c = self.core
        return (c is not None and c.usable
                and time.monotonic() - c.last_activity < self._opts.idle_timeout)

    # -- istekler ---------------------------------------------------------------
    def request_many(self, reqs: "list[tuple]", timeout: Optional[float]):
        """reqs: (method, path, headers, body) listesi. Aynı QUIC bağlantısında eşzamanlı
        (multiplexing) gönderir; her biri için (status, headers, body) ya da Exception döner."""
        with self._lock:
            core = self.core
            authority = authority_for(*self.origin)
            deadline = time.monotonic() + (timeout if timeout is not None else 3600.0)
            streams = []
            for method, path, headers, body in reqs:
                try:
                    streams.append(core.send_request(method, authority, path, headers, body))
                except Http3Error as e:
                    streams.append(e)
            live = [s for s in streams if not isinstance(s, Exception)]
            try:
                self._run(lambda: all(s.ended for s in live) or core.closed, deadline, "istek")
            except TimeoutError as e:
                for s in live:
                    if not s.ended:
                        s.error = e
                        s.ended = True
            out = []
            for s in streams:
                if isinstance(s, Exception):
                    out.append(s)
                    continue
                core.release(s)
                if s.error is not None:
                    out.append(s.error)
                else:
                    out.append((s.headers, b"".join(s.chunks)))
            return out

    def close(self) -> None:
        with self._lock:
            if self.core is not None and not self.core.closed:
                self.core.close()
                try:
                    self._flush()
                except Exception:   # kapanışta hata önemsiz
                    pass
            if self._sock is not None:
                self._sock.close()
                self._sock = None
