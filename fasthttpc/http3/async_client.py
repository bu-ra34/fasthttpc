"""asyncio HTTP/3 istemcisi: aioquic sans-IO çekirdeği + asyncio DatagramProtocol.

Aynı QUIC bağlantısı üzerinde eşzamanlı istekler (stream multiplexing) ve akış (stream)
yanıtı: ``stream()`` başlıkları döner, gövde parça parça ``aiter`` ile okunur.
"""
from __future__ import annotations

import asyncio
import time
from typing import AsyncIterator, Optional

from ..security.cert_validator import CertificateValidationError
from .core import (H3Core, Http3ConnectError, Http3Error, Http3RequestRefused, address_probe_window,
                   authority_for)
from .options import Http3Options


class _Proto(asyncio.DatagramProtocol):
    def __init__(self, owner: "AsyncH3Connection"):
        self.owner = owner

    def datagram_received(self, data, addr):
        self.owner._on_datagram(data)

    def error_received(self, exc):
        self.owner._on_udp_error(exc)

    def connection_lost(self, exc):
        self.owner._on_udp_error(exc or Http3Error("UDP taşıması kapandı"))


class AsyncH3Connection:
    def __init__(self, host: str, port: int, connect_host: str, connect_port: int, *,
                 ca_path, impersonate, opts: Http3Options):
        self.origin = (host, port)
        self._target = (connect_host, connect_port)
        self._opts = opts
        self._ca_path, self._impersonate = ca_path, impersonate
        self.core: "Optional[H3Core]" = None
        self._transport = None
        self._timer: "Optional[asyncio.TimerHandle]" = None
        self._state_waiters: "list[asyncio.Future]" = []
        self.loop: "Optional[asyncio.AbstractEventLoop]" = None
        self._connected_addr = None
        self._retired = False

    # -- IO ---------------------------------------------------------------------
    def _on_datagram(self, data: bytes) -> None:
        if self.core.closed:
            return
        try:
            self.core.receive(data, self._connected_addr)
        except Exception as e:      # aioquic ayrıştırma hatası: bağlantıyı düşür
            self.core.error = Http3Error(f"QUIC işleme hatası: {e}")
            self.core._fail_all(self.core.error, mark_closed=True)
        self._after_event()

    def _on_udp_error(self, exc) -> None:
        if self.core is not None and not self.core.closed and not self.core.handshake_done:
            self.core.error = Http3ConnectError(f"UDP hatası: {exc}", exc)
            self.core._fail_all(self.core.error, mark_closed=True)
        self._after_event()

    def _after_event(self) -> None:
        core = self.core
        if self._transport is not None and not self._transport.is_closing():
            for data, _a in core.transmit():
                self._transport.sendto(data)
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        t = core.timer()
        if t is not None and not core.closed and self.loop is not None:
            self._timer = self.loop.call_later(max(0.0, t - time.monotonic()), self._on_timer)
        waiters, self._state_waiters = self._state_waiters, []
        for w in waiters:
            if not w.done():
                w.set_result(None)

    def _on_timer(self) -> None:
        self._timer = None
        self.core.handle_timer()
        self._after_event()

    async def _wait_state(self) -> None:
        fut = self.loop.create_future()
        self._state_waiters.append(fut)
        await fut

    async def connect(self) -> None:
        """Adresleri sırayla dener (bkz. SyncH3Connection.connect); toplam süre connect_timeout."""
        import socket
        o = self._opts
        self.loop = asyncio.get_running_loop()
        try:
            infos = await self.loop.getaddrinfo(self._target[0], self._target[1],
                                                type=socket.SOCK_DGRAM)
        except OSError as e:
            raise Http3ConnectError(f"DNS çözümlenemedi: {e}", e) from e
        addrs: list = []
        for info in infos:
            if (info[0], info[4]) not in addrs:
                addrs.append((info[0], info[4]))
        if not addrs:
            raise Http3ConnectError("UDP için adres bulunamadı")
        deadline = time.monotonic() + o.connect_timeout
        last: "Exception | None" = None
        for i, (family, addr) in enumerate(addrs):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                await self._attempt(family, addr, deadline, address_probe_window(remaining, len(addrs) - i))
                return
            except Http3ConnectError as e:
                last = e
                if isinstance(getattr(e, "cause", None), CertificateValidationError):
                    raise
        raise last or Http3ConnectError("QUIC el sıkışması zaman aşımı")

    async def _attempt(self, family, addr, deadline: float, probe: "Optional[float]") -> None:
        o = self._opts
        host, port = self.origin
        try:
            # asyncio remote_addr için 2'li (host, port) ister; aile adresle eşleşir
            # (IPv6 4'lü adresi AF_INET soketine verilmez). scope id gerekiyorsa host'ta %scope.
            host_part = addr[0] if len(addr) == 2 or not addr[3] else f"{addr[0]}%{addr[3]}"
            self._transport, _ = await self.loop.create_datagram_endpoint(
                lambda: _Proto(self), remote_addr=(host_part, addr[1]), family=family)
        except OSError as e:
            raise Http3ConnectError(f"UDP soketi açılamadı: {e}", e) from e
        self._connected_addr = addr
        self.core = H3Core(host, port, ca_path=self._ca_path, impersonate=self._impersonate,
                           idle_timeout=o.idle_timeout, clock=time.monotonic)
        self.core.connect(addr)
        self._after_event()
        try:
            if probe is not None:
                try:
                    await asyncio.wait_for(self._wait_first_response(),
                                           min(probe, deadline - time.monotonic()))
                except asyncio.TimeoutError:
                    if self.core.datagrams_received == 0:
                        raise asyncio.TimeoutError(f"{probe:.2f} sn içinde yanıt yok") from None
            await asyncio.wait_for(self._wait_handshake(), max(0.0, deadline - time.monotonic()))
        except (asyncio.TimeoutError, Http3Error) as e:
            err = self.core.error
            await self.close()
            if isinstance(err, Http3ConnectError):
                raise err from None
            raise Http3ConnectError(f"QUIC el sıkışması başarısız: {e or 'zaman aşımı'}", e) from e
        if not self.core.handshake_done:
            err = self.core.error
            await self.close()
            raise err or Http3ConnectError("QUIC el sıkışması başarısız")

    async def _wait_first_response(self) -> None:
        core = self.core
        while not (core.handshake_done or core.closed or core.datagrams_received):
            await self._wait_state()

    async def _wait_handshake(self) -> None:
        while not (self.core.handshake_done or self.core.closed):
            await self._wait_state()

    @property
    def usable(self) -> bool:
        c = self.core
        return (c is not None and c.usable
                and time.monotonic() - c.last_activity < self._opts.idle_timeout)

    @property
    def finished(self) -> bool:
        return self._transport is None

    def retire(self) -> None:
        """Yeni istek alma; süren istekler bitince (son akış serbest bırakılınca) kapan."""
        self._retired = True
        if self.core is None or not self.core.streams:
            self._close_now()

    def _release(self, st) -> None:
        self.core.release(st)
        if self._retired and not self.core.streams:
            self._close_now()

    # -- istekler ---------------------------------------------------------------
    async def _open(self, method, path, headers, body):
        st = self.core.send_request(method, authority_for(*self.origin), path, headers, body)
        evt = asyncio.Event()
        st.notify = evt.set
        self._after_event()
        return st, evt

    async def request(self, method: str, path: str, headers, body: bytes = b"",
                      timeout: Optional[float] = None):
        """``(headers_list, body)`` döner; hata -> Http3Error/TimeoutError/Http3RequestRefused."""
        st, evt = await self._open(method, path, headers, body)
        try:
            async def _wait():
                while not st.ended:
                    evt.clear()
                    if st.ended:
                        break
                    await evt.wait()
            await asyncio.wait_for(_wait(), timeout)
            if st.error is not None:
                raise st.error
            return st.headers, b"".join(st.chunks)
        finally:
            self._release(st)

    async def stream(self, method: str, path: str, headers, body: bytes = b"",
                     timeout: Optional[float] = None):
        """Akış yanıtı: ``(headers_list, async_iterator[bytes])``. Başlıklar gelince döner;
        iteratör tüketilince/kapanınca stream serbest bırakılır."""
        st, evt = await self._open(method, path, headers, body)

        async def _until(pred):
            while not pred():
                evt.clear()
                if pred():
                    break
                await evt.wait()

        try:
            await asyncio.wait_for(_until(lambda: st.headers is not None or st.ended), timeout)
            if st.headers is None:
                raise st.error or Http3Error("yanıt başlıkları gelmedi")
        except BaseException:
            self._release(st)
            raise

        async def body_iter() -> AsyncIterator[bytes]:
            try:
                while True:
                    while st.chunks:
                        yield st.chunks.popleft()
                    if st.ended:
                        if st.error is not None:
                            raise st.error
                        return
                    evt.clear()
                    if st.chunks or st.ended:
                        continue
                    await asyncio.wait_for(evt.wait(), timeout)
            finally:
                self._release(st)

        return st.headers, body_iter()

    async def close(self) -> None:
        self._close_now()

    def _close_now(self) -> None:
        if self.core is not None and not self.core.closed:
            self.core.close()
        if self._transport is not None:
            if self.core is not None:
                for data, _a in self.core.transmit():
                    self._transport.sendto(data)
            self._transport.close()
            self._transport = None
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
