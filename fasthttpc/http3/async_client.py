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
        # Taşıma GERÇEKTEN kapandığında (soket kapatıldı) tamamlanır: transport.close()
        # eşzamansızdır; ProactorEventLoop'ta süren bir overlapped yazma varken soketin
        # kapanması o yazma bitene dek ertelenir.
        self.lost: "asyncio.Future[None]" = asyncio.get_running_loop().create_future()
        self.transport: "Optional[asyncio.DatagramTransport]" = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.owner._on_datagram(data)

    def error_received(self, exc):
        self.owner._on_udp_error(exc)

    def connection_lost(self, exc):
        if not self.lost.done():
            self.lost.set_result(None)
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
        self._protos: "list[_Proto]" = []      # kapanışı beklenecek UDP protokolleri

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
        core = self.core
        if core is not None and not core.closed:
            if not core.handshake_done:
                core.error = Http3ConnectError(f"UDP hatası: {exc}", exc)
                core._fail_all(core.error, mark_closed=True)
            elif self._udp_error_is_fatal(exc):
                # El sıkışmadan SONRA: eş artık yok (ICMP reddi) ya da taşıma okumayı bıraktı.
                # Bağlantı "kullanılabilir" kalsaydı sonraki istekler yanıt alamayıp zaman
                # aşımına uğrardı; kapatılır, sıradaki istek yeni bağlantı kurar.
                core.error = Http3Error(f"UDP hatası: {exc}")
                core._fail_all(core.error, mark_closed=True)
        self._after_event()

    def _is_proactor(self) -> bool:
        proactor = getattr(asyncio, "ProactorEventLoop", None)
        return proactor is not None and isinstance(self.loop, proactor)

    def _udp_error_is_fatal(self, exc) -> bool:
        """Kurulu bağlantıda UDP hatası bağlantıyı bitirir mi?

        ICMP kaynaklı ret/sıfırlama her zaman. Windows ProactorEventLoop'ta HER alım hatası:
        datagram taşıması (CPython 3.12 ``_ProactorDatagramTransport._loop_reading``) hatada
        ``error_received`` çağırıp yeni okuma başlatmaz, soket bir daha veri vermez. Diğer
        döngülerde geçici gönderim hataları (ENOBUFS, EMSGSIZE) QUIC kayıp kurtarmasına kalır."""
        if isinstance(exc, (ConnectionRefusedError, ConnectionResetError)):
            return True
        return self._is_proactor()

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
            self._transport, proto = await self.loop.create_datagram_endpoint(
                lambda: _Proto(self), remote_addr=(host_part, addr[1]), family=family)
            self._protos.append(proto)
        except OSError as e:
            raise Http3ConnectError(f"UDP soketi açılamadı: {e}", e) from e
        # Bu denemenin taşıması HER çıkış yolunda (hata, zaman aşımı, iptal) kapatılır ve
        # connection_lost'u beklenir; yalnızca el sıkışması başarıyla biterse bağlantıya kalır.
        ok = False
        try:
            await self._handshake_on(addr, host, port, o, deadline, probe)
            ok = True
        finally:
            if not ok:
                self._close_now()
                try:
                    await self.wait_transport_closed()
                except BaseException:              # iptal: taşıma close() edildi, kapanış sürer
                    pass

    async def _handshake_on(self, addr, host, port, o, deadline: float, probe: "Optional[float]") -> None:
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
            if isinstance(err, Http3ConnectError):
                raise err from None
            raise Http3ConnectError(f"QUIC el sıkışması başarısız: {e or 'zaman aşımı'}", e) from e
        if not self.core.handshake_done:
            raise self.core.error or Http3ConnectError("QUIC el sıkışması başarısız")

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
        """Kapatıldı VE UDP taşıması gerçekten kapandı (soket serbest)."""
        return self._transport is None and all(p.lost.done() for p in self._protos)

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
        """Bağlantıyı kapatır ve UDP taşımasının gerçekten kapanmasını (connection_lost) bekler.

        ``transport.close()`` soketi hemen kapatmaz: kapanış olay döngüsünün sonraki
        turlarında olur (ProactorEventLoop'ta süren overlapped yazma bitene dek ertelenir).
        Beklenmeden dönülürse döngü (ör. ``asyncio.run`` sonu) kapanınca taşıma yarım kalır:
        açık UDP soketi, ``_ProactorBasePipeTransport.__del__`` ResourceWarning'i."""
        self._close_now()
        await self.wait_transport_closed()

    async def wait_transport_closed(self, timeout: float = 2.0) -> None:
        """Kapatılmış UDP taşımalarının ``connection_lost``'unu (en fazla ``timeout`` sn) bekler."""
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            return
        protos = [p for p in self._protos if not p.lost.done() and p.lost.get_loop() is running]
        if not protos:
            return
        _, pending = await asyncio.wait([asyncio.shield(p.lost) for p in protos], timeout=timeout / 2)
        if pending:
            # Kapanış takıldı (bkz. _close_now: Proactor datagram hatası): zorla kapat.
            for p in protos:
                if not p.lost.done() and p.transport is not None:
                    p.transport.abort()
            rest = [asyncio.shield(p.lost) for p in protos if not p.lost.done()]
            if rest:
                await asyncio.wait(rest, timeout=timeout / 2)

    def _close_now(self) -> None:
        if self.core is not None and not self.core.closed:
            self.core.close()
        if self._transport is not None:
            if self.core is not None:
                for data, _a in self.core.transmit():
                    self._transport.sendto(data)
            self._transport.close()
            if self._is_proactor():
                # CPython (3.12) _ProactorDatagramTransport hatası: close() sırasında süren bir
                # yazma (az önce gönderilen CONNECTION_CLOSE) varsa connection_lost o yazma
                # bitince çağrılmalı, ama _loop_writing ``_conn_lost``'u görüp erken döner:
                # taşıma HİÇ kapanmaz, soket __del__'e kalır (ResourceWarning). abort()
                # kapanışı zorlar; datagram çekirdeğe WSASendTo ile zaten verilmiştir.
                self._transport.abort()
            self._transport = None
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
