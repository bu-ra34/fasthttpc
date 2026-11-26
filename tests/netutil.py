"""Test sunucuları için çift-yığınlı (127.0.0.1 + ::1) loopback dinleme.

İstemci "localhost"u önce ::1'e çözebilir (Windows'ta tipik). Sunucu yalnızca 127.0.0.1'de
dinlerse ::1 denemesi reddedilir (Windows'ta ~2 sn); sunucu iki adreste de AYNI portu dinlerse
bağlantı ilk denemede kurulur ve IPv6 yolu da gerçekten sınanır. IPv6 yoksa sessizce yalnız IPv4.
"""
from __future__ import annotations

import asyncio
import atexit
import socket
import threading
from typing import Any, Awaitable, Callable, Optional


_RESERVED: "list[socket.socket]" = []
atexit.register(lambda: [s.close() for s in _RESERVED])


def refused_port() -> int:
    """Bağlantıyı REDDEDEN (RST/ECONNREFUSED) bir TCP portu.

    "Boş port seç ve kapat" paralel test süreçlerinde yarışır: araya giren başka bir süreç
    portu dinlemeye başlarsa "kapalı port" testi bir sunucuya bağlanır. Burada port, bağlanmış
    ama dinlemeyen bir sokete süreç boyunca ayrılır: kimse onu alamaz ve dinleyen olmadığı için
    çekirdek bağlantıyı reddeder (Linux/macOS/Windows)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    _RESERVED.append(s)
    return s.getsockname()[1]


def dual_endpoint() -> "tuple[list[str], int]":
    """(host listesi, ortak boş port). IPv6 kullanılamıyorsa (["127.0.0.1"], port)."""
    if not socket.has_ipv6:
        return ["127.0.0.1"], 0
    for _ in range(20):
        s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s4.bind(("127.0.0.1", 0))
        port = s4.getsockname()[1]
        s6 = None
        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)   # çekirdekte IPv6 yoksa EAFNOSUPPORT
            s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s6.bind(("::1", port))
        except OSError as e:
            s4.close()
            if s6 is not None:
                s6.close()
            if e.errno in (98, 10048):        # EADDRINUSE: başka port dene
                continue
            return ["127.0.0.1"], 0            # ::1 yok/kapalı
        s4.close()
        s6.close()
        return ["127.0.0.1", "::1"], port
    return ["127.0.0.1"], 0


def linger_close(sock: socket.socket, timeout: float = 2.0) -> None:
    """Soketi RST üretmeden kapatır: yazma yönünü kapatıp (FIN) karşı taraf kapatana ya da
    ``timeout`` dolana kadar gelen veriyi okuyup atar, sonra kapatır.

    Alım tamponunda okunmamış veri varken ``close()`` RST gönderir; RST, istemcinin henüz
    okumadığı yanıtı onun çekirdeğinde siler (bkz. fasthttpc/transport/lingering.py)."""
    try:
        sock.shutdown(socket.SHUT_WR)
        sock.settimeout(timeout)
        while sock.recv(65536):
            pass
    except OSError:
        pass
    finally:
        sock.close()


async def _quiet(aw) -> None:
    try:
        await aw
    except Exception:  # noqa: BLE001 - kapanış hatası testin konusu değil
        pass


class TrackedServer:
    """``asyncio.Server`` + bağlantı görevlerinin takibi.

    Python 3.10/3.11'de ``Server.wait_closed()`` bağlantı görevlerini beklemez ve görevlere
    güçlü referans tutulmaz; olay döngüsü kapandıktan sonra çöp toplanan bir görevin
    ``finally``'si (``writer.close()``) "Event loop is closed" ile patlar ve yarım kalan
    soketler ResourceWarning verir. Burada her bağlantı görevi ve yazıcısı tutulur:

      * ``close()``          : yalnızca dinlemeyi bırakır (stdlib ile aynı anlam).
      * ``wait_closed()`` / ``aclose()`` / ``async with``: dinlemeyi bırakır, bağlantı
        görevlerini iptal edip bekler, yazıcıları kapatır (TLS kapanışı yanıtsız kalırsa
        kısa süre sonra TCP'yi keser) — döngü kapanmadan her şey temizlenir.
      * Testin unuttuğu sunucular için bir bekçi görev vardır: döngü kapanırken
        (``asyncio.run`` kalan görevleri iptal eder) aynı temizliği yapar.
    """

    def __init__(self, cb: Callable[..., Awaitable[Any]]):
        self._cb = cb
        self._server: Optional[asyncio.AbstractServer] = None
        self._tasks: "set[asyncio.Task]" = set()
        self._writers: "list[asyncio.StreamWriter]" = []
        self._shutdown_started = False
        self._shutdown_done: Optional[asyncio.Future] = None
        self._guard: Optional[asyncio.Task] = None

    async def _start(self, *args: Any, **kw: Any) -> "TrackedServer":
        self._server = await asyncio.start_server(self._handle, *args, **kw)
        self._guard = asyncio.ensure_future(self._guardian())
        return self

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.append(writer)
        if self._shutdown_started:          # kapanış başladıktan sonra kabul edilmiş bağlantı
            writer.close()
            return
        task = asyncio.current_task()
        assert task is not None
        self._tasks.add(task)
        try:
            await self._cb(reader, writer)
        finally:
            self._tasks.discard(task)

    async def _guardian(self) -> None:
        try:
            await asyncio.get_running_loop().create_future()      # döngü kapanana kadar
        finally:
            await self._shutdown()

    async def _shutdown(self) -> None:
        if self._shutdown_started:
            if self._shutdown_done is not None and not self._shutdown_done.done():
                await asyncio.shield(self._shutdown_done)
            return
        self._shutdown_started = True
        self._shutdown_done = asyncio.get_running_loop().create_future()
        try:
            assert self._server is not None
            self._server.close()
            me = asyncio.current_task()
            tasks = [t for t in self._tasks if t is not me and not t.done()]
            for t in tasks:
                t.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            for w in self._writers:
                w.close()
            waits = {asyncio.ensure_future(_quiet(w.wait_closed())): w for w in self._writers}
            if waits:
                _, pending = await asyncio.wait(waits, timeout=2.0)
                for t in pending:            # karşı taraf TLS close_notify'a yanıt vermedi
                    t.cancel()
                    waits[t].transport.abort()
                if pending:
                    await asyncio.wait(pending)
                    await asyncio.sleep(0)   # abort'un connection_lost geri çağrısı
            if self._guard is not None and self._guard is not me:
                self._guard.cancel()
        finally:
            self._shutdown_done.set_result(None)

    # -- asyncio.Server arayüzü
    @property
    def sockets(self) -> Any:
        assert self._server is not None
        return self._server.sockets

    def close(self) -> None:
        assert self._server is not None
        self._server.close()

    async def wait_closed(self) -> None:
        await self._shutdown()

    aclose = wait_closed

    async def __aenter__(self) -> "TrackedServer":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._shutdown()

    def __getattr__(self, name: str) -> Any:      # serve_forever, is_serving, get_loop ...
        return getattr(self._server, name)


async def start_server(client_connected_cb: Callable[..., Awaitable[Any]], host: Any = "127.0.0.1",
                       port: int = 0, **kw: Any) -> TrackedServer:
    """``asyncio.start_server`` — bağlantı görevleri izlenen ``TrackedServer`` döner."""
    return await TrackedServer(client_connected_cb)._start(host, port, **kw)


async def start_dual(client_connected_cb: Callable[..., Awaitable[Any]], **kw: Any) -> TrackedServer:
    """``start_server`` — 127.0.0.1 ve ::1'de aynı portta.

    ``dual_endpoint`` portu seçip bırakır; başka bir süreç araya girerse bind başarısız olur:
    birkaç kez yeni portla denenir, sonra yalnızca IPv4 (port 0, yarışsız)."""
    for _ in range(5):
        hosts, port = dual_endpoint()
        if len(hosts) == 1:
            break
        try:
            return await start_server(client_connected_cb, hosts, port, **kw)
        except OSError:                       # port yarışı kaybedildi / IPv6 bind hatası
            continue
    return await start_server(client_connected_cb, "127.0.0.1", 0, **kw)


def close_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Durmuş bir döngüyü ``asyncio.run`` gibi kapatır: kalan görevleri iptal edip bekler,
    async üreteçleri sonlandırır, döngüyü kapatır (iş parçacığındaki döngüler için)."""
    try:
        for _ in range(20):
            tasks = [t for t in asyncio.all_tasks(loop) if not t.done()]
            if not tasks:
                break
            for t in tasks:
                t.cancel()
            loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
        loop.run_until_complete(loop.shutdown_asyncgens())
    finally:
        asyncio.set_event_loop(None)
        loop.close()


class LoopThread:
    """Ayrı iş parçacığında çalışan asyncio döngüsü (sahte sunucular için).

    Döngü iş parçacığının KENDİSİNDE kurulur: Windows'ta ``ProactorEventLoop`` ana iş
    parçacığında oluşturulursa ``signal.set_wakeup_fd``'yi kendi soketine çevirir (ve ancak
    ``close()``'ta geri alır); aynı süreçte ana iş parçacığında çalışan trio bunu görüp
    "signal handling code might have collided" RuntimeWarning'i verir. ``close()``
    tüm görevleri (sunucu bekçileri dahil) iptal edip bekler, döngüyü durdurup kapatır.
    """

    def __init__(self) -> None:
        self._ready = threading.Event()
        self.loop: asyncio.AbstractEventLoop
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        assert self._ready.wait(10), "olay döngüsü iş parçacığı başlamadı"

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.loop = loop
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            close_loop(loop)

    def call(self, coro: Awaitable[Any], timeout: float = 10) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)   # type: ignore[arg-type]

    def close(self) -> None:
        async def cancel_all() -> None:
            me = asyncio.current_task()
            for _ in range(20):               # iptal sırasında doğan görevler (geç kabul) dahil
                tasks = [t for t in asyncio.all_tasks() if t is not me]
                if not tasks:
                    return
                for t in tasks:
                    t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        if self._thread.is_alive():
            try:
                self.call(cancel_all(), timeout=15)
            finally:
                self.loop.call_soon_threadsafe(self.loop.stop)
                self._thread.join(10)
