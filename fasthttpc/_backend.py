"""
fasthttpc — async G/Ç arka ucu soyutlaması (asyncio / trio).

Tasarım (httpx'ten farkı: anyio ZORUNLU DEĞİL):

  * **asyncio** altında bu modül yalnızca stdlib asyncio'ya ince bir geçiştir:
    ``asyncio.wait_for``, ``asyncio.sleep``, ``asyncio.Semaphore`` ... aynen
    çağrılır (davranış önceki sürümle BİREBİR aynı; ``anyio`` gerekmez).
  * **trio** altında (çalışan bir trio görevinden çağrıldığında) aynı arayüz
    ``anyio`` ilkelleriyle (``connect_tcp``, ``fail_after``, ``Lock``, ``Event``,
    ``Semaphore``, ``create_task_group``, ``TLSStream``) gerçeklenir. ``anyio`` +
    ``trio`` ``pip install fasthttpc[trio]`` ile gelir; yoksa trio altında
    anlaşılır bir ``ImportError`` verilir.

Arka uç, her çağrıda ÇALIŞAN görevden belirlenir (``current_backend``): aynı
``AsyncSession`` sınıfı asyncio da trio da altında çalışır.

Akış arayüzü (``read``/``readexactly``/``readuntil``/``at_eof``/``write``/
``drain``/``close``/``wait_closed``/``is_closing``/``get_extra_info``/
``start_tls``) asyncio ``StreamReader``/``StreamWriter`` yüzeyinin alt kümesidir;
trio'da :class:`AnyioStream` bunu hem okuyucu hem yazıcı olarak sağlar.
"""
from __future__ import annotations

import asyncio
import sys
from typing import Any, Awaitable, Callable, Optional

from ._log import get_logger

logger = get_logger("backend")

_TRIO_HINT = ("trio altında fasthttpc için 'anyio' ve 'trio' gerekir: pip install 'fasthttpc[trio]'")


# --------------------------------------------------------------- arka uç tespiti
def current_backend(default: Optional[str] = "asyncio") -> Optional[str]:
    """Çalışan görevin arka ucu: ``"asyncio"`` | ``"trio"`` (hiçbiri yoksa ``default``)."""
    try:
        asyncio.get_running_loop()
        return "asyncio"
    except RuntimeError:
        pass
    trio = sys.modules.get("trio")
    if trio is not None:
        try:
            trio.lowlevel.current_task()
            return "trio"
        except RuntimeError:
            pass
    return default


def _is_trio() -> bool:
    return current_backend() == "trio"


def _anyio():
    try:
        import anyio
        return anyio
    except ImportError as e:  # pragma: no cover - ortam bağımlı
        raise ImportError(_TRIO_HINT) from e


def current_token() -> Any:
    """Çalışan olay döngüsünü tanımlayan nesne (havuzdaki bağlantı kime ait?).

    Çalışan döngü yoksa ``None``.
    """
    kind = current_backend(None)
    if kind == "asyncio":
        return asyncio.get_running_loop()
    if kind == "trio":
        import trio
        return trio.lowlevel.current_trio_token()
    return None


def cancelled_exc_class() -> type:
    """İptal istisnası: asyncio.CancelledError | trio.Cancelled."""
    if _is_trio():
        import trio
        return trio.Cancelled
    return asyncio.CancelledError


# ------------------------------------------------------------------ zaman / uyku
async def sleep(delay: float) -> None:
    if _is_trio():
        await _anyio().sleep(delay)
    else:
        await asyncio.sleep(delay)


async def wait_for(aw: Awaitable, timeout: Optional[float]) -> Any:
    """``asyncio.wait_for`` eşdeğeri; zaman aşımında HER İKİ arka uçta
    ``asyncio.TimeoutError`` (3.11+'da yerleşik TimeoutError ile aynı) yükselir."""
    if not _is_trio():
        return await asyncio.wait_for(aw, timeout)
    if timeout is None:
        return await aw
    anyio = _anyio()
    try:
        with anyio.fail_after(timeout):
            return await aw
    except TimeoutError as e:
        if isinstance(e, asyncio.TimeoutError):
            raise
        raise asyncio.TimeoutError(*e.args) from None


# --------------------------------------------------------------------- ilkeller
def Lock():
    return _anyio().Lock() if _is_trio() else asyncio.Lock()


def Semaphore(value: int):
    return _anyio().Semaphore(value) if _is_trio() else asyncio.Semaphore(value)


def Event():
    return _anyio().Event() if _is_trio() else asyncio.Event()


class TrioFuture:
    """``asyncio.Future`` alt kümesi (trio altında): set_result/set_exception/
    cancel/done/result/exception/cancelled ve ``await``."""

    def __init__(self):
        self._event = _anyio().Event()
        self._result: Any = None
        self._exc: Optional[BaseException] = None
        self._cancelled = False

    def done(self) -> bool:
        return self._event.is_set()

    def cancelled(self) -> bool:
        return self._cancelled

    def set_result(self, value: Any) -> None:
        if self.done():
            raise asyncio.InvalidStateError("Future zaten tamamlandı")
        self._result = value
        self._event.set()

    def set_exception(self, exc: BaseException) -> None:
        if self.done():
            raise asyncio.InvalidStateError("Future zaten tamamlandı")
        self._exc = exc
        self._event.set()

    def cancel(self) -> bool:
        if self.done():
            return False
        self._cancelled = True
        self._event.set()
        return True

    def result(self) -> Any:
        if not self.done():
            raise asyncio.InvalidStateError("Sonuç henüz hazır değil")
        if self._cancelled:
            raise asyncio.CancelledError()
        if self._exc is not None:
            raise self._exc
        return self._result

    def exception(self) -> Optional[BaseException]:
        if not self.done():
            raise asyncio.InvalidStateError("İstisna henüz hazır değil")
        if self._cancelled:
            raise asyncio.CancelledError()
        return self._exc

    async def _wait(self) -> Any:
        await self._event.wait()
        return self.result()

    def __await__(self):
        return self._wait().__await__()


def new_future():
    """Çalışan arka uca uygun, ``asyncio.Future`` benzeri bekleme nesnesi."""
    if _is_trio():
        return TrioFuture()
    return asyncio.get_running_loop().create_future()


async def wait_future(fut, timeout: Optional[float]) -> bool:
    """``fut`` tamamlanana ya da ``timeout`` dolana kadar bekler (zaman aşımı
    istisna ATMAZ); tamamlandıysa True."""
    if not _is_trio():
        done, _ = await asyncio.wait({fut}, timeout=timeout)
        return bool(done)
    if fut.done():
        return True
    anyio = _anyio()
    with anyio.move_on_after(timeout) as scope:
        await fut._event.wait()
    return not scope.cancelled_caught or fut.done()


async def gather(*aws: Awaitable) -> list:
    """``asyncio.gather`` (return_exceptions=False) eşdeğeri.

    asyncio'da kendisi çağrılır. trio'da bir istek başarısız olursa kalanlar
    iptal edilir (yapısal eşzamanlılık) ve ilk istisna yükselir.
    """
    if not _is_trio():
        return await asyncio.gather(*aws)
    anyio = _anyio()
    results: list = [None] * len(aws)
    first: list[BaseException] = []

    async def run(i: int, aw: Awaitable) -> None:
        try:
            results[i] = await aw
        except Exception as e:  # noqa: BLE001 - ilkini sakla, kalanları iptal et
            if not first:
                first.append(e)
            tg.cancel_scope.cancel()

    async with anyio.create_task_group() as tg:
        for i, aw in enumerate(aws):
            tg.start_soon(run, i, aw)
    if first:
        raise first[0]
    return results


# ----------------------------------------------------------------- arka plan görevi
class TrioTask:
    """Arka plan görevi sapı (``asyncio.Task`` alt kümesi)."""

    def __init__(self):
        anyio = _anyio()
        self._scope = anyio.CancelScope()
        self._done = anyio.Event()
        self._cbs: list[Callable[[Any], None]] = []
        self._trio_task: Any = None

    def cancel(self) -> bool:
        if self._done.is_set():
            return False
        self._scope.cancel()
        return True

    def done(self) -> bool:
        return self._done.is_set()

    def add_done_callback(self, cb: Callable[[Any], None]) -> None:
        if self._done.is_set():
            cb(self)
        else:
            self._cbs.append(cb)

    async def wait(self) -> None:
        await self._done.wait()


def spawn(coro, name: Optional[str] = None):
    """Arka plan görevi başlatır (asyncio: ``Task``; trio: sistem görevi).

    trio'da görev, çağıranın iptal kapsamlarından bağımsızdır (bağlantı okuyucu
    görevi gibi uzun ömürlü işler için) ve ``cancel()``/``cancel_task`` ile
    durdurulur; trio.run biterken de iptal edilir. Hataları yutulup loglanır
    (sistem görevinde kaçan istisna trio.run'ı çökertirdi).
    """
    if not _is_trio():
        return asyncio.get_running_loop().create_task(coro, name=name)
    import trio
    t = TrioTask()

    async def runner() -> None:
        t._trio_task = trio.lowlevel.current_task()
        try:
            with t._scope:
                await coro
        except Exception as e:  # noqa: BLE001
            logger.debug("arka plan görevi hata verdi: %r", e)
        finally:
            t._done.set()
            cbs, t._cbs = t._cbs, []
            for cb in cbs:
                try:
                    cb(t)
                except Exception:  # noqa: BLE001
                    pass

    trio.lowlevel.spawn_system_task(runner, name=name)
    return t


def is_current_task(task) -> bool:
    if isinstance(task, TrioTask):
        import trio
        return task._trio_task is trio.lowlevel.current_task()
    try:
        return task is asyncio.current_task()
    except RuntimeError:
        return False


async def cancel_task(task) -> None:
    """Görevi iptal edip bitmesini bekler (hataları yutar)."""
    if task is None or task.done() or is_current_task(task):
        return
    task.cancel()
    if isinstance(task, TrioTask):
        with _anyio().CancelScope(shield=True):
            await task.wait()
        return
    try:
        await task
    except (asyncio.CancelledError, Exception):  # noqa: BLE001
        pass


async def run_in_thread(func: Callable, *args) -> Any:
    """Bloklayan işlevi thread'de çalıştırır (DoH çözümleme vb.)."""
    if _is_trio():
        import functools
        return await _anyio().to_thread.run_sync(functools.partial(func, *args))
    return await asyncio.get_running_loop().run_in_executor(None, func, *args)


async def close_streams(writers: list, timeout: float) -> None:
    """Boştaki akışların ``wait_closed``'ını en fazla ``timeout`` sn bekler.

    Karşı taraf TLS close_notify'a yanıt vermezse takılmaz; asyncio'da kalanların
    TCP'si hemen bırakılır (abort). Akışlar önceden ``close()`` edilmiş olmalı.
    """
    if not writers:
        return
    if _is_trio():
        anyio = _anyio()
        with anyio.move_on_after(timeout):
            async with anyio.create_task_group() as tg:
                for w in writers:
                    tg.start_soon(_quiet_wait_closed, w)
        return
    waits = [(w, asyncio.ensure_future(w.wait_closed())) for w in writers]
    _, pending = await asyncio.wait([t for _, t in waits], timeout=timeout)
    for w, t in waits:
        if t in pending:
            t.cancel()
            inner = getattr(w, "writer", w)
            transport = getattr(inner, "transport", None)
            if transport is not None:
                transport.abort()       # TCP'yi şimdi bırak
        elif not t.cancelled() and t.exception() is not None:
            logger.debug("wait_closed hatası yok sayıldı: %s", t.exception())


async def _quiet_wait_closed(w) -> None:
    try:
        await w.wait_closed()
    except Exception as e:  # noqa: BLE001
        logger.debug("wait_closed hatası yok sayıldı: %s", e)


# -------------------------------------------------------------------- bağlantılar
async def open_connection(host: str, port: int, *, ssl: Any = None,
                          server_hostname: Optional[str] = None):
    """``(reader, writer)`` döner. asyncio: ``asyncio.open_connection``; trio:
    anyio TCP (+ ``ssl`` verilirse TLS) akışı, okuyucu = yazıcı = :class:`AnyioStream`."""
    if not _is_trio():
        if ssl is None:
            return await asyncio.open_connection(host, port)
        return await asyncio.open_connection(host, port, ssl=ssl, server_hostname=server_hostname)
    anyio = _anyio()
    sock = await anyio.connect_tcp(host, port)
    s = AnyioStream(sock)
    if ssl is not None:
        try:
            await s.start_tls(ssl, server_hostname=server_hostname or host)
        except BaseException:
            s.close()
            raise
    return s, s


class AnyioStream:
    """anyio bayt akışını asyncio StreamReader+StreamWriter yüzeyine uyarlar.

    * ``write`` eşzamanlıdır (tampona yazar), ``drain`` tamponu gönderir;
      böylece StreamWriter ile aynı çağrı düzeni çalışır.
    * Gönderme sırasında iptal/zaman aşımı olursa kısmen yazılmış olabilir:
      akış bozulmuş sayılır (sonraki yazma ConnectionResetError).
    * ``close`` eşzamanlıdır; kalan tamponu gönderip akışı arka planda kapatır,
      ``wait_closed`` bunu bekler.
    """

    _LIMIT = 2 ** 16

    def __init__(self, stream: Any):
        anyio = _anyio()
        self._s = stream
        self._wbuf = bytearray()
        self._rbuf = bytearray()
        self._eof = False
        self._closing = False
        self._broken = False
        self._send_lock = anyio.Lock()
        self._closed_evt = anyio.Event()
        self._close_started = False

    # ------------------------------------------------------------------ okuma
    async def _fill(self) -> bool:
        """Tampona bir parça ekler; EOF'ta False."""
        if self._eof:
            return False
        anyio = _anyio()
        try:
            data = await self._s.receive(65536)
        except anyio.EndOfStream:
            self._eof = True
            return False
        except anyio.ClosedResourceError:
            self._eof = True
            return False
        except anyio.BrokenResourceError as e:
            self._eof = True
            raise ConnectionResetError(f"Bağlantı koptu: {e}") from e
        self._rbuf += data
        return True

    async def read(self, n: int = -1) -> bytes:
        if n == 0:
            return b""
        if n < 0:
            while await self._fill():
                pass
            out = bytes(self._rbuf)
            self._rbuf.clear()
            return out
        if not self._rbuf:
            await self._fill()
        out = bytes(self._rbuf[:n])
        del self._rbuf[:n]
        return out

    async def readexactly(self, n: int) -> bytes:
        while len(self._rbuf) < n:
            if not await self._fill():
                partial = bytes(self._rbuf)
                self._rbuf.clear()
                raise asyncio.IncompleteReadError(partial, n)
        out = bytes(self._rbuf[:n])
        del self._rbuf[:n]
        return out

    async def readuntil(self, sep: bytes = b"\n") -> bytes:
        start = 0
        while True:
            i = self._rbuf.find(sep, start)
            if i != -1:
                end = i + len(sep)
                if end > self._LIMIT:
                    raise asyncio.LimitOverrunError("Ayraç sınırdan sonra bulundu", end)
                out = bytes(self._rbuf[:end])
                del self._rbuf[:end]
                return out
            if len(self._rbuf) > self._LIMIT:
                raise asyncio.LimitOverrunError("Ayraç sınır içinde bulunamadı", len(self._rbuf))
            start = max(0, len(self._rbuf) - len(sep) + 1)
            if not await self._fill():
                partial = bytes(self._rbuf)
                self._rbuf.clear()
                raise asyncio.IncompleteReadError(partial, None)

    def at_eof(self) -> bool:
        return self._eof and not self._rbuf

    # ------------------------------------------------------------------ yazma
    def write(self, data: bytes) -> None:
        if self._closing:
            return
        self._wbuf += data

    async def _flush_locked(self) -> None:
        anyio = _anyio()
        if self._broken:
            raise ConnectionResetError("Bağlantı bozuldu (gönderim yarıda kesilmişti).")
        if not self._wbuf:
            return
        data = bytes(self._wbuf)
        self._wbuf.clear()
        ok = False
        try:
            await self._s.send(data)
            ok = True
        except (anyio.BrokenResourceError, anyio.ClosedResourceError) as e:
            raise ConnectionResetError(f"Bağlantı koptu: {e}") from e
        finally:
            if not ok:
                self._broken = True      # kısmi gönderim olmuş olabilir

    async def drain(self) -> None:
        async with self._send_lock:
            await self._flush_locked()

    # ----------------------------------------------------------------- kapanış
    def is_closing(self) -> bool:
        return self._closing

    def close(self) -> None:
        if self._closing:
            return
        self._closing = True
        coro = self._do_close()
        try:
            spawn(coro, name="fasthttpc-close")
            self._close_started = True
        except RuntimeError:        # çalışan döngü yok: GC kapatır
            coro.close()
            self._closed_evt.set()

    async def _do_close(self) -> None:
        anyio = _anyio()
        try:
            with anyio.CancelScope(shield=True):
                with anyio.move_on_after(1.0):
                    async with self._send_lock:
                        if self._wbuf and not self._broken:
                            try:
                                await self._s.send(bytes(self._wbuf))
                            except Exception:  # noqa: BLE001
                                pass
                        self._wbuf.clear()
                    await self._s.aclose()
        except Exception as e:  # noqa: BLE001
            logger.debug("akış kapatma hatası: %s", e)
        finally:
            self._eof = True
            self._closed_evt.set()

    async def wait_closed(self) -> None:
        if not self._close_started:
            self.close()
        await self._closed_evt.wait()

    # -------------------------------------------------------------------- TLS
    async def start_tls(self, ctx: Any, *, server_hostname: Optional[str] = None) -> None:
        """Mevcut akışın üstüne TLS (stdlib ``ssl`` bağlamı) kurar."""
        from anyio.streams.tls import TLSStream
        await self.drain()
        self._rbuf.clear()
        self._s = await TLSStream.wrap(self._s, hostname=server_hostname, ssl_context=ctx,
                                       standard_compatible=False)

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        anyio = _anyio()
        try:
            if name == "peername":
                addr = self._s.extra(anyio.abc.SocketAttribute.remote_address)
                return tuple(addr)[:2] if isinstance(addr, tuple) else addr
            if name == "sockname":
                return self._s.extra(anyio.abc.SocketAttribute.local_address)
            if name == "alpn":
                from anyio.streams.tls import TLSAttribute
                return self._s.extra(TLSAttribute.alpn_protocol, None)
        except Exception:  # noqa: BLE001 - anyio.TypedAttributeLookupError dahil
            return default
        return default
