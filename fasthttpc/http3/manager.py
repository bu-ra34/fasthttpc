"""Oturum entegrasyonu: Alt-Svc keşfi, h2'ye düşüş, bağlantı havuzu, Response dönüşümü."""
from __future__ import annotations

import asyncio
import threading
import time
from typing import Any, Optional

from .._backend import current_backend
from ..models.headers import Headers
from ..security.cert_validator import CertificateValidationError
from .altsvc import AltSvcCache
from .core import Http3ConnectError, Http3Error, Http3RequestRefused
from .options import Http3Options

# Sunucunun işlemediği istek (GOAWAY, H3_REQUEST_REJECTED) en fazla bu kadar kez YENİ bağlantıda
# tekrarlanır; her bağlantı reddederse sonsuz döngü yok, açık bir Http3RequestRefused verilir.
MAX_REFUSED_RETRIES = 1


def _replayable(body: object) -> bool:
    """Reddedilen istek aynen yeniden gönderilebilir mi? HTTP/3 gövdeleri bugün HER ZAMAN
    tamponlanmış bytes'tır (Request.body); tek seferlik (akışlı) bir gövde yeniden denenmez."""
    return isinstance(body, (bytes, bytearray, memoryview))


def _refused_after(e: BaseException, attempts: int) -> Http3RequestRefused:
    return Http3RequestRefused(f"HTTP/3 isteği {attempts} denemede de sunucu tarafından işlenmedi: {e}")

_TRIO_UNSUPPORTED = ("HTTP/3 trio altında desteklenmiyor (aioquic yalnızca asyncio ile çalışır); "
                     "http3='force' yerine http3=True (h2/h1'e düşer) ya da asyncio kullanın.")


def require_aioquic() -> None:
    try:
        import aioquic  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "HTTP/3 için 'aioquic' gerekli: pip install 'fasthttpc[http3]'") from e


def convert_response(raw_headers, body: bytes):
    """aioquic başlık listesi -> (status, Headers, HAM gövde).

    Content-Encoding burada AÇILMAZ: oturum, kendi ``Limits.max_decompressed_size``
    sınırıyla açar (async yol eskiden gövdeyi burada ve oturumda iki kez açmaya çalışıyordu)."""
    status = 0
    headers = Headers()
    for k, v in raw_headers or []:
        ks = k.decode("latin-1")
        if ks.startswith(":"):
            if ks == ":status":
                status = int(v)
            continue
        headers.add(ks, v.decode("latin-1"))
    return status, headers, bytes(body)


class Http3State:
    """Keşif + devre dışı bırakma durumu (aioquic'siz, saf mantık)."""

    def __init__(self, opts: Http3Options, clock=time.monotonic):
        self.opts = opts
        self._clock = clock
        self.altsvc = AltSvcCache(clock)
        self._disabled: dict[tuple, float] = {}
        self._lock = threading.Lock()

    @property
    def force(self) -> bool:
        return self.opts.mode == "force"

    def target_for(self, host: str, port: int) -> "Optional[tuple[str, int]]":
        """Bağlanılacak (host, udp_port) ya da None (h3 denenmeyecek)."""
        if self.force:
            return host, port
        with self._lock:
            until = self._disabled.get((host, port))
            if until is not None:
                if until > self._clock():
                    return None
                del self._disabled[(host, port)]
        alt = self.altsvc.get((host, port))
        if alt is None:
            return None
        return (alt.host or host), alt.port

    def observe(self, host: str, port: int, headers: Headers) -> None:
        values = headers.get_list("alt-svc")
        if values:
            self.altsvc.update((host, port), values)

    def mark_failed(self, host: str, port: int) -> None:
        with self._lock:
            self._disabled[(host, port)] = self._clock() + self.opts.disable_for


def _cert_error(e: BaseException) -> "Optional[CertificateValidationError]":
    c = getattr(e, "cause", None)
    return c if isinstance(c, CertificateValidationError) else None


class SyncHttp3:
    """Sync Session için: ``exchange`` -> (status, Headers, ham body) ya da None (h2'ye düş).

    İş parçacığı güvenli: bağlantı sözlüğü ve her bağlantının kullanıcı sayısı
    (``users``) ``_lock`` altında tutulur. Kullanılamaz hâle gelen ya da ``close()``
    ile emekliye ayrılan (``retired``) bağlantı, onu kullanan son iş parçacığı
    bitirince kapatılır; süren bir alışveriş yarıda kesilmez ve ``close()`` beklemez."""

    def __init__(self, opts: Http3Options, ca_path, impersonate):
        require_aioquic()
        self.state = Http3State(opts)
        self._ca_path, self._impersonate = ca_path, impersonate
        self._conns: dict[tuple, object] = {}
        self._lock = threading.Lock()
        self._closed = False

    def _conn(self, origin, target):
        """Bağlantıyı KİRALAR (``users`` +1); iş bitince :meth:`_done` çağrılmalı."""
        from .sync_client import SyncH3Connection
        with self._lock:
            if self._closed:
                raise RuntimeError("Session kapatıldı (close()); yeni istek gönderilemez.")
            c = self._conns.get(origin)
            if c is not None and not c.usable:
                del self._conns[origin]
                c.retired = True
                if c.users == 0:
                    c.close()       # kimse kullanmıyor: kilidi boşta, beklemez
                c = None
            if c is None:
                c = SyncH3Connection(origin[0], origin[1], target[0], target[1],
                                     ca_path=self._ca_path, impersonate=self._impersonate,
                                     opts=self.state.opts)
                c.connect()     # kilit altında: aynı kaynağa tek el sıkışma
                self._conns[origin] = c
            c.users += 1
            return c

    def _done(self, c) -> None:
        with self._lock:
            c.users -= 1
            close_now = c.retired and c.users == 0
        if close_now:
            c.close()

    def exchange(self, host: str, port: int, method: str, path: str,
                 headers: "list[tuple[str, str]]", body: bytes,
                 timeout: Optional[float]) -> "tuple[int, Headers, bytes] | None":
        origin = (host, port)
        target = self.state.target_for(host, port)
        if target is None:
            return None
        for attempt in range(MAX_REFUSED_RETRIES + 1):
            try:
                conn = self._conn(origin, target)
            except Http3ConnectError as e:
                return self._connect_failed(host, port, e)
            try:
                (res,) = conn.request_many([(method, path, headers, body)], timeout)
            finally:
                self._done(conn)
            if isinstance(res, Exception):
                if isinstance(res, Http3RequestRefused):
                    if attempt < MAX_REFUSED_RETRIES and _replayable(body):
                        continue     # işlenmedi: yeni bağlantıda yeniden dene
                    raise _refused_after(res, attempt + 1) from res
                raise (res if isinstance(res, Http3Error) else ConnectionError(f"HTTP/3: {res}")) from None
            return convert_response(*res)
        return None  # pragma: no cover

    def _connect_failed(self, host, port, e):
        if self.state.force:
            raise (_cert_error(e) or e)
        self.state.mark_failed(host, port)
        return None

    def close(self) -> None:
        """Kalıcı kapanış: boştaki bağlantılar hemen, kullanılanlar son kullanıcı bitince
        kapanır; sonraki istekler ``RuntimeError`` verir."""
        with self._lock:
            self._closed = True
            conns, self._conns = list(self._conns.values()), {}
            idle = []
            for c in conns:
                c.retired = True
                if c.users == 0:
                    idle.append(c)
        for c in idle:
            c.close()


class AsyncHttp3:
    def __init__(self, opts: Http3Options, ca_path, impersonate):
        require_aioquic()
        self.state = Http3State(opts)
        self._ca_path, self._impersonate = ca_path, impersonate
        self._conns: dict[tuple, object] = {}
        self._retired: set = set()      # havuzdan çıkarılmış, süren istekleri biten bağlantılar
        self._locks: dict[tuple, asyncio.Lock] = {}

    async def _conn(self, origin, target):
        from .async_client import AsyncH3Connection
        loop = asyncio.get_running_loop()
        lock = self._locks.setdefault(origin, asyncio.Lock())
        async with lock:
            c = self._conns.get(origin)
            if c is not None and (not c.usable or c.loop is not loop):
                if c.loop is loop:
                    # GOAWAY/REJECTED: süren (işlenecek) istekler kesilmesin; bağlantı son akış
                    # bitince kendini kapatır.
                    self._retired = {r for r in self._retired if not r.finished}
                    self._retired.add(c)
                    c.retire()
                else:
                    await c.close()
                c = None
            if c is None:
                c = AsyncH3Connection(origin[0], origin[1], target[0], target[1],
                                      ca_path=self._ca_path, impersonate=self._impersonate,
                                      opts=self.state.opts)
                await c.connect()
                self._conns[origin] = c
            return c

    async def exchange(self, host: str, port: int, method: str, path: str,
                       headers: "list[tuple[str, str]]", body: bytes, timeout: Optional[float],
                       *, stream: bool = False) -> "tuple[int, Headers, Any] | None":
        """(status, Headers, body) | None. ``stream=True`` -> body bir async iteratördür."""
        origin = (host, port)
        target = self.state.target_for(host, port)
        if target is None:
            return None
        if current_backend() != "asyncio":
            # aioquic'in G/Ç katmanı asyncio'ya bağlıdır: trio altında h3 YOK. "force" -> açık
            # hata (RuntimeError yerine); "auto" -> mTLS/proxy durumlarındaki gibi h2/h1'e düş.
            if self.state.force:
                raise Http3ConnectError(_TRIO_UNSUPPORTED)
            return None
        for attempt in range(MAX_REFUSED_RETRIES + 1):
            try:
                conn = await self._conn(origin, target)
            except Http3ConnectError as e:
                if self.state.force:
                    raise (_cert_error(e) or e) from None
                self.state.mark_failed(host, port)
                return None
            try:
                if stream:
                    raw_headers, it = await conn.stream(method, path, headers, body, timeout)
                    status, hdrs, _ = convert_response(raw_headers, b"")
                    return status, hdrs, it
                raw_headers, data = await conn.request(method, path, headers, body, timeout)
            except Http3RequestRefused as e:
                if attempt < MAX_REFUSED_RETRIES and _replayable(body):
                    continue     # işlenmedi: yeni bağlantıda yeniden dene
                raise _refused_after(e, attempt + 1) from e
            except asyncio.TimeoutError as e:
                raise TimeoutError("HTTP/3 istek zaman aşımı") from e
            return convert_response(raw_headers, data)
        return None  # pragma: no cover

    async def close(self) -> None:
        conns, self._conns = list(self._conns.values()), {}
        conns += list(self._retired)
        self._retired = set()
        for c in conns:
            await c.close()          # UDP taşımasının gerçekten kapanmasını da bekler
