"""Oturum entegrasyonu: Alt-Svc keşfi, h2'ye düşüş, bağlantı havuzu, Response dönüşümü."""
from __future__ import annotations

import asyncio
import threading
import time
from typing import Any, Optional

from .._backend import current_backend
from ..models.headers import Headers
from ..protocol.http1_parser import HTTP1Parser
from ..security.cert_validator import CertificateValidationError
from .altsvc import AltSvcCache
from .core import Http3ConnectError, Http3Error
from .options import Http3Options

_TRIO_UNSUPPORTED = ("HTTP/3 trio altında desteklenmiyor (aioquic yalnızca asyncio ile çalışır); "
                     "http3='force' yerine http3=True (h2/h1'e düşer) ya da asyncio kullanın.")


def require_aioquic() -> None:
    try:
        import aioquic  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "HTTP/3 için 'aioquic' gerekli: pip install 'fasthttpc[http3]'") from e


def convert_response(raw_headers, body: bytes):
    """aioquic başlık listesi -> (status, Headers, çözülmüş gövde)."""
    status = 0
    headers = Headers()
    for k, v in raw_headers or []:
        ks = k.decode("latin-1")
        if ks.startswith(":"):
            if ks == ":status":
                status = int(v)
            continue
        headers.add(ks, v.decode("latin-1"))
    body = HTTP1Parser._decompress(bytes(body), headers.get("content-encoding", "").lower())
    return status, headers, body


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
    """Sync Session için: ``exchange`` -> (status, Headers, body) ya da None (h2'ye düş)."""

    def __init__(self, opts: Http3Options, ca_path, impersonate):
        require_aioquic()
        self.state = Http3State(opts)
        self._ca_path, self._impersonate = ca_path, impersonate
        self._conns: dict[tuple, object] = {}
        self._lock = threading.Lock()

    def _conn(self, origin, target):
        from .sync_client import SyncH3Connection
        with self._lock:
            c = self._conns.get(origin)
            if c is not None and not c.usable:
                c.close()
                c = None
            if c is None:
                c = SyncH3Connection(origin[0], origin[1], target[0], target[1],
                                     ca_path=self._ca_path, impersonate=self._impersonate,
                                     opts=self.state.opts)
                c.connect()     # kilit altında: aynı kaynağa tek el sıkışma
                self._conns[origin] = c
            return c

    def exchange(self, host: str, port: int, method: str, path: str,
                 headers: "list[tuple[str, str]]", body: bytes,
                 timeout: Optional[float]) -> "tuple[int, Headers, bytes] | None":
        origin = (host, port)
        target = self.state.target_for(host, port)
        if target is None:
            return None
        for attempt in (0, 1):
            try:
                conn = self._conn(origin, target)
            except Http3ConnectError as e:
                return self._connect_failed(host, port, e)
            (res,) = conn.request_many([(method, path, headers, body)], timeout)
            if isinstance(res, Exception):
                from .core import Http3RequestRefused
                if isinstance(res, Http3RequestRefused) and attempt == 0:
                    continue     # GOAWAY: işlenmedi, yeni bağlantıda yeniden dene
                raise (res if isinstance(res, Http3Error) else ConnectionError(f"HTTP/3: {res}")) from None
            return convert_response(*res)
        return None  # pragma: no cover

    def _connect_failed(self, host, port, e):
        if self.state.force:
            raise (_cert_error(e) or e)
        self.state.mark_failed(host, port)
        return None

    def close(self) -> None:
        with self._lock:
            conns, self._conns = list(self._conns.values()), {}
        for c in conns:
            c.close()


class AsyncHttp3:
    def __init__(self, opts: Http3Options, ca_path, impersonate):
        require_aioquic()
        self.state = Http3State(opts)
        self._ca_path, self._impersonate = ca_path, impersonate
        self._conns: dict[tuple, object] = {}
        self._locks: dict[tuple, asyncio.Lock] = {}

    async def _conn(self, origin, target):
        from .async_client import AsyncH3Connection
        loop = asyncio.get_running_loop()
        lock = self._locks.setdefault(origin, asyncio.Lock())
        async with lock:
            c = self._conns.get(origin)
            if c is not None and (not c.usable or c.loop is not loop):
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
        from .core import Http3RequestRefused
        for attempt in (0, 1):
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
            except Http3RequestRefused:
                if attempt == 0:
                    continue
                raise
            except asyncio.TimeoutError as e:
                raise TimeoutError("HTTP/3 istek zaman aşımı") from e
            return convert_response(raw_headers, data)
        return None  # pragma: no cover

    async def close(self) -> None:
        conns, self._conns = list(self._conns.values()), {}
        for c in conns:
            await c.close()
