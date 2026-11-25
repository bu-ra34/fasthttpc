"""
fasthttpc — asyncio HTTP/2 bağlantısı (gerçek multiplexing).

Senkron :class:`~fasthttpc.protocol.http2_parser.Http2Connection` ile AYNI
frame sınıflarını (:class:`HTTP2Frame`), HPACK encoder/decoder'ı ve padding
yardımcılarını yeniden kullanır; burada yalnızca asyncio'ya özgü bağlantı ve
stream yönetimi vardır:

  * Tek okuyucu görev (``_read_loop``) tüm frame'leri okur ve stream'lere
    dağıtır; istekler ``await`` ile kendi yanıtlarını bekler. Aynı bağlantıda
    aynı anda birden çok istek açık olabilir (``asyncio.gather``).
  * Bağlantı + stream akış kontrolü (WINDOW_UPDATE), gövde gönderirken pencere
    bekleme, SETTINGS (INITIAL_WINDOW_SIZE farkı açık stream'lere uygulanır,
    MAX_CONCURRENT_STREAMS'e uyulur, MAX_FRAME_SIZE), PING ack, RST_STREAM,
    GOAWAY (last_stream_id'den büyük stream'ler "işlenmedi" sayılır ve
    yeniden denenebilir).
  * Parmak izi tutarlılığı: ön ek + SETTINGS baytları, senkron
    ``Http2Connection.send_preface_and_settings`` çalıştırılarak ELDE EDİLİR
    (kopya sabit yok), pseudo-header sırası ve HPACK kodlaması aynıdır.

Akış (``stream``) arayüzü: ``read(n)`` (await), ``write(b)``, ``drain()``
(await), ``close()``, ``wait_closed()`` (await). Hem
:class:`~fasthttpc.tls13.AsyncTLSStream` hem de asyncio StreamReader/Writer
çifti (``_ReaderWriter``) bu arayüze uyar.
"""
from __future__ import annotations

import asyncio
import collections
import struct
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterable, Callable, Optional, Union

from .. import _backend as B
from .._log import get_logger
from .http2_parser import (
    HPACK_MAX_HEADER_LIST_SIZE,
    FrameFlags,
    FrameType,
    HTTP2Frame,
    HpackDecoder,
    HpackDecodingError,
    HpackEncoder,
    Http2Connection,
    Http2ConnectionError,
    Http2StreamError,
    _window_update_frame,
    h2_for_profile,
    h2_headers_priority_field,
    h2_request_headers,
    h2_setting,
    h2_wu_thresholds,
    HPACK_DEFAULT_TABLE_SIZE,
    _strip_data_frame_padding,
    _strip_headers_frame_fields,
)

logger = get_logger("async_h2")

# İstek gövdesi: bellekte bayt ya da bayt parçaları üreten async iterable (akış).
_Body = Union[bytes, bytearray, memoryview, AsyncIterable[bytes]]

__all__ = ["AsyncHttp2Connection", "H2Response", "H2StreamHandle", "H2StreamRefused", "client_preface_bytes"]

_MAX_STREAM_ID = 2 ** 31 - 1
_MAX_WINDOW = 2 ** 31 - 1
_OUR_MAX_FRAME = 16384          # SETTINGS_MAX_FRAME_SIZE göndermiyoruz -> varsayılan

_ERR_NAMES = {
    0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR",
    3: "FLOW_CONTROL_ERROR", 4: "SETTINGS_TIMEOUT", 5: "STREAM_CLOSED",
    6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM", 8: "CANCEL",
    9: "COMPRESSION_ERROR", 10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM",
    12: "INADEQUATE_SECURITY", 13: "HTTP_1_1_REQUIRED",
}


#: request()/request_stream() zaman aşımı verilmezse bağlantının varsayılanı kullanılır.
#: Session her istekte KENDİ etkin süresini geçirir: bağlantı, onu açan ilk isteğin
#: süresiyle (ör. ``timeout=None``) yeniden kullanılan isteklere taşınmamalı.
_CONN_DEFAULT: Any = object()


class H2StreamRefused(Http2ConnectionError):
    """İstek sunucu tarafından HİÇ İŞLENMEDİ (GOAWAY last_stream_id'den büyük,
    REFUSED_STREAM veya bağlantı yeni stream kabul etmiyor). Başka bir
    bağlantıda güvenle (idempotent olmayan istekler dahil) yeniden denenebilir."""


@dataclass
class H2Response:
    status: int
    headers: "list[tuple[str, str]]"
    body: bytes
    first_byte_time: float = 0.0


class _Stream:
    __slots__ = ("id", "fut", "status", "headers", "body", "headers_done",
                 "send_window", "activity", "first_byte_time",
                 "streaming", "chunks", "hdr_fut", "waiter", "unacked")

    def __init__(self, sid: int, fut: "asyncio.Future", send_window: int):
        self.id = sid
        self.fut = fut
        self.status = 0
        self.headers: list[tuple[str, str]] = []
        # Gövde parçaları; sonda TEK b"".join (bytearray'e ekleyip bytes() almak
        # büyük gövdede yeniden boyutlamalar + bir tam kopya daha demekti).
        self.body: list[bytes] = []
        self.headers_done = False
        self.send_window = send_window
        self.activity = False
        self.first_byte_time = 0.0
        # Akış modu: DATA ``chunks``'ta (bytes, ham_uzunluk) birikir; ``hdr_fut``
        # başlıklar gelince; ``waiter`` okuyucuyu uyandırır. ``fut`` akış sonunu işaret eder.
        self.streaming = False
        self.chunks: "collections.deque[tuple[bytes, int]]" = collections.deque()
        self.hdr_fut: "Optional[asyncio.Future]" = None
        self.waiter: "Optional[asyncio.Future]" = None
        self.unacked = 0          # tüketilmiş, stream WINDOW_UPDATE'i ile geri verilmemiş bayt

    def notify(self) -> None:
        w, self.waiter = self.waiter, None
        if w is not None and not w.done():
            w.set_result(None)


class _ReaderWriter:
    """asyncio (StreamReader, StreamWriter) çiftini tek 'stream' arayüzüne sarar."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._r, self._w = reader, writer

    async def read(self, n: int = -1) -> bytes:
        return await self._r.read(n)

    def write(self, data: bytes) -> None:
        self._w.write(data)

    async def drain(self) -> None:
        await self._w.drain()

    def close(self) -> None:
        self._w.close()

    async def wait_closed(self) -> None:
        await self._w.wait_closed()


class H2StreamHandle:
    """``request_stream`` dönüşü: başlıklar hazır; ``read_chunk()`` ile gövde (``b""`` = bitti)."""

    def __init__(self, conn: "AsyncHttp2Connection", st: _Stream,
                 read_timeout: Any = _CONN_DEFAULT, write_timeout: Any = _CONN_DEFAULT):
        self._c, self._st = conn, st
        self.status = 0
        self.headers: "list[tuple[str, str]]" = []
        self.first_byte_time = 0.0
        self._closed = False
        # Gövde okumaları akışı açan İSTEĞİN süreleriyle sınırlıdır (bağlantınınkiyle değil).
        self.read_timeout: Optional[float] = (
            conn.read_timeout if read_timeout is _CONN_DEFAULT else read_timeout)
        self.write_timeout: Optional[float] = (
            conn.write_timeout if write_timeout is _CONN_DEFAULT else write_timeout)

    async def read_chunk(self) -> bytes:
        st, c = self._st, self._c
        while True:
            if st.chunks:
                data, raw_len = st.chunks.popleft()
                if raw_len:
                    st.unacked += raw_len
                if (st.unacked >= c._wu_stream_threshold and st.unacked
                        and not st.fut.done() and not c._closed):
                    # Stream kredisi tüketildikçe; eşik: h2_wu_thresholds (varsayılan
                    # 65535 pencerede her parçada, büyük pencerede toplanarak).
                    try:
                        c._write(_window_update_frame(st.id, st.unacked))
                        st.unacked = 0
                        await c._drain(self.write_timeout)
                    except (OSError, Http2ConnectionError):
                        pass        # bağlantı koptu: sıradaki okuma hatayı bildirir
                if data:
                    return data
                continue
            if st.fut.done():
                self._closed = True
                if st.fut.cancelled():
                    return b""
                st.fut.result()      # hata varsa fırlatır
                return b""
            fut = B.new_future()
            st.waiter = fut
            try:
                await B.wait_for(fut, self.read_timeout)
            except asyncio.TimeoutError:
                st.waiter = None
                if st.activity:
                    st.activity = False
                    continue
                self.close_nowait()
                raise asyncio.TimeoutError(
                    f"HTTP/2 gövdesi {self.read_timeout} sn içinde gelmedi (stream {st.id}).") from None

    def close_nowait(self) -> None:
        """Bitmemiş stream'i RST_STREAM(CANCEL) ile iptal eder; bağlantı yaşar."""
        st, c = self._st, self._c
        if self._closed:
            return
        self._closed = True
        if not st.fut.done():
            c._streams.pop(st.id, None)
            c._rst(st.id, 8)
            st.fut.cancel()
            if st.hdr_fut is not None and not st.hdr_fut.done():
                st.hdr_fut.cancel()
            st.notify()
            c._wake()
        else:
            if not st.fut.cancelled():
                st.fut.exception()          # "never retrieved" uyarısını önle
            if st.hdr_fut is not None and st.hdr_fut.done() and not st.hdr_fut.cancelled():
                st.hdr_fut.exception()

    async def aclose(self) -> None:
        self.close_nowait()
        if not self._c._closed:
            try:
                await self._c._drain()
            except (OSError, asyncio.TimeoutError, Http2ConnectionError):
                pass


def _frame(ftype: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return HTTP2Frame(len(payload), ftype, flags, stream_id, payload).serialize()


class _Recorder:
    def __init__(self):
        self.chunks: list[bytes] = []

    def send_record(self, data: bytes, content_type: int = 0x17, use_app_keys: bool = True) -> None:
        self.chunks.append(bytes(data))


def client_preface_bytes(profile=None) -> bytes:
    """Bağlantı ön eki + SETTINGS baytları: senkron taraf neyi gönderiyorsa o.

    ``Http2Connection.send_preface_and_settings`` sahte bir sokete karşı
    çalıştırılır; böylece senkron ve async HTTP/2 parmak izi (SETTINGS kümesi,
    sırası, değerleri) kendiliğinden tutarlı kalır.
    """
    rec = _Recorder()
    Http2Connection(rec, profile=profile).send_preface_and_settings()
    return b"".join(rec.chunks)


class AsyncHttp2Connection:
    """Tek bir TLS bağlantısı üzerinde eşzamanlı çok istekli HTTP/2 istemcisi."""

    def __init__(
        self,
        stream,
        *,
        read_timeout: Optional[float] = None,
        write_timeout: Optional[float] = None,
        on_close: Optional[Callable[[], None]] = None,
        profile=None,
    ):
        self._s = stream
        self._h2 = h2_for_profile(profile)
        self._profile = profile
        self.read_timeout = read_timeout
        self.write_timeout = write_timeout
        self._on_close = on_close
        self._decoder = HpackDecoder(
            max_table_size=h2_setting(self._h2, 0x1, HPACK_DEFAULT_TABLE_SIZE),
            max_header_list_size=HPACK_MAX_HEADER_LIST_SIZE)
        self._encoder = HpackEncoder()
        self._buf = bytearray()
        self._streams: dict[int, _Stream] = {}
        self._next_stream_id = 1
        self._conn_send = Http2Connection.DEFAULT_WINDOW
        self._peer_initial_window = Http2Connection.DEFAULT_WINDOW
        self._peer_max_frame = 16384
        self._max_streams = 2 ** 31          # sunucu SETTINGS ile sınırlayana kadar
        self._goaway: Optional[tuple[int, int]] = None
        self._closed = False
        self._waiters: list = []
        self._drain_lock = B.Lock()
        self._task = None
        self._close_error: Optional[BaseException] = None
        # Başlık bloğu birleştirme (CONTINUATION bağlantı genelinde ardışık olmalı)
        self._hblock = bytearray()
        self._hblock_sid = 0
        self._hblock_end_stream = False
        self.last_used = time.perf_counter()
        self.loop = B.current_token()   # asyncio: olay döngüsü; trio: TrioToken
        # Alım akış kontrolü (bkz. http2_parser.h2_wu_thresholds): bağlantı düzeyinde
        # geri verilmemiş kredi ve eşikler.
        self._conn_unacked = 0
        self._wu_conn_threshold, self._wu_stream_threshold = h2_wu_thresholds(self._h2)
        # Son drain'den beri yazım yapıldı mı? Okuma döngüsü her frame'den sonra
        # (yazacak bir şey yokken bile) drain beklemesin.
        self._need_drain = False

    # ------------------------------------------------------------- durum
    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def active_streams(self) -> int:
        return len(self._streams)

    @property
    def usable(self) -> bool:
        """Yeni stream açılabilir mi?"""
        return (not self._closed and self._goaway is None
                and self._next_stream_id <= _MAX_STREAM_ID)

    # ---------------------------------------------------------- el sıkışma
    async def start(self) -> None:
        """Ön ek + SETTINGS gönderir ve okuyucu görevi başlatır."""
        self._s.write(client_preface_bytes(self._profile))
        await self._drain()
        self._task = B.spawn(self._read_loop(), name="fasthttpc-h2-reader")

    # ------------------------------------------------------- düşük seviye
    async def _drain(self, timeout: Any = _CONN_DEFAULT) -> None:
        self._need_drain = False
        wt = self.write_timeout if timeout is _CONN_DEFAULT else timeout
        async with self._drain_lock:
            if wt is None:
                await self._s.drain()
            else:
                await B.wait_for(self._s.drain(), wt)

    def _write(self, data: bytes) -> None:
        if self._closed:
            raise Http2ConnectionError("HTTP/2 bağlantısı kapalı.")
        self._s.write(data)
        self._need_drain = True

    def _wake(self) -> None:
        waiters, self._waiters = self._waiters, []
        for w in waiters:
            if not w.done():
                w.set_result(None)

    async def _wait_change(self, timeout: Optional[float]) -> None:
        fut = B.new_future()
        self._waiters.append(fut)
        try:
            await B.wait_for(fut, timeout)
        finally:
            if fut in self._waiters:
                self._waiters.remove(fut)

    def _send_goaway(self, error_code: int) -> None:
        """En iyi çabayla GOAWAY (bağlantı zaten bozuksa hata yutulur)."""
        try:
            if not self._closed:
                self._s.write(_frame(FrameType.GOAWAY, 0, 0, struct.pack("!II", 0, error_code)))
                self._need_drain = True
        except (OSError, RuntimeError, Http2ConnectionError) as e:
            logger.debug("GOAWAY gönderilemedi: %s", e)

    def _conn_error(self, code: int, msg: str) -> Http2ConnectionError:
        self._send_goaway(code)
        return Http2ConnectionError(f"{_ERR_NAMES.get(code, code)}: {msg}")

    def _rst(self, sid: int, code: int) -> None:
        try:
            self._write(_frame(FrameType.RST_STREAM, 0, sid, struct.pack("!I", code)))
        except (OSError, RuntimeError, Http2ConnectionError):
            pass

    # --------------------------------------------------------- okuma döngüsü
    async def _read_frame(self) -> HTTP2Frame:
        buf = self._buf
        while True:
            if len(buf) >= HTTP2Frame.HEADER_SIZE:
                length = int.from_bytes(buf[0:3], "big")
                if length > _OUR_MAX_FRAME:
                    raise self._conn_error(6, f"frame çok büyük ({length})")
                total = HTTP2Frame.HEADER_SIZE + length
                if len(buf) >= total:
                    # Alanlar doğrudan tampondan, yük tek kopyayla (bytes(dilim) +
                    # parse() içinde yeniden dilimleme iki kopyaydı).
                    sid = int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
                    with memoryview(buf) as mv:
                        payload = mv[HTTP2Frame.HEADER_SIZE:total].tobytes()
                    f = HTTP2Frame(length, buf[3], buf[4], sid, payload)
                    del buf[:total]
                    return f
            data = await self._s.read(65536)
            if not data:
                raise Http2ConnectionError("Bağlantı beklenmedik şekilde kapandı.")
            buf += data

    async def _read_loop(self) -> None:
        err: BaseException = Http2ConnectionError("HTTP/2 bağlantısı kapandı.")
        try:
            while True:
                frame = await self._read_frame()
                self._dispatch(frame)
                if self._goaway is not None and not self._streams:
                    err = Http2ConnectionError("GOAWAY alındı; bağlantı kapatıldı.")
                    return
                if self._closed:
                    return
                if self._need_drain:
                    await self._drain()
        except B.cancelled_exc_class():
            err = Http2ConnectionError("HTTP/2 bağlantısı kapatıldı.")
            raise
        except BaseException as e:  # noqa: BLE001 - tüm stream'lere iletilecek
            err = e if isinstance(e, Http2ConnectionError) else Http2ConnectionError(
                f"HTTP/2 bağlantı hatası: {e!r}")
            if err is not e:
                err.__cause__ = e
        finally:
            self._teardown(err)

    def _teardown(self, err: BaseException) -> None:
        if self._closed and not self._streams:
            return
        self._closed = True
        self._close_error = err
        streams, self._streams = self._streams, {}
        for st in streams.values():
            self._fail(st, err)
        self._wake()
        try:
            self._s.close()
        except (OSError, RuntimeError):
            pass
        cb, self._on_close = self._on_close, None
        if cb is not None:
            cb()

    # ------------------------------------------------------------ dağıtım
    def _dispatch(self, f: HTTP2Frame) -> None:
        t = f.type
        if self._hblock_sid and (t != FrameType.CONTINUATION or f.stream_id != self._hblock_sid):
            raise self._conn_error(1, "CONTINUATION dizisi kesildi")
        if t == FrameType.DATA:
            self._on_data(f)
        elif t in (FrameType.HEADERS, FrameType.CONTINUATION):
            self._on_headers(f)
        elif t == FrameType.RST_STREAM:
            self._on_rst(f)
        elif t == FrameType.SETTINGS:
            self._on_settings(f)
        elif t == FrameType.PING:
            if len(f.payload) != 8:
                raise self._conn_error(6, "PING uzunluğu")
            if not f.flags & 0x1:
                self._write(_frame(FrameType.PING, 0x1, 0, f.payload))
        elif t == FrameType.GOAWAY:
            self._on_goaway(f)
        elif t == FrameType.WINDOW_UPDATE:
            self._on_window_update(f)
        elif t == FrameType.PUSH_PROMISE:
            raise self._conn_error(1, "ENABLE_PUSH=0 iken PUSH_PROMISE alındı")
        # PRIORITY ve bilinmeyen frame türleri yok sayılır (RFC 7540 §4.1)

    def _finish(self, st: _Stream) -> None:
        self._streams.pop(st.id, None)
        self.last_used = time.perf_counter()
        self._flush_conn_credit()
        if not st.fut.done():
            st.fut.set_result(H2Response(st.status, st.headers, b"".join(st.body), st.first_byte_time))
        if st.hdr_fut is not None and not st.hdr_fut.done():
            st.hdr_fut.set_result(None)
        st.notify()
        self._wake()

    @staticmethod
    def _fail(st: _Stream, exc: BaseException) -> None:
        if not st.fut.done():
            st.fut.set_exception(exc)
        if st.hdr_fut is not None and not st.hdr_fut.done():
            st.hdr_fut.set_exception(exc)
        st.notify()

    def _fail_stream(self, sid: int, exc: BaseException) -> None:
        st = self._streams.pop(sid, None)
        if st is not None:
            self._fail(st, exc)
        self._wake()

    def _on_data(self, f: HTTP2Frame) -> None:
        if f.stream_id == 0:
            raise self._conn_error(1, "stream 0 üzerinde DATA")
        raw_len = len(f.payload)        # pencere, padding dahil HAM uzunlukla açılır
        st = self._streams.get(f.stream_id)
        if st is not None:
            st.activity = True
            if st.streaming:
                data = _strip_data_frame_padding(f)
                st.chunks.append((bytes(data), raw_len))
                st.notify()
            else:
                st.body.append(_strip_data_frame_padding(f))
        if raw_len:
            # Bağlantı kredisi alındığı anda (diğer stream'ler aç kalmasın), eşiğe
            # ulaşınca TOPLU geri verilir; bkz. h2_wu_thresholds. Kalan, stream bitince
            # (_finish) geri verilir. İki frame tek yazımda (= tek TLS record'u).
            self._conn_unacked += raw_len
            wu = b""
            if self._conn_unacked >= self._wu_conn_threshold:
                wu = _window_update_frame(0, self._conn_unacked)
                self._conn_unacked = 0
            # Akış modunda stream penceresi TÜKETİCİ okudukça açılır (geri basınç):
            # okunmayan veri en çok ilan edilen stream penceresi kadar tamponlanır.
            if st is not None and not f.end_stream and not st.streaming:
                st.unacked += raw_len
                if st.unacked >= self._wu_stream_threshold:
                    wu += _window_update_frame(f.stream_id, st.unacked)
                    st.unacked = 0
            if wu:
                self._write(wu)
        if st is not None and f.end_stream:
            self._finish(st)

    def _flush_conn_credit(self) -> None:
        """Geri verilmemiş bağlantı kredisini gönderir (stream bitişinde; pencere sızmaz)."""
        if self._conn_unacked and not self._closed:
            n, self._conn_unacked = self._conn_unacked, 0
            try:
                self._write(_window_update_frame(0, n))
            except (OSError, RuntimeError, Http2ConnectionError):
                pass

    def _on_headers(self, f: HTTP2Frame) -> None:
        if f.type == FrameType.HEADERS:
            if f.stream_id == 0:
                raise self._conn_error(1, "stream 0 üzerinde HEADERS")
            self._hblock = bytearray(_strip_headers_frame_fields(f))
            self._hblock_sid = f.stream_id
            self._hblock_end_stream = f.end_stream
        else:
            if not self._hblock_sid:
                raise self._conn_error(1, "beklenmeyen CONTINUATION")
            self._hblock += f.payload
        if len(self._hblock) > HPACK_MAX_HEADER_LIST_SIZE:
            raise self._conn_error(11, "header bloğu sınırı aşıldı (HEADERS/CONTINUATION seli)")
        if not f.end_headers:
            return
        sid, end_stream = self._hblock_sid, self._hblock_end_stream
        block = bytes(self._hblock)
        self._hblock = bytearray()
        self._hblock_sid = 0
        # HPACK durumu bağlantı geneli: bilinmeyen/iptal edilmiş stream'lerin
        # blokları da decode edilmeli.
        try:
            decoded = self._decoder.decode(block)
        except HpackDecodingError as e:
            raise self._conn_error(HpackDecodingError.error_code, str(e)) from e
        st = self._streams.get(sid)
        if st is None:
            return
        st.activity = True
        status = 0
        hdrs: list[tuple[str, str]] = []
        for k, v in decoded:
            if k == ":status":
                try:
                    status = int(v)
                except ValueError:
                    self._rst(sid, 1)
                    self._fail_stream(sid, Http2StreamError(f"Stream {sid}: geçersiz :status {v!r}"))
                    return
            else:
                hdrs.append((k, v))
        if 100 <= status < 200:
            pass                         # ara yanıt (100-continue / 103): nihai yanıt bekleniyor
        elif st.headers_done:
            st.headers.extend(hdrs)      # trailer
        else:
            st.headers_done = True
            st.status = status
            st.headers.extend(hdrs)
            st.first_byte_time = time.perf_counter()
            if st.hdr_fut is not None and not st.hdr_fut.done():
                st.hdr_fut.set_result(None)
        if end_stream:
            self._finish(st)

    def _on_rst(self, f: HTTP2Frame) -> None:
        if f.stream_id == 0 or len(f.payload) != 4:
            raise self._conn_error(1 if f.stream_id == 0 else 6, "RST_STREAM geçersiz")
        code = struct.unpack("!I", f.payload)[0]
        name = _ERR_NAMES.get(code, f"UNKNOWN({code})")
        msg = f"Stream {f.stream_id} sıfırlandı (RST_STREAM), error_code={code} [{name}]."
        exc: Http2ConnectionError | Http2StreamError = (
            H2StreamRefused(msg) if code == 7 else Http2StreamError(msg))
        self._fail_stream(f.stream_id, exc)

    def _on_settings(self, f: HTTP2Frame) -> None:
        if f.stream_id != 0:
            raise self._conn_error(1, "SETTINGS stream 0 olmalı")
        if f.flags & 0x1:               # ACK
            return
        p = f.payload
        if len(p) % 6:
            raise self._conn_error(6, "SETTINGS uzunluğu 6'nın katı değil")
        for i in range(0, len(p), 6):
            ident, value = struct.unpack("!HI", p[i:i + 6])
            if ident == 0x3:
                self._max_streams = value
            elif ident == 0x4:
                if value > _MAX_WINDOW:
                    raise self._conn_error(3, "INITIAL_WINDOW_SIZE çok büyük")
                delta = value - self._peer_initial_window
                self._peer_initial_window = value
                for st in self._streams.values():
                    st.send_window += delta
            elif ident == 0x5:
                if not 16384 <= value <= 16777215:
                    raise self._conn_error(1, "MAX_FRAME_SIZE geçersiz")
                self._peer_max_frame = value
            # 0x1 HEADER_TABLE_SIZE: encoder dinamik tablo kullanmıyor (literal), 0x2/0x6 bilgi
        self._write(_frame(FrameType.SETTINGS, 0x1, 0))
        self._wake()

    def _on_window_update(self, f: HTTP2Frame) -> None:
        if len(f.payload) != 4:
            raise self._conn_error(6, "WINDOW_UPDATE uzunluğu")
        inc = struct.unpack("!I", f.payload)[0] & 0x7FFFFFFF
        if f.stream_id == 0:
            if inc == 0:
                raise self._conn_error(1, "WINDOW_UPDATE artışı 0")
            self._conn_send += inc
            if self._conn_send > _MAX_WINDOW:
                raise self._conn_error(3, "bağlantı penceresi taştı")
        else:
            st = self._streams.get(f.stream_id)
            if st is None:
                return
            if inc == 0 or st.send_window + inc > _MAX_WINDOW:
                self._rst(f.stream_id, 1 if inc == 0 else 3)
                self._fail_stream(f.stream_id, Http2StreamError(
                    f"Stream {f.stream_id}: geçersiz WINDOW_UPDATE"))
                return
            st.send_window += inc
        self._wake()

    def _on_goaway(self, f: HTTP2Frame) -> None:
        if len(f.payload) < 8:
            raise self._conn_error(6, "GOAWAY uzunluğu")
        last_id, code = struct.unpack("!II", f.payload[:8])
        last_id &= 0x7FFFFFFF
        self._goaway = (last_id, code)
        debug = f.payload[8:]
        for sid in [s for s in self._streams if s > last_id]:
            self._fail_stream(sid, H2StreamRefused(
                f"Sunucu GOAWAY gönderdi (last_stream_id={last_id}, "
                f"{_ERR_NAMES.get(code, code)}): stream {sid} işlenmedi. {debug!r}"))
        self._wake()

    # ------------------------------------------------------------- istek
    def _alloc_stream(self) -> _Stream:
        sid = self._next_stream_id
        self._next_stream_id += 2
        st = _Stream(sid, B.new_future(), self._peer_initial_window)
        self._streams[sid] = st
        return st

    def _send_headers(self, sid: int, headers: "list[tuple[str, str]]", end_stream: bool) -> None:
        block = self._encoder.encode(headers)
        max_frame = self._peer_max_frame
        prio = h2_headers_priority_field(self._h2)
        out = bytearray()
        offset = 0
        first = True
        while first or offset < len(block):
            room = max_frame - (len(prio) if first else 0)
            chunk = block[offset: offset + room]
            offset += len(chunk)
            last = offset >= len(block)
            flags = 0
            if end_stream and last:
                flags |= FrameFlags.END_STREAM
            if last:
                flags |= FrameFlags.END_HEADERS
            if first and prio:
                flags |= FrameFlags.PRIORITY
            out += _frame(FrameType.HEADERS if first else FrameType.CONTINUATION, flags, sid,
                          (prio + chunk) if first else chunk)
            first = False
        # Tek write: HEADERS+CONTINUATION arasına başka frame giremez.
        self._write(bytes(out))

    async def _send_body(self, st: _Stream, body: "_Body", write_timeout: Any = _CONN_DEFAULT) -> None:
        """Gövdeyi DATA frame'leriyle gönderir; END_STREAM SON frame'dedir.

        ``body``: bayt ya da bayt parçaları üreten async iterable (akış gövdesi; belleğe
        alınmaz). Frame'ler ``max_frame_size``'ı ve pencereleri aşmaz; her frame'den sonra
        ``drain`` ``write_timeout`` ile sınırlıdır. Son frame ancak kaynak bitince
        bilindiğinden bir parça geride tutulur. Yanıt erken gelirse gönderim kesilir."""
        wt = self.write_timeout if write_timeout is _CONN_DEFAULT else write_timeout
        if isinstance(body, (bytes, bytearray, memoryview)):
            mv = memoryview(body)
            step = self._peer_max_frame
            for off in range(0, len(mv), step):
                if not await self._send_piece(st, mv[off:off + step], off + step >= len(mv), wt):
                    return
            return
        pending: Optional[memoryview] = None
        try:
            async for chunk in body:
                if not chunk:
                    continue
                mv = memoryview(chunk)
                step = self._peer_max_frame
                for off in range(0, len(mv), step):
                    if pending is not None and not await self._send_piece(st, pending, False, wt):
                        return
                    pending = mv[off:off + step]
            await self._send_piece(st, pending if pending is not None else memoryview(b""), True, wt)
        finally:
            aclose = getattr(body, "aclose", None)
            if aclose is not None:
                await aclose()

    async def _send_piece(self, st: _Stream, data: memoryview, end_stream: bool, wt: Any) -> bool:
        """En çok bir frame'lik veri (pencereye göre bölünerek). Yanıt/RST erken geldiyse False."""
        off, n = 0, len(data)
        while True:
            if st.fut.done():            # yanıt/RST erken geldi
                return False
            if self._closed:
                raise Http2ConnectionError("Gövde gönderilirken bağlantı kapandı.")
            take = n - off
            if take:
                avail = min(self._conn_send, st.send_window)
                if avail <= 0:
                    await self._wait_change(wt)
                    continue
                take = min(take, avail)
            last = off + take >= n
            self._write(_frame(FrameType.DATA, FrameFlags.END_STREAM if (end_stream and last) else 0,
                               st.id, data[off:off + take].tobytes()))
            self._conn_send -= take
            st.send_window -= take
            off += take
            await self._drain(wt)
            if last:
                return True

    def _timeouts(self, read_timeout: Any, write_timeout: Any) -> "tuple[Optional[float], Optional[float]]":
        return (self.read_timeout if read_timeout is _CONN_DEFAULT else read_timeout,
                self.write_timeout if write_timeout is _CONN_DEFAULT else write_timeout)

    async def request(
        self,
        method: str,
        authority: str,
        path: str,
        headers: "list[tuple[str, str]]",
        body: "_Body" = b"",
        scheme: str = "https",
        *,
        read_timeout: Any = _CONN_DEFAULT,
        write_timeout: Any = _CONN_DEFAULT,
    ) -> H2Response:
        """Tek bir isteği gönderir ve yanıtı bekler. Eşzamanlı çağrılabilir.

        ``read_timeout``/``write_timeout`` bu isteğin süreleridir (verilmezse
        bağlantınınkiler); bağlantıyı açan isteğin süresi sonrakilere taşınmaz."""
        rt, wt = self._timeouts(read_timeout, write_timeout)
        # Eşzamanlı stream sınırı (sunucunun MAX_CONCURRENT_STREAMS'i)
        while True:
            if not self.usable:
                raise H2StreamRefused("HTTP/2 bağlantısı yeni stream kabul etmiyor.")
            if len(self._streams) < self._max_streams:
                break
            await self._wait_change(wt)

        # Pseudo-header ve başlık sırası: senkron taraftakiyle AYNI fonksiyon.
        full = h2_request_headers(self._h2, method, authority, scheme, path, headers)

        # await YOK: stream id tahsisi ile HEADERS yazımı sıralı kalmalı
        # (stream id'ler artan sırada gönderilmek zorunda; RFC 7540 §5.1.1).
        st = self._alloc_stream()
        self.last_used = time.perf_counter()
        in_memory = isinstance(body, (bytes, bytearray, memoryview))
        try:
            self._send_headers(st.id, full, end_stream=in_memory and not body)
        except BaseException:
            self._streams.pop(st.id, None)
            raise
        try:
            await self._drain(wt)
            if not in_memory or body:
                await self._send_body(st, body, wt)
            while True:
                done = await B.wait_future(st.fut, rt)
                if done:
                    return st.fut.result()
                if st.activity:          # son aralıkta veri geldi: hareketsizlik süresi sıfırlanır
                    st.activity = False
                    continue
                raise asyncio.TimeoutError(
                    f"HTTP/2 yanıtı {rt} sn içinde gelmedi (stream {st.id}).")
        finally:
            if not st.fut.done():
                # iptal / zaman aşımı / hata: stream'i bırak ve sunucuya bildir
                self._streams.pop(st.id, None)
                self._rst(st.id, 8)      # CANCEL
                st.fut.cancel()
                self._wake()
            elif not st.fut.cancelled():
                st.fut.exception()       # "never retrieved" uyarısını önle

    async def request_stream(
        self,
        method: str,
        authority: str,
        path: str,
        headers: "list[tuple[str, str]]",
        body: "_Body" = b"",
        scheme: str = "https",
        *,
        read_timeout: Any = _CONN_DEFAULT,
        write_timeout: Any = _CONN_DEFAULT,
    ) -> "H2StreamHandle":
        """İsteği gönderir, yanıt BAŞLIKLARI gelince döner; gövde
        :meth:`H2StreamHandle.read_chunk` ile parça parça okunur (bu isteğin
        ``read_timeout``'u ile; verilmezse bağlantınınki).

        Geri basınç: stream WINDOW_UPDATE'i tüketici okudukça gönderilir
        (bağlantı penceresi hemen açılır ki aynı bağlantıdaki diğer stream'ler
        aç kalmasın); okunmayan veri ilan edilen stream penceresiyle sınırlıdır."""
        rt, wt = self._timeouts(read_timeout, write_timeout)
        while True:
            if not self.usable:
                raise H2StreamRefused("HTTP/2 bağlantısı yeni stream kabul etmiyor.")
            if len(self._streams) < self._max_streams:
                break
            await self._wait_change(wt)

        full = h2_request_headers(self._h2, method, authority, scheme, path, headers)
        st = self._alloc_stream()
        st.streaming = True
        st.hdr_fut = B.new_future()
        self.last_used = time.perf_counter()
        handle = H2StreamHandle(self, st, rt, wt)
        in_memory = isinstance(body, (bytes, bytearray, memoryview))
        try:
            self._send_headers(st.id, full, end_stream=in_memory and not body)
        except BaseException:
            self._streams.pop(st.id, None)
            raise
        try:
            await self._drain(wt)
            if not in_memory or body:
                await self._send_body(st, body, wt)
            while True:
                done = await B.wait_future(st.hdr_fut, rt)
                if done:
                    st.hdr_fut.result()
                    break
                if st.activity:
                    st.activity = False
                    continue
                raise asyncio.TimeoutError(
                    f"HTTP/2 yanıtı {rt} sn içinde gelmedi (stream {st.id}).")
        except BaseException:
            handle.close_nowait()
            raise
        handle.status, handle.headers = st.status, list(st.headers)
        handle.first_byte_time = st.first_byte_time
        return handle

    # ------------------------------------------------------------ kapanış
    async def close(self) -> None:
        """GOAWAY(NO_ERROR) gönderip bağlantıyı kapatır."""
        if not self._closed:
            self._send_goaway(0)
        task = self._task
        self._teardown(Http2ConnectionError("HTTP/2 bağlantısı kapatıldı."))
        await B.cancel_task(task)
        try:
            await self._s.wait_closed()
        except (OSError, ConnectionError, asyncio.CancelledError, RuntimeError):
            pass
