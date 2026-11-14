"""HTTP/2 akış testleri: senkron Http2Connection.request_stream (sahte soket) ve
Session (iş parçacığındaki sahte h2 sunucusuna karşı), AsyncSession h2 akışı."""
import asyncio
import struct
import threading

import pytest

from fasthttpc import AsyncSession, Session
from fasthttpc.protocol.http2_parser import (
    FrameType, HTTP2Frame, HpackEncoder, Http2Connection, Http2StreamError,
)

from async_fakes import RawH2Conn, start_h2
from test_http2 import SahteSoket
from tls13_fakeserver import PKI

HOST = "localhost"


def _hdr(sid, status=200, extra=(), end=False):
    block = HpackEncoder().encode([(":status", str(status))] + list(extra))
    return HTTP2Frame(len(block), FrameType.HEADERS, 0x4 | (1 if end else 0), sid, block)


def _data(sid, body, end=False):
    return HTTP2Frame(len(body), FrameType.DATA, 1 if end else 0, sid, body)


def _wus(sock):
    out = []
    for f in sock.gonderilen_frameler():
        if f.type == FrameType.WINDOW_UPDATE:
            out.append((f.stream_id, struct.unpack("!I", f.payload)[0]))
    return out


GET = dict(method="GET", authority="x", path="/", headers=[])


def test_sync_h2_stream_govde_parca_parca_ve_wu_tuketildikce():
    sock = SahteSoket([_hdr(1), _data(1, b"aaaa"), _data(1, b"bb"), _data(1, b"c", end=True)])
    conn = Http2Connection(sock)
    st = conn.request_stream(**GET)
    assert st.status == 200 and _wus(sock) == []      # henüz DATA okunmadı -> WU yok
    assert st.read_chunk() == b"aaaa"
    assert (1, 4) in _wus(sock) and (0, 4) in _wus(sock)
    assert [_wus(sock).count((0, n)) for n in (2, 1)] == [0, 0]   # sıradakiler okunmadı
    assert st.read_chunk() == b"bb"
    assert st.read_chunk() == b"c"
    assert st.read_chunk() == b""
    assert conn._lock.acquire(blocking=False)         # akış bitince kilit serbest
    conn._lock.release()


def test_sync_h2_erken_close_rst_cancel_gonderir_ve_baglanti_yasar():
    sock = SahteSoket([_hdr(1), _data(1, b"xxxx")])
    conn = Http2Connection(sock)
    st = conn.request_stream(**GET)
    assert st.read_chunk() == b"xxxx"
    st.close()
    rst = [f for f in sock.gonderilen_frameler() if f.type == FrameType.RST_STREAM]
    assert len(rst) == 1 and rst[0].stream_id == 1
    assert struct.unpack("!I", rst[0].payload)[0] == 8      # CANCEL
    assert not st.broken and st.cancelled
    # bağlantı yeni istek kabul eder; eski stream'in geç DATA/trailer'ı yutulur ve
    # bağlantı penceresi geri açılır, HPACK senkron kalır
    sock._gelen += _data(1, b"gec-veri").serialize()
    sock._gelen += _hdr(3).serialize() + _data(3, b"ok", end=True).serialize()
    status, hdrs, body = conn.request(**GET)
    assert (status, body) == (200, b"ok")
    assert (0, 8) in _wus(sock)


def test_sync_h2_rst_stream_hatasi_kilidi_birakir():
    rst = HTTP2Frame(4, FrameType.RST_STREAM, 0, 1, struct.pack("!I", 2))
    sock = SahteSoket([_hdr(1), rst])
    conn = Http2Connection(sock)
    st = conn.request_stream(**GET)
    with pytest.raises(Http2StreamError):
        st.read_chunk()
    assert st.broken and conn._lock.acquire(blocking=False)


def test_sync_h2_request_eski_davranis_ayni():
    sock = SahteSoket([_hdr(1, 201, [("x-a", "1")]), _data(1, b"he"), _data(1, b"llo", end=True)])
    status, hdrs, body = Http2Connection(sock).request(**GET)
    assert (status, body) == (201, b"hello") and ("x-a", "1") in hdrs


# ---------------------------------------------------------------- Session <-> sahte sunucu
@pytest.fixture(scope="module")
def pki():
    return PKI(HOST)


@pytest.fixture
def ca(pki, tmp_path):
    p = tmp_path / "ca.pem"
    p.write_bytes(pki.ca_pem())
    return str(p)


class _Sunucu:
    """Ayrı iş parçacığında asyncio döngüsü: RawH2Conn tabanlı sahte h2 sunucusu."""

    def __init__(self, pki, script):
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.conns = []
        self.port = None
        threading.Thread(target=self._run, args=(pki, script), daemon=True).start()
        assert self.ready.wait(10)

    def _run(self, pki, script):
        asyncio.set_event_loop(self.loop)

        async def main():
            self.server, self.port, self.conns = await start_h2(pki, script)
            self.ready.set()
            await self.server.serve_forever()
        try:
            self.loop.run_until_complete(main())
        except asyncio.CancelledError:
            pass

    def stop(self):
        def _s():
            self.server.close()
            for t in asyncio.all_tasks(self.loop):
                t.cancel()
        self.loop.call_soon_threadsafe(_s)


async def _servis(c: RawH2Conn):
    """GET /n -> n baytlık gövde 4 DATA frame'inde; DATA arasında kısa bekleme.
    RST_STREAM alınırsa ``c.rst_alindi`` listesine eklenir."""
    c.rst_alindi = []
    await c.handshake()
    while True:
        f = await c.next_frame()
        if f is None:
            return
        if f.type == FrameType.RST_STREAM:
            c.rst_alindi.append(f.stream_id)
        if f.type == FrameType.HEADERS and c.requests[f.stream_id]["ended"]:
            sid = f.stream_id
            path = dict(c.requests[sid]["headers"])[":path"]
            n = int(path.strip("/") or 0)
            c.send(c.response_headers(sid, 200, [("content-type", "application/octet-stream")]))
            parca = n // 4
            for i in range(4):
                son = i == 3
                c.send(c.data(sid, bytes([65 + i]) * (parca if not son else n - 3 * parca), end=son))
                await c.flush()
                await asyncio.sleep(0.02)


def test_session_h2_stream_uctan_uca_ve_baglanti_yeniden_kullanilir(pki, ca):
    sv = _Sunucu(pki, _servis)
    try:
        with Session(impersonate="chrome_131", verify=ca, timeout=5) as s:
            url = f"https://localhost:{sv.port}"
            with s.get(url + "/4000", stream=True) as r:
                assert r.http_version == "HTTP/2" and not r.is_stream_consumed
                data = b"".join(r.iter_content(chunk_size=None))
            assert data == b"A" * 1000 + b"B" * 1000 + b"C" * 1000 + b"D" * 1000
            # yarıda kapat: stream CANCEL ile iptal edilir, bağlantı yaşar
            r = s.get(url + "/4000", stream=True)
            first = next(r.iter_raw())
            assert first.startswith(b"A")
            r.close()
            r2 = s.get(url + "/40")
            assert r2.content == b"A" * 10 + b"B" * 10 + b"C" * 10 + b"D" * 10
            assert len(sv.conns) == 1
            assert sv.conns[0].rst_alindi == [3]
    finally:
        sv.stop()


# ---------------------------------------------------------------- async h2
def run(coro, timeout=20):
    return asyncio.run(asyncio.wait_for(coro, timeout))


def test_async_h2_stream_ve_geri_basinc(pki, ca):
    """Tüketici okumadıkça stream WINDOW_UPDATE gitmez; okudukça gider."""
    async def script(c: RawH2Conn):
        await c.handshake()
        f = await c.next_frame(FrameType.HEADERS)
        sid = f.stream_id
        c.send(c.response_headers(sid, 200))
        c.send(c.data(sid, b"x" * 1000), c.data(sid, b"y" * 1000))
        await c.flush()
        c.wu_before = []
        try:
            while True:
                g = await c.next_frame(FrameType.WINDOW_UPDATE, timeout=0.4)
                if g is None:
                    break
                c.wu_before.append((g.stream_id, struct.unpack("!I", g.payload)[0]))
        except asyncio.TimeoutError:
            pass
        c.send(c.data(sid, b"z", end=True))
        await c.flush()
        try:
            while True:
                g = await c.next_frame(timeout=1)
                if g is None:
                    return
        except asyncio.TimeoutError:
            return

    async def main():
        srv, port, conns = await start_h2(pki, script)
        async with srv:
            async with AsyncSession(impersonate="chrome_131", verify=ca, timeout=5) as s:
                r = await s.get(f"https://localhost:{port}/", stream=True)
                assert r.status_code == 200 and r.http_version == "HTTP/2"
                await asyncio.sleep(0.6)       # tüketici okumuyor
                c = conns[0]
                # bağlantı penceresi hemen, STREAM penceresi hiç açılmadı
                assert all(sid == 0 for sid, _ in c.wu_before), c.wu_before
                got = [ch async for ch in r.aiter_bytes()]
                assert b"".join(got) == b"x" * 1000 + b"y" * 1000 + b"z"
    run(main())


def test_async_h2_aclose_cancel_ve_baglanti_yasar(pki, ca):
    async def main():
        srv, port, conns = await start_h2(pki, _servis)
        async with srv:
            async with AsyncSession(impersonate="chrome_131", verify=ca, timeout=5) as s:
                u = f"https://localhost:{port}"
                async with s.stream("GET", u + "/4000") as r:
                    it = r.aiter_raw()
                    assert (await it.__anext__()).startswith(b"A")
                r2 = await s.get(u + "/40")
                assert r2.body.startswith(b"A" * 10)
                assert len(conns) == 1 and conns[0].rst_alindi == [1]
                async with s.stream("GET", u + "/400") as r3:
                    assert len(await r3.aread()) == 400
                    assert len(r3.content) == 400
    run(main())
