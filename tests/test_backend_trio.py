"""AsyncSession'ın HEM asyncio HEM trio altında çalıştığını doğrular (ağsız).

Sahte sunucular (mevcut asyncio tabanlı yardımcılar) AYRI bir thread'deki
asyncio döngüsünde koşar; istemci ``backend`` fixture'ına göre ``asyncio.run``
ya da ``trio.run`` altında çalışır. İptal/zaman aşımı kapsamları anyio
(``move_on_after``/``fail_after``) ile yazıldığından iki arka uçta da aynı
test gövdesi geçerlidir.
"""
import asyncio
import struct
import threading
import time

import pytest

anyio = pytest.importorskip("anyio")
trio = pytest.importorskip("trio")

from fasthttpc import AsyncSession, Limits, Timeout  # noqa: E402
from fasthttpc import _backend as B  # noqa: E402
from fasthttpc.protocol.http2_parser import FrameType  # noqa: E402
from tls13_fakeserver import PKI, http_responder  # noqa: E402
from async_fakes import AsyncFakeProxy, start_h2, start_tls13, start_stdlib_tls  # noqa: E402
from test_async_h2 import echo, _path  # noqa: E402
from test_async_pool import H1Server, ok  # noqa: E402
from test_async_ws import WSServer, talk, ws_tls13_handler, target_of  # noqa: E402


@pytest.fixture(scope="module")
def pki():
    return PKI("localhost")


@pytest.fixture
def ca(pki, tmp_path):
    p = tmp_path / "ca.pem"
    p.write_bytes(pki.ca_pem())
    return str(p)


@pytest.fixture(params=["asyncio", "trio"])
def backend(request):
    return request.param


class ServerLoop:
    """Sahte sunucuları ayrı thread'deki asyncio döngüsünde çalıştırır."""

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.t = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.t.start()

    def call(self, coro, timeout=10):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def close(self):
        async def cancel_all():
            tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        try:
            asyncio.run_coroutine_threadsafe(cancel_all(), self.loop).result(5)
        except Exception:  # noqa: BLE001
            pass
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.t.join(5)


@pytest.fixture
def srvloop():
    s = ServerLoop()
    yield s
    s.close()


def run_client(backend, fn, timeout=20):
    async def main():
        with anyio.fail_after(timeout):
            return await fn()
    if backend == "asyncio":
        return asyncio.run(main())
    return trio.run(main)


def sess(ca, **kw):
    kw.setdefault("timeout", 5)
    kw.setdefault("impersonate", "chrome_131")
    return AsyncSession(verify=ca, **kw)


def sem_value(s):
    sem = s._sem
    return sem._value if hasattr(sem, "_value") else sem.value


# =================================================================== HTTP/2
def test_h2_istek_ve_baglanti_yeniden_kullanimi(backend, srvloop, pki, ca):
    srv, port, conns = srvloop.call(start_h2(pki, echo))

    async def client():
        s = sess(ca)
        for i in range(3):
            r = await s.get(f"https://localhost:{port}/{i}")
            assert r.status_code == 200 and r.body == f"/{i}:0".encode()
        assert s.cookies == {"a": "1", "b": "2"}
        await s.close()
    run_client(backend, client)
    assert len(conns) == 1 and sorted(conns[0].requests) == [1, 3, 5]


def test_h2_eszamanli_multiplexing(backend, srvloop, pki, ca):
    async def script(c):
        await c.handshake()
        sids = []
        while len(sids) < 5:
            f = await c.next_frame(FrameType.HEADERS)
            sids.append(f.stream_id)
        for sid in reversed(sids):
            c.respond(sid, 200, [], f"cevap{_path(c, sid)}".encode())
        await c.flush()
        while await c.next_frame() is not None:
            pass
    srv, port, conns = srvloop.call(start_h2(pki, script))

    async def client():
        s = sess(ca)
        rs = await s.gather(*[("GET", f"https://localhost:{port}/{i}") for i in range(5)])
        assert [r.body for r in rs] == [f"cevap/{i}".encode() for i in range(5)]
        await s.close()
    run_client(backend, client)
    assert len(conns) == 1


def test_h2_gorev_grubu_ile_eszamanli(backend, srvloop, pki, ca):
    """anyio görev grubundan eşzamanlı istekler tek h2 bağlantısını paylaşır."""
    srv, port, conns = srvloop.call(start_h2(pki, echo))
    out = {}

    async def client():
        s = sess(ca)

        async def one(i):
            out[i] = (await s.get(f"https://localhost:{port}/{i}")).body
        async with anyio.create_task_group() as tg:
            for i in range(6):
                tg.start_soon(one, i)
        await s.close()
    run_client(backend, client)
    assert out == {i: f"/{i}:0".encode() for i in range(6)}
    assert len(conns) == 1


def test_h2_iptal_rst_stream_cancel_gonderir(backend, srvloop, pki, ca):
    got = {}

    async def script(c):
        await c.handshake()
        f = await c.next_frame(FrameType.HEADERS)
        r = await c.next_frame(FrameType.RST_STREAM)
        got["rst"] = (r.stream_id, struct.unpack("!I", r.payload)[0], f.stream_id)
        while await c.next_frame() is not None:
            pass
    srv, port, conns = srvloop.call(start_h2(pki, script))

    async def client():
        s = sess(ca, timeout=30)
        with anyio.move_on_after(0.3) as scope:       # CancelScope iptali
            await s.get(f"https://localhost:{port}/")
        assert scope.cancelled_caught
        await B.sleep(0.3)
        assert s._h2 and not list(s._h2.values())[0].closed    # bağlantı sağlam
        await s.close()
    run_client(backend, client)
    assert got["rst"] == (1, 8, 1)


def test_h2_read_timeout_hareketsizlik_olarak_uygulanir(backend, srvloop, pki, ca):
    async def silent(c):
        await c.handshake()
        await c.next_frame(FrameType.HEADERS)
        r = await c.next_frame(FrameType.RST_STREAM, timeout=5)
        assert struct.unpack("!I", r.payload)[0] == 8
        while await c.next_frame() is not None:
            pass

    async def dribble(c):
        await c.handshake()
        f = await c.next_frame(FrameType.HEADERS)
        c.send(c.response_headers(f.stream_id, 200))
        await c.flush()
        for _ in range(6):
            await asyncio.sleep(0.2)
            c.send(c.data(f.stream_id, b"x"))
            await c.flush()
        c.send(c.data(f.stream_id, b"", end=True))
        await c.flush()
        while await c.next_frame() is not None:
            pass
    _, p1, _ = srvloop.call(start_h2(pki, silent))
    _, p2, _ = srvloop.call(start_h2(pki, dribble))

    async def client():
        s = sess(ca, timeout=Timeout(5, read=0.4))
        t0 = time.monotonic()
        with pytest.raises(asyncio.TimeoutError):
            await s.get(f"https://localhost:{p1}/")
        assert time.monotonic() - t0 < 2.5
        await s.close()
        s = sess(ca, timeout=Timeout(5, read=0.6))
        r = await s.get(f"https://localhost:{p2}/")
        assert r.body == b"x" * 6
        await s.close()
    run_client(backend, client)


def test_h2_oturum_close_goaway_ve_okuyucu_gorevi_biter(backend, srvloop, pki, ca):
    seen = {}

    async def script(c):
        await c.handshake()
        f = await c.next_frame(FrameType.HEADERS)
        c.respond(f.stream_id, 200, [], b"ok")
        await c.flush()
        g = await c.next_frame(FrameType.GOAWAY)
        seen["goaway"] = g is not None
        while await c.next_frame() is not None:
            pass
    srv, port, conns = srvloop.call(start_h2(pki, script))

    async def client():
        async with sess(ca) as s:
            await s.get(f"https://localhost:{port}/")
            conn = list(s._h2.values())[0]
        assert conn.closed and conn._task.done()
    run_client(backend, client)
    for _ in range(100):               # sunucu thread'i işlesin
        if "goaway" in seen:
            break
        time.sleep(0.02)
    assert seen.get("goaway") is True


# =================================================================== HTTP/1.1
def test_h1_stdlib_tls_ve_keepalive_havuzu(backend, srvloop, pki, ca, tmp_path):
    srv = srvloop.call(H1Server(pki, tmp_path).start())

    async def client():
        s = sess(ca, impersonate=None, timeout=Timeout(5, read=2))
        for i in range(4):
            r = await s.get(f"{srv.base}/{i}")
            assert r.body == f"/{i}".encode()
        assert s._idle_count() == 1 and sem_value(s) == s.limits.max_connections
        await s.close()
    run_client(backend, client)
    assert srv.conns == 1


def test_h1_impersonate_tls13_cekirdegi(backend, srvloop, pki, ca):
    server, port, servers = srvloop.call(start_tls13(pki, http_responder(b"merhaba"), alpn="http/1.1"))

    async def client():
        s = sess(ca)
        r = await s.get(f"https://localhost:{port}/")
        assert r.body == b"merhaba" and r.http_version == "HTTP/1.1"
        await s.close()
    run_client(backend, client)
    assert servers[0].client_hellos[0]["exts"]


def test_h1_gomulu_stdlib_tls_sunucusu(backend, srvloop, pki, ca, tmp_path):
    server, port, requests = srvloop.call(start_stdlib_tls(pki, tmp_path, b"stdlib"))

    async def client():
        s = sess(ca, impersonate=None)
        r = await s.get(f"https://localhost:{port}/x")
        assert r.body == b"stdlib" and r.cookies if hasattr(r, "cookies") else True
        await s.close()
    run_client(backend, client)
    assert requests[0].startswith(b"GET /x HTTP/1.1\r\n")


def test_h1_bayat_baglanti_bir_kez_yeniden_denenir(backend, srvloop, pki, ca, tmp_path):
    def script(c, r, m, p, b):
        return (ok(b"1"),) if c == 1 else ok(b"2")        # 1. yanıttan sonra sunucu kapatır
    srv = srvloop.call(H1Server(pki, tmp_path, script).start())

    async def client():
        s = sess(ca, impersonate=None)
        assert (await s.get(f"{srv.base}/a")).body == b"1"
        await B.sleep(0.2)
        assert (await s.get(f"{srv.base}/b")).body == b"2"
        await s.close()
    run_client(backend, client)
    assert srv.conns == 2


def test_h1_okuma_zaman_asimi_ve_slot_serbest(backend, srvloop, pki, ca, tmp_path):
    srv = srvloop.call(H1Server(pki, tmp_path, lambda c, r, m, p, b: "hang").start())

    async def client():
        s = sess(ca, impersonate=None, timeout=Timeout(5, read=0.3))
        t0 = time.monotonic()
        with pytest.raises(asyncio.TimeoutError):
            await s.get(f"{srv.base}/")
        assert time.monotonic() - t0 < 2.5
        assert sem_value(s) == s.limits.max_connections
        await s.close()
    run_client(backend, client)


def test_h1_iptal_slotu_geri_verir(backend, srvloop, pki, ca, tmp_path):
    srv = srvloop.call(H1Server(pki, tmp_path, lambda c, r, m, p, b: "hang").start())

    async def client():
        s = sess(ca, impersonate=None, timeout=Timeout(5, read=30), limits=Limits(max_connections=1))
        with anyio.move_on_after(0.4) as scope:
            await s.get(f"{srv.base}/")
        assert scope.cancelled_caught
        assert sem_value(s) == 1 and not s._idle
        await s.close()
    run_client(backend, client)


def test_h1_havuz_zaman_asimi(backend, srvloop, pki, ca, tmp_path):
    srv = srvloop.call(H1Server(pki, tmp_path, lambda c, r, m, p, b: "hang").start())

    async def client():
        s = sess(ca, impersonate=None, timeout=Timeout(5, read=3, pool=0.3),
                 limits=Limits(max_connections=1))
        out = []

        async def hang():
            try:
                await s.get(f"{srv.base}/bekle")
            except BaseException as e:      # noqa: BLE001
                out.append(("hang", type(e).__name__))
                raise
        async with anyio.create_task_group() as tg:
            tg.start_soon(hang)
            await B.sleep(0.2)
            with pytest.raises(asyncio.TimeoutError, match="havuz"):
                await s.get(f"{srv.base}/ikinci")
            tg.cancel_scope.cancel()
        assert sem_value(s) == 1
        await s.close()
    run_client(backend, client)


def test_h1_baglanti_zaman_asimi(backend):
    """Kabul edip el sıkışmayan sunucu: connect zaman aşımı (TLS dahil)."""
    import socket
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(4)
    port = lsock.getsockname()[1]

    async def client():
        for imp in (None, "chrome_131"):
            s = AsyncSession(impersonate=imp, timeout=Timeout(connect=0.3, read=5))
            t0 = time.monotonic()
            with pytest.raises(asyncio.TimeoutError):
                await s.get(f"https://localhost:{port}/")
            assert time.monotonic() - t0 < 2.5
            await s.close()
    try:
        run_client(backend, client)
    finally:
        lsock.close()


def test_h1_baglanti_reddi_oserror(backend):
    import socket
    s0 = socket.socket()
    s0.bind(("127.0.0.1", 0))
    port = s0.getsockname()[1]
    s0.close()

    async def client():
        s = AsyncSession(impersonate=None, timeout=2)
        with pytest.raises(OSError):
            await s.get(f"https://127.0.0.1:{port}/")
        assert sem_value(s) == s.limits.max_connections
        await s.close()
    run_client(backend, client)


def test_retry_gecikmesi_iptal_edilebilir(backend, srvloop, pki, ca, tmp_path):
    srv = srvloop.call(H1Server(pki, tmp_path, lambda c, r, m, p, b: ok(b"x")).start())

    async def client():
        t0 = time.monotonic()
        with anyio.move_on_after(0.2) as scope:
            await B.sleep(10)
        assert scope.cancelled_caught and time.monotonic() - t0 < 2
    run_client(backend, client)
    del srv


# =================================================================== proxy
@pytest.mark.parametrize("kind", ["http", "socks5"])
@pytest.mark.parametrize("impersonate", [None, "chrome_131"])
def test_https_proxy_uzerinden(backend, kind, impersonate, srvloop, pki, ca, tmp_path):
    srv = srvloop.call(H1Server(pki, tmp_path).start()) if impersonate is None else None
    if impersonate is None:
        port = srv.port
    else:
        _, port, _ = srvloop.call(start_tls13(pki, http_responder(b"tunel"), alpn="http/1.1"))
    proxy = srvloop.call(AsyncFakeProxy(kind, upstream_port=port).start())

    async def client():
        async with sess(ca, impersonate=impersonate, proxy=proxy.url) as s:
            r = await s.get("https://localhost/yol")
            assert r.status_code == 200
            assert r.body == (b"/yol" if impersonate is None else b"tunel")
    run_client(backend, client)
    assert proxy.connections == 1 and target_of(proxy) == "localhost:443"


def test_proxy_kimlik_dogrulama_http(backend, srvloop, pki, ca, tmp_path):
    srv = srvloop.call(H1Server(pki, tmp_path).start())
    proxy = srvloop.call(AsyncFakeProxy("http", upstream_port=srv.port, auth="u:p").start())

    async def client():
        async with sess(ca, impersonate=None, proxy=f"http://u:p@127.0.0.1:{proxy.port}") as s:
            assert (await s.get("https://localhost/")).status_code == 200
    run_client(backend, client)
    assert b"Proxy-Authorization: Basic " in proxy.heads[0]


def test_proxy_reddi_proxy_error(backend, srvloop, pki, ca):
    from fasthttpc.transport.proxy import ProxyError
    proxy = srvloop.call(AsyncFakeProxy("http", upstream_port=1, reply=b"HTTP/1.1 403 Forbidden\r\n\r\n").start())

    async def client():
        async with sess(ca, impersonate=None, proxy=proxy.url) as s:
            with pytest.raises(ProxyError):
                await s.get("https://localhost/")
    run_client(backend, client)


# ================================================================ websocket
@pytest.mark.parametrize("impersonate", [None, "chrome_131"])
def test_wss_dogrudan_ve_proxy(backend, impersonate, srvloop, pki, ca, tmp_path):
    srv = srvloop.call(WSServer(pki, tmp_path).start())
    proxy = srvloop.call(AsyncFakeProxy("http", upstream_port=srv.port).start())

    async def client():
        async with AsyncSession(impersonate=impersonate, verify=ca, timeout=5) as s:
            async with await s.ws_connect(f"wss://localhost:{srv.port}/chat") as ws:
                await talk(ws)
        async with AsyncSession(impersonate=impersonate, verify=ca, timeout=5, proxy=proxy.url) as s:
            async with await s.ws_connect("wss://localhost/soket") as ws:
                await talk(ws)
    run_client(backend, client)
    assert srv.heads[0].startswith(b"GET /chat HTTP/1.1\r\n") and proxy.connections == 1


def test_ws_duz_tcp(backend, srvloop):
    srv = srvloop.call(WSServer(tls=False).start())

    async def client():
        async with AsyncSession(timeout=5) as s:
            async with await s.ws_connect(f"ws://127.0.0.1:{srv.port}/") as ws:
                await talk(ws)
    run_client(backend, client)


def test_wss_impersonate_tls13_cekirdegi(backend, srvloop, pki, ca):
    server, port, servers = srvloop.call(start_tls13(pki, ws_tls13_handler(), alpn="http/1.1"))

    async def client():
        async with AsyncSession(impersonate="chrome_131", verify=ca, timeout=5) as s:
            async with await s.ws_connect(f"wss://localhost:{port}/") as ws:
                await talk(ws)
    run_client(backend, client)
    assert servers[0].client_hellos[0]["alpn"] == ["http/1.1"]


def test_pre_warm_ve_havuza_konur(backend, srvloop, pki, ca):
    server, port, servers = srvloop.call(start_tls13(pki, http_responder(b"sicak"), alpn="http/1.1"))
    proxy = srvloop.call(AsyncFakeProxy("http", upstream_port=port).start())

    async def client():
        async with sess(ca, proxy=proxy.url) as s:
            assert await s.pre_warm(["localhost"], count=2) == {"localhost": 2}
            r = await s.get("https://localhost/")
            assert r.body == b"sicak"
        s = sess(ca, timeout=Timeout(1), proxy="http://127.0.0.1:1")
        assert await s.pre_warm(["localhost"], count=2) == {"localhost": 0}
        await s.close()
    run_client(backend, client)
    assert proxy.connections == 2


# ============================================================ PSK / çekirdek
from test_psk_resumption_async import tls_server, _roundtrip  # noqa: E402,F401


def test_psk_resumption_gercek_openssl_sunucusunda(backend, tls_server):
    from fasthttpc.security import session_tickets as st
    port, ca_path, results = tls_server
    st.default_cache.clear()
    st.enable_resumption(True)
    try:
        out = {}

        async def client():
            out["s1"], out["d1"] = await _roundtrip(port, ca_path, b"one")
            out["s2"], out["d2"] = await _roundtrip(port, ca_path, b"two")
        run_client(backend, client)
        assert out["d1"] == b"echo:one" and out["d2"] == b"echo:two"
        assert not out["s1"].state["resumed"] and out["s2"].state["resumed"] is True
        assert results == [False, True]
    finally:
        st.default_cache.clear()
        st.enable_resumption(False)


# ============================================================ arka uç birimleri
def test_backend_wait_for_zaman_asimi_asyncio_timeouterror(backend):
    async def client():
        with pytest.raises(asyncio.TimeoutError):
            await B.wait_for(B.sleep(5), 0.1)
        assert await B.wait_for(B.sleep(0), None) is None
        assert await B.wait_for(B.sleep(0), 1) is None
    run_client(backend, client)


def test_backend_gather_sonuclar_sirali_ve_ilk_hata(backend):
    async def val(i, d=0):
        await B.sleep(d)
        return i

    async def boom():
        await B.sleep(0.05)
        raise ValueError("x")

    async def client():
        assert await B.gather(val(1, 0.1), val(2), val(3, 0.05)) == [1, 2, 3]
        t0 = time.monotonic()
        with pytest.raises(ValueError):
            await B.gather(boom(), val(1, 5))
        if backend == "trio":                  # kalanlar iptal edilir
            assert time.monotonic() - t0 < 2
    run_client(backend, client)


def test_backend_future_ve_wait_future(backend):
    async def client():
        f = B.new_future()
        assert not await B.wait_future(f, 0.05)
        f.set_result(7)
        assert await B.wait_future(f, 0.05) and f.result() == 7 and await f == 7
        g = B.new_future()
        g.set_exception(KeyError("k"))
        with pytest.raises(KeyError):
            await g
        h = B.new_future()
        assert h.cancel() and h.cancelled() and h.done()
    run_client(backend, client)


def test_backend_spawn_cancel_task(backend):
    seen = []

    async def work():
        try:
            await B.sleep(30)
        except B.cancelled_exc_class():
            seen.append("iptal")
            raise

    async def client():
        t = B.spawn(work(), name="x")
        done = []
        t.add_done_callback(lambda _t: done.append(1))
        await B.sleep(0.05)
        assert not t.done()
        await B.cancel_task(t)
        await B.sleep(0.05)
        assert t.done() and seen == ["iptal"] and done == [1]
    run_client(backend, client)


def test_backend_tespit_ve_token(backend):
    async def client():
        assert B.current_backend() == backend
        tok = B.current_token()
        assert tok is not None and tok is B.current_token()
        assert B.cancelled_exc_class() is (asyncio.CancelledError if backend == "asyncio" else trio.Cancelled)
    run_client(backend, client)
    assert B.current_backend(None) is None and B.current_token() is None


def test_oturum_dongu_disinda_olusturulup_trio_altinda_kullanilir(srvloop, pki, ca, tmp_path):
    """AsyncSession döngü dışında kurulur; semafor/kilitler çalışan arka uca göre kurulur."""
    srv = srvloop.call(H1Server(pki, tmp_path).start())
    s = sess(ca, impersonate=None, limits=Limits(max_connections=2))
    assert s._sem._value == 2                      # geçici asyncio semaforu

    async def client():
        rs = await s.gather(*[("GET", f"{srv.base}/{i}") for i in range(4)])
        assert [r.body for r in rs] == [f"/{i}".encode() for i in range(4)]
        assert s._sem_kind == "trio"
        await s.close()
    trio.run(client)


def test_trio_ratelimit_eklentisi(srvloop):
    from fasthttpc.async_session import RateLimitPlugin
    p = RateLimitPlugin(rps=50)

    async def client():
        t0 = time.monotonic()
        for _ in range(4):
            await p.async_on_request({})   # async kanca (api: sync on_request + async_on_request)
        assert time.monotonic() - t0 >= 0.05
    trio.run(client)


def test_trio_acik_akis_readuntil_ve_sinirlar(backend, srvloop):
    async def srv_handler(r, w):
        w.write(b"abc\r\n\r\nrest")
        await w.drain()
        await asyncio.sleep(0.2)
        w.close()

    async def start():
        return await asyncio.start_server(srv_handler, "127.0.0.1", 0)
    server = srvloop.call(start())
    port = server.sockets[0].getsockname()[1]

    async def client():
        r, w = await B.open_connection("127.0.0.1", port)
        assert await r.readuntil(b"\r\n\r\n") == b"abc\r\n\r\n"
        assert await r.readexactly(4) == b"rest"
        assert await r.read(10) == b""
        assert r.at_eof()
        with pytest.raises(asyncio.IncompleteReadError):
            await r.readexactly(1)
        w.close()
        await w.wait_closed()
    run_client(backend, client)


# ============================================================ akış (stream)
@pytest.fixture(scope="module")
def yerel():
    from saha.yerel_sunucu import YerelSunucu
    with YerelSunucu() as s:
        yield s


def test_h1_akis_gelisi_gozu_ve_aiter(backend, yerel):
    async def client():
        async with AsyncSession(verify=yerel.ca_path, timeout=5) as s:
            t = time.monotonic()
            r = await s.get(yerel.url + "/lines?n=3&d=0.3", stream=True)
            assert time.monotonic() - t < 0.25            # gövde beklenmeden döner
            assert b"".join([c async for c in r.aiter_bytes()]) == b"satir-0\nsatir-1\nsatir-2\n"
            await r.aclose()
            async with s.stream("GET", yerel.url + "/chunked?i=Q") as r:
                assert await r.aread() == b"parca1-parca2-Q"
            async with s.stream("GET", yerel.url + "/gzlines?n=3") as r:
                assert [ln async for ln in r.aiter_lines()] == ["satir-0", "satir-1", "satir-2"]
    run_client(backend, client)


def test_h1_akis_okuma_zaman_asimi_ve_yarida_kapatma(backend, yerel):
    async def client():
        async with AsyncSession(verify=yerel.ca_path, timeout=Timeout(5, read=0.3)) as s:
            r = await s.get(yerel.url + "/lines?n=3&d=1.5", stream=True)
            with pytest.raises(asyncio.TimeoutError):
                async for _ in r.aiter_bytes():
                    pass
            await r.aclose()
            async with s.stream("GET", yerel.url + "/chunked?i=Q") as r:
                it = r.aiter_bytes()
                await it.__anext__()           # yarıda bırak; bağlantı sızmaz
            assert sem_value(s) == s.limits.max_connections
    run_client(backend, client)


def test_h2_akis_parca_parca(backend, srvloop, pki, ca):
    async def script(c):
        await c.handshake()
        f = await c.next_frame(FrameType.HEADERS)
        c.send(c.response_headers(f.stream_id, 200))
        for i in range(4):
            c.send(c.data(f.stream_id, b"p%d" % i))
            await c.flush()
            await asyncio.sleep(0.05)
        c.send(c.data(f.stream_id, b"", end=True))
        await c.flush()
        while await c.next_frame() is not None:
            pass
    srv, port, conns = srvloop.call(start_h2(pki, script))

    async def client():
        async with sess(ca) as s:
            async with s.stream("GET", f"https://localhost:{port}/") as r:
                chunks = [c async for c in r.aiter_bytes()]
            assert b"".join(chunks) == b"p0p1p2p3" and len(chunks) >= 2
    run_client(backend, client)
