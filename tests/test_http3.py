"""HTTP/3 testleri: tümü yerel (127.0.0.1 UDP), kendi CA'mızla. aioquic yoksa atlanır."""
import asyncio
import json
import socket
import time

import pytest

pytest.importorskip("aioquic")

from fasthttpc import AsyncSession, Session  # noqa: E402
from fasthttpc.http3 import Http3Options, parse_alt_svc  # noqa: E402
from fasthttpc.security.cert_validator import CertificateValidationError  # noqa: E402

from h3_servers import HITS, H3TestServer, NoFqdnHTTPServer, make_ca, make_leaf  # noqa: E402


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    ca_key, ca_cert, ca_pem = make_ca(d, "ca")
    _, _, other_ca = make_ca(d, "other")
    crt, key = make_leaf(d, ca_key, ca_cert, ("localhost",))
    wcrt, wkey = make_leaf(d, ca_key, ca_cert, ("wrong.example",), tag="wrong")
    return {"ca": ca_pem, "other_ca": other_ca, "crt": crt, "key": key, "wcrt": wcrt, "wkey": wkey}


@pytest.fixture(scope="module")
def h3(pki):
    s = H3TestServer(pki["crt"], pki["key"]).start()
    yield s
    s.stop()


def url(s, path="/"):
    return f"https://localhost:{s.port}{path}"


def test_sync_get_post(pki, h3):
    with Session(http3="force", verify=pki["ca"]) as s:
        r = s.get(url(h3, "/a?b=1"))
        assert r.http_version == "HTTP/3" and r.status_code == 200
        assert r.headers["x-proto"] == "h3"
        assert json.loads(r.body)["path"] == "/a?b=1"
        r2 = s.post(url(h3, "/p"), data=b"hello")
        d = json.loads(r2.body)
        assert d["method"] == "POST" and d["body"] == "hello"


def test_async_get_post_and_reuse(pki, h3):
    async def go():
        async with AsyncSession(http3="force", verify=pki["ca"]) as s:
            r = await s.get(url(h3))
            assert r.http_version == "HTTP/3"
            r2 = await s.post(url(h3, "/x"), data=b"abc")
            assert json.loads(r2.body)["body"] == "abc"
            assert len(s._h3._conns) == 1      # bağlantı yeniden kullanıldı
    asyncio.run(go())


def test_async_multiplexing_10(pki, h3):
    async def go():
        async with AsyncSession(http3="force", verify=pki["ca"]) as s:
            rs = await asyncio.gather(*[s.get(url(h3, f"/m{i}")) for i in range(10)])
            assert [json.loads(r.body)["path"] for r in rs] == [f"/m{i}" for i in range(10)]
            assert len(s._h3._conns) == 1
    asyncio.run(go())


def test_sync_multiplexing_request_many(pki, h3):
    with Session(http3="force", verify=pki["ca"]) as s:
        s.get(url(h3))
        conn = next(iter(s._h3._conns.values()))
        res = conn.request_many([("GET", f"/m{i}", [], b"") for i in range(10)], 10)
        assert len(res) == 10 and all(not isinstance(r, Exception) for r in res)


def test_large_body(pki, h3):
    n = 3_000_000
    with Session(http3="force", verify=pki["ca"], timeout=30) as s:
        assert len(s.get(url(h3, f"/big={n}")).body) == n
    async def go():
        async with AsyncSession(http3="force", verify=pki["ca"], timeout=30) as s:
            assert len((await s.get(url(h3, f"/big={n}"))).body) == n
    asyncio.run(go())


def test_large_post_body(pki, h3):
    payload = b"y" * 500_000
    with Session(http3="force", verify=pki["ca"], timeout=30) as s:
        d = json.loads(s.post(url(h3, "/up"), data=payload).body)
        assert len(d["body"]) == 500_000


def test_stream_chunks(pki, h3):
    async def go():
        async with AsyncSession(http3="force", verify=pki["ca"]) as s:
            conn = await s._h3._conn(("localhost", h3.port), ("localhost", h3.port))
            hdrs, it = await conn.stream("GET", "/chunks", [], b"", 5)
            got = [c async for c in it]
            assert b"".join(got) == b"part0;part1;part2;" and len(got) >= 2
    asyncio.run(go())


def test_wrong_ca_rejected(pki, h3):
    with Session(http3="force", verify=pki["other_ca"]) as s:
        with pytest.raises(CertificateValidationError):
            s.get(url(h3))
    async def go():
        async with AsyncSession(http3="force", verify=pki["other_ca"]) as s:
            with pytest.raises(CertificateValidationError):
                await s.get(url(h3))
    asyncio.run(go())


def test_wrong_hostname_rejected(pki):
    srv = H3TestServer(pki["wcrt"], pki["wkey"]).start()
    try:
        with Session(http3="force", verify=pki["ca"]) as s:
            with pytest.raises(CertificateValidationError):
                s.get(url(srv))
    finally:
        srv.stop()


def test_custom_ca_only_default_store_rejects(h3):
    # verify=True (varsayılan depo) yerel CA'yı tanımaz
    with Session(http3="force") as s:
        with pytest.raises(CertificateValidationError):
            s.get(url(h3))


def test_default_aioquic_verify_none_but_fasthttpc_enforces(pki, h3):
    """aioquic CERT_NONE ile açılsa bile (varsayılan yol) fasthttpc doğrulaması zorunlu."""
    from fasthttpc.http3.core import H3Core
    c = H3Core("localhost", h3.port, ca_path=None, impersonate=None, clock=time.monotonic)
    import ssl
    assert c.quic.configuration.verify_mode == ssl.CERT_NONE
    c2 = H3Core("localhost", h3.port, ca_path=pki["ca"], impersonate=None, clock=time.monotonic)
    assert c2.quic.configuration.verify_mode == ssl.CERT_REQUIRED
    assert c.quic.configuration.session_ticket is None      # 0-RTT/resumption yok


def test_force_fails_when_udp_closed(pki):
    s0 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s0.bind(("127.0.0.1", 0))
    port = s0.getsockname()[1]            # dinleyen ama yanıt vermeyen UDP: zaman aşımı
    try:
        opts = Http3Options(mode="force", connect_timeout=0.5)
        with Session(http3=opts, verify=pki["ca"]) as s:
            t = time.monotonic()
            with pytest.raises(ConnectionError):
                s.get(f"https://localhost:{port}/")
            assert time.monotonic() - t < 5
    finally:
        s0.close()


@pytest.fixture
def dual(pki):
    s = H3TestServer(pki["crt"], pki["key"], tcp=True, alt_svc='h3=":{port}"; ma=60').start()
    yield s
    s.stop()


def test_altsvc_discovery_sync(pki, dual):
    with Session(http3=True, verify=pki["ca"], impersonate=None) as s:
        r1 = s.get(url(dual))
        assert r1.http_version == "HTTP/1.1" and r1.headers["x-proto"] == "h1"
        r2 = s.get(url(dual))
        assert r2.http_version == "HTTP/3" and r2.headers["x-proto"] == "h3"
        assert dual.tcp_hits == 1


def test_altsvc_discovery_async(pki, dual):
    async def go():
        async with AsyncSession(http3=True, verify=pki["ca"], impersonate=None) as s:
            assert (await s.get(url(dual))).http_version == "HTTP/1.1"
            assert (await s.get(url(dual))).http_version == "HTTP/3"
    asyncio.run(go())


def test_fallback_to_h2_when_udp_dead(pki):
    # Alt-Svc h3 ilan eden TCP sunucusu, UDP tarafında kimse yok -> sessiz düşüş
    srv = H3TestServer(pki["crt"], pki["key"], tcp=True, alt_svc='h3=":{port}"; ma=60').start()
    srv._loop.call_soon_threadsafe(lambda: None)
    port = srv.port
    # UDP'yi kapatmak için sunucuyu durdur; TCP'yi ayrı ayağa kaldır
    srv.stop()
    import http.server, ssl, threading

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Length", "2")
            self.send_header("Alt-Svc", f'h3=":{port}"; ma=60'); self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *a): pass
    httpd = NoFqdnHTTPServer(("127.0.0.1", port), H)   # macOS: getfqdn gecikmesi yok
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(pki["crt"], pki["key"])
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        opts = Http3Options(connect_timeout=0.4, disable_for=60)
        with Session(http3=opts, verify=pki["ca"], impersonate=None) as s:
            assert s.get(url(srv)).http_version == "HTTP/1.1"      # keşif
            t = time.monotonic()
            r = s.get(url(srv))                                    # h3 dener, düşer
            assert r.status_code == 200 and r.http_version == "HTTP/1.1"
            assert time.monotonic() - t < 4
            t = time.monotonic()
            s.get(url(srv))                                        # devre dışı: gecikme yok
            assert time.monotonic() - t < 0.35
        async def go():
            async with AsyncSession(http3=opts, verify=pki["ca"], impersonate=None) as a:
                await a.get(url(srv))
                r = await a.get(url(srv))
                assert r.status_code == 200 and r.http_version == "HTTP/1.1"
        asyncio.run(go())
    finally:
        httpd.shutdown(); httpd.server_close()


def test_proxy_disables_h3(pki, h3):
    with Session(http3=True, verify=pki["ca"], proxy="http://127.0.0.1:9") as s:
        assert s._h3.state.target_for("localhost", h3.port) is None
    with pytest.raises(ConnectionError):
        with Session(http3="force", verify=pki["ca"], proxy="http://127.0.0.1:9") as s:
            s.get(url(h3))


def test_idle_timeout_reconnect(pki, h3):
    opts = Http3Options(mode="force", idle_timeout=0.3)
    with Session(http3=opts, verify=pki["ca"]) as s:
        s.get(url(h3))
        first = next(iter(s._h3._conns.values()))
        time.sleep(0.5)
        s.get(url(h3))
        assert next(iter(s._h3._conns.values())) is not first


def test_goaway_marks_connection_unusable(pki, h3):
    with Session(http3="force", verify=pki["ca"]) as s:
        s.get(url(h3))
        conn = next(iter(s._h3._conns.values()))
        conn.core.goaway_id = 0       # GOAWAY alınmış gibi
        assert not conn.usable
        assert s.get(url(h3)).http_version == "HTTP/3"      # yeni bağlantı kuruldu
        assert next(iter(s._h3._conns.values())) is not conn


def test_goaway_event_refuses_inflight(pki, h3):
    # aioquic >= 1.8: aioquic'in kendi olayı; < 1.8 (Python 3.10'da en yenisi 1.3): fasthttpc'nin
    # GOAWAY uyumluluk katmanının ürettiği olay (bkz. core._with_goaway_shim).
    from fasthttpc.http3.core import GoAwayReceived, Http3RequestRefused, _Stream
    with Session(http3="force", verify=pki["ca"]) as s:
        s.get(url(h3))
        core = next(iter(s._h3._conns.values())).core
        st = _Stream(100); core.streams[100] = st
        core.h3.handle_event = lambda ev: [GoAwayReceived(stream_id=100)]
        core._h3_events(object())
        assert isinstance(st.error, Http3RequestRefused) and core.goaway_id == 100


def _wait_core(conn, cond, timeout=5.0):
    """Senkron bağlantıyı istek göndermeden sür (sunucunun kendiliğinden gönderdiği çerçeveler)."""
    with conn._lock:
        conn._run(cond, time.monotonic() + timeout, "test bekleme")


def test_server_goaway_frame_marks_connection_unusable(pki, h3):
    """Sunucudan GERÇEK GOAWAY çerçevesi: aioquic 1.3-1.7 bunu sessizce yutuyordu."""
    with Session(http3="force", verify=pki["ca"]) as s:
        r = s.get(url(h3, "/goaway"))           # akış 0; sunucu ardından GOAWAY(4) yollar
        assert r.status_code == 200 and r.http_version == "HTTP/3"
        conn = next(iter(s._h3._conns.values()))
        _wait_core(conn, lambda: conn.core.goaway_id is not None)
        assert conn.core.goaway_id == 4 and not conn.usable
        assert s.get(url(h3)).http_version == "HTTP/3"      # yeni bağlantı kuruldu
        assert next(iter(s._h3._conns.values())) is not conn


def test_server_goaway_refuses_unprocessed_request_and_retries(pki, h3):
    """Sunucu isteği işlemeden GOAWAY(akış) gönderir: istek reddedilir, yeni bağlantıda tekrarlanır."""
    with Session(http3="force", verify=pki["ca"]) as s:
        s.get(url(h3))                                     # akış 0
        first = next(iter(s._h3._conns.values()))
        r = s.get(url(h3, f"/refuse-once-sync-{id(s)}"))   # akış 4 -> GOAWAY(4), yanıt yok
        assert r.status_code == 200 and r.http_version == "HTTP/3"
        assert first.core.goaway_id == 4
        assert next(iter(s._h3._conns.values())) is not first


def test_server_goaway_refusal_async(pki, h3):
    async def go():
        async with AsyncSession(http3="force", verify=pki["ca"]) as s:
            await s.get(url(h3))
            first = next(iter(s._h3._conns.values()))
            r = await s.get(url(h3, f"/refuse-once-async-{id(s)}"))
            assert r.status_code == 200 and r.http_version == "HTTP/3"
            assert first.core.goaway_id == 4
            assert next(iter(s._h3._conns.values())) is not first
    asyncio.run(go())


@pytest.mark.parametrize("goaway_id", [2, 3])   # sunucu tek yönlü / sunucu kaynaklı akış: H3_ID_ERROR
def test_server_goaway_with_invalid_id_closes_connection(pki, h3, goaway_id):
    from fasthttpc.http3.core import Http3Error
    with Session(http3="force", verify=pki["ca"]) as s:
        with pytest.raises(Http3Error, match="kod=0x108"):     # H3_ID_ERROR ile kapatıldı
            s.get(url(h3, f"/goaway={goaway_id}"))
        conn = next(iter(s._h3._conns.values()))
        assert conn.core.closed and conn.core.goaway_id is None and not conn.usable
        assert s.get(url(h3)).http_version == "HTTP/3"      # yeni bağlantı kuruldu


def _wait_for(cond, timeout=5.0):
    """Başka bir iş parçacığının sürdüğü bağlantıyı (kilidine dokunmadan) gözle."""
    deadline = time.monotonic() + timeout
    while not cond():
        assert time.monotonic() < deadline, "koşul gerçekleşmedi (zaman aşımı)"
        time.sleep(0.01)


def test_server_goaway_id_must_not_increase(pki, h3):
    """RFC 9114 §5.2: sonraki GOAWAY kimliği ARTIRAMAZ (8 -> 12: H3_ID_ERROR). İki GOAWAY de aynı
    bağlantıda, istek hâlâ sürerken gelir: istemci ilk GOAWAY'den sonra yeni istek BAŞLATMAZ (aioquic
    >= 1.9 buna zaten izin vermez; tüm desteklenen sürümlerde aynı senaryo)."""
    from concurrent.futures import ThreadPoolExecutor
    from fasthttpc.http3.core import Http3Error
    path = "/goaway-hold=8"
    with Session(http3="force", verify=pki["ca"]) as s, ThreadPoolExecutor(1) as ex:
        fut = ex.submit(s.get, url(h3, path), timeout=10)  # akış 0: GOAWAY(8), yanıt bekletilir
        conns = s._h3._conns
        _wait_for(lambda: any(c.core is not None and c.core.goaway_id is not None
                              for c in list(conns.values())))
        conn = next(iter(conns.values()))
        assert conn.core.goaway_id == 8 and not conn.core.closed
        assert not fut.done()                   # akış 0 < 8: istek reddedilmedi, sürüyor
        h3.send_goaway(path, 12)                # aynı bağlantıda ikinci GOAWAY
        with pytest.raises(Http3Error, match="kod=0x108"):     # 8 -> 12: artış, H3_ID_ERROR
            fut.result(10)
        assert conn.core.closed and next(iter(s._h3._conns.values())) is conn


def test_unrecorded_goaway_request_is_retried_not_leaked(pki, h3):
    """aioquic >= 1.9 GOAWAY aldıktan sonra yeni istek başlatmayı reddeder (InvalidConnectionStateError).
    fasthttpc o GOAWAY'i henüz işlememişse (yarış) istek HİÇ gönderilmemiştir: Http3RequestRefused olur,
    yeni bağlantıda tekrarlanır; aioquic'in istisnası kullanıcıya sızmaz (CI'daki hata izi)."""
    from aioquic.h3 import exceptions as h3exc
    with Session(http3="force", verify=pki["ca"]) as s:
        s.get(url(h3, "/goaway=8"))             # akış 0, ardından GOAWAY(8)
        conn = next(iter(s._h3._conns.values()))
        _wait_core(conn, lambda: conn.core.goaway_id is not None)
        conn.core.goaway_id = None              # yarış: aioquic GOAWAY'i gördü, fasthttpc görmedi
        r = s.get(url(h3, "/sonra"))
        assert r.status_code == 200 and r.http_version == "HTTP/3"
        assert json.loads(r.body)["path"] == "/sonra"
        if hasattr(h3exc, "InvalidConnectionStateError"):     # aioquic >= 1.9: reddetti -> yeni bağlantı
            assert conn.core.draining and not conn.usable
            assert next(iter(s._h3._conns.values())) is not conn
        else:                                   # < 1.9: akış 4 < 8, aynı bağlantıda işlendi
            assert next(iter(s._h3._conns.values())) is conn


def _refuse_start(core):
    """aioquic >= 1.9'un send_headers reddini (her sürümde) taklit et."""
    from fasthttpc.http3.core import InvalidConnectionStateError

    def send_headers(*a, **kw):
        raise InvalidConnectionStateError("Cannot start a request after receiving GOAWAY")
    core.h3.send_headers = send_headers


def test_invalid_connection_state_becomes_request_refused(pki, h3):
    from fasthttpc.http3.core import Http3RequestRefused
    with Session(http3="force", verify=pki["ca"]) as s:
        s.get(url(h3))
        conn = next(iter(s._h3._conns.values()))
        _refuse_start(conn.core)
        with pytest.raises(Http3RequestRefused, match="aioquic"):
            conn.core.send_request("GET", "localhost", "/", [], b"")
        assert conn.core.draining and not conn.usable and not conn.core.streams
        r = s.get(url(h3, "/yeni"))                       # yeni bağlantıda tekrarlandı
        assert r.status_code == 200 and r.http_version == "HTTP/3"
        assert next(iter(s._h3._conns.values())) is not conn

    async def go():
        async with AsyncSession(http3="force", verify=pki["ca"]) as a:
            await a.get(url(h3))
            first = next(iter(a._h3._conns.values()))
            _refuse_start(first.core)
            r = await a.get(url(h3, "/yeni"))
            assert r.status_code == 200 and r.http_version == "HTTP/3"
            assert first.core.draining and next(iter(a._h3._conns.values())) is not first
    asyncio.run(go())



# --- H3_REQUEST_REJECTED (0x10B): işlenmedi -> yeni bağlantıda yeniden dene (RFC 9114 §4.1.1) ---------

def test_request_rejected_is_retried_on_new_connection_sync(pki, h3):
    path = f"/reject-once-sync-{id(pki)}"
    with Session(http3="force", verify=pki["ca"]) as s:
        s.get(url(h3))
        first = next(iter(s._h3._conns.values()))
        r = s.post(url(h3, path), data=b"govde")             # bytes gövde: aynen yeniden gönderilir
        assert r.status_code == 200 and r.http_version == "HTTP/3"
        assert json.loads(r.body)["body"] == "govde"
        assert HITS[path] == 2                                # bir red + bir yeniden deneme
        assert first.core.draining and next(iter(s._h3._conns.values())) is not first


def test_request_rejected_is_retried_async_without_killing_siblings(pki, h3):
    """Reddedilen isteğin yeniden denemesi, eski bağlantıda SÜREN istekleri kesmez."""
    path = f"/reject-once-async-{id(pki)}"

    async def go():
        async with AsyncSession(http3="force", verify=pki["ca"]) as s:
            await s.get(url(h3))
            first = next(iter(s._h3._conns.values()))
            slow, rejected = await asyncio.gather(s.get(url(h3, "/chunks")), s.get(url(h3, path)))
            assert slow.body == b"part0;part1;part2;" and slow.http_version == "HTTP/3"
            assert rejected.status_code == 200 and rejected.http_version == "HTTP/3"
            assert HITS[path] == 2 and first.core.draining
            assert next(iter(s._h3._conns.values())) is not first
            assert first.finished                         # son akış bitince kendini kapattı
    asyncio.run(go())


def test_request_rejected_repeatedly_fails_after_bound(pki, h3):
    from fasthttpc.http3.core import Http3RequestRefused
    from fasthttpc.http3.manager import MAX_REFUSED_RETRIES
    attempts = MAX_REFUSED_RETRIES + 1
    path = f"/reject-always-sync-{id(pki)}"
    with Session(http3="force", verify=pki["ca"]) as s:
        with pytest.raises(Http3RequestRefused, match=f"{attempts} denemede de .*H3_REQUEST_REJECTED"):
            s.get(url(h3, path))
    assert HITS[path] == attempts                        # sınırlı: sonsuz döngü yok

    apath = f"/reject-always-async-{id(pki)}"

    async def go():
        async with AsyncSession(http3="force", verify=pki["ca"]) as a:
            with pytest.raises(Http3RequestRefused, match=f"{attempts} denemede de .*H3_REQUEST_REJECTED"):
                await a.get(url(h3, apath))
    asyncio.run(go())
    assert HITS[apath] == attempts


@pytest.mark.parametrize("kind", ["cancel", "reject-after-headers"])
def test_cancelled_or_processed_request_is_not_retried(pki, h3, kind):
    """H3_REQUEST_CANCELLED (0x10C) işlenmemişliği garanti ETMEZ; yanıt başlığından sonra gelen
    REJECTED da işlenmiş isteğe aittir: ikisi de yeniden denenmez (RFC 9114 §4.1.1)."""
    from fasthttpc.http3.core import Http3Error, Http3RequestRefused
    code = "0x10c" if kind == "cancel" else "0x10b"
    for mode in ("sync", "async"):
        path = f"/{kind}-{mode}-{id(pki)}"
        if mode == "sync":
            with Session(http3="force", verify=pki["ca"]) as s:
                with pytest.raises(Http3Error, match=f"sıfırlandı: {code}") as ei:
                    s.get(url(h3, path))
        else:
            async def go():
                async with AsyncSession(http3="force", verify=pki["ca"]) as a:
                    await a.get(url(h3, path))
            with pytest.raises(Http3Error, match=f"sıfırlandı: {code}") as ei:
                asyncio.run(go())
        assert not isinstance(ei.value, Http3RequestRefused)
        assert HITS[path] == 1                             # yeniden denenmedi


def test_streaming_body_is_not_replayed():
    """Yeniden deneme varsayımı açık: yalnızca tamponlanmış bytes gövdeler aynen yeniden gönderilir."""
    from fasthttpc.http3.manager import _replayable
    assert _replayable(b"") and _replayable(b"x") and _replayable(bytearray(b"x"))
    assert not _replayable(iter([b"x"])) and not _replayable(None)


def test_alt_svc_parse():
    assert parse_alt_svc("clear") is None
    a = parse_alt_svc('h3=":443"; ma=3600, h3-29=":443"; ma=10, h2=":443"')
    assert len(a) == 1 and a[0].port == 443 and a[0].max_age == 3600 and a[0].host == ""
    b = parse_alt_svc('h3="alt.example.com:8443"')
    assert b[0].host == "alt.example.com" and b[0].port == 8443 and b[0].max_age == 86400
    assert parse_alt_svc('h3=":443"; ma=0') == []
    assert parse_alt_svc("garbage") == []


def test_alt_svc_cache_expiry_and_clear():
    from fasthttpc.http3 import AltSvcCache
    now = [0.0]
    c = AltSvcCache(clock=lambda: now[0])
    c.update(("h", 443), ['h3=":443"; ma=10'])
    assert c.get(("h", 443)) is not None
    now[0] = 11
    assert c.get(("h", 443)) is None
    c.update(("h", 443), ['h3=":443"; ma=10']); c.update(("h", 443), ["clear"])
    assert c.get(("h", 443)) is None


def test_chrome_profile_applied(pki, h3):
    from fasthttpc.http3 import fingerprint as fp
    with Session(http3="force", verify=pki["ca"], impersonate="chrome_131") as s:
        s.get(url(h3))
        core = next(iter(s._h3._conns.values())).core
        p = fp.CHROME
        q = core.quic
        assert q._local_max_data.value == p.max_data
        assert q._local_max_stream_data_bidi_local == p.max_stream_data
        assert q._local_max_streams_bidi.value == 100 and q._local_active_connection_id_limit == 4
        sent = core.h3.sent_settings
        assert list(sent)[:3] == [1, 6, 7] and sent[1] == 65536 and sent[6] == 262144
        assert len(sent) == 4                                   # + GREASE ayarı


def test_options_validation():
    assert Http3Options.from_value(False) is None
    assert Http3Options.from_value("force").mode == "force"
    with pytest.raises(ValueError):
        Http3Options.from_value("yes")
    # aioquic >= 1.9 1 ms altını/sonsuzu QuicConnection kurarken reddeder: her sürümde erken ValueError
    assert Http3Options.from_value(Http3Options(idle_timeout=0.001)).idle_timeout == 0.001
    for bad in (0, 0.0005, -1.0, float("inf"), float("nan")):
        with pytest.raises(ValueError, match="idle_timeout"):
            Http3Options.from_value(Http3Options(idle_timeout=bad))
    with pytest.raises(ValueError, match="idle_timeout"):
        Session(http3=Http3Options(mode="force", idle_timeout=0.0005))


def test_core_imports_without_aioquic():
    import subprocess, sys
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    code = (f"import sys; sys.path.insert(0, {root!r}); sys.modules['aioquic']=None; import fasthttpc; from fasthttpc import Session; "
            "Session(); import fasthttpc.http3 as h; assert not h.available();\n"
            "try:\n Session(http3=True)\nexcept ImportError as e: print('OK', e)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert "OK" in out.stdout, out.stderr


# --- Çok adresli çözümleme (localhost -> ::1 kapalı, 127.0.0.1 açık) regresyonu ---------------

def _free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _patch_addrs(monkeypatch, first, port):
    """getaddrinfo: önce ``first`` (dinleyen yok / sessiz), sonra 127.0.0.1:port (sunucu).
    Yalnızca 127.0.0.1 ve FARKLI PORTLAR kullanılır (macOS lo0'da 127.0.0.2/3 yoktur)."""
    real = socket.getaddrinfo
    udp = socket.SOCK_DGRAM

    def fake(host, p, *a, **kw):
        if host == "localhost":
            out = [(f, udp, 17, "", ad) for f, ad in first]
            out.append((socket.AF_INET, udp, 17, "", ("127.0.0.1", port)))
            return out
        return real(host, p, *a, **kw)
    monkeypatch.setattr(socket, "getaddrinfo", fake)


@pytest.mark.parametrize("kind", ["ipv6_dead", "icmp_refused", "silent"])
def test_multi_address_fallthrough(pki, h3, monkeypatch, kind):
    silent = None
    if kind == "ipv6_dead":      # ::1'de dinleyen yok (ya da IPv6 hiç yok)
        first = [(socket.AF_INET6, ("::1", h3.port, 0, 0))]
    elif kind == "icmp_refused":
        first = [(socket.AF_INET, ("127.0.0.1", _free_udp_port()))]   # kapalı port -> ICMP reddi
    else:
        silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        silent.bind(("127.0.0.1", 0))            # dinler ama yanıt vermez
        first = [(socket.AF_INET, ("127.0.0.1", silent.getsockname()[1]))]
    _patch_addrs(monkeypatch, first, h3.port)
    opts = Http3Options(mode="force", connect_timeout=4.0)
    try:
        t = time.monotonic()
        with Session(http3=opts, verify=pki["ca"]) as s:
            assert s.get(url(h3)).http_version == "HTTP/3"
        sync_t = time.monotonic() - t
        assert sync_t < 4.5

        async def go():
            async with AsyncSession(http3=opts, verify=pki["ca"]) as a:
                assert (await a.get(url(h3))).http_version == "HTTP/3"
        asyncio.run(go())
    finally:
        if silent:
            silent.close()


# --- Adres başına süre bütçesi (belirlenimli: sahte saat, ağ yok) ---------------------------

def test_address_probe_window_sinirli_ve_son_adres_sinirsiz():
    from fasthttpc.http3.core import ADDRESS_PROBE_TIMEOUT, address_probe_window
    assert address_probe_window(4.0, 2) == ADDRESS_PROBE_TIMEOUT == 1.0
    assert address_probe_window(1.0, 2) == 0.5            # kısa toplam sürede eşit pay
    assert address_probe_window(0.3, 3) == pytest.approx(0.1)
    assert address_probe_window(4.0, 1) is None           # son adres: kalanın tamamı
    assert address_probe_window(-1.0, 2) == 0.0


class _FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _two_addrs(monkeypatch, mod):
    infos = [(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("127.0.0.1", 1)),
             (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("127.0.0.1", 2))]
    monkeypatch.setattr(mod.socket, "getaddrinfo", lambda *a, **k: infos)
    return infos


@pytest.mark.parametrize("ilk", ["sessiz", "icmp_red"])
def test_sync_cok_adres_butcesi_son_adres_kalani_alir(monkeypatch, ilk):
    """Windows CI regresyonu: ilk adres sessizken (ya da ICMP reddi bildirilmeyip yanıt
    gelmezken) payının tamamını değil en fazla ADDRESS_PROBE_TIMEOUT'u harcar; hızlı
    reddedilirse kullanılmayan süre sonraki adrese kalır. Son adres kalanın tamamını alır."""
    from fasthttpc.http3 import sync_client
    from fasthttpc.http3.core import Http3ConnectError
    clock = _FakeClock()
    monkeypatch.setattr(sync_client.time, "monotonic", clock)
    _two_addrs(monkeypatch, sync_client)
    calls = []

    def fake_attempt(self, family, addr, deadline, probe):
        calls.append((addr[1], round(deadline - clock.t, 6), probe))
        if addr[1] == 1:
            clock.t += probe if ilk == "sessiz" else 0.01      # sessiz: pencere sonuna kadar
            raise Http3ConnectError("yanıt yok")

    monkeypatch.setattr(sync_client.SyncH3Connection, "_attempt", fake_attempt)
    c = sync_client.SyncH3Connection("localhost", 443, "localhost", 443, ca_path=None,
                                     impersonate=None, opts=Http3Options(connect_timeout=4.0))
    c.connect()
    assert calls[0] == (1, 4.0, 1.0)
    assert calls[1] == (2, 3.0 if ilk == "sessiz" else 3.99, None)


def test_async_cok_adres_butcesi_son_adres_kalani_alir(monkeypatch):
    from fasthttpc.http3 import async_client
    from fasthttpc.http3.core import Http3ConnectError
    clock = _FakeClock()
    monkeypatch.setattr(async_client.time, "monotonic", clock)
    infos = [(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("127.0.0.1", 1)),
             (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("127.0.0.1", 2))]
    calls = []

    async def fake_attempt(self, family, addr, deadline, probe):
        calls.append((addr[1], round(deadline - clock.t, 6), probe))
        if addr[1] == 1:
            clock.t += probe
            raise Http3ConnectError("yanıt yok")

    monkeypatch.setattr(async_client.AsyncH3Connection, "_attempt", fake_attempt)

    async def go():
        async def fake_gai(*a, **k):
            return infos
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", fake_gai)
        c = async_client.AsyncH3Connection("localhost", 443, "localhost", 443, ca_path=None,
                                           impersonate=None, opts=Http3Options(connect_timeout=4.0))
        await c.connect()
    asyncio.run(go())
    assert calls == [(1, 4.0, 1.0), (2, 3.0, None)]


def test_yanitsiz_adres_yoklama_penceresinde_birakilir(monkeypatch):
    """Gerçek soket: yanıt vermeyen adreste el sıkışması toplam süreyi değil yalnızca
    yoklama penceresini bekler (sync ve async)."""
    from fasthttpc.http3.async_client import AsyncH3Connection
    from fasthttpc.http3.core import Http3ConnectError
    from fasthttpc.http3.sync_client import SyncH3Connection
    silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    silent.bind(("127.0.0.1", 0))
    addr = silent.getsockname()
    kw = dict(ca_path=None, impersonate=None, opts=Http3Options(connect_timeout=30.0))
    try:
        c = SyncH3Connection("localhost", addr[1], "127.0.0.1", addr[1], **kw)
        t = time.monotonic()
        with pytest.raises(Http3ConnectError, match="yanıt yok"):
            c._attempt(socket.AF_INET, addr, time.monotonic() + 30.0, 0.3)
        assert time.monotonic() - t < 10.0          # 30 sn'lik toplam sürenin çok altında

        async def go():
            a = AsyncH3Connection("localhost", addr[1], "127.0.0.1", addr[1], **kw)
            a.loop = asyncio.get_running_loop()
            t = time.monotonic()
            with pytest.raises(Http3ConnectError, match="yanıt yok"):
                await a._attempt(socket.AF_INET, addr, time.monotonic() + 30.0, 0.3)
            assert time.monotonic() - t < 10.0
        asyncio.run(go())
    finally:
        silent.close()


# --- Kayıp ve ICMP dayanıklılığı (Windows CI'daki el sıkışma zaman aşımları) --------------------

def test_ilk_initial_kaybolursa_pto_ile_el_sikisilir(pki, h3, monkeypatch):
    """İstemcinin ilk Initial datagram'ı kaybolursa sürücü aioquic'in PTO zamanlayıcısıyla
    yeniden gönderir; el sıkışması varsayılan connect_timeout'tan (3 sn) çok önce biter
    (PTO ~0,2 sn). Sync ve async sürücü."""
    from fasthttpc.http3 import async_client, sync_client
    orig_flush = sync_client.SyncH3Connection._flush

    def flush(self):
        if not getattr(self, "_dusuruldu", False):
            dg = self.core.transmit()
            self._dusuruldu = bool(dg)
            for data, _a in dg[1:]:                      # ilk datagram (Initial) kaybolur
                self._sock.send(data)
            return
        orig_flush(self)
    monkeypatch.setattr(sync_client.SyncH3Connection, "_flush", flush)
    t = time.monotonic()
    with Session(http3="force", verify=pki["ca"]) as s:
        assert s.get(url(h3)).http_version == "HTTP/3"
    assert time.monotonic() - t < 2.0

    orig_after = async_client.AsyncH3Connection._after_event

    def after(self):
        if not getattr(self, "_dusuruldu", False) and self._transport is not None:
            dg = self.core.transmit()
            self._dusuruldu = bool(dg)
            for data, _a in dg[1:]:
                self._transport.sendto(data)
        orig_after(self)
    monkeypatch.setattr(async_client.AsyncH3Connection, "_after_event", after)

    async def go():
        t = time.monotonic()
        async with AsyncSession(http3="force", verify=pki["ca"]) as a:
            assert (await a.get(url(h3))).http_version == "HTTP/3"
        assert time.monotonic() - t < 2.0
    asyncio.run(go())


def test_sunucu_icmp_hatasindan_sonra_almaya_devam_eder(pki, h3):
    """Sunucu kapalı bir porta datagram gönderir (Windows'ta sonraki alım ICMP kaynaklı hata
    verir). Paylaşılan test sunucusu yine de yeni bağlantıları kabul etmeli: Proactor
    datagram taşıması bu hatada okumayı bırakıyordu (bkz. h3_servers.H3TestServer._run)."""
    for _ in range(3):
        h3.send_raw(b"\x00" * 32, ("127.0.0.1", _free_udp_port()))
    time.sleep(0.1)
    with Session(http3="force", verify=pki["ca"]) as s:
        assert s.get(url(h3)).http_version == "HTTP/3"


def test_kurulu_baglantida_udp_reddi_baglantiyi_dusurur(pki, h3):
    """El sıkışmadan sonra gelen ICMP reddi (ConnectionRefusedError) bağlantıyı kapatır;
    sonraki istek yeni bağlantı kurar (eski bağlantı sessizce "kullanılabilir" kalmaz)."""
    async def go():
        async with AsyncSession(http3="force", verify=pki["ca"]) as a:
            assert (await a.get(url(h3))).http_version == "HTTP/3"
            first = next(iter(a._h3._conns.values()))
            first._on_udp_error(ConnectionRefusedError(111, "Connection refused"))
            assert first.core.closed and not first.usable
            assert (await a.get(url(h3))).http_version == "HTTP/3"
            assert next(iter(a._h3._conns.values())) is not first
    asyncio.run(go())


def test_async_close_udp_tasimasinin_kapanmasini_bekler(pki, h3):
    """AsyncSession.close() (ve bağlantının close()'u) UDP taşıması GERÇEKTEN kapanmadan
    (protokolün connection_lost'u) dönmez. transport.close() eşzamansızdır; beklenmeden
    dönülürse asyncio.run sonunda taşıma yarım kalır (Windows Proactor: açık UDP soketi,
    _ProactorBasePipeTransport.__del__ ResourceWarning). Retire edilmiş bağlantılar dahil."""
    async def go():
        a = AsyncSession(http3="force", verify=pki["ca"])
        assert (await a.get(url(h3))).http_version == "HTTP/3"
        conn = next(iter(a._h3._conns.values()))
        protos = list(conn._protos)
        assert protos and not any(p.lost.done() for p in protos)
        conn.retire()                         # akış yok: hemen kapanır (eşzamanlı yol)
        a._h3._retired.add(conn)
        a._h3._conns.clear()
        assert (await a.get(url(h3))).http_version == "HTTP/3"
        second = next(iter(a._h3._conns.values()))
        await a.close()
        for c in (conn, second):
            assert c._protos and all(p.lost.done() for p in c._protos), "close() connection_lost'tan önce döndü"
            assert c.finished
    asyncio.run(go())


def test_multi_address_all_dead_fails_within_timeout(pki, monkeypatch):
    s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s1.bind(("127.0.0.1", 0))
    port = s1.getsockname()[1]            # sessiz adres; ikinci adres: kapalı port
    _patch_addrs(monkeypatch, [(socket.AF_INET, ("127.0.0.1", port))], _free_udp_port())
    try:
        opts = Http3Options(mode="force", connect_timeout=1.0)
        t = time.monotonic()
        with Session(http3=opts, verify=pki["ca"]) as s:
            with pytest.raises(ConnectionError):
                s.get(f"https://localhost:{port}/")
        assert time.monotonic() - t < 2.5
    finally:
        s1.close()


@pytest.mark.parametrize("exc", [ConnectionRefusedError, ConnectionResetError])
def test_sync_udp_icmp_reddi_http3error_olur(exc):
    """Linux ECONNREFUSED / Windows WSAECONNRESET (10054) aynı: Http3Error (-> sonraki adres)."""
    from fasthttpc.http3.core import Http3Error
    from fasthttpc.http3.sync_client import SyncH3Connection
    a, b = socket.socketpair()
    b.send(b"x")                                   # select: okunabilir

    class Sock:
        def fileno(self): return a.fileno()
        def send(self, d): pass
        def recv(self, n): raise exc()

    class Core:
        def transmit(self): return []
        def timer(self): return None
        def handle_timer(self): pass

    c = object.__new__(SyncH3Connection)
    c._sock, c.core, c._target = Sock(), Core(), ("::1", 1)
    try:
        with pytest.raises(Http3Error, match="reddedildi"):
            c._run(lambda: False, time.monotonic() + 5, "el sıkışma")
    finally:
        a.close(); b.close()


# ------------------------------------------------ trio: aioquic yalnızca asyncio ile çalışır
def test_trio_force_acik_hata_verir(pki, h3):
    """trio altında http3='force' -> RuntimeError('no running event loop') DEĞİL, Http3ConnectError."""
    trio = pytest.importorskip("trio")
    pytest.importorskip("anyio")
    from fasthttpc.http3.core import Http3ConnectError

    async def go():
        async with AsyncSession(http3="force", verify=pki["ca"]) as s:
            with pytest.raises(Http3ConnectError, match="trio"):
                await s.get(url(h3))
    trio.run(go)


def test_trio_auto_altsvc_h1e_duser(pki, dual):
    """trio altında http3=True: Alt-Svc h3 ilan edilse de istekler TCP'de (h1/h2) başarılı."""
    trio = pytest.importorskip("trio")
    pytest.importorskip("anyio")

    async def go():
        async with AsyncSession(http3=True, verify=pki["ca"], impersonate=None) as s:
            for _ in range(3):
                r = await s.get(url(dual))
                assert r.status_code == 200 and r.http_version == "HTTP/1.1"
                assert r.headers["x-proto"] == "h1"
    trio.run(go)
    assert dual.tcp_hits == 3


def test_http3_akis_govdesi_bellege_alinip_gonderilir(pki, h3):
    """HTTP/3'te akış gövdesi (dosya/üreteç) belleğe alınıp eksiksiz gönderilir (boş DEĞİL)."""
    import io

    def gen():
        yield b""
        yield b"uretec-"
        yield "ç".encode()

    with Session(http3="force", verify=pki["ca"]) as s:
        r1 = s.post(url(h3, "/f"), data=io.BytesIO(b"dosya-icerigi"))
        r2 = s.post(url(h3, "/g"), data=gen())
    assert r1.http_version == r2.http_version == "HTTP/3"
    assert json.loads(r1.body)["body"] == "dosya-icerigi"
    assert json.loads(r2.body)["body"] == "uretec-ç".encode().decode("latin-1")

    async def agen():
        yield b"async-"
        yield b"uretec"

    async def go():
        async with AsyncSession(http3="force", verify=pki["ca"]) as s:
            r = await s.post(url(h3, "/a"), data=agen())
            assert r.http_version == "HTTP/3"
            assert json.loads(r.body)["body"] == "async-uretec"
    asyncio.run(go())


# --- FHC-07: açılmış gövde sınırı HTTP/3'te de (docs/security-audit.md) -----------------
_LIMIT = 100 * 1024


@pytest.mark.parametrize("enc", ["gzip", "br"])
def test_h3_sikistirma_bombasi_sinirlanir_sync(pki, h3, enc):
    from fasthttpc import DecompressedSizeError, Limits
    lim = Limits(max_decompressed_size=_LIMIT)
    with Session(http3="force", verify=pki["ca"], limits=lim) as s:
        with pytest.raises(DecompressedSizeError) as ei:
            s.get(url(h3, f"/bomb?enc={enc}&n={1024 * 1024}"))
        assert (ei.value.limit, ei.value.encoding) == (_LIMIT, enc)
        r = s.get(url(h3, f"/bomb?enc={enc}&n={_LIMIT}"))       # tam sınırda: geçer
        assert r.http_version == "HTTP/3" and r.content == bytes(_LIMIT)
    with Session(http3="force", verify=pki["ca"], limits=Limits(max_decompressed_size=None)) as s:
        assert s.get(url(h3, f"/bomb?enc={enc}&n={1024 * 1024}")).content == bytes(1024 * 1024)


@pytest.mark.parametrize("enc", ["gzip", "br"])
def test_h3_sikistirma_bombasi_sinirlanir_async(pki, h3, enc):
    from fasthttpc import DecompressedSizeError, Limits

    async def go():
        lim = Limits(max_decompressed_size=_LIMIT)
        async with AsyncSession(http3="force", verify=pki["ca"], limits=lim) as s:
            with pytest.raises(DecompressedSizeError):
                await s.get(url(h3, f"/bomb?enc={enc}&n={1024 * 1024}"))
            r = await s.get(url(h3, f"/bomb?enc={enc}&n={_LIMIT}"))
            # gövde bir kez açılır (eskiden async h3 yolu iki kez açmaya çalışıyordu)
            assert r.http_version == "HTTP/3" and r.content == bytes(_LIMIT)
    asyncio.run(go())


def test_request_rejected_akis_govdesi_ayni_baytlarla_yeniden(pki, h3):
    """data= üreteci HTTP/3'ten önce belleğe alınır: REJECTED sonrası yeniden deneme AYNI
    baytları gönderir; tamponlanmamış (akış) gövde HTTP/3 katmanında yeniden denenmez."""
    from fasthttpc._body import StreamingBody
    from fasthttpc.http3.manager import _replayable

    def gen():
        yield b"bir-"
        yield b""
        yield b"iki"

    path = f"/reject-once-stream-sync-{id(pki)}"
    with Session(http3="force", verify=pki["ca"]) as s:
        r = s.post(url(h3, path), data=gen())
    assert r.status_code == 200 and r.http_version == "HTTP/3"
    assert json.loads(r.body)["body"] == "bir-iki" and HITS[path] == 2

    async def agen():
        yield b"async-"
        yield b"govde"

    apath = f"/reject-once-stream-async-{id(pki)}"

    async def go():
        async with AsyncSession(http3="force", verify=pki["ca"]) as s:
            return await s.post(url(h3, apath), data=agen())
    r = asyncio.run(go())
    assert json.loads(r.body)["body"] == "async-govde" and HITS[apath] == 2
    assert not _replayable(StreamingBody.from_iterable(gen()))
