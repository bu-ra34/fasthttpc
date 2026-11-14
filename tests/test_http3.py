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

from h3_servers import H3TestServer, make_ca, make_leaf  # noqa: E402


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
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
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
    from fasthttpc.http3.core import Http3RequestRefused, _Stream
    GoAwayReceived = pytest.importorskip("aioquic.h3.events").__dict__.get("GoAwayReceived")
    if GoAwayReceived is None:
        pytest.skip("bu aioquic sürümü GoAwayReceived olayı sunmuyor")
    with Session(http3="force", verify=pki["ca"]) as s:
        s.get(url(h3))
        core = next(iter(s._h3._conns.values())).core
        st = _Stream(100); core.streams[100] = st
        core.h3.handle_event = lambda ev: [GoAwayReceived(stream_id=100)]
        core._h3_events(object())
        assert isinstance(st.error, Http3RequestRefused) and core.goaway_id == 100


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

def _patch_addrs(monkeypatch, first, port):
    """getaddrinfo: önce ``first`` (dinleyen yok / sessiz), sonra 127.0.0.1 (sunucu)."""
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
        first = [(socket.AF_INET, ("127.0.0.3", h3.port))]
    else:
        silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        silent.bind(("127.0.0.2", h3.port))      # dinler ama yanıt vermez
        first = [(socket.AF_INET, ("127.0.0.2", h3.port))]
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


def test_multi_address_all_dead_fails_within_timeout(pki, monkeypatch):
    s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s1.bind(("127.0.0.2", 0))
    port = s1.getsockname()[1]
    _patch_addrs(monkeypatch, [(socket.AF_INET, ("127.0.0.2", port))], port + 1)
    try:
        opts = Http3Options(mode="force", connect_timeout=1.0)
        t = time.monotonic()
        with Session(http3=opts, verify=pki["ca"]) as s:
            with pytest.raises(ConnectionError):
                s.get(f"https://localhost:{port}/")
        assert time.monotonic() - t < 2.5
    finally:
        s1.close()
