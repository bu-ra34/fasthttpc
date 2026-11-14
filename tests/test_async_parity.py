"""AsyncSession: proxy (HTTP CONNECT / SOCKS5), Timeout/Limits ve HTTP/1.1 gövde
çerçevelemesi testleri (ağsız; yerel asyncio sunucular)."""
import asyncio
import socket
import time

import pytest

from fasthttpc import AsyncSession, Limits, Timeout
from fasthttpc.transport import proxy as P
from fasthttpc.transport.proxy import ProxyConfig, ProxyError

from async_fakes import AsyncFakeProxy, start_stdlib_tls, start_tls13
from tls13_fakeserver import PKI, http_responder

HOST = "example.com"


@pytest.fixture(scope="module")
def pki():
    return PKI(HOST)


@pytest.fixture(scope="module")
def pki_local():
    return PKI("localhost")


@pytest.fixture
def ca(pki, tmp_path):
    p = tmp_path / "ca.pem"
    p.write_bytes(pki.ca_pem())
    return str(p)


@pytest.fixture
def ca_local(pki_local, tmp_path):
    p = tmp_path / "ca_local.pem"
    p.write_bytes(pki_local.ca_pem())
    return str(p)


def run(coro, timeout=20):
    return asyncio.run(asyncio.wait_for(coro, timeout))


# ------------------------------------------------ proxy: bayt üretimi eşitliği
def test_saf_fonksiyonlar_senkronla_ayni_baytlari_uretir():
    class Rec:
        def __init__(self, replies=b""):
            self.sent, self.replies = b"", bytearray(replies)

        def sendall(self, d):
            self.sent += d

        def recv(self, n):
            out = bytes(self.replies[:n])
            del self.replies[:n]
            return out

    for host in ("example.com", "1.2.3.4", "::1"):
        for cfg in (ProxyConfig("http", "p", 1), ProxyConfig("http", "p", 1, "u", "p:ß")):
            s = Rec(b"HTTP/1.1 200 OK\r\n\r\n")
            P.http_connect(s, cfg, host, 443)
            assert s.sent == P.build_connect_request(cfg, host, 443)
        cfg = ProxyConfig("socks5", "p", 1, "u", "pw")
        s = Rec(b"\x05\x02\x01\x00\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        P.socks5_connect(s, cfg, host, 443)
        assert s.sent == (P.socks5_greeting(cfg) + P.socks5_auth_request(cfg)
                          + P.socks5_connect_request(host, 443))
    assert P.socks5_connect_request("example.com", 443)[3] == 3          # ATYP=DOMAIN (DNS proxy'de)
    with pytest.raises(ProxyError, match="407"):
        P.check_connect_response(b"HTTP/1.1 407 X\r\n\r\n")
    with pytest.raises(ProxyError, match="reddedildi"):
        P.check_connect_response(b"HTTP/1.1 403 Forbidden\r\n\r\n")
    with pytest.raises(ProxyError, match="Geçersiz"):
        P.check_connect_response(b"garbage\r\n\r\n")


# ------------------------------------------------------ proxy: uçtan uca
async def _via(kind, pki, ca, *, auth=None, impersonate="chrome_131", tmp_path=None,
               use_dict=False, reply=None, sess_auth=None):
    if impersonate is None:
        srv, port, _ = await start_stdlib_tls(pki, tmp_path)
    else:
        srv, port, _ = await start_tls13(pki, http_responder(b"tunel icinde"))
    proxy = await AsyncFakeProxy(kind, upstream_port=port, auth=auth, reply=reply).start()
    try:
        url = proxy.url
        if sess_auth is not None:
            url = f"{'http' if kind == 'http' else 'socks5'}://{sess_auth}@127.0.0.1:{proxy.port}"
        kw = {"proxies": {"https": url}} if use_dict else {"proxy": url}
        s = AsyncSession(impersonate=impersonate, verify=ca, timeout=5, **kw)
        try:
            r = await s.get("https://example.com/yol")
        finally:
            await s.close()
        return r, proxy
    finally:
        await proxy.stop()
        srv.close()


@pytest.mark.parametrize("kind", ["http", "socks5"])
@pytest.mark.parametrize("impersonate", ["chrome_131", None])
def test_proxy_tuneli_hem_impersonate_hem_stdlib(kind, impersonate, pki, ca, tmp_path):
    r, proxy = run(_via(kind, pki, ca, impersonate=impersonate, tmp_path=tmp_path))
    assert r.status_code == 200
    assert r.body == (b"tunel icinde" if impersonate else b"stdlib tamam")
    if kind == "http":
        assert proxy.targets == ["example.com:443"]
        assert b"Proxy-Authorization" not in proxy.heads[0]
    else:
        assert proxy.targets == [(3, "example.com", 443)]     # hedef adı proxy'de çözülür


@pytest.mark.parametrize("kind", ["http", "socks5"])
def test_proxy_kimlik_dogrulama_ve_proxies_sozlugu(kind, pki, ca):
    r, proxy = run(_via(kind, pki, ca, auth="kul:p%ss", use_dict=True,
                        sess_auth="kul:p%25ss"))
    assert r.status_code == 200
    if kind == "http":
        import base64
        assert b"Proxy-Authorization: Basic " + base64.b64encode(b"kul:p%ss") in proxy.heads[0]


@pytest.mark.parametrize("kind", ["http", "socks5"])
def test_proxy_yanlis_kimlik_hata(kind, pki, ca):
    with pytest.raises(ProxyError):
        run(_via(kind, pki, ca, auth="kul:dogru", sess_auth="kul:yanlis"))


def test_proxy_http_reddi_ve_socks_reddi(pki, ca):
    with pytest.raises(ProxyError, match="403"):
        run(_via("http", pki, ca, reply=b"HTTP/1.1 403 Forbidden\r\n\r\n"))
    with pytest.raises(ProxyError, match="reddedildi"):
        run(_via("socks5", pki, ca, reply=5))


def test_proxy_ulasilamaz_proxyerror(ca):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    async def main():
        a = AsyncSession(verify=ca, timeout=2, proxy=f"http://127.0.0.1:{port}")
        with pytest.raises(ProxyError, match="bağlanılamadı"):
            await a.get("https://example.com/")
    run(main())


def test_proxy_parametre_dogrulamasi(ca):
    with pytest.raises(ValueError, match="birlikte"):
        AsyncSession(verify=ca, proxy="http://a:1", proxies={"https": "http://b:1"})
    with pytest.raises(ValueError, match="https:// proxy"):
        AsyncSession(verify=ca, proxy="https://a:1")
    with pytest.raises(ValueError):
        AsyncSession(verify=ca, proxies={"https": "ftp://a"})
    assert AsyncSession(verify=ca, proxies={"http": "http://a:1"})        # https için yok -> doğrudan


def test_proxies_sozlugu_all_anahtari_ve_rotator_gercekten_kullanilir(pki, ca):
    async def main():
        srv, port, _ = await start_tls13(pki, http_responder(b"rot"))
        p1 = await AsyncFakeProxy("http", upstream_port=port).start()
        p2 = await AsyncFakeProxy("socks5", upstream_port=port).start()
        s = AsyncSession(verify=ca, timeout=5, proxies={"all": p1.url})
        assert (await s.get("https://example.com/")).body == b"rot"
        assert p1.connections == 1
        s2 = AsyncSession(verify=ca, timeout=5).set_proxies([p1.url, p2.url])
        await s2.get("https://example.com/")
        await s2.get("https://example.com/")
        assert p1.connections == 2 and p2.connections == 1
        await s.close()
        await s2.close()               # boştaki keep-alive bağlantıları kapat (stop() beklemesin)
        await p1.stop()
        await p2.stop()
        srv.close()
    run(main())


# --------------------------------------------------------- Timeout / Limits
def test_timeout_nesnesi_ve_limits_kabul_edilir(ca):
    s = AsyncSession(verify=ca, timeout=Timeout(10, connect=2, read=7, pool=1))
    assert (s.timeout.connect, s.timeout.read, s.timeout.write, s.timeout.pool) == (2, 7, 10, 1)
    assert AsyncSession(verify=ca, timeout=3).timeout == Timeout(3)
    assert AsyncSession(verify=ca).timeout.read == 30.0
    lim = Limits(max_connections=3, keepalive_expiry=5)
    s = AsyncSession(verify=ca, limits=lim, max_connections=99)
    assert s.limits is lim and s._sem._value == 3         # limits, max_connections'ı geçersiz kılar
    assert AsyncSession(verify=ca, max_connections=7).limits.max_connections == 7


def test_connect_timeout_tls_el_sikisma_takilirsa(ca):
    async def main():
        async def hang(r, w):
            await r.read()               # istemci kapatana kadar sessiz kal
            # Sunucu tarafını da kapat: Python 3.12+ Server.wait_closed() açık
            # kalan bağlantı transport'larını bekler; kapatılmazsa test asılı kalır.
            w.close()
        srv = await asyncio.start_server(hang, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        async with srv:
            s = AsyncSession(verify=ca, timeout=Timeout(30, connect=0.3))
            t = time.monotonic()
            with pytest.raises(asyncio.TimeoutError):
                await s.get(f"https://127.0.0.1:{port}/")
            assert time.monotonic() - t < 3
    run(main())


def test_read_timeout_h1(pki_local, ca_local):
    async def main():
        def never(server):
            return b""
        srv, port, _ = await start_tls13(pki_local, never)
        async with srv:
            s = AsyncSession(verify=ca_local, timeout=Timeout(5, read=0.3))
            t = time.monotonic()
            with pytest.raises(asyncio.TimeoutError):
                await s.get(f"https://localhost:{port}/")
            assert time.monotonic() - t < 3
    run(main())


def test_limits_max_connections_ve_pool_timeout_h1(pki_local, ca_local):
    state = {"open": 0, "max": 0}

    async def main():
        async def slow_handler_conn(r, w):
            from tls13_fakeserver import FakeTLS13Server
            srv = FakeTLS13Server(pki_local, alpn="http/1.1")
            state["open"] += 1
            state["max"] = max(state["max"], state["open"])
            try:
                while True:
                    data = await r.read(65536)
                    if not data:
                        break
                    out = srv.receive(data)
                    if srv.state == "CONNECTED" and srv.app_in:
                        srv.app_in.clear()
                        await asyncio.sleep(0.2)
                        out += srv.send_app(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    if out:
                        w.write(out)
                        await w.drain()
            finally:
                state["open"] -= 1
                w.close()
        srv = await asyncio.start_server(slow_handler_conn, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        async with srv:
            s = AsyncSession(impersonate="chrome_131", verify=ca_local, timeout=5,
                             limits=Limits(max_connections=2))
            rs = await asyncio.gather(*[s.get(f"https://localhost:{port}/{i}") for i in range(6)])
            assert [r.body for r in rs] == [b"ok"] * 6
            assert state["max"] == 2
            await s.close()
            # havuz zaman aşımı
            s = AsyncSession(impersonate="chrome_131", verify=ca_local,
                             timeout=Timeout(5, pool=0.05), limits=Limits(max_connections=1))
            res = await asyncio.gather(s.get(f"https://localhost:{port}/a"),
                                       s.get(f"https://localhost:{port}/b"),
                                       return_exceptions=True)
            assert sum(isinstance(x, asyncio.TimeoutError) for x in res) == 1
            await s.close()
    run(main())


# ----------------------------------------------- HTTP/1.1 gövde çerçevelemesi
def _raw_h1(pki, resp: bytes, *, close=True):
    def handler(server):
        if not server.app_in:
            return b""
        server.app_in.clear()
        out = server.send_app(resp)
        if close:
            out += server.send_alert(1, 0)               # temiz close_notify
        return out
    return handler


async def _get(pki, ca, resp, method="GET", **kw):
    srv, port, _ = await start_tls13(pki, _raw_h1(pki, resp, **kw))
    async with srv:
        s = AsyncSession(impersonate="chrome_131", verify=ca, timeout=Timeout(5, read=3))
        t = time.monotonic()
        try:
            r = await s.request(method, f"https://localhost:{port}/")
        finally:
            await s.close()
        return r, time.monotonic() - t


@pytest.mark.parametrize("resp", [
    b"HTTP/1.1 204 No Content\r\n\r\n",
    b"HTTP/1.1 304 Not Modified\r\nETag: x\r\n\r\n",
])
def test_h1_204_304_govde_beklenmez(pki_local, ca_local, resp):
    r, dt = run(_get(pki_local, ca_local, resp, close=False))
    assert r.body == b"" and r.status_code in (204, 304)
    assert dt < 1.0                      # eskiden ~2 sn bekliyordu


def test_h1_head_govdesiz(pki_local, ca_local):
    r, dt = run(_get(pki_local, ca_local, b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n",
                     method="HEAD", close=False))
    assert r.body == b"" and dt < 1.0


def test_h1_eksik_content_length_hata(pki_local, ca_local):
    with pytest.raises(ConnectionResetError, match="eksik"):
        run(_get(pki_local, ca_local, b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n0123456789"))


def test_h1_yarim_chunked_hata(pki_local, ca_local):
    with pytest.raises(ConnectionResetError):
        run(_get(pki_local, ca_local,
                 b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n10\r\nkisa"))


def test_h1_chunked_tam_ve_http10_kapanisla_biten(pki_local, ca_local):
    r, _ = run(_get(pki_local, ca_local,
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                    b"5\r\nhello\r\n6;x=1\r\n dunya\r\n0\r\n\r\n", close=False))
    assert r.body == b"hello dunya"
    r, _ = run(_get(pki_local, ca_local, b"HTTP/1.0 200 OK\r\n\r\nbitis-kapanista"))
    assert r.body == b"bitis-kapanista"
