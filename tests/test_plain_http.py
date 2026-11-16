"""Düz (cleartext) ``http://``: TLS'siz HTTP/1.1 (h2c yok), Session ve AsyncSession.

0.6.2'ye kadar ``http://`` adresleri de TLS ile isteniyordu; artık requests/httpx gibi
düz TCP üzerinden HTTP/1.1 konuşulur. Proxy'de: HTTP proxy'sine mutlak biçimli istek
(CONNECT yok), SOCKS5'te tünelin içinde düz HTTP. https -> http yönlendirmesi kimlik
bilgisini ve Secure çerezleri sızdırmaz.
"""
import asyncio
import base64

import pytest

from fasthttpc import AsyncSession, Session
from fasthttpc.fingerprint import order_h1

from plain_servers import ForwardProxy, ThreadedHTTPServer, closed_port, ok, tls_context
from tls13_fakeserver import PKI


def run(coro, timeout=30):
    return asyncio.run(asyncio.wait_for(coro, timeout))


def b64(user, pw):
    return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()


def echo(r):
    return ok(b"%s %s %s" % (r.method.encode(), r.target.encode(), r.body))


def chunked(r):
    return [b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"7\r\nmerha", b"ba\r\n", b"7\r\n d\xc3\xbcnya\r\n", b"0\r\nX-Trailer: 1\r\n\r\n"]


@pytest.fixture
def srv():
    with ThreadedHTTPServer(echo) as s:
        yield s


@pytest.fixture(scope="module")
def pki():
    return PKI("localhost")


@pytest.fixture
def ca(pki, tmp_path):
    p = tmp_path / "ca.pem"
    p.write_bytes(pki.ca_pem())
    return str(p)


# ---- Session -------------------------------------------------------------------------

@pytest.mark.parametrize("impersonate", ["chrome_131", "firefox_133", None])
def test_sync_get_duz_tcp_tls_yok(srv, impersonate):
    with Session(impersonate=impersonate, timeout=5) as s:
        r = s.get(srv.base + "/merhaba?x=1")
    assert r.status_code == 200
    assert r.content == b"GET /merhaba?x=1 "
    assert r.http_version == "HTTP/1.1"
    assert r.tls_info is None
    req = srv.requests[0]
    assert req.first_byte == b"G"            # TLS ClientHello (0x16) değil, düz HTTP
    assert req.line == "GET /merhaba?x=1 HTTP/1.1"
    assert req.header("host") == f"localhost:{srv.port}"   # varsayılan olmayan port Host'ta


def test_sync_post_ve_keep_alive(srv):
    with Session(timeout=5) as s:
        r1 = s.post(srv.base + "/a", data=b"govde-1")
        r2 = s.post(srv.base + "/b", json={"k": 1})
        r3 = s.get(srv.base + "/c")
    assert r1.content == b"POST /a govde-1"
    assert r2.content.startswith(b"POST /b {") and b"\"k\"" in r2.content
    assert r3.content == b"GET /c "
    assert srv.requests[0].header("content-length") == "7"
    assert srv.conns == 1                      # üç istek tek bağlantıda (keep-alive)


def test_sync_connection_close_sonrasi_yeni_baglanti():
    with ThreadedHTTPServer(lambda r: (ok(b"x", b"Connection: close\r\n"),)) as srv:
        with Session(timeout=5) as s:
            assert s.get(srv.base + "/1").content == b"x"
            assert s.get(srv.base + "/2").content == b"x"
        assert srv.conns == 2


def test_sync_chunked_ve_trailer_keep_alive():
    with ThreadedHTTPServer(chunked) as srv:
        with Session(timeout=5) as s:
            assert s.get(srv.base + "/c").content == "merhaba dünya".encode()
            assert s.get(srv.base + "/c").content == "merhaba dünya".encode()
        assert srv.conns == 1                   # trailer tüketildi, bağlantı yeniden kullanıldı


def test_sync_stream_duz_http():
    body = bytes(range(256)) * 400
    with ThreadedHTTPServer(lambda r: ok(body)) as srv:
        with Session(timeout=5) as s:
            with s.get(srv.base + "/s", stream=True) as r:
                assert b"".join(r.iter_content(chunk_size=1000)) == body
            assert s.get(srv.base + "/t").content == body
        assert srv.conns == 1


def test_sync_eof_cerceveli_govde():
    with ThreadedHTTPServer(lambda r: (b"HTTP/1.0 200 OK\r\n\r\neof-govde",)) as srv:
        with Session(timeout=5) as s:
            assert s.get(srv.base + "/").content == b"eof-govde"


def test_baslik_sirasi_profili_izler_tls_ile_ayni(pki, ca, tmp_path):
    """Düz HTTP'de TLS parmak izi anlamsız ama HTTP/1.1 başlık sırası profili izler:
    aynı istek https ve http'de aynı sırada başlık gönderir."""
    with ThreadedHTTPServer() as plain, \
            ThreadedHTTPServer(ssl_ctx=tls_context(pki, tmp_path)) as tls:
        with Session(impersonate="chrome_131", verify=ca, timeout=5) as s:
            s.get(plain.base + "/")
            s.get(tls.base + "/")
    plain_names, tls_names = plain.requests[0].names, tls.requests[0].names
    assert plain_names == tls_names
    sent = plain.requests[0].headers
    assert order_h1("chrome_131", list(sent)) == sent     # gönderilen sıra zaten profil sırası
    assert "user-agent" in plain_names and plain_names[0] == "host"


def test_ayni_host_port_http_https_baglantisi_paylasilmaz(pki, ca, tmp_path):
    """http://h:P ile https://h:P ayrı havuz anahtarı: düz istek TLS bağlantısına gitmez."""
    with ThreadedHTTPServer(ssl_ctx=tls_context(pki, tmp_path)) as tls:
        with Session(verify=ca, timeout=3) as s:
            assert s.get(tls.base + "/").status_code == 200
            with pytest.raises(Exception):
                s.get(f"http://localhost:{tls.port}/")      # TLS sunucusuna düz HTTP: hata
        assert tls.conns == 2


# ---- AsyncSession --------------------------------------------------------------------

@pytest.mark.parametrize("impersonate", ["chrome_131", None])
def test_async_get_post_keep_alive(srv, impersonate):
    async def main():
        async with AsyncSession(impersonate=impersonate, timeout=5) as s:
            r1 = await s.get(srv.base + "/a?q=1")
            r2 = await s.post(srv.base + "/b", data=b"veri")
            return r1, r2
    r1, r2 = run(main())
    assert r1.content == b"GET /a?q=1 " and r1.http_version == "HTTP/1.1"
    assert r1.tls_info is None
    assert r2.content == b"POST /b veri"
    assert srv.requests[0].first_byte == b"G"
    assert srv.requests[0].header("host") == f"localhost:{srv.port}"
    assert srv.conns == 1


def test_async_chunked_ve_stream():
    with ThreadedHTTPServer(chunked) as srv:
        async def main():
            async with AsyncSession(timeout=5) as s:
                a = (await s.get(srv.base + "/1")).content
                async with s.stream("GET", srv.base + "/2") as r:
                    b = b"".join([c async for c in r.aiter_bytes()])
                return a, b, s.pool_stats()
        a, b, stats = run(main())
    assert a == b == "merhaba dünya".encode()
    assert srv.conns == 1
    assert stats == {f"http://localhost:{srv.port}": {"idle": 1, "h2": 0}}


def test_async_baslik_sirasi_sync_ile_ayni(srv):
    async def main():
        async with AsyncSession(impersonate="chrome_131", timeout=5) as s:
            await s.get(srv.base + "/")
    run(main())
    with Session(impersonate="chrome_131", timeout=5) as s:
        s.get(srv.base + "/")
    assert srv.requests[0].names == srv.requests[1].names


# ---- proxy üzerinden düz HTTP ------------------------------------------------------------

def test_sync_http_proxy_mutlak_bicim_connect_yok():
    px = ForwardProxy(require_auth=b64("al ice", "s:cret"))
    try:
        with Session(proxy="http://al%20ice:s%3Acret@" + px.url[len("http://"):], timeout=5) as s:
            r1 = s.get("http://hedef.test:8080/yol?a=1")
            r2 = s.get("http://hedef.test:8080/iki")
        assert r1.status_code == 200 and r1.content == b"via-proxy http://hedef.test:8080/yol?a=1"
        assert r2.content == b"via-proxy http://hedef.test:8080/iki"
        req = px.requests[0]
        assert req.line == "GET http://hedef.test:8080/yol?a=1 HTTP/1.1"
        assert req.header("host") == "hedef.test:8080"
        assert req.header("proxy-authorization") == b64("al ice", "s:cret")
        assert px.conns == 1                    # proxy bağlantısı keep-alive
    finally:
        px.close()


def test_async_http_proxy_mutlak_bicim():
    px = ForwardProxy(require_auth=b64("u", "p"))
    try:
        async def main():
            async with AsyncSession(proxy=f"http://u:p@127.0.0.1:{px.port}", timeout=5) as s:
                return await s.get("http://hedef.test/x"), await s.get("http://hedef.test/y")
        r1, r2 = run(main())
        assert r1.content == b"via-proxy http://hedef.test/x"
        assert r2.content == b"via-proxy http://hedef.test/y"
        assert px.requests[0].line == "GET http://hedef.test/x HTTP/1.1"
        assert px.requests[0].header("host") == "hedef.test"
        assert px.requests[0].header("proxy-authorization") == b64("u", "p")
        assert px.conns == 1
    finally:
        px.close()


def test_proxy_407_yanit_olarak_doner():
    """Mutlak biçimde 407 normal bir HTTP yanıtıdır (requests gibi; CONNECT'teki ProxyError değil)."""
    px = ForwardProxy(require_auth=b64("u", "p"))
    try:
        with Session(proxy=px.url, timeout=5) as s:
            assert s.get("http://hedef.test/").status_code == 407
    finally:
        px.close()


def test_socks5_uzerinden_duz_http(srv):
    from test_proxy import FakeProxy
    px = FakeProxy("socks5", upstream_port=srv.port)
    with Session(proxy=f"socks5://{px.url_base}", timeout=5) as s:
        r = s.get("http://localhost:%d/socks" % srv.port)
    assert r.content == b"GET /socks "
    assert px.target == (3, "localhost", srv.port)
    assert srv.requests[0].first_byte == b"G"


def test_async_socks5_uzerinden_duz_http(srv):
    from test_proxy import FakeProxy
    px = FakeProxy("socks5", upstream_port=srv.port)

    async def main():
        async with AsyncSession(proxy=f"socks5://{px.url_base}", timeout=5) as s:
            return await s.get("http://localhost:%d/as" % srv.port)
    assert run(main()).content == b"GET /as "
    assert px.target == (3, "localhost", srv.port)


def test_https_hala_http_proxy_connect_ile():
    """https:// hedefler HTTP proxy'sinde CONNECT tünelini kullanmaya devam eder (ForwardProxy
    CONNECT'i 405 ile reddeder -> ProxyError)."""
    from fasthttpc.transport.proxy import ProxyError
    px = ForwardProxy()
    try:
        with Session(proxy=px.url, timeout=5) as s:
            with pytest.raises(ProxyError, match="405"):
                s.get("https://hedef.test/")
        assert px.requests[0].line == "CONNECT hedef.test:443 HTTP/1.1"
    finally:
        px.close()


# ---- https -> http yönlendirmesi: kimlik ve Secure çerez sızmaz --------------------------

def _downgrade_servers(pki, tmp_path, plain):
    def tls_handler(r):
        return (b"HTTP/1.1 302 Found\r\n"
                b"Set-Cookie: sid=gizli; Secure; Path=/\r\n"
                b"Set-Cookie: tercih=1; Path=/\r\n"
                b"Location: " + f"http://localhost:{plain.port}/hedef".encode() + b"\r\n"
                b"Content-Length: 0\r\n\r\n")
    return ThreadedHTTPServer(tls_handler, ssl_ctx=tls_context(pki, tmp_path))


def _assert_no_leak(tls, plain):
    first = tls.requests[0]
    assert first.header("authorization") is not None        # https'te gönderildi
    hop = plain.requests[0]
    assert hop.line == "GET /hedef HTTP/1.1"
    assert hop.header("authorization") is None
    assert hop.header("proxy-authorization") is None
    assert hop.header("cookie") == "tercih=1"                # Secure 'sid' düz HTTP'ye gitmez


@pytest.mark.parametrize("kw", [
    {"headers": {"Authorization": "Bearer gizli-token", "Proxy-Authorization": "Basic eA=="}},
    {"auth": ("kullanici", "parola")},
])
def test_sync_https_http_redirect_kimlik_ve_secure_cerez_sizmaz(pki, ca, tmp_path, kw):
    with ThreadedHTTPServer() as plain, _downgrade_servers(pki, tmp_path, plain) as tls:
        with Session(verify=ca, timeout=5) as s:
            r = s.get(tls.base + "/giris", **kw)
            assert r.status_code == 200 and r.history[0].status_code == 302
            assert r.content == b"/hedef"
            assert s.cookies == {"sid": "gizli", "tercih": "1"}   # https'te alınan Secure çerez saklanır
        _assert_no_leak(tls, plain)


@pytest.mark.parametrize("kw", [
    {"headers": {"Authorization": "Bearer gizli-token", "Proxy-Authorization": "Basic eA=="}},
    {"auth": ("kullanici", "parola")},
])
def test_async_https_http_redirect_kimlik_ve_secure_cerez_sizmaz(pki, ca, tmp_path, kw):
    with ThreadedHTTPServer() as plain, _downgrade_servers(pki, tmp_path, plain) as tls:
        async def main():
            async with AsyncSession(verify=ca, timeout=5) as s:
                return await s.get(tls.base + "/giris", **kw)
        r = run(main())
        assert r.status_code == 200 and r.content == b"/hedef"
        _assert_no_leak(tls, plain)


def test_https_http_redirect_netrc_ve_url_kimligi_gonderilmez(pki, ca, tmp_path, monkeypatch):
    """requests .netrc'yi yönlendirme hedefi için yeniden uygular; düz HTTP'ye düşüşte
    fasthttpc hiçbir kimlik göndermez (.netrc ve URL'deki user:pass@ dahil)."""
    netrc = tmp_path / "netrc"
    netrc.write_text("machine localhost login nuser password npass\n")
    netrc.chmod(0o600)
    monkeypatch.setenv("NETRC", str(netrc))
    with ThreadedHTTPServer() as plain, _downgrade_servers(pki, tmp_path, plain) as tls:
        with Session(verify=ca, timeout=5) as s:
            s.get(tls.base.replace("https://", "https://u:p@") + "/giris")
        async def main():
            async with AsyncSession(verify=ca, timeout=5) as s:
                await s.get(tls.base + "/giris")
        run(main())
        assert tls.requests[0].header("authorization") == b64("nuser", "npass")
        for hop in plain.requests:
            assert hop.header("authorization") is None
            assert hop.header("cookie") == "tercih=1"
    with ThreadedHTTPServer() as plain2:            # doğrudan http:// isteğinde .netrc geçerli
        with Session(timeout=5) as s:
            s.get(plain2.base + "/")
        assert plain2.requests[0].header("authorization") == b64("nuser", "npass")


def test_duz_http_yaniti_secure_cerez_koyamaz_ve_ezemez():
    """RFC 6265bis §5.7: http yanıtındaki Set-Cookie: Secure yok sayılır ve https'te konmuş
    aynı adlı Secure çerezin üzerine yazamaz."""
    from fasthttpc.cookies import CookieJar
    jar = CookieJar()
    jar.update_from_headers(["sid=https-degeri; Secure"], "a.test", "/")
    jar.update_from_headers(["sid=saldirgan", "yeni=1; Secure", "duz=1"], "a.test", "/",
                            secure_origin=False)
    assert jar.as_dict() == {"sid": "https-degeri", "duz": "1"}
    jar.update_from_headers(["sid=; Max-Age=0"], "a.test", "/", secure_origin=False)
    assert jar.as_dict()["sid"] == "https-degeri"            # http'den silinemez de
    with ThreadedHTTPServer(lambda r: ok(b"", b"Set-Cookie: s2=1; Secure\r\n"
                                             b"Set-Cookie: d2=1\r\n")) as srv:
        with Session(timeout=5) as s:
            s.get(srv.base + "/")
            assert s.cookies == {"d2": "1"}


def test_http3_duz_http_icin_kullanilmaz_alt_svc_yok_sayilir(srv):
    """HTTP/3 (QUIC = TLS) yalnızca https:// içindir; http3="force" olsa da http:// düz
    HTTP/1.1 ile gider ve düz yanıttaki Alt-Svc (ağdaki saldırgan ekleyebilir) kaydedilmez."""
    pytest.importorskip("aioquic")
    srv.handler = lambda r: ok(b"duz", b'Alt-Svc: h3=":443"\r\n')
    with Session(http3="force", timeout=5) as s:
        r = s.get(srv.base + "/")
        assert r.content == b"duz" and r.http_version == "HTTP/1.1"
        assert not s._h3.state.altsvc.get(("localhost", srv.port))

    async def main():
        async with AsyncSession(http3="force", timeout=5) as s:
            r = await s.get(srv.base + "/")
            return r, s._h3.state.altsvc.get(("localhost", srv.port))
    r, alt = run(main())
    assert r.content == b"duz" and r.http_version == "HTTP/1.1" and not alt
