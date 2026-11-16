"""trust_env: HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / NO_PROXY ve CA bundle ortam değişkenleri.

conftest.py her testten önce bu değişkenleri temizler; testler ``monkeypatch.setenv`` ile kurar.
"""
import asyncio

import pytest

from fasthttpc import AsyncSession, Session
from fasthttpc.config import environ_ca_bundle
from fasthttpc.transport.proxy import (EnvProxies, ProxyConfig, ProxyError, environ_proxies,
                                       proxy_bypass, select_proxy)

from plain_servers import ForwardProxy, ThreadedHTTPServer, closed_port, tls_context
from tls13_fakeserver import PKI


def run(coro, timeout=30):
    return asyncio.run(asyncio.wait_for(coro, timeout))


# ---- environ_proxies ------------------------------------------------------------------

def test_environ_proxies_kucuk_harf_oncelikli_ve_semasiz_deger():
    env = {"HTTP_PROXY": "http://buyuk:1", "http_proxy": "http://kucuk:2",
           "HTTPS_PROXY": "proxy.local:3128", "ALL_PROXY": "socks5://s:1080",
           "NO_PROXY": "a.test", "no_proxy": ""}
    e = environ_proxies(env)
    assert e.proxies == {"http": "http://kucuk:2", "https": "http://proxy.local:3128",
                         "all": "socks5://s:1080"}
    assert e.sources == {"http": "http_proxy", "https": "HTTPS_PROXY", "all": "ALL_PROXY"}
    assert e.no_proxy == "a.test"                      # boş küçük harfli değer yok sayılır


def test_environ_proxies_yoksa_none_ve_bos_degerler():
    assert environ_proxies({}) is None
    assert environ_proxies({"HTTP_PROXY": "  ", "NO_PROXY": "x"}) is None


def test_environ_proxies_cgi_ortaminda_buyuk_harf_http_proxy_yok_sayilir():
    """httpoxy: CGI'da istemcinin 'Proxy:' başlığı HTTP_PROXY olur; ona güvenilmez."""
    env = {"REQUEST_METHOD": "GET", "HTTP_PROXY": "http://saldirgan:1",
           "HTTPS_PROXY": "http://p:2"}
    e = environ_proxies(env)
    assert "http" not in e.proxies and e.proxies["https"] == "http://p:2"
    assert environ_proxies({"REQUEST_METHOD": "GET", "http_proxy": "http://ok:1"}).proxies == {
        "http": "http://ok:1"}


# ---- NO_PROXY eşleştirme -------------------------------------------------------------

@pytest.mark.parametrize("host,port,no_proxy,beklenen", [
    ("example.com", 443, "*", True),
    ("example.com", 443, "example.com", True),
    ("api.example.com", 443, "example.com", True),           # alt alan adları da
    ("api.example.com", 443, ".example.com", True),
    ("api.example.com", 443, "*.example.com", True),
    ("example.com", 443, ".example.com", True),
    ("notexample.com", 443, "example.com", False),           # sonek ama alan sınırı değil
    ("example.com.evil", 443, "example.com", False),
    ("EXAMPLE.com.", 443, "example.COM", True),              # harf/sondaki nokta
    ("a.test", 443, "b.test, c.test ,a.test", True),         # boşluklu liste
    ("a.test", 443, "b.test c.test a.test", True),           # boşlukla ayrılmış
    ("a.test", 8080, "a.test:8080", True),                   # port
    ("a.test", 443, "a.test:8080", False),
    ("10.1.2.3", 80, "10.0.0.0/8", True),                    # CIDR
    ("11.1.2.3", 80, "10.0.0.0/8", False),
    ("10.1.2.3", 80, "10.1.2.3", True),
    ("10.1.2.3", 80, "10.1.2.4", False),
    ("::1", 80, "::1", True),
    ("::1", 80, "[::1]", True),
    ("::1", 8080, "[::1]:8080", True),
    ("::1", 9090, "[::1]:8080", False),
    ("fd00::5", 443, "fd00::/8", True),
    ("127.0.0.1", 80, "localhost", False),                   # ad çözümlenmez
    ("localhost", 80, "127.0.0.0/8", False),                 # CIDR yalnızca IP hedefe
    ("example.com", 443, "", False),
    ("example.com", 443, ",,", False),
])
def test_proxy_bypass(host, port, no_proxy, beklenen):
    assert proxy_bypass(host, port, no_proxy) is beklenen


def test_proxy_bypass_gercekci_liste():
    np = ("localhost,127.0.0.1,::1,127.0.0.0/8,169.254.0.0/16,pypi.org,10.0.0.0/8,"
          ".svc.cluster.local,*.svc.cluster.local")
    assert proxy_bypass("127.0.0.5", 80, np)
    assert proxy_bypass("db.ns.svc.cluster.local", 5432, np)
    assert proxy_bypass("pypi.org", 443, np)
    assert not proxy_bypass("example.com", 443, np)
    assert not proxy_bypass("8.8.8.8", 443, np)


# ---- select_proxy: öncelik ---------------------------------------------------------

ENV = EnvProxies(proxies={"http": "http://hp:1", "https": "http://sp:2", "all": "socks5://ap:3"},
                 sources={"http": "HTTP_PROXY", "https": "HTTPS_PROXY", "all": "ALL_PROXY"},
                 no_proxy="ic.test")


def test_select_proxy_semaya_gore():
    assert select_proxy("http", "x.test", 80, None, ENV) == ProxyConfig("http", "hp", 1)
    assert select_proxy("https", "x.test", 443, None, ENV) == ProxyConfig("http", "sp", 2)
    assert select_proxy("wss", "x.test", 443, None, ENV) == ProxyConfig("http", "sp", 2)
    assert select_proxy("ws", "x.test", 80, None, ENV) == ProxyConfig("http", "hp", 1)
    only_all = EnvProxies({"all": "socks5://ap:3"}, {"all": "ALL_PROXY"})
    assert select_proxy("https", "x.test", 443, None, only_all) == ProxyConfig("socks5", "ap", 3)
    only_http = EnvProxies({"http": "http://hp:1"}, {"http": "HTTP_PROXY"})
    assert select_proxy("https", "x.test", 443, None, only_http) is None


def test_select_proxy_no_proxy_ve_acik_proxy_onceligi():
    assert select_proxy("https", "api.ic.test", 443, None, ENV) is None
    # Açık proxy= ortamı tamamen ezer (NO_PROXY dahil); proxies={} "proxy yok" demektir.
    assert select_proxy("https", "api.ic.test", 443, "http://acik:9", ENV) == ProxyConfig(
        "http", "acik", 9)
    assert select_proxy("http", "x.test", 80, {"https": "http://acik:9"}, ENV) is None
    assert select_proxy("https", "x.test", 443, {}, ENV) is None
    assert select_proxy("https", "x.test", 443, None, None) is None


@pytest.mark.parametrize("url", ["https://p.local:3128", "socks4://p.local:1080"])
def test_select_proxy_desteklenmeyen_ortam_proxysi_acik_hata(url):
    env = EnvProxies({"https": url}, {"https": "HTTPS_PROXY"})
    with pytest.raises(ValueError, match="HTTPS_PROXY ortam değişkenindeki proxy") as ei:
        select_proxy("https", "x.test", 443, None, env)
    assert "trust_env=False" in str(ei.value)
    assert select_proxy("https", "x.test", 443, None,
                        EnvProxies({"https": url}, {"https": "HTTPS_PROXY"}, "x.test")) is None


# ---- Session / AsyncSession uçtan uca ------------------------------------------------

@pytest.fixture
def srv():
    with ThreadedHTTPServer(scheme_host="127.0.0.1") as s:
        yield s


@pytest.fixture
def px():
    p = ForwardProxy()
    yield p
    p.close()


def _bad_proxy():
    return f"http://127.0.0.1:{closed_port()}"


def test_sync_env_http_proxy_kullanilir(monkeypatch, px):
    monkeypatch.setenv("HTTP_PROXY", px.url)
    monkeypatch.setenv("HTTPS_PROXY", _bad_proxy())
    with Session(timeout=5) as s:
        r = s.get("http://hedef.test/a")
    assert r.content == b"via-proxy http://hedef.test/a"
    assert px.requests[0].line == "GET http://hedef.test/a HTTP/1.1"


@pytest.mark.parametrize("scheme,var", [("https", "HTTPS_PROXY"), ("http", "HTTP_PROXY")])
def test_sync_env_proxy_ulasilamazsa_proxyerror(monkeypatch, scheme, var):
    """CONNECT (https) ve tünelsiz mutlak biçim (http) yolunda proxy'ye bağlanılamaması ProxyError."""
    port = closed_port()
    monkeypatch.setenv(var, f"http://127.0.0.1:{port}")
    with Session(timeout=3) as s:
        with pytest.raises(ProxyError, match=f"127.0.0.1:{port}"):
            s.get(f"{scheme}://hedef.test/")


def test_sync_env_all_proxy_yedek(monkeypatch, px):
    monkeypatch.setenv("ALL_PROXY", px.url)
    with Session(timeout=5) as s:
        assert s.get("http://hedef.test/b").content == b"via-proxy http://hedef.test/b"


def test_sync_no_proxy_dogrudan(monkeypatch, srv):
    monkeypatch.setenv("HTTP_PROXY", _bad_proxy())
    monkeypatch.setenv("no_proxy", "localhost,127.0.0.0/8")
    with Session(timeout=5) as s:
        assert s.get(srv.base + "/d").content == b"/d"


def test_sync_trust_env_false_ortam_proxysini_yok_sayar(monkeypatch, srv):
    monkeypatch.setenv("HTTP_PROXY", _bad_proxy())
    monkeypatch.setenv("ALL_PROXY", _bad_proxy())
    with Session(timeout=5, trust_env=False) as s:
        assert s.pool.env_proxies is None
        assert s.get(srv.base + "/t").content == b"/t"


def test_sync_acik_proxy_ortami_ezer(monkeypatch, srv, px):
    monkeypatch.setenv("HTTP_PROXY", _bad_proxy())
    with Session(timeout=5, proxy=px.url) as s:
        assert s.get("http://hedef.test/e").content == b"via-proxy http://hedef.test/e"
    with Session(timeout=5, proxies={}) as s:               # boş sözlük: proxy yok, env de yok
        assert s.get(srv.base + "/f").content == b"/f"
    with Session(timeout=5, proxies={"https": _bad_proxy()}) as s:   # http için açık giriş yok
        assert s.get(srv.base + "/g").content == b"/g"


def test_sync_desteklenmeyen_env_proxy_istekte_acik_hata(monkeypatch, srv):
    monkeypatch.setenv("HTTP_PROXY", "https://p.local:3128")
    with Session(timeout=5) as s:                           # kurulum hata vermez
        with pytest.raises(ValueError, match="HTTP_PROXY ortam değişkenindeki proxy"):
            s.get("http://hedef.test/")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    with Session(timeout=5) as s:                           # proxy kullanılmayacaksa sorun yok
        assert s.get(srv.base + "/ok").content == b"/ok"


def test_sync_env_proxy_varken_http3_kullanilmaz(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    with Session(http3="force", timeout=1) as s:
        with pytest.raises(ConnectionError, match="proxy"):
            s.get("https://hedef.test/")


def test_async_env_proxy_secimi_no_proxy_ve_trust_env(monkeypatch, srv, px):
    monkeypatch.setenv("http_proxy", px.url)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")

    async def main():
        async with AsyncSession(timeout=5) as s:
            a = await s.get("http://hedef.test/x")          # env proxy
            b = await s.get(srv.base + "/y")                # NO_PROXY -> doğrudan
        async with AsyncSession(timeout=5, trust_env=False) as s:
            assert s._env_proxies is None
            c = await s.get(srv.base + "/z")
        async with AsyncSession(timeout=5, proxies={}) as s:
            assert s._env_proxies is None
        return a, b, c
    a, b, c = run(main())
    assert a.content == b"via-proxy http://hedef.test/x"
    assert b.content == b"/y" and c.content == b"/z"
    assert [r.line for r in px.requests] == ["GET http://hedef.test/x HTTP/1.1"]


def test_async_acik_proxy_ortami_ezer_ve_desteklenmeyen_env(monkeypatch, px):
    monkeypatch.setenv("HTTP_PROXY", "socks4://p.local:1080")

    async def main():
        async with AsyncSession(timeout=5) as s:
            with pytest.raises(ValueError, match="HTTP_PROXY ortam değişkenindeki proxy"):
                await s.get("http://hedef.test/")
        async with AsyncSession(timeout=5, proxy=px.url) as s:
            return await s.get("http://hedef.test/q")
    assert run(main()).content == b"via-proxy http://hedef.test/q"


# ---- CA bundle ortam değişkenleri -----------------------------------------------------

@pytest.fixture(scope="module")
def pki():
    return PKI("localhost")


@pytest.fixture
def ca(pki, tmp_path):
    p = tmp_path / "ca.pem"
    p.write_bytes(pki.ca_pem())
    return str(p)


def test_environ_ca_bundle_oncelik_ve_eksik_dosya(tmp_path):
    a, b = tmp_path / "a.pem", tmp_path / "b.pem"
    a.write_text("x")
    b.write_text("y")
    assert environ_ca_bundle({}) is None
    assert environ_ca_bundle({"SSL_CERT_FILE": str(b), "REQUESTS_CA_BUNDLE": str(a)}) == str(a)
    assert environ_ca_bundle({"SSL_CERT_FILE": str(b), "CURL_CA_BUNDLE": str(a)}) == str(b)
    with pytest.raises(FileNotFoundError, match="SSL_CERT_FILE"):
        environ_ca_bundle({"SSL_CERT_FILE": str(tmp_path / "yok.pem")})


@pytest.mark.parametrize("var", ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"])
def test_env_ca_bundle_kullanilir_dogrulama_acik(monkeypatch, pki, ca, tmp_path, var):
    monkeypatch.setenv(var, ca)
    with ThreadedHTTPServer(ssl_ctx=tls_context(pki, tmp_path)) as tls:
        with Session(timeout=5) as s:
            assert s._ca_path == ca
            assert s.get(tls.base + "/").status_code == 200

        async def main():
            async with AsyncSession(timeout=5) as s:
                assert s._ca_path == ca
                return await s.get(tls.base + "/")
        assert run(main()).status_code == 200


def test_env_ca_bundle_baska_ca_ise_dogrulama_basarisiz(monkeypatch, pki, tmp_path):
    """Ortamdaki bundle yalnızca güven deposunu DEĞİŞTİRİR; doğrulama kapanmaz."""
    other = tmp_path / "other.pem"
    other.write_bytes(PKI("localhost").ca_pem())
    monkeypatch.setenv("SSL_CERT_FILE", str(other))
    with ThreadedHTTPServer(ssl_ctx=tls_context(pki, tmp_path)) as tls:
        with Session(timeout=5) as s:
            with pytest.raises(Exception, match="(?i)sertifika|certificate|doğrula"):
                s.get(tls.base + "/")


def test_acik_verify_ve_trust_env_false_env_ca_yi_ezer(monkeypatch, pki, ca, tmp_path):
    other = tmp_path / "other.pem"
    other.write_bytes(PKI("localhost").ca_pem())
    monkeypatch.setenv("SSL_CERT_FILE", str(other))
    with ThreadedHTTPServer(ssl_ctx=tls_context(pki, tmp_path)) as tls:
        with Session(timeout=5, verify=ca) as s:             # açık verify= kazanır
            assert s.get(tls.base + "/").status_code == 200
    with Session(trust_env=False) as s:
        assert s._ca_path is None
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "yok.pem"))
    with pytest.raises(FileNotFoundError, match="SSL_CERT_FILE"):
        Session()
    with pytest.raises(FileNotFoundError, match="SSL_CERT_FILE"):
        AsyncSession()
    Session(trust_env=False).close()
    with pytest.raises(ValueError):
        Session(verify=False)                                # verify=False hâlâ desteklenmez
