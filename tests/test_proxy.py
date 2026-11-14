"""
Faz 2 — proxy testleri (HTTP CONNECT ve SOCKS5), ağsız.

Yerel sahte proxy sunucuları her hedefi yerel sahte TLS 1.3 sunucusuna
yönlendirir ve istenen hedefi/kimlik bilgisini kaydeder. Uçtan uca testlerde
TLS, tünelin içinde fasthttpc'nin kendi yığınıyla kurulur.
"""
import base64
import socket
import struct
import threading

import pytest
from cryptography import x509

from fasthttpc import Session
from fasthttpc.security import tls_adapter
from fasthttpc.transport.proxy import (
    ProxyConfig, ProxyError, connect_via_proxy, parse_proxy_url, resolve_proxy,
)

from fake_tls_server import FakeTLS13Server, recv_exact


@pytest.fixture
def trust_leaf(monkeypatch):
    def _validate(hs_payload, hostname, **_kw):
        body = hs_payload[4:]
        p = 1 + body[0] + 3
        clen = struct.unpack("!I", b"\x00" + body[p:p + 3])[0]
        return x509.load_der_x509_certificate(body[p + 3:p + 3 + clen])
    monkeypatch.setattr(tls_adapter, "validate_server_certificate", _validate)


def _pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class FakeProxy:
    """kind='http' veya 'socks5'. Tek bağlantı; her hedefi upstream_port'a bağlar."""

    def __init__(self, kind, upstream_port=None, auth=None, reply=None):
        self.kind, self.upstream_port, self.auth, self.reply = kind, upstream_port, auth, reply
        self.target = None
        self.headers = b""
        self.error = None
        self.ls = socket.socket()
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(2)
        self.port = self.ls.getsockname()[1]
        threading.Thread(target=self._run, daemon=True).start()

    @property
    def url_base(self):
        return f"127.0.0.1:{self.port}"

    def _run(self):
        try:
            c, _ = self.ls.accept()
            c.settimeout(5)
            ok = self._http(c) if self.kind == "http" else self._socks(c)
            if not ok or self.upstream_port is None:
                c.close()
                return
            up = socket.create_connection(("127.0.0.1", self.upstream_port), timeout=5)
            threading.Thread(target=_pipe, args=(up, c), daemon=True).start()
            _pipe(c, up)
        except Exception as e:  # noqa: BLE001
            self.error = e

    def _http(self, c):
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += c.recv(1)
        self.headers = buf
        line = buf.split(b"\r\n")[0].decode()
        self.target = line.split(" ")[1]
        if self.reply:
            c.sendall(self.reply)
            return False
        if self.auth:
            exp = b"Proxy-Authorization: Basic " + base64.b64encode(self.auth.encode())
            if exp not in buf:
                c.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                return False
        c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        return True

    def _socks(self, c):
        ver, n = recv_exact(c, 2)
        methods = recv_exact(c, n)
        if self.auth:
            if 2 not in methods:
                c.sendall(b"\x05\xff")
                return False
            c.sendall(b"\x05\x02")
            _v, ul = recv_exact(c, 2)
            user = recv_exact(c, ul)
            pl = recv_exact(c, 1)[0]
            pwd = recv_exact(c, pl)
            if f"{user.decode()}:{pwd.decode()}" != self.auth:
                c.sendall(b"\x01\x01")
                return False
            c.sendall(b"\x01\x00")
        else:
            c.sendall(b"\x05\x00")
        _v, cmd, _r, atyp = recv_exact(c, 4)
        if atyp == 3:
            host = recv_exact(c, recv_exact(c, 1)[0]).decode()
        elif atyp == 1:
            host = socket.inet_ntoa(recv_exact(c, 4))
        else:
            host = socket.inet_ntop(socket.AF_INET6, recv_exact(c, 16))
        port = struct.unpack("!H", recv_exact(c, 2))[0]
        self.target = (atyp, host, port)
        rep = self.reply if self.reply is not None else 0
        c.sendall(bytes([5, rep, 0, 1]) + b"\x7f\x00\x00\x01" + struct.pack("!H", 1080))
        return rep == 0


# ---- URL ayrıştırma -----------------------------------------------------------

def test_parse_proxy_url():
    p = parse_proxy_url("http://us%40r:p%3Ass@proxy.local:3128")
    assert (p.scheme, p.host, p.port, p.username, p.password) == \
        ("http", "proxy.local", 3128, "us@r", "p:ss")
    assert parse_proxy_url("socks5://h").port == 1080
    assert "p:ss" not in repr(p)
    with pytest.raises(ValueError):
        parse_proxy_url("https://h:1")
    with pytest.raises(ValueError):
        parse_proxy_url("ftp://h:1")


def test_resolve_proxy_dict():
    d = {"https": "socks5://a:1", "http": "http://b:2"}
    assert resolve_proxy(d, "https").host == "a"
    assert resolve_proxy(d, "http").host == "b"
    assert resolve_proxy({"all": "http://c:3"}, "https").host == "c"
    assert resolve_proxy({"http": "http://b:2"}, "https") is None
    assert resolve_proxy(None) is None


def test_session_proxy_param_validation():
    with pytest.raises(ValueError):
        Session(proxy="http://a:1", proxies={"https": "http://b:2"})
    with pytest.raises(ValueError):
        Session(proxy="gopher://x")
    s = Session(proxies={"https": "socks5://127.0.0.1:1"})
    assert s.pool.proxy == {"https": "socks5://127.0.0.1:1"}
    s.close()


# ---- Tünel kurulumu (protokol düzeyi) ----------------------------------------

def test_http_connect_with_basic_auth():
    px = FakeProxy("http", auth="user:pa ss")
    sock = connect_via_proxy(ProxyConfig("http", "127.0.0.1", px.port, "user", "pa ss"),
                             "example.com", 443, timeout=5)
    sock.close()
    assert px.target == "example.com:443"
    assert b"Host: example.com:443" in px.headers


def test_http_connect_407():
    px = FakeProxy("http", auth="user:pass")
    with pytest.raises(ProxyError, match="407"):
        connect_via_proxy(ProxyConfig("http", "127.0.0.1", px.port), "example.com", 443, timeout=5)


def test_http_connect_refused_status():
    px = FakeProxy("http", reply=b"HTTP/1.1 403 Forbidden\r\n\r\n")
    with pytest.raises(ProxyError, match="403"):
        connect_via_proxy(ProxyConfig("http", "127.0.0.1", px.port), "example.com", 443, timeout=5)


def test_http_connect_ipv6_target():
    px = FakeProxy("http")
    connect_via_proxy(ProxyConfig("http", "127.0.0.1", px.port), "::1", 8443, timeout=5).close()
    assert px.target == "[::1]:8443"


def test_socks5_noauth_domain():
    px = FakeProxy("socks5")
    connect_via_proxy(ProxyConfig("socks5", "127.0.0.1", px.port), "example.com", 443,
                      timeout=5).close()
    assert px.target == (3, "example.com", 443)


def test_socks5_ipv4_literal():
    px = FakeProxy("socks5")
    connect_via_proxy(ProxyConfig("socks5", "127.0.0.1", px.port), "10.1.2.3", 443,
                      timeout=5).close()
    assert px.target == (1, "10.1.2.3", 443)


def test_socks5_userpass_ok_and_bad():
    px = FakeProxy("socks5", auth="u:p")
    connect_via_proxy(ProxyConfig("socks5", "127.0.0.1", px.port, "u", "p"), "example.com", 443,
                      timeout=5).close()
    px2 = FakeProxy("socks5", auth="u:p")
    with pytest.raises(ProxyError, match="kimlik"):
        connect_via_proxy(ProxyConfig("socks5", "127.0.0.1", px2.port, "u", "yanlis"),
                          "example.com", 443, timeout=5)
    px3 = FakeProxy("socks5", auth="u:p")
    with pytest.raises(ProxyError):
        connect_via_proxy(ProxyConfig("socks5", "127.0.0.1", px3.port), "example.com", 443,
                          timeout=5)


def test_socks5_connect_failure_reply():
    px = FakeProxy("socks5", reply=5)
    with pytest.raises(ProxyError, match="reddedildi"):
        connect_via_proxy(ProxyConfig("socks5", "127.0.0.1", px.port), "example.com", 443,
                          timeout=5)


def test_proxy_unreachable():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(ProxyError):
        connect_via_proxy(ProxyConfig("http", "127.0.0.1", port), "example.com", 443, timeout=2)


# ---- Uçtan uca: Session + tünel + kendi TLS yığınımız ------------------------

@pytest.mark.parametrize("proxy_url_fmt,kind", [
    ("http://alice:secret@{}", "http"),
    ("socks5://alice:secret@{}", "socks5"),
    ("socks5h://{}", "socks5"),
])
def test_session_through_proxy_end_to_end(trust_leaf, proxy_url_fmt, kind):
    srv = FakeTLS13Server()
    auth = "alice:secret" if "alice" in proxy_url_fmt else None
    px = FakeProxy(kind, upstream_port=srv.port, auth=auth)
    with Session(impersonate="chrome_131", proxy=proxy_url_fmt.format(px.url_base)) as s:
        r = s.get("https://example.com/merhaba")
    assert r.status_code == 200
    assert r.content == b"ok"
    srv.done.wait(5)
    assert srv.error is None, srv.error
    assert srv.request.startswith(b"GET /merhaba HTTP/1.1")
    assert px.target in ("example.com:443", (3, "example.com", 443))
    srv.close()


def test_session_proxies_dict_end_to_end_with_hrr(trust_leaf):
    srv = FakeTLS13Server(hrr_group=0x0017)
    px = FakeProxy("http", upstream_port=srv.port)
    with Session(proxies={"https": f"http://{px.url_base}"}) as s:
        r = s.get("https://example.com/")
    assert r.status_code == 200
    srv.close()


def test_psk_bilet_anahtari_proxy_degil_hedef_portu(trust_leaf, monkeypatch):
    """Proxy tünelinde bilet önbelleği anahtarı HEDEF portu içermeli (proxy'ninkini değil);
    aksi halde aynı proxy arkasındaki aynı host'un farklı portları bileti paylaşır."""
    from fasthttpc.security import session_tickets
    anahtarlar = []
    gercek = session_tickets.resumption_key

    def kaydet(host, port=None, ca_path=None):
        anahtarlar.append((host, port))
        return gercek(host, port, ca_path)

    monkeypatch.setattr(session_tickets, "_enabled", True)
    monkeypatch.setattr(session_tickets, "resumption_key", kaydet)
    srv = FakeTLS13Server()
    px = FakeProxy("http", upstream_port=srv.port)
    with Session(impersonate="chrome_131", proxy=f"http://{px.url_base}") as s:
        r = s.get("https://example.com:8443/")
    assert r.status_code == 200
    srv.close()
    assert anahtarlar == [("example.com", 8443)], anahtarlar


def test_async_proxy_connect_zaman_asimi_proxyerror(monkeypatch):
    """Proxy'ye TCP bağlantısı zaman aşımına uğrarsa (Windows'ta kapalı port ret'i ~2 sn'de bildirilir)
    sync yolla aynı: ProxyError (ConnectionError), ham TimeoutError değil."""
    import asyncio

    from fasthttpc import _backend as B
    from fasthttpc.transport.proxy import ProxyConfig, ProxyError, async_connect_via_proxy

    async def asili(*a, **k):
        await asyncio.sleep(30)
    monkeypatch.setattr(B, "open_connection", asili)

    async def main():
        with pytest.raises(ProxyError, match="bağlanılamadı"):
            await async_connect_via_proxy(ProxyConfig("http", "127.0.0.1", 9), "example.com", 443,
                                          timeout=0.2)
    asyncio.run(main())


@pytest.mark.parametrize("url", ["https://example.com/", "http://example.com/"])
def test_async_session_proxy_connect_zaman_asimi_proxyerror(monkeypatch, url):
    """AsyncSession proxy yolunu aynı süreli DIŞ bir zaman aşımıyla da sarar; proxy'ye TCP
    bağlanırken süre dolunca dış zamanlayıcı içtekini geçer. Sonuç yine ProxyError olmalı
    (Windows CI'da kapalı porta ret ~2 sn'de geldiği için görüldü)."""
    import asyncio

    from fasthttpc import AsyncSession
    from fasthttpc import _backend as B
    from fasthttpc.transport.proxy import ProxyError

    async def asili(*a, **k):
        await asyncio.sleep(30)
    monkeypatch.setattr(B, "open_connection", asili)

    async def main():
        a = AsyncSession(timeout=0.2, proxy="http://127.0.0.1:9")
        try:
            with pytest.raises(ProxyError, match="bağlanılamadı"):
                await a.get(url)
        finally:
            await a.close()
    asyncio.run(asyncio.wait_for(main(), 10))
