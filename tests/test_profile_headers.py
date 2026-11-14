"""Profil başına varsayılan tarayıcı başlıkları, oturum başlıkları ve sıralama (ağsız)."""
import socket
import ssl
import threading

import pytest
from cryptography.hazmat.primitives import serialization

from fasthttpc import AsyncSession, Limits, Session, Timeout
from fasthttpc import fingerprint as fp
from fasthttpc.protocol import http1_parser
from fasthttpc.protocol.http2_parser import h2_request_headers

from test_async_pool import pki, ca, run  # noqa: F401  (fixture'lar)


class HeaderServer:
    """Keep-alive TLS HTTP/1.1 sunucusu (iş parçacığı); ham istek başlık satırlarını kaydeder."""

    def __init__(self, pki, tmp_path):
        cert, key = tmp_path / "leaf.pem", tmp_path / "leaf.key"
        cert.write_bytes(pki.cert.public_bytes(serialization.Encoding.PEM))
        key.write_bytes(pki.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(cert), str(key))
        self.ctx.set_alpn_protocols(["http/1.1"])
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.requests = []          # [[satır, ...], ...]
        self.conns = 0
        threading.Thread(target=self._accept, daemon=True).start()

    @property
    def base(self):
        return f"https://localhost:{self.port}"

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            self.conns += 1
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            with self.ctx.wrap_socket(c, server_side=True) as t:
                buf = b""
                while True:
                    while b"\r\n\r\n" not in buf:
                        d = t.recv(4096)
                        if not d:
                            return
                        buf += d
                    head, _, buf = buf.partition(b"\r\n\r\n")
                    self.requests.append(head.decode("latin-1").split("\r\n"))
                    t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        except (OSError, ssl.SSLError):
            pass

    def close(self):
        self.sock.close()

    def names(self, i=-1):
        return [ln.split(":", 1)[0] for ln in self.requests[i][1:]]

    def value(self, name, i=-1):
        for ln in self.requests[i][1:]:
            k, _, v = ln.partition(":")
            if k.lower() == name.lower():
                return v.strip()
        return None


@pytest.fixture
def srv(pki, tmp_path):
    s = HeaderServer(pki, tmp_path)
    yield s
    s.close()


def sync_s(ca, **kw):
    kw.setdefault("timeout", Timeout(5, read=3))
    return Session(verify=ca, **kw)


# ------------------------------------------------------------- profil verisi
@pytest.mark.parametrize("name", ["chrome_131", "firefox_133", "safari_18", None])
def test_varsayilan_ua_profilin_user_agent_i(name):
    d = dict((k.lower(), v) for k, v in fp.default_headers(name))
    assert d["user-agent"] == fp.get_profile(name)["user_agent"]


def test_sec_ch_ua_yalniz_chrome():
    chrome = {k.lower() for k, _ in fp.default_headers("chrome_131")}
    assert {"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "upgrade-insecure-requests", "sec-fetch-site", "sec-fetch-mode",
            "sec-fetch-user", "sec-fetch-dest", "priority"} <= chrome
    for other in ("firefox_133", "safari_18", None):
        assert not any(k.lower().startswith("sec-ch-ua") for k, _ in fp.default_headers(other))


def test_safari_ua_macos_donuk_ve_chrome_firefox_farkli():
    uas = {n: fp.get_profile(n)["user_agent"] for n in ("chrome_131", "firefox_133", "safari_18")}
    assert "Firefox/133" in uas["firefox_133"] and "Chrome" not in uas["firefox_133"]
    assert "Version/18.0 Safari" in uas["safari_18"] and "Chrome" not in uas["safari_18"]
    assert "Mac OS X 10_15_7" in uas["safari_18"]


@pytest.mark.parametrize("br,zstd,chrome,safari", [
    (False, False, "gzip, deflate", "gzip, deflate"),
    (True, False, "gzip, deflate, br", "gzip, deflate, br"),
    (False, True, "gzip, deflate, zstd", "gzip, deflate"),
    (True, True, "gzip, deflate, br, zstd", "gzip, deflate, br"),
])
def test_accept_encoding_yalniz_acabildiklerimiz(monkeypatch, br, zstd, chrome, safari):
    monkeypatch.setattr(http1_parser, "_BROTLI", br)
    monkeypatch.setattr(http1_parser, "_ZSTD", zstd)
    assert fp.accept_encoding_for("chrome_131") == chrome
    assert fp.accept_encoding_for("firefox_133") == chrome
    assert fp.accept_encoding_for("safari_18") == safari      # Safari zstd ilan etmez
    assert fp.accept_encoding_for(None) == chrome


@pytest.mark.parametrize("name", ["chrome_131", "firefox_133", "safari_18"])
def test_h2_basliklari_profil_siralamasinda(name):
    h2 = fp.h2_config(name)
    pairs = fp.merge_default_headers(name, {"X-Ozel": "1", "Cookie": "a=b"})
    out = h2_request_headers(h2, "GET", "x.test", "https", "/",
                             [(k.lower(), v) for k, v in pairs])
    names = [k for k, _ in out if not k.startswith(":")]
    order = [n for n in h2["header_order"] if n in names]
    assert [n for n in names if n in h2["header_order"]] == order
    assert names[-1] == "x-ozel"                       # bilinmeyen başlık sona
    assert names[0] == order[0]


def test_merge_kullanici_gecersiz_kilar_ve_none_kaldirir():
    pairs = dict(fp.merge_default_headers("chrome_131",
                                          {"user-agent": "X/1", "Accept-Language": None}))
    assert pairs["user-agent"] == "X/1" and "User-Agent" not in pairs
    assert "Accept-Language" not in pairs and "accept-language" not in pairs


# ------------------------------------------------------- sync: gerçek istek (h1)
def test_sync_chrome_h1_basliklar_ve_sira(srv, ca):
    with sync_s(ca, impersonate="chrome_131") as s:
        assert s.get(f"{srv.base}/").status_code == 200
    assert srv.names() == [
        "Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
        "Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site",
        "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding",
        "Accept-Language"]                              # h1'de Priority YOK
    assert "Chrome/131" in srv.value("user-agent")
    assert srv.value("accept-encoding") == fp.accept_encoding_for("chrome_131")


@pytest.mark.parametrize("name,ua_part", [("firefox_133", "Firefox/133"), ("safari_18", "Version/18.0")])
def test_sync_firefox_safari_ua_ve_sec_ch_ua_yok(srv, ca, name, ua_part):
    with sync_s(ca, impersonate=name) as s:
        s.get(f"{srv.base}/")
    assert ua_part in srv.value("user-agent")
    assert not any(n.lower().startswith("sec-ch-ua") for n in srv.names())
    assert "Priority" not in srv.names() and "TE" not in srv.names()


def test_sync_default_profil_ua(srv, ca):
    with sync_s(ca, impersonate=None) as s:
        s.get(f"{srv.base}/")
    assert srv.value("user-agent") == fp.get_profile(None)["user_agent"]
    assert srv.value("accept") == "*/*"


def test_sync_oturum_basliklari_ve_oncelik(srv, ca):
    with sync_s(ca, impersonate="chrome_131",
                headers={"X-Oturum": "o", "user-agent": "OturumUA/1", "Accept-Language": "tr"}) as s:
        s.get(f"{srv.base}/")
        assert srv.value("x-oturum") == "o" and srv.value("user-agent") == "OturumUA/1"
        assert srv.value("accept-language") == "tr"
        s.headers["X-Sonra"] = "1"                       # mutable
        s.get(f"{srv.base}/", headers={"x-oturum": "istek", "Accept-Language": None})
        assert srv.value("x-oturum") == "istek" and srv.value("x-sonra") == "1"
        assert srv.value("accept-language") is None
        assert srv.names().count("X-Oturum") + srv.names().count("x-oturum") == 1
        del s.headers["x-sonra"]
        s.get(f"{srv.base}/")
        assert srv.value("x-sonra") is None


# ------------------------------------------------------------ async: gerçek istek
def test_async_basliklar_ve_oturum_basliklari(srv, ca):
    async def main():
        async with AsyncSession(verify=ca, impersonate="chrome_131", timeout=Timeout(5, read=3),
                                headers={"X-Oturum": "o"}) as s:
            await s.get(f"{srv.base}/")
            n1, ua = srv.names(), srv.value("user-agent")
            s.headers["User-Agent"] = "AsyncUA/2"
            await s.get(f"{srv.base}/", headers={"x-oturum": "istek"})
            return n1, ua
    n1, ua = run(main())
    assert n1[:8] == ["Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile",
                      "sec-ch-ua-platform", "Upgrade-Insecure-Requests", "User-Agent", "Accept"]
    assert "Priority" not in n1 and "Chrome/131" in ua
    assert srv.value("user-agent") == "AsyncUA/2" and srv.value("x-oturum") == "istek"


def test_async_firefox_ua(srv, ca):
    async def main():
        async with AsyncSession(verify=ca, impersonate="firefox_133",
                                timeout=Timeout(5, read=3)) as s:
            await s.get(f"{srv.base}/")
    run(main())
    assert "Firefox/133" in srv.value("user-agent")
    assert not any(n.lower().startswith("sec-ch") for n in srv.names())


# -------------------------------------------------------------- hizalanan davranış
def test_keepalive_expiry_sifir_senkronda_da_kapali(srv, ca):
    with sync_s(ca, impersonate=None, limits=Limits(keepalive_expiry=0)) as s:
        s.get(f"{srv.base}/")
        s.get(f"{srv.base}/")
    assert srv.conns == 2
    with sync_s(ca, impersonate=None, limits=Limits(keepalive_expiry=None)) as s:
        before = srv.conns
        s.get(f"{srv.base}/")
        s.get(f"{srv.base}/")
    assert srv.conns == before + 1


def test_sync_set_proxies_rotasyonu_ve_hatali_proxy_devre_disi(ca):
    s = sync_s(ca, impersonate=None, timeout=Timeout(1, read=1))
    assert s.set_proxies(["http://127.0.0.1:1"]) is s
    with pytest.raises(ConnectionError):
        s.get("https://localhost:9/")
    assert s._rotator.stats()["failed"] == ["http://127.0.0.1:1"]
    with pytest.raises(ValueError):
        s.set_proxies(["https://proxy.test:1"])
    s.close()


def test_options_sync(srv, ca):
    with sync_s(ca, impersonate=None) as s:
        assert s.options(f"{srv.base}/").status_code == 200
    assert srv.requests[-1][0].startswith("OPTIONS /")


def test_elapsed_ayni_tur(srv, ca):
    with sync_s(ca, impersonate=None) as s:
        r1 = s.get(f"{srv.base}/")

    async def main():
        async with AsyncSession(verify=ca, impersonate=None, timeout=Timeout(5, read=3)) as a:
            return await a.get(f"{srv.base}/")
    r2 = run(main())
    assert type(r1.elapsed) is type(r2.elapsed)
    assert r1.elapsed.total_seconds() > 0 and r2.elapsed.total_seconds() > 0
