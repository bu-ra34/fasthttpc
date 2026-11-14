"""Session / AsyncSession API eşitliği (imzalar + davranış)."""
import asyncio
import inspect

import pytest

from fasthttpc import AsyncSession, Session, Timeout
from fasthttpc.models.urls import URL

from test_async_pool import H1Server, ok, pki, ca, run  # noqa: F401  (fixture'lar)


def params(fn):
    return [p for p in inspect.signature(fn).parameters if p != "self"]


def test_init_parametreleri_ayni_kume():
    assert set(params(Session.__init__)) == set(params(AsyncSession.__init__))


@pytest.mark.parametrize("name", ["request", "get", "post", "put", "patch", "delete", "head"])
def test_http_metotlari_ayni_parametreler(name):
    assert params(getattr(Session, name)) == params(getattr(AsyncSession, name))
    assert inspect.iscoroutinefunction(getattr(AsyncSession, name))


# Bilinçli, belgelenmiş farklar: ``gather`` (asyncio.gather), ``ws_connect``
# (``websocket`` takma adı) yalnızca async'te. ``use`` artık İKİ tarafta da var.
ASYNC_ONLY = {"gather", "ws_connect"}
SYNC_ONLY: set = set()


def _public(cls):
    return {n for n in dir(cls) if not n.startswith("_")}


def test_public_yuzey_iki_yonlu_esit():
    sync_pub, async_pub = _public(Session), _public(AsyncSession)
    assert sync_pub - async_pub == SYNC_ONLY, sync_pub - async_pub
    assert async_pub - sync_pub == ASYNC_ONLY, async_pub - sync_pub
    assert "options" in sync_pub and "set_proxies" in sync_pub and "use" in sync_pub & async_pub


def test_ortak_metot_imzalari_ayni():
    for n in sorted(_public(Session) & _public(AsyncSession)):
        f, g = getattr(Session, n), getattr(AsyncSession, n)
        if callable(f):
            assert params(f) == params(g), n
            assert inspect.iscoroutinefunction(g) == (
                inspect.iscoroutinefunction(f) or n in ASYNC_COROUTINES), n


# Async'te coroutine olan, senkronda düz fonksiyon olan ortak metotlar.
ASYNC_COROUTINES = {"request", "get", "post", "put", "patch", "delete", "head", "options",
                    "pre_warm", "websocket", "close"}


def test_ornek_nitelikleri_iki_yonlu_esit():
    s, a = Session(), AsyncSession()
    pub = lambda o: {n for n in vars(o) if not n.startswith("_")}
    assert pub(s) - pub(a) == {"pool"} and pub(a) - pub(s) == set()
    s.close()
    run(a.close())


def test_init_varsayilanlari_ayni_anlamda():
    for name in ("impersonate", "verify", "retries", "limits", "proxies", "proxy",
                 "resolver", "headers", "transport", "cache", "cache_ttl"):
        ps, pa = (inspect.signature(c.__init__).parameters[name] for c in (Session, AsyncSession))
        assert ps.default == pa.default, name


def test_session_headers_iki_tarafta_mutable_ve_ayni_tur():
    s, a = Session(headers={"X-A": "1"}), AsyncSession(headers={"X-A": "1"})
    for o in (s, a):
        assert o.headers["x-a"] == "1"
        o.headers["X-B"] = "2"
        del o.headers["X-A"]
        assert dict(o.headers.items()) == {"x-b": "2"} and type(o.headers) is type(s.headers)
    s.close()
    run(a.close())


def sess(ca, **kw):
    kw.setdefault("impersonate", None)
    kw.setdefault("timeout", Timeout(5, read=3))
    return AsyncSession(verify=ca, **kw)


def test_files_str_data_url_nesnesi_ve_options(pki, ca, tmp_path):
    seen = {}

    def script(c, r, m, p, b):
        seen[(m, p)] = b
        return ok(b"x", b"Allow: GET\r\n")

    async def main():
        srv = await H1Server(pki, tmp_path, script).start()
        async with sess(ca) as s:
            r = await s.post(f"{srv.base}/up", data={"alan": "d"},
                             files={"f": ("a.txt", b"icerik", "text/plain")})
            assert r.status_code == 200
            body = seen[("POST", "/up")]
            assert b'name="alan"' in body and b'filename="a.txt"' in body and b"icerik" in body
            await s.put(f"{srv.base}/s", data="türkçe")
            assert seen[("PUT", "/s")] == "türkçe".encode("utf-8")
            r = await s.get(URL(f"{srv.base}/u"))
            assert r.url.endswith("/u") and r.ok and r.elapsed > 0
            r = await s.options(f"{srv.base}/o")
            assert r.headers.get("allow") == "GET"
            assert ("OPTIONS", "/o") in [(m, p) for _, m, p in srv.requests]
        await srv.stop()
    run(main())


def test_post_allow_redirects_false(pki, ca, tmp_path):
    def script(c, r, m, p, b):
        return b"HTTP/1.1 302 Found\r\nLocation: /son\r\nContent-Length: 0\r\n\r\n" \
            if p == "/git" else ok(p.encode())

    async def main():
        srv = await H1Server(pki, tmp_path, script).start()
        async with sess(ca) as s:
            r = await s.post(f"{srv.base}/git", data=b"x", allow_redirects=False)
            assert r.status_code == 302
            r = await s.post(f"{srv.base}/git", data=b"x")
            assert r.status_code == 200 and r.body == b"/son" and r.history
            assert r.url.endswith("/son")
        await srv.stop()
    run(main())


def test_cerezler_path_kapsaminda_ve_silinir(pki, ca, tmp_path):
    def script(c, r, m, p, b):
        if p == "/a/set":
            return ok(b"", b"Set-Cookie: sid=1; Path=/a\r\nSet-Cookie: g=2\r\n")
        if p == "/a/del":
            return ok(b"", b"Set-Cookie: sid=; Max-Age=0; Path=/a\r\n")
        return ok(b"")

    async def main():
        srv = await H1Server(pki, tmp_path, script).start()
        async with sess(ca) as s:
            await s.get(f"{srv.base}/a/set")
            assert s.cookies == {"sid": "1", "g": "2"} and len(s.cookie_jar) == 2
            h_a = s.cookie_jar.header_for("localhost", "/a/x", True)
            h_b = s.cookie_jar.header_for("localhost", "/b", True)
            assert "sid=1" in h_a and "g=2" in h_a      # g: varsayılan path /a
            assert h_b == ""
            # başka host'a çerez gitmez
            assert s.cookie_jar.header_for("baska.test", "/a/x", True) == ""
            await s.get(f"{srv.base}/a/del")
            assert s.cookies == {"g": "2"}
        await srv.stop()
    run(main())


def test_pool_stats_ve_websocket_adi(pki, ca, tmp_path):
    async def main():
        srv = await H1Server(pki, tmp_path).start()
        async with sess(ca) as s:
            await s.get(f"{srv.base}/")
            st = s.pool_stats()
            assert st == {f"https://localhost:{srv.port}": {"idle": 1, "h2": 0}}
            assert inspect.iscoroutinefunction(s.websocket)
        await srv.stop()
    run(main())


class FakeResolver:
    def __init__(self, ip="127.0.0.1", fail=False):
        self.ip, self.fail, self.calls = ip, fail, []

    def resolve_one(self, host):
        self.calls.append(host)
        if self.fail:
            raise RuntimeError("doh yok")
        return self.ip


@pytest.mark.parametrize("impersonate", [None])
def test_resolver_ip_baglanir_sni_ozgun_ad(impersonate, pki, ca, tmp_path):
    async def main():
        srv = await H1Server(pki, tmp_path).start()
        res = FakeResolver()
        async with sess(ca, resolver=res, impersonate=impersonate) as s:
            assert (await s.get(f"{srv.base}/r")).body == b"/r"
        assert res.calls == ["localhost"]
        # çözücü hata verirse OS çözücüsüne dönülür
        bad = FakeResolver(fail=True)
        async with sess(ca, resolver=bad) as s:
            assert (await s.get(f"{srv.base}/r")).body == b"/r"
        assert bad.calls == ["localhost"]
        await srv.stop()
    run(main())
