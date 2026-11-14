"""params / cookies / timeout / HEAD / history / links / is_redirect / next — ağsız."""
import asyncio
import threading
import time

import pytest

from fasthttpc import AsyncSession, MockTransport, Response, Session, Timeout
from fasthttpc import _api


def run(c):
    return asyncio.run(c)


def echo(r):
    return Response(200)


def both(fn):
    """Aynı senaryoyu sync ve async oturumda çalıştır: fn(call) -> (transport)"""
    t1 = MockTransport(echo)
    with Session(transport=t1) as s:
        fn(lambda m, *a, **k: getattr(s, m)(*a, **k), s)
    t2 = MockTransport(echo)

    async def main():
        async with AsyncSession(transport=t2) as s:
            calls = []

            def call(m, *a, **k):
                calls.append(getattr(s, m)(*a, **k))
            fn(call, s)
            for c in calls:
                await c
    run(main())
    return t1, t2


# ---- params ---------------------------------------------------------------------

@pytest.mark.parametrize("url,params,expected", [
    ("https://x.example/p", {"a": "1", "b": "ü"}, "a=1&b=%C3%BC"),
    ("https://x.example/p", [("a", "1"), ("a", "2")], "a=1&a=2"),
    ("https://x.example/p", {"a": ["1", "2"], "n": None}, "a=1&a=2"),
    ("https://x.example/p", "raw=1&z=2", "raw=1&z=2"),
    ("https://x.example/p?v=0", {"a": "1"}, "v=0&a=1"),            # mevcut query ile birleşir
    ("https://x.example/p?v=0", [], "v=0"),
    ("https://x.example/p?", {"a": "1"}, "a=1"),
])
def test_params_birlesme(url, params, expected):
    t1, t2 = both(lambda call, s: call("get", url, params=params))
    for t in (t1, t2):
        assert t.requests[0].url.raw_query == expected


def test_oturum_params_ve_istek_ezmesi():
    t = MockTransport(echo)
    with Session(transport=t, params={"k": "oturum", "s": "1"}) as s:
        s.get("https://x.example/", params={"k": "istek"})
        s.get("https://x.example/")
    assert t.requests[0].url.raw_query == "k=istek&s=1" and t.requests[1].url.raw_query == "k=oturum&s=1"


def test_params_redirectte_tekrarlanmaz():
    def h(r):
        return Response(302, headers={"Location": "/b"}) if r.url.path == "/a" else Response(200)
    t = MockTransport(h)
    with Session(transport=t) as s:
        s.get("https://x.example/a", params={"q": "1"})
    assert t.requests[0].url.raw_query == "q=1" and t.requests[1].url.raw_query == ""


# ---- cookies ----------------------------------------------------------------------

def test_istek_duzeyi_cerez_kavanoza_yazilmaz_ve_kavanozla_birlesir():
    def h(r):
        return Response(200, headers=[("Set-Cookie", "sid=1; Path=/")]) if r.url.path == "/set" else Response(200)
    t = MockTransport(h)
    with Session(transport=t) as s:
        s.get("https://x.example/set")
        s.get("https://x.example/x", cookies={"a": "2", "sid": "ezer"})
        assert set(t.requests[1].headers["cookie"].split("; ")) == {"sid=ezer", "a=2"}
        s.get("https://x.example/y")
        assert t.requests[2].headers["cookie"] == "sid=1" and "a" not in s.cookies


def test_istek_cerezi_cross_origin_redirectte_gitmez_ve_async():
    def h(r):
        return Response(302, headers={"Location": "https://baska.example/b"}) if r.url.path == "/a" else Response(200)
    t = MockTransport(h)

    async def main():
        async with AsyncSession(transport=t) as s:
            await s.get("https://x.example/a", cookies={"a": "1"})
    run(main())
    assert t.requests[0].headers["cookie"] == "a=1" and "cookie" not in t.requests[1].headers


# ---- timeout --------------------------------------------------------------------------

def test_timeout_cozumleme():
    base = Timeout(30)
    assert _api.resolve_timeout(_api.USE_CLIENT_DEFAULT, base) is None
    t = _api.resolve_timeout(5, base)
    assert (t.connect, t.read) == (5.0, 5.0)
    t = _api.resolve_timeout((2, 7), base)
    assert (t.connect, t.read) == (2.0, 7.0)
    tt = Timeout(connect=1, read=2)
    assert _api.resolve_timeout(tt, base) is tt
    assert _api.resolve_timeout(None, base).read is None
    with pytest.raises(TypeError):
        _api.resolve_timeout(True, base)
    with pytest.raises(TypeError):
        _api.resolve_timeout("5", base)


def test_istek_timeout_transporta_gorunur_ve_oturumu_degistirmez():
    t = MockTransport(echo)
    with Session(transport=t, timeout=30) as s:
        s.get("https://x.example/", timeout=(1.5, 4))
        s.get("https://x.example/", timeout=Timeout(connect=2, read=3))
        s.get("https://x.example/")
        assert [(r.timeout.connect, r.timeout.read) for r in t.requests] == [(1.5, 4.0), (2.0, 3.0), (30.0, 30.0)]
        assert s.timeout.read == 30.0
    t2 = MockTransport(echo)

    async def main():
        async with AsyncSession(transport=t2, timeout=30) as s:
            await s.get("https://x.example/", timeout=9)
    run(main())
    assert t2.requests[0].timeout.read == 9.0


from test_async_pool import H1Server, ok, pki, ca  # noqa: E402,F401


def test_istek_duzeyi_okuma_zaman_asimi_gercekten_uygulanir_async(pki, ca, tmp_path):
    def script(c, rn, m, p, b):
        return "hang" if p == "/yavas" else ok(b"hizli")

    async def main():
        srv = await H1Server(pki, tmp_path, script).start()
        async with AsyncSession(impersonate=None, verify=ca, timeout=20) as s:
            t0 = time.monotonic()
            with pytest.raises((TimeoutError, asyncio.TimeoutError)):
                await s.get(f"{srv.base}/yavas", timeout=(5, 0.3))
            assert time.monotonic() - t0 < 5
            assert (await s.get(f"{srv.base}/h")).body == b"hizli"      # oturum varsayılanı bozulmadı
        await srv.stop()
    asyncio.run(asyncio.wait_for(main(), 30))


def test_istek_duzeyi_okuma_zaman_asimi_gercekten_uygulanir_sync(pki, ca, tmp_path):
    ready, box = threading.Event(), {}

    def serve():
        async def main():
            def script(c, rn, m, p, b):
                return "hang" if p == "/yavas" else ok(b"hizli")
            box["srv"] = await H1Server(pki, tmp_path, script).start()
            box["loop"] = asyncio.get_running_loop()
            box["stop"] = asyncio.Event()
            ready.set()
            await box["stop"].wait()
        asyncio.run(main())
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    assert ready.wait(10)
    base = box["srv"].base
    try:
        with Session(impersonate=None, verify=ca, timeout=20) as s:
            t0 = time.monotonic()
            with pytest.raises((TimeoutError, OSError)):
                s.get(f"{base}/yavas", timeout=(5, 0.3))
            assert time.monotonic() - t0 < 5
            assert s.get(f"{base}/h").body == b"hizli"
    finally:
        box["loop"].call_soon_threadsafe(box["stop"].set)


# ---- HEAD, history, links, is_redirect, next ---------------------------------------------

def test_head_varsayilani_redirect_izlemez():
    def h(r):
        return Response(301, headers={"Location": "/b"}) if r.url.path == "/a" else Response(200)
    t1, t2 = both(lambda call, s: call("head", "https://x.example/a"))
    assert [r.url.path for r in t1.requests] == ["/a"] == [r.url.path for r in t2.requests]
    t = MockTransport(h)
    with Session(transport=t) as s:
        assert s.head("https://x.example/a", allow_redirects=True).status_code == 200
        assert s.request("HEAD", "https://x.example/a").status_code == 200   # request(): requests gibi izler


def test_history_is_redirect_ve_next():
    def h(r):
        p = r.url.path
        if p == "/a":
            return Response(301, headers={"Location": "/b"})
        if p == "/b":
            return Response(307, headers={"Location": "https://baska.example/c"})
        return Response(200)
    with Session(transport=MockTransport(h)) as s:
        r = s.get("https://x.example/a")
        assert [x.status_code for x in r.history] == [301, 307] and r.next is None
        assert r.history[0].is_redirect and r.history[0].is_permanent_redirect
        assert not r.history[1].is_permanent_redirect and not r.is_redirect
        r1 = s.get("https://x.example/a", allow_redirects=False)
        assert r1.is_redirect and r1.next.method == "GET" and str(r1.next.url) == "https://x.example/b"
        r2 = s.post("https://x.example/b", data=b"x", headers={"Authorization": "t"}, allow_redirects=False)
        assert str(r2.next.url) == "https://baska.example/c" and r2.next.method == "POST"
        assert "authorization" not in r2.next.headers          # çapraz origin
    assert not Response(302).is_redirect                         # Location yok → yönlendirme değil


def test_links_requests_uyumlu():
    r = Response(200, headers={"Link": '<https://a/x?p=1,2>; rel="next"; title="a, b", '
                                       '<https://a/l>; rel="last"'})
    assert r.links["next"] == {"url": "https://a/x?p=1,2", "rel": "next", "title": "a, b"}
    assert r.links["last"]["url"] == "https://a/l"
    assert Response(200).links == {}
    r = Response(200)
    r.headers.add("Link", '<https://a/1>; rel="prev"')
    r.headers.add("Link", '<https://a/3>; rel="next"')
    assert set(r.links) == {"prev", "next"}
    assert Response(200, headers={"Link": "<https://a/z>"}).links == {"https://a/z": {"url": "https://a/z"}}
