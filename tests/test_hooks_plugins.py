"""hooks= / event_hooks= ve sync+async plugin arayüzü — ağsız."""
import asyncio
import time

import pytest

from fasthttpc import (AsyncSession, LoggingPlugin, MockTransport, Plugin, RateLimitPlugin,
                       Response, RetryPlugin, Session)


def run(c):
    return asyncio.run(c)


def ok_handler(r):
    return Response(200, body=b"ok")


# ---- requests tarzı hooks ---------------------------------------------------------

def test_requests_hooks_istek_ve_oturum_duzeyi_donus_degeri_yanit_degistirir():
    calls = []

    def sess_hook(r, **kw):
        calls.append(("s", r.status_code, sorted(kw)))

    def req_hook(r, **kw):
        calls.append(("r", r.status_code))
        r.headers["X-Hooked"] = "1"
        return r

    with Session(transport=MockTransport(ok_handler), hooks={"response": sess_hook}) as s:
        r = s.get("https://x.example/", hooks={"response": [req_hook]})
        assert r.headers["x-hooked"] == "1"
        s.hooks["response"].append(lambda r, **kw: Response(299, body=b"yeni"))   # requests: s.hooks[...].append
        r = s.get("https://x.example/")
    assert r.status_code == 299 and r.body == b"yeni"
    assert calls[0] == ("s", 200, ["cert", "proxies", "stream", "timeout", "verify"])
    assert [c[0] for c in calls[:3]] == ["s", "s", "r"] or [c[0] for c in calls[:2]] == ["s", "r"]


def test_requests_hooks_redirect_adimlarinda_da_calisir():
    seen = []

    def h(r):
        return Response(302, headers={"Location": "/b"}) if r.url.path == "/a" else Response(200)
    with Session(transport=MockTransport(h)) as s:
        s.get("https://x.example/a", hooks={"response": lambda r, **kw: seen.append(r.status_code)})
    assert seen == [302, 200]


def test_bilinmeyen_hook_olayi_hata():
    with pytest.raises(ValueError):
        Session(hooks={"request": print})
    with pytest.raises(ValueError):
        Session(event_hooks={"bogus": []})
    with Session(transport=MockTransport(ok_handler)) as s, pytest.raises(ValueError):
        s.get("https://x.example/", hooks={"nope": print})


# ---- httpx tarzı event_hooks --------------------------------------------------------

def test_event_hooks_sync_istek_degistirir_yanit_gozler():
    log = []

    def on_req(request):
        log.append(("req", request.method, request.url.path))
        request.headers["X-Trace"] = "abc"

    def on_resp(response):
        log.append(("resp", response.status_code))

    t = MockTransport(ok_handler)
    with Session(transport=t, event_hooks={"request": [on_req], "response": [on_resp]}) as s:
        s.post("https://x.example/p", json={"a": 1})
    assert t.requests[0].headers["x-trace"] == "abc" and t.requests[0].body == b'{"a": 1}'
    assert log == [("req", "POST", "/p"), ("resp", 200)]


def test_event_hooks_async_hem_duz_hem_coroutine():
    log = []

    async def on_req(request):
        await asyncio.sleep(0)
        request.headers["X-A"] = "1"
        log.append("areq")

    def on_resp(response):
        log.append("resp")

    async def on_resp2(response):
        log.append("aresp")

    t = MockTransport(ok_handler)

    async def main():
        async with AsyncSession(transport=t, event_hooks={"request": [on_req],
                                                           "response": [on_resp, on_resp2]}) as s:
            await s.get("https://x.example/", hooks={"response": [lambda r, **kw: log.append("rq")]})
    run(main())
    assert t.requests[0].headers["x-a"] == "1"
    assert log == ["areq", "resp", "aresp", "rq"]


def test_sync_hook_coroutine_olursa_acik_hata():
    async def bad(r):
        pass
    with Session(transport=MockTransport(ok_handler), event_hooks={"response": [bad]}) as s:
        with pytest.raises(TypeError, match="coroutine"):
            s.get("https://x.example/")


# ---- sync plugin ---------------------------------------------------------------------

class Imza(Plugin):
    def __init__(self):
        self.events = []

    def on_request(self, request):
        request["headers"]["X-Imza"] = "ok"
        self.events.append("req")
        return request

    def on_response(self, response):
        self.events.append("resp")
        response.headers["X-Plugin"] = "1"
        return response


def test_sync_use_zincir_ve_kancalar():
    p = Imza()
    t = MockTransport(ok_handler)
    with Session(transport=t) as s:
        assert s.use(p) is s
        r = s.get("https://x.example/")
    assert t.requests[0].headers["x-imza"] == "ok" and r.headers["x-plugin"] == "1"
    assert p.events == ["req", "resp"]


def test_ayni_plugin_sync_ve_async_oturumda():
    class Sade(Plugin):
        def on_request(self, request):
            request["headers"]["X-S"] = "1"
            return request
    t1, t2 = MockTransport(ok_handler), MockTransport(ok_handler)
    with Session(transport=t1) as s:
        s.use(Sade()).use(LoggingPlugin())
        s.get("https://x.example/")

    async def main():
        async with AsyncSession(transport=t2) as a:
            a.use(Sade()).use(LoggingPlugin())
            await a.get("https://x.example/")
    run(main())
    assert t1.requests[0].headers["x-s"] == "1" == t2.requests[0].headers["x-s"]


def test_async_plugin_coroutine_ve_duz_kabul():
    class Karma(Plugin):
        async def on_request(self, request):
            await asyncio.sleep(0)
            request["headers"]["X-C"] = "1"
            return request

        def on_response(self, response):         # düz fonksiyon
            response.headers["X-D"] = "1"
            return response
    t = MockTransport(ok_handler)

    async def main():
        async with AsyncSession(transport=t) as a:
            a.use(Karma())
            return await a.get("https://x.example/")
    r = run(main())
    assert t.requests[0].headers["x-c"] == "1" and r.headers["x-d"] == "1"


def test_sync_session_coroutine_plugin_acik_hata():
    class A(Plugin):
        async def on_request(self, request):
            return request
    with Session(transport=MockTransport(ok_handler)) as s:
        s.use(A())
        with pytest.raises(TypeError, match="coroutine"):
            s.get("https://x.example/")


def test_on_error_sync_ve_async():
    class Yut(Plugin):
        def on_error(self, error):
            return None

    def boom(r):
        raise ConnectionError("x")
    with Session(transport=MockTransport(boom)) as s:
        with pytest.raises(ConnectionError):
            s.get("https://x.example/")
        s.use(Yut())
        assert s.get("https://x.example/").status_code == 0

    async def main():
        async with AsyncSession(transport=MockTransport(boom)) as a:
            a.use(Yut())
            return await a.get("https://x.example/")
    assert run(main()).status_code == 0


def test_retry_plugin_sync_ve_async():
    def make():
        n = {"c": 0}

        def h(r):
            n["c"] += 1
            return Response(503) if n["c"] < 3 else Response(200)
        return n, MockTransport(h)
    n, t = make()
    with Session(transport=t) as s:
        s.use(RetryPlugin(max_retries=3, backoff=0))
        assert s.get("https://x.example/").status_code == 200 and n["c"] == 3
    n, t = make()

    async def main():
        async with AsyncSession(transport=t) as a:
            a.use(RetryPlugin(max_retries=3, backoff=0))
            return await a.get("https://x.example/")
    assert run(main()).status_code == 200 and n["c"] == 3


def test_rate_limit_plugin_sync_ve_async():
    with Session(transport=MockTransport(ok_handler)) as s:
        s.use(RateLimitPlugin(rps=20))
        t0 = time.perf_counter()
        for _ in range(4):
            s.get("https://x.example/")
        assert time.perf_counter() - t0 >= 0.14          # 3 aralık * 50 ms

    async def main():
        async with AsyncSession(transport=MockTransport(ok_handler)) as a:
            a.use(RateLimitPlugin(rps=20))
            t0 = time.perf_counter()
            await asyncio.gather(*[a.get("https://x.example/") for _ in range(4)])
            return time.perf_counter() - t0
    assert run(main()) >= 0.14
