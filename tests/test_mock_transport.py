"""MockTransport ile ağsız Session/AsyncSession testleri."""
import asyncio
import json

import pytest

from fasthttpc import AsyncSession, MockTransport, Response, Session


def test_temel_get_ve_istek_icerigi():
    def handler(request):
        assert request.method == "GET"
        assert request.url.host == "api.example.com"
        assert request.url.path == "/v1/items"
        assert request.headers["x-test"] == "1"
        assert request.headers["host"] == "api.example.com"
        return Response(200, headers={"Content-Type": "application/json"}, body=b'{"ok": true}')

    t = MockTransport(handler)
    with Session(transport=t) as s:
        r = s.get("https://api.example.com/v1/items", headers={"X-Test": "1"})
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    assert r.request is t.requests[0]


def test_post_json_govdesi():
    def handler(request):
        assert request.headers["content-type"] == "application/json"
        return Response(201, body=request.body)

    with Session(transport=MockTransport(handler)) as s:
        r = s.post("https://x.example/", json={"a": 1})
    assert r.status_code == 201 and json.loads(r.body) == {"a": 1}


def test_files_multipart():
    def handler(request):
        assert request.headers["content-type"].startswith("multipart/form-data")
        assert b"merhaba" in request.body
        return Response(200)

    with Session(transport=MockTransport(handler)) as s:
        assert s.post("https://x.example/up",
                      files={"f": ("a.txt", b"merhaba", "text/plain")}).status_code == 200


def test_redirect_ve_history():
    def handler(request):
        if request.url.path == "/eski":
            return Response(302, headers={"Location": "/yeni"})
        return Response(200, body=b"son")

    t = MockTransport(handler)
    with Session(transport=t) as s:
        r = s.post("https://x.example/eski", data=b"x")
    assert r.status_code == 200 and r.body == b"son"
    assert [h.status_code for h in r.history] == [302]
    assert t.requests[1].method == "GET"  # 302 → GET


def test_redirect_baska_origin_authorization_tasinmaz():
    def handler(request):
        if request.url.host == "a.example":
            return Response(301, headers={"Location": "https://b.example/"})
        assert "authorization" not in request.headers
        return Response(200)

    with Session(transport=MockTransport(handler)) as s:
        assert s.get("https://a.example/", headers={"Authorization": "gizli"}).status_code == 200


def test_cerezler_saklanir_ve_gonderilir():
    def handler(request):
        if request.url.path == "/giris":
            return Response(200, headers={"Set-Cookie": "sid=abc; Path=/"})
        assert request.headers.get("cookie") == "sid=abc"
        return Response(200)

    with Session(transport=MockTransport(handler)) as s:
        s.get("https://x.example/giris")
        assert s.cookies == {"sid": "abc"}
        s.get("https://x.example/profil")


def test_raise_for_status():
    from fasthttpc import HTTPStatusError

    with Session(transport=MockTransport(lambda r: Response(404))) as s:
        with pytest.raises(HTTPStatusError):
            s.get("https://x.example/").raise_for_status()


def test_handler_hatasi_iletilir():
    def handler(request):
        raise ConnectionRefusedError("kapalı")

    with Session(transport=MockTransport(handler)) as s:
        with pytest.raises(ConnectionRefusedError):
            s.get("https://x.example/")


def test_handler_response_donmezse_typeerror():
    with Session(transport=MockTransport(lambda r: "yanlış")) as s:
        with pytest.raises(TypeError):
            s.get("https://x.example/")


def test_sync_session_async_handler_reddeder():
    async def handler(request):
        return Response(200)

    with Session(transport=MockTransport(handler)) as s:
        with pytest.raises(TypeError, match="AsyncSession"):
            s.get("https://x.example/")


def test_ag_kullanilmaz(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("ağa çıkılmamalı")

    with Session(transport=MockTransport(lambda r: Response(200))) as s:
        monkeypatch.setattr(s.pool, "acquire", boom)
        assert s.get("https://x.example/").status_code == 200


# --- AsyncSession ---------------------------------------------------------

def test_async_sync_ve_async_handler():
    async def ahandler(request):
        assert request.method == "POST"
        assert json.loads(request.body) == {"k": "v"}
        return Response(200, headers={"Set-Cookie": "t=1"}, body=b"a")

    async def main():
        async with AsyncSession(impersonate=None,
                                transport=MockTransport(ahandler)) as s:
            r1 = await s.post("https://x.example/", json={"k": "v"})
            assert s.cookies == {"t": "1"}
        async with AsyncSession(impersonate=None,
                                transport=MockTransport(lambda r: Response(204))) as s:
            r2 = await s.get("https://x.example/")
        return r1, r2

    r1, r2 = asyncio.run(main())
    assert r1.body == b"a" and r2.status_code == 204


def test_async_redirect():
    def handler(request):
        if request.url.path == "/a":
            return Response(307, headers={"Location": "https://x.example/b"})
        return Response(200, body=request.url.path.encode())

    async def main():
        async with AsyncSession(impersonate=None, transport=MockTransport(handler)) as s:
            return await s.get("https://x.example/a")

    r = asyncio.run(main())
    assert r.body == b"/b" and len(r.history) == 1
