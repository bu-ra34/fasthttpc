"""Müdür denetiminde bulunan hataların ağsız regresyon testleri."""
from types import SimpleNamespace

import pytest

from fasthttpc import Session
from fasthttpc.models.request import Request
from async_fakes import start_h2
from test_async_h2 import ca, echo, pki, run, sess  # noqa: F401  (fixture'lar)


class _FakeH2:
    def __init__(self, pairs):
        self.pairs, self.calls = pairs, []

    def request(self, **kw):
        self.calls.append(kw)
        return 200, self.pairs, b"ok"


def _sync_h2(url, pairs=None):
    s = Session()
    fake = _FakeH2(pairs or [("content-type", "text/plain")])
    conn = SimpleNamespace(h2_conn=fake)
    req = Request("GET", url)
    resp = s._send_h2_request(conn, req, None, None, "GET", url)
    return s, fake, resp


@pytest.mark.parametrize("url,beklenen", [
    ("https://example.com/x", "example.com"),
    ("https://example.com:443/x", "example.com"),
    ("https://example.com:8443/x", "example.com:8443"),
])
def test_senkron_h2_authority_port(url, beklenen):
    _, fake, _ = _sync_h2(url)
    assert fake.calls[0]["authority"] == beklenen


def test_senkron_h2_coklu_set_cookie_korunur_ve_jar_hepsini_alir():
    s, _, resp = _sync_h2("https://example.com/", [("set-cookie", "a=1"), ("set-cookie", "b=2")])
    assert resp.headers.get_list("set-cookie") == ["a=1", "b=2"]
    assert resp.http_version == "HTTP/2"
    assert s.cookie_jar.header_for(host="example.com", path="/", secure=True) in ("a=1; b=2", "b=2; a=1")


def test_senkron_h1_coklu_set_cookie_cookie_jar():
    """h1 ayrıştırıcısı Headers.add kullanır; jar tüm Set-Cookie'leri almalı."""
    from fasthttpc.models.headers import Headers
    from fasthttpc.models.urls import URL
    h = Headers()
    h.add("Set-Cookie", "a=1")
    h.add("Set-Cookie", "b=2")
    s = Session()
    s._update_cookies(h, URL("https://example.com/"))
    assert s.cookie_jar.header_for(host="example.com", path="/", secure=True) in ("a=1; b=2", "b=2; a=1")


def test_async_h2_http_version(pki, ca):  # noqa: F811
    async def main():
        srv, port, _ = await start_h2(pki, echo)
        async with srv:
            s = sess(ca)
            r = await s.get(f"https://localhost:{port}/x")
            assert r.http_version == "HTTP/2"
            await s.close()
    run(main())
