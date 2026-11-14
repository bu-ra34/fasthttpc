"""Auth: Basic / Digest (RFC 7616) / Bearer / .netrc / URL kimliği / özel auth — ağsız."""
import asyncio
import base64
import hashlib
import os
import threading

import pytest

from fasthttpc import (AsyncSession, BasicAuth, BearerAuth, DigestAuth, MockTransport,
                       Response, Session)
from fasthttpc.auth import Auth, parse_challenges, resolve_auth

# ---- RFC 7616 §3.9.1 örnek vektörü -------------------------------------------
RFC = dict(user="Mufasa", pw="Circle of Life", realm="http-auth@example.org",
           nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
           opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS",
           cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ")
RFC_SHA256 = "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"
RFC_MD5 = "8ca523f5e9506fed4657c9700eebdbec"


def _h(algo):
    base = hashlib.sha256 if algo.upper().startswith("SHA-256") else hashlib.md5
    return lambda s: base(s if isinstance(s, bytes) else s.encode()).hexdigest()


def parse_auth_header(v):
    assert v.startswith("Digest ")
    return {k: (a or b) for k, a, b in __import__("re").findall(
        r'(\w+)=(?:"((?:[^"\\]|\\.)*)"|([^,\s]+))', v[7:])}


def expected_response(p, method, body=b"", password=RFC["pw"], user=RFC["user"]):
    """Bağımsız (sunucu tarafı) RFC 7616 doğrulayıcısı."""
    h = _h(p["algorithm"] if "algorithm" in p else "MD5")
    algo = p.get("algorithm", "MD5").upper()
    ha1 = h(f"{user}:{p['realm']}:{password}")
    if algo.endswith("-SESS"):
        ha1 = h(f"{ha1}:{p['nonce']}:{p['cnonce']}")
    a2 = f"{method}:{p['uri']}" + (f":{h(body)}" if p.get("qop") == "auth-int" else "")
    ha2 = h(a2)
    if "qop" in p:
        return h(f"{ha1}:{p['nonce']}:{p['nc']}:{p['cnonce']}:{p['qop']}:{ha2}")
    return h(f"{ha1}:{p['nonce']}:{ha2}")


class DigestServer:
    """MockTransport handler'ı: RFC 7616 sunucusu (challenge + doğrulama)."""

    def __init__(self, algorithm="SHA-256", qop='auth, auth-int', nonce=RFC["nonce"], stale_first=False):
        self.algorithm, self.qop, self.nonce, self.stale_first = algorithm, qop, nonce, stale_first
        self.log = []           # (Authorization | None, doğrulandı mı)

    def challenge(self, stale=False):
        v = (f'Digest realm="{RFC["realm"]}", qop="{self.qop}", algorithm={self.algorithm}, '
             f'nonce="{self.nonce}", opaque="{RFC["opaque"]}"')
        if stale:
            v += ", stale=true"
        return v

    def __call__(self, request):
        a = request.headers.get("authorization")
        if not a:
            self.log.append((None, False))
            return Response(401, headers={"WWW-Authenticate": self.challenge()})
        p = parse_auth_header(a)
        good = p["response"] == expected_response(p, request.method, request.body) \
            and p["username"] == RFC["user"] and p["uri"] == request.url.raw_path.decode()
        self.log.append((a, good))
        if self.stale_first and len(self.log) == 3:
            self.nonce = "yeninonce" + self.nonce
            return Response(401, headers={"WWW-Authenticate": self.challenge(stale=True)})
        return Response(200, body=b"gizli") if good else Response(401, headers={
            "WWW-Authenticate": self.challenge()})


def fixed(auth):
    auth._cnonce_factory = lambda: RFC["cnonce"]
    return auth


def run(coro):
    return asyncio.run(coro)


# ---- RFC vektörü ---------------------------------------------------------------

@pytest.mark.parametrize("algo,expected", [("SHA-256", RFC_SHA256), ("MD5", RFC_MD5)])
def test_rfc7616_ornek_vektoru(algo, expected):
    srv = DigestServer(algorithm=algo, qop="auth")
    t = MockTransport(srv)
    with Session(transport=t) as s:
        r = s.get("https://example.org/dir/index.html",
                  auth=fixed(DigestAuth(RFC["user"], RFC["pw"])))
    assert r.status_code == 200 and r.text == "gizli"
    sent = parse_auth_header(srv.log[-1][0])
    assert sent["response"] == expected                     # RFC'deki sabit değer
    assert sent["nc"] == "00000001" and sent["qop"] == "auth"
    assert sent["opaque"] == RFC["opaque"] and sent["algorithm"] == algo
    assert [h.status_code for h in r.history] == [401]       # challenge history'de
    assert len(t.requests) == 2                              # tek yeniden deneme


@pytest.mark.parametrize("algo", ["MD5", "MD5-sess", "SHA-256", "SHA-256-sess"])
@pytest.mark.parametrize("qop", ["auth", "auth-int", "auth, auth-int"])
def test_digest_algoritma_ve_qop_sunucu_dogrular(algo, qop):
    srv = DigestServer(algorithm=algo, qop=qop)
    with Session(transport=MockTransport(srv)) as s:
        r = s.post("https://example.org/dir/index.html?a=1", data=b"govde",
                   auth=DigestAuth(RFC["user"], RFC["pw"]))
    assert r.status_code == 200 and srv.log[-1][1] is True


def test_digest_rfc2069_qop_yok():
    srv = DigestServer(algorithm="MD5", qop="")
    srv.challenge = lambda stale=False: (f'Digest realm="{RFC["realm"]}", nonce="{srv.nonce}"')
    with Session(transport=MockTransport(srv)) as s:
        r = s.get("https://example.org/x", auth=DigestAuth(RFC["user"], RFC["pw"]))
    sent = parse_auth_header(srv.log[-1][0])
    assert r.status_code == 200 and "qop" not in sent and "nc" not in sent


def test_digest_yanlis_parola_tek_yeniden_deneme_sonra_401():
    srv = DigestServer()
    t = MockTransport(srv)
    with Session(transport=t) as s:
        r = s.get("https://example.org/x", auth=DigestAuth(RFC["user"], "yanlis"))
        assert r.status_code == 401 and len(t.requests) == 2     # sonsuz döngü yok
        n = len(t.requests)
        r = s.get("https://example.org/x", auth=DigestAuth(RFC["user"], "yanlis"))
        assert len(t.requests) - n == 2


def test_digest_nonce_sayaci_artar_ve_onden_gonderilir():
    srv = DigestServer(qop="auth")
    t = MockTransport(srv)
    auth = fixed(DigestAuth(RFC["user"], RFC["pw"]))
    with Session(transport=t) as s:
        for _ in range(3):
            assert s.get("https://example.org/dir/index.html", auth=auth).status_code == 200
    ncs = [parse_auth_header(a)["nc"] for a, _ in srv.log if a]
    assert ncs == ["00000001", "00000002", "00000003"]
    assert len(t.requests) == 4        # yalnızca ilki challenge turu; sonrakiler önceden gönderildi


def test_digest_stale_true_yeni_nonce_ile_tek_deneme():
    srv = DigestServer(qop="auth", stale_first=True)
    t = MockTransport(srv)
    auth = DigestAuth(RFC["user"], RFC["pw"])
    with Session(transport=t) as s:
        assert s.get("https://example.org/a", auth=auth).status_code == 200   # nonce'ı edin
        r = s.get("https://example.org/b", auth=auth)   # önceden gönder -> stale -> yeniden dene
    assert r.status_code == 200 and srv.log[-1][1] is True
    assert parse_auth_header(srv.log[-1][0])["nonce"].startswith("yeninonce")


def test_digest_asenkron():
    srv = DigestServer()
    async def main():
        async with AsyncSession(transport=MockTransport(srv)) as s:
            return await s.get("https://example.org/dir/index.html",
                               auth=DigestAuth(RFC["user"], RFC["pw"]))
    r = run(main())
    assert r.status_code == 200 and len(r.history) == 1 and srv.log[-1][1]


def test_challenge_ayristirma():
    ch = parse_challenges('Basic realm="a, b=c", Digest realm="x\\"y", nonce=abc, qop="auth,auth-int", '
                          'algorithm=SHA-256, Bearer realm="z"')
    assert [c[0] for c in ch] == ["Basic", "Digest", "Bearer"]
    assert ch[0][1] == {"realm": "a, b=c"}
    assert ch[1][1]["realm"] == 'x"y' and ch[1][1]["algorithm"] == "SHA-256"


# ---- Basic / Bearer / oturum-istek önceliği ---------------------------------------

def seen_auth():
    t = MockTransport(lambda r: Response(200))
    return t, lambda: t.requests[-1].headers.get("authorization")


def b64(u, p):
    return "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()


@pytest.mark.parametrize("auth", [("u", "p"), BasicAuth("u", "p")])
def test_basic_demet_ve_sinif(auth):
    t, got = seen_auth()
    with Session(transport=t) as s:
        s.get("https://x.example/", auth=auth)
        assert got() == b64("u", "p")
    t2, got2 = seen_auth()
    async def main():
        async with AsyncSession(transport=t2) as a:
            await a.get("https://x.example/", auth=auth)
    run(main())
    assert got2() == b64("u", "p")


def test_bearer_ve_oturum_duzeyi_auth():
    t, got = seen_auth()
    with Session(transport=t, auth=BearerAuth("tok")) as s:
        s.get("https://x.example/")
        assert got() == "Bearer tok"
        s.get("https://x.example/", auth=("a", "b"))             # istek oturumu ezer
        assert got() == b64("a", "b")
        s.get("https://x.example/", auth=None)                    # None: oturum auth'u kapalı
        assert got() is None
        s.auth = ("y", "z")                                       # s.auth atanabilir
        s.get("https://x.example/")
        assert got() == b64("y", "z")


def test_oturum_auth_asenkron():
    t, got = seen_auth()
    async def main():
        async with AsyncSession(transport=t, auth=BearerAuth("tok")) as s:
            await s.get("https://x.example/")
            assert got() == "Bearer tok"
            s.auth = None
            await s.get("https://x.example/")
            assert got() is None
    run(main())


def test_gecersiz_auth_turu():
    with pytest.raises(TypeError):
        resolve_auth(42)
    with pytest.raises(TypeError):
        resolve_auth(("sadece-biri",))


# ---- özel auth: requests tarzı ve httpx tarzı ----------------------------------------

class ReqStyle:                       # requests.auth.AuthBase benzeri
    def __call__(self, r):
        r.headers["X-Imza"] = "req:" + r.method + ":" + r.url.path
        return r


class HttpxStyle(Auth):               # httpx.Auth benzeri: 401 görünce belirteci yenile
    def __init__(self):
        self.tokens = ["eski", "yeni"]

    def auth_flow(self, request):
        request.headers["Authorization"] = "Bearer " + self.tokens[0]
        response = yield request
        if response.status_code == 401:
            request.headers["Authorization"] = "Bearer " + self.tokens[1]
            yield request


def test_ozel_requests_tarzi_ve_fonksiyon_sync_async():
    t = MockTransport(lambda r: Response(200))
    with Session(transport=t) as s:
        s.get("https://x.example/p", auth=ReqStyle())
        s.get("https://x.example/q", auth=lambda r: r.headers.__setitem__("X-F", "1"))
    assert t.requests[0].headers["x-imza"] == "req:GET:/p" and t.requests[1].headers["x-f"] == "1"
    t2 = MockTransport(lambda r: Response(200))
    async def main():
        async with AsyncSession(transport=t2) as s:
            await s.get("https://x.example/p", auth=ReqStyle())
    run(main())
    assert t2.requests[0].headers["x-imza"] == "req:GET:/p"


def test_ozel_httpx_tarzi_akis_sync_async():
    def handler(r):
        return Response(200 if r.headers.get("authorization") == "Bearer yeni" else 401)
    with Session(transport=MockTransport(handler)) as s:
        r = s.get("https://x.example/", auth=HttpxStyle())
    assert r.status_code == 200 and [h.status_code for h in r.history] == [401]
    async def main():
        async with AsyncSession(transport=MockTransport(handler)) as s:
            return await s.get("https://x.example/", auth=HttpxStyle())
    assert run(main()).status_code == 200


# ---- redirect: aynı origin korur, çapraz origin düşürür ---------------------------------

def redirect_handler(to):
    def h(r):
        if r.url.path == "/a":
            return Response(302, headers={"Location": to})
        return Response(200)
    return h


@pytest.mark.parametrize("to,keeps", [("/b", True), ("https://baska.example/b", False)])
def test_redirect_authorization(to, keeps):
    t = MockTransport(redirect_handler(to))
    with Session(transport=t, auth=("u", "p")) as s:
        s.get("https://x.example/a")
    assert t.requests[0].headers.get("authorization") == b64("u", "p")
    assert (t.requests[1].headers.get("authorization") == b64("u", "p")) is keeps
    t2 = MockTransport(redirect_handler(to))
    async def main():
        async with AsyncSession(transport=t2, auth=("u", "p")) as s:
            await s.get("https://x.example/a")
    run(main())
    assert (t2.requests[1].headers.get("authorization") == b64("u", "p")) is keeps


# ---- .netrc ve URL kimliği ------------------------------------------------------------------

@pytest.fixture
def netrc_file(tmp_path, monkeypatch):
    p = tmp_path / "netrc"
    p.write_text("machine x.example login nuser password npass\n"
                 "machine baska.example login buser password bpass\n")
    p.chmod(0o600)
    monkeypatch.setenv("NETRC", str(p))
    return p


def test_netrc_trust_env(netrc_file):
    t, got = seen_auth()
    with Session(transport=t) as s:
        s.get("https://x.example/")
        assert got() == b64("nuser", "npass")
        s.get("https://yok.example/")
        assert got() is None
        s.get("https://x.example/", auth=("e", "f"))             # açık auth netrc'yi ezer
        assert got() == b64("e", "f")
    t2, got2 = seen_auth()
    with Session(transport=t2, trust_env=False) as s:
        s.get("https://x.example/")
        assert got2() is None


def test_netrc_asenkron_ve_capraz_origin_yeniden_bakar(netrc_file):
    t = MockTransport(redirect_handler("https://baska.example/b"))
    async def main():
        async with AsyncSession(transport=t) as s:
            await s.get("https://x.example/a")
    run(main())
    assert t.requests[0].headers["authorization"] == b64("nuser", "npass")
    assert t.requests[1].headers["authorization"] == b64("buser", "bpass")   # yeni host'un kaydı


def test_url_kimligi_ve_oncelik(monkeypatch, tmp_path):
    monkeypatch.setenv("NETRC", str(tmp_path / "yok"))
    t, got = seen_auth()
    with Session(transport=t) as s:
        s.get("https://us%40er:p%3Aw@x.example/yol?q=1")
        assert got() == b64("us@er", "p:w")
        assert str(t.requests[-1].url) == "https://x.example/yol?q=1"   # kimlik URL'de taşınmaz
        s.get("https://u:p@x.example/", auth=("a", "b"))
        assert got() == b64("a", "b")
    t2, got2 = seen_auth()
    async def main():
        async with AsyncSession(transport=t2) as s:
            r = await s.get("https://u:p@x.example/")
            assert "u:p@" not in r.url
    run(main())
    assert got2() == b64("u", "p")


def test_url_kimligi_capraz_origin_redirectte_tasinmaz(monkeypatch, tmp_path):
    monkeypatch.setenv("NETRC", str(tmp_path / "yok"))
    t = MockTransport(redirect_handler("https://baska.example/b"))
    with Session(transport=t) as s:
        s.get("https://u:p@x.example/a")
    assert t.requests[0].headers.get("authorization") == b64("u", "p")
    assert "authorization" not in t.requests[1].headers


# ---- yerel TLS sahte sunucuda uçtan uca Digest (gerçek G/Ç) -------------------------------------

from test_async_pool import H1Server, pki, ca  # noqa: E402,F401


class HeaderServer(H1Server):
    """H1Server + istek başlıklarını da script'e geçirir: script(conn, req_no, method, path, body, headers)."""

    async def _on_conn(self, r, w):
        self.conns += 1
        no, req_no = self.conns, 0
        try:
            while True:
                head = await r.readuntil(b"\r\n\r\n")
                lines = head.decode().split("\r\n")
                method, path, _ = lines[0].split(" ")
                hdrs = {k.lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:] if ln)}
                n = int(hdrs.get("content-length", 0))
                body = await r.readexactly(n) if n else b""
                req_no += 1
                w.write(self.script(no, req_no, method, path, body, hdrs))
                await w.drain()
        except (OSError, asyncio.IncompleteReadError, asyncio.CancelledError):
            pass
        finally:
            w.close()


def test_digest_gercek_tls_sunucu_sha256_rfc_vektoru(pki, ca, tmp_path):
    srv_state = DigestServer(algorithm="SHA-256", qop="auth")

    class Req:  # DigestServer'ı Request benzeri nesneyle sür
        pass

    def script(c, rn, method, path, body, hdrs):
        from fasthttpc.models.urls import URL
        rq = Req()
        rq.headers, rq.method, rq.body = hdrs, method, body
        rq.url = URL("https://localhost" + path)
        resp = srv_state(rq)
        head = b"HTTP/1.1 %d X\r\nContent-Length: %d\r\n" % (resp.status_code, len(resp.body))
        if "www-authenticate" in resp.headers:
            head += b"WWW-Authenticate: " + resp.headers["www-authenticate"].encode() + b"\r\n"
        return head + b"\r\n" + resp.body

    async def main():
        srv = await HeaderServer(pki, tmp_path, script).start()
        async with AsyncSession(impersonate=None, verify=ca) as s:
            r = await s.get(f"{srv.base}/dir/index.html",
                            auth=fixed(DigestAuth(RFC["user"], RFC["pw"])))
        await srv.stop()
        return r
    r = run(main())
    assert r.status_code == 200 and r.text == "gizli"
    assert parse_auth_header(srv_state.log[-1][0])["response"] == RFC_SHA256
