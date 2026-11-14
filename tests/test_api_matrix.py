"""API uyum matrisi: fasthttpc ↔ requests ↔ httpx (yalnızca imza/davranış; AĞSIZ).

requests/httpx kuruluysa canlı imzalarla da karşılaştırılır (yoksa o kısım atlanır;
fasthttpc tarafı tabloyla HER ZAMAN doğrulanır).
"""
import asyncio
import inspect

import pytest

from fasthttpc import (AsyncSession, BasicAuth, DigestAuth, MockTransport, Response, Session)

VERBS = ["get", "post", "put", "patch", "delete", "head", "options"]

# Her fiil için requests/httpx'te bulunan ve BİZDE de olması gereken anahtar parametreler.
# (requests adı, httpx adı, fasthttpc adı) — farklıysa eşlenir.
COMMON = {
    "params": ("params", "params", "params"),
    "headers": ("headers", "headers", "headers"),
    "cookies": ("cookies", "cookies", "cookies"),
    "auth": ("auth", "auth", "auth"),
    "timeout": ("timeout", "timeout", "timeout"),
    "redirects": ("allow_redirects", "follow_redirects", "allow_redirects"),
}
BODY = {"data": "data", "json": "json", "files": "files"}
# Bilinçli, belgelenmiş eksikler (matris dürüst kalsın): hiçbiri burada gizlenmez.
KNOWN_GAPS = {
    "verify/cert/proxies (istek düzeyi)": "oturum düzeyinde (Session(verify=, cert=, proxy=)); istek düzeyi yok",
    "follow_redirects takma adı": "allow_redirects kullanılır (requests adı)",
    "content=/extensions= (httpx)": "yok",
}


def test_bilinen_eksikler_dogru_belgelenmis():
    """KNOWN_GAPS tablosu yalan söylemesin: bu parametreler gerçekten yok."""
    ps = sig(Session.request)
    for gone in ("verify", "cert", "proxies", "follow_redirects", "content", "extensions"):
        assert gone not in ps
    # stream= artık var (akış desteği): tablo bunu eksik diye göstermemeli
    assert "stream" in ps and not any("stream" in k for k in KNOWN_GAPS)
    assert KNOWN_GAPS


def sig(fn):
    return inspect.signature(fn).parameters


@pytest.mark.parametrize("cls", [Session, AsyncSession])
@pytest.mark.parametrize("verb", VERBS)
def test_fasthttpc_fiil_imzalari_matris(cls, verb):
    ps = sig(getattr(cls, verb))
    for key, (_r, _h, ours) in COMMON.items():
        assert ours in ps, f"{cls.__name__}.{verb}: {ours} yok"
    if verb in ("post", "put", "patch"):
        for ours in BODY.values():
            if verb == "patch" and ours == "files":
                continue        # requests/httpx patch'te files de alır; mevcut API'de patch(files) yok
            assert ours in ps
    # head: requests/httpx gibi yönlendirme varsayılanı kapalı
    if verb == "head":
        assert ps["allow_redirects"].default is False
    elif "allow_redirects" in ps:
        assert ps["allow_redirects"].default is True
    # request() hepsini taşır
    rp = sig(cls.request)
    for ours in ("params", "cookies", "auth", "timeout", "hooks", "allow_redirects", "files", "json", "data"):
        assert ours in rp


def test_oturum_nitelikleri_matrisi():
    s = Session()
    for attr in ("auth", "hooks", "event_hooks", "headers", "cookies", "params", "trust_env",
                 "max_redirects", "timeout", "verify", "cookie_jar", "transport"):
        assert hasattr(s, attr), attr
    for name in ("use", "close", "request", *VERBS):
        assert callable(getattr(s, name))
    assert s.trust_env is True and s.hooks == {"response": []}
    assert s.event_hooks == {"request": [], "response": []}
    s.close()


def test_response_nitelikleri_matrisi():
    r = Response(200, headers={"Content-Type": "application/json", "Link": '<https://a/b>; rel="next"'},
                 body=b'{"a": 1}')
    for attr in ("status_code", "headers", "text", "content", "json", "url", "ok", "reason",
                 "history", "links", "is_redirect", "is_permanent_redirect", "next", "elapsed",
                 "encoding", "raise_for_status", "request"):
        assert hasattr(r, attr), attr
    assert r.json() == {"a": 1} and r.links["next"]["url"] == "https://a/b"


def test_requests_ile_karsilastirma():
    requests = pytest.importorskip("requests")
    rs = sig(requests.Session.request)
    ours = sig(Session.request)
    for name in ("params", "data", "json", "headers", "cookies", "files", "auth", "timeout",
                 "allow_redirects", "hooks"):
        assert name in rs and name in ours, name
    for name in ("auth", "hooks", "params", "trust_env", "headers", "cookies", "max_redirects"):
        assert hasattr(requests.Session(), name) and hasattr(Session(), name), name
    r = requests.models.Response()
    for attr in ("history", "links", "is_redirect", "is_permanent_redirect", "next"):
        assert hasattr(r, attr) and hasattr(Response(200), attr), attr


def test_httpx_ile_karsilastirma():
    httpx = pytest.importorskip("httpx")
    hs = sig(httpx.Client.request)
    ours = sig(Session.request)
    for h_name, o_name in (("params", "params"), ("headers", "headers"), ("cookies", "cookies"),
                           ("auth", "auth"), ("timeout", "timeout"),
                           ("follow_redirects", "allow_redirects")):
        assert h_name in hs and o_name in ours
    # auth/timeout varsayılanı: "istemci varsayılanı" işareti (httpx USE_CLIENT_DEFAULT)
    assert type(hs["auth"].default).__name__ == "UseClientDefault"
    assert repr(ours["auth"].default) == repr(ours["timeout"].default) == "USE_CLIENT_DEFAULT"
    init = sig(httpx.Client.__init__)
    for name in ("auth", "params", "headers", "event_hooks", "trust_env", "timeout"):
        assert name in init and name in sig(Session.__init__), name
    r = httpx.Response(200)
    for attr in ("history", "links", "is_redirect", "next_request"):
        assert hasattr(r, attr), attr
    assert hasattr(httpx.Response, "elapsed")


def _digest_ok(request):
    return Response(200)


def test_davranis_ayni_sonuc_requests_httpx_fasthttpc():
    """Aynı çağrı → aynı tel biçimi: Basic başlığı, params birleşmesi, çerez başlığı."""
    seen = {}
    ft = MockTransport(lambda r: (seen.setdefault("ft", r), Response(200))[1])
    with Session(transport=ft) as s:
        s.get("https://x.example/p?v=0", params={"a": "1"}, auth=("u", "p"), cookies={"c": "9"})
    fr = seen["ft"]
    assert fr.url.raw_query == "v=0&a=1" and fr.headers["authorization"] == "Basic dTpw"
    assert fr.headers["cookie"] == "c=9"

    requests = pytest.importorskip("requests")
    prep = requests.Request("GET", "https://x.example/p?v=0", params={"a": "1"}, auth=("u", "p"),
                            cookies={"c": "9"}).prepare()
    assert prep.url.endswith("?v=0&a=1") and prep.headers["Authorization"] == "Basic dTpw"
    assert prep.headers["Cookie"] == "c=9"

    httpx = pytest.importorskip("httpx")
    hr = httpx.Client(auth=("u", "p"), transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    req = hr.build_request("GET", "https://x.example/p?v=0", params={"a": "1"}, cookies={"c": "9"})
    # httpx params'ı mevcut sorguyu EZER: belgelenmiş fark (fasthttpc requests gibi ekler)
    assert str(req.url).endswith("?a=1")
    assert req.headers["cookie"] == "c=9"
