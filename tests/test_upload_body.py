"""``data=`` istek gövdesi türleri ve akış (yükleme) davranışı — yerel sunucular, ağsız.

Hata (0.7.0): ``encode_body`` tanımadığı her ``data=`` türü için SESSİZCE boş gövde
gönderiyordu (``io.BytesIO``, üreteç, memoryview...) ya da bayt listesinde urlencode
içinde anlaşılmaz bir TypeError veriyordu. Burada her tür için sunucunun TAM OLARAK aldığı
bayt ve çerçeve (``Content-Length`` / ``Transfer-Encoding: chunked`` / HTTP/2 DATA
frame'leri ve END_STREAM) doğrulanır; yeniden gönderim (307/308, yeniden deneme, Digest,
bayat bağlantı) gerektiğinde dosya başa sarılır, üreteç açık bir hata verir.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import os
import time
import tracemalloc

import pytest

from fasthttpc import AsyncSession, DigestAuth, MockTransport, Request, Response, Retry, Session
from fasthttpc import Timeout
from fasthttpc._body import UnrewindableBodyError
from thread_servers import StallServer
from upload_servers import Got, make_server

KINDS = ["plain", "h1", "h2"]
MAX_FRAME = 16384


def _session(srv, **kw) -> Session:
    return Session(verify=srv.ca_path, **kw)


def _asession(srv, **kw) -> AsyncSession:
    return AsyncSession(verify=srv.ca_path, **kw)


def _check(kind: str, got: Got, body: bytes, *, known: bool) -> None:
    """Sunucunun aldığı gövde ``body`` ile bayt bayt aynı ve çerçeve doğru mu?"""
    assert got.body == body
    assert got.length == len(body)
    _check_framing(kind, got, len(body), known=known)


def _check_framing(kind: str, got: Got, n: int, *, known: bool) -> None:
    h = got.headers
    if kind == "h2":
        assert "transfer-encoding" not in h
        assert h.get("content-length") == (str(n) if known else None)
        assert got.frames, "DATA frame'i yok"
        assert all(size <= MAX_FRAME for size, _ in got.frames)
        assert [end for _, end in got.frames] == [False] * (len(got.frames) - 1) + [True]
        if n:
            assert got.frames[-1][0] > 0, "END_STREAM son VERİ frame'inde olmalı"
        assert sum(size for size, _ in got.frames) == n
    elif known:
        assert h.get("content-length") == str(n)
        assert "transfer-encoding" not in h and not got.chunked
    else:
        assert h.get("transfer-encoding") == "chunked" and got.chunked
        assert "content-length" not in h
        assert all(size > 0 for size in got.chunk_sizes)
        assert sum(got.chunk_sizes) == n


def _gen(*parts):
    yield from parts


async def _agen(*parts):
    for p in parts:
        await asyncio.sleep(0)
        yield p


@pytest.fixture(params=KINDS)
def srv(request):
    s = make_server(request.param)
    s.kind = request.param
    yield s
    s.close()


# --------------------------------------------------------------- senkron Session
def test_bytesio(srv):
    with _session(srv) as s:
        r = s.post(f"{srv.base}/echo", data=io.BytesIO(b"file-bytes"))
    assert r.status_code == 200 and r.content == b"10"
    _check(srv.kind, srv.requests[0], b"file-bytes", known=True)


def test_gercek_dosya_content_length(srv, tmp_path):
    payload = os.urandom(200_000)
    p = tmp_path / "f.bin"
    p.write_bytes(payload)
    with _session(srv) as s, open(p, "rb") as f:
        r = s.put(f"{srv.base}/echo", data=f)
    assert r.content == b"200000"
    _check(srv.kind, srv.requests[0], payload, known=True)


def test_dosya_sifirdan_farkli_konumda(srv, tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"HEADER" + b"x" * 1000)
    with _session(srv) as s, open(p, "rb") as f:
        f.seek(6)
        s.post(f"{srv.base}/echo", data=f)
        bio = io.BytesIO(b"0123456789")
        bio.seek(4)
        s.post(f"{srv.base}/echo", data=bio)
    _check(srv.kind, srv.requests[0], b"x" * 1000, known=True)
    _check(srv.kind, srv.requests[1], b"456789", known=True)


def test_metin_kipi_dosya_utf8(srv, tmp_path):
    text = "ğüşiöç €\n" * 5000
    p = tmp_path / "t.txt"
    p.write_text(text, encoding="utf-8")
    with _session(srv) as s, open(p, encoding="utf-8", newline="") as f:
        s.post(f"{srv.base}/echo", data=f)
        s.post(f"{srv.base}/echo", data=io.StringIO("şç"))
    # Metin: bayt uzunluğu önceden bilinemez -> chunked (h2: content-length yok).
    _check(srv.kind, srv.requests[0], text.encode("utf-8"), known=False)
    _check(srv.kind, srv.requests[1], "şç".encode(), known=False)


def test_uretec_chunked(srv):
    parts = [b"alpha-", b"beta-" * 10_000, "gamma-ç".encode(), b"!"]
    with _session(srv) as s:
        r = s.post(f"{srv.base}/echo", data=_gen(*parts))
    assert r.status_code == 200
    _check(srv.kind, srv.requests[0], b"".join(parts), known=False)


def test_uretec_bos_parcalar_akisi_bitirmez(srv):
    with _session(srv) as s:
        s.post(f"{srv.base}/echo", data=_gen(b"", b"ab", b"", "cç", b"", bytearray(b"d"), b""))
        s.post(f"{srv.base}/echo", data=_gen())            # tamamen boş üreteç
        s.post(f"{srv.base}/echo", data=_gen(b"", b""))
    _check(srv.kind, srv.requests[0], "abcçd".encode(), known=False)
    _check(srv.kind, srv.requests[1], b"", known=False)
    _check(srv.kind, srv.requests[2], b"", known=False)


def test_bayt_benzeri_olduğu_gibi(srv):
    import array
    with _session(srv) as s:
        s.post(f"{srv.base}/echo", data=memoryview(b"mv-data"))
        s.post(f"{srv.base}/echo", data=bytearray(b"ba-data"))
        s.post(f"{srv.base}/echo", data=memoryview(b"0123456789")[2:6])
        s.post(f"{srv.base}/echo", data=array.array("B", b"arr"))
    bodies = [g.body for g in srv.requests]
    assert bodies == [b"mv-data", b"ba-data", b"2345", b"arr"]
    for g in srv.requests:
        _check(srv.kind, g, g.body, known=True)


@pytest.mark.parametrize("source", ["file", "generator"])
def test_buyuk_govde_8mib_akitilir(srv, tmp_path, source):
    n = 8 * 1024 * 1024
    p = tmp_path / "big.bin"
    with open(p, "wb") as f:
        for i in range(n // 65536):
            f.write(hashlib.sha256(i.to_bytes(4, "big")).digest() * 2048)
    want = hashlib.sha256(p.read_bytes()).hexdigest()

    def chunks():
        with open(p, "rb") as f:
            while True:
                c = f.read(50_000)
                if not c:
                    return
                yield c

    with _session(srv, timeout=60) as s:
        tracemalloc.start()
        try:
            if source == "file":
                with open(p, "rb") as f:
                    r = s.post(f"{srv.base}/big", data=f)
            else:
                r = s.post(f"{srv.base}/big", data=chunks())
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
    assert r.status_code == 200 and r.content == str(n).encode()
    got = srv.requests[0]
    assert got.length == n and got.sha256 == want
    _check_framing(srv.kind, got, n, known=source == "file")
    assert peak < n // 2, f"gövde belleğe alınmış görünüyor (tepe {peak} bayt)"


@pytest.mark.parametrize("code", [307, 308])
def test_307_308_dosya_bastan_yeniden_gonderilir(srv, code):
    bio = io.BytesIO(b"PREFIX" + b"payload" * 3000)
    bio.seek(6)
    with _session(srv) as s:
        r = s.post(f"{srv.base}/r{code}", data=bio)
    assert r.status_code == 200 and [h.status_code for h in r.history] == [code]
    assert [g.path for g in srv.requests] == [f"/r{code}", "/echo"]
    for g in srv.requests:
        assert g.method == "POST"
        _check(srv.kind, g, b"payload" * 3000, known=True)


def test_307_uretec_acik_hata(srv):
    with _session(srv) as s, pytest.raises(UnrewindableBodyError, match="307"):
        s.post(f"{srv.base}/r307", data=_gen(b"tek", b"sefer"))
    assert [g.path for g in srv.requests] == ["/r307"]      # boş/yarım ikinci istek YOK
    _check(srv.kind, srv.requests[0], b"teksefer", known=False)


def test_303_uretec_get_ile_govdesiz(srv):
    with _session(srv) as s:
        r = s.post(f"{srv.base}/r303", data=_gen(b"x", b"y"))
    assert r.status_code == 200
    assert [(g.method, g.path, g.body) for g in srv.requests] == [
        ("POST", "/r303", b"xy"), ("GET", "/echo", b"")]
    assert "transfer-encoding" not in srv.requests[1].headers


def test_yeniden_deneme_status_uretec_tekrarlanmaz(srv):
    retry = Retry(2, status_forcelist=[503])
    with _session(srv, retries=retry) as s:
        r = s.put(f"{srv.base}/s503", data=_gen(b"bir", b"kez"))
    assert r.status_code == 503                         # yeniden denenmedi
    assert len(srv.requests) == 1
    _check(srv.kind, srv.requests[0], b"birkez", known=False)


def test_yeniden_deneme_status_dosya_bastan(srv):
    retry = Retry(2, status_forcelist=[503])
    with _session(srv, retries=retry) as s:
        r = s.put(f"{srv.base}/s503", data=io.BytesIO(b"tekrar-gonder"))
    assert r.status_code == 200
    assert len(srv.requests) == 2
    for g in srv.requests:
        _check(srv.kind, g, b"tekrar-gonder", known=True)


def test_yeniden_deneme_ag_hatasi_uretec(srv):
    with _session(srv, retries=2) as s, pytest.raises(ConnectionError) as ei:
        s.put(f"{srv.base}/drop", data=_gen(b"yalniz", b"bir-kez"))
    assert len(srv.requests) == 1
    _check(srv.kind, srv.requests[0], b"yalnizbir-kez", known=False)
    notes = getattr(ei.value, "__notes__", None)
    if notes is not None:                                   # Python 3.11+
        assert any("yeniden denenmedi" in n for n in notes)


def test_yeniden_deneme_ag_hatasi_dosya(srv):
    with _session(srv, retries=2) as s, pytest.raises(ConnectionError):
        s.put(f"{srv.base}/drop", data=io.BytesIO(b"hep-ayni"))
    assert len(srv.requests) == 3
    for g in srv.requests:
        _check(srv.kind, g, b"hep-ayni", known=True)


def test_digest_challenge_dosya_ve_uretec(srv):
    with _session(srv, auth=DigestAuth("u", "p")) as s:
        r = s.post(f"{srv.base}/digest", data=io.BytesIO(b"gizli-govde"))
        assert r.status_code == 200 and [h.status_code for h in r.history] == [401]
    assert [g.path for g in srv.requests] == ["/digest", "/digest"]
    assert "authorization" in srv.requests[1].headers
    for g in srv.requests:
        _check(srv.kind, g, b"gizli-govde", known=True)

    srv.requests.clear()
    with _session(srv, auth=DigestAuth("u", "p")) as s, \
            pytest.raises(UnrewindableBodyError, match="Digest"):
        s.post(f"{srv.base}/digest", data=_gen(b"a", b"b"))
    assert len(srv.requests) == 1


def test_kullanici_content_length_uretec(srv):
    with _session(srv) as s:
        s.put(f"{srv.base}/echo", data=_gen(b"abc", b"de"), headers={"Content-Length": "5"})
        _check(srv.kind, srv.requests[0], b"abcde", known=True)
        with pytest.raises(ValueError, match="kısa"):
            s.put(f"{srv.base}/echo", data=_gen(b"abc"), headers={"Content-Length": "5"})
        with pytest.raises(ValueError, match="uzun"):
            s.put(f"{srv.base}/echo", data=_gen(b"abcdef"), headers={"Content-Length": "5"})
        # Sonraki istek temiz bir bağlantıda doğru gider (yarım istek bağlantısı atıldı).
        r = s.post(f"{srv.base}/echo", data=b"sonra")
    assert r.content == b"5" and srv.requests[-1].body == b"sonra"


def test_desteklenmeyen_tur_typeerror(srv):
    with _session(srv) as s:
        for bad in (object(), 12345, 1.5):
            with pytest.raises(TypeError, match="desteklenmeyen tür"):
                s.post(f"{srv.base}/echo", data=bad)
        with pytest.raises(TypeError, match="AsyncSession"):
            s.post(f"{srv.base}/echo", data=_agen(b"x"))
    assert srv.requests == []                             # hiçbir şey gönderilmedi


def test_bayt_listesi_form_degil_acik_hata(srv):
    with _session(srv) as s:
        with pytest.raises(TypeError, match=r"\(anahtar, değer\) çiftleri"):
            s.post(f"{srv.base}/echo", data=[b"ab", b"cd"])
        with pytest.raises(TypeError, match=r"\(anahtar, değer\) çiftleri"):
            s.post(f"{srv.base}/echo", data=(b"ab",))
        s.post(f"{srv.base}/echo", data=[("a", "1"), ("b", "x y")])
        s.post(f"{srv.base}/echo", data=iter([b"ab", b"cd"]))      # belgelenen akış yolu
    form, stream = srv.requests
    assert form.body == b"a=1&b=x+y"
    assert form.headers["content-type"] == "application/x-www-form-urlencoded"
    _check(srv.kind, stream, b"abcd", known=False)


def test_multipart_dosyalar_eksiksiz(srv, tmp_path):
    p = tmp_path / "notlar.txt"
    p.write_text("çğü metin\n", encoding="utf-8")
    with _session(srv) as s, open(p, encoding="utf-8") as tf, open(p, "rb") as bf:
        s.post(f"{srv.base}/echo", data=[("alan", "1"), ("alan", 2)],
               files={"metin": tf, "ikili": bf, "bio": ("b.bin", io.BytesIO(b"\x00\x01")),
                      "s": ("s.txt", "düz str", "text/plain")})
    body = srv.requests[0].body
    assert body.count(b'name="alan"') == 2 and b"\r\n\r\n2\r\n" in body
    assert b'name="metin"; filename="notlar.txt"' in body
    assert b'name="ikili"; filename="notlar.txt"' in body
    assert body.count("çğü metin\n".encode()) == 2
    assert b"\x00\x01" in body and "düz str".encode() in body


# ------------------------------------------------------------ bayat bağlantı (h1)
@pytest.mark.parametrize("kind", ["plain", "h1"])
def test_bayat_keepalive_baglantida_uretec_kaybolmaz(kind):
    srv = make_server(kind)
    orig = srv._serve

    def serve_once(sock):           # ilk yanıttan sonra keep-alive bağlantıyı sessizce kapat
        srv._serve = orig
        f = sock.makefile("rb")
        while f.readline() not in (b"\r\n", b""):
            pass
        sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    srv._serve = serve_once
    try:
        with _session(srv) as s:
            assert s.get(f"{srv.base}/ilk").content == b"ok"
            time.sleep(0.3)                     # sunucu bağlantıyı kapattı (FIN geldi)
            r = s.post(f"{srv.base}/echo", data=_gen(b"bayat-", b"degil"))
        assert r.status_code == 200
        _check(kind, srv.requests[0], b"bayat-degil", known=False)
    finally:
        srv.close()


# ------------------------------------------------------------ Timeout.write
def test_uretec_gonderimi_write_ile_sinirli():
    with StallServer(tls=False, rcvbuf=32 * 1024) as srv, \
            Session(timeout=Timeout(10, write=0.5)) as s:
        def endless():
            while True:
                yield b"x" * 65536
        t0 = time.perf_counter()
        with pytest.raises(TimeoutError, match="Timeout.write"):
            s.post(f"{srv.base}/up", data=endless())
        assert time.perf_counter() - t0 < 6


# ------------------------------------------------------------ MockTransport / Request
def test_mock_transport_akisi_okur_ve_tekrarlar():
    seen: list[bytes] = []

    def handler(req: Request) -> Response:
        seen.append(req.content)
        return Response(503 if len(seen) == 1 else 200)

    with Session(transport=MockTransport(handler),
                 retries=Retry(2, status_forcelist=[503])) as s:
        r = s.put("https://x.test/u", data=_gen(b"mo", b"ck"))
    assert r.status_code == 200 and seen == [b"mock", b"mock"]   # bellekten yeniden


def test_request_nesnesi_akis():
    req = Request("POST", "https://x.test/", data=_gen(b"a", "ç"))
    assert req.body == b"" and req.stream is not None
    assert req.headers["transfer-encoding"] == "chunked"
    assert req.read() == "aç".encode() and req.content == "aç".encode()
    req2 = Request("POST", "https://x.test/", data=io.BytesIO(b"12345"))
    assert req2.headers["content-length"] == "5"
    with pytest.raises(TypeError):
        Request("POST", "https://x.test/", data=object())


# --------------------------------------------------------------- AsyncSession
def _run(coro):
    return asyncio.run(coro)


def test_async_turler(srv, tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"HEAD" + os.urandom(100_000))
    text = "ğüş\n" * 100

    async def go():
        async with _asession(srv) as s:
            await s.post(f"{srv.base}/echo", data=io.BytesIO(b"file-bytes"))
            with open(p, "rb") as f:
                f.seek(4)
                await s.post(f"{srv.base}/echo", data=f)
            await s.post(f"{srv.base}/echo", data=io.StringIO(text))
            await s.post(f"{srv.base}/echo", data=_gen(b"", b"sync", b"", b"-gen"))
            await s.post(f"{srv.base}/echo", data=_agen(b"", b"async", "-ç", b""))
            await s.post(f"{srv.base}/echo", data=memoryview(b"mv"))
            with pytest.raises(TypeError, match="desteklenmeyen tür"):
                await s.post(f"{srv.base}/echo", data=object())
            with pytest.raises(TypeError, match="çiftleri"):
                await s.post(f"{srv.base}/echo", data=[b"ab"])
    _run(go())
    g = srv.requests
    assert len(g) == 6
    _check(srv.kind, g[0], b"file-bytes", known=True)
    _check(srv.kind, g[1], p.read_bytes()[4:], known=True)
    _check(srv.kind, g[2], text.encode(), known=False)
    _check(srv.kind, g[3], b"sync-gen", known=False)
    _check(srv.kind, g[4], "async-ç".encode(), known=False)
    _check(srv.kind, g[5], b"mv", known=True)


def test_async_buyuk_async_uretec(srv):
    n = 8 * 1024 * 1024
    block = os.urandom(65536)

    async def chunks():
        for _ in range(n // len(block)):
            yield block

    async def go():
        async with _asession(srv, timeout=60) as s:
            return await s.post(f"{srv.base}/big", data=chunks())
    r = _run(go())
    assert r.content == str(n).encode()
    got = srv.requests[0]
    assert got.length == n and got.sha256 == hashlib.sha256(block * (n // len(block))).hexdigest()
    _check_framing(srv.kind, got, n, known=False)


def test_async_307_ve_yeniden_deneme(srv):
    async def go():
        async with _asession(srv, retries=Retry(2, status_forcelist=[503])) as s:
            r = await s.post(f"{srv.base}/r307", data=io.BytesIO(b"geri-sar"))
            assert r.status_code == 200
            with pytest.raises(UnrewindableBodyError, match="307"):
                await s.post(f"{srv.base}/r307", data=_agen(b"a", b"b"))
            r = await s.put(f"{srv.base}/s503", data=_agen(b"tek"))
            assert r.status_code == 503
            r = await s.put(f"{srv.base}/echo", data=_agen(b"abc"), headers={"Content-Length": "3"})
            assert r.content == b"3"
    _run(go())
    paths = [g.path for g in srv.requests]
    assert paths == ["/r307", "/echo", "/r307", "/s503", "/echo"]
    _check(srv.kind, srv.requests[0], b"geri-sar", known=True)
    _check(srv.kind, srv.requests[1], b"geri-sar", known=True)
    _check(srv.kind, srv.requests[2], b"ab", known=False)
    _check(srv.kind, srv.requests[3], b"tek", known=False)
    _check(srv.kind, srv.requests[4], b"abc", known=True)


def test_async_ag_hatasi_uretec_tekrarlanmaz(srv):
    async def go():
        async with _asession(srv, retries=2) as s:
            with pytest.raises((ConnectionError, OSError)):
                await s.put(f"{srv.base}/drop", data=_agen(b"x", b"y"))
    _run(go())
    assert len(srv.requests) == 1 and srv.requests[0].body == b"xy"


def test_async_uretec_gonderimi_write_ile_sinirli():
    async def go():
        async with AsyncSession(timeout=Timeout(10, write=0.5)) as s:
            async def endless():
                while True:
                    yield b"x" * 65536
            with pytest.raises((TimeoutError, asyncio.TimeoutError)):
                await s.post(f"{srv.base}/up", data=endless())

    with StallServer(tls=False, rcvbuf=32 * 1024) as srv:
        t0 = time.perf_counter()
        _run(go())
        assert time.perf_counter() - t0 < 6
