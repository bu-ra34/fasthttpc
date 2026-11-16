"""Content-Encoding (br / zstd) açma: yerel h1 ve h2 sunucuları, sync/async,
akışlı/akışsız (ağsız).

Hata: açıcı paketi (brotli / zstandard) yoksa sıkıştırılmış gövde UYARISIZ, ham
haliyle dönüyordu; ``.json()`` UnicodeDecodeError veriyordu. Ayrıca akışsız yol
zstd'yi tek seferlik ``ZstdDecompressor().decompress`` ile açtığından, çerçevede
içerik boyutu olmayan (akış sıkıştırıcısıyla üretilmiş) gövde yine ham dönüyordu.
Artık eksik açıcı için açık bir ``MissingDecoderError`` yükselir.
"""
import asyncio
import json
import sys

import pytest

import fasthttpc
from fasthttpc import AsyncSession, Session
from fasthttpc.protocol.http1_parser import HTTP1Parser
from fasthttpc.protocol.http2_parser import FrameType
from fasthttpc.streaming import (
    DecodeError, IncrementalDecoder, MissingDecoderError, decode_body,
)
from saha.yerel_sunucu import YerelSunucu

from async_fakes import RawH2Conn, start_h2
from test_streaming_h2 import _Sunucu
from tls13_fakeserver import PKI

brotli = pytest.importorskip("brotli")
zstandard = pytest.importorskip("zstandard")

HOST = "localhost"
BEKLENEN = {"id": "x", "dolgu": "a" * 5000}
HAM = json.dumps(BEKLENEN).encode()
PAKET = {"br": "brotli", "zstd": "zstandard"}


def sikistir(enc: str, data: bytes) -> bytes:
    if enc == "br":
        return brotli.compress(data)
    co = zstandard.ZstdCompressor().compressobj()       # içerik boyutu YOK
    return co.compress(data) + co.flush()


@pytest.fixture
def acici_yok(monkeypatch):
    """brotli/brotlicffi/zstandard kurulu değilmiş gibi: import ImportError verir."""
    for name in ("brotli", "brotlicffi", "zstandard"):
        monkeypatch.setitem(sys.modules, name, None)


def eksik_acici_hatasi(exc_info, enc):
    e = exc_info.value
    assert isinstance(e, DecodeError) and isinstance(e, ValueError)
    assert e.encoding == enc and e.package == PAKET[enc]
    msg = str(e)
    assert PAKET[enc] in msg and "pip install" in msg


@pytest.fixture(scope="module")
def sv():
    with YerelSunucu() as s:
        yield s


@pytest.fixture(scope="module")
def pki():
    return PKI(HOST)


@pytest.fixture
def ca(pki, tmp_path):
    p = tmp_path / "ca.pem"
    p.write_bytes(pki.ca_pem())
    return str(p)


async def _h2_sikistirilmis(c: RawH2Conn):
    """GET /br, /zstd -> sıkıştırılmış JSON, 3 DATA frame'ine bölünmüş."""
    await c.handshake()
    while True:
        f = await c.next_frame()
        if f is None:
            return
        if f.type != FrameType.HEADERS or not c.requests[f.stream_id]["ended"]:
            continue
        sid = f.stream_id
        enc = dict(c.requests[sid]["headers"])[":path"].strip("/")
        z = sikistir(enc, HAM)
        c.send(c.response_headers(sid, 200, [("content-type", "application/json"),
                                             ("content-encoding", enc)]))
        n = len(z) // 3 + 1
        for i in range(0, len(z), n):
            c.send(c.data(sid, z[i:i + n], end=i + n >= len(z)))
        await c.flush()


@pytest.fixture
def h2sv(pki):
    s = _Sunucu(pki, _h2_sikistirilmis)
    yield s
    s.stop()


def run(coro, timeout=20):
    return asyncio.run(asyncio.wait_for(coro, timeout))


# --------------------------------------------------------------- birim
@pytest.mark.parametrize("enc", ["br", "zstd"])
def test_decode_body_ve_artimli_ayni_sonuc(enc):
    z = sikistir(enc, HAM)
    assert decode_body(z, enc) == HAM
    d = IncrementalDecoder(enc)
    assert b"".join(d.decode(z[i:i + 11]) for i in range(0, len(z), 11)) + d.flush() == HAM


def test_http1parser_decompress_icerik_boyutsuz_zstd():
    assert HTTP1Parser._decompress(sikistir("zstd", HAM), "zstd") == HAM


@pytest.mark.parametrize("enc", ["br", "zstd"])
def test_eksik_acici_birim(acici_yok, enc):
    z = sikistir(enc, HAM)
    with pytest.raises(MissingDecoderError) as ei:
        decode_body(z, enc)
    eksik_acici_hatasi(ei, enc)
    with pytest.raises(MissingDecoderError):
        IncrementalDecoder(enc).decode(z)
    with pytest.raises(MissingDecoderError):
        decode_body(z, f"gzip, {enc}")              # zincirde de
    # gövde yoksa (HEAD/304) açılacak bir şey yok: hata da yok
    assert decode_body(b"", enc) == b""
    assert IncrementalDecoder(enc).decode(b"") == b""


def test_eksik_acici_disa_aktarilir():
    assert fasthttpc.MissingDecoderError is MissingDecoderError
    assert fasthttpc.DecodeError is DecodeError
    assert issubclass(MissingDecoderError, DecodeError)


# --------------------------------------------------------------- sync HTTP/1.1
@pytest.mark.parametrize("enc", ["br", "zstd"])
def test_sync_h1_akissiz_ve_akisli(sv, enc):
    with Session(verify=sv.ca_path, timeout=10) as s:
        r = s.get(f"{sv.url}/{enc}?i=x")
        assert r.headers["content-encoding"] == enc
        assert r.json() == BEKLENEN
        with s.get(f"{sv.url}/{enc}?i=x", stream=True) as r:
            assert json.loads(b"".join(r.iter_bytes(chunk_size=97))) == BEKLENEN
        with s.get(f"{sv.url}/{enc}?i=x", stream=True) as r:
            assert json.loads("".join(r.iter_text())) == BEKLENEN


@pytest.mark.parametrize("enc", ["br", "zstd"])
def test_sync_h1_eksik_acici_acik_hata(sv, acici_yok, enc):
    with Session(verify=sv.ca_path, timeout=10) as s:
        with pytest.raises(MissingDecoderError) as ei:
            s.get(f"{sv.url}/{enc}?i=x")
        eksik_acici_hatasi(ei, enc)
        with s.get(f"{sv.url}/{enc}?i=x", stream=True) as r:
            with pytest.raises(MissingDecoderError):
                b"".join(r.iter_bytes())
        with s.get(f"{sv.url}/{enc}?i=x", stream=True) as r:
            with pytest.raises(MissingDecoderError):
                "".join(r.iter_text())
        # ham bayt isteyen yine alabilir (açma yok)
        with s.get(f"{sv.url}/{enc}?i=x", stream=True) as r:
            assert b"".join(r.iter_raw()) == sikistir(enc, HAM)


# --------------------------------------------------------------- async HTTP/1.1
@pytest.mark.parametrize("enc", ["br", "zstd"])
def test_async_h1_akissiz_ve_akisli(sv, enc):
    async def main():
        async with AsyncSession(verify=sv.ca_path, timeout=10) as s:
            r = await s.get(f"{sv.url}/{enc}?i=x")
            assert r.json() == BEKLENEN
            r = await s.get(f"{sv.url}/{enc}?i=x", stream=True)
            assert json.loads(b"".join([c async for c in r.aiter_bytes(chunk_size=97)])) == BEKLENEN
            r = await s.get(f"{sv.url}/{enc}?i=x", stream=True)
            assert json.loads("".join([t async for t in r.aiter_text()])) == BEKLENEN
    run(main())


@pytest.mark.parametrize("enc", ["br", "zstd"])
def test_async_h1_eksik_acici_acik_hata(sv, acici_yok, enc):
    async def main():
        async with AsyncSession(verify=sv.ca_path, timeout=10) as s:
            with pytest.raises(MissingDecoderError) as ei:
                await s.get(f"{sv.url}/{enc}?i=x")
            eksik_acici_hatasi(ei, enc)
            r = await s.get(f"{sv.url}/{enc}?i=x", stream=True)
            with pytest.raises(MissingDecoderError):
                [c async for c in r.aiter_bytes()]
            await r.aclose()
            r = await s.get(f"{sv.url}/{enc}?i=x", stream=True)
            with pytest.raises(MissingDecoderError):
                [t async for t in r.aiter_text()]
            await r.aclose()
    run(main())


# --------------------------------------------------------------- HTTP/2
@pytest.mark.parametrize("enc", ["br", "zstd"])
def test_sync_h2_akissiz_ve_akisli(h2sv, ca, enc):
    with Session(impersonate="chrome_131", verify=ca, timeout=10) as s:
        url = f"https://localhost:{h2sv.port}/{enc}"
        r = s.get(url)
        assert r.http_version == "HTTP/2" and r.json() == BEKLENEN
        with s.get(url, stream=True) as r:
            assert json.loads(b"".join(r.iter_bytes())) == BEKLENEN
        with s.get(url, stream=True) as r:
            assert json.loads("".join(r.iter_text(chunk_size=50))) == BEKLENEN


@pytest.mark.parametrize("enc", ["br", "zstd"])
def test_sync_h2_eksik_acici_acik_hata(h2sv, ca, acici_yok, enc):
    with Session(impersonate="chrome_131", verify=ca, timeout=10) as s:
        url = f"https://localhost:{h2sv.port}/{enc}"
        with pytest.raises(MissingDecoderError) as ei:
            s.get(url)
        eksik_acici_hatasi(ei, enc)
        with s.get(url, stream=True) as r:
            with pytest.raises(MissingDecoderError):
                b"".join(r.iter_bytes())


@pytest.mark.parametrize("enc", ["br", "zstd"])
def test_async_h2_akissiz_akisli_ve_eksik_acici(pki, ca, monkeypatch, enc):
    async def main():
        srv, port, conns = await start_h2(pki, _h2_sikistirilmis)
        async with srv:
            async with AsyncSession(impersonate="chrome_131", verify=ca, timeout=10) as s:
                url = f"https://localhost:{port}/{enc}"
                r = await s.get(url)
                assert r.http_version == "HTTP/2" and r.json() == BEKLENEN
                r = await s.get(url, stream=True)
                assert json.loads("".join([t async for t in r.aiter_text()])) == BEKLENEN

                for name in ("brotli", "brotlicffi", "zstandard"):
                    monkeypatch.setitem(sys.modules, name, None)
                with pytest.raises(MissingDecoderError) as ei:
                    await s.get(url)
                eksik_acici_hatasi(ei, enc)
                r = await s.get(url, stream=True)
                with pytest.raises(MissingDecoderError):
                    [c async for c in r.aiter_bytes()]
                await r.aclose()
    run(main())
