"""Response akış API'si + artımlı decoder birim testleri (G/Ç yok)."""
import asyncio
import gzip
import zlib

import pytest

from fasthttpc.models.response import Response
from fasthttpc.streaming import (
    DecodeError, IncrementalDecoder, LineSplitter, Rechunker, ResponseNotRead,
)


class Kaynak:
    def __init__(self, parcalar):
        self.p = list(parcalar)
        self.kapali = False

    def read_chunk(self):
        return self.p.pop(0) if self.p else b""

    def close(self):
        self.kapali = True


def parcala(b, n):
    return [b[i:i + n] for i in range(0, len(b), n)]


METIN = ("merhaba dünya\nikinci satır\r\nüçüncü\rson" * 40).encode()


@pytest.mark.parametrize("enc,sikistir", [
    ("gzip", gzip.compress),
    ("deflate", zlib.compress),
    ("deflate", lambda b: zlib.compress(b)[2:-4]),          # ham deflate
    ("gzip, identity", gzip.compress),
])
def test_decoder_zlib_aileleri(enc, sikistir):
    d = IncrementalDecoder(enc)
    z = sikistir(METIN)
    out = b"".join(d.decode(c) for c in parcala(z, 5)) + d.flush()
    assert out == METIN


def test_decoder_br():
    br = pytest.importorskip("brotli")
    d = IncrementalDecoder("br")
    assert b"".join(d.decode(c) for c in parcala(br.compress(METIN), 7)) + d.flush() == METIN


def test_decoder_zstd():
    zstd = pytest.importorskip("zstandard")
    d = IncrementalDecoder("zstd")
    z = zstd.ZstdCompressor().compress(METIN)
    assert b"".join(d.decode(c) for c in parcala(z, 7)) + d.flush() == METIN


def test_decoder_zincir_ve_bozuk_veri():
    z = gzip.compress(zlib.compress(METIN))               # önce deflate, sonra gzip uygulanmış
    d = IncrementalDecoder("deflate, gzip")
    assert b"".join(d.decode(c) for c in parcala(z, 9)) + d.flush() == METIN
    d = IncrementalDecoder("gzip")
    assert d.decode(b"gzip-degil") == b"gzip-degil"       # ilk parça: ham geçiş (akışsız yol gibi)
    d = IncrementalDecoder("gzip")
    z = gzip.compress(b"a" * 1000)
    d.decode(z[:20])
    with pytest.raises(DecodeError):
        d.decode(b"\x00" * 50 + b"bozuk" * 20)


def test_satir_bolucu_kenar_durumlari():
    sp = LineSplitter()
    out = sp.feed(b"a\r") + sp.feed(b"\nb\n") + sp.feed(b"c") + sp.feed(b"d\re") + sp.flush()
    assert out == [b"a", b"b", b"cd", b"e"]
    sp = LineSplitter(b"||")
    assert sp.feed(b"x||y|") + sp.feed(b"|z") + sp.flush() == [b"x", b"y", b"z"]
    assert LineSplitter().feed(b"") == []


def test_rechunker():
    rc = Rechunker(4)
    assert rc.feed(b"abcdefghi") == [b"abcd", b"efgh"] and rc.flush() == [b"i"]


def test_iter_lines_gzip_parca_parca():
    z = gzip.compress("bir\niki\nüç\n".encode())
    r = Response(200, {"content-encoding": "gzip"}, stream=Kaynak(parcala(z, 3)))
    assert list(r.iter_lines()) == [b"bir", b"iki", "üç".encode()]


def test_iter_text_cok_baytli_karakter_parca_sinirinda():
    ham = ("çğışöü" * 10).encode()
    r = Response(200, {"content-type": "text/plain; charset=utf-8"}, stream=Kaynak(parcala(ham, 1)))
    assert "".join(r.iter_text()) == "çğışöü" * 10
    r = Response(200, {}, stream=Kaynak(parcala(ham, 3)))
    assert list(r.iter_lines(decode_unicode=True)) == ["çğışöü" * 10]


def test_akissiz_yanit_da_iterable_ve_raw():
    r = Response(200, {}, body=b"abcdef")
    assert list(r.iter_content(2)) == [b"ab", b"cd", b"ef"]
    assert list(r.iter_bytes()) == [b"abcdef"] and r.raw.read() == b"abcdef"
    assert list(r.iter_lines()) == [b"abcdef"]
    assert r.is_stream_consumed
    r.close()
    assert r.content == b"abcdef"


def test_content_acilmis_text_json_ve_tek_sefer():
    z = gzip.compress(b'{"a": 1}')
    r = Response(200, {"content-encoding": "gzip"}, stream=Kaynak(parcala(z, 4)))
    assert r.json() == {"a": 1} and r.text == '{"a": 1}'


def test_with_cikisinda_kapanir_ve_sync_asenkron_karismaz():
    k = Kaynak([b"x"])
    with Response(200, {}, stream=k) as r:
        pass
    assert k.kapali and r.is_closed

    class AK:
        async def read_chunk(self):
            return b""
        async def aclose(self): pass
        def close_nowait(self): pass
    r = Response(200, {}, astream=AK())
    with pytest.raises(ResponseNotRead):
        r.content
    with pytest.raises(RuntimeError):
        list(r.iter_bytes())
    assert asyncio.run(r.aread()) == b""


def test_mock_transport_ile_stream_true(monkeypatch):
    from fasthttpc import Session
    from fasthttpc.transport.mock import MockTransport
    t = MockTransport(lambda req: Response(200, {"content-type": "text/plain"}, body=b"a\nb\n"))
    with Session(transport=t) as s:
        with s.get("https://x.test/", stream=True) as r:
            assert list(r.iter_lines()) == [b"a", b"b"]
