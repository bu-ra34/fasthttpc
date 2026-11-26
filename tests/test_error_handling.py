"""except-pass temizliği: beklenen hatalar daraltıldı ve loglanıyor, gerisi yükseliyor."""
import logging

import pytest

from fasthttpc.protocol import http1_parser, http2_parser
from fasthttpc.protocol.http1_parser import HTTP1Parser
from fasthttpc.protocol.http2_parser import StreamingDecompressor


def test_bozuk_brotli_ham_veri_doner_ve_loglanir(caplog):
    if not http1_parser._BROTLI:
        pytest.skip("brotli yok")
    with caplog.at_level(logging.WARNING, logger="fasthttpc"):
        assert HTTP1Parser._decompress(b"bozuk-veri", "br") == b"bozuk-veri"
    assert any("Brotli" in r.message for r in caplog.records)


def test_brotli_beklenmeyen_hata_yukselir(monkeypatch):
    if not http1_parser._BROTLI:
        pytest.skip("brotli yok")

    # _decompress artık ortak (çıktısı sınırlı) artımlı açıcıyı kullanır: brotli'nin
    # Decompressor'ı patlarsa beklenmeyen hata yine yutulmadan yükselmeli.
    class Patlak:
        def process(self, data, output_buffer_limit=None):
            raise RuntimeError("programlama hatası")

        def can_accept_more_data(self):
            return True

    monkeypatch.setattr(http1_parser._brotli, "Decompressor", Patlak)
    with pytest.raises(RuntimeError):
        HTTP1Parser._decompress(b"x", "br")


def test_akis_bozuk_gzip_ham_chunk_doner_ve_loglanir(caplog):
    d = StreamingDecompressor("gzip")
    with caplog.at_level(logging.WARNING, logger="fasthttpc"):
        assert d.decompress(b"gzip-degil") == b"gzip-degil"
    assert any("açılamadı" in r.message for r in caplog.records)


def test_akis_beklenmeyen_hata_yukselir(monkeypatch):
    from fasthttpc import streaming

    class Patlak:
        def decompress(self, chunk, max_length=0):
            raise RuntimeError("beklenmeyen")

    # StreamingDecompressor artık streaming.IncrementalDecoder'ı sarar: açıcı nesnesi
    # beklenmeyen bir hata verirse yutulmaz.
    monkeypatch.setattr(streaming.zlib, "decompressobj", lambda *a: Patlak())
    d = StreamingDecompressor("gzip")
    with pytest.raises(RuntimeError):
        d.decompress(b"x")


def test_websocket_close_baglanti_kopuksa_sessiz_ama_beklenmeyen_hata_yukselir():
    from fasthttpc.protocol.http2_parser import WebSocketConnection

    class Conn:
        def close(self):
            pass

    class KopukWire:
        def send_record(self, data, **kw):
            raise BrokenPipeError("koptu")

    ws = WebSocketConnection(Conn(), "ws://x/", KopukWire())
    ws.close()  # OSError yutulur

    class HataliWire:
        def send_record(self, data, **kw):
            raise TypeError("bug")

    ws2 = WebSocketConnection(Conn(), "ws://x/", HataliWire())
    with pytest.raises(TypeError):
        ws2.close()


def test_kalan_genis_except_bloklari_yok():
    """Denetlenen dosyalarda çıplak except veya 'except Exception: pass' kalmadı."""
    import inspect, re
    from fasthttpc import session, async_session
    for mod in (session, async_session, http1_parser, http2_parser):
        src = inspect.getsource(mod)
        assert not re.search(r"except\s*:", src), mod.__name__
        assert not re.search(r"except Exception(\s+as\s+\w+)?:\s*\n\s*(pass|return)", src), mod.__name__
