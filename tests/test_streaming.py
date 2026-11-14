"""Senkron akış (stream=True) testleri — yerel TLS 1.3 sunucusu (ağsız)."""
import gzip
import time
import tracemalloc

import pytest

from fasthttpc import Session
from fasthttpc.streaming import StreamClosed, StreamConsumed
from saha.yerel_sunucu import YerelSunucu, govde_uret


@pytest.fixture(scope="module")
def sv():
    with YerelSunucu() as s:
        yield s


@pytest.fixture
def sess(sv):
    with Session(verify=sv.ca_path, timeout=5, max_connections=2) as s:
        yield s


def _baglanti(sv):
    return sv.kabul_edilen_baglanti


def test_stream_govdeyi_okumadan_doner(sv, sess):
    t = time.monotonic()
    r = sess.get(sv.url + "/lines?n=4&d=0.3", stream=True)
    assert time.monotonic() - t < 0.25          # gövde 1.2 sn sürer
    assert r.status_code == 200 and not r.is_stream_consumed
    r.close()


def test_iter_content_bayt_butunlugu_ve_havuz_geri_doner(sv, sess):
    once = _baglanti(sv)
    for _ in range(3):
        with sess.get(sv.url + "/big?n=300000", stream=True) as r:
            data = b"".join(r.iter_content(chunk_size=4096))
        assert data == govde_uret(300000)
    assert _baglanti(sv) - once <= 1           # hepsi aynı bağlantı (havuza döndü)


def test_iter_content_chunk_boyutu(sv, sess):
    with sess.get(sv.url + "/big?n=1000", stream=True) as r:
        parts = list(r.iter_content(chunk_size=300))
    assert [len(p) for p in parts] == [300, 300, 300, 100]


def test_chunked_akis(sv, sess):
    with sess.get(sv.url + "/chunked?i=Z", stream=True) as r:
        assert b"".join(r.iter_bytes()) == b"parca1-parca2-Z"
    assert sess.get(sv.url + "/id?i=ok").content == b"ok"


def test_yarida_kapatinca_h1_baglantisi_yeniden_kullanilmaz(sv, sess):
    sess.get(sv.url + "/id?i=isin").content
    once = _baglanti(sv)
    r = sess.get(sv.url + "/big?n=5000000", stream=True)
    first = next(r.iter_content(1024))
    assert len(first) == 1024
    r.close()
    assert sess.get(sv.url + "/id?i=sonra").content == b"sonra"
    assert _baglanti(sv) == once + 1            # kapatılan bağlantı havuza girmedi -> yenisi


def test_havuz_slotu_sizmaz(sv, sess):
    for _ in range(6):                          # max_connections=2'den fazla
        r = sess.get(sv.url + "/big?n=200000", stream=True)
        r.close()
    assert sess.get(sv.url + "/id?i=x").content == b"x"


def test_content_kalani_okur_ve_onbellekler(sv, sess):
    r = sess.get(sv.url + "/big?n=50000", stream=True)
    first = next(r.iter_bytes())
    assert r.content == govde_uret(50000)[len(first):]
    assert r.content is r.content
    r.close()


def test_content_tuketilmisken_ve_kapaliyken_hata(sv, sess):
    r = sess.get(sv.url + "/big?n=1000", stream=True)
    list(r.iter_content(500))
    with pytest.raises(StreamConsumed):
        r.content
    r2 = sess.get(sv.url + "/big?n=100000", stream=True)
    r2.close()
    with pytest.raises(StreamClosed):
        r2.content


def test_stream_baglam_yoneticisi_httpx_tarzi(sv, sess):
    with sess.stream("GET", sv.url + "/id?i=abc") as r:
        assert r.text == "abc"
    assert r.is_closed


def test_raw_okunabilir_nesne(sv, sess):
    with sess.get(sv.url + "/big?n=20000", stream=True) as r:
        a = r.raw.read(10)
        b = r.raw.read()
    assert a + b == govde_uret(20000)


def test_gzip_parca_parca_acilir_raw_ham(sv, sess):
    with sess.get(sv.url + "/gzlines?n=200", stream=True) as r:
        text = b"".join(r.iter_content(chunk_size=None))
    assert text == "".join(f"satir-{i}\n" for i in range(200)).encode()
    with sess.get(sv.url + "/gzlines?n=200", stream=True) as r:
        ham = b"".join(r.iter_raw())
    assert gzip.decompress(ham) == text


def test_kesik_govde_stream_yolunda_da_hata(sv, sess):
    r = sess.get(sv.url + "/cut", stream=True)
    with pytest.raises(ConnectionError):
        b"".join(r.iter_bytes())
    assert sess.get(sv.url + "/id?i=x").content == b"x"   # havuz sağlam


def test_close_delimited_akis(sv, sess):
    with sess.get(sv.url + "/http10", stream=True) as r:
        assert b"".join(r.iter_bytes()) == b"http10-govde"
    assert sess.get(sv.url + "/id?i=y").content == b"y"


def test_govdesiz_yanit_stream_modunda_takilmaz(sv, sess):
    r = sess.get(sv.url + "/s204", stream=True)
    assert r.status_code == 204 and r.content == b""
    assert sess.get(sv.url + "/id?i=ok").content == b"ok"


def test_iter_lines_ilk_satir_govde_bitmeden(sv, sess):
    """SSE: sunucu satırları gecikmeli gönderirken ilk satır hemen gelmeli."""
    t0 = time.monotonic()
    zamanlar, satirlar = [], []
    with sess.get(sv.url + "/lines?n=4&d=0.4", stream=True) as r:
        for ln in r.iter_lines():
            zamanlar.append(time.monotonic() - t0)
            satirlar.append(ln)
    assert satirlar == [b"satir-0", b"satir-1", b"satir-2", b"satir-3"]
    assert zamanlar[0] < 0.35                  # gövde ~1.6 sn sürer
    assert zamanlar[-1] > 1.2
    assert zamanlar[1] - zamanlar[0] > 0.25    # satırlar gerçekten ayrı ayrı geldi


def test_iter_lines_decode_unicode_ve_iter_text(sv, sess):
    with sess.get(sv.url + "/chunked?i=Z", stream=True) as r:
        assert list(r.iter_lines(decode_unicode=True)) == ["parca1-parca2-Z"]
    with sess.get(sv.url + "/chunked?i=Z", stream=True) as r:
        assert "".join(r.iter_text()) == "parca1-parca2-Z"


def test_yonlendirme_stream_modunda(sv, sess):
    # 404 yok-yol: yalnızca stream bayrağının normal yanıtı bozmadığını doğrular
    r = sess.get(sv.url + "/yok", stream=True)
    assert r.status_code == 404 and r.content == b"yok"


def test_bellek_sabit_50mb_indirme(sv, sess):
    """50 MB'lık indirmede tracemalloc tepe değeri < 10 MB (200 MB'a ölçeklenir)."""
    n = 50 * 1024 * 1024
    for yol in ("/gen", "/chunkgen"):
        tracemalloc.start()
        toplam = 0
        with sess.get(f"{sv.url}{yol}?n={n}", stream=True) as r:
            for c in r.iter_content(chunk_size=65536):
                toplam += len(c)
        _, tepe = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert toplam == n
        assert tepe < 10 * 1024 * 1024, f"{yol}: tepe bellek {tepe / 1e6:.1f} MB"


def test_eski_iter_content_modul_fonksiyonu(sv, sess):
    from fasthttpc.protocol.http2_parser import iter_content
    data = b"".join(iter_content(sess, "GET", sv.url + "/big?n=30000", chunk_size=8192))
    assert data == govde_uret(30000)
    assert sess.get(sv.url + "/id?i=ok").content == b"ok"
