"""Senkron ``Session``'ın birden çok iş parçacığından aynı anda kullanımı (yerel sunucular).

Doğrulananlar: her yanıt KENDİ isteğine ait (istek başına eşsiz yol/gövde), eşzamanlı
konan çerezlerin hepsi kavanozda, havuz sınırı (``max_connections``) hiç aşılmıyor, bir
bağlantı aynı anda tek isteğe hizmet ediyor (HTTP/2'de bağlantı başına tek açık stream),
istek düzeyi zaman aşımı iş parçacıkları arasında sızmıyor ve ``close()`` başka iş
parçacıkları istek ortasındayken belirlenimli davranıyor.

Testler zamanlamaya dayanmaz: eşzamanlılık noktaları olay/bariyerle kurulur; süre
ölçümleri yalnızca geniş paylı alt/üst sınırlarla ve ``time.perf_counter`` ile yapılır.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from fasthttpc import DigestAuth, Limits, MockTransport, Response, Session, Timeout
from fasthttpc.cache import CacheEntry
from fasthttpc.models.request import Request
from fasthttpc.session import _from_cache
from fasthttpc.transport.connection_pool import ConnectionPool, HTTPConnection
from fasthttpc.models.urls import URL
from plain_servers import Req, ThreadedHTTPServer, ok
from saha.yerel_sunucu import YerelSunucu
from thread_servers import H2ThreadServer

THREADS = 16
PER_THREAD = 20
MAX_CONN = 4


class _CountingH1(YerelSunucu):
    """YerelSunucu + aynı anda işlenen istek sayısının tepe değeri."""

    def __init__(self):
        self.active = 0
        self.peak_active = 0
        super().__init__()

    def _yanit(self, s, *a):
        with self._kilit:
            self.active += 1
            self.peak_active = max(self.peak_active, self.active)
        try:
            return super()._yanit(s, *a)
        finally:
            with self._kilit:
                self.active -= 1


@pytest.fixture(scope="module")
def h1():
    with _CountingH1() as s:
        yield s


@pytest.fixture
def h2():
    with H2ThreadServer() as s:
        yield s


def _lease_counter(pool):
    """Havuzun acquire/release'ini sarar: aynı anda kirada olan bağlantıların tepe değeri."""
    st = {"cur": 0, "peak": 0}
    lock = threading.Lock()
    acquire, release = pool.acquire, pool.release

    def acq(*a, **kw):
        c = acquire(*a, **kw)
        with lock:
            st["cur"] += 1
            st["peak"] = max(st["peak"], st["cur"])
        return c

    def rel(c):
        if c.leased:                 # çift iade sayılmaz (havuz da saymaz)
            with lock:
                st["cur"] -= 1
        release(c)

    pool.acquire, pool.release = acq, rel
    return st


def _worker(s: Session, base: str, tid: int) -> "list[str]":
    """Karışık istekler; her biri eşsiz anahtar taşır ve yanıt ona göre doğrulanır."""
    done = []
    for n in range(PER_THREAD):
        key = f"t{tid}-{n}"
        kind = n % 4
        if kind == 0:
            r = s.get(f"{base}/id?i={key}")
            expect = key.encode()
        elif kind == 1:
            body = f"-govde-{key}-".encode() * 50
            r = s.post(f"{base}/id?i={key}", data=body)
            expect = key.encode() + body
        elif kind == 2:
            with s.stream("GET", f"{base}/id?i={key}") as r:
                got = b"".join(r.iter_bytes())
            assert got == key.encode(), (key, got)
            done.append(key)
            continue
        else:
            ck = f"{tid}_{n}"
            r = s.get(f"{base}/setcookie?i={ck}")
            expect = ck.encode()
        assert r.status_code == 200, (key, r.status_code)
        assert r.content == expect, (key, r.content[:60])
        done.append(key)
    return done


def _run_stress(s: Session, base: str) -> None:
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futs = [ex.submit(_worker, s, base, t) for t in range(THREADS)]
        results = [f.result() for f in futs]        # ilk istisna burada yükselir
    assert sum(len(r) for r in results) == THREADS * PER_THREAD
    # Eşzamanlı konan bütün çerezler kavanozda (kind == 3 olan her istek bir çerez).
    jar = s.cookies
    want = {f"c{t}_{n}": f"v{t}_{n}" for t in range(THREADS) for n in range(3, PER_THREAD, 4)}
    assert {k: jar.get(k) for k in want} == want


def _assert_pool_drained(s: Session, limit: int) -> None:
    stats = s.pool_stats()
    assert all(v["in_use"] == 0 for v in stats.values()), stats     # kiralık bağlantı sızmadı
    assert sum(v["idle"] for v in stats.values()) <= limit, stats


# ------------------------------------------------------------------ stres testleri
def test_thread_stres_h1_tls(h1):
    with Session(verify=h1.ca_path, timeout=30, max_connections=MAX_CONN) as s:
        leases = _lease_counter(s.pool)
        accepted0 = h1.kabul_edilen_baglanti
        h1.peak_active = 0
        _run_stress(s, h1.url)
        assert 1 <= leases["peak"] <= MAX_CONN
        assert h1.peak_active <= MAX_CONN
        # keep-alive: hiçbir bağlantı düşmedi, sınırdan fazla bağlantı hiç açılmadı
        assert h1.kabul_edilen_baglanti - accepted0 <= MAX_CONN
        _assert_pool_drained(s, MAX_CONN)


def test_thread_stres_h2(h2):
    limit = 3
    with Session(verify=h2.ca_path, timeout=30, max_connections=limit) as s:
        leases = _lease_counter(s.pool)
        _run_stress(s, h2.base)
        assert 1 <= leases["peak"] <= limit
        assert h2.accepted <= limit and h2.peak_open <= limit
        # senkron tarafta bir HTTP/2 bağlantısı aynı anda tek isteğe (tek stream'e) aittir
        assert h2.max_streams_per_conn == 1
        assert h2.requests == THREADS * PER_THREAD
        assert not h2.errors
        _assert_pool_drained(s, limit)


def _plain_handler(r: Req) -> bytes:
    path, _, query = r.target.partition("?")
    i = query.partition("=")[2]
    if path == "/setcookie":
        return ok(i.encode(), f"Set-Cookie: c{i}=v{i}; Path=/\r\n".encode())
    return ok(i.encode() + (r.body if r.method == "POST" else b""))


def test_thread_stres_duz_http():
    with ThreadedHTTPServer(_plain_handler) as srv:
        with Session(timeout=30, max_connections=MAX_CONN) as s:
            leases = _lease_counter(s.pool)
            _run_stress(s, srv.base)
            assert 1 <= leases["peak"] <= MAX_CONN
            assert srv.conns <= MAX_CONN
            assert not srv.errors
            _assert_pool_drained(s, MAX_CONN)


def test_thread_h2_tek_baglanti_siraya_girer(h2):
    """max_connections=1: iş parçacıkları tek h2 bağlantısını SIRAYLA kullanır (bekler),
    ikinci bağlantı açılmaz, kilitlenme olmaz."""
    with Session(verify=h2.ca_path, timeout=30, limits=Limits(max_connections=1)) as s:
        def one(i):
            return s.get(f"{h2.base}/id?i=k{i}").content == f"k{i}".encode()
        with ThreadPoolExecutor(max_workers=8) as ex:
            assert all(ex.map(one, range(64)))
        assert h2.accepted == 1 and h2.max_streams_per_conn == 1


def test_thread_dolu_havuz_bekleme_suresiyle_sinirli(h2):
    """Kiradaki tek bağlantı (açık akış) bırakılmazsa başka iş parçacığı Timeout.pool kadar
    bekleyip TimeoutError alır (kilitlenmez); bağlantı bırakılınca istek geçer."""
    with Session(verify=h2.ca_path, timeout=Timeout(30, pool=0.3), max_connections=1) as s:
        r = s.get(f"{h2.base}/id?i=akis", stream=True)
        err: list[BaseException] = []

        def other():
            try:
                s.get(f"{h2.base}/id?i=x")
            except BaseException as e:  # noqa: BLE001 - testte toplanır
                err.append(e)
        t = threading.Thread(target=other)
        t.start()
        t.join(30)
        assert not t.is_alive()
        assert len(err) == 1 and isinstance(err[0], TimeoutError) and "havuzu" in str(err[0])
        assert r.read() == b"akis"
        r.close()
        assert s.get(f"{h2.base}/id?i=y").content == b"y"


# ------------------------------------------------------- istek düzeyi ayarlar sızmaz
@pytest.mark.parametrize("kind", ["h1", "h2"])
def test_thread_istek_timeout_is_parcaciklari_arasinda_sizmaz(kind, h1, h2):
    """Aynı anda: A iş parçacıkları ``timeout=5`` ile 1 sn süren isteği BAŞARIR, B iş
    parçacıkları ``timeout=0.3`` ile aynı isteği ZAMAN AŞIMIYLA bitirir."""
    base, ca = (h1.url, h1.ca_path) if kind == "h1" else (h2.base, h2.ca_path)
    with Session(verify=ca, timeout=30, max_connections=8) as s:
        start = threading.Barrier(8)

        def run(i):
            start.wait(10)
            if i % 2 == 0:
                return s.get(f"{base}/sleep?d=1&i=a{i}", timeout=Timeout(5)).content
            try:
                s.get(f"{base}/sleep?d=1&i=b{i}", timeout=0.3)
            except TimeoutError:
                return "timeout"
            return "zaman aşımı olmadı"

        with ThreadPoolExecutor(max_workers=8) as ex:
            out = list(ex.map(run, range(8)))
        assert out == [f"a{i}".encode() if i % 2 == 0 else "timeout" for i in range(8)]


# ------------------------------------------------------------------ close()
def test_thread_close_istek_ortasinda_belirlenimli(h2):
    """max_connections=2, 4 iş parçacığı: ikisi bağlantısını almış ve sunucuda beklerken
    close() çağrılır. close() onları BEKLEMEDEN döner; o ikisi başarıyla biter, bağlantı
    bekleyen ya da sonra gelen her istek RuntimeError alır; hiçbir bağlantı açık kalmaz."""
    s = Session(verify=h2.ca_path, timeout=30, max_connections=2)
    s.get(f"{h2.base}/id?i=isinma")                  # bir boş bağlantı havuzda
    conns: list[HTTPConnection] = []
    acquire = s.pool.acquire

    def acq(*a, **kw):
        c = acquire(*a, **kw)
        conns.append(c)
        return c
    s.pool.acquire = acq

    finished = threading.Event()
    results: dict[int, object] = {}

    def run(i):
        try:
            results[i] = s.get(f"{h2.base}/sleep?d=1.5&i=r{i}").content
        except BaseException as e:  # noqa: BLE001 - testte toplanır
            results[i] = e
        finally:
            if len(results) == 4:
                finished.set()

    req0 = h2.requests
    threads = [threading.Thread(target=run, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    # İki slot da dolu: iki iş parçacığı bağlantısını aldı (kiralar 1,5 sn'lik yanıttan önce
    # bırakılmaz, bu yüzden sayı burada tam 2'dir); diğer ikisi slot bekliyor ya da başlamadı.
    got_two = threading.Event()
    for _ in range(6000):
        if len(conns) >= 2:
            got_two.set()
            break
        got_two.wait(0.005)
    assert got_two.is_set() and len(conns) == 2
    s.close()
    assert not finished.is_set()                      # close() süren istekleri beklemedi
    for t in threads:
        t.join(30)
    oks = [v for v in results.values() if isinstance(v, bytes)]
    errs = [v for v in results.values() if not isinstance(v, bytes)]
    assert len(oks) == 2 and all(v.startswith(b"r") for v in oks)
    assert len(errs) == 2 and all(isinstance(e, RuntimeError) for e in errs), errs
    assert h2.requests - req0 == 2
    assert all(c.is_closed for c in conns)            # kullanılan bağlantılar kapatıldı
    assert s.pool.stats() == {}                       # boşta ya da kirada bağlantı yok
    with pytest.raises(RuntimeError, match="kapatıldı"):
        s.get(f"{h2.base}/id?i=sonra")
    s.close()                                         # idempotent


def test_thread_close_akis_okunabilir_sonra_baglanti_kapanir(h1):
    s = Session(verify=h1.ca_path, timeout=30)
    r = s.get(f"{h1.url}/id?i=akis-govdesi", stream=True)
    conn = r._stream._conn
    s.close()
    assert not conn.is_closed                         # süren alışveriş kesilmedi
    assert r.read() == b"akis-govdesi"
    assert conn.is_closed                             # bitince havuza dönmedi, kapandı
    assert s.pool.stats() == {}


# ------------------------------------------------------------------ havuz birimleri
def test_thread_havuz_cift_release_siniri_bozmaz():
    pool = ConnectionPool(max_connections=1)
    c = HTTPConnection(("https", "a.test", 443))
    c.is_closed = False
    sem = pool._get_semaphore(c.pool_key)
    assert sem.acquire(blocking=False)
    pool.release(c)
    pool.release(c)                                    # ikinci iade: semaphore artmamalı
    assert sem.acquire(blocking=False)
    assert not sem.acquire(blocking=False)             # sınır hâlâ 1


def test_thread_havuz_close_bekleyeni_runtimeerror_ile_uyandirir(monkeypatch):
    pool = ConnectionPool(max_connections=1, timeout=30)
    monkeypatch.setattr(HTTPConnection, "connect", lambda self, **kw: setattr(self, "is_closed", False))
    url = URL("https://a.test/")
    held = pool.acquire(url)
    out: list[BaseException] = []
    waiting = threading.Event()

    def waiter():
        waiting.set()
        try:
            pool.acquire(url)
        except BaseException as e:  # noqa: BLE001
            out.append(e)
    t = threading.Thread(target=waiter)
    t.start()
    waiting.wait(5)
    drained = []
    pool.close(on_drained=lambda: drained.append(True))
    assert drained == []                               # kirada bağlantı var
    pool.release(held)                                 # bekleyen uyanır -> RuntimeError
    t.join(10)
    assert len(out) == 1 and isinstance(out[0], RuntimeError)
    assert drained == [True] and held.is_closed
    with pytest.raises(RuntimeError):
        pool.acquire(url)


def test_thread_close_mtls_anahtarini_son_iadede_birakir():
    class _Cert:
        closed = 0

        def close(self):
            _Cert.closed += 1
    s = Session()
    s.client_cert, s._owns_cert = _Cert(), True        # type: ignore[assignment]
    c = HTTPConnection(("https", "a.test", 443))
    c.is_closed = False
    s.pool._in_use.add(c)
    s.close()
    assert _Cert.closed == 0                           # süren el sıkışması anahtarsız kalmaz
    s.pool.release(c)
    assert _Cert.closed == 1


# ------------------------------------------------------------------ paylaşılan durum
def test_thread_digest_nc_esiz():
    """Paylaşılan DigestAuth: eşzamanlı ilk istekler aynı challenge'ı alsa da her
    (nonce, nc) çifti eşsizdir (sayaç sıfırlanıp tekrar kullanılmaz)."""
    seen: list[str] = []
    lock = threading.Lock()

    def handler(req: Request) -> Response:
        h = req.headers.get("authorization", "")
        if not h.startswith("Digest"):
            return Response(401, headers={"WWW-Authenticate":
                                          'Digest realm="r", nonce="n1", qop="auth"'})
        nc = h.split("nc=")[1].split(",")[0]
        with lock:
            seen.append(nc)
        return Response(200, body=b"ok")

    with Session(transport=MockTransport(handler), auth=DigestAuth("u", "p")) as s:
        start = threading.Barrier(THREADS)

        def run(_):
            start.wait(10)
            return [s.get("https://d.test/x").status_code for _ in range(10)]
        with ThreadPoolExecutor(max_workers=THREADS) as ex:
            codes = [c for r in ex.map(run, range(THREADS)) for c in r]
    assert codes == [200] * THREADS * 10
    assert len(seen) == len(set(seen)) == THREADS * 10


def test_thread_onbellek_304_kopyasi_paylasilmaz():
    orig = Response(200, headers={"ETag": '"v1"'}, body=b"govde")
    entry = CacheEntry(orig, '"v1"', None, 0.0)
    a = _from_cache(entry, Request("GET", "https://c.test/a"), None)
    b = _from_cache(entry, Request("GET", "https://c.test/b"), None)
    assert a is not b and a is not orig
    assert str(a.request.url).endswith("/a") and str(b.request.url).endswith("/b")
    assert orig.request is None and a.content == b.content == b"govde"
    a.headers["x"] = "1"
    assert "x" not in orig.headers and "x" not in b.headers
