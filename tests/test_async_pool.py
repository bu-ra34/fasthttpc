"""AsyncSession HTTP/1.1 keep-alive bağlantı havuzu (yerel sunucular, ağsız)."""
import asyncio
import ssl
import time

import pytest
from cryptography.hazmat.primitives import serialization

from fasthttpc import AsyncSession, Limits, Timeout
from fasthttpc import _backend as B

from netutil import start_dual
from async_fakes import AsyncFakeProxy, start_tls13
from tls13_fakeserver import PKI, http_responder


@pytest.fixture(scope="module")
def pki():
    return PKI("localhost")


@pytest.fixture
def ca(pki, tmp_path):
    p = tmp_path / "ca.pem"
    p.write_bytes(pki.ca_pem())
    return str(p)


def run(coro, timeout=30):
    return asyncio.run(asyncio.wait_for(coro, timeout))


def ok(body=b"ok", extra=b""):
    return b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n%s\r\n" % (len(body), extra) + body


class H1Server:
    """stdlib ssl keep-alive HTTP/1.1 sunucusu. ``script(conn_no, req_no, method, path, body)``
    -> bayt (yanıt) | (bayt,) (yanıttan sonra kapat) | None (yanıtsız kapat) | "hang"."""

    def __init__(self, pki, tmp_path, script=None):
        self.script = script or (lambda c, r, m, p, b: ok(p.encode()))
        self.conns = 0
        self.open = 0
        self.requests = []           # (conn_no, method, path)
        cert, key = tmp_path / "leaf.pem", tmp_path / "leaf.key"
        cert.write_bytes(pki.cert.public_bytes(serialization.Encoding.PEM))
        key.write_bytes(pki.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(cert), str(key))
        self.ctx.set_alpn_protocols(["http/1.1"])

    async def start(self):
        self.server = await start_dual(self._on_conn, ssl=self.ctx)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self):
        await self.server.aclose()

    @property
    def base(self):
        return f"https://localhost:{self.port}"

    async def _on_conn(self, r, w):
        self.conns += 1
        no = self.conns
        self.open += 1
        try:
            req_no = 0
            while True:
                head = await r.readuntil(b"\r\n\r\n")
                lines = head.decode().split("\r\n")
                method, path, _ = lines[0].split(" ")
                n = 0
                for ln in lines[1:]:
                    if ln.lower().startswith("content-length:"):
                        n = int(ln.split(":")[1])
                body = await r.readexactly(n) if n else b""
                req_no += 1
                self.requests.append((no, method, path))
                out = self.script(no, req_no, method, path, body)
                if out is None:
                    break
                if out == "hang":
                    await asyncio.sleep(30)
                    break
                close_after = isinstance(out, tuple)
                if close_after:
                    out = out[0]
                w.write(out)
                await w.drain()
                if close_after:
                    break
        except (OSError, asyncio.IncompleteReadError, asyncio.CancelledError):
            pass
        finally:
            self.open -= 1
            w.close()


def sess(ca, **kw):
    kw.setdefault("impersonate", None)
    kw.setdefault("timeout", Timeout(5, read=2))
    return AsyncSession(verify=ca, **kw)


# ------------------------------------------------------------------ yeniden kullanım
def test_yeniden_kullanim_stdlib(pki, ca, tmp_path):
    async def main():
        srv = await H1Server(pki, tmp_path).start()
        async with sess(ca) as s:
            for i in range(5):
                r = await s.get(f"{srv.base}/{i}")
                assert r.body == f"/{i}".encode() and r.http_version == "HTTP/1.1"
            assert srv.conns == 1 and len(srv.requests) == 5
        await asyncio.sleep(0.05)
        assert srv.open == 0                       # close() boştaki bağlantıyı kapattı
        await srv.stop()
    run(main())


def test_yeniden_kullanim_impersonate_tek_tcp_baglantisi(pki, ca):
    async def main():
        server, port, servers = await start_tls13(pki, http_responder(b"imp"), alpn="http/1.1")
        async with server:
            async with AsyncSession(impersonate="chrome_131", verify=ca, timeout=5) as s:
                for _ in range(5):
                    assert (await s.get(f"https://localhost:{port}/")).body == b"imp"
                assert len(servers) == 1
                assert len(servers[0].requests) == 5
    run(main())


def test_anahtar_host_port_tls_yolu_ayri(pki, ca, tmp_path):
    async def main():
        a = await H1Server(pki, tmp_path).start()
        b = await H1Server(pki, tmp_path).start()
        async with sess(ca) as s:
            for _ in range(2):
                await s.get(f"{a.base}/x")
                await s.get(f"{b.base}/x")
            assert a.conns == 1 and b.conns == 1
        await a.stop()
        await b.stop()
    run(main())


def test_proxy_anahtarli_havuz(pki, ca, tmp_path):
    async def main():
        srv = await H1Server(pki, tmp_path).start()
        p = await AsyncFakeProxy("http", upstream_port=srv.port).start()
        async with sess(ca, proxy=p.url) as s:
            for _ in range(3):
                assert (await s.get("https://localhost/q")).body == b"/q"
            assert p.connections == 1 and srv.conns == 1
        await p.stop()
        await srv.stop()
    run(main())


# ------------------------------------------------------------------ yeniden kullanılmayanlar
CLOSERS = {
    "connection-close": lambda p: (ok(p.encode(), b"Connection: close\r\n"),),
    "http10-kapanis": lambda p: (b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n" % len(p) + p.encode(),),
    "eof-cercevesi": lambda p: (b"HTTP/1.1 200 OK\r\n\r\n" + p.encode(),),
    "connection-close-sunucu-acik": lambda p: ok(p.encode(), b"Connection: close\r\n"),
}


@pytest.mark.parametrize("kind", list(CLOSERS))
def test_close_sonrasi_slot_sizintisi_yok(kind, pki, ca, tmp_path):
    def script(c, r, m, p, b):
        return CLOSERS[kind](p)

    async def main():
        srv = await H1Server(pki, tmp_path, script).start()
        s = sess(ca, limits=Limits(max_connections=1), timeout=Timeout(5, read=3, pool=1))
        t = time.monotonic()
        for i in range(10):
            r = await s.get(f"{srv.base}/{i}")
            assert r.body == f"/{i}".encode()
        assert s._sem._value == 1
        assert srv.conns == 10                # hiçbiri havuza dönmedi
        assert not s._idle
        assert time.monotonic() - t < 15
        await s.close()
        await srv.stop()
    run(main())


def test_hata_sonrasi_baglanti_havuza_donmez_slot_serbest(pki, ca, tmp_path):
    def script(c, r, m, p, b):
        if p == "/kes":                       # gövde eksik: Content-Length 100, 3 bayt
            return b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc"
        return ok(p.encode())

    async def main():
        srv = await H1Server(pki, tmp_path, script).start()
        async with sess(ca, limits=Limits(max_connections=1),
                        timeout=Timeout(5, read=1, pool=1)) as s:
            assert (await s.get(f"{srv.base}/a")).body == b"/a"
            with pytest.raises((ConnectionResetError, asyncio.TimeoutError)):
                await s.get(f"{srv.base}/kes")
            assert s._sem._value == 1
            assert (await s.get(f"{srv.base}/b")).body == b"/b"
            assert srv.conns == 2             # bozuk bağlantı havuza dönmedi
    run(main())


def test_istek_connection_close_ve_artik_veri(pki, ca, tmp_path):
    def script(c, r, m, p, b):
        if p == "/fazla":                     # gövdeden sonra fazladan bayt
            return ok(b"x") + b"HTTP/1.1 200 OK\r\n\r\n"
        return ok(p.encode())

    async def main():
        srv = await H1Server(pki, tmp_path, script).start()
        async with sess(ca) as s:
            await s.get(f"{srv.base}/a", headers={"Connection": "close"})
            await s.get(f"{srv.base}/b")
            assert srv.conns == 2
            await s.get(f"{srv.base}/fazla")
            await s.get(f"{srv.base}/c")
            assert srv.conns == 3             # artık veri olan bağlantı kullanılmadı
    run(main())


def test_chunked_trailer_sonrasi_yeniden_kullanim(pki, ca, tmp_path):
    def script(c, r, m, p, b):
        return (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhello\r\n0\r\nX-T: 1\r\n\r\n")

    async def main():
        srv = await H1Server(pki, tmp_path, script).start()
        async with sess(ca) as s:
            for _ in range(3):
                assert (await s.get(f"{srv.base}/")).body == b"hello"
            assert srv.conns == 1
    run(main())


def test_head_204_sonrasi_yeniden_kullanim(pki, ca, tmp_path):
    def script(c, r, m, p, b):
        if m == "HEAD":
            return b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n"
        if p == "/204":
            return b"HTTP/1.1 204 No Content\r\n\r\n"
        return ok(p.encode())

    async def main():
        srv = await H1Server(pki, tmp_path, script).start()
        async with sess(ca) as s:
            assert (await s.head(f"{srv.base}/h")).body == b""
            assert (await s.get(f"{srv.base}/204")).status_code == 204
            assert (await s.get(f"{srv.base}/z")).body == b"/z"
            assert srv.conns == 1
    run(main())


# ------------------------------------------------------------------ bayat bağlantı
def test_bayat_baglanti_bir_kez_yeniden_denenir(pki, ca, tmp_path):
    def script(c, r, m, p, b):
        if c == 1 and r == 2:
            return None                       # yeniden kullanılan bağlantıda yanıtsız kapat
        return ok(p.encode())

    async def main():
        srv = await H1Server(pki, tmp_path, script).start()
        async with sess(ca) as s:
            assert (await s.get(f"{srv.base}/1")).body == b"/1"
            assert (await s.get(f"{srv.base}/2")).body == b"/2"   # bayat -> yeni bağlantı
            assert srv.conns == 2
            assert s._sem._value == s.limits.max_connections
        await srv.stop()
    run(main())


def test_bayat_baglanti_surekli_bozuksa_ikinci_hata_yukselir(pki, ca, tmp_path):
    def script(c, r, m, p, b):
        return ok(b"1") if r == 1 and p == "/ilk" else None

    async def main():
        srv = await H1Server(pki, tmp_path, script).start()
        async with sess(ca, limits=Limits(max_connections=1)) as s:
            await s.get(f"{srv.base}/ilk")
            with pytest.raises(ConnectionError):
                await s.get(f"{srv.base}/ikinci")
            # bir yeniden deneme (toplam 2 deneme), sonsuz döngü yok
            assert [x for x in srv.requests if x[2] == "/ikinci"].__len__() == 2
            assert s._sem._value == 1
    run(main())


def test_post_yarim_yanit_sonrasi_cift_gonderilmez(pki, ca, tmp_path):
    def script(c, r, m, p, b):
        if r == 2:
            return (b"HTTP/1.1 200 OK\r\nContent-Len",)   # yarım yanıt, sonra kapanış
        return ok(b"1")

    async def main():
        srv = await H1Server(pki, tmp_path, script).start()
        async with sess(ca) as s:
            await s.get(f"{srv.base}/a")
            with pytest.raises(ConnectionError):
                await s.post(f"{srv.base}/p", data=b"veri")
            assert [m for _, m, _ in srv.requests].count("POST") == 1
    run(main())


def test_post_zaman_asimi_sonrasi_cift_gonderilmez(pki, ca, tmp_path):
    def script(c, r, m, p, b):
        return "hang" if r == 2 else ok(b"1")

    async def main():
        srv = await H1Server(pki, tmp_path, script).start()
        async with sess(ca, timeout=Timeout(5, read=0.3)) as s:
            await s.get(f"{srv.base}/a")
            with pytest.raises(asyncio.TimeoutError):
                await s.post(f"{srv.base}/p", data=b"veri")
            assert [m for _, m, _ in srv.requests].count("POST") == 1
            assert s._sem._value == s.limits.max_connections
        await srv.stop()
    run(main())


def test_yeni_baglantida_hata_yeniden_denenmez(pki, ca, tmp_path):
    async def main():
        srv = await H1Server(pki, tmp_path, lambda *a: None).start()
        async with sess(ca) as s:
            with pytest.raises(ConnectionError):
                await s.get(f"{srv.base}/x")
            assert len(srv.requests) == 1
    run(main())


# ------------------------------------------------------------------ eşzamanlılık
def test_50_eszamanli_gorev_dogru_eslesme(pki, ca, tmp_path):
    import random
    rnd = random.Random(7)
    delays = {i: rnd.random() * 0.05 for i in range(50)}

    async def main():
        srv = await H1Server(pki, tmp_path).start()
        async with sess(ca, limits=Limits(max_connections=8), timeout=Timeout(10, read=5)) as s:
            async def one(i):
                await asyncio.sleep(delays[i])
                if i % 2:
                    r = await s.post(f"{srv.base}/p{i}", data=f"b{i}".encode())
                else:
                    r = await s.get(f"{srv.base}/g{i}")
                return i, r.body
            res = await asyncio.gather(*[one(i) for i in range(50)])
            for i, body in res:
                assert body == (f"/p{i}" if i % 2 else f"/g{i}").encode()
            assert srv.conns <= 8
            assert s._sem._value == 8
        await srv.stop()
    run(main())


def test_50_eszamanli_gorev_impersonate(pki, ca):
    def handler(server):
        buf = b"".join(server.app_in)
        if b"\r\n\r\n" not in buf:
            return b""
        server.app_in.clear()
        path = buf.split(b" ", 2)[1]
        return server.send_app(ok(path))

    async def main():
        server, port, servers = await start_tls13(pki, handler, alpn="http/1.1")
        async with server:
            async with AsyncSession(impersonate="chrome_131", verify=ca, timeout=10,
                                    limits=Limits(max_connections=5)) as s:
                rs = await asyncio.gather(*[s.get(f"https://localhost:{port}/{i}")
                                            for i in range(50)])
                assert [r.body for r in rs] == [f"/{i}".encode() for i in range(50)]
                assert len(servers) <= 5
    run(main())


# ------------------------------------------------------------------ keepalive_expiry / sınırlar
def test_keepalive_expiry(pki, ca, tmp_path):
    async def main():
        srv = await H1Server(pki, tmp_path).start()
        async with sess(ca, limits=Limits(max_connections=2, keepalive_expiry=0.25)) as s:
            await s.get(f"{srv.base}/1")
            await s.get(f"{srv.base}/2")
            assert srv.conns == 1                       # süre dolmadan yeniden kullanıldı
            await asyncio.sleep(0.4)
            await s.get(f"{srv.base}/3")
            assert srv.conns == 2                       # süre doldu: yeni bağlantı
            await asyncio.sleep(0.05)
            assert srv.open == 1                        # eskisi kapatıldı
        await srv.stop()
    run(main())


def test_keepalive_expiry_sifir_ve_none(pki, ca, tmp_path):
    async def main():
        srv = await H1Server(pki, tmp_path).start()
        async with sess(ca, limits=Limits(keepalive_expiry=0)) as s:
            await s.get(f"{srv.base}/1")
            await s.get(f"{srv.base}/2")
            assert srv.conns == 2 and not s._idle       # 0 -> keep-alive yok
        async with sess(ca, limits=Limits(keepalive_expiry=None)) as s:
            await s.get(f"{srv.base}/1")
            await asyncio.sleep(0.2)
            await s.get(f"{srv.base}/2")
            assert srv.conns == 3                       # None -> sınırsız: yalnızca +1 bağlantı
        await srv.stop()
    run(main())


def test_max_keepalive_connections_uygulanir(pki, ca, tmp_path):
    async def main():
        srv = await H1Server(pki, tmp_path).start()
        async with sess(ca, limits=Limits(max_connections=5, max_keepalive_connections=2),
                        timeout=Timeout(5, read=3)) as s:
            # 5 eşzamanlı istek -> 5 bağlantı; bitince yalnızca 2'si havuzda kalır
            await asyncio.gather(*[s.get(f"{srv.base}/{i}") for i in range(5)])
            assert srv.conns == 5
            assert s._idle_count() == 2
            await asyncio.sleep(0.05)
            assert srv.open == 2                        # fazlalar kapatıldı
        await srv.stop()
    run(main())


def test_max_keepalive_sifir_havuzlamaz(pki, ca, tmp_path):
    async def main():
        srv = await H1Server(pki, tmp_path).start()
        async with sess(ca, limits=Limits(max_keepalive_connections=0)) as s:
            await s.get(f"{srv.base}/1")
            await s.get(f"{srv.base}/2")
            assert srv.conns == 2
        await srv.stop()
    run(main())


def test_iptal_edilen_istek_slotu_birakir(pki, ca, tmp_path):
    def script(c, r, m, p, b):
        return "hang" if p == "/bekle" else ok(p.encode())

    async def main():
        srv = await H1Server(pki, tmp_path, script).start()
        async with sess(ca, limits=Limits(max_connections=1),
                        timeout=Timeout(5, read=10, pool=2)) as s:
            t = asyncio.ensure_future(s.get(f"{srv.base}/bekle"))
            await asyncio.sleep(0.2)
            t.cancel()
            with pytest.raises(asyncio.CancelledError):
                await t
            assert s._sem._value == 1 and not s._idle
            assert (await s.get(f"{srv.base}/ok")).body == b"/ok"
        await srv.stop()
    run(main())


def test_wait_closed_iptali_kapanis_futureini_bozmaz(pki, ca, tmp_path):
    """asyncio StreamWriter.wait_closed() protokolün paylaşılan kapanış future'ını doğrudan
    bekler; bekleyen iptal edilirse future da iptal olur ve sonraki wait_closed() TLS kapanışı
    bitmeden döner (iptal edilen istekten sonra session.close() bağlantıyı yarım bırakırdı).
    B.wait_closed iptal edilse de kapanış future'ı sağlam kalır ve gerçekten beklenir."""
    async def main():
        srv = await H1Server(pki, tmp_path).start()
        ctx = ssl.create_default_context(cafile=ca)
        _r, w = await asyncio.open_connection("127.0.0.1", srv.port, ssl=ctx,
                                              server_hostname="localhost")
        sock = w.get_extra_info("socket")
        w.close()                                      # TLS kapanışı birkaç tur sürer
        t = asyncio.ensure_future(B.wait_closed(w))
        await asyncio.sleep(0)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t
        await asyncio.wait_for(B.wait_closed(w), 5)    # iptal edilmiş future'la hemen dönmez
        assert sock.fileno() == -1                     # ham soket gerçekten kapandı
        await srv.stop()
    run(main())
