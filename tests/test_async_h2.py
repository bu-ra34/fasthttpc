"""AsyncSession HTTP/2 testleri (ağsız, yerel sahte h2 sunucuları).

Ham frame sunucusu (RawH2Conn) bağımlılıksızdır ve her zaman çalışır; ``h2``
kütüphanesi kuruluysa ayrıca bağımsız bir uygulamayla birlikte-çalışma
(Huffman, dinamik tablo, akış kontrolü) test edilir.
"""
import asyncio
import struct

import pytest

from fasthttpc import AsyncSession, Limits, Timeout
from fasthttpc.protocol.async_h2 import client_preface_bytes
from fasthttpc.protocol.http2_parser import (
    FrameType, HpackDecoder, Http2Connection,
)

from async_fakes import PREFACE, AsyncFakeProxy, RawH2Conn, start_h2
from tls13_fakeserver import PKI, FakeTLS13Server

HOST = "localhost"


@pytest.fixture(scope="module")
def pki():
    return PKI(HOST)


@pytest.fixture
def ca(pki, tmp_path):
    p = tmp_path / "ca.pem"
    p.write_bytes(pki.ca_pem())
    return str(p)


def run(coro, timeout=20):
    return asyncio.run(asyncio.wait_for(coro, timeout))


def sess(ca, **kw):
    kw.setdefault("timeout", 5)
    return AsyncSession(impersonate="chrome_131", verify=ca, **kw)


def _path(c, sid):
    return dict(c.requests[sid]["headers"])[":path"]


async def no_data(c: RawH2Conn, wait=0.25):
    """``wait`` sn boyunca istemciden DATA frame'i gelmediğini doğrular."""
    try:
        f = await c.next_frame(FrameType.DATA, timeout=wait)
    except asyncio.TimeoutError:
        return
    assert f is None, "pencere kapalıyken istemci DATA gönderdi"


async def echo(c: RawH2Conn, **settings):
    """Her tamamlanan isteğe 'yol:gövde-uzunluğu' döner; gövdeler için pencere açar."""
    await c.handshake(**settings)
    answered = set()
    while True:
        f = await c.next_frame()
        if f is None:
            return
        if f.type == FrameType.DATA and f.payload:
            c.send(c.window_update(0, len(f.payload)), c.window_update(f.stream_id, len(f.payload)))
        if f.type in (FrameType.HEADERS, FrameType.DATA):
            r = c.requests[f.stream_id]
            if r["ended"] and f.stream_id not in answered:
                answered.add(f.stream_id)
                body = _path(c, f.stream_id).encode() + b":" + str(len(r["body"])).encode()
                c.respond(f.stream_id, 200, [("content-type", "text/plain"),
                                             ("set-cookie", "a=1"), ("set-cookie", "b=2")], body)
        await c.flush()


# ------------------------------------------------------------ temel
def test_h2_alpn_secilir_ve_istek_calisir(pki, ca):
    async def main():
        srv, port, conns = await start_h2(pki, echo)
        async with srv:
            s = sess(ca)
            r = await s.get(f"https://localhost:{port}/merhaba")
            assert r.status_code == 200 and r.body == b"/merhaba:0"
            assert r.headers.get("content-type") == "text/plain"
            assert r.headers.get_list("set-cookie") == ["a=1", "b=2"]   # çoklu başlık korunur
            assert s.cookies == {"a": "1", "b": "2"}
            c = conns[0]
            assert c.preface_ok
            hdrs = c.requests[1]["headers"]
            names = [k for k, _ in hdrs]
            assert names[:4] == [":method", ":authority", ":scheme", ":path"]   # Chrome sırası
            d = dict(hdrs)
            assert d[":authority"] == f"localhost:{port}" and d[":scheme"] == "https"
            for forbidden in ("host", "connection", "keep-alive", "transfer-encoding", "upgrade"):
                assert forbidden not in d
            assert d["user-agent"].startswith("Mozilla/5.0")
            await s.close()
    run(main())


def test_h2_baglanti_yeniden_kullanilir(pki, ca):
    async def main():
        srv, port, conns = await start_h2(pki, echo)
        async with srv:
            s = sess(ca)
            for i in range(4):
                r = await s.get(f"https://localhost:{port}/{i}")
                assert r.body == f"/{i}:0".encode()
            assert len(conns) == 1
            assert sorted(conns[0].requests) == [1, 3, 5, 7]
            await s.close()
    run(main())


def test_h2_client_hello_alpn_profilden(pki, ca):
    async def main():
        srv, port, conns = await start_h2(pki, echo)
        async with srv:
            s = sess(ca)
            await s.get(f"https://localhost:{port}/")
            assert conns[0].srv.client_hellos[0]["alpn"] == ["h2", "http/1.1"]
            await s.close()
    run(main())


def test_h2_parmak_izi_senkronla_ayni(pki, ca):
    """SETTINGS + ön ek baytları senkron Http2Connection'ınkiyle birebir aynı."""
    class Rec:
        def __init__(self):
            self.out = []

        def send_record(self, data, content_type=0x17, use_app_keys=True):
            self.out.append(bytes(data))

    rec = Rec()
    Http2Connection(rec).send_preface_and_settings()
    assert client_preface_bytes() == b"".join(rec.out)
    for ad in ("chrome_131", "firefox_133", "safari_18"):
        rec = Rec()
        Http2Connection(rec, profile=ad).send_preface_and_settings()
        assert client_preface_bytes(ad) == b"".join(rec.out)

    async def main():
        srv, port, conns = await start_h2(pki, echo)
        async with srv:
            s = sess(ca)
            await s.get(f"https://localhost:{port}/")
            c = conns[0]
            assert c.raw_in.startswith(client_preface_bytes("chrome_131"))      # telde de aynı (profil: chrome_131)
            await s.close()
    run(main())


def test_h2_pseudo_header_ve_hpack_senkronla_ayni(pki, ca):
    """Aynı istek için async HEADERS bloğu senkron encoder çıktısıyla aynı sırada."""
    from fasthttpc.protocol.http2_parser import HpackEncoder

    async def main():
        srv, port, conns = await start_h2(pki, echo)
        async with srv:
            s = sess(ca)
            await s.get(f"https://localhost:{port}/x", headers={"X-Test": "1"})
            sent = conns[0].requests[1]["headers"]
            await s.close()
            return sent, port
    sent, port = run(main())
    pairs = [(k, v) for k, v in sent if not k.startswith(":")]
    expect = HpackEncoder().encode([(":method", "GET"), (":authority", f"localhost:{port}"),
                                    (":scheme", "https"), (":path", "/x")] + pairs)
    assert HpackDecoder().decode(expect) == sent


def test_h2_http11_secilirse_eski_yol(pki, ca):
    from tls13_fakeserver import async_serve, http_responder

    async def main():
        servers = []

        async def on_conn(r, w):
            srv = FakeTLS13Server(pki, alpn="http/1.1")
            servers.append(srv)
            await async_serve(srv, r, w, http_responder(b"h1 yolu"))
        srv = await asyncio.start_server(on_conn, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        async with srv:
            s = sess(ca)
            for _ in range(3):
                r = await s.get(f"https://localhost:{port}/")
                assert r.body == b"h1 yolu"
            assert s._origin_proto
            assert not s._h2
            assert len(servers) == 1                       # h1: keep-alive, tek bağlantı yeniden kullanılır
            assert servers[0].requests[0].startswith(b"GET / HTTP/1.1\r\n")
            await s.close()
    run(main())


# --------------------------------------------------------- multiplexing
def test_h2_eszamanli_multiplexing(pki, ca):
    async def script(c):
        await c.handshake()
        sids = []
        while len(sids) < 5:
            f = await c.next_frame(FrameType.HEADERS)
            sids.append(f.stream_id)
        assert c.requests and all(c.requests[s]["ended"] for s in sids)
        for sid in reversed(sids):          # ters sırada yanıtla: eşleştirme stream_id ile
            c.respond(sid, 200, [], f"cevap{_path(c, sid)}".encode())
        await c.flush()
        while await c.next_frame() is not None:
            pass

    async def main():
        srv, port, conns = await start_h2(pki, script)
        async with srv:
            s = sess(ca)
            rs = await asyncio.gather(*[s.get(f"https://localhost:{port}/{i}") for i in range(5)])
            assert [r.body for r in rs] == [f"cevap/{i}".encode() for i in range(5)]
            assert len(conns) == 1                         # tek TLS bağlantısı
            assert sorted(conns[0].requests) == [1, 3, 5, 7, 9]
            await s.close()
    run(main())


def test_h2_max_concurrent_streams_sinirina_uyulur(pki, ca):
    seen = {"max_open": 0}

    async def script(c):
        await c.handshake(max_streams=1)
        open_ = set()
        while True:
            f = await c.next_frame()
            if f is None:
                return
            if f.type == FrameType.HEADERS:
                open_.add(f.stream_id)
                seen["max_open"] = max(seen["max_open"], len(open_))
                await asyncio.sleep(0.05)
                c.respond(f.stream_id, 200, [], b"ok")
                open_.discard(f.stream_id)
                await c.flush()

    async def main():
        srv, port, conns = await start_h2(pki, script)
        async with srv:
            s = sess(ca)
            rs = await asyncio.gather(*[s.get(f"https://localhost:{port}/{i}") for i in range(4)])
            assert [r.body for r in rs] == [b"ok"] * 4
            assert seen["max_open"] == 1
            await s.close()
    run(main())


def test_h2_farkli_kaynaklar_ayri_baglanti(pki, ca):
    async def main():
        srv, port, conns = await start_h2(pki, echo)
        srv2, port2, conns2 = await start_h2(pki, echo)
        async with srv, srv2:
            s = sess(ca)
            a, b = await asyncio.gather(s.get(f"https://localhost:{port}/a"),
                                        s.get(f"https://localhost:{port2}/b"))
            assert a.body == b"/a:0" and b.body == b"/b:0"
            assert len(conns) == 1 and len(conns2) == 1
            await s.close()
    run(main())


# ----------------------------------------------------------- akış kontrolü
def test_h2_gonderim_akis_kontrolu_pencereye_uyar(pki, ca):
    BODY = bytes(range(256)) * 800          # 204800 bayt > 65535
    got = {}

    async def script(c):
        await c.handshake()
        f = await c.next_frame(FrameType.HEADERS)
        sid = f.stream_id
        total = 0
        lens = []
        # Pencere açılmadan istemci tam 65535 bayt göndermeli ve beklemeli.
        while total < 65535:
            d = await c.next_frame(FrameType.DATA)
            total += len(d.payload)
            lens.append(len(d.payload))
        await no_data(c)                                     # fazladan DATA yok
        assert total == 65535
        got["first_window"] = total
        while not c.requests[sid]["ended"]:
            # Bağlantı penceresi yalnızca 65535: her 16K'da bir iki pencereyi de aç
            c.send(c.window_update(0, 16384), c.window_update(sid, 16384))
            await c.flush()
            d = await c.next_frame(FrameType.DATA, timeout=3)
            lens.append(len(d.payload))
        got["lens"] = lens
        got["body"] = bytes(c.requests[sid]["body"])
        c.respond(sid, 200, [], b"yuklendi")
        await c.flush()
        while await c.next_frame() is not None:
            pass

    async def main():
        srv, port, conns = await start_h2(pki, script)
        async with srv:
            s = sess(ca)
            r = await s.post(f"https://localhost:{port}/up", data=BODY)
            assert r.status_code == 200 and r.body == b"yuklendi"
            assert got["body"] == BODY
            assert max(got["lens"]) <= 16384                # varsayılan MAX_FRAME_SIZE
            await s.close()
    run(main())


def test_h2_settings_initial_window_size_ve_max_frame_size(pki, ca):
    BODY = b"z" * 5000
    seen = {}

    async def script(c):
        await c.handshake(window=1000, max_frame=16384)
        f = await c.next_frame(FrameType.HEADERS)        # ısındırma GET'i
        c.respond(f.stream_id, 200, [], b"w")
        await c.flush()
        f = await c.next_frame(FrameType.HEADERS)
        sid = f.stream_id
        d = await c.next_frame(FrameType.DATA)
        assert len(d.payload) == 1000                        # yeni pencere kadar
        await no_data(c)
        # Akış ortasında INITIAL_WINDOW_SIZE 1000 -> 3000 (açık stream'lere +2000 uygulanır)
        c.send(c.settings(window=3000))
        await c.flush()
        got = len(d.payload)
        while got < 3000:
            d = await c.next_frame(FrameType.DATA)
            got += len(d.payload)
        assert got == 3000
        await no_data(c)
        c.send(c.window_update(sid, 2000))
        await c.flush()
        while not c.requests[sid]["ended"]:
            await c.next_frame(FrameType.DATA)
        seen["len"] = len(c.requests[sid]["body"])
        c.respond(sid, 200, [], b"tamam")
        await c.flush()
        while await c.next_frame() is not None:
            pass

    async def main():
        srv, port, conns = await start_h2(pki, script)
        async with srv:
            s = sess(ca)
            await s.get(f"https://localhost:{port}/warm")   # sunucu SETTINGS'i işlensin
            r = await s.post(f"https://localhost:{port}/p", data=BODY)
            assert r.body == b"tamam" and seen["len"] == 5000
            # SETTINGS ACK gönderildi mi
            acks = []
            while not conns[0].frames.empty():
                f = conns[0].frames.get_nowait()
                if f is not None and f.type == FrameType.SETTINGS and f.flags & 1:
                    acks.append(f)
            await s.close()
    run(main())


def test_h2_indirme_akis_kontrolu_window_update_yollar(pki, ca):
    BODY = bytes(range(256)) * 1200         # 307200 bayt
    state = {}

    async def script(c):
        await c.handshake()
        f = await c.next_frame(FrameType.HEADERS)
        sid = f.stream_id
        conn_win = stream_win = 65535
        off = 0
        c.send(c.response_headers(sid, 200, [("content-length", str(len(BODY)))]))
        await c.flush()
        stalls = 0
        while off < len(BODY):
            n = min(16384, conn_win, stream_win, len(BODY) - off)
            if n <= 0:
                stalls += 1
                u = await c.next_frame(FrameType.WINDOW_UPDATE, timeout=3)
                inc = struct.unpack("!I", u.payload)[0]
                if u.stream_id == 0:
                    conn_win += inc
                else:
                    stream_win += inc
                continue
            c.send(c.data(sid, BODY[off:off + n], end=(off + n == len(BODY))))
            conn_win -= n
            stream_win -= n
            off += n
            await c.flush()
            # biriken WINDOW_UPDATE'leri işle
            while not c.frames.empty():
                u = c.frames.get_nowait()
                if u is not None and u.type == FrameType.WINDOW_UPDATE:
                    inc = struct.unpack("!I", u.payload)[0]
                    if u.stream_id == 0:
                        conn_win += inc
                    else:
                        stream_win += inc
        state["stalls"] = stalls
        while await c.next_frame() is not None:
            pass

    async def main():
        srv, port, conns = await start_h2(pki, script)
        async with srv:
            s = sess(ca)
            r = await s.get(f"https://localhost:{port}/big")
            assert r.body == BODY
            await s.close()
        assert state["stalls"] >= 1       # sunucu pencereyi gerçekten tüketti ve bekledi
    run(main())


# ------------------------------------------------------------ hata/kontrol
def test_h2_goaway_islenmeyen_stream_yeni_baglantida_yeniden_denenir(pki, ca):
    holder = {}

    async def script(c):
        if c is holder["conns"][0]:
            await c.handshake()
            await c.next_frame(FrameType.HEADERS)
            await c.next_frame(FrameType.HEADERS)
            c.respond(1, 200, [], b"bir")
            c.send(c.goaway(1, 0))          # stream 3 işlenmedi
            await c.flush()
            while await c.next_frame() is not None:
                pass
        else:
            await echo(c)

    async def main():
        srv, port, cs = await start_h2(pki, script)
        holder["conns"] = conns_ref = cs
        async with srv:
            s = sess(ca)
            r1, r2 = await asyncio.gather(s.get(f"https://localhost:{port}/a"),
                                          s.get(f"https://localhost:{port}/b"))
            assert r1.body == b"bir"
            assert r2.body == b"/b:0"
            assert len(conns_ref) == 2          # ikinci bağlantı açıldı
            await s.close()
    run(main())


def test_h2_goaway_sonrasi_yeni_istek_yeni_baglanti(pki, ca):
    async def script(c):
        await c.handshake()
        f = await c.next_frame(FrameType.HEADERS)
        c.respond(f.stream_id, 200, [], b"x")
        c.send(c.goaway(f.stream_id, 0))
        await c.flush()
        while await c.next_frame() is not None:
            pass

    async def main():
        srv, port, conns = await start_h2(pki, script)
        async with srv:
            s = sess(ca)
            assert (await s.get(f"https://localhost:{port}/1")).body == b"x"
            await asyncio.sleep(0.05)
            assert (await s.get(f"https://localhost:{port}/2")).body == b"x"
            assert len(conns) == 2
            await s.close()
    run(main())


def test_h2_rst_stream_hatasi_diger_stream_ve_baglanti_saglam(pki, ca):
    async def script(c):
        await c.handshake()
        a = await c.next_frame(FrameType.HEADERS)
        b = await c.next_frame(FrameType.HEADERS)
        c.send(c.rst(a.stream_id, 2))                       # INTERNAL_ERROR
        c.respond(b.stream_id, 200, [], b"saglam")
        await c.flush()
        f = await c.next_frame(FrameType.HEADERS)           # sonraki istek aynı bağlantıda
        c.respond(f.stream_id, 200, [], b"devam")
        await c.flush()
        while await c.next_frame() is not None:
            pass

    async def main():
        srv, port, conns = await start_h2(pki, script)
        async with srv:
            s = sess(ca)
            ra, rb = await asyncio.gather(s.get(f"https://localhost:{port}/a"),
                                          s.get(f"https://localhost:{port}/b"),
                                          return_exceptions=True)
            assert isinstance(ra, ConnectionError) and "INTERNAL_ERROR" in str(ra)
            assert rb.body == b"saglam"
            assert (await s.get(f"https://localhost:{port}/c")).body == b"devam"
            assert len(conns) == 1
            await s.close()
    run(main())


def test_h2_refused_stream_yeniden_denenir(pki, ca):
    async def script(c):
        await c.handshake()
        f = await c.next_frame(FrameType.HEADERS)
        c.send(c.rst(f.stream_id, 7))                       # REFUSED_STREAM
        await c.flush()
        f = await c.next_frame(FrameType.HEADERS)
        c.respond(f.stream_id, 200, [], b"ikinci deneme")
        await c.flush()
        while await c.next_frame() is not None:
            pass

    async def main():
        srv, port, conns = await start_h2(pki, script)
        async with srv:
            s = sess(ca)
            assert (await s.get(f"https://localhost:{port}/")).body == b"ikinci deneme"
            await s.close()
    run(main())


def test_h2_ping_ack(pki, ca):
    got = {}

    async def script(c):
        await c.handshake()
        c.send(c.ping(b"ABCDEFGH"))
        await c.flush()
        while "ping" not in got or not c.requests:
            f = await c.next_frame()
            if f.type == FrameType.PING:
                got["ping"] = (f.flags, f.payload)
        c.respond(1, 204)
        await c.flush()
        while await c.next_frame() is not None:
            pass

    async def main():
        srv, port, conns = await start_h2(pki, script)
        async with srv:
            s = sess(ca)
            r = await s.get(f"https://localhost:{port}/")
            assert r.status_code == 204 and r.body == b""
            assert got["ping"] == (1, b"ABCDEFGH")
            await s.close()
    run(main())


def test_h2_iptal_rst_stream_cancel_gonderir(pki, ca):
    got = {}

    async def script(c):
        await c.handshake()
        f = await c.next_frame(FrameType.HEADERS)
        r = await c.next_frame(FrameType.RST_STREAM)
        got["rst"] = (r.stream_id, struct.unpack("!I", r.payload)[0], f.stream_id)
        while await c.next_frame() is not None:
            pass

    async def main():
        srv, port, conns = await start_h2(pki, script)
        async with srv:
            s = sess(ca, timeout=30)
            t = asyncio.ensure_future(s.get(f"https://localhost:{port}/"))
            await asyncio.sleep(0.3)
            t.cancel()
            with pytest.raises(asyncio.CancelledError):
                await t
            await asyncio.sleep(0.2)
            assert got["rst"] == (1, 8, 1)                   # CANCEL
            await s.close()
    run(main())


def test_h2_read_timeout_hareketsizlik_olarak_uygulanir(pki, ca):
    async def silent(c):
        await c.handshake()
        await c.next_frame(FrameType.HEADERS)
        r = await c.next_frame(FrameType.RST_STREAM, timeout=5)
        assert struct.unpack("!I", r.payload)[0] == 8
        while await c.next_frame() is not None:
            pass

    async def dribble(c):
        await c.handshake()
        f = await c.next_frame(FrameType.HEADERS)
        c.send(c.response_headers(f.stream_id, 200))
        await c.flush()
        for _ in range(6):                    # toplam ~1.2 sn > read=0.6, ama aralık < 0.6
            await asyncio.sleep(0.2)
            c.send(c.data(f.stream_id, b"x"))
            await c.flush()
        c.send(c.data(f.stream_id, b"", end=True))
        await c.flush()
        while await c.next_frame() is not None:
            pass

    async def main():
        srv, port, _ = await start_h2(pki, silent)
        async with srv:
            s = sess(ca, timeout=Timeout(5, read=0.4))
            with pytest.raises(asyncio.TimeoutError):
                await s.get(f"https://localhost:{port}/")
            await s.close()
        srv, port, _ = await start_h2(pki, dribble)
        async with srv:
            s = sess(ca, timeout=Timeout(5, read=0.6))
            r = await s.get(f"https://localhost:{port}/")
            assert r.body == b"x" * 6
            await s.close()
    run(main())


def test_h2_session_close_goaway_gonderir(pki, ca):
    got = {}

    async def script(c):
        await c.handshake()
        f = await c.next_frame(FrameType.HEADERS)
        c.respond(f.stream_id, 200, [], b"x")
        await c.flush()
        g = await c.next_frame(FrameType.GOAWAY)
        got["goaway"] = struct.unpack("!II", g.payload[:8])

    async def main():
        srv, port, conns = await start_h2(pki, script)
        async with srv:
            s = sess(ca)
            await s.get(f"https://localhost:{port}/")
            await s.close()
            await asyncio.sleep(0.2)
            assert got["goaway"] == (0, 0)
            assert not s._h2
    run(main())


def test_h2_keepalive_expiry_suresi_dolunca_yeni_baglanti(pki, ca):
    async def main():
        srv, port, conns = await start_h2(pki, echo)
        async with srv:
            s = sess(ca, limits=Limits(max_connections=4, keepalive_expiry=0.1))
            await s.get(f"https://localhost:{port}/1")
            await asyncio.sleep(0.25)
            await s.get(f"https://localhost:{port}/2")
            assert len(conns) == 2
            await s.close()
    run(main())


# -------------------------------------------------- yanıt çözümleme ayrıntıları
def test_h2_ara_yanit_trailer_padding_ve_continuation(pki, ca):
    async def script(c):
        await c.handshake()
        f = await c.next_frame(FrameType.HEADERS)
        sid = f.stream_id
        # 103 Early Hints, sonra PADDED+PRIORITY'li 200 HEADERS (CONTINUATION'a bölünmüş)
        c.send(c.response_headers(sid, 103, [("link", "</a.css>; rel=preload")]))
        block = c.encoder.encode([(":status", "200"), ("content-type", "text/plain"),
                                  ("x-uzun", "u" * 300)])
        half = len(block) // 2
        pad = b"\x07" + b"\x00\x00\x00\x00" + b"\x10"        # pad_len=7, priority(5 bayt: dep+weight)
        # PADDED(0x8)|PRIORITY(0x20) HEADERS; END_HEADERS YOK
        payload = b"\x07" + b"\x00\x00\x00\x00\x10" + block[:half] + b"\x00" * 7
        c.send(c.frame(FrameType.HEADERS, 0x8 | 0x20, sid, payload))
        c.send(c.frame(FrameType.CONTINUATION, 0x4, sid, block[half:]))
        # PADDED DATA
        c.send(c.frame(FrameType.DATA, 0x8, sid, b"\x05" + b"merhaba" + b"\x00" * 5))
        # trailer
        tr = c.encoder.encode([("x-trailer", "son")])
        c.send(c.frame(FrameType.HEADERS, 0x4 | 0x1, sid, tr))
        await c.flush()
        del pad
        while await c.next_frame() is not None:
            pass

    async def main():
        srv, port, conns = await start_h2(pki, script)
        async with srv:
            s = sess(ca)
            r = await s.get(f"https://localhost:{port}/")
            assert r.status_code == 200
            assert r.body == b"merhaba"
            assert r.headers.get("x-uzun") == "u" * 300
            assert r.headers.get("x-trailer") == "son"
            assert r.headers.get("link") is None             # ara yanıt başlıkları sızmaz
            await s.close()
    run(main())


def test_h2_gzip_govde_cozulur_ve_head_govdesiz(pki, ca):
    import gzip

    async def script(c):
        await c.handshake()
        while True:
            f = await c.next_frame(FrameType.HEADERS)
            if f is None:
                return
            m = dict(c.requests[f.stream_id]["headers"])[":method"]
            if m == "HEAD":
                c.respond(f.stream_id, 200, [("content-length", "999")])
            else:
                c.respond(f.stream_id, 200, [("content-encoding", "gzip")],
                          gzip.compress(b"sikistirilmis"))
            await c.flush()

    async def main():
        srv, port, conns = await start_h2(pki, script)
        async with srv:
            s = sess(ca)
            assert (await s.get(f"https://localhost:{port}/")).body == b"sikistirilmis"
            r = await s.head(f"https://localhost:{port}/")
            assert r.status_code == 200 and r.body == b""
            await s.close()
    run(main())


def test_h2_post_json_ve_redirect(pki, ca):
    async def script(c):
        await c.handshake()
        while True:
            f = await c.next_frame()
            if f is None:
                return
            if f.type == FrameType.DATA and f.payload:
                c.send(c.window_update(0, len(f.payload)))
            if f.type in (FrameType.HEADERS, FrameType.DATA) and c.requests[f.stream_id]["ended"]:
                r = c.requests[f.stream_id]
                d = dict(r["headers"])
                if d[":path"] == "/r":
                    c.respond(f.stream_id, 302, [("location", "/son")])
                else:
                    c.respond(f.stream_id, 200, [], d[":method"].encode() + b" " + bytes(r["body"])
                              + b" " + d.get("content-type", "").encode())
                await c.flush()

    async def main():
        srv, port, conns = await start_h2(pki, script)
        async with srv:
            s = sess(ca)
            r = await s.post(f"https://localhost:{port}/x", json={"a": 1})
            assert r.body == b'POST {"a": 1} application/json'
            r = await s.post(f"https://localhost:{port}/r", json={"a": 1})
            assert r.status_code == 200 and r.body == b"GET  "      # 302 -> GET, gövdesiz
            assert len(r.history) == 1
            assert len(conns) == 1
            await s.close()
    run(main())


# ------------------------------------------------------------- proxy + h2
def test_h2_proxy_tuneli_icinde(pki, ca):
    async def main():
        srv, port, conns = await start_h2(pki, echo)
        proxy = await AsyncFakeProxy("http", upstream_port=port).start()
        async with srv:
            s = sess(ca, proxy=proxy.url)
            rs = await asyncio.gather(*[s.get(f"https://localhost:{port}/{i}") for i in range(3)])
            assert [r.body for r in rs] == [f"/{i}:0".encode() for i in range(3)]
            assert proxy.connections == 1 and len(conns) == 1
            assert proxy.targets == [f"localhost:{port}"]
            await s.close()
        await proxy.stop()
    run(main())


# ---------------------------------------------- h2 kütüphanesiyle birlikte-çalışma
h2 = pytest.importorskip("h2", reason="h2 kütüphanesi kurulu değil (pip install h2)")


async def _h2lib_server(pki, delay=0.0, big=b""):
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import (DataReceived, RemoteSettingsChanged, RequestReceived,
                           StreamEnded, WindowUpdated)
    state = {"conns": [], "max_conc": 0}

    async def on_conn(r, w):
        srv = FakeTLS13Server(pki, alpn="h2")
        h2c = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
        h2c.initiate_connection()
        state["conns"].append(h2c)
        reqs = {}
        win = asyncio.Event()
        started = False
        inflight = set()
        tasks = []

        async def flush():
            out = h2c.data_to_send()
            if out:
                w.write(srv.send_app(out))
                await w.drain()

        async def send_flow(sid, body):
            while body:
                n = min(h2c.local_flow_control_window(sid), len(body), h2c.max_outbound_frame_size)
                if n <= 0:
                    await flush()
                    await win.wait()
                    win.clear()
                    continue
                h2c.send_data(sid, body[:n])
                body = body[n:]
                await flush()
            h2c.end_stream(sid)
            await flush()

        async def respond(sid):
            inflight.add(sid)
            state["max_conc"] = max(state["max_conc"], len(inflight))
            await asyncio.sleep(delay)
            req = reqs[sid]
            path = dict(req["headers"])[":path"]
            body = big if path == "/big" else f"{path}|{len(req['body'])}".encode()
            h2c.send_headers(sid, [(":status", "200"), ("content-type", "text/plain"),
                                   ("set-cookie", "a=1"), ("set-cookie", "b=2"),
                                   ("x-ortak", "tekrar eden deger" * 5), ("server", "h2lib")])
            await flush()
            await send_flow(sid, body)
            inflight.discard(sid)

        try:
            while True:
                data = await r.read(65536)
                if not data:
                    break
                out = srv.receive(data)
                if out:
                    w.write(out)
                    await w.drain()
                if srv.state != "CONNECTED":
                    continue
                if not started:
                    started = True
                    await flush()
                pt = b"".join(srv.app_in)
                srv.app_in.clear()
                if not pt:
                    continue
                for ev in h2c.receive_data(pt):
                    if isinstance(ev, RequestReceived):
                        reqs[ev.stream_id] = {"headers": ev.headers, "body": bytearray()}
                    elif isinstance(ev, DataReceived):
                        reqs[ev.stream_id]["body"] += ev.data
                        h2c.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                    elif isinstance(ev, StreamEnded):
                        tasks.append(asyncio.ensure_future(respond(ev.stream_id)))
                    elif isinstance(ev, (WindowUpdated, RemoteSettingsChanged)):
                        win.set()
                await flush()
        except (OSError, asyncio.CancelledError):
            pass
        finally:
            for t in tasks:
                t.cancel()
            w.close()

    server = await asyncio.start_server(on_conn, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1], state


def test_h2lib_birlikte_calisma_huffman_dinamik_tablo_multiplex(pki, ca):
    async def main():
        srv, port, state = await _h2lib_server(pki, delay=0.1)
        async with srv:
            s = sess(ca)
            # 1. tur: Huffman'lı başlıklar; 2. tur: dinamik tablo referansları
            for _ in range(2):
                rs = await asyncio.gather(*[s.get(f"https://localhost:{port}/p{i}",
                                                  headers={"X-Req": "değer-" + str(i)})
                                            for i in range(8)])
                for i, r in enumerate(rs):
                    assert r.status_code == 200 and r.body == f"/p{i}|0".encode()
                    assert r.headers.get("x-ortak") == "tekrar eden deger" * 5
                    assert r.headers.get_list("set-cookie") == ["a=1", "b=2"]
                    assert r.headers.get("server") == "h2lib"
            assert len(state["conns"]) == 1
            assert state["max_conc"] == 8                    # gerçekten eşzamanlı
            await s.close()
    run(main())


def test_h2lib_buyuk_indirme_ve_yukleme(pki, ca):
    BIG = bytes(range(256)) * 2000          # 512000 bayt
    UP = b"u" * 300000

    async def main():
        srv, port, state = await _h2lib_server(pki, big=BIG)
        async with srv:
            s = sess(ca)
            r, r2 = await asyncio.gather(
                s.get(f"https://localhost:{port}/big"),
                s.post(f"https://localhost:{port}/up", data=UP),
            )
            assert r.body == BIG
            assert r2.body == f"/up|{len(UP)}".encode()
            await s.close()
    run(main(), timeout=40)


def test_h2lib_stdlib_ssl_yolu_h1_kalir(pki, ca, tmp_path):
    """impersonate=None HTTP/1.1 konuşur (ALPN'de h2 teklif edilmez)."""
    from async_fakes import start_stdlib_tls

    async def main():
        srv, port, reqs = await start_stdlib_tls(pki, tmp_path)
        async with srv:
            s = AsyncSession(impersonate=None, verify=ca, timeout=5)
            r = await s.get(f"https://localhost:{port}/")
            assert r.body == b"stdlib tamam"
            assert reqs[0].startswith(b"GET / HTTP/1.1")
            await s.close()
    run(main())


def test_preface_sabiti():
    assert PREFACE.startswith(b"PRI * HTTP/2.0")
