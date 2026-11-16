"""PUSH_PROMISE regresyonu: istemci SETTINGS_ENABLE_PUSH=0 ilan ettiği için
PUSH_PROMISE almak PROTOCOL_ERROR türünde bağlantı hatasıdır (RFC 9113 §6.6,
§8.4). Senkron yol eskiden frame'i sessizce yutuyor (başlık bloğunu HPACK ile
decode etmeden), async yol ise hata veriyordu; ikisi aynı davranmalı:
GOAWAY(PROTOCOL_ERROR) gönderilir, bağlantı havuza dönmez."""
import asyncio
import struct
import time

import pytest

from fasthttpc import AsyncSession, Session
from fasthttpc.protocol.http2_parser import (
    FrameType, HpackEncoder, HTTP2Frame, Http2Connection, Http2ConnectionError,
)

from async_fakes import RawH2Conn, start_h2
from test_http2 import SahteSoket
from test_streaming_h2 import _Sunucu, _data, _hdr
from tls13_fakeserver import PKI

HOST = "localhost"
GET = dict(method="GET", authority="x", path="/", headers=[])
PROTOCOL_ERROR = 0x1


def _push_promise_payload(encoder, promised_sid=2):
    # Dinamik tabloya eklenen başlıklar: blok decode edilmeden yutulursa sonraki
    # yanıtların HPACK durumu bozulur.
    block = encoder.encode([(":method", "GET"), (":scheme", "https"),
                            (":authority", HOST), (":path", "/itilen.css"),
                            ("x-itilen", "evet")])
    return struct.pack("!I", promised_sid) + block


def _push_promise(sid, encoder=None):
    payload = _push_promise_payload(encoder or HpackEncoder())
    return HTTP2Frame(len(payload), FrameType.PUSH_PROMISE, 0x4, sid, payload)


def _goaways(sock):
    return [struct.unpack("!II", f.payload[:8]) for f in sock.gonderilen_frameler()
            if f.type == FrameType.GOAWAY]


# ------------------------------------------------------------ Http2Connection (sahte soket)
def test_sync_h2_push_promise_baslik_oncesi_protocol_error_ve_goaway():
    sock = SahteSoket([_push_promise(1), _hdr(1), _data(1, b"ok", end=True)])
    conn = Http2Connection(sock)
    with pytest.raises(Http2ConnectionError,
                       match="PROTOCOL_ERROR: ENABLE_PUSH=0 iken PUSH_PROMISE alındı"):
        conn.request(**GET)
    assert _goaways(sock) == [(0, PROTOCOL_ERROR)]
    assert conn._lock.acquire(blocking=False)          # kilit serbest bırakıldı
    conn._lock.release()


def test_sync_h2_push_promise_govde_sirasinda_stream_bozulur():
    sock = SahteSoket([_hdr(1), _data(1, b"aa"), _push_promise(1), _data(1, b"bb", end=True)])
    conn = Http2Connection(sock)
    st = conn.request_stream(**GET)
    assert st.read_chunk() == b"aa"
    with pytest.raises(Http2ConnectionError, match="PROTOCOL_ERROR"):
        st.read_chunk()
    assert st.broken                                   # bağlantı yeniden kullanılmaz
    assert _goaways(sock) == [(0, PROTOCOL_ERROR)]
    assert conn._lock.acquire(blocking=False)
    conn._lock.release()


def test_sync_h2_push_promise_baska_stream_idsiyle_de_hata():
    """PUSH_PROMISE'in stream_id'si bizimkinden farklı olsa bile (yabancı frame
    yoluna düşmeden) bağlantı hatasıdır."""
    sock = SahteSoket([_push_promise(5), _hdr(1), _data(1, b"ok", end=True)])
    with pytest.raises(Http2ConnectionError, match="PROTOCOL_ERROR"):
        Http2Connection(sock).request(**GET)
    assert _goaways(sock) == [(0, PROTOCOL_ERROR)]


# ------------------------------------------------------------ Session / AsyncSession uçtan uca
@pytest.fixture(scope="module")
def pki():
    return PKI(HOST)


@pytest.fixture
def ca(pki, tmp_path):
    p = tmp_path / "ca.pem"
    p.write_bytes(pki.ca_pem())
    return str(p)


def _script():
    """İlk bağlantı: istek gelince PUSH_PROMISE + normal yanıt gönderir, ardından
    istemcinin GOAWAY'ini bekleyip ``c.goaway_alinan``'a yazar. Sonraki
    bağlantılar normal yanıt verir."""
    sira = {"n": 0}

    async def script(c: RawH2Conn):
        sira["n"] += 1
        ilk = sira["n"] == 1
        c.goaway_alinan = None
        await c.handshake()
        while True:
            f = await c.next_frame(FrameType.HEADERS, FrameType.GOAWAY)
            if f is None:
                return
            if f.type == FrameType.GOAWAY:
                c.goaway_alinan = struct.unpack("!II", f.payload[:8])
                return
            if not c.requests[f.stream_id]["ended"]:
                continue
            sid = f.stream_id
            if ilk:
                c.send(c.frame(FrameType.PUSH_PROMISE, 0x4, sid,
                               _push_promise_payload(c.encoder)))
            c.respond(sid, 200, [("content-type", "text/plain")], b"merhaba")
            await c.flush()
    return script


def test_session_h2_push_promise_hata_goaway_ve_yeni_baglanti(pki, ca):
    sv = _Sunucu(pki, _script())
    try:
        with Session(impersonate="chrome_131", verify=ca, timeout=5) as s:
            url = f"https://localhost:{sv.port}/"
            with pytest.raises(ConnectionError, match="PROTOCOL_ERROR"):
                s.get(url)
            r = s.get(url)
            assert r.status_code == 200 and r.http_version == "HTTP/2"
            assert r.content == b"merhaba"
        assert len(sv.conns) == 2                      # bozuk bağlantı yeniden kullanılmadı
        for _ in range(100):                           # GOAWAY sunucu döngüsünde işlenir
            if sv.conns[0].goaway_alinan is not None:
                break
            time.sleep(0.02)
        assert sv.conns[0].goaway_alinan == (0, PROTOCOL_ERROR)
    finally:
        sv.stop()


def test_async_session_h2_push_promise_ayni_davranis(pki, ca):
    async def main():
        srv, port, conns = await start_h2(pki, _script())
        async with srv:
            async with AsyncSession(impersonate="chrome_131", verify=ca, timeout=5) as s:
                url = f"https://localhost:{port}/"
                with pytest.raises(ConnectionError, match="PROTOCOL_ERROR"):
                    await s.get(url)
                r = await s.get(url)
                assert r.status_code == 200 and r.content == b"merhaba"
            assert len(conns) == 2
            for _ in range(100):
                if conns[0].goaway_alinan is not None:
                    break
                await asyncio.sleep(0.02)
            assert conns[0].goaway_alinan == (0, PROTOCOL_ERROR)
    asyncio.run(asyncio.wait_for(main(), 20))
