"""Senkron tarafta ``Timeout.write``: her gönderim ``write`` ile (kalan ``total`` ile
kısaltılmış) sınırlı, okumalar ``read`` ile sınırlı kalır (yerel sunucular, ağsız).

Sunucu bağlantıyı kabul edip (TLS el sıkışmasından sonra) HİÇ okumaz; büyük gövde
gönderen istemci soket tamponları dolunca bloklanır. Süreler ``time.perf_counter`` ile
ölçülür ve yalnızca geniş paylı sınırlarla doğrulanır (Windows'ta soket zaman aşımı
~15,6 ms adımlı saatle sayıldığından alt sınırda 50 ms pay bırakılır).
"""
from __future__ import annotations

import socket
import struct
import time

import pytest

from fasthttpc import Session, Timeout
from fasthttpc.transport.iotimeout import SEND_CHUNK, IOTimeouts, send_all
from fasthttpc.transport.proxy import ProxyConfig, http_connect, socks5_connect
from saha.yerel_sunucu import YerelSunucu
from thread_servers import H2ThreadServer, StallServer

BIG = 32 * 1024 * 1024          # her platformun soket tamponlarından çok büyük
SMALL_RCVBUF = 32 * 1024
PAY = 0.05                      # alt sınır payı (saat çözünürlüğü)
UST = 5.0                       # üst sınır payı (yük altındaki CI)


def _frame(ftype: int, flags: int, sid: int, payload: bytes) -> bytes:
    return struct.pack("!I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack("!I", sid) + payload


_W = 2 ** 31 - 1
# Sunucu ön eki: dev başlangıç penceresi + bağlantı ve stream 1 için WINDOW_UPDATE. İstemci
# akış kontrolünde takılmaz, gövdeyi soket tamponları dolana dek gönderir.
H2_OPEN_WINDOW = (_frame(0x4, 0, 0, struct.pack("!HI", 0x4, _W))
                  + _frame(0x8, 0, 0, struct.pack("!I", _W - 65535))
                  + _frame(0x8, 0, 1, struct.pack("!I", _W - 65535)))


def _stall(kind: str, **kw) -> StallServer:
    if kind == "plain":
        return StallServer(tls=False, rcvbuf=SMALL_RCVBUF, **kw)
    if kind == "h1":
        return StallServer(alpn=["http/1.1"], rcvbuf=SMALL_RCVBUF, **kw)
    return StallServer(alpn=["h2"], rcvbuf=SMALL_RCVBUF, preamble=H2_OPEN_WINDOW, **kw)


def _session(srv: StallServer, timeout: Timeout) -> Session:
    return Session(verify=srv.ca_path, timeout=timeout)


def _post(s: Session, srv: StallServer, body: bytes) -> "tuple[BaseException, float]":
    t0 = time.perf_counter()
    with pytest.raises(TimeoutError) as ei:
        s.post(f"{srv.base}/upload", data=body)
    return ei.value, time.perf_counter() - t0


KINDS = ["plain", "h1", "h2"]


# ------------------------------------------------------------------ write
@pytest.mark.parametrize("kind", KINDS)
def test_write_timeout_buyuk_govde(kind):
    with _stall(kind) as srv, _session(srv, Timeout(10, write=0.5)) as s:
        err, dt = _post(s, srv, b"x" * BIG)
    assert "Timeout.write" in str(err), err
    assert 0.5 - PAY <= dt < 0.5 + UST, dt


@pytest.mark.parametrize("kind", KINDS)
def test_write_timeout_read_suresini_kullanmaz(kind):
    """read=0.3 < write=1.5: gönderim tıkanınca 0.3 sn'de DEĞİL, write süresinde biter."""
    with _stall(kind) as srv, _session(srv, Timeout(10, read=0.3, write=1.5)) as s:
        err, dt = _post(s, srv, b"x" * BIG)
    assert "Timeout.write" in str(err), err
    assert 1.5 - PAY <= dt < 1.5 + UST, dt


def test_write_timeout_h2_akis_kontrolu_beklemesi():
    """Sunucu WINDOW_UPDATE göndermez: ilk 64 KiB'ten sonra pencere beklemesi write ile sınırlı
    (read=30 beklenmez)."""
    with StallServer(alpn=["h2"], rcvbuf=512 * 1024) as srv, \
            _session(srv, Timeout(30, write=0.5)) as s:
        err, dt = _post(s, srv, b"x" * (1024 * 1024))
    assert "Timeout.write" in str(err) and "WINDOW_UPDATE" in str(err), err
    assert 0.5 - PAY <= dt < 0.5 + UST, dt


# ------------------------------------------------------------------ read bağımsız
@pytest.mark.parametrize("kind", KINDS)
def test_read_timeout_write_ten_bagimsiz(kind):
    """Küçük istek tampona sığar (gönderim biter); yanıt gelmez: read süresinde biter, hata
    yazma hatası değildir (write=30 beklenmez)."""
    with _stall(kind) as srv, _session(srv, Timeout(30, read=0.5)) as s:
        err, dt = _post(s, srv, b"kucuk")
    assert "Timeout.write" not in str(err), err
    assert 0.5 - PAY <= dt < 0.5 + UST, dt


# ------------------------------------------------------------------ total
@pytest.mark.parametrize("kind", KINDS)
def test_total_gonderimi_de_sinirlar(kind):
    with _stall(kind) as srv, _session(srv, Timeout(10, total=0.8)) as s:
        err, dt = _post(s, srv, b"x" * BIG)
    assert "Timeout.total" in str(err), err
    assert 0.8 - PAY <= dt < 0.8 + UST, dt


# ------------------------------------------------------------------ okuma süresi geri gelir
def test_gonderimden_sonra_okuma_read_suresiyle_h1():
    """write=1 iken gövde gönderilir, sunucu 1,5 sn sonra yanıtlar: okuma write'la değil
    read=10 ile sınırlı olmalı (soket zaman aşımı gönderimden sonra geri yüklenir)."""
    with YerelSunucu() as sv, Session(verify=sv.ca_path, timeout=Timeout(10, write=1.0)) as s:
        r = s.post(f"{sv.url}/sleep?d=1.5&i=tamam", data=b"g" * (512 * 1024))
        assert r.content == b"tamam"


def test_gonderimden_sonra_okuma_read_suresiyle_h2():
    with H2ThreadServer() as sv, Session(verify=sv.ca_path, timeout=Timeout(10, write=1.0)) as s:
        r = s.post(f"{sv.base}/sleep?d=1.5&i=tamam", data=b"g" * (512 * 1024))
        assert r.content == b"tamam" and r.http_version == "HTTP/2"


# ------------------------------------------------------------------ birim testleri
class _RecSock:
    """sendall/settimeout çağrılarını kaydeden sahte soket."""

    def __init__(self, fail_after: "int | None" = None):
        self.log: list = []
        self.fail_after = fail_after
        self.recv_buf = b""

    def settimeout(self, t):
        self.log.append(("timeout", t))

    def sendall(self, data):
        if self.fail_after is not None and len([x for x in self.log if x[0] == "send"]) >= self.fail_after:
            raise socket.timeout("timed out")
        self.log.append(("send", len(data)))

    def recv(self, n):
        out, self.recv_buf = self.recv_buf[:n], self.recv_buf[n:]
        return out


def test_send_all_parcalar_ve_okuma_suresini_geri_yukler():
    sock = _RecSock()
    send_all(sock, b"a" * (2 * SEND_CHUNK + 10), IOTimeouts(read=7.0, write=2.0))
    assert sock.log == [("timeout", 2.0), ("send", SEND_CHUNK), ("send", SEND_CHUNK),
                        ("send", 10), ("timeout", 7.0)]


def test_send_all_write_read_esitse_sistem_cagrisi_yok():
    sock = _RecSock()
    send_all(sock, b"abc", IOTimeouts(read=5.0, write=5.0))
    assert sock.log == [("send", 3)]


def test_send_all_total_dolmussa_gondermez():
    sock = _RecSock()
    with pytest.raises(TimeoutError, match="Timeout.total"):
        send_all(sock, b"abc", IOTimeouts(read=5.0, write=5.0, deadline=time.perf_counter() - 1))
    assert sock.log == []


def test_send_all_zaman_asimi_yazma_hatasina_cevrilir():
    sock = _RecSock(fail_after=0)
    with pytest.raises(TimeoutError, match="Timeout.write=0.25"):
        send_all(sock, b"abc", IOTimeouts(read=5.0, write=0.25))
    assert sock.log[-1] == ("timeout", 5.0)                     # okuma süresi geri yüklendi


def test_proxy_connect_gonderimi_write_ile_sinirli():
    sock = _RecSock()
    sock.recv_buf = b"HTTP/1.1 200 Connection established\r\n\r\n"
    http_connect(sock, ProxyConfig("http", "127.0.0.1", 1), "example.com", 443,
                 IOTimeouts(read=9.0, write=0.5))
    assert sock.log[0] == ("timeout", 0.5) and sock.log[1][0] == "send"
    assert sock.log[2] == ("timeout", 9.0)                       # tünel okumaları connect ile


def test_socks5_gonderimi_write_ile_sinirli_ve_zaman_asimi():
    sock = _RecSock(fail_after=0)
    with pytest.raises(TimeoutError, match="Timeout.write"):
        socks5_connect(sock, ProxyConfig("socks5", "127.0.0.1", 1), "example.com", 443,
                       IOTimeouts(read=9.0, write=0.5))


# ------------------------------------------------------- neden belirleme: kaba saat
# Windows'ta zaman aşımı saati ~15,6 ms adımlıdır: soket zaman aşımı total yüzünden
# dolduğunda saat bitiş anından hemen ÖNCEYİ okuyabilir. Neden, hata sonrası saati okuyarak
# değil, süre kurulurken belirlenmelidir. Donmuş saat bu durumu her platformda canlandırır.
class _FrozenClock:
    def __init__(self, now: float = 100.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def perf_counter(self) -> float:
        return self.now


def test_send_all_total_belirleyiciyse_kaba_saatte_de_total():
    clock = _FrozenClock()
    sock = _RecSock(fail_after=0)
    io = IOTimeouts(read=10.0, write=10.0, deadline=clock.now + 0.8, clock=clock)
    with pytest.raises(TimeoutError, match="Timeout.total"):
        send_all(sock, b"abc", io)
    assert sock.log == [("timeout", pytest.approx(0.8)), ("timeout", 10.0)]


def test_send_all_write_belirleyiciyse_write():
    clock = _FrozenClock()
    io = IOTimeouts(read=10.0, write=0.5, deadline=clock.now + 0.8, clock=clock)
    with pytest.raises(TimeoutError, match="Timeout.write=0.5"):
        send_all(_RecSock(fail_after=0), b"abc", io)


class _TimeoutSock:
    """recv_record her zaman soket zaman aşımı verir; raw_socket zaman aşımını tutar."""

    def __init__(self):
        self.t = 30.0
        self.raw_socket = self

    def gettimeout(self):
        return self.t

    def settimeout(self, t):
        self.t = t

    def send_record(self, data, content_type=0x17, use_app_keys=True):
        pass

    def recv_record(self, skip_post_handshake=False):
        raise socket.timeout("timed out")


def test_h1_okuma_total_belirleyiciyse_kaba_saatte_de_total():
    clock = _FrozenClock()
    sock = _TimeoutSock()
    sock.io = IOTimeouts(read=10.0, write=10.0, deadline=clock.now + 0.8, clock=clock)
    conn = type("C", (), {"socket": sock})()
    with Session() as s, pytest.raises(TimeoutError, match="Timeout.total"):
        s._read_app_data(conn)
    sock.io = IOTimeouts(read=0.3, write=10.0, deadline=clock.now + 0.8, clock=clock)
    with Session() as s, pytest.raises(TimeoutError) as ei:
        s._read_app_data(conn)                      # read belirleyici: genel okuma hatası
    assert "Timeout.total" not in str(ei.value)


def test_h2_pencere_beklemesi_ve_okuma_total_kaba_saatte_de_total(monkeypatch):
    from fasthttpc.protocol import http2_parser
    from fasthttpc.protocol.http2_parser import Http2Connection
    clock = _FrozenClock()
    monkeypatch.setattr(http2_parser, "time", clock)
    conn = Http2Connection(_TimeoutSock())
    conn.read_timeout, conn.write_timeout, conn.deadline = 10.0, 10.0, clock.now + 0.8
    conn._stream_windows[1] = 0
    with pytest.raises(TimeoutError, match="Timeout.total"):
        conn._await_window(1, 16384)                # akış kontrolü beklemesi (gönderim)
    with pytest.raises(TimeoutError, match="Timeout.total"):
        conn._recv_record()                         # yanıt okuması
    conn.write_timeout = 0.5                        # write belirleyici
    with pytest.raises(TimeoutError, match="Timeout.write=0.5"):
        conn._await_window(1, 16384)


def test_async_total_nedeni_saatten_bagimsiz(monkeypatch):
    """Async: dıştaki total zaman aşımı, saat donmuş olsa da total olarak raporlanır; içteki
    read/write zaman aşımı mesajıyla korunur."""
    import asyncio

    from fasthttpc import AsyncSession, async_session
    from fasthttpc.models.urls import URL
    monkeypatch.setattr(async_session, "time", _FrozenClock())

    async def yavas(*a, **kw):
        await asyncio.sleep(5)

    async def ic_hata(*a, **kw):
        raise asyncio.TimeoutError("ic okuma")

    async def main():
        s = AsyncSession(timeout=Timeout(5, total=0.2))
        u = URL("https://t.test/")
        s._exchange = yavas
        with pytest.raises(asyncio.TimeoutError, match="Timeout.total"):
            await s._timed_exchange("GET", u, None, {}, b"", None)
        s._exchange = ic_hata
        with pytest.raises(asyncio.TimeoutError, match="ic okuma"):
            await s._timed_exchange("GET", u, None, {}, b"", None)
        await s.close()
    asyncio.run(main())
