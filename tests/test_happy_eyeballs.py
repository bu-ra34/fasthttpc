"""Happy Eyeballs (RFC 8305): ağsız birim testleri (yalnızca loopback)."""
import errno
import socket
import time

import pytest

from fasthttpc.transport import happy_eyeballs as he


def _listener(family=socket.AF_INET, host="127.0.0.1"):
    ls = socket.socket(family, socket.SOCK_STREAM)
    ls.bind((host, 0))
    ls.listen(8)
    return ls


def _closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _info(family, addr):
    return (family, socket.SOCK_STREAM, 0, "", addr)


class _KaraDelik:
    """connect() hiç tamamlanmayan (SYN'e yanıt gelmeyen) rota: yazılabilir olmayan fd."""
    def __init__(self, *a):
        self._a, self._b = socket.socketpair()
        self._a.setblocking(False)
        try:                                   # gönderim tamponunu doldur -> asla yazılabilir değil
            while True:
                self._a.send(b"x" * 65536)
        except (BlockingIOError, OSError):
            pass
        self.closed = False

    def setsockopt(self, *a): pass
    def setblocking(self, f): pass
    def connect_ex(self, addr): return errno.EINPROGRESS
    def fileno(self): return self._a.fileno()
    def getsockopt(self, *a): return 0
    def close(self):
        self.closed = True
        self._a.close()
        self._b.close()


def test_ilk_adres_kara_delik_ikinci_acik_hizli_baglanir():
    ls = _listener()
    kara = []

    def fabrika(family, socktype, proto):
        if family == socket.AF_INET6:         # "IPv6 rotası kara delik"
            k = _KaraDelik()
            kara.append(k)
            return k
        return socket.socket(family, socktype, proto)

    infos = [_info(socket.AF_INET6, ("::1", ls.getsockname()[1], 0, 0)),
             _info(socket.AF_INET, ls.getsockname())]
    t = time.perf_counter()
    s = he.connect_infos(infos, 10, delay=0.05, _socket=fabrika)
    dt = time.perf_counter() - t
    try:
        assert s.getpeername() == ls.getsockname()
        assert 0.04 < dt < 2                   # gecikme kadar bekledi, 10 sn zaman aşımını değil
        assert kara and kara[0].closed         # kaybeden deneme kapatıldı
        assert s.gettimeout() == 10
    finally:
        s.close()
        ls.close()


def test_reddedilen_adreste_beklemeden_sonrakine_gecer():
    ls = _listener()
    infos = [_info(socket.AF_INET, ("127.0.0.1", _closed_port())),
             _info(socket.AF_INET, ls.getsockname())]
    t = time.perf_counter()
    s = he.connect_infos(infos, 10, delay=5.0)     # gecikme 5 sn: hata -> hemen sonraki
    assert time.perf_counter() - t < 2
    s.close()
    ls.close()


def test_hepsi_basarisizsa_son_hata_yukselir():
    infos = [_info(socket.AF_INET, ("127.0.0.1", _closed_port()))]
    with pytest.raises(ConnectionRefusedError):
        he.connect_infos(infos, 5)


def test_hepsi_kara_delikse_toplam_zaman_asimi():
    infos = [_info(socket.AF_INET6, ("::1", 9, 0, 0)), _info(socket.AF_INET, ("127.0.0.1", 9))]
    t = time.perf_counter()
    with pytest.raises(TimeoutError):
        he.connect_infos(infos, 0.3, delay=0.05, _socket=lambda *a: _KaraDelik())
    assert 0.25 < time.perf_counter() - t < 2


def test_aileler_dönüşümlü_siralanir():
    a1, a2, b1 = _info(10, "a1"), _info(10, "a2"), _info(2, "b1")
    assert he.interleave([a1, a2, b1]) == [a1, b1, a2]
    assert he.interleave([b1, a1, a2]) == [b1, a1, a2]


def test_create_connection_localhost_ikinci_aileden_baglanir(monkeypatch):
    """getaddrinfo ::1 (kimse dinlemiyor) + 127.0.0.1 (dinliyor) döndürür."""
    ls = _listener()
    port = ls.getsockname()[1]
    infos = [_info(socket.AF_INET6, ("::1", port, 0, 0)), _info(socket.AF_INET, ("127.0.0.1", port))]
    monkeypatch.setattr(he.socket, "getaddrinfo", lambda *a, **k: infos)
    s = he.create_connection(("localhost", port), 5)
    assert s.getpeername() == ("127.0.0.1", port)
    s.close()
    ls.close()


def test_izin_reddi_beklemeden_yukselir(monkeypatch):
    class Reddeden(_KaraDelik):
        def connect_ex(self, addr): return errno.EACCES
    with pytest.raises(PermissionError):
        he.connect_infos([_info(socket.AF_INET, ("127.0.0.1", 9))], 5, _socket=lambda *a: Reddeden())


# --------------------------------------------------------------- kütüphane entegrasyonu
def _localhost_cift_yigin(monkeypatch, port):
    """Windows'taki gibi: localhost -> ::1 (dinleyen yok) önce, 127.0.0.1 sonra."""
    infos = [_info(socket.AF_INET6, ("::1", port, 0, 0)), _info(socket.AF_INET, ("127.0.0.1", port))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: infos)


def test_httpconnection_connect_happy_eyeballs_kullanir(monkeypatch):
    from fasthttpc.transport.connection_pool import HTTPConnection
    cagrilar = []
    gercek = he.connect_infos

    def spy(infos, timeout, **kw):
        cagrilar.append((list(infos), timeout, kw.get("delay", he.CONNECTION_ATTEMPT_DELAY)))
        return gercek(infos, timeout, **kw)
    monkeypatch.setattr("fasthttpc.transport.connection_pool.connect_infos", spy)
    ls = _listener()
    port = ls.getsockname()[1]
    _localhost_cift_yigin(monkeypatch, port)
    c = HTTPConnection(("http", "localhost", port))
    c.connect(timeout=5)
    try:
        assert len(cagrilar) == 1 and len(cagrilar[0][0]) == 2
        assert c.socket.getpeername() == ("127.0.0.1", port)
        assert c.socket.gettimeout() == 5
    finally:
        c.close()
        ls.close()


def test_proxy_sync_baglantisi_happy_eyeballs(monkeypatch):
    from fasthttpc.transport import proxy as px
    ls = _listener()
    port = ls.getsockname()[1]
    _localhost_cift_yigin(monkeypatch, port)
    seen = []
    monkeypatch.setattr(px, "open_tunnel", lambda sock, *a: seen.append(sock.getpeername()))
    s = px.connect_via_proxy(px.ProxyConfig("http", "localhost", port), "example.com", 443, timeout=5)
    s.close()
    ls.close()
    assert seen == [("127.0.0.1", port)]


def test_async_open_connection_happy_eyeballs_gecikmesiyle_cagrilir(monkeypatch):
    """Tüm asyncio bağlantı noktaları happy_eyeballs_delay geçirir (Python 3.8+)."""
    import asyncio

    from fasthttpc.async_session import AsyncSession
    from fasthttpc.tls13.async_stream import AsyncTLSStream
    kwlist = []
    gercek = asyncio.open_connection

    async def spy(*a, **kw):
        kwlist.append(kw)
        return await gercek(*a, **kw)
    monkeypatch.setattr(asyncio, "open_connection", spy)

    async def main():
        ls = _listener()
        port = ls.getsockname()[1]
        _localhost_cift_yigin(monkeypatch, port)
        with pytest.raises(Exception):          # TLS konuşmayan sunucu: el sıkışma hatası beklenir
            await asyncio.wait_for(AsyncTLSStream.connect("localhost", port, "chrome_131"), 1)
        s = AsyncSession(timeout=2)
        with pytest.raises(Exception):
            await s.get(f"http://localhost:{port}/")
        await s.close()
        ls.close()
    asyncio.run(main())
    assert kwlist and all(k.get("happy_eyeballs_delay") == he.CONNECTION_ATTEMPT_DELAY for k in kwlist)
