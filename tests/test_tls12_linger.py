"""Fatal alert sonrası kapanış RST DEĞİL, düzenli FIN olmalı (lingering close).

İstemcinin alım tamponunda okunmamış veri varken ``close()`` RST üretir. RST, karşı tarafın
henüz okumadığı verileri (gönderdiğimiz fatal alert'i!) Windows'ta siler (Linux'ta kuyruktaki
veri okunabilir kalır ama sonraki okuma ECONNRESET verir). Bu yüzden istemci alert'ten sonra
yazma yönünü kapatıp (FIN) kısa süre boşaltır, sonra kapatır.
"""
import socket
import threading
import time

import pytest

from fasthttpc.security import tls12
from fasthttpc.security.tls_adapter import TLSAdapter
from tls12_servers import HOST, Fake12Server, PKI12


@pytest.fixture(scope="module")
def pki():
    return PKI12()


@pytest.fixture(scope="module")
def files(pki, tmp_path_factory):
    return pki.write(tmp_path_factory.mktemp("tls12linger"))


class _GecikmeliSoket:
    """Sunucunun el sıkışma uçuşunun SON kaydını (ServerHelloDone) geciktirir: istemci SKE'de
    hata verip alert gönderdikten SONRA gelir. Kapanışta eş tarafın FIN mi RST mi gördüğünü yazar."""

    def __init__(self, s, gecikme=0.05, gecikmeli_gonderim_no=4):
        self._s, self._gecikme, self._no, self._n = s, gecikme, gecikmeli_gonderim_no, 0
        self.kapanis = None

    def sendall(self, b):
        self._n += 1
        if self._n >= self._no:
            time.sleep(self._gecikme)
        try:
            return self._s.sendall(b)
        except OSError:
            pass

    def close(self):
        try:
            self._s.settimeout(2)
            self.kapanis = "FIN" if self._s.recv(1) == b"" else "VERI"
        except ConnectionResetError:
            self.kapanis = "RST"
        except OSError as e:
            self.kapanis = f"hata:{e!r}"
        self._s.close()

    def __getattr__(self, n):
        return getattr(self._s, n)


def test_fatal_alert_sonrasi_kapanis_rst_degil_fin(pki, files, monkeypatch):
    # İstemci SKE imzasını doğrularken (yavaşlatıldı) ServerHelloDone çekirdek tamponuna gelir:
    # hata anında OKUNMAMIŞ veri vardır -> naif close() RST üretir.
    gercek = tls12.verify_server_key_exchange

    def yavas(*a, **k):
        time.sleep(0.25)
        return gercek(*a, **k)
    monkeypatch.setattr(tls12, "verify_server_key_exchange", yavas)
    srv = Fake12Server(pki, tamper={"bad_ske_sig"})
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    sarmal = {}

    def run():
        c, _ = ls.accept()
        sarmal["s"] = _GecikmeliSoket(c)
        srv.serve(sarmal["s"])
        ls.close()
    t = threading.Thread(target=run, daemon=True)
    t.start()

    s = socket.create_connection(("127.0.0.1", ls.getsockname()[1]), timeout=8)
    try:
        with pytest.raises(ConnectionError):
            TLSAdapter.negotiate(s, HOST, "chrome_131", ca_path=files[0])
    finally:
        s.close()
    t.join(10)
    assert srv.alerts and srv.alerts[0] == bytes([2, tls12.AL_DECRYPT_ERROR])
    assert sarmal["s"].kapanis == "FIN", f"eş taraf {sarmal['s'].kapanis} gördü (RST: okunmamış veriyle close)"


def test_shutdown_and_drain_sinirli_ve_hatasiz():
    from fasthttpc.transport.lingering import shutdown_and_drain
    a, b = socket.socketpair()
    a.settimeout(5)
    b.sendall(b"x" * 1000)                      # okunmamış veri
    t = time.perf_counter()
    shutdown_and_drain(a, max_wait=0.2)         # b hiç kapatmıyor -> en fazla ~0.2 sn
    assert 0.15 < time.perf_counter() - t < 1.5
    assert a.gettimeout() == 5                  # zaman aşımı geri yüklenir
    assert b.recv(10) == b""                    # a FIN gönderdi
    b.close()
    shutdown_and_drain(a, max_wait=0.2)         # eş kapalı/kırık: hata fırlatmaz
    a.close()
    shutdown_and_drain(a, max_wait=0.2)         # kapalı soket: hata fırlatmaz
