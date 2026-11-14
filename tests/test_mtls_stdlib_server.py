"""mTLS uçtan uca: Python ssl sunucusu (CERT_REQUIRED) + sync/async Session (loopback)."""
from __future__ import annotations

import asyncio
import os
import socket
import ssl
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fasthttpc import AsyncSession, Session  # noqa: E402
from interop import pki  # noqa: E402


class Env:
    def __init__(self, d):
        self.sca = pki.make_cert("S CA", None, "p256", ca=True)
        self.sca_path = pki.write_ca(d, "sca", self.sca)
        self.srv = pki.write(d, "srv", pki.make_cert("localhost", self.sca, "p256"))
        self.cca = pki.make_cert("C CA", None, "p256", ca=True)
        self.cca_path = pki.write_ca(d, "cca", self.cca)
        self.cl = {}
        for k in ("rsa2048", "p256", "ed25519"):
            c = pki.make_cert(f"kimlik-{k}", self.cca, k, server_auth=False, sans=[])
            cp, kp = pki.write(d, f"c_{k}", c)
            os.chmod(kp, 0o600)
            self.cl[k] = (cp, kp)
        self.rogue = pki.make_cert("rogue", pki.make_cert("R CA", None, "p256", ca=True), "p256",
                                   server_auth=False, sans=[])
        self.rogue_files = pki.write(d, "rogue", self.rogue)
        os.chmod(self.rogue_files[1], 0o600)


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    return Env(tmp_path_factory.mktemp("stdmtls"))


class Srv:
    def __init__(self, env, max_version):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*env.srv)
        ctx.load_verify_locations(env.cca_path)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.maximum_version = max_version
        ctx.set_alpn_protocols(["http/1.1"])
        self.ctx = ctx
        self.ls = socket.socket()
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(16)
        self.port = self.ls.getsockname()[1]
        self.failures = 0
        self.version = None
        self._stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while not self._stop:
            try:
                c, _ = self.ls.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c):
        try:
            c.settimeout(10)
            with self.ctx.wrap_socket(c, server_side=True) as s:
                self.version = s.version()
                cn = s.getpeercert()["subject"][0][0][1].encode()
                s.recv(65536)
                s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(cn), cn))
        except Exception:
            self.failures += 1
        finally:
            try:
                c.close()
            except OSError:
                pass

    def close(self):
        self._stop = True
        self.ls.close()


VERS = {"tls13": ssl.TLSVersion.TLSv1_3, "tls12": ssl.TLSVersion.TLSv1_2}


def _sync(port, ca, cert):
    with Session(impersonate="chrome_131", verify=ca, timeout=10, cert=cert) as s:
        return s.get(f"https://localhost:{port}/")


def _async(port, ca, cert):
    async def run():
        async with AsyncSession(impersonate="chrome_131", verify=ca, timeout=10, cert=cert) as s:
            return await s.get(f"https://localhost:{port}/")
    return asyncio.run(run())


@pytest.mark.parametrize("fn", [_sync, _async], ids=["sync", "async"])
@pytest.mark.parametrize("key", ["rsa2048", "p256", "ed25519"])
@pytest.mark.parametrize("ver", list(VERS))
def test_uctan_uca(env, ver, key, fn):
    srv = Srv(env, VERS[ver])
    try:
        r = fn(srv.port, env.sca_path, env.cl[key])
        assert r.status_code == 200
        assert r.content == f"kimlik-{key}".encode()           # sunucu doğru kimliği gördü
        assert srv.version == ("TLSv1.3" if ver == "tls13" else "TLSv1.2")
    finally:
        srv.close()


@pytest.mark.parametrize("fn", [_sync, _async], ids=["sync", "async"])
@pytest.mark.parametrize("ver", list(VERS))
def test_sertifikasiz_ve_yanlis_ca_reddedilir(env, ver, fn):
    srv = Srv(env, VERS[ver])
    try:
        for cert in (None, env.rogue_files):
            ok = False
            try:
                fn(srv.port, env.sca_path, cert)
                ok = True
            except Exception:
                pass                           # (TLS 1.3'te hata okuma sırasında gelir)
            assert not ok, "sunucu istemciyi KABUL etti"
        for _ in range(100):           # sunucu iş parçacıkları el sıkışma hatasını kaydedene dek bekle
            if srv.failures >= 2:
                break
            time.sleep(0.05)
    finally:
        srv.close()
    assert srv.failures >= 2


def test_session_cert_parametre_hatalari(env):
    from fasthttpc.security.client_cert import ClientCertError
    with pytest.raises(ClientCertError):
        Session(cert=("yok.pem", "yok.key"))
    with pytest.raises(ValueError, match="impersonate"):
        AsyncSession(impersonate=None, cert=env.cl["p256"])


def test_havuz_anahtarina_cert_kimligi_girer(env):
    from fasthttpc.models.urls import URL
    from fasthttpc.transport.connection_pool import ConnectionPool
    a = AsyncSession(impersonate="chrome_131", cert=env.cl["p256"])
    b = AsyncSession(impersonate="chrome_131", cert=env.cl["rsa2048"])
    c = AsyncSession(impersonate="chrome_131")
    u = URL("https://localhost:8443/")
    ka, kb, kc = a._h1_key(u, None), b._h1_key(u, None), c._h1_key(u, None)
    assert len({ka, kb, kc}) == 3 and a._origin_key(u, None) != b._origin_key(u, None) != c._origin_key(u, None)
    p1, p2, p3 = (ConnectionPool(tls_scope=x) for x in ("cert:a", "cert:b", None))
    assert len({p1._key(("https", "h", 443)), p2._key(("https", "h", 443)), p3._key(("https", "h", 443))}) == 3
    assert p3._key(("https", "h", 443)) == ("https", "h", 443)       # sertifikasız: eski anahtar biçimi
