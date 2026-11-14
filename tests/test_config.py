"""fasthttpc.config — Timeout / Limits / verify çözümlemesi."""
import pytest

from fasthttpc import Limits, Session, Timeout
from fasthttpc.config import resolve_verify
from fasthttpc.timeout import Timeout as LegacyTimeout


def test_legacy_import_ayni_sinif():
    assert LegacyTimeout is Timeout


def test_tek_deger_tum_alanlara():
    t = Timeout(10)
    assert (t.connect, t.read, t.write, t.pool) == (10.0, 10.0, 10.0, 10.0)


def test_alan_bazli_gecersiz_kilma():
    t = Timeout(10, connect=2, pool=None)
    assert t.connect == 2.0 and t.read == 10.0 and t.write == 10.0 and t.pool is None


def test_eski_imza_uyumlu():
    t = Timeout(connect=5, read=60)
    assert t.connect_timeout == 5.0 and t.read_timeout == 60.0
    assert t.write is None and t.write_timeout == 30.0
    assert Timeout(default=3).read == 3.0


def test_from_value():
    assert Timeout.from_value(5) == Timeout(5.0)
    assert Timeout.from_value(None) == Timeout(30.0)
    t = Timeout(1)
    assert Timeout.from_value(t) is t
    with pytest.raises(TypeError):
        Timeout.from_value("10")
    with pytest.raises(TypeError):
        Timeout.from_value(True)


def test_timeout_kopyalama_ve_negatif():
    base = Timeout(5, read=9)
    assert Timeout(base, write=1) == Timeout(5, read=9, write=1)
    with pytest.raises(ValueError):
        Timeout(-1)


def test_limits_dogrulama():
    assert Limits().max_connections == 10
    with pytest.raises(ValueError):
        Limits(max_connections=0)
    with pytest.raises(ValueError):
        Limits(keepalive_expiry=-1)


def test_session_float_timeout_hala_calisir():
    s = Session(timeout=7)
    assert s.timeout.connect_timeout == 7.0 and s.timeout.read_timeout == 7.0
    assert s.pool.timeout == 7.0


def test_session_limits_havuza_uygulanir():
    s = Session(limits=Limits(max_connections=3, max_keepalive_connections=1,
                              keepalive_expiry=None))
    assert s.pool.max_connections == 3
    assert s.pool.max_keepalive_connections == 1
    assert s.pool.idle_timeout is None


def test_session_varsayilan_limits_eski_davranis():
    s = Session(max_connections=4)
    assert s.pool.max_connections == 4
    assert s.pool.idle_timeout == 30.0


def test_keepalive_siniri_release_de_uygulanir():
    from fasthttpc.transport.connection_pool import HTTPConnection

    s = Session(limits=Limits(max_connections=5, max_keepalive_connections=1))
    origin = ("https", "a.example", 443)
    conns = []
    for _ in range(2):
        c = HTTPConnection(origin)
        c.is_closed = False
        s.pool._get_semaphore(origin).acquire()
        conns.append(c)
    for c in conns:
        s.pool.release(c)
    assert len(s.pool._pools[origin]) == 1
    assert conns[1].is_closed


# --- verify --------------------------------------------------------------

def test_verify_false_desteklenmez():
    with pytest.raises(ValueError, match="desteklenmez"):
        Session(verify=False)


def test_verify_true_varsayilan():
    assert resolve_verify(True) is None
    assert Session()._ca_path is None


def test_verify_yol(tmp_path):
    pem = tmp_path / "ca.pem"
    pem.write_text("x")
    s = Session(verify=str(pem))
    assert s._ca_path == str(pem.resolve())
    assert resolve_verify(pem) == str(pem.resolve())  # PathLike


def test_verify_olmayan_dosya(tmp_path):
    with pytest.raises(FileNotFoundError):
        Session(verify=str(tmp_path / "yok.pem"))


def test_verify_gecersiz_tip():
    with pytest.raises(TypeError):
        resolve_verify(1)


def test_verify_negotiate_e_tasinir(tmp_path, monkeypatch):
    """ca_path, Session -> TLSAdapter.negotiate(ca_path=...) yolunu izlemeli."""
    from fasthttpc import session as session_mod

    pem = tmp_path / "ca.pem"
    pem.write_text("x")
    s = Session(verify=str(pem))

    class FakeConn:
        tls_established = False
        h2_conn = None
        socket = object()

        def close(self):
            pass

    seen = {}

    def fake_negotiate(sock, host, profile, *, ca_path=None, port=None):
        seen["ca_path"] = ca_path
        seen["host"] = host
        seen["port"] = port
        raise ConnectionError("test: el sıkışma kesildi")

    monkeypatch.setattr(s.pool, "acquire", lambda url, timeout=None: FakeConn())
    monkeypatch.setattr(s.pool, "release", lambda conn: None)
    monkeypatch.setattr(session_mod.TLSAdapter, "negotiate", staticmethod(fake_negotiate))
    with pytest.raises(ConnectionError):
        s.get("https://intranet.example/")
    assert seen == {"ca_path": str(pem.resolve()), "host": "intranet.example", "port": 443}


def test_async_verify(tmp_path):
    import warnings
    from fasthttpc import AsyncSession

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with pytest.raises(ValueError):
            AsyncSession(verify=False)
        pem = tmp_path / "ca.pem"
        pem.write_text("x")
        assert AsyncSession(impersonate=None, verify=str(pem))._ca_path == str(pem.resolve())
