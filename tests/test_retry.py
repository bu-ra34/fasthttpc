"""fasthttpc.retry.Retry — birim testleri + Session/AsyncSession entegrasyonu (ağsız)."""
import asyncio
import email.utils
import time

import pytest

from fasthttpc import AsyncSession, MockTransport, Response, Retry, Session


# --- Retry birim ----------------------------------------------------------

def test_from_value():
    assert Retry.from_value(None).total == 0
    assert Retry.from_value(False).total == 0
    assert Retry.from_value(5).total == 5
    r = Retry(2)
    assert Retry.from_value(r) is r
    with pytest.raises(TypeError):
        Retry.from_value("3")
    with pytest.raises(ValueError):
        Retry(-1)


def test_varsayilan_metotlar_idempotent():
    r = Retry(3, status_forcelist=[503])
    for m in ("GET", "head", "PUT", "DELETE", "OPTIONS", "TRACE"):
        assert r.is_method_retryable(m)
    assert not r.is_method_retryable("POST")
    assert not r.is_method_retryable("PATCH")
    assert Retry(allowed_methods=None).is_method_retryable("POST")


def test_should_retry_status_sinirlar():
    r = Retry(2, status_forcelist=[503])
    assert r.should_retry_status("GET", 503, 0)
    assert r.should_retry_status("GET", 503, 1)
    assert not r.should_retry_status("GET", 503, 2)
    assert not r.should_retry_status("GET", 500, 0)
    assert not r.should_retry_status("POST", 503, 0)


def test_should_retry_error():
    from fasthttpc.security.cert_validator import CertificateValidationError

    r = Retry(1)
    assert r.should_retry_error("GET", ConnectionResetError(), 0)
    assert r.should_retry_error("GET", TimeoutError(), 0)
    assert not r.should_retry_error("GET", ConnectionError(), 1)
    assert not r.should_retry_error("POST", ConnectionError(), 0)
    assert not r.should_retry_error("GET", ValueError(), 0)
    assert not r.should_retry_error("GET", CertificateValidationError("x"), 0)
    assert not Retry(1, retry_on_connection_errors=False).should_retry_error(
        "GET", ConnectionError(), 0)


def test_backoff():
    r = Retry(5, backoff_factor=0.5, backoff_max=3)
    assert [r.get_backoff_time(n) for n in (1, 2, 3, 4)] == [0.5, 1.0, 2.0, 3.0]
    assert Retry(5).get_backoff_time(3) == 0.0


def test_retry_after_parse():
    assert Retry.parse_retry_after("7") == 7.0
    assert Retry.parse_retry_after("") is None
    assert Retry.parse_retry_after("çöp") is None
    future = email.utils.formatdate(time.time() + 60, usegmt=True)
    assert 55 <= Retry.parse_retry_after(future) <= 61
    past = email.utils.formatdate(time.time() - 60, usegmt=True)
    assert Retry.parse_retry_after(past) == 0.0


def test_get_delay_retry_after_oncelikli_ve_sinirli():
    r = Retry(3, backoff_factor=1, backoff_max=10)
    assert r.get_delay(1, Response(503, headers={"Retry-After": "4"})) == 4.0
    assert r.get_delay(1, Response(503, headers={"Retry-After": "9999"})) == 10.0
    # 500 Retry-After'ı tanımlı kodlardan değil → backoff
    assert r.get_delay(2, Response(500, headers={"Retry-After": "4"})) == 2.0
    assert Retry(3, respect_retry_after_header=False).get_delay(
        1, Response(429, headers={"Retry-After": "4"})) == 0.0


# --- Session entegrasyonu ------------------------------------------------

def _flaky(statuses, headers=None):
    seq = list(statuses)

    def handler(request):
        code = seq.pop(0)
        if isinstance(code, BaseException):
            raise code
        return Response(code, headers=headers or {}, body=b"ok")

    return handler


@pytest.fixture
def sleeps(monkeypatch):
    calls = []
    monkeypatch.setattr(time, "sleep", lambda s: calls.append(s))
    return calls


def test_session_status_retry(sleeps):
    t = MockTransport(_flaky([503, 503, 200]))
    s = Session(transport=t, retries=Retry(3, backoff_factor=0.1, status_forcelist=[503]))
    assert s.get("https://x.example/").status_code == 200
    assert len(t.requests) == 3
    assert sleeps == [0.1, 0.2]


def test_session_retry_tukenince_son_yanit(sleeps):
    t = MockTransport(_flaky([502, 502, 502]))
    s = Session(transport=t, retries=Retry(2, status_forcelist=[502]))
    assert s.get("https://x.example/").status_code == 502
    assert len(t.requests) == 3


def test_session_retry_after_saygi(sleeps):
    t = MockTransport(_flaky([429, 200], headers={"Retry-After": "3"}))
    s = Session(transport=t, retries=Retry(1, status_forcelist=[429]))
    assert s.get("https://x.example/").status_code == 200
    assert sleeps == [3.0]


def test_session_post_yeniden_denenmez(sleeps):
    t = MockTransport(_flaky([503, 200]))
    s = Session(transport=t, retries=Retry(3, status_forcelist=[503]))
    assert s.post("https://x.example/", data=b"a").status_code == 503
    assert len(t.requests) == 1


def test_session_baglanti_hatasi_retry(sleeps):
    t = MockTransport(_flaky([ConnectionResetError("rst"), TimeoutError(), 200]))
    s = Session(transport=t, retries=2)
    assert s.get("https://x.example/").status_code == 200
    assert len(t.requests) == 3


def test_session_baglanti_hatasi_tukenir(sleeps):
    t = MockTransport(_flaky([ConnectionError("a"), ConnectionError("b")]))
    s = Session(transport=t, retries=1)
    with pytest.raises(ConnectionError, match="b"):
        s.get("https://x.example/")


def test_session_varsayilan_retry_kapali(sleeps):
    t = MockTransport(_flaky([ConnectionError("a"), 200]))
    s = Session(transport=t)
    with pytest.raises(ConnectionError):
        s.get("https://x.example/")
    assert len(t.requests) == 1


def test_async_session_retry(monkeypatch):
    slept = []

    async def fake_sleep(d):
        slept.append(d)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    t = MockTransport(_flaky([503, ConnectionError("x"), 200]))

    async def main():
        s = AsyncSession(impersonate=None, transport=t,
                         retries=Retry(2, backoff_factor=1, status_forcelist=[503]))
        return await s.get("https://x.example/")

    assert asyncio.run(main()).status_code == 200
    assert slept == [1.0, 2.0]
