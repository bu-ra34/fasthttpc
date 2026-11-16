"""Opt-in LIVE HTTP/3 tests against real public servers (internet + outbound UDP/443).

Skipped unless ``FASTHTTPC_LIVE=1``: they depend on third-party servers and on the
network (UDP/443 egress, no TLS interception), so they must not run in CI or in a
plain ``pytest -q``. Run them with::

    FASTHTTPC_LIVE=1 python -m pytest -m live tests/live -v

See docs/testing.md ("Live HTTP/3 tests") for what each failure means.
"""
from __future__ import annotations

import asyncio
import datetime
import os

import pytest

LIVE = os.environ.get("FASTHTTPC_LIVE") == "1"

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not LIVE,
        reason="live internet test (public HTTP/3 servers, needs outbound UDP/443): "
               "opt in with FASTHTTPC_LIVE=1",
    ),
]

if LIVE:
    # Opted in: a missing HTTP/3 backend is a setup error, not a reason to skip (a
    # live run that silently skips every test would look green).
    import aioquic  # noqa: F401
else:
    pytest.importorskip("aioquic")

from fasthttpc import AsyncSession, Session  # noqa: E402
from fasthttpc.http3 import Http3Options  # noqa: E402
from fasthttpc.security.cert_validator import CertificateValidationError  # noqa: E402

TIMEOUT = 15
# Short QUIC handshake budget so a blocked UDP path fails fast instead of hanging.
H3_CONNECT_TIMEOUT = 5.0

# Origins that advertise ``Alt-Svc: h3=...`` over TCP and really serve HTTP/3.
DISCOVERY_ORIGINS = (
    "https://cloudflare-quic.com/",
    "https://quic.nginx.org/",
)

# Cloudflare's trace endpoint reports, from the SERVER side, which protocol it saw.
CF_TRACE = "https://cloudflare-quic.com/cdn-cgi/trace"

# Each of these must be rejected by certificate verification (never fetched).
BAD_TLS = (
    "https://expired.badssl.com/",
    "https://wrong.host.badssl.com/",
    "https://self-signed.badssl.com/",
    "https://untrusted-root.badssl.com/",
)


def _opts(mode: str) -> Http3Options:
    return Http3Options(mode=mode, connect_timeout=H3_CONNECT_TIMEOUT)


def _describe(r) -> str:
    """Context for assertion messages: status, protocol, server and Alt-Svc."""
    return (f"{r.request.url} -> {r.status_code} {r.http_version} "
            f"server={r.headers.get('server')!r} alt-svc={r.headers.get('alt-svc')!r}")


def _assert_h3_ok(r) -> None:
    assert r.status_code == 200 and r.http_version == "HTTP/3", _describe(r)


def _trace(text: str) -> dict:
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def _assert_cert_rejected(excinfo) -> None:
    """The TCP path raises ``ConnectionError`` chained from ``CertificateValidationError``;
    the QUIC path raises ``CertificateValidationError`` itself. Either is a rejection."""
    e = excinfo.value
    while e is not None and not isinstance(e, CertificateValidationError):
        e = e.__cause__ or e.__context__
    assert e is not None, f"not a certificate error: {excinfo.value!r}"


def _unrelated_ca(tmp_path) -> str:
    """A freshly generated CA that has signed nothing on the internet."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fasthttpc live unrelated CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    path = tmp_path / "unrelated-ca.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(path)


# -- discovery + negotiation ----------------------------------------------------------


@pytest.mark.parametrize("origin", DISCOVERY_ORIGINS)
def test_alt_svc_discovery_then_h3(origin):
    """mode=auto: the first request (TCP) learns Alt-Svc, the next one uses HTTP/3."""
    with Session(http3=_opts("auto")) as s:
        r1 = s.get(origin, timeout=TIMEOUT)
        assert r1.status_code == 200, _describe(r1)
        assert r1.http_version in ("HTTP/2", "HTTP/1.1"), _describe(r1)
        alt_svc = ", ".join(r1.headers.get_list("alt-svc"))
        assert "h3=" in alt_svc, f"{origin} did not advertise h3 over TCP: {alt_svc!r}"
        assert s._h3.state.altsvc.get((r1.request.url.host, 443)) is not None

        r2 = s.get(origin, timeout=TIMEOUT)
        assert r2.status_code == 200, _describe(r2)
        assert r2.http_version == "HTTP/3", (
            f"Alt-Svc advertised h3 but the request fell back to {r2.http_version}; "
            "is outbound UDP/443 blocked? (test_h3_force_* show the exact QUIC error)")


def test_h3_force_get_body_verified_by_server():
    """Force HTTP/3 and verify the body: Cloudflare echoes the protocol it received."""
    with Session(http3=_opts("force")) as s:
        r = s.get(CF_TRACE, timeout=TIMEOUT)
    _assert_h3_ok(r)
    fields = _trace(r.text)
    assert fields.get("h") == "cloudflare-quic.com", r.text
    assert fields.get("http") == "http/3", r.text
    assert fields.get("tls") == "TLSv1.3", r.text


def test_h3_force_requests_reuse_connection():
    with Session(http3=_opts("force")) as s:
        responses = [s.get("https://quic.nginx.org/", timeout=TIMEOUT) for _ in range(3)]
        assert len(s._h3._conns) == 1, f"expected one pooled QUIC connection: {s._h3._conns!r}"
    for r in responses:
        _assert_h3_ok(r)
        assert b"NGINX QUIC" in r.content


def test_h3_force_google():
    with Session(http3=_opts("force")) as s:
        r = s.get("https://www.google.com/", timeout=TIMEOUT)
    _assert_h3_ok(r)
    assert b"<html" in r.content.lower()


def test_h3_force_async_get_body():
    async def go():
        async with AsyncSession(http3=_opts("force")) as s:
            return await s.get(CF_TRACE, timeout=TIMEOUT)
    r = asyncio.run(go())
    _assert_h3_ok(r)
    assert _trace(r.text).get("http") == "http/3", r.text


# -- fallback -----------------------------------------------------------------------


def test_fallback_to_h2_when_h3_unreachable():
    """Alt-Svc points at a UDP port nobody serves: the request must silently use h2.

    Deterministic on any network: it does not depend on UDP/443 being open."""
    origin = "https://cloudflare-quic.com/"
    with Session(http3=_opts("auto")) as s:
        r1 = s.get(origin, timeout=TIMEOUT)
        assert r1.http_version == "HTTP/2", _describe(r1)
        # Replace the discovered entry with an unreachable alternative (UDP port 1).
        s._h3.state.altsvc.update(("cloudflare-quic.com", 443), ['h3=":1"; ma=60'])
        r2 = s.get(origin, timeout=TIMEOUT)
        assert r2.status_code == 200 and r2.http_version == "HTTP/2", _describe(r2)
        assert b"QUIC" in r2.content
        # h3 is now disabled for this origin; the next request does not retry QUIC.
        assert s._h3.state.target_for("cloudflare-quic.com", 443) is None
        assert s.get(origin, timeout=TIMEOUT).http_version == "HTTP/2"


# -- certificate verification ------------------------------------------------------


@pytest.mark.parametrize("url", BAD_TLS)
def test_bad_certificates_rejected(url):
    """Expired / wrong host / self-signed / untrusted root must fail verification.

    Behind a TLS-intercepting egress proxy these are re-signed by the proxy's CA and
    this test fails, correctly: the client is then not talking to the real server."""
    with Session(http3=_opts("auto")) as s:
        with pytest.raises((CertificateValidationError, ConnectionError)) as ei:
            s.get(url, timeout=TIMEOUT)
    _assert_cert_rejected(ei)


def test_h3_rejects_chain_from_untrusted_ca(tmp_path):
    """The QUIC handshake verifies the chain: a real h3 server is rejected when its root
    is not trusted, and force mode surfaces the certificate error (no h2 fallback)."""
    with Session(http3=_opts("force"), verify=_unrelated_ca(tmp_path)) as s:
        with pytest.raises(CertificateValidationError):
            s.get(CF_TRACE, timeout=TIMEOUT)


def test_auto_mode_with_untrusted_ca_never_fetches(tmp_path):
    with Session(http3=_opts("auto"), verify=_unrelated_ca(tmp_path)) as s:
        with pytest.raises((CertificateValidationError, ConnectionError)) as ei:
            s.get("https://cloudflare-quic.com/", timeout=TIMEOUT)
    _assert_cert_rejected(ei)
