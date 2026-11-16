"""Opt-in LIVE tests against real public servers (internet + outbound UDP/443): HTTP/3,
and certificate validation on both the QUIC and the TCP (TLS 1.3/1.2) path.

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
import socket
import ssl

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
from fasthttpc.security.tls12 import AL_HANDSHAKE_FAILURE, TLS12Error  # noqa: E402
from fasthttpc.tls13.errors import TLSAlertError  # noqa: E402
from fasthttpc.tls_crafter import TLSImpersonator  # noqa: E402

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

# badssl.com bad-certificate hosts. badssl.com only offers TLS 1.2 WITHOUT Extended
# Master Secret, which fasthttpc refuses at ServerHello, BEFORE the certificate is
# examined. These hosts therefore prove "refused, nothing fetched", not certificate
# validation; see test_badssl_bad_cert_hosts_refused and docs/testing.md.
BADSSL_BAD_CERT = (
    "https://expired.badssl.com/",
    "https://wrong.host.badssl.com/",
    "https://self-signed.badssl.com/",
    "https://untrusted-root.badssl.com/",
)
# badssl.com's own (valid-certificate) front page: same server, same missing EMS.
BADSSL_VALID_CERT = "https://badssl.com/"
# Every badssl check runs once per TLS profile, so a CI log shows exactly which
# ClientHello (if any) a badssl.com server resets: chrome_131 (the 0.6.x default),
# chrome_158 (the 0.7.0 default: trust_anchors 0xca34, ML-DSA sigalgs, ALPS 17613),
# firefox_160, safari_27 and fasthttpc's own non-browser "default" profile.
BADSSL_PROFILES = ("chrome_131", "chrome_158", "firefox_160", "safari_27", "default")

# Real servers that negotiate TLS 1.3 over TCP: certificate validation on the TCP path
# is exercised against these.
TCP_TLS13_ORIGINS = (
    "https://www.cloudflare.com/",
    "https://www.google.com/",
)

# TLS 1.3 front ends reached under a name their certificate cannot cover. A server
# can react to an unknown SNI in two ways: serve its default certificate (fasthttpc
# must then reject it with "no matching subjectAltName") or abort the handshake with
# the unrecognized_name alert (RFC 6066 §3; quic.nginx.org does this, which is why it
# is no longer used here). The alert never reaches certificate validation, so it
# proves nothing about hostname verification: it is tolerated per target, but at
# least one target must produce the SAN mismatch.
#  - www.google.com: Google's front ends answer an SNI they do not host with their
#    default *.google.com certificate.
#  - github.com: single-tenant front end, serves the github.com certificate
#    whatever the SNI.
MISMATCH_TARGETS = ("www.google.com", "github.com")
# RFC 2606 ``.invalid``: guaranteed never to appear in a publicly trusted certificate.
MISMATCH_WRONG_NAME = "fasthttpc-hostname-mismatch.invalid"

# The exact refusal fasthttpc.security.tls12.parse_server_hello_12 raises for a
# TLS 1.2 ServerHello without the extended_master_secret extension.
_EMS_REFUSAL = "Extended Master Secret (RFC 7627) kabul etmedi"
# cryptography's verifier error when the leaf's SAN does not cover the requested
# name. It checks the leaf's SAN before building the chain, so this is reported for
# a wrong name whether or not the chain itself would be trusted.
_SAN_MISMATCH = "no matching subjectAltName"
# TLS alert 112 (RFC 6066 §3): the server does not host the requested SNI name.
AL_UNRECOGNIZED_NAME = 112
# How fasthttpc.security.alerts.describe_alert renders it when the alert arrives as
# a plaintext record before ServerHello (raised as a plain ConnectionError).
_UNRECOGNIZED_NAME_TEXT = "fatal alert 112 (unrecognized_name)"


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


def _chain(exc: BaseException):
    """``exc`` and every exception it was raised from / during."""
    seen: set[int] = set()
    e: BaseException | None = exc
    while e is not None and id(e) not in seen:
        seen.add(id(e))
        yield e
        e = e.__cause__ or e.__context__


def _cert_error(exc: BaseException) -> CertificateValidationError | None:
    return next((e for e in _chain(exc) if isinstance(e, CertificateValidationError)), None)


def _ems_refusal(exc: BaseException) -> TLS12Error | None:
    """The specific "server did not accept Extended Master Secret" refusal, nothing else."""
    return next((e for e in _chain(exc) if isinstance(e, TLS12Error)
                 and e.alert == AL_HANDSHAKE_FAILURE and _EMS_REFUSAL in str(e)), None)


def _unrecognized_name_alert(exc: BaseException) -> BaseException | None:
    """Exactly the server's unrecognized_name alert, nothing else."""
    for e in _chain(exc):
        if isinstance(e, TLSAlertError) and e.description == AL_UNRECOGNIZED_NAME:
            return e
        if isinstance(e, ConnectionError) and _UNRECOGNIZED_NAME_TEXT in str(e):
            return e
    return None


def _hello_size(profile: str, host: str) -> int:
    """Size of one ClientHello record of ``profile`` for ``host`` (varies by up to
    ~100 bytes between connections: ECH GREASE length, extension permutation)."""
    name = None if profile == "default" else profile
    return len(TLSImpersonator(host, profile=name).build_client_hello()[0])


def _assert_cert_rejected(excinfo) -> CertificateValidationError:
    """The TCP path raises ``ConnectionError`` chained from ``CertificateValidationError``;
    the QUIC path raises ``CertificateValidationError`` itself. Either is a rejection.
    Any other error (reset, timeout, protocol error) is NOT accepted as one."""
    err = _cert_error(excinfo.value)
    assert err is not None, f"not a certificate error: {excinfo.value!r}"
    return err


class _PinnedResolver:
    """Session ``resolver=``: every name resolves to one fixed IPv4 address (like
    ``curl --resolve``). The URL's host name is still what is sent as SNI and what the
    certificate is verified against; only the TCP destination is pinned."""

    def __init__(self, ip: str):
        self.ip = ip

    def resolve_one(self, host: str) -> str:
        return self.ip


def _ipv4_of(host: str) -> str:
    return socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]


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


# TCP path (TLS 1.3 / TLS 1.2 stack of fasthttpc itself; http3 is off by default).


@pytest.mark.parametrize("origin", TCP_TLS13_ORIGINS)
def test_tcp_tls13_baseline_succeeds(origin):
    """Control for the two tests below: with the default trust store the same origins
    are fetched over TLS 1.3, so a failure below is caused by the certificate, not by
    reachability or an unsupported protocol."""
    with Session() as s:
        r = s.get(origin, timeout=TIMEOUT)
    assert r.status_code < 500
    assert r.tls_info is not None and r.tls_info["version"] == "TLSv1.3", r.tls_info


@pytest.mark.parametrize("origin", TCP_TLS13_ORIGINS)
def test_tcp_rejects_chain_from_untrusted_ca(origin, tmp_path):
    """TCP mirror of test_h3_rejects_chain_from_untrusted_ca: a real TLS 1.3 server whose
    root is not in ``verify=`` must fail with CertificateValidationError in the chain."""
    with Session(verify=_unrelated_ca(tmp_path)) as s:
        with pytest.raises((CertificateValidationError, ConnectionError)) as ei:
            s.get(origin, timeout=TIMEOUT)
    _assert_cert_rejected(ei)


def _hostname_mismatch_outcome(target: str) -> str:
    """Pin the TCP destination to ``target``'s IPv4 address. Under its own name the
    request must succeed over TLS 1.3 (control); under the ``.invalid`` name it must
    fail. Returns "san_mismatch" or "unrecognized_name"; anything else fails."""
    resolver = _PinnedResolver(_ipv4_of(target))
    with Session(resolver=resolver) as s:
        ok = s.get(f"https://{target}/", timeout=TIMEOUT)
        assert ok.status_code < 500, _describe(ok)
        assert ok.tls_info is not None and ok.tls_info["version"] == "TLSv1.3", (
            f"{target}: control request did not use TLS 1.3: {ok.tls_info}")
    with Session(resolver=resolver) as s:
        with pytest.raises((CertificateValidationError, ConnectionError)) as ei:
            s.get(f"https://{MISMATCH_WRONG_NAME}/", timeout=TIMEOUT)
    err = _cert_error(ei.value)
    if err is not None:
        causes = " | ".join(str(e) for e in _chain(err))
        assert _SAN_MISMATCH in causes, (
            f"{target}: certificate error, but not a hostname mismatch: {causes}")
        return "san_mismatch"
    assert _unrecognized_name_alert(ei.value) is not None, (
        f"{target}: neither a certificate error nor the unrecognized_name alert "
        f"(a reset/timeout/protocol error proves nothing): {ei.value!r}")
    return "unrecognized_name"


def test_tcp_rejects_hostname_mismatch():
    """Real TLS 1.3 servers reached under a name their certificate does not cover.

    For every target in MISMATCH_TARGETS the TCP destination is pinned to the target's
    IPv4 address; the URL host (sent as SNI and verified) is either the right name
    (control: must succeed over TLS 1.3 with the default trust store) or an RFC 2606
    ``.invalid`` name, which no publicly trusted certificate can contain.

    Per target the wrong name must give either the SAN mismatch itself or exactly the
    unrecognized_name alert (the server refused the SNI before sending a certificate).
    The alert proves nothing about hostname verification, so at least one target must
    produce the SAN mismatch. Any other error (reset, timeout, a different certificate
    error) fails the test."""
    outcomes = {target: _hostname_mismatch_outcome(target) for target in MISMATCH_TARGETS}
    assert "san_mismatch" in outcomes.values(), (
        "no target served a certificate for the unknown name, so hostname "
        f"verification was never reached: {outcomes}")


@pytest.mark.parametrize("profile", BADSSL_PROFILES)
@pytest.mark.parametrize("url", BADSSL_BAD_CERT)
def test_badssl_bad_cert_hosts_refused(url, profile):
    """badssl.com bad-certificate hosts must be refused (nothing fetched), per profile.

    This does NOT test certificate validation: badssl.com serves only TLS 1.2 without
    Extended Master Secret, so fasthttpc refuses it at ServerHello, before the
    certificate is examined. Accepted outcomes: a certificate error (should badssl ever
    add TLS 1.3/EMS) or exactly the EMS refusal. A reset, timeout or any other error is
    a FAILURE that names the profile: it does not show why the host was refused. If
    only some profiles are reset, their ClientHello is the suspect; compare with
    test_badssl_reachable_with_stdlib_ssl (OpenSSL's ClientHello, same hosts)."""
    host = url.split("/")[2]
    with Session(impersonate=profile) as s:
        with pytest.raises(Exception) as ei:
            s.get(url, timeout=TIMEOUT)
    assert _cert_error(ei.value) is not None or _ems_refusal(ei.value) is not None, (
        f"{url} with profile {profile} (ClientHello ~{_hello_size(profile, host)} bytes): "
        f"refused, but neither by certificate validation nor by the EMS check "
        f"(remote reset/timeout?): {ei.value!r}")


@pytest.mark.parametrize("profile", BADSSL_PROFILES)
def test_badssl_valid_cert_host_refused_for_missing_ems(profile):
    """badssl.com's valid-certificate front page is refused by the EMS check too, which
    shows the refusals above are independent of the certificates. If this starts
    failing because badssl.com now succeeds, it has gained TLS 1.3 or EMS: the
    bad-certificate tests above then reach certificate validation, and docs/testing.md
    should be updated."""
    host = BADSSL_VALID_CERT.split("/")[2]
    with Session(impersonate=profile) as s:
        with pytest.raises(Exception) as ei:
            s.get(BADSSL_VALID_CERT, timeout=TIMEOUT)
    assert _ems_refusal(ei.value) is not None, (
        f"profile {profile} (ClientHello ~{_hello_size(profile, host)} bytes): "
        f"not the EMS refusal: {ei.value!r}")


@pytest.mark.parametrize("url", (*BADSSL_BAD_CERT, BADSSL_VALID_CERT))
def test_badssl_reachable_with_stdlib_ssl(url):
    """Control for the badssl tests: the same hosts through Python's ssl module
    (OpenSSL's ClientHello, certificate verification ON, certifi roots). OpenSSL
    accepts TLS 1.2 without EMS, so the handshake reaches the certificate: the
    bad-certificate hosts must fail with SSLCertVerificationError and the front page
    must complete. This passing while fasthttpc profiles are reset means the reset
    is specific to their ClientHello; this being reset too means badssl.com itself
    was dropping connections."""
    import certifi

    host = url.split("/")[2]
    ctx = ssl.create_default_context(cafile=certifi.where())
    with socket.create_connection((host, 443), timeout=TIMEOUT) as raw:
        if url == BADSSL_VALID_CERT:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                assert tls.version() in ("TLSv1.2", "TLSv1.3"), tls.version()
            return
        with pytest.raises(ssl.SSLCertVerificationError):
            ctx.wrap_socket(raw, server_hostname=host)


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
