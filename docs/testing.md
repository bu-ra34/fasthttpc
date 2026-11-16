# Testing with MockTransport

`MockTransport` skips TLS, pooling and proxies, but redirects, cookies and
retries still run exactly as in production.

```python
from fasthttpc import Session, Response, MockTransport

def handler(request):
    if request.url.path == "/login":
        return Response(200, headers={"Set-Cookie": "sid=1"})
    return Response(200, headers={"Content-Type": "application/json"}, body=b'{"ok": true}')

transport = MockTransport(handler)
with Session(transport=transport) as s:
    s.get("https://api.example.com/login")
    assert s.get("https://api.example.com/me").json() == {"ok": True}
assert len(transport.requests) == 2
```

- Exceptions raised by the handler propagate to the caller (useful to test retries).
- With `AsyncSession(transport=...)` the handler may be `async def`.
- For a custom transport subclass `fasthttpc.BaseTransport` and implement
  `handle_request(request) -> Response`.

## Live HTTP/3 tests

The regular test suite is fully offline: HTTP/3 is exercised against a local
aioquic server on `127.0.0.1`. `tests/live/test_http3_live.py` additionally checks
HTTP/3 against real public servers. These tests are marked `live` and are
**skipped unless `FASTHTTPC_LIVE=1` is set**, so `pytest -q` and CI never touch
the network.

```bash
pip install -e ".[dev]"            # includes aioquic
FASTHTTPC_LIVE=1 python -m pytest -m live tests/live -v
```

Requirements: internet access, outbound **UDP/443** (QUIC), and a network that
does **not** intercept TLS. The tests use `cloudflare-quic.com`, `quic.nginx.org`,
`www.cloudflare.com`, `www.google.com`, `github.com` and `badssl.com`.

| Test | What it checks |
| --- | --- |
| `test_alt_svc_discovery_then_h3` | `http3=True`: first request over TCP learns `Alt-Svc: h3`, the next one is `HTTP/3` |
| `test_h3_force_*` | `http3="force"` GETs (sync and async) against Cloudflare, nginx and Google; Cloudflare's `/cdn-cgi/trace` body must report `http=http/3`; repeated requests reuse one QUIC connection |
| `test_fallback_to_h2_when_h3_unreachable` | Alt-Svc pointing at a dead UDP port: the request silently uses HTTP/2 and h3 is disabled for that origin |
| `test_h3_rejects_chain_from_untrusted_ca` | the QUIC handshake rejects a real server whose root is not trusted (`verify=` set to an unrelated CA) |
| `test_auto_mode_with_untrusted_ca_never_fetches` | in auto mode with an unrelated CA the request fails with a certificate error instead of falling back to an unverified fetch |
| `test_tcp_tls13_baseline_succeeds` | control: `www.cloudflare.com` and `www.google.com` are fetched over TCP with TLS 1.3 and the default trust store |
| `test_tcp_rejects_chain_from_untrusted_ca` | the same two servers over TCP with `verify=` set to a freshly generated, unrelated CA: `CertificateValidationError` must be in the exception chain |
| `test_tcp_rejects_hostname_mismatch` | for `www.google.com` and `github.com` the TCP connection is pinned (custom `resolver=`) to the target's IPv4 address; under its own name it succeeds over TLS 1.3, under `fasthttpc-hostname-mismatch.invalid` it must fail with a certificate error whose cause is "no matching subjectAltName" or with exactly the `unrecognized_name` alert, and at least one target must give the certificate error (see below) |
| `test_badssl_bad_cert_hosts_refused` | expired, wrong-host, self-signed and untrusted-root `badssl.com` hosts are refused, once per profile (`chrome_131`, `chrome_158`, `firefox_160`, `safari_27`, `default`): the error must be a certificate error or exactly the Extended Master Secret refusal (see below) |
| `test_badssl_valid_cert_host_refused_for_missing_ems` | `badssl.com` itself (valid certificate) is refused by the Extended Master Secret check, per profile, which shows that refusal does not depend on the certificate |
| `test_badssl_reachable_with_stdlib_ssl` | control: the same five `badssl.com` hosts through Python's `ssl` module (OpenSSL's ClientHello, verification on, certifi roots): bad-certificate hosts fail with `SSLCertVerificationError`, the front page completes |

These tests never run on push or pull requests. They run in the separate
**Live tests** GitHub Actions workflow (`.github/workflows/live.yml`), on
GitHub-hosted runners, which allow outbound UDP/443 and do not intercept TLS:

- **When:** manually, and automatically once a week (Monday 05:17 UTC). A
  failure there never blocks CI or a merge.
- **Run it by hand:** on GitHub open the **Actions** tab → **Live tests** →
  **Run workflow** (choose the branch) → **Run workflow**. Each job's log shows
  the installed aioquic version and the result of every test (`-rA`).
- **Matrix:** Ubuntu with Python 3.10 and aioquic 1.3 (oldest supported
  version, uses fasthttpc's GOAWAY shim), Ubuntu with Python 3.13 and the latest
  aioquic (native GOAWAY), and macOS and Windows with Python 3.12 and the latest
  aioquic. The package is installed with the `http3`, `brotli` and `zstd` extras.
- **Limits:** each test has a 120 s hard limit (`pytest-timeout`) and each job
  15 minutes. Tests are not retried: a retry could hide a real handshake or
  fallback bug. If a third-party server is down, re-run the failed job.

With `FASTHTTPC_LIVE=1` a missing aioquic is an import error, not a skip, so a
live run cannot pass by skipping everything.

### badssl.com and Extended Master Secret

`badssl.com` only offers TLS 1.2, without the Extended Master Secret extension
(RFC 7627). fasthttpc refuses such servers by design (unless `legacy_tls=True`),
and it does so when it reads the ServerHello, **before** the certificate is
examined. So the `badssl.com` bad-certificate hosts never reach certificate
validation: they fail with `TLS12Error("handshake_failure: Sunucu Extended
Master Secret (RFC 7627) kabul etmedi ...")`.

The tests account for that as follows:

- `test_badssl_bad_cert_hosts_refused` only claims "refused, nothing fetched".
  It accepts a certificate error or that specific EMS refusal (alert
  `handshake_failure`, exact message), nothing else. A connection reset or a
  timeout from `badssl.com` fails the test, under this name, instead of being
  skipped or counted as a rejection.
- Every `badssl.com` check runs once per profile. The 0.7.0 default profile
  `chrome_158` sends a larger ClientHello than `chrome_131` (about 1.9-2.0 KB
  instead of 1.7-1.8 KB: `trust_anchors` 0xca34 with 28 IDs, ML-DSA and GREASE
  signature algorithms, ALPS 17613). Both are well above 512 bytes, so neither
  needs the padding extension, and both span two TCP segments. Against a local
  OpenSSL TLS 1.2 server without EMS all five profiles get the EMS refusal. If a
  CI run shows resets for some profiles and EMS refusals for others, the
  ClientHello of the reset profiles is the suspect; if every profile and the
  stdlib control are reset, `badssl.com` is dropping connections.
- Certificate validation on the TCP path is tested against servers that
  negotiate TLS 1.3 (`test_tcp_rejects_chain_from_untrusted_ca`,
  `test_tcp_rejects_hostname_mismatch`), each with a control request that
  succeeds, so a failure there really is the certificate. Expired,
  not-yet-valid, wrong-host, self-signed and untrusted-root certificates are
  covered offline against local OpenSSL servers in
  `tests/test_interop_openssl.py`.
- For the hostname check a server must answer an unknown SNI with a
  certificate. `quic.nginx.org` (used before 0.7.0) aborts with the
  `unrecognized_name` alert (112) instead, so validation was never reached.
  `test_tcp_rejects_hostname_mismatch` now uses `www.google.com` (Google's front
  ends serve their default `*.google.com` certificate for an unknown name) and
  `github.com` (one certificate whatever the SNI). Per target it accepts the SAN
  mismatch or exactly the `unrecognized_name` alert, because a server may
  legitimately refuse the name. At least one target must give the SAN mismatch,
  since the alert says nothing about hostname verification. A reset, timeout or
  any other error fails the test.
- Certificate-authority test sites (for example SSL.com's
  `expired-rsa-dv.ssl.com`) are not used: there is no documentation that they
  offer TLS 1.3 or TLS 1.2 with EMS, so they could fail for the same reason.

How to read failures:

- `Http3ConnectError: ... UDP: bağlantı reddedildi (ICMP port unreachable)` or a
  handshake timeout in the `test_h3_force_*` tests means UDP/443 is blocked on
  your network; the discovery tests then fail with "fell back to HTTP/2".
  `test_fallback_to_h2_when_h3_unreachable` does not need UDP and should still pass.
- The certificate tests failing with "DID NOT RAISE" means something on the path
  re-signs TLS (a corporate or sandbox egress proxy). The client is then not
  talking to the real server, so the tests are right to fail. The baseline tests
  fail with a certificate error in that case.
- `test_badssl_bad_cert_hosts_refused` failing with "neither by certificate
  validation nor by the EMS check" and a reset or timeout means `badssl.com` was
  unreachable or dropped the connection. Nothing was fetched, but the test cannot
  tell why, so it fails. The message names the profile and its approximate
  ClientHello size. Compare the profiles with each other and with
  `test_badssl_reachable_with_stdlib_ssl`: resets only for some profiles point at
  their ClientHello (a compatibility bug to investigate), resets everywhere point
  at `badssl.com`.
- `test_tcp_rejects_hostname_mismatch` failing with "no target served a
  certificate for the unknown name" means every target now refuses the unknown
  SNI with the alert: pick another target that serves a default certificate.
- `test_badssl_valid_cert_host_refused_for_missing_ems` failing because the
  request succeeded means `badssl.com` now offers TLS 1.3 or EMS: the
  bad-certificate hosts then reach certificate validation and this section
  should be updated.

Certificate verification is never disabled by these tests: `verify=False` is not
supported by fasthttpc.
