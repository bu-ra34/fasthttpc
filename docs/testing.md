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
`www.google.com` and `badssl.com`.

| Test | What it checks |
| --- | --- |
| `test_alt_svc_discovery_then_h3` | `http3=True`: first request over TCP learns `Alt-Svc: h3`, the next one is `HTTP/3` |
| `test_h3_force_*` | `http3="force"` GETs (sync and async) against Cloudflare, nginx and Google; Cloudflare's `/cdn-cgi/trace` body must report `http=http/3`; repeated requests reuse one QUIC connection |
| `test_fallback_to_h2_when_h3_unreachable` | Alt-Svc pointing at a dead UDP port: the request silently uses HTTP/2 and h3 is disabled for that origin |
| `test_bad_certificates_rejected` | expired, wrong-host, self-signed and untrusted-root certificates are rejected |
| `test_h3_rejects_chain_from_untrusted_ca` | the QUIC handshake rejects a real server whose root is not trusted (`verify=` set to an unrelated CA) |
| `test_auto_mode_with_untrusted_ca_never_fetches` | in auto mode with an unrelated CA the request fails with a certificate error instead of falling back to an unverified fetch |

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

How to read failures:

- `Http3ConnectError: ... UDP: bağlantı reddedildi (ICMP port unreachable)` or a
  handshake timeout in the `test_h3_force_*` tests means UDP/443 is blocked on
  your network; the discovery tests then fail with "fell back to HTTP/2".
  `test_fallback_to_h2_when_h3_unreachable` does not need UDP and should still pass.
- `test_bad_certificates_rejected` failing with "DID NOT RAISE" means something on
  the path re-signs TLS (a corporate or sandbox egress proxy). The client is then
  not talking to the real server, so the test is right to fail.

Certificate verification is never disabled by these tests: `verify=False` is not
supported by fasthttpc.
