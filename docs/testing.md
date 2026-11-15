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
| `test_h3_force_*` | `http3="force"` GETs (sync and async); Cloudflare's `/cdn-cgi/trace` body must report `http=http/3` |
| `test_fallback_to_h2_when_h3_unreachable` | Alt-Svc pointing at a dead UDP port: the request silently uses HTTP/2 and h3 is disabled for that origin |
| `test_bad_certificates_rejected` | expired, wrong-host, self-signed and untrusted-root certificates are rejected |
| `test_h3_rejects_chain_from_untrusted_ca` | the QUIC handshake rejects a real server whose root is not trusted (`verify=` set to an unrelated CA) |

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
