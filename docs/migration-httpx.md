# Migrating from httpx

| httpx | fasthttpc |
|---|---|
| `httpx.Client()` | `fasthttpc.Session()` |
| `httpx.AsyncClient()` | `fasthttpc.AsyncSession()` (asyncio, or trio with `fasthttpc[trio]`) |
| `httpx.Timeout(10, connect=5)` | `fasthttpc.Timeout(10, connect=5)` |
| `httpx.Limits(...)` | `fasthttpc.Limits(...)` (same field names) |
| `httpx.MockTransport(handler)` | `fasthttpc.MockTransport(handler)` |
| `httpx.URL`, `httpx.Headers` | `fasthttpc.URL`, `fasthttpc.Headers` |
| `client.stream(...)`, `iter_bytes`, `aiter_lines` ... | same names; see [streaming](features/streaming.md) |
| `verify=False` | **not supported** by design |
| `cert=...` | `Session(cert=...)`; see [client certificates](features/client-certs.md) |
| `http2=True` | automatic through ALPN |
| `auth=`, `event_hooks=`, `Auth` subclasses with `auth_flow` | same; see [auth and hooks](features/auth-hooks.md) |
| `trust_env=True` | only `.netrc` is read; proxy and `SSL_CERT_FILE` environment variables are not |

New in fasthttpc: `impersonate=` for browser TLS/HTTP/2 fingerprints, and
experimental opt-in [HTTP/3](features/http3.md). Differences: `params=` is
appended to the existing query string (httpx replaces it); `verify`, `cert` and
`proxies` are session-level only; `http://` URLs are fetched over TLS;
HTTP/3 does not work under trio; the TLS stack is young and not battle-tested.
