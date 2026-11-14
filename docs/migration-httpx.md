# Migrating from httpx

| httpx | fasthttpc |
|---|---|
| `httpx.Client()` | `fasthttpc.Session()` |
| `httpx.AsyncClient()` | `fasthttpc.AsyncSession()` |
| `httpx.Timeout(10, connect=5)` | `fasthttpc.Timeout(10, connect=5)` |
| `httpx.Limits(...)` | `fasthttpc.Limits(...)` (same field names) |
| `httpx.MockTransport(handler)` | `fasthttpc.MockTransport(handler)` |
| `httpx.URL`, `httpx.Headers` | `fasthttpc.URL`, `fasthttpc.Headers` |
| `client.stream(...)` | see [streaming](features/streaming.md) |
| `verify=False` | **not supported** by design |
| `http2=True` | automatic through ALPN |
| `trust_env`, event hooks, auth classes | see [auth and hooks](features/auth-hooks.md) |

New in fasthttpc: `impersonate=` for browser TLS/HTTP/2 fingerprints. Missing
compared with httpx: anyio/trio backend (see [trio](features/trio.md)),
mature streaming API, battle-tested TLS.
