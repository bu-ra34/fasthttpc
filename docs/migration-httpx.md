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
| `content=b"..."` / `content=generator` | `data=` (bytes, file object, sync or async iterable; streamed); `content=` is not a parameter; see [request bodies](usage.md#request-bodies-data-json-files) |
| `trust_env=True` | same default: `.netrc`, `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY` and `SSL_CERT_FILE` (also `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`; not `SSL_CERT_DIR`); see [proxies](proxy.md) |

New in fasthttpc: `impersonate=` for browser TLS/HTTP/2 fingerprints, and
experimental opt-in [HTTP/3](features/http3.md). Differences: `params=` is
appended to the existing query string (httpx replaces it); `verify`, `cert` and
`proxies` are session-level only; `http://` URLs are plain HTTP/1.1 as in
httpx (no h2c; 0.6.2 and older fetched them over TLS); `NO_PROXY` uses the
requests/curl syntax (`example.com`, `.example.com`, CIDR, `host:port`), not
httpx's `all://` mount patterns;
`data=` takes raw bodies too (httpx's `content=`), and `AsyncSession` also
accepts sync iterables and sync file objects (it reads real files in a worker
thread); a generator body on a 307/308 redirect raises `UnrewindableBodyError`
(httpx: `StreamConsumed`);
HTTP/3 is not used under trio (it falls back to HTTP/2 or HTTP/1.1); the TLS stack is young and not battle-tested.
