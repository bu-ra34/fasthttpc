# Migrating from requests

| requests | fasthttpc |
|---|---|
| `requests.get(url)` | `with Session() as s: s.get(url)` (no module-level helpers) |
| `requests.Session()` | `fasthttpc.Session()` (context manager; close it) |
| `r.status_code`, `r.headers`, `r.url`, `r.ok`, `r.reason`, `r.history`, `r.elapsed` | same |
| `r.text` (property) | same; charset from `Content-Type`, default utf-8 |
| `r.json()` | same (method) |
| `r.raise_for_status()` | same; raises `HTTPStatusError` |
| `timeout=10` | `Session(timeout=10)` or a `Timeout` object, set on the session |
| `proxies={...}` | `Session(proxies={...})` / `proxy=` |
| `verify="ca.pem"` | same |
| `verify=False` | **not supported**; trust the CA/cert via `verify="path.pem"` |
| `HTTPAdapter(max_retries=Retry(...))` | `Session(retries=Retry(...))` |
| `files={"f": open(...)}` | `files={"f": ("name", bytes_or_file, "mime")}` |

Differences to know: options such as `timeout`, `proxies` and `verify` are
session-level, not per request; `Session` is not thread-safe; there is no
`params=`/`auth=` per-request shortcut yet (build the URL, set
`Authorization` in `headers`). See [auth and hooks](features/auth-hooks.md).
