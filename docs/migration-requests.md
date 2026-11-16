# Migrating from requests

| requests | fasthttpc |
|---|---|
| `requests.get(url)` | `with Session() as s: s.get(url)` (no module-level helpers) |
| `requests.Session()` | `fasthttpc.Session()` (context manager; close it) |
| `r.status_code`, `r.headers`, `r.url`, `r.ok`, `r.reason`, `r.history`, `r.elapsed` | same |
| `r.text` (property) | same; charset from `Content-Type`, default utf-8 |
| `r.json()` | same (method) |
| `r.raise_for_status()` | same; raises `HTTPStatusError` |
| `timeout=10`, `timeout=(5, 30)` | same per request (number, `(connect, read)` or `Timeout`); on the session `Session(timeout=10)` or a `Timeout` object |
| `params=`, `auth=`, `cookies=`, `hooks=` | same, per request or on the session; see [auth and hooks](features/auth-hooks.md) |
| `stream=True`, `r.iter_content()`, `r.iter_lines()` | same; see [streaming](features/streaming.md) |
| `proxies={...}` | `Session(proxies={...})` / `proxy=` (session-level only) |
| `verify="ca.pem"` | `Session(verify="ca.pem")` (session-level only) |
| `cert=("c.pem", "k.pem")` | `Session(cert=...)` (session-level only); see [client certificates](features/client-certs.md) |
| `verify=False` | **not supported**; trust the CA/cert via `verify="path.pem"` |
| `HTTPAdapter(max_retries=Retry(...))` | `Session(retries=Retry(...))` |
| `files={"f": open(...)}` | works, but the file name is not taken from the file object; use `files={"f": ("name", file_or_bytes, "mime")}` |

Differences to know: `verify`, `cert` and `proxies` are session-level, not per
request; `Session` is not thread-safe; proxy environment variables
(`HTTPS_PROXY` ...) are not read; `http://` URLs are fetched over TLS (there is
no cleartext HTTP); `Session()` impersonates Chrome by default
(`impersonate="chrome_131"`).
