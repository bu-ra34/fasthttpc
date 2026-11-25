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
| `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` | read the same way with `trust_env=True` (default); see [proxies](proxy.md) |
| `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE` | honoured with `trust_env=True` and `verify=True` (also `SSL_CERT_FILE`) |
| `verify="ca.pem"` | `Session(verify="ca.pem")` (session-level only) |
| `cert=("c.pem", "k.pem")` | `Session(cert=...)` (session-level only); see [client certificates](features/client-certs.md) |
| `verify=False` | **not supported**; trust the CA/cert via `verify="path.pem"` |
| `HTTPAdapter(max_retries=Retry(...))` | `Session(retries=Retry(...))` |
| `files={"f": open(...)}` | same; the file name is taken from the file object's `name` (field name if it has none); `(name, content, mime, headers)` tuples and a list of pairs also work |
| `data=open(...)`, `data=generator` | same: streamed, `Content-Length` from the file size, chunked for generators; see [request bodies](usage.md#request-bodies-data-json-files) |

Differences to know: `verify`, `cert` and `proxies` are session-level, not per
request; `Session()` impersonates Chrome by default
(`impersonate="chrome_158"`). One `Session` can be shared by many threads, as is
common with requests ([guarantees](usage.md#using-one-session-from-many-threads)).
After `close()` the session stays closed: further requests raise `RuntimeError`
(requests reopens its pools).

Request bodies: as in requests, a `list`/`tuple` passed as `data=` is form data
made of `(key, value)` pairs. Any other item, such as a `bytes` chunk, raises
`TypeError` (requests silently produces a broken form body). Use `iter(chunks)`
to stream a list of chunks. A generator body is not re-sent on a 307/308
redirect or a retry: fasthttpc raises `UnrewindableBodyError` or does not retry,
while requests resends an empty body. A file body is rewound and sent again. A
type fasthttpc does not know raises `TypeError` and is never sent as an empty body.

Proxies and redirects: an explicit `proxies=` dict replaces the environment
completely (requests fills missing schemes from `HTTP_PROXY`/`HTTPS_PROXY`;
fasthttpc, like httpx, does not), and environment variables are read when the
session is created, not per request. `http://` URLs are plain HTTP/1.1 as in
requests (fasthttpc 0.6.2 and older fetched them over TLS). An `https://` to
`http://` redirect is followed but sends no credentials at all: requests
re-applies `.netrc` credentials on that hop, fasthttpc does not. `Secure`
cookies never go over `http://`.
