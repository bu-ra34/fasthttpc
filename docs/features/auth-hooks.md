# Auth and hooks

## Authentication

```python
from fasthttpc import Session, BearerAuth, DigestAuth

s = Session(auth=("user", "pass"))                 # Basic
s.get(url, auth=DigestAuth("user", "pass"))        # per request
Session(auth=BearerAuth("token"))
s.get(url, auth=None)                              # skip the session-level auth
```

- Precedence: per-request `auth=` > session `auth=` > `.netrc` (when
  `trust_env=True`, the default; the `NETRC` environment variable is honoured)
  > credentials in the URL (`https://user:pass@host/`).
- `trust_env` also controls the proxy environment variables (see
  [proxies](../proxy.md)) and the CA bundle variables (`REQUESTS_CA_BUNDLE`,
  `SSL_CERT_FILE`, `CURL_CA_BUNDLE`).
- After an `https://` to `http://` redirect no credentials are sent at all
  (not even `.netrc`).
- Digest follows RFC 7616: MD5, SHA-256 and their `-sess` variants,
  `qop=auth`/`auth-int`, `userhash`. The strongest offered algorithm is used.
- Custom auth: requests-style callable `__call__(request) -> request`, or an
  httpx-style `Auth` subclass with an `auth_flow(request)` generator
  (`response = yield request`).
- `Authorization` is dropped when a redirect goes to another origin.

The same arguments work on `AsyncSession`.

## Hooks

```python
Session(hooks={"response": [lambda r, **kw: ...]})
s.get(url, hooks={"response": [fn]})
Session(event_hooks={"request": [fn(req)], "response": [fn(resp)]})   # httpx style
```

A requests-style response hook may return a new `Response`. On `AsyncSession`
hooks may be plain functions or `async def`; on `Session` only plain functions.

## Plugins

```python
from fasthttpc import RetryPlugin, RateLimitPlugin

s.use(RetryPlugin(max_retries=3)).use(RateLimitPlugin(rps=5))
```

Same on `Session` and `AsyncSession`; hooks `on_request`, `on_response`,
`on_error` (async allowed on `AsyncSession`, which also prefers
`async_on_request` / `async_on_response` / `async_on_error` when a plugin
defines them).

## requests compatibility notes

`params=` (dict/list/str) is **appended** to the existing query like requests
(httpx replaces it); `cookies=`; `timeout=(connect, read)` or `Timeout`;
`head()` defaults to `allow_redirects=False`; `r.history`, `r.links`,
`r.is_redirect`, `r.next`. There is no per-request `verify`/`cert`/`proxies`.
