# Auth and hooks

!!! info "Status: landing in the next release"
    Names follow the plan from the implementing agent; verify against the released API.

## Authentication

```python
from fasthttpc import Session
from fasthttpc.auth import BearerAuth, DigestAuth

s = Session(auth=("user", "pass"))                 # Basic
s.get(url, auth=DigestAuth("user", "pass"))        # per request
Session(auth=BearerAuth("token"))
s.get(url, auth=None)                              # disable session-level auth
```

- `.netrc` is used automatically (`trust_env=True`, `NETRC` env var).
- `https://user:pass@host/` URLs work.
- Custom auth: requests-style callable `__call__(request) -> request`, or an
  httpx-style `Auth` subclass with an `auth_flow(request)` generator
  (`response = yield request`).

## Hooks

```python
Session(hooks={"response": [lambda r, **kw: ...]})
s.get(url, hooks={"response": [fn]})
Session(event_hooks={"request": [fn(req)], "response": [fn(resp)]})   # httpx style
```

On `AsyncSession` hooks may be plain functions or `async def`; on `Session`
only plain functions.

## Plugins

```python
s.use(RetryPlugin(max_retries=3)).use(RateLimitPlugin(rps=5))
```

Same on `Session` and `AsyncSession`; hooks `on_request`, `on_response`,
`on_error` (async allowed on `AsyncSession`).

## requests compatibility notes

`params=` (dict/list/str) is **appended** to the existing query like requests
(httpx replaces it); `cookies=`; `timeout=(connect, read)` or `Timeout`;
`head()` defaults to `allow_redirects=False`; `r.history`, `r.links`,
`r.is_redirect`, `r.next`. There is no per-request `verify`/`cert`/`proxies`.
