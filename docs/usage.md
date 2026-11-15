# Sync and async usage

## Synchronous: `Session`

```python
from fasthttpc import Session

with Session(impersonate="chrome_131", timeout=10, retries=3) as s:
    s.headers["Authorization"] = "Bearer ..."     # session-level default headers
    r = s.get("https://api.example.com/items")
    for item in r.json():
        print(item)
    print(s.cookies)                              # dict view of the cookie jar
```

Methods: `get`, `post`, `put`, `patch`, `delete`, `head`, `options` and the
generic `request(method, url, ...)`. Redirects are followed by default
(`allow_redirects=False` to disable; `max_redirects=` on the session) and the
chain is in `r.history`.

!!! note
    `Session` is **not thread-safe**. Use one instance per thread.

## Asynchronous: `AsyncSession`

```python
import asyncio
from fasthttpc import AsyncSession

async def main():
    async with AsyncSession(impersonate="chrome_131") as s:
        r = await s.get("https://httpbin.org/get")
        print(r.status_code)

        # Concurrent requests; over HTTP/2 they share one multiplexed connection.
        results = await asyncio.gather(
            *(s.get(f"https://httpbin.org/anything/{i}") for i in range(10))
        )

asyncio.run(main())
```

`AsyncSession` accepts the same options as `Session` (`impersonate`,
`proxy`/`proxies`, `verify`, `cert`, `auth`, `Timeout`, `Limits`, `http3`,
`legacy_tls` ...). Its fingerprint (JA3/JA4, HTTP/2 settings) matches the
synchronous client's. With `impersonate=None` it uses Python's `ssl` module
and HTTP/1.1 only. It also runs under trio, see [trio](features/trio.md).

Both clients support `stream=True` ([streaming](features/streaming.md)) and
[auth and hooks](features/auth-hooks.md).

### Plugins

```python
from fasthttpc import AsyncSession, RetryPlugin, RateLimitPlugin

async with AsyncSession() as s:
    s.use(RetryPlugin(max_retries=3, retry_on=(429, 500, 502, 503, 504)))
    s.use(RateLimitPlugin(rps=5.0))
```

`Session.use()` takes the same plugins; there the plugin hooks must be plain
functions.

## WebSocket

```python
async with AsyncSession() as s:
    ws = await s.websocket("wss://echo.example.com/")
    ...
    await ws.close()
```

`AsyncSession` supports `ws://` (plain TCP) and `wss://`; `wss://` uses the
profile's ClientHello with ALPN `http/1.1`, directly or through a proxy.
`Session.websocket()` also exists, but it is less tested: a `ws://` URL
currently fails with `TypeError`, and for `wss://` it offers the profile's full
ALPN list (`h2, http/1.1`), so prefer `AsyncSession` for WebSockets.

## DNS-over-HTTPS

```python
from fasthttpc import Session, DoHResolver

with Session(resolver=DoHResolver(provider="cloudflare")) as s:
    s.get("https://example.com")
```

## Cookies and caching

Cookies follow RFC 6265 (domain, path, `Secure`). `Domain=` is ignored for IP
hosts and single-label suffixes such as `com`, but there is no Public Suffix
List, so multi-label suffixes (`co.uk`) are still accepted. Pass `cache=True` (or a
`ResponseCache`) to enable a response cache with conditional requests.
