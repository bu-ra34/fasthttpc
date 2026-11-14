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

`AsyncSession` accepts the same `impersonate`, `proxy`/`proxies`, `verify`,
`Timeout` and `Limits` options. Its fingerprint (JA3/JA4, HTTP/2 settings)
matches the synchronous client's.

### Plugins (async)

```python
from fasthttpc import AsyncSession, RetryPlugin, RateLimitPlugin

async with AsyncSession() as s:
    s.use(RetryPlugin(max_retries=3, retry_on=(429, 500, 502, 503, 504)))
    s.use(RateLimitPlugin(rps=5.0))
```

## WebSocket

```python
async with AsyncSession() as s:
    ws = await s.websocket("wss://echo.example.com/")
    ...
    await ws.close()
```

## DNS-over-HTTPS

```python
from fasthttpc import Session, DoHResolver

with Session(resolver=DoHResolver(provider="cloudflare")) as s:
    s.get("https://example.com")
```

## Cookies and caching

Cookies follow RFC 6265 (domain, path, `Secure`). Pass `cache=True` (or a
`ResponseCache`) to enable a response cache with conditional requests.
