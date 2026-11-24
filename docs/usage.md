# Sync and async usage

## Synchronous: `Session`

```python
from fasthttpc import Session

with Session(impersonate="chrome_158", timeout=10, retries=3) as s:
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

### Using one `Session` from many threads

`Session` is thread-safe: one instance can be shared by any number of threads,
for example from a `ThreadPoolExecutor`. Sharing it is the intended way to use
it, because the threads then share its connection pool, cookie jar, cache and
TLS state.

```python
from concurrent.futures import ThreadPoolExecutor
from fasthttpc import Session

with Session(max_connections=8) as s:
    with ThreadPoolExecutor(max_workers=16) as ex:
        pages = list(ex.map(lambda i: s.get(f"https://api.example.com/items/{i}").json(),
                            range(100)))
```

What is guaranteed:

- **Connections are exclusive.** A pooled connection, HTTP/1.1 or HTTP/2, is used
  by one request (one thread) at a time. It goes back to the pool when the
  response body has been read, or when a streamed response is closed. On the
  sync side an HTTP/2 connection carries one stream at a time; concurrent
  streams on one connection are an `AsyncSession` feature.
- **Pool limits hold under contention.** At most `Limits.max_connections`
  connections per origin are in use or being opened at the same time. A thread
  takes an idle connection if one is free and otherwise opens a new one while
  the origin is below the limit. At the limit it waits up to `Timeout.pool` for
  a connection to be released, then raises `TimeoutError`. Locks are only held
  for short bookkeeping, never during network I/O, and a thread holds at most
  one pool slot per request. Waiting therefore cannot deadlock: the wait is
  bounded by `Timeout.pool` even when another thread keeps a streamed response
  open.
- **Per-request settings stay per request.** `timeout=`, `auth=`, `cookies=`,
  `params=`, `headers=` and `hooks=` passed to one call never affect a call in
  another thread. The effective timeouts are attached to the connection the
  request leases, so a streamed body that another thread reads keeps the
  timeouts of the request that opened it.
- **Shared state is synchronized.** The cookie jar, the response cache (a `304`
  returns a fresh copy of the cached response for each request), `DigestAuth`
  nonce counters (every `nc` is unique), `RateLimitPlugin`, the proxy rotator,
  Alt-Svc/HTTP/3 state, the DoH cache and the TLS session-ticket cache are all
  safe under concurrent use.
- Session-level attributes (`s.headers`, `s.auth`, `s.params`, `s.hooks` …) can
  be changed between requests. Changing them while other threads are sending
  requests is not synchronized; configure the session before sharing it.
  Your own hooks and plugins run in the calling thread and must be thread-safe
  themselves.

`close()` can be called from any thread, at any time, any number of times (only
the first call does anything). It does not interrupt requests that are in
progress in other threads, and it does not wait for them:

- every exchange that already holds a connection finishes normally (its response,
  or the rest of a streamed body, can still be read), and that connection is then
  closed instead of going back to the pool;
- idle connections are closed immediately;
- every request that has not obtained a connection raises `RuntimeError`: requests
  started after `close()`, threads waiting for a free pool slot, and the next step
  of a call already in progress (redirect hop, retry, auth challenge);
- with `cert=` given as a path or tuple, the private key is released when the last
  connection still in use is returned, so a TLS handshake that is in progress
  does not lose its key.

A closed `Session` stays closed. Create a new one if you need to send more
requests.

## Asynchronous: `AsyncSession`

```python
import asyncio
from fasthttpc import AsyncSession

async def main():
    async with AsyncSession(impersonate="chrome_158") as s:
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
`Session.websocket()` supports `ws://` and `wss://` as well: `wss://` uses the
profile's ClientHello with ALPN `http/1.1` only, and reads use the session's
read timeout. `AsyncSession` is the more complete option (proxies, concurrency).

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
