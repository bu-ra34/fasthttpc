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

!!! note
    `Session` is **not thread-safe**. Use one instance per thread.

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
hosts (the cookie stays host-only). Like browsers, fasthttpc checks `Domain=`
against the [Public Suffix List](https://publicsuffix.org/): a cookie whose
`Domain` is a public suffix (`com`, `co.uk`, `github.io`, `herokuapp.com`,
`рф`, ...) is ignored, so `evil.co.uk` cannot set a cookie that would be sent
to every other `.co.uk` site. If the attribute equals the request host (a
request to `github.io` itself), the cookie is kept as host-only. Both the ICANN
and the PRIVATE sections of the list are used, and IDN names are compared as
A-labels (`пример.рф` and `xn--e1afmkfd.xn--p1ai` are the same host).

The list is a snapshot shipped inside the package
(`fasthttpc/public_suffix_list.dat.gz`, about 44 KB, MPL-2.0); its upstream
`VERSION` and `COMMIT` are at the top of the decompressed file, and the
changelog names the snapshot a release ships. It is never downloaded at
runtime and is parsed once per process (about 8 ms), on the first `Set-Cookie`
with a `Domain` attribute. To refresh it, run `python scripts/update_psl.py` in
a checkout of the repository (it downloads the list from publicsuffix.org,
checks its format and rewrites the file), then commit the regenerated file.

Pass `cache=True` (or a `ResponseCache`) to enable a response cache with
conditional requests.
