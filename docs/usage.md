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

### Request bodies: `data=`, `json=`, `files=`

`data=` accepts the same kinds of values in `Session` and `AsyncSession`:

| `data=` | Sent as |
|---|---|
| `bytes`, `bytearray`, `memoryview` (any bytes-like object) | the bytes as they are, `Content-Length` |
| `str` | UTF-8 encoded, `Content-Length` |
| `dict`, or a `list`/`tuple` of `(key, value)` pairs | form data (`application/x-www-form-urlencoded`) |
| file-like object (anything with `.read()`) | **streamed** from its current position, not read into memory |
| iterable or generator of `bytes`/`str` chunks | **streamed** with `Transfer-Encoding: chunked` |
| async iterable / async generator (`AsyncSession` only) | **streamed** with `Transfer-Encoding: chunked` |

Any other type raises `TypeError`. A `list`/`tuple` is always form data, as in
requests. If one of its items is not a `(key, value)` pair, for example a list of
`bytes` chunks, you get a `TypeError`. To stream such a list pass `iter(chunks)`,
or pass `b"".join(chunks)` to send it as one body. `json=` is serialised to UTF-8
JSON. With `files=`, `data=` must be a dict or a list of pairs (multipart form
fields).

```python
with Session() as s, open("backup.tar", "rb") as f:
    s.put("https://example.com/upload", data=f)          # Content-Length from the file size

def rows():
    for row in produce_rows():
        yield row.encode() + b"\n"

with Session() as s:
    s.post("https://example.com/ingest", data=rows())    # chunked
```

How streaming works:

- **Length.** For a file, the length is taken from `os.fstat()` (regular files)
  or `seek`/`tell`. It is counted from the current position to the end of the
  file and sent as `Content-Length`. Exactly that many bytes are sent: if the file
  grows during the upload the extra bytes are not read, and if it shrinks the
  request fails with `ValueError` and the connection is closed. Pipes, sockets
  and generators have no known length and are sent chunked. To send such a
  stream without chunked encoding (some servers refuse it), set the
  `Content-Length` header yourself. The stream must then produce exactly that
  many bytes, or the request fails with `ValueError`.
- **Text.** A text-mode file (`open(path)`, `io.StringIO`) and `str` chunks are
  encoded as UTF-8. Their byte length is not known in advance, so a text-mode
  file is always sent chunked. Open the file in binary mode (`"rb"`) to get
  `Content-Length`.
- **Empty chunks** from an iterable are skipped. They do not end the chunked
  body early.
- **HTTP/2.** Streamed bodies go out as DATA frames that stay within the server's
  flow-control window and maximum frame size. `END_STREAM` is set on the last
  frame, and `content-length` is sent when the length is known.
- **HTTP/3** (opt-in): the body is read into memory before the request. aioquic
  buffers stream data itself, and an HTTP/3 attempt may fall back to HTTP/2 or be
  retried on a new connection, which means sending the body again.
- **Memory.** A file is read in 64 KiB pieces. `AsyncSession` reads real files in
  a worker thread so the event loop is not blocked. Every piece is sent within
  `Timeout.write`, capped by what is left of `Timeout.total`.

A streamed body can only be read once. When it has to be sent again, fasthttpc
behaves as follows:

- **307/308 redirects and Digest 401 challenges.** A file whose position is
  known (seekable) is rewound to where it started. An iterable that is not an
  iterator (`iter(x) is not x`, for example a class whose `__iter__` returns a
  new generator each time) is iterated again. A generator or other one-shot
  iterator raises `fasthttpc.UnrewindableBodyError`. 301, 302 and 303
  redirects switch to `GET` and drop the body, as before.
- **Retries** (`retries=`/`Retry`, `RetryPlugin`, reconnecting after a stale
  keep-alive connection or an HTTP/2 `GOAWAY`). A rewindable body is sent again
  from the start. A consumed generator is not retried: you get the original
  error, or the response that would have triggered the retry. An empty or
  partial body is never sent.
- **Reused HTTP/1.1 connections.** Before a one-shot stream is sent on an idle
  connection from the pool, fasthttpc checks that the server has not closed it.

`files=` values can be `bytes`, `str`, a file object, or a tuple
`(filename, content[, content_type[, headers]])`, given as a dict or as a list of
`(field, value)` pairs. File contents are read into memory, and text-mode files
are encoded as UTF-8. A bare file object gets the last component of its `name`
as its filename, like requests does. With `MockTransport`, a streamed request
body is read into memory before your handler runs, so `request.content` holds
the bytes (httpx does the same).

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

Cookies follow RFC 6265 (domain, path, `Secure`). As in browsers, a cookie is
ignored when its `Domain=` is not the request host or one of its parent domains
(`evil.com` sending `Domain=bank.com`). On an IP host, `Domain=` must be the IP
itself (IPv6 in brackets, `[::1]`), which gives a host-only cookie; any other
value makes the cookie be ignored. Like browsers, fasthttpc also checks `Domain=`
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
