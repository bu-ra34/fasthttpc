# Timeouts, limits and retries

## `Timeout`

```python
from fasthttpc import Session, Timeout

Session(timeout=30)                              # all phases 30 s
Session(timeout=Timeout(10.0, connect=5.0))      # connect 5, read/write/pool 10
```

| Field | Meaning |
|---|---|
| `connect` | TCP connect + TLS handshake |
| `read` | Waiting for data (inactivity period on async) |
| `write` | Sending data (on the sync side it shares the read socket timeout) |
| `pool` | Waiting for a free pooled connection. Takes the first argument like the other fields; if it ends up `None`, `Session` uses the connect timeout and `AsyncSession` waits without limit |
| `total` | Per-request budget for getting/opening the connection plus the whole response including the body (default `None`, no limit); unlike `read` it also catches servers that trickle data slowly. With `stream=True` it covers the request up to the response headers; each read of the streamed body is then bounded by `read` |

A per-request `timeout=` (number, `(connect, read)` tuple or `Timeout`)
overrides the session's for that request; `timeout=None` there means no limit.

Timeouts belong to the request, not to the connection: a request sent over an
already-open keep-alive HTTP/1.1 or HTTP/2 connection uses its own effective
`read`/`write`/`total` (session or per-request), never the values of the request
that opened the connection. This holds for `Session` and `AsyncSession`,
streaming and non-streaming. A timeout raises `TimeoutError` (`asyncio.TimeoutError`
on `AsyncSession`, the same class on Python 3.11+); timed-out requests are not
retried automatically, because the server may already be processing them.

## `Limits`

```python
from fasthttpc import Session, Limits

Session(limits=Limits(max_connections=20, max_keepalive_connections=5, keepalive_expiry=30.0))
```

`max_connections` caps concurrent connections per origin (sync) or in total
(async); idle keep-alive connections are capped by `max_keepalive_connections`
and expire after `keepalive_expiry` seconds (`0` disables keep-alive). Without
`limits=`, `Session` allows 10 connections per origin and `AsyncSession` 100 in
total (the `max_connections=` argument).

### Decompressed body size

```python
from fasthttpc import Session, Limits, DecompressedSizeError

Session(limits=Limits(max_decompressed_size=2 * 1024**3))   # allow up to 2 GiB
Session(limits=Limits(max_decompressed_size=None))          # no limit (opt-out)
```

`max_decompressed_size` (bytes, default **256 MiB**) caps the size of a response
body after decompression: `Content-Encoding` (`gzip`, `deflate`, `br`, `zstd`,
including chains such as `gzip, br`) and the transfer codings `gzip`/`deflate`
of HTTP/1.1. It protects against decompression bombs: a few kilobytes of gzip,
or a few hundred bytes of brotli or zstd, can expand to gigabytes. Exceeding the
limit raises `fasthttpc.DecompressedSizeError` (a `DecodeError`, so also a
`ValueError`; attributes `limit` and `encoding`). The body is never silently
truncated.

- Decompression is incremental. The output of each decoder step is bounded
  (zlib `max_length`, brotli `output_buffer_limit`, zstd in small input slices),
  so memory does not grow past the limit before the check fires.
- It applies to HTTP/1.1, HTTP/2 and HTTP/3, to `Session` and `AsyncSession`,
  buffered and `stream=True`. When streaming, every decoded chunk is at most
  about 64 KiB, and the limit applies to the total number of decoded bytes, so
  `iter_bytes()`/`aiter_bytes()` raise once that total passes the limit. Every
  step of a chain is limited.
- Bodies without a `Content-Encoding` are not limited (they cost the server the
  same bandwidth as the client), and `iter_raw()` still returns raw
  `Content-Encoding` bytes.
- At most 5 content codings are decoded per response (as in urllib3); a longer
  `Content-Encoding` chain raises `DecodeError`.

Why 256 MiB: that is over a thousand times a typical HTML page or JSON API
response, so legitimate traffic does not reach it. A buffered body is held in
memory as a single `bytes` object (plus a temporary copy while it is joined), so
a default in the gigabyte range would still let one small compressed response
use up the memory of a typical container or CI runner, which is the attack the
limit exists to stop. If you expect larger compressed bodies (for example big
exports or downloads that the server sends with `Content-Encoding`), raise the
limit or pass `None`.

## `Retry`

```python
from fasthttpc import Session, Retry

retry = Retry(total=5, backoff_factor=0.5, status_forcelist=(429, 502, 503, 504))
with Session(retries=retry) as s:      # Session(retries=3) == Retry(total=3)
    s.get("https://api.example.com/items")
```

- Off by default.
- Only `allowed_methods` are retried (idempotent methods by default); pass
  `allowed_methods=None` to retry POST/PATCH.
- Connection errors are retried; **certificate validation errors never are**.
- `Retry-After` (seconds or HTTP-date) on 413/429/503 is honoured, capped by
  `backoff_max` (120 s default).
- Delay: `backoff_factor * 2 ** (n - 1)`.
