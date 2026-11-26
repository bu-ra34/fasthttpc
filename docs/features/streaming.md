# Streaming responses

By default the whole body is read before the response is returned. With
`stream=True` (or the `stream()` context manager) the response comes back as
soon as the headers arrive and the body is read on demand. This works on
`Session` and `AsyncSession`, over HTTP/1.1 and HTTP/2.

## Sync

```python
from fasthttpc import Session

with Session() as s:
    with s.stream("GET", "https://example.com/big.bin") as r:
        for chunk in r.iter_bytes(chunk_size=65536):
            ...

    r = s.get("https://example.com/events", stream=True)
    try:
        for line in r.iter_lines(decode_unicode=True):
            print(line)
    finally:
        r.close()
```

| Method | Yields |
|---|---|
| `iter_bytes(chunk_size=None)` | decoded bytes (`Content-Encoding` removed) |
| `iter_text(chunk_size=None)` | `str` (multi-byte characters are never split) |
| `iter_lines(decode_unicode=False, delimiter=None)` | each line as soon as it is complete (useful for SSE) |
| `iter_raw(chunk_size=None)` | raw bytes, still compressed |
| `iter_content(chunk_size=1, decode_unicode=False)` | requests-compatible alias |
| `r.raw` | file-like reader of the raw body |
| `r.read()` | the rest of the body |

Decoding (gzip, deflate, br, zstd and chains such as `gzip, br`) behaves the
same as for non-streamed responses: if the decoder for a `Content-Encoding` is
not installed, the decoded iterators raise `fasthttpc.MissingDecoderError`
instead of yielding compressed bytes; `iter_raw()` is unaffected. Each decoded
chunk is at most about 64 KiB, and once the total decoded size passes
`Limits.max_decompressed_size` (256 MiB by default) the iterators raise
`fasthttpc.DecompressedSizeError` (see
[Decompressed body size](../timeouts-limits-retries.md#decompressed-body-size)).
Each read of a streamed body is bounded by the request's own `read` timeout
(also on a reused keep-alive or HTTP/2 connection).

## Async

```python
async with AsyncSession() as s:
    async with s.stream("GET", "https://example.com/big.bin") as r:
        async for chunk in r.aiter_bytes():
            ...
```

`aiter_bytes`, `aiter_text`, `aiter_lines` (yields `str` by default, like
httpx), `aiter_raw`, `aread()` and `aclose()` mirror the sync methods.

## Connections

- Once the body has been read to the end, the connection goes back to the pool.
- Closing a response early (`close()`, `aclose()` or leaving the `with` block)
  closes the HTTP/1.1 connection, or cancels the HTTP/2 stream with
  RST_STREAM(CANCEL) while the connection stays usable.
- On HTTP/2 flow-control credit (WINDOW_UPDATE) is only returned for data you
  have consumed, so a slow reader slows the server down.
- Bodies of redirect and 401 intermediate responses are discarded, and a
  response that is retried is closed.
- A body consumed with `iter_*` is not kept: `r.content` afterwards raises.

## Limits

- HTTP/3 responses are always read completely, even with `stream=True`.
- `MockTransport` responses are already in memory.
