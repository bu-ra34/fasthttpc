# Quick start

## Install

```bash
pip install fasthttpc
pip install "fasthttpc[brotli,zstd]"   # optional content decoders
pip install "fasthttpc[trio]"          # optional: AsyncSession under trio
pip install "fasthttpc[http3]"         # optional: experimental HTTP/3 (aioquic)
pip install "fasthttpc[all]"           # all of the above
```

Requires Python 3.10+. Runtime dependencies: `cryptography` and `certifi`.
Post-quantum key exchange (X25519MLKEM768) is only offered when the installed
`cryptography` is version 47 or newer.

## First request

```python
from fasthttpc import Session

with Session(impersonate="chrome_131") as s:
    r = s.get("https://httpbin.org/get")
    print(r.status_code, r.ok, r.elapsed)
    print(r.headers["content-type"])
    print(r.json())
```

`Session` is a context manager; leaving the block closes pooled connections.
Responses expose `status_code`, `headers`, `url`, `ok`, `reason`, `encoding`,
`content` (bytes), `text` (str), `json()`, `raise_for_status()`, `history`
and `elapsed`.

## Sending data

```python
with Session() as s:
    s.post("https://httpbin.org/post", json={"a": 1})
    s.post("https://httpbin.org/post", data={"k": "v"})
    s.post("https://httpbin.org/post", files={"f": ("a.txt", b"hello", "text/plain")})
    s.get("https://httpbin.org/get", headers={"X-Demo": "1"})
```

## Errors

```python
r = s.get("https://httpbin.org/status/404")
r.raise_for_status()      # raises fasthttpc.HTTPStatusError
```

Certificate validation failures raise an exception and are never retried.

## Debug logging

The library never prints. To see what happens on the wire:

```python
from fasthttpc import enable_debug_logging
enable_debug_logging()
```
