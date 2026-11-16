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
| `total` | Budget for the whole request including the body (default `None`, no limit); unlike `read` it also catches servers that trickle data slowly |

A per-request `timeout=` (number, `(connect, read)` tuple or `Timeout`)
overrides the session's for that request; `timeout=None` there means no limit.

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
