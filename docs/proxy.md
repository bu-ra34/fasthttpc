# Proxies

```python
from fasthttpc import Session

# HTTP CONNECT (Proxy-Authorization: Basic included)
with Session(proxy="http://user:pass@proxy.local:3128") as s:
    s.get("https://example.com")

# SOCKS5 (no-auth or username/password, RFC 1929; names are resolved by the proxy)
with Session(proxies={"https": "socks5://u:p@127.0.0.1:1080"}) as s:
    s.get("https://example.com")
```

TLS, and therefore the fingerprint, is always established **inside** the
tunnel with fasthttpc's own stack; the proxy only carries TCP bytes.
`https://` proxies (TLS to the proxy itself) are not supported.

## Rotation

```python
s = Session()
s.set_proxies(["http://p1:3128", "http://p2:3128"], strategy="round_robin")
```

`AsyncSession` supports the same arguments; `set_proxies` overrides `proxy=`.
A proxy that cannot be reached is taken out of the rotation. `strategy` is
`"round_robin"` or `"performance"`.

Notes:

- `socks5h://` is accepted as well; with both schemes the target name is
  resolved by the proxy (IP literals are sent as addresses).
- Proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`) are not
  read; pass the proxy explicitly.
- HTTP/3 (UDP) is never used through a proxy; with `http3="force"` a proxied
  request raises `ConnectionError`.
- `AsyncSession(impersonate=None)` (stdlib `ssl`) also works through a proxy,
  on every supported Python version.
