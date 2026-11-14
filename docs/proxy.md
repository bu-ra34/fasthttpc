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
Using stdlib `ssl` (no `impersonate`) through a proxy requires Python 3.11+.
