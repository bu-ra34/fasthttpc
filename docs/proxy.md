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

## Plain `http://` through a proxy

Like requests and httpx, a plain `http://` URL sent through an HTTP proxy does
**not** use CONNECT: the request goes to the proxy in absolute form
(`GET http://host:port/path HTTP/1.1`), with `Proxy-Authorization` when the
proxy URL has credentials. The proxy sees the whole request, as it would
anyway for cleartext HTTP. A proxy error such as 407 is returned as a normal
response (only CONNECT failures raise `ProxyError`). Through SOCKS5 the
request is plain HTTP inside the tunnel.

## Environment variables

With `trust_env=True` (the default, as in requests and httpx) and no
`proxy=`/`proxies=` argument, the proxy comes from the environment:

| Variable | Used for |
|---|---|
| `HTTP_PROXY` | `http://` (and `ws://`) URLs |
| `HTTPS_PROXY` | `https://` (and `wss://`) URLs |
| `ALL_PROXY` | either scheme, when the specific variable is not set |
| `NO_PROXY` | targets that bypass the proxy |

- Lowercase names (`https_proxy`) win over uppercase ones; empty values are
  ignored; a value without a scheme (`proxy.local:3128`) means `http://`.
- `NO_PROXY` is a comma- (or space-) separated list: `*` (everything),
  host names (`example.com` also matches its subdomains; `.example.com` and
  `*.example.com` mean the same), IP addresses (`10.0.0.1`, `::1`, `[::1]`),
  CIDR blocks (`10.0.0.0/8`, `fd00::/8`; only for IP-literal targets, names are
  not resolved) and ports (`example.com:8080`, `[::1]:8080`). Matching is
  case-insensitive.
- Precedence: an explicit `proxy=`/`proxies=` replaces the environment
  completely (httpx semantics; `NO_PROXY` is not applied to it).
  `proxies={}` means "no proxy at all". `trust_env=False` never reads the
  environment.
- Variables are read once, when the session is created.
- Unsupported schemes (`https://` proxies, `socks4://`, ...) are not ignored
  silently: the request that would use such a proxy raises `ValueError`
  naming the variable. Use `trust_env=False` or `proxies={}` to opt out.
- In a CGI environment (`REQUEST_METHOD` set), uppercase `HTTP_PROXY` is
  ignored, because it can be set by a client `Proxy:` header (httpoxy).

## Rotation

```python
s = Session()
s.set_proxies(["http://p1:3128", "http://p2:3128"], strategy="round_robin")
```

`AsyncSession` supports the same arguments; `set_proxies` overrides `proxy=`
and the environment. A proxy that cannot be reached is taken out of the
rotation. `strategy` is `"round_robin"` or `"performance"`.

Notes:

- `socks5h://` is accepted as well; with both schemes the target name is
  resolved by the proxy (IP literals are sent as addresses).
- HTTP/3 (UDP) is never used through a proxy (also when the proxy comes from
  the environment); with `http3="force"` a proxied request raises
  `ConnectionError`.
- `AsyncSession(impersonate=None)` (stdlib `ssl`) also works through a proxy,
  on every supported Python version.
