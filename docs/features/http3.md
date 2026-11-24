# HTTP/3

!!! warning "Experimental, off by default"
    HTTP/3 support is experimental. The offline test suite exercises it against a
    local aioquic server. The [live tests](../testing.md#live-http3-tests) run it
    against Cloudflare (`cloudflare-quic.com`), nginx (`quic.nginx.org`) and
    Google (`www.google.com`) in the separate "Live tests" GitHub Actions
    workflow, weekly and on demand, on GitHub-hosted Ubuntu, macOS and Windows
    runners. That workflow is not part of push/PR CI.

```bash
pip install "fasthttpc[http3]"     # installs aioquic>=1.3
```

```python
from fasthttpc import Session, AsyncSession
from fasthttpc.http3 import Http3Options

Session(http3=True)       # "auto": discover h3 through Alt-Svc, fall back to HTTP/2
Session(http3="force")    # always HTTP/3, no fallback
Session(http3=Http3Options(mode="auto", connect_timeout=3.0, disable_for=300.0,
                           idle_timeout=30.0))
AsyncSession(http3=True)  # same options; asyncio only
```

`http3=False` (the default) never uses QUIC. Without aioquic installed,
enabling HTTP/3 raises `ImportError`.

## Modes

- **auto** (`http3=True`): the first request to an origin goes over TCP
  (HTTP/2 or HTTP/1.1). If the response carries `Alt-Svc: h3=...`, later
  requests try HTTP/3. If the QUIC handshake fails (UDP blocked, timeout,
  certificate error) before the request is sent, the request silently uses
  TCP and HTTP/3 stays disabled for that origin for `disable_for` seconds.
- **force** (`http3="force"`): HTTP/3 straight away, no fallback; connection and
  certificate errors are raised.

`Http3Options.connect_timeout` bounds the QUIC handshake (default 3 s, kept
short so a blocked UDP path falls back quickly). `r.http_version` is
`"HTTP/3"` for responses that came over QUIC.

## Fingerprint

The TLS handshake inside QUIC is done by aioquic, so the browser ClientHello
(extension order, GREASE, post-quantum key_share, ECH GREASE) is **not**
reproduced over HTTP/3. With a Chrome profile (`impersonate="chrome..."`) the
QUIC transport parameters, UDP datagram size, HTTP/3 SETTINGS (with a GREASE
setting) and QPACK table capacity follow Chrome-like values; these were
compiled from known defaults and are approximate. Other profiles use aioquic
defaults.

## Security

aioquic's own verification is replaced by fasthttpc's certificate validator,
which runs on the QUIC handshake before any request is sent (chain, hostname,
validity, the same rules as TLS over TCP). With `verify="ca.pem"` aioquic
also verifies against that CA. `verify=False` is not supported here either.
No session tickets are used: there is no resumption and no 0-RTT over HTTP/3.

## Limits

- Not used through proxies (UDP cannot pass an HTTP CONNECT proxy); with
  `http3="force"` and a proxy the request raises `ConnectionError`.
- Not used when `cert=` (mTLS) is set: the HTTP/3 path cannot send a client
  certificate. `http3="force"` together with `cert=` raises `ValueError`.
- `AsyncSession` HTTP/3 needs asyncio. Under trio, `http3=True` falls back to
  HTTP/2 or HTTP/1.1 and `http3="force"` raises `Http3ConnectError`.
- Response bodies are read completely before the response is returned, also
  with `stream=True`.

## Server GOAWAY

A server's HTTP/3 GOAWAY marks the connection as not reusable; requests the
server did not process are retried once on a new connection. aioquic before 1.8
(the newest release for Python 3.10 is 1.3) drops GOAWAY frames, so fasthttpc
parses them itself on those versions, with the same validation as aioquic 1.8.

## Testing against real servers

The offline suite uses a local aioquic server. To check HTTP/3 against public
servers (Alt-Svc discovery, fallback, certificate verification), see
[Live HTTP/3 tests](../testing.md#live-http3-tests).
