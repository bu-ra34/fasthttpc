# fasthttpc

A pure-Python HTTP client with its own **TLS 1.3 / TLS 1.2** stack, **browser
TLS and HTTP/2 fingerprint impersonation** (Chrome, Firefox, Safari),
**HTTP/2 multiplexing**, and both a synchronous (`Session`) and an async
(`AsyncSession`, asyncio or trio) API. Streaming, auth, hooks, client
certificates (mTLS) and an opt-in legacy TLS mode are included; HTTP/3 is
available as an **experimental** extra.

!!! warning "Experimental"
    The TLS stack is written from scratch. It has had an
    [internal security review](security-audit.md) but has **not been
    independently security-audited**. For critical production traffic prefer a
    mature client (`requests`, `httpx`, `curl_cffi`). See the
    [security model](security.md) and [known limits](limits.md).

```bash
pip install fasthttpc
pip install "fasthttpc[trio]"    # optional: AsyncSession under trio
pip install "fasthttpc[http3]"   # optional: experimental HTTP/3
```

```python
from fasthttpc import Session

with Session(impersonate="chrome_158") as s:
    print(s.get("https://httpbin.org/get").json())
```

## Where to go next

- New here? [Quick start](quickstart.md) and [sync & async usage](usage.md).
- Coming from another library? [requests](migration-requests.md), [httpx](migration-httpx.md).
- Fingerprinting: [profiles](profiles.md). Networking: [proxies](proxy.md), [TLS](tls.md), [HTTP/2](http2.md), [HTTP/3](features/http3.md).
- Features: [streaming](features/streaming.md), [auth and hooks](features/auth-hooks.md), [client certificates](features/client-certs.md), [legacy TLS](features/legacy-tls.md), [trio](features/trio.md).
- Robustness: [timeouts, limits, retries](timeouts-limits-retries.md); offline tests: [MockTransport](testing.md).
- Every public name: [API reference](reference/api.md).
