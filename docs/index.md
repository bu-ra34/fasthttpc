# fasthttpc

A pure-Python HTTP client with its own **TLS 1.3 / TLS 1.2** stack, **browser
TLS and HTTP/2 fingerprint impersonation** (Chrome, Firefox, Safari),
**HTTP/2 multiplexing**, and both a synchronous (`Session`) and an asyncio
(`AsyncSession`) API.

!!! warning "Experimental"
    The TLS stack is written from scratch and has **not been independently
    security-audited**. For critical production traffic prefer a mature client
    (`requests`, `httpx`, `curl_cffi`). See the [security model](security.md)
    and [known limits](limits.md).

```bash
pip install fasthttpc
```

```python
from fasthttpc import Session

with Session(impersonate="chrome_131") as s:
    print(s.get("https://httpbin.org/get").json())
```

## Where to go next

- New here? [Quick start](quickstart.md) and [sync & async usage](usage.md).
- Coming from another library? [requests](migration-requests.md), [httpx](migration-httpx.md).
- Fingerprinting: [profiles](profiles.md). Networking: [proxies](proxy.md), [TLS](tls.md), [HTTP/2](http2.md).
- Robustness: [timeouts, limits, retries](timeouts-limits-retries.md); offline tests: [MockTransport](testing.md).
- Every public name: [API reference](reference/api.md).
