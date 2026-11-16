# Trio support

```bash
pip install "fasthttpc[trio]"      # installs anyio>=4.0 and trio>=0.22
```

```python
import trio
from fasthttpc import AsyncSession

async def main():
    async with AsyncSession(impersonate="chrome_158") as s:
        r = await s.get("https://httpbin.org/get")
        print(r.status_code)

trio.run(main)
```

The same `AsyncSession` class runs under both asyncio and trio. The backend is
picked from the running task on every call: under asyncio fasthttpc calls
stdlib asyncio directly, so asyncio users do **not** need anyio or trio
installed; under trio it uses anyio primitives. Running under trio without
anyio/trio installed raises an `ImportError` that names the extra.

Under trio the test suite covers HTTP/1.1 and HTTP/2 (including multiplexing,
cancellation and streaming), the browser TLS stack and stdlib `ssl`, proxies,
WebSockets, `pre_warm`, timeouts and retries. Use `trio.open_nursery()` (or
`AsyncSession.gather`) instead of `asyncio.gather` for concurrency.

!!! warning "Not under trio"
    HTTP/3 (`http3=`) is implemented on asyncio only and does not work under
    trio.
