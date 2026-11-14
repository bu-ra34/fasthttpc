# Trio support

!!! info "Status: landing in the next release"
    Verify names against the released API.

```bash
pip install "fasthttpc[trio]"      # installs anyio>=4.0 and trio>=0.22
```

```python
import trio
from fasthttpc import AsyncSession

async def main():
    async with AsyncSession(impersonate="chrome_131") as s:
        r = await s.get("https://httpbin.org/get")
        print(r.status_code)

trio.run(main)
```

`AsyncSession` runs under both asyncio and trio through an anyio-based
backend layer. asyncio users do **not** need anyio or trio installed.
