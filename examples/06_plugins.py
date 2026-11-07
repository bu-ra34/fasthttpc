"""
Örnek 6 — Plugin sistemi (loglama + rate limiting)
"""
import asyncio
from fasthttpc import AsyncSession
from fasthttpc import LoggingPlugin, RateLimitPlugin

async def main():
    async with AsyncSession(impersonate=None) as s:
        s.use(LoggingPlugin(verbose=True))
        s.use(RateLimitPlugin(rps=2.0))                     

        for url in [
            "https://httpbin.org/get",
            "https://httpbin.org/ip",
            "https://httpbin.org/user-agent",
        ]:
            r = await s.get(url)
            print(f"  {r.status_code} — {url}")

asyncio.run(main())
