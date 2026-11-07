"""
Örnek 5 — AsyncSession ile eşzamansız istek
"""
import asyncio
from fasthttpc import AsyncSession

async def main():
    async with AsyncSession(impersonate=None, impersonate="chrome_131") as s:
        r = await s.get("https://httpbin.org/get")
        print(f"Durum: {r.status_code}")

asyncio.run(main())
