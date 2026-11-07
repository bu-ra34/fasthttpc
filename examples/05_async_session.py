"""
Örnek 5 — AsyncSession ile eşzamansız istek
"""
import asyncio
from fasthttpc import AsyncSession

async def main():
    # impersonate verilince async tarafta da kendi TLS 1.3 yığını ve tarayıcı parmak izi kullanılır.
    async with AsyncSession(impersonate="chrome_131") as s:
        r = await s.get("https://httpbin.org/get")
        print(f"Durum: {r.status_code}")

asyncio.run(main())
