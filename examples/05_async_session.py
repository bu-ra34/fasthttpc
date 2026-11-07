"""
Örnek 5 — AsyncSession ile eşzamansız istek
"""
import asyncio
from fasthttpc import AsyncSession

async def main():
    # AsyncSession henüz TLS taklidi desteklemiyor; impersonate=None uyarıyı susturur.
    async with AsyncSession(impersonate=None) as s:
        r = await s.get("https://httpbin.org/get")
        print(f"Durum: {r.status_code}")

asyncio.run(main())
