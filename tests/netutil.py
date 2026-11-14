"""Test sunucuları için çift-yığınlı (127.0.0.1 + ::1) loopback dinleme.

İstemci "localhost"u önce ::1'e çözebilir (Windows'ta tipik). Sunucu yalnızca 127.0.0.1'de
dinlerse ::1 denemesi reddedilir (Windows'ta ~2 sn); sunucu iki adreste de AYNI portu dinlerse
bağlantı ilk denemede kurulur ve IPv6 yolu da gerçekten sınanır. IPv6 yoksa sessizce yalnız IPv4.
"""
from __future__ import annotations

import asyncio
import socket


def dual_endpoint() -> "tuple[list[str], int]":
    """(host listesi, ortak boş port). IPv6 kullanılamıyorsa (["127.0.0.1"], port)."""
    if not socket.has_ipv6:
        return ["127.0.0.1"], 0
    for _ in range(20):
        s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s4.bind(("127.0.0.1", 0))
        port = s4.getsockname()[1]
        s6 = None
        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)   # çekirdekte IPv6 yoksa EAFNOSUPPORT
            s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s6.bind(("::1", port))
        except OSError as e:
            s4.close()
            if s6 is not None:
                s6.close()
            if e.errno in (98, 10048):        # EADDRINUSE: başka port dene
                continue
            return ["127.0.0.1"], 0            # ::1 yok/kapalı
        s4.close()
        s6.close()
        return ["127.0.0.1", "::1"], port
    return ["127.0.0.1"], 0


async def start_dual(client_connected_cb, **kw) -> asyncio.AbstractServer:
    """``asyncio.start_server`` — 127.0.0.1 ve ::1'de aynı portta."""
    hosts, port = dual_endpoint()
    try:
        return await asyncio.start_server(client_connected_cb, hosts, port, **kw)
    except OSError:                           # port yarışı kaybedildi / IPv6 bind hatası
        return await asyncio.start_server(client_connected_cb, "127.0.0.1", 0, **kw)
