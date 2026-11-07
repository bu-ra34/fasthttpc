"""
FAZ 4 — Özellik 22: DNS-over-HTTPS Resolver
Sistem DNS'inden tamamen bağımsız, şifreli çözümleme.
Cloudflare (1.1.1.1) ve Google (8.8.8.8) DoH destekli.
Thread-safe TTL cache dahil.
"""
from __future__ import annotations
import json
import socket
import ssl
import struct
import threading
import time
from typing import Optional


class DoHCache:
    """TTL'li DNS cache — tekrar sorgulama önler."""
    def __init__(self):
        self._store: dict[str, tuple[list[str], float]] = {}
        self._lock  = threading.Lock()

    def get(self, host: str) -> Optional[list[str]]:
        with self._lock:
            entry = self._store.get(host)
        if not entry:
            return None
        ips, expires = entry
        if time.monotonic() > expires:
            with self._lock:
                self._store.pop(host, None)
            return None
        return ips

    def set(self, host: str, ips: list[str], ttl: int = 300) -> None:
        with self._lock:
            self._store[host] = (ips, time.monotonic() + ttl)

    def invalidate(self, host: str) -> None:
        with self._lock:
            self._store.pop(host, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


class DoHResolver:
    """
    DNS-over-HTTPS çözümleyici.

    Kullanım:
        resolver = DoHResolver(provider="cloudflare")
        ips = resolver.resolve("example.com")
        # → ['93.184.216.34']

    Session entegrasyonu:
        session = Session(dns_resolver=DoHResolver())
    """

    PROVIDERS = {
        "cloudflare": ("1.1.1.1", "/dns-query"),
        "google":     ("8.8.8.8", "/resolve"),
        "quad9":      ("9.9.9.9", "/dns-query"),
    }

    def __init__(
        self,
        provider:   str   = "cloudflare",
        timeout:    float = 5.0,
        cache:      bool  = True,
        fallback:   bool  = True,                               
    ):
        if provider not in self.PROVIDERS:
            raise ValueError(f"Bilinmeyen DoH sağlayıcı: {provider}. Seçenekler: {list(self.PROVIDERS)}")
        self._host, self._path = self.PROVIDERS[provider]
        self._timeout  = timeout
        self._cache    = DoHCache() if cache else None
        self._fallback = fallback
        self._provider = provider

                                                                               

    def _query_https(self, name: str, qtype: str = "A") -> list[str]:
        """DoH sunucusuna HTTPS GET isteği atar, A/AAAA kayıtları döner."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode    = ssl.CERT_REQUIRED

        raw = socket.create_connection((self._host, 443), timeout=self._timeout)
        sock = ctx.wrap_socket(raw, server_hostname=self._host)

        try:
            req = (
                f"GET {self._path}?name={name}&type={qtype} HTTP/1.1\r\n"
                f"Host: {self._host}\r\n"
                f"Accept: application/dns-json\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(req.encode("ascii"))

            resp = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
        finally:
            sock.close()

                              
        if b"\r\n\r\n" not in resp:
            return []
        body = resp.split(b"\r\n\r\n", 1)[1]

                                             
        if b"\r\n" in body and body[:4].isalnum():
            try:
                parts  = body.split(b"\r\n")
                body   = b"".join(p for i, p in enumerate(parts) if i % 2 == 1)
            except Exception:
                pass

        try:
            data = json.loads(body)
        except Exception:
            return []

        ips = []
        for answer in data.get("Answer", []):
                          
            if answer.get("type") in (1, 28):
                ip = answer.get("data", "").strip()
                if ip:
                    ips.append(ip)
                ttl = answer.get("TTL", 300)

        return ips

                                                                               

    def resolve(self, host: str, qtype: str = "A") -> list[str]:
        """
        Host'u IP adresine çöz.
        Cache'te varsa direkt döner, yoksa DoH sorgular.
        DoH başarısız ve fallback=True ise sistem DNS kullanılır.
        """
                                
        try:
            socket.inet_pton(socket.AF_INET, host)
            return [host]
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return [host]
        except OSError:
            pass

                       
        if self._cache:
            cached = self._cache.get(host)
            if cached:
                return cached

                     
        try:
            ips = self._query_https(host, qtype)
            if ips:
                if self._cache:
                    self._cache.set(host, ips)
                return ips
        except Exception:
            pass

                              
        if self._fallback:
            try:
                info = socket.getaddrinfo(host, None, socket.AF_INET)
                ips  = list({r[4][0] for r in info})
                if ips and self._cache:
                    self._cache.set(host, ips, ttl=60)
                return ips
            except Exception:
                pass

        return []

    def resolve_one(self, host: str) -> Optional[str]:
        """İlk IP adresini döner veya None."""
        ips = self.resolve(host)
        return ips[0] if ips else None

    def cache_stats(self) -> dict:
        if not self._cache:
            return {"enabled": False}
        return {"enabled": True, "entries": len(self._cache)}

    def __repr__(self) -> str:
        return f"<DoHResolver provider={self._provider} cache={len(self._cache) if self._cache else 0}>"
