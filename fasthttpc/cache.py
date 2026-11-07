"""
FAZ 1 — Response Cache (ETag / Last-Modified)
Thread-safe, TTL destekli, bellek sınırlı.
"""
from __future__ import annotations
import time
import threading
import hashlib
from typing import Optional, NamedTuple
from .models.response import Response
from .models.headers import Headers


class CacheEntry(NamedTuple):
    response:     Response
    etag:         Optional[str]
    last_modified: Optional[str]
    expires_at:   float                                


class ResponseCache:
    """
    ETag + Last-Modified bazlı HTTP response cache'i.

    Kullanım:
        cache = ResponseCache(max_size=256, default_ttl=300)
        entry = cache.get(url, method)
        if entry:
            # conditional request için header ekle
            ...
        cache.store(url, method, response)
    """
    def __init__(self, max_size: int = 256, default_ttl: float = 300.0):
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._store: dict[str, CacheEntry] = {}
        self._lock = threading.Lock()

                                                                              

    @staticmethod
    def _cache_key(url: str, method: str) -> str:
        raw = f"{method.upper()}:{url}"
        return hashlib.md5(raw.encode()).hexdigest()

    @staticmethod
    def _is_cacheable(response: Response) -> bool:
        """Yalnızca GET 200/203/204/206/301/410 cache'lenir."""
        return response.status_code in (200, 203, 204, 206, 301, 410)

    @staticmethod
    def _parse_ttl(headers: Headers) -> float:
        """Cache-Control: max-age=N veya Expires header'ından TTL hesapla."""
        cc = headers.get("cache-control", "")
        for part in cc.split(","):
            part = part.strip()
            if part.startswith("max-age="):
                try:
                    return float(part[8:])
                except ValueError:
                    pass
                                          
        if "no-store" in cc or "no-cache" in cc:
            return -1.0
        return 0.0                                    

                                                                              

    def get(self, url: str, method: str = "GET") -> Optional[CacheEntry]:
        """
        Cache'te taze giriş varsa döner.
        Süresi geçmişse siler ve None döner.
        """
        if method.upper() != "GET":
            return None
        key = self._cache_key(url, method)
        with self._lock:
            entry = self._store.get(key)
        if entry is None:
            return None
                      
        if entry.expires_at > 0 and time.monotonic() > entry.expires_at:
            with self._lock:
                self._store.pop(key, None)
            return None
        return entry

    def store(self, url: str, method: str, response: Response) -> bool:
        """
        Response'u cache'e yaz.
        Cache'lenemez (POST, no-store, vs.) ise False döner.
        """
        if method.upper() != "GET":
            return False
        if not self._is_cacheable(response):
            return False

        etag         = response.headers.get("etag", None) or None
        last_modified = response.headers.get("last-modified", None) or None
        ttl          = self._parse_ttl(response.headers)

        if ttl < 0:             
            return False

        if ttl == 0:
            ttl = self._default_ttl             

        expires_at = time.monotonic() + ttl if ttl > 0 else 0.0

        entry = CacheEntry(
            response=response,
            etag=etag,
            last_modified=last_modified,
            expires_at=expires_at,
        )

        key = self._cache_key(url, method)
        with self._lock:
                                                                  
            if len(self._store) >= self._max_size and key not in self._store:
                oldest = next(iter(self._store))
                del self._store[oldest]
            self._store[key] = entry
        return True

    def build_conditional_headers(self, entry: CacheEntry) -> dict:
        """
        Conditional GET için If-None-Match / If-Modified-Since header'larını üret.
        """
        h = {}
        if entry.etag:
            h["If-None-Match"] = entry.etag
        if entry.last_modified:
            h["If-Modified-Since"] = entry.last_modified
        return h

    def invalidate(self, url: str, method: str = "GET") -> None:
        key = self._cache_key(url, method)
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)

    def __repr__(self) -> str:
        return f"<ResponseCache entries={len(self)} max={self._max_size}>"
