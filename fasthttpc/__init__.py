"""
fasthttpc — Pure-Python HTTP istemcisi

TLS 1.3 fingerprinting, Chrome/Firefox/Safari impersonation,
async destek, akıllı connection pool ve plugin sistemi içerir.

Hızlı başlangıç::

    from fasthttpc import Session, Timeout

    with Session(impersonate="chrome_131") as s:
        r = s.get("https://httpbin.org/get")
        print(r.status_code, r.elapsed)

Async::

    from fasthttpc import AsyncSession

    async with AsyncSession() as s:
        r = await s.get("https://httpbin.org/get")
"""

# `cryptography` alt modülleri import edilmeden ÖNCE ayarlanmalı. Bazı
# ortamlarda (özellikle Pydroid3/Android'deki OpenSSL 3.0) legacy provider
# yüklenemez ve import ölümcül bir RuntimeError ile patlar. fasthttpc yalnızca
# modern algoritmalar kullanır (AES-GCM, ChaCha20-Poly1305, x25519, ECDSA,
# RSA-PSS, Ed25519) — hiçbiri legacy provider'a ihtiyaç duymaz, dolayısıyla
# onu devre dışı bırakmak güvenli ve gereklidir.
import os as _os
_os.environ.setdefault("CRYPTOGRAPHY_OPENSSL_NO_LEGACY", "1")

from .session       import Session
from .async_session import AsyncSession
from .config        import Timeout, Limits
from .retry         import Retry
from .transport.mock import MockTransport, BaseTransport
from .multipart     import encode_multipart
from .models.response import Response, HTTPStatusError
from .models.request  import Request
from .models.headers  import Headers
from .models.urls     import URL
from .cache         import ResponseCache
from .cookies       import CookieJar, Cookie
from ._log          import enable_debug_logging
from .protocol.dns_over_https import DoHResolver
from .fingerprint   import (
    get_profile,
    available_profiles,
    ja3_from_client_hello,
    ja3_for_profile,
)
from .metrics       import RequestMetrics
from .tls_tools     import (
    TLSFragmenter,
    TLSDowngradeDetector,
    ClientHelloEntropyScorer,
)
from .async_session import ProxyRotator
from .plugins import Plugin, RetryPlugin, LoggingPlugin, RateLimitPlugin
from .auth import Auth, BasicAuth, BearerAuth, DigestAuth
from ._api import USE_CLIENT_DEFAULT

__version__ = "0.6.0"
__author__  = "Buğra"
__all__ = [
    "Session",
    "AsyncSession",
    "Timeout",
    "Limits",
    "Retry",
    "MockTransport",
    "BaseTransport",
    "encode_multipart",
    "Response",
    "HTTPStatusError",
    "Request",
    "Headers",
    "URL",
    "ResponseCache",
    "CookieJar",
    "Cookie",
    "DoHResolver",
    "enable_debug_logging",
    "get_profile",
    "available_profiles",
    "ja3_from_client_hello",
    "ja3_for_profile",
    "RequestMetrics",
    "TLSFragmenter",
    "TLSDowngradeDetector",
    "ClientHelloEntropyScorer",
    "Plugin",
    "RetryPlugin",
    "LoggingPlugin",
    "RateLimitPlugin",
    "ProxyRotator",
    "Auth",
    "BasicAuth",
    "BearerAuth",
    "DigestAuth",
    "USE_CLIENT_DEFAULT",
]
