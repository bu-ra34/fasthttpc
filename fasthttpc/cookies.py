"""
fasthttpc — Cookie yönetimi.

Önceki sürüm cookie'leri düz bir ``dict[str, str]`` olarak tutuyordu. Bunun iki
somut sonucu vardı:

  1. ``a.com`` için alınan bir oturum çerezi, redirect ``b.com``'a giderse
     ``b.com``'a da gönderiliyordu — yani oturum token'ı üçüncü tarafa sızıyordu.
  2. ``Secure`` bayrağı yok sayıldığı için HTTPS'te alınan çerez düz HTTP
     isteğine de ekleniyordu.

Bu modül RFC 6265 §5.1.3 (domain matching), §5.1.4 (path matching), Secure ve
Max-Age/Expires kurallarını uygular. Amaç tam bir tarayıcı uyumluluğu değil,
çerezlerin yanlış hedefe gitmemesidir.
"""
from __future__ import annotations

import ipaddress
import threading
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Iterable, Optional


@dataclass
class Cookie:
    name: str
    value: str
    domain: str
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    expires_at: Optional[float] = None
    host_only: bool = True

    def is_expired(self, now: Optional[float] = None) -> bool:
        if self.expires_at is None:
            return False
        return (now if now is not None else time.time()) >= self.expires_at


def _domain_matches(request_host: str, cookie_domain: str, host_only: bool) -> bool:
    """RFC 6265 §5.1.3."""
    request_host = request_host.lower().rstrip(".")
    cookie_domain = cookie_domain.lower().rstrip(".")
    if request_host == cookie_domain:
        return True
    if host_only:
        return False
    # Alt alan adı eşleşmesi: 'a.example.com' <- '.example.com'
    return request_host.endswith("." + cookie_domain)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _domain_attr_allowed(host: str, declared: str) -> bool:
    """``Domain=`` özniteliği çerezi alan-geneli (host-only olmayan) yapabilir mi?

    RFC 6265 §5.3 adım 5-6: öznitelik istek host'unu domain-match etmeli; IP adresi
    olan host'ta alan-geneli çerez olmaz (``Domain=0.1`` '10.0.0.1'den '9.0.0.1'e
    sızardı); tek etiketli bir değer (``com``, ``local``) genel sonek kabul edilir —
    aksi halde ``Domain=com`` ile konan çerez TÜM ``.com`` sitelerine giderdi.
    Tam Public Suffix List (``co.uk``, ``github.io``) uygulanmaz; bkz. docs/security-audit.md.
    """
    if not declared or _is_ip(host):
        return False
    if host != declared and not host.endswith("." + declared):
        return False
    return "." in declared


def _path_matches(request_path: str, cookie_path: str) -> bool:
    """RFC 6265 §5.1.4."""
    if not request_path.startswith("/"):
        request_path = "/" + request_path
    if request_path == cookie_path:
        return True
    if not request_path.startswith(cookie_path):
        return False
    if cookie_path.endswith("/"):
        return True
    return request_path[len(cookie_path):].startswith("/")


def _default_path(request_path: str) -> str:
    if not request_path.startswith("/"):
        return "/"
    idx = request_path.rfind("/")
    return "/" if idx <= 0 else request_path[:idx]


def parse_set_cookie(header_value: str, request_host: str, request_path: str) -> Optional[Cookie]:
    """Tek bir ``Set-Cookie`` başlığını Cookie nesnesine çevirir."""
    parts = header_value.split(";")
    if not parts or "=" not in parts[0]:
        return None

    name, _, value = parts[0].partition("=")
    name, value = name.strip(), value.strip()
    if not name:
        return None

    cookie = Cookie(
        name=name,
        value=value,
        domain=request_host.lower(),
        path=_default_path(request_path),
        host_only=True,
    )

    max_age: Optional[float] = None
    expires: Optional[float] = None

    for attr in parts[1:]:
        key, _, val = attr.partition("=")
        key = key.strip().lower()
        val = val.strip()

        if key == "domain" and val:
            declared = val.lstrip(".").lower().rstrip(".")
            # Sunucu yalnızca kendi alan adı veya üst alanı için çerez
            # koyabilir; 'evil.com' 'bank.com' için çerez ayarlayamaz.
            host = request_host.lower().rstrip(".")
            if _domain_attr_allowed(host, declared):
                cookie.domain = declared
                cookie.host_only = False
        elif key == "path" and val.startswith("/"):
            cookie.path = val
        elif key == "secure":
            cookie.secure = True
        elif key == "httponly":
            cookie.http_only = True
        elif key == "max-age" and val:
            try:
                max_age = time.time() + int(val)
            except ValueError:
                pass
        elif key == "expires" and val:
            try:
                expires = parsedate_to_datetime(val).timestamp()
            except (TypeError, ValueError):
                pass

    # Max-Age, Expires'a göre önceliklidir (RFC 6265 §5.2.2)
    cookie.expires_at = max_age if max_age is not None else expires
    return cookie


class CookieJar:
    """Domain/path/secure kurallarına uyan basit cookie deposu."""

    def __init__(self) -> None:
        self._cookies: dict[tuple[str, str, str], Cookie] = {}
        # Session thread'ler arasında paylaşılabilir: sözlük, başka bir thread
        # eklerken yinelenirse "dictionary changed size during iteration" olur.
        self._lock = threading.RLock()

    def update_from_headers(self, set_cookie_values: Iterable[str],
                            request_host: str, request_path: str) -> None:
        for raw in set_cookie_values:
            if not raw:
                continue
            cookie = parse_set_cookie(raw, request_host, request_path)
            if cookie is None:
                continue
            key = (cookie.domain, cookie.path, cookie.name)
            # Boş değer + geçmiş tarih = silme talebi
            with self._lock:
                if cookie.is_expired():
                    self._cookies.pop(key, None)
                else:
                    self._cookies[key] = cookie

    def header_for(self, host: str, path: str, secure: bool) -> str:
        """Verilen istek için gönderilecek ``Cookie`` başlığı değerini üretir."""
        now = time.time()
        with self._lock:
            snapshot = list(self._cookies.values())
        matched = [
            c for c in snapshot
            if not c.is_expired(now)
            and _domain_matches(host, c.domain, c.host_only)
            and _path_matches(path, c.path)
            and (secure or not c.secure)
        ]
        # RFC 6265 §5.4: daha uzun path önce gönderilir
        matched.sort(key=lambda c: -len(c.path))
        return "; ".join(f"{c.name}={c.value}" for c in matched)

    def clear(self) -> None:
        with self._lock:
            self._cookies.clear()

    def as_dict(self) -> dict[str, str]:
        """Geriye dönük uyumluluk: isim -> değer sözlüğü."""
        with self._lock:
            snapshot = list(self._cookies.values())
        return {c.name: c.value for c in snapshot if not c.is_expired()}

    def __len__(self) -> int:
        return len(self._cookies)

    def __repr__(self) -> str:
        return f"<CookieJar {len(self._cookies)} çerez>"
