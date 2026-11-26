"""
fasthttpc — Cookie yönetimi.

Önceki sürüm cookie'leri düz bir ``dict[str, str]`` olarak tutuyordu. Bunun iki
somut sonucu vardı:

  1. ``a.com`` için alınan bir oturum çerezi, redirect ``b.com``'a giderse
     ``b.com``'a da gönderiliyordu — yani oturum token'ı üçüncü tarafa sızıyordu.
  2. ``Secure`` bayrağı yok sayıldığı için HTTPS'te alınan çerez düz HTTP
     isteğine de ekleniyordu.

Bu modül RFC 6265 §5.1.3 (domain matching), §5.1.4 (path matching), §5.3 adım 5
(Public Suffix List; bkz. ``_psl``), Secure ve Max-Age/Expires kurallarını uygular.
Amaç tam bir tarayıcı uyumluluğu değil, çerezlerin yanlış hedefe gitmemesidir.
"""
from __future__ import annotations

import ipaddress
import threading
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Iterable, Optional

from ._psl import is_public_suffix, to_ascii


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


def _ip_literal(host: str) -> str:
    """IP host'un tarayıcıların ``Domain=`` ile karşılaştırdığı biçimi: IPv6
    köşeli parantezli (URL host'u gibi ``[::1]``), IPv4 olduğu gibi."""
    bare = host.strip("[]")
    return f"[{bare}]" if ":" in bare else bare


def _domain_attr_allowed(host: str, declared: str) -> bool:
    """İstek host'u ``Domain=`` değerini domain-match ediyor mu (RFC 6265 §5.1.3)?

    Host ya değerin kendisi ya da onun alt alan adıdır: ``a.example.com`` <-
    ``example.com`` evet, ``evil.com`` <- ``bank.com`` hayır. IP host'ta hiçbir
    değer alan-geneli çerez vermez (``Domain=0.0.1`` '10.0.0.1'den '9.0.0.1'e
    sızardı). ``host`` ve ``declared`` kanoniktir.
    """
    if not declared or _is_ip(host):
        return False
    return host == declared or host.endswith("." + declared)


def _domain_attr_verdict(host: str, declared: str) -> Optional[bool]:
    """``Domain=`` özniteliğinin sonucu: ``True`` alan-geneli çerez, ``False``
    host-only çerez, ``None`` çerez tümden yok sayılır.

    * IP host: öznitelik IP'nin kendisiyse host-only, başka her değerde çerez yok
      sayılır. Tarayıcılar böyle yapar (2026-11-24'te kaynaktan bakıldı):
      Chromium ``net/cookies/cookie_util.cc`` ``GetCookieDomainWithString()``
      ("IP address that don't have an empty or matching domain attribute are
      invalid"; eşitse host cookie) ve Firefox
      ``netwerk/cookie/CookieValidation.cpp`` ``CookieValidation::CheckDomain()``
      (IP / eTLD host'ta ``aRequireHostMatch``: tam eşitlik, yoksa
      ``eRejectedInvalidDomain``; mozilla-central 8390f786553b). Karşılaştırma
      URL host biçimiyledir (IPv6 köşeli parantezli).
    * RFC 6265 §5.3 adım 5: öznitelik bir genel sonekse (Public Suffix List; tek
      etiketli her değer de varsayılan ``*`` kuralıyla genel sonektir) ve istek
      host'una eşitse çerez host-only olur, değilse yok sayılır — aksi halde
      ``evil.co.uk``'nin ``Domain=co.uk`` çerezi tüm ``.co.uk`` sitelerine giderdi.
    * RFC 6265 §5.3 adım 6: host özniteliği domain-match etmiyorsa
      (``evil.com``'dan ``Domain=bank.com``) çerez yok sayılır; Chromium ve
      Firefox da reddeder.
    """
    if not declared:
        return False            # boş öznitelik yok sayılır (§5.2.3): host-only
    if _is_ip(host):
        return False if declared == _ip_literal(host) else None
    if is_public_suffix(declared):
        return False if declared == host else None
    return True if _domain_attr_allowed(host, declared) else None


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

    host = to_ascii(request_host)       # küçük harf, sondaki nokta yok, IDN -> A-label
    cookie = Cookie(
        name=name,
        value=value,
        domain=host,
        path=_default_path(request_path),
        host_only=True,
    )

    max_age: Optional[float] = None
    expires: Optional[float] = None
    domain_attr: Optional[str] = None

    for attr in parts[1:]:
        key, _, val = attr.partition("=")
        key = key.strip().lower()
        val = val.strip()

        if key == "domain" and val:
            domain_attr = val           # RFC 6265 §5.3 adım 4: son Domain geçerli
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

    if domain_attr is not None:
        # Sunucu yalnızca kendi alan adı veya üst alanı için çerez koyabilir
        # ('evil.com' 'bank.com' için koyamaz), genel sonek için hiç koyamaz.
        declared = to_ascii(domain_attr.lstrip(".")).rstrip(".")
        verdict = _domain_attr_verdict(host, declared)
        if verdict is None:
            return None
        if verdict:
            cookie.domain = declared
            cookie.host_only = False

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
                            request_host: str, request_path: str,
                            secure_origin: bool = True) -> None:
        """``secure_origin=False`` (düz ``http://`` yanıtı): RFC 6265bis §5.7 gereği
        ``Secure`` çerez KONULAMAZ ve aynı adlı, örtüşen bir ``Secure`` çerezin üzerine
        yazılamaz/silinemez (ağdaki saldırgan https oturum çerezini değiştiremesin)."""
        for raw in set_cookie_values:
            if not raw:
                continue
            cookie = parse_set_cookie(raw, request_host, request_path)
            if cookie is None:
                continue
            key = (cookie.domain, cookie.path, cookie.name)
            # Boş değer + geçmiş tarih = silme talebi
            with self._lock:
                if not secure_origin and (cookie.secure or self._shadows_secure(cookie)):
                    continue
                if cookie.is_expired():
                    self._cookies.pop(key, None)
                else:
                    self._cookies[key] = cookie

    def _shadows_secure(self, new: Cookie) -> bool:
        """Aynı adlı, alan adı örtüşen ve yeni çerezin path'i onunkine path-match eden
        Secure çerez var mı (RFC 6265bis §5.7)?"""
        for c in self._cookies.values():
            if (c.secure and c.name == new.name
                    and (_domain_matches(c.domain, new.domain, False)
                         or _domain_matches(new.domain, c.domain, False))
                    and _path_matches(new.path, c.path)):
                return True
        return False

    def header_for(self, host: str, path: str, secure: bool) -> str:
        """Verilen istek için gönderilecek ``Cookie`` başlığı değerini üretir."""
        host = to_ascii(host)
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
