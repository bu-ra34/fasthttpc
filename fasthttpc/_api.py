"""Session / AsyncSession'ın ortak, G/Ç'siz yardımcıları (requests/httpx uyumu).

params birleştirme, istek düzeyi çerez/zaman aşımı, gövde kodlama, URL'deki
``user:pass@`` ayrıştırma ve hook sözlüklerinin normalleştirilmesi burada
durur; senkron ve asenkron oturum aynı kodu kullanır (davranış farkı olmaz).
"""
from __future__ import annotations

import contextvars
from http.cookies import SimpleCookie
from typing import TYPE_CHECKING, Any, Callable, Mapping, Optional, TypeAlias, Union
from urllib.parse import unquote, urlencode, urlsplit

from .config import Timeout
from .multipart import encode_multipart

if TYPE_CHECKING:
    from .models.request import Request
    from .models.response import Response

# requests/httpx uyumlu, duck-typed kullanıcı girdileri: dict, (k, v) çiftleri,
# str/bytes ... Bu fonksiyonlar bunları çalışma zamanında ayırt eder.
ParamsArg: TypeAlias = Any
CookiesArg: TypeAlias = Any
# ``("u", "p")``, Auth, requests çağrılabiliri ya da httpx ``auth_flow`` nesnesi
# (bkz. auth.resolve_auth) veya USE_CLIENT_DEFAULT.
AuthArg: TypeAlias = Any
# float/int, ``(connect, read)``, Timeout, None ya da USE_CLIENT_DEFAULT (bkz. resolve_timeout).
TimeoutArg: TypeAlias = Any
# Kullanıcı başlıkları: Mapping (dict, Headers...) ya da (ad, değer) listesi; değeri
# ``None`` olan başlık profil/oturum varsayılanını KALDIRIR.
HeadersArg: TypeAlias = Union[Mapping[str, Optional[str]], list[tuple[str, Optional[str]]], None]
# Birleştirilmiş istek başlıkları (aynı ``None`` anlamı).
HeaderDict: TypeAlias = dict[str, Optional[str]]
Hook: TypeAlias = Callable[..., Any]
HookMap: TypeAlias = dict[str, list[Hook]]


class _UseClientDefault:
    """``auth=`` / ``timeout=`` için "oturum varsayılanını kullan" işareti (httpx ile aynı ad)."""

    def __repr__(self) -> str:
        return "USE_CLIENT_DEFAULT"


USE_CLIENT_DEFAULT: Any = _UseClientDefault()


# --- params -----------------------------------------------------------------

def _encode_params(params: ParamsArg) -> str:
    if params is None:
        return ""
    if isinstance(params, bytes):
        return params.decode("latin-1")
    if isinstance(params, str):
        return params
    items = params.items() if hasattr(params, "items") else params
    flat: list[tuple[Any, Any]] = []
    for k, v in items:
        if v is None:
            continue                      # requests gibi: None → parametre yok
        if isinstance(v, (list, tuple)):
            flat.extend((k, x) for x in v if x is not None)
        else:
            flat.append((k, v))
    return urlencode([(k, _scalar(v)) for k, v in flat])


def _scalar(v: Any) -> Any:
    if isinstance(v, bool):
        return "true" if v else "false"   # httpx ile aynı
    return v


def merge_params(session_params: ParamsArg, request_params: ParamsArg) -> str:
    """Oturum ve istek parametrelerini tek query string'e çevirir.

    İkisi de sözlükse istek aynı anahtarı ezer (``None`` anahtarı kaldırır);
    aksi hâlde sıralı birleştirilir.
    """
    if session_params is None:
        return _encode_params(request_params)
    if request_params is None:
        return _encode_params(session_params)
    if isinstance(session_params, dict) and isinstance(request_params, dict):
        merged = {k: v for k, v in session_params.items()}
        merged.update(request_params)
        return _encode_params(merged)
    return "&".join(p for p in (_encode_params(session_params),
                                _encode_params(request_params)) if p)


def apply_params(url: str, session_params: ParamsArg, request_params: ParamsArg) -> str:
    """``params`` sorgusunu URL'in mevcut sorgusuna EKLER (requests gibi)."""
    extra = merge_params(session_params, request_params)
    if not extra:
        return url
    frag = ""
    if "#" in url:
        url, _, frag = url.partition("#")
        frag = "#" + frag
    sep = "&" if "?" in url else "?"
    if url.endswith(("?", "&")):
        sep = ""
    return f"{url}{sep}{extra}{frag}"


# --- URL'deki kimlik ----------------------------------------------------------

def split_userinfo(url: object) -> "tuple[str, Optional[tuple[str, str]]]":
    """``https://u:p@host/x`` -> (``https://host/x``, ``("u", "p")``)."""
    username = getattr(url, "username", None)
    if username is not None and not isinstance(url, str):      # URL nesnesi
        creds = (username, getattr(url, "password", "") or "")
        return str(url), (creds if any(creds) else None)
    url = str(url)
    netloc = urlsplit(url).netloc
    if "@" not in netloc:
        return url, None
    userinfo, _, hostport = netloc.rpartition("@")
    user, _, pw = userinfo.partition(":")
    clean = url.replace(netloc, hostport, 1)
    creds = (unquote(user), unquote(pw))
    return clean, (creds if any(creds) else None)


# --- gövde ----------------------------------------------------------------------

def _has(headers: "dict[str, Any]", name: str) -> bool:
    return any(k.lower() == name for k in headers)


def encode_body(data: Any, json: Any, files: Any, headers: "dict[str, Any]") -> bytes:
    """``data/json/files`` -> bayt gövde; gerekirse Content-Type ``headers``'a eklenir."""
    import json as jsonlib
    if files is not None:
        body, ct = encode_multipart(fields=data if isinstance(data, dict) else None,
                                    files=files)
        if not _has(headers, "content-type"):
            headers["Content-Type"] = ct
        return body
    if json is not None:
        if not _has(headers, "content-type"):
            headers["Content-Type"] = "application/json"
        return jsonlib.dumps(json).encode("utf-8")
    if isinstance(data, (dict, list, tuple)):
        if not _has(headers, "content-type"):
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        return urlencode(data, doseq=True).encode("ascii")
    if isinstance(data, str):
        return data.encode("utf-8")
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    return b""


# --- çerezler -------------------------------------------------------------------

def merge_cookie_header(jar_header: str, extra: CookiesArg) -> str:
    """Çerez kavanozundan gelen ``Cookie`` değerine istek çerezlerini ekler (istek kazanır)."""
    if not extra:
        return jar_header
    pairs: dict[str, str] = {}
    for part in (jar_header or "").split(";"):
        k, sep, v = part.strip().partition("=")
        if sep:
            pairs[k] = v
    items = extra.items() if hasattr(extra, "items") else extra
    for k, v in items:
        pairs[str(k)] = str(v)
    return "; ".join(f"{k}={v}" for k, v in pairs.items())


def parse_cookie_arg(cookies: CookiesArg) -> "dict[str, str]":
    """``cookies=`` (dict / (k, v) listesi / ``Cookie:`` metni) -> dict."""
    if not cookies:
        return {}
    if isinstance(cookies, str):
        sc = SimpleCookie()
        sc.load(cookies)
        return {k: m.value for k, m in sc.items()}
    if hasattr(cookies, "as_dict"):
        return dict(cookies.as_dict())
    return {str(k): str(v) for k, v in (cookies.items() if hasattr(cookies, "items") else cookies)}


# --- zaman aşımı -------------------------------------------------------------------

def resolve_timeout(value: Any, session_timeout: Timeout) -> Optional[Timeout]:
    """İstek düzeyi ``timeout=`` -> Timeout; varsayılansa ``None`` (oturumunki geçerli).

    float/int -> hepsi; ``(connect, read)`` ikilisi (requests); ``Timeout``;
    ``None`` -> sınırsız (``Timeout(None)``).
    """
    if value is USE_CLIENT_DEFAULT:
        return None
    if isinstance(value, bool):
        raise TypeError("timeout bool olamaz; saniye, (connect, read) ikilisi veya Timeout verin.")
    if isinstance(value, Timeout):
        return value
    if value is None:
        return Timeout(None)
    if isinstance(value, (int, float)):
        return Timeout(float(value))
    if isinstance(value, (tuple, list)) and len(value) == 2:
        c, r = value
        return Timeout(session_timeout, connect=c, read=r)
    raise TypeError(f"Geçersiz timeout değeri: {value!r}")


_TIMEOUT_OVERRIDE: "contextvars.ContextVar[Optional[tuple[object, Timeout]]]" = contextvars.ContextVar(
    "fasthttpc_timeout_override", default=None)


_OverrideToken: TypeAlias = "contextvars.Token[Optional[tuple[object, Timeout]]]"


def set_timeout_override(owner: object, timeout: Optional[Timeout]) -> _OverrideToken:
    """İstek boyunca (iş parçacığı/görev başına) geçerli zaman aşımını ayarlar."""
    return _TIMEOUT_OVERRIDE.set(None if timeout is None else (owner, timeout))


def reset_timeout_override(token: _OverrideToken) -> None:
    _TIMEOUT_OVERRIDE.reset(token)


def effective_timeout(owner: object, default: Timeout) -> Timeout:
    cur = _TIMEOUT_OVERRIDE.get()
    return cur[1] if cur is not None and cur[0] is owner else default


# --- hook'lar -------------------------------------------------------------------

_RESPONSE_ONLY = ("response",)
_EVENT_KEYS = ("request", "response")


def _as_list(v: Any) -> list[Hook]:
    if v is None:
        return []
    if callable(v):
        return [v]
    return list(v)


def normalize_hooks(hooks: "dict[str, Any] | None",
                    allowed: "tuple[str, ...]" = _RESPONSE_ONLY,
                    label: str = "hooks") -> HookMap:
    """``{"response": fn | [fn, ...]}`` -> ``{"response": [fn, ...]}`` (anahtarlar doğrulanır)."""
    out: HookMap = {k: [] for k in allowed}
    for k, v in (hooks or {}).items():
        if k not in allowed:
            raise ValueError(f"{label}: bilinmeyen olay {k!r}; geçerli: {', '.join(allowed)}")
        out[k] = _as_list(v)
    return out


def normalize_event_hooks(hooks: "dict[str, Any] | None") -> HookMap:
    return normalize_hooks(hooks, _EVENT_KEYS, "event_hooks")


def hook_list(mapping: "dict[str, Any] | None", key: str) -> list[Hook]:
    """Canlı (mutable) hook sözlüğünden ``key`` listesini okur (callable / liste kabul)."""
    return _as_list((mapping or {}).get(key))


def hook_kwargs(session: object, timeout: Optional[Timeout]) -> dict[str, Any]:
    """requests hook'larına geçirilen ``**kwargs`` (``timeout``, ``verify`` ...)."""
    return {"timeout": timeout, "verify": getattr(session, "verify", True),
            "proxies": None, "stream": False, "cert": None}


REDIRECT_STATUSES = (301, 302, 303, 307, 308)


def next_request(resp: "Response", method: str, current_url: object,
                 headers: "dict[str, Any] | None", body: bytes) -> "Request | None":
    """``allow_redirects=False`` iken ``r.next``: izlenecek yönlendirme isteği (ya da None)."""
    from .models.request import Request
    from .models.urls import URL
    from .session import _resolve_location
    if resp.status_code not in REDIRECT_STATUSES:
        return None
    location = resp.headers.get("location", "")
    if not location:
        return None
    target = _resolve_location(URL(str(current_url)), location)
    hdrs = {k: v for k, v in dict(headers or {}).items() if v is not None}
    if URL(target).origin != URL(str(current_url)).origin:
        hdrs = {k: v for k, v in hdrs.items()
                if k.lower() not in ("authorization", "cookie", "proxy-authorization")}
    if resp.status_code in (301, 302, 303):
        method, body = "GET", b""
        hdrs = {k: v for k, v in hdrs.items() if k.lower() not in ("content-type", "content-length")}
    return Request(method, target, headers=hdrs, data=body or None)

