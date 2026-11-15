"""Kimlik doğrulama: Basic, Digest (RFC 7616), Bearer, .netrc ve özel auth.

İki arayüz de desteklenir ve oturum/istek düzeyinde (``Session(auth=...)``,
``s.get(url, auth=...)``) sync ve async'te aynı çalışır:

* requests tarzı  — ``__call__(request) -> request`` (ör. ``requests.auth.AuthBase``)
* httpx tarzı     — ``auth_flow(request)`` üreteci: ``response = yield request``

``auth=("kullanici", "parola")`` Basic'e çevrilir. Çapraz-origin yönlendirmede
``Authorization`` düşürülür; aynı origin'de korunur.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import netrc as _netrc
import os
import re
import threading
from typing import TYPE_CHECKING, Callable, Generator, Optional

if TYPE_CHECKING:
    from .models.request import Request
    from .models.response import Response

__all__ = ["Auth", "BasicAuth", "BearerAuth", "DigestAuth", "FunctionAuth",
           "resolve_auth", "netrc_credentials"]

# httpx tarzı akış: istek verir (yield), yanıtı alır (send).
AuthFlow = Generator["Request", "Response", None]


class Auth:
    """Auth taban sınıfı. Alt sınıf ``auth_flow`` (httpx) ya da ``__call__`` (requests) yazar."""

    requires_request_body = False     # httpx uyumu: gövde zaten bellekte
    requires_response_body = False

    def auth_flow(self, request) -> AuthFlow:
        yield self(request)

    def __call__(self, request):
        """requests tarzı: isteği değiştirip döndürür (tek adımlı akışlar için)."""
        if type(self).auth_flow is Auth.auth_flow:
            raise NotImplementedError("auth_flow ya da __call__ uygulanmalı")
        flow = self.auth_flow(request)
        try:
            return next(flow)
        finally:
            flow.close()


class FunctionAuth(Auth):
    """requests tarzı çağrılabilir (fonksiyon / ``AuthBase`` nesnesi) için sarmalayıcı."""

    def __init__(self, func: Callable) -> None:
        self._func = func

    def auth_flow(self, request) -> AuthFlow:
        out = self._func(request)
        yield request if out is None else out

    def __call__(self, request):
        out = self._func(request)
        return request if out is None else out


def _basic_value(username, password) -> str:
    raw = f"{_s(username)}:{_s(password)}"
    try:
        data = raw.encode("latin-1")          # requests ile aynı bayt'lar
    except UnicodeEncodeError:
        data = raw.encode("utf-8")            # RFC 7617
    return "Basic " + base64.b64encode(data).decode("ascii")


def _s(v) -> str:
    return v.decode("latin-1") if isinstance(v, bytes) else str(v)


class BasicAuth(Auth):
    """``Authorization: Basic ...`` (RFC 7617)."""

    def __init__(self, username, password="") -> None:
        self.username, self.password = username, password

    def auth_flow(self, request) -> AuthFlow:
        request.headers["Authorization"] = _basic_value(self.username, self.password)
        yield request

    def __eq__(self, other):
        return isinstance(other, BasicAuth) and (self.username, self.password) == (
            other.username, other.password)

    __hash__ = None  # type: ignore[assignment]

    def __repr__(self) -> str:
        return f"BasicAuth(username={self.username!r}, password='***')"


class BearerAuth(Auth):
    """``Authorization: Bearer <token>``."""

    def __init__(self, token: str) -> None:
        self.token = token

    def auth_flow(self, request) -> AuthFlow:
        request.headers["Authorization"] = f"Bearer {_s(self.token)}"
        yield request

    def __repr__(self) -> str:
        return "BearerAuth(token='***')"


# --- Digest (RFC 7616) -----------------------------------------------------

_HASHES = {
    "MD5": lambda b: hashlib.md5(b).hexdigest(),          # noqa: S324 - RFC gereği
    "SHA-256": lambda b: hashlib.sha256(b).hexdigest(),
}
_PREFERENCE = ("SHA-256-SESS", "SHA-256", "MD5-SESS", "MD5")   # güçlüden zayıfa

_TOKEN = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~/-]+")
_WS = re.compile(r"[ \t]*")


def parse_challenges(value: str) -> "list[tuple[str, dict[str, str]]]":
    """``WWW-Authenticate`` değerini [(şema, {param: değer})] listesine çevirir.

    Tırnaklı dizgeleri (``\\"`` kaçışlı) ve bir başlıkta birden çok challenge'ı
    (``Basic realm="a", Digest realm="b", ...``) destekler. Param adları küçük harf.
    """
    out: "list[tuple[str, dict[str, str]]]" = []
    i, n = 0, len(value)
    while i < n:
        while i < n and value[i] in " \t,":
            i += 1
        m = _TOKEN.match(value, i)
        if not m:
            break
        scheme, i = m.group(0), m.end()
        params: "dict[str, str]" = {}
        while True:
            i = _WS.match(value, i).end()
            m = _TOKEN.match(value, i)
            if not m:
                break
            j = _WS.match(value, m.end()).end()
            if j >= n or value[j] != "=" or (j + 1 < n and value[j + 1] == "="):
                break                              # '=' yok → yeni şema (ya da token68)
            key = m.group(0).lower()
            j = _WS.match(value, j + 1).end()
            if j < n and value[j] == '"':
                j += 1
                buf = []
                while j < n and value[j] != '"':
                    if value[j] == "\\" and j + 1 < n:
                        j += 1
                    buf.append(value[j])
                    j += 1
                j += 1
                params[key] = "".join(buf)
            else:
                m2 = _TOKEN.match(value, j)
                params[key] = m2.group(0) if m2 else ""
                j = m2.end() if m2 else j
            i = _WS.match(value, j).end()
            if i < n and value[i] == ",":
                i += 1
        out.append((scheme, params))
    return out


class _Challenge:
    __slots__ = ("realm", "nonce", "opaque", "algorithm", "qop", "userhash", "stale", "nc")

    def __init__(self, params: dict, algorithm: str, qop: Optional[str]) -> None:
        self.realm = params.get("realm", "")
        self.nonce = params["nonce"]
        self.opaque = params.get("opaque")
        self.algorithm = algorithm            # sunucunun yazımıyla (başlıkta aynen yankılanır)
        self.qop = qop                        # "auth" | "auth-int" | None (RFC 2069)
        self.userhash = params.get("userhash", "").lower() == "true"
        self.stale = params.get("stale", "").lower() == "true"
        self.nc = 0                           # bu nonce için kullanılan sayaç


class DigestAuth(Auth):
    """HTTP Digest (RFC 7616; RFC 2617 geriye uyumlu).

    Algoritmalar: ``MD5``, ``MD5-sess``, ``SHA-256``, ``SHA-256-sess``;
    ``qop``: ``auth`` (tercih) ve ``auth-int``; yoksa RFC 2069 biçimi.
    401 challenge'ı alınınca isteği TEK kez yeniden dener; ``stale=true`` yeni
    nonce ile yine tek yeniden deneme yapar. Nonce başına ``nc`` sayacı artar ve
    sonraki isteklerde (aynı origin) challenge beklenmeden önceden gönderilir.
    """

    def __init__(self, username, password="") -> None:
        self.username, self.password = _s(username), _s(password)
        self._lock = threading.Lock()
        self._state: "dict[tuple, _Challenge]" = {}
        self._cnonce_factory: Callable[[], str] = lambda: binascii.hexlify(os.urandom(12)).decode()

    def __repr__(self) -> str:
        return f"DigestAuth(username={self.username!r}, password='***')"

    # -- yardımcılar --
    @staticmethod
    def _pick(response) -> "Optional[_Challenge]":
        values = response.headers.get_list("www-authenticate") if hasattr(
            response.headers, "get_list") else [response.headers.get("www-authenticate", "")]
        best: "tuple[int, _Challenge] | None" = None
        for value in values:
            for scheme, params in parse_challenges(value):
                if scheme.lower() != "digest" or "nonce" not in params:
                    continue
                algo = params.get("algorithm", "MD5")
                rank = _rank(algo)
                if rank is None:
                    continue
                qops = [q.strip().lower() for q in params.get("qop", "").split(",") if q.strip()]
                qop = "auth" if "auth" in qops else ("auth-int" if "auth-int" in qops else None)
                if qops and qop is None:
                    continue
                ch = _Challenge(params, algo, qop)
                if best is None or rank < best[0]:
                    best = (rank, ch)
        return best[1] if best else None

    def _header(self, request, ch: _Challenge) -> str:
        algo = ch.algorithm.upper()
        sess = algo.endswith("-SESS")
        h = _HASHES["SHA-256" if algo.startswith("SHA-256") else "MD5"]
        uri = request.url.raw_path.decode("latin-1")
        with self._lock:
            ch.nc += 1
            nc = f"{ch.nc:08x}"
        cnonce = self._cnonce_factory()
        ha1 = h(f"{self.username}:{ch.realm}:{self.password}".encode("latin-1", "replace"))
        if sess:
            ha1 = h(f"{ha1}:{ch.nonce}:{cnonce}".encode())
        a2 = f"{request.method}:{uri}"
        if ch.qop == "auth-int":
            a2 += ":" + h(request.body or b"")
        ha2 = h(a2.encode("latin-1", "replace"))
        if ch.qop:
            response = h(f"{ha1}:{ch.nonce}:{nc}:{cnonce}:{ch.qop}:{ha2}".encode())
        else:
            response = h(f"{ha1}:{ch.nonce}:{ha2}".encode())
        user = h(f"{self.username}:{ch.realm}".encode()) if ch.userhash else self.username
        parts = [f'username="{_q(user)}"', f'realm="{_q(ch.realm)}"', f'nonce="{ch.nonce}"',
                 f'uri="{uri}"']
        if ch.algorithm:
            parts.append(f"algorithm={ch.algorithm}")
        parts.append(f'response="{response}"')
        if ch.opaque is not None:
            parts.append(f'opaque="{ch.opaque}"')
        if ch.qop:
            parts += [f"qop={ch.qop}", f"nc={nc}", f'cnonce="{cnonce}"']
        if ch.userhash:
            parts.append("userhash=true")
        return "Digest " + ", ".join(parts)

    def auth_flow(self, request) -> AuthFlow:
        origin = request.url.origin
        ch = self._state.get(origin)
        preemptive = ch is not None
        if preemptive:
            request.headers["Authorization"] = self._header(request, ch)
        response = yield request
        if response is None or response.status_code != 401:
            return
        new = self._pick(response)
        if new is None:
            return
        if preemptive and not new.stale:
            return                              # kimlik bilgisi reddedildi; tekrar denemek boşuna
        self._state[origin] = new
        request.headers["Authorization"] = self._header(request, new)
        yield request


def _rank(algo: str) -> Optional[int]:
    try:
        return _PREFERENCE.index(algo.upper())
    except ValueError:
        return None


def _q(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"')


# --- .netrc / çözümleme -----------------------------------------------------

def netrc_credentials(host: str) -> "Optional[tuple[str, str]]":
    """``NETRC`` ortam değişkeni, ``~/.netrc`` ya da ``~/_netrc``'den ``(login, parola)``.

    requests gibi bozuk/okunamayan dosya sessizce yok sayılır.
    """
    candidates = [os.environ["NETRC"]] if os.environ.get("NETRC") else [
        os.path.join("~", f) for f in (".netrc", "_netrc")]
    for cand in candidates:
        path = os.path.expanduser(cand)
        if not os.path.exists(path):
            continue
        try:
            auth = _netrc.netrc(path).authenticators(host)
        except (_netrc.NetrcParseError, OSError):
            return None
        if auth:
            login, account, password = auth
            return (login or account or "", password or "")
        return None
    return None


def resolve_auth(auth) -> "Optional[Auth]":
    """``("u", "p")`` / Auth / requests-çağrılabilir / httpx-akış nesnesi -> :class:`Auth`."""
    if auth is None:
        return None
    if isinstance(auth, Auth):
        return auth
    if isinstance(auth, (tuple, list)):
        if len(auth) != 2:
            raise TypeError("auth=(kullanici, parola) ikilisi olmalı")
        return BasicAuth(auth[0], auth[1])
    if hasattr(auth, "auth_flow"):
        return auth                                   # httpx.Auth ve benzerleri
    if callable(auth):
        return FunctionAuth(auth)
    raise TypeError(f"Geçersiz auth değeri: {type(auth).__name__}")
