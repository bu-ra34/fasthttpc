"""
fasthttpc — Response modeli

HTTP yanıtını temsil eder. status_code, headers, body, elapsed,
history ve links özelliklerini içerir.
"""
from __future__ import annotations

import http
import json as jsonlib
import re
import time
from typing import Optional, List
from .headers import Headers

_CHARSET_RE = re.compile(r"""charset\s*=\s*["']?([^\s;"']+)""", re.IGNORECASE)


class _Text(str):
    """``Response.text`` değeri: hem ``str`` (requests/httpx uyumu: ``r.text``)
    hem çağrılabilir (eski API: ``r.text()``, ``r.text(encoding="latin-1")``)."""

    def __new__(cls, value: str, body: bytes = b""):
        self = super().__new__(cls, value)
        self._body = body
        return self

    def __call__(self, encoding: Optional[str] = None, errors: str = "replace") -> str:
        if encoding is None:
            return str(self)
        return self._body.decode(encoding, errors=errors)

    def __reduce__(self):
        return (_Text, (str(self), self._body))


class _Elapsed(float):
    """Saniye cinsinden float; requests'teki ``timedelta.total_seconds()`` ile uyumlu."""

    def total_seconds(self) -> float:
        return float(self)


class HTTPStatusError(Exception):
    """4xx veya 5xx HTTP hatalarında fırlatılır."""
    def __init__(self, message: str, response: "Response"):
        super().__init__(message)
        self.response = response


def _reason(status: int) -> str:
    try:
        return http.HTTPStatus(status).phrase
    except ValueError:
        return ""


class Response:
    """
    Bir HTTP yanıtını temsil eder.

    Attributes:
        status_code: HTTP durum kodu (200, 404, vb.)
        headers:     Yanıt başlıkları (Headers objesi)
        body:        Ham yanıt gövdesi (bytes)
        request:     Bu yanıtı oluşturan istek objesi
        history:     Redirect zinciri (önceki Response listesi)
        elapsed:     İsteğin toplam süresi (saniye cinsinden float)
        http_version: Yanıtın taşındığı protokol ("HTTP/1.1" veya "HTTP/2")
    """

    def __init__(
        self,
        status_code: int,
        headers: "dict | Headers | None" = None,
        body: bytes = b"",
        request=None,
        elapsed: float = 0.0,
    ):
        self.status_code: int              = status_code
        self.headers: Headers              = headers if isinstance(headers, Headers) else Headers(headers)
        self.body: bytes                   = body
        self.request                       = request
        self.history: List["Response"]     = []
        self.elapsed                       = elapsed
        self._reason: str                  = ""
        self._url: Optional[str]           = None
        self._encoding: Optional[str]      = None
        self.http_version: str             = "HTTP/1.1"   # "HTTP/2" ise h2 üzerinden geldi

                                                                              

    @property
    def encoding(self) -> str:
        """Gövde kodlaması: atanmışsa o, yoksa Content-Type charset'i, yoksa ``utf-8``."""
        if self._encoding:
            return self._encoding
        m = _CHARSET_RE.search(self.headers.get("content-type", "") or "")
        return m.group(1) if m else "utf-8"

    @encoding.setter
    def encoding(self, value: Optional[str]) -> None:
        self._encoding = value

    @property
    def text(self) -> str:
        """
        Yanıt gövdesi (``str``); kodlama :attr:`encoding`'den gelir (hatalı
        byte'lar ``replace`` ile). Eski kullanım ``r.text()`` ve
        ``r.text(encoding="latin-1", errors="strict")`` da çalışır.
        """
        try:
            s = self.body.decode(self.encoding, errors="replace")
        except LookupError:            # bilinmeyen charset adı
            s = self.body.decode("utf-8", errors="replace")
        return _Text(s, self.body)

    @property
    def elapsed(self) -> float:
        """İstek süresi (saniye); ``.total_seconds()`` de desteklenir."""
        return self._elapsed

    @elapsed.setter
    def elapsed(self, value: float) -> None:
        self._elapsed = _Elapsed(value or 0.0)

    @property
    def url(self) -> str:
        """İsteğin (yönlendirmeler sonrası) URL'i."""
        if self._url is not None:
            return self._url
        return str(self.request.url) if self.request is not None else ""

    @url.setter
    def url(self, value) -> None:
        self._url = None if value is None else str(value)

    @property
    def ok(self) -> bool:
        """Durum kodu 400'den küçükse True (requests ile aynı)."""
        return self.status_code < 400

    @property
    def reason(self) -> str:
        """Durum ifadesi ("OK", "Not Found"); atanmadıysa standart ifade."""
        return self._reason or _reason(self.status_code)

    @reason.setter
    def reason(self, value: str) -> None:
        self._reason = value or ""

    def close(self) -> None:
        """Uyumluluk için no-op (gövde zaten belleğe okunmuştur)."""

    def json(self, **kwargs):
        """
        Yanıt gövdesini JSON olarak parse eder ve döner.

        Args:
            **kwargs: json.loads'a iletilir.

        Raises:
            json.JSONDecodeError: Geçersiz JSON formatı.
        """
        return jsonlib.loads(self.body, **kwargs)

    @property
    def content(self) -> bytes:
        """Ham yanıt gövdesi (body ile aynı, httpx uyumluluğu için)."""
        return self.body

                                                                               

    @property
    def links(self) -> dict[str, dict[str, str]]:
        """
        ``Link`` başlığını parse ederek sözlük döner.

        Örnek::

            # Link: <https://api.github.com/repos?page=2>; rel="next"
            response.links
            # {"next": {"url": "https://...", "rel": "next"}}
        """
        link_header = self.headers.get("link", "")
        if not link_header:
            return {}

        result: dict[str, dict[str, str]] = {}
        for part in link_header.split(","):
            part = part.strip()
            if not part:
                continue
            segments = [s.strip() for s in part.split(";")]
            if not segments:
                continue
            url_part = segments[0]
            if url_part.startswith("<") and url_part.endswith(">"):
                url = url_part[1:-1]
            else:
                continue
            params: dict[str, str] = {"url": url}
            for seg in segments[1:]:
                if "=" in seg:
                    k, _, v = seg.partition("=")
                    params[k.strip()] = v.strip().strip('"')
            rel = params.get("rel", url)
            result[rel] = params
        return result

                                                                               

    @property
    def is_success(self) -> bool:
        """2xx yanıtı mı?"""
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        """Redirect yanıtı mı? (301, 302, 303, 307, 308)"""
        return self.status_code in (301, 302, 303, 307, 308)

    @property
    def is_client_error(self) -> bool:
        """4xx istemci hatası mı?"""
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        """5xx sunucu hatası mı?"""
        return 500 <= self.status_code < 600

    def raise_for_status(self) -> "Response":
        """
        4xx veya 5xx ise HTTPStatusError fırlatır, aksi hâlde self döner.

        Raises:
            HTTPStatusError: HTTP hata kodu alındığında.
        """
        if self.is_client_error or self.is_server_error:
            raise HTTPStatusError(
                f"HTTP {self.status_code} hatası: {self.url}",
                response=self,
            )
        return self

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}] elapsed={self.elapsed:.3f}s>"
