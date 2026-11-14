"""
fasthttpc — Response modeli

HTTP yanıtını temsil eder. status_code, headers, body, elapsed,
history ve links özelliklerini içerir.
"""
from __future__ import annotations

import json as jsonlib
import time
from typing import Optional, List
from .headers import Headers


class HTTPStatusError(Exception):
    """4xx veya 5xx HTTP hatalarında fırlatılır."""
    def __init__(self, message: str, response: "Response"):
        super().__init__(message)
        self.response = response


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
        self.elapsed: float                = elapsed
        self.http_version: str             = "HTTP/1.1"   # "HTTP/2" ise h2 üzerinden geldi

                                                                              

    def text(self, encoding: str = "utf-8", errors: str = "replace") -> str:
        """
        Yanıt gövdesini string olarak döner.

        Args:
            encoding: Karakter kodlaması (varsayılan: utf-8)
            errors:   Hatalı byte'lar için strateji (varsayılan: replace)
        """
        return self.body.decode(encoding, errors=errors)

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
            url = self.request.url if self.request else ""
            raise HTTPStatusError(
                f"HTTP {self.status_code} hatası: {url}",
                response=self,
            )
        return self

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}] elapsed={self.elapsed:.3f}s>"
