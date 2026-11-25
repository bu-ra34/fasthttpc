                             
from typing import TYPE_CHECKING, Any, Optional
from .urls import URL
from .headers import Headers
from .._body import StreamingBody

if TYPE_CHECKING:
    from ..timeout import Timeout


class Request:
    """Gönderilecek istek. ``data``/``json``/``files``, ``Session.request`` ile AYNI kurallarla
    kodlanır (bkz. ``_api.encode_body``): bayt gövde ``body``'de, akış gövdesi (dosya
    nesnesi, iterable) ``stream``'dedir (``body`` o zaman ``b""``; ``read()``/``aread()``
    akışı belleğe alır)."""

    def __init__(
        self,
        method: str,
        url: "str | URL",
        data: Any = None,
        json: Any = None,
        headers: "dict[str, str] | list[tuple[str, str]] | Headers | None" = None,
        files: "dict[str, Any] | None" = None,
    ):
        from .._api import encode_body
        self.method = method.upper()
        self.url = url if isinstance(url, URL) else URL(url)
        self.headers = headers if isinstance(headers, Headers) else Headers(headers)
        self.body = b""
        self.stream: Optional[StreamingBody] = None
        self.timeout: "Timeout | None" = None   # gönderim sırasında etkin Timeout (transport/hook'lar okuyabilir)

        hdrs: dict[str, Any] = dict(self.headers.items())
        encoded = encode_body(data, json, files, hdrs, allow_async=True)
        ct = hdrs.get("Content-Type")
        if ct is not None and "content-type" not in self.headers:
            self.headers["Content-Type"] = ct
        if isinstance(encoded, StreamingBody):
            self.stream = encoded
            # Çerçeve: uzunluk biliniyorsa Content-Length, yoksa chunked (h2/h3'te başlık düşer).
            for name in ("content-length", "transfer-encoding"):
                if name in self.headers:
                    del self.headers[name]
            if encoded.length is not None:
                self.headers["Content-Length"] = str(encoded.length)
            else:
                self.headers["Transfer-Encoding"] = "chunked"
        else:
            self.body = encoded
            if self.body:
                self.headers["Content-Length"] = str(len(self.body))

    def read(self) -> bytes:
        """Akış gövdesini belleğe alır ve döner (``body``/``content`` da dolar)."""
        if self.stream is not None:
            self.body = self.stream.read()
        return self.body

    async def aread(self) -> bytes:
        if self.stream is not None:
            self.body = await self.stream.aread()
        return self.body

    @property
    def content(self) -> bytes:
        """Gövde (httpx uyumu: ``request.content``)."""
        return self.body

    def __repr__(self) -> str:
        return f"<Request [{self.method}] url={self.url}>"
