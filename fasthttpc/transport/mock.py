"""
fasthttpc — ağsız test için sahte transport (``httpx.MockTransport`` benzeri).

Örnek::

    from fasthttpc import Session, Response
    from fasthttpc.transport.mock import MockTransport

    def handler(request):
        assert request.url.host == "api.example.com"
        return Response(200, headers={"Content-Type": "application/json"},
                        body=b'{"ok": true}')

    with Session(transport=MockTransport(handler)) as s:
        assert s.get("https://api.example.com/v1").json() == {"ok": True}

Akış gövdesi (``data=`` dosya nesnesi / üreteç) handler çağrılmadan önce belleğe
alınır (``request.content`` dolu; httpx ile aynı). Özel transport'lar gövdeyi
``request.stream``'den parça parça okuyabilir ya da ``request.read()`` çağırabilir.

Handler, :class:`~fasthttpc.models.request.Request` alır ve
:class:`~fasthttpc.models.response.Response` döner. Handler'ın fırlattığı
istisnalar (ör. ``ConnectionError``) çağırana aynen iletilir — bu sayede
yeniden deneme davranışı da ağsız test edilebilir. ``AsyncSession`` ile
kullanıldığında handler ``async def`` de olabilir.

Transport verildiğinde TLS, bağlantı havuzu, proxy ve cache katmanları
atlanır; redirect, çerez, retry ve ``raise_for_status`` gibi Session
seviyesindeki davranışlar aynen çalışır.
"""
from __future__ import annotations

import inspect
from typing import Callable

from ..models.request import Request
from ..models.response import Response


class BaseTransport:
    """Session'ın istek gönderme kancası. Alt sınıflar ``handle_request`` uygular."""

    def handle_request(self, request: Request) -> Response:  # pragma: no cover - arayüz
        raise NotImplementedError

    async def handle_async_request(self, request: Request) -> Response:
        return self.handle_request(request)

    def close(self) -> None:
        pass


class MockTransport(BaseTransport):
    """``handler(request) -> Response`` çağrısıyla yanıt üreten transport.

    Attributes:
        requests: Gönderilen tüm isteklerin listesi (testte doğrulama için).
    """

    def __init__(self, handler: Callable[[Request], "Response"]) -> None:
        self.handler = handler
        self.requests: list[Request] = []

    def _finish(self, request: Request, resp: Response) -> Response:
        if not isinstance(resp, Response):
            raise TypeError(
                f"MockTransport handler'ı Response döndürmeli, {type(resp).__name__} döndü."
            )
        resp.request = request
        return resp

    def handle_request(self, request: Request) -> Response:
        self.requests.append(request)
        request.read()          # akış gövdesi (data= dosya/üreteç) -> request.content
        resp = self.handler(request)
        if inspect.isawaitable(resp):
            close = getattr(resp, "close", None)
            if close:
                close()
            raise TypeError("Async handler yalnızca AsyncSession ile kullanılabilir.")
        return self._finish(request, resp)

    async def handle_async_request(self, request: Request) -> Response:
        self.requests.append(request)
        await request.aread()   # akış gövdesi (data= dosya/(async) üreteç) -> request.content
        resp = self.handler(request)
        if inspect.isawaitable(resp):
            resp = await resp
        return self._finish(request, resp)
