"""Plugin arayüzü — Session ve AsyncSession için ORTAK (``s.use(plugin)``).

Kancalar (hepsi opsiyonel) normal fonksiyondur::

    class Imzala(Plugin):
        def on_request(self, request: dict) -> dict:   # {"method","url","headers","body"}
            request["headers"]["X-Imza"] = "..."
            return request
        def on_response(self, response): return response
        def on_error(self, error): return error        # None -> hatayı yut

* Senkron ``Session``: kancalar düz fonksiyon olmalıdır (coroutine döndürürse TypeError).
* ``AsyncSession``: kanca düz fonksiyon VEYA ``async def`` olabilir. Bir plugin
  bloklayıcı olmayan ayrı bir async gerçekleme istiyorsa ``async_on_request`` /
  ``async_on_response`` / ``async_on_error`` tanımlar; AsyncSession onları tercih eder
  (ör. :class:`RateLimitPlugin`).
"""
from __future__ import annotations

import asyncio
import inspect
import threading
import time
from typing import Optional

from .models.response import Response


class Plugin:
    """Base plugin sınıfı. Yalnızca gereken kancaları override edin."""

    def on_request(self, request: dict) -> dict:
        """İstek gönderilmeden önce çağrılır. request dict'ini döndürün."""
        return request

    def on_response(self, response: Response) -> Response:
        """Yanıt alındıktan sonra çağrılır. response döndürün."""
        return response

    def on_error(self, error: Exception) -> Optional[Exception]:
        """Hata oluştuğunda çağrılır. None → hatayı yut; Exception → yeniden fırlat."""
        return error


def call_sync(plugin, name: str, arg):
    """Senkron oturum için kancayı çağırır; coroutine döndüren kancayı reddeder."""
    out = getattr(plugin, name)(arg)
    if inspect.isawaitable(out):
        if hasattr(out, "close"):
            out.close()
        raise TypeError(
            f"{type(plugin).__name__}.{name} coroutine döndürdü; senkron Session "
            f"yalnızca düz fonksiyon kancaları destekler (async plugin için AsyncSession kullanın).")
    return out


async def call_async(plugin, name: str, arg):
    """AsyncSession için: ``async_<ad>`` varsa onu, yoksa ``<ad>``'ı çağırır; coroutine ise bekler."""
    fn = getattr(plugin, "async_" + name, None) or getattr(plugin, name)
    out = fn(arg)
    if inspect.isawaitable(out):
        out = await out
    return out


class RetryPlugin(Plugin):
    """Belirli durum kodlarında isteği otomatik tekrar dener.

    Yeniden deneme, istek döngüsünün SAHİBİ olan ``request`` tarafından
    uygulanır; plugin yalnızca politikayı bildirir, kararı session verir.

    Args:
        max_retries: Azami yeniden deneme sayısı (ilk istek hariç).
        retry_on:    Yeniden denenecek HTTP durum kodları.
        backoff:     Üstel bekleme taban süresi (saniye). 0 ise beklenmez.
    """

    def __init__(self, max_retries: int = 3,
                 retry_on: tuple = (429, 500, 502, 503, 504),
                 backoff: float = 0.5):
        self.max_retries = max_retries
        self.retry_on = set(retry_on)
        self.backoff = backoff

    def should_retry(self, response: Response, attempt: int) -> bool:
        return attempt < self.max_retries and response.status_code in self.retry_on

    def delay_for(self, response: Response, attempt: int) -> float:
        """Retry-After başlığına saygı duyar, yoksa üstel bekleme uygular."""
        retry_after = response.headers.get("retry-after", "")
        if retry_after:
            try:
                return max(0.0, float(retry_after.strip()))
            except ValueError:
                pass
        return self.backoff * (2 ** attempt) if self.backoff else 0.0


class LoggingPlugin(Plugin):
    """İstekleri ve yanıtları loglar (sync ve async'te aynı)."""

    def __init__(self, verbose: bool = False):
        self._verbose = verbose

    def on_request(self, request: dict) -> dict:
        print(f"[LOG] → {request['method']} {request['url']}")
        return request

    def on_response(self, response: Response) -> Response:
        print(f"[LOG] ← {response.status_code} ({len(response.body)}B)")
        if self._verbose and hasattr(response, "metrics"):
            print(f"       ttfb={response.metrics.ttfb:.1f}ms total={response.metrics.total_time:.1f}ms")
        return response


class RateLimitPlugin(Plugin):
    """Saniyedeki istek sayısını sınırlar.

    Senkron oturumda ``on_request`` bekler (``time.sleep``, iş parçacığı güvenli);
    AsyncSession ``async_on_request``'i kullanır (olay döngüsünü bloklamaz).
    """

    def __init__(self, rps: float = 10.0):
        self._interval = 1.0 / rps
        self._last_req = 0.0
        self._tlock    = threading.Lock()
        self._alock: "asyncio.Lock | None" = None   # döngüye bağlı; tembel oluşur

    def on_request(self, request: dict) -> dict:
        with self._tlock:
            wait = self._interval - (time.monotonic() - self._last_req)
            if wait > 0:
                time.sleep(wait)
            self._last_req = time.monotonic()
        return request

    async def async_on_request(self, request: dict) -> dict:
        if self._alock is None:
            self._alock = asyncio.Lock()
        async with self._alock:
            wait = self._interval - (time.monotonic() - self._last_req)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_req = time.monotonic()
        return request
