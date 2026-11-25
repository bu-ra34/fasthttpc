"""İstek gövdesi akışı (``data=``): dosya benzeri nesneler ve (async) iterable'lar.

``Session``/``AsyncSession``, ``data=`` olarak verilen dosya nesnesini ya da bayt/str
üreten iterable'ı belleğe ALMADAN, parça parça gönderir:

* Uzunluk biliniyorsa (dosyada ``os.fstat(fileno())`` ya da ``seek``/``tell``; dosyanın
  O ANKİ konumundan sonuna kadar) ``Content-Length``; bilinmiyorsa (üreteç, boru, metin
  kipi dosya) HTTP/1.1'de ``Transfer-Encoding: chunked``. HTTP/2'de DATA frame'leri.
* Metin kipindeki dosyaların ve ``str`` parçaların içeriği UTF-8 kodlanır; metnin bayt
  uzunluğu önceden bilinemediğinden metin dosyası chunked gönderilir.
* Boş parçalar atlanır (chunked akışını erken bitirmez).
* Uzunluk biliniyorsa tam o kadar bayt gönderilir: dosya bu arada büyüdüyse fazlası
  okunmaz, eksik kalırsa (dosya küçüldü, iterable erken bitti) istek ``ValueError`` ile
  kesilir (bağlantı kapatılır; yanlış çerçeveli istek gönderilmez).

Akış bir kez okunur. Yeniden gönderim gerektiğinde (307/308 yönlendirmesi, yeniden
deneme, Digest 401 challenge'ı, bayat bağlantı) konumu bilinen (seek edilebilir) dosya
başlangıç konumuna, yeniden yinelenebilen iterable (iterator OLMAYAN; ``iter(x) is not
x``) baştan alınır; üreteç/iterator gibi tek seferlik kaynaklar
:class:`UnrewindableBodyError` verir — boş ya da yarım gövde ASLA gönderilmez.
"""
from __future__ import annotations

import io
import os
import stat
from typing import Any, AsyncIterator, Iterator, Optional

__all__ = ["CHUNK_SIZE", "StreamingBody", "UnrewindableBodyError"]

# Dosyadan tek okumada en çok bayt (transport.iotimeout.SEND_CHUNK ile aynı).
CHUNK_SIZE = 65536


class UnrewindableBodyError(RuntimeError):
    """Akış gövdesinin yeniden gönderilmesi gerekiyor ama kaynak başa sarılamıyor
    (üreteç/iterator ya da konumu bilinmeyen dosya zaten okundu)."""


def _coerce(chunk: Any) -> bytes:
    if isinstance(chunk, bytes):
        return chunk
    if isinstance(chunk, str):
        return chunk.encode("utf-8")
    if isinstance(chunk, (bytearray, memoryview)):
        return bytes(chunk)
    raise TypeError(
        f"Akış gövdesi parçası bytes, bytearray, memoryview ya da str olmalı; "
        f"{type(chunk).__name__} geldi.")


class StreamingBody:
    """``data=`` ile verilen akış gövdesi (kaynak: ``"file"``, ``"iter"``, ``"aiter"``).

    ``length``: gönderilecek bayt sayısı (``Content-Length``) ya da ``None`` (chunked).
    ``sent``: son gönderimde üretilen bayt sayısı.
    """

    __slots__ = ("_src", "kind", "length", "_start", "_threaded", "_reiterable",
                 "_started", "_buffer", "_left", "sent")

    def __init__(self, src: Any, kind: str, length: Optional[int] = None,
                 start: Any = None, threaded: bool = False, reiterable: bool = False) -> None:
        self._src = src
        self.kind = kind
        self.length = length
        self._start = start            # dosyanın başlangıç konumu (tell()); None = sarılamaz
        self._threaded = threaded      # AsyncSession: okumalar iş parçacığında (gerçek dosya)
        self._reiterable = reiterable
        self._started = False
        self._buffer: Optional[bytes] = None    # read()/aread() ile belleğe alındıysa
        self._left: Optional[int] = None
        self.sent = 0

    # ------------------------------------------------------------ kurulum
    @classmethod
    def from_file(cls, f: Any) -> "StreamingBody":
        text = isinstance(f, io.TextIOBase)
        try:
            seekable = bool(f.seekable()) if hasattr(f, "seekable") else hasattr(f, "seek")
        except (OSError, ValueError):
            seekable = False
        start = None
        if seekable:
            try:
                start = f.tell()
            except (AttributeError, OSError, ValueError):
                start = None
        try:
            fd = f.fileno()
        except (AttributeError, OSError, ValueError):
            fd = None
        if not isinstance(fd, int):
            fd = None
        # Metin dosyasında tell() opak bir çerezdir ve karakter != bayt: uzunluk bilinmez.
        length = None if text else cls._size(f, fd, start)
        return cls(f, "file", length, start, threaded=fd is not None)

    @staticmethod
    def _size(f: Any, fd: Optional[int], start: Any) -> Optional[int]:
        """Başlangıç konumundan dosya sonuna kadar bayt sayısı; bilinmiyorsa ``None``."""
        if not isinstance(start, int):
            return None                  # konum yok (boru, soket...): chunked
        if fd is not None:
            try:
                st: Optional[os.stat_result] = os.fstat(fd)
            except (OSError, ValueError):
                st = None
            if st is not None and stat.S_ISREG(st.st_mode):
                if st.st_size > start:
                    return st.st_size - start
                # Boyutu 0 görünen sözde dosya (/proc...) ya da gerçekten boş/sonda:
                # bir bayt okuyup anla, konuma geri dön.
                try:
                    more = f.read(1)
                finally:
                    f.seek(start)
                return None if more else 0
        try:
            f.seek(0, os.SEEK_END)
            end = f.tell()
        except (AttributeError, OSError, ValueError):
            end = None
        try:
            f.seek(start)
        except (AttributeError, OSError, ValueError):
            return None
        return max(end - start, 0) if isinstance(end, int) else None

    @classmethod
    def from_iterable(cls, it: Any) -> "StreamingBody":
        # Iterator değilse (iter(x) yeni nesne) her gönderimde baştan yinelenebilir.
        return cls(it, "iter", reiterable=iter(it) is not it)

    @classmethod
    def from_async_iterable(cls, it: Any) -> "StreamingBody":
        return cls(it, "aiter", reiterable=it.__aiter__() is not it)

    # ------------------------------------------------------------ durum
    @property
    def rewindable(self) -> bool:
        """Kaynak başa sarılabilir mi (konumu bilinen dosya ya da yeniden yinelenebilir)."""
        return (self.kind == "file" and self._start is not None) or self._reiterable

    @property
    def replayable(self) -> bool:
        """(Yeniden) gönderilebilir mi: hiç okunmadı, belleğe alındı ya da sarılabilir."""
        return not self._started or self._buffer is not None or self.rewindable

    def _begin(self) -> None:
        if self._started and self._buffer is None:
            if not self.rewindable:
                raise UnrewindableBodyError(
                    "Akış gövdesi (data=) zaten gönderildi ve başa sarılamıyor (üreteç/iterator "
                    "ya da konumu bilinmeyen dosya); boş ya da yarım gövde gönderilmez. Yeniden "
                    "gönderilebilmesi için seek edilebilir bir dosya ya da bytes verin.")
            if self.kind == "file":
                self._src.seek(self._start)
        self._started = True
        self._left = self.length
        self.sent = 0

    def _read_size(self) -> int:
        left = self._left
        return CHUNK_SIZE if left is None else min(CHUNK_SIZE, left)

    def _take(self, chunk: Any) -> bytes:
        data = _coerce(chunk)
        if data:
            left = self._left
            if left is not None:
                if len(data) > left:
                    raise ValueError(
                        f"Akış gövdesi bildirilen uzunluktan uzun (Content-Length: {self.length}).")
                self._left = left - len(data)
            self.sent += len(data)
        return data

    def _end(self) -> None:
        if self._left:
            raise ValueError(
                f"Akış gövdesi bildirilen uzunluktan kısa: {self.sent}/{self.length} bayt "
                f"(dosya gönderilirken küçüldü ya da iterable erken bitti).")

    def _file_reads(self) -> Iterator[Any]:
        read = self._src.read
        while True:
            n = self._read_size()
            if n <= 0:
                return                   # bildirilen uzunluk tamam: fazlası okunmaz
            chunk = read(n)
            if not chunk:
                return
            yield chunk

    # ------------------------------------------------------------ okuma
    def __iter__(self) -> Iterator[bytes]:
        """Boş olmayan bayt parçaları (senkron). Her yineleme baştan gönderimdir."""
        self._begin()
        if self._buffer is not None:
            if self._buffer:
                self.sent = len(self._buffer)
                yield self._buffer
            return
        if self.kind == "aiter":
            raise TypeError("Async iterable gövde yalnızca AsyncSession ile gönderilebilir.")
        src = self._file_reads() if self.kind == "file" else iter(self._src)
        for chunk in src:
            data = self._take(chunk)
            if data:
                yield data
        self._end()

    async def aiter_chunks(self) -> AsyncIterator[bytes]:
        """Boş olmayan bayt parçaları (async). Gerçek dosyalar iş parçacığında okunur."""
        self._begin()
        if self._buffer is not None:
            if self._buffer:
                self.sent = len(self._buffer)
                yield self._buffer
            return
        if self.kind == "aiter":
            async for chunk in self._src:
                data = self._take(chunk)
                if data:
                    yield data
        elif self.kind == "file" and self._threaded:
            from ._backend import run_in_thread
            read = self._src.read
            while True:
                n = self._read_size()
                if n <= 0:
                    break
                chunk = await run_in_thread(read, n)
                if not chunk:
                    break
                data = self._take(chunk)
                if data:
                    yield data
        else:
            src = self._file_reads() if self.kind == "file" else iter(self._src)
            for chunk in src:
                data = self._take(chunk)
                if data:
                    yield data
        self._end()

    def read(self) -> bytes:
        """Gövdenin tamamını belleğe alır (sonraki gönderimler bu kopyadan yapılır)."""
        if self._buffer is None:
            data = b"".join(self)
            self._buffer, self.length = data, len(data)
        return self._buffer

    async def aread(self) -> bytes:
        if self._buffer is None:
            data = b"".join([c async for c in self.aiter_chunks()])
            self._buffer, self.length = data, len(data)
        return self._buffer

    def __repr__(self) -> str:
        return f"<StreamingBody kind={self.kind} length={self.length}>"
