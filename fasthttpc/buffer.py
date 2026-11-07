"""
FAZ 1 — Zero-copy buffer yönetimi, Buffer Pool, Adaptive Receive Buffer
"""
from __future__ import annotations
import io
import threading
from typing import Optional

                                                                               

class BufferPool:
    """
    Önceden ayrılmış byte dizilerini yeniden kullanan havuz.
    Her acquire() çağrısı bir bytearray döner; release() onu geri koyar.
    Thread-safe (Lock korumalı).
    """
    DEFAULT_SIZE = 65536                                              
    DEFAULT_CAPACITY = 32                                         

    def __init__(self, buf_size: int = DEFAULT_SIZE, capacity: int = DEFAULT_CAPACITY):
        self._size = buf_size
        self._capacity = capacity
        self._pool: list[bytearray] = []
        self._lock = threading.Lock()
                              
        for _ in range(capacity // 2):
            self._pool.append(bytearray(buf_size))

    def acquire(self) -> bytearray:
        """Havuzdan buffer al; havuz boşsa yenisini üret."""
        with self._lock:
            if self._pool:
                return self._pool.pop()
        return bytearray(self._size)

    def release(self, buf: bytearray) -> None:
        """Buffer'ı sıfırlayıp havuza geri koy."""
        with self._lock:
            if len(self._pool) < self._capacity:
                                                                        
                buf[:] = b'\x00' * len(buf)
                self._pool.append(buf)
                                     

    @property
    def pool_size(self) -> int:
        with self._lock:
            return len(self._pool)


                                     
_global_pool = BufferPool()

def get_pool() -> BufferPool:
    return _global_pool


                                                                               

class ZeroCopyReader:
    """
    bytes/bytearray verisini kopyalamadan memoryview üzerinde dilimler.
    HTTP parser'ına geçirilmeden önce veriyi kopyalamak yerine view döner.
    """
    __slots__ = ("_buf", "_pos", "_mv")

    def __init__(self, data: bytes | bytearray):
        self._buf = data
        self._pos = 0
        self._mv = memoryview(data)

    def peek(self, n: int) -> memoryview:
        return self._mv[self._pos : self._pos + n]

    def read(self, n: int) -> memoryview:
        chunk = self._mv[self._pos : self._pos + n]
        self._pos += len(chunk)
        return chunk

    def find(self, needle: bytes, start: int = 0) -> int:
        """needle'ı mevcut pozisyondan itibaren bul; bulunmazsa -1."""
        idx = bytes(self._mv[self._pos + start:]).find(needle)
        return -1 if idx == -1 else self._pos + start + idx

    def skip(self, n: int) -> None:
        self._pos = min(self._pos + n, len(self._buf))

    @property
    def remaining(self) -> int:
        return len(self._buf) - self._pos

    @property
    def pos(self) -> int:
        return self._pos


                                                                               

class AdaptiveReceiver:
    """
    Soket okuma sırasında dinamik chunk boyutu ayarlar.
    - Küçük başla, hızlı doluyorsa büyüt
    - Boş gelmeye başlarsa küçült
    Bellek israfını ve sys-call sayısını dengeler.
    """
    MIN_CHUNK  = 4_096             
    MAX_CHUNK  = 1_048_576         
    GROW_RATIO = 2.0
    SHRINK_RATIO = 0.5
    FULL_THRESHOLD = 0.9                                    

    def __init__(self, initial: int = 65536):
        self._chunk = initial

    def recv_into_buffer(self, sock, pool: BufferPool) -> tuple[bytes, int]:
        """
        Soket'ten veri oku, pool'dan buffer al, adaptive chunk boyutuyla doldur.
        Döner: (okunan_bytes, okunan_miktar)
        """
        buf = pool.acquire()
        chunk = min(self._chunk, len(buf))
        n = sock.recv_into(buf, chunk)

        if n > 0:
            fill_ratio = n / chunk
            if fill_ratio >= self.FULL_THRESHOLD:
                self._chunk = min(int(self._chunk * self.GROW_RATIO), self.MAX_CHUNK)
            elif fill_ratio < 0.3:
                self._chunk = max(int(self._chunk * self.SHRINK_RATIO), self.MIN_CHUNK)

        result = bytes(buf[:n])
        pool.release(buf)
        return result, n

    @property
    def chunk_size(self) -> int:
        return self._chunk
