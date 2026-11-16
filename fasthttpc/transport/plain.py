"""
fasthttpc — düz (TLS'siz) ``http://`` bağlantıları için soket sarmalayıcı.

Senkron HTTP/1.1 yolu TLS soketinin ``send_record`` / ``recv_record`` arayüzünü
kullanır; :class:`PlainSocket` aynı arayüzü ham TCP soketi üzerinde sağlar, böylece
istek yazma, başlık ve gövde okuma (chunked, Content-Length, EOF) kodu TLS olsun
olmasın aynıdır. Düz HTTP'de ALPN yoktur: her zaman HTTP/1.1 (h2c YOK).
"""
from __future__ import annotations

import socket

_RECV_SIZE = 65536


class PlainSocket:
    """Ham TCP soketi üzerinde ``EncryptedSocket`` uyumlu ince arayüz."""

    __slots__ = ("raw_socket",)

    # TLS durumu yok: ``Session._tls_info`` ``None`` döner (``resp.tls_info is None``).
    state = None

    def __init__(self, raw_socket: socket.socket):
        self.raw_socket = raw_socket

    def send_record(self, data: bytes, content_type: int = 0x17,
                    use_app_keys: bool = True) -> None:
        self.raw_socket.sendall(data)

    def recv_record(self, skip_post_handshake: bool = False) -> "tuple[bytes, int]":
        """``(veri, 23)``; bağlantı kapandıysa ``(b"", 23)``. Zaman aşımı ve bağlantı
        hataları (``ConnectionResetError`` dahil) çağırana yükseltilir."""
        return self.raw_socket.recv(_RECV_SIZE), 23
