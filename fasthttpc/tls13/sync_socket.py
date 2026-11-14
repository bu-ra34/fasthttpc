"""Senkron sarmalayıcı: socket.socket + sans-IO çekirdek.

EncryptedSocket ile aynı yüzey (send_record / recv_record / raw_socket /
state), böylece HTTP/1.1 ve HTTP/2 katmanı değişmeden kullanabilir.
"""
from __future__ import annotations

import socket
from typing import Optional

from .connection import TLSClientConnection
from ._records import RecordQueue


class SyncTLSSocket:
    def __init__(self, raw_socket: socket.socket, conn: TLSClientConnection):
        self.raw_socket = raw_socket
        self.conn = conn
        self._records = RecordQueue()

    # --------------------------------------------------------------- kurulum
    @classmethod
    def negotiate(
        cls,
        raw_socket: socket.socket,
        host: str,
        profile_name: Optional[str] = None,
        **conn_kwargs,
    ) -> "SyncTLSSocket":
        """TLSAdapter.negotiate ile aynı imza (+ çekirdek kwargs: alpn, ca_path)."""
        conn = TLSClientConnection(host, profile_name, **conn_kwargs)
        self = cls(raw_socket, conn)
        raw_socket.sendall(conn.initiate())
        while not conn.handshake_complete:
            data = raw_socket.recv(65536)
            if not data:
                raise ConnectionResetError("TLS handshake sırasında sunucu bağlantıyı kapattı.")
            events = conn.receive_data(data)
            out = conn.data_to_send()
            if out:
                raw_socket.sendall(out)
            self._records.extend(events)
        return self

    @property
    def state(self) -> dict:
        return self.conn.crypto_state()

    # ------------------------------------------------- EncryptedSocket arayüzü
    def send_record(self, data: bytes, content_type: int = 0x17, use_app_keys: bool = True) -> None:
        # use_app_keys yalnızca imza uyumluluğu için: handshake sonrası çekirdek
        # her zaman güncel application anahtarını kullanır.
        self.conn.send_record(data, content_type)
        self.raw_socket.sendall(self.conn.data_to_send())

    def recv_record(self, skip_post_handshake: bool = False) -> tuple[bytes, int]:
        while True:
            rec = self._records.pop(skip_post_handshake)
            if rec is not None:
                return rec
            if self.conn.closed:
                raise ConnectionResetError("TLS bağlantısı kapandı.")
            data = self.raw_socket.recv(65536)
            if not data:
                raise ConnectionResetError("TLS şifreli paket beklenirken bağlantı koptu!")
            try:
                self._records.extend(self.conn.receive_data(data))
            except Exception:
                # Hata öncesi kuyruğa alınan alert'ler (ör. TLS 1.2 fatal alert /
                # no_renegotiation uyarıları) best-effort gönderilir.
                try:
                    out = self.conn.data_to_send()
                    if out:
                        self.raw_socket.sendall(out)
                except OSError:
                    pass
                raise
            out = self.conn.data_to_send()      # ör. KeyUpdate yanıtı
            if out:
                self.raw_socket.sendall(out)

    # ----------------------------------------------------------- yardımcılar
    def settimeout(self, t) -> None:
        self.raw_socket.settimeout(t)

    def close(self) -> None:
        try:
            out = self.conn.close()
            if out:
                self.raw_socket.sendall(out)
        except OSError:
            pass
        finally:
            self.raw_socket.close()
