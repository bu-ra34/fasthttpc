"""Asenkron sarmalayıcı: asyncio StreamReader/StreamWriter (ya da trio'da anyio akışı) + sans-IO çekirdek.

İki yüzey sunar:
  * EncryptedSocket'in await'li karşılığı: `await send_record(...)`,
    `await recv_record(skip_post_handshake=...)`, `state`.
  * StreamReader/StreamWriter benzeri: `await read(n)`, `write(b)`,
    `await drain()`, `close()`, `await wait_closed()` — böylece
    asyncio.open_connection(ssl=...) dönüşü kullanan kod
    `reader = writer = stream` ile değişmeden çalışır.
"""
from __future__ import annotations

from typing import Any, Optional

from .. import _backend as B
from ..transport.lingering import async_send_and_drain
from .connection import TLSClientConnection
from ._records import RecordQueue


class AsyncTLSStream:
    def __init__(self, reader: Any, writer: Any,
                 conn: TLSClientConnection):
        self.reader = reader
        self.writer = writer
        self.conn = conn
        self._records = RecordQueue()
        self._appbuf = bytearray()
        self._eof = False

    # --------------------------------------------------------------- kurulum
    @classmethod
    async def connect(
        cls,
        host: str,
        port: int = 443,
        profile_name: Optional[str] = None,
        *,
        server_hostname: Optional[str] = None,
        **conn_kwargs,
    ) -> "AsyncTLSStream":
        """TCP bağlantısı açar ve TLS handshake'ini yapar."""
        reader, writer = await B.open_connection(host, port)
        try:
            conn_kwargs.setdefault("port", port)
            return await cls.negotiate(reader, writer, server_hostname or host,
                                       profile_name, **conn_kwargs)
        except BaseException:
            writer.close()
            raise

    @classmethod
    async def negotiate(
        cls,
        reader: Any,
        writer: Any,
        host: str,
        profile_name: Optional[str] = None,
        **conn_kwargs,
    ) -> "AsyncTLSStream":
        if conn_kwargs.get("port") is None:
            # Port verilmediyse (proxy tüneli) eş adresinden; resumption anahtarı için.
            peer = writer.get_extra_info("peername")
            if peer:
                conn_kwargs["port"] = peer[1]
        conn = TLSClientConnection(host, profile_name, **conn_kwargs)
        self = cls(reader, writer, conn)
        writer.write(conn.initiate())
        await writer.drain()
        try:
            while not conn.handshake_complete:
                data = await reader.read(65536)
                if not data:
                    raise ConnectionResetError("TLS handshake sırasında sunucu bağlantıyı kapattı.")
                events = conn.receive_data(data)
                out = conn.data_to_send()
                if out:
                    writer.write(out)
                    await writer.drain()
                self._records.extend(events)
        except Exception:
            # Senkron yolla (tls12.negotiate_tls12) aynı: çekirdeğin kuyruğa aldığı fatal
            # alert best-effort gönderilir, ardından RST yerine FIN + kısa boşaltma
            # (bkz. transport/lingering.py). Gönderim hatası asıl istisnayı maskelemez.
            await async_send_and_drain(reader, writer, conn.data_to_send())
            raise
        return self

    @property
    def state(self) -> dict:
        return self.conn.crypto_state()

    # ------------------------------------------ EncryptedSocket (await'li)
    async def send_record(self, data: bytes, content_type: int = 0x17,
                          use_app_keys: bool = True) -> None:
        self.conn.send_record(data, content_type)
        self.writer.write(self.conn.data_to_send())
        await self.writer.drain()

    async def recv_record(self, skip_post_handshake: bool = False) -> tuple[bytes, int]:
        while True:
            rec = self._records.pop(skip_post_handshake)
            if rec is not None:
                return rec
            if self.conn.closed:
                raise ConnectionResetError("TLS bağlantısı kapandı.")
            data = await self.reader.read(65536)
            if not data:
                raise ConnectionResetError("TLS şifreli paket beklenirken bağlantı koptu!")
            try:
                self._records.extend(self.conn.receive_data(data))
            except Exception:
                # Hata öncesi kuyruğa alınan alert'ler best-effort gönderilir.
                out = self.conn.data_to_send()
                if out and not self.writer.is_closing():
                    self.writer.write(out)
                raise
            out = self.conn.data_to_send()
            if out:
                self.writer.write(out)
                await self.writer.drain()

    # ------------------------------------------- StreamReader/Writer yüzeyi
    async def read(self, n: int = -1) -> bytes:
        """En fazla n byte uygulama verisi; EOF/close_notify'da b"" döner."""
        while not self._appbuf and not self._eof:
            try:
                content, ctype = await self.recv_record(skip_post_handshake=True)
            except ConnectionResetError:
                self._eof = True
                break
            if ctype == 23:
                self._appbuf += content
            elif ctype == 21:
                self._eof = True
                if content[1:2] != b"\x00":
                    raise ConnectionError(f"Sunucudan TLS alert: {content.hex()}")
        # Çekirdeğin zaten çözdüğü sıradaki uygulama verisi record'larını da (await
        # etmeden) ekle: tek read() çağrısı record başına bir tur yerine elde ne
        # varsa (en çok n bayt) döner. Alert/kapanış kuyrukta bırakılır.
        unbounded = n is None or n < 0
        while unbounded or len(self._appbuf) < n:
            more = self._records.pop_data()
            if more is None:
                break
            self._appbuf += more
        if unbounded or n >= len(self._appbuf):
            out = bytes(self._appbuf)
            self._appbuf.clear()
            return out
        out = bytes(self._appbuf[:n])
        del self._appbuf[:n]
        return out

    def at_eof(self) -> bool:
        return self._eof and not self._appbuf

    def write(self, data: bytes) -> None:
        self.conn.send_record(data, 0x17)
        self.writer.write(self.conn.data_to_send())

    async def drain(self) -> None:
        await self.writer.drain()

    def close(self) -> None:
        try:
            out = self.conn.close()
            if out and not self.writer.is_closing():
                self.writer.write(out)
        except (OSError, RuntimeError):
            pass
        self.writer.close()

    async def wait_closed(self) -> None:
        await self.writer.wait_closed()

    def get_extra_info(self, name: str, default=None):
        if name == "alpn":
            return self.conn.alpn
        if name == "peercert":
            return self.conn.peer_certificate
        return self.writer.get_extra_info(name, default)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        self.close()
        try:
            await self.wait_closed()
        except (OSError, ConnectionError):
            pass
