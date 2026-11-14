"""
fasthttpc — proxy tünelleri (HTTP CONNECT ve SOCKS5).

Proxy yalnızca TCP baytlarını taşır; TLS (ve tarayıcı parmak izi) her zaman
tünelin İÇİNDE fasthttpc'nin kendi TLS 1.3 yığınıyla kurulur. Bu yüzden proxy
TLS'i göremez/değiştiremez ve sertifika doğrulaması hedef host'a karşı yapılır.

Desteklenen proxy URL'leri:
  http://[user:pass@]host[:port]     — HTTP CONNECT (Proxy-Authorization: Basic)
  socks5://[user:pass@]host[:port]   — SOCKS5 (RFC 1928), no-auth veya
  socks5h://...                        kullanıcı/parola (RFC 1929)

SOCKS5'te hedef adı her zaman DOMAIN (ATYP=3) olarak gönderilir, yani DNS
çözümlemesi proxy tarafında yapılır (yerel DNS sızıntısı olmaz). Hedef bir IP
literal'i ise ATYP=1/4 kullanılır. TLS ile proxy'ye bağlanma (https://proxy)
desteklenmez.
"""
from __future__ import annotations

import base64
import ipaddress
import socket
import struct
from dataclasses import dataclass
from typing import Mapping, Optional, Union
from urllib.parse import unquote, urlsplit

from .._log import get_logger
from .happy_eyeballs import CONNECTION_ATTEMPT_DELAY, create_connection

logger = get_logger("proxy")

_MAX_CONNECT_RESPONSE = 64 * 1024


class ProxyError(ConnectionError):
    """Proxy bağlantısı veya tünel kurulumu başarısız."""


@dataclass(frozen=True)
class ProxyConfig:
    scheme: str            # "http" | "socks5" | "socks5h"
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None

    def __repr__(self) -> str:  # parolayı loglara sızdırma
        auth = f"{self.username}:***@" if self.username else ""
        return f"ProxyConfig({self.scheme}://{auth}{self.host}:{self.port})"


_DEFAULT_PORTS = {"http": 8080, "socks5": 1080, "socks5h": 1080}


def parse_proxy_url(url: str) -> ProxyConfig:
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    if scheme == "https":
        raise ValueError(
            "https:// proxy (proxy'ye TLS ile bağlanma) desteklenmiyor; http:// "
            "(CONNECT) veya socks5:// kullanın. Hedefe giden TLS yine uçtan uca kurulur."
        )
    if scheme not in _DEFAULT_PORTS:
        raise ValueError(f"Desteklenmeyen proxy şeması: {url!r} (http, socks5, socks5h)")
    if not parts.hostname:
        raise ValueError(f"Proxy URL'inde host yok: {url!r}")
    return ProxyConfig(
        scheme=scheme,
        host=parts.hostname,
        port=parts.port or _DEFAULT_PORTS[scheme],
        username=unquote(parts.username) if parts.username is not None else None,
        password=unquote(parts.password) if parts.password is not None else None,
    )


ProxySpec = Union[None, str, ProxyConfig, Mapping[str, Optional[str]]]


def resolve_proxy(proxies: ProxySpec, target_scheme: str = "https") -> Optional[ProxyConfig]:
    """``proxy=``/``proxies=`` değerinden hedef şema için ProxyConfig seçer.

    proxies: None, tek URL / ProxyConfig, ya da requests tarzı sözlük
    ({"https": "...", "http": "...", "all": "..."}).
    """
    if proxies is None:
        return None
    if isinstance(proxies, ProxyConfig):
        return proxies
    if isinstance(proxies, str):
        return parse_proxy_url(proxies)
    url = proxies.get(target_scheme) or proxies.get("all")
    return parse_proxy_url(url) if url else None


# ---- düşük seviye yardımcılar ------------------------------------------------

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProxyError("Proxy bağlantıyı beklenmedik biçimde kapattı.")
        buf.extend(chunk)
    return bytes(buf)


def _host_header(host: str, port: int) -> str:
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]:{port}"
    except ValueError:
        pass
    return f"{host}:{port}"


def http_connect(sock: socket.socket, proxy: ProxyConfig, host: str, port: int) -> None:
    """Bağlı soket üzerinde HTTP CONNECT tüneli kurar (RFC 9110 §9.3.6)."""
    target = _host_header(host, port)
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
    if proxy.username is not None:
        cred = f"{proxy.username}:{proxy.password or ''}".encode("utf-8")
        lines.append("Proxy-Authorization: Basic " + base64.b64encode(cred).decode("ascii"))
    lines.append("Proxy-Connection: keep-alive")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))

    # Yanıtı byte byte oku: başlıklardan sonrası tünel verisidir ve TLS
    # katmanına aittir, fazla okunmamalı.
    buf = bytearray()
    while not buf.endswith(b"\r\n\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise ProxyError("Proxy CONNECT yanıtı tamamlanmadan bağlantıyı kapattı.")
        buf.extend(chunk)
        if len(buf) > _MAX_CONNECT_RESPONSE:
            raise ProxyError("Proxy CONNECT yanıt başlıkları çok büyük.")

    status_line = bytes(buf).split(b"\r\n", 1)[0].decode("latin-1")
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        raise ProxyError(f"Geçersiz proxy yanıtı: {status_line!r}")
    code = int(parts[1])
    if code == 407:
        raise ProxyError(
            "Proxy kimlik doğrulaması gerekli/başarısız (407). Proxy URL'inde "
            "kullanıcı:parola verin."
        )
    if not 200 <= code < 300:
        raise ProxyError(f"Proxy CONNECT reddedildi: {status_line}")


_SOCKS5_REPLIES = {
    1: "genel SOCKS sunucu hatası", 2: "kural seti bağlantıya izin vermiyor",
    3: "ağa ulaşılamıyor", 4: "host'a ulaşılamıyor", 5: "bağlantı reddedildi",
    6: "TTL süresi doldu", 7: "komut desteklenmiyor", 8: "adres tipi desteklenmiyor",
}


def socks5_connect(sock: socket.socket, proxy: ProxyConfig, host: str, port: int) -> None:
    """Bağlı soket üzerinde SOCKS5 CONNECT yapar (RFC 1928 / RFC 1929)."""
    methods = [0x00]
    if proxy.username is not None:
        methods = [0x02, 0x00]
    sock.sendall(bytes([0x05, len(methods)]) + bytes(methods))
    ver, method = _recv_exact(sock, 2)
    if ver != 0x05:
        raise ProxyError(f"SOCKS5 değil (sürüm={ver}).")
    if method == 0xFF:
        raise ProxyError("SOCKS5 proxy teklif edilen kimlik doğrulama yöntemlerini kabul etmedi.")
    if method == 0x02:
        if proxy.username is None:
            raise ProxyError("SOCKS5 proxy kullanıcı/parola istedi ama verilmedi.")
        user = proxy.username.encode("utf-8")
        pwd = (proxy.password or "").encode("utf-8")
        if len(user) > 255 or len(pwd) > 255:
            raise ProxyError("SOCKS5 kullanıcı adı/parola 255 byte'ı aşamaz.")
        sock.sendall(bytes([0x01, len(user)]) + user + bytes([len(pwd)]) + pwd)
        _v, status = _recv_exact(sock, 2)
        if status != 0x00:
            raise ProxyError("SOCKS5 kimlik doğrulaması başarısız (kullanıcı/parola).")
    elif method != 0x00:
        raise ProxyError(f"SOCKS5 proxy desteklenmeyen yöntem seçti: {method}")

    try:
        ip = ipaddress.ip_address(host)
        addr = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
    except ValueError:
        name = host.encode("idna")
        if len(name) > 255:
            raise ProxyError("SOCKS5 için host adı çok uzun.")
        addr = b"\x03" + bytes([len(name)]) + name
    sock.sendall(b"\x05\x01\x00" + addr + struct.pack("!H", port))

    ver, rep, _rsv, atyp = _recv_exact(sock, 4)
    if ver != 0x05:
        raise ProxyError("SOCKS5 yanıtı bozuk.")
    if rep != 0x00:
        raise ProxyError(f"SOCKS5 CONNECT reddedildi: {_SOCKS5_REPLIES.get(rep, rep)}")
    # BND.ADDR / BND.PORT'u tüket
    if atyp == 0x01:
        _recv_exact(sock, 4 + 2)
    elif atyp == 0x04:
        _recv_exact(sock, 16 + 2)
    elif atyp == 0x03:
        _recv_exact(sock, _recv_exact(sock, 1)[0] + 2)
    else:
        raise ProxyError(f"SOCKS5 yanıtında bilinmeyen adres tipi: {atyp}")


def open_tunnel(sock: socket.socket, proxy: ProxyConfig, host: str, port: int) -> None:
    """Proxy'ye BAĞLI soket üzerinde hedef host:port'a tünel kurar."""
    logger.debug("Proxy tüneli: %r -> %s:%d", proxy, host, port)
    if proxy.scheme == "http":
        http_connect(sock, proxy, host, port)
    else:
        socks5_connect(sock, proxy, host, port)


def connect_via_proxy(proxy: ProxyConfig, host: str, port: int,
                      timeout: Optional[float] = 30.0) -> socket.socket:
    """Proxy'ye TCP bağlanır, tüneli kurar ve ham soketi döner.

    Dönen soket üzerinde doğrudan ``TLSAdapter.negotiate`` çalıştırılabilir.
    """
    try:
        sock = create_connection((proxy.host, proxy.port), timeout=timeout)
    except OSError as e:
        raise ProxyError(f"Proxy'ye bağlanılamadı ({proxy.host}:{proxy.port}): {e}") from e
    try:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        open_tunnel(sock, proxy, host, port)
    except BaseException:
        sock.close()
        raise
    return sock


# ---- asyncio sürümü -------------------------------------------------------------
# Aşağıdaki saf fonksiyonlar (bayt üretimi / yanıt ayrıştırma) ve asyncio
# sarmalayıcıları, yukarıdaki senkron ``http_connect`` / ``socks5_connect`` ile
# AYNI wire formatını üretir ve aynı hata mesajlarını verir (testlerle sabitlenir).

def build_connect_request(proxy: ProxyConfig, host: str, port: int) -> bytes:
    """HTTP CONNECT isteğinin baytlarını üretir (Basic auth dahil)."""
    target = _host_header(host, port)
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
    if proxy.username is not None:
        cred = f"{proxy.username}:{proxy.password or ''}".encode("utf-8")
        lines.append("Proxy-Authorization: Basic " + base64.b64encode(cred).decode("ascii"))
    lines.append("Proxy-Connection: keep-alive")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def check_connect_response(head: bytes) -> None:
    """CONNECT yanıt başlıklarını doğrular; başarısızsa :class:`ProxyError`."""
    status_line = bytes(head).split(b"\r\n", 1)[0].decode("latin-1")
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        raise ProxyError(f"Geçersiz proxy yanıtı: {status_line!r}")
    code = int(parts[1])
    if code == 407:
        raise ProxyError(
            "Proxy kimlik doğrulaması gerekli/başarısız (407). Proxy URL'inde "
            "kullanıcı:parola verin."
        )
    if not 200 <= code < 300:
        raise ProxyError(f"Proxy CONNECT reddedildi: {status_line}")


def socks5_greeting(proxy: ProxyConfig) -> bytes:
    methods = [0x02, 0x00] if proxy.username is not None else [0x00]
    return bytes([0x05, len(methods)]) + bytes(methods)


def socks5_auth_request(proxy: ProxyConfig) -> bytes:
    if proxy.username is None:
        raise ProxyError("SOCKS5 proxy kullanıcı/parola istedi ama verilmedi.")
    user = proxy.username.encode("utf-8")
    pwd = (proxy.password or "").encode("utf-8")
    if len(user) > 255 or len(pwd) > 255:
        raise ProxyError("SOCKS5 kullanıcı adı/parola 255 byte'ı aşamaz.")
    return bytes([0x01, len(user)]) + user + bytes([len(pwd)]) + pwd


def socks5_connect_request(host: str, port: int) -> bytes:
    try:
        ip = ipaddress.ip_address(host)
        addr = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
    except ValueError:
        name = host.encode("idna")
        if len(name) > 255:
            raise ProxyError("SOCKS5 için host adı çok uzun.")
        addr = b"\x03" + bytes([len(name)]) + name
    return b"\x05\x01\x00" + addr + struct.pack("!H", port)


def _socks5_check_method(method_reply: bytes, proxy: ProxyConfig) -> int:
    ver, method = method_reply
    if ver != 0x05:
        raise ProxyError(f"SOCKS5 değil (sürüm={ver}).")
    if method == 0xFF:
        raise ProxyError("SOCKS5 proxy teklif edilen kimlik doğrulama yöntemlerini kabul etmedi.")
    if method not in (0x00, 0x02):
        raise ProxyError(f"SOCKS5 proxy desteklenmeyen yöntem seçti: {method}")
    return method


async def async_http_connect(reader, writer, proxy: ProxyConfig, host: str, port: int) -> None:
    """asyncio akışı üzerinde HTTP CONNECT tüneli kurar."""
    import asyncio
    writer.write(build_connect_request(proxy, host, port))
    await writer.drain()
    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError as e:
        raise ProxyError("Proxy CONNECT yanıtı tamamlanmadan bağlantıyı kapattı.") from e
    except asyncio.LimitOverrunError as e:
        raise ProxyError("Proxy CONNECT yanıt başlıkları çok büyük.") from e
    if len(head) > _MAX_CONNECT_RESPONSE:
        raise ProxyError("Proxy CONNECT yanıt başlıkları çok büyük.")
    check_connect_response(head)


async def _async_recv_exact(reader, n: int) -> bytes:
    import asyncio
    try:
        return await reader.readexactly(n)
    except asyncio.IncompleteReadError as e:
        raise ProxyError("Proxy bağlantıyı beklenmedik biçimde kapattı.") from e


async def async_socks5_connect(reader, writer, proxy: ProxyConfig, host: str, port: int) -> None:
    """asyncio akışı üzerinde SOCKS5 CONNECT yapar (RFC 1928 / RFC 1929)."""
    writer.write(socks5_greeting(proxy))
    await writer.drain()
    method = _socks5_check_method(await _async_recv_exact(reader, 2), proxy)
    if method == 0x02:
        writer.write(socks5_auth_request(proxy))
        await writer.drain()
        _v, status = await _async_recv_exact(reader, 2)
        if status != 0x00:
            raise ProxyError("SOCKS5 kimlik doğrulaması başarısız (kullanıcı/parola).")
    writer.write(socks5_connect_request(host, port))
    await writer.drain()

    ver, rep, _rsv, atyp = await _async_recv_exact(reader, 4)
    if ver != 0x05:
        raise ProxyError("SOCKS5 yanıtı bozuk.")
    if rep != 0x00:
        raise ProxyError(f"SOCKS5 CONNECT reddedildi: {_SOCKS5_REPLIES.get(rep, rep)}")
    if atyp == 0x01:
        await _async_recv_exact(reader, 4 + 2)
    elif atyp == 0x04:
        await _async_recv_exact(reader, 16 + 2)
    elif atyp == 0x03:
        await _async_recv_exact(reader, (await _async_recv_exact(reader, 1))[0] + 2)
    else:
        raise ProxyError(f"SOCKS5 yanıtında bilinmeyen adres tipi: {atyp}")


async def async_open_tunnel(reader, writer, proxy: ProxyConfig, host: str, port: int) -> None:
    """Proxy'ye BAĞLI asyncio akışı üzerinde hedef host:port'a tünel kurar."""
    logger.debug("Proxy tüneli (async): %r -> %s:%d", proxy, host, port)
    if proxy.scheme == "http":
        await async_http_connect(reader, writer, proxy, host, port)
    else:
        await async_socks5_connect(reader, writer, proxy, host, port)


async def async_connect_via_proxy(proxy: ProxyConfig, host: str, port: int,
                                  timeout: Optional[float] = 30.0):
    """Proxy'ye bağlanır, tüneli kurar; (reader, writer) döner.

    ``timeout`` TCP bağlantısı + tünel kurulumu için toplam süredir. Dönen akış
    üzerinde ``AsyncTLSStream.negotiate`` veya ``writer.start_tls`` çalıştırılır.
    """
    import asyncio
    import time

    from .. import _backend as B

    # Senkron ``connect_via_proxy`` ile aynı anlam: proxy'ye TCP bağlantısı kurulamaması —
    # reddedilme de, connect süresinin dolması da (Windows'ta kapalı porta bağlanma reddi ~2 sn
    # sonra bildirilir) — ProxyError'dır. Tünel aşamasının zaman aşımı ham TimeoutError kalır.
    t0 = time.perf_counter()
    try:
        reader, writer = await B.wait_for(B.open_connection(proxy.host, proxy.port), timeout)
    except (OSError, asyncio.TimeoutError) as e:
        raise ProxyError(f"Proxy'ye bağlanılamadı ({proxy.host}:{proxy.port}): "
                         f"{e or type(e).__name__}") from e
    left = None if timeout is None else max(0.0, timeout - (time.perf_counter() - t0))

    async def _tunnel():
        try:
            await async_open_tunnel(reader, writer, proxy, host, port)
        except BaseException:
            writer.close()
            raise
        return reader, writer

    return await B.wait_for(_tunnel(), left)
