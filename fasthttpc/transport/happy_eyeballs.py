"""Happy Eyeballs (RFC 8305) — senkron TCP bağlantısı.

Bir host birden çok adrese çözüldüğünde (tipik: AAAA + A) adresler sırayla
değil, ``delay`` (varsayılan 250 ms) aralıkla ve aileler dönüşümlü
yarıştırılır; ilk tamamlanan bağlantı kazanır, kalanlar kapatılır. Bir deneme
hata ile biterse bir sonrakine beklemeden geçilir.

Neden: Windows'ta "localhost" önce ``::1``'e çözülür, ama sunucu yalnızca
127.0.0.1'de dinliyorsa reddedilen bağlantı ~2 sn SYN yeniden denemesiyle
anlaşılır (Linux/macOS'ta RST hemen gelir). Sıralı deneme her bağlantıya +2 sn
ekler; yarışta ise 250 ms'de IPv4 kazanır. Aynı etki, IPv6 rotası kara delik
olan gerçek ağlarda da vardır.

Tek bir iş parçacığında, ``selectors`` ile; ek thread yok.
"""
from __future__ import annotations

import errno
import selectors
import socket
import time
from typing import Callable, Optional, Sequence

#: RFC 8305 "Connection Attempt Delay" (öneri 250 ms).
CONNECTION_ATTEMPT_DELAY = 0.25

_IN_PROGRESS = {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, 10035}  # 10035 = WSAEWOULDBLOCK
_DENIED = {errno.EACCES, errno.EPERM}

AddrInfo = tuple  # (family, type, proto, canonname, sockaddr)


def interleave(infos: Sequence[AddrInfo]) -> list[AddrInfo]:
    """Adres ailelerini dönüşümlü sıralar (ilk gelen aile önce); sıra korunur."""
    by_family: dict[int, list[AddrInfo]] = {}
    for info in infos:
        by_family.setdefault(info[0], []).append(info)
    queues = list(by_family.values())
    out: list[AddrInfo] = []
    while any(queues):
        for q in queues:
            if q:
                out.append(q.pop(0))
    return out


def connect_infos(infos: Sequence[AddrInfo], timeout: Optional[float], *,
                  delay: float = CONNECTION_ATTEMPT_DELAY,
                  prepare: Optional[Callable[[socket.socket], None]] = None,
                  _socket=socket.socket) -> socket.socket:
    """``infos`` (getaddrinfo çıktısı) adreslerini yarıştırıp bağlı soketi döner.

    ``timeout`` toplam süredir (``None``: sınırsız). Dönen soket bloklayan kipte
    ve ``timeout`` ayarlıdır. Hepsi başarısız olursa son ``OSError`` yükselir;
    ``PermissionError`` (güvenlik duvarı/sandbox) beklemeden yükselir.
    """
    if not infos:
        raise OSError("bağlanılacak adres yok")
    todo = interleave(infos)
    deadline = None if timeout is None else time.perf_counter() + timeout
    sel = selectors.DefaultSelector()
    pending: dict[int, tuple] = {}            # fd -> (sock, sockaddr)
    last_error: Optional[OSError] = None
    winner: Optional[socket.socket] = None
    timed_out = False

    def start() -> Optional[socket.socket]:
        """Sıradaki adresi dener; hemen bağlandıysa soketi döner."""
        nonlocal last_error
        family, socktype, proto, _canon, addr = todo.pop(0)
        try:
            s = _socket(family, socktype, proto)
        except OSError as e:
            last_error = e
            return None
        try:
            if prepare is not None:
                prepare(s)
            s.setblocking(False)
            err = s.connect_ex(addr)
        except OSError as e:
            s.close()
            last_error = e
            return None
        if err == 0:
            return s
        if err in _IN_PROGRESS:
            pending[s.fileno()] = (s, addr)
            sel.register(s.fileno(), selectors.EVENT_WRITE)
            return None
        s.close()
        if err in _DENIED:
            raise PermissionError(err, "Permission denied")
        last_error = OSError(err, errno.errorcode.get(err, "connect"))
        return None

    try:
        while winner is None:
            if todo:
                winner = start()
                if winner is not None:
                    break
            if not pending:
                if todo:
                    continue                  # hata: beklemeden sonraki adres
                break
            now = time.perf_counter()
            remaining = None if deadline is None else deadline - now
            if remaining is not None and remaining <= 0:
                timed_out = True
                break
            wait = remaining
            if todo:                          # sıradaki deneme için yarış gecikmesi
                wait = delay if remaining is None else min(delay, remaining)
            events = sel.select(wait)
            for key, _ in events:
                s, _addr = pending.pop(key.fd)
                sel.unregister(key.fd)
                err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err == 0:
                    winner = s
                    break
                s.close()
                last_error = OSError(err, errno.errorcode.get(err, "connect"))
            # events boşsa gecikme doldu: döngü başında sıradaki adres başlar
        if winner is None:
            if timed_out or last_error is None:
                raise TimeoutError("timed out")
            raise last_error
        winner.settimeout(timeout)
        return winner
    finally:
        for s, _a in pending.values():
            s.close()
        sel.close()


def create_connection(address: tuple[str, int], timeout: Optional[float] = 30.0, *,
                      delay: float = CONNECTION_ATTEMPT_DELAY,
                      prepare: Optional[Callable[[socket.socket], None]] = None) -> socket.socket:
    """``socket.create_connection`` yerine: getaddrinfo + Happy Eyeballs."""
    host, port = address
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    return connect_infos(infos, timeout, delay=delay, prepare=prepare)
