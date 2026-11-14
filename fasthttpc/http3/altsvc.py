"""Alt-Svc (RFC 7838) ayrıştırma ve host başına önbellek.

Bu modül aioquic'e bağlı DEĞİLDİR (çekirdek paket aioquic'siz import edilebilir).
"""
from __future__ import annotations

import re
import threading
import time
from typing import NamedTuple, Optional

DEFAULT_MA = 86400          # RFC 7838 §3.1: ma verilmezse 24 saat
MAX_MA = 7 * 86400          # aşırı uzun ma değerlerini kırp (bayat yönlendirme riski)

_ALT_RE = re.compile(r'^\s*([^=\s;,]+)\s*=\s*"((?:[^"\\]|\\.)*)"\s*(.*)$', re.S)
_PARAM_RE = re.compile(r'\s*;\s*([A-Za-z0-9_.-]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^;,\s]*)')


class AltService(NamedTuple):
    host: str            # "" -> kaynakla aynı host
    port: int
    max_age: float


def _split_entries(value: str) -> list[str]:
    """Virgülle ayır (tırnak içindeki virgüller korunur)."""
    out, cur, quoted, esc = [], [], False, False
    for ch in value:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\" and quoted:
            cur.append(ch)
            esc = True
        elif ch == '"':
            quoted = not quoted
            cur.append(ch)
        elif ch == "," and not quoted:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return [e for e in (x.strip() for x in out) if e]


def parse_alt_svc(value: str) -> "Optional[list[AltService]]":
    """``Alt-Svc`` değerinden h3 girdilerini çıkarır.

    ``None`` → ``clear`` (önbelleği sil); liste (boş olabilir) → h3 girdileri.
    Yalnızca tam ``h3`` protokol kimliği kabul edilir (h3-29 gibi taslaklar değil).
    """
    if value.strip().lower() == "clear":
        return None
    result: list[AltService] = []
    for entry in _split_entries(value):
        m = _ALT_RE.match(entry)
        if not m or m.group(1).lower() != "h3":
            continue
        authority, rest = m.group(2), m.group(3)
        host, sep, port_s = authority.rpartition(":")
        if not sep or not port_s.isdigit() or not 0 < int(port_s) < 65536:
            continue
        ma = float(DEFAULT_MA)
        for pk, pv in _PARAM_RE.findall(rest):
            if pk.lower() == "ma":
                try:
                    ma = float(pv.strip('"'))
                except ValueError:
                    ma = float(DEFAULT_MA)
        if ma <= 0:
            continue
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        result.append(AltService(host.lower(), int(port_s), min(ma, MAX_MA)))
    return result


class AltSvcCache:
    """(host, port) -> h3 alternatifi; ``ma`` süresiyle."""

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        self._map: dict[tuple, tuple[AltService, float]] = {}

    def update(self, origin: tuple, header_values: "list[str]") -> None:
        # Birden çok Alt-Svc başlığı birleşik değerlendirilir; "clear" hepsini siler.
        found: list[AltService] = []
        for v in header_values:
            parsed = parse_alt_svc(v)
            if parsed is None:
                with self._lock:
                    self._map.pop(origin, None)
                return
            found.extend(parsed)
        if not found:
            return
        alt = found[0]
        with self._lock:
            self._map[origin] = (alt, self._clock() + alt.max_age)

    def get(self, origin: tuple) -> Optional[AltService]:
        with self._lock:
            item = self._map.get(origin)
            if item is None:
                return None
            if item[1] <= self._clock():
                del self._map[origin]
                return None
            return item[0]

    def drop(self, origin: tuple) -> None:
        with self._lock:
            self._map.pop(origin, None)
