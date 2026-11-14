"""Sans-IO HTTP/3 istemci çekirdeği (aioquic QuicConnection + H3Connection).

Ne soket ne asyncio içerir: ``receive`` / ``transmit`` / ``timer`` ile sürülür. Sync
(select) ve async (asyncio) sürücüleri bunun üzerine kuruludur.
"""
from __future__ import annotations

import collections
import ipaddress
import ssl
from typing import Callable, Optional

from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

try:    # aioquic >= 1.8; eski sürümlerde GOAWAY olayı yüzeye çıkmaz (sunucu GOAWAY'i görünmez)
    from aioquic.h3.events import GoAwayReceived
except ImportError:     # pragma: no cover - sürüme bağlı
    class GoAwayReceived:       # type: ignore[no-redef]
        stream_id = 0
from aioquic.quic import events as qevents
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

from ..security.cert_validator import CertificateValidationError
from . import fingerprint as fp
from .verify import validate_peer_chain


class Http3Error(ConnectionError):
    """HTTP/3 taşıma hatası (ConnectionError alt sınıfı: retry politikasıyla uyumlu)."""


class Http3ConnectError(Http3Error):
    """İstek gönderilmeden ÖNCE oluşan hata (el sıkışma/UDP/sertifika): h2'ye düşmek güvenli."""

    def __init__(self, message: str, cause: "BaseException | None" = None):
        super().__init__(message)
        self.cause = cause


class Http3RequestRefused(Http3Error):
    """Sunucu (GOAWAY) isteği işlemedi: yeni bağlantıda yeniden denemek güvenli."""


def make_h3_class(profile: fp.QuicProfile):
    """Profilin SETTINGS'ini/QPACK ayarını uygulayan H3Connection alt sınıfı."""
    import pylsqpack

    settings = fp.h3_settings(profile)

    class _H3(H3Connection):
        def _get_local_settings(self):
            return dict(settings) if settings else super()._get_local_settings()

        def __init__(self, quic):
            super().__init__(quic)
            if profile.qpack_table_capacity:
                # Gerçek dinamik tablo kapasitesi ilan ediliyorsa çözücü de ona göre kurulur
                # (bloklanan akış sayısı 0: aioquic StreamBlocked'ı işlemez).
                self._max_table_capacity = profile.qpack_table_capacity
                try:
                    self._decoder = pylsqpack.Decoder(
                        profile.qpack_table_capacity, 0,
                        max_field_section_size=profile.max_field_section_size)
                except TypeError:   # eski pylsqpack: bu anahtar yok
                    self._decoder = pylsqpack.Decoder(profile.qpack_table_capacity, 0)

    return _H3


class _Stream:
    def __init__(self, stream_id: int):
        self.stream_id = stream_id
        self.headers: "Optional[list[tuple[bytes, bytes]]]" = None
        self.chunks: "collections.deque[bytes]" = collections.deque()
        self.ended = False
        self.error: "Optional[BaseException]" = None
        self.refused = False
        self.notify: "Optional[Callable[[], None]]" = None

    def wake(self) -> None:
        if self.notify is not None:
            self.notify()


class H3Core:
    def __init__(self, host: str, port: int, *, ca_path: Optional[str], impersonate: Optional[str],
                 idle_timeout: Optional[float] = None, clock: Callable[[], float]):
        self.host, self.port = host, port
        self.ca_path = ca_path
        self.clock = clock
        self.profile = fp.profile_for(impersonate)
        p = self.profile
        cfg = QuicConfiguration(
            is_client=True, alpn_protocols=["h3"], server_name=host,
            max_data=p.max_data, max_stream_data=p.max_stream_data,
            idle_timeout=idle_timeout or p.idle_timeout, max_datagram_size=p.max_datagram_size,
            verify_mode=ssl.CERT_NONE,        # doğrulama _on_handshake'te fasthttpc ile (aşağıda)
            session_ticket=None,              # 0-RTT/resumption YOK (güvenlik)
        )
        if ca_path is not None:
            # Özel CA'da aioquic de ayrıca doğrular (derinlemesine savunma; el sıkışma sırasında).
            cfg.verify_mode = ssl.CERT_REQUIRED
            cfg.load_verify_locations(cafile=ca_path)
        self.quic = QuicConnection(configuration=cfg)
        self.applied = fp.apply_quic_profile(self.quic, p)
        self.h3 = make_h3_class(p)(self.quic)
        self.streams: dict[int, _Stream] = {}
        self.handshake_done = False
        self.closed = False
        self.error: "Optional[BaseException]" = None
        self.goaway_id: "Optional[int]" = None
        self.last_activity = clock()
        self.on_state_change: "Optional[Callable[[], None]]" = None
        self._addr: "Optional[tuple]" = None

    # -- bağlantı yaşam döngüsü -------------------------------------------------
    def connect(self, addr: tuple) -> None:
        self._addr = addr
        self.quic.connect(addr, now=self.clock())

    @property
    def usable(self) -> bool:
        return self.handshake_done and not self.closed and self.goaway_id is None

    def receive(self, data: bytes, addr: tuple) -> None:
        self.last_activity = self.clock()
        self.quic.receive_datagram(data, addr, self.clock())
        self._pump()

    def transmit(self) -> "list[tuple[bytes, tuple]]":
        return self.quic.datagrams_to_send(self.clock())

    def timer(self) -> "Optional[float]":
        return self.quic.get_timer()

    def handle_timer(self) -> None:
        t = self.quic.get_timer()
        if t is not None and t <= self.clock():
            self.quic.handle_timer(self.clock())
            self._pump()

    def close(self) -> None:
        if not self.closed:
            self.quic.close(error_code=0x100)   # H3_NO_ERROR
            self._fail_all(Http3Error("bağlantı kapatıldı"), mark_closed=True)

    # -- olaylar ----------------------------------------------------------------
    def _pump(self) -> None:
        while (ev := self.quic.next_event()) is not None:
            if isinstance(ev, qevents.HandshakeCompleted):
                self._on_handshake(ev)
            elif isinstance(ev, qevents.ConnectionTerminated):
                err = Http3Error(f"QUIC bağlantısı kapandı: kod={ev.error_code:#x} {ev.reason_phrase!r}")
                if not self.handshake_done and self.error is None:
                    cause = None
                    if 0x12A <= ev.error_code <= 0x130:     # TLS alert: bad_certificate .. (aioquic'in kendi doğrulaması)
                        cause = CertificateValidationError(
                            f"HTTP/3 sertifika doğrulaması başarısız (aioquic): {ev.reason_phrase}")
                        err = cause
                    self.error = Http3ConnectError(str(err), cause)
                self._fail_all(err, mark_closed=True)
            elif isinstance(ev, qevents.StreamReset):
                st = self.streams.get(ev.stream_id)
                if st is not None and not st.ended:
                    st.error = Http3Error(f"stream sıfırlandı: {ev.error_code:#x}")
                    st.ended = True
                    st.wake()
            else:
                if self.handshake_done:
                    self._h3_events(ev)
        if self.on_state_change is not None:
            self.on_state_change()

    def _on_handshake(self, ev) -> None:
        try:
            tls = self.quic.tls
            certs = getattr(tls, "peer_certificates", None)
            if certs is None:       # aioquic < 1.8
                certs = ([tls._peer_certificate] if tls._peer_certificate is not None else []) \
                    + list(tls._peer_certificate_chain)
            chain = [c.public_bytes(_DER) for c in certs]
            validate_peer_chain(chain, self.host, self.ca_path)
        except CertificateValidationError as e:
            # Hiçbir uygulama verisi gönderilmeden bağlantıyı kes.
            self.error = Http3ConnectError(f"HTTP/3 sertifika doğrulaması başarısız: {e}", e)
            self.quic.close(error_code=0x12A)   # TLS alert: bad_certificate (0x100+42)
            self._fail_all(self.error, mark_closed=True)
            return
        if ev.alpn_protocol != "h3":
            self.error = Http3ConnectError(f"ALPN h3 değil: {ev.alpn_protocol!r}")
            self.quic.close(error_code=0x178)   # no_application_protocol
            self._fail_all(self.error, mark_closed=True)
            return
        self.handshake_done = True

    def _h3_events(self, quic_event) -> None:
        for ev in self.h3.handle_event(quic_event):
            if isinstance(ev, HeadersReceived):
                st = self.streams.get(ev.stream_id)
                if st is None:
                    continue
                status = dict(ev.headers).get(b":status", b"")
                if status.startswith(b"1"):     # 1xx ara yanıt: son yanıtı bekle
                    continue
                if st.headers is None:
                    st.headers = ev.headers
                # sonraki HEADERS (trailer) yok sayılır
                st.ended = st.ended or ev.stream_ended
                st.wake()
            elif isinstance(ev, DataReceived):
                st = self.streams.get(ev.stream_id)
                if st is None:
                    continue
                if ev.data:
                    st.chunks.append(ev.data)
                st.ended = st.ended or ev.stream_ended
                st.wake()
            elif isinstance(ev, GoAwayReceived):
                self.goaway_id = ev.stream_id
                for st in self.streams.values():
                    if st.stream_id >= ev.stream_id and not st.ended:
                        st.refused = True
                        st.error = Http3RequestRefused("sunucu GOAWAY: istek işlenmedi")
                        st.ended = True
                        st.wake()

    def _fail_all(self, exc: BaseException, *, mark_closed: bool) -> None:
        if mark_closed:
            self.closed = True
        for st in self.streams.values():
            if not st.ended:
                st.error = exc
                st.ended = True
                st.wake()
        if self.on_state_change is not None:
            self.on_state_change()

    # -- istekler ---------------------------------------------------------------
    def send_request(self, method: str, authority: str, path: str,
                     headers: "list[tuple[str, str]]", body: bytes = b"") -> _Stream:
        if not self.usable:
            raise Http3RequestRefused("bağlantı kullanılamıyor (kapalı/GOAWAY)")
        sid = self.quic.get_next_available_stream_id()
        hdrs = [(b":method", method.encode()), (b":scheme", b"https"),
                (b":authority", authority.encode("latin-1")), (b":path", path.encode("latin-1"))]
        for k, v in headers:
            hdrs.append((k.lower().encode("latin-1"), v.encode("latin-1")))
        st = _Stream(sid)
        self.streams[sid] = st
        self.h3.send_headers(sid, hdrs, end_stream=not body)
        if body:
            self.h3.send_data(sid, body, end_stream=True)
        self.last_activity = self.clock()
        return st

    def release(self, st: _Stream) -> None:
        self.streams.pop(st.stream_id, None)


def _der():
    from cryptography.hazmat.primitives.serialization import Encoding
    return Encoding.DER


_DER = _der()


def authority_for(host: str, port: int) -> str:
    try:
        is_v6 = ipaddress.ip_address(host).version == 6
    except ValueError:
        is_v6 = False
    h = f"[{host}]" if is_v6 else host
    return h if port == 443 else f"{h}:{port}"
