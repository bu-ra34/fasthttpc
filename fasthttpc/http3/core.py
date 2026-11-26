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
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived

try:    # aioquic >= 1.8 emits GoAwayReceived for a server GOAWAY.
    from aioquic.h3.events import GoAwayReceived
    _NATIVE_GOAWAY = True
except ImportError:     # pragma: no cover - aioquic < 1.8 (the only line on Python 3.10: 1.3)
    # aioquic 1.3-1.7 parse a GOAWAY frame on the control stream and silently DROP it
    # (H3Connection._handle_control_frame has no GOAWAY branch), so a server's graceful
    # shutdown would be invisible. make_h3_class() adds a shim that surfaces it as this event.
    from dataclasses import dataclass

    @dataclass
    class GoAwayReceived(H3Event):      # type: ignore[no-redef]
        stream_id: int

    _NATIVE_GOAWAY = False
from aioquic.quic import events as qevents
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

try:    # aioquic >= 1.9: send_headers refuses to start a request after a GOAWAY (RFC 9114 section 5.2)
    from aioquic.h3.exceptions import InvalidConnectionStateError
except ImportError:     # pragma: no cover - aioquic < 1.9 never refuses; nothing raises this placeholder
    class InvalidConnectionStateError(Exception):     # type: ignore[no-redef]
        pass

from ..security.cert_validator import CertificateValidationError

# Çok adresli çözümlemede (ör. localhost -> ::1, 127.0.0.1) SON OLMAYAN bir adres, bu süre
# içinde sunucudan hiç datagram gelmezse bırakılıp sıradakine geçilir (RFC 8305'teki sabit
# "connection attempt delay" fikri; QUIC Initial'ı birkaç kez yeniden gönderilecek kadar uzun).
# Yanıt gelen adrese bağlanılır: el sıkışması kalan toplam sürenin tamamını kullanabilir.
ADDRESS_PROBE_TIMEOUT = 1.0


def address_probe_window(remaining: float, addrs_left: int) -> "Optional[float]":
    """Sıradaki adresin "ilk yanıt" bekleme penceresi (sn); ``None``: son adres, sınır yok.

    Eski davranış kalan süreyi adreslere EŞİT bölüyordu: sessiz (ya da ICMP reddinin
    bildirilmediği) ilk adres payının tamamını harcıyor, çalışan son adrese soğuk bir QUIC
    el sıkışması için yetersiz süre kalıyordu. Artık son olmayan adres en fazla
    ``min(ADDRESS_PROBE_TIMEOUT, remaining / addrs_left)`` sn yanıtsız beklenir; hızlı
    başarısızlıkta (ICMP reddi) kullanılmayan süre zaten sonraki adrese kalır."""
    if addrs_left <= 1:
        return None
    return max(0.0, min(ADDRESS_PROBE_TIMEOUT, remaining / addrs_left))
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

    return _H3 if _NATIVE_GOAWAY else _with_goaway_shim(_H3)


def _with_goaway_shim(base: type) -> type:
    """aioquic < 1.8: surface the server GOAWAY that H3Connection drops, with the checks
    aioquic 1.8 performs (RFC 9114 sections 5.2, 7.2.6): a malformed frame is H3_FRAME_ERROR,
    an ID that is not a client bidi stream or that increases is H3_ID_ERROR. aioquic's
    handle_event turns these ProtocolErrors into a connection close."""
    from aioquic.buffer import Buffer, BufferReadError
    from aioquic.h3.connection import ErrorCode, FrameType, ProtocolError

    def _error(code: int, reason: str) -> ProtocolError:
        err = ProtocolError(reason)
        err.error_code = code
        return err

    class _H3GoAway(base):  # type: ignore[valid-type, misc]
        def __init__(self, quic):
            super().__init__(quic)
            self._fh_goaway_id: "Optional[int]" = None
            self._fh_goaway_pending: "list[int]" = []

        def _handle_control_frame(self, frame_type, frame_data):
            super()._handle_control_frame(frame_type, frame_data)   # SETTINGS-first check etc.
            if frame_type != FrameType.GOAWAY or not self._is_client:
                return
            buf = Buffer(data=frame_data)
            try:
                goaway_id = buf.pull_uint_var()
            except BufferReadError:
                raise _error(ErrorCode.H3_FRAME_ERROR, "truncated GOAWAY frame") from None
            if not buf.eof():
                raise _error(ErrorCode.H3_FRAME_ERROR, "GOAWAY frame has trailing bytes")
            if goaway_id % 4 != 0:
                raise _error(ErrorCode.H3_ID_ERROR,
                             "GOAWAY does not carry a client-initiated bidirectional stream ID")
            if self._fh_goaway_id is not None and goaway_id > self._fh_goaway_id:
                raise _error(ErrorCode.H3_ID_ERROR, "GOAWAY increased the ID of a previous GOAWAY")
            self._fh_goaway_id = goaway_id
            self._fh_goaway_pending.append(goaway_id)

        def handle_event(self, event):
            events = super().handle_event(event)
            if self._fh_goaway_pending:
                events = list(events) + [GoAwayReceived(stream_id=i) for i in self._fh_goaway_pending]
                self._fh_goaway_pending.clear()
            return events

    return _H3GoAway


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
        # aioquic yeni istek başlatmayı reddetti (GOAWAY alındı / bağlantı kapanıyor): yeniden kullanılmaz.
        self.draining = False
        self.last_activity = clock()
        self.datagrams_received = 0          # eşten gelen datagram sayısı (adres yoklaması)
        self.on_state_change: "Optional[Callable[[], None]]" = None
        self._addr: "Optional[tuple]" = None

    # -- bağlantı yaşam döngüsü -------------------------------------------------
    def connect(self, addr: tuple) -> None:
        self._addr = addr
        self.quic.connect(addr, now=self.clock())

    @property
    def usable(self) -> bool:
        return self.handshake_done and not self.closed and self.goaway_id is None and not self.draining

    def receive(self, data: bytes, addr: tuple) -> None:
        self.last_activity = self.clock()
        self.datagrams_received += 1
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
        try:
            self.h3.send_headers(sid, hdrs, end_stream=not body)
        except InvalidConnectionStateError as e:
            # aioquic >= 1.9: GOAWAY alınmış (fasthttpc henüz işlememiş olabilir: yarış) ya da
            # bağlantı kapanıyor. İstek akışına hiçbir şey yazılmadan reddedilir, istek HİÇ
            # gönderilmedi: yeni bağlantıda yeniden denemek güvenli (aioquic'in istisnası sızmaz).
            self.draining = True
            raise Http3RequestRefused(f"aioquic isteği başlatmadı: {e}") from e
        self.streams[sid] = st
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
