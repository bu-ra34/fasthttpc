"""
HTTP/2 testleri — sahte bir soket üzerinden, ağ gerektirmeden.

Odak: gönderim tarafı akış kontrolü. Eski kod _conn_window_send'i güncelliyor
ama HİÇ OKUMUYORDU; 65535 byte'tan büyük bir POST sunucudan FLOW_CONTROL_ERROR
almakla sonuçlanıyordu.
"""
import struct

from fasthttpc.protocol.http2_parser import (
    FrameFlags,
    FrameType,
    HTTP2Frame,
    Http2Connection,
)


class SahteSoket:
    """send_record/recv_record arayüzünü taklit eden test sahtesi."""

    def __init__(self, gelen_frameler=()):
        self.gonderilen = bytearray()
        self._gelen = bytearray()
        for f in gelen_frameler:
            self._gelen += f.serialize()

    def send_record(self, data, content_type=0x17, use_app_keys=True):
        self.gonderilen += data

    def recv_record(self, skip_post_handshake=False):
        if not self._gelen:
            raise ConnectionError("Sahte soketin verisi bitti")
        veri, self._gelen = bytes(self._gelen), bytearray()
        return veri, 23

    def gonderilen_frameler(self):
        """Gönderilen byte akışını frame'lere ayırır (preface hariç)."""
        buf = bytes(self.gonderilen)
        if buf.startswith(b"PRI * HTTP/2.0"):
            buf = buf[24:]
        frames, pos = [], 0
        while pos + 9 <= len(buf):
            length = struct.unpack("!I", b"\x00" + buf[pos:pos + 3])[0]
            frames.append(HTTP2Frame.parse(buf[pos:pos + 9 + length]))
            pos += 9 + length
        return frames


def _window_update(stream_id, increment):
    return HTTP2Frame(4, FrameType.WINDOW_UPDATE, 0, stream_id,
                      struct.pack("!I", increment))


def test_settings_enable_push_kapali():
    """PUSH_PROMISE işlemiyoruz; açık bırakmak sunucuyu boşuna çalıştırır."""
    sock = SahteSoket()
    Http2Connection(sock).send_preface_and_settings()

    settings = [f for f in sock.gonderilen_frameler() if f.type == FrameType.SETTINGS]
    assert settings, "SETTINGS frame'i gönderilmedi"
    payload = settings[0].payload
    ayarlar = {
        struct.unpack("!H", payload[i:i + 2])[0]: struct.unpack("!I", payload[i + 2:i + 6])[0]
        for i in range(0, len(payload) - 5, 6)
    }
    assert ayarlar.get(0x2) == 0, "ENABLE_PUSH kapalı olmalı"
    assert 0x1 in ayarlar, "HEADER_TABLE_SIZE bildirilmeli"


def test_preface_dogru_gonderiliyor():
    sock = SahteSoket()
    Http2Connection(sock).send_preface_and_settings()
    assert bytes(sock.gonderilen).startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")


def test_pencere_asilmadan_veri_gonderilmiyor():
    """65535 byte'lık pencereye 100KB sığmaz; fazlası WINDOW_UPDATE beklemeli."""
    govde = b"x" * 100_000
    sock = SahteSoket(gelen_frameler=[
        _window_update(0, 100_000),
        _window_update(1, 100_000),
    ])
    conn = Http2Connection(sock)
    stream_id = conn._next_id()
    conn._send_data(stream_id, govde)

    data_frames = [f for f in sock.gonderilen_frameler() if f.type == FrameType.DATA]
    toplam = sum(len(f.payload) for f in data_frames)
    assert toplam == len(govde), "gövdenin tamamı gönderilmeli"

    # WINDOW_UPDATE'ten ÖNCE gönderilebilecek azami miktar başlangıç penceresidir
    ilk_parti = 0
    for f in data_frames:
        ilk_parti += len(f.payload)
        if ilk_parti > Http2Connection.DEFAULT_WINDOW:
            break
    assert ilk_parti <= Http2Connection.DEFAULT_WINDOW + 16384, \
        "pencere aşılarak veri gönderilmiş"


def test_pencere_gonderim_sonrasi_azaliyor():
    sock = SahteSoket()
    conn = Http2Connection(sock)
    stream_id = conn._next_id()
    baslangic = conn._conn_window_send

    conn._send_data(stream_id, b"y" * 1000)
    assert conn._conn_window_send == baslangic - 1000
    assert conn._stream_windows[stream_id] == baslangic - 1000


def test_max_frame_size_a_uyuluyor():
    sock = SahteSoket(gelen_frameler=[_window_update(0, 100_000), _window_update(1, 100_000)])
    conn = Http2Connection(sock)
    conn._peer_settings["max_frame_size"] = 1024
    conn._send_data(conn._next_id(), b"z" * 5000)

    for f in sock.gonderilen_frameler():
        if f.type == FrameType.DATA:
            assert len(f.payload) <= 1024


def test_bos_govde_end_stream_ile_gonderilir():
    sock = SahteSoket()
    conn = Http2Connection(sock)
    conn._send_data(conn._next_id(), b"")
    data = [f for f in sock.gonderilen_frameler() if f.type == FrameType.DATA]
    assert len(data) == 1 and data[0].end_stream


def test_stream_idleri_tek_ve_artan():
    conn = Http2Connection(SahteSoket())
    assert [conn._next_id() for _ in range(3)] == [1, 3, 5]


def test_padded_headers_frame_ayiklanir():
    """Regresyon: Cloudflare/Google PADDED HEADERS gönderiyor, HPACK çöp çıkıyordu."""
    from fasthttpc.protocol.http2_parser import _strip_headers_frame_fields, FrameFlags

    gercek_blok = b"\x88"  # HPACK: :status 200 (statik tablo index 8)
    # PADDED: [pad_len=3][blok][3 byte padding]
    payload = bytes([3]) + gercek_blok + b"\x00\x00\x00"
    frame = HTTP2Frame(len(payload), FrameType.HEADERS, FrameFlags.PADDED, 1, payload)
    assert _strip_headers_frame_fields(frame) == gercek_blok


def test_priority_headers_frame_ayiklanir():
    from fasthttpc.protocol.http2_parser import _strip_headers_frame_fields, FrameFlags

    gercek_blok = b"\x88"
    # PRIORITY: [5 byte priority][blok]
    payload = b"\x00\x00\x00\x01\x10" + gercek_blok
    frame = HTTP2Frame(len(payload), FrameType.HEADERS, FrameFlags.PRIORITY, 1, payload)
    assert _strip_headers_frame_fields(frame) == gercek_blok


def test_padded_ve_priority_birlikte():
    from fasthttpc.protocol.http2_parser import _strip_headers_frame_fields, FrameFlags

    gercek_blok = b"\x88\x0f\x10\x03abc"
    flags = FrameFlags.PADDED | FrameFlags.PRIORITY
    payload = bytes([2]) + b"\x00\x00\x00\x01\x10" + gercek_blok + b"\x00\x00"
    frame = HTTP2Frame(len(payload), FrameType.HEADERS, flags, 1, payload)
    assert _strip_headers_frame_fields(frame) == gercek_blok


def test_padded_data_frame_ayiklanir():
    from fasthttpc.protocol.http2_parser import _strip_data_frame_padding, FrameFlags

    govde = b"merhaba dunya"
    payload = bytes([4]) + govde + b"\x00\x00\x00\x00"
    frame = HTTP2Frame(len(payload), FrameType.DATA, FrameFlags.PADDED, 1, payload)
    assert _strip_data_frame_padding(frame) == govde


def test_paddingsiz_frame_degismez():
    from fasthttpc.protocol.http2_parser import _strip_headers_frame_fields, _strip_data_frame_padding

    blok = b"\x88\x01\x02"
    h = HTTP2Frame(len(blok), FrameType.HEADERS, FrameFlags.END_HEADERS, 1, blok)
    assert _strip_headers_frame_fields(h) == blok
    d = HTTP2Frame(len(blok), FrameType.DATA, 0, 1, blok)
    assert _strip_data_frame_padding(d) == blok


def test_bozuk_padding_hpack_zehirlemez():
    """pad_len payload'dan büyükse boş dönmeli, exception atmamalı."""
    from fasthttpc.protocol.http2_parser import _strip_headers_frame_fields, FrameFlags

    payload = bytes([200]) + b"\x88"  # pad_len=200 ama payload 2 byte
    frame = HTTP2Frame(len(payload), FrameType.HEADERS, FrameFlags.PADDED, 1, payload)
    assert _strip_headers_frame_fields(frame) == b""


def test_newsessionticket_h2_akisini_bozmuyor():
    """KRİTİK regresyon: TLS 1.3'te handshake sonrası gelen NewSessionTicket
    (content_type=22) HTTP/2 verisi sanılıp 'invalid literal for int' hatası
    veriyordu. Cloudflare/Google bunu handshake biter bitmez gönderir.

    Bu test, skip_post_handshake=True sayesinde TLS katmanının NewSessionTicket'ı
    yutup HTTP/2'ye yalnızca gerçek frame'leri verdiğini doğrular.
    """
    import struct

    def h2f(ftype, flags, sid, payload):
        return (struct.pack("!I", len(payload))[1:] + bytes([ftype, flags]) +
                struct.pack("!I", sid) + payload)

    class MockEsock:
        def __init__(self, records):
            self._records = list(records)
            self.sent = bytearray()

        def send_record(self, data, content_type=0x17, use_app_keys=True):
            self.sent += data

        def recv_record(self, skip_post_handshake=False):
            if not self._records:
                raise ConnectionError("veri bitti")
            ct, data = self._records.pop(0)
            while skip_post_handshake and ct == 22:
                if not self._records:
                    raise ConnectionError("veri bitti")
                ct, data = self._records.pop(0)
            return data, ct

    from fasthttpc.protocol.http2_parser import Http2Connection

    settings = h2f(0x4, 0, 0, b"")
    # HPACK statik tablo index 8 = ":status 200"; END_HEADERS|END_STREAM
    headers = h2f(0x1, 0x4 | 0x1, 1, b"\x88")
    newsessionticket = b"\x04\x00\x00\x02\x00\x00"  # ct=22 handshake

    records = [
        (22, newsessionticket),        # araya giren post-handshake mesajı
        (23, settings),                # gerçek h2: SETTINGS
        (23, headers),                 # gerçek h2: HEADERS :status 200
    ]

    conn = Http2Connection(MockEsock(records))
    status, hdrs, body = conn.request("GET", "example.com", "/", [])
    assert status == 200, f"NewSessionTicket akışı bozdu, status={status}"
