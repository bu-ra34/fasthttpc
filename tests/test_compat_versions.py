"""
Faz 2 — nginx.org alert 70 analizi regresyon testleri (ağsız).

Bulgu: TLS 1.2-only bir OpenSSL sunucusu, supported_versions yalnızca 0x0304
içerdiğinde ortak sürüm bulamaz ve protocol_version (70) alert'i döner.
Profiller artık gerçek tarayıcılar gibi 0x0303'ü de ilan ediyor; böyle bir
sunucudan TLS 1.2 ServerHello gelirse istemci NET bir hata verir.
"""
import os
import socket
import struct
import threading

import pytest

from fasthttpc.fingerprint import PROFILES, _GREASE_VALUES
from fasthttpc.security.alerts import describe_alert
from fasthttpc.security.tls_adapter import TLSAdapter
from fasthttpc.tls_crafter import TLSImpersonator

from fake_tls_server import parse_client_hello, recv_record


def _versions(profile):
    ch = parse_client_hello(TLSImpersonator("example.com", profile=profile).build_client_hello()[0][5:])
    data = dict(ch["exts"])[0x2B]
    return [struct.unpack("!H", data[1 + i:3 + i])[0] for i in range(0, data[0], 2)]


def test_chrome_supported_versions_like_real_chrome():
    v = _versions("chrome_131")
    assert v[0] in _GREASE_VALUES
    assert v[1:] == [0x0304, 0x0303]


@pytest.mark.parametrize("name", list(PROFILES))
def test_tls13_first_and_no_duplicate_extensions(name):
    v = [x for x in _versions(name) if x not in _GREASE_VALUES]
    assert v[0] == 0x0304
    ch = TLSImpersonator("example.com", profile=name).build_client_hello()[0]
    assert ch[1:3] == b"\x03\x01"            # record legacy_version
    assert ch[9:11] == b"\x03\x03"           # ClientHello legacy_version
    types = [t for t, _ in parse_client_hello(ch[5:])["exts"]]
    assert len(types) == len(set(types)), "tekrarlanan extension tipi (decode_error sebebi)"


def test_describe_alert_70_hint():
    msg = describe_alert(b"\x02\x46")
    assert "protocol_version" in msg and "TLS 1.3" in msg


def _one_shot_server(response):
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)

    def run():
        c, _ = ls.accept()
        _hdr, ch = recv_record(c)
        c.sendall(response(parse_client_hello(ch)) if callable(response) else response)
        try:
            c.recv(10)
        except OSError:
            pass
        c.close()
        ls.close()
    threading.Thread(target=run, daemon=True).start()
    return ls.getsockname()[1]


def _negotiate(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        return TLSAdapter.negotiate(s, "example.com", "chrome_131")
    finally:
        s.close()


def test_alert_70_clear_error():
    port = _one_shot_server(b"\x15\x03\x03\x00\x02\x02\x46")
    with pytest.raises(ConnectionError, match="protocol_version"):
        _negotiate(port)


def _tls12_server_hello(random):
    return lambda ch: _tls12_sh(random, ch["session_id"])


def _tls12_sh(random, sid):
    body = b"\x03\x03" + random + bytes([len(sid)]) + sid + b"\xc0\x2f" + b"\x00" + b"\x00\x05" + b"\xff\x01\x00\x01\x00"
    msg = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(msg)) + msg


def test_tls12_server_hello_clear_error():
    # TLS 1.2 artık güvenli alt küme olarak desteklenir; ama bu sahte ServerHello
    # Extended Master Secret içermediği için NET bir hatayla reddedilir.
    port = _one_shot_server(_tls12_server_hello(os.urandom(32)))
    with pytest.raises(ConnectionError, match="Extended Master Secret"):
        _negotiate(port)


def test_tls12_downgrade_sentinel_detected():
    port = _one_shot_server(_tls12_server_hello(os.urandom(24) + b"DOWNGRD\x01"))
    with pytest.raises(ConnectionError, match="DOWNGRD"):
        _negotiate(port)
