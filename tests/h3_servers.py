"""Yerel HTTP/3 test düzeneği: kendi CA'mız + aioquic H3 sunucusu (UDP) + isteğe bağlı TCP h1 sunucusu."""
from __future__ import annotations

import asyncio
import datetime
import http.server
import json
import socket
import socketserver
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.buffer import encode_uint_var
from aioquic.h3.connection import FrameType, H3Connection, encode_frame
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca(tmp_path, tag="ca"):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(_name(f"test {tag}")).issuer_name(_name(f"test {tag}"))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    ca_pem = tmp_path / f"{tag}.pem"
    ca_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert, str(ca_pem)


def make_leaf(tmp_path, ca_key, ca_cert, names=("localhost",), tag="leaf"):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(_name(names[0])).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    cf, kf = tmp_path / f"{tag}.crt", tmp_path / f"{tag}.key"
    cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    return str(cf), str(kf)


_REFUSED: "set[str]" = set()     # /refuse-once yolları: yalnız İLK istek GOAWAY ile reddedilir
_HELD: "dict[str, _H3Server]" = {}  # /goaway-hold yolları: yanıtı bekletilen isteğin bağlantısı


class _H3Server(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._http = None
        self._req = {}

    def quic_event_received(self, event):
        if self._http is None:
            self._http = H3Connection(self._quic)
        for ev in self._http.handle_event(event):
            if isinstance(ev, HeadersReceived):
                self._req[ev.stream_id] = {"headers": dict(ev.headers), "body": b""}
            elif isinstance(ev, DataReceived):
                self._req[ev.stream_id]["body"] += ev.data
            else:
                continue
            if getattr(ev, "stream_ended", False):
                self._respond(ev.stream_id)

    def _send_goaway(self, goaway_id):
        """Ham GOAWAY çerçevesi (aioquic sunucu tarafında GOAWAY gönderme API'si sunmuyor)."""
        self._http._quic.send_stream_data(self._http._local_control_stream_id,
                                          encode_frame(FrameType.GOAWAY, encode_uint_var(goaway_id)))

    def _respond(self, sid):
        r = self._req.pop(sid)
        h = r["headers"]
        path = h[b":path"].decode()
        method = h[b":method"].decode()
        extra = []
        if path.startswith("/refuse-once") and path not in _REFUSED:
            # Zarif kapanış: bu isteği İŞLEMEDEN GOAWAY(sid) gönder (yanıt yok).
            _REFUSED.add(path)
            self._send_goaway(sid)
            self.transmit()
            return
        if path.startswith("/goaway-hold="):
            # GOAWAY(id) gönder, yanıtı VERME: istek, test H3TestServer.send_goaway ile aynı
            # bağlantıda bir GOAWAY daha gönderene kadar sürer (istemci yeni istek başlatmadan).
            _HELD[path] = self
            self._send_goaway(int(path.split("=")[1]))
            self.transmit()
            return
        if path.startswith("/goaway"):
            # Yanıtı ver, ardından GOAWAY(id) (varsayılan: sonraki istemci akışı).
            gid = int(path.split("=")[1]) if "=" in path else sid + 4
            self._send_goaway(gid)
        if path.startswith("/big"):
            body = b"x" * int(path.split("=")[1])
        elif path.startswith("/chunks"):
            asyncio.ensure_future(self._chunks(sid))
            return
        else:
            body = json.dumps({"method": method, "path": path, "body": r["body"].decode("latin-1"),
                               "ua": h.get(b"user-agent", b"").decode()}).encode()
        self._http.send_headers(sid, [(b":status", b"200"), (b"content-length", str(len(body)).encode()),
                                      (b"x-proto", b"h3")] + extra)
        self._http.send_data(sid, body, end_stream=True)
        self.transmit()

    async def _chunks(self, sid):
        self._http.send_headers(sid, [(b":status", b"200"), (b"x-proto", b"h3")])
        for i in range(3):
            self._http.send_data(sid, f"part{i};".encode(), end_stream=False)
            self.transmit()
            await asyncio.sleep(0.05)
        self._http.send_data(sid, b"", end_stream=True)
        self.transmit()


class NoFqdnHTTPServer(http.server.ThreadingHTTPServer):
    """ThreadingHTTPServer, ters DNS sorgusu YAPMADAN.

    ``HTTPServer.server_bind()`` ``socket.getfqdn(host)`` çağırır; macOS CI runner'larında
    127.0.0.1 için bu ters sorgu saniyelerce sürüp test sunucusunun başlama süresini
    aşıyordu ("sunucu başlamadı (zaman aşımı)").
    """

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class H3TestServer:
    """UDP'de H3; ``port=0`` -> boş port. ``tcp=True`` aynı numarada TCP h1 (Alt-Svc başlıklı)."""

    def __init__(self, certfile, keyfile, port=0, tcp=False, alt_svc=None, tcp_cert=None):
        self.certfile, self.keyfile, self.port = certfile, keyfile, port
        self.tcp, self.alt_svc = tcp, alt_svc
        self.tcp_cert = tcp_cert or (certfile, keyfile)
        self._ready = threading.Event()
        self._stop = None
        self.tcp_hits = 0

    def start(self):
        self._exc = None
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        ok = self._ready.wait(10)
        if self._exc is not None:           # iş parçacığındaki hatayı testte görünür kıl
            raise RuntimeError(f"H3 test sunucusu başlamadı: {self._exc!r}") from self._exc
        assert ok, "sunucu başlamadı (zaman aşımı)"
        return self

    def _run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        cfg = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
        cfg.load_cert_chain(self.certfile, self.keyfile)

        async def main():
            srv = None
            # Önce UDP; ``tcp=True`` ise aynı numarayı TCP için de bağlamayı dene, olmazsa başka
            # UDP portu seç (TCP/UDP port uzayları ayrıdır ama bir başka sürecin TCP portu
            # dolu olabilir; platforma özgü SO_REUSE* davranışına güvenilmez).
            for _ in range(20):
                srv = await serve("127.0.0.1", self.port, configuration=cfg, create_protocol=_H3Server)
                if self.port == 0 or self.tcp:
                    self.port = srv._transport.get_extra_info("sockname")[1]
                if not self.tcp:
                    break
                try:
                    self._start_tcp()
                    break
                except OSError:
                    srv.close()
                    self.port = 0
            else:
                raise OSError("aynı numarada TCP+UDP portu bulunamadı")
            self._stop = asyncio.Event()
            self._ready.set()
            await self._stop.wait()
            srv.close()
        try:
            loop.run_until_complete(main())
        except BaseException as e:      # noqa: BLE001 - start() yeniden fırlatır
            self._exc = e
            self._ready.set()

    def send_goaway(self, path, goaway_id):
        """``/goaway-hold`` isteği ``path``'i bekleten bağlantıda bir GOAWAY(goaway_id) daha gönder
        (test iş parçacığından; çerçeve sunucunun olay döngüsünde yazılır)."""
        proto = _HELD.pop(path)
        sent = threading.Event()

        def go():
            proto._send_goaway(goaway_id)
            proto.transmit()
            sent.set()
        self._loop.call_soon_threadsafe(go)
        assert sent.wait(5), "GOAWAY gönderilemedi (zaman aşımı)"

    def _start_tcp(self):
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                outer.tcp_hits += 1
                body = b'{"proto":"h1"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Proto", "h1")
                if outer.alt_svc:
                    self.send_header("Alt-Svc", outer.alt_svc.replace("{port}", str(outer.port)))
                self.end_headers()
                self.wfile.write(body)

            do_POST = do_GET

            def log_message(self, *a):
                pass

        httpd = NoFqdnHTTPServer(("127.0.0.1", self.port), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(*self.tcp_cert)
        ctx.set_alpn_protocols(["http/1.1"])
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        self._httpd = httpd
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

    def stop(self):
        if self._stop is not None:
            self._loop.call_soon_threadsafe(self._stop.set)
        if self.tcp:
            self._httpd.shutdown(); self._httpd.server_close()
