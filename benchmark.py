"""
fasthttpc performans ölçümleri.

Kullanım:
    python3 benchmark.py                 # yalnızca ağsız mikro-benchmark'lar
    python3 benchmark.py --network       # + gerçek ağ senaryoları
    python3 benchmark.py --network --url https://example.com --big-url https://.../10MB.bin

Ağsız (yerel) bölümler:
  M1) Record katmanı throughput'u: EncryptedSocket.recv_record / send_record
      (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) — eski yol (bytes += + her
      record'da yeni AEAD nesnesi) ile yeni yol (bytearray+ofset + AEAD önbelleği).
  M2) CA güven deposu yükleme: soğuk (her handshake'te yeniden kurulum, eski
      davranış) vs önbellekli.
  M3) 127.0.0.1 üzerinde yerel OpenSSL TLS 1.3 sunucusuna tam handshake vs PSK
      resumption (session_tickets).

Ağ bölümleri (--network): soğuk handshake, sıcak bağlantı, büyük indirme,
paralel istekler. requests / httpx / curl_cffi kuruluysa onlarla karşılaştırılır,
kurulu değilse atlanır.
"""
from __future__ import annotations

import argparse
import os
import socket
import statistics
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

os.environ.setdefault("CRYPTOGRAPHY_OPENSSL_NO_LEGACY", "1")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def header(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def _best(fn, repeat: int = 5) -> float:
    """fn'i `repeat` kez çalıştırıp en iyi süreyi (saniye) döner."""
    best = float("inf")
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    return best


# ---------------------------------------------------------------------------
# M1) Record katmanı
# ---------------------------------------------------------------------------
class _ReplaySock:
    def __init__(self, data: bytes):
        self.data = memoryview(data)
        self.pos = 0
        self.sent = 0

    def recv(self, n):
        out = self.data[self.pos:self.pos + n].tobytes()
        self.pos += len(out)
        return out

    def sendall(self, b):
        self.sent += len(b)


def _nonce(iv, seq):
    return bytes(a ^ b for a, b in zip(iv, b"\x00" * 4 + seq.to_bytes(8, "big")))


def _make_legacy_socket_cls():
    """v0.2.4 davranışını taklit eden EncryptedSocket alt sınıfı: yalnızca faz4'ün
    değiştirdiği iki parça (okuma tamponu + AEAD nesnesi) eski haline döndürülür,
    şifre çözme/padding/seq mantığı ortaktır — böylece fark yalnızca bu iki değişikliği ölçer."""
    from fasthttpc.crypto_math import FastAESGCM, FastChaCha20Poly1305
    from fasthttpc.security.tls_adapter import EncryptedSocket

    class LegacyEncryptedSocket(EncryptedSocket):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._legacy_buf = b""

        def _cipher(self, key):  # her record'da yeni AEAD nesnesi
            if self.state["cipher_name"].startswith("AES"):
                return FastAESGCM(key), True
            return FastChaCha20Poly1305(key), False

        def _read_raw_record(self):  # bytes += ve dilimleme
            while len(self._legacy_buf) < 5:
                self._legacy_buf += self.raw_socket.recv(16384)
            hdr = self._legacy_buf[:5]
            rec_len = struct.unpack("!H", hdr[3:5])[0]
            while len(self._legacy_buf) < 5 + rec_len:
                self._legacy_buf += self.raw_socket.recv(16384)
            payload = self._legacy_buf[5:5 + rec_len]
            self._legacy_buf = self._legacy_buf[5 + rec_len:]
            return hdr[0], hdr, payload

    return LegacyEncryptedSocket


def bench_record_layer(total_mb: int = 16, record_size: int = 16000) -> dict:
    header(f"M1) Record katmanı throughput ({total_mb} MB, {record_size} B/record)")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from fasthttpc.security.tls_adapter import EncryptedSocket

    Legacy = _make_legacy_socket_cls()
    results = {}
    n = total_mb * 1024 * 1024 // record_size
    for label, name, klen, cls in (
        ("AES-128-GCM", "AES", 16, AESGCM),
        ("AES-256-GCM", "AES", 32, AESGCM),
        ("ChaCha20-Poly1305", "CHACHA20-POLY1305", 32, ChaCha20Poly1305),
    ):
        key, iv = os.urandom(klen), os.urandom(12)
        aead = cls(key)
        plain = os.urandom(record_size) + b"\x17"
        parts = []
        for seq in range(n):
            h = struct.pack("!BHH", 0x17, 0x0303, len(plain) + 16)
            parts.append(h + aead.encrypt(_nonce(iv, seq), plain, h))
        wire = b"".join(parts)

        def mkstate():
            return {"is_tls13": True, "using_app_keys": True, "cipher_name": name,
                    "app_server_write_key": key, "app_server_write_iv": iv,
                    "app_client_write_key": key, "app_client_write_iv": iv,
                    "app_server_seq_num": 0, "app_client_seq_num": 0}

        def new_path():
            es = EncryptedSocket(_ReplaySock(wire), mkstate())
            for _ in range(n):
                es.recv_record()

        def old_path():
            es = Legacy(_ReplaySock(wire), mkstate())
            for _ in range(n):
                es.recv_record()

        def send_path():
            es = EncryptedSocket(_ReplaySock(b""), mkstate())
            payload = plain[:-1]
            for _ in range(n):
                es.send_record(payload)

        mb = n * record_size / 1e6
        t_new, t_old, t_send = _best(new_path, 3), _best(old_path, 3), _best(send_path, 3)
        results[label] = (mb / t_old, mb / t_new, mb / t_send)
        print(f"  {label:18s} çözme eski: {mb / t_old:8.1f} MB/s   yeni: {mb / t_new:8.1f} MB/s"
              f"   ({t_old / t_new:4.2f}x)   şifreleme yeni: {mb / t_send:8.1f} MB/s")
    return results


# ---------------------------------------------------------------------------
# M2) CA güven deposu
# ---------------------------------------------------------------------------
def bench_trust_store() -> tuple[float, float]:
    header("M2) CA güven deposu yükleme (certifi + sistem bundle)")
    from fasthttpc.security import cert_validator as cv

    def cold():
        cv.clear_trust_store_cache()
        cv.load_trust_store()

    t_cold = _best(cold, 5)
    cv.load_trust_store()
    t_warm = _best(cv.load_trust_store, 200)
    print(f"  soğuk (eski davranış: her handshake) : {t_cold * 1000:8.2f} ms")
    print(f"  önbellekli                            : {t_warm * 1e6:8.2f} µs   ({t_cold / t_warm:,.0f}x)")
    return t_cold, t_warm


# ---------------------------------------------------------------------------
# M3) Yerel TLS 1.3 handshake: tam vs PSK resumption
# ---------------------------------------------------------------------------
def _local_tls_server(tmpdir):
    import datetime
    import ssl
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(name("Bench CA")).issuer_name(name("Bench CA"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(name("localhost")).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_path = os.path.join(tmpdir, "ca.pem")
    cert_path = os.path.join(tmpdir, "leaf.pem")
    key_path = os.path.join(tmpdir, "leaf.key")
    open(ca_path, "wb").write(ca.public_bytes(serialization.Encoding.PEM))
    open(cert_path, "wb").write(leaf.public_bytes(serialization.Encoding.PEM))
    open(key_path, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert_path, key_path)
    ctx.num_tickets = 2
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(64)
    stop = threading.Event()

    def serve():
        lsock.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = lsock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                c.settimeout(5)
                s = ctx.wrap_socket(c, server_side=True)
                s.sendall(b"ok:" + s.recv(64))
                s.close()
            except Exception:
                c.close()

    threading.Thread(target=serve, daemon=True).start()
    return lsock.getsockname()[1], ca_path, stop, lsock


def bench_local_handshake(n: int = 30) -> dict:
    header(f"M3) Yerel TLS 1.3 handshake (127.0.0.1, OpenSSL sunucu, {n} tekrar)")
    import tempfile
    from fasthttpc.security import session_tickets, tls_adapter
    from fasthttpc.security.cert_validator import validate_server_certificate

    out = {}
    with tempfile.TemporaryDirectory() as d:
        port, ca_path, stop, lsock = _local_tls_server(d)
        orig = tls_adapter.validate_server_certificate
        tls_adapter.validate_server_certificate = (
            lambda p, h, *a, **k: validate_server_certificate(p, h, ca_path=ca_path))
        try:
            def one():
                raw = socket.create_connection(("127.0.0.1", port), timeout=5)
                t0 = time.perf_counter()
                es = tls_adapter.TLSAdapter.negotiate(raw, "localhost", "chrome_131")
                dt = time.perf_counter() - t0
                es.send_record(b"x")
                es.recv_record(skip_post_handshake=True)  # biletleri de tüketir
                raw.close()
                return dt, bool(es.state.get("resumed"))

            for label, on in (("tam handshake", False), ("PSK resumption", True)):
                session_tickets.enable_resumption(on)
                session_tickets.default_cache.clear()
                one()  # ısınma / ilk bilet
                times, resumed = [], 0
                for _ in range(n):
                    dt, r = one()
                    times.append(dt)
                    resumed += r
                med = statistics.median(times)
                out[label] = med
                print(f"  {label:16s}: medyan {med * 1000:7.2f} ms  (resumed {resumed}/{n})")
        finally:
            tls_adapter.validate_server_certificate = orig
            session_tickets.enable_resumption(False)
            session_tickets.default_cache.clear()
            stop.set()
            lsock.close()
    return out


# ---------------------------------------------------------------------------
# Ağ senaryoları
# ---------------------------------------------------------------------------
def _clients(timeout: float):
    """(ad, fabrika) listesi. Fabrika: get(url)->(status, nbytes) ve close() içeren nesne."""
    out = []

    class _Fast:
        def __init__(self):
            from fasthttpc.session import Session
            self.s = Session(impersonate="chrome_131", timeout=timeout)

        def get(self, url):
            r = self.s.get(url)
            return r.status_code, len(r.content if hasattr(r, "content") else r.body)

        def close(self):
            self.s.close()

    out.append(("fasthttpc", _Fast))

    try:
        import requests

        class _Req:
            def __init__(self):
                self.s = requests.Session()

            def get(self, url):
                r = self.s.get(url, timeout=timeout)
                return r.status_code, len(r.content)

            def close(self):
                self.s.close()

        out.append(("requests", _Req))
    except ImportError:
        print("  [atla] requests kurulu değil")

    try:
        import httpx

        class _Hx:
            def __init__(self):
                self.c = httpx.Client(timeout=timeout, http2=_has_h2())

            def get(self, url):
                r = self.c.get(url)
                return r.status_code, len(r.content)

            def close(self):
                self.c.close()

        out.append(("httpx", _Hx))
    except ImportError:
        print("  [atla] httpx kurulu değil")

    try:
        from curl_cffi import requests as cr

        class _Cc:
            def __init__(self):
                self.s = cr.Session(impersonate="chrome")

            def get(self, url):
                r = self.s.get(url, timeout=timeout)
                return r.status_code, len(r.content)

            def close(self):
                self.s.close()

        out.append(("curl_cffi", _Cc))
    except ImportError:
        print("  [atla] curl_cffi kurulu değil")
    return out


def _has_h2() -> bool:
    try:
        import h2  # noqa: F401
        return True
    except ImportError:
        return False


def bench_network(url: str, big_url: str | None, n: int, parallel: int, timeout: float) -> None:
    clients = _clients(timeout)

    header(f"N1) Soğuk handshake (her istekte yeni oturum) — {n}x GET {url}")
    for name, cls in clients:
        times = []
        for _ in range(n):
            t0 = time.perf_counter()
            try:
                c = cls()
                c.get(url)
                c.close()
                times.append(time.perf_counter() - t0)
            except Exception as e:
                print(f"  {name:10s}: HATA {type(e).__name__}: {e}")
                break
        if times:
            print(f"  {name:10s}: medyan {statistics.median(times) * 1000:8.1f} ms")

    header(f"N2) Sıcak bağlantı (tek oturum, yeniden kullanım) — {n}x GET {url}")
    for name, cls in clients:
        try:
            c = cls()
            c.get(url)
            times = []
            for _ in range(n):
                t0 = time.perf_counter()
                c.get(url)
                times.append(time.perf_counter() - t0)
            c.close()
            print(f"  {name:10s}: medyan {statistics.median(times) * 1000:8.1f} ms")
        except Exception as e:
            print(f"  {name:10s}: HATA {type(e).__name__}: {e}")

    if big_url:
        header(f"N3) Büyük indirme — {big_url}")
        for name, cls in clients:
            try:
                c = cls()
                t0 = time.perf_counter()
                _st, nbytes = c.get(big_url)
                dt = time.perf_counter() - t0
                c.close()
                print(f"  {name:10s}: {nbytes / 1e6:7.1f} MB  {dt:6.2f} s  {nbytes / 1e6 / dt:7.1f} MB/s")
            except Exception as e:
                print(f"  {name:10s}: HATA {type(e).__name__}: {e}")
    else:
        print("\n  [atla] N3 büyük indirme: --big-url verilmedi")

    header(f"N4) Paralel istekler — {parallel} iş parçacığı x {n} istek")
    for name, cls in clients:
        try:
            c = cls()
            c.get(url)
            t0 = time.perf_counter()
            with ThreadPoolExecutor(parallel) as ex:
                list(ex.map(lambda _: c.get(url), range(n)))
            dt = time.perf_counter() - t0
            c.close()
            print(f"  {name:10s}: toplam {dt:6.2f} s  ({n / dt:6.1f} istek/s)")
        except Exception as e:
            print(f"  {name:10s}: HATA {type(e).__name__}: {e}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--network", action="store_true", help="gerçek ağ senaryolarını da çalıştır")
    ap.add_argument("--url", default="https://www.google.com/")
    ap.add_argument("--big-url", default=None)
    ap.add_argument("-n", type=int, default=10)
    ap.add_argument("--parallel", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--mb", type=int, default=16, help="M1 için veri miktarı (MB)")
    ap.add_argument("--skip-local-tls", action="store_true")
    args = ap.parse_args(argv)

    bench_record_layer(args.mb)
    bench_trust_store()
    if not args.skip_local_tls:
        bench_local_handshake()
    if args.network:
        bench_network(args.url, args.big_url, args.n, args.parallel, args.timeout)
    else:
        print("\n(ağ senaryoları için --network)")


if __name__ == "__main__":
    main()
