"""Saha testleri için yerel TLS 1.3 HTTP/1.1 sunucusu (ağsız, kendi CA'mızla).

``python -m saha.yerel_sunucu`` ile elle de çalıştırılabilir; testler ve
soak/yük betikleri ``YerelSunucu`` sınıfını kullanır.

Yollar (sorgu parametreleri ``?k=v``):
  /id?i=X          gövde = ``X`` (eşsiz kimlik), başlık X-Id: X; keep-alive
  /big?n=BAYT      n bayt deterministik gövde (Content-Length)
  /chunked?i=X     chunked yanıt (gövde: 3 parça, ``X`` ile biter)
  /gzip, /br       sıkıştırılmış JSON yanıt (Content-Encoding)
  /setcookie?i=X   Set-Cookie: cX=vX (çerez kavanozu yarış testi)
  /sleep?d=SN      SN saniye bekleyip yanıtla
  /drip?n=N&d=SN   N parça, her biri arası SN sn (toplam süre N*SN)
  /cut             Content-Length 1000 vaat edip 10 bayt gönderip kapatır (close_notify'sız)
  /cutn            aynısı, ama temiz TLS kapanışıyla (close_notify)
  /trailer         chunked + trailer, kapanış satırı ayrı TLS kaydında
  /rst             isteği okur, RST ile keser
  /noreply         isteği okur, yanıtsız kapatır (FIN)
  /s204, /s304     gövdesiz, Content-Length'siz yanıt
  /close           ``Connection: close`` ile yanıt
  /http10          HTTP/1.0, Content-Length'siz, kapanışla biten yanıt
  /once            bu bağlantıda ilk istek yanıtlanır, sonra sunucu bağlantıyı kapatır
"""
from __future__ import annotations

import datetime
import gzip
import json
import socket
import ssl
import struct
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

import brotli
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _ad(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def pki_uret(dizin: str, host: str = "localhost") -> tuple[str, str, str]:
    """CA + yaprak sertifika üretir; (ca_pem, cert_pem, key_pem) yollarını döner."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder().subject_name(_ad("Saha Test CA")).issuer_name(_ad("Saha Test CA"))
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder().subject_name(_ad(host)).issuer_name(ca.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=10))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    ca_p, cert_p, key_p = (f"{dizin}/{n}" for n in ("ca.pem", "cert.pem", "key.pem"))
    with open(ca_p, "wb") as f:
        f.write(ca.public_bytes(pem))
    with open(cert_p, "wb") as f:
        f.write(leaf.public_bytes(pem))
    with open(key_p, "wb") as f:
        f.write(key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return ca_p, cert_p, key_p


def govde_uret(n: int) -> bytes:
    """Deterministik n baytlık gövde (sıkıştırılamaz değil ama doğrulanabilir)."""
    blok = bytes(range(256)) * 16
    tam, kalan = divmod(n, len(blok))
    return blok * tam + blok[:kalan]


class YerelSunucu:
    def __init__(self, host: str = "localhost"):
        self.host = host
        self._tmp = tempfile.TemporaryDirectory(prefix="saha-pki-")
        self.ca_path, cert, key = pki_uret(self._tmp.name, host)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ctx.load_cert_chain(cert, key)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(256)
        self.port = self.sock.getsockname()[1]
        self.kabul_edilen_baglanti = 0   # kaç TCP bağlantısı kabul edildi
        self.istek_sayisi = 0
        self.acik_baglanti = 0
        self._kilit = threading.Lock()
        self._dur = False
        self._soketler: set = set()
        threading.Thread(target=self._kabul_dongusu, daemon=True).start()

    @property
    def url(self) -> str:
        return f"https://{self.host}:{self.port}"

    def durdur(self) -> None:
        self._dur = True
        try:
            self.sock.close()
        except OSError:
            pass
        with self._kilit:
            for s in list(self._soketler):
                try:
                    s.close()
                except OSError:
                    pass
        self._tmp.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.durdur()

    # ------------------------------------------------------------------
    def _kabul_dongusu(self) -> None:
        while not self._dur:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._baglanti, args=(raw,), daemon=True).start()

    def _baglanti(self, raw: socket.socket) -> None:
        with self._kilit:
            self.kabul_edilen_baglanti += 1
            self.acik_baglanti += 1
        try:
            raw.settimeout(30)
            try:
                s = self.ctx.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError):
                raw.close()
                return
            with self._kilit:
                self._soketler.add(s)
            try:
                self._istekleri_isle(s)
            finally:
                with self._kilit:
                    self._soketler.discard(s)
                try:
                    s.close()
                except OSError:
                    pass
        finally:
            with self._kilit:
                self.acik_baglanti -= 1

    @staticmethod
    def _istek_oku(s) -> tuple[str, str, dict, bytes] | None:
        tampon = b""
        while b"\r\n\r\n" not in tampon:
            try:
                d = s.recv(65536)
            except (OSError, ssl.SSLError):
                return None
            if not d:
                return None
            tampon += d
        bas, _, geri = tampon.partition(b"\r\n\r\n")
        satirlar = bas.decode("latin-1").split("\r\n")
        metot, hedef, _ = satirlar[0].split(" ", 2)
        basliklar = {}
        for ln in satirlar[1:]:
            k, _, v = ln.partition(":")
            basliklar[k.strip().lower()] = v.strip()
        n = int(basliklar.get("content-length", "0") or 0)
        while len(geri) < n:
            d = s.recv(65536)
            if not d:
                return None
            geri += d
        return metot, hedef, basliklar, geri[:n]

    def _istekleri_isle(self, s) -> None:
        ilk = True
        while not self._dur:
            istek = self._istek_oku(s)
            if istek is None:
                return
            metot, hedef, basliklar, govde = istek
            with self._kilit:
                self.istek_sayisi += 1
            u = urlsplit(hedef)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            try:
                devam = self._yanit(s, metot, u.path, q, basliklar, govde, ilk)
            except (OSError, ssl.SSLError):
                return
            ilk = False
            if not devam:
                return

    @staticmethod
    def _gonder(s, durum: str, basliklar: list[tuple[str, str]], govde: bytes = b"",
                cl: bool = True, surum: str = "HTTP/1.1") -> None:
        h = [f"{surum} {durum}"] + [f"{k}: {v}" for k, v in basliklar]
        if cl:
            h.append(f"Content-Length: {len(govde)}")
        s.sendall(("\r\n".join(h) + "\r\n\r\n").encode("latin-1") + govde)

    def _yanit(self, s, metot, yol, q, basliklar, govde, ilk) -> bool:
        """True → bağlantı açık kalsın."""
        if yol == "/id":
            i = q.get("i", "")
            ek = govde.decode("latin-1") if metot == "POST" else ""
            self._gonder(s, "200 OK", [("X-Id", i), ("Content-Type", "text/plain")],
                         (i + ek).encode())
        elif yol == "/big":
            self._gonder(s, "200 OK", [("Content-Type", "application/octet-stream")],
                         govde_uret(int(q["n"])))
        elif yol == "/chunked":
            i = q.get("i", "x")
            parcalar = [b"parca1-", b"parca2-", i.encode()]
            out = b"".join(b"%x\r\n%s\r\n" % (len(p), p) for p in parcalar) + b"0\r\n\r\n"
            self._gonder(s, "200 OK", [("Transfer-Encoding", "chunked")], out, cl=False)
        elif yol in ("/gzip", "/br"):
            ham = json.dumps({"id": q.get("i", ""), "dolgu": "a" * 5000}).encode()
            if yol == "/gzip":
                z, enc = gzip.compress(ham), "gzip"
            else:
                z, enc = brotli.compress(ham), "br"
            self._gonder(s, "200 OK", [("Content-Encoding", enc), ("Content-Type", "application/json")], z)
        elif yol == "/setcookie":
            i = q.get("i", "")
            self._gonder(s, "200 OK", [("Set-Cookie", f"c{i}=v{i}; Path=/")], i.encode())
        elif yol == "/sleep":
            time.sleep(float(q.get("d", "1")))
            self._gonder(s, "200 OK", [("X-Id", q.get("i", ""))], q.get("i", "").encode())
        elif yol == "/drip":
            n, d = int(q.get("n", "5")), float(q.get("d", "1"))
            s.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {n}\r\n\r\n".encode())
            for _ in range(n):
                time.sleep(d)
                s.sendall(b"x")
        elif yol == "/cut":
            s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n0123456789")
            return False
        elif yol == "/cutn":
            # Eksik gövde + TEMİZ TLS kapanışı (close_notify): sessiz kısaltma tuzağı
            s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n0123456789")
            s.settimeout(0.5)
            try:
                s.unwrap()
            except (OSError, ssl.SSLError):
                pass
            return False
        elif yol == "/trailer":
            # chunked + trailer, kapanış satırı AYRI TLS kaydında gelir
            s.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n")
            time.sleep(0.1)
            s.sendall(b"X-Trailer: 1\r\n")
            time.sleep(0.1)
            s.sendall(b"\r\n")
        elif yol == "/rst":
            # SO_LINGER(1, 0) + close → FIN yerine RST; TLS close_notify gönderilmez.
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            s.close()
            return False
        elif yol == "/noreply":
            return False
        elif yol == "/s204":
            self._gonder(s, "204 No Content", [], cl=False)
        elif yol == "/s304":
            self._gonder(s, "304 Not Modified", [("ETag", '"x"')], cl=False)
        elif yol == "/close":
            self._gonder(s, "200 OK", [("Connection", "close")], b"kapanis")
            return False
        elif yol == "/http10":
            self._gonder(s, "200 OK", [], b"http10-govde", cl=False, surum="HTTP/1.0")
            return False
        elif yol == "/once":
            self._gonder(s, "200 OK", [("X-Id", q.get("i", ""))], q.get("i", "").encode())
            return False
        else:
            self._gonder(s, "404 Not Found", [], b"yok")
        return True


if __name__ == "__main__":
    with YerelSunucu() as sv:
        print(sv.url, sv.ca_path, flush=True)
        while True:
            time.sleep(3600)
