"""Windows'ta `openssl s_server` metin kipi okumasına dayanıklı test verisi (Linux'ta benzetimle)."""
import test_interop_openssl as io


def _crt_metin_okuma(data: bytes) -> bytes:
    """Windows C çalışma zamanı metin kipi: CR+LF -> LF ve 0x1A'da EOF."""
    i = data.find(b"\x1a")
    if i != -1:
        data = data[:i]
    return data.replace(b"\r\n", b"\n")


def test_win32_yuku_metin_kipinde_degismez(monkeypatch):
    monkeypatch.setattr(io.sys, "platform", "win32")
    big = io._big_payload(3 * 1024 * 1024 + 17)
    assert len(big) == 3 * 1024 * 1024 + 17
    assert _crt_metin_okuma(big) == big          # 0x1A / CRLF yok -> aynen
    assert len(set(big)) == 62                   # hâlâ rastgele (alfasayısal alfabenin tamamı)


def test_win32_baslik_crlf_metin_kipinde_korunur(monkeypatch):
    head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
    monkeypatch.setattr(io.sys, "platform", "win32")
    assert _crt_metin_okuma(io.text_mode_crlf(head)) == head
    monkeypatch.setattr(io.sys, "platform", "linux")
    assert io.text_mode_crlf(head) == head
