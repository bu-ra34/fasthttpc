"""
fasthttpc — Multipart/form-data Encoder

HTTP POST isteklerinde dosya ve form verisi göndermek için kullanılır.

Örnek::

    from fasthttpc.multipart import encode_multipart

    body, content_type = encode_multipart(
        fields={"username": "bugra"},
        files={"avatar": ("foto.png", b"...png bytes...", "image/png")},
    )

Dosya nesnelerinin içeriği (mevcut konumdan sonuna kadar) okunup gövdeye BELLEKTE
eklenir; metin kipindeki dosya/``str`` içerik UTF-8 kodlanır.
"""

from __future__ import annotations

import os
import uuid
from typing import Any, Iterable, Mapping, Optional, Tuple, Union

# İçerik: bytes-benzeri, str (UTF-8) ya da dosya benzeri nesne (.read()).
FileContent = Any
FileValue = Union[
    FileContent,
    Tuple[Optional[str], FileContent],
    Tuple[Optional[str], FileContent, str],
    Tuple[Optional[str], FileContent, str, Mapping[str, str]],
]
FilesParam = Union[Mapping[str, FileValue], Iterable[Tuple[str, FileValue]]]
FieldsParam = Union[Mapping[str, Any], Iterable[Tuple[str, Any]]]


def _boundary() -> str:
    """Rastgele MIME boundary üretir."""
    return "----fasthttpcBoundary" + uuid.uuid4().hex


def _quote(value: str) -> str:
    """Content-Disposition parametre değeri (HTML5 / urllib3 gibi): ``"``, CR, LF kaçışlanır."""
    return value.replace('"', "%22").replace("\r", "%0D").replace("\n", "%0A")


def _bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    return str(value).encode("utf-8")


def _content(field: str, raw: Any) -> bytes:
    """Dosya içeriği: dosya nesnesi okunur (str -> UTF-8); bytes-benzeri / str olduğu gibi."""
    if hasattr(raw, "read"):
        data = raw.read()
        if isinstance(data, str):
            return data.encode("utf-8")
        if isinstance(data, (bytes, bytearray, memoryview)):
            return bytes(data)
        raise TypeError(f"files[{field!r}]: read() bytes ya da str döndürmeli, "
                        f"{type(data).__name__} döndü.")
    if isinstance(raw, (bytes, bytearray, memoryview, str)):
        return _bytes(raw)
    raise TypeError(
        f"files[{field!r}] içeriği geçersiz tip: {type(raw).__name__}. bytes, str ya da "
        "dosya nesnesi bekleniyor.")


def _pairs(items: Any) -> "list[tuple[Any, Any]]":
    return list(items.items()) if hasattr(items, "items") else list(items)


def encode_multipart(
    fields:  Optional[FieldsParam] = None,
    files:   Optional[FilesParam]  = None,
    boundary: Optional[str]        = None,
) -> Tuple[bytes, str]:
    """
    Multipart/form-data gövdesi oluşturur.

    Args:
        fields:   Düz metin form alanları: ``{"key": "value"}`` ya da ``[(key, value), ...]``.
                  Liste/demet değer aynı adla birden çok alan üretir; str dışı değerler
                  ``str()`` ile yazılır, bytes olduğu gibi.
        files:    Dosya alanları (sözlük ya da ``[(alan, değer), ...]``; aynı alanda birden
                  çok dosya için liste). Her değer şunlardan biri olabilir:

                  - ``bytes`` / ``str`` — ham dosya içeriği, dosya adı yok
                  - dosya nesnesi — içeriği okunur; dosya adı ``name``'in son bileşeni,
                    yoksa alan adı (requests gibi)
                  - ``("dosya.txt", içerik)`` — dosya adı + içerik (bytes, str ya da dosya)
                  - ``("dosya.txt", içerik, "text/plain")`` — + MIME tipi
                  - ``("dosya.txt", içerik, "text/plain", {"X-Baslik": "..."})`` — + ek başlıklar

                  Dosya adı ``None`` ise bölüm dosya adısız (düz alan) gönderilir.

        boundary: Özel boundary string (testler için). Verilmezse rastgele üretilir.

    Returns:
        ``(body_bytes, content_type_header)`` çifti.
        ``content_type_header`` doğrudan ``Content-Type`` başlığına atanabilir.

    Örnek::

        body, ct = encode_multipart(
            fields={"not": "deneme"},
            files={"dosya": ("belge.pdf", pdf_bytes, "application/pdf")},
        )
        headers = {"Content-Type": ct}
    """
    if boundary is None:
        boundary = _boundary()

    parts: list[bytes] = []
    sep = f"--{boundary}\r\n".encode()

    for name, value in _pairs(fields or {}):
        for v in (value if isinstance(value, (list, tuple)) else (value,)):
            parts.append(sep)
            parts.append(
                f'Content-Disposition: form-data; name="{_quote(str(name))}"\r\n\r\n'.encode()
            )
            parts.append(_bytes(v))
            parts.append(b"\r\n")

    for field_name, file_value in _pairs(files or {}):
        field_name = str(field_name)
        filename: Optional[str] = None
        mime_type = "application/octet-stream"
        extra: Mapping[str, str] = {}

        if isinstance(file_value, tuple):
            if not 2 <= len(file_value) <= 4:
                raise TypeError(
                    f"files[{field_name!r}] demeti 2-4 öğeli olmalı: (dosya_adı, içerik[, mime"
                    f"[, başlıklar]]); {len(file_value)} öğe geldi.")
            filename, raw = file_value[0], file_value[1]
            if len(file_value) >= 3 and file_value[2]:
                mime_type = file_value[2]
            if len(file_value) == 4 and file_value[3]:
                extra = file_value[3]
            data = _content(field_name, raw)
        elif hasattr(file_value, "read"):
            name = getattr(file_value, "name", None)
            filename = os.path.basename(name) if isinstance(name, str) and name else field_name
            data = _content(field_name, file_value)
        elif isinstance(file_value, (bytes, bytearray, memoryview, str)):
            data = _bytes(file_value)
        else:
            raise TypeError(
                f"files[{field_name!r}] geçersiz tip: {type(file_value)}. bytes, str, dosya "
                "nesnesi, (filename, içerik), (filename, içerik, mime) veya "
                "(filename, içerik, mime, başlıklar) bekleniyor."
            )

        disp = f'Content-Disposition: form-data; name="{_quote(field_name)}"'
        if filename:
            disp += f'; filename="{_quote(str(filename))}"'
        disp += "\r\n"

        parts.append(sep)
        parts.append(disp.encode())
        parts.append(f"Content-Type: {mime_type}\r\n".encode())
        for hk, hv in extra.items():
            parts.append(f"{hk}: {hv}\r\n".encode())
        parts.append(b"\r\n")
        parts.append(data)
        parts.append(b"\r\n")

    parts.append(f"--{boundary}--\r\n".encode())

    body = b"".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type
