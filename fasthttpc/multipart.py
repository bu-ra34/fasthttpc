"""
fasthttpc — Multipart/form-data Encoder

HTTP POST isteklerinde dosya ve form verisi göndermek için kullanılır.

Örnek::

    from fasthttpc.multipart import encode_multipart

    body, content_type = encode_multipart(
        fields={"username": "bugra"},
        files={"avatar": ("foto.png", b"...png bytes...", "image/png")},
    )
"""

from __future__ import annotations

import os
import uuid
from typing import Dict, Optional, Tuple, Union

                                          
                                                     
FileValue  = Union[bytes, Tuple[str, bytes], Tuple[str, bytes, str]]
FilesParam = Dict[str, FileValue]
FieldsParam = Dict[str, str]


def _boundary() -> str:
    """Rastgele MIME boundary üretir."""
    return "----fasthttpcBoundary" + uuid.uuid4().hex


def encode_multipart(
    fields:  Optional[FieldsParam] = None,
    files:   Optional[FilesParam]  = None,
    boundary: Optional[str]        = None,
) -> Tuple[bytes, str]:
    """
    Multipart/form-data gövdesi oluşturur.

    Args:
        fields:   Düz metin form alanları. ``{"key": "value"}``
        files:    Dosya alanları.
                  Her değer şunlardan biri olabilir:

                  - ``bytes`` — ham dosya içeriği, dosya adı yok
                  - ``("dosya.txt", bytes)`` — dosya adı + içerik
                  - ``("dosya.txt", bytes, "text/plain")`` — dosya adı + içerik + MIME tipi

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

                                                                              
    for name, value in (fields or {}).items():
        parts.append(sep)
        parts.append(
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        )
        parts.append(value.encode() if isinstance(value, str) else value)
        parts.append(b"\r\n")

                                                                               
    for field_name, file_value in (files or {}).items():
        filename: Optional[str] = None
        mime_type = "application/octet-stream"

        if isinstance(file_value, bytes):
            data = file_value
        elif hasattr(file_value, "read"):
                                                  
            data = file_value.read()
        elif isinstance(file_value, tuple):
            if len(file_value) == 2:
                filename, raw = file_value                              
                data = raw.read() if hasattr(raw, "read") else raw
            else:
                filename, raw, mime_type = file_value                      
                data = raw.read() if hasattr(raw, "read") else raw
        else:
            raise TypeError(
                f"files[{field_name!r}] geçersiz tip: {type(file_value)}. "
                "bytes, (filename, bytes) veya (filename, bytes, mime) bekleniyor."
            )

        disp = f'Content-Disposition: form-data; name="{field_name}"'
        if filename:
            disp += f'; filename="{filename}"'
        disp += "\r\n"

        parts.append(sep)
        parts.append(disp.encode())
        parts.append(f"Content-Type: {mime_type}\r\n\r\n".encode())
        parts.append(data)
        parts.append(b"\r\n")

                                                                               
    parts.append(f"--{boundary}--\r\n".encode())

    body = b"".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type
