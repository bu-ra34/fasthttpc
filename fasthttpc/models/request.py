                             
import json as jsonlib
import os
import uuid
from urllib.parse import urlencode
from .urls import URL
from .headers import Headers


def _build_multipart(files: dict, data: dict | None = None) -> tuple[bytes, str]:
    """
    files: {"field": ("filename", file_obj, "mime/type")}
           veya {"field": file_obj}  (kısa form)
    data:  ek form alanları (text)
    Döner: (body_bytes, content_type_header_value)
    """
    boundary = uuid.uuid4().hex
    parts = bytearray()

                            
    for key, val in (data or {}).items():
        parts += (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{key}"\r\n\r\n'
            f"{val}\r\n"
        ).encode("utf-8")

                    
    for field, spec in files.items():
        if hasattr(spec, "read"):
            filename = getattr(spec, "name", field)
            mime = "application/octet-stream"
            content = spec.read()
        else:
            filename, fileobj, mime = spec
            if hasattr(fileobj, "read"):
                content = fileobj.read()
            else:
                content = fileobj         

        parts += (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field}"; filename="{os.path.basename(filename)}"\r\n'
            f"Content-Type: {mime}\r\n\r\n"
        ).encode("utf-8")
        parts += content
        parts += b"\r\n"

    parts += f"--{boundary}--\r\n".encode("utf-8")
    return bytes(parts), f"multipart/form-data; boundary={boundary}"


class Request:
    def __init__(
        self,
        method: str,
        url: "str | URL",
        data: "dict | bytes | str | None" = None,
        json: "dict | list | None" = None,
        headers: "dict | Headers | None" = None,
        files: "dict | None" = None,
    ):
        self.method = method.upper()
        self.url = url if isinstance(url, URL) else URL(url)
        self.headers = headers if isinstance(headers, Headers) else Headers(headers)
        self.body = b""
        self.timeout = None   # gönderim sırasında etkin Timeout (transport/hook'lar okuyabilir)

        if files is not None:
                                                                  
            body, ct = _build_multipart(files, data if isinstance(data, dict) else None)
            self.body = body
            if "content-type" not in self.headers:
                self.headers["Content-Type"] = ct

        elif json is not None:
            self.body = jsonlib.dumps(json).encode("utf-8")
            if "content-type" not in self.headers:
                self.headers["Content-Type"] = "application/json"

        elif data is not None:
            if isinstance(data, dict):
                self.body = urlencode(data).encode("utf-8")
                if "content-type" not in self.headers:
                    self.headers["Content-Type"] = "application/x-www-form-urlencoded"
            elif isinstance(data, str):
                self.body = data.encode("utf-8")
            elif isinstance(data, bytes):
                self.body = data

        if self.body:
            self.headers["Content-Length"] = str(len(self.body))

    @property
    def content(self) -> bytes:
        """Gövde (httpx uyumu: ``request.content``)."""
        return self.body

    def __repr__(self) -> str:
        return f"<Request [{self.method}] url={self.url}>"
