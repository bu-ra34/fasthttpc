                          
from typing import Any
from urllib.parse import urlparse, urlencode, parse_qs, unquote

class QueryParams:
    """Immutable (değişmez) query parametreleri yönetimi."""
    def __init__(self, query_string: str = ""):
        self._dict = parse_qs(query_string, keep_blank_values=True)

    def set(self, key: str, value: str) -> 'QueryParams':
        new_q = QueryParams()
        new_q._dict = dict(self._dict)
        new_q._dict[key] = [value]
        return new_q

    def __str__(self) -> str:
                                           
        return urlencode(self._dict, doseq=True)

class URL:
    """Immutable URL nesnesi."""

    def __init__(self, url: str):
        parsed = urlparse(url)
        self.scheme = (parsed.scheme or "https").lower()

        if not parsed.hostname:
            raise ValueError(
                f"URL bir host içermiyor: {url!r}. Şema dahil mutlak bir URL bekleniyor "
                f"(örn. 'https://example.com/yol')."
            )

        host = parsed.hostname.lower()
        # Uluslararası alan adları tel üzerinde punycode olmak zorundadır
        # (RFC 5891); 'köşe.com' ham UTF-8 olarak gönderilirse SNI ve Host
        # başlığı geçersiz olur.
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            pass
        self.host = host
        # URL'deki ``user:pass@`` (str(URL)/istek satırına ASLA yazılmaz; auth için).
        self.username = unquote(parsed.username) if parsed.username else ""
        self.password = unquote(parsed.password) if parsed.password else ""

        try:
            self.port = parsed.port or (443 if self.scheme in ("https", "wss") else 80)
        except ValueError as e:
            raise ValueError(f"URL'de geçersiz port: {url!r}") from e

        self.path = parsed.path or "/"
        # Ham query string SAKLANIR. parse_qs -> urlencode turundan geçirmek
        # sorguyu yeniden yazar: '?foo' -> '?foo=' olur, parametre sırası ve
        # tekrar eden anahtarların düzeni değişir, kodlama farklılaşır. İmza
        # doğrulayan API'lerde bu doğrudan 403 demektir.
        self.raw_query = parsed.query
        self.params = QueryParams(parsed.query)

    def copy_with(self, **kwargs: Any) -> 'URL':
        """İstenen parametreleri değiştirerek yeni bir URL nesnesi döner."""
                                        
        new_url = URL.__new__(URL)
        new_url.scheme = kwargs.get("scheme", self.scheme)
        new_url.host = kwargs.get("host", self.host)
        new_url.username = kwargs.get("username", self.username)
        new_url.password = kwargs.get("password", self.password)
        new_url.port = kwargs.get("port", self.port)
        new_url.path = kwargs.get("path", self.path)
        if "params" in kwargs:
            new_url.params = kwargs["params"]
            new_url.raw_query = str(kwargs["params"])
        else:
            new_url.params = self.params
            new_url.raw_query = kwargs.get("raw_query", self.raw_query)
        return new_url

    @property
    def raw_path(self) -> bytes:
        """İstek satırına basılacak (path + query) bytes verisi.

        Query string kullanıcının verdiği hâliyle korunur, yeniden kodlanmaz.
        """
        q = self.raw_query
        full_path = f"{self.path}?{q}" if q else self.path
        # urlencode zaten non-ASCII karakterleri percent-encode eder, bu yüzden
        # normalde ascii yeterlidir; yine de elle set edilmiş/encode edilmemiş
        # bir path gelirse (örn. copy_with ile) patlamaması için latin-1 fallback.
        try:
            return full_path.encode("ascii")
        except UnicodeEncodeError:
            return full_path.encode("utf-8")

    @property
    def origin(self) -> tuple[str, str, int]:
        return (self.scheme, self.host, self.port)

    def __str__(self) -> str:
        default = 443 if self.scheme in ("https", "wss") else 80
        netloc = self.host if self.port == default else f"{self.host}:{self.port}"
        q = f"?{self.raw_query}" if self.raw_query else ""
        return f"{self.scheme}://{netloc}{self.path}{q}"

    def __repr__(self) -> str:
        return f"URL({self})"
