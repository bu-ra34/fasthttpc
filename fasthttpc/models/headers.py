                             
from collections.abc import Mapping, MutableMapping
import typing

# HTTP header adları ve değerleri RFC 7230 §3.2.4 gereği ISO-8859-1 (latin-1)
# alfabesindedir, ASCII değil. latin-1, 0-255 arası her byte için bire bir
# (kayıpsız) bir Unicode karşılığa sahiptir; bu yüzden hiçbir zaman
# UnicodeEncodeError/UnicodeDecodeError fırlatmaz. Kullanıcının Accept-Language,
# Cookie, X-* gibi header'lara Türkçe/aksanlı/UTF-8 karakter koyması gayet
# olağan bir senaryodur ve ascii bunu kaldıramaz.
_HDR_ENCODING = "latin-1"


class Headers(MutableMapping[str, str]):
    """
    HTTP Header'ları için case-insensitive, sıralı multi-dict yapısı.
    """
    def __init__(self, headers: typing.Optional[typing.Union[
            "Headers", Mapping[typing.Any, typing.Any], list[typing.Any]]] = None):
                                     
        self._list: list[tuple[bytes, bytes, bytes]] = []
        
        if isinstance(headers, Headers):
            # Kopya: çoklu değerler (Set-Cookie...) ve özgün yazım/sıra korunur.
            self._list = list(headers._list)
        elif isinstance(headers, Mapping):
            # dict dışındaki Mapping'ler de (MappingProxyType, httpx/requests başlık
            # nesneleri...) kabul edilir; eskiden yalnızca dict'e bakıldığı için bunlar
            # SESSİZCE yok sayılıyordu (ör. ``Session(headers=Headers(...))``).
            for k, v in headers.items():
                self[k] = v
        elif isinstance(headers, list):
            for k, v in headers:
                self[k] = v

    def __getitem__(self, key: str) -> str:
        """Key'i bul, varsa tüm değerleri virgülle birleştirip dön."""
        lookup = key.lower().encode(_HDR_ENCODING, errors="ignore")
        values = [v.decode(_HDR_ENCODING, errors="replace") for _, l_key, v in self._list if l_key == lookup]
        if not values:
            raise KeyError(key)
        return ", ".join(values)

    def __setitem__(self, key: str, value: str) -> None:
        """Header'ı ayarlar; aynı isimdeki ÖNCEKİ tüm değerleri siler.

        Çoklu değer korunacaksa :meth:`add` kullanılmalıdır. Set-Cookie gibi
        başlıklar tek bir yanıtta birden çok kez gelir ve ``__setitem__`` ile
        parse edilirse yalnızca sonuncusu hayatta kalır.
        """
        raw_key = key.encode(_HDR_ENCODING, errors="ignore")
        lookup = raw_key.lower()
        val_bytes = str(value).encode(_HDR_ENCODING, errors="replace")

        # Var olan girdinin yerinde güncellenmesi sırayı korur; sondan
        # eklemek header sırasını bozar (bu da bir parmak izi sinyalidir).
        new_list = []
        replaced = False
        for item in self._list:
            if item[1] != lookup:
                new_list.append(item)
            elif not replaced:
                new_list.append((raw_key, lookup, val_bytes))
                replaced = True
        if not replaced:
            new_list.append((raw_key, lookup, val_bytes))
        self._list = new_list

    def add(self, key: str, value: str) -> None:
        """Var olan değerleri silmeden yeni bir header satırı ekler.

        Set-Cookie, Link, Via, Warning gibi tekrar edebilen başlıklar için
        kullanılır (RFC 9110 §5.2).
        """
        raw_key = key.encode(_HDR_ENCODING, errors="ignore")
        self._list.append((
            raw_key,
            raw_key.lower(),
            str(value).encode(_HDR_ENCODING, errors="replace"),
        ))

    def setdefault_header(self, key: str, value: str) -> None:
        """Header yoksa ekler, varsa dokunmaz."""
        if key.lower() not in {k.lower() for k in self}:
            self[key] = value

    def __delitem__(self, key: str) -> None:
        lookup = key.lower().encode(_HDR_ENCODING, errors="ignore")
        new_list = [item for item in self._list if item[1] != lookup]
        if len(new_list) == len(self._list):
            raise KeyError(key)
        self._list = new_list

    def __iter__(self) -> typing.Iterator[str]:
                                
        seen = set()
        for _, l_key, _ in self._list:
            if l_key not in seen:
                seen.add(l_key)
                yield l_key.decode(_HDR_ENCODING, errors="replace")

    def __len__(self) -> int:
        return len(set(l_key for _, l_key, _ in self._list))

    def get_list(self, key: str) -> list[str]:
        """Aynı key'den birden fazla varsa hepsini döndür (örn: Set-Cookie)."""
        lookup = key.lower().encode(_HDR_ENCODING, errors="ignore")
        return [v.decode(_HDR_ENCODING, errors="replace") for _, l_key, v in self._list if l_key == lookup]

    @property
    def raw(self) -> list[tuple[bytes, bytes]]:
        """Transport katmanı için (raw_key, value) formatı."""
        return [(k, v) for k, _, v in self._list]

    def __repr__(self) -> str:
        return f"Headers({dict(self.items())})"
