"""
fasthttpc — Public Suffix List (PSL) araması.

Çerez ``Domain=`` özniteliğinin bir genel sonek (``co.uk``, ``github.io``) olup
olmadığına bakmak için kullanılır (RFC 6265 §5.3 adım 5). Liste pakete gömülü bir
anlık görüntüdür (``public_suffix_list.dat.gz``; Mozilla Public License 2.0, bkz.
``LICENSE-PSL``); çalışma anında ağa çıkılmaz. Dosya ``scripts/update_psl.py`` ile
üretilir: ICANN ve PRIVATE bölümlerinin ikisi de var (tarayıcılar gibi), IDN
etiketleri A-label'a (punycode) çevrilmiş, yorumlar atılmıştır.

Eşleştirme resmi algoritmayı izler
(https://github.com/publicsuffix/list/wiki/Format#algorithm): normal kurallar,
joker (``*.ck``), istisna (``!www.ck``) ve hiçbir kural uymazsa varsayılan ``*``
kuralı. Liste ilk kullanımda süreç başına bir kez (thread-safe) yüklenir; arama
etiket başına bir küme (set) sorgusudur.
"""
from __future__ import annotations

import threading
from importlib import resources
from typing import NamedTuple, Optional

DATA_FILE = "public_suffix_list.dat.gz"

# IDNA'da etiket ayırıcı sayılan noktalar (RFC 3490 §3.1); stdlib "idna" codec'i de
# bunlarla böler, URL host'u ile aynı sonucu vermek için burada da '.' yapılır.
_DOTS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})


class _Rules(NamedTuple):
    normal: frozenset[str]      # "co.uk"
    wildcard: frozenset[str]    # "*.ck"   -> "ck"
    exception: frozenset[str]   # "!www.ck" -> "www.ck"


_lock = threading.Lock()
_loaded: Optional[_Rules] = None


def _label_to_ascii(label: str) -> str:
    if label.isascii():
        return label
    import encodings.idna       # yalnızca IDN'de gerekir; `import fasthttpc` süresine eklenmesin
    try:
        return encodings.idna.ToASCII(label).decode("ascii")
    except UnicodeError:
        # Çevrilemeyen etiket (çok uzun, yasaklı karakter) olduğu gibi kalır;
        # liste ve host tarafı aynı fonksiyondan geçtiği için yine tutarlıdır.
        return label


def to_ascii(name: str) -> str:
    """Alan adını kanonik biçime getirir: küçük harf, sondaki nokta yok, IDN
    etiketleri A-label (``пример.рф`` -> ``xn--e1afmkfd.xn--p1ai``).

    ``URL.host`` ile aynı dönüşüm (stdlib ``idna`` codec'i, etiket etiket);
    hem liste kuralları hem host'lar buradan geçer.
    """
    name = name.lower()
    if not name.isascii():
        name = ".".join(_label_to_ascii(label) for label in name.translate(_DOTS).split("."))
    return name[:-1] if name.endswith(".") else name


def parse(text: str) -> _Rules:
    """PSL biçimindeki metni (ham liste ya da paketlenmiş anlık görüntü) ayrıştırır."""
    normal: set[str] = set()
    wildcard: set[str] = set()
    exception: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        rule = line.split(None, 1)[0]       # kural ilk boşlukta biter
        if rule.startswith("!"):
            exception.add(to_ascii(rule[1:]))
        elif rule.startswith("*."):
            wildcard.add(to_ascii(rule[2:]))
        else:
            normal.add(to_ascii(rule))
    return _Rules(frozenset(normal), frozenset(wildcard), frozenset(exception))


def _read_packaged() -> str:
    import gzip                 # yalnızca ilk yüklemede gerekir
    data = resources.files("fasthttpc").joinpath(DATA_FILE).read_bytes()
    return gzip.decompress(data).decode("utf-8")


def _rules() -> _Rules:
    global _loaded
    rules = _loaded
    if rules is None:
        with _lock:
            rules = _loaded
            if rules is None:
                rules = _loaded = parse(_read_packaged())
    return rules


def _suffix_label_count(labels: list[str], rules: _Rules) -> int:
    """Genel sonekin kaç etiketten oluştuğu (``labels`` kanonik, boş etiket yok)."""
    n = len(labels)
    best = 1                                # varsayılan kural "*"
    suffix = ""
    for k in range(1, n + 1):
        suffix = labels[n - k] if k == 1 else labels[n - k] + "." + suffix
        if suffix in rules.exception:
            # İstisna her zaman kazanır; soldaki etiketi atılmış hali sonektir.
            return k - 1
        if suffix in rules.normal:
            best = k
        if k < n and suffix in rules.wildcard:
            best = k + 1                    # "*.suffix" bir etiket daha tüketir
    return best


def _split(domain: str) -> Optional[list[str]]:
    name = to_ascii(domain)
    labels = name.split(".")
    if not name or "" in labels:
        return None                         # boş ad, baştaki nokta, ".." geçersiz
    return labels


def public_suffix(domain: str) -> Optional[str]:
    """``domain``'in genel soneki (``a.b.example.co.uk`` -> ``co.uk``), A-label
    biçiminde. Geçersiz adda (boş, baştaki nokta, boş etiket) ``None``."""
    labels = _split(domain)
    if labels is None:
        return None
    k = _suffix_label_count(labels, _rules())
    return ".".join(labels[-k:])


def registrable_domain(domain: str) -> Optional[str]:
    """Genel sonek + bir etiket (eTLD+1): ``a.b.example.co.uk`` -> ``example.co.uk``.
    ``domain`` kendisi genel sonekse ya da geçersizse ``None``."""
    labels = _split(domain)
    if labels is None:
        return None
    k = _suffix_label_count(labels, _rules())
    if k >= len(labels):
        return None
    return ".".join(labels[-(k + 1):])


def is_public_suffix(domain: str) -> bool:
    """``domain`` bir genel sonek mi (``co.uk``, ``github.io``, ``com``, listede
    olmayan tek etiketli ``local``)? Geçersiz adda ``False``."""
    labels = _split(domain)
    if labels is None:
        return False
    return _suffix_label_count(labels, _rules()) == len(labels)
