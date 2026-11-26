"""Public Suffix List araması (fasthttpc/_psl.py) ve paketlenmiş anlık görüntü.

Ağ gerektirmez: liste pakete gömülüdür, test vektörleri aşağıya kopyalanmıştır.
"""
import gzip
import importlib.util
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from fasthttpc import _psl
from fasthttpc._psl import is_public_suffix, public_suffix, registrable_domain, to_ascii
from fasthttpc.models.urls import URL

ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Resmi test vektörleri: publicsuffix/list tests/test_psl.txt (CC0), commit
# faf981a207f390881e6c3bcc7b9a1d57b8db066f ile aynı gün alındı.
# checkPublicSuffix(girdi, beklenen kayıt edilebilir alan adı) — None: yok.
# "null input" satırı atlandı; "Listed, but non-Internet, TLD" satırları upstream'de
# de yorum satırı. IDN beklenenleri A-label'a çevrilip karşılaştırılır.
# ---------------------------------------------------------------------------
PSL_TEST_VECTORS = [
    # Mixed case.
    ("COM", None),
    ("example.COM", "example.com"),
    ("WwW.example.COM", "example.com"),
    # Leading dot.
    (".com", None),
    (".example", None),
    (".example.com", None),
    (".example.example", None),
    # Unlisted TLD.
    ("example", None),
    ("example.example", "example.example"),
    ("b.example.example", "example.example"),
    ("a.b.example.example", "example.example"),
    # TLD with only 1 rule.
    ("biz", None),
    ("domain.biz", "domain.biz"),
    ("b.domain.biz", "domain.biz"),
    ("a.b.domain.biz", "domain.biz"),
    # TLD with some 2-level rules.
    ("com", None),
    ("example.com", "example.com"),
    ("b.example.com", "example.com"),
    ("a.b.example.com", "example.com"),
    ("uk.com", None),
    ("example.uk.com", "example.uk.com"),
    ("b.example.uk.com", "example.uk.com"),
    ("a.b.example.uk.com", "example.uk.com"),
    ("test.ac", "test.ac"),
    # TLD with only 1 (wildcard) rule.
    ("mm", None),
    ("c.mm", None),
    ("b.c.mm", "b.c.mm"),
    ("a.b.c.mm", "b.c.mm"),
    # More complex TLD.
    ("jp", None),
    ("test.jp", "test.jp"),
    ("www.test.jp", "test.jp"),
    ("ac.jp", None),
    ("test.ac.jp", "test.ac.jp"),
    ("www.test.ac.jp", "test.ac.jp"),
    ("kyoto.jp", None),
    ("test.kyoto.jp", "test.kyoto.jp"),
    ("ide.kyoto.jp", None),
    ("b.ide.kyoto.jp", "b.ide.kyoto.jp"),
    ("a.b.ide.kyoto.jp", "b.ide.kyoto.jp"),
    ("c.kobe.jp", None),
    ("b.c.kobe.jp", "b.c.kobe.jp"),
    ("a.b.c.kobe.jp", "b.c.kobe.jp"),
    ("city.kobe.jp", "city.kobe.jp"),
    ("www.city.kobe.jp", "city.kobe.jp"),
    # TLD with a wildcard rule and exceptions.
    ("ck", None),
    ("test.ck", None),
    ("b.test.ck", "b.test.ck"),
    ("a.b.test.ck", "b.test.ck"),
    ("www.ck", "www.ck"),
    ("www.www.ck", "www.ck"),
    # US K12.
    ("us", None),
    ("test.us", "test.us"),
    ("www.test.us", "test.us"),
    ("ak.us", None),
    ("test.ak.us", "test.ak.us"),
    ("www.test.ak.us", "test.ak.us"),
    ("k12.ak.us", None),
    ("test.k12.ak.us", "test.k12.ak.us"),
    ("www.test.k12.ak.us", "test.k12.ak.us"),
    # IDN labels.
    ("食狮.com.cn", "食狮.com.cn"),
    ("食狮.公司.cn", "食狮.公司.cn"),
    ("www.食狮.公司.cn", "食狮.公司.cn"),
    ("shishi.公司.cn", "shishi.公司.cn"),
    ("公司.cn", None),
    ("食狮.中国", "食狮.中国"),
    ("www.食狮.中国", "食狮.中国"),
    ("shishi.中国", "shishi.中国"),
    ("中国", None),
    # Same as above, but punycoded.
    ("xn--85x722f.com.cn", "xn--85x722f.com.cn"),
    ("xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn"),
    ("www.xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn"),
    ("shishi.xn--55qx5d.cn", "shishi.xn--55qx5d.cn"),
    ("xn--55qx5d.cn", None),
    ("xn--85x722f.xn--fiqs8s", "xn--85x722f.xn--fiqs8s"),
    ("www.xn--85x722f.xn--fiqs8s", "xn--85x722f.xn--fiqs8s"),
    ("shishi.xn--fiqs8s", "shishi.xn--fiqs8s"),
    ("xn--fiqs8s", None),
]


@pytest.mark.parametrize("domain,expected", PSL_TEST_VECTORS)
def test_official_vectors(domain, expected):
    assert registrable_domain(domain) == (to_ascii(expected) if expected else None)


@pytest.mark.parametrize("domain,suffix", [
    ("www.example.co.uk", "co.uk"),
    ("foo.github.io", "github.io"),            # PRIVATE bölümü
    ("my-app.herokuapp.com", "herokuapp.com"),
    ("a.b.test.ck", "test.ck"),                # joker *.ck
    ("www.ck", "ck"),                          # istisna !www.ck
    ("x.www.ck", "ck"),
    ("a.b.c.kobe.jp", "c.kobe.jp"),            # joker *.kobe.jp
    ("www.city.kobe.jp", "kobe.jp"),           # istisna !city.kobe.jp
    ("printer.local", "local"),                # listede yok: varsayılan "*"
    ("example.com.", "com"),                   # sondaki nokta yok sayılır
    ("сайт.пример.рф", "xn--p1ai"),
])
def test_public_suffix(domain, suffix):
    assert public_suffix(domain) == suffix


@pytest.mark.parametrize("domain", [
    "com", "co.uk", "CO.UK", "co.uk.", "github.io", "herokuapp.com", "local",
    "test.ck", "ck", "c.kobe.jp", "рф", "РФ", "xn--p1ai", "公司.cn", "xn--55qx5d.cn",
])
def test_is_public_suffix(domain):
    assert is_public_suffix(domain)


@pytest.mark.parametrize("domain", [
    "example.co.uk", "foo.github.io", "www.ck", "city.kobe.jp", "пример.рф",
    "xn--e1afmkfd.xn--p1ai", "食狮.公司.cn", "",
    ".co.uk", "a..co.uk",                      # geçersiz ad genel sonek sayılmaz
])
def test_is_not_public_suffix(domain):
    assert not is_public_suffix(domain)


@pytest.mark.parametrize("name,ascii_name", [
    ("ПРИМЕР.РФ.", "xn--e1afmkfd.xn--p1ai"),
    ("食狮\u3002公司\uff61cn", "xn--85x722f.xn--55qx5d.cn"),  # IDNA nokta ayırıcıları
    ("WWW.Example.COM", "www.example.com"),
    ("xn--p1ai", "xn--p1ai"),
])
def test_to_ascii(name, ascii_name):
    assert to_ascii(name) == ascii_name


@pytest.mark.parametrize("host", ["пример.рф", "WWW.食狮.公司.cn", "bücher.example"])
def test_to_ascii_matches_url_host(host):
    """Liste ve istek host'u aynı dönüşümden geçmeli (URL stdlib idna codec'ini kullanır)."""
    assert to_ascii(host) == URL(f"https://{host}/").host


def test_parse_raw_list_format():
    rules = _psl.parse(
        "// yorum\n\n"
        "uk\nco.uk   bu kısım kural değil\n"
        "*.ck\n!www.ck\n"
        "рф\n公司.cn\n"
    )
    assert rules.normal == {"uk", "co.uk", "xn--p1ai", "xn--55qx5d.cn"}
    assert rules.wildcard == {"ck"}
    assert rules.exception == {"www.ck"}


# ---------------------------------------------------------------------------
# Yükleme: tembel, süreç başına bir kez, thread-safe
# ---------------------------------------------------------------------------
def test_list_not_loaded_on_import():
    code = ("import fasthttpc, fasthttpc._psl as p; assert p._loaded is None; "
            "p.is_public_suffix('co.uk'); assert p._loaded is not None")
    subprocess.run([sys.executable, "-c", code], check=True, cwd=ROOT)


def test_list_loaded_once_under_concurrency(monkeypatch):
    monkeypatch.setattr(_psl, "_loaded", None)
    calls = []
    real_parse = _psl.parse

    def slow_parse(text):
        calls.append(1)
        time.sleep(0.05)                       # diğer thread'ler kilitte beklesin
        return real_parse(text)

    monkeypatch.setattr(_psl, "parse", slow_parse)
    barrier = threading.Barrier(8)
    results = []

    def worker():
        barrier.wait()
        results.append(is_public_suffix("co.uk"))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert calls == [1]
    assert results == [True] * 8


# ---------------------------------------------------------------------------
# Paketlenmiş anlık görüntü
# ---------------------------------------------------------------------------
def test_packaged_snapshot_metadata():
    text = gzip.decompress((ROOT / "fasthttpc" / _psl.DATA_FILE).read_bytes()).decode("utf-8")
    lines = text.splitlines()
    assert lines[0].startswith("// This Source Code Form is subject to the terms of the Mozilla Public")
    assert any(line.startswith("// VERSION: ") for line in lines)
    assert any(line.startswith("// COMMIT: ") for line in lines)
    assert "// ===BEGIN ICANN DOMAINS===" in lines and "// ===BEGIN PRIVATE DOMAINS===" in lines
    rules = [line for line in lines if line and not line.startswith("//")]
    assert len(rules) > 9000
    assert all(rule.isascii() for rule in rules)      # IDN'ler A-label olarak saklanır


def test_snapshot_is_package_data():
    """Wheel/sdist'e girmezse kurulu pakette her Domain= çerezi hata verirdi."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'"{_psl.DATA_FILE}"' in pyproject
    assert '"LICENSE-PSL"' in pyproject
    assert (ROOT / "LICENSE-PSL").is_file()


# ---------------------------------------------------------------------------
# scripts/update_psl.py (ağsız: küçük, uydurma bir ham liste ile)
# ---------------------------------------------------------------------------
def _update_script():
    spec = importlib.util.spec_from_file_location("update_psl", ROOT / "scripts" / "update_psl.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_RAW = """\
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// VERSION: 2026-01-01_00-00-00_UTC
// COMMIT: 0123456789abcdef0123456789abcdef01234567

// ===BEGIN ICANN DOMAINS===
// uk : https://example.invalid
uk
co.uk
*.ck
!www.ck
рф
{extra}
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
// GitHub
github.io
// ===END PRIVATE DOMAINS===
"""


def test_update_script_builds_snapshot():
    mod = _update_script()
    raw = _RAW.format(extra="公司.cn")
    out = mod.build(raw)
    lines = out.splitlines()
    assert lines[:3] == mod.MPL_NOTICE
    assert "// VERSION: 2026-01-01_00-00-00_UTC" in lines
    assert "// COMMIT: 0123456789abcdef0123456789abcdef01234567" in lines
    assert "// uk : https://example.invalid" not in lines and "// GitHub" not in lines
    assert "xn--p1ai" in lines and "xn--55qx5d.cn" in lines and "*.ck" in lines and "!www.ck" in lines
    assert _psl.parse(out) == _psl.parse(raw)


@pytest.mark.parametrize("extra", ["a.*.uk", "*foo.uk", "!*.uk", "a..uk"])
def test_update_script_rejects_unsupported_rules(extra):
    with pytest.raises(ValueError):
        _update_script().build(_RAW.format(extra=extra))


def test_update_script_requires_both_sections_and_license():
    mod = _update_script()
    raw = _RAW.format(extra="")
    with pytest.raises(ValueError, match="PRIVATE"):
        mod.build(raw.replace("// ===BEGIN PRIVATE DOMAINS===\n", ""))
    with pytest.raises(ValueError, match="MPL"):
        mod.build(raw.split("\n", 3)[3])
