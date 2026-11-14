"""Response: requests/httpx uyumlu alanlar (text property'si hâlâ çağrılabilir)."""
import copy
import pickle

import pytest

from fasthttpc.models.request import Request
from fasthttpc.models.response import HTTPStatusError, Response


def mk(body=b"merhaba", status=200, **h):
    return Response(status, headers=h, body=body)


def test_text_property_str_ve_cagrilabilir():
    r = mk("çay".encode("utf-8"))
    assert isinstance(r.text, str) and r.text == "çay"
    assert r.text() == "çay"                      # eski API
    assert r.text(encoding="latin-1") == "çay".encode("utf-8").decode("latin-1")
    assert r.text("utf-8", "strict") == "çay"
    assert r.text.upper() == "ÇAY" and len(r.text) == 3


def test_text_charset_content_type_den():
    r = mk("çay".encode("latin-1"), **{"Content-Type": 'text/html; charset="ISO-8859-1"'})
    assert r.encoding == "ISO-8859-1" and r.text == "çay" and r.text() == "çay"


def test_text_charset_yoksa_utf8_ve_replace():
    r = mk(b"a\xffb")
    assert r.encoding == "utf-8" and r.text == "a�b"
    with pytest.raises(UnicodeDecodeError):
        r.text("utf-8", "strict")


def test_text_bilinmeyen_charset_utf8e_duser():
    r = mk(b"abc", **{"Content-Type": "text/plain; charset=bogus-9"})
    assert r.text == "abc"


def test_encoding_atanabilir():
    r = mk("çay".encode("latin-1"))
    r.encoding = "latin-1"
    assert r.text == "çay"


def test_text_pickle_copy():
    r = mk(b"xyz")
    t = pickle.loads(pickle.dumps(r.text))
    assert t == "xyz" and t() == "xyz"
    assert copy.deepcopy(r.text)() == "xyz"


def test_json_content_ok_reason_url_elapsed():
    r = mk(b'{"a": 1}', 404)
    assert r.json() == {"a": 1} and r.content == b'{"a": 1}'
    assert r.ok is False and mk(status=399).ok and mk(status=200).ok
    assert r.reason == "Not Found" and mk(status=599).reason == ""
    r.reason = "Yok"
    assert r.reason == "Yok"
    assert r.url == ""
    r.request = Request("GET", "http://x.test/a")
    assert r.url.endswith("x.test/a")
    r.url = "http://son.test/"
    assert r.url == "http://son.test/"
    r.elapsed = 1.5
    assert r.elapsed == 1.5 and r.elapsed.total_seconds() == 1.5
    assert mk().elapsed == 0.0


def test_raise_for_status():
    assert mk().raise_for_status().status_code == 200
    with pytest.raises(HTTPStatusError) as ei:
        mk(status=500).raise_for_status()
    assert ei.value.response.status_code == 500
    mk().close()
