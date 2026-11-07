"""Redirect Location çözümleme testleri (RFC 9110 §10.2.2)."""
import pytest

from fasthttpc.models.urls import URL
from fasthttpc.session import _resolve_location


BASE = URL("https://a.com/dizin/sayfa.html?q=1")


@pytest.mark.parametrize("location,beklenen", [
    ("https://b.com/z",     "https://b.com/z"),        # mutlak
    ("http://b.com/z",      "http://b.com/z"),         # şema değişimi
    ("//cdn.com/z",         "https://cdn.com/z"),      # protokol-göreli
    ("/kok",                "https://a.com/kok"),      # kökten
    ("komsu.html",          "https://a.com/dizin/komsu.html"),  # göreli
])
def test_location_cozumleme(location, beklenen):
    assert _resolve_location(BASE, location) == beklenen


def test_varsayilan_disi_port_korunur():
    base = URL("https://a.com:8443/x/y")
    assert _resolve_location(base, "/z") == "https://a.com:8443/z"


def test_bosluklar_kirpilir():
    assert _resolve_location(BASE, "  /z  ") == "https://a.com/z"


def test_protokol_goreli_semayi_tabandan_alir():
    assert _resolve_location(URL("http://a.com/x"), "//b.com/y") == "http://b.com/y"
