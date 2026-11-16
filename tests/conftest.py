"""Ortak test ayarları.

``trust_env=True`` (varsayılan) oturumlar proxy ve CA bundle ortam değişkenlerini
okur. Testler yerel sahte sunuculara bağlanır; geliştiricinin ya da CI'ın kabuğundaki
``HTTPS_PROXY`` / ``SSL_CERT_FILE`` gibi değişkenler sonuçları değiştirmesin diye her
testten önce temizlenir. Bu değişkenleri sınayan testler ``monkeypatch.setenv`` ile
kendileri kurar. Gerçek internet testleri (``live``) kabuğun ortamını olduğu gibi kullanır.
"""
import pytest

_ENV_VARS = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "REQUEST_METHOD",
    "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE",
)


@pytest.fixture(autouse=True)
def _hermetic_network_env(request, monkeypatch):
    if request.node.get_closest_marker("live") is None:
        for name in _ENV_VARS:
            monkeypatch.delenv(name, raising=False)
    yield
