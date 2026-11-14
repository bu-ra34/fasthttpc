"""HTTP/3 (QUIC) desteği — OPSİYONEL: ``pip install 'fasthttpc[http3]'`` (aioquic).

Çekirdek fasthttpc aioquic'siz import edilebilir; bu paketin aioquic gerektiren modülleri
(core, sync_client, async_client) yalnızca HTTP/3 kullanılınca yüklenir.
"""
from .altsvc import AltSvcCache, AltService, parse_alt_svc
from .options import Http3Options


def available() -> bool:
    try:
        import aioquic  # noqa: F401
    except ImportError:
        return False
    return True


__all__ = ["AltSvcCache", "AltService", "Http3Options", "available", "parse_alt_svc"]
