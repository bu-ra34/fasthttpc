"""
fasthttpc — logging altyapısı.

Kütüphane kodu stdout'a ``print()`` ATMAZ. Bir kütüphanenin çıktısını nereye
yazacağına uygulama karar verir; ``print()`` çağrıları çıktıyı kirletir,
JSON/CSV üreten pipeline'ları bozar ve susturulamaz.

Varsayılan olarak hiçbir şey yazılmaz (NullHandler). Görmek isteyen::

    import logging
    logging.basicConfig(level=logging.DEBUG)

veya sadece bu kütüphane için::

    from fasthttpc import enable_debug_logging
    enable_debug_logging()
"""
from __future__ import annotations

import logging

_ROOT_NAME = "fasthttpc"

logging.getLogger(_ROOT_NAME).addHandler(logging.NullHandler())


def get_logger(name: str) -> logging.Logger:
    """Modül bazlı alt logger döner (örn. ``fasthttpc.session``)."""
    if name.startswith(_ROOT_NAME):
        return logging.getLogger(name)
    return logging.getLogger(f"{_ROOT_NAME}.{name}")


def enable_debug_logging(level: int = logging.DEBUG) -> None:
    """Geliştirme sırasında fasthttpc loglarını stderr'e açar."""
    logger = logging.getLogger(_ROOT_NAME)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(name)s] %(levelname)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)
