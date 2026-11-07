"""
fasthttpc — Timeout (geriye dönük uyumluluk modülü).

Asıl tanım :mod:`fasthttpc.config` içindedir; ``from fasthttpc.timeout import
Timeout`` eskisi gibi çalışmaya devam eder. Yeni alanlar: ``write`` ve ``pool``.
"""
from .config import Timeout

__all__ = ["Timeout"]
