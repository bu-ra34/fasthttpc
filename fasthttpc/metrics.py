"""
FAZ 1 — Per-request metrik objesi (resp.metrics)
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class RequestMetrics:
    """
    Tek bir HTTP isteğinin zaman ve boyut ölçümlerini tutar.
    resp.metrics ile erişilir.

    Zaman damgaları: monotonic (float, saniye)
    """
                     
    request_start:     float = 0.0                      
    connect_start:     float = 0.0                         
    connect_end:       float = 0.0                 
    tls_start:         float = 0.0                          
    tls_end:           float = 0.0                   
    first_byte_time:   float = 0.0                                     
    transfer_end:      float = 0.0                    
    total_end:         float = 0.0                        

              
    bytes_sent:        int   = 0
    bytes_received:    int   = 0

                      
    connection_reused: bool  = False
    redirect_count:    int   = 0

                                                                              

    @property
    def dns_time(self) -> float:
        """DNS çözümleme süresi (şimdilik 0 — DoH fazında doldurulacak)."""
        return 0.0

    @property
    def connect_time(self) -> float:
        """TCP bağlantı süresi (ms)."""
        if self.connect_end and self.connect_start:
            return (self.connect_end - self.connect_start) * 1000
        return 0.0

    @property
    def tls_time(self) -> float:
        """TLS handshake süresi (ms)."""
        if self.tls_end and self.tls_start:
            return (self.tls_end - self.tls_start) * 1000
        return 0.0

    @property
    def ttfb(self) -> float:
        """Time to First Byte — istek gönderildikten sonra ilk byte'a kadar (ms)."""
        if self.first_byte_time and self.request_start:
            return (self.first_byte_time - self.request_start) * 1000
        return 0.0

    @property
    def transfer_time(self) -> float:
        """Body transferi süresi (ms)."""
        if self.transfer_end and self.first_byte_time:
            return (self.transfer_end - self.first_byte_time) * 1000
        return 0.0

    @property
    def total_time(self) -> float:
        """Toplam istek süresi (ms)."""
        if self.total_end and self.request_start:
            return (self.total_end - self.request_start) * 1000
        return 0.0

    @property
    def throughput_mbps(self) -> float:
        """Transfer hızı (Mbps). 0 ise hesaplanamadı."""
        t = self.transfer_time / 1000                  
        if t > 0 and self.bytes_received > 0:
            return (self.bytes_received * 8) / (t * 1_000_000)
        return 0.0

    def __repr__(self) -> str:
        return (
            f"<RequestMetrics "
            f"total={self.total_time:.1f}ms "
            f"ttfb={self.ttfb:.1f}ms "
            f"tls={self.tls_time:.1f}ms "
            f"reused={self.connection_reused} "
            f"rx={self.bytes_received}B>"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_ms":         round(self.total_time, 2),
            "ttfb_ms":          round(self.ttfb, 2),
            "connect_ms":       round(self.connect_time, 2),
            "tls_ms":           round(self.tls_time, 2),
            "transfer_ms":      round(self.transfer_time, 2),
            "throughput_mbps":  round(self.throughput_mbps, 3),
            "bytes_sent":       self.bytes_sent,
            "bytes_received":   self.bytes_received,
            "connection_reused": self.connection_reused,
            "redirect_count":   self.redirect_count,
        }
