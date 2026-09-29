from dataclasses import dataclass, field
from enum import StrEnum

class Protocol(StrEnum):
    """ Network protocols identified during packet analysis. """
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    DNS = "DNS"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    ARP = "ARP"
    OTHER = "OTHER"

@dataclass(frozen=True, slots=True)
class PacketInfo:
    """ Information extracted from a single captured packet. """
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: Protocol
    size: int
    src_port: int | None = None
    dst_port: int | None = None
    src_mac: int | None = None
    dst_mac: int | None = None