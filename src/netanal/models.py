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

@dataclass(slots=True)
class EndpointStats:
    """ Traffic statistics for a single network endpoint. """
    ip_address: str
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0

    @property
    def total_packets(self) -> int:
        """ Calculate total packets for this endpoint. """
        return self.packets_sent + self.packets_received

    @property
    def total_bytes(self) -> int:
        """ Calculate total bytes for this endpoint. """
        return self.bytes_sent + self.bytes_received