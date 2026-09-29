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