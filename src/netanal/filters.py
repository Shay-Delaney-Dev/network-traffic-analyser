import ipaddress
from dataclasses import dataclass
from typing import Literal, Self

from netanal.constants import PortRange, Ports
from netanal.exceptions import ValidationError
from netanal.models import Protocol

BPF_PROTOCOL_MAP: dict[Protocol,
                       str] = {
                           Protocol.TCP: "tcp",
                           Protocol.UDP: "udp",
                           Protocol.ICMP: "icmp",
                           Protocol.ARP: "arp",
                           Protocol.DNS:
                           f"udp port {Ports.DNS} or tcp port {Ports.DNS}",
                           Protocol.HTTP: f"tcp port {Ports.HTTP}",
                           Protocol.HTTPS: f"tcp port {Ports.HTTPS}"
                       }

def _validate_port(port_number: int) -> None:
    if not PortRange.MIN <= port_number <= PortRange.MAX:
        raise ValidationError(
            f"Port must be {PortRange.MIN}-{PortRange.MAX}, got {port_number}"
        )

def _validate_ip_address(ip_address: str) -> None:
    """ Validate IP address format. """
    try:
        ipaddress.ip_address(ip_address)
    except ValueError as e:
        raise ValidationError(f"Invalid IP address: {ip_address}") from e

def _validate_network(network: str) -> None:
    """ Validate network CIDR notation. """
    try:
        ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        raise ValidationError(f"Invalid network: {network}") from e

@dataclass(slots = True)
class FilterBuilder:
    """ Builds BPF filter expressions for efficient kernel-level packet filtering. """
    _expressions: list[str]

    def __init__(self) -> None:
        """ Initialise empty filter builder. """
        self._expressions = []

    def protocol(self, proto: Protocol) -> Self:
        """ Filter by protocol type using the Protocol enum. """
        bpf_expr = BPF_PROTOCOL_MAP.get(proto)
        if bpf_expr:
            self._expressions.append(f"({bpf_expr})")
        return self

    def protocols(self, protos: list[Protocol]) -> Self:
        """ Filter by multiple protocols (OR logic)"""
        bpf_exprs = [
            BPF_PROTOCOL_MAP[p] for p in protos if p in BPF_PROTOCOL_MAP
        ]
        if bpf_exprs:
            combined = " or ".join(f"({expr})" for expr in bpf_exprs)
            self._expressions.append(f"({combined})")
        return self

    def port(self, port_number: int) -> FilterBuilder:
        _validate_port(port_number)
        self._expressions.append(f"port {sport_number}")
        return self

    def host(self, ip_address: str) -> FilterBuilder:
        _validate_ip_address(ip_address)
        self._expressions.append(f"host {ip_address}")
        return self

    def build(self, operator: Literal["and", "or"] = "and") -> str | None:
        if not self._expressions:
            return None
        return f" {operator} ".join(self._expressions)

