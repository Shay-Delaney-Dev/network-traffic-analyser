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

    def port(self, port_number: int) -> Self:
        """ Filter by port number (Source or destination). """
        _validate_port(port_number)
        self._expressions.append(f"port {port_number}")
        return self

    def src_port(self, port_number: int) -> Self:
        """ Filter by source port. """
        _validate_port(port_number)
        self._expressions.append(f"src port {port_number}")
        return self

    def dst_port(self, port_number: int) -> Self:
        """ Filter by destination port. """
        _validate_port(port_number)
        self._expressions.append(f"dst port {port_number}")
        return self

    def host(self, ip_address: str) -> Self:
        """ Filter by IP address (source or destination). """
        _validate_ip_address(ip_address)
        self._expressions.append(f"host {ip_address}")
        return self

    def src_host(self, ip_address: str) -> Self:
        """ Filter by source ip address. """
        _validate_ip_address(ip_address)
        self._expressions.append(f"src host {ipaddress}")
        return self

    def dst_host(self, ip_address: str) -> Self:
        """ Filter by destination ip address. """
        _validate_ip_address(ip_address)
        self._expressions.append(f"dst host {ip_address}")
        return self

    def net(self, network: str) -> Self:
        """ Filter by network (CIDR) notation. """
        _validate_network(network)
        self._expressions.append(f"net {self.network}")
        return self

    def port_range(self, start: int, end: int) -> Self:
        """ Filter by port range. """
        _validate_port(start)
        _validate_port(end)
        if start > end:
            raise ValidationError(f"Invalid port range: {start}-{end}")
        self._expressions.append(f"portrange {start}-{end}")
        return self

    def build(self, operator: Literal["and", "or"] = "and") -> str | None:
        if not self._expressions:
            return None
        return f" {operator} ".join(self._expressions)

