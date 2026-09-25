@dataclass(slots = True)
class FilterBuilder:
    _expressions: list[str]

    def __init__(self) -> None:
        self._expressions = []

    def protocol(self, proto: Protocol) -> FilterBuilder:
        bpf_expr = BPF_PROTOCOL_MAP.get(proto)
        if bpf_expr:
            self._expressions.append(f"({bpf_expr})")
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

    def _validate_port(port_number: int) -> None:
        if not PortRange.MIN <= port_number <= PortRange.MAX:
            raise ValidationError(
                f"Port must be {PortRange.MIN}-{PortRange.MAX}, got {port_number}"
            )