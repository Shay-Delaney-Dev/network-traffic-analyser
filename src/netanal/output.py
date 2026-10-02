import os
import sys

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from netanal.constants import ByteUnits, ProtocolColors, TimeConstants
from netanal.models import CaptureStatistics, PacketInfo, Protocol

def get_console() -> Console:
    """ Create console with environment-aware settings. """
    if not sys.stdout.isatty():
        return Console(force_terminal=False, no_color=True)
    if os.environ.get("CI"):
        return Console(force_terminal=True, force_interactive=False)
    if os.environ.get("NO_COLOR"):
        return Console(no_color=True)

console = get_console()

def create_capture_progress() -> Progress:
    """ Create progress display for packet capture. """
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )

def _get_protocol_color(protocol: Protocol) -> str:
    """ Get rich console color for a protocol. """
    return ProtocolColors.RICH.get(protocol.value, "white")

def print_packet(packet: PacketInfo) -> None:
    """ Print single packet information. """
    color = _get_protocol_color(packet.protocol)
    port_info = ""

    if packet.src_port and packet.dst_port:
        port_info = f":{packet.src_port} -> :{packet.dst_port}"

    console.print(
        f"[{color}]{packet.protocol.value:5}[/{color}] "
        f"{packet.src_ip:15} -> {packet.dst_ip:15} "
        f"{port_info:20} "
        f"[dim]{packet.size:6} bytes[/dim]"
    )

def print_protocol_table(stats: CaptureStatistics) -> None:
    """ Print protocol distribution table. """
    table = Table(title="Protocol Distribution")
    table.add_column("Protocol", style="cyan", justify="left")
    table.add_column("Packets", style="green", justify="right")
    table.add_column("Bytes", style="yellow", justify="right")
    table.add_column("Percentage", style="magenta", justify="right")

    percentages = stats.get_protocol_percentages()

    for protocol in sorted(stats.protocol_distribution.keys(), key=lambda p: p.value):
        count = stats.protocol_distribution[protocol]
        bytes_count = stats.protocol_bytes.get(protocol, 0)
        pct = percentages.get(protocol, 0.0)
        table.add_row(
            protocol.value,
            f"{count:,}",
            format_bytes(bytes_count),
            f"{pct:.1f}%",
        )

    console.print(table)


def print_top_talkers(stats: CaptureStatistics, limit: int = 10) -> None:
    """ Print top talkers table. """
    table = Table(title=f"Top {limit} Talkers")
    table.add_column("IP Address", style="cyan", justify="left")
    table.add_column("Packets Sent", style="green", justify="right")
    table.add_column("Packets Recv", style="yellow", justify="right")
    table.add_column("Bytes Sent", style="blue", justify="right")
    table.add_column("Bytes Recv", style="magenta", justify="right")
    table.add_column("Total", style="white", justify="right")

    top_talkers = stats.get_top_talkers(limit)

    for endpoint in top_talkers:
        table.add_row(
            endpoint.ip_address,
            f"{endpoint.packets_sent:,}",
            f"{endpoint.packets_received:,}",
            format_bytes(endpoint.bytes_sent),
            format_bytes(endpoint.bytes_received),
            format_bytes(endpoint.total_bytes),
        )

    console.print(table)


