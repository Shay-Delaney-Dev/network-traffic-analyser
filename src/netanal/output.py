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


