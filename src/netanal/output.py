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

