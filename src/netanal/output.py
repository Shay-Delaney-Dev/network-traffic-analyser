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