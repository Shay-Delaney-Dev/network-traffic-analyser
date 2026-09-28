from pathlib import Path

import matplotlib


matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.figure import Figure

from netanal.constants import ByteUnits, ChartDefaults, ProtocolColors
from netanal.models import CaptureStatistics, Protocol

def _get_protocol_hex_color(protocol: Protocol) -> str:
    """ Get matplotlib hex colour for a protocol. """
    return ProtocolColors.HEX.get(
        protocol.value,
        ProtocolColors.HEX["OTHER"]
    )

def create_protocol_pie_chart(
        stats: CaptureStatistics,
        title: str = "Protocol Distribution",
) -> Figure:
    """ Create pie chart showing protocol distribution by packet count. """
    fig, ax = plt.subplots(figsize=ChartDefaults.FIGSIZE_SQUARE)

    protocols = list(stats.protocol_distribution.keys())
    counts = [stats.protocol_distribution[p] for p in protocols]
    colors = [_get_protocol_hex_color(p) for p in protocols]
    labels = [p.value for p in protocols]

    autotexts = ax.pie(
        counts,
        labels=labels,
        colors=colors,
        autopct="%1.1f%%",
        startangle=90,
        pctdistance=0.85,
    )[2]

    for autotext in autotexts:
        autotext.set_fontsize(ChartDefaults.FONT_SIZE_SMALL)
        autotext.set_color("white")
        autotext.set_fontweight("bold")

    ax.set_title(
        title,
        fontsize=ChartDefaults.FONT_SIZE_LARGE,
        fontweight="bold"
    )
    plt.tight_layout()

    return fig

def create_protocol_bar_chart(
        stats: CaptureStatistics,
        title: str = "Protocol Distribution",
) -> Figure:
    """ Create a bar chart showing protocol distribution. """
    fig, ax = plt.subplots(figsize=ChartDefaults.FIGSIZE_STANDARD)

    protocols = sorted(
        stats.protocol_distribution.keys(),
        key=lambda p: stats.protocol_distribution[p],
        reverse=True,
    )
    counts = [stats.protocol_distribution[p] for p in protocols]
    colors = [_get_protocol_hex_color(p) for p in protocols]
    labels = [p.value for p in protocols]

    bars = ax.bar(
        labels,
        counts,
        color=colors,
        edgecolor="black",
        linewidth=ChartDefaults.LINE_WIDTH_THIN,
    )

    for bar, count in zip(bars, counts, strict=False):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(counts) * 0.01,
            f"{count:,}",
            ha="center",
            va="bottom",
            fontsize=ChartDefaults.FONT_SIZE_SMALL,
        )

    ax.set_xlabel("Protocol", fontsize=ChartDefaults.FONT_SIZE_MEDIUM)
    ax.set_ylabel(
        "Packet Count",
        fontsize=ChartDefaults.FONT_SIZE_MEDIUM
    )
    ax.set_title(
        title,
        fontsize=ChartDefaults.FONT_SIZE_LARGE,
        fontweight="bold"
    )
    ax.grid(axis="y", alpha=ChartDefaults.GRID_ALPHA)
    plt.tight_layout()

    return fig
