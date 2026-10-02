import csv
import json
from pathlib import Path
from typing import Any

from netanal.models import (
    CaptureStatistics,
    ExportOptions,
    PacketInfo,
    Protocol,
)
def statistics_to_dict(stats: CaptureStatistics) -> dict[str, Any]:
    """ Convert CaptureStatistcis to JSON-serializable dictionary. """
    protocol_dist = {
        proto.value: count
        for proto, count in stats.protocol_distribution.items()
    }

    protocol_bytes = {
        proto.value: count
        for proto, count in stats.protocol_bytes.items()
    }

    endpoints = [
        {
            "ip_address": e.ip_address,
            "packets_sent": e.packets_sent,
            "packets_received": e.packets_received,
            "bytes_sent": e.bytes_sent,
            "bytes_received": e.bytes_received,
            "total_bytes": e.total_bytes,
        } for e in stats.endpoints.values()
    ]

    conversations = [
        {
            "endpoint_a": c.endpoint_a,
            "endpoint_b": c.endpoint_b,
            "packets": c.packets,
            "bytes_total": c.bytes_total,
        } for c in stats.conversations.values()
    ]

    bandwidth_samples = [
        {
            "timestamp": s.timestamp,
            "bytes_per_second": s.bytes_per_second,
            "packets_per_second": s.packets_per_second,
        } for s in stats.bandwidth_samples
    ]

    return {
        "start_time": stats.start_time,
        "end_time": stats.end_time,
        "duration_seconds": stats.duration_seconds,
        "total_packets": stats.total_packets,
        "total_bytes": stats.total_bytes,
        "average_bandwidth": stats.average_bandwidth,
        "protocol_distribution": protocol_dist,
        "protocol_bytes": protocol_bytes,
        "endpoints": endpoints,
        "conversations": conversations,
        "bandwidth_samples": bandwidth_samples,
    }

def packet_to_dict(packet: PacketInfo) -> dict[str, Any]:
    """ Convert PacketInfo to JSON-serializable dictionary. """
    return {
        "timestamp": packet.timestamp,
        "src_ip": packet.src_ip,
        "dst_ip": packet.dst_ip,
        "protocol": packet.protocol.value,
        "size": packet.size,
        "src_port": packet.src_port,
        "dst_port": packet.dst_port,
        "src_mac": packet.src_mac,
        "dst_mac": packet.dst_mac,
    }

def export_to_json(
    stats: CaptureStatistics,
    filepath: Path,
    packets: list[PacketInfo] | None = None,
    options: ExportOptions | None = None, 
) -> None:
    """ Export capture data to JSON file. """
    if options is None:
        options = ExportOptions()

    data: dict[str, Any] = {}

    if options.include_statistics:
        stats_dict = statistics_to_dict(stats)
        if not options.include_endpoints:
            stats_dict.pop("endpoints", None)
        if not options.include_conversations:
            stats_dict.pop("conversations", None)
        data["statistics"] = stats_dict

    if options.include_packets and packets:
        data["packets"] = [packet_to_dict(p) for p in packets]

    indent = 2 if options.pretty_print else None

    with filepath.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent)

def export_to_csv(
        stats: CaptureStatistics,
        filepath: Path,
        packets: list[PacketInfo] | None = None,
) -> None:
    """ Export packet data to CSV file. """
    fieldnames = [
        "timestamp",
        "src_ip",
        "dst_ip",
        "protocol",
        "size",
        "src_port",
        "dst_port",
        "src_mac",
        "dst_mac",
    ]

    with filepath.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        if packets:
            for packet in packets:
                writer.writerow(packet_to_dict(packet))

def export_endpoints_csv(stats: CaptureStatistics, filepath: Path) -> None:
    """ Export endpoint statistics to CSV file. """
    fieldnames = [
        "ip_address",
        "packets_sent",
        "packets_received",
        "bytes_sent",
        "bytes_received",
        "total_packets",
        "total_bytes",
    ]

    with filepath.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for endpoint in stats.endpoints.values():
            writer.writerow(
                {
                    "ip_address": endpoint.ip_address,
                    "packets_sent": endpoint.packets_sent,
                    "packets_received": endpoint.packets_received,
                    "bytes_sent": endpoint.bytes_sent,
                    "bytes_received": endpoint.bytes_received,
                    "total_packets": endpoint.total_packets,
                    "total_bytes": endpoint.total_bytes,
                }
            )

def export_protocol_summary_csv(
    stats: CaptureStatistics,
    filepath: Path
) -> None:
    """ Export protocol distribution to CSV file. """
    fieldnames = ["protocol", "packets", "bytes", "percentage"]
    percentages = stats.get_protocol_percentages()

    with filepath.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for protocol, count in stats.protocol_distribution.items():
            writer.writerow(
                {
                    "protocol": protocol.value,
                    "packets": count,
                    "bytes": stats.protocol_bytes.get(protocol,0),
                    "percentage": f"{percentages.get(protocol, 0.0):.2f}",
                }
            )