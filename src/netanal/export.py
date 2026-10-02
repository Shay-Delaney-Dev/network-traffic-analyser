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