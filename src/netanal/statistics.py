import threading
import time
from collections import defaultdict

from netanal.constants import CaptureDefaults
from netanal.models import (
    BandwidthSample,
    CaptureStatistics,
    ConversationStats,
    EndpointStats,
    PacketInfo,
    Protocol,
)

class StatisticsCollector:
    """ Thread-safe collector with bandwidth sampling interval. """
    def __init__(
        self,
        bandwidth_interval: float = CaptureDefaults.BANDWIDTH_SAMPLE_INTERVAL_SECONDS,
    ) -> None:
        """ Initialize statistics collector with bandwidth sampling interval. """
        self._lock = threading.Lock()
        self._bandwidth_interval = bandwidth_interval

        self._start_time: float = 0.0
        self._last_sample_time: float = 0.0
        self._interval_bytes: int = 0
        self._interval_packets: int = 0

        self._total_packets: int = 0
        self._total_bytes: int = 0
        self._protocol_counts: dict[Protocol, int] = defaultdict(int)
        self._protocol_bytes: dict[Protocol, int] = defaultdict(int)
        self._endpoints: dict[str, EndpointStats] = {}
        self._conversations: dict[tuple[str, str], ConversationStats] = {}
        self._bandwidth_samples: list[BandwidthSample] = []

    def start(self) -> None:
        """ Mark the start of a capture session. """
        with self.lock:
            self._start_time = time.time()
            self._last_sample_time = self._start_time

def record_packet(self, packet: PacketInfo) -> None:
    with self._lock:
        self._total_packets += 1
        self._total_bytes += packet.size
        self._interval_packets += 1
        self._interval_bytes += packet.size

        self._protocol_counts[packet.protocol] += 1
        self._protocol_bytes[packet.protocol] += packet.size

        self._update_endpoint(packet.src_ip, sent_bytes = packet.size)
        self._update_endpoint(
            packet.dst_ip,
            received_bytes = packet.size
        )

        self._update_conversation(
            packet.src_ip,
            packet.dst_ip,
            packet.size
        )

        self._check_bandwidth_sample(packet.timestamp)

def _check_bandwidth_sample(self, timestamp: float) -> None:
    if timestamp - self._last_sample_time >= self._bandwidth_interval:
        elapsed = timestamp - self._last_sample_time
        if elapsed > 0:
            bps = self._interval_bytes / elapsed
            pps = self._interval_packets / elapsed
            self._bandwidth_samples.append(
                BandwidthSample(
                    timestamp = timestamp
                    bytes_per_second = bps,
                    packets_per_second = pps,
                )
            )
        self._interval_bytes = 0
        self._interval_packets = 0
        self._last_sample_time = timestamp