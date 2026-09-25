import contextlib
import os
import platform
import signal
import socket
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from queue import Empty, Full, Queue
from typing import TYPE_CHECKING

from scapy.sendrecv import AsyncSniffer

from netanal.analyzer import extract_packet_info
from netanal.constants import CaptureDefaults, NpcapPaths
from netanal.models import CaptureConfig, CaptureStatistics, PacketInfo
from netanal.statistics import StatisticsCollector

if TYPE_CHECKING:
    from scapy.packet import Packet

class CaptureEngine:
    """ Packet capture engine using Scapy with producer-consumer pattern. """
    def __init__(
            self,
            config: CaptureConfig,
            on_packet: Callable[[packet_info], None] | None = None,
            queue_size: int = CaptureDefaults.QUEUE_SIZE
    ) -> None:
        self._config = config
        self._on_packet = on_packet
        self._queue: Queue[Packet] = Queue(maxsize = queue_size)
        self._stats = StatisticsCollector()
        self._sniffer: AsyncSniffer | None = None
        self._processor_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._packet_count = 0
        self._dropped_packets = 0
        self._running = False
        self._count_lock = threading.Lock()

    def _enqueue_packet(self, packet: Packet) -> None:
        try:
            self._queue.put_nowait(packet)
        except Full:
            with self._count_lock:
                self._dropped_packets += 1

    def start(self) -> None:
        if self._running:
            return

        self._running = True
        self._stop_event.clear()

        with self._count_lock:
            self._packet_count = 0
            self._dropped_packets = 0

        self._stats.reset()
        self._stats.start()

        self._processor_thread = threading.Thread(
            target = self._process_packets,
            daemon = True,
        )
        self._processor_thread.start()

        sniffer_kwargs: dict[str, object] = {
            "prn": self._enqueue_packet,
            "store": self._config.store_packets,
        }

        if self._config.interface:
            sniffer_kwargs["iface"] = self._config.interface

        if self._config.bpf_filter:
            sniffer_kwargs["filter"] = self._config.bpf_filter

        self._sniffer = AsyncSniffer(**sniffer_kwargs)
        self._sniffer.start()

