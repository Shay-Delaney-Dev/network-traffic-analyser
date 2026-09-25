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
        """ Callback for AsyncSniffer to add captured packets to the queue. """
        try:
            self._queue.put_nowait(packet)
        except Full:
            with self._count_lock:
                self._dropped_packets += 1

    def _process_packets(self) -> None:
        """ Consumer thread that processes packets from the queue. """
        while not self._stop_event.is_set():
            try:
                packet = self._queue.get(
                    timeout=CaptureDefaults.QUEUE_TIMEOUT_SECONDS
                )
            except Empty:
                continue

            info = extract_packet_info(packet)
            if info is None:
                continue

            self._stats.record_packet(info)

            with self._count_lock:
                self._packet_count += 1
                current_count = self._packet_count

            if self._on_packet:
                self._on_packet(info)

            if self._config.packet_count and current_count >= self._config.packet_count:
                self._stop_event.set()
                break

    def start(self) -> None:
        """ Start packet capture. """
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

        if self._config.packet_count:
            sniffer_kwargs["count"] = self._config.packet_count

        if self._config.timeout_seconds:
            sniffer_kwargs["timeout"] = self._config.timeout_seconds

        self._sniffer = AsyncSniffer(**sniffer_kwargs)
        self._sniffer.start()

    def stop(self) -> CaptureStatistics:
        """ Stop packet capture and return statistics. """
        self._stop_event.set()

        if self._sniffer and self._sniffer.running:
            self._sniffer.stop()

        if self._processor_thread and self._processor_thread.is_alive():
            self._processor_thread.join(
                timeout=CaptureDefaults.THREAD_JOIN_TIMEOUT_SECONDS
            )

        self._running = False
        return self._stats.get_statistics()

    def wait(self) -> CaptureStatistics:
        """ Wait for capture to complete and return statistics. """
        if self._sniffer:
            with contextlib.suppress(AttributeError):
                self._sniffer.join()

        self._stop_event.set()

        if self._processor_thread and self._processor_thread.is_alive():
            self._processor_thread.join(
                timeout=CaptureDefaults.THREAD_JOIN_TIMEOUT_SECONDS
            )

            self._running = False
            return self._stats.get_statistics()

