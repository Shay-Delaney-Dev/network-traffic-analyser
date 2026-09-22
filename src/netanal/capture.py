class CaptureEngine:
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