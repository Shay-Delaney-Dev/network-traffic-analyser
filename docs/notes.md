# capture.py

Capture Engine that recieves packets from Scapy at wire speed while processing them in a seperate thread without dropping data.

Due to asynchronous and unpredictable nature of packet capture, it is possible for the processing thread to block the capture thread, resulting in dropped packets. This is a concern as dropped packets may lead to missed security events. The solution for this problem is a producer-consumer pattern with a bounded queue.

Step 1: Producer-Consumer Setup

```
class CaptureEngine:
    def __init__(
        self,
        config: CaptureConfig,
        on_packet: Callable[[PacketInfo], None] | None = None,
        queue_size: int = CaptureDefaults.QUEUE_SIZE,
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
```

Key Components:
- Queue[Packet]: Bounded buffer between threads. If the queue fills (exceeds maxsize), the producer will drop packets rather than blocking. This prevents the capture thread from slowing down.
- StatisticsCollector: Seperate object that handles all metrics, this seperates capture logic from statistics logic.
- threading.Event: _stop_event signals both threads when its time to shut down. This is a better approach than using flags such as Event.wait(), which is interruptible.
- Lock: _count_lock protects _packet_count and _dropped_packets which both threads modify, precenting race conditions from corrupting the counts in the case of simultaneous acess. 