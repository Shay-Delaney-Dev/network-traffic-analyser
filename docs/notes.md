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

Step 2: Producer Thread Setup

When starting Scapy's AsyncSniffer as the producer, its important to actually start the consumer thread first. This ensures that the queue has a consumer once packets start to arrive. If we started the producer thread first, it would fill the queue almost immediately after beginning capture, potentially leading to an overflow.

We also use daemon threads in this implementation to ensure threads automatically exit when the user exits the application. This prevents the threads from continuing to run in the background.

We also ensure that we start from a clean slate every time we start up the producer thread, resetting all counters and statistics to 0 and double checking nothing is currenstly running to prevent duplicate threads.

```
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
```

Key Components: 
- Checks _running flag to prevent a double-start which would create duplicate threads.
- Resets counters and statistics to 0, giving a clean state for a new capture.
- Starts consumer (analyser) thread before producer (capture), ensuring the queue has a consumer when packets arrive. This prevents queue overflow during initalisation. If the producer runs first and the consumer thread hasn't started yet, the queue fills immediately and may overflow.
- We use daemon threads in this implementation as they automatically exit when the program exits, ensuring nothing is running in the background . Non-Daemon threads would keep the program alive even after user exits.
- Build sniffer_kwargs dictionary conditionally, including only non-None config values.
- Pass _enqueue_packet as callback (prn parameter).
- AsyncSniffer.start() spawns the producer thread internally. 

Step 3: Producer Callback

The producer callback runs in Scapy's capture thread for every packet, handling adding packets to the queue without blocking. 

We make sure to catch exceptions if the queue is full, and handle it gracefully by incrementing the dropped packets counter by 1, this prevents crashing. There is also a lock on the dropped packets counter, preventing race conditions from causing inaccuracies in our counter when two threads attempt to access it simulteanously.

Additionally, we used put_nowait() instead of put() which blocks until space is available. This would result in our capture thread slowing to the speed of our processing thread. In this instance losing the occasional packet is preferable to slowing the rate of packet capture. 

```
    def _enqueue_packet(self, packet: Packet) -> None:
        try:
            self._queue.put_nowait(packet)
        except Full:
            with self._count_lock:
                self._dropped_packets += 1
```

Key Components:
- Runs in Scapy's capture thread for every packet.
- Handles adding packets to the queue without blocking.
- put_nowait() raises Full exception if the queue is full, caught by error handling and the dropped packets counter is incremented by 1 instead of crashing.
- put_nowait() is used over put() due to performance, put() blocks until space is available which would slow the capture threads speed down to match the consumer threads speed. In this instance it is better to drop packets than to slow capture.
- the lock on _dropped_packets prevents lost increment operations occuring in the instance of multiple threads accessing the same counter simultaenously and one operation never completing (race condition).