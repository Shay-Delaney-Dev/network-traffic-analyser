from enum import IntEnum
from typing import Final

class Ports(IntEnum):
    """ Standard network port numbers for protocol identification. """
    HTTP = 80
    HTTPS = 443
    DNS = 53

class TimeConstants:
    """ Time-related constants for duration formatting. """
    SECONDS_PER_MINUTE: Final[int] = 60
    SECONDS_PER_HOUR: Final[int] = 3600

class ByteUnits:
    """ Byte unit conversion constants. """
    BYTES_PER_KB: Final[float] = 1024.0
    UNITS: Final[tuple[str, ...]] = ("B", "KB", "MB", "GB", "TB", "PB")

class CaptureDefaults:
    """ Default values for packet capture operations. """
    QUEUE_SIZE: Final[int] = 10_000
    QUEUE_TIMEOUT_SECONDS: Final[float] = 0.1
    THREAD_JOIN_TIMEOUT_SECONDS: Final[float] = 2.0
    BANDWIDTH_SAMPLE_INTERVAL_SECONDS: Final[float] = 1.0