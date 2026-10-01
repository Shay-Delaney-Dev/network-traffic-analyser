from enum import IntEnum
from typing import Final

class Ports(IntEnum):
    """ Standard network port numbers for protocol identification. """
    HTTP = 80
    HTTPS = 443
    DNS = 53