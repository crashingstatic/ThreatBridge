"""Flow record shared by every file data source."""
from dataclasses import dataclass

PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmp"}

# Seconds of silence after which a connection is considered over (Zeek's defaults).
IDLE_TIMEOUT = {"tcp": 300.0, "udp": 60.0, "icmp": 60.0}
DEFAULT_IDLE_TIMEOUT = 60.0


class SourceError(Exception):
    """An evidence file can't be read."""


@dataclass(slots=True, frozen=True)
class Flow:
    """One connection, oriented initiator -> responder like a Zeek conn record.

    Packets and bytes cover both directions; bytes are counted at the IP layer.
    """
    src: str
    dst: str
    sport: int
    dport: int
    proto: str        # "tcp", "udp", "icmp", or the IP protocol number
    start: float      # epoch seconds, UTC
    end: float
    packets: int
    bytes: int
    source: str       # evidence file the flow was first seen in


def proto_name(number):
    return PROTO_NAMES.get(number, str(number))


def idle_timeout(proto):
    return IDLE_TIMEOUT.get(proto, DEFAULT_IDLE_TIMEOUT)


def looks_reversed(sport, dport):
    """True when the sender looks like the server: well-known source port, ephemeral destination.

    Used only when the capture shows no handshake or timing to say who started the connection.
    """
    return sport < 1024 <= dport
