"""Flow record shared by every file data source."""
from dataclasses import dataclass

PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmp"}

# Seconds of silence after which a connection is considered over (Zeek's defaults).
IDLE_TIMEOUT = {"tcp": 300.0, "udp": 60.0, "icmp": 60.0}
DEFAULT_IDLE_TIMEOUT = 60.0

# Ports operating systems give outgoing connections by default: Linux 32768-60999
# (net.ipv4.ip_local_port_range), Windows since Vista 49152-65535 (IANA's dynamic range).
EPHEMERAL_PORTS = range(32768, 65536)

TCP_SYN, TCP_ACK = 0x02, 0x10


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


# Who started a connection is decided by time, then TCP flags, then ports: the side that sent
# first; when both sides' first packets (or both NetFlow halves) have the same time,
# flags_say_reversed; then looks_reversed; failing all three, the order they were read in.

def flags_say_reversed(first, other, packets=False):
    """Whether TCP flags say the `other` side started the connection: True, False, or None
    when they can't tell. A SYN without ACK comes from the client. With `packets` (the flags of
    each side's first packet, not a NetFlow half's flags ORed together), a SYN-ACK marks the
    server too."""
    def role(f):
        if f & TCP_SYN:
            if not f & TCP_ACK:
                return "client"
            if packets:
                return "server"
        return None
    a, b = role(first), role(other)
    other_client = b == "client" or a == "server"
    first_client = a == "client" or b == "server"
    return other_client if other_client != first_client else None


def looks_reversed(sport, dport):
    """True when the sender looks like the server: a well-known port (below 1024) talking to a
    port of 1024 or above; failing that, a port outside EPHEMERAL_PORTS talking to one inside.

    Used only when neither time nor TCP flags tell who started the connection.
    """
    return sport < 1024 <= dport or (sport not in EPHEMERAL_PORTS and dport in EPHEMERAL_PORTS)
