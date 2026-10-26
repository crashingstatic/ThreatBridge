"""Flow record shared by every file data source."""
from dataclasses import dataclass

PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmp"}

# Seconds of silence after which a connection is considered over (Zeek's defaults).
IDLE_TIMEOUT = {"tcp": 300.0, "udp": 60.0, "icmp": 60.0}
DEFAULT_IDLE_TIMEOUT = 60.0

# Ports operating systems give outgoing connections by default: Linux 32768-60999
# (net.ipv4.ip_local_port_range), Windows since Vista 49152-65535 (IANA's dynamic range).
EPHEMERAL_PORTS = range(32768, 65536)

TCP_SYN, TCP_RST, TCP_ACK = 0x02, 0x04, 0x10


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


# Who started a connection: first time (the side seen first, when both sides were seen at
# different times); then the TCP flags (flags_say_reversed); then the ports
# (ports_say_reversed). When none can tell, the connection is taken both ways (oriented).

def icmp_flags(proto, icmp_type):
    """ICMP echo requests and replies open and answer like a SYN and a SYN-ACK, so they are
    given those flags for telling who started a connection. `proto`: 1 (ICMP) or 58 (ICMPv6)."""
    request, reply = (8, 0) if proto == 1 else (128, 129)
    if icmp_type == request:
        return TCP_SYN
    return TCP_SYN | TCP_ACK if icmp_type == reply else 0


def flags_say_reversed(first, other, packets=False):
    """Whether TCP flags say the `other` side started the connection: True, False, or None
    when they can't tell. `first` and `other` are each side's flags, None for a side never seen:
    with `packets`, those of its first packet; otherwise a NetFlow half's, ORed over the
    connection.

    A SYN without ACK is the client's. A SYN-ACK answered by a RST without ACK is a SYN-ACK scan,
    so it is the client's too. With `packets`, a SYN-ACK answered otherwise is the server's; one
    never answered can't be told from a scan.
    """
    def role(f, answer):
        if f is None or not f & TCP_SYN:
            return None
        if not f & TCP_ACK:
            return "client"
        if answer is None:
            return None
        if answer & TCP_RST and not answer & (TCP_SYN | TCP_ACK):
            return "client"                       # a SYN-ACK scan, reset by its target
        return "server" if packets else None
    a, b = role(first, other), role(other, first)
    other_client = b == "client" or a == "server"
    first_client = a == "client" or b == "server"
    return other_client if other_client != first_client else None


def refused(a, b):
    """Whether a TCP connection was refused, from each side's flags ORed together: one side's
    SYN (without ACK) answered only by a RST, never a SYN-ACK. Zeek calls it REJ. Refused
    connections aren't mapped: a single port scan would swamp the map."""
    def answered_by_reset(x, y):
        return x & TCP_SYN and not x & TCP_ACK and y & TCP_RST and not y & TCP_SYN
    return bool(answered_by_reset(a, b) or answered_by_reset(b, a))


def ports_say_reversed(first, other):
    """Whether the ports say the `other` side started the connection: True, False, or None when
    they can't tell. A well-known port (below 1024) facing one of 1024 or above is the server's;
    failing that, a port in EPHEMERAL_PORTS facing one outside it is the client's."""
    if (first < 1024) != (other < 1024):
        return first < 1024
    if (first in EPHEMERAL_PORTS) != (other in EPHEMERAL_PORTS):
        return first not in EPHEMERAL_PORTS
    return None


def settle(first_flags, other_flags, first_port, other_port, packets=False):
    """Who started a connection when time can't tell: the flags, then the ports. True if the
    `other` side did, False if the first side did, None if neither can be told."""
    flip = flags_say_reversed(first_flags, other_flags, packets)
    return ports_say_reversed(first_port, other_port) if flip is None else flip


def oriented(flip, a, aport, b, bport, proto, start, end, packets, nbytes, source):
    """A connection between a:aport and b:bport as flows: one from a (`flip` False) or from b
    (True); when who started it can't be told (None), two identical flows, one each way."""
    flows = []
    if not flip:
        flows.append(Flow(a, b, aport, bport, proto, start, end, packets, nbytes, source))
    if flip is not False:
        flows.append(Flow(b, a, bport, aport, proto, start, end, packets, nbytes, source))
    return flows
