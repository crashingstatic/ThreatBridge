"""Community ID, version 1 (https://github.com/corelight/community-id-spec): a hash of a
connection's addresses, protocol and ports that Zeek, Suricata, Arkime and Security Onion also
record, so one string finds the connection in each. Seed 0, the default everywhere.

The hash input, in network byte order: the seed (2 bytes), the two addresses with the smaller
address-and-port first, the IP protocol (1 byte) and a 0 byte, then for TCP, UDP and SCTP the
two ports in the same order. ICMP uses the type and code instead of ports; the readers keep
neither, and keep no SCTP ports, so those flows have no Community ID here.
"""
import base64
import hashlib
import ipaddress
import struct

_NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1}
_PORTS = {6, 17}              # protocols whose ports the readers keep
_UNKNOWABLE = {1, 58, 132}    # ICMP, ICMPv6 (type and code not kept), SCTP (ports not kept)


def community_id(src, dst, proto, sport, dport):
    """"1:<base64>" for a flow, or None when it can't be worked out (see above, or a value that
    isn't an address, protocol or port). `proto`: "tcp", "udp", "icmp" or an IP protocol number."""
    try:
        number = _NUMBERS[proto] if proto in _NUMBERS else int(proto)
        if number in _UNKNOWABLE or not 0 <= number <= 255:
            return None
        a, b = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
        if len(a) != len(b):
            return None
        tail = b""
        if number in _PORTS:
            ports = [int(sport), int(dport)]
            if (b, ports[1]) < (a, ports[0]):
                a, b, ports = b, a, ports[::-1]
            tail = struct.pack("!HH", *ports)
        elif b < a:
            a, b = b, a
        data = struct.pack("!H", 0) + a + b + struct.pack("!BB", number, 0) + tail
    except (KeyError, TypeError, ValueError, struct.error):
        return None
    return "1:" + base64.b64encode(hashlib.sha1(data, usedforsecurity=False).digest()).decode()
