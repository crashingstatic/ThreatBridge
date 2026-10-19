"""Read tcpdump captures (classic pcap format) into connection flows."""
import logging
import socket
import struct

import dpkt

from ..model import Flow, SourceError, idle_timeout, looks_reversed, proto_name

log = logging.getLogger(__name__)

SWEEP_EVERY = 60.0  # capture seconds between sweeps for idle connections
_SYN, _ACK, _FIN, _RST = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_FIN, dpkt.tcp.TH_RST


def _raw_ip(buf):
    version = buf[0] >> 4
    if version == 4:
        return dpkt.ip.IP(buf)
    if version == 6:
        return dpkt.ip6.IP6(buf)
    return None


# Link types tcpdump writes: Ethernet, Linux "any" (SLL and SLL2), raw IP, BSD loopback.
_DECODERS = {
    0: lambda buf: dpkt.loopback.Loopback(buf).data,
    1: lambda buf: dpkt.ethernet.Ethernet(buf).data,
    101: _raw_ip,
    108: lambda buf: dpkt.loopback.Loopback(buf).data,
    113: lambda buf: dpkt.sll.SLL(buf).data,
    276: lambda buf: dpkt.sll2.SLL2(buf).data,
}


class _Conn:
    __slots__ = ("orig", "oport", "resp", "rport", "proto", "start", "last", "packets",
                 "bytes", "source", "closing")

    def __init__(self, orig, oport, resp, rport, proto, ts, source):
        self.orig, self.oport, self.resp, self.rport = orig, oport, resp, rport
        self.proto, self.start, self.last, self.source = proto, ts, ts, source
        self.packets = self.bytes = 0
        self.closing = False


class FlowTracker:
    """Groups packets into connections, keyed by protocol and both endpoints.

    A connection ends after its idle timeout, on a TCP RST, or when a new SYN arrives after
    a FIN. The initiator is the SYN sender; without a handshake, the first sender, unless it
    looks like the server (see model.looks_reversed).
    """

    def __init__(self):
        self.open = {}
        self.flows = []
        self.now = 0.0
        self.next_sweep = 0.0

    def add(self, ts, src, dst, proto, sport, dport, nbytes, flags, source):
        if ts > self.now:
            self.now = ts
        if self.now >= self.next_sweep:
            self._sweep()
            self.next_sweep = self.now + SWEEP_EVERY
        key = (proto, src, sport, dst, dport) if (src, sport) <= (dst, dport) \
            else (proto, dst, dport, src, sport)
        conn = self.open.get(key)
        new_syn = proto == "tcp" and flags & _SYN and not flags & _ACK
        if conn is not None and (ts - conn.last > idle_timeout(proto) or (new_syn and conn.closing)):
            self._close(key)
            conn = None
        if conn is None:
            if proto == "tcp" and flags & _SYN:
                reverse = bool(flags & _ACK)  # a SYN-ACK comes from the responder
            else:
                reverse = looks_reversed(sport, dport)
            conn = _Conn(dst, dport, src, sport, proto, ts, source) if reverse \
                else _Conn(src, sport, dst, dport, proto, ts, source)
            self.open[key] = conn
        conn.packets += 1
        conn.bytes += nbytes
        if ts < conn.start:
            conn.start = ts
        if ts > conn.last:
            conn.last = ts
        if proto == "tcp":
            if flags & _RST:
                self._close(key)
            elif flags & _FIN:
                conn.closing = True

    def _sweep(self):
        idle = [k for k, c in self.open.items() if self.now - c.last > idle_timeout(c.proto)]
        for key in idle:
            self._close(key)

    def _close(self, key):
        c = self.open.pop(key)
        self.flows.append(Flow(c.orig, c.resp, c.oport, c.rport, c.proto, c.start, c.last,
                               c.packets, c.bytes, c.source))

    def finish(self):
        for key in list(self.open):
            self._close(key)
        return self.flows


def _open(fh, path):
    try:
        return dpkt.pcap.Reader(fh)
    except (ValueError, dpkt.Error) as e:
        raise SourceError(f"{path}: not a readable pcap file ({e})")


def _first_timestamp(path):
    with open(path, "rb") as fh:
        for ts, _ in _open(fh, path):
            return float(ts)
    return float("inf")


def _read_one(path, tracker):
    packets = skipped = 0
    with open(path, "rb") as fh:
        reader = _open(fh, path)
        decode = _DECODERS.get(reader.datalink())
        if decode is None:
            raise SourceError(f"{path}: unsupported link type {reader.datalink()}")
        for ts, buf in reader:
            ts = float(ts)  # nanosecond captures come back as Decimal
            packets += 1
            try:
                ip = decode(buf)
            except (dpkt.Error, IndexError, struct.error):
                skipped += 1
                continue
            if isinstance(ip, dpkt.ip.IP):
                if ip.offset:
                    continue  # later fragments have no ports; only the first is counted
                src, dst = socket.inet_ntop(socket.AF_INET, ip.src), socket.inet_ntop(socket.AF_INET, ip.dst)
                nbytes = ip.len or len(ip)
            elif isinstance(ip, dpkt.ip6.IP6):
                src, dst = socket.inet_ntop(socket.AF_INET6, ip.src), socket.inet_ntop(socket.AF_INET6, ip.dst)
                nbytes = ip.plen + 40
            else:
                continue  # ARP and other non-IP traffic
            proto = proto_name(ip.p)
            t = ip.data
            if isinstance(t, dpkt.tcp.TCP):
                sport, dport, flags = t.sport, t.dport, t.flags
            elif isinstance(t, dpkt.udp.UDP):
                sport, dport, flags = t.sport, t.dport, 0
            else:
                sport = dport = flags = 0
            tracker.add(ts, src, dst, proto, sport, dport, nbytes, flags, path)
    log.info("%s: %d packets, %d undecodable", path, packets, skipped)


def read_pcaps(paths):
    """Flows from tcpdump captures. Files are read in capture order, so a connection that
    spans rotated files (tcpdump -C / -G) comes out as one flow."""
    tracker = FlowTracker()
    for path in sorted(paths, key=_first_timestamp):
        _read_one(path, tracker)
    return tracker.finish()
