"""Read tcpdump captures (classic pcap format) into connection flows."""
import logging
import os
import socket
import struct

import dpkt

from ..model import Flow, SourceError, flags_say_reversed, idle_timeout, looks_reversed, proto_name
from ..progress import counted
from .workers import in_order

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
                 "bytes", "source", "closing", "first_flags", "answered")

    def __init__(self, orig, oport, resp, rport, proto, ts, source, flags):
        self.orig, self.oport, self.resp, self.rport = orig, oport, resp, rport
        self.proto, self.start, self.last, self.source = proto, ts, ts, source
        self.packets = self.bytes = 0
        self.closing = False
        self.first_flags, self.answered = flags, False   # the first sender's; the other side's yet?

    def orient(self, ts, flags):
        """The other side's first packet, at `ts` with `flags`: settle who started the
        connection. Time first: the side that sent first. On a tie, the TCP flags of each side's
        first packet, then the ports; failing both, capture order."""
        if ts == self.start:
            flip = flags_say_reversed(self.first_flags, flags, packets=True)
            if flip is None:
                flip = looks_reversed(self.oport, self.rport)
        else:
            flip = ts < self.start
        if flip:
            self.orig, self.oport, self.resp, self.rport = self.resp, self.rport, self.orig, self.oport


class FlowTracker:
    """Groups packets into connections, keyed by protocol and both endpoints.

    A connection ends after its idle timeout, on a TCP RST, or when a new SYN arrives after
    a FIN. The initiator is the side that sent first (see _Conn.orient).
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
            conn = self.open[key] = _Conn(src, sport, dst, dport, proto, ts, source, flags)
        elif not conn.answered and (src, sport) != (conn.orig, conn.oport):
            conn.answered = True
            conn.orient(ts, flags)
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


class _Counts:
    """What reading one capture came to."""
    __slots__ = ("packets", "skipped", "cut_off")

    def __init__(self):
        self.packets = self.skipped = 0
        self.cut_off = False


def _packets(reader, counts):
    """(timestamp, frame) for each packet. A capture cut off inside a record (tcpdump killed
    mid-write) ends at the last whole packet."""
    packets = iter(reader)
    while True:
        try:
            ts, buf = next(packets)
        except StopIteration:
            return
        except (dpkt.Error, struct.error):
            counts.cut_off = True
            return
        yield float(ts), buf  # nanosecond captures come back as Decimal


def _first_timestamp(path):
    with open(path, "rb") as fh:
        for ts, _ in _packets(_open(fh, path), _Counts()):
            return ts
    return float("inf")


def _name(n):
    return n.rstrip(".").lower()


def record_dns(payload, ts, dns):
    """Add the A/AAAA answers of a DNS response to `dns`: {name: {ip: [first, last]}}.

    Every name on the chain from the question (the question and each CNAME on the way) maps
    to every address the chain leads to. Answer records for other names are ignored: a
    resolver wouldn't use them, and a crafted response could otherwise tie a benign name to
    an attacker's address."""
    try:
        msg = dpkt.dns.DNS(payload)
    except (dpkt.Error, IndexError, struct.error, UnicodeDecodeError):
        return
    if msg.qr != dpkt.dns.DNS_R or msg.rcode != dpkt.dns.DNS_RCODE_NOERR:
        return
    names = {_name(q.name) for q in msg.qd}
    answers = [(_name(rr.name), rr) for rr in msg.an]
    chained = True
    while chained:              # follow CNAMEs from the question, in any order they come
        chained = False
        for owner, rr in answers:
            if rr.type == dpkt.dns.DNS_CNAME and owner in names and _name(rr.cname) not in names:
                names.add(_name(rr.cname))
                chained = True
    ips = set()
    for owner, rr in answers:
        if owner not in names:
            continue
        if rr.type == dpkt.dns.DNS_A and len(rr.rdata) == 4:
            ips.add(socket.inet_ntop(socket.AF_INET, rr.rdata))
        elif rr.type == dpkt.dns.DNS_AAAA and len(rr.rdata) == 16:
            ips.add(socket.inet_ntop(socket.AF_INET6, rr.rdata))
    names.discard("")
    for name in names:
        seen = dns.setdefault(name, {})
        for ip in ips:
            if ip in seen:
                seen[ip][0] = min(seen[ip][0], ts)
                seen[ip][1] = max(seen[ip][1], ts)
            else:
                seen[ip] = [ts, ts]


REPORT_EVERY = 4096   # packets between progress reports


def _decoded(path, dns, counts, report=None):
    """The IP packets of one capture as (ts, IP version, IP protocol, src, dst, sport, dport,
    IP-layer bytes, TCP flags), with the addresses as packed bytes. DNS answers over UDP go
    into `dns` unless it is None. `report` is called with the bytes read since its last call."""
    with open(path, "rb") as fh:
        reader = _open(fh, path)
        decode = _DECODERS.get(reader.datalink())
        if decode is None:
            raise SourceError(f"{path}: unsupported link type {reader.datalink()}")
        offset = 0
        for ts, buf in _packets(reader, counts):
            counts.packets += 1
            if report and not counts.packets % REPORT_EVERY:
                report(fh.tell() - offset)
                offset = fh.tell()
            try:
                ip = decode(buf)
            except (dpkt.Error, IndexError, struct.error):
                counts.skipped += 1
                continue
            if isinstance(ip, dpkt.ip.IP):
                if ip.offset:
                    continue  # later fragments have no ports; only the first is counted
                version, nbytes = 4, ip.len or len(ip)
            elif isinstance(ip, dpkt.ip6.IP6):
                frag = getattr(ip, "extension_hdrs", {}).get(dpkt.ip.IP_PROTO_FRAGMENT)
                if frag is not None and frag.frag_off:
                    continue  # as above: a later fragment is payload only
                version, nbytes = 6, ip.plen + 40
            else:
                continue  # ARP and other non-IP traffic
            t = ip.data
            if isinstance(t, dpkt.tcp.TCP):
                sport, dport, flags = t.sport, t.dport, t.flags
            elif isinstance(t, dpkt.udp.UDP):
                sport, dport, flags = t.sport, t.dport, 0
                if sport == 53 and dns is not None:
                    record_dns(t.data, ts, dns)
            elif ip.p in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
                # Header cut short by the snap length: the ports are its first 4 bytes.
                if len(t) < 4:
                    counts.skipped += 1
                    continue
                sport, dport = struct.unpack("!HH", t[:4])
                flags = t[13] if ip.p == dpkt.ip.IP_PROTO_TCP and len(t) > 13 else 0
            else:
                sport = dport = flags = 0
            yield ts, version, ip.p, ip.src, ip.dst, sport, dport, nbytes, flags
        if report:
            report(fh.tell() - offset)


class _Hosts:
    """Packed addresses as text, each worked out once: the same hosts turn up again and again."""

    def __init__(self):
        self.text = {4: {}, 6: {}}

    def __call__(self, version, packed):
        known = self.text[version]
        name = known.get(packed)
        if name is None:
            family, size = (socket.AF_INET, 4) if version == 4 else (socket.AF_INET6, 16)
            name = known[packed] = socket.inet_ntop(family, packed[:size])
        return name


def _track(tracker, packets, path, hosts):
    for ts, version, p, src, dst, sport, dport, nbytes, flags in packets:
        tracker.add(ts, hosts(version, src), hosts(version, dst), proto_name(p), sport, dport,
                    nbytes, flags, path)


def _logged(path, counts):
    if counts.cut_off:
        log.warning("%s: capture is cut off after its last whole packet", path)
    log.info("%s: %d packets, %d undecodable", path, counts.packets, counts.skipped)


# A decoded packet as worker processes pass it back (see _decoded): addresses in 16 bytes,
# an IPv4 address in the first 4.
_PACKED = struct.Struct("<dBB16s16sHHIB")


def _decode_file(path, want_dns):
    """In a worker process: one capture's packets, packed, with its DNS answers and counts."""
    dns = {} if want_dns else None
    counts = _Counts()
    packed = bytearray()
    for packet in _decoded(path, dns, counts):
        packed += _PACKED.pack(*packet)
    return packed, dns, counts


def _merge_dns(dns, more):
    for name, seen in more.items():
        known = dns.setdefault(name, {})
        for ip, (first, last) in seen.items():
            if ip in known:
                known[ip][0] = min(known[ip][0], first)
                known[ip][1] = max(known[ip][1], last)
            else:
                known[ip] = [first, last]


def read_pcaps(paths, dns=None, workers=1, stage=None):
    """Flows from tcpdump captures. Files are read in capture order, so a connection that
    spans rotated files (tcpdump -C / -G) comes out as one flow. If `dns` is a dict, DNS
    answers seen over UDP are added to it (see record_dns).

    With several files and workers, that many worker processes decode files at once; the
    connections are still followed packet by packet in capture order, so the flows are the
    same. `stage` (see progress.py) is told the bytes read."""
    stage = stage or (lambda amount=0, note=None: None)
    tracker, hosts = FlowTracker(), _Hosts()
    files = sorted(paths, key=_first_timestamp)
    packets = 0
    if workers <= 1 or len(files) <= 1:
        for i, path in enumerate(files, 1):
            counts = _Counts()
            note = f"file {i} of {len(files)}"
            _track(tracker, _decoded(path, dns, counts,
                                     lambda n: stage(n, f"{note}, {packets + counts.packets:,} packets")),
                   path, hosts)
            packets += counts.packets
            _logged(path, counts)
        return tracker.finish()
    decoded = in_order(_decode_file, files, workers, dns is not None)
    for i, (path, (packed, file_dns, counts)) in enumerate(decoded, 1):
        if dns is not None:
            _merge_dns(dns, file_dns)
        size, n = os.path.getsize(path), len(packed) // _PACKED.size
        note = f"file {i} of {len(files)}, {packets + counts.packets:,} packets"
        progress = (lambda k: stage(size * k / n, note)) if n else (lambda k: None)
        _track(tracker, counted(_PACKED.iter_unpack(packed), progress, REPORT_EVERY), path, hosts)
        if not n:
            stage(size, note)
        packets += counts.packets
        _logged(path, counts)
    return tracker.finish()
