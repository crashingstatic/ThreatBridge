"""Read tcpdump captures (classic pcap format) into connection flows."""
import logging
import os
import socket
import struct

import dpkt

from .. import protocols
from ..model import SourceError, icmp_flags, idle_timeout, oriented, proto_name, refused, settle
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
    """A connection being followed. `orig` is the side seen first in the capture; who started
    it is settled when it closes (flows)."""
    __slots__ = ("orig", "oport", "resp", "rport", "proto", "start", "last", "packets",
                 "bytes", "source", "closing", "first_flags", "other_flags", "time_flip",
                 "oall", "rall", "code", "ftp")

    def __init__(self, orig, oport, resp, rport, proto, ts, source, flags):
        self.orig, self.oport, self.resp, self.rport = orig, oport, resp, rport
        self.proto, self.start, self.last, self.source = proto, ts, ts, source
        self.packets = self.bytes = 0
        self.closing = False
        # Each side's first packet's flags (None: the other side not seen yet), and what time
        # says about who started it (None: it can't, or can't yet).
        self.first_flags, self.other_flags, self.time_flip = flags, None, None
        self.oall = self.rall = 0          # all of each side's flags, ORed together
        self.code = 0                      # the protocol the first recognized payload showed
        self.ftp = None                    # FTP control messages seen (see FlowTracker._ftp)

    def answer(self, ts, flags):
        """The other side's first packet, at `ts` with `flags`. If it came at another time than
        the first side's, time tells who started the connection: the side seen first."""
        self.other_flags = flags
        if ts != self.start:
            self.time_flip = ts < self.start

    def flows(self):
        """As flows (see model.oriented); none if it was refused. When time didn't tell who
        started it, the first packets' flags, then the ports, decide."""
        if refused(self.oall, self.rall):
            return []
        flip = self.time_flip if self.time_flip is not None else \
            settle(self.first_flags, self.other_flags, self.oport, self.rport, packets=True)
        server, client = (self.oport, self.rport) if flip else (self.rport, self.oport)
        return oriented(flip, self.orig, self.oport, self.resp, self.rport, self.proto,
                        self.start, self.last, self.packets, self.bytes, self.source,
                        protocols.name(self.proto, self.code, server, client))


def _ftp_port_side(conn):
    """The side of `conn` on an FTP port (21, 2811), if exactly one is."""
    o, r = conn.oport in protocols.FTP_PORTS, conn.rport in protocols.FTP_PORTS
    if o == r:
        return None
    return (conn.orig, conn.oport) if o else (conn.resp, conn.rport)


# Data connections FTP control connections may announce at once, as Zeek caps them
# (FTP::max_expected_data_channels).
MAX_EXPECTED = 100_000


class FlowTracker:
    """Groups packets into connections, keyed by protocol and both endpoints.

    A connection ends after its idle timeout, on a TCP RST, or when a new SYN arrives after
    a FIN. Who started it is decided by time, then flags, then ports (see _Conn). Refused
    connections are counted, not kept.

    FTP data connections are named FTP as Zeek names them: an FTP control connection
    announces one (PORT/EPRT, or a 227/229 reply), and the first connection to the announced
    address and port from the expected side within FTP_DATA_WAIT is it.
    """

    def __init__(self):
        self.open = {}
        self.flows = []
        self.refused = 0
        self.now = 0.0
        self.next_sweep = 0.0
        self.expected = {}   # (host, port) -> (who connects to it, until when): FTP data

    def add(self, ts, src, dst, proto, sport, dport, nbytes, flags, source, code=0, note=None):
        """One packet: its connection (a new one after the idle timeout, or a SYN after a FIN)
        takes its protocol code (or FTP message), flags, size and time."""
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
            if self.expected and proto == "tcp" and self._announced(ts, src, sport, dst, dport):
                conn.code = protocols.FTP
        if code >= protocols.FTP_GREETING:
            self._ftp(conn, ts, src, sport, code, note)
        elif code and not conn.code:
            conn.code = code
        if (src, sport) == (conn.orig, conn.oport):
            conn.oall |= flags
        else:
            conn.rall |= flags
            if conn.other_flags is None:
                conn.answer(ts, flags)
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
        """Close the idle connections, and forget the FTP announcements past their time."""
        idle = [k for k, c in self.open.items() if self.now - c.last > idle_timeout(c.proto)]
        for key in idle:
            self._close(key)
        for spot in [k for k, (_, until) in self.expected.items() if until < self.now]:
            del self.expected[spot]

    def _ftp(self, conn, ts, src, sport, code, note):
        """An FTP control message from (src, sport) on `conn`. The control connection is one on
        an FTP port, or one where a side greeted (120/220) and answered a login (230/331) and
        the other sent USER (Zeek's signature). Its client's PORT/EPRT and its server's 227/229
        announce a data connection."""
        side = (src, sport)
        state = conn.ftp = conn.ftp or {}
        if code in (protocols.FTP_GREETING, protocols.FTP_LOGIN, protocols.FTP_USER):
            state.setdefault(code, side)
            server = state.get(protocols.FTP_GREETING)
            if server and state.get(protocols.FTP_LOGIN) == server and \
                    state.get(protocols.FTP_USER) not in (None, server):
                state["server"] = server
                conn.code = conn.code or protocols.FTP
            return
        server = state.get("server") or _ftp_port_side(conn)
        if server is None:
            return
        client = (conn.resp, conn.rport) if server == (conn.orig, conn.oport) else (conn.orig, conn.oport)
        host, port = note
        if code == protocols.FTP_PORT and side == client:       # the server connects to it
            self._expect(host, port, server[0], ts)
        elif code == protocols.FTP_PASV and side == server:     # the client connects to it
            self._expect(host or server[0], port, client[0], ts)

    def _expect(self, host, port, by, ts):
        if (host, port) in self.expected or len(self.expected) < MAX_EXPECTED:
            self.expected[(host, port)] = (by, ts + protocols.FTP_DATA_WAIT)

    def _announced(self, ts, src, sport, dst, dport):
        """Whether a new connection is an announced FTP data connection, its first packet
        seen either way; an announcement is used once."""
        for spot, by in (((dst, dport), src), ((src, sport), dst)):
            hit = self.expected.get(spot)
            if hit and hit[0] == by and ts <= hit[1]:
                del self.expected[spot]
                return True
        return False

    def _close(self, key):
        flows = self.open.pop(key).flows()
        self.flows.extend(flows)
        self.refused += not flows

    def finish(self):
        for key in list(self.open):
            self._close(key)
        if self.refused:
            log.info("%d refused connection(s) left out", self.refused)
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
    _merge_dns(dns, {name: {ip: (ts, ts) for ip in ips} for name in names})


REPORT_EVERY = 4096   # packets between progress reports


def _decoded(path, dns, counts, report=None, notes=None):
    """The IP packets of one capture as (ts, IP version, IP protocol, src, dst, sport, dport,
    IP-layer bytes, TCP flags, protocol code), with the addresses as packed bytes. DNS answers
    over UDP go into `dns` unless it is None. A data connection an FTP control message
    announces goes into `notes` as {packet's index: (host, port)}. `report` is called with the
    bytes read since its last call."""
    with open(path, "rb") as fh:
        reader = _open(fh, path)
        decode = _DECODERS.get(reader.datalink())
        if decode is None:
            raise SourceError(f"{path}: unsupported link type {reader.datalink()}")
        offset, index = 0, 0
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
            sized = _ip_size(ip)
            if sized is None:
                continue
            version, nbytes = sized
            t = ip.data
            code = 0
            if isinstance(t, dpkt.tcp.TCP):
                sport, dport, flags = t.sport, t.dport, t.flags
                code = protocols.from_payload(True, sport, dport, t.data)
                if not code:
                    signal = protocols.ftp_signal(t.data)
                    if signal:
                        code = signal[0]
                        if signal[2] is not None and notes is not None:
                            notes[index] = signal[1:]
            elif isinstance(t, dpkt.udp.UDP):
                sport, dport, flags = t.sport, t.dport, 0
                code = protocols.from_payload(False, sport, dport, t.data)
                if sport == 53 and dns is not None:
                    record_dns(t.data, ts, dns)
            elif ip.p in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
                # Header cut short by the snap length: the ports are its first 4 bytes.
                if len(t) < 4:
                    counts.skipped += 1
                    continue
                sport, dport = struct.unpack("!HH", t[:4])
                flags = t[13] if ip.p == dpkt.ip.IP_PROTO_TCP and len(t) > 13 else 0
            elif isinstance(t, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
                sport, dport, flags = 0, 0, icmp_flags(ip.p, t.type)
            else:
                sport = dport = flags = 0
            yield ts, version, ip.p, ip.src, ip.dst, sport, dport, nbytes, flags, code
            index += 1
        if report:
            report(fh.tell() - offset)


def _ip_size(ip):
    """(IP version, IP-layer bytes) of a decoded frame; None for one that isn't IP (ARP, ...)
    or is a later fragment, which has no ports (only the first fragment is counted)."""
    if isinstance(ip, dpkt.ip.IP):
        return None if ip.offset else (4, ip.len or len(ip))
    if isinstance(ip, dpkt.ip6.IP6):
        frag = getattr(ip, "extension_hdrs", {}).get(dpkt.ip.IP_PROTO_FRAGMENT)
        return None if frag is not None and frag.frag_off else (6, ip.plen + 40)
    return None


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


def _track(tracker, packets, path, hosts, notes):
    for i, (ts, version, p, src, dst, sport, dport, nbytes, flags, code) in enumerate(packets):
        tracker.add(ts, hosts(version, src), hosts(version, dst), proto_name(p), sport, dport,
                    nbytes, flags, path, code, notes.get(i) if notes else None)


def _logged(path, counts):
    if counts.cut_off:
        log.warning("%s: capture is cut off after its last whole packet", path)
    log.info("%s: %d packets, %d undecodable", path, counts.packets, counts.skipped)


# A decoded packet as worker processes pass it back (see _decoded): addresses in 16 bytes,
# an IPv4 address in the first 4; the last byte is the payload's protocol code, or what an
# FTP control message says (its announcement, if any, is kept apart: _decode_file's notes).
_PACKED = struct.Struct("<dBB16s16sHHIBB")


def _decode_file(path, want_dns):
    """In a worker process: one capture's packets, packed, with its DNS answers, the FTP data
    connections announced in it, and counts."""
    dns = {} if want_dns else None
    counts, notes = _Counts(), {}
    packed = bytearray()
    for packet in _decoded(path, dns, counts, notes=notes):
        packed += _PACKED.pack(*packet)
    return packed, dns, counts, notes


def _merge_dns(dns, more):
    """Add `more` ({name: {ip: (first, last)}}) to `dns`, widening the times already there."""
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
    if workers <= 1 or len(files) <= 1:        # decoded and followed as they are read, unpacked
        for i, path in enumerate(files, 1):
            counts, notes = _Counts(), {}
            note = f"file {i} of {len(files)}"
            _track(tracker, _decoded(path, dns, counts,
                                     lambda n: stage(n, f"{note}, {packets + counts.packets:,} packets"),
                                     notes),
                   path, hosts, notes)
            packets += counts.packets
            _logged(path, counts)
        return tracker.finish()
    decoded = in_order(_decode_file, files, workers, dns is not None)
    for i, (path, (packed, file_dns, counts, notes)) in enumerate(decoded, 1):
        if dns is not None:
            _merge_dns(dns, file_dns)
        size, n = os.path.getsize(path), len(packed) // _PACKED.size
        note = f"file {i} of {len(files)}, {packets + counts.packets:,} packets"
        progress = (lambda k: stage(size * k / n, note)) if n else (lambda k: None)
        _track(tracker, counted(_PACKED.iter_unpack(packed), progress, REPORT_EVERY), path, hosts,
               notes)
        if not n:
            stage(size, note)
        packets += counts.packets
        _logged(path, counts)
    return tracker.finish()
