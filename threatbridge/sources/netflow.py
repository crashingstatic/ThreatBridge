"""Read nfcapd files (NetFlow/IPFIX collected by nfdump) into connection flows.

Records are read with the nfdump binary. NetFlow records are one-way, so the two halves of a
connection are merged into one flow and oriented initiator -> responder.
"""
import ipaddress
import logging
import os
import subprocess
import tempfile

from .. import protocols
from ..model import SourceError, icmp_flags, idle_timeout, oriented, proto_name, refused, settle
from .workers import in_order

log = logging.getLogger(__name__)

# nfdump's custom output format: start|end|proto|src|sport|dst|dport|TCP flags|packets|bytes,
# each padded with spaces. Times are epoch seconds, unaffected by the local time zone (unlike
# "csv" and "json"); -N prints plain numbers (protocol, packets, bytes); -6 prints IPv6
# addresses in full (otherwise they are shortened, losing digits). "-o pipe", read before, is
# not in nfdump 1.7.6.
FORMAT = "fmt:%tsr|%ter|%pr|%sa|%sp|%da|%dp|%flg|%pkt|%byt"
FIELDS = FORMAT.count("|") + 1
TESTED = "tested with nfdump 1.7.3 and 1.7.6"
TCP_FLAG_LETTERS = "CEUAPRSF"      # bits 7 to 0, as nfdump prints them ("." for a flag not set)


def _tcp_flags(text):
    """TCP flags as nfdump prints them: a number (1.7.9 with -N) or TCP_FLAG_LETTERS, with "."
    for each flag not set (1.7.3 and 1.7.6; all dots for a record that isn't TCP)."""
    if text.isdigit():
        return int(text)
    if len(text) != 8 or any(c not in (letter, ".") for c, letter in zip(text, TCP_FLAG_LETTERS)):
        raise ValueError(f"TCP flags {text!r}")
    return sum(1 << (7 - i) for i, c in enumerate(text) if c != ".")


def parse_line(line):
    """One line of nfdump FORMAT output -> (start, end, proto, src, sport, dst, dport, packets,
    bytes, TCP flags). An ICMP record has no ports; nfdump prints "type.code" as its destination
    port, and the type gives its flags (see model.icmp_flags)."""
    f = [field.strip() for field in line.split("|")]
    if len(f) != FIELDS:
        raise SourceError(f"unexpected nfdump output ({len(f)} fields, expected {FIELDS}); {TESTED}")
    try:
        number = int(f[2])
        proto = proto_name(number)
        if proto == "icmp":
            sport, dport, flags = 0, 0, icmp_flags(number, int(f[6].partition(".")[0]))
        else:
            sport, dport, flags = int(f[4]), int(f[6]), _tcp_flags(f[7])
        return (float(f[0]), float(f[1]), proto, str(ipaddress.ip_address(f[3])), sport,
                str(ipaddress.ip_address(f[5])), dport, int(f[8]), int(f[9]), flags)
    except ValueError as e:
        raise SourceError(f"unexpected nfdump output ({e}); {TESTED}")


def read_records(path):
    """Yield parsed records from one nfcapd file."""
    cmd = [os.environ.get("TB_NFDUMP", "nfdump"), "-q", "-N", "-6", "-o", FORMAT, "-r", path]
    with tempfile.TemporaryFile() as err:
        try:
            # Argument list, no shell: the path is never interpreted.
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err, text=True)
        except FileNotFoundError:
            raise SourceError("nfdump not found: install nfdump (or set TB_NFDUMP) to read nfcapd files")
        try:
            for line in proc.stdout:
                line = line.strip()
                if line:
                    yield parse_line(line)
        except BaseException:  # parse error, or the caller stopped reading
            proc.kill()
            proc.wait()
            raise
        finally:
            proc.stdout.close()
        rc = proc.wait()
        if rc != 0:
            err.seek(0)
            msg = err.read().decode(errors="replace").strip().splitlines()
            raise SourceError(f"{path}: nfdump failed: {msg[-1] if msg else f'exit {rc}'}")


class _Conn:
    __slots__ = ("orig", "oport", "resp", "rport", "proto", "start", "last", "packets",
                 "bytes", "source", "reverse_seen", "tie", "oflags", "rflags")

    def __init__(self, record, source):
        start, end, proto, src, sport, dst, dport = record[:7]
        self.orig, self.oport, self.resp, self.rport = src, sport, dst, dport
        self.proto, self.start, self.last, self.source = proto, start, end, source
        self.packets = self.bytes = 0
        self.reverse_seen = self.tie = False
        self.oflags = self.rflags = 0      # each half's TCP flags, ORed together (0: not seen)

    def see(self, record):
        """Count one of its records, from either side."""
        start, end, _, src, sport, _, _, packets, nbytes, flags = record[:10]
        if (src, sport) == (self.orig, self.oport):
            self.oflags |= flags
        else:
            self.tie = self.tie or (not self.reverse_seen and start == self.start)
            self.reverse_seen = True
            self.rflags |= flags
        self.packets += packets
        self.bytes += nbytes
        self.last = max(self.last, end)

    def flows(self):
        """As flows (see model.oriented); none if it was refused. Time decides who started the
        connection when both halves were recorded and one started first: records are taken in
        start order, so this one. Otherwise (both started in the same millisecond, or one half
        alone) the flags, then the ports."""
        if refused(self.oflags, self.rflags):
            return []
        flip = False if self.reverse_seen and not self.tie else settle(self.oflags, self.rflags, self.oport, self.rport)
        server, client = (self.oport, self.rport) if flip else (self.rport, self.oport)
        return oriented(flip, self.orig, self.oport, self.resp, self.rport, self.proto,
                        self.start, self.last, self.packets, self.bytes, self.source,
                        protocols.name(self.proto, 0, server, client))   # no payload: by port


def pair_records(records):
    """Merge one-way records (start, end, proto, src, sport, dst, dport, packets, bytes, TCP
    flags, source) into connections. Records of the same endpoints (either way round) closer
    together than the idle timeout belong to one connection; that also rejoins long
    connections split by the exporter."""
    flows, open_, left_out = [], {}, 0

    def close(conn):
        nonlocal left_out
        out = conn.flows()
        flows.extend(out)
        left_out += not out             # refused

    for rec in sorted(records, key=lambda r: r[0]):
        start, _, proto, src, sport, dst, dport, *_, source = rec
        key = (proto, src, sport, dst, dport) if (src, sport) <= (dst, dport) \
            else (proto, dst, dport, src, sport)
        conn = open_.get(key)
        if conn is not None and start > conn.last + idle_timeout(proto):
            close(open_.pop(key))
            conn = None
        if conn is None:
            conn = open_[key] = _Conn(rec, source)
        conn.see(rec)
    for c in open_.values():
        close(c)
    if left_out:
        log.info("%d refused connection(s) left out", left_out)
    return flows


def _file_records(path):
    """One nfcapd file's records, each with the file it came from (run in a worker process)."""
    return [r + (path,) for r in read_records(path)]


def read_nfcapd(paths, workers=1, stage=None):
    """Connections from nfcapd files: up to `workers` files are read at once, each by its own
    nfdump. `stage` (see progress.py) is told the bytes read."""
    stage = stage or (lambda amount=0, note=None: None)
    files = sorted(paths)
    records = []
    for i, (path, found) in enumerate(in_order(_file_records, files, workers), 1):
        records.extend(found)
        log.info("%s: %d records", path, len(found))
        stage(os.path.getsize(path), f"file {i} of {len(files)}, {len(records):,} records")
    return pair_records(records)
