"""Read nfcapd files (NetFlow/IPFIX collected by nfdump) into connection flows.

Records are read with the nfdump binary. NetFlow records are one-way, so the two halves of a
connection are merged into one flow and oriented initiator -> responder.
"""
import ipaddress
import logging
import os
import socket
import subprocess
import tempfile

from .. import protocols
from ..model import SourceError, icmp_flags, idle_timeout, oriented, proto_name, refused, settle
from .workers import in_order

log = logging.getLogger(__name__)

# `nfdump -o pipe`, as printed by nfdump 1.7.3 (the only version tested):
#   af|first_ms|last_ms|proto|src x4|sport|dst x4|dport|src_as|dst_as|in_if|out_if|flags|tos|packets|bytes
# Addresses are four 32-bit integers, so IPv6 is never abbreviated (the "fmt:" output truncates
# it), and times are epoch milliseconds, unaffected by the local time zone (unlike "csv").
PIPE_FIELDS = 22


def _address(af, words):
    if af == socket.AF_INET:
        return str(ipaddress.IPv4Address(int(words[3])))
    if af == socket.AF_INET6:
        value = 0
        for w in words:
            value = (value << 32) | int(w)
        return str(ipaddress.IPv6Address(value))
    raise ValueError(f"unknown address family {af}")


def parse_pipe_line(line):
    """One `nfdump -o pipe` line -> (start, end, proto, src, sport, dst, dport, packets, bytes,
    TCP flags). An ICMP record has no ports; its type (nfdump prints type * 256 + code as the
    destination port) gives its flags (see model.icmp_flags)."""
    f = line.split("|")
    if len(f) != PIPE_FIELDS:
        raise SourceError(f"unexpected nfdump output ({len(f)} fields, expected {PIPE_FIELDS}); "
                          "tested with nfdump 1.7.3")
    try:
        af, number = int(f[0]), int(f[3])
        proto = proto_name(number)
        if proto == "icmp":
            sport, dport, flags = 0, 0, icmp_flags(number, int(f[13]) >> 8)
        else:
            sport, dport, flags = int(f[8]), int(f[13]), int(f[18])
        return (int(f[1]) / 1000.0, int(f[2]) / 1000.0, proto, _address(af, f[4:8]), sport,
                _address(af, f[9:13]), dport, int(f[20]), int(f[21]), flags)
    except ValueError as e:
        raise SourceError(f"unexpected nfdump output ({e}); tested with nfdump 1.7.3")


def read_records(path):
    """Yield parsed records from one nfcapd file."""
    cmd = [os.environ.get("TB_NFDUMP", "nfdump"), "-q", "-o", "pipe", "-r", path]
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
                    yield parse_pipe_line(line)
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
        start, end, proto, src, sport, dst, dport, packets, nbytes, flags, source = rec
        key = (proto, src, sport, dst, dport) if (src, sport) <= (dst, dport) \
            else (proto, dst, dport, src, sport)
        conn = open_.get(key)
        if conn is not None and start > conn.last + idle_timeout(proto):
            close(open_.pop(key))
            conn = None
        if conn is None:
            conn = open_[key] = _Conn(rec, source)
        if (src, sport) == (conn.orig, conn.oport):
            conn.oflags |= flags
        else:
            if not conn.reverse_seen and start == conn.start:
                conn.tie = True
            conn.reverse_seen = True
            conn.rflags |= flags
        conn.packets += packets
        conn.bytes += nbytes
        if end > conn.last:
            conn.last = end
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
