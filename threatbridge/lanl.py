"""The LANL 2015 data as a case to measure on (item 13, D35).

Kent (2015), "Comprehensive, Multi-Source Cyber-Security Events", Los Alamos National
Laboratory, https://csr.lanl.gov/data/cyber1/ (CC0; download it yourself, the site asks what
it is for). Two of its files:

- flows.txt.gz: time,duration,source computer,source port,destination computer,destination
  port,protocol,packet count,byte count;
- redteam.txt.gz: time,user@domain,source computer,destination computer: the red team's
  logons, the ground truth.

Times are seconds from 1; the calendar is not disclosed, so time 1 is put on a made-up date
(BASE). Computers become stable made-up addresses (address()). Ports de-identified as N<number>
have none. The protocol is read as an IP protocol number (6 TCP, 17 UDP, 1 ICMP); the page
doesn't say so. The flows are read in the order they come, which the examples show is by time,
and reading stops some way past the slice asked for.

The first red-team logon's source, at that time, is the indicator an analyst starts from. Each
host the red team reached from it, in time order through its logons, is a chain: its hops are
those logons (measure.py looks for them in the flows, within a tolerance).

    python -m threatbridge.lanl flows.txt.gz redteam.txt.gz [--hours 6] [--window 24h] [--tolerance 120]
"""
import argparse
import gzip
import hashlib
import os
import sys
import time

from . import measure
from .backends import CaseBackend
from .config import Config
from .model import Flow
from .query import parse_window

BASE = 1_420_070_400.0 - 1          # time 1 = 2015-01-01T00:00:00Z, a made-up date
STOP_AFTER = 600                    # seconds past the slice read before stopping (out-of-order lines)
PROTOCOLS = {"6": "tcp", "17": "udp", "1": "icmp"}


def address(computer):
    """A computer's made-up address: C<n> -> 10.x.y.z from n (n < 2**24); any other name
    (a few are named) -> 172.16.0.0/12 from its SHA-256."""
    if computer.startswith("C") and computer[1:].isdigit() and int(computer[1:]) < 2**24:
        n = int(computer[1:])
        return f"10.{n >> 16}.{(n >> 8) & 255}.{n & 255}"
    h = int.from_bytes(hashlib.sha256(computer.encode()).digest()[:3], "big")       # 24 bits
    return f"172.{16 + (h >> 20)}.{(h >> 12) & 255}.{(h >> 4) & 255}"


def _port(value):
    return int(value) if value.isdigit() else None        # N<number>: de-identified


def _lines(path):
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="ascii", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield line.split(",")


def redteam(path):
    """[(time, user, source computer, destination computer)], by time."""
    return sorted((int(t), user, src, dst) for t, user, src, dst in _lines(path))


def flows(path, lo, hi):
    """The flows that started in [lo, hi] (LANL seconds), as Flows on the made-up calendar."""
    out, name = [], os.path.basename(str(path))
    for row in _lines(path):
        t = int(row[0])
        if t > hi + STOP_AFTER:
            break
        if t < lo or t > hi or len(row) != 9:
            continue
        _, duration, src, sport, dst, dport, proto, packets, nbytes = row
        start = BASE + t
        out.append(Flow(address(src), address(dst), _port(sport), _port(dport), PROTOCOLS.get(proto, proto), start,
                        start + float(duration), int(packets), int(nbytes), name))
    return out


def chains(events):
    """The chains from the first logon's source (module docstring): [measure.Chain]."""
    if not events:
        return []
    t0, _, entry, _ = events[0]
    reached = {entry: (t0, [])}
    for t, _, src, dst in events:
        if src in reached and reached[src][0] <= t and dst not in reached:
            reached[dst] = (t, reached[src][1] + [(src, dst, t)])
    return [measure.Chain(f"{entry} to {dst}", (address(entry), BASE + t0), None,
                          [(address(s), address(d), None, BASE + t) for s, d, t in hops])
            for dst, (_, hops) in sorted(reached.items(), key=lambda item: item[1][0]) if hops]


def summary(results):
    """One Markdown row of totals over [(name, measure())]."""
    def total(method, key="found", of="of"):
        return f"{sum(r[method][key] for _, r in results)}/{sum(r[method][of] for _, r in results)}"
    return ("| Chains | Hops seen in flows | Suspect hops | Path hops | Chains listed | Chain hosts on the line |\n"
            "|---|---|---|---|---|---|\n"
            f"| {len(results)} | {sum(r['seen'] for _, r in results)}/{sum(r['hops'] for _, r in results)} | "
            f"{total('suspects')} | {total('paths')} | {sum(r['paths']['chain'] for _, r in results)}/{len(results)} | "
            f"{total('line')} |")


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m threatbridge.lanl", description=__doc__.split("\n\n")[0])
    p.add_argument("flows", help="flows.txt.gz")
    p.add_argument("redteam", help="redteam.txt.gz")
    p.add_argument("--hours", type=float, default=6, help="the slice read, from the first red-team logon (default 6)")
    p.add_argument("--before", type=float, default=1, help="hours read before it (default 1)")
    p.add_argument("--window", default="24h", help="the Window between hops (default 24h)")
    p.add_argument("--tolerance", type=float, default=120, help="seconds between a logon and its flow (default 120)")
    p.add_argument("--details", action="store_true", help="a row for each chain too")
    a = p.parse_args(argv)
    events = redteam(a.redteam)
    if not events:
        p.exit(2, "error: no red-team logons\n")
    lo, hi = events[0][0] - a.before * 3600, events[0][0] + a.hours * 3600
    events = [e for e in events if e[0] <= hi]
    clock = time.monotonic()
    found = flows(a.flows, lo, hi)
    read = time.monotonic() - clock
    case = CaseBackend(Config(backend="case"), flows=found)
    window = parse_window(a.window)
    cache = {}
    results = [(c.name, measure.measure(case, c, window=window, tolerance=a.tolerance, cache=cache))
               for c in chains(events)]
    print(f"LANL 2015: {len(found)} flows from time {int(lo)} to {int(hi)} (read in {read:.0f} s), "
          f"{len(events)} red-team logons, window {a.window}, tolerance {a.tolerance:g} s\n")
    print(summary(results))
    if a.details:
        print("\n" + measure.table(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
