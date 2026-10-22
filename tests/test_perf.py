"""PRF-1 / PRF-2: at least 1M flows, case built within 5 minutes for under 100 MB.
PRF-3: on an office-like week of traffic, the queries an analyst waits on stay fast.

Slow, so opt-in: TB_PERF=1 python -m pytest -s tests/test_perf.py
"""
import os
import random
import resource
import time
from datetime import datetime, timedelta, timezone

import pytest

from evidence import write_bulk_pcap
from threatbridge.backends import CaseBackend
from threatbridge.config import Config
from threatbridge.model import Flow

N = 1_250_000  # 93 MiB of minimum-size packets, one flow each


@pytest.mark.skipif(os.environ.get("TB_PERF") != "1", reason="set TB_PERF=1 to run")
def test_million_flows_under_five_minutes(tmp_path):
    path = tmp_path / "bulk.pcap"
    write_bulk_pcap(path, N)
    assert path.stat().st_size < 100 * 2**20
    cfg = Config(backend="case", case_paths=[str(path)], case_db=str(tmp_path / "case.db"))
    t = time.monotonic()
    backend = CaseBackend(cfg)
    built = time.monotonic() - t
    t = time.monotonic()
    CaseBackend(cfg)
    reopened = time.monotonic() - t
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024     # this process so far
    print(f"\n{N} flows, {path.stat().st_size / 2**20:.0f} MiB: built in {built:.0f}s, "
          f"reopened in {reopened:.0f}s, peak memory {peak:.0f} MiB")
    assert backend.summary()["flows"] == N
    assert built < 300


def busy_week(n=1_000_000, seed=3):
    """Office-like traffic over a week: 2,000 workstations and 500 outside hosts. Most flows go
    to a few servers (DC, DNS, proxy); one workstation-to-server pair carries 100k flows."""
    rng = random.Random(seed)
    t0, week = 1_714_564_800.0, 7 * 86400.0
    ws = [f"10.1.{i // 250}.{i % 250 + 1}" for i in range(2000)]
    outside = [f"203.0.{i // 250}.{i % 250 + 1}" for i in range(500)]
    servers = {"10.0.0.1": 88, "10.0.0.53": 53, "10.0.0.80": 3128}
    flows = []
    for i in range(n):
        t = t0 + rng.random() * week
        r = rng.random()
        if i < 100_000:
            src, dst, port = "10.1.0.7", "10.0.0.80", 3128
        elif r < 0.6:
            src, (dst, port) = rng.choice(ws), rng.choice(list(servers.items()))
        elif r < 0.85:
            src, dst, port = rng.choice(ws), rng.choice(ws), rng.choice([445, 3389, 135, 5985])
        elif r < 0.95:
            src, dst, port = "10.0.0.80", rng.choice(outside), 443
        else:
            src, dst, port = rng.choice(outside), rng.choice(ws), rng.choice([443, 22])
        flows.append(Flow(src, dst, 40000 + i % 20000, port, "tcp", t, t + 1, 4, 400, "synthetic"))
    return flows


@pytest.mark.skipif(os.environ.get("TB_PERF") != "1", reason="set TB_PERF=1 to run")
def test_interactive_queries_stay_fast_on_a_busy_case():
    # PRF-3: hubs and a 100k-flow connection are where a search can blow up.
    backend = CaseBackend(Config(backend="case"), flows=busy_week())
    g = backend.graph
    start, end = backend.span
    day = timedelta(days=1)
    busiest = max(g.nodes, key=g.degree)
    a, b = max(g.edges, key=lambda e: len(g.edges[e]["times"]))
    first = datetime.fromtimestamp(g[a][b]["times"][0], timezone.utc)
    last = datetime.fromtimestamp(g[a][b]["times"][-1], timezone.utc)
    busy = sorted(g.nodes, key=lambda h: -g.degree(h))[:10]
    timings = {}

    def timed(name, call):
        t = time.monotonic()
        result = call()
        timings[name] = time.monotonic() - t
        return result
    timed("expand busiest host", lambda: backend.neighbors(busiest, "in", start, end, 50, "top", []))
    timed("expand rarest", lambda: backend.neighbors(busiest, "out", start, end, 50, "bottom", []))
    timed("flow list, last page", lambda: backend.flows(a, b, start, end, 99_950, 50))
    line = timed("threat line, busiest connection", lambda: backend.threat_line(a, b, first, last, day, 6, [], 300))
    pairs = timed("attack paths, 10 busy hosts", lambda: backend.attack_paths(
        {h: None for h in busy}, day, 6, [], max_paths=10))
    middle = start.timestamp() + (end - start).total_seconds() / 2
    timed("attack paths, 10 busy hosts with IOC times", lambda: backend.attack_paths(
        {h: middle + i * 3600 for i, h in enumerate(busy)}, day, 6, [], max_paths=10))
    between = timed("paths between two busy hosts", lambda: backend.paths_between(
        busy[0], busy[1], None, None, day, 6, [], max_paths=500))
    print("\n" + "  ".join(f"{k}: {v:.2f}s" for k, v in timings.items()))
    # The searches did real work...
    assert line["truncated"] and len(line["nodes"]) > 300
    assert pairs["pairs"] and between["paths"]
    # ...and still answered quickly: within 3 s for what the analyst waits on. Attack paths
    # between every pair of marked hosts are recomputed in the background after each change
    # (the map stays usable); with the ten busiest servers all marked it may take longer.
    background = {k: v for k, v in timings.items() if k.startswith("attack paths")}
    interactive = {k: v for k, v in timings.items() if k not in background}
    assert max(interactive.values()) < 3, interactive
    assert max(background.values()) < 10, background
