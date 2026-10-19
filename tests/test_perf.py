"""PRF-1 / PRF-2: at least 1M flows, graph built within 5 minutes for under 100 MB.

Slow (about a minute), so opt-in: TB_PERF=1 python -m pytest tests/test_perf.py
"""
import os
import time

import pytest

from evidence import write_bulk_pcap
from threatbridge import sources
from threatbridge.graph import build_graph

N = 1_250_000  # ~97 MB of minimum-size packets, one flow each


@pytest.mark.skipif(os.environ.get("TB_PERF") != "1", reason="set TB_PERF=1 to run")
def test_million_flows_under_five_minutes(tmp_path):
    path = tmp_path / "bulk.pcap"
    write_bulk_pcap(path, N)
    assert path.stat().st_size < 100 * 2**20
    t = time.monotonic()
    g = build_graph(sources.load([str(path)]))
    elapsed = time.monotonic() - t
    print(f"\n{N} flows, {path.stat().st_size / 2**20:.0f} MB: graph built in {elapsed:.0f}s")
    assert g.number_of_edges() == N
    assert elapsed < 300
