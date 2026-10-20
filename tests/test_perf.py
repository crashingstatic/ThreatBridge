"""PRF-1 / PRF-2: at least 1M flows, case built within 5 minutes for under 100 MB.

Slow (about a minute), so opt-in: TB_PERF=1 python -m pytest -s tests/test_perf.py
"""
import os
import time

import pytest

from evidence import write_bulk_pcap
from threatbridge.backends import CaseBackend
from threatbridge.config import Config

N = 1_250_000  # ~97 MB of minimum-size packets, one flow each


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
    print(f"\n{N} flows, {path.stat().st_size / 2**20:.0f} MB: built in {built:.0f}s, "
          f"reopened in {reopened:.0f}s")
    assert backend.summary()["flows"] == N
    assert built < 300
