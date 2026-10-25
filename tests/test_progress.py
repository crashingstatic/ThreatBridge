"""Progress of long jobs (building a case): on a terminal and in the log."""
import io
import logging

import pytest

from evidence import ACK, SYN, tcp, write_pcap
from threatbridge.backends import CaseBackend
from threatbridge.config import Config
from threatbridge.progress import QUIET, Progress, _duration, counted

T = 1_714_564_800.0


class Terminal(io.StringIO):
    def isatty(self):
        return True

    def screen(self):
        """What the terminal shows: each line as it was last redrawn."""
        return [line.rsplit("\r", 1)[-1].rstrip() for line in self.getvalue().split("\n")]


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_an_updating_line_on_a_terminal():
    out, clock = Terminal(), Clock()
    with Progress(out, clock=clock).stage("Reading evidence", 1000) as stage:
        assert out.screen() == ["Reading evidence…"]
        clock.now += 0.1
        stage(100, "file 1 of 4")                       # too soon to redraw
        assert out.screen() == ["Reading evidence…"]
        clock.now += 0.2
        stage(100, "file 1 of 4")
        assert out.screen() == ["Reading evidence: 20%, file 1 of 4"]
        clock.now += 3.7                                # 4 s for 400 of 1000: 6 s to go
        stage(200, "file 2 of 4")
        assert out.screen() == ["Reading evidence: 40%, file 2 of 4, about 6 s left"]
        clock.now += 66
        stage(600)
    assert out.screen() == ["Reading evidence: done in 1 min 10 s (file 2 of 4)", ""]


def test_log_lines_on_a_terminal_start_on_a_clean_line():
    out, clock = Terminal(), Clock()
    handler = logging.StreamHandler(out)
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        with Progress(out, clock=clock).stage("Reading evidence", 10) as stage:
            clock.now += 1
            stage(5)
            logging.getLogger("threatbridge.sources.pcap").warning("cap1.pcap: capture is cut off")
            clock.now += 1
            stage(5)
        logging.getLogger("threatbridge").warning("after")
    finally:
        root.removeHandler(handler)
    assert out.screen() == ["cap1.pcap: capture is cut off", "Reading evidence: done in 2 s", "after", ""]
    assert handler.filters == []


def test_a_log_line_every_interval_elsewhere(caplog):
    caplog.set_level(logging.INFO, logger="threatbridge")
    clock = Clock()
    with Progress(io.StringIO(), interval=10, clock=clock).stage("Saving the flows", 400) as stage:
        for _ in range(4):
            clock.now += 4
            stage(100)
    assert [r.getMessage() for r in caplog.records] == [
        "Saving the flows: 75%, about 4 s left", "Saving the flows: done in 16 s"]   # at 12 s


def test_stages_without_a_total_and_streams_without_a_terminal():
    clock = Clock()
    stage_text = Progress(io.StringIO(), clock=clock).stage("Indexing the flows")
    with stage_text as stage:
        assert stage.describe(clock.now) == "Indexing the flows…"
    closed = io.StringIO()
    closed.close()
    assert Progress(closed).tty is False and Progress(object()).tty is False


@pytest.mark.parametrize("seconds,text", [(0.4, "0 s"), (59.6, "1 min 0 s"), (75, "1 min 15 s"),
                                          (3600, "1 h 0 min"), (3725, "1 h 2 min")])
def test_durations(seconds, text):
    assert _duration(seconds) == text


def test_counted_passes_everything_through():
    seen = []
    assert list(counted(range(7), seen.append, every=3)) == list(range(7))
    assert seen == [3, 3, 1]
    with QUIET.stage("anything", 5) as stage:
        stage(5, "ignored")


def test_building_a_case_shows_each_stage(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    write_pcap(d / "cap.pcap", [(T, tcp("10.0.0.5", "10.0.0.9", 50000, 445, SYN)),
                                (T + 0.001, tcp("10.0.0.9", "10.0.0.5", 445, 50000, SYN | ACK))])
    cfg = Config(backend="case", case_paths=[str(d)], case_db=str(tmp_path / "case.db"))
    out = Terminal()
    CaseBackend(cfg, progress=Progress(out))
    stages = [line.split(":")[0] for line in out.screen() if line]
    assert stages == ["Reading 1 evidence file(s)", "Saving the flows", "Indexing the flows", "Building the graph"]
    assert "Reading 1 evidence file(s): done in 0 s (file 1 of 1, 2 packets)" in out.screen()
    out = Terminal()
    CaseBackend(cfg, progress=Progress(out))                      # reused: only the graph
    assert [line.split(":")[0] for line in out.screen() if line] == ["Building the graph"]
