"""Progress of long jobs (building a case): on a terminal and in the log."""
import io
import logging
import os
import sys

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
        """What the terminal shows: a carriage return goes back to the start of the line, and
        what follows overwrites it character by character."""
        lines = []
        for line in self.getvalue().split("\n"):
            cells, col = [], 0
            for ch in line:
                if ch == "\r":
                    col = 0
                    continue
                if col == len(cells):
                    cells.append(ch)
                else:
                    cells[col] = ch
                col += 1
            lines.append("".join(cells).rstrip())
        return lines


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Ticking(Clock):
    """A second passes every time anyone looks: every update is drawn."""

    def __call__(self):
        self.now += 1
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


class NarrowTerminal(Terminal):
    def fileno(self):
        return 2


def test_an_updating_line_is_cut_to_the_terminal_width(monkeypatch):
    sizes = [40]
    monkeypatch.setattr(os, "get_terminal_size", lambda fd: os.terminal_size((sizes[0], 24)))
    out, clock = NarrowTerminal(), Clock()
    with Progress(out, clock=clock).stage("Reading 8 evidence file(s)", 1000) as stage:
        clock.now += 3
        stage(410, "file 4 of 8, 612,330 packets")
        assert out.screen() == ["Reading 8 evidence file(s): 41%, file …"]      # 39 of 40 columns
        sizes[0] = 30                                  # narrowed: the old line's tail is off-screen
        clock.now += 1
        stage(10)
        assert out.screen()[0][:29] == "Reading 8 evidence file(s): …"
        assert out.getvalue().endswith("\rReading 8 evidence file(s): …")          # no padding past 29
    # The last line is kept whole: a new line follows it, so it may wrap.
    assert out.screen() == ["Reading 8 evidence file(s): done in 4 s (file 4 of 8, 612,330 packets)", ""]
    assert Progress(NarrowTerminal()).columns() == 30
    assert Progress(io.StringIO()).columns() == 80 and Progress(object()).columns() == 80


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


def test_redraws_and_log_lines_at_exactly_the_interval(caplog):
    caplog.set_level(logging.INFO, logger="threatbridge")
    out, clock = Terminal(), Clock()
    with Progress(out, clock=clock).stage("Reading", 10) as stage:
        clock.now += 0.25
        stage(1)
        assert out.screen() == ["Reading: 10%"]
    clock = Clock()
    with Progress(io.StringIO(), interval=10, clock=clock).stage("Saving", 10) as stage:
        clock.now += 10
        stage(5)
    assert [r.getMessage() for r in caplog.records][0] == "Saving: 50%, about 10 s left"


def test_percentages_and_the_time_left():
    clock = Clock()
    with Progress(io.StringIO(), clock=clock).stage("Reading", 101) as stage:
        stage.done = 1
        assert stage.describe(clock.now) == "Reading: 0%"                # 0.99%: rounded down
        stage.done = 120                                                 # more than expected
        assert stage.describe(clock.now) == "Reading: 100%"
        stage.done = 50
        assert stage.describe(clock.now + 1.99) == "Reading: 49%"         # too early to guess
        assert stage.describe(clock.now + 2) == "Reading: 49%, about 2 s left"
    assert Progress().stream is sys.stderr


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
    CaseBackend(cfg, progress=Progress(out, clock=Ticking()))
    for done in ("Reading 1 evidence file(s): 100%", "Saving the flows: 100%", "Building the graph: 100%"):
        assert done in out.getvalue(), done                         # each stage counted to its total
    stages = [line.split(":")[0] for line in out.screen() if line]
    assert stages == ["Reading 1 evidence file(s)", "Saving the flows", "Indexing the flows", "Building the graph"]
    assert "Reading 1 evidence file(s): done in 2 s (file 1 of 1, 2 packets)" in out.screen()
    out = Terminal()
    CaseBackend(cfg, progress=Progress(out))                      # reused: only the graph
    assert [line.split(":")[0] for line in out.screen() if line] == ["Building the graph"]
