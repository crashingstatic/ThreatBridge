"""Tasks projected to take more than 5 minutes ask first, with an estimate (owner, 2026-11-25;
D37): building a case, projected from its first 10 seconds of reading; hashing the evidence
for a report (test_hashing.py)."""
import io
import logging

import pytest

from threatbridge import app as app_mod
from threatbridge import backends
from threatbridge.backends import CaseBackend, Stopped
from threatbridge.config import Config


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def projected(confirm, total=1000):
    """A CaseBackend's reading check on a fake stage and clock (no evidence read)."""
    backend = CaseBackend.__new__(CaseBackend)
    backend.confirm = confirm
    told, clock = [], Clock()
    check = backend._projected(lambda amount=0, note=None: told.append(amount), total, clock)
    return check, clock, told


def test_a_long_build_asks_once_with_the_time_left():
    asked = []
    check, clock, told = projected(lambda seconds: asked.append(seconds) or True)
    clock.now = 5
    check(5)                                   # under 10 s: too early to tell
    assert asked == []
    clock.now = 10
    check(5)                                   # 10 of 1000 bytes in 10 s: 1000 s to read, 1700 s in all
    assert asked == [pytest.approx(1690)] and told == [5, 5]
    clock.now = 20
    check(10)
    assert len(asked) == 1                     # once


def test_saying_no_stops_the_build():
    check, clock, _ = projected(lambda seconds: False)
    clock.now = 10
    with pytest.raises(Stopped, match="about 28 min 10 s more"):
        check(10)


def test_a_short_build_doesnt_ask():
    asked = []
    check, clock, _ = projected(lambda seconds: asked.append(seconds) or True)
    clock.now = 10
    check(600)                                 # 600 of 1000 in 10 s: about 28 s in all
    assert asked == []


def test_without_anyone_to_ask_it_warns(caplog):
    check, clock, _ = projected(None)
    caplog.set_level(logging.WARNING)
    clock.now = 10
    check(10)
    assert "building the case will take about 28 min 10 s more" in caplog.text


def test_the_question_on_a_terminal():
    out = io.StringIO()
    prompts = []

    def read(prompt):
        prompts.append(prompt)
        return answers.pop(0)
    answers = ["y", "", "no", " YES "]
    results = [app_mod.ask_to_wait(1500, out, read, interactive=True) for _ in range(4)]
    assert results == [True, False, False, True]
    assert prompts[0] == "Building the case will take about 25 min 0 s more. Continue? [y/N] "
    assert app_mod.ask_to_wait(1500, out, read, interactive=False) is True     # a service: no one to ask


def test_a_real_build_passes_the_projection_through(tmp_path, monkeypatch):
    from evidence import ACK, SYN, tcp, write_pcap
    write_pcap(tmp_path / "cap.pcap", [(1714564800.0, tcp("10.0.0.5", "10.0.0.9", 40000, 445, SYN)),
                                       (1714564800.001, tcp("10.0.0.9", "10.0.0.5", 445, 40000, SYN | ACK))])
    monkeypatch.setattr(backends, "CHECK_AFTER", 0.0)        # check at the first bytes read
    monkeypatch.setattr(backends, "LONG_TASK", -1.0)         # and call anything long
    asked = []
    case = CaseBackend(Config(backend="case", case_paths=[str(tmp_path)]), confirm=lambda s: asked.append(s) or True)
    assert asked and case.summary()["flows"] == 1
    with pytest.raises(Stopped):
        CaseBackend(Config(backend="case", case_paths=[str(tmp_path)]), confirm=lambda s: False)
