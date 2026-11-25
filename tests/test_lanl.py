"""The LANL 2015 loader (item 13, D35), on small files written in its format: its flows'
fields, made-up addresses, the slice read, the red team's chains, and a measurement."""
import gzip

from threatbridge import lanl, measure
from threatbridge.backends import CaseBackend
from threatbridge.config import Config

# time,duration,source computer,source port,destination computer,destination port,protocol,packets,bytes
FLOWS = """1,9,C3090,N10471,C3420,N46,6,3,144
50,0,C9,N1,C10,53,17,2,120
99,2,C1,N2,C2,445,6,10,5323
101,0,ActiveDirectory,N3,C2,389,6,4,400
205,1,C2,N4,C3,3389,6,40,9000
290,0,C1,N5,C4,N7,6,2,92
500,0,C5,N6,C6,443,6,2,92
9000,0,C7,N8,C8,443,6,2,92
"""
# time,user@domain,source computer,destination computer
REDTEAM = """200,U2@DOM1,C2,C3
100,U1@DOM1,C1,C2
330,U1@DOM1,C1,C4
400,U9@DOM1,C77,C78
"""


def files(tmp_path):
    f, r = tmp_path / "flows.txt.gz", tmp_path / "redteam.txt.gz"
    with gzip.open(f, "wt") as fh:
        fh.write(FLOWS)
    with gzip.open(r, "wt") as fh:
        fh.write(REDTEAM)
    return f, r


def test_addresses_are_stable_and_made_up():
    assert lanl.address("C1") == "10.0.0.1" and lanl.address("C17693") == "10.0.69.29"
    assert lanl.address("ActiveDirectory") == lanl.address("ActiveDirectory")
    assert lanl.address("ActiveDirectory").startswith("172.") and lanl.address("ActiveDirectory") != lanl.address("C1")


def test_flows_in_a_slice(tmp_path):
    f, _ = files(tmp_path)
    found = lanl.flows(f, 50, 500)
    assert [(x.src, x.dst, x.sport, x.dport, x.proto) for x in found] == [
        ("10.0.0.9", "10.0.0.10", None, 53, "udp"), ("10.0.0.1", "10.0.0.2", None, 445, "tcp"),
        (lanl.address("ActiveDirectory"), "10.0.0.2", None, 389, "tcp"), ("10.0.0.2", "10.0.0.3", None, 3389, "tcp"),
        ("10.0.0.1", "10.0.0.4", None, None, "tcp"), ("10.0.0.5", "10.0.0.6", None, 443, "tcp")]
    assert (found[1].start, found[1].end, found[1].packets, found[1].bytes) == (lanl.BASE + 99, lanl.BASE + 101, 10, 5323)
    assert found[0].source == "flows.txt.gz"


def test_the_red_teams_chains():
    events = [(100, "U1@DOM1", "C1", "C2"), (200, "U2@DOM1", "C2", "C3"), (330, "U1@DOM1", "C1", "C4"),
                                  (400, "U9@DOM1", "C77", "C78")]             # C77 never reached: left out
    found = lanl.chains(events)
    assert [(c.name, c.entry, [(s, d, t - lanl.BASE) for s, d, _, t in c.hops]) for c in found] == [
        ("C1 to C2", ("10.0.0.1", lanl.BASE + 100), [("10.0.0.1", "10.0.0.2", 100)]),
        ("C1 to C3", ("10.0.0.1", lanl.BASE + 100), [("10.0.0.1", "10.0.0.2", 100), ("10.0.0.2", "10.0.0.3", 200)]),
        ("C1 to C4", ("10.0.0.1", lanl.BASE + 100), [("10.0.0.1", "10.0.0.4", 330)])]
    assert lanl.chains([]) == []


def test_measured_within_the_tolerance(tmp_path, capsys):
    f, r = files(tmp_path)
    events = lanl.redteam(r)
    case = CaseBackend(Config(backend="case"), flows=lanl.flows(f, 0, 1000))
    cache = {}
    results = [(c.name, measure.measure(case, c, tolerance=10, cache=cache)) for c in lanl.chains(events)]
    seen = {name: (r["seen"], r["hops"], r["suspects"]["found"]) for name, r in results}
    # The logon at 100 has its flow at 99, the one at 200 at 205; the one at 330 none within 10 s.
    assert seen == {"C1 to C2": (1, 1, 1), "C1 to C3": (2, 2, 2), "C1 to C4": (0, 1, 0)}
    assert len(cache) == 1                                          # one search for the three chains
    assert lanl.main([str(f), str(r), "--hours", "1", "--tolerance", "10", "--details"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("LANL 2015: 7 flows from time -3500 to 3700 ")     # not the line at 9000
    assert "4 red-team logons" in out
    assert "| 3 | 3/4 | 3/4 |" in out and "| C1 to C3 |" in out


def test_a_long_read_asks_first(tmp_path):
    """Reading on to the slice asked for is projected from how far into the data the lines are
    after 10 seconds; over 5 minutes in all, it asks first (D37)."""
    import pytest
    from threatbridge.backends import Stopped
    f, _ = files(tmp_path)

    def clock():                      # 6 s per look: 12 s in by the third line
        clock.now += 6
        return clock.now
    clock.now = 0
    asked = []
    with pytest.raises(Stopped):
        lanl.flows(f, 0, 100_000, confirm=lambda s: asked.append(s) or False, clock=clock)
    assert len(asked) == 1 and asked[0] > 300
    clock.now = 0
    assert len(lanl.flows(f, 0, 100_000, confirm=lambda s: True, clock=clock)) == 8
    fast = iter(range(100))                     # a second per look: done within 10 s, no question
    assert len(lanl.flows(f, 0, 500, confirm=lambda s: asked.append(s) or False, clock=lambda: next(fast))) == 7
    assert len(asked) == 1
