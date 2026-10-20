"""Threat lines and attack paths: time-respecting traversal of the flow graph."""
import pytest

from threatbridge import analysis
from threatbridge import graph
from threatbridge.model import Flow

H = 3600.0
DAY = 24 * H
W = DAY  # per-hop window used in most tests


def f(src, dst, start, dport=445):
    return Flow(src, dst, 50000, dport, "tcp", start, start + 1, 2, 120, "x")


def build_graph(flows):
    return graph.build_graph((x.src, x.dst, x.start) for x in flows)


# phish -> ws -> fs -> dc -> backup, with noise that breaks time order or the window.
FLOWS = [
    f("evil", "ws", 1 * H, 443),
    f("ws", "fs", 2 * H),
    f("fs", "dc", 3 * H),
    f("dc", "backup", 4 * H),
    f("dc", "printer", 2.5 * H),       # before dc was reached: not part of the line
    f("fs", "nas", 3 * H + 2 * DAY),   # more than a window after fs was reached
    f("old", "ws", 0.5 * H),           # also reached ws before the selected hop
    f("ws", "ws", 2 * H),              # self-connection
]
G = build_graph(FLOWS)


def test_threat_line_follows_time_order():
    up, down = analysis.threat_line(G, "ws", "fs", 2 * H, 2 * H, W, 6)
    assert set(up.via) == {"evil", "old"}
    assert set(down.via) == {"dc", "backup"}
    assert down.time == {"fs": 2 * H, "dc": 3 * H, "backup": 4 * H}
    assert down.hops["backup"] == 2 and not down.truncated


def test_window_and_hop_limit():
    _, down = analysis.threat_line(G, "ws", "fs", 2 * H, 2 * H, 3 * DAY, 6)
    assert "nas" in down.via                         # a wider window lets the late hop in
    _, down = analysis.threat_line(G, "ws", "fs", 2 * H, 2 * H, W, 1)
    assert set(down.via) == {"dc"}


def test_blocked_hosts_are_not_traversed_and_cap_truncates():
    _, down = analysis.threat_line(G, "ws", "fs", 2 * H, 2 * H, W, 6, blocked={"dc"})
    assert down.via == {}
    up, _ = analysis.threat_line(G, "ws", "fs", 2 * H, 2 * H, W, 6, max_hosts=2)
    assert len(up.time) == 2 and up.truncated


def test_tree_edges_carry_their_time_range():
    up, down = analysis.threat_line(G, "ws", "fs", 2 * H, 2 * H, W, 6)
    assert sorted(analysis.tree_edges(down)) == [("dc", "backup", 3 * H, 3 * H + W),
                                                 ("fs", "dc", 2 * H, 2 * H + W)]
    assert sorted(analysis.tree_edges(up)) == [("evil", "ws", 2 * H - W, 2 * H),
                                               ("old", "ws", 2 * H - W, 2 * H)]


def test_earliest_arrival_wins():
    g = build_graph([f("a", "b", 10), f("a", "c", 1), f("c", "b", 2)])
    r = analysis.forward(g, "a", 0, W, 6)
    assert r.time["b"] == 2 and r.via["b"].src == "c"
    assert [x.dst for x in analysis.path_to(r, "b")] == ["c", "b"]


def path_hosts(paths):
    return [(a, b, [x.src for x in hops] + [hops[-1].dst]) for a, b, hops in paths]


def test_attack_paths_between_compromised_hosts():
    found = analysis.attack_paths(G, {"ws": 1.5 * H, "dc": 5 * H}, W, 6)
    assert path_hosts(found) == [("ws", "dc", ["ws", "fs", "dc"])]
    # dc compromised before the path could reach it: no path.
    assert analysis.attack_paths(G, {"ws": 1.5 * H, "dc": 2.5 * H}, W, 6) == []
    # Unknown times: the first hop may happen any time in the data.
    found = analysis.attack_paths(G, {"evil": None, "backup": None}, W, 6, data_start=0)
    assert path_hosts(found) == [("evil", "backup", ["evil", "ws", "fs", "dc", "backup"])]
    # An excluded host breaks the path.
    assert analysis.attack_paths(G, {"ws": 0, "dc": None}, W, 6, blocked={"fs"}) == []


def test_unknown_time_lifts_only_the_first_window():
    g = build_graph([f("a", "b", 5 * DAY), f("b", "c", 5 * DAY + H), f("b", "d", 9 * DAY)])
    found = analysis.attack_paths(g, {"a": None, "c": None, "d": None}, W, 6, data_start=0)
    assert path_hosts(found) == [("a", "c", ["a", "b", "c"])]


@pytest.mark.parametrize("compromised", [{}, {"nowhere": None}])
def test_attack_paths_empty(compromised):
    assert analysis.attack_paths(G, compromised, W, 6, data_start=0) == []
