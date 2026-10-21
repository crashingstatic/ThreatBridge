"""Threat lines and attack paths: time-respecting traversal of the flow graph."""
import itertools
import random

import pytest

from threatbridge import analysis
from threatbridge import graph
from threatbridge.model import Flow

H = 3600.0
DAY = 24 * H
W = DAY  # per-hop window used in most tests
INF = analysis.INF


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
    assert {h: hop.start for h, hop in down.via.items()} == {"dc": 3 * H, "backup": 4 * H}
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
    assert len(up.allowed) == 2 and up.truncated


def test_tree_edges_carry_the_times_that_fit():
    up, down = analysis.threat_line(G, "ws", "fs", 2 * H, 2 * H, W, 6)
    assert sorted(analysis.tree_edges(down)) == [("dc", "backup", [(3 * H, 3 * H + W)]),
                                                 ("fs", "dc", [(2 * H, 2 * H + W)])]
    assert sorted(analysis.tree_edges(up)) == [("evil", "ws", [(2 * H - W, 2 * H)]),
                                               ("old", "ws", [(2 * H - W, 2 * H)])]


def test_time_range_bounds_both_searches():
    # Only flows starting 1.5h-3.5h: evil's and old's hops into ws, and dc -> backup, fall outside.
    up, down = analysis.threat_line(G, "ws", "fs", 2 * H, 2 * H, W, 6, bounds=(1.5 * H, 3.5 * H))
    assert up.via == {} and set(down.via) == {"dc"}
    assert analysis.tree_edges(down) == [("fs", "dc", [(2 * H, 3.5 * H)])]


def test_a_later_arrival_can_open_a_hop_the_earliest_cannot():
    # a -> b at 1h and at 10h; b -> c at 30h. Only the 10h arrival is within a day of it.
    g = build_graph([f("a", "b", 1 * H), f("a", "b", 10 * H), f("b", "c", 30 * H)])
    r = analysis.spread(g, {"a": [(0, W)]}, W, 6)
    assert set(r.via) == {"b", "c"} and r.via["b"].start == 1 * H      # shown: earliest arrival
    up = analysis.spread(g, {"c": [(30 * H - W, 30 * H)]}, W, 6, forward=False)
    assert set(up.via) == {"b", "a"} and up.via["a"].start == 10 * H    # shown: latest departure
    paths, cut = analysis.paths_between(g, "a", "c", 0, None, W, 6)
    assert paths == [[analysis.Hop("a", "b", 10 * H), analysis.Hop("b", "c", 30 * H)]] and not cut


def hosts(path):
    return [path[0].src] + [h.dst for h in path]


def path_hosts(pairs):
    return [(a, b, [hosts(p) for p in paths], cut) for a, b, paths, cut in pairs]


def test_attack_paths_between_compromised_hosts():
    found = analysis.attack_paths(G, {"ws": 1.5 * H, "dc": 5 * H}, W, 6)
    assert path_hosts(found) == [("ws", "dc", [["ws", "fs", "dc"]], False)]
    # dc compromised before the path could reach it: no path.
    assert analysis.attack_paths(G, {"ws": 1.5 * H, "dc": 2.5 * H}, W, 6) == []
    # Unknown times: the first hop may happen any time in the data.
    found = analysis.attack_paths(G, {"evil": None, "backup": None}, W, 6, data_start=0)
    assert path_hosts(found) == [("evil", "backup", [["evil", "ws", "fs", "dc", "backup"]], False)]
    # An excluded host breaks the path.
    assert analysis.attack_paths(G, {"ws": 0, "dc": None}, W, 6, blocked={"fs"}) == []
    # So does a time range that leaves out a hop, even an unbounded first one.
    assert analysis.attack_paths(G, {"evil": None, "backup": None}, W, 6, data_start=0,
                                 bounds=(1.5 * H, INF)) == []


def test_unknown_time_lifts_only_the_first_window():
    g = build_graph([f("a", "b", 5 * DAY), f("b", "c", 5 * DAY + H), f("b", "d", 9 * DAY)])
    found = analysis.attack_paths(g, {"a": None, "c": None, "d": None}, W, 6, data_start=0)
    assert path_hosts(found) == [("a", "c", [["a", "b", "c"]], False)]


@pytest.mark.parametrize("compromised", [{}, {"nowhere": None}])
def test_attack_paths_empty(compromised):
    assert analysis.attack_paths(G, compromised, W, 6, data_start=0) == []


# A small network with several ways from a to d.
ROUTES = build_graph([
    f("a", "d", 9 * H),
    f("a", "b", 1 * H), f("b", "d", 2 * H),
    f("a", "c", 1 * H), f("c", "d", 3 * H),
    f("b", "c", 1.5 * H),
    f("c", "b", 4 * H),                  # after b was left for c: b -> c -> b is no use
    f("d", "a", 5 * H),                  # leads back out of d: paths end at d
])


def test_every_path_shortest_first():
    paths, cut = analysis.paths_between(ROUTES, "a", "d", 0, None, W, 6)
    # a -> c -> b -> d is not one: b -> d happened before c -> b.
    assert [hosts(p) for p in paths] == [["a", "d"], ["a", "b", "d"], ["a", "c", "d"],
                                         ["a", "b", "c", "d"]]
    assert not cut
    # Each is shown by a chain of flows that follows the rule.
    assert paths[3] == [analysis.Hop("a", "b", 1 * H), analysis.Hop("b", "c", 1.5 * H),
                        analysis.Hop("c", "d", 3 * H)]


def test_paths_respect_hops_deadline_cap_and_excludes():
    def found(**kw):
        args = dict(ta=0, tb=None, window=W, max_hops=6)
        args.update(kw)
        return [hosts(p) for p in analysis.paths_between(
            ROUTES, "a", "d", args.pop("ta"), args.pop("tb"), args.pop("window"),
            args.pop("max_hops"), **args)[0]]
    assert found(max_hops=2) == [["a", "d"], ["a", "b", "d"], ["a", "c", "d"]]
    assert found(tb=2.5 * H) == [["a", "b", "d"]]                     # d compromised at 2.5h
    assert found(blocked={"b"}) == [["a", "d"], ["a", "c", "d"]]
    assert found(window=1 * H) == [["a", "b", "d"]]                  # b -> d within the hour
    paths, cut = analysis.paths_between(ROUTES, "a", "d", 0, None, W, 6, max_paths=2)
    assert [hosts(p) for p in paths] == [["a", "d"], ["a", "b", "d"]] and cut
    [(_, _, preview, cut)] = analysis.attack_paths(ROUTES, {"a": 0, "d": None}, W, 6, max_paths=3)
    assert len(preview) == 3 and cut
    assert analysis.paths_between(ROUTES, "a", "d", 0, None, W, 6, max_paths=4)[1] is False
    assert analysis.paths_between(ROUTES, "a", "a", 0, None, W, 6) == ([], False)
    assert analysis.paths_between(ROUTES, "a", "zz", 0, None, W, 6) == ([], False)


# ---- against brute force on random graphs ---------------------------------------------------

def brute_paths(flows, a, b, ta, tb, window, max_hops, data_start, bounds):
    """Host sequences a..b (no repeats) for which some choice of flows follows the rule."""
    by_pair = {}
    for x in flows:
        if bounds[0] <= x.start <= bounds[1]:
            by_pair.setdefault((x.src, x.dst), []).append(x.start)
    out = set()

    def chains(seq, i, t):
        if i == len(seq) - 1:
            return True
        lo, hi = (t, t + window) if i else ((data_start, INF) if ta is None else (ta, ta + window))
        for s in by_pair.get((seq[i], seq[i + 1]), []):
            if lo <= s <= hi and (i + 2 < len(seq) or tb is None or s <= tb) and chains(seq, i + 1, s):
                return True
        return False

    others = sorted({x for pair in by_pair for x in pair} - {a, b})
    for n in range(0, max_hops):
        for mid in itertools.permutations(others, n):
            seq = (a, *mid, b)
            if chains(seq, 0, None):
                out.add(seq)
    return out


def brute_reach(flows, origin, t0, window, max_hops, bounds):
    """host -> fewest hops from `origin`, reached at t0, over walks of flows."""
    best, frontier = {origin: 0}, [(origin, t0, 0)]
    seen = set(frontier)
    while frontier:
        nxt = []
        for x, t, k in frontier:
            if k == max_hops:
                continue
            for fl in flows:
                if fl.src == x and fl.dst != x and t <= fl.start <= t + window \
                        and bounds[0] <= fl.start <= bounds[1] and (fl.dst, fl.start, k + 1) not in seen:
                    seen.add((fl.dst, fl.start, k + 1))
                    best.setdefault(fl.dst, k + 1)
                    nxt.append((fl.dst, fl.start, k + 1))
        frontier = nxt
    return best


@pytest.mark.parametrize("seed", range(60))
def test_matches_brute_force(seed):
    rng = random.Random(seed)
    names = "abcdefg"[:rng.randint(4, 7)]
    flows = [f(s, d, float(rng.randint(0, 40))) for s, d in
             (rng.sample(names, 2) for _ in range(rng.randint(6, 30)))]
    g = build_graph(flows)
    window, max_hops = rng.choice([3.0, 6.0, 15.0]), rng.randint(1, 5)
    bounds = rng.choice([(-INF, INF), (5.0, 35.0)])
    a, b = "a", "b"
    ta = rng.choice([None, 0.0, 10.0])
    tb = rng.choice([None, 25.0])
    paths, cut = analysis.paths_between(g, a, b, ta, tb, window, max_hops, data_start=0.0,
                                        bounds=bounds)
    assert not cut
    assert {tuple(hosts(p)) for p in paths} == brute_paths(flows, a, b, ta, tb, window, max_hops,
                                                           0.0, bounds)
    for p in paths:                                    # the chain shown follows the rule
        assert ta is None or ta <= p[0].start <= ta + window
        assert all(x.start <= y.start <= x.start + window for x, y in zip(p, p[1:]))
        assert tb is None or p[-1].start <= tb
        assert all(bounds[0] <= h.start <= bounds[1] and h.start in g[h.src][h.dst]["times"] for h in p)

    start = rng.choice([0.0, 10.0])
    r = analysis.spread(g, {a: [(start, start + window)]}, window, max_hops, bounds=bounds)
    expect = brute_reach(flows, a, start, window, max_hops, bounds)
    del expect[a]
    assert {h: r.hops[h] for h in r.via} == expect
    # Backward is forward with the flows reversed and time running the other way.
    end = rng.choice([30.0, 40.0])
    r = analysis.spread(g, {b: [(end - window, end)]}, window, max_hops, forward=False, bounds=bounds)
    expect = brute_reach([f(x.dst, x.src, -x.start) for x in flows], b, -end, window, max_hops,
                         (-bounds[1], -bounds[0]))
    del expect[b]
    assert {h: r.hops[h] for h in r.via} == expect
