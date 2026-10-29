"""Threat lines and attack paths: time-respecting traversal of the connection graph."""
import itertools
import random
import time

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


def hosts(path):
    return [path[0].src] + [h.dst for h in path]


def path_hosts(pairs):
    return [(a, b, [hosts(p) for p in paths], cut) for a, b, paths, cut in pairs]


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


# ---- interval sets ------------------------------------------------------------------------

@pytest.mark.parametrize("given,merged", [
    ([], []),
    ([(3, 4), (1, 2)], [(1, 2), (3, 4)]),                  # unsorted
    ([(1, 2), (2, 3)], [(1, 3)]),                          # touching
    ([(1, 10), (2, 3)], [(1, 10)]),                        # nested
    ([(5, 5), (5, 5)], [(5, 5)]),                          # repeated point
])
def test_merge(given, merged):
    assert analysis.merge(given) == merged
    assert analysis.merge(iter(given)) == merged           # any iterable


@pytest.mark.parametrize("a,b,out", [
    ([], [(0, 1)], []),
    ([(0, 5)], [(5, 9)], [(5, 5)]),                        # touching: one point in common
    ([(0, 2), (4, 6), (8, 10)], [(1, 9)], [(1, 2), (4, 6), (8, 9)]),
    ([(0, 10)], [(2, 3), (5, 6)], [(2, 3), (5, 6)]),
])
def test_intersect(a, b, out):
    assert analysis.intersect(a, b) == out
    assert analysis.intersect(b, a) == out


@pytest.mark.parametrize("a,b,out", [
    ([(0, 10)], [], [(0, 10)]),
    ([(0, 10)], [(0, 10)], []),                            # covered exactly
    ([(0, 10)], [(-5, 20)], []),
    ([(0, 10)], [(3, 4)], [(0, 3), (4, 10)]),              # a hole
    ([(0, 10)], [(2, 3), (5, 6)], [(0, 2), (3, 5), (6, 10)]),  # several holes
    ([(5, 5)], [(0, 10)], []),                             # a covered point
    ([(5, 5)], [(6, 10)], [(5, 5)]),                       # a point outside
    ([(0, 4), (6, 10)], [(2, 8)], [(0, 2), (8, 10)]),
])
def test_subtract(a, b, out):
    assert analysis.subtract(a, b) == out


@pytest.mark.parametrize("seed", range(40))
def test_interval_sets_against_point_sets(seed):
    rng = random.Random(seed)

    def rand_set():
        return analysis.merge((x, x + rng.choice([0, 0, 1, 2, 3]))
                              for x in (rng.randint(0, 30) for _ in range(rng.randint(0, 6))))

    def points(s):
        return {x / 2 for x in range(-2, 70) if any(lo <= x / 2 <= hi for lo, hi in s)}
    a, b = rand_set(), rand_set()
    assert points(analysis.intersect(a, b)) == points(a) & points(b)
    left = points(analysis.subtract(a, b))
    assert points(a) - points(b) <= left <= points(a)       # nothing lost; extras only on b's edges
    assert all(x in points(b) and (x - 0.5 not in points(b) or x + 0.5 not in points(b))
               for x in left & points(b))


# ---- graph helpers ------------------------------------------------------------------------

def test_between_helpers_outside_the_range():
    times = graph.array("d", [10.0, 20.0, 30.0])
    assert graph.count_between(times, 11, 19) == (0, None, None)
    assert graph.count_between(times, 10, 30) == (3, 10.0, 30.0)
    assert graph.first_between(times, 31, 40) is None and graph.first_between(times, 0, 9) is None
    assert graph.last_between(times, 0, 9) is None and graph.last_between(times, 21, 29) is None
    assert graph.last_between(times, 0, 25) == 20.0 and graph.first_between(times, 15, 40) == 20.0


def test_runs_edge_cases():
    g = build_graph([f("a", "b", t) for t in (1, 1, 2, 4, 4, 9)])
    e = g["a"]["b"]
    assert graph.runs(e, 0, 0, 10) == [(1, 1), (2, 2), (4, 4), (9, 9)]   # equal times: one run
    assert graph.runs(e, 2, 0, 10) == [(1, 4), (9, 9)]
    assert graph.runs(e, 2, 5, 3) == []                                  # empty range
    assert graph.runs(e, 2, -INF, INF) == [(1, 4), (9, 9)]
    assert graph.runs(e, 5, 0, 10) == [(1, 9)]                           # the cache follows the window
    assert graph.runs(e, 2, 4, 4) == [(4, 4)]


# ---- reachability and threat lines --------------------------------------------------------

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


def test_threat_line_through_a_connection_with_several_flows():
    # a -> b at 1h and again at 40h (two runs a day apart). Each run has its own before/after.
    g = build_graph([f("a", "b", 1 * H), f("a", "b", 40 * H),
                     f("x", "a", 0.5 * H), f("y", "a", 39 * H),          # before each run
                     f("b", "p", 2 * H), f("b", "q", 41 * H)])           # after each run
    up, down = analysis.threat_line(g, "a", "b", 0, 50 * H, W, 6)
    assert set(up.via) == {"x", "y"} and set(down.via) == {"p", "q"}


def test_threat_line_caps_both_directions():
    g = build_graph([f("u1", "a", 1), f("u2", "a", 1), f("a", "b", 2), f("b", "d1", 3), f("b", "d2", 3)])
    up, down = analysis.threat_line(g, "a", "b", 2, 2, W, 6, max_hosts=2)
    assert up.truncated and down.truncated and len(down.allowed) == 2


def test_threat_line_with_no_selected_flows_reaches_nothing():
    up, down = analysis.threat_line(G, "ws", "fs", 5 * H, 4 * H, W, 6)
    assert up.via == {} and down.via == {}


def test_window_edges_are_inclusive():
    g = build_graph([f("a", "b", 10), f("b", "c", 10 + W), f("b", "d", 10 + W + 0.001),
                     f("b", "e", 10)])                       # same instant as the hop in: allowed
    r = analysis.spread(g, {"a": [(0, W)]}, W, 6)
    assert set(r.via) == {"b", "c", "e"}
    paths = analysis.paths_between(g, "a", "e", 0, None, W, 6)[0]
    assert [hosts(p) for p in paths] == [["a", "b", "e"]]


def test_hop_limits():
    g = build_graph([f("a", "b", 1), f("b", "c", 2), f("a", "c", 3)])
    r = analysis.spread(g, {"a": [(0, W)]}, W, 0)
    assert r.via == {} and r.allowed == {"a": [(0, W)]}
    assert [hosts(p) for p in analysis.paths_between(g, "a", "c", 0, None, W, 1)[0]] == [["a", "c"]]


def test_reach_may_revisit_a_host_but_paths_never_do():
    # a -> b -> a -> c: back on a at 2, and only from then can a reach c within the window.
    g = build_graph([f("a", "b", 1), f("b", "a", 2), f("a", "c", 2 + 1.5)])
    r = analysis.spread(g, {"a": [(0, 2)]}, 2, 6)
    assert set(r.via) == {"b", "c"} and r.hops["c"] == 3
    assert analysis.paths_between(g, "a", "c", 0, None, 2, 6) == ([], False)


def test_sources_need_not_be_sorted_or_disjoint():
    g = build_graph([f("a", "b", 4), f("b", "c", 5)])
    messy = analysis.spread(g, {"a": [(3, 6), (0, 4)]}, W, 6)
    clean = analysis.spread(g, {"a": [(0, 6)]}, W, 6)
    assert (messy.via, messy.allowed) == (clean.via, clean.allowed)


def test_spread_carries_on_past_a_source_missing_from_the_graph():
    g = build_graph([f("a", "b", 1)])
    r = analysis.spread(g, {"ghost": [(0, W)], "a": [(0, W)]}, W, 6)
    assert set(r.via) == {"b"}


# ---- paths between two hosts --------------------------------------------------------------

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


def test_compromise_times_and_slack():
    g = build_graph([f("a", "b", 100), f("b", "c", 200)])
    ok = lambda **kw: bool(analysis.paths_between(g, "a", "c", window=W, max_hops=6, **kw)[0])  # noqa: E731
    assert ok(ta=100, tb=200)                                # both ends inclusive
    assert not ok(ta=100.5, tb=200)                          # first hop before a was compromised
    assert ok(ta=100.0005, tb=200, slack=0.001)              # ... unless within the UI's rounding
    assert not ok(ta=0, tb=199.9)                            # reached c after c's IOC time
    assert ok(ta=0, tb=199.9995, slack=0.001)
    assert not ok(ta=300, tb=200)                            # deadline before the start
    assert not ok(ta=None, tb=None)                          # time unknown and no data start
    assert ok(ta=None, tb=None, data_start=0)


def test_default_slack_is_zero():
    g = build_graph([f("a", "b", 100), f("b", "c", 200)])
    assert analysis.attack_paths(g, {"a": 100.5, "c": None}, W, 6) == []         # left a too early
    assert analysis.attack_paths(g, {"a": 0, "c": 199.5}, W, 6) == []            # reached c too late
    assert analysis.paths_between(g, "a", "c", 0, 199.5, W, 6) == ([], False)


def test_no_data_is_not_a_cut_list():
    assert analysis.paths_between(G, "ws", "dc", None, None, W, 6) == ([], False)


def test_step_budget_cuts_the_search(monkeypatch):
    monkeypatch.setattr(analysis, "MAX_STEPS", 1)          # one hop tried: a -> d
    paths, cut = analysis.paths_between(ROUTES, "a", "d", 0, None, W, 6)
    assert cut and [hosts(p) for p in paths] == [["a", "d"]]


@pytest.mark.parametrize("seed", range(30))
def test_a_capped_list_keeps_the_shortest_paths(seed):
    rng = random.Random(seed)
    names = "abcdefgh"
    flows = [f(s, d, float(rng.randint(0, 30))) for s, d in
             (rng.sample(names, 2) for _ in range(rng.randint(15, 45)))]
    g = build_graph(flows)
    every, cut = analysis.paths_between(g, "a", "b", 0.0, None, 10.0, 5)
    assert not cut
    for n in range(1, len(every)):
        kept, cut = analysis.paths_between(g, "a", "b", 0.0, None, 10.0, 5, max_paths=n)
        assert cut and len(kept) == n
        assert max(map(len, kept)) <= min(len(p) for p in every if p not in kept)
        assert all(p in every for p in kept)


def test_results_do_not_depend_on_the_order_flows_were_read():
    # Five same-length paths a -> m -> b. Which ones a capped list keeps must not depend on
    # the order the evidence was read in.
    flows = [f("a", m, 1) for m in "pqrst"] + [f(m, "b", 2) for m in "pqrst"]
    expect = analysis.paths_between(build_graph(flows), "a", "b", 0, None, W, 6, max_paths=2)
    for seed in range(5):
        shuffled = flows[:]
        random.Random(seed).shuffle(shuffled)
        g = build_graph(shuffled)
        assert analysis.paths_between(g, "a", "b", 0, None, W, 6, max_paths=2) == expect
        _, down = analysis.threat_line(g, "a", "p", 1, 1, W, 6)
        assert down.via == analysis.threat_line(build_graph(flows), "a", "p", 1, 1, W, 6)[1].via


def test_a_hub_with_many_dead_ends_is_not_rescanned():
    # 400 ways from a to the hub; the hub talks to 60k hosts, one of which leads to b.
    flows = [f("a", f"m{i}", 1) for i in range(400)] + [f(f"m{i}", "hub", 2) for i in range(400)]
    flows += [f("hub", f"x{i}", 3) for i in range(60000)] + [f("hub", "y", 3), f("y", "b", 4)]
    g = build_graph(flows)
    t = time.perf_counter()
    paths, cut = analysis.paths_between(g, "a", "b", 0, None, W, 6, max_paths=1000)
    assert len(paths) == 400 and not cut
    assert time.perf_counter() - t < 1.5


def test_pruning_bounds_for_the_path_search():
    # a -> b at 1, b -> c at 5, a -> c at 10; target c.
    g = build_graph([f("a", "b", 1), f("b", "c", 5), f("a", "c", 10)])
    r = analysis.spread_into(g, "c", 7, 6)          # c's IOC time 7: a -> c at 10 is too late
    assert r.hops == {"c": 0, "b": 1, "a": 1}            # fewest hops, time ignored
    assert r.allowed == {"c": [(-INF, 7)], "b": [(-INF, 5)], "a": [(-INF, 1)]}   # latest hop in
    assert analysis.spread_into(g, "c", None, 6).allowed == {h: [(-INF, INF)] for h in "abc"}
    assert analysis.spread_into(g, "c", 7, 6, blocked={"b"}).hops == {"c": 0}   # only via b in time
    assert analysis.spread_into(g, "c", 7, 2).hops == {"c": 0, "b": 1, "a": 1}
    assert analysis.spread_into(g, "c", None, 1).hops == {"c": 0}                # no hops left to use
    assert analysis.spread_into(g, "c", 7, 6, bounds=(2, INF)).allowed == {"c": [(-INF, 7)], "b": [(-INF, 5)]}


def test_pruning_bounds_reach_past_self_loops_and_stale_entries():
    # Target b, IOC time 100. y1 -> b at 100 and y2 -> b at 50; x reaches y1 at 5 and y2 at 40,
    # so x is first queued at 5 and then improved to 40 (the 5 becomes stale); z -> x at 2,
    # w -> z at 1. A self-connection on b comes first among its predecessors.
    g = build_graph([f("b", "b", 0), f("y1", "b", 100), f("y2", "b", 50), f("x", "y1", 5),
                     f("x", "y2", 40), f("z", "x", 2), f("w", "z", 1), f("far", "w", 0.5)])
    r = analysis.spread_into(g, "b", 100, 5)          # hosts up to 4 hops from b: not "far"
    assert {h: iv[0][1] for h, iv in r.allowed.items()} == {"b": 100, "y1": 100, "y2": 50, "x": 40,
                                                            "z": 2, "w": 1}
    paths, _ = analysis.paths_between(g, "w", "b", 0, 100, W, 5)
    assert [hosts(p) for p in paths] == [["w", "z", "x", "y2", "b"], ["w", "z", "x", "y1", "b"]]


# ---- attack paths between compromised hosts -----------------------------------------------

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


def test_attack_paths_skip_unusable_hosts():
    assert analysis.attack_paths(G, {"ws": 0}, W, 6) == []                       # one host
    assert analysis.attack_paths(G, {"ws": 0, "nowhere": None}, W, 6) == []
    assert analysis.attack_paths(G, {"ws": 0, "dc": None}, W, 6, blocked={"dc"}) == []
    assert analysis.paths_between(G, "ws", "dc", 0, None, W, 6, blocked={"ws"}) == ([], False)


def test_attack_paths_skip_an_unusable_host_and_carry_on():
    # "aaa" sorts first and is not in the graph; the pair after it must still be found.
    found = analysis.attack_paths(G, {"aaa": None, "ws": 1.5 * H, "dc": 5 * H}, W, 6)
    assert path_hosts(found) == [("ws", "dc", [["ws", "fs", "dc"]], False)]


def test_attack_paths_list_pairs_by_source_then_target():
    g = build_graph([f("b", "a", 1), f("a", "c", 2)])
    found = analysis.attack_paths(g, {"a": None, "b": None, "c": None}, W, 6, data_start=0)
    assert [(a, b) for a, b, _, _ in found] == [("a", "c"), ("b", "a"), ("b", "c")]


# ---- against brute force on random graphs -------------------------------------------------

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


# ---- suspect flows (D16): the lines into and out of marked hosts --------------------------

M = 60.0   # a minute


def suspect_set(flows, marks, window=W, max_hops=6, blocked=frozenset(), bounds=(-INF, INF), slack=0.0):
    """The suspect flows, as (src, dst, start)."""
    found = analysis.suspects(build_graph(flows), marks, window, max_hops, blocked, bounds, slack)
    return {(x.src, x.dst, x.start) for x in flows
            if any(lo <= x.start <= hi for lo, hi in found.get((x.src, x.dst), []))}


T0 = 10 * H
# The user story's timeline: E -> A -> X -> B, X -> C, then B -> F and A -> Y.
STORY = [f("E", "A", T0), f("A", "X", T0 + 5 * M), f("X", "B", T0 + 10 * M), f("X", "C", T0 + 15 * M),
         f("B", "F", T0 + 20 * M), f("A", "Y", T0 + 30 * M)]


def flows_named(*names):
    return {(x.src, x.dst, x.start) for x in STORY if f"{x.src}{x.dst}" in names}


def test_marks_keep_every_flow_after_the_attacker_reached_them():
    # Marks A and B: how the attacker got to each, and every flow after it reached them (option c).
    assert suspect_set(STORY, {"A": None, "B": None}) == flows_named("EA", "AX", "XB", "XC", "BF", "AY")
    # Marks B and C: both lines in, and where B and C went next.
    assert suspect_set(STORY, {"B": None, "C": None}) == flows_named("EA", "AX", "XB", "XC", "BF")
    # B alone, reached at 10:10: the line in, and B's flow 10 minutes later.
    assert suspect_set(STORY, {"B": T0 + 10 * M}) == flows_named("EA", "AX", "XB", "BF")


def test_a_reached_time_bounds_both_lines():
    # A reached at 10:00: the line in must arrive by then, the line out leave within the Window.
    assert suspect_set(STORY, {"A": T0}) == flows_named("EA", "AX", "XB", "XC", "BF", "AY")
    assert suspect_set(STORY, {"A": T0 - 1}) == flows_named("AX", "XB", "XC", "BF", "AY")   # E -> A came after
    assert suspect_set(STORY, {"A": T0}, window=20 * M) == flows_named("EA", "AX", "XB", "XC", "BF")
    # The Window between hops: X -> C 10 minutes after A -> X breaks a 4-minute window.
    assert suspect_set(STORY, {"C": None}, window=4 * M) == flows_named("XC")
    # Times a little off (TIME_SLACK): a flow out of A up to the slack before A was reached counts.
    assert suspect_set(STORY, {"A": T0 + 5 * M + 30}) == flows_named("EA", "AY")
    assert suspect_set(STORY, {"A": T0 + 5 * M + 30}, slack=M) == flows_named("EA", "AX", "XB", "XC", "BF", "AY")


def test_hop_limit_excludes_and_time_range():
    chain = [f(f"h{i}", f"h{i + 1}", T0 + i * M) for i in range(8)]
    assert suspect_set(chain, {"h8": None}, max_hops=6) == {(x.src, x.dst, x.start) for x in chain[2:]}
    assert suspect_set(chain, {"h0": None}, max_hops=3) == {(x.src, x.dst, x.start) for x in chain[:3]}
    # An excluded host is never reached, so nothing beyond it, nor its own flows, count.
    assert suspect_set(chain, {"h8": None}, blocked={"h5"}) == {(x.src, x.dst, x.start) for x in chain[6:]}
    assert suspect_set(chain, {"h5": None}, blocked={"h5"}) == set()
    assert suspect_set(chain, {"h8": None}, bounds=(T0 + 4 * M, INF)) == {(x.src, x.dst, x.start) for x in chain[4:]}
    # The same on the way out of a mark.
    assert suspect_set(chain, {"h0": None}, blocked={"h3"}) == {(x.src, x.dst, x.start) for x in chain[:2]}
    assert suspect_set(chain, {"h0": None}, bounds=(-INF, T0 + 3 * M)) == {(x.src, x.dst, x.start) for x in chain[:4]}
    assert suspect_set(chain, {"nowhere": None}) == set()


def brute_force_suspects(flows, marks, window, max_hops):
    """Every hop of every time-ordered chain (each hop no earlier than the one before, and
    within `window` of it) of at most max_hops hops that ends at a marked host by its time,
    or starts at one within `window` after its time."""
    out = set()

    def extend(chain):
        if chain:
            first, last = chain[0], chain[-1]
            t = marks.get(last.dst, "-")
            if t != "-" and (t is None or last.start <= t):
                out.update((x.src, x.dst, x.start) for x in chain)
            t = marks.get(first.src, "-")
            if t != "-" and (t is None or t <= first.start <= t + window):
                out.update((x.src, x.dst, x.start) for x in chain)
        if len(chain) == max_hops:
            return
        for x in flows:
            if x.src == x.dst:
                continue
            if not chain or (x.src == chain[-1].dst and chain[-1].start <= x.start <= chain[-1].start + window):
                extend(chain + [x])

    extend([])
    return out


@pytest.mark.parametrize("seed", range(200))
def test_suspects_against_brute_force(seed):
    rng = random.Random(seed)
    names = [f"h{i}" for i in range(6)]
    flows = list({(a, b, t): f(a, b, t) for a, b, t in
                  ((rng.choice(names), rng.choice(names), float(rng.randint(0, 40))) for _ in range(rng.randint(3, 14)))}.values())
    marks = {h: rng.choice([None, float(rng.randint(0, 40))]) for h in rng.sample(names, rng.randint(1, 3))}
    window, hops = float(rng.choice([3, 8, 20])), rng.choice([1, 2, 3])
    assert suspect_set(flows, marks, window, hops) == brute_force_suspects(flows, marks, window, hops)
