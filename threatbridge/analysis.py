"""Time-respecting traversal of the connection graph: threat lines and attack paths.

A hop X -> Y counts only if its flow starts no earlier than the attacker reached X, and at
most `window` seconds later. That is the rule the map applies when an analyst expands hosts by
hand, done automatically and to a hop limit. An optional `bounds` (lo, hi) is the analyst's
time range: flows starting outside it are ignored.

The searches are exact under that rule. The attacker may have reached a host at many times,
and a later arrival can open a hop an earlier one can't (its window ends later), so each host
keeps every time it could be left at (forward) or entered at (backward) as a set of intervals,
not just the earliest arrival. A hop over a busy host pair is found by binary search on the
pair's sorted flow start times (graph.py), so it costs no more than over a quiet one.

Times are epoch seconds. Interval sets are sorted lists of disjoint closed intervals.

The hot loops read the DiGraph's adjacency dicts (g._succ, g._pred) directly: networkx's
read-only views around them cost about half the time of a search on a busy case.
"""
import heapq
from collections import namedtuple
from dataclasses import dataclass, field

from .graph import first_between, last_between, runs

INF = float("inf")

Hop = namedtuple("Hop", "src dst start")  # one flow, by its start time


# ---- interval sets ------------------------------------------------------------------------

def merge(intervals):
    out = []
    for lo, hi in sorted(intervals):
        if out and lo <= out[-1][1]:
            if hi > out[-1][1]:
                out[-1] = (out[-1][0], hi)
        else:
            out.append((lo, hi))
    return out


def intersect(a, b):
    out, i, j = [], 0, 0
    while i < len(a) and j < len(b):
        lo, hi = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        if lo <= hi:
            out.append((lo, hi))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return out


def subtract(a, b):
    """The parts of `a` not in `b`. A shared end point may stay in; that only repeats work."""
    out, j = [], 0
    for lo, hi in a:
        while j < len(b) and b[j][1] < lo:
            j += 1
        k, start, cut = j, lo, False
        while k < len(b) and b[k][0] <= hi:
            if b[k][0] > start:
                out.append((start, b[k][0]))
            start, cut = max(start, b[k][1]), True
            k += 1
        if start < hi or (start == hi and not cut):
            out.append((start, hi))
    return out


def _clip(intervals, bounds):
    return intersect(intervals, [bounds]) if bounds != (-INF, INF) else intervals


def _found(edge, intervals, window):
    """Runs of the edge's flows that start within the interval set."""
    return [r for lo, hi in intervals for r in runs(edge, window, lo, hi)]


# ---- reachability: threat lines -----------------------------------------------------------

@dataclass
class Reach:
    forward: bool
    # host -> interval set of the hop start times allowed out of it (forward) or into it
    # (backward). For a source, what it was given; for others, what the hops found give.
    allowed: dict
    hops: dict = field(default_factory=dict)   # host -> fewest hops from the sources
    via: dict = field(default_factory=dict)    # host -> the Hop that reached it in that many
    truncated: bool = False                    # stopped at max_hosts


def spread(g, sources, window, max_hops, forward=True, blocked=frozenset(), max_hosts=None,
           bounds=(-INF, INF), record=None):
    """Every host reachable from `sources` ({host: interval set}) under the time rule, within
    max_hops hops: forward along flows out of hosts, backward along flows into them.

    Layer k adds what k-hop chains reach. Each layer starts only from the time intervals the
    previous layer added, so a flow is looked at about once per search. With `record` (a
    dict), every hop of those chains goes into it: {(src, dst): [runs of their start times]}."""
    r = Reach(forward, {h: _clip(merge(iv), bounds) for h, iv in sources.items()})
    r.hops = {h: 0 for h in sources}
    delta = dict(r.allowed)
    for k in range(1, max_hops + 1):
        found, best = {}, {}
        for x, intervals in delta.items():
            if x not in g:
                continue
            for y, edge in (g._succ[x] if forward else g._pred[x]).items():
                if y == x or y in blocked:
                    continue
                found_runs = _found(edge, intervals, window)
                if not found_runs:
                    continue
                if record is not None:
                    record.setdefault((x, y) if forward else (y, x), []).extend(found_runs)
                if forward:   # arriving at y at time a allows leaving y within [a, a + window]
                    found.setdefault(y, []).extend((a, b + window) for a, b in found_runs)
                    hop = Hop(x, y, found_runs[0][0])                 # earliest arrival
                    if y not in best or hop.start < best[y].start:
                        best[y] = hop
                else:         # leaving y at time b needs being on y within [b - window, b]
                    found.setdefault(y, []).extend((a - window, b) for a, b in found_runs)
                    hop = Hop(y, x, found_runs[-1][1])                # latest departure
                    if y not in best or hop.start > best[y].start:
                        best[y] = hop
        delta = {}
        for y, intervals in sorted(found.items()):
            new = subtract(_clip(merge(intervals), bounds), r.allowed.get(y, []))
            if not new:
                continue
            if y not in r.allowed:
                if max_hosts and len(r.allowed) >= max_hosts:
                    r.truncated = True
                    continue
                r.hops[y], r.via[y] = k, best[y]
            r.allowed[y] = merge(r.allowed.get(y, []) + new)
            delta[y] = new
        if not delta:
            break
    return r


def tree_edges(r):
    """(src, dst, interval set) for the hop that reached each host: the start times at which
    flows on that host pair fit the line."""
    return [(h.src, h.dst, r.allowed[h.src] if r.forward else r.allowed[h.dst])
            for h in r.via.values()]


def threat_line(g, a, b, first, last, window, max_hops, blocked=frozenset(), max_hosts=None,
                bounds=(-INF, INF)):
    """Everything time-consistent with the conversation a -> b, whose flows started in
    [first, last]: who could have reached `a` before it (up), and where `b` could have gone
    after it (down)."""
    selected = runs(g[a][b], window, max(first, bounds[0]), min(last, bounds[1]))
    up = spread(g, {a: [(s - window, e) for s, e in selected]}, window, max_hops, False,
                blocked, max_hosts, bounds)
    down = spread(g, {b: [(s, e + window) for s, e in selected]}, window, max_hops, True,
                  blocked, max_hosts, bounds)
    return up, down


# ---- suspect flows: the lines into and out of marked hosts --------------------------------

def suspects(g, marks, window, max_hops, blocked=frozenset(), bounds=(-INF, INF), slack=0.0):
    """The suspect flows (D16): {(src, dst): interval set of their start times}.

    marks: {host: when the attacker reached it (epoch), or None if unknown}. A flow is suspect
    if it is a hop of a time-ordered chain that ends at a marked host no later than it was
    reached (any time if unknown), or one that starts at a marked host within `window` after
    it was reached (any time if unknown); at most max_hops hops, as spread() follows them."""
    found = {}
    for host, t in sorted(marks.items()):
        if host not in g or host in blocked:
            continue
        into = [(-INF, INF)] if t is None else [(-INF, t + slack)]
        out = [(-INF, INF)] if t is None else [(t - slack, t + window)]
        spread(g, {host: into}, window, max_hops, False, blocked, bounds=bounds, record=found)
        spread(g, {host: out}, window, max_hops, True, blocked, bounds=bounds, record=found)
    return {pair: merge(runs) for pair, runs in found.items()}


# ---- every path between two hosts: attack paths -------------------------------------------

MAX_STEPS = 500_000   # hops tried per search, so a pathological graph can't hang a request


def spread_into(g, b, tb, max_hops, blocked=frozenset(), slack=0.0, bounds=(-INF, INF)):
    """What the path search needs to prune with: the hosts that might still reach b by tb, each
    with the fewest hops to b and the latest time a hop into it could start.

    Both are optimistic (hops ignore time, times ignore the Window), so pruning on them never
    loses a path; paths_between() checks every hop exactly."""
    deadline = min(INF if tb is None else tb + slack, bounds[1])
    hops, frontier = {b: 0}, [b]
    for k in range(1, max_hops):                 # fewest hops to b, time ignored
        nxt = []
        for y in frontier:
            for x in g._pred[y]:
                if x not in hops and x not in blocked:
                    hops[x] = k
                    nxt.append(x)
        frontier = nxt
    if deadline == INF:                          # no deadline: time can't rule anything out
        return Reach(False, {h: [(-INF, INF)] for h in hops}, hops=hops)
    latest, heap = {b: deadline}, [(-deadline, b)]
    while heap:                                  # latest departure towards b, Window ignored
        t, y = heapq.heappop(heap)
        if -t < latest[y]:
            continue
        for x, edge in g._pred[y].items():
            if x == y or x not in hops:
                continue
            s = last_between(edge["times"], bounds[0], -t)
            if s is not None and s > latest.get(x, -INF):
                latest[x] = s
                heapq.heappush(heap, (-s, x))
    return Reach(False, {h: [(-INF, t)] for h, t in latest.items()},
                 hops={h: hops[h] for h in latest})


def paths_between(g, a, b, ta, tb, window, max_hops, blocked=frozenset(), data_start=None,
                  slack=0.0, bounds=(-INF, INF), max_paths=None, into_b=None):
    """Every path a -> ... -> b, no host twice, whose hops chain under the time rule: the
    first leaves a within `window` after ta, the last reaches b no later than tb.

    ta None: the first hop may happen at any time from data_start. tb None: no deadline.
    `slack` widens both (times entered in the UI are rounded to the millisecond).
    into_b: spread_into() for b, to share between searches towards the same b.

    Returns ([[Hop, ...], ...], truncated). Paths come shortest first, then by arrival at b.
    Each is shown by one chain of flows: the earliest arrival at b, and before each hop the
    latest flow that leads to it. truncated: stopped at max_paths or MAX_STEPS.
    """
    if a == b or a not in g or b not in g or a in blocked or b in blocked:
        return [], False
    if ta is None and data_start is None:
        return [], False
    if into_b is None:
        into_b = spread_into(g, b, tb, max_hops, blocked, slack, bounds)
    start = [(data_start, INF)] if ta is None else [(ta - slack, ta + window)]
    start = _clip(start, bounds)
    found, steps = [], 0
    nexts = {}

    def onward(x):
        # x's successors that can still reach b, in a fixed order: computed once per host, so
        # a hub with many dead-end peers is scanned once, and a capped list doesn't depend on
        # the order the evidence was read in.
        if x not in nexts:
            nexts[x] = sorted((y, e) for y, e in g._succ[x].items() if y in into_b.hops)
        return nexts[x]

    class Stop(Exception):
        pass

    def search(x, leave, hosts, entered, length):
        # leave: when hosts[-1] can be left; entered[i]: the times hop i could start at.
        nonlocal steps
        left = length - (len(hosts) - 1)              # hops still to take, including this one
        for y, edge in onward(x):
            if y in hosts:                            # (blocked hosts never reach b)
                continue
            if (y == b) != (left == 1) or into_b.hops.get(y, INF) > left - 1:
                continue                # b not reached in exactly `length` hops, or not in time
            steps += 1
            if steps > MAX_STEPS:
                raise Stop
            allowed = intersect(leave, into_b.allowed[y])
            arrivals = _found(edge, allowed, window)
            if not arrivals:
                continue
            if y == b:
                found.append(_chain(g, hosts + [b], entered + [allowed], window))
                if max_paths and len(found) > max_paths:
                    raise Stop
                continue
            nxt = _clip(merge((s, e + window) for s, e in arrivals), bounds)
            search(y, nxt, hosts + [y], entered + [allowed], length)

    truncated = False
    try:
        for length in range(1, max_hops + 1):     # shortest first, so a cut keeps those
            search(a, start, [a], [], length)
    except Stop:
        truncated = True
    found.sort(key=lambda p: (len(p), p[-1].start, [h.dst for h in p]))
    return found[:max_paths] if max_paths else found, truncated


def _chain(g, hosts, entered, window):
    """One chain of flows along `hosts`: the earliest arrival at the last host, and before
    each hop the latest flow that fits (within `window` before it, and allowed for that hop)."""
    hops = []
    times = g[hosts[-2]][hosts[-1]]["times"]
    t = min(s for s in (first_between(times, lo, hi) for lo, hi in entered[-1]) if s is not None)
    hops.append(Hop(hosts[-2], hosts[-1], t))
    for i in range(len(hosts) - 2, 0, -1):
        times = g[hosts[i - 1]][hosts[i]]["times"]
        t = max(s for s in (last_between(times, max(lo, t - window), min(hi, t))
                            for lo, hi in entered[i - 1]) if s is not None)
        hops.append(Hop(hosts[i - 1], hosts[i], t))
    return hops[::-1]


def attack_paths(g, compromised, window, max_hops, blocked=frozenset(), data_start=None,
                 slack=0.0, bounds=(-INF, INF), max_paths=None):
    """The paths between each ordered pair of compromised hosts (see paths_between).

    compromised: {ip: compromise time (epoch) or None if unknown}. A path a -> b must leave a
    after a's compromise time and reach b no later than b's. Returns
    [(a, b, [[Hop, ...], ...], truncated), ...] for the pairs with paths; max_paths per pair."""
    out = []
    for b, tb in sorted(compromised.items()):
        if b not in g or b in blocked:
            continue
        into_b = spread_into(g, b, tb, max_hops, blocked, slack, bounds)
        for a, ta in sorted(compromised.items()):
            paths, cut = paths_between(g, a, b, ta, tb, window, max_hops, blocked, data_start,
                                       slack, bounds, max_paths, into_b)
            if paths:
                out.append((a, b, paths, cut))
    out.sort(key=lambda pair: pair[:2])
    return out
