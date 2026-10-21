"""Time-respecting traversal of the connection graph: threat lines and attack paths.

A hop A -> B counts only if its flow starts no earlier than the attacker could have been on A,
and at most `window` seconds later. That is the rule the map applies when an analyst expands
hosts by hand, done automatically and to a hop limit.

An optional `bounds` (lo, hi) is the analyst's time range: flows starting outside it are
ignored.

Each search keeps one best hop per host: the earliest arrival going forward, the latest
departure going backward. The result is a tree that explains how each host was reached.

The graph is graph.py's DiGraph: per host pair, the sorted start times of its flows. Finding
the best flow on a pair is a binary search, so a busy pair costs no more than a quiet one.
"""
import heapq
from collections import namedtuple
from dataclasses import dataclass, field

from .graph import first_between, last_between

INF = float("inf")

Hop = namedtuple("Hop", "src dst start")  # one flow on a search tree, by its start time


@dataclass
class Reach:
    origin: str
    forward: bool
    window: float
    unbounded_first_hop: bool = False
    bounds: tuple = (-INF, INF)               # only flows starting in [lo, hi]
    time: dict = field(default_factory=dict)  # host -> arrival (forward) / departure (backward)
    via: dict = field(default_factory=dict)   # host -> the Hop on its tree edge
    hops: dict = field(default_factory=dict)
    truncated: bool = False                    # stopped at max_hosts

    def allowed(self, n):
        """Start times allowed for a hop out of n (forward) or into n (backward)."""
        t = self.time[n]
        lo, hi = self.bounds
        if self.forward:
            top = INF if (n == self.origin and self.unbounded_first_hop) else t + self.window
            return max(t, lo), min(top, hi)
        return max(t - self.window, lo), min(t, hi)

    def interval(self, src, dst):
        """Start times allowed for flows on the tree hop src -> dst."""
        return self.allowed(src if self.forward else dst)


def forward(g, origin, t0, window, max_hops, blocked=frozenset(), max_hosts=None,
            unbounded_first_hop=False, bounds=(-INF, INF)):
    """Earliest-arrival search from `origin`, present on it from time t0."""
    r = Reach(origin, True, window, unbounded_first_hop, bounds, {origin: t0}, {}, {origin: 0})
    heap, done = [(t0, origin)], set()
    while heap:
        t, n = heapq.heappop(heap)
        if n in done:
            continue
        done.add(n)
        if r.hops[n] >= max_hops:
            continue
        lo, hi = r.allowed(n)
        for v, edge in g.succ[n].items():
            if v == n or v in blocked:
                continue
            start = first_between(edge["times"], lo, hi)
            if start is not None and start < r.time.get(v, INF):
                if v not in r.time and max_hosts and len(r.time) >= max_hosts:
                    r.truncated = True
                    continue
                r.time[v], r.via[v], r.hops[v] = start, Hop(n, v, start), r.hops[n] + 1
                heapq.heappush(heap, (start, v))
    return r


def backward(g, origin, t0, window, max_hops, blocked=frozenset(), max_hosts=None,
             bounds=(-INF, INF)):
    """Latest-departure search into `origin`: who could have reached it by time t0."""
    r = Reach(origin, False, window, False, bounds, {origin: t0}, {}, {origin: 0})
    heap, done = [(-t0, origin)], set()
    while heap:
        neg_t, n = heapq.heappop(heap)
        t = -neg_t
        if n in done:
            continue
        done.add(n)
        if r.hops[n] >= max_hops:
            continue
        lo, hi = r.allowed(n)
        for u, edge in g.pred[n].items():
            if u == n or u in blocked:
                continue
            start = last_between(edge["times"], lo, hi)
            if start is not None and start > r.time.get(u, -INF):
                if u not in r.time and max_hosts and len(r.time) >= max_hosts:
                    r.truncated = True
                    continue
                r.time[u], r.via[u], r.hops[u] = start, Hop(u, n, start), r.hops[n] + 1
                heapq.heappush(heap, (-start, u))
    return r


def tree_edges(r):
    """(src, dst, lo, hi) for each hop of a search tree: the hop and its allowed time range."""
    return [(h.src, h.dst, *r.interval(h.src, h.dst)) for h in r.via.values()]


def path_to(r, target):
    """Hops from the origin of a forward search to `target`, in order."""
    hops = []
    while target in r.via:
        hop = r.via[target]
        hops.append(hop)
        target = hop.src
    return hops[::-1]


def threat_line(g, a, b, first, last, window, max_hops, blocked=frozenset(), max_hosts=None,
                bounds=(-INF, INF)):
    """Everything time-consistent with the conversation a -> b, whose flows started in
    [first, last]: who could have reached `a` before it (up), and where `b` could have
    gone after it (down)."""
    up = backward(g, a, last, window, max_hops, blocked, max_hosts, bounds=bounds)
    down = forward(g, b, first, window, max_hops, blocked, max_hosts, bounds=bounds)
    return up, down


def attack_paths(g, compromised, window, max_hops, blocked=frozenset(), data_start=None,
                 slack=0.0, bounds=(-INF, INF)):
    """Time-respecting paths between compromised hosts.

    compromised: {ip: compromise time (epoch) or None if unknown}. A path a -> b must leave a
    after a's compromise time and reach b no later than b's. When a's time is unknown the
    first hop may happen at any time in the data. `slack` widens both time limits (compromise
    times entered in the UI are rounded to the millisecond). Returns [(a, b, [Hop, ...])].
    """
    paths = []
    for a, ta in sorted(compromised.items()):
        if a not in g or a in blocked:
            continue
        unknown = ta is None
        t0 = data_start if unknown else ta - slack
        if t0 is None:
            continue
        r = forward(g, a, t0, window, max_hops, blocked, unbounded_first_hop=unknown,
                    bounds=bounds)
        for b, tb in sorted(compromised.items()):
            if b == a or b not in r.via:
                continue
            if tb is not None and r.time[b] > tb + slack:
                continue
            paths.append((a, b, path_to(r, b)))
    return paths
