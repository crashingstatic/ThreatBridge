"""Time-respecting traversal of the connection graph: threat lines and attack paths.

A hop A -> B counts only if its flow starts no earlier than the attacker could have been on A,
and at most `window` seconds later. That is the rule the map applies when an analyst expands
hosts by hand, done automatically and to a hop limit.

Each search keeps one best hop per host: the earliest arrival going forward, the latest
departure going backward. The result is a tree that explains how each host was reached.
"""
import heapq
from dataclasses import dataclass, field

INF = float("inf")


@dataclass
class Reach:
    origin: str
    forward: bool
    window: float
    unbounded_first_hop: bool = False
    time: dict = field(default_factory=dict)  # host -> arrival (forward) / departure (backward)
    via: dict = field(default_factory=dict)   # host -> the Flow on its tree hop
    hops: dict = field(default_factory=dict)
    truncated: bool = False                    # stopped at max_hosts

    def interval(self, src, dst):
        """Start times allowed for flows on the tree hop src -> dst."""
        if self.forward:
            t = self.time[src]
            return t, INF if (src == self.origin and self.unbounded_first_hop) else t + self.window
        t = self.time[dst]
        return t - self.window, t


def forward(g, origin, t0, window, max_hops, blocked=frozenset(), max_hosts=None,
            unbounded_first_hop=False):
    """Earliest-arrival search from `origin`, present on it from time t0."""
    r = Reach(origin, True, window, unbounded_first_hop, {origin: t0}, {}, {origin: 0})
    heap, done = [(t0, origin)], set()
    while heap:
        t, n = heapq.heappop(heap)
        if n in done:
            continue
        done.add(n)
        if r.hops[n] >= max_hops:
            continue
        hi = INF if (n == origin and unbounded_first_hop) else t + window
        for _, v, f in g.out_edges(n, data="flow"):
            if v == n or v in blocked or not t <= f.start <= hi:
                continue
            if f.start < r.time.get(v, INF):
                if v not in r.time and max_hosts and len(r.time) >= max_hosts:
                    r.truncated = True
                    continue
                r.time[v], r.via[v], r.hops[v] = f.start, f, r.hops[n] + 1
                heapq.heappush(heap, (f.start, v))
    return r


def backward(g, origin, t0, window, max_hops, blocked=frozenset(), max_hosts=None):
    """Latest-departure search into `origin`: who could have reached it by time t0."""
    r = Reach(origin, False, window, False, {origin: t0}, {}, {origin: 0})
    heap, done = [(-t0, origin)], set()
    while heap:
        neg_t, n = heapq.heappop(heap)
        t = -neg_t
        if n in done:
            continue
        done.add(n)
        if r.hops[n] >= max_hops:
            continue
        for u, _, f in g.in_edges(n, data="flow"):
            if u == n or u in blocked or not t - window <= f.start <= t:
                continue
            if f.start > r.time.get(u, -INF):
                if u not in r.time and max_hosts and len(r.time) >= max_hosts:
                    r.truncated = True
                    continue
                r.time[u], r.via[u], r.hops[u] = f.start, f, r.hops[n] + 1
                heapq.heappush(heap, (-f.start, u))
    return r


def tree_edges(r):
    """(src, dst, lo, hi) for each hop of a search tree: the hop and its allowed time range."""
    out = []
    for host, f in r.via.items():
        src, dst = (f.src, host) if r.forward else (host, f.dst)
        lo, hi = r.interval(src, dst)
        out.append((src, dst, lo, hi))
    return out


def path_to(r, target):
    """Flows from the origin of a forward search to `target`, in order."""
    hops = []
    while target in r.via:
        f = r.via[target]
        hops.append(f)
        target = f.src
    return hops[::-1]


def threat_line(g, a, b, first, last, window, max_hops, blocked=frozenset(), max_hosts=None):
    """Everything time-consistent with the conversation a -> b, whose flows started in
    [first, last]: who could have reached `a` before it (up), and where `b` could have
    gone after it (down)."""
    up = backward(g, a, last, window, max_hops, blocked, max_hosts)
    down = forward(g, b, first, window, max_hops, blocked, max_hosts)
    return up, down


def attack_paths(g, compromised, window, max_hops, blocked=frozenset(), data_start=None,
                 slack=0.0):
    """Time-respecting paths between compromised hosts.

    compromised: {ip: compromise time (epoch) or None if unknown}. A path a -> b must leave a
    after a's compromise time and reach b no later than b's. When a's time is unknown the
    first hop may happen at any time in the data. `slack` widens both time limits (compromise
    times entered in the UI are rounded to the millisecond). Returns [(a, b, [Flow, ...])].
    """
    paths = []
    for a, ta in sorted(compromised.items()):
        if a not in g or a in blocked:
            continue
        unknown = ta is None
        t0 = data_start if unknown else ta - slack
        if t0 is None:
            continue
        r = forward(g, a, t0, window, max_hops, blocked, unbounded_first_hop=unknown)
        for b, tb in sorted(compromised.items()):
            if b == a or b not in r.via:
                continue
            if tb is not None and r.time[b] > tb + slack:
                continue
            paths.append((a, b, path_to(r, b)))
    return paths
