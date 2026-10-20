"""Connection graph: a NetworkX DiGraph with one edge per host pair, initiator -> responder.

Each edge carries `times`: the sorted start times (epoch seconds) of the flows from src to dst.
The flows themselves are in the FlowStore (store.py). Time-ordered searches need only the
times, and visit each host pair once instead of every flow.
"""
from array import array
from bisect import bisect_left, bisect_right
from collections import defaultdict

import networkx as nx


def build_graph(pairs):
    """pairs: (src, dst, start) for each flow."""
    times = defaultdict(list)
    for src, dst, start in pairs:
        times[(src, dst)].append(start)
    g = nx.DiGraph()
    for (src, dst), ts in times.items():
        ts.sort()
        g.add_edge(src, dst, times=array("d", ts))
    return g


def first_between(times, lo, hi):
    """Earliest time in [lo, hi], or None."""
    i = bisect_left(times, lo)
    return times[i] if i < len(times) and times[i] <= hi else None


def count_between(times, lo, hi):
    """(how many, earliest, latest) of the times in [lo, hi]; (0, None, None) if none."""
    i, j = bisect_left(times, lo), bisect_right(times, hi)
    return (j - i, times[i], times[j - 1]) if j > i else (0, None, None)


def last_between(times, lo, hi):
    """Latest time in [lo, hi], or None."""
    i = bisect_right(times, hi)
    return times[i - 1] if i and times[i - 1] >= lo else None
