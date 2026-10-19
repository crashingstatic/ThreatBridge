"""Connection graph: a NetworkX MultiDiGraph with one edge per flow, initiator -> responder.

Hosts (IP strings) are nodes; each edge carries its Flow under the "flow" attribute.
"""
import networkx as nx


def build_graph(flows):
    g = nx.MultiDiGraph()
    for f in flows:
        g.add_edge(f.src, f.dst, flow=f)
    return g


def time_span(g):
    """(earliest start, latest end) over all flows, as epoch seconds; None if empty."""
    start = end = None
    for _, _, f in g.edges(data="flow"):
        if start is None or f.start < start:
            start = f.start
        if end is None or f.end > end:
            end = f.end
    return None if start is None else (start, end)


def host_flows(g, host, direction, start=None, end=None):
    """Flows into ("in") or out of ("out") a host that started within [start, end]."""
    if host not in g:
        return
    edges = g.in_edges(host, data="flow") if direction == "in" else g.out_edges(host, data="flow")
    for _, _, f in edges:
        if (start is None or f.start >= start) and (end is None or f.start <= end):
            yield f
