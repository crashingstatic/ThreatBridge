"""Beacons: the same source, destination, port and protocol connected again and again at regular
intervals, with sizes alike, as malware calling home does.

Each group of a case's flows with the same (src, dst, dport, proto) and at least FLOOR flows is
scored when the case is built. The score, from 0 to 1, is the mean of a timing score and a size
score, each the mean of two parts, after the method RITA describes (its code is not used):

- symmetry: 1 - |Bowley skewness| of the values (the intervals between starts, or the bytes),
  which is 1 when the quartiles sit evenly around the median;
- spread: 1 - (median absolute deviation / median), at least 0, which is 1 when the values are
  all alike and falls as they scatter (jitter).

Settings decide what counts as a beacon when asked (TB_BEACON_SCORE, TB_BEACON_MIN), so they can
change without rebuilding the case.
"""
from statistics import median, quantiles

FLOOR = 5     # flows a group needs to be scored at all


def _regularity(values):
    """(symmetry, spread, median, median absolute deviation) of `values`, each score 0 to 1."""
    q1, q2, q3 = quantiles(values, n=4, method="inclusive")
    symmetry = 1.0 if q3 == q1 else 1.0 - min(1.0, abs((q3 + q1 - 2 * q2) / (q3 - q1)))
    mad = median(abs(v - q2) for v in values)
    if q2 > 0:
        spread = max(0.0, 1.0 - mad / q2)
    else:
        spread = 1.0 if mad == 0 else 0.0
    return symmetry, spread, q2, mad


def score(starts, sizes):
    """The beacon score of one group from its flows' start times (sorted) and bytes:
    {"interval": median seconds between starts, "jitter": their median absolute deviation as
    a share of it, "size_jitter": the same for bytes, "score": 0 to 1}; None below FLOOR flows."""
    if len(starts) < FLOOR:
        return None
    intervals = [b - a for a, b in zip(starts, starts[1:])]
    t_sym, t_spread, interval, t_mad = _regularity(intervals)
    s_sym, s_spread, size, s_mad = _regularity(sizes)
    timing, sizing = (t_sym + t_spread) / 2, (s_sym + s_spread) / 2
    return {"interval": interval, "jitter": t_mad / interval if interval else 0.0,
            "size_jitter": s_mad / size if size else 0.0, "score": round((timing + sizing) / 2, 4)}


def groups(rows):
    """(src, dst, dport, proto, flows, first start, last start, score dict) for each group of
    `rows` (src, dst, dport, proto, start, bytes), sorted by group then start, that is scored."""
    key, starts, sizes = None, [], []

    def done():
        found = score(starts, sizes)
        return None if found is None else (*key, len(starts), starts[0], starts[-1], found)

    for src, dst, dport, proto, start, nbytes in rows:
        if (src, dst, dport, proto) != key:
            if key is not None:
                found = done()
                if found:
                    yield found
            key, starts, sizes = (src, dst, dport, proto), [], []
        starts.append(start)
        sizes.append(nbytes or 0)
    if key is not None:
        found = done()
        if found:
            yield found
