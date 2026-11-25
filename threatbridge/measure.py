"""How well the map finds an attack (item 13, D35).

Attack chains go into a case with known hops, and each is looked for the way an analyst would,
from two indicators: the victim's first contact with its command-and-control address (the
victim and that time), and an alert on the chain's last hop (that connection and its time).

- Suspect connections (D16): the victim marked compromised at its first contact. Which true
  hops are suspect, and how many hosts the analyst is pointed at.
- Attack paths (ATK-1): between the victim at its first contact and the last hop's target at
  its time. Which true hops' host pairs lie on a listed path (a path shows the earliest flow of
  a pair that keeps the order, which may not be the attacker's), whether the chain itself is
  listed, how many paths and hosts.
- Threat line (INT-1): through the alerted connection. Which of the chain's hosts are on it,
  and how many hosts it holds.

Each against the hosts active over the chain's span, with the time each took. The synthetic
case (office()) runs in CI with floors (tests/test_detection.py); public data with ground truth
runs through scripts/lanl.py (docs/RESULTS.md).

    python -m threatbridge.measure          # the synthetic case's table
"""
import random
import time
from collections import namedtuple
from datetime import timedelta

from . import analysis
from .backends import TIME_SLACK, CaseBackend
from .config import Config
from .model import Flow

T0 = 1_714_564_800.0                      # 2024-05-01T12:00:00Z
DC, DNS, PROXY, FILES = "10.0.0.1", "10.0.0.53", "10.0.0.80", "10.0.0.20"
APPS = [f"10.0.1.{i}" for i in range(1, 11)]
ADMINS = [f"10.2.0.{i}" for i in range(1, 6)]

# A chain: where it starts, (victim, time), the indicator an analyst would have; the victim's
# outbound contact (src, dst, dport, start), if known; and its hops inward [(src, dst, dport,
# start)], the last of them alerted on.
Chain = namedtuple("Chain", "name entry contact hops")


def _flow(src, dst, dport, t, rng, proto="tcp", source="synthetic"):
    return Flow(src, dst, rng.randrange(40000, 65000), dport, proto, t, t + rng.uniform(0.01, 30),
                rng.randrange(4, 400), rng.randrange(200, 400_000), source)


def office(seed=1, workstations=300, hours=24, n=30_000):
    """A day of office traffic: workstations to the domain controller, DNS, the proxy and the
    file server; the proxy to the Internet; administrators' jump hosts to servers; now and then
    one workstation to another."""
    rng = random.Random(seed)
    ws = [f"10.1.{i // 250}.{i % 250 + 1}" for i in range(workstations)]
    outside = [f"203.0.113.{i}" for i in range(1, 201)]
    flows = []
    for _ in range(n):
        t = T0 + rng.random() * hours * 3600
        r = rng.random()
        if r < 0.40:
            flows.append(_flow(rng.choice(ws), DC, rng.choice([88, 389, 445, 135]), t, rng))
        elif r < 0.55:
            flows.append(_flow(rng.choice(ws), DNS, 53, t, rng, proto="udp"))
        elif r < 0.70:
            flows.append(_flow(rng.choice(ws), PROXY, 3128, t, rng))
        elif r < 0.80:
            flows.append(_flow(PROXY, rng.choice(outside), 443, t, rng))
        elif r < 0.90:
            flows.append(_flow(rng.choice(ws), FILES, 445, t, rng))
        elif r < 0.95:
            flows.append(_flow(rng.choice(ws), rng.choice(APPS), rng.choice([443, 1433]), t, rng))
        elif r < 0.98:
            flows.append(_flow(rng.choice(ADMINS), rng.choice(APPS + [DC, FILES]), rng.choice([3389, 5985]), t, rng))
        else:
            a, b = rng.sample(ws, 2)
            flows.append(_flow(a, b, rng.choice([445, 135]), t, rng))
    return flows, ws


def chains(flows, ws, seed=2, count=3):
    """Attack chains through busy hosts and through quiet ones (after Apruzzese et al.): an
    outbound contact from a workstation, then three hops inward 10 to 40 minutes apart, during
    the working day. Busy chains go through the hosts with the most flows, on the ports
    everyone uses; quiet ones through hosts with the fewest, on rarer ports."""
    rng = random.Random(seed)
    activity = {}
    for f in flows:
        for h in (f.src, f.dst):
            activity[h] = activity.get(h, 0) + 1
    by_activity = sorted(ws, key=lambda h: (activity.get(h, 0), h))
    quiet, busy = by_activity[:len(ws) // 5], by_activity[-len(ws) // 5:]
    out = []
    for kind, pool, ports, last in (("busy", busy, [445, 3389, 445], DC), ("quiet", quiet, [5985, 22, 5985], APPS[-1])):
        for i in range(count):
            victim, h1, h2 = rng.sample(pool, 3)
            t = T0 + rng.uniform(1, 6) * 3600
            contact = (victim, f"198.51.100.{10 * i + (1 if kind == 'busy' else 5)}", 443, t)
            hops = []
            for src, dst, port in ((victim, h1, ports[0]), (h1, h2, ports[1]), (h2, last, ports[2])):
                t += rng.uniform(10, 40) * 60
                hops.append((src, dst, port, t))
            out.append(Chain(f"{kind} {i + 1}", (victim, contact[3]), contact, hops))
    return out


def inject(flows, found_chains, seed=3):
    """The flows of the chains' hops, added to `flows`."""
    rng = random.Random(seed)
    return flows + [_flow(s, d, p, t, rng, source="attack") for c in found_chains
                    for s, d, p, t in ([c.contact] if c.contact else []) + c.hops]


def _active(g, lo, hi):
    """The hosts with a flow that started in [lo, hi]."""
    found = set()
    for a, b, data in g.edges(data=True):
        times = data["times"]
        i = next((k for k, t in enumerate(times) if t >= lo), None)
        if i is not None and times[i] <= hi:
            found.update((a, b))
    return found


def _within(t, runs, tolerance):
    return any(a - tolerance <= t <= b + tolerance for a, b in runs)


def measure(backend, chain, window=timedelta(hours=24), max_hops=6, max_hosts=300, max_paths=500,
            tolerance=TIME_SLACK, cache=None):
    """One chain looked for (module docstring): {"suspects": {...}, "paths": {...}, "line": {...},
    "active": hosts active over its span, "seen": its hops with a flow of their host pair near
    their time}. A true hop is found when the result holds its host pair at its time, within
    `tolerance` seconds (public data's logs and flows differ in time). With `cache` (a dict),
    chains from the same entry share one search for suspects; its time is counted once."""
    g, w = backend.graph, window.total_seconds()
    victim, t0 = chain.entry
    a, b, _, t_last = chain.hops[-1]
    every = ([chain.contact] if chain.contact else []) + chain.hops
    hosts = {h for s, d, _, _ in every for h in (s, d)}
    seen = sum(1 for s, d, _, t in every
               if g.has_edge(s, d) and any(abs(u - t) <= max(TIME_SLACK, tolerance) for u in g[s][d]["times"]))
    out = {"active": len(_active(g, t0 - w, t_last + w)), "seen": seen, "hops": len(every)}

    clock = time.perf_counter()
    key = (victim, t0, w, max_hops, tolerance)
    if cache is not None and key in cache:
        found = cache[key]
    else:
        found = analysis.suspects(g, {victim: t0}, w, max_hops, slack=max(TIME_SLACK, tolerance))
        if cache is not None:
            cache[key] = found
    out["suspects"] = {
        "found": sum(1 for (s, d, _, t) in every if _within(t, found.get((s, d), []), tolerance)),
        "of": len(every), "hosts": len({h for pair in found for h in pair}), "seconds": time.perf_counter() - clock}

    clock = time.perf_counter()
    pairs = analysis.attack_paths(g, {victim: t0, b: t_last}, w, max_hops, data_start=None,
                                  slack=max(TIME_SLACK, tolerance), max_paths=max_paths)
    paths = [p for x, y, ps, _ in pairs if (x, y) == (victim, b) for p in ps]
    cut = any(c for x, y, _, c in pairs if (x, y) == (victim, b))
    on_paths = {(h.src, h.dst) for p in paths for h in p}
    route = [chain.hops[0][0]] + [d for _, d, _, _ in chain.hops]
    out["paths"] = {
        "found": sum(1 for s, d, _, _ in chain.hops if (s, d) in on_paths), "of": len(chain.hops),
        "chain": any([p[0].src] + [h.dst for h in p] == route for p in paths), "paths": len(paths), "truncated": cut,
        "hosts": len({h for p in paths for hop in p for h in (hop.src, hop.dst)}), "seconds": time.perf_counter() - clock}

    clock = time.perf_counter()
    up, down = analysis.threat_line(g, a, b, t_last - tolerance, t_last + tolerance, w, max_hops, max_hosts=max_hosts)
    line = set(up.allowed) | set(down.allowed)
    out["line"] = {"found": len(hosts & line), "of": len(hosts), "hosts": len(line),
                   "truncated": up.truncated or down.truncated, "seconds": time.perf_counter() - clock}
    return out


def synthetic(seed=1):
    """The synthetic case and its chains: (CaseBackend, [Chain])."""
    flows, ws = office(seed)
    found = chains(flows, ws, seed + 1)
    return CaseBackend(Config(backend="case"), flows=inject(flows, found, seed + 2)), found


def table(results):
    """A Markdown table of [(chain name, measure())]."""
    rows = ["| Chain | Active hosts | Hops seen in flows | Suspect hops | Suspect hosts | Path hops | Chain listed | "
            "Paths | Path hosts | Chain hosts on the line | Line hosts | Milliseconds (suspects, paths, line) |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for name, r in results:
        s, p, line = r["suspects"], r["paths"], r["line"]
        rows.append(f"| {name} | {r['active']} | {r['seen']}/{r['hops']} | {s['found']}/{s['of']} | {s['hosts']} | "
                    f"{p['found']}/{p['of']} | "
                    f"{'yes' if p['chain'] else 'no'} | {p['paths']}{'+' if p['truncated'] else ''} | {p['hosts']} | "
                    f"{line['found']}/{line['of']} | {line['hosts']}{'+' if line['truncated'] else ''} | "
                    f"{1000 * s['seconds']:.0f}, {1000 * p['seconds']:.0f}, {1000 * line['seconds']:.0f} |")
    return "\n".join(rows)


if __name__ == "__main__":
    case, found = synthetic()
    print(table([(c.name, measure(case, c)) for c in found]))
