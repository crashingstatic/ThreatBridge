"""Data backends.

neighbors() returns {"peers": [...], "distinct_peers": int|None, "truncated": bool}
where each peer is {"peer", "count", "first_seen", "last_seen", "ports"}.

flows() returns {"total": int, "flows": [...]}: one page of a connection's flows, oldest
first, each {"start", "duration", "sport", "dport", "proto", "packets", "bytes"} (duration in
seconds; any but start may be None).

Times are ISO-8601 UTC strings.
"""
import fcntl
import hashlib
import ipaddress
import logging
import os
import random
import sqlite3
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import requests

from . import analysis, sources
from .graph import build_graph, count_between, first_between
from .query import (ValidationError, es_details_body, es_flows_body, es_scan_body, es_top_body,
                    fmt_time, parse_time)
from .store import FlowStore, NotAStore

log = logging.getLogger(__name__)
SCAN_PAGE = 1000
# Elasticsearch's default index.max_result_window: from + size may not go past it.
ES_MAX_RESULTS = 10000
# Times reach the browser rounded down to the millisecond (fmt_time) and come back that way,
# so case queries allow this much either side.
TIME_SLACK = 0.001


class BackendError(RuntimeError):
    pass


class ElasticBackend:
    def __init__(self, cfg):
        self.cfg = cfg
        self.session = requests.Session()
        if cfg.es_user:
            self.session.auth = (cfg.es_user, cfg.es_pass or "")
        self.session.verify = cfg.es_ca if cfg.es_ca else cfg.es_verify
        self.session.headers["Content-Type"] = "application/json"

    def _search(self, body):
        return self._post(body).get("aggregations", {})

    def _post(self, body):
        url = f"{self.cfg.es_url.rstrip('/')}/{self.cfg.es_index}/_search"
        try:
            resp = self.session.post(url, json=body, timeout=self.cfg.es_timeout,
                                     params={"ignore_unavailable": "true"})
        except requests.RequestException as e:
            raise BackendError(f"Elasticsearch request failed: {e.__class__.__name__}")
        if resp.status_code != 200:
            raise BackendError(f"Elasticsearch returned HTTP {resp.status_code}")
        return resp.json()

    def neighbors(self, ip, direction, start, end, limit, order, exclude):
        if order == "top":
            aggs = self._search(es_top_body(self.cfg, ip, direction, start, end, limit, exclude))
            peers = [self._bucket(b) for b in aggs.get("peers", {}).get("buckets", [])]
            return {"peers": peers, "distinct_peers": aggs.get("distinct", {}).get("value"),
                    "truncated": False}
        return self._rarest(ip, direction, start, end, limit, exclude)

    def _rarest(self, ip, direction, start, end, limit, exclude):
        """Exact bottom-N: count every distinct peer (up to the cap), sort ascending."""
        cap = self.cfg.rare_scan_cap
        counts, after, truncated = [], None, False
        while True:
            body = es_scan_body(self.cfg, ip, direction, start, end, exclude,
                                min(SCAN_PAGE, cap - len(counts)), after)
            scan = self._search(body).get("scan", {})
            buckets = scan.get("buckets", [])
            counts.extend((b["key"]["peer"], b["doc_count"]) for b in buckets)
            after = scan.get("after_key")
            if not buckets or not after:
                break
            if len(counts) >= cap:
                truncated = True
                break
        counts.sort(key=lambda kv: (kv[1], kv[0]))
        chosen = [peer for peer, _ in counts[:limit]]
        peers = []
        if chosen:
            aggs = self._search(es_details_body(self.cfg, ip, direction, start, end, chosen, exclude))
            peers = [self._bucket(b) for b in aggs.get("peers", {}).get("buckets", [])]
            peers.sort(key=lambda p: (p["count"], p["peer"]))
        return {"peers": peers, "distinct_peers": len(counts), "truncated": truncated}

    @staticmethod
    def _agg_time(agg):
        if agg.get("value_as_string"):
            return agg["value_as_string"]
        if agg.get("value") is not None:
            return fmt_time(datetime.fromtimestamp(agg["value"] / 1000.0, timezone.utc))
        return None

    def _bucket(self, b):
        return {
            "peer": b["key"],
            "count": b["doc_count"],
            "first_seen": self._agg_time(b.get("first_seen", {})),
            "last_seen": self._agg_time(b.get("last_seen", {})),
            "ports": [p["key"] for p in b.get("ports", {}).get("buckets", [])],
        }

    def flows(self, src, dst, start, end, offset, limit):
        if offset + limit > ES_MAX_RESULTS:
            raise ValidationError(f"Security Onion lists only the first {ES_MAX_RESULTS} flows of "
                                  "a connection; narrow the time range to see later ones")
        hits = self._post(es_flows_body(self.cfg, src, dst, start, end, offset, limit)).get("hits", {})
        return {"total": hits.get("total", {}).get("value", 0),
                "flows": [self._flow(h.get("fields", {})) for h in hits.get("hits", [])]}

    def _flow(self, fields):
        def one(name):
            values = fields.get(name)
            return values[0] if values else None

        def number(name):  # None when missing or not numeric (e.g. mapped as a string)
            try:
                return float(one(name))
            except (TypeError, ValueError):
                return None

        def total(names):
            values = [v for v in map(number, names) if v is not None]
            return int(sum(values)) if values else None
        cfg = self.cfg
        return {"start": fmt_time(parse_time(one(cfg.f_ts))), "duration": number(cfg.f_duration),
                "sport": one(cfg.f_sport), "dport": one(cfg.f_dport), "proto": one(cfg.f_proto),
                "packets": total(cfg.f_packets), "bytes": total(cfg.f_bytes)}


class DemoBackend:
    """Deterministic fake data so the UI can be exercised without Security Onion."""

    PORTS = [22, 53, 80, 443, 445, 3389, 5985, 8080]

    def __init__(self, cfg):
        self.cfg = cfg

    @staticmethod
    def _rng(key):
        return random.Random(int(hashlib.sha256(key.encode()).hexdigest()[:12], 16))

    def _pair(self, src, dst):
        """A random generator for the host pair, and how many flows the pair has."""
        rng = self._rng(f"{src}>{dst}")
        return rng, rng.choice([1, 2, 3, rng.randint(4, 500)])

    def neighbors(self, ip, direction, start, end, limit, order, exclude):
        rng = self._rng(f"{ip}|{direction}")
        span = max((end - start).total_seconds(), 1)
        nets = [ipaddress.ip_network(e) for e in exclude]
        seen = {}
        for _ in range(rng.randint(3, 12)):
            peer = f"10.{rng.randint(0, 3)}.{rng.randint(0, 9)}.{rng.randint(2, 30)}"
            if peer == ip or peer in seen:
                continue
            _, count = self._pair(*((peer, ip) if direction == "in" else (ip, peer)))
            a = start + timedelta(seconds=rng.uniform(0, span))
            b = a if count == 1 else start + timedelta(seconds=rng.uniform(0, span))
            seen[peer] = {
                "peer": peer,
                "count": count,
                "first_seen": fmt_time(min(a, b)),
                "last_seen": fmt_time(max(a, b)),
                "ports": sorted(rng.sample(self.PORTS, rng.randint(1, 3))),
            }
        peers = [p for p in seen.values()
                 if not any(ipaddress.ip_address(p["peer"]) in n for n in nets)]
        if order == "top":
            peers.sort(key=lambda p: (-p["count"], p["peer"]))
        else:
            peers.sort(key=lambda p: (p["count"], p["peer"]))
        return {"peers": peers[:limit], "distinct_peers": len(peers), "truncated": False}

    def flows(self, src, dst, start, end, offset, limit):
        # As many flows as neighbors() reports for the pair, the first and last at the ends
        # of [start, end] (the connection's first and last seen).
        rng, count = self._pair(src, dst)
        span = (end - start).total_seconds()
        starts = sorted([start, end][:count] +
                        [start + timedelta(seconds=rng.uniform(0, span)) for _ in range(count - 2)])
        rows = [{"start": fmt_time(t), "duration": round(rng.expovariate(0.2), 3),
                 "sport": rng.randint(1024, 65535), "dport": rng.choice(self.PORTS), "proto": "tcp",
                 "packets": rng.randint(2, 400), "bytes": rng.randint(120, 500000)} for t in starts]
        return {"total": count, "flows": rows[offset:offset + limit]}


def _utc(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc)


class CaseBackend:
    """Post-mortem: flows read from tcpdump and nfdump files.

    The flows go into a SQLite store (store.py) and a DiGraph of host pairs and flow start
    times (graph.py). With `cfg.case_db` set, the store is kept in that file and reused when
    the evidence files are unchanged; otherwise it lives in a temporary directory.
    """

    def __init__(self, cfg, flows=None, dns=None):
        self._tmp = None
        path = cfg.case_db
        if not path:
            self._tmp = tempfile.TemporaryDirectory(prefix="threatbridge-")
            path = os.path.join(self._tmp.name, "case.db")
        self.store = FlowStore(path)
        t = time.monotonic()
        with _build_lock(cfg.case_db):
            if flows is not None:   # given directly (tests, scripts)
                self.dns = dns or {}
                self._write(flows, [])
                self.graph = build_graph((f.src, f.dst, f.start) for f in flows)
            else:
                self._load(cfg.case_paths)
        self.flow_count, first, last = self.store.stats()
        self.span = (_utc(first), _utc(last)) if self.flow_count else None
        log.info("case ready: %d flows, %d hosts, %d host pairs, %d names in DNS answers, in %.1fs",
                 self.flow_count, self.graph.number_of_nodes(), self.graph.number_of_edges(),
                 len(self.dns), time.monotonic() - t)

    def _load(self, paths):
        found = sources.find(paths)
        evidence = sources.manifest(found)
        if self.store.matches(evidence):
            log.info("reusing %s: the evidence files are unchanged", self.store.path)
            self.dns = self.store.dns()
        else:
            self.dns = {}
            flows = sources.read(found, self.dns)
            self._write(flows, evidence)
            del flows
        self.graph = build_graph(self.store.pairs())

    def _write(self, flows, evidence):
        try:
            self.store.write(flows, self.dns, evidence)
        except NotAStore as e:
            raise sources.SourceError(str(e))
        except sqlite3.Error as e:
            raise sources.SourceError(f"{self.store.path}: can't write the case database ({e})")

    def summary(self):
        return {
            "flows": self.flow_count,
            "hosts": self.graph.number_of_nodes(),
            "start": fmt_time(self.span[0]) if self.span else None,
            "end": fmt_time(self.span[1]) if self.span else None,
            "dns_names": len(self.dns),
        }

    def neighbors(self, ip, direction, start, end, limit, order, exclude):
        excluded = _Excluded(exclude)
        lo, hi = start.timestamp() - TIME_SLACK, end.timestamp() + TIME_SLACK
        # Counts and times come from the graph's per-pair start times; only the ports of
        # the peers shown need the flows themselves.
        adjacency = {} if ip not in self.graph else (
            self.graph.pred[ip] if direction == "in" else self.graph.succ[ip])
        peers = {}
        for peer, edge in adjacency.items():
            if peer != ip and peer not in excluded:
                n, first, last = count_between(edge["times"], lo, hi)
                if n:
                    peers[peer] = (n, first, last)
        sign = -1 if order == "top" else 1
        ranked = sorted(peers.items(), key=lambda kv: (sign * kv[1][0], kv[0]))[:limit]
        ports = self.store.ports(ip, direction, [peer for peer, _ in ranked], lo, hi)
        return {
            "peers": [{"peer": peer, "count": n, "first_seen": fmt_time(_utc(first)),
                       "last_seen": fmt_time(_utc(last)), "ports": _top_ports(ports[peer])}
                      for peer, (n, first, last) in ranked],
            "distinct_peers": len(peers),
            "truncated": False,
        }

    def _edge(self, src, dst, intervals, role):
        n, first, last, ports = self.store.edge(src, dst, intervals)
        return {"source": src, "target": dst, "role": role, "count": n,
                "first_seen": fmt_time(_utc(first)), "last_seen": fmt_time(_utc(last)),
                "ports": _top_ports(ports)}

    def flows(self, src, dst, start, end, offset, limit):
        lo, hi = start.timestamp() - TIME_SLACK, end.timestamp() + TIME_SLACK
        total = (count_between(self.graph[src][dst]["times"], lo, hi)[0]
                 if self.graph.has_edge(src, dst) else 0)
        page = self.store.flows(src, dst, lo, hi, offset, limit) if offset < total else []
        return {"total": total, "flows": [{
            "start": fmt_time(_utc(f.start)), "duration": round(f.end - f.start, 6),
            "sport": f.sport, "dport": f.dport, "proto": f.proto, "packets": f.packets,
            "bytes": f.bytes} for f in page]}

    def threat_line(self, a, b, first, last, window, max_hops, exclude, max_hosts,
                    bounds=(None, None)):
        """Hosts and hops time-consistent with the conversation a -> b (see analysis.py),
        using only flows within the analyst's time range `bounds`."""
        first = first.timestamp() - TIME_SLACK
        last = last.timestamp() + TIME_SLACK
        window = window.total_seconds()
        if not self.graph.has_edge(a, b) or \
                first_between(self.graph[a][b]["times"], first, last) is None:
            raise ValidationError(f"no flows from {a} to {b} in that time range")
        up, down = analysis.threat_line(self.graph, a, b, first, last, window, max_hops,
                                        _Excluded(exclude), max_hosts, _epochs(bounds))
        nodes = {a: {"id": a, "role": "selected", "time": fmt_time(_utc(last)), "hops": 0},
                 b: {"id": b, "role": "selected", "time": fmt_time(_utc(first)), "hops": 0}}
        for reach, role in ((up, "up"), (down, "down")):
            for ip in reach.via:
                node = nodes.get(ip)
                if node is None:
                    nodes[ip] = {"id": ip, "role": role,
                                 "time": fmt_time(_utc(reach.via[ip].start)), "hops": reach.hops[ip]}
                elif node["role"] not in ("selected", role):
                    node["role"] = "both"
        edges = [self._edge(a, b, [(first, last)], "selected")]
        for reach, role in ((up, "up"), (down, "down")):
            edges += [self._edge(s, d, iv, role) for s, d, iv in analysis.tree_edges(reach)]
        return {"nodes": list(nodes.values()), "edges": edges,
                "truncated": up.truncated or down.truncated}

    def attack_paths(self, compromised, window, max_hops, exclude, bounds=(None, None),
                     max_paths=None):
        """Time-respecting paths between each pair of compromised hosts ({ip: epoch or None};
        see analysis.attack_paths), using only flows within the time range `bounds`: up to
        max_paths per pair, shortest first."""
        found = analysis.attack_paths(
            self.graph, compromised, window.total_seconds(), max_hops, _Excluded(exclude),
            self._data_start(), TIME_SLACK, _epochs(bounds), max_paths)
        flows = {}
        return {"pairs": [{"from": a, "to": b, "paths": self._paths(paths, flows), "truncated": cut}
                          for a, b, paths, cut in found]}

    def paths_between(self, a, b, ta, tb, window, max_hops, exclude, bounds=(None, None),
                      max_paths=None):
        """Every time-respecting path from a to b (see analysis.paths_between). ta, tb: when
        each was compromised, datetimes or None if unknown."""
        found, truncated = analysis.paths_between(
            self.graph, a, b, _epoch(ta), _epoch(tb), window.total_seconds(), max_hops,
            _Excluded(exclude), self._data_start(), TIME_SLACK, _epochs(bounds), max_paths)
        return {"paths": self._paths(found, {}), "truncated": truncated}

    def _data_start(self):
        return self.span[0].timestamp() if self.span else None

    def _paths(self, found, flows):
        """[[Hop, ...], ...] -> JSON, each hop with its flow's details (`flows` caches them)."""
        for h in {h for hops in found for h in hops} - flows.keys():
            flows[h] = self.store.flow_at(h.src, h.dst, h.start)
        return [{"hops": [{"source": f.src, "target": f.dst, "start": fmt_time(_utc(f.start)),
                           "sport": f.sport, "dport": f.dport, "proto": f.proto,
                           "packets": f.packets, "bytes": f.bytes}
                          for f in (flows[h] for h in hops)]} for hops in found]


@contextmanager
def _build_lock(db_path):
    """With a shared case database (gunicorn starts several workers), one process builds it at
    a time; the others wait, then find it built and reuse it."""
    if not db_path:
        yield
        return
    try:
        fh = open(db_path + ".lock", "a")
    except OSError as e:
        raise sources.SourceError(f"{db_path}: can't use this case database ({e.strerror})")
    with fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


class _Excluded:
    """Membership test against the exclude list (IPs/CIDRs), cached per host."""

    def __init__(self, exclude):
        self.nets = [ipaddress.ip_network(e) for e in exclude]
        self.cache = {}

    def __contains__(self, ip):
        hit = self.cache.get(ip)
        if hit is None:
            addr = ipaddress.ip_address(ip)
            hit = self.cache[ip] = any(addr in n for n in self.nets)
        return hit


def _epoch(t):
    return t.timestamp() if t else None


def _epochs(bounds):
    """The analyst's time range (datetimes, None = open) in epoch seconds, widened by
    TIME_SLACK."""
    lo, hi = bounds
    return (lo.timestamp() - TIME_SLACK if lo else -analysis.INF,
            hi.timestamp() + TIME_SLACK if hi else analysis.INF)


def _top_ports(counts, n=5):
    """The n most used ports from {port: count}."""
    return [port for port, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:n]]


def make_backend(cfg):
    if cfg.backend == "case":
        return CaseBackend(cfg)
    if cfg.backend == "demo":
        return DemoBackend(cfg)
    if cfg.backend == "elastic":
        return ElasticBackend(cfg)
    raise ValueError(f"unknown backend {cfg.backend!r}")
