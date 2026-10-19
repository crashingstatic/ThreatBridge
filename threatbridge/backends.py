"""Data backends.

neighbors() returns {"peers": [...], "distinct_peers": int|None, "truncated": bool}
where each peer is {"peer", "count", "first_seen", "last_seen", "ports"}
(times as ISO-8601 UTC strings).
"""
import hashlib
import ipaddress
import logging
import random
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

import requests

from . import sources
from .graph import build_graph, host_flows, time_span
from .query import es_details_body, es_scan_body, es_top_body, fmt_time

log = logging.getLogger(__name__)
SCAN_PAGE = 1000


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
        url = f"{self.cfg.es_url.rstrip('/')}/{self.cfg.es_index}/_search"
        try:
            resp = self.session.post(url, json=body, timeout=self.cfg.es_timeout,
                                     params={"ignore_unavailable": "true"})
        except requests.RequestException as e:
            raise BackendError(f"Elasticsearch request failed: {e.__class__.__name__}")
        if resp.status_code != 200:
            raise BackendError(f"Elasticsearch returned HTTP {resp.status_code}")
        return resp.json().get("aggregations", {})

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


class DemoBackend:
    """Deterministic fake data so the UI can be exercised without Security Onion."""

    PORTS = [22, 53, 80, 443, 445, 3389, 5985, 8080]

    def __init__(self, cfg):
        self.cfg = cfg

    def neighbors(self, ip, direction, start, end, limit, order, exclude):
        seed = int(hashlib.sha256(f"{ip}|{direction}".encode()).hexdigest()[:12], 16)
        rng = random.Random(seed)
        span = max((end - start).total_seconds(), 1)
        nets = [ipaddress.ip_network(e) for e in exclude]
        seen = {}
        for _ in range(rng.randint(3, 12)):
            peer = f"10.{rng.randint(0, 3)}.{rng.randint(0, 9)}.{rng.randint(2, 30)}"
            if peer == ip or peer in seen:
                continue
            a = start + timedelta(seconds=rng.uniform(0, span))
            b = start + timedelta(seconds=rng.uniform(0, span))
            seen[peer] = {
                "peer": peer,
                "count": rng.choice([1, 2, 3, rng.randint(4, 500)]),
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


def _utc(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc)


class CaseBackend:
    """Post-mortem: flows read from tcpdump and nfdump files into an in-memory graph."""

    def __init__(self, cfg, graph=None):
        if graph is None:
            t = time.monotonic()
            graph = build_graph(sources.load(cfg.case_paths))
            log.info("case loaded: %d flows between %d hosts in %.1fs",
                     graph.number_of_edges(), graph.number_of_nodes(), time.monotonic() - t)
        self.graph = graph
        span = time_span(graph)
        self.span = (_utc(span[0]), _utc(span[1])) if span else None

    def summary(self):
        return {
            "flows": self.graph.number_of_edges(),
            "hosts": self.graph.number_of_nodes(),
            "start": fmt_time(self.span[0]) if self.span else None,
            "end": fmt_time(self.span[1]) if self.span else None,
        }

    def neighbors(self, ip, direction, start, end, limit, order, exclude):
        nets = [ipaddress.ip_network(e) for e in exclude]
        excluded, peers = {}, {}
        for f in host_flows(self.graph, ip, direction, start.timestamp(), end.timestamp()):
            peer = f.src if direction == "in" else f.dst
            if peer == ip:
                continue
            if peer not in excluded:
                addr = ipaddress.ip_address(peer)
                excluded[peer] = any(addr in n for n in nets)
            if excluded[peer]:
                continue
            p = peers.get(peer)
            if p is None:
                p = peers[peer] = {"count": 0, "first": f.start, "last": f.start, "ports": Counter()}
            p["count"] += 1
            p["first"] = min(p["first"], f.start)
            p["last"] = max(p["last"], f.start)
            if f.proto in ("tcp", "udp"):
                p["ports"][f.dport] += 1
        sign = -1 if order == "top" else 1
        ranked = sorted(peers.items(), key=lambda kv: (sign * kv[1]["count"], kv[0]))[:limit]
        return {
            "peers": [{
                "peer": peer,
                "count": p["count"],
                "first_seen": fmt_time(_utc(p["first"])),
                "last_seen": fmt_time(_utc(p["last"])),
                "ports": [port for port, _ in sorted(p["ports"].items(),
                                                     key=lambda kv: (-kv[1], kv[0]))[:5]],
            } for peer, p in ranked],
            "distinct_peers": len(peers),
            "truncated": False,
        }


def make_backend(cfg):
    if cfg.backend == "case":
        return CaseBackend(cfg)
    if cfg.backend == "demo":
        return DemoBackend(cfg)
    if cfg.backend == "elastic":
        return ElasticBackend(cfg)
    raise ValueError(f"unknown backend {cfg.backend!r}")
