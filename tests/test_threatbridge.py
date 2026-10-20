from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

import pytest

from threatbridge.app import create_app
from threatbridge.backends import DemoBackend, ElasticBackend
from threatbridge.config import Config
from threatbridge.excludes import ExcludeStore
from threatbridge import query as q

T0 = datetime(2024, 5, 1, 12, 0, tzinfo=timezone.utc)


# ---- query helpers ----------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("2024-05-01T12:00:00Z", T0),
    ("2024-05-01T12:00:00.123456789Z", T0 + timedelta(microseconds=123456)),
    ("2024-05-01T14:00:00+02:00", T0),
    ("1714564800", T0),
    ("1714564800000", T0),
])
def test_parse_time(raw, expected):
    assert q.parse_time(raw) == expected


@pytest.mark.parametrize("bad", ["", "1.2.3", "10.0.0.1 OR *", "::g"])
def test_parse_ip_rejects(bad):
    with pytest.raises(q.ValidationError):
        q.parse_ip(bad)


def test_parse_network_canonicalises():
    assert q.parse_network("10.0.0.7/24") == "10.0.0.0/24"
    assert q.parse_network("10.0.0.7") == "10.0.0.7"
    with pytest.raises(q.ValidationError):
        q.parse_network("10.0.0.0/33")


def test_time_range_direction():
    w = timedelta(hours=24)
    assert q.time_range(T0, "in", w) == (T0 - w, T0)
    assert q.time_range(T0, "out", w) == (T0, T0 + w)


def test_es_filter_direction_and_excludes():
    cfg = Config()
    f = q.es_filter(cfg, "10.0.0.5", "in", T0, T0, ["10.9.0.0/16"])["bool"]
    assert {"term": {"destination.ip": "10.0.0.5"}} in f["filter"]
    assert {"terms": {"event.dataset": ["conn", "zeek.conn"]}} in f["filter"]
    assert f["must_not"] == [{"term": {"source.ip": "10.9.0.0/16"}}]
    f = q.es_filter(cfg, "10.0.0.5", "out", T0, T0, [])["bool"]
    assert {"term": {"source.ip": "10.0.0.5"}} in f["filter"]


def test_pivot_query_both_directions_up_to_ioc():
    cfg = Config(soc_url="https://so")
    query = q.soc_pivot_query(cfg, "10.0.0.1", "fe80::1", T0)
    assert '(source.ip:"10.0.0.1" AND destination.ip:"fe80::1")' in query
    assert '(source.ip:"fe80::1" AND destination.ip:"10.0.0.1")' in query
    assert '@timestamp:[* TO "2024-05-01T12:00:00.000Z"]' in query
    url = q.soc_url(cfg, query)
    assert url.startswith("https://so/#/dashboards?q=")
    assert unquote(url.split("q=", 1)[1]) == query


# ---- exact rarest scan against a fake Elasticsearch -------------------------

class FakeResp:
    status_code = 200

    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


class FakeES:
    """Serves composite pages over `counts`, then a details terms agg."""

    def __init__(self, counts):
        self.counts = sorted(counts.items())
        self.calls = []

    def post(self, url, json, timeout, params):
        self.calls.append(json)
        aggs = json["aggs"]
        if "scan" in aggs:
            comp = aggs["scan"]["composite"]
            start = comp.get("after", {}).get("idx", 0)
            page = self.counts[start:start + comp["size"]]
            body = {"buckets": [{"key": {"peer": p}, "doc_count": c} for p, c in page]}
            if page:
                body["after_key"] = {"idx": start + len(page)}
            return FakeResp({"aggregations": {"scan": body}})
        wanted = next(f["terms"] for f in json["query"]["bool"]["filter"]
                      if "terms" in f and "source.ip" in f["terms"])["source.ip"]
        d = dict(self.counts)
        return FakeResp({"aggregations": {"peers": {"buckets": [
            {"key": p, "doc_count": d[p], "first_seen": {"value_as_string": "a"},
             "last_seen": {"value_as_string": "b"}, "ports": {"buckets": [{"key": 443}]}}
            for p in wanted]}}})


def _elastic(counts, cap=10000):
    be = ElasticBackend(Config(rare_scan_cap=cap))
    be.session = FakeES(counts)
    return be


def test_rarest_is_exact_across_pages():
    counts = {f"10.0.{i // 250}.{i % 250}": 2500 - i for i in range(2500)}
    res = _elastic(counts).neighbors("10.9.9.9", "in", T0, T0, 3, "bottom", [])
    assert [p["count"] for p in res["peers"]] == [1, 2, 3]
    assert res["distinct_peers"] == 2500 and res["truncated"] is False


def test_rarest_truncates_at_cap():
    counts = {f"10.0.{i // 250}.{i % 250}": 5 for i in range(2500)}
    res = _elastic(counts, cap=1500).neighbors("10.9.9.9", "in", T0, T0, 5, "bottom", [])
    assert res["truncated"] is True and res["distinct_peers"] == 1500


# ---- HTTP API ---------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    cfg = Config(backend="demo", soc_url="https://so",
                 compromised_file=str(tmp_path / "compromised.json"))
    app = create_app(cfg, DemoBackend(cfg), ExcludeStore(str(tmp_path / "ex.json")))
    return app.test_client()


def test_neighbors_and_validation(client):
    r = client.get("/api/neighbors?ip=10.0.0.5&direction=out&ts=2024-05-01T12:00:00Z&order=bottom")
    assert r.status_code == 200
    body = r.get_json()
    assert body["start"] == "2024-05-01T12:00:00.000Z" and body["order"] == "bottom"
    counts = [p["count"] for p in body["peers"]]
    assert counts == sorted(counts)
    assert client.get("/api/neighbors?ip=nope").status_code == 400
    assert client.get("/api/neighbors?ip=10.0.0.5&direction=up").status_code == 400
    assert client.get("/api/neighbors?ip=10.0.0.5&window=90d").status_code == 400


def test_excludes_shared_and_applied(client):
    peers = client.get("/api/neighbors?ip=10.0.0.5&ts=2024-05-01T12:00:00Z").get_json()["peers"]
    victim = peers[0]["peer"]
    # Writes without the custom header are rejected (CSRF guard).
    assert client.post("/api/excludes", json={"entry": victim}).status_code == 403
    h = {"X-ThreatBridge": "1"}
    assert client.post("/api/excludes", json={"entry": "not valid!"}, headers=h).status_code == 400
    assert client.post("/api/excludes", json={"entry": victim}, headers=h).get_json()["entries"] == [victim]
    after = client.get("/api/neighbors?ip=10.0.0.5&ts=2024-05-01T12:00:00Z").get_json()["peers"]
    assert victim not in {p["peer"] for p in after}
    assert client.delete("/api/excludes", json={"entry": victim}, headers=h).get_json()["entries"] == []


def test_resolve_and_pivot(client):
    r = client.get("/api/resolve?ip=10.0.0.5&ts=1714564800").get_json()
    assert r == {"ip": "10.0.0.5", "anchor": "2024-05-01T12:00:00.000Z"}
    p = client.get("/api/pivot?a=10.0.0.5&b=10.0.0.6&until=2024-05-01T12:00:00Z").get_json()
    assert p["url"].startswith("https://so/#/dashboards?q=")
    assert "@timestamp:[* TO" in p["query"]


def test_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
