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


def test_es_flows_body():
    body = q.es_flows_body(Config(), "10.0.0.1", "10.0.0.2", T0, T0, 100, 50)
    assert (body["from"], body["size"], body["sort"]) == (100, 50, [{"@timestamp": "asc"}])
    f = body["query"]["bool"]["filter"]
    assert {"term": {"source.ip": "10.0.0.1"}} in f and {"terms": {"destination.ip": ["10.0.0.2"]}} in f
    assert body["_source"] is False and body["track_total_hits"] is True
    assert {"source.port", "event.duration", "client.packets", "server.ip_bytes"} <= set(body["fields"][1:])


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


class FlowsES:
    def __init__(self, hits, total):
        self.body = {"hits": {"total": {"value": total}, "hits": [{"fields": h} for h in hits]}}

    def post(self, url, json, timeout, params):
        return FakeResp(self.body)


def test_elastic_flows_read_fields_and_stop_at_the_result_window():
    be = ElasticBackend(Config())
    be.session = FlowsES([
        {"@timestamp": ["2024-05-01T12:00:00.123456Z"], "source.port": [50000],
         "destination.port": [445], "network.transport": ["tcp"], "event.duration": [1.5],
         "client.packets": [3], "server.packets": [4], "client.ip_bytes": [300]},
        {"@timestamp": ["2024-05-01T12:00:01Z"], "event.duration": ["n/a"]}], total=7)
    res = be.flows("10.0.0.1", "10.0.0.2", T0, T0, 0, 50)
    assert res["total"] == 7
    assert res["flows"][0] == {"start": "2024-05-01T12:00:00.123Z", "duration": 1.5, "sport": 50000,
                               "dport": 445, "proto": "tcp", "packets": 7, "bytes": 300}
    assert res["flows"][1]["packets"] is None and res["flows"][1]["sport"] is None
    assert res["flows"][1]["duration"] is None                      # not a number: left out
    with pytest.raises(q.ValidationError, match="narrow the time range"):
        be.flows("10.0.0.1", "10.0.0.2", T0, T0, 9990, 50)


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


def test_pivots_carry_the_time_range(client):
    base = "/api/pivot?a=10.0.0.5&range_from=2024-05-01T10:00:00Z"
    p = client.get(base + "&b=10.0.0.6&until=2024-05-01T12:00:00Z&range_to=2024-05-01T11:00:00Z")
    assert '@timestamp:["2024-05-01T10:00:00.000Z" TO "2024-05-01T11:00:00.000Z"] |' in p.get_json()["query"]
    p = client.get(base).get_json()                                  # host pivot, open end
    assert p["query"] == ('(source.ip:"10.0.0.5" OR destination.ip:"10.0.0.5") AND '
                          '@timestamp:["2024-05-01T10:00:00.000Z" TO *] | groupby source.ip '
                          'destination.ip destination.port')
    assert "@timestamp" not in client.get("/api/pivot?a=10.0.0.5").get_json()["query"]


def test_time_range_and_flows_on_the_demo_backend(client):
    r = client.get("/api/neighbors?ip=10.0.0.5&ts=2024-05-01T12:00:00Z"
                   "&range_from=2024-05-01T11:00:00Z").get_json()
    assert r["start"] == "2024-05-01T11:00:00.000Z" and r["peers"]
    assert all(p["first_seen"] >= r["start"] for p in r["peers"])
    base = "/api/flows?src=10.0.0.7&dst=10.0.0.5&from=2024-05-01T11:00:00Z&to=2024-05-01T12:00:00Z"
    every = client.get(base + "&limit=500").get_json()
    starts = [f["start"] for f in every["flows"]]
    assert every["total"] == len(starts) == 2 and starts == sorted(starts)
    assert client.get(base + "&limit=1&offset=1").get_json()["flows"] == every["flows"][1:]


def test_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]


# ---- edge cases: validation, shared files, Elasticsearch -----------------------------------

import json  # noqa: E402
import threading  # noqa: E402

from threatbridge.backends import BackendError  # noqa: E402

WRITE = {"X-ThreatBridge": "1"}


@pytest.mark.parametrize("bad", ["fe80::1%eth0", 'fe80::1%a" OR source.ip:*'])
def test_scoped_ipv6_addresses_are_rejected(client, bad):
    # A scope can hold any text, quotes included, which would break out of OQL quoting.
    with pytest.raises(q.ValidationError):
        q.parse_ip(bad)
    assert client.get("/api/pivot", query_string={"a": bad, "b": "10.0.0.6"}).status_code == 400
    assert client.get("/api/neighbors", query_string={"ip": bad}).status_code == 400
    assert client.post("/api/excludes", json={"entry": bad}, headers=WRITE).status_code == 400


@pytest.mark.parametrize("url,body", [
    ("/api/excludes", ["10.0.0.1"]), ("/api/excludes", {"entry": 5}),
    ("/api/compromised", ["10.0.0.5"]), ("/api/compromised", {"ip": 5}),
    ("/api/compromised", {"ip": "10.0.0.5", "note": 5}), ("/api/compromised", {"ip": "10.0.0.5", "time": []}),
    ("/api/excludes", "10.0.0.1"),
])
def test_json_of_the_wrong_shape_is_a_bad_request(client, url, body):
    assert client.post(url, json=body, headers=WRITE).status_code == 400


def test_a_numeric_compromise_time_is_an_epoch(client):
    r = client.post("/api/compromised", json={"ip": "10.0.0.5", "time": 1714564800}, headers=WRITE)
    assert r.status_code == 200 and r.get_json()["hosts"][0]["time"] == "2024-05-01T12:00:00.000Z"


def test_writes_need_the_header_whatever_the_method(client):
    for method in ("post", "put", "patch", "delete"):
        assert getattr(client, method)("/api/excludes", json={"entry": "10.0.0.1"}).status_code == 403


@pytest.mark.parametrize("window", ["99999999999d", "999999999999w", "0x10h"])
def test_absurd_windows_are_rejected(client, window):
    assert client.get(f"/api/neighbors?ip=10.0.0.5&window={window}").status_code == 400


def test_flows_to_before_from_is_rejected(client):
    r = client.get("/api/flows?src=10.0.0.1&dst=10.0.0.5&from=2024-05-01T12:00:00Z&to=2024-05-01T11:00:00Z")
    assert r.status_code == 400


def test_demo_flows_past_the_end(client):
    r = client.get("/api/flows?src=10.0.0.7&dst=10.0.0.5&from=2024-05-01T11:00:00Z"
                   "&to=2024-05-01T12:00:00Z&offset=100000").get_json()
    assert r["flows"] == [] and r["total"] == 2


def shared_client(tmp_path, exclude_text=None, compromised_text=None):
    ex, comp = tmp_path / "ex.json", tmp_path / "c.json"
    if exclude_text is not None:
        ex.write_text(exclude_text)
    if compromised_text is not None:
        comp.write_text(compromised_text)
    cfg = Config(backend="demo", exclude_file=str(ex), compromised_file=str(comp), live_dns=False)
    return create_app(cfg, DemoBackend(cfg)).test_client()


def test_hand_edited_shared_files_with_bad_entries(tmp_path):
    c = shared_client(tmp_path, json.dumps({"entries": ["10.0.0.1", "bogus!!", "Example.COM"]}),
                      json.dumps({"hosts": [{"ip": "10.0.0.5", "time": "garbage", "note": ""},
                                            {"ip": "nope", "time": None, "note": ""},
                                            {"ip": "10.0.0.6", "time": None, "note": "ok"}]}))
    # One bad line doesn't break every map query; the valid entries still apply.
    assert c.get("/api/excludes").get_json()["entries"] == ["10.0.0.1", "example.com"]
    assert c.get("/api/neighbors?ip=10.0.0.5&ts=2024-05-01T12:00:00Z").status_code == 200
    assert [h["ip"] for h in c.get("/api/compromised").get_json()["hosts"]] == ["10.0.0.6"]


def test_a_corrupt_shared_file_is_reported_and_left_alone(tmp_path):
    c = shared_client(tmp_path, exclude_text="{not json")
    r = c.get("/api/excludes")
    assert r.status_code == 500 and "ex.json" in r.get_json()["error"]
    assert c.post("/api/excludes", json={"entry": "10.0.0.1"}, headers=WRITE).status_code == 500
    assert (tmp_path / "ex.json").read_text() == "{not json"
    c = shared_client(tmp_path, exclude_text=json.dumps(["10.0.0.1"]))          # wrong shape
    assert c.get("/api/excludes").status_code == 500


def test_concurrent_writers_lose_nothing(tmp_path):
    path = str(tmp_path / "ex.json")
    threads = [threading.Thread(target=ExcludeStore(path).add, args=(f"10.0.0.{i}",))
               for i in range(1, 21)]   # separate stores, like separate gunicorn workers
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(ExcludeStore(path).list()) == sorted(f"10.0.0.{i}" for i in range(1, 21))


class OddES:
    """A session whose answer is not what Elasticsearch normally sends."""

    def __init__(self, body=None, text="<html>proxy login</html>"):
        self.body, self.text = body, text

    def post(self, url, json, timeout, params):
        resp = FakeResp(self.body)
        if self.body is None:
            def bad_json():
                raise ValueError("Expecting value: line 1 column 1 (char 0)")
            resp.json = bad_json
        return resp


def test_an_answer_that_is_not_json_is_a_backend_error():
    be = ElasticBackend(Config())
    be.session = OddES()
    with pytest.raises(BackendError):
        be.neighbors("10.0.0.5", "in", T0, T0, 5, "top", [])
    with pytest.raises(BackendError):
        be.flows("10.0.0.1", "10.0.0.2", T0, T0, 0, 50)


def test_hits_total_as_a_plain_number():
    be = ElasticBackend(Config())
    be.session = OddES({"hits": {"total": 3, "hits": [{"fields": {"@timestamp": ["2024-05-01T12:00:00Z"]}}]}})
    assert be.flows("10.0.0.1", "10.0.0.2", T0, T0, 0, 50)["total"] == 3
