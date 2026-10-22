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


# ---- gaps found by mutation testing -------------------------------------------------------

import os  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402

import requests  # noqa: E402

from threatbridge import backends  # noqa: E402
from threatbridge.compromised import CompromisedStore  # noqa: E402
from threatbridge.jsonstore import JsonStore, StoreError  # noqa: E402

T1 = T0 + timedelta(hours=1)
RANGE = {"range": {"@timestamp": {"gte": "2024-05-01T12:00:00.000Z", "lte": "2024-05-01T13:00:00.000Z",
                                  "format": "strict_date_optional_time"}}}
DATASETS = {"terms": {"event.dataset": ["conn", "zeek.conn"]}}
DETAILS = {"first_seen": {"min": {"field": "@timestamp"}}, "last_seen": {"max": {"field": "@timestamp"}},
           "ports": {"terms": {"field": "destination.port", "size": 5}}}


def test_es_top_body_exactly():
    assert q.es_top_body(Config(), "10.0.0.5", "in", T0, T1, 7, ["10.9.0.0/16"]) == {
        "size": 0, "track_total_hits": False,
        "query": {"bool": {"filter": [{"term": {"destination.ip": "10.0.0.5"}}, RANGE, DATASETS],
                           "must_not": [{"term": {"source.ip": "10.9.0.0/16"}}]}},
        "aggs": {"peers": {"terms": {"field": "source.ip", "size": 7, "order": {"_count": "desc"}},
                           "aggs": DETAILS},
                 "distinct": {"cardinality": {"field": "source.ip"}}}}


def test_es_scan_and_details_bodies_exactly():
    out_filter = {"bool": {"filter": [{"term": {"source.ip": "10.0.0.5"}}, RANGE, DATASETS], "must_not": []}}
    assert q.es_scan_body(Config(), "10.0.0.5", "out", T0, T1, [], 1000, {"peer": "10.0.0.9"}) == {
        "size": 0, "track_total_hits": False, "query": out_filter,
        "aggs": {"scan": {"composite": {"size": 1000, "after": {"peer": "10.0.0.9"},
                                        "sources": [{"peer": {"terms": {"field": "destination.ip"}}}]}}}}
    body = q.es_details_body(Config(), "10.0.0.5", "out", T0, T1, ["10.0.0.7", "10.0.0.8"], [])
    assert body == {
        "size": 0, "track_total_hits": False,
        "query": {"bool": {"filter": out_filter["bool"]["filter"] +
                           [{"terms": {"destination.ip": ["10.0.0.7", "10.0.0.8"]}}], "must_not": []}},
        "aggs": {"peers": {"terms": {"field": "destination.ip", "size": 2}, "aggs": DETAILS}}}
    assert q.es_details_body(Config(), "10.0.0.5", "out", T0, T1, [], [])["aggs"]["peers"]["terms"]["size"] == 1


class RecordingES:
    """Records requests; answers with `body` (or raises `error`)."""

    def __init__(self, body=None, status=200, error=None):
        self.body, self.status, self.error, self.calls = body or {}, status, error, []

    def post(self, url, json, timeout, params):
        self.calls.append({"url": url, "json": json, "timeout": timeout, "params": params})
        if self.error:
            raise self.error
        resp = FakeResp(self.body)
        resp.status_code = self.status
        return resp


def test_elastic_top_peers():
    es = RecordingES({"aggregations": {
        "peers": {"buckets": [
            {"key": "10.0.0.7", "doc_count": 9, "first_seen": {"value": 1714564800000.0},
             "last_seen": {"value_as_string": "2024-05-01T12:30:00.000Z"},
             "ports": {"buckets": [{"key": 443}, {"key": 80}]}},
            {"key": "10.0.0.8", "doc_count": 1, "first_seen": {"value": None}, "last_seen": {}}]},
        "distinct": {"value": 42}}})
    be = ElasticBackend(Config(es_url="https://es.example:9200/", es_index="logs-zeek-*", es_timeout=7))
    be.session = es
    res = be.neighbors("10.0.0.5", "in", T0, T1, 2, "top", [])
    assert res == {"peers": [
        {"peer": "10.0.0.7", "count": 9, "first_seen": "2024-05-01T12:00:00.000Z",
         "last_seen": "2024-05-01T12:30:00.000Z", "ports": [443, 80]},
        {"peer": "10.0.0.8", "count": 1, "first_seen": None, "last_seen": None, "ports": []}],
        "distinct_peers": 42, "truncated": False}
    [call] = es.calls
    assert call["url"] == "https://es.example:9200/logs-zeek-*/_search"
    assert (call["timeout"], call["params"]) == (7, {"ignore_unavailable": "true"})
    assert call["json"] == q.es_top_body(be.cfg, "10.0.0.5", "in", T0, T1, 2, [])


def test_rarest_asks_about_the_right_host_and_direction():
    be = _elastic({"10.0.0.7": 3, "10.0.0.8": 1})
    be.neighbors("10.9.9.9", "in", T0, T1, 1, "bottom", ["10.200.0.0/16"])
    first, more, details = be.session.calls            # two scan pages (the second is empty)
    assert first == q.es_scan_body(be.cfg, "10.9.9.9", "in", T0, T1, ["10.200.0.0/16"], 1000)
    assert more == q.es_scan_body(be.cfg, "10.9.9.9", "in", T0, T1, ["10.200.0.0/16"], 1000, {"idx": 2})
    assert details == q.es_details_body(be.cfg, "10.9.9.9", "in", T0, T1, ["10.0.0.8"], ["10.200.0.0/16"])


@pytest.mark.parametrize("es,message", [
    (RecordingES(error=requests.ConnectionError("down")), "Elasticsearch request failed: ConnectionError"),
    (RecordingES(status=401), "Elasticsearch returned HTTP 401"),
    (OddES(), "not JSON"),
    (OddES(["a", "list"]), "not a JSON object"),
])
def test_elastic_errors_say_what_went_wrong(es, message):
    be = ElasticBackend(Config())
    be.session = es
    with pytest.raises(BackendError, match=message):
        be.neighbors("10.0.0.5", "in", T0, T1, 5, "top", [])


def test_elastic_session_setup():
    be = ElasticBackend(Config(es_user="svc", es_pass=None, es_ca="/etc/pki/ca.crt"))
    assert be.session.auth == ("svc", "") and be.session.verify == "/etc/pki/ca.crt"
    assert be.session.headers["Content-Type"] == "application/json"
    be = ElasticBackend(Config(es_user="svc", es_pass="pw", es_verify=False))
    assert be.session.auth == ("svc", "pw") and be.session.verify is False
    assert ElasticBackend(Config()).session.auth is None


def test_elastic_flows_request_and_limits():
    es = RecordingES({"hits": {}})
    be = ElasticBackend(Config())
    be.session = es
    assert be.flows("10.0.0.1", "10.0.0.2", T0, T1, 9950, 50) == {"total": 0, "flows": []}   # last allowed page
    assert es.calls[0]["json"] == q.es_flows_body(be.cfg, "10.0.0.1", "10.0.0.2", T0, T1, 9950, 50)


def test_make_backend():
    assert isinstance(backends.make_backend(Config(backend="demo")), DemoBackend)
    es = backends.make_backend(Config(backend="elastic", es_timeout=9))
    assert isinstance(es, ElasticBackend) and es.cfg.es_timeout == 9
    with pytest.raises(ValueError, match="unknown backend 'nope'"):
        backends.make_backend(Config(backend="nope"))


@pytest.mark.parametrize("direction", ["in", "out"])
def test_demo_edges_match_their_flow_lists(direction):
    be = DemoBackend(Config())
    start, end = T0 - timedelta(hours=24), T0
    top = be.neighbors("10.0.0.5", direction, start, end, 50, "top", [])["peers"]
    bottom = be.neighbors("10.0.0.5", direction, start, end, 50, "bottom", [])["peers"]
    assert [p["count"] for p in top] == sorted((p["count"] for p in top), reverse=True)
    assert [p["count"] for p in bottom] == sorted(p["count"] for p in bottom)
    peers = [p["peer"] for p in top]
    assert len(peers) == len(set(peers)) and "10.0.0.5" not in peers
    for p in top:
        src, dst = (p["peer"], "10.0.0.5") if direction == "in" else ("10.0.0.5", p["peer"])
        first, last = q.parse_time(p["first_seen"]), q.parse_time(p["last_seen"])
        assert start <= first <= last <= end
        r = be.flows(src, dst, first, last, 0, 1000)
        assert r["total"] == p["count"] == len(r["flows"])
        assert (r["flows"][0]["start"], r["flows"][-1]["start"]) == (p["first_seen"], p["last_seen"])
        assert all(p["first_seen"] <= f["start"] <= p["last_seen"] for f in r["flows"])


@pytest.fixture
def new_york(monkeypatch):
    monkeypatch.setenv("TZ", "America/New_York")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def test_times_are_utc_whatever_the_local_zone(new_york):
    assert q.parse_time("2024-05-01T12:00:00") == T0                      # no zone given: UTC
    assert q.parse_time("2024-05-01T12:00:00").tzinfo == timezone.utc
    assert q.fmt_time(datetime(2024, 5, 1, 14, 0, tzinfo=timezone(timedelta(hours=2)))) == \
        "2024-05-01T12:00:00.000Z"
    now = q.parse_time("  ")                                               # blank: now
    assert now.tzinfo == timezone.utc and abs((now - datetime.now(timezone.utc)).total_seconds()) < 5


def test_domain_length_limit():
    ok = ".".join(["a" * 63] * 3 + ["b" * 61])                            # 253 characters
    assert len(ok) == 253 and q.parse_exclude(ok) == ok
    with pytest.raises(q.ValidationError):
        q.parse_exclude(ok + "b")


def test_host_pivot_with_a_closed_range(client):
    p = client.get("/api/pivot?a=10.0.0.5&range_from=2024-05-01T10:00:00Z&range_to=2024-05-01T11:00:00Z")
    assert '@timestamp:["2024-05-01T10:00:00.000Z" TO "2024-05-01T11:00:00.000Z"] |' in p.get_json()["query"]


@pytest.mark.parametrize("call,match", [
    (lambda: q.parse_ip("nope"), "invalid IP address: 'nope'"),
    (lambda: q.parse_ip(5), "invalid IP address: 5"),
    (lambda: q.parse_ip("fe80::1%eth0"), "IPv6 scope not allowed"),
    (lambda: q.parse_direction("up"), "direction must be 'in' or 'out'"),
    (lambda: q.parse_order("middle"), "order must be 'top' or 'bottom'"),
    (lambda: q.parse_window("soon"), "invalid window 'soon'; use e.g. 30m, 24h, 7d"),
    (lambda: q.parse_window(None), "invalid window None"),
    (lambda: q.parse_window("99999999999d"), "window '99999999999d' is too large"),
    (lambda: q.parse_time("yesterday"), "invalid timestamp: 'yesterday'"),
    (lambda: q.parse_network("10.0.0.0/33"), "invalid IP/CIDR: '10.0.0.0/33'"),
    (lambda: q.parse_network(5), "invalid IP/CIDR: 5"),
    (lambda: q.parse_exclude(5), "invalid IP, CIDR or domain name: 5"),
    (lambda: q.parse_exclude("not valid!"), "invalid IP, CIDR or domain name: 'not valid!'"),
    (lambda: q.parse_exclude("*.com"), "a wildcard needs at least two labels"),
])
def test_validation_messages(call, match):
    with pytest.raises(q.ValidationError, match=match):
        call()


def test_api_boundaries_and_messages(client):
    ok = "/api/neighbors?ip=10.0.0.5&ts=2024-05-01T12:00:00Z"
    assert client.get(ok + "&window=30d").status_code == 200                       # the maximum itself
    r = client.get(ok + "&window=31d")
    assert r.status_code == 400 and r.get_json()["error"] == "window exceeds maximum of 30d"
    assert client.get(ok + "&range_from=2024-05-01T11:00:00Z&range_to=2024-05-01T11:00:00Z").status_code == 200
    r = client.get(ok + "&range_from=2024-05-01T11:00:00Z&range_to=2024-05-01T10:00:00Z")
    assert r.get_json()["error"] == "range_to is before range_from"
    assert client.get(ok + "&limit=x").get_json()["error"] == "limit must be an integer"
    r = client.post("/api/excludes", data="{not json", headers=dict(WRITE, **{"Content-Type": "application/json"}))
    assert r.status_code == 400 and "invalid IP, CIDR or domain name" in r.get_json()["error"]
    r = client.post("/api/excludes", json=["x"], headers=WRITE)
    assert r.get_json()["error"] == "the request body must be a JSON object"
    r = client.get("/api/paths")
    assert r.status_code == 501 and "--case" in r.get_json()["error"]
    r = client.get("/static/app.js")
    assert r.status_code == 200 and b"threatbridge" in r.data


def test_live_dns_setting_is_honoured(tmp_path):
    def app_for(live):
        cfg = Config(backend="demo", live_dns=live, exclude_file=str(tmp_path / f"ex{live}.json"),
                     compromised_file=str(tmp_path / "c.json"))
        c = create_app(cfg, DemoBackend(cfg)).test_client()
        c.post("/api/excludes", json={"entry": "localhost"}, headers=WRITE)
        return c
    on, off = app_for(True), app_for(False)
    assert "127.0.0.1" in on.get("/api/excludes").get_json()["resolved"]["localhost"]["dns"]
    assert "127.0.0.1" in on.get("/api/excludes").get_json()["resolved"]["localhost"]["dns"]   # cached
    assert off.get("/api/excludes").get_json()["resolved"]["localhost"]["dns"] == []


def test_config_from_the_environment(monkeypatch):
    for k in list(os.environ):
        if k.startswith("TB_"):
            monkeypatch.delenv(k)
    assert Config.from_env() == Config()                     # nothing set: the documented defaults
    env = {
        "TB_BACKEND": "case", "TB_CASE_PATHS": os.pathsep.join(["/cases/a", "", "/cases/b"]),
        "TB_CASE_DB": "/work/case.db", "TB_ES_URL": "https://es:9200", "TB_ES_USER": "u",
        "TB_ES_PASS": "p", "TB_ES_VERIFY": "no", "TB_ES_CA": "/ca.pem", "TB_ES_INDEX": "so-*",
        "TB_ES_TIMEOUT": "9", "TB_DATASETS": "conn, ,zeek.conn", "TB_FIELD_SRC": "s", "TB_FIELD_DST": "d",
        "TB_FIELD_TS": "ts", "TB_FIELD_DPORT": "dp", "TB_FIELD_DATASET": "ds", "TB_FIELD_SPORT": "sp",
        "TB_FIELD_PROTO": "pr", "TB_FIELD_DURATION": "du", "TB_FIELD_PACKETS": "p1,p2",
        "TB_FIELD_BYTES": "b1", "TB_SOC_URL": "https://so/", "TB_SOC_PATH": "/x?q={query}",
        "TB_PIVOT_TIME_CLAUSE": "false", "TB_WINDOW": "1h", "TB_MAX_WINDOW": "7d", "TB_LIMIT": "9",
        "TB_MAX_LIMIT": "99", "TB_RARE_SCAN_CAP": "77", "TB_EXCLUDE_FILE": "/d/ex.json",
        "TB_COMPROMISED_FILE": "/d/c.json", "TB_LIVE_DNS": "0", "TB_DNS_TTL": "11",
        "TB_DNS_TIMEOUT": "0.5", "TB_THREAT_HOPS": "4", "TB_THREAT_MAX_HOSTS": "50", "TB_MAX_PATHS": "20",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert Config.from_env() == Config(
        backend="case", case_paths=["/cases/a", "/cases/b"], case_db="/work/case.db",
        es_url="https://es:9200", es_user="u", es_pass="p", es_verify=False, es_ca="/ca.pem",
        es_index="so-*", es_timeout=9, datasets=["conn", "zeek.conn"], f_src="s", f_dst="d", f_ts="ts",
        f_dport="dp", f_dataset="ds", f_sport="sp", f_proto="pr", f_duration="du", f_packets=["p1", "p2"],
        f_bytes=["b1"], soc_url="https://so", soc_path="/x?q={query}", pivot_time_clause=False,
        default_window="1h", max_window="7d", default_limit=9, max_limit=99, rare_scan_cap=77,
        exclude_file="/d/ex.json", compromised_file="/d/c.json", live_dns=False, dns_ttl=11,
        dns_timeout=0.5, threat_hops=4, threat_max_hosts=50, max_paths=20)
    for value, expected in (("1", True), ("TRUE", True), ("yes", True), ("on", True), ("off", False), ("", True)):
        monkeypatch.setenv("TB_ES_VERIFY", value)
        assert Config.from_env().es_verify is expected, value
    # Set but empty means "none" (README: "empty = no dataset filter"); unset means the default.
    monkeypatch.setenv("TB_DATASETS", "")
    assert Config.from_env().datasets == []
    assert q.es_filter(Config.from_env(), "10.0.0.5", "in", T0, T0, [])["bool"]["filter"][-1] != DATASETS
    monkeypatch.delenv("TB_DATASETS")
    assert Config.from_env().datasets == ["conn", "zeek.conn"]


def test_main(monkeypatch):
    from threatbridge import app as app_mod
    seen = {}

    class FakeApp:
        def run(self, host, port):
            seen["run"] = (host, port)

    def fake_create_app(cfg):
        seen["cfg"] = cfg
        return FakeApp()
    monkeypatch.setattr(app_mod, "create_app", fake_create_app)
    for k in list(os.environ):
        if k.startswith("TB_"):
            monkeypatch.delenv(k)
    monkeypatch.setattr(sys, "argv", ["threatbridge", "--case", "/c/a", "/c/b", "--db", "/w/x.db",
                                      "--host", "0.0.0.0", "--port", "6000"])
    app_mod.main()
    assert (seen["cfg"].backend, seen["cfg"].case_paths, seen["cfg"].case_db) == ("case", ["/c/a", "/c/b"], "/w/x.db")
    assert seen["run"] == ("0.0.0.0", 6000)
    monkeypatch.setattr(sys, "argv", ["threatbridge", "--demo"])
    app_mod.main()
    assert seen["cfg"].backend == "demo" and seen["cfg"].case_db is None and seen["run"] == ("127.0.0.1", 5055)

    def failing(cfg):
        raise app_mod.SourceError("no pcap or nfcapd files found in: /c")
    monkeypatch.setattr(app_mod, "create_app", failing)
    monkeypatch.setattr(sys, "argv", ["threatbridge", "--case", "/c"])
    with pytest.raises(SystemExit) as e:
        app_mod.main()
    assert e.value.code == 2


def test_json_store_shapes_and_atomic_writes(tmp_path, monkeypatch):
    path = tmp_path / "x.json"
    path.write_text("{}")
    with JsonStore(str(path), "entries").locked() as items:
        assert items == []                                                 # no key yet: empty
    path.write_text('{"entries": {"not": "a list"}}')
    with pytest.raises(StoreError, match=r'x.json should hold \{"entries": \[\.\.\.\]\}'):
        with JsonStore(str(path), "entries").locked():
            pass
    import tempfile as tempfile_mod
    dirs = []
    real = tempfile_mod.mkstemp
    monkeypatch.setattr(tempfile_mod, "mkstemp", lambda **kw: dirs.append(kw.get("dir")) or real(**kw))
    path.write_text("{}")
    ExcludeStore(str(path)).add("10.0.0.1")
    assert dirs == [str(tmp_path)]                     # beside the file, so os.replace is atomic
    assert json.loads(path.read_text()) == {"entries": ["10.0.0.1"]}


def test_compromised_notes_and_hand_edits(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"hosts": [{"ip": "nope", "time": None, "note": ""}]}))
    store = CompromisedStore(str(path))
    assert store.mark("10.0.0.5", None, "x" * 500)[0]["note"] == "x" * 500
    with pytest.raises(q.ValidationError, match="note longer than 500 characters"):
        store.mark("10.0.0.5", None, "x" * 501)
    with pytest.raises(q.ValidationError, match="invalid time: True"):
        store.mark("10.0.0.5", True)
    with pytest.raises(q.ValidationError, match="note must be text"):
        store.mark("10.0.0.5", None, 5)
    store.unmark("10.0.0.5")
    # The invalid hand-edited entry is ignored, but kept for someone to fix.
    assert json.loads(path.read_text())["hosts"] == [{"ip": "nope", "time": None, "note": ""}]


def test_es_bodies_for_inbound_peers():
    assert q.es_scan_body(Config(), "10.0.0.5", "in", T0, T1, [], 10)["aggs"]["scan"]["composite"]["sources"] == \
        [{"peer": {"terms": {"field": "source.ip"}}}]
    body = q.es_details_body(Config(), "10.0.0.5", "in", T0, T1, ["10.0.0.7"], [])
    assert body["aggs"]["peers"]["terms"]["field"] == "source.ip"
    assert body["query"]["bool"]["filter"][0] == {"term": {"destination.ip": "10.0.0.5"}}
    assert {"terms": {"source.ip": ["10.0.0.7"]}} in body["query"]["bool"]["filter"]


@pytest.mark.parametrize("order", ["top", "bottom"])
def test_elastic_answers_with_parts_missing(order):
    be = ElasticBackend(Config())
    be.session = RecordingES({})                                  # no aggregations at all
    assert be.neighbors("10.0.0.5", "in", T0, T1, 5, order, [])["peers"] == []
    be.session = RecordingES({"aggregations": {"peers": {"buckets": [{"key": "10.0.0.7", "doc_count": 2}]},
                                               "scan": {"buckets": [{"key": {"peer": "10.0.0.7"}, "doc_count": 2}]}}})
    [p] = be.neighbors("10.0.0.5", "in", T0, T1, 5, order, [])["peers"]
    assert (p["first_seen"], p["last_seen"], p["ports"]) == (None, None, [])


def test_elastic_flow_hits_with_parts_missing():
    # No @timestamp among the fields: the hit's sort value (epoch ms of @timestamp) places it.
    # With no time at all the hit is left out rather than shown at a made-up time.
    be = ElasticBackend(Config())
    be.session = RecordingES({"hits": {"total": {"relation": "gte"}, "hits": [
        {"sort": [1714564800000]}, {}, {"fields": {"@timestamp": ["2024-05-01T12:00:01Z"]}}]}})
    r = be.flows("10.0.0.1", "10.0.0.2", T0, T1, 0, 50)
    assert r["total"] == 0
    assert [f["start"] for f in r["flows"]] == ["2024-05-01T12:00:00.000Z", "2024-05-01T12:00:01.000Z"]


def test_resolver_settings_come_from_the_config(tmp_path, monkeypatch):
    from threatbridge import app as app_mod
    made = {}

    class Recording(app_mod.DomainResolver):
        def __init__(self, passive, **kw):
            made.update(kw)
            super().__init__(passive, **kw)
    monkeypatch.setattr(app_mod, "DomainResolver", Recording)
    cfg = Config(backend="demo", live_dns=False, dns_ttl=17, dns_timeout=0.25,
                 exclude_file=str(tmp_path / "ex.json"), compromised_file=str(tmp_path / "c.json"))
    create_app(cfg, DemoBackend(cfg))
    assert made == {"live": False, "ttl": 17, "timeout": 0.25}


def test_main_reports_unreadable_evidence(monkeypatch, capsys):
    from threatbridge import app as app_mod

    def failing(cfg):
        raise app_mod.SourceError("no pcap or nfcapd files found in: /c")
    monkeypatch.setattr(app_mod, "create_app", failing)
    monkeypatch.setattr(sys, "argv", ["threatbridge", "--case", "/c"])
    with pytest.raises(SystemExit):
        app_mod.main()
    assert capsys.readouterr().err == "error: no pcap or nfcapd files found in: /c\n"


def test_json_store_top_level_list(tmp_path):
    path = tmp_path / "x.json"
    path.write_text('["10.0.0.1"]')
    with pytest.raises(StoreError, match="should hold"):
        with JsonStore(str(path), "entries").locked():
            pass


def test_inbound_scan_filters_on_the_destination():
    body = q.es_scan_body(Config(), "10.0.0.5", "in", T0, T1, ["10.9.0.0/16"], 10)
    assert body["query"]["bool"]["filter"][0] == {"term": {"destination.ip": "10.0.0.5"}}
    assert body["query"]["bool"]["must_not"] == [{"term": {"source.ip": "10.9.0.0/16"}}]


class SequenceES(RecordingES):
    def __init__(self, bodies):
        super().__init__()
        self.bodies = list(bodies)

    def post(self, url, json, timeout, params):
        self.body = self.bodies.pop(0)
        return super().post(url, json, timeout, params)


def test_rarest_details_answer_without_peers():
    be = ElasticBackend(Config())
    be.session = SequenceES([{"aggregations": {"scan": {"buckets": [{"key": {"peer": "10.0.0.7"}, "doc_count": 1}],
                                                        "after_key": {"peer": "10.0.0.7"}}}},
                             {"aggregations": {"scan": {"buckets": []}}},
                             {"aggregations": {}}])                 # details: nothing came back
    assert be.neighbors("10.0.0.5", "in", T0, T1, 5, "bottom", []) == {
        "peers": [], "distinct_peers": 1, "truncated": False}


def test_flows_answer_without_hits():
    be = ElasticBackend(Config())
    be.session = RecordingES({"took": 3})
    assert be.flows("10.0.0.1", "10.0.0.2", T0, T1, 0, 50) == {"total": 0, "flows": []}


def test_backend_failures_reach_the_client_as_502(tmp_path):
    cfg = Config(backend="elastic", live_dns=False, exclude_file=str(tmp_path / "ex.json"),
                 compromised_file=str(tmp_path / "c.json"))
    be = ElasticBackend(cfg)
    be.session = RecordingES(status=503)
    c = create_app(cfg, be).test_client()
    r = c.get("/api/neighbors?ip=10.0.0.5&ts=2024-05-01T12:00:00Z")
    assert r.status_code == 502 and r.get_json() == {"error": "Elasticsearch returned HTTP 503"}
    assert c.get("/healthz").get_json() == {"status": "ok", "backend": "elastic"}


def test_adding_an_entry_twice_keeps_one(tmp_path):
    store = ExcludeStore(str(tmp_path / "ex.json"))
    store.add("10.0.0.7/24")
    assert store.add("10.0.0.0/24") == ["10.0.0.0/24"]
    assert json.loads((tmp_path / "ex.json").read_text()) == {"entries": ["10.0.0.0/24"]}


def test_hand_edited_note_that_is_not_text(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"hosts": [{"ip": "10.0.0.5", "time": None, "note": 7},
                                          {"ip": "10.0.0.6", "time": None}]}))
    assert CompromisedStore(str(path)).list() == [{"ip": "10.0.0.6", "time": None, "note": ""}]
