"""Input validation, time handling and query builders (Elasticsearch and SOC OQL)."""
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

import pytest

from threatbridge import query as q
from threatbridge.config import Config


T0 = datetime(2024, 5, 1, 12, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(hours=1)
RANGE = {"range": {"@timestamp": {"gte": "2024-05-01T12:00:00.000Z", "lte": "2024-05-01T13:00:00.000Z",
                                  "format": "strict_date_optional_time"}}}
DATASETS = {"terms": {"event.dataset": ["conn", "zeek.conn"]}}
DETAILS = {"first_seen": {"min": {"field": "@timestamp"}}, "last_seen": {"max": {"field": "@timestamp"}},
           "ports": {"terms": {"field": "destination.port", "size": 5}}}


# ---- validation and times -----------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("2024-05-01T12:00:00Z", T0),
    ("2024-05-01T12:00:00.123456789Z", T0 + timedelta(microseconds=123456)),
    ("2024-05-01T14:00:00+02:00", T0),
    ("1714564800", T0),
    ("1714564800000", T0),
])
def test_parse_time(raw, expected):
    assert q.parse_time(raw) == expected


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


def test_time_range_direction():
    w = timedelta(hours=24)
    assert q.time_range(T0, "in", w) == (T0 - w, T0)
    assert q.time_range(T0, "out", w) == (T0, T0 + w)


@pytest.mark.parametrize("bad", ["", "1.2.3", "10.0.0.1 OR *", "::g"])
def test_parse_ip_rejects(bad):
    with pytest.raises(q.ValidationError):
        q.parse_ip(bad)


def test_parse_network_canonicalises():
    assert q.parse_network("10.0.0.7/24") == "10.0.0.0/24"
    assert q.parse_network("10.0.0.7") == "10.0.0.7"
    with pytest.raises(q.ValidationError):
        q.parse_network("10.0.0.0/33")


def test_domain_length_limit():
    ok = ".".join(["a" * 63] * 3 + ["b" * 61])                            # 253 characters
    assert len(ok) == 253 and q.parse_exclude(ok) == ok
    with pytest.raises(q.ValidationError):
        q.parse_exclude(ok + "b")


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


# ---- Elasticsearch queries ----------------------------------------------------------------

def test_es_filter_direction_and_excludes():
    cfg = Config()
    f = q.es_filter(cfg, "10.0.0.5", "in", T0, T0, ["10.9.0.0/16"])["bool"]
    assert {"term": {"destination.ip": "10.0.0.5"}} in f["filter"]
    assert {"terms": {"event.dataset": ["conn", "zeek.conn"]}} in f["filter"]
    assert f["must_not"] == [{"term": {"source.ip": "10.9.0.0/16"}}]
    f = q.es_filter(cfg, "10.0.0.5", "out", T0, T0, [])["bool"]
    assert {"term": {"source.ip": "10.0.0.5"}} in f["filter"]


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


def test_es_bodies_for_inbound_peers():
    body = q.es_scan_body(Config(), "10.0.0.5", "in", T0, T1, ["10.9.0.0/16"], 10)
    assert body["aggs"]["scan"]["composite"]["sources"] == [{"peer": {"terms": {"field": "source.ip"}}}]
    assert body["query"]["bool"]["filter"][0] == {"term": {"destination.ip": "10.0.0.5"}}
    assert body["query"]["bool"]["must_not"] == [{"term": {"source.ip": "10.9.0.0/16"}}]
    body = q.es_details_body(Config(), "10.0.0.5", "in", T0, T1, ["10.0.0.7"], [])
    assert body["aggs"]["peers"]["terms"]["field"] == "source.ip"
    assert body["query"]["bool"]["filter"][0] == {"term": {"destination.ip": "10.0.0.5"}}
    assert {"terms": {"source.ip": ["10.0.0.7"]}} in body["query"]["bool"]["filter"]


def test_es_flows_body():
    body = q.es_flows_body(Config(), "10.0.0.1", "10.0.0.2", T0, T0, 100, 50)
    assert (body["from"], body["size"], body["sort"]) == (100, 50, [{"@timestamp": "asc"}])
    f = body["query"]["bool"]["filter"]
    assert {"term": {"source.ip": "10.0.0.1"}} in f and {"terms": {"destination.ip": ["10.0.0.2"]}} in f
    assert body["_source"] is False and body["track_total_hits"] is True
    assert {"source.port", "event.duration", "client.packets", "server.ip_bytes"} <= set(body["fields"][1:])


def test_es_dns_body_asks_about_every_entry_at_once():
    body = q.es_dns_body(Config(), ["evil.test", "*.cdn.test"])
    assert body["query"] == {"bool": {"filter": [{"exists": {"field": "dns.resolved_ip"}},
                                                 {"terms": {"event.dataset": ["dns", "zeek.dns"]}}]}}
    assert body["size"] == 0 and body["track_total_hits"] is False
    entries = body["aggs"]["entries"]
    assert entries["filters"]["filters"] == {
        "evil.test": {"term": {"dns.query.name": {"value": "evil.test", "case_insensitive": True}}},
        "*.cdn.test": {"wildcard": {"dns.query.name": {"value": "*.cdn.test", "case_insensitive": True}}}}
    assert entries["aggs"] == {"ips": {"terms": {"field": "dns.resolved_ip", "size": q.DNS_ADDRESSES},
                                       "aggs": {"first": {"min": {"field": "@timestamp"}},
                                                "last": {"max": {"field": "@timestamp"}}}}}
    cfg = Config(dns_datasets=[], f_dns_query="q", f_dns_ip="ip")
    body = q.es_dns_body(cfg, ["x.test"])
    assert body["query"]["bool"]["filter"] == [{"exists": {"field": "ip"}}]
    assert body["aggs"]["entries"]["filters"]["filters"]["x.test"] == {"term": {"q": {"value": "x.test", "case_insensitive": True}}}


def test_pcap_links_and_document_ids():
    cfg = Config(soc_url="https://so")
    assert q.soc_pcap_url(cfg, "P5mgnpEB0JpjNDZz1bIN", "2024-05-01T12:00:00.123Z") == \
        "https://so/joblookup?esid=P5mgnpEB0JpjNDZz1bIN&time=2024-05-01T12%3A00%3A00.123Z"
    assert q.parse_es_id("abc_-09XYZ") == "abc_-09XYZ" and q.parse_es_id("a" * 512) == "a" * 512
    for bad in ("", "a b", "x&time=1", "../x", "a" * 513, 5, None):
        with pytest.raises(q.ValidationError, match="invalid document ID"):
            q.parse_es_id(bad)


# ---- SOC pivots ---------------------------------------------------------------------------

def test_pivot_query_both_directions_up_to_ioc():
    cfg = Config(soc_url="https://so")
    query = q.soc_pivot_query(cfg, "10.0.0.1", "fe80::1", T0)
    assert '(source.ip:"10.0.0.1" AND destination.ip:"fe80::1")' in query
    assert '(source.ip:"fe80::1" AND destination.ip:"10.0.0.1")' in query
    assert '@timestamp:[* TO "2024-05-01T12:00:00.000Z"]' in query
    url = q.soc_url(cfg, query)
    assert url.startswith("https://so/#/dashboards?q=")
    assert unquote(url.split("q=", 1)[1]) == query
