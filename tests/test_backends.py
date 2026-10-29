"""The Elasticsearch (Security Onion) and demo backends. The case backend is in test_case.py."""
from datetime import datetime, timedelta, timezone

import pytest
import requests

from threatbridge import backends, protocols
from threatbridge import query as q
from threatbridge.app import create_app
from threatbridge.backends import BackendError, DemoBackend, ElasticBackend
from threatbridge.config import Config


T0 = datetime(2024, 5, 1, 12, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(hours=1)


# ---- fake Elasticsearch sessions ----------------------------------------------------------

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


class SequenceES(RecordingES):
    def __init__(self, bodies):
        super().__init__()
        self.bodies = list(bodies)

    def post(self, url, json, timeout, params):
        self.body = self.bodies.pop(0)
        return super().post(url, json, timeout, params)


def _elastic(counts, cap=10000):
    be = ElasticBackend(Config(rare_scan_cap=cap))
    be.session = FakeES(counts)
    return be


# ---- Elasticsearch: peers -----------------------------------------------------------------

def test_elastic_top_peers():
    es = RecordingES({"aggregations": {
        "peers": {"buckets": [
            {"key": "10.0.0.7", "doc_count": 9, "first_seen": {"value": 1714564800000.0},
             "last_seen": {"value_as_string": "2024-05-01T12:30:00.000Z"},
             "ports": {"buckets": [{"key": 443}, {"key": 80}]},
             # Zeek's service: lists, aliases, and records it named nothing for, by transport.
             "protocols": {"buckets": [
                 {"key": "smb,ntlm,gssapi"}, {"key": "krb_tcp"},
                 {"key": "", "transports": {"buckets": [{"key": "tcp"}, {"key": "icmp"}]}}]}},
            {"key": "10.0.0.8", "doc_count": 1, "first_seen": {"value": None}, "last_seen": {},
             "protocols": {"buckets": [{"key": "", "transports": {"buckets": [{"key": "icmp"}]}}]}}]},
        "distinct": {"value": 42}}})
    be = ElasticBackend(Config(es_url="https://es.example:9200/", es_index="logs-zeek-*", es_timeout=7))
    be.session = es
    res = be.neighbors("10.0.0.5", "in", T0, T1, 2, "top", [])
    assert res == {"peers": [
        {"peer": "10.0.0.7", "count": 9, "first_seen": "2024-05-01T12:00:00.000Z",
         "last_seen": "2024-05-01T12:30:00.000Z", "ports": [443, 80],
         "protocols": ["gssapi", "icmp", "krb", "ntlm", "smb", "unknown"]},
        {"peer": "10.0.0.8", "count": 1, "first_seen": None, "last_seen": None, "ports": [],
         "protocols": ["icmp"]}],
        "distinct_peers": 42, "truncated": False}
    [call] = es.calls
    assert call["url"] == "https://es.example:9200/logs-zeek-*/_search"
    assert (call["timeout"], call["params"]) == (7, {"ignore_unavailable": "true"})
    assert call["json"] == q.es_top_body(be.cfg, "10.0.0.5", "in", T0, T1, 2, [])


def test_rarest_is_exact_across_pages():
    counts = {f"10.0.{i // 250}.{i % 250}": 2500 - i for i in range(2500)}
    res = _elastic(counts).neighbors("10.9.9.9", "in", T0, T0, 3, "bottom", [])
    assert [p["count"] for p in res["peers"]] == [1, 2, 3]
    assert res["distinct_peers"] == 2500 and res["truncated"] is False


def test_rarest_truncates_at_cap():
    counts = {f"10.0.{i // 250}.{i % 250}": 5 for i in range(2500)}
    res = _elastic(counts, cap=1500).neighbors("10.9.9.9", "in", T0, T0, 5, "bottom", [])
    assert res["truncated"] is True and res["distinct_peers"] == 1500


def test_rarest_asks_about_the_right_host_and_direction():
    be = _elastic({"10.0.0.7": 3, "10.0.0.8": 1})
    be.neighbors("10.9.9.9", "in", T0, T1, 1, "bottom", ["10.200.0.0/16"])
    first, more, details = be.session.calls            # two scan pages (the second is empty)
    assert first == q.es_scan_body(be.cfg, "10.9.9.9", "in", T0, T1, ["10.200.0.0/16"], 1000)
    assert more == q.es_scan_body(be.cfg, "10.9.9.9", "in", T0, T1, ["10.200.0.0/16"], 1000, {"idx": 2})
    assert details == q.es_details_body(be.cfg, "10.9.9.9", "in", T0, T1, ["10.0.0.8"], ["10.200.0.0/16"])


def test_rarest_details_answer_without_peers():
    be = ElasticBackend(Config())
    be.session = SequenceES([{"aggregations": {"scan": {"buckets": [{"key": {"peer": "10.0.0.7"}, "doc_count": 1}],
                                                        "after_key": {"peer": "10.0.0.7"}}}},
                             {"aggregations": {"scan": {"buckets": []}}},
                             {"aggregations": {}}])                 # details: nothing came back
    assert be.neighbors("10.0.0.5", "in", T0, T1, 5, "bottom", []) == {
        "peers": [], "distinct_peers": 1, "truncated": False}


@pytest.mark.parametrize("order", ["top", "bottom"])
def test_elastic_answers_with_parts_missing(order):
    be = ElasticBackend(Config())
    be.session = RecordingES({})                                  # no aggregations at all
    assert be.neighbors("10.0.0.5", "in", T0, T1, 5, order, [])["peers"] == []
    be.session = RecordingES({"aggregations": {"peers": {"buckets": [{"key": "10.0.0.7", "doc_count": 2}]},
                                               "scan": {"buckets": [{"key": {"peer": "10.0.0.7"}, "doc_count": 2}]}}})
    [p] = be.neighbors("10.0.0.5", "in", T0, T1, 5, order, [])["peers"]
    assert (p["first_seen"], p["last_seen"], p["ports"]) == (None, None, [])


# ---- Elasticsearch: a connection's flows --------------------------------------------------

def test_elastic_flows_read_fields_and_stop_at_the_result_window():
    be = ElasticBackend(Config())
    be.session = FlowsES([
        {"@timestamp": ["2024-05-01T12:00:00.123456Z"], "source.port": [50000],
         "destination.port": [445], "network.transport": ["tcp"], "event.duration": [1.5],
         "client.packets": [3], "server.packets": [4], "client.ip_bytes": [300],
         "network.protocol": ["smb,ntlm"]},
        {"@timestamp": ["2024-05-01T12:00:01Z"], "event.duration": ["n/a"]},
        {"@timestamp": ["2024-05-01T12:00:02Z"], "network.transport": ["icmp"]}], total=7)
    res = be.flows("10.0.0.1", "10.0.0.2", T0, T0, 0, 50)
    assert res["total"] == 7
    assert res["flows"][0] == {"start": "2024-05-01T12:00:00.123Z", "duration": 1.5, "sport": 50000,
                               "dport": 445, "proto": "tcp", "packets": 7, "bytes": 300,
                               "protocols": ["smb", "ntlm"]}
    assert res["flows"][1]["packets"] is None and res["flows"][1]["sport"] is None
    assert [f["protocols"] for f in res["flows"][1:]] == [["unknown"], ["icmp"]]    # none named
    assert res["flows"][1]["duration"] is None                      # not a number: left out
    with pytest.raises(q.ValidationError, match="narrow the time range"):
        be.flows("10.0.0.1", "10.0.0.2", T0, T0, 9990, 50)


def test_elastic_flows_read_the_configured_fields():
    cfg = Config(f_ts="t", f_sport="sp", f_dport="dp", f_proto="pr", f_duration="du",
                 f_packets=["p1", "p2"], f_bytes=["b1", "b2"], f_service="sv")
    be = ElasticBackend(cfg)
    be.session = FlowsES([{"t": ["2024-05-01T12:00:00Z"], "sp": [53000], "dp": [53], "pr": ["udp"],
                           "du": [0.25], "p1": [1], "p2": [1], "b1": [70], "b2": [90], "sv": ["dns"]}],
                         total=1)
    assert be.flows("10.0.0.1", "10.0.0.2", T0, T0, 0, 50)["flows"] == [
        {"start": "2024-05-01T12:00:00.000Z", "duration": 0.25, "sport": 53000, "dport": 53,
         "proto": "udp", "packets": 2, "bytes": 160, "protocols": ["dns"]}]
    # TB_FIELD_SERVICE= (empty): not asked for, so unknown.
    be.cfg.f_service = ""
    assert be.flows("10.0.0.1", "10.0.0.2", T0, T0, 0, 50)["flows"][0]["protocols"] == ["unknown"]


def test_elastic_flows_request_and_limits():
    es = RecordingES({"hits": {}})
    be = ElasticBackend(Config())
    be.session = es
    assert be.flows("10.0.0.1", "10.0.0.2", T0, T1, 9950, 50) == {"total": 0, "flows": []}   # last allowed page
    assert es.calls[0]["json"] == q.es_flows_body(be.cfg, "10.0.0.1", "10.0.0.2", T0, T1, 9950, 50)


def test_elastic_flow_hits_with_parts_missing():
    # No @timestamp among the fields: the hit's sort value (epoch ms of @timestamp) places it.
    # With no time at all the hit is left out rather than shown at a made-up time.
    be = ElasticBackend(Config())
    be.session = RecordingES({"hits": {"total": {"relation": "gte"}, "hits": [
        {"sort": [1714564800000]}, {}, {"fields": {"@timestamp": ["2024-05-01T12:00:01Z"]}}]}})
    r = be.flows("10.0.0.1", "10.0.0.2", T0, T1, 0, 50)
    assert r["total"] == 0
    assert [f["start"] for f in r["flows"]] == ["2024-05-01T12:00:00.000Z", "2024-05-01T12:00:01.000Z"]


def test_flows_answer_without_hits():
    be = ElasticBackend(Config())
    be.session = RecordingES({"took": 3})
    assert be.flows("10.0.0.1", "10.0.0.2", T0, T1, 0, 50) == {"total": 0, "flows": []}


def test_elastic_flows_link_to_their_pcap():
    be = ElasticBackend(Config(soc_url="https://so"))
    be.session = RecordingES({"hits": {"total": {"value": 2}, "hits": [
        {"_id": "P5mgnpEB0JpjNDZz1bIN", "fields": {"@timestamp": ["2024-05-01T12:00:00.123Z"]}},
        {"fields": {"@timestamp": ["2024-05-01T12:00:01Z"]}}]}})
    first, second = be.flows("10.0.0.1", "10.0.0.2", T0, T1, 0, 50)["flows"]
    assert first["id"] == "P5mgnpEB0JpjNDZz1bIN"
    assert first["soc_pcap"] == q.soc_pcap_url(be.cfg, "P5mgnpEB0JpjNDZz1bIN", "2024-05-01T12:00:00.123Z")
    assert "id" not in second and "soc_pcap" not in second


def test_elastic_dns_answers():
    be = ElasticBackend(Config())
    be.session = RecordingES({"aggregations": {"entries": {"buckets": {
        "evil.test": {"doc_count": 3, "ips": {"buckets": [
            {"key": "192.0.2.7", "doc_count": 2, "first": {"value": 1714564800000.0},
             "last": {"value": 1714564860500.0}},
            {"key": "2001:db8::7", "doc_count": 1, "first": {"value": None}, "last": {}}]}},
        "*.cdn.test": {"doc_count": 0, "ips": {"buckets": []}}}}}})
    assert be.dns_answers(["evil.test", "*.cdn.test", "gone.test"]) == {
        "evil.test": {"192.0.2.7": [1714564800.0, 1714564860.5], "2001:db8::7": [None, None]},
        "*.cdn.test": {}, "gone.test": {}}
    [call] = be.session.calls
    assert call["json"] == q.es_dns_body(be.cfg, ["evil.test", "*.cdn.test", "gone.test"])
    be.session = RecordingES({})                                   # no aggregations at all
    assert be.dns_answers(["x.test"]) == {"x.test": {}}
    be.session = RecordingES(status=503)
    with pytest.raises(BackendError, match="HTTP 503"):
        be.dns_answers(["x.test"])


# ---- Elasticsearch: connection and errors -------------------------------------------------

def test_elastic_session_setup():
    be = ElasticBackend(Config(es_user="svc", es_pass=None, es_ca="/etc/pki/ca.crt"))
    assert be.session.auth == ("svc", "") and be.session.verify == "/etc/pki/ca.crt"
    assert be.session.headers["Content-Type"] == "application/json"
    be = ElasticBackend(Config(es_user="svc", es_pass="pw", es_verify=False))
    assert be.session.auth == ("svc", "pw") and be.session.verify is False
    assert ElasticBackend(Config()).session.auth is None


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


def test_an_answer_that_is_not_json_is_a_backend_error():
    be = ElasticBackend(Config())
    be.session = OddES()
    with pytest.raises(BackendError):
        be.neighbors("10.0.0.5", "in", T0, T0, 5, "top", [])
    with pytest.raises(BackendError):
        be.flows("10.0.0.1", "10.0.0.2", T0, T0, 0, 50)


def test_backend_failures_reach_the_client_as_502(tmp_path):
    cfg = Config(backend="elastic", live_dns=False, exclude_file=str(tmp_path / "ex.json"),
                 compromised_file=str(tmp_path / "c.json"))
    be = ElasticBackend(cfg)
    be.session = RecordingES(status=503)
    c = create_app(cfg, be).test_client()
    r = c.get("/api/neighbors?ip=10.0.0.5&ts=2024-05-01T12:00:00Z")
    assert r.status_code == 502 and r.get_json() == {"error": "Elasticsearch returned HTTP 503"}
    assert c.get("/healthz").get_json() == {"status": "ok", "backend": "elastic", "api_version": 1}


# ---- demo backend, and choosing a backend -------------------------------------------------

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
        assert all(f["soc_pcap"] == q.soc_pcap_url(be.cfg, f["id"], f["start"]) for f in r["flows"])
        assert len({f["id"] for f in r["flows"]}) == len(r["flows"])
        # Protocols by port, as case files without a payload have them.
        assert p["protocols"] == sorted({protocols.name("tcp", 0, port, 0) for port in p["ports"]})
        assert all(f["protocols"] == [protocols.name("tcp", 0, f["dport"], 0)] for f in r["flows"])


def test_make_backend():
    assert isinstance(backends.make_backend(Config(backend="demo")), DemoBackend)
    es = backends.make_backend(Config(backend="elastic", es_timeout=9))
    assert isinstance(es, ElasticBackend) and es.cfg.es_timeout == 9
    with pytest.raises(ValueError, match="unknown backend 'nope'"):
        backends.make_backend(Config(backend="nope"))


# ---- protocols in the data (D20) ----------------------------------------------------------

def test_elastic_counts_the_flows_of_each_protocol():
    be = ElasticBackend(Config())
    be.session = RecordingES({"aggregations": {"protocols": {"buckets": [
        {"key": "smb,ntlm", "doc_count": 5}, {"key": "smb", "doc_count": 2}, {"key": "krb_tcp", "doc_count": 1},
        {"key": "", "doc_count": 4, "transports": {"buckets": [{"key": "icmp", "doc_count": 3},
                                                               {"key": "tcp", "doc_count": 1}]}}]}}})
    start, end, counts = be.protocols(T0, T1)
    assert (start, end, counts) == (T0, T1, {"smb": 7, "ntlm": 5, "krb": 1, "icmp": 3, "unknown": 1})
    body = be.session.calls[0]["json"]
    assert body["size"] == 0 and body["aggs"]["protocols"]["terms"]["field"] == "network.protocol"
    filters = body["query"]["bool"]["filter"]
    assert {"range": {"@timestamp": {"gte": "2024-05-01T12:00:00.000Z", "lte": "2024-05-01T13:00:00.000Z",
                                     "format": "strict_date_optional_time"}}} in filters
    assert not any("term" in f for f in filters)                     # every host, not one
    assert body["query"]["bool"]["must_not"] == [{"match": {"connection.state": "REJ"}}]


def test_elastic_protocol_counts_default_to_the_last_max_window():
    be = ElasticBackend(Config(max_window="7d"))
    be.session = RecordingES({"aggregations": {}})
    start, end, counts = be.protocols(None, None)
    assert counts == {} and end - start == timedelta(days=7)
    assert abs((end - datetime.now(timezone.utc)).total_seconds()) < 60
    assert be.protocols(T0, None)[0] == T0                            # from then until now
    assert be.protocols(None, T1)[:2] == (T1 - timedelta(days=7), T1)


def test_elastic_protocol_counts_without_zeek_service_names():
    be = ElasticBackend(Config(f_service=""))
    be.session = RecordingES({"aggregations": {"protocols": {"buckets": [
        {"key": "icmp", "doc_count": 3}, {"key": "tcp", "doc_count": 4}, {"key": "udp", "doc_count": 1}]}}})
    assert be.protocols(T0, T1)[2] == {"icmp": 3, "unknown": 5}
    assert be.session.calls[0]["json"]["aggs"]["protocols"]["terms"]["field"] == "network.transport"


def test_demo_protocol_counts_follow_the_filter():
    be = DemoBackend(Config(backend="demo"))
    start, end, counts = be.protocols(T0, T1)
    assert (start, end) == (T0, T1) and set(counts) == {protocols.name("tcp", 0, p, 0) for p in DemoBackend.PORTS}
    assert all(n > 0 for n in counts.values()) and be.protocols(T0, T1)[2] == counts       # deterministic
    from threatbridge import filters
    from threatbridge.backends import Scope
    assert set(be.protocols(T0, T1, Scope(filters.parse("SMB OR dport 22")))[2]) == {"smb", "ssh"}
