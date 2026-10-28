"""Marks (D15), filters in queries (D17), suspect connections (D16) and exports, through the
stores, the backends and the HTTP API."""
import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest

from threatbridge import app as app_module
from threatbridge import backends
from threatbridge import compromised as comp
from threatbridge import filters
from threatbridge.app import create_app
from threatbridge.backends import (CaseBackend, DemoBackend, ElasticBackend, Scope, es_scope, host_rows,
                                   marked_flow_rows)
from threatbridge.compromised import CompromisedStore
from threatbridge.config import Config
from threatbridge.excludes import ExcludeStore
from threatbridge.model import Flow
from threatbridge.query import ValidationError, es_details_body, fmt_time, parse_time
from threatbridge.store import FlowStore

T = 1_714_564_800.0          # 2024-05-01T12:00:00Z
WRITE = {"X-ThreatBridge": "1"}
E, A, X, B, C, F, Y = "10.9.0.1", "10.9.0.2", "10.9.0.3", "10.9.0.4", "10.9.0.5", "10.9.0.6", "10.9.0.7"
M = 60


def iso(epoch):
    return fmt_time(datetime.fromtimestamp(epoch, timezone.utc))


def flow(src, dst, start, dport=445, service="smb", sport=50000, proto="tcp"):
    return Flow(src, dst, sport, dport, proto, start, start + 1, 2, 120, "x.pcap", service)


# The user story's timeline: E -> A -> X -> B, X -> C, then B -> F and A -> Y; and apart from
# it, a part of the map with no marks: 10.8.0.1 -> 10.8.0.2.
STORY = [flow(E, A, T, 443, "ssl"), flow(A, X, T + 5 * M), flow(X, B, T + 10 * M, 3389, "rdp"),
         flow(X, C, T + 15 * M), flow(B, F, T + 20 * M, 22, "ssh"), flow(A, Y, T + 30 * M, 53, "dns", proto="udp"),
         flow(A, Y, T + 31 * M, 80, "http"), flow(A, Y, T + 100 * M, 53, "dns", proto="udp"),
         flow("10.8.0.1", "10.8.0.2", T + 1, 80, "http")]
EDGES = [{"source": f.src, "target": f.dst, "from": iso(f.start), "to": iso(f.start)} for f in STORY]
EDGES[5]["to"] = iso(T + 100 * M)
del EDGES[6:8]


def key(f, note=""):
    return {"src": f.src, "dst": f.dst, "start": iso(f.start), "sport": f.sport, "dport": f.dport,
            "proto": f.proto, "note": note}


@pytest.fixture
def client(tmp_path):
    cfg = Config(backend="case", compromised_file=str(tmp_path / "c.json"), live_dns=False)
    return create_app(cfg, CaseBackend(cfg, flows=STORY), ExcludeStore(str(tmp_path / "ex.json"))).test_client()


# ---- the shared marks ---------------------------------------------------------------------

def test_hosts_marked_through_flows_count_and_take_the_earliest_time(tmp_path):
    store = CompromisedStore(str(tmp_path / "c.json"))
    store.mark(A, "2024-05-01T12:30:00Z", "EDR")
    view = store.mark_flow(key(STORY[0], "phish"))
    hosts = {h["ip"]: h for h in view["hosts"]}
    assert hosts[A] == {"ip": A, "time": "2024-05-01T12:00:00.000Z", "note": "EDR", "direct": True, "count": 2}
    assert hosts[E] == {"ip": E, "time": "2024-05-01T12:00:00.000Z", "note": "", "direct": False, "count": 1}
    assert view["flows"] == [key(STORY[0], "phish")]
    view = store.mark_flow(key(STORY[1]))
    assert {h["ip"]: h["count"] for h in view["hosts"]} == {E: 1, A: 3, X: 1}
    assert store.times() == {E: T, A: T, X: T + 5 * M}
    # Unmarking a flow drops only it; unmarking a host drops its own mark and its flows.
    view = store.unmark_flow(key(STORY[1]))
    assert {h["ip"]: h["count"] for h in view["hosts"]} == {E: 1, A: 2}
    view = store.unmark(A)
    assert (view["hosts"], view["marked"], view["flows"]) == ([], [], [])
    # A host marked with its time unknown, and through a flow, was reached at the flow's start.
    store.mark(B, "")
    store.mark_flow(key(STORY[2]))
    assert store.times() == {X: T + 10 * M, B: T + 10 * M}
    store.unmark_flow(key(STORY[2]))
    assert store.times() == {B: None}


def test_marked_flows_are_told_apart_by_all_but_the_note(tmp_path):
    store = CompromisedStore(str(tmp_path / "c.json"))
    store.mark_flow(key(STORY[0], "one"))
    view = store.mark_flow(key(STORY[0], "two"))
    assert view["flows"] == [key(STORY[0], "two")]
    other = dict(key(STORY[0]), sport=50001)
    assert len(store.mark_flow(other)["flows"]) == 2
    same_ms = dict(key(STORY[0]), start="2024-05-01T12:00:00.000999Z")    # the same millisecond
    assert len(store.unmark_flow(same_ms)["flows"]) == 1


@pytest.mark.parametrize("body,error", [
    ([], "a flow is an object"),
    ({"dst": B, "start": "2024-05-01T12:00:00Z", "sport": 1, "dport": 2, "proto": "tcp"}, "invalid IP address"),
    ({"src": A, "dst": B, "sport": 1, "dport": 2, "proto": "tcp"}, "start (the flow's start time) is required"),
    ({"src": A, "dst": B, "start": " ", "sport": 1, "dport": 2, "proto": "tcp"}, "start (the flow's start time) is required"),
    ({"src": A, "dst": B, "start": "soon", "sport": 1, "dport": 2, "proto": "tcp"}, "invalid timestamp"),
    ({"src": A, "dst": B, "start": "2024-05-01T12:00:00Z", "sport": "1", "dport": 2, "proto": "tcp"}, "sport must be a port"),
    ({"src": A, "dst": B, "start": "2024-05-01T12:00:00Z", "sport": 1, "dport": 70000, "proto": "tcp"}, "dport must be a port"),
    ({"src": A, "dst": B, "start": "2024-05-01T12:00:00Z", "sport": True, "dport": 2, "proto": "tcp"}, "sport must be a port"),
    ({"src": A, "dst": B, "start": "2024-05-01T12:00:00Z", "sport": 1, "dport": 2, "proto": ""}, "proto must be"),
    ({"src": A, "dst": B, "start": "2024-05-01T12:00:00Z", "sport": 1, "dport": 2, "proto": "tcp", "note": 5}, "note must be text"),
])
def test_invalid_flow_marks(tmp_path, body, error):
    with pytest.raises(ValidationError, match=re.escape(error)):
        CompromisedStore(str(tmp_path / "c.json")).mark_flow(body)


GOOD = {"src": A, "dst": B, "start": "2024-05-01T12:00:00Z", "sport": 1, "dport": 2, "proto": "tcp"}


@pytest.mark.parametrize("parse,body,error", [
    (comp.parse_flow, [], "a flow is an object with src, dst, start, sport, dport and proto"),
    (comp.parse_flow, dict(GOOD, start=None), "start (the flow's start time) is required"),
    (comp.parse_flow, dict(GOOD, proto=" "), "proto must be tcp, udp, icmp or an IP protocol number"),
    (comp.parse_flow, dict(GOOD, proto="x" * 17), "proto must be tcp, udp, icmp or an IP protocol number"),
    (comp.parse_flow, dict(GOOD, sport=65536), "sport must be a port number (0-65535)"),
    (comp.parse_flow, dict(GOOD, dport=-1), "dport must be a port number (0-65535)"),
    (comp.parse_flow, dict(GOOD, note=5), "note must be text"),
    (comp.parse_host, [], "a host is an object with ip, time and note"),
    (comp.parse_marks, [], 'marks are an object: {"hosts": [...], "flows": [...]}'),
    (comp.parse_marks, {"hosts": {}}, 'marks are an object: {"hosts": [...], "flows": [...]}'),
])
def test_invalid_marks_say_what_is_wrong(parse, body, error):
    with pytest.raises(ValidationError) as e:
        parse(body)
    assert str(e.value) == error


def test_the_widest_values_a_flow_mark_takes():
    f = comp.parse_flow(dict(GOOD, sport=0, dport=65535, proto="X" * 16))
    assert (f["sport"], f["dport"], f["proto"]) == (0, 65535, "x" * 16)


def test_how_many_marks_there_may_be(tmp_path, monkeypatch):
    monkeypatch.setattr(comp, "MAX_MARKS", 2)
    store = CompromisedStore(str(tmp_path / "c.json"))
    store.mark(A)
    store.mark(B)
    store.mark(B, note="again")                     # marking one again is not one more
    with pytest.raises(ValidationError) as e:
        store.mark(C)
    assert str(e.value) == "at most 2 marked hosts"
    store.mark_flow(key(STORY[0]))
    store.mark_flow(key(STORY[1]))
    store.mark_flow(key(STORY[1], "again"))
    with pytest.raises(ValidationError) as e:
        store.mark_flow(key(STORY[2]))
    assert str(e.value) == "at most 2 marked flows"
    two = [{"ip": A}, {"ip": B}]
    assert len(comp.parse_marks({"hosts": two, "flows": [key(STORY[0]), key(STORY[1])]})[1]) == 2
    for body in ({"hosts": two + [{"ip": C}]}, {"flows": [key(f) for f in STORY[:3]]}):
        with pytest.raises(ValidationError, match="at most 2 marked hosts and 2 marked flows"):
            comp.parse_marks(body)


def test_hosts_reached_at_an_unknown_time_come_first(tmp_path):
    store = CompromisedStore(str(tmp_path / "c.json"))
    store.mark(A, "2024-05-01T12:00:00Z")
    view = store.mark(C)
    assert [h["ip"] for h in view["marked"]] == [C, A] and [h["ip"] for h in view["hosts"]] == [C, A]
    assert view["marked"][0]["note"] == ""                         # no note given
    assert re.fullmatch("[0-9a-f]{16}", view["version"])


def test_replacing_every_mark_and_the_version(tmp_path):
    store = CompromisedStore(str(tmp_path / "c.json"))
    first = store.list()["version"]
    assert store.list()["version"] == first                     # unchanged: the same tag
    store.mark(A, None)
    assert store.list()["version"] != first
    view = store.replace({"hosts": [{"ip": C, "time": "2024-05-01T12:15:00Z"}], "flows": [key(STORY[4])]})
    assert [h["ip"] for h in view["marked"]] == [C] and view["flows"] == [key(STORY[4])]
    assert {h["ip"] for h in view["hosts"]} == {B, C, F}
    assert store.replace({})["hosts"] == []                    # nothing: every mark goes
    for bad in ([], {"hosts": {}}, {"flows": [{"src": "x"}]}):
        with pytest.raises(ValidationError):
            store.replace(bad)
    with pytest.raises(ValidationError, match="at most 10000 marked hosts"):
        comp.parse_marks({"hosts": [{"ip": A}] * (comp.MAX_MARKS + 1)})


def test_hand_edited_flows_are_skipped_but_kept(tmp_path, caplog):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"hosts": [], "flows": [{"src": "nope"}, key(STORY[0])]}))
    store = CompromisedStore(str(path))
    assert store.list()["flows"] == [key(STORY[0])]
    assert f"{path}: ignoring invalid entry {{'src': 'nope'}}" in caplog.text
    store.unmark(E)
    assert json.loads(path.read_text())["flows"] == [{"src": "nope"}]   # left for someone to fix


def test_the_marks_api(client):
    assert client.post("/api/compromised/flows", json=key(STORY[0])).status_code == 403   # CSRF
    assert client.put("/api/compromised", json={}).status_code == 403
    r = client.post("/api/compromised/flows", json=key(STORY[0]), headers=WRITE).get_json()
    assert [h["ip"] for h in r["hosts"]] == [E, A] and r["flows"] == [key(STORY[0])]
    assert client.post("/api/compromised/flows", json={"src": A}, headers=WRITE).status_code == 400
    r = client.delete("/api/compromised/flows", json=key(STORY[0]), headers=WRITE).get_json()
    assert r["hosts"] == []
    r = client.put("/api/compromised", json={"hosts": [{"ip": B}], "flows": [key(STORY[1])]}, headers=WRITE)
    assert {h["ip"] for h in r.get_json()["hosts"]} == {A, X, B}
    client.post("/api/compromised/flows", json=key(STORY[2]), headers=WRITE)
    r = client.delete("/api/compromised", json={"ip": X}, headers=WRITE).get_json()     # X's flows go too
    assert [h["ip"] for h in r["hosts"]] == [B] and r["flows"] == []


def test_attack_paths_use_hosts_marked_through_flows_and_sent_marks(client):
    client.post("/api/compromised/flows", json=key(STORY[0]), headers=WRITE)     # E and A, at 12:00
    client.post("/api/compromised", json={"ip": B, "time": "2024-05-01T13:00:00Z"}, headers=WRITE)
    pairs = {(p["from"], p["to"]) for p in client.get("/api/paths").get_json()["pairs"]}
    assert pairs == {(E, A), (E, B), (A, B)}
    # An opened map's own marks (D19), sent with the request, instead of the shared ones.
    body = {"marks": {"hosts": [{"ip": X}, {"ip": C}], "flows": []}}
    r = client.post("/api/paths", json=body, headers=WRITE).get_json()
    assert {(p["from"], p["to"]) for p in r["pairs"]} == {(X, C)}
    assert client.post("/api/paths", json={"marks": {"hosts": [{"ip": "x"}]}}, headers=WRITE).status_code == 400


# ---- filters in every query ---------------------------------------------------------------

def test_filters_narrow_expansions_flow_lists_and_connections(client):
    base = f"/api/neighbors?ip={A}&direction=out&ts=2024-05-01T12:00:00Z&window=1h"
    assert {p["peer"] for p in client.get(base).get_json()["peers"]} == {X, Y}
    r = client.get(base + "&filter=SMB").get_json()
    assert [(p["peer"], p["count"], p["protocols"]) for p in r["peers"]] == [(X, 1, ["smb"])]
    r = client.get(base + "&filter=DNS OR HTTP&filter=port 80").get_json()           # combined with AND
    assert [(p["peer"], p["count"], p["ports"], p["protocols"]) for p in r["peers"]] == [(Y, 1, [80], ["http"])]
    r = client.post("/api/neighbors", json={"ip": A, "direction": "out", "ts": "2024-05-01T12:00:00Z",
                                            "window": "1h", "filters": ["DNS"]}, headers=WRITE).get_json()
    assert [(p["peer"], p["count"]) for p in r["peers"]] == [(Y, 1)]
    flows = f"/api/flows?src={A}&dst={Y}&from=2024-05-01T12:30:00Z&to=2024-05-01T12:31:00Z"
    assert client.get(flows).get_json()["total"] == 2
    r = client.get(flows + "&filter=dport 80").get_json()
    assert r["total"] == 1 and [f["dport"] for f in r["flows"]] == [80]
    edge = f"/api/edge?src={A}&dst={Y}&from=2024-05-01T12:30:00Z&to=2024-05-01T12:31:00Z"
    assert client.get(edge).get_json() == {"source": A, "target": Y, "count": 2,
                                           "first_seen": "2024-05-01T12:30:00.000Z",
                                           "last_seen": "2024-05-01T12:31:00.000Z", "ports": [53, 80],
                                           "protocols": ["dns", "http"]}
    r = client.get(f"/api/edge?src={A}&dst={Y}")
    assert r.status_code == 400 and r.get_json()["error"] == "from (start of the first flow) is required"
    r = client.get(edge + "&filter=SSH").get_json()
    assert (r["count"], r["first_seen"], r["ports"]) == (0, None, [])
    assert client.get(edge + "&range_from=2024-05-02T00:00:00Z").get_json()["count"] == 0


def test_filters_apply_to_threat_lines_and_paths(client):
    line = f"/api/threatline?a={A}&b={X}&from=2024-05-01T12:05:00Z&window=1h"
    roles = {n["id"]: n["role"] for n in client.get(line).get_json()["nodes"]}
    assert roles[E] == "up" and roles[B] == roles[C] == "down"
    roles = {n["id"]: n["role"] for n in client.get(line + "&filter=NOT RDP").get_json()["nodes"]}
    assert E in roles and B not in roles and roles[C] == "down"
    assert client.get(line + "&filter=RDP").status_code == 400     # the conversation itself fails
    paths = f"/api/paths?src={E}&dst={B}&window=1h"
    assert len(client.get(paths).get_json()["paths"]) == 1
    assert client.get(paths + "&filter=NOT SMB").get_json()["paths"] == []


def test_marked_flows_pass_every_filter(client):
    """Locked in (D15): a marked flow passes any filter, in every query."""
    client.post("/api/compromised/flows", json=key(STORY[1]), headers=WRITE)     # A -> X, SMB
    base = f"/api/neighbors?ip={A}&direction=out&ts=2024-05-01T12:00:00Z&window=1h&filter=DNS"
    assert {p["peer"] for p in client.get(base).get_json()["peers"]} == {X, Y}
    paths = f"/api/paths?src={E}&dst={B}&window=1h&filter=TLS OR RDP"
    assert len(client.get(paths).get_json()["paths"]) == 1        # E -> A (TLS), A -> X (marked), X -> B
    # The map's own marks, when it sends them, decide what is locked in.
    body = {"ip": A, "direction": "out", "ts": "2024-05-01T12:00:00Z", "window": "1h", "filters": ["DNS"],
            "marks": {"hosts": [], "flows": []}}
    r = client.post("/api/neighbors", json=body, headers=WRITE).get_json()
    assert {p["peer"] for p in r["peers"]} == {Y}


def test_filter_checks_and_limits(client):
    assert client.get("/api/filter?filter=(SMB||TLS)%26%26sport 42000").get_json() == \
        {"filter": "(SMB OR TLS) AND sport == 42000"}
    r = client.get("/api/filter?filter=smb")
    assert r.status_code == 400 and r.get_json()["error"] == "at character 1: protocol names are case-sensitive: write SMB"
    assert client.get("/api/filter").status_code == 400
    base = f"/api/neighbors?ip={A}&direction=out&ts=2024-05-01T12:00:00Z"
    assert client.get(base + "&filter=smb").status_code == 400
    assert client.get(base + "&filter=SMB" * 21).status_code == 400
    r = client.post("/api/neighbors", json={"ip": A, "filters": "SMB"}, headers=WRITE)
    assert r.status_code == 400 and r.get_json()["error"] == "filters are a list of expressions"
    r = client.post("/api/neighbors", json={"ip": A, "limit": [1]}, headers=WRITE)
    assert r.get_json()["error"] == "limit must be text or a number"
    assert client.post("/api/neighbors", json={"ip": A}).status_code == 403


def test_filtered_graphs_are_kept_and_rebuilt_when_marked_flows_change():
    backend = CaseBackend(Config(backend="case"), flows=STORY)
    smb = Scope(filters.parse("SMB"))
    g1, _ = backend._view(smb)
    assert backend._view(Scope(filters.parse("SMB")))[0] is g1                 # reused
    assert backend._view(None)[0] is backend.graph
    g2, _ = backend._view(Scope(filters.parse("SMB"), [key(STORY[0])]))       # a marked flow: rebuilt
    assert g2 is not g1 and g2.has_edge(E, A) and not g1.has_edge(E, A)
    for text in ("DNS", "HTTP", "SSH", "RDP"):
        backend._view(Scope(filters.parse(text)))
    assert len(backend._graphs) == backend.GRAPHS_KEPT
    assert backend._view(smb)[0] is not g1                                     # dropped, oldest first


def test_the_store_queries_take_a_filter(tmp_path):
    store = FlowStore(str(tmp_path / "case.db"))
    store.write([flow(A, Y, T, 53, "dns", proto="udp"), flow(A, Y, T, 80, "http", sport=50001),
                 flow(A, Y, T + 60, 53, "dns", proto="udp"),
                 flow(A, X, T + 9.5), flow(A, X, T + 10), flow(A, X, T + 10.5)], {}, [])
    http = filters.to_sql(filters.parse("HTTP").core, "f.")
    span = [(T - 1, T + 100)]
    assert store.count(A, Y, span) == 3 and store.count(A, Y, span, http) == 1
    assert [f.service for f in store.edge_flows(A, Y, span, http)] == ["http"]
    assert store.times(A, Y, T - 1, T + 100) == [T, T, T + 60] and store.times(A, Y, T - 1, T + 100, http) == [T]
    assert store.flow_at(A, Y, T).service == "dns" and store.flow_at(A, Y, T, http).service == "http"
    # Limited to intervals, one of which touches the range only at its start.
    assert [f.start for f in store.flows(A, Y, T + 60, T + 100, 0, 50, None, [(T, T + 60)])] == [T + 60]
    # A mark names its flow to the millisecond: not one half a second either side.
    [(_, start)] = store.find(A, X, T + 10, 50000, 445, "tcp")
    assert start == T + 10


# Pairs that carry more than one protocol, so a filter changes what a connection counts.
MIXED = [flow(E, A, T, 443, "ssl"), flow(E, A, T + 60, 53, "dns", proto="udp"),
         flow(A, X, T + 5 * M), flow(A, X, T + 5 * M, 80, "http", sport=50001),       # the same start
         flow(X, B, T + 10 * M, 3389, "rdp"), flow(X, B, T + 10 * M + 1, 53, "dns", proto="udp"),
         flow(B, F, T + 20 * M, 22, "ssh"), flow(B, F, T + 21 * M, 53, "dns", proto="udp")]


def at(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc)


def test_a_filter_narrows_every_connection_of_a_threat_line():
    backend = CaseBackend(Config(backend="case"), flows=MIXED)
    line = backend.threat_line(X, B, at(T + 10 * M), at(T + 10 * M + 1), timedelta(hours=1), 6, [], 300,
                               scope=Scope(filters.parse("NOT DNS")))
    assert {(e["source"], e["target"]): (e["role"], e["count"], e["protocols"]) for e in line["edges"]} == {
        (X, B): ("selected", 1, ["rdp"]), (A, X): ("up", 2, ["http", "smb"]), (E, A): ("up", 1, ["ssl"]),
        (B, F): ("down", 1, ["ssh"])}
    nodes = {n["id"]: n for n in line["nodes"]}
    assert nodes[E] == {"id": E, "role": "up", "time": iso(T), "hops": 2}
    assert nodes[F] == {"id": F, "role": "down", "time": iso(T + 20 * M), "hops": 1}


def test_a_filter_picks_the_flow_each_hop_of_a_path_shows():
    backend = CaseBackend(Config(backend="case"), flows=MIXED)
    hour = timedelta(hours=1)
    assert [h["protocols"] for h in backend.paths_between(E, B, None, None, hour, 6, [])["paths"][0]["hops"]][1] == ["smb"]
    scope = Scope(filters.parse("NOT (SMB OR DNS)"))
    [path] = backend.paths_between(E, B, None, None, hour, 6, [], scope=scope)["paths"]
    assert [(h["source"], h["protocols"]) for h in path["hops"]] == [(E, ["ssl"]), (A, ["http"]), (X, ["rdp"])]
    [pair] = backend.attack_paths({E: None, B: None}, hour, 6, [], scope=scope)["pairs"]
    assert pair["paths"] == [path]


def test_a_filter_narrows_suspect_connections_and_their_flow_lists(client, monkeypatch):
    client.post("/api/compromised", json={"ip": B, "time": "2024-05-01T12:10:00Z"}, headers=WRITE)
    # Without SMB, nothing leads from E -> A to B.
    got = suspect(client, filters=["NOT SMB"])
    assert {pair: e["status"] for pair, e in got.items() if e["status"] == "kept"} == {(X, B): "kept", (B, F): "kept"}
    r = client.post("/api/export", json={"edges": EDGES, "window": "1h", "filters": ["NOT SMB"]}, headers=WRITE)
    assert [(f["src"], f["dst"]) for f in r.get_json()["flows"]] == [(X, B), (B, F)]
    # A flow list limited to intervals counts only what passes the filter...
    body = {"src": A, "dst": Y, "from": "2024-05-01T12:30:00Z", "to": "2024-05-01T13:40:00Z",
            "within": [["2024-05-01T12:30:00Z", "2024-05-01T12:31:00Z"]]}
    assert client.post("/api/flows", json=body, headers=WRITE).get_json()["total"] == 2
    r = client.post("/api/flows", json=dict(body, filters=["NOT DNS"]), headers=WRITE).get_json()
    assert r["total"] == 1 and [f["dport"] for f in r["flows"]] == [80]
    # ...and nothing when the intervals are outside the range asked for.
    r = client.post("/api/flows", json=dict(body, within=[["2024-05-01T15:00:00Z", "2024-05-01T15:01:00Z"]]),
                    headers=WRITE).get_json()
    assert (r["total"], r["flows"]) == (0, [])
    # An interval that ends just where the range starts still holds a flow at that instant.
    monkeypatch.setattr(backends, "TIME_SLACK", 0)
    r = client.post("/api/flows", json=dict(body, within=[["2024-05-01T12:00:00Z", "2024-05-01T12:30:00Z"]]),
                    headers=WRITE).get_json()
    assert r["total"] == 1 and [f["dport"] for f in r["flows"]] == [53]


def test_a_reached_time_a_little_after_a_flow_out_still_keeps_it(client):
    # Times a little off (TIME_SLACK): A reached half a millisecond after A -> X started.
    client.post("/api/compromised", json={"ip": A, "time": "2024-05-01T12:05:00.0005Z"}, headers=WRITE)
    assert suspect(client)[(A, X)]["status"] == "kept"


def test_a_filter_counts_only_the_flows_it_lets_through_on_a_kept_connection():
    backend = CaseBackend(Config(backend="case"), flows=MIXED + [flow(E, A, T + 120, 443, "ssl")])
    drawn = [(E, A, T, T + 120), (A, X, T + 5 * M, T + 5 * M)]
    hosts = [{"ip": A, "time": None, "note": ""}]
    got = backend.suspects(drawn, hosts, [], timedelta(hours=1), 6, [], scope=Scope(filters.parse("NOT DNS")))
    e = next(e for e in got["edges"] if e["source"] == E)
    assert (e["status"], e["count"], e["protocols"]) == ("kept", 2, ["ssl"])


# ---- suspect connections and exports -------------------------------------------------------

def suspect(client, marks=None, **extra):
    body = {"edges": EDGES, "window": "1h", **extra}
    if marks is not None:
        body["marks"] = marks
    r = client.post("/api/suspect", json=body, headers=WRITE)
    assert r.status_code == 200, r.get_json()
    return {(e["source"], e["target"]): e for e in r.get_json()["edges"]}


def test_suspect_connections(client):
    # No marks: nothing is affected.
    assert {e["status"] for e in suspect(client).values()} == {"unaffected"}
    # B marked at 12:10: the line into it, and where it went next; the rest of its part hidden,
    # the other part left as it is.
    client.post("/api/compromised", json={"ip": B, "time": "2024-05-01T12:10:00Z"}, headers=WRITE)
    got = suspect(client)
    assert {pair: e["status"] for pair, e in got.items()} == {
        (E, A): "kept", (A, X): "kept", (X, B): "kept", (X, C): "hidden", (B, F): "kept",
        (A, Y): "hidden", ("10.8.0.1", "10.8.0.2"): "unaffected"}
    assert got[(X, B)] == {"source": X, "target": B, "status": "kept", "count": 1, "marked": 0, "suspect": 1,
                           "first_seen": "2024-05-01T12:10:00.000Z", "last_seen": "2024-05-01T12:10:00.000Z",
                           "ports": [3389], "protocols": ["rdp"],
                           "within": [["2024-05-01T12:10:00.000Z", "2024-05-01T12:10:00.000Z"]]}
    # Marking A -> Y's first flow (12:30) marks A and Y, reached then: the flow is kept as
    # marked, the next (12:31) as suspect, and the one at 13:40, past the Window, is not counted.
    client.post("/api/compromised/flows", json=key(STORY[5]), headers=WRITE)
    got = suspect(client)
    assert {k: got[(A, Y)][k] for k in ("status", "count", "marked", "suspect", "protocols", "last_seen")} == \
        {"status": "kept", "count": 2, "marked": 1, "suspect": 1, "protocols": ["dns", "http"],
         "last_seen": "2024-05-01T12:31:00.000Z"}
    assert got[(X, C)]["status"] == "hidden"                  # before A was reached, on no line
    # Its flow list, by the intervals given, holds just those two.
    r = client.post("/api/flows", json={"src": A, "dst": Y, "from": "2024-05-01T12:30:00Z", "to": "2024-05-01T13:40:00Z",
                                        "within": got[(A, Y)]["within"]}, headers=WRITE).get_json()
    assert r["total"] == 2 and [f["dport"] for f in r["flows"]] == [53, 80]
    # Filters narrow the lines: without SMB, E -> A -> X -> B is broken at A -> X.
    got = suspect(client, filters=["NOT SMB"])
    assert got[(A, X)]["status"] == "hidden" and got[(E, A)]["status"] == "kept"     # E -> A leads to A
    # A map's own marks (D19) replace the shared ones.
    got = suspect(client, marks={"hosts": [{"ip": "10.8.0.2"}], "flows": []})
    assert got[("10.8.0.1", "10.8.0.2")]["status"] == "kept" and got[(X, B)]["status"] == "unaffected"
    # The Window and the time range bound the lines.
    got = suspect(client, window="4m")
    assert got[(A, X)]["status"] == "hidden"
    got = suspect(client, range_from="2024-05-01T12:04:00Z")
    assert got[(E, A)]["status"] == "hidden" and got[(A, X)]["status"] == "kept"


@pytest.mark.parametrize("body,error", [
    ({"edges": "x"}, "edges is a list of at most 20000 connections"),
    ({"edges": [{"source": A, "target": B}]}, "each connection is {source, target, from, to}"),
    ({"edges": [{"source": A, "target": "b", "from": "2024-05-01T12:00:00Z"}]}, "invalid IP address"),
    ({"edges": [{"source": A, "target": B, "from": "2024-05-01T12:00:00Z", "to": "2024-05-01T11:00:00Z"}]},
     "a connection's to is before its from"),
])
def test_suspect_requests_are_checked(client, body, error):
    r = client.post("/api/suspect", json=body, headers=WRITE)
    assert r.status_code == 400 and r.get_json()["error"].startswith(error)


def test_how_many_connections_and_intervals_a_map_may_send(client, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_EDGES", 2)
    monkeypatch.setattr(app_module, "MAX_WITHIN", 2)
    assert client.post("/api/suspect", json={"edges": EDGES[:2]}, headers=WRITE).status_code == 200
    assert client.post("/api/suspect", json={"edges": EDGES[:3]}, headers=WRITE).status_code == 400
    flows = {"src": A, "dst": Y, "from": "2024-05-01T12:30:00Z", "to": "2024-05-01T12:31:00Z"}
    assert client.post("/api/flows", json=flows, headers=WRITE).get_json()["total"] == 2      # no "within"
    span = ["2024-05-01T12:30:00Z", "2024-05-01T12:31:00Z"]
    assert client.post("/api/flows", json=dict(flows, within=[span, span]), headers=WRITE).status_code == 200
    for within in ([span] * 3, [span[:1]], [[1, 2]], [["", span[1]]], "x"):
        r = client.post("/api/flows", json=dict(flows, within=within), headers=WRITE)
        assert r.status_code == 400 and r.get_json()["error"] == "within is a list of [from, to] times", within


def test_how_each_host_was_marked():
    flows = [comp.parse_flow(key(STORY[1])), comp.parse_flow(key(STORY[3]))]          # A -> X, X -> C
    hosts = [comp.parse_host({"ip": C}), comp.parse_host({"ip": B})]
    assert {h["ip"]: (h["marked"], h["count"]) for h in host_rows(hosts, flows)} == {
        A: ("flows", 1), X: ("flows", 2), C: ("both", 2), B: ("direct", 1)}


def test_a_marked_flow_passes_any_filter():
    fl = filters.flow_values(STORY[1])                                                   # A -> X, SMB
    scope = Scope(filters.parse("DNS"), [comp.parse_flow(key(STORY[0])), comp.parse_flow(key(STORY[1]))])
    assert scope.passes(fl, A, X) and not Scope(filters.parse("DNS")).passes(fl, A, X)
    assert not scope.passes(fl, X, A)
    for change in ({"sport": 1}, {"dport": 1}, {"proto": "udp"}, {"start": STORY[1].start + 0.001}):
        assert not scope.passes(dict(fl, **change), A, X), change


class FlowLists:
    """A backend's flows(), from {(src, dst): [flow rows]}; it remembers what it was asked."""

    def __init__(self, rows):
        self.rows, self.asked = rows, []

    def flows(self, src, dst, start, end, offset, limit):
        self.asked.append((src, dst, start, end, offset, limit))
        return {"total": 0, "flows": self.rows.get((src, dst), [])}


def test_marked_flows_exported_with_what_the_backend_knows_of_them():
    ax, xc, ea = (comp.parse_flow(key(f)) for f in (STORY[1], STORY[3], STORY[0]))
    row = {"start": ax["start"], "duration": 1.5, "sport": 50000, "dport": 445, "proto": "tcp",
           "protocols": ["smb"], "packets": 2, "bytes": 120}
    backend = FlowLists({(A, X): [dict(row, sport=1), row], (X, C): [dict(row, start=xc["start"], duration=None)]})
    drawn = [(A, X, 0, 0), (X, C, 0, 0)]
    rows = marked_flow_rows(backend, drawn, [ea, ax, xc], 10)                 # E -> A is not drawn
    assert rows == [
        {"start": ax["start"], "end": "2024-05-01T12:05:01.500Z", "src": A, "sport": 50000, "dst": X, "dport": 445,
         "proto": "tcp", "protocols": ["smb"], "packets": 2, "bytes": 120, "status": "marked"},
        {"start": xc["start"], "end": None, "src": X, "sport": 50000, "dst": C, "dport": 445, "proto": "tcp",
         "protocols": ["smb"], "packets": 2, "bytes": 120, "status": "marked"}]
    t = parse_time(ax["start"])
    assert backend.asked[0] == (A, X, t, t + timedelta(milliseconds=1), 0, 50)
    # Not found: what the mark says, the rest unknown; and no more than the limit.
    assert marked_flow_rows(FlowLists({}), drawn, [ax, xc], 1) == [
        {"start": ax["start"], "end": None, "src": A, "sport": 50000, "dst": X, "dport": 445, "proto": "tcp",
         "protocols": [], "packets": None, "bytes": None, "status": "marked"}]


def test_elasticsearch_exports_marked_hosts_and_flows(monkeypatch):
    backend = ElasticBackend(Config())
    ax = comp.parse_flow(key(STORY[1]))
    lists = FlowLists({(A, X): [{"start": ax["start"], "duration": 1.0, "sport": 50000, "dport": 445, "proto": "tcp",
                                 "protocols": ["smb"], "packets": 2, "bytes": 120}]})
    monkeypatch.setattr(backend, "flows", lists.flows)
    assert backend.export([(A, X, 0, 0)], [comp.parse_host({"ip": B})], [ax], 10) == {
        "hosts": [{"ip": B, "time": None, "note": "", "count": 1, "marked": "direct"},
                  {"ip": A, "time": ax["start"], "note": "", "count": 1, "marked": "flows"},
                  {"ip": X, "time": ax["start"], "note": "", "count": 1, "marked": "flows"}],
        "flows": [{"start": ax["start"], "end": "2024-05-01T12:05:01.000Z", "src": A, "sport": 50000, "dst": X,
                   "dport": 445, "proto": "tcp", "protocols": ["smb"], "packets": 2, "bytes": 120,
                   "status": "marked"}],
        "truncated": False}


def test_exports(client):
    client.post("/api/compromised", json={"ip": B, "time": "2024-05-01T12:10:00Z", "note": "EDR"}, headers=WRITE)
    client.post("/api/compromised/flows", json=key(STORY[2]), headers=WRITE)                  # X -> B
    r = client.post("/api/export", json={"edges": EDGES, "window": "1h"}, headers=WRITE).get_json()
    assert r["hosts"] == [{"ip": X, "time": "2024-05-01T12:10:00.000Z", "note": "", "count": 1, "marked": "flows"},
                          {"ip": B, "time": "2024-05-01T12:10:00.000Z", "note": "EDR", "count": 2, "marked": "both"}]
    # X, reached at 12:10 through the marked flow, went on to C at 12:15: suspect too.
    assert [(f["src"], f["dst"], f["status"]) for f in r["flows"]] == [
        (E, A, "suspect"), (A, X, "suspect"), (X, B, "marked"), (X, C, "suspect"), (B, F, "suspect")]
    assert r["flows"][0] == {"start": "2024-05-01T12:00:00.000Z", "end": "2024-05-01T12:00:01.000Z", "src": E,
                             "sport": 50000, "dst": A, "dport": 443, "proto": "tcp", "protocols": ["ssl"],
                             "packets": 2, "bytes": 120, "status": "suspect"}
    assert r["truncated"] is False
    assert client.post("/api/export", json={"edges": EDGES, "window": "1h", "marks": {"hosts": [], "flows": []}},
                       headers=WRITE).get_json() == {"hosts": [], "flows": [], "truncated": False}


def test_exports_stop_at_the_limit():
    backend = CaseBackend(Config(backend="case"), flows=STORY)
    hosts = [{"ip": B, "time": None, "note": ""}]
    drawn = [(f.src, f.dst, f.start, f.start) for f in STORY]
    r = backend.export(drawn, hosts, [], 2, window=timedelta(hours=1), max_hops=6, exclude=[], bounds=(None, None))
    assert len(r["flows"]) == 2 and r["truncated"] is True
    r = backend.export(drawn, hosts, [], 4, window=timedelta(hours=1), max_hops=6, exclude=[], bounds=(None, None))
    assert len(r["flows"]) == 4 and r["truncated"] is False                     # exactly the limit


def test_suspect_connections_need_the_case_backend(tmp_path):
    cfg = Config(backend="demo", compromised_file=str(tmp_path / "c.json"), live_dns=False)
    c = create_app(cfg, DemoBackend(cfg), ExcludeStore(str(tmp_path / "ex.json"))).test_client()
    assert c.post("/api/suspect", json={"edges": []}, headers=WRITE).status_code == 501
    conf = c.get("/api/config").get_json()
    assert conf["suspects"] is False and conf["marks_poll"] == 5 and conf["protocol_names"]["ssl"] == "TLS"


# ---- the demo and Security Onion backends ------------------------------------------------

def test_demo_backend_filters_and_exports(tmp_path):
    cfg = Config(backend="demo", compromised_file=str(tmp_path / "c.json"), live_dns=False)
    c = create_app(cfg, DemoBackend(cfg), ExcludeStore(str(tmp_path / "ex.json"))).test_client()
    base = "/api/neighbors?ip=10.0.0.5&direction=out&ts=2024-05-01T12:00:00Z"
    every = c.get(base).get_json()["peers"]
    some = c.get(base + "&filter=dport 445").get_json()["peers"]
    assert some and len(some) <= len(every) and all(p["ports"] == [445] for p in some)
    p = some[0]
    r = c.get(f"/api/flows?src=10.0.0.5&dst={p['peer']}&from={p['first_seen']}&to={p['last_seen']}&filter=dport 445").get_json()
    assert r["total"] == p["count"] and {f["dport"] for f in r["flows"]} == {445}
    e = c.get(f"/api/edge?src=10.0.0.5&dst={p['peer']}&from={p['first_seen']}&to={p['last_seen']}&filter=dport 445").get_json()
    assert (e["count"], e["ports"]) == (p["count"], [445])
    f = r["flows"][0]
    mark = {"src": "10.0.0.5", "dst": p["peer"], "start": f["start"], "sport": f["sport"], "dport": 445, "proto": "tcp"}
    c.post("/api/compromised/flows", json=mark, headers=WRITE)
    edges = [{"source": "10.0.0.5", "target": p["peer"], "from": p["first_seen"], "to": p["last_seen"]}]
    r = c.post("/api/export", json={"edges": edges}, headers=WRITE).get_json()
    assert [h["ip"] for h in r["hosts"]] == sorted(["10.0.0.5", p["peer"]])
    assert [(x["src"], x["dport"], x["status"]) for x in r["flows"]] == [("10.0.0.5", 445, "marked")]
    assert r["flows"][0]["packets"] == f["packets"] and r["flows"][0]["protocols"] == ["smb"]
    assert r["truncated"] is False


def top_ports(rows):
    counts = Counter(r["dport"] for r in rows)
    return [p for p, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:5]]


@pytest.mark.parametrize("direction", ["in", "out"])
def test_demo_backend_counts_only_what_passes(direction):
    backend = DemoBackend(Config(backend="demo"))
    ip, t0, t1 = "10.0.0.9", at(T), at(T + 3600)
    scope = Scope(filters.parse(f"host {ip} AND NOT dport 443"))
    every = {p["peer"]: p for p in backend.neighbors(ip, direction, t0, t1, 50, "top", [])["peers"]}
    some = backend.neighbors(ip, direction, t0, t1, 50, "top", [], scope)["peers"]
    assert some and any(p["count"] >= 3 for p in some)
    for p in some:
        src, dst = (p["peer"], ip) if direction == "in" else (ip, p["peer"])
        whole = every[p["peer"]]
        lo, hi = parse_time(whole["first_seen"]), parse_time(whole["last_seen"])
        rows = backend.flows(src, dst, lo, hi, 0, 10 ** 6, scope)["flows"]
        assert rows and all(r["dport"] != 443 for r in rows)
        seen = {"count": len(rows), "first_seen": rows[0]["start"], "last_seen": rows[-1]["start"],
                "ports": top_ports(rows), "protocols": sorted({x for r in rows for x in r["protocols"]})}
        assert p == dict(whole, **seen)
        assert backend.edge(src, dst, lo, hi, scope) == {"source": src, "target": dst, **seen}
    src, dst = (some[0]["peer"], ip) if direction == "in" else (ip, some[0]["peer"])
    assert backend.edge(src, dst, t0, t1, Scope(filters.parse("dport 1"))) == {
        "source": src, "target": dst, "count": 0, "first_seen": None, "last_seen": None, "ports": [], "protocols": []}
    # A marked flow passes even a filter nothing else does.
    row = backend.flows(src, dst, t0, t1, 0, 1)["flows"][0]
    mark = comp.parse_flow({"src": src, "dst": dst, "start": row["start"], "sport": row["sport"],
                            "dport": row["dport"], "proto": "tcp"})
    assert backend.flows(src, dst, t0, t1, 0, 50, Scope(filters.parse("dport 1"), [mark]))["flows"] == [row]


def test_elasticsearch_queries_carry_filters_and_marked_flows(monkeypatch):
    cfg = Config()
    backend = ElasticBackend(cfg)
    sent = []
    bucket = {"key": X, "doc_count": 3, "first_seen": {"value_as_string": "2024-05-01T12:05:00.000Z"},
              "last_seen": {"value_as_string": "2024-05-01T12:06:00.000Z"}, "ports": {"buckets": [{"key": 445}]},
              "protocols": {"buckets": [{"key": "smb"}]}}
    reply = {"hits": {"hits": [], "total": {"value": 0}},
             "aggregations": {"scan": {"buckets": [{"key": {"peer": X}, "doc_count": 3}]},
                              "peers": {"buckets": [bucket]}}}
    monkeypatch.setattr(backend, "_post", lambda body: sent.append(body) or reply)
    t0, t1 = datetime(2024, 5, 1, 12, tzinfo=timezone.utc), datetime(2024, 5, 1, 13, tzinfo=timezone.utc)
    scope = Scope(filters.parse("SMB"), [key(STORY[1])])
    backend.neighbors(A, "out", t0, t1, 5, "top", [], scope)
    assert [p["peer"] for p in backend.neighbors(A, "out", t0, t1, 5, "bottom", [], scope)["peers"]] == [X]
    backend.flows(A, X, t0, t1, 0, 50, scope)
    assert backend.edge(A, X, t0, t1, scope) == {
        "source": A, "target": X, "count": 3, "first_seen": "2024-05-01T12:05:00.000Z",
        "last_seen": "2024-05-01T12:06:00.000Z", "ports": [445], "protocols": ["smb"]}
    clause = es_scope(cfg, scope)
    assert sent[-1] == es_details_body(cfg, A, "out", t0, t1, [X], [], clause)
    assert len(sent) == 5 and all(clause in body["query"]["bool"]["filter"] for body in sent)
    assert clause["bool"]["minimum_should_match"] == 1 and len(clause["bool"]) == 2
    assert clause["bool"]["should"][1] == {"bool": {"filter": [
        {"term": {"source.ip": A}}, {"term": {"destination.ip": X}}, {"term": {"source.port": 50000}},
        {"term": {"destination.port": 445}}, {"term": {"network.transport": "tcp"}},
        {"range": {"@timestamp": {"gte": 1714565100000, "lt": 1714565100001, "format": "epoch_millis"}}}]}}
    assert es_scope(cfg, Scope(filters.parse("SMB"))) == filters.to_es(filters.parse("SMB").core, cfg)
    assert es_scope(cfg, None) is None
    reply["aggregations"] = {}
    assert backend.edge(A, X, t0, t1) == {"source": A, "target": X, "count": 0, "first_seen": None,
                                          "last_seen": None, "ports": [], "protocols": []}
