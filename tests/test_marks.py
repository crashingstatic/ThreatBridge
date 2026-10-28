"""Marks (D15), filters in queries (D17), suspect connections (D16) and exports, through the
stores, the backends and the HTTP API."""
import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from threatbridge import compromised as comp
from threatbridge import filters
from threatbridge.app import create_app
from threatbridge.backends import CaseBackend, DemoBackend, ElasticBackend, Scope, es_scope
from threatbridge.compromised import CompromisedStore
from threatbridge.config import Config
from threatbridge.excludes import ExcludeStore
from threatbridge.model import Flow
from threatbridge.query import ValidationError, fmt_time

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


def test_hand_edited_flows_are_skipped_but_kept(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"hosts": [], "flows": [{"src": "nope"}, key(STORY[0])]}))
    store = CompromisedStore(str(path))
    assert store.list()["flows"] == [key(STORY[0])]
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
    ({"edges": "x"}, "edges is a list"),
    ({"edges": [{"source": A, "target": B}]}, "each connection is {source, target, from, to}"),
    ({"edges": [{"source": A, "target": "b", "from": "2024-05-01T12:00:00Z"}]}, "invalid IP address"),
    ({"edges": [{"source": A, "target": B, "from": "2024-05-01T12:00:00Z", "to": "2024-05-01T11:00:00Z"}]},
     "a connection's to is before its from"),
])
def test_suspect_requests_are_checked(client, body, error):
    r = client.post("/api/suspect", json=body, headers=WRITE)
    assert r.status_code == 400 and error in r.get_json()["error"]


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


def test_elasticsearch_queries_carry_filters_and_marked_flows(monkeypatch):
    cfg = Config()
    backend = ElasticBackend(cfg)
    sent = []
    monkeypatch.setattr(backend, "_post", lambda body: sent.append(body) or {"hits": {"hits": [], "total": {"value": 0}},
                                                                            "aggregations": {}})
    t0, t1 = datetime(2024, 5, 1, 12, tzinfo=timezone.utc), datetime(2024, 5, 1, 13, tzinfo=timezone.utc)
    scope = Scope(filters.parse("SMB"), [key(STORY[1])])
    backend.neighbors(A, "out", t0, t1, 5, "top", [], scope)
    backend.neighbors(A, "out", t0, t1, 5, "bottom", [], scope)
    backend.flows(A, X, t0, t1, 0, 50, scope)
    backend.edge(A, X, t0, t1, scope)
    clause = es_scope(cfg, scope)
    assert all(clause in body["query"]["bool"]["filter"] for body in sent)
    assert clause["bool"]["should"][1] == {"bool": {"filter": [
        {"term": {"source.ip": A}}, {"term": {"destination.ip": X}}, {"term": {"source.port": 50000}},
        {"term": {"destination.port": 445}}, {"term": {"network.transport": "tcp"}},
        {"range": {"@timestamp": {"gte": 1714565100000, "lt": 1714565100001, "format": "epoch_millis"}}}]}}
    assert es_scope(cfg, Scope(filters.parse("SMB"))) == filters.to_es(filters.parse("SMB").core, cfg)
    assert es_scope(cfg, None) is None
    assert backend.edge(A, X, t0, t1)["count"] == 0
