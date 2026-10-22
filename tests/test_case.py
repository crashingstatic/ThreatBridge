"""Post-mortem ("case") backend: the flow store, graph queries and the HTTP API on top of them."""
import os
import sqlite3
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from evidence import ACK, SYN, tcp, udp, write_pcap
from threatbridge import sources
from threatbridge import store as store_mod
from threatbridge.app import create_app
from threatbridge.backends import CaseBackend, DemoBackend
from threatbridge.config import Config
from threatbridge.excludes import ExcludeStore
from threatbridge.graph import build_graph
from threatbridge.model import Flow, SourceError
from threatbridge.query import ValidationError
from threatbridge.store import FlowStore, NotAStore


T = 1_714_564_800.0
H = "10.0.0.9"   # host under investigation
WRITE = {"X-ThreatBridge": "1"}


def flow(src, dst, dport, start, proto="tcp", sport=50000):
    return Flow(src, dst, sport, dport, proto, start, start + 1, 2, 120, "x.pcap")


def utc(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc)


FLOWS = [
    flow("10.0.0.1", H, 445, T + 10), flow("10.0.0.1", H, 445, T + 20), flow("10.0.0.1", H, 3389, T + 30),
    flow("10.0.0.2", H, 22, T + 40),
    flow("10.1.0.7", H, 445, T + 50),
    flow("10.0.0.3", H, 0, T + 60, proto="icmp", sport=0),
    flow("10.0.0.4", H, 445, T + 5000),                       # outside the window below
    flow(H, "10.0.0.20", 443, T + 70), flow(H, H, 8080, T + 80),
]


@pytest.fixture
def backend():
    return CaseBackend(Config(backend="case"), flows=FLOWS)


def case_client(tmp_path, flows, **cfg_args):
    """An API client on a case backend holding `flows`."""
    cfg = Config(backend="case", compromised_file=str(tmp_path / "c.json"), **cfg_args)
    return create_app(cfg, CaseBackend(cfg, flows=flows),
                      ExcludeStore(str(tmp_path / "ex.json"))).test_client()


# ---- the flow store -----------------------------------------------------------------------

def test_store_queries(tmp_path):
    store = FlowStore(str(tmp_path / "case.db"))
    store.write(FLOWS, {"x.example": {"10.0.0.1": [T, T + 1]}}, [("/e/cap.pcap", 10, 5)])
    assert store.stats() == (9, T + 10, T + 5001)
    assert store.ports(H, "in", ["10.0.0.1", "10.0.0.2", "10.0.0.3"], T + 15, T + 45) == {
        "10.0.0.1": {445: 1, 3389: 1}, "10.0.0.2": {22: 1}, "10.0.0.3": {}}
    assert store.ports(H, "out", ["10.0.0.20"], 0, T * 2) == {"10.0.0.20": {443: 1}}
    assert store.ports("10.9.9.9", "in", [], 0, T * 2) == {}
    assert store.edge("10.0.0.1", H, [(T, T + 25)]) == (2, T + 10, T + 20, {445: 2})
    assert store.edge("10.0.0.1", H, [(T, T + 15), (T + 25, T + 35)]) == (2, T + 10, T + 30,
                                                                       {445: 1, 3389: 1})
    assert store.edge("10.0.0.1", H, [(-float("inf"), float("inf"))])[0] == 3
    assert store.flow_at("10.0.0.2", H, T + 40) == FLOWS[3]
    assert store.dns() == {"x.example": {"10.0.0.1": [T, T + 1]}}
    assert store.matches([("/e/cap.pcap", 10, 5)])
    assert not store.matches([("/e/cap.pcap", 10, 6)])                 # file changed
    assert not FlowStore(str(tmp_path / "other.db")).matches([])      # never built
    store.write(FLOWS[:1], {}, [])                                     # rebuild replaces
    assert store.stats()[0] == 1


def test_store_pages_a_connections_flows_oldest_first(tmp_path):
    store = FlowStore(str(tmp_path / "case.db"))
    store.write(FLOWS[::-1], {}, [])
    assert [f.start for f in store.flows("10.0.0.1", H, T, T + 100, 0, 2)] == [T + 10, T + 20]
    assert [f.start for f in store.flows("10.0.0.1", H, T, T + 100, 2, 2)] == [T + 30]
    assert store.flows("10.0.0.1", H, T + 11, T + 29, 0, 9) == [FLOWS[1]]


def test_flows_with_the_same_start_page_without_gaps(tmp_path):
    same = [Flow("10.0.0.1", H, 50000 + i, 445, "tcp", T, T + 1, 2, 120, "x") for i in range(5)]
    store = FlowStore(str(tmp_path / "case.db"))
    store.write(same, {}, [])
    pages = [store.flows("10.0.0.1", H, T, T, off, 2) for off in (0, 2, 4)]
    assert sorted(f.sport for page in pages for f in page) == [50000 + i for i in range(5)]


def test_flow_at_without_a_match(tmp_path):
    store = FlowStore(str(tmp_path / "case.db"))
    store.write(FLOWS, {}, [])
    assert store.flow_at("10.0.0.1", H, T + 11) is None


def test_reuse_keeps_dns_and_ignores_file_order(tmp_path):
    store = FlowStore(str(tmp_path / "case.db"))
    dns = {"x.example": {"10.0.0.1": [T, T + 1]}}
    files = [("/e/a.pcap", 1, 1), ("/e/b.pcap", 2, 2)]
    store.write(FLOWS, dns, files)
    again = FlowStore(store.path)
    assert again.matches(files[::-1]) and again.dns() == dns
    assert not again.matches(files[:1]) and not again.matches(files + [("/e/c.pcap", 3, 3)])


def test_store_refuses_to_overwrite_other_databases(tmp_path):
    path = str(tmp_path / "app.db")
    sqlite3.connect(path).execute("CREATE TABLE users (name TEXT)").connection.commit()
    with pytest.raises(NotAStore):
        FlowStore(path).write(FLOWS, {}, [])
    assert sqlite3.connect(path).execute("SELECT name FROM sqlite_master").fetchall() == [("users",)]


def test_a_non_sqlite_file_is_never_overwritten(tmp_path):
    notes = tmp_path / "notes.txt"
    notes.write_text("analyst notes, not a database\n" * 20)
    with pytest.raises(NotAStore):
        FlowStore(str(notes)).write(FLOWS, {}, [])
    assert notes.read_text() == "analyst notes, not a database\n" * 20
    cfg = Config(backend="case", case_db=str(notes))
    with pytest.raises(SourceError, match="not a ThreatBridge case database"):
        CaseBackend(cfg, flows=FLOWS)


def test_an_interrupted_build_is_not_reused(tmp_path, monkeypatch):
    path = str(tmp_path / "case.db")
    monkeypatch.setattr(store_mod, "_INDEXES", "CREATE INDEX broken ON nowhere (x);")
    with pytest.raises(sqlite3.Error):
        FlowStore(path).write(FLOWS, {}, [("/e/cap.pcap", 10, 5)])     # dies building the index
    assert not FlowStore(path).matches([("/e/cap.pcap", 10, 5)])


# ---- case backend queries -----------------------------------------------------------------

def test_graph_keeps_every_flow():
    g = build_graph((f.src, f.dst, f.start) for f in FLOWS)
    assert g.number_of_edges() == 7                            # host pairs
    assert list(g["10.0.0.1"][H]["times"]) == [T + 10, T + 20, T + 30]


def test_summary(backend):
    assert backend.summary() == {"flows": 9, "hosts": 7, "start": "2024-05-01T12:00:10.000Z",
                                 "end": "2024-05-01T13:23:21.000Z", "dns_names": 0}


def test_neighbors_inbound(backend):
    res = backend.neighbors(H, "in", utc(T), utc(T + 3600), 10, "top", [])
    rows = {p["peer"]: p for p in res["peers"]}
    assert res["distinct_peers"] == 4 and not res["truncated"]
    assert res["peers"][0]["peer"] == "10.0.0.1"
    assert rows["10.0.0.1"]["count"] == 3 and rows["10.0.0.1"]["ports"] == [445, 3389]
    assert rows["10.0.0.1"]["first_seen"] == "2024-05-01T12:00:10.000Z"
    assert rows["10.0.0.1"]["last_seen"] == "2024-05-01T12:00:30.000Z"
    assert rows["10.0.0.3"]["ports"] == []                    # ICMP has no ports
    assert "10.0.0.4" not in rows                              # outside the window


def test_neighbors_order_limit_exclude_and_self(backend):
    bottom = backend.neighbors(H, "in", utc(T), utc(T + 3600), 2, "bottom", ["10.1.0.0/16"])
    assert [p["peer"] for p in bottom["peers"]] == ["10.0.0.2", "10.0.0.3"]
    assert bottom["distinct_peers"] == 3
    out = backend.neighbors(H, "out", utc(T), utc(T + 3600), 10, "top", [])
    assert [p["peer"] for p in out["peers"]] == ["10.0.0.20"]  # self-connection skipped


def test_neighbor_ties_are_ordered_by_address():
    flows = [flow(p, H, 445, T + i) for i, p in enumerate(["10.0.0.30", "10.0.0.4", "fe80::1", "10.0.0.200"])]
    be = CaseBackend(Config(backend="case"), flows=flows)
    for order in ("top", "bottom"):
        res = be.neighbors(H, "in", utc(T), utc(T + 60), 10, order, [])
        assert [p["peer"] for p in res["peers"]] == sorted(p["peer"] for p in res["peers"])


def test_case_window_math_matches_flow_starts(backend):
    # A flow starting exactly at the window edge is included (same as the Elasticsearch range).
    res = backend.neighbors(H, "in", utc(T + 10), utc(T + 10), 10, "top", [])
    assert [p["peer"] for p in res["peers"]] == ["10.0.0.1"]


def test_ports_rank_by_use_then_number():
    flows = [flow("10.0.0.1", H, 3389, T + i) for i in range(3)] + [flow("10.0.0.1", H, 445, T + 5)] + \
            [flow("10.0.0.1", H, p, T + 6) for p in (8080, 22, 80, 53, 25)]
    be = CaseBackend(Config(backend="case"), flows=flows)
    [peer] = be.neighbors(H, "in", utc(T), utc(T + 60), 10, "top", [])["peers"]
    assert peer["ports"] == [3389, 22, 25, 53, 80]


def test_flow_durations_keep_microseconds():
    f = Flow("10.0.0.1", H, 50000, 445, "tcp", T, T + 1.2345678, 2, 120, "x")
    be = CaseBackend(Config(backend="case"), flows=[f])
    [row] = be.flows("10.0.0.1", H, utc(T), utc(T), 0, 10)["flows"]
    assert row["duration"] == 1.234568


def test_the_store_answers_from_other_threads(backend):
    out = []
    t = threading.Thread(target=lambda: out.append(backend.flows(
        "10.0.0.1", H, utc(T), utc(T + 100), 0, 10)["total"]))
    t.start()
    t.join()
    assert out == [3]


# ---- the API in case mode -----------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    return case_client(tmp_path, FLOWS)


def test_api_config_and_default_anchor(client, backend):
    cfg = client.get("/api/config").get_json()
    assert cfg["backend"] == "case" and cfg["soc_pivots"] is False
    assert cfg["case"]["flows"] == 9
    # No timestamp: look back from the end of the data, or forward from its start.
    r_in = client.get(f"/api/resolve?ip={H}&direction=in").get_json()
    r_out = client.get(f"/api/resolve?ip={H}&direction=out").get_json()
    assert r_in["anchor"] == backend.summary()["end"]
    assert r_out["anchor"] == backend.summary()["start"]
    r_ts = client.get(f"/api/resolve?ip={H}&ts=2024-05-01T12:30:00Z").get_json()
    assert r_ts["anchor"] == "2024-05-01T12:30:00.000Z"


def test_flows_api_lists_a_connection_oldest_first(client):
    base = f"/api/flows?src=10.0.0.1&dst={H}&from=2024-05-01T12:00:10.000Z&to=2024-05-01T12:00:30.000Z"
    r = client.get(base + "&limit=2").get_json()
    assert (r["total"], r["offset"]) == (3, 0)
    assert r["flows"] == [
        {"start": "2024-05-01T12:00:10.000Z", "duration": 1.0, "sport": 50000, "dport": 445,
         "proto": "tcp", "packets": 2, "bytes": 120},
        {"start": "2024-05-01T12:00:20.000Z", "duration": 1.0, "sport": 50000, "dport": 445,
         "proto": "tcp", "packets": 2, "bytes": 120}]
    r = client.get(base + "&limit=2&offset=2").get_json()
    assert [(f["start"], f["dport"]) for f in r["flows"]] == [("2024-05-01T12:00:30.000Z", 3389)]
    assert client.get(base + "&offset=3").get_json()["flows"] == []
    # The analyst's time range narrows the list; outside it there is nothing.
    r = client.get(base + "&range_from=2024-05-01T12:00:15Z").get_json()
    assert r["total"] == 2 and r["start"] == "2024-05-01T12:00:15.000Z"
    assert client.get(base + "&range_to=2024-05-01T12:00:05Z").get_json()["total"] == 0
    assert client.get(f"/api/flows?src=10.0.0.9&dst={H}&from=2024-05-01T12:00:10Z").get_json()["total"] == 0


@pytest.mark.parametrize("query", [
    f"src=10.0.0.1&dst={H}",                                        # no from
    f"src=nope&dst={H}&from=2024-05-01T12:00:10Z",
    f"src=10.0.0.1&dst={H}&from=2024-05-01T12:00:10Z&offset=x",
    f"src=10.0.0.1&dst={H}&from=2024-05-01T12:00:10Z&range_from=2024-05-02T00:00:00Z"
    "&range_to=2024-05-01T00:00:00Z",                                # range ends before it starts
])
def test_flows_api_validation(client, query):
    assert client.get(f"/api/flows?{query}").status_code == 400


def test_time_range_limits_neighbors_and_the_default_anchor(client, backend):
    base = f"/api/neighbors?ip={H}&direction=in&ts=2024-05-01T13:00:00Z&window=24h"

    def peers(extra):
        return {p["peer"]: p["count"] for p in client.get(base + extra).get_json()["peers"]}
    assert peers("")["10.0.0.1"] == 3
    assert peers("&range_from=2024-05-01T12:00:15Z&range_to=2024-05-01T12:00:45Z") == {
        "10.0.0.1": 2, "10.0.0.2": 1}
    assert peers("&range_from=2024-05-02T00:00:00Z") == {}               # window before the range
    # No timestamp: the range's end (inbound) or start (outbound), if inside the data.
    resolve = f"/api/resolve?ip={H}&direction="
    assert client.get(resolve + "in&range_to=2024-05-01T12:30:00Z").get_json()["anchor"] == \
        "2024-05-01T12:30:00.000Z"
    assert client.get(resolve + "out&range_from=2024-05-01T12:30:00Z").get_json()["anchor"] == \
        "2024-05-01T12:30:00.000Z"
    assert client.get(resolve + "in&range_to=2030-01-01T00:00:00Z").get_json()["anchor"] == \
        backend.summary()["end"]
    assert client.get(resolve + "out&range_from=2020-01-01T00:00:00Z").get_json()["anchor"] == \
        backend.summary()["start"]


def test_api_neighbors_from_pcap_directory(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    write_pcap(d / "cap.pcap", [
        (T, tcp("10.0.0.5", H, 50000, 445, SYN)), (T + 0.001, tcp(H, "10.0.0.5", 445, 50000, SYN | ACK)),
        (T + 10, udp(H, "10.0.0.53", 40000, 53, b"q")),
    ])
    cfg = Config(backend="case", case_paths=[str(d)], exclude_file=str(tmp_path / "ex.json"),
                 compromised_file=str(tmp_path / "compromised.json"))
    client = create_app(cfg).test_client()
    res = client.get(f"/api/neighbors?ip={H}&direction=in&ts=2024-05-01T13:00:00Z&window=24h").get_json()
    assert [(p["peer"], p["count"], p["ports"]) for p in res["peers"]] == [("10.0.0.5", 1, [445])]
    res = client.get(f"/api/neighbors?ip={H}&direction=out&ts=2024-05-01T11:00:00Z&window=24h").get_json()
    assert [(p["peer"], p["ports"]) for p in res["peers"]] == [("10.0.0.53", [53])]


def test_an_empty_case_works_end_to_end(tmp_path):
    c = case_client(tmp_path, [])
    assert c.get("/api/config").get_json()["case"] == {
        "flows": 0, "hosts": 0, "start": None, "end": None, "dns_names": 0}
    assert c.get(f"/api/resolve?ip={H}&direction=in").status_code == 200
    assert c.get(f"/api/neighbors?ip={H}&ts=2024-05-01T12:00:00Z").get_json()["peers"] == []
    assert c.get(f"/api/flows?src=10.0.0.1&dst={H}&from=2024-05-01T12:00:00Z").get_json()["total"] == 0
    assert c.get("/api/paths").get_json() == {"pairs": []}
    assert c.get(f"/api/paths?src=10.0.0.1&dst={H}").get_json()["paths"] == []
    assert c.get(f"/api/threatline?a=10.0.0.1&b={H}&from=2024-05-01T12:00:00Z").status_code == 400


def test_analysis_needs_case_backend(tmp_path):
    cfg = Config(backend="demo", compromised_file=str(tmp_path / "c.json"))
    c = create_app(cfg, DemoBackend(cfg), ExcludeStore(str(tmp_path / "ex.json"))).test_client()
    assert c.get("/api/config").get_json()["analysis"] is False
    assert c.get("/api/paths").status_code == 501
    assert c.get(f"/api/paths?src=10.0.0.5&dst={H}").status_code == 501
    assert c.get(f"/api/threatline?a=10.0.0.5&b={H}&from=2024-05-01T12:10:00Z").status_code == 501


# ---- threat lines -------------------------------------------------------------------------

CHAIN = [flow("203.0.113.66", "10.0.0.5", 443, T), flow("10.0.0.5", H, 445, T + 600),
         flow(H, "10.0.0.20", 3389, T + 1200), flow(H, "10.0.0.20", 3389, T + 1300),
         flow("10.0.0.20", "10.0.0.30", 22, T - 600)]   # before the chain: not on it


@pytest.fixture
def chain_client(tmp_path):
    return case_client(tmp_path, CHAIN)


def test_threatline_api(chain_client):
    r = chain_client.get(f"/api/threatline?a=10.0.0.5&b={H}&from=2024-05-01T12:10:00Z").get_json()
    roles = {n["id"]: n["role"] for n in r["nodes"]}
    assert roles == {"10.0.0.5": "selected", H: "selected", "203.0.113.66": "up", "10.0.0.20": "down"}
    edges = {(e["source"], e["target"]): e for e in r["edges"]}
    assert set(edges) == {("10.0.0.5", H), ("203.0.113.66", "10.0.0.5"), (H, "10.0.0.20")}
    assert edges[(H, "10.0.0.20")]["count"] == 2 and edges[(H, "10.0.0.20")]["ports"] == [3389]
    assert edges[(H, "10.0.0.20")]["role"] == "down" and not r["truncated"]
    # Excluded hosts are not traversed.
    chain_client.post("/api/excludes", json={"entry": "10.0.0.20"}, headers=WRITE)
    r = chain_client.get(f"/api/threatline?a=10.0.0.5&b={H}&from=2024-05-01T12:10:00Z").get_json()
    assert "10.0.0.20" not in {n["id"] for n in r["nodes"]}


@pytest.mark.parametrize("query,status", [
    (f"a=10.0.0.5&b={H}", 400),                                       # no from
    (f"a=10.0.0.5&b={H}&from=2024-05-01T15:00:00Z", 400),             # no flows then
    (f"a=10.0.0.5&b={H}&from=2024-05-01T12:10:00Z&hops=0", 400),
    (f"a=10.0.0.5&b={H}&from=2024-05-01T12:10:00Z&window=90d", 400),
])
def test_threatline_validation(chain_client, query, status):
    assert chain_client.get(f"/api/threatline?{query}").status_code == status


def test_threatline_to_before_from(chain_client):
    r = chain_client.get(f"/api/threatline?a=10.0.0.5&b={H}&from=2024-05-01T12:10:00Z&to=2024-05-01T12:00:00Z")
    assert r.status_code == 400 and r.get_json()["error"] == "to is before from"


def test_a_threat_line_needs_flows_in_its_time_range(backend):
    with pytest.raises(ValidationError, match=f"no flows from 10.0.0.1 to {H} in that time range"):
        backend.threat_line("10.0.0.1", H, utc(T + 1000), utc(T + 1000), timedelta(days=1), 6, [], 300)


def test_threat_line_nodes_and_edges_in_detail():
    # X reaches A before the selected hop and B reaches X after it: X is on both sides.
    A, B, X = "10.0.0.1", "10.0.0.2", "10.0.0.3"
    flows = [flow(X, A, 1, T), flow(A, B, 2, T + 10), flow(A, B, 2, T + 20), flow(B, X, 3, T + 30)]
    be = CaseBackend(Config(backend="case"), flows=flows)
    r = be.threat_line(A, B, utc(T + 10), utc(T + 20), timedelta(days=1), 6, [], 300)
    nodes = {n["id"]: n for n in r["nodes"]}
    assert nodes[A] == {"id": A, "role": "selected", "time": "2024-05-01T12:00:20.000Z", "hops": 0}
    assert nodes[B] == {"id": B, "role": "selected", "time": "2024-05-01T12:00:10.000Z", "hops": 0}
    assert nodes[X]["role"] == "both"
    edges = {(e["source"], e["target"]): e for e in r["edges"]}
    assert (edges[(A, B)]["role"], edges[(A, B)]["count"]) == ("selected", 2)
    assert not r["truncated"]


def test_threat_line_truncated_on_one_side_only():
    A, B = "10.0.0.1", "10.0.0.2"
    flows = [flow("10.0.0.11", A, 1, T), flow("10.0.0.12", A, 1, T), flow(A, B, 2, T + 10),
             flow(B, "10.0.0.21", 3, T + 20)]
    be = CaseBackend(Config(backend="case"), flows=flows)
    r = be.threat_line(A, B, utc(T + 10), utc(T + 10), timedelta(days=1), 6, [], 2)
    assert r["truncated"] is True            # up hit the cap; down did not


def test_threat_line_cap_from_the_config(tmp_path):
    flows = [flow("10.0.0.11", "10.0.0.1", 1, T), flow("10.0.0.12", "10.0.0.1", 1, T),
             flow("10.0.0.1", "10.0.0.2", 2, T + 10)]
    c = case_client(tmp_path, flows, threat_max_hosts=2)
    r = c.get("/api/threatline?a=10.0.0.1&b=10.0.0.2&from=2024-05-01T12:00:10Z").get_json()
    assert r["truncated"] is True and len([n for n in r["nodes"] if n["role"] == "up"]) == 1


# ---- compromised hosts and attack paths ---------------------------------------------------

def test_compromised_hosts_crud(chain_client):
    c = chain_client
    assert c.get("/api/compromised").get_json() == {"hosts": []}
    assert c.post("/api/compromised", json={"ip": H}).status_code == 403      # CSRF header
    r = c.post("/api/compromised", json={"ip": H, "time": "2024-05-01T12:10:00Z", "note": "EDR"},
               headers=WRITE).get_json()
    assert r["hosts"] == [{"ip": H, "time": "2024-05-01T12:10:00.000Z", "note": "EDR"}]
    r = c.post("/api/compromised", json={"ip": H, "time": ""}, headers=WRITE).get_json()
    assert r["hosts"] == [{"ip": H, "time": None, "note": ""}]               # re-mark replaces
    assert c.post("/api/compromised", json={"ip": "nope"}, headers=WRITE).status_code == 400
    assert c.post("/api/compromised", json={"ip": H, "time": "soon"}, headers=WRITE).status_code == 400
    r = c.delete("/api/compromised", json={"ip": H}, headers=WRITE).get_json()
    assert r["hosts"] == []


def test_attack_paths_update_with_marked_hosts(chain_client):
    c = chain_client
    assert c.get("/api/paths").get_json() == {"pairs": []}
    c.post("/api/compromised", json={"ip": "203.0.113.66"}, headers=WRITE)
    c.post("/api/compromised", json={"ip": "10.0.0.20", "time": "2024-05-01T13:00:00Z"}, headers=WRITE)
    [pair] = c.get("/api/paths").get_json()["pairs"]
    assert (pair["from"], pair["to"], pair["truncated"]) == ("203.0.113.66", "10.0.0.20", False)
    [p] = pair["paths"]
    assert [(h["source"], h["target"], h["dport"]) for h in p["hops"]] == [
        ("203.0.113.66", "10.0.0.5", 443), ("10.0.0.5", H, 445), (H, "10.0.0.20", 3389)]
    assert p["hops"][2]["start"] == "2024-05-01T12:20:00.000Z"     # earliest arrival
    # Marked compromised before the chain reached it: no path any more.
    c.post("/api/compromised", json={"ip": "10.0.0.20", "time": "2024-05-01T12:15:00Z"}, headers=WRITE)
    assert c.get("/api/paths").get_json() == {"pairs": []}


def test_attack_paths_preview_ten_per_pair(tmp_path):
    flows = [flow("10.4.0.2", f"10.4.1.{i}", 445, T + i) for i in range(12)] + \
            [flow(f"10.4.1.{i}", "10.5.0.3", 3389, T + 100 + i) for i in range(12)]
    c = case_client(tmp_path, flows)
    c.post("/api/compromised", json={"ip": "10.4.0.2"}, headers=WRITE)
    c.post("/api/compromised", json={"ip": "10.5.0.3"}, headers=WRITE)
    [pair] = c.get("/api/paths").get_json()["pairs"]
    assert len(pair["paths"]) == 10 and pair["truncated"] is True
    r = c.get("/api/paths?src=10.4.0.2&dst=10.5.0.3").get_json()
    assert len(r["paths"]) == 12 and r["truncated"] is False


def test_time_range_limits_threat_lines_and_attack_paths(chain_client):
    c = chain_client
    line = f"/api/threatline?a=10.0.0.5&b={H}&from=2024-05-01T12:10:00Z"
    r = c.get(line + "&range_from=2024-05-01T12:05:00Z").get_json()
    roles = {n["id"]: n["role"] for n in r["nodes"]}
    assert "203.0.113.66" not in roles and roles["10.0.0.20"] == "down"     # 12:00 hop cut off
    r = c.get(line + "&range_to=2024-05-01T12:20:30Z").get_json()
    counts = {(e["source"], e["target"]): e["count"] for e in r["edges"]}
    assert counts[(H, "10.0.0.20")] == 1                                     # 12:21:40 flow cut off
    assert c.get(line + "&range_from=2024-05-01T12:15:00Z").status_code == 400  # hop itself outside

    c.post("/api/compromised", json={"ip": "203.0.113.66"}, headers=WRITE)
    c.post("/api/compromised", json={"ip": "10.0.0.20", "time": "2024-05-01T13:00:00Z"}, headers=WRITE)
    assert len(c.get("/api/paths").get_json()["pairs"]) == 1
    assert c.get("/api/paths?range_from=2024-05-01T12:05:00Z").get_json() == {"pairs": []}
    assert len(c.get("/api/paths?range_to=2024-05-01T12:20:00Z").get_json()["pairs"]) == 1


def test_hop_limits_accepted_by_the_api(chain_client):
    for hops, status in ((1, 200), (20, 200), (0, 400), (21, 400)):
        r = chain_client.get(f"/api/paths?hops={hops}")
        assert r.status_code == status, hops
    assert chain_client.get("/api/paths?hops=21").get_json()["error"] == "hops must be between 1 and 20"


# ---- paths between two hosts --------------------------------------------------------------

# 10.4.0.2 is compromised; 10.5.0.3, on another subnet, matches a different IOC. Ways across:
# through the jump host 10.9.0.1, through the file server 10.4.0.9, or through both.
A, B, JUMP, FS = "10.4.0.2", "10.5.0.3", "10.9.0.1", "10.4.0.9"


LATERAL = [flow(A, JUMP, 445, T + 100), flow(JUMP, B, 3389, T + 200), flow(A, FS, 445, T + 50),
           flow(FS, JUMP, 22, T + 80), flow(FS, B, 445, T + 5000),
           flow(B, A, 445, T + 10),                     # B connecting to A: no hop A -> B
           flow(JUMP, B, 3389, T - 100)]                # before A was reached


@pytest.fixture
def lateral(tmp_path):
    return lambda **cfg_args: case_client(tmp_path, LATERAL, **cfg_args)


def route(path):
    return [path["hops"][0]["source"]] + [h["target"] for h in path["hops"]]


def test_every_path_between_two_hosts(lateral):
    c = lateral()
    r = c.get(f"/api/paths?src={A}&dst={B}").get_json()
    assert (r["src"], r["dst"], r["truncated"]) == (A, B, False)
    assert [route(p) for p in r["paths"]] == [[A, JUMP, B], [A, FS, B], [A, FS, JUMP, B]]
    assert [(h["start"], h["dport"]) for h in r["paths"][2]["hops"]] == [
        ("2024-05-01T12:00:50.000Z", 445), ("2024-05-01T12:01:20.000Z", 22),
        ("2024-05-01T12:03:20.000Z", 3389)]
    # B's IOC time: the path must reach it by then. A's: the first hop leaves after it.
    r = c.get(f"/api/paths?src={A}&dst={B}&dst_time=2024-05-01T12:16:40Z").get_json()
    assert [route(p) for p in r["paths"]] == [[A, JUMP, B], [A, FS, JUMP, B]]
    r = c.get(f"/api/paths?src={A}&dst={B}&src_time=2024-05-01T12:01:00Z").get_json()
    assert [route(p) for p in r["paths"]] == [[A, JUMP, B]]
    # The other way round there is only B's own connection to A: hops follow who connected.
    assert [route(p) for p in c.get(f"/api/paths?src={B}&dst={A}").get_json()["paths"]] == [[B, A]]
    # Excluded hosts, the hop limit and the time range all apply.
    c.post("/api/excludes", json={"entry": JUMP}, headers=WRITE)
    assert [route(p) for p in c.get(f"/api/paths?src={A}&dst={B}").get_json()["paths"]] == [[A, FS, B]]
    c.delete("/api/excludes", json={"entry": JUMP}, headers=WRITE)
    assert len(c.get(f"/api/paths?src={A}&dst={B}&hops=2").get_json()["paths"]) == 2
    r = c.get(f"/api/paths?src={A}&dst={B}&range_to=2024-05-01T12:05:00Z").get_json()
    assert [route(p) for p in r["paths"]] == [[A, JUMP, B], [A, FS, JUMP, B]]


def test_path_list_is_capped_shortest_first(lateral):
    r = lateral(max_paths=1).get(f"/api/paths?src={A}&dst={B}").get_json()
    assert [route(p) for p in r["paths"]] == [[A, JUMP, B]] and r["truncated"] is True


@pytest.mark.parametrize("query", [f"src={A}&dst={A}", f"src={A}&dst=nope", f"src={A}",
                                   f"src={A}&dst={B}&src_time=soon"])
def test_paths_between_validation(lateral, query):
    assert lateral().get(f"/api/paths?{query}").status_code == 400


# ---- times the UI rounds to the millisecond -----------------------------------------------

def test_submillisecond_times_survive_the_round_trip(tmp_path):
    # The UI only ever sees times rounded down to the millisecond.
    t = T + 0.000731
    flows = [flow("10.0.0.5", H, 445, t), flow(H, "10.0.0.20", 3389, t + 0.25)]
    c = case_client(tmp_path, flows)
    r = c.get(f"/api/threatline?a=10.0.0.5&b={H}&from=2024-05-01T12:00:00.000Z"
              "&to=2024-05-01T12:00:00.000Z")
    assert r.status_code == 200 and {n["id"] for n in r.get_json()["nodes"]} == {"10.0.0.5", H, "10.0.0.20"}
    c.post("/api/compromised", json={"ip": "10.0.0.5", "time": "2024-05-01T12:00:00.000Z"}, headers=WRITE)
    c.post("/api/compromised", json={"ip": "10.0.0.20", "time": "2024-05-01T12:00:00.250Z"}, headers=WRITE)
    assert len(c.get("/api/paths").get_json()["pairs"]) == 1


def test_the_time_range_allows_the_ui_rounding_at_its_start(client):
    # Flows start at whole seconds plus nothing; a range starting at that millisecond keeps them,
    # and one a millisecond later doesn't (UI times are rounded down to the millisecond).
    base = f"/api/neighbors?ip={H}&direction=in&ts=2024-05-01T13:00:00Z&window=24h"
    peers = lambda q: {p["peer"] for p in client.get(base + q).get_json()["peers"]}  # noqa: E731
    assert "10.0.0.2" in peers("&range_from=2024-05-01T12:00:40.000Z")
    assert "10.0.0.2" not in peers("&range_from=2024-05-01T12:00:40.002Z")


def test_search_bounds_allow_the_ui_rounding(tmp_path):
    # The second hop starts 0.4 ms into a millisecond; a range starting at that millisecond
    # (as the UI writes it) must keep it.
    flows = [flow("10.0.0.1", "10.0.0.2", 445, T), flow("10.0.0.2", "10.0.0.3", 445, T + 60.0004)]
    c = case_client(tmp_path, flows)
    r = c.get("/api/paths?src=10.0.0.2&dst=10.0.0.3&range_from=2024-05-01T12:01:00.000Z").get_json()
    assert len(r["paths"]) == 1
    r = c.get("/api/threatline?a=10.0.0.1&b=10.0.0.2&from=2024-05-01T12:00:00Z"
              "&range_from=2024-05-01T12:00:00.000Z&range_to=2024-05-01T12:01:00.000Z").get_json()
    assert "10.0.0.3" in {n["id"] for n in r["nodes"]}


# ---- the case database (--db, TB_CASE_DB) -------------------------------------------------

def test_case_db_is_reused_until_the_evidence_changes(tmp_path, monkeypatch):
    d = tmp_path / "case"
    d.mkdir()
    write_pcap(d / "cap.pcap", [(T, tcp("10.0.0.5", H, 50000, 445, SYN)),
                                (T + 0.001, tcp(H, "10.0.0.5", 445, 50000, SYN | ACK))])
    cfg = Config(backend="case", case_paths=[str(d)], case_db=str(tmp_path / "case.db"))
    assert CaseBackend(cfg).summary()["flows"] == 1

    real_read = sources.read
    monkeypatch.setattr(sources, "read", lambda *a, **k: pytest.fail("evidence re-read"))
    again = CaseBackend(cfg)                                   # unchanged: reuse the file
    assert again.summary()["flows"] == 1 and again.graph.has_edge("10.0.0.5", H)

    monkeypatch.setattr(sources, "read", real_read)
    write_pcap(d / "more.pcap", [(T + 5, udp(H, "10.0.0.53", 40000, 53, b"q"))])
    assert CaseBackend(cfg).summary()["flows"] == 2           # new file: rebuilt


def test_two_loaders_sharing_a_db_read_the_evidence_once(tmp_path, monkeypatch):
    # gunicorn starts several workers; with TB_CASE_DB they share one file.
    d = tmp_path / "case"
    d.mkdir()
    write_pcap(d / "cap.pcap", [(T, tcp("10.0.0.5", H, 50000, 445, SYN)),
                                (T + 0.001, tcp(H, "10.0.0.5", 445, 50000, SYN | ACK))])
    real_read, reads = sources.read, []

    def slow_read(*a, **k):
        reads.append(1)
        time.sleep(0.5)
        return real_read(*a, **k)
    monkeypatch.setattr(sources, "read", slow_read)
    cfg = Config(backend="case", case_paths=[str(d)], case_db=str(tmp_path / "case.db"))
    results, errors = [], []

    def load():
        try:
            results.append(CaseBackend(cfg).summary()["flows"])
        except Exception as e:  # noqa: BLE001 - reported below
            errors.append(e)
    threads = [threading.Thread(target=load) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == [] and results == [1, 1] and len(reads) == 1


def test_db_in_a_missing_directory_is_a_clear_error(tmp_path):
    cfg = Config(backend="case", case_db=str(tmp_path / "nowhere" / "case.db"))
    with pytest.raises(SourceError, match="nowhere"):
        CaseBackend(cfg, flows=FLOWS)


def test_database_errors_name_the_problem(tmp_path):
    with pytest.raises(SourceError, match="can't write the case database"):
        CaseBackend(Config(backend="case", case_db=str(tmp_path)), flows=FLOWS)     # a directory


def test_the_temporary_store_is_never_in_the_working_directory():
    be = CaseBackend(Config(backend="case"), flows=FLOWS)
    path = os.path.abspath(be.store.path)
    assert path.startswith(os.path.abspath(tempfile.gettempdir()) + os.sep)
    assert os.path.dirname(path) != os.getcwd()
