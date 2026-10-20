"""Post-mortem ("case") backend: graph queries and the HTTP API on top of it."""
from datetime import datetime, timezone

import pytest

from evidence import ACK, SYN, tcp, udp, write_pcap
from threatbridge.app import create_app
from threatbridge.backends import CaseBackend
from threatbridge.config import Config
from threatbridge.excludes import ExcludeStore
from threatbridge.graph import build_graph
from threatbridge.store import FlowStore
from threatbridge.model import Flow

T = 1_714_564_800.0
H = "10.0.0.9"   # host under investigation


def flow(src, dst, dport, start, proto="tcp", sport=50000):
    return Flow(src, dst, sport, dport, proto, start, start + 1, 2, 120, "x.pcap")


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


def utc(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc)


def test_graph_keeps_every_flow():
    g = build_graph((f.src, f.dst, f.start) for f in FLOWS)
    assert g.number_of_edges() == 7                            # host pairs
    assert list(g["10.0.0.1"][H]["times"]) == [T + 10, T + 20, T + 30]


def test_store_queries(tmp_path):
    store = FlowStore(str(tmp_path / "case.db"))
    store.write(FLOWS, {"x.example": {"10.0.0.1": [T, T + 1]}}, [("/e/cap.pcap", 10, 5)])
    assert store.stats() == (9, T + 10, T + 5001)
    assert store.ports(H, "in", ["10.0.0.1", "10.0.0.2", "10.0.0.3"], T + 15, T + 45) == {
        "10.0.0.1": {445: 1, 3389: 1}, "10.0.0.2": {22: 1}, "10.0.0.3": {}}
    assert store.ports(H, "out", ["10.0.0.20"], 0, T * 2) == {"10.0.0.20": {443: 1}}
    assert store.ports("10.9.9.9", "in", [], 0, T * 2) == {}
    assert store.edge("10.0.0.1", H, T, T + 25) == (2, T + 10, T + 20, {445: 2})
    assert store.flow_at("10.0.0.2", H, T + 40) == FLOWS[3]
    assert store.dns() == {"x.example": {"10.0.0.1": [T, T + 1]}}
    assert store.matches([("/e/cap.pcap", 10, 5)])
    assert not store.matches([("/e/cap.pcap", 10, 6)])                 # file changed
    assert not FlowStore(str(tmp_path / "other.db")).matches([])      # never built
    store.write(FLOWS[:1], {}, [])                                     # rebuild replaces
    assert store.stats()[0] == 1


def test_store_refuses_to_overwrite_other_databases(tmp_path):
    import sqlite3
    from threatbridge.store import NotAStore
    path = str(tmp_path / "app.db")
    sqlite3.connect(path).execute("CREATE TABLE users (name TEXT)").connection.commit()
    with pytest.raises(NotAStore):
        FlowStore(path).write(FLOWS, {}, [])
    assert sqlite3.connect(path).execute("SELECT name FROM sqlite_master").fetchall() == [("users",)]


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


def test_summary(backend):
    assert backend.summary() == {"flows": 9, "hosts": 7, "start": "2024-05-01T12:00:10.000Z",
                                 "end": "2024-05-01T13:23:21.000Z", "dns_names": 0}


@pytest.fixture
def client(tmp_path, backend):
    cfg = Config(backend="case", compromised_file=str(tmp_path / "compromised.json"))
    app = create_app(cfg, backend, ExcludeStore(str(tmp_path / "ex.json")))
    return app.test_client()


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


def test_case_window_math_matches_flow_starts(backend):
    # A flow starting exactly at the window edge is included (same as the Elasticsearch range).
    res = backend.neighbors(H, "in", utc(T + 10), utc(T + 10), 10, "top", [])
    assert [p["peer"] for p in res["peers"]] == ["10.0.0.1"]


# ---- compromised hosts, threat lines, attack paths ---------------------------------------

WRITE = {"X-ThreatBridge": "1"}
CHAIN = [flow("203.0.113.66", "10.0.0.5", 443, T), flow("10.0.0.5", H, 445, T + 600),
         flow(H, "10.0.0.20", 3389, T + 1200), flow(H, "10.0.0.20", 3389, T + 1300),
         flow("10.0.0.20", "10.0.0.30", 22, T - 600)]   # before the chain: not on it


@pytest.fixture
def chain_client(tmp_path):
    cfg = Config(backend="case", compromised_file=str(tmp_path / "compromised.json"))
    app = create_app(cfg, CaseBackend(cfg, flows=CHAIN),
                     ExcludeStore(str(tmp_path / "ex.json")))
    return app.test_client()


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


def test_attack_paths_update_with_marked_hosts(chain_client):
    c = chain_client
    assert c.get("/api/paths").get_json() == {"paths": []}
    c.post("/api/compromised", json={"ip": "203.0.113.66"}, headers=WRITE)
    c.post("/api/compromised", json={"ip": "10.0.0.20", "time": "2024-05-01T13:00:00Z"}, headers=WRITE)
    [p] = c.get("/api/paths").get_json()["paths"]
    assert (p["from"], p["to"]) == ("203.0.113.66", "10.0.0.20")
    assert [(h["source"], h["target"], h["dport"]) for h in p["hops"]] == [
        ("203.0.113.66", "10.0.0.5", 443), ("10.0.0.5", H, 445), (H, "10.0.0.20", 3389)]
    assert p["hops"][2]["start"] == "2024-05-01T12:20:00.000Z"     # earliest arrival
    # Marked compromised before the chain reached it: no path any more.
    c.post("/api/compromised", json={"ip": "10.0.0.20", "time": "2024-05-01T12:15:00Z"}, headers=WRITE)
    assert c.get("/api/paths").get_json() == {"paths": []}


def test_analysis_needs_case_backend(tmp_path):
    from threatbridge.backends import DemoBackend
    cfg = Config(backend="demo", compromised_file=str(tmp_path / "c.json"))
    c = create_app(cfg, DemoBackend(cfg), ExcludeStore(str(tmp_path / "ex.json"))).test_client()
    assert c.get("/api/config").get_json()["analysis"] is False
    assert c.get("/api/paths").status_code == 501
    assert c.get(f"/api/threatline?a=10.0.0.5&b={H}&from=2024-05-01T12:10:00Z").status_code == 501


def test_submillisecond_times_survive_the_round_trip(tmp_path):
    # The UI only ever sees times rounded down to the millisecond.
    t = T + 0.000731
    flows = [flow("10.0.0.5", H, 445, t), flow(H, "10.0.0.20", 3389, t + 0.25)]
    cfg = Config(backend="case", compromised_file=str(tmp_path / "c.json"))
    c = create_app(cfg, CaseBackend(cfg, flows=flows), ExcludeStore(str(tmp_path / "ex.json"))).test_client()
    r = c.get(f"/api/threatline?a=10.0.0.5&b={H}&from=2024-05-01T12:00:00.000Z"
              "&to=2024-05-01T12:00:00.000Z")
    assert r.status_code == 200 and {n["id"] for n in r.get_json()["nodes"]} == {"10.0.0.5", H, "10.0.0.20"}
    c.post("/api/compromised", json={"ip": "10.0.0.5", "time": "2024-05-01T12:00:00.000Z"}, headers=WRITE)
    c.post("/api/compromised", json={"ip": "10.0.0.20", "time": "2024-05-01T12:00:00.250Z"}, headers=WRITE)
    assert len(c.get("/api/paths").get_json()["paths"]) == 1


def test_case_db_is_reused_until_the_evidence_changes(tmp_path, monkeypatch):
    from threatbridge import sources
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
