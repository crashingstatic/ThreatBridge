"""Post-mortem ("case") backend: graph queries and the HTTP API on top of it."""
from datetime import datetime, timezone

import pytest

from evidence import ACK, SYN, tcp, udp, write_pcap
from threatbridge.app import create_app
from threatbridge.backends import CaseBackend
from threatbridge.config import Config
from threatbridge.excludes import ExcludeStore
from threatbridge.graph import build_graph, host_flows
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
    return CaseBackend(Config(backend="case"), graph=build_graph(FLOWS))


def utc(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc)


def test_graph_keeps_every_flow():
    g = build_graph(FLOWS)
    assert g.number_of_edges() == len(FLOWS)
    assert g.number_of_edges("10.0.0.1", H) == 3
    assert [f.start for f in host_flows(g, H, "in", T + 15, T + 45)] == [T + 20, T + 30, T + 40]
    assert list(host_flows(g, "10.9.9.9", "in")) == []


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
                                 "end": "2024-05-01T13:23:21.000Z"}


@pytest.fixture
def client(tmp_path, backend):
    cfg = Config(backend="case")
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
    cfg = Config(backend="case", case_paths=[str(d)], exclude_file=str(tmp_path / "ex.json"))
    client = create_app(cfg).test_client()
    res = client.get(f"/api/neighbors?ip={H}&direction=in&ts=2024-05-01T13:00:00Z&window=24h").get_json()
    assert [(p["peer"], p["count"], p["ports"]) for p in res["peers"]] == [("10.0.0.5", 1, [445])]
    res = client.get(f"/api/neighbors?ip={H}&direction=out&ts=2024-05-01T11:00:00Z&window=24h").get_json()
    assert [(p["peer"], p["ports"]) for p in res["peers"]] == [("10.0.0.53", [53])]


def test_case_window_math_matches_flow_starts(backend):
    # A flow starting exactly at the window edge is included (same as the Elasticsearch range).
    res = backend.neighbors(H, "in", utc(T + 10), utc(T + 10), 10, "top", [])
    assert [p["peer"] for p in res["peers"]] == ["10.0.0.1"]
