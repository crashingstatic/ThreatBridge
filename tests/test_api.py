"""The HTTP API on the demo backend: validation, security, pivots and the shared lists.
Endpoints that need the case backend are tested in test_case.py."""
import json

import pytest

from threatbridge import app as app_mod
from threatbridge import query as q
from threatbridge.app import create_app
from threatbridge.backends import DemoBackend
from threatbridge.config import Config
from threatbridge.excludes import ExcludeStore


WRITE = {"X-ThreatBridge": "1"}


@pytest.fixture
def client(tmp_path):
    cfg = Config(backend="demo", soc_url="https://so",
                 compromised_file=str(tmp_path / "compromised.json"))
    app = create_app(cfg, DemoBackend(cfg), ExcludeStore(str(tmp_path / "ex.json")))
    return app.test_client()


def shared_client(tmp_path, exclude_text=None, compromised_text=None):
    ex, comp = tmp_path / "ex.json", tmp_path / "c.json"
    if exclude_text is not None:
        ex.write_text(exclude_text)
    if compromised_text is not None:
        comp.write_text(compromised_text)
    cfg = Config(backend="demo", exclude_file=str(ex), compromised_file=str(comp), live_dns=False)
    return create_app(cfg, DemoBackend(cfg)).test_client()


# ---- requests and validation --------------------------------------------------------------

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


@pytest.mark.parametrize("window", ["99999999999d", "999999999999w", "0x10h"])
def test_absurd_windows_are_rejected(client, window):
    assert client.get(f"/api/neighbors?ip=10.0.0.5&window={window}").status_code == 400


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


def test_flows_to_before_from_is_rejected(client):
    r = client.get("/api/flows?src=10.0.0.1&dst=10.0.0.5&from=2024-05-01T12:00:00Z&to=2024-05-01T11:00:00Z")
    assert r.status_code == 400


# ---- security -----------------------------------------------------------------------------

def test_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]


def test_writes_need_the_header_whatever_the_method(client):
    for method in ("post", "put", "patch", "delete"):
        assert getattr(client, method)("/api/excludes", json={"entry": "10.0.0.1"}).status_code == 403


# ---- maps, flows and pivots ---------------------------------------------------------------

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
    p = client.get(base + "&range_to=2024-05-01T11:00:00Z").get_json()     # host pivot, closed
    assert '@timestamp:["2024-05-01T10:00:00.000Z" TO "2024-05-01T11:00:00.000Z"] |' in p["query"]
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


def test_demo_flows_past_the_end(client):
    r = client.get("/api/flows?src=10.0.0.7&dst=10.0.0.5&from=2024-05-01T11:00:00Z"
                   "&to=2024-05-01T12:00:00Z&offset=100000").get_json()
    assert r["flows"] == [] and r["total"] == 2


# ---- shared lists -------------------------------------------------------------------------

def test_excludes_shared_and_applied(client):
    peers = client.get("/api/neighbors?ip=10.0.0.5&ts=2024-05-01T12:00:00Z").get_json()["peers"]
    victim = peers[0]["peer"]
    # Writes without the custom header are rejected (CSRF guard).
    assert client.post("/api/excludes", json={"entry": victim}).status_code == 403
    assert client.post("/api/excludes", json={"entry": "not valid!"}, headers=WRITE).status_code == 400
    assert client.post("/api/excludes", json={"entry": victim}, headers=WRITE).get_json()["entries"] == [victim]
    after = client.get("/api/neighbors?ip=10.0.0.5&ts=2024-05-01T12:00:00Z").get_json()["peers"]
    assert victim not in {p["peer"] for p in after}
    assert client.delete("/api/excludes", json={"entry": victim}, headers=WRITE).get_json()["entries"] == []


def test_a_numeric_compromise_time_is_an_epoch(client):
    r = client.post("/api/compromised", json={"ip": "10.0.0.5", "time": 1714564800}, headers=WRITE)
    assert r.status_code == 200 and r.get_json()["hosts"][0]["time"] == "2024-05-01T12:00:00.000Z"


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


def test_resolver_settings_come_from_the_config(tmp_path, monkeypatch):
    made = {}

    class Recording(app_mod.DomainResolver):
        def __init__(self, passive, **kw):
            made.update(kw)
            super().__init__(passive, **kw)
    monkeypatch.setattr(app_mod, "DomainResolver", Recording)
    cfg = Config(backend="demo", live_dns=False, dns_ttl=17, dns_timeout=0.25,
                 exclude_file=str(tmp_path / "ex.json"), compromised_file=str(tmp_path / "c.json"))
    create_app(cfg, DemoBackend(cfg))
    assert made == {"live": False, "ttl": 17, "timeout": 0.25, "answers": None}   # demo: no DNS records
