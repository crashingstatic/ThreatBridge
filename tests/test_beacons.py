"""Beacons and long connections (ATK-12): the score, what a case lists, and the filter words
beacon and long in the case store, in Python and for Elasticsearch."""
import random

import pytest

from threatbridge import filters
from threatbridge.app import create_app
from threatbridge.backends import CaseBackend, DemoBackend
from threatbridge.beacons import FLOOR, groups, score
from threatbridge.config import Config
from threatbridge.model import Flow
from threatbridge.sources.netflow import pair_records

T = 1_714_564_800.0
WRITE = {"X-ThreatBridge": "1"}
INFECTED, C2, OTHER = "10.0.0.5", "198.51.100.9", "10.0.0.6"


def jittered(n, period, jitter, rng, t=T):
    starts = []
    for _ in range(n):
        starts.append(t)
        t += period * (1 + rng.uniform(-jitter, jitter))
    return starts


def flow(src, dst, dport, start, end=None, nbytes=500, sport=50000):
    return Flow(src, dst, sport, dport, "tcp", start, start + 0.5 if end is None else end, 4, nbytes, "x.pcap", "ssl")


def test_a_jittered_beacon_scores_high_and_random_traffic_low():
    rng = random.Random(7)
    for jitter in (0.0, 0.1, 0.3):
        found = score(jittered(40, 60, jitter, rng), [500] * 40)
        assert found["score"] >= 0.9, (jitter, found)
        assert found["interval"] == pytest.approx(60, rel=0.1)
    assert score(jittered(40, 60, 0.5, rng), [500] * 40)["score"] >= 0.8      # still over the default
    starts, t = [], T
    for _ in range(40):
        starts.append(t)
        t += rng.expovariate(1 / 60)
    noisy = score(starts, [int(rng.lognormvariate(7, 1.5)) for _ in starts])
    assert noisy["score"] < 0.6 and noisy["jitter"] > 0.5
    assert score(starts, [500] * 40)["score"] < 0.8          # regular sizes alone aren't enough
    exact = score([T + 300 * i for i in range(10)], [1200] * 10)
    assert exact == {"interval": 300.0, "jitter": 0.0, "size_jitter": 0.0, "score": 1.0}
    assert score([T + i for i in range(FLOOR - 1)], [1] * (FLOOR - 1)) is None


def test_groups_are_scored_one_by_one():
    rows = [("a", "b", 443, "tcp", T + 60 * i, 500) for i in range(6)] + \
           [("a", "b", 53, "udp", T + i, 80) for i in range(3)] + \
           [("a", "c", 443, "tcp", T + 60 * i, 500) for i in range(5)]
    found = list(groups(sorted(rows)))
    assert [(src, dst, dport, n) for src, dst, dport, _, n, *_ in found] == [("a", "b", 443, 6), ("a", "c", 443, 5)]
    assert found[0][5:7] == (T, T + 300)


def case(tmp_path, **cfg_args):
    rng = random.Random(3)
    flows = [flow(INFECTED, C2, 443, t) for t in jittered(30, 60, 0.1, rng, T + 100)]
    flows += [flow(OTHER, "10.0.0.9", 445, T + rng.uniform(0, 3600), nbytes=rng.randint(100, 90000),
                   sport=40000 + i) for i in range(30)]
    flows += [flow(OTHER, "198.51.100.10", 22, T + 50, T + 50 + 7250), flow(OTHER, "198.51.100.10", 22, T + 9000,
                                                                              T + 9000 + 4000)]
    flows += [flow(INFECTED, "10.0.0.9", 445, T + 10, T + 10 + 3599)]                   # just short
    cfg = Config(backend="case", live_dns=False, exclude_file=str(tmp_path / "ex.json"),
                 compromised_file=str(tmp_path / "c.json"), **cfg_args)
    return create_app(cfg, CaseBackend(cfg, flows=sorted(flows, key=lambda f: f.start))).test_client()


def test_a_case_lists_its_beacons_and_long_connections(tmp_path):
    c = case(tmp_path)
    cfg = c.get("/api/config").get_json()
    assert (cfg["flagged"], cfg["beacon_score"], cfg["beacon_min"], cfg["long_connection"]) == (True, 0.8, 10, 3600.0)
    r = c.get("/api/flagged").get_json()
    assert [(b["src"], b["dst"], b["dport"], b["flows"]) for b in r["beacons"]] == [(INFECTED, C2, 443, 30)]
    b = r["beacons"][0]
    assert b["score"] >= 0.9 and b["interval"] == pytest.approx(60, rel=0.1) and b["first_seen"] == "2024-05-01T12:01:40.000Z"
    assert r["long"] == [{"src": OTHER, "dst": "198.51.100.10", "flows": 2, "longest": 7250.0,
                          "first_seen": "2024-05-01T12:00:50.000Z", "last_seen": "2024-05-01T14:30:00.000Z"}]
    assert r["truncated"] is False
    # The time range: a beacon active in it, long flows that started in it.
    r = c.get("/api/flagged?range_from=2024-05-01T14:00:00Z").get_json()
    assert r["beacons"] == [] and [p["flows"] for p in r["long"]] == [1]
    # The limit, and the exclude list.
    assert c.get("/api/flagged?limit=1").get_json()["truncated"] is False
    c.post("/api/excludes", json={"entry": C2}, headers=WRITE)
    assert c.get("/api/flagged").get_json()["beacons"] == []


def test_the_settings_decide_what_is_listed(tmp_path):
    c = case(tmp_path, beacon_min=31, long_connection="2h")
    r = c.get("/api/flagged").get_json()
    assert r["beacons"] == [] and r["long"][0]["flows"] == 1 and r["long_connection"] == 7200.0
    c = case(tmp_path, beacon_score=0.0, beacon_min=5)              # everything regular enough
    assert len(c.get("/api/flagged").get_json()["beacons"]) > 1


def test_beacon_and_long_as_filters(tmp_path):
    c = case(tmp_path)
    peers = lambda q: sorted(p["peer"] for p in c.get(  # noqa: E731
        f"/api/neighbors?ip={q[0]}&direction=out&ts=2024-05-01T12:00:00Z&window=1d&{q[1]}").get_json()["peers"])
    assert peers((INFECTED, "")) == ["10.0.0.9", C2]
    assert peers((INFECTED, "filter=beacon")) == [C2]
    assert peers((OTHER, "filter=long")) == ["198.51.100.10"]
    assert peers((OTHER, "filter=NOT long")) == ["10.0.0.9"]            # both its flows there are long


def test_flag_words_in_the_language():
    f = filters.parse("beacon AND NOT long")
    assert f.text == "beacon AND NOT long"
    assert filters.parse("(long)").text == "(long)"
    with pytest.raises(filters.FilterError, match="fields are in lower case: write beacon"):
        filters.parse("Beacon")
    assert filters.vocabulary()["flags"].keys() == {"beacon", "long"}
    limits = {"long": 100.0, "beacon_score": 0.9, "beacon_min": 12}
    assert filters.to_sql(filters.parse("long").core, "f.", limits) == ("(f.end_ts - f.start_ts) >= ?", [100.0])
    sql, params = filters.to_sql(filters.parse("beacon").core, "f.", limits)
    assert sql.startswith("EXISTS (SELECT 1 FROM beacon AS b WHERE b.src = f.src") and params == [0.9, 12]
    flow_ = {"src": "a", "dst": "b", "duration": 150.0, "protocols": []}
    assert filters.matches(filters.parse("long").core, flow_, limits)
    assert not filters.matches(filters.parse("long").core, dict(flow_, duration=50.0), limits)
    assert not filters.matches(filters.parse("long").core, dict(flow_, duration=None), limits)
    assert not filters.matches(filters.parse("beacon").core, flow_, limits)
    assert filters.matches(filters.parse("beacon").core, dict(flow_, beacon=True), limits)


def test_security_onion_takes_long_but_not_beacon():
    cfg = Config(long_connection="90m")
    assert filters.to_es(filters.parse("long").core, cfg) == {"range": {"event.duration": {"gte": 5400.0}}}
    with pytest.raises(filters.FilterError, match="beacon needs a case's beacon scores"):
        filters.to_es(filters.parse("beacon").core, cfg)


def test_the_demo_has_no_flagged_list(tmp_path):
    cfg = Config(backend="demo", live_dns=False, compromised_file=str(tmp_path / "c.json"))
    demo = create_app(cfg, DemoBackend(cfg)).test_client()
    assert demo.get("/api/config").get_json()["flagged"] is False
    assert demo.get("/api/flagged").status_code == 501


def test_a_connection_netflow_split_is_one_long_connection():
    # An exporter's active timeout cuts a long connection into records; they rejoin into one
    # flow that lasts the whole time.
    halves = [(T + 1800 * i, T + 1800 * (i + 1), "tcp", INFECTED, 50000, C2, 22, 10, 1000, 0x18, False, "nf")
              for i in range(3)]
    [f] = pair_records(halves)
    assert f.end - f.start == 5400 and f.end - f.start >= 3600
