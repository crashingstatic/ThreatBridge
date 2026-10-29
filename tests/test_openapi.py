"""The API's description for programs (D20-D22): the OpenAPI document generated from
threatbridge/apidoc.py, API.md's index, the version and limits in /api/config, and the
saved-map format. Every response any API test gets is checked against the document by
tests/conftest.py; the tour below makes sure every operation is among them."""
import json
import os
import re
import subprocess
import sys

import pytest
from openapi_spec_validator import validate

from conftest import CALLED, OPENAPI, ROOT, schema_error
from threatbridge import apidoc
from threatbridge import app as app_mod
from threatbridge import compromised, filters, sessions
from threatbridge.app import create_app
from threatbridge.backends import ES_MAX_RESULTS, BackendError, CaseBackend, DemoBackend
from threatbridge.config import Config
from threatbridge.model import Flow

T = 1_714_564_800.0           # 2024-05-01T12:00:00Z
WRITE = {"X-ThreatBridge": "1"}
E, A, X = "10.7.0.1", "10.7.0.2", "10.7.0.3"
FLOWS = [Flow(E, A, 50000, 443, "tcp", T, T + 1, 2, 120, "x.pcap", "ssl"),
         Flow(A, X, 50001, 445, "tcp", T + 60, T + 61, 4, 400, "x.pcap", "smb"),
         Flow(A, X, 50002, 53, "udp", T + 90, T + 90, 2, 200, "x.pcap", "dns")]


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def operations():
    return {(m.upper(), p) for p, ops in OPENAPI["paths"].items() for m in ops if m != "parameters"}


def test_the_committed_document_is_the_generated_one():
    assert read("threatbridge", "openapi.json") == apidoc.text(), "run: python -m threatbridge.apidoc"


def test_the_generator_stops_at_a_route_it_cannot_describe():
    routes = apidoc.routes()
    with pytest.raises(apidoc.Undescribed, match="GET /api/new"):
        apidoc.build({**routes, ("GET", "/api/new"): "api_new"})
    del routes[("GET", "/healthz")]
    with pytest.raises(apidoc.Undescribed, match="healthz"):
        apidoc.build(routes)


def test_the_service_runs_without_pydantic():
    script = ("import sys; sys.modules['pydantic'] = None\n"
              "from threatbridge.app import create_app\n"
              "from threatbridge.config import Config\n"
              "from threatbridge.backends import DemoBackend\n"
              "cfg = Config(backend='demo', live_dns=False, compromised_file='/nonexistent/c.json')\n"
              "r = create_app(cfg, DemoBackend(cfg)).test_client().get('/api/openapi.json')\n"
              "assert r.status_code == 200 and r.get_json()['openapi'].startswith('3.1')\n")
    r = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr


def examples(node, pointer=""):
    """(pointer to a schema, one of its examples) for every example in the document."""
    if isinstance(node, dict):
        for example in node.get("examples", []) if isinstance(node.get("examples"), list) else []:
            yield pointer, example
        for key, value in node.items():
            yield from examples(value, f"{pointer}/{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from examples(value, f"{pointer}/{i}")


def test_every_example_matches_its_schema():
    found = list(examples(OPENAPI["components"]["schemas"], "/components/schemas"))
    assert len(found) >= 5
    for pointer, example in found:
        assert schema_error(example, pointer) is None, pointer


def test_the_document_is_valid_openapi_3_1():
    validate(OPENAPI)
    assert OPENAPI["openapi"].startswith("3.1")


def test_the_document_and_the_routes_list_the_same_operations(tmp_path):
    cfg = Config(backend="demo", live_dns=False, exclude_file=str(tmp_path / "ex.json"),
                 compromised_file=str(tmp_path / "c.json"))
    app = create_app(cfg, DemoBackend(cfg))
    served = {(m, r.rule) for r in app.url_map.iter_rules() for m in r.methods - {"HEAD", "OPTIONS"}
              if not r.rule.startswith("/static/") and r.rule != "/"}
    assert served == operations()


def api_md_index():
    """{(METHOD, path)} from the rows of API.md's index: | `path` | METHOD, METHOD | what |."""
    rows = re.findall(r"^\| `(/\S*)` \| ([A-Z, ]+) \|", read("docs", "API.md"), re.M)
    return {(m.strip(), path) for path, methods in rows for m in methods.split(",")}


def test_api_md_indexes_the_operations_the_document_has():
    assert api_md_index() == operations()


def test_api_md_leaves_parameters_and_fields_to_the_document():
    assert not re.search(r"^\| (Field|Parameter) \|", read("docs", "API.md"), re.M)


def test_the_version_is_the_same_everywhere(tmp_path):
    cfg = Config(backend="demo", live_dns=False, compromised_file=str(tmp_path / "c.json"))
    client = create_app(cfg, DemoBackend(cfg)).test_client()
    version = app_mod.API_VERSION
    assert type(version) is int and version >= 1
    assert client.get("/healthz").get_json()["api_version"] == version
    assert client.get("/api/config").get_json()["api_version"] == version
    assert OPENAPI["info"]["version"] == str(version)
    assert f"API version **{version}**" in read("docs", "API.md")


def test_the_limits_are_those_applied(tmp_path):
    cfg = Config(backend="demo", live_dns=False, compromised_file=str(tmp_path / "c.json"),
                 threat_max_hosts=77, max_paths=88)
    limits = create_app(cfg, DemoBackend(cfg)).test_client().get("/api/config").get_json()["limits"]
    assert limits == {
        "hops": app_mod.MAX_HOPS, "threat_line_hosts": 77, "paths": 88, "paths_per_pair": app_mod.PATHS_PER_PAIR,
        "flow_page": app_mod.MAX_FLOW_PAGE, "connection_flows": None, "filter_length": filters.MAX_LENGTH,
        "filter_depth": filters.MAX_DEPTH, "edges": app_mod.MAX_EDGES, "within": app_mod.MAX_WITHIN,
        "export_flows": app_mod.MAX_EXPORT, "marks": compromised.MAX_MARKS, "note": compromised.MAX_NOTE,
        "saved_maps": sessions.MAX_SESSIONS, "map_bytes": sessions.MAX_BYTES, "map_name": sessions.MAX_NAME}
    elastic = Config(backend="elastic", live_dns=False, compromised_file=str(tmp_path / "c.json"))
    config = create_app(elastic).test_client().get("/api/config").get_json()
    assert config["limits"]["connection_flows"] == ES_MAX_RESULTS


class StandInSoc:
    def pcap(self, doc_id, when):
        return iter([b"\xd4\xc3\xb2\xa1", b"rest"])


class FailingBackend(DemoBackend):
    def neighbors(self, *args, **kwargs):
        raise BackendError("Elasticsearch request failed: ConnectTimeout")


def test_every_operation_answers_as_documented(tmp_path):
    """Each operation, and each kind of error, once; conftest.py checks every answer."""
    def files(name):
        cfg = dict(exclude_file=str(tmp_path / f"{name}-ex.json"), compromised_file=str(tmp_path / f"{name}-c.json"),
                   sessions_dir=str(tmp_path / f"{name}-maps"), live_dns=False)
        return cfg
    case_cfg = Config(backend="case", **files("case"))
    case = create_app(case_cfg, CaseBackend(case_cfg, flows=FLOWS)).test_client()
    demo_cfg = Config(backend="demo", soc_url="https://so", **files("demo"))
    demo = create_app(demo_cfg, DemoBackend(demo_cfg), soc=StandInSoc()).test_client()
    failing_cfg = Config(backend="demo", **files("failing"))
    failing = create_app(failing_cfg, FailingBackend(failing_cfg), soc=None).test_client()
    t0, t1 = "2024-05-01T12:00:00Z", "2024-05-01T12:01:30Z"
    edges = [{"source": E, "target": A, "from": t0, "to": t0}, {"source": A, "target": X, "from": "2024-05-01T12:01:00Z", "to": t1}]
    mark = {"src": A, "dst": X, "start": "2024-05-01T12:01:00.000Z", "sport": 50001, "dport": 445, "proto": "tcp"}
    query = {"ip": A, "direction": "out", "ts": t0, "window": "1h", "filters": ["NOT DNS"],
             "marks": {"hosts": [{"ip": X, "time": None, "note": ""}], "flows": []}}

    assert case.get("/healthz").status_code == 200
    assert case.get("/api/config").status_code == 200
    assert case.get("/api/openapi.json").get_json() == OPENAPI
    assert case.get(f"/api/protocols?range_from={t0}&filter=NOT DNS").status_code == 200
    assert case.post("/api/protocols", json={"range_to": t1, "filters": ["SMB"]}, headers=WRITE).status_code == 200
    assert case.get(f"/api/resolve?ip={A}&direction=out").status_code == 200
    assert case.get(f"/api/neighbors?ip={A}&direction=out&ts={t0}&window=1h&filter=SMB").status_code == 200
    assert case.post("/api/neighbors", json=query, headers=WRITE).status_code == 200
    assert case.get(f"/api/flows?src={A}&dst={X}&from={t0}&to={t1}&offset=0&limit=10").status_code == 200
    assert case.post("/api/flows", json={"src": A, "dst": X, "from": t0, "to": t1, "within": [[t0, t1]]},
                     headers=WRITE).status_code == 200
    assert case.get(f"/api/edge?src={A}&dst={X}&from={t0}&to={t1}").status_code == 200
    assert case.post("/api/edge", json={"src": A, "dst": X, "from": t0, "to": t1, "filters": ["SMB"]},
                     headers=WRITE).status_code == 200
    assert case.get("/api/filter?filter=SMB").status_code == 200
    assert case.get(f"/api/pivot?a={A}&b={X}&until={t1}").status_code == 200
    assert case.get(f"/api/threatline?a={A}&b={X}&from=2024-05-01T12:01:00Z&window=1h&hops=3").status_code == 200
    assert case.post("/api/threatline", json={"a": A, "b": X, "from": "2024-05-01T12:01:00Z"},
                     headers=WRITE).status_code == 200
    assert case.get(f"/api/paths?src={E}&dst={X}&window=1h").status_code == 200
    assert case.post("/api/paths", json={"window": "1h", "marks": {"hosts": [{"ip": E}, {"ip": X}], "flows": []}},
                     headers=WRITE).status_code == 200
    assert case.post("/api/compromised/flows", json=mark, headers=WRITE).status_code == 200
    assert case.post("/api/suspect", json={"edges": edges, "window": "1h"}, headers=WRITE).status_code == 200
    assert case.post("/api/export", json={"edges": edges, "window": "1h"}, headers=WRITE).status_code == 200
    assert case.get("/api/paths").status_code == 200
    assert case.delete("/api/compromised/flows", json=mark, headers=WRITE).status_code == 200
    assert case.post("/api/compromised", json={"ip": X, "time": t0, "note": "EDR"}, headers=WRITE).status_code == 200
    assert case.get("/api/compromised").status_code == 200
    assert case.put("/api/compromised", json={"hosts": [{"ip": A}], "flows": [mark]}, headers=WRITE).status_code == 200
    assert case.delete("/api/compromised", json={"ip": A}, headers=WRITE).status_code == 200
    assert case.post("/api/excludes", json={"entry": "10.9.9.0/24"}, headers=WRITE).status_code == 200
    assert case.get("/api/excludes").status_code == 200
    assert case.delete("/api/excludes", json={"entry": "10.9.9.0/24"}, headers=WRITE).status_code == 200
    saved = {"version": 2, "nodes": [], "edges": []}
    assert case.post("/api/sessions", json={"name": "tour", "map": saved}, headers=WRITE).status_code == 200
    assert case.get("/api/sessions").status_code == 200
    assert case.get("/api/sessions?name=tour").status_code == 200
    assert case.delete("/api/sessions", json={"name": "tour"}, headers=WRITE).status_code == 200
    r = demo.post("/api/pcap", json={"id": "P5mgnpEB0JpjNDZz1bIN", "time": t0}, headers=WRITE)
    assert r.status_code == 200 and r.data == b"\xd4\xc3\xb2\xa1rest"
    # Errors, each kind once.
    assert case.get("/api/neighbors?ip=nope").status_code == 400
    assert case.post("/api/excludes", json={"entry": "10.0.0.1"}).status_code == 403
    assert case.get("/api/sessions?name=none").status_code == 404
    case.post("/api/sessions", json={"name": "twice", "map": saved}, headers=WRITE)
    assert case.post("/api/sessions", json={"name": "twice", "map": saved}, headers=WRITE).status_code == 409
    (tmp_path / "case-c.json").write_text("{broken")
    assert case.get("/api/compromised").status_code == 500
    assert demo.get(f"/api/threatline?a={A}&b={X}&from={t0}").status_code == 501
    assert failing.post("/api/pcap", json={"id": "P5mgnpEB0JpjNDZz1bIN", "time": t0}, headers=WRITE).status_code == 501
    assert failing.get(f"/api/neighbors?ip={A}").status_code == 502
    # Every operation was answered, and so was each error status the document lists.
    answered = {(m, p) for m, p, s in CALLED if s < 300}
    assert operations() <= answered, operations() - answered
    statuses = {s for m, p, s in CALLED}
    assert {400, 403, 404, 409, 500, 501, 502} <= statuses


# ---- the saved-map format (D22) ------------------------------------------------------------

MAP = {
    "version": 2, "iocTime": "2024-05-01T12:00:00.000Z",
    "settings": {"ip": A, "ts": "", "direction": "in", "window": "24h", "range-from": "", "range-to": "",
                 "order": "top", "limit": "50", "route-src": "", "route-src-time": "", "route-dst": "",
                 "route-dst-time": ""},
    "nodes": [{"id": A, "position": {"x": 1.5, "y": -2}, "classes": ["up"], "anchor": "2024-05-01T12:00:00.000Z",
               "root": True, "depth": 0, "expandedIn": True},
              {"id": X, "position": {"x": 0, "y": 0}, "classes": [], "depth": 1}],
    "edges": [{"source": A, "target": X, "direction": "out", "count": 2, "ports": [445, 53], "protocols": ["smb", "dns"],
               "classes": ["attack"], "first_seen": "2024-05-01T12:01:00.000Z", "last_seen": "2024-05-01T12:01:30.000Z"}],
    "view": {"zoom": 1.2, "pan": {"x": 10, "y": 20}},
    "filters": ["NOT DNS"],
    "marks": {"hosts": [{"ip": X, "time": None, "note": ""}],
              "flows": [{"src": A, "dst": X, "start": "2024-05-01T12:01:00.000Z", "sport": 50001, "dport": 445,
                         "proto": "tcp", "note": ""}]},
    "queries": [{"op": "root", "ip": A, "ts": "", "direction": "in", "window": "24h", "limit": "50", "order": "top"},
                {"op": "expand", "ip": A, "direction": "out", "anchor": "2024-05-01T12:00:00.000Z", "window": "24h",
                 "limit": "50", "order": "top"},
                {"op": "threatline", "a": A, "b": X, "from": "2024-05-01T12:01:00.000Z",
                 "to": "2024-05-01T12:01:30.000Z", "window": "24h"},
                {"op": "routes", "src": A, "dst": X, "src_time": "", "dst_time": "", "window": "24h"},
                {"op": "remove", "ip": E}],
}
MAP_SCHEMA = "/components/schemas/MapDocument"


def test_the_map_format_describes_what_the_map_saves():
    assert schema_error(MAP, MAP_SCHEMA) is None
    version_1 = {"version": 1, "nodes": MAP["nodes"], "edges": MAP["edges"]}
    assert schema_error(version_1, MAP_SCHEMA) is None
    for wrong in (dict(MAP, version=3), dict(MAP, extra=1), dict(MAP, nodes=[{"position": {}}]),
                  dict(MAP, queries=[{"op": "teleport"}])):
        assert schema_error(wrong, MAP_SCHEMA) is not None


@pytest.mark.skipif(not os.environ.get("TB_SAVED_MAPS"), reason="set TB_SAVED_MAPS to the browser tests' maps")
def test_maps_the_browser_tests_saved_match_the_format():
    # CI points TB_SAVED_MAPS at the maps the browser tests saved (ui_helpers.keepMap): what the
    # map really writes.
    folder = os.environ["TB_SAVED_MAPS"]
    names = sorted(n for n in os.listdir(folder) if n.endswith(".json"))
    assert names
    for name in names:
        with open(os.path.join(folder, name), encoding="utf-8") as fh:
            assert schema_error(json.load(fh), MAP_SCHEMA) is None, name
