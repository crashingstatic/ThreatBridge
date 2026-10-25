"""Saved maps (INT-S2): the shared store and its API."""
import json
import os

import pytest

from threatbridge import sessions as sessions_mod
from threatbridge.app import create_app
from threatbridge.backends import DemoBackend
from threatbridge.config import Config
from threatbridge.jsonstore import StoreError
from threatbridge.query import ValidationError
from threatbridge.sessions import Conflict, NotFound, SessionStore

WRITE = {"X-ThreatBridge": "1"}
MAP = {"version": 1, "nodes": [{"id": "10.0.0.5", "x": 1, "y": 2}], "edges": []}


def test_save_list_open_and_delete(tmp_path):
    store = SessionStore(str(tmp_path / "sessions"))
    assert store.list() == []                                    # the directory comes with the first save
    saved = store.save("Incident 42 / ws-7", MAP)
    assert saved["name"] == "Incident 42 / ws-7" and saved["saved"].endswith("Z")
    store.save("  ünïcode ✓  ", {"version": 1})
    assert {s["name"] for s in store.list()} == {"Incident 42 / ws-7", "ünïcode ✓"}
    assert store.get("Incident 42 / ws-7") == {"name": "Incident 42 / ws-7", "saved": saved["saved"], "map": MAP}
    with pytest.raises(Conflict, match="a map called 'Incident 42 / ws-7' is already saved"):
        store.save("Incident 42 / ws-7", {"version": 1})
    store.save("Incident 42 / ws-7", {"version": 1, "nodes": []}, overwrite=True)
    assert store.get("Incident 42 / ws-7")["map"] == {"version": 1, "nodes": []}
    store.delete("Incident 42 / ws-7")
    with pytest.raises(NotFound):
        store.get("Incident 42 / ws-7")
    with pytest.raises(NotFound, match="no saved map called 'Incident 42 / ws-7'"):
        store.delete("Incident 42 / ws-7")
    assert [s["name"] for s in store.list()] == ["ünïcode ✓"]


def test_a_map_deleted_while_listing_is_left_out(tmp_path, monkeypatch):
    store = SessionStore(str(tmp_path))
    store.save("kept", {})
    store.save("gone", {})
    real = store._saved

    def saved(path):
        if path.endswith(store._file("gone")):
            raise FileNotFoundError(path)
        return real(path)
    monkeypatch.setattr(store, "_saved", saved)
    assert [s["name"] for s in store.list()] == ["kept"]


def test_the_latest_first(tmp_path):
    store = SessionStore(str(tmp_path))
    for i, name in enumerate(["old", "newer", "newest"]):
        store.save(name, {})
        os.utime(tmp_path / store._file(name), (1_700_000_000 + i, 1_700_000_000 + i))
    assert [s["name"] for s in store.list()] == ["newest", "newer", "old"]


def test_names_and_sizes(tmp_path, monkeypatch):
    store = SessionStore(str(tmp_path))
    for bad in ("", "   ", "x" * 101, "tab\there", "line\nbreak", None, 5):
        with pytest.raises(ValidationError, match="1 to 100 printable characters"):
            store.save(bad, {})
    store.save("x" * 100, {})
    with pytest.raises(ValidationError, match="must be a JSON object"):
        store.save("list", [1, 2])
    with pytest.raises(ValidationError, match="larger than 2 MB"):
        store.save("big", {"blob": "x" * (2 * 2**20)})
    monkeypatch.setattr(sessions_mod, "MAX_SESSIONS", 2)
    store.save("second", {})
    with pytest.raises(ValidationError, match="2 maps are saved already"):
        store.save("third", {})
    store.save("second", {"again": 1}, overwrite=True)           # replacing one is still fine


def test_other_files_in_the_directory_are_left_alone(tmp_path):
    store = SessionStore(str(tmp_path))
    store.save("mine", {})
    for name in ("notes.txt", "README.json", ".tb-partial", "%%%.json", "abcde.json"):
        (tmp_path / name).write_text("{}")
    assert [s["name"] for s in store.list()] == ["mine"]
    (tmp_path / store._file("broken")).write_text("{not json")
    with pytest.raises(StoreError, match="not valid JSON"):
        store.get("broken")
    (tmp_path / store._file("odd")).write_text(json.dumps({"map": [1]}))
    with pytest.raises(StoreError, match="not a saved map"):
        store.get("odd")


@pytest.fixture
def client(tmp_path):
    cfg = Config(backend="demo", live_dns=False, exclude_file=str(tmp_path / "ex.json"),
                 compromised_file=str(tmp_path / "c.json"), sessions_dir=str(tmp_path / "sessions"))
    return create_app(cfg, DemoBackend(cfg)).test_client()


def test_the_sessions_api(client):
    assert client.get("/api/sessions").get_json() == {"sessions": []}
    assert client.post("/api/sessions", json={"name": "a", "map": MAP}).status_code == 403      # CSRF header
    r = client.post("/api/sessions", json={"name": "a", "map": MAP}, headers=WRITE).get_json()
    assert r["name"] == "a" and [s["name"] for s in r["sessions"]] == ["a"]
    r = client.post("/api/sessions", json={"name": "a", "map": {"version": 1}}, headers=WRITE)
    assert r.status_code == 409 and r.get_json()["error"] == "a map called 'a' is already saved"
    r = client.post("/api/sessions", json={"name": "a", "map": {"version": 1}, "overwrite": True}, headers=WRITE)
    assert r.status_code == 200
    assert client.get("/api/sessions?name=a").get_json()["map"] == {"version": 1}
    r = client.get("/api/sessions?name=nope")
    assert r.status_code == 404 and r.get_json()["error"] == "no saved map called 'nope'"
    assert client.post("/api/sessions", json={"name": "b", "map": "x"}, headers=WRITE).status_code == 400
    assert client.post("/api/sessions", json={"name": "a", "map": {}, "overwrite": "yes"},
                       headers=WRITE).status_code == 409                 # only true replaces
    assert client.delete("/api/sessions", json={"name": "a"}, headers=WRITE).get_json() == {"sessions": []}
    assert client.delete("/api/sessions", json={"name": "a"}, headers=WRITE).status_code == 404
