"""The shared JSON files (exclude list, compromised hosts): locking, atomic writes, hand edits."""
import json
import tempfile
import threading

import pytest

from threatbridge.compromised import CompromisedStore
from threatbridge.excludes import ExcludeStore
from threatbridge.jsonstore import JsonStore, StoreError
from threatbridge.query import ValidationError


def test_json_store_shapes_and_atomic_writes(tmp_path, monkeypatch):
    path = tmp_path / "x.json"
    path.write_text("{}")
    with JsonStore(str(path), "entries").locked() as items:
        assert items == []                                                 # no key yet: empty
    for wrong in ('{"entries": {"not": "a list"}}', '["10.0.0.1"]'):
        path.write_text(wrong)
        with pytest.raises(StoreError, match=r'x.json should hold \{"entries": \[\.\.\.\]\}'):
            with JsonStore(str(path), "entries").locked():
                pass
    dirs = []
    real = tempfile.mkstemp
    monkeypatch.setattr(tempfile, "mkstemp", lambda **kw: dirs.append(kw.get("dir")) or real(**kw))
    path.write_text("{}")
    ExcludeStore(str(path)).add("10.0.0.1")
    assert dirs == [str(tmp_path)]                     # beside the file, so os.replace is atomic
    assert json.loads(path.read_text()) == {"entries": ["10.0.0.1"]}


def test_concurrent_writers_lose_nothing(tmp_path):
    path = str(tmp_path / "ex.json")
    threads = [threading.Thread(target=ExcludeStore(path).add, args=(f"10.0.0.{i}",))
               for i in range(1, 21)]   # separate stores, like separate gunicorn workers
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(ExcludeStore(path).list()) == sorted(f"10.0.0.{i}" for i in range(1, 21))


def test_adding_an_entry_twice_keeps_one(tmp_path):
    store = ExcludeStore(str(tmp_path / "ex.json"))
    store.add("10.0.0.7/24")
    assert store.add("10.0.0.0/24") == ["10.0.0.0/24"]
    assert json.loads((tmp_path / "ex.json").read_text()) == {"entries": ["10.0.0.0/24"]}


def test_compromised_notes_and_hand_edits(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"hosts": [{"ip": "nope", "time": None, "note": ""}]}))
    store = CompromisedStore(str(path))
    assert store.mark("10.0.0.5", None, "x" * 500)["hosts"][0]["note"] == "x" * 500
    with pytest.raises(ValidationError, match="note longer than 500 characters"):
        store.mark("10.0.0.5", None, "x" * 501)
    with pytest.raises(ValidationError, match="invalid time: True"):
        store.mark("10.0.0.5", True)
    with pytest.raises(ValidationError, match="note must be text"):
        store.mark("10.0.0.5", None, 5)
    store.unmark("10.0.0.5")
    # The invalid hand-edited entry is ignored, but kept for someone to fix.
    assert json.loads(path.read_text())["hosts"] == [{"ip": "nope", "time": None, "note": ""}]


def test_hand_edited_note_that_is_not_text(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"hosts": [{"ip": "10.0.0.5", "time": None, "note": 7},
                                          {"ip": "10.0.0.6", "time": None}]}))
    assert CompromisedStore(str(path)).list()["marked"] == [{"ip": "10.0.0.6", "time": None, "note": ""}]
