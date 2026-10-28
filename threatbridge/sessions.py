"""Saved maps (analysis sessions), shared by every analyst: one JSON file each in a directory.

A map is a document the UI writes and reads back (hosts, positions, connections, highlights,
toolbar); the server keeps it as it is, within a size limit, under a name.
"""
import base64
import json
import os
from datetime import datetime, timezone

from .jsonstore import StoreError, write_atomically
from .query import ValidationError, fmt_time

MAX_NAME = 100
MAX_BYTES = 2 * 2**20
MAX_SESSIONS = 500


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


def parse_name(value):
    name = value.strip() if isinstance(value, str) else ""
    if not name or len(name) > MAX_NAME or not name.isprintable():
        raise ValidationError(f"a map's name is 1 to {MAX_NAME} printable characters")
    return name


class SessionStore:
    def __init__(self, directory):
        self.directory = directory

    def _file(self, name):
        return base64.urlsafe_b64encode(name.encode()).decode().rstrip("=") + ".json"

    def _name(self, filename):
        """The name a file in the directory was saved under, or None if it isn't a saved map."""
        if not filename.endswith(".json"):
            return None
        stem = filename[:-len(".json")]
        try:
            name = base64.urlsafe_b64decode(stem + "=" * (-len(stem) % 4)).decode()
        except (ValueError, UnicodeDecodeError):
            return None
        return name if self._file(name) == filename else None

    def _saved(self, path):
        return fmt_time(datetime.fromtimestamp(os.stat(path).st_mtime, timezone.utc))

    def list(self):
        """[{"name", "saved"}], the most recently saved first."""
        try:
            files = os.listdir(self.directory)
        except FileNotFoundError:
            return []
        out = []
        for f in files:
            name = self._name(f)
            if name is not None:
                try:
                    out.append({"name": name, "saved": self._saved(os.path.join(self.directory, f))})
                except FileNotFoundError:   # deleted meanwhile
                    pass
        return sorted(out, key=lambda s: (s["saved"], s["name"]), reverse=True)

    def get(self, name):
        name = parse_name(name)
        path = os.path.join(self.directory, self._file(name))
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
            saved = self._saved(path)
        except FileNotFoundError:
            raise NotFound(f"no saved map called {name!r}")
        except ValueError as e:
            raise StoreError(f"{path} is not valid JSON ({e}); fix or remove it")
        if not isinstance(doc, dict) or not isinstance(doc.get("map"), dict):
            raise StoreError(f"{path} is not a saved map; fix or remove it")
        return {"name": name, "saved": saved, "map": doc["map"]}

    def save(self, name, doc, overwrite=False):
        name = parse_name(name)
        if not isinstance(doc, dict):
            raise ValidationError("the map must be a JSON object")
        text = json.dumps({"name": name, "map": doc}, separators=(",", ":"))
        if len(text.encode()) > MAX_BYTES:
            raise ValidationError(f"the map is larger than {MAX_BYTES // 2**20} MB")
        path = os.path.join(self.directory, self._file(name))
        if os.path.exists(path):                # replacing a map needs leave to; a new one
            if not overwrite:                   # counts against MAX_SESSIONS
                raise Conflict(f"a map called {name!r} is already saved")
        elif len(self.list()) >= MAX_SESSIONS:
            raise ValidationError(f"{MAX_SESSIONS} maps are saved already; delete some first")
        os.makedirs(self.directory, exist_ok=True)
        write_atomically(path, text)
        return {"name": name, "saved": self._saved(path)}

    def delete(self, name):
        name = parse_name(name)
        try:
            os.remove(os.path.join(self.directory, self._file(name)))
        except FileNotFoundError:
            raise NotFound(f"no saved map called {name!r}")
