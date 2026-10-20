"""A JSON file shared by gunicorn workers: locked read-modify-write, atomic replace."""
import contextlib
import fcntl
import json
import os
import tempfile
import threading


class JsonStore:
    def __init__(self, path, key):
        self.path = path
        self.key = key  # top-level list in the file, e.g. {"entries": [...]}
        self._tlock = threading.Lock()

    @contextlib.contextmanager
    def locked(self):
        """Yield the current list; if the block changes it in place, it is written back."""
        # Thread lock + flock: gunicorn runs several worker processes.
        with self._tlock, open(self.path + ".lock", "a") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                items = self._load()
                before = json.dumps(items, sort_keys=True)
                yield items
                if json.dumps(items, sort_keys=True) != before:
                    self._save(items)
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                return json.load(fh).get(self.key, [])
        except FileNotFoundError:
            return []

    def _save(self, items):
        directory = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tb-")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({self.key: items}, fh, indent=2)
        os.replace(tmp, self.path)
