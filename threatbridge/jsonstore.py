"""A JSON file shared by gunicorn workers: locked read-modify-write, atomic replace."""
import contextlib
import fcntl
import json
import os
import tempfile
import threading


class StoreError(RuntimeError):
    """The shared file can't be read; it is left as it is for someone to fix."""


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
                data = json.load(fh)
        except FileNotFoundError:
            return []
        except ValueError as e:
            raise StoreError(f"{self.path} is not valid JSON ({e}); fix or remove it")
        items = data.get(self.key, []) if isinstance(data, dict) else None
        if not isinstance(items, list):
            raise StoreError(f'{self.path} should hold {{"{self.key}": [...]}}; fix or remove it')
        return items

    def _save(self, items):
        write_atomically(self.path, json.dumps({self.key: items}, indent=2))


def write_atomically(path, text):
    """Replace the file at `path` with `text` in one step: readers see the old or the new
    contents, never part of either."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".tb-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)
