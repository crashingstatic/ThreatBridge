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
    def __init__(self, path, key, *more):
        self.path = path
        self.key = key            # top-level list in the file, e.g. {"entries": [...]}
        self.keys = (key, *more)  # all the lists it holds
        self._tlock = threading.Lock()

    @contextlib.contextmanager
    def locked(self):
        """Yield the current list; if the block changes it in place, it is written back."""
        with self.locked_all() as lists:
            yield lists[self.key]

    @contextlib.contextmanager
    def locked_all(self):
        """Yield {key: list} for every list the file holds; changed in place, they are written
        back together."""
        # Thread lock + flock: gunicorn runs several worker processes.
        with self._tlock, open(self.path + ".lock", "a") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                lists = self._load()
                before = json.dumps(lists, sort_keys=True)
                yield lists
                if json.dumps(lists, sort_keys=True) != before:
                    self._save(lists)
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return {k: [] for k in self.keys}
        except ValueError as e:
            raise StoreError(f"{self.path} is not valid JSON ({e}); fix or remove it")
        lists = {}
        for key in self.keys:
            items = data.get(key, []) if isinstance(data, dict) else None
            if not isinstance(items, list):
                raise StoreError(f'{self.path} should hold {{"{key}": [...]}}; fix or remove it')
            lists[key] = items
        return lists

    def _save(self, lists):
        write_atomically(self.path, json.dumps({k: lists[k] for k in self.keys}, indent=2))


def write_atomically(path, text):
    """Replace the file at `path` with `text` in one step: readers see the old or the new
    contents, never part of either."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".tb-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)
