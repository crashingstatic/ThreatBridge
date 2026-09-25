"""Shared, file-backed exclude list of IPs/CIDRs."""
import contextlib
import fcntl
import json
import os
import tempfile
import threading

from .query import parse_network


class ExcludeStore:
    def __init__(self, path):
        self.path = path
        self._tlock = threading.Lock()

    @contextlib.contextmanager
    def _lock(self):
        # Thread lock + flock: gunicorn runs several worker processes.
        with self._tlock, open(self.path + ".lock", "a") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return []
        return [parse_network(e) for e in data.get("entries", [])]

    def _save(self, entries):
        directory = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".exclude-")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"entries": entries}, fh, indent=2)
        os.replace(tmp, self.path)

    def list(self):
        with self._lock():
            return self._load()

    def add(self, value):
        entry = parse_network(value)
        with self._lock():
            entries = self._load()
            if entry not in entries:
                entries.append(entry)
                self._save(entries)
            return entries

    def remove(self, value):
        entry = parse_network(value)
        with self._lock():
            entries = [e for e in self._load() if e != entry]
            self._save(entries)
            return entries

