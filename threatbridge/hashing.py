"""SHA-256 of a case's evidence files, for the report (D31).

Computed when asked, not when the case is built, and in the background: hashing gigabytes
outlasts a request. The first ask starts it; each ask reports how far it has got. Once done, the
digests are kept until a file changes, when the next ask hashes again.
"""
import hashlib
import os
import threading
import time
from datetime import datetime, timezone

from .query import fmt_time

CHUNK = 1 << 20
SAMPLE = 64 << 20        # bytes read and hashed to estimate how long the rest takes
SETTING = "setting "     # manifest entries that are settings, not files (CaseBackend._load)


def _stat(path):
    """(size, mtime_ns) of a file, or None if it can't be read."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st.st_size, st.st_mtime_ns


def _time(ns):
    return fmt_time(datetime.fromtimestamp(ns / 1e9, timezone.utc))


def estimate(manifest, sample=SAMPLE, clock=time.perf_counter):
    """{"total": bytes, "seconds": how long hashing them would take}, from reading and hashing
    the first `sample` bytes of the largest file. Files still in the operating system's cache
    (just read to build the case) read faster than from disk, so the estimate can be low."""
    files = [(p, _stat(p)) for p, _, _ in manifest if not p.startswith(SETTING)]
    files = [(p, s[0]) for p, s in files if s]
    total = sum(size for _, size in files)
    if not total:
        return {"total": 0, "seconds": 0.0}
    path = max(files, key=lambda f: f[1])[0]
    digest, read, start = hashlib.sha256(), 0, clock()
    try:
        with open(path, "rb") as fh:
            while read < sample:
                chunk = fh.read(min(CHUNK, sample - read))
                if not chunk:
                    break
                digest.update(chunk)
                read += len(chunk)
    except OSError:
        return {"total": total, "seconds": 0.0}
    took = clock() - start
    return {"total": total, "seconds": total * took / read if read else 0.0}


class Hashing:
    """The hashing of the files in a case's evidence manifest [(path, size, mtime_ns)]."""

    def __init__(self, manifest):
        self.files = [(p, size, mtime) for p, size, mtime in manifest if not p.startswith(SETTING)]
        self.settings = dict(p[len(SETTING):].split("=", 1) for p, _, _ in manifest if p.startswith(SETTING))
        self.stats = {p: _stat(p) for p, _, _ in self.files}          # as hashing began
        self.total = sum(s[0] for s in self.stats.values() if s)
        self.hashed, self.digests, self.errors, self.done = 0, {}, {}, False
        self.started = time.monotonic()
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._run, daemon=True, name="evidence-hashing")

    def start(self):
        self.thread.start()
        return self

    def _run(self):
        for path, _, _ in self.files:
            if self.stats[path] is None:
                continue
            digest = hashlib.sha256()
            try:
                with open(path, "rb") as fh:
                    while chunk := fh.read(CHUNK):
                        digest.update(chunk)
                        with self.lock:
                            self.hashed += len(chunk)
            except OSError as e:
                with self.lock:
                    self.errors[path] = e.strerror or str(e)
                continue
            with self.lock:
                self.digests[path] = digest.hexdigest()
        with self.lock:
            self.done = True

    def stale(self):
        """Done, but a file changed since: hash again."""
        with self.lock:
            done = self.done
        return done and any(_stat(p) != s for p, s in self.stats.items())

    def report(self):
        """{"done", "hashed": bytes so far, "total": bytes, "left": seconds still to go at the
        rate so far (None until it can tell), "files": [...], "settings": {...}}. A
        file is "unchanged" since the case was built, "changed" (its digest is of what it holds
        now, not of what was read), or "missing" (gone or unreadable: no digest)."""
        with self.lock:
            files = []
            for path, size, mtime in self.files:
                now = self.stats[path]
                if now is None or path in self.errors:
                    state = "missing"
                else:
                    state = "unchanged" if now == (size, mtime) else "changed"
                files.append({"path": path, "size": now[0] if now else size,
                              "modified": _time(now[1] if now else mtime), "sha256": self.digests.get(path),
                              "state": state})
            hashed, elapsed = min(self.hashed, self.total), time.monotonic() - self.started
            left = 0.0 if self.done else (elapsed * (self.total - hashed) / hashed if hashed and elapsed >= 1 else None)
            return {"done": self.done, "hashed": hashed, "total": self.total, "left": left,
                    "files": files, "settings": self.settings}
