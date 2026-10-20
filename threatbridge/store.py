"""Flow records in SQLite: the detail behind each graph edge (counts, ports, timings).

The graph (graph.py) keeps only host pairs and flow start times; anything that needs the
flows themselves asks the store. The file is a derived cache of the evidence: it records
which files it was built from, so a case can be reopened without re-reading them.
"""
import json
import sqlite3
import threading

from .model import Flow

VERSION = "2"
_SCHEMA = """
CREATE TABLE flow (src TEXT, dst TEXT, sport INTEGER, dport INTEGER, proto TEXT,
                   start_ts REAL, end_ts REAL, packets INTEGER, bytes INTEGER, source TEXT);
CREATE TABLE dns (name TEXT, ip TEXT, first_ts REAL, last_ts REAL);
CREATE TABLE evidence (path TEXT, size INTEGER, mtime_ns INTEGER);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
"""
_INDEXES = """
CREATE INDEX flow_pair ON flow (src, dst, start_ts);
"""
_TABLES = {"flow", "dns", "evidence", "meta"}
_DROP = "".join(f"DROP TABLE IF EXISTS {t};" for t in sorted(_TABLES))
# TCP/UDP destination ports per peer, for flows into ("in") or out of ("out") a host.
# The peers are one JSON array parameter, so the SQL text never changes.
_PORTS = {
    "in": "SELECT src, dport, count(*) FROM flow WHERE dst = ? "
          "AND src IN (SELECT value FROM json_each(?)) AND start_ts BETWEEN ? AND ? "
          "AND proto IN ('tcp', 'udp') GROUP BY src, dport",
    "out": "SELECT dst, dport, count(*) FROM flow WHERE src = ? "
           "AND dst IN (SELECT value FROM json_each(?)) AND start_ts BETWEEN ? AND ? "
           "AND proto IN ('tcp', 'udp') GROUP BY dst, dport",
}


class NotAStore(Exception):
    """The file is some other SQLite database."""


class FlowStore:
    def __init__(self, path):
        self.path = path
        self._local = threading.local()  # one connection per thread

    def _db(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._local.conn = sqlite3.connect(self.path)
        return conn

    # ---- building ---------------------------------------------------------------------

    def write(self, flows, dns, evidence):
        """Replace the contents with `flows`, the passive DNS map and the evidence manifest
        [(path, size, mtime_ns)]."""
        db = self._db()
        tables = {name for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if tables - _TABLES:
            raise NotAStore(f"{self.path} is not a ThreatBridge case database; not overwriting it")
        db.execute("PRAGMA journal_mode=OFF")  # a cache: if a build is interrupted, rebuild
        db.execute("PRAGMA synchronous=OFF")
        db.executescript(_DROP + _SCHEMA)
        with db:
            db.executemany("INSERT INTO flow VALUES (?,?,?,?,?,?,?,?,?,?)",
                           ((f.src, f.dst, f.sport, f.dport, f.proto, f.start, f.end, f.packets,
                             f.bytes, f.source) for f in flows))
            db.executemany("INSERT INTO dns VALUES (?,?,?,?)",
                           ((name, ip, t[0], t[1]) for name, seen in dns.items()
                            for ip, t in seen.items()))
            db.executemany("INSERT INTO evidence VALUES (?,?,?)", evidence)
            db.execute("INSERT INTO meta VALUES ('version', ?)", (VERSION,))
        db.executescript(_INDEXES)

    def matches(self, evidence):
        """True if the store was built from exactly these files, unchanged."""
        try:
            db = self._db()
            version = db.execute("SELECT value FROM meta WHERE key='version'").fetchone()
            built = db.execute("SELECT path, size, mtime_ns FROM evidence").fetchall()
        except sqlite3.DatabaseError:  # empty, foreign or older file
            return False
        return version == (VERSION,) and sorted(built) == sorted(map(tuple, evidence))

    # ---- reading ----------------------------------------------------------------------

    def pairs(self):
        """(src, dst, start) for every flow."""
        return self._db().execute("SELECT src, dst, start_ts FROM flow")

    def dns(self):
        out = {}
        for name, ip, first, last in self._db().execute("SELECT * FROM dns"):
            out.setdefault(name, {})[ip] = [first, last]
        return out

    def stats(self):
        """(flow count, earliest start, latest end)."""
        return self._db().execute("SELECT count(*), min(start_ts), max(end_ts) FROM flow").fetchone()

    def ports(self, host, direction, peers, lo, hi):
        """{peer: {dport: count}} for TCP/UDP flows into ("in") or out of ("out") `host`
        from/to the given peers, started within [lo, hi]."""
        out = {peer: {} for peer in peers}
        if peers:
            for peer, port, n in self._db().execute(_PORTS[direction],
                                                    (host, json.dumps(list(peers)), lo, hi)):
                out[peer][port] = n
        return out

    def edge(self, src, dst, lo, hi):
        """(count, first start, last start, {dport: count}) for flows src -> dst in [lo, hi]."""
        db = self._db()
        n, first, last = db.execute(
            "SELECT count(*), min(start_ts), max(start_ts) FROM flow "
            "WHERE src = ? AND dst = ? AND start_ts BETWEEN ? AND ?", (src, dst, lo, hi)).fetchone()
        ports = dict(db.execute(
            "SELECT dport, count(*) FROM flow WHERE src = ? AND dst = ? AND start_ts BETWEEN ? AND ? "
            "AND proto IN ('tcp', 'udp') GROUP BY dport", (src, dst, lo, hi)))
        return n, first, last, ports

    def flow_at(self, src, dst, start):
        """The flow src -> dst that started at exactly `start`."""
        row = self._db().execute(
            "SELECT src, dst, sport, dport, proto, start_ts, end_ts, packets, bytes, source "
            "FROM flow WHERE src = ? AND dst = ? AND start_ts = ? LIMIT 1", (src, dst, start)).fetchone()
        return Flow(*row) if row else None
