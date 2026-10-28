"""Flow records in SQLite: the detail behind each graph edge (counts, ports, timings).

The graph (graph.py) keeps only host pairs and flow start times; anything that needs the
flows themselves asks the store. The file is a derived cache of the evidence: it records
which files it was built from, so a case can be reopened without re-reading them.
"""
import json
import sqlite3
import threading

from .filters import in_network
from .model import Flow
from .progress import QUIET, counted

VERSION = "8"   # changes when flows are read differently, so older stores are rebuilt
_SCHEMA = """
CREATE TABLE flow (src TEXT, dst TEXT, sport INTEGER, dport INTEGER, proto TEXT,
                   start_ts REAL, end_ts REAL, packets INTEGER, bytes INTEGER, source TEXT,
                   service TEXT);
CREATE TABLE dns (name TEXT, ip TEXT, first_ts REAL, last_ts REAL);
CREATE TABLE evidence (path TEXT, size INTEGER, mtime_ns INTEGER);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
"""
_INDEXES = """
CREATE INDEX flow_pair ON flow (src, dst, start_ts);
"""
_TABLES = {"flow", "dns", "evidence", "meta"}
_FAR = 1e18  # seconds
_DROP = "".join(f"DROP TABLE IF EXISTS {t};" for t in sorted(_TABLES))
_COLUMNS = "f.src, f.dst, f.sport, f.dport, f.proto, f.start_ts, f.end_ts, f.packets, f.bytes, f.source, f.service"
# Destination ports and protocols per peer, for flows between a host and its peers (one JSON
# array parameter).
_DETAILS = ("SELECT f.{peer}, f.dport, f.proto, f.service, count(*) FROM flow AS f WHERE f.{host} = ? "
            "AND f.{peer} IN (SELECT value FROM json_each(?)) AND f.start_ts BETWEEN ? AND ? AND ({where}) "
            "GROUP BY f.{peer}, f.dport, f.proto, f.service")

# Count, first/last start, destination ports and protocols of the flows src -> dst within a
# JSON array of [lo, hi] intervals. CROSS JOIN keeps the intervals as the outer loop, so each
# one is a range search on the flow_pair index.
_IN_INTERVALS = ("FROM json_each(?) AS j CROSS JOIN flow AS f WHERE f.src = ? AND f.dst = ? "
                 "AND f.start_ts BETWEEN json_extract(j.value, '$[0]') AND json_extract(j.value, '$[1]') "
                 "AND ({})")
_EDGE = "SELECT count(*), min(f.start_ts), max(f.start_ts) " + _IN_INTERVALS
_EDGE_DETAILS = "SELECT f.dport, f.proto, f.service, count(*) " + _IN_INTERVALS + \
    " GROUP BY f.dport, f.proto, f.service"
_EDGE_ROWS = f"SELECT {_COLUMNS} " + _IN_INTERVALS + " ORDER BY f.start_ts, f.rowid LIMIT ? OFFSET ?"


def _where(where):
    """(SQL, parameters) of a filter on the flows (columns as "f.<name>"); None: every flow.
    The SQL is filters.to_sql's (and backends.CaseBackend._where's): column names and
    placeholders only, every value a bound parameter, so putting it in a query is safe."""
    return where or ("1", [])


def _intervals(intervals):
    """Disjoint [(lo, hi), ...] as a JSON parameter. JSON has no infinity: an open end
    becomes a far-off time."""
    return json.dumps([[max(lo, -_FAR), min(hi, _FAR)] for lo, hi in intervals])


def _ports_and_protocols(rows):
    """({dport: count} of the TCP/UDP flows, sorted protocols) from (dport, proto, service, n)."""
    ports, protocols = {}, set()
    for dport, proto, service, n in rows:
        if proto in ("tcp", "udp"):
            ports[dport] = ports.get(dport, 0) + n
        protocols.add(service)
    return ports, sorted(protocols)


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
            conn.create_function("ip_in_net", 2, in_network, deterministic=True)   # filters.py
        return conn

    # ---- building ---------------------------------------------------------------------

    def write(self, flows, dns, evidence, progress=None):
        """Replace the contents with `flows`, the passive DNS map and the evidence manifest
        [(path, size, mtime_ns)]. `progress` (see progress.py) shows how far it has got."""
        progress = progress or QUIET
        db = self._db()
        try:
            tables = {name for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        except sqlite3.OperationalError:   # e.g. locked: a database, but not one to touch now
            raise
        except sqlite3.DatabaseError:      # some other kind of file
            tables = {"?"}
        if tables - _TABLES:
            raise NotAStore(f"{self.path} is not a ThreatBridge case database; not overwriting it")
        db.execute("PRAGMA journal_mode=OFF")  # a cache: if a build is interrupted, rebuild
        db.execute("PRAGMA synchronous=OFF")
        db.executescript(_DROP + _SCHEMA)
        with db, progress.stage("Saving the flows", len(flows)) as stage:
            db.executemany("INSERT INTO flow VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                           ((f.src, f.dst, f.sport, f.dport, f.proto, f.start, f.end, f.packets,
                             f.bytes, f.source, f.service) for f in counted(flows, stage)))
            db.executemany("INSERT INTO dns VALUES (?,?,?,?)",
                           ((name, ip, t[0], t[1]) for name, seen in dns.items()
                            for ip, t in seen.items()))
            db.executemany("INSERT INTO evidence VALUES (?,?,?)", evidence)
        with progress.stage("Indexing the flows"):
            db.executescript(_INDEXES)
        with db:   # last: a build that stopped before here is never reused
            db.execute("INSERT INTO meta VALUES ('version', ?)", (VERSION,))

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

    def pairs(self, where=None):
        """(src, dst, start) for every flow, or those `where` (see _where) selects."""
        sql, params = _where(where)
        query = f"SELECT f.src, f.dst, f.start_ts FROM flow AS f WHERE {sql}"   # nosec B608 (_where)
        return self._db().execute(query, params)

    def dns(self):
        out = {}
        for name, ip, first, last in self._db().execute("SELECT * FROM dns"):
            out.setdefault(name, {})[ip] = [first, last]
        return out

    def stats(self):
        """(flow count, earliest start, latest end)."""
        return self._db().execute("SELECT count(*), min(start_ts), max(end_ts) FROM flow").fetchone()

    def details(self, host, direction, peers, lo, hi, where=None):
        """{peer: ({dport: count} of TCP/UDP flows, sorted protocols)} for flows into ("in")
        or out of ("out") `host` from/to the given peers, started within [lo, hi]."""
        rows = {peer: [] for peer in peers}
        if peers:
            sql, params = _where(where)
            host_col, peer_col = ("dst", "src") if direction == "in" else ("src", "dst")
            query = _DETAILS.format(host=host_col, peer=peer_col, where=sql)
            for peer, *row in self._db().execute(query, (host, json.dumps(list(peers)), lo, hi, *params)):
                rows[peer].append(row)
        return {peer: _ports_and_protocols(r) for peer, r in rows.items()}

    def edge(self, src, dst, intervals, where=None):
        """(count, first start, last start, {dport: count} of TCP/UDP flows, sorted protocols)
        for flows src -> dst that started within the disjoint intervals [(lo, hi), ...]."""
        db = self._db()
        sql, params = _where(where)
        args = (_intervals(intervals), src, dst, *params)
        n, first, last = db.execute(_EDGE.format(sql), args).fetchone()
        return (n, first, last, *_ports_and_protocols(db.execute(_EDGE_DETAILS.format(sql), args)))

    def edge_flows(self, src, dst, intervals, where=None, limit=-1, offset=0):
        """The flows src -> dst that started within the intervals, oldest first."""
        sql, params = _where(where)
        rows = self._db().execute(_EDGE_ROWS.format(sql), (_intervals(intervals), src, dst, *params, limit, offset))
        return [Flow(*row) for row in rows]

    def count(self, src, dst, intervals, where=None):
        """How many flows src -> dst started within the intervals."""
        sql, params = _where(where)
        return self._db().execute(_EDGE.format(sql), (_intervals(intervals), src, dst, *params)).fetchone()[0]

    def flows(self, src, dst, lo, hi, offset, limit, where=None, within=None):
        """One page of the flows src -> dst that started within [lo, hi] (and, if given,
        within the intervals `within`), oldest first."""
        intervals = [(lo, hi)] if within is None else [
            (max(a, lo), min(b, hi)) for a, b in within if max(a, lo) <= min(b, hi)]
        return self.edge_flows(src, dst, intervals, where, limit, offset)

    def times(self, src, dst, lo, hi, where=None):
        """The start times of the flows src -> dst within [lo, hi], sorted."""
        sql, params = _where(where)
        return [t for (t,) in self._db().execute(
            f"SELECT f.start_ts FROM flow AS f WHERE f.src = ? AND f.dst = ? AND f.start_ts BETWEEN ? AND ? "  # nosec B608 (_where)
            f"AND ({sql}) ORDER BY f.start_ts", (src, dst, lo, hi, *params))]

    def find(self, src, dst, start, sport, dport, proto):
        """[(row id, start)] of the flows a mark names: `start` as flow lists show it, to the
        millisecond (rounded down)."""
        return self._db().execute(
            "SELECT rowid, start_ts FROM flow WHERE src = ? AND dst = ? AND start_ts >= ? AND start_ts < ? "
            "AND sport = ? AND dport = ? AND proto = ?",
            (src, dst, start - 1e-6, start + 0.001, sport, dport, proto)).fetchall()

    def flow_at(self, src, dst, start, where=None):
        """A flow src -> dst that started at exactly `start` (and that `where` selects)."""
        sql, params = _where(where)
        row = self._db().execute(
            f"SELECT {_COLUMNS} FROM flow AS f WHERE f.src = ? AND f.dst = ? AND f.start_ts = ? "  # nosec B608 (_where)
            f"AND ({sql}) ORDER BY f.rowid LIMIT 1", (src, dst, start, *params)).fetchone()
        return Flow(*row) if row else None
