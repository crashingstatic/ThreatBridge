"""Shared, file-backed marks (D15): hosts the analysts marked as compromised, and single flows.

The file holds {"hosts": [...], "flows": [...]}: the hosts marked themselves, each
{"ip", "time" (ISO-8601 UTC or None if unknown), "note"}, and the flows marked, each
{"src", "dst", "start", "sport", "dport", "proto", "note"}. A flow marks its two hosts too:
marked_hosts() works out every marked host, with its mark count and the time it was reached.
"""
import hashlib
import json
import logging

from .jsonstore import JsonStore
from .query import ValidationError, fmt_time, parse_ip, parse_time

log = logging.getLogger(__name__)
MAX_NOTE = 500
MAX_MARKS = 10_000    # per list


def _time(value):
    """ISO-8601 UTC, or None for unknown (blank). Numbers are epoch seconds or milliseconds."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise ValidationError(f"invalid time: {value!r}")
    return fmt_time(parse_time(value))


def _note(note):
    if note is not None and not isinstance(note, str):
        raise ValidationError("note must be text")
    note = (note or "").strip()
    if len(note) > MAX_NOTE:
        raise ValidationError(f"note longer than {MAX_NOTE} characters")
    return note


def _port(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
        raise ValidationError(f"{name} must be a port number (0-65535)")
    return value


def parse_flow(body):
    """A marked flow from {"src", "dst", "start", "sport", "dport", "proto"[, "note"]}, in
    canonical form: the start to the millisecond, as flow lists show it."""
    if not isinstance(body, dict):
        raise ValidationError("a flow is an object with src, dst, start, sport, dport and proto")
    start = _time(body.get("start"))
    if start is None:
        raise ValidationError("start (the flow's start time) is required")
    proto = body.get("proto")
    if not isinstance(proto, str) or not proto.strip() or len(proto) > 16:
        raise ValidationError("proto must be tcp, udp, icmp or an IP protocol number")
    return {"src": parse_ip(body.get("src")), "dst": parse_ip(body.get("dst")),
            "start": start, "sport": _port(body.get("sport"), "sport"),
            "dport": _port(body.get("dport"), "dport"), "proto": proto.strip().lower(),
            "note": _note(body.get("note"))}


def parse_host(body):
    """A host marked itself, from {"ip", "time"[, "note"]}."""
    if not isinstance(body, dict):
        raise ValidationError("a host is an object with ip, time and note")
    return {"ip": parse_ip(body.get("ip")), "time": _time(body.get("time")),
            "note": _note(body.get("note"))}


def flow_key(f):
    """What tells marked flows apart: all but the note."""
    return (f["src"], f["dst"], f["start"], f["sport"], f["dport"], f["proto"])


def parse_marks(body):
    """Marks sent with a request ({"hosts": [...], "flows": [...]}, e.g. an opened map's), in
    canonical form; ValidationError if any is invalid."""
    if not isinstance(body, dict):
        raise ValidationError('marks are an object: {"hosts": [...], "flows": [...]}')
    hosts, flows = body.get("hosts", []), body.get("flows", [])
    if not isinstance(hosts, list) or not isinstance(flows, list):
        raise ValidationError('marks are an object: {"hosts": [...], "flows": [...]}')
    if len(hosts) > MAX_MARKS or len(flows) > MAX_MARKS:
        raise ValidationError(f"at most {MAX_MARKS} marked hosts and {MAX_MARKS} marked flows")
    return (list({h["ip"]: h for h in map(parse_host, hosts)}.values()),
            list({flow_key(f): f for f in map(parse_flow, flows)}.values()))


def marked_hosts(hosts, flows):
    """Every marked host: {"ip", "time", "note", "direct", "count"}, by time then IP. `count`
    is its own mark (`direct`) plus the marked flows it is an end of; `time`, when it was
    reached: the earliest known of its own mark's time and those flows' starts (None if
    none is known)."""
    out = {h["ip"]: {"ip": h["ip"], "time": h["time"], "note": h["note"], "direct": True,
                     "count": 1} for h in hosts}
    for f in flows:
        for ip in dict.fromkeys((f["src"], f["dst"])):
            row = out.setdefault(ip, {"ip": ip, "time": None, "note": "", "direct": False, "count": 0})
            row["count"] += 1
            if row["time"] is None or f["start"] < row["time"]:
                row["time"] = f["start"]
    return sorted(out.values(), key=lambda h: (h["time"] or "", h["ip"]))


def reached(hosts, flows):
    """{ip: when each marked host was reached, as epoch seconds, or None if unknown}."""
    return {h["ip"]: parse_time(h["time"]).timestamp() if h["time"] else None
            for h in marked_hosts(hosts, flows)}


class CompromisedStore:
    def __init__(self, path):
        self.store = JsonStore(path, "hosts", "flows")

    def _valid(self, items, parse):
        """Entries in canonical form. Invalid ones (a hand edit) are skipped with a warning:
        one bad line must not break every attack-path query."""
        out = []
        for item in items:
            try:
                out.append(parse(item))
            except (ValidationError, AttributeError):
                log.warning("%s: ignoring invalid entry %r", self.store.path, item)
        return out

    def _view(self, lists):
        hosts = sorted(self._valid(lists["hosts"], parse_host), key=lambda h: (h["time"] or "", h["ip"]))
        flows = sorted(self._valid(lists["flows"], parse_flow), key=lambda f: (f["start"], flow_key(f)))
        version = hashlib.sha256(json.dumps([hosts, flows], sort_keys=True).encode()).hexdigest()[:16]
        return {"hosts": marked_hosts(hosts, flows), "marked": hosts, "flows": flows,
                "version": version}

    def list(self):
        """{"hosts": every marked host (marked_hosts), "marked": the hosts marked themselves,
        "flows": the marked flows, "version": a tag that changes when any of them does}."""
        with self.store.locked_all() as lists:
            return self._view(lists)

    def _put(self, kind, entry, same):
        """Add `entry` to the list `kind` ("hosts" or "flows"), in place of the one it is the
        `same` as."""
        with self.store.locked_all() as lists:
            kept = [e for e in lists[kind] if not same(e)]
            if len(kept) >= MAX_MARKS:
                raise ValidationError(f"at most {MAX_MARKS} marked {kind}")
            lists[kind][:] = kept + [entry]
            return self._view(lists)

    def mark(self, ip, time=None, note=""):
        entry = parse_host({"ip": ip, "time": time, "note": note})
        return self._put("hosts", entry, lambda h: self._is(h, entry["ip"]))

    def unmark(self, ip):
        """Remove the host's own mark and every marked flow it is an end of (D15)."""
        ip = parse_ip(ip)
        with self.store.locked_all() as lists:
            lists["hosts"][:] = [h for h in lists["hosts"] if not self._is(h, ip)]
            lists["flows"][:] = [f for f in lists["flows"] if not self._touches(f, ip)]
            return self._view(lists)

    def mark_flow(self, body):
        entry = parse_flow(body)
        return self._put("flows", entry, lambda f: self._key(f) == flow_key(entry))

    def unmark_flow(self, body):
        key = flow_key(parse_flow(body))
        with self.store.locked_all() as lists:
            lists["flows"][:] = [f for f in lists["flows"] if self._key(f) != key]
            return self._view(lists)

    def replace(self, body):
        """Replace every mark with `body` ({"hosts", "flows"}, as parse_marks reads it)."""
        hosts, flows = parse_marks(body)
        with self.store.locked_all() as lists:
            lists["hosts"][:] = hosts
            lists["flows"][:] = flows
            return self._view(lists)

    def marks(self):
        """(hosts marked themselves, marked flows), as parse_marks gives them."""
        view = self.list()
        return view["marked"], view["flows"]

    @staticmethod
    def _is(entry, ip):
        try:
            return parse_ip(entry.get("ip")) == ip
        except (ValidationError, AttributeError):
            return False

    @staticmethod
    def _key(entry):
        try:
            return flow_key(parse_flow(entry))
        except (ValidationError, AttributeError):
            return None

    @classmethod
    def _touches(cls, entry, ip):
        key = cls._key(entry)
        return key is not None and ip in key[:2]
