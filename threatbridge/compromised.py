"""Shared, file-backed list of hosts the analyst has marked as compromised."""
from .jsonstore import JsonStore
from .query import ValidationError, fmt_time, parse_ip, parse_time

MAX_NOTE = 500


class CompromisedStore:
    """Entries are {"ip", "time" (ISO-8601 UTC or None if unknown), "note"}."""

    def __init__(self, path):
        self.store = JsonStore(path, "hosts")

    def list(self):
        with self.store.locked() as hosts:
            return sorted((dict(h) for h in hosts), key=lambda h: (h["time"] or "", h["ip"]))

    def mark(self, ip, time=None, note=""):
        entry = {
            "ip": parse_ip(ip),
            "time": fmt_time(parse_time(time)) if (time or "").strip() else None,
            "note": (note or "").strip(),
        }
        if len(entry["note"]) > MAX_NOTE:
            raise ValidationError(f"note longer than {MAX_NOTE} characters")
        with self.store.locked() as hosts:
            hosts[:] = [h for h in hosts if h["ip"] != entry["ip"]] + [entry]
        return self.list()

    def unmark(self, ip):
        ip = parse_ip(ip)
        with self.store.locked() as hosts:
            hosts[:] = [h for h in hosts if h["ip"] != ip]
        return self.list()

    def times(self):
        """{ip: compromise time as epoch seconds, or None if unknown}."""
        return {h["ip"]: parse_time(h["time"]).timestamp() if h["time"] else None
                for h in self.list()}
