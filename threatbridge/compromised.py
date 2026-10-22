"""Shared, file-backed list of hosts the analyst has marked as compromised."""
import logging

from .jsonstore import JsonStore
from .query import ValidationError, fmt_time, parse_ip, parse_time

log = logging.getLogger(__name__)
MAX_NOTE = 500


def _time(value):
    """ISO-8601 UTC, or None for unknown (blank). Numbers are epoch seconds or milliseconds."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise ValidationError(f"invalid time: {value!r}")
    return fmt_time(parse_time(value))


class CompromisedStore:
    """Entries are {"ip", "time" (ISO-8601 UTC or None if unknown), "note"}."""

    def __init__(self, path):
        self.store = JsonStore(path, "hosts")

    def _valid(self, hosts):
        """Entries in canonical form. Invalid ones (a hand edit) are skipped with a warning:
        one bad line must not break every attack-path query."""
        out = []
        for h in hosts:
            try:
                note = h.get("note") or ""
                if not isinstance(note, str):
                    raise ValidationError("note must be text")
                out.append({"ip": parse_ip(h.get("ip")), "time": _time(h.get("time")), "note": note})
            except (ValidationError, AttributeError):
                log.warning("%s: ignoring invalid entry %r", self.store.path, h)
        return sorted(out, key=lambda h: (h["time"] or "", h["ip"]))

    def list(self):
        with self.store.locked() as hosts:
            return self._valid(hosts)

    def mark(self, ip, time=None, note=""):
        if note is not None and not isinstance(note, str):
            raise ValidationError("note must be text")
        entry = {"ip": parse_ip(ip), "time": _time(time), "note": (note or "").strip()}
        if len(entry["note"]) > MAX_NOTE:
            raise ValidationError(f"note longer than {MAX_NOTE} characters")
        with self.store.locked() as hosts:
            hosts[:] = [h for h in hosts if not self._is(h, entry["ip"])] + [entry]
            return self._valid(hosts)

    def unmark(self, ip):
        ip = parse_ip(ip)
        with self.store.locked() as hosts:
            hosts[:] = [h for h in hosts if not self._is(h, ip)]
            return self._valid(hosts)

    @staticmethod
    def _is(entry, ip):
        try:
            return parse_ip(entry.get("ip")) == ip
        except (ValidationError, AttributeError):
            return False

    def times(self):
        """{ip: compromise time as epoch seconds, or None if unknown}."""
        return {h["ip"]: parse_time(h["time"]).timestamp() if h["time"] else None
                for h in self.list()}
