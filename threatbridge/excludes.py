"""Shared, file-backed exclude list: IPs, CIDRs and domain names."""
import logging

from .jsonstore import JsonStore
from .query import ValidationError, parse_exclude

log = logging.getLogger(__name__)


class ExcludeStore:
    def __init__(self, path):
        self.store = JsonStore(path, "entries")

    def _canonical(self, entry):
        """The entry as parse_exclude() writes it, or None (with a warning) if the file holds
        something invalid, e.g. after a hand edit: one bad line must not break every query."""
        try:
            return parse_exclude(entry)
        except ValidationError:
            log.warning("%s: ignoring invalid entry %r", self.store.path, entry)
            return None

    def _valid(self, entries):
        return list(dict.fromkeys(e for e in map(self._canonical, entries) if e))

    def list(self):
        with self.store.locked() as entries:
            return self._valid(entries)

    def add(self, value):
        entry = parse_exclude(value)
        with self.store.locked() as entries:
            if entry not in self._valid(entries):
                entries.append(entry)
            return self._valid(entries)

    def remove(self, value):
        entry = parse_exclude(value)
        with self.store.locked() as entries:
            entries[:] = [e for e in entries if self._canonical(e) != entry]
            return self._valid(entries)
