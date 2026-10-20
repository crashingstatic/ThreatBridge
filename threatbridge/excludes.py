"""Shared, file-backed exclude list of IPs/CIDRs."""
from .jsonstore import JsonStore
from .query import parse_network


class ExcludeStore:
    def __init__(self, path):
        self.store = JsonStore(path, "entries")

    def list(self):
        with self.store.locked() as entries:
            return [parse_network(e) for e in entries]

    def add(self, value):
        entry = parse_network(value)
        with self.store.locked() as entries:
            if entry not in entries:
                entries.append(entry)
            return list(entries)

    def remove(self, value):
        entry = parse_network(value)
        with self.store.locked() as entries:
            entries[:] = [e for e in entries if e != entry]
            return list(entries)
