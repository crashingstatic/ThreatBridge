"""Shared, file-backed exclude list: IPs, CIDRs and domain names."""
from .jsonstore import JsonStore
from .query import parse_exclude


class ExcludeStore:
    def __init__(self, path):
        self.store = JsonStore(path, "entries")

    def list(self):
        with self.store.locked() as entries:
            return [parse_exclude(e) for e in entries]

    def add(self, value):
        entry = parse_exclude(value)
        with self.store.locked() as entries:
            if entry not in entries:
                entries.append(entry)
            return list(entries)

    def remove(self, value):
        entry = parse_exclude(value)
        with self.store.locked() as entries:
            entries[:] = [e for e in entries if e != entry]
            return list(entries)
