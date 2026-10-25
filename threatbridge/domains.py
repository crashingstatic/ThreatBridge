"""Domain names on the exclude list, resolved to the addresses they stand for.

Two sources, used together:

- capture: DNS answers seen on the network, i.e. what the name resolved to during the
  incident: from the pcaps (case backend), or from the sensors' Zeek DNS records in
  Elasticsearch (Security Onion), cached for `ttl` seconds. Wildcards ("*.example.com")
  match these only.
- dns: a live lookup through the system resolver, cached for `ttl` seconds. Names behind a
  CDN may resolve differently today than during the incident, which is why the capture
  answers are always included.
"""
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

from .query import is_domain


def ip_key(ip):
    addr = ipaddress.ip_address(ip)
    return addr.version, int(addr)


def system_lookup(name):
    """A and AAAA addresses of `name` from the system resolver."""
    infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    return sorted({str(ipaddress.ip_address(i[4][0].split("%")[0])) for i in infos}, key=ip_key)


class DomainResolver:
    def __init__(self, passive=None, live=True, ttl=300, timeout=2.0, lookup=system_lookup,
                 clock=time.monotonic, answers=None):
        self.passive = passive or {}   # {name: {ip: [first, last]}} from the capture
        # Or, instead: answers([entry, ...]) -> {entry: {ip: [first, last]}}, asked when needed
        # (Security Onion's DNS records). It raises RuntimeError when it can't answer.
        self.answers = answers
        self.live, self.ttl, self.timeout = live, ttl, timeout
        self.lookup, self.clock = lookup, clock
        self._live_cache = {}          # name -> (looked up at, [ips], error or None)
        self._capture_cache = {}       # entry -> [ips] (passive), or (asked at, [ips], error)
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dns") if live else None

    def captured(self, entry):
        ips = self._capture_cache.get(entry)
        if ips is None:
            if entry.startswith("*."):
                suffix = entry[1:]  # ".example.com": subdomains only
                found = set()
                for name, seen in self.passive.items():
                    if name.endswith(suffix):
                        found.update(seen)
            else:
                found = set(self.passive.get(entry, {}))
            ips = self._capture_cache[entry] = sorted(found, key=ip_key)
        return ips

    def _refresh(self, names):
        """Look up names whose cached answer is missing or older than the TTL, in parallel,
        waiting at most `timeout` seconds in total."""
        now = self.clock()
        stale = [n for n in names
                 if n not in self._live_cache or now - self._live_cache[n][0] >= self.ttl]
        futures = {n: self._pool.submit(self.lookup, n) for n in stale}
        deadline = time.monotonic() + self.timeout
        for name, fut in futures.items():
            try:
                ips, error = fut.result(timeout=max(0.0, deadline - time.monotonic())), None
            except FutureTimeout:
                ips, error = [], "DNS lookup timed out"
            except OSError as e:  # socket.gaierror: no such name, no resolver, ...
                ips, error = [], f"DNS lookup failed: {e.strerror or e}"
            except ValueError as e:  # e.g. UnicodeError from IDNA encoding
                ips, error = [], f"DNS lookup failed: {e}"
            self._live_cache[name] = (now, ips, error)

    def _refresh_answers(self, entries):
        """Ask for the entries whose answers are missing or older than the TTL, all at once."""
        now = self.clock()
        stale = [e for e in entries
                 if e not in self._capture_cache or now - self._capture_cache[e][0] >= self.ttl]
        if not stale:
            return
        try:
            found, error = self.answers(stale), None
        except RuntimeError as e:   # e.g. BackendError: Elasticsearch unreachable
            found, error = {}, str(e)
        for e in stale:
            ips = sorted(found.get(e, {}), key=ip_key)
            self._capture_cache[e] = (now, ips, error)

    def describe(self, entries):
        """{domain entry: {"capture": [ips], "dns": [ips], "error": str or None}}."""
        domains = [e for e in entries if is_domain(e)]
        if self.answers:
            self._refresh_answers(domains)
        if self.live:
            self._refresh([d for d in domains if not d.startswith("*.")])
        out = {}
        for d in domains:
            _, live_ips, error = self._live_cache.get(d, (None, [], None))
            if self.answers:
                _, captured, capture_error = self._capture_cache[d]
                error = "; ".join(e for e in (capture_error, error) if e) or None
            else:
                captured = self.captured(d)
            out[d] = {"capture": captured, "dns": live_ips, "error": error}
        return out

    def expand(self, entries):
        """Exclude entries with every domain replaced by its addresses (IPs/CIDRs only)."""
        nets = [e for e in entries if not is_domain(e)]
        for r in self.describe(entries).values():
            nets.extend(r["capture"])
            nets.extend(r["dns"])
        return list(dict.fromkeys(nets))
