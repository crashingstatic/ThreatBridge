"""Which account made a connection, from Windows Security events (D28).

Read from .evtx files (with the evtx library) or JSON lines of the same records, as evtx_dump
writes them ({"Event": {"System": ..., "EventData": ...}}). Four events:

- 4624, an account logged on: on the host logged on to (Computer), from IpAddress. Network
  logons only (types 3, 8 and 10).
- 4648, a logon with explicit credentials: on the host the account came from (Computer), to
  IpAddress or TargetServerName.
- 4768, a Kerberos ticket-granting ticket: on the domain controller (Computer), for the client
  at IpAddress.
- 4769, a Kerberos service ticket: on the domain controller, for the client at IpAddress, to
  ServiceName; also the client's connection to that service's host.

Machine accounts (ending in "$") and ANONYMOUS LOGON are left out. Each event makes claims:
(source, destination, time, account, event, logon type, preferred ports, file), an end being an
address or a host name. Names are resolved at the claim's time (Names), and each claim labels
the one flow between its ends within the tolerance that fits best: a preferred port first, then
the nearest in time. Labels only: nothing is scored or ranked.
"""
import ipaddress
import json
import logging
from datetime import datetime

from ..model import SourceError

log = logging.getLogger(__name__)

MAGIC = b"ElfFile\0"
EVENTS = (4624, 4648, 4768, 4769)
NETWORK_LOGONS = {3: {445, 139, 135, 5985, 5986, 389, 636, 3268, 1433}, 8: {80, 443}, 10: {3389}}
EXPLICIT_PORTS = {445, 135, 3389, 5985, 5986}
KERBEROS = {88}
SERVICE_PORTS = {"cifs": {445, 139}, "host": {445, 135, 139}, "http": {80, 443}, "mssqlsvc": {1433},
                 "termsrv": {3389}, "ldap": {389, 636, 3268}, "wsman": {5985, 5986}, "rpcss": {135}}


def kind(head):
    """"evtx" or "jsonl" for the first bytes of a Security event log, else None."""
    if head.startswith(MAGIC):
        return "evtx"
    text = head.decode("utf-8", errors="replace").lstrip()
    if text.startswith("{") and '"Event"' in text[:2000] and '"System"' in text[:4000]:
        return "jsonl"
    return None


def _value(v):
    """A field's value: evtx gives some as {"#text": ..., "#attributes": ...}."""
    if isinstance(v, dict):
        return v.get("#text")
    return v


def _address(v):
    """An address from an event's IpAddress, without its IPv4-mapped prefix; None for none or
    the host itself."""
    v = (str(_value(v) or "")).strip()
    if v.startswith("::ffff:"):
        v = v[7:]
    try:
        addr = ipaddress.ip_address(v)
    except ValueError:
        return None
    return None if addr.is_loopback or addr.is_unspecified else str(addr)


def _account(data, user="TargetUserName", domain="TargetDomainName"):
    name = str(_value(data.get(user)) or "").strip()
    if not name or name == "-" or name.endswith("$") or name.upper() == "ANONYMOUS LOGON":
        return None
    dom = str(_value(data.get(domain)) or "").strip()
    return f"{dom}\\{name}" if dom and dom != "-" and "@" not in name else name


def _time(system):
    created = system.get("TimeCreated") or {}
    attrs = created.get("#attributes", created) if isinstance(created, dict) else {}
    value = attrs.get("SystemTime")
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def claims_of(record, source=""):
    """The claims one event record ({"Event": {...}}) makes: [(src, dst, time, account, event,
    logon type, ports, source)], each end an address or ("name", host name)."""
    event = record.get("Event", record)
    system, data = event.get("System") or {}, event.get("EventData") or {}
    if not isinstance(system, dict) or not isinstance(data, dict):
        return []
    try:
        number = int(_value(system.get("EventID")))
    except (TypeError, ValueError):
        return []
    t = _time(system)
    computer = str(_value(system.get("Computer")) or "").strip()
    if number not in EVENTS or t is None or not computer:
        return []
    here = ("name", computer)
    if number == 4624:
        try:
            logon_type = int(_value(data.get("LogonType")))
        except (TypeError, ValueError):
            return []
        src, account = _address(data.get("IpAddress")), _account(data)
        if logon_type not in NETWORK_LOGONS or not src or not account:
            return []
        return [(src, here, t, account, number, logon_type, NETWORK_LOGONS[logon_type], source)]
    if number == 4648:
        account = _account(data)
        dst = _address(data.get("IpAddress"))
        server = str(_value(data.get("TargetServerName")) or "").strip()
        dst = dst or (("name", server) if server and server not in ("-", "localhost") else None)
        return [(here, dst, t, account, number, None, EXPLICIT_PORTS, source)] if account and dst else []
    client, account = _address(data.get("IpAddress")), _account(data)
    if not client or not account:
        return []
    out = [(client, here, t, account, number, None, KERBEROS, source)]
    if number == 4769:
        service = str(_value(data.get("ServiceName")) or "").strip()
        cls, _, host = service.rpartition("/") if "/" in service else ("", "", service)
        host = host.split(":")[0].rstrip("$")
        if host and host.lower() != "krbtgt":
            out.append((client, ("name", host), t, account, number, None,
                        SERVICE_PORTS.get(cls.split("/")[0].lower(), set()), source))
    return out


def records(path):
    """The event records of a .evtx file or a JSON-lines file, as dicts."""
    with open(path, "rb") as fh:
        head = fh.read(4096)
    found = kind(head)
    if found == "evtx":
        try:
            from evtx import PyEvtxParser
        except ImportError:                          # pragma: no cover (a dependency)
            raise SourceError(f"{path}: reading .evtx needs the evtx package")
        try:
            for rec in PyEvtxParser(str(path), skip_errors=True).records_json():
                try:
                    yield json.loads(rec["data"])
                except (ValueError, KeyError, TypeError):
                    continue
        except (RuntimeError, OSError) as e:
            raise SourceError(f"{path}: not a readable .evtx file ({e})")
    elif found == "jsonl":
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("{"):
                    try:
                        yield json.loads(line)
                    except ValueError:
                        continue
    else:
        raise SourceError(f"{path}: not a Windows event log ThreatBridge reads")


def read_file(path):
    """Every claim the events of one file make."""
    out, n = [], 0
    for rec in records(path):
        n += 1
        out.extend(claims_of(rec, path))
    if not n:      # the evtx library skips what it can't read: a damaged file reads as empty
        log.warning("%s: no event records could be read", path)
    return out


def _short(name):
    return name.strip().lower().rstrip(".").rstrip("$").split(".")[0]


class Names:
    """Host names to addresses at a time: from DHCP holdings (dhcp.holdings), the capture's DNS
    answers ({name: {ip: [first, last]}}), and a hosts file ({name: [ip]}). A full name matches
    the same full name; any name also matches by its first label."""

    def __init__(self, holdings=(), dns=None, hosts=None):
        self.leases, self.dns, self.hosts = {}, {}, {}
        for ip, _mac, name, start, until, _src in holdings:
            if name:
                self.leases.setdefault(_short(name), []).append((start, until, ip))
        for name, seen in (dns or {}).items():
            for ip, (first, last) in seen.items():
                self.dns.setdefault(name.lower().rstrip("."), []).append((first, last, ip))
                self.dns.setdefault(_short(name), []).append((first, last, ip))
        for name, ips in (hosts or {}).items():
            self.hosts[name.lower()] = list(ips)
            self.hosts.setdefault(_short(name), list(ips))

    def resolve(self, name, t):
        """The address `name` had at time t, or None when nothing says or the sources disagree."""
        full, short = name.strip().lower().rstrip(".").rstrip("$"), _short(name)
        held = {ip for start, until, ip in self.leases.get(short, []) if start <= t and (until is None or t <= until)}
        if len(held) == 1:
            return held.pop()
        if held:
            return None
        for key in (full, short):
            seen = self.dns.get(key, [])
            if seen:
                ips = {ip for _, _, ip in seen}
                if len(ips) == 1:
                    return ips.pop()
                nearest = min(seen, key=lambda s: 0 if s[0] <= t <= s[1] else min(abs(t - s[0]), abs(t - s[1])))
                return nearest[2]
            ips = self.hosts.get(key)
            if ips and len(set(ips)) == 1:
                return ips[0]
        return None


def read_hosts(path):
    """A hosts file ("address name [alias ...]", # comments) as {name: [address]}."""
    out = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.split("#", 1)[0].split()
            if len(parts) >= 2:
                try:
                    ip = str(ipaddress.ip_address(parts[0]))
                except ValueError:
                    continue
                for name in parts[1:]:
                    out.setdefault(name.lower(), []).append(ip)
    return out


def match(claims, names, flows_between, tolerance):
    """Labels: [(src, dst, start, sport, dport, proto, account, event, logon type, time, host,
    source)], one per claim that finds its flow; claims that put the same account on the same
    flow by the same event (Windows often logs a logon twice at once) give one label, the
    earliest. `flows_between(src, dst, lo, hi)` gives the flows src -> dst that started in
    [lo, hi] as (start, sport, dport, proto)."""
    out = {}
    for src, dst, t, account, event, logon_type, ports, source in sorted(claims, key=lambda c: c[2]):
        host = next((end[1] for end in (src, dst) if isinstance(end, tuple)), "")
        ends = [names.resolve(end[1], t) if isinstance(end, tuple) else end for end in (src, dst)]
        if None in ends or ends[0] == ends[1]:
            continue
        found = flows_between(ends[0], ends[1], t - tolerance, t + tolerance)
        if not found:
            continue
        best = min(found, key=lambda f: (f[2] not in ports, abs(f[0] - t)))
        label = (ends[0], ends[1], best[0], best[1], best[2], best[3], account, event, logon_type)
        out.setdefault(label, label + (t, host, source))
    return list(out.values())
