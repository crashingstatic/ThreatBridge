"""DHCP leases: which machine (MAC address, host name) held which address when (D27).

Read from, as evidence files found among the others:
- Windows DHCP server audit logs (DhcpSrvLog-*.log): times are the server's local time, read in
  TB_DHCP_TIMEZONE (an IANA zone name, default UTC); the log records no lease length.
- ISC dhcpd leases files (dhcpd.leases): each lease's start, end, MAC address and host name.
- Zeek's dhcp.log, tab-separated or JSON lines.
And from the DHCP messages in packet captures (pcap.py passes them in as observations).

Each source gives observations: (address, MAC, host name or None, time, held until or None,
kind), kind "assign" or "release". holdings() turns them into who held each address when.
"""
import csv
import io
import ipaddress
import json
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ..model import SourceError

ASSIGN, RELEASE = "assign", "release"
SNIFF = 4096        # bytes read to tell what a file is

# Windows DHCP audit log event IDs: a lease given or renewed; a lease that ended.
_WIN_ASSIGN = {"10", "11", "20", "21"}
_WIN_END = {"12", "16", "17", "18"}
_ISC_TIME = re.compile(r"(?:\d\s+)?(\d{4})/(\d{2})/(\d{2})\s+(\d{2}):(\d{2}):(\d{2})")


def kind(head):
    """"windows", "isc" or "zeek" for the first bytes of a DHCP log, else None."""
    text = _decode(head)
    if "Microsoft DHCP Service Activity Log" in text[:600]:
        return "windows"
    if "#path\tdhcp" in text or (text.lstrip().startswith("{") and '"assigned_addr"' in text):
        return "zeek"
    if "dhcpd.leases" in text[:600] or re.search(r"^lease\s+[0-9a-fA-F.:]+\s*\{", text, re.M):
        return "isc"
    return None


def _decode(data):
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


def _address(value):
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError):
        return None


def _mac(value):
    """A MAC address as aa:bb:cc:dd:ee:ff, from any of the usual spellings; None if it isn't one."""
    digits = re.sub(r"[^0-9a-fA-F]", "", value or "").lower()
    if len(digits) < 12:
        return None
    digits = digits[:12]               # Windows may append padding for longer hardware addresses
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def _name(value):
    value = (value or "").strip().strip('"')
    return value or None


def read_windows(text, tz):
    """Observations from a Windows DHCP server audit log, its times in zone `tz`."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith("ID,Date,Time")), None)
    if start is None:
        return []
    out = []
    for row in csv.reader(io.StringIO("\n".join(lines[start + 1:]))):
        if len(row) < 7 or row[0].strip() not in _WIN_ASSIGN | _WIN_END:
            continue
        ip, mac = _address(row[4]), _mac(row[6])
        if not ip or not mac:
            continue
        try:
            local = datetime.strptime(f"{row[1].strip()} {row[2].strip()}", "%m/%d/%y %H:%M:%S")
        except ValueError:
            continue
        t = local.replace(tzinfo=tz).timestamp()
        out.append((ip, mac, _name(row[5]), t, None, ASSIGN if row[0].strip() in _WIN_ASSIGN else RELEASE))
    return out


def _isc_time(value):
    """An ISC lease time: "W YYYY/MM/DD HH:MM:SS" (UTC), "epoch N", or "never" (None)."""
    value = value.strip()
    if value.startswith("epoch"):
        return float(value.split()[1])
    m = _ISC_TIME.match(value)
    if not m:
        return None
    return datetime(*map(int, m.groups()), tzinfo=timezone.utc).timestamp()


def read_isc(text):
    """Observations from an ISC dhcpd leases file: each lease from its start to its end."""
    out = []
    for m in re.finditer(r"^lease\s+([0-9a-fA-F.:]+)\s*\{(.*?)^\}", text, re.M | re.S):
        ip, body = _address(m.group(1)), m.group(2)
        fields = {}
        for line in body.splitlines():
            line = line.split(";")[0].strip()          # "starts epoch 1714575600; # Wed May ..."
            for key in ("starts", "ends", "hardware ethernet", "client-hostname"):
                if line.startswith(key + " "):
                    fields.setdefault(key, line[len(key):].strip())
        start, mac = fields.get("starts"), _mac(fields.get("hardware ethernet"))
        if not ip or not mac or not start or _isc_time(start) is None:
            continue
        out.append((ip, mac, _name(fields.get("client-hostname")), _isc_time(start),
                    _isc_time(fields.get("ends", "never")), ASSIGN))
    return out


def _zeek_time(value):
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _zeek_record(rec):
    """Observations from one Zeek dhcp.log record (a dict, unset fields missing or "-")."""
    def get(key):
        value = rec.get(key)
        return None if value in (None, "-", "(empty)", "") else value
    types = get("msg_types") or []
    if isinstance(types, str):
        types = types.split(",")
    t, mac = _zeek_time(get("ts")), _mac(get("mac"))
    if t is None or not mac:
        return []
    name = _name(get("host_name")) or _name(get("client_fqdn"))
    out = []
    assigned = _address(get("assigned_addr") or "")
    if "ACK" in types and assigned:
        lease = get("lease_time")
        try:
            until = t + float(lease) if lease is not None else None
        except (TypeError, ValueError):
            until = None
        out.append((assigned, mac, name, t, until, ASSIGN))
    released = _address(get("client_addr") or "")
    if "RELEASE" in types and released:
        out.append((released, mac, name, t, None, RELEASE))
    return out


def read_zeek(text):
    """Observations from Zeek's dhcp.log, tab-separated (with its #fields line) or JSON lines."""
    out, fields = [], None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        elif line.startswith("#"):
            continue
        elif line.lstrip().startswith("{"):
            try:
                out.extend(_zeek_record(json.loads(line)))
            except ValueError:
                continue
        elif fields:
            out.extend(_zeek_record(dict(zip(fields, line.split("\t")))))
    return out


NAME = "name"     # an observation kind: a client's host name, from its own DHCP messages


def record_message(payload, ts, out, source=""):
    """Add what one DHCP message (a UDP payload) tells to `out`: an acknowledgement assigns its
    address for its lease time, a release ends one, and a client's request names it."""
    import dpkt   # here: dhcp.py otherwise needs no packet library
    try:
        msg = dpkt.dhcp.DHCP(payload)
        opts = dict(msg.opts)
    except (dpkt.Error, ValueError, TypeError, IndexError):
        return
    kind_ = opts.get(dpkt.dhcp.DHCP_OPT_MSGTYPE, b"")[:1]
    mac = _mac(msg.chaddr[:min(msg.hln, 16)].hex()) if msg.hln >= 6 else None
    if not kind_ or not mac:
        return
    kind_ = kind_[0]
    name = opts.get(dpkt.dhcp.DHCP_OPT_HOSTNAME)
    name = _name(name.decode("ascii", "replace")) if name else None
    if kind_ == dpkt.dhcp.DHCPACK and msg.yiaddr:
        lease = opts.get(dpkt.dhcp.DHCP_OPT_LEASE_SEC, b"")
        until = ts + int.from_bytes(lease[:4], "big") if len(lease) >= 4 else None
        out.append((str(ipaddress.IPv4Address(msg.yiaddr)), mac, name, ts, until, ASSIGN, source))
    elif kind_ == dpkt.dhcp.DHCPRELEASE and msg.ciaddr:
        out.append((str(ipaddress.IPv4Address(msg.ciaddr)), mac, name, ts, None, RELEASE, source))
    elif name and kind_ in (dpkt.dhcp.DHCPREQUEST, 1):               # REQUEST, DISCOVER
        out.append((None, mac, name, ts, None, NAME, source))


def named(observations):
    """The assignments and releases of `observations`, those without a host name given the one
    their client last sent before (or, failing that, after) them."""
    names = {}
    for _, mac, name, t, _, what, *_ in observations:
        if what == NAME:
            names.setdefault(mac, []).append((t, name))
    out = []
    for obs in observations:
        ip, mac, name, t, until, what, *rest = obs
        if what == NAME:
            continue
        if name is None and mac in names:
            before = [n for s, n in sorted(names[mac]) if s <= t]
            name = before[-1] if before else sorted(names[mac])[0][1]
        out.append((ip, mac, name, t, until, what, *rest))
    return out


def timezone_named(name):
    """The zone Windows DHCP logs are read in (TB_DHCP_TIMEZONE)."""
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as e:
        raise SourceError(f"TB_DHCP_TIMEZONE: unknown time zone {name!r} ({e}); on Windows, pip install tzdata")


def read_file(path, tz):
    """Observations from one DHCP log file (kind() says which), each with its path."""
    with open(path, "rb") as fh:
        data = fh.read()
    if data.startswith(b"\x1f\x8b"):                  # Zeek's archived dhcp.log.gz
        import gzip
        data = gzip.decompress(data)
    found = kind(data[:SNIFF])
    text = _decode(data)
    readers = {"windows": lambda: read_windows(text, tz), "isc": lambda: read_isc(text), "zeek": lambda: read_zeek(text)}
    if found not in readers:
        raise SourceError(f"{path}: not a DHCP log ThreatBridge reads")
    return [obs + (path,) for obs in readers[found]()]


def holdings(observations):
    """[(address, MAC, host name, from, until or None, sources)]: who held each address when.

    A machine holds an address from its first assignment and keeps it through renewals and
    re-assignments, up to the latest lease end seen; the holding ends at a release or expiry,
    or when another machine is given the address. With no lease end known (Windows logs), it
    lasts until one of those, or stays open."""
    by_ip = {}
    for ip, mac, name, t, until, what, *source in observations:
        by_ip.setdefault(ip, []).append((t, 0 if what == ASSIGN else 1, mac, name, until, source[0] if source else ""))
    out = []
    for ip, events in by_ip.items():
        current = None          # [mac, name, from, until, sources]
        for t, release, mac, name, until, source in sorted(events, key=lambda e: e[:2]):
            if release:
                if current and current[0] == mac:
                    current[3] = t if current[3] is None else min(current[3], t)
                    out.append((ip, *current[:4], sorted(current[4])))
                    current = None
                continue
            if current and (current[0] != mac or (current[3] is not None and t > current[3])):
                if current[0] != mac and (current[3] is None or current[3] > t):
                    current[3] = t                     # another machine took the address
                out.append((ip, *current[:4], sorted(current[4])))
                current = None
            if current is None:
                current = [mac, name, t, until, {source}]
            else:
                current[1] = current[1] or name
                current[3] = None if until is None and current[3] is None else max(
                    x for x in (current[3], until, t) if x is not None)
                current[4].add(source)
        if current:
            out.append((ip, *current[:4], sorted(current[4])))
    return sorted(out, key=lambda h: (h[0], h[3]))


def at(leases, t):
    """The holding of an address (from `leases`, one address's holdings) that covers time t."""
    for h in leases:
        if h[3] <= t and (h[4] is None or t <= h[4]):
            return h
    return None

