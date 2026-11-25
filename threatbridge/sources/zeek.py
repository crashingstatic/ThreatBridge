"""Zeek logs as evidence (D36): conn.log -> flows, dns.log -> DNS answers.

Either of Zeek's formats: tab-separated with its header (#separator, #fields, ...), the default,
or JSON lines (LogAscii::use_json), keys dotted ("id.orig_h") or nested ({"id": {"orig_h"}}),
times as epoch seconds or ISO 8601. Plain or gzip-compressed, as Zeek archives its logs
(conn.12:00:00-13:00:00.log.gz). dhcp.log is read by dhcp.py; other Zeek logs (http, ssl,
files, ...) are recognised and left out.

conn.log: each record is a flow, oriented as Zeek oriented it (originator -> responder). It
starts at ts and ends duration later; its packets are orig_pkts + resp_pkts and its bytes
orig_ip_bytes + resp_ip_bytes (the IP layer, as captures count them). Its protocol is the
service Zeek named (of several, the first that isn't an authentication helper: ntlm, gssapi),
else that of a well-known port, as for NetFlow. Refused connections (conn_state REJ) are left
out, as from captures and in Security Onion; ICMP flows have no ports, as from captures.

dns.log: a NOERROR answer maps its query and each name among its answers (the CNAME chain) to
each address among them, at its time, as a capture's DNS answers do.
"""
import gzip
import ipaddress
import json
import logging
import os
import re
from datetime import datetime

from ..model import Flow
from .. import protocols

log = logging.getLogger(__name__)

GZIP = b"\x1f\x8b"
HELPERS = {"ntlm", "gssapi"}          # authentication inside another protocol's connection
REFUSED = {"REJ"}


def head(path, size):
    """The first `size` bytes of a file, decompressed if it is gzip."""
    with open(path, "rb") as fh:
        start = fh.read(size)
    if not start.startswith(GZIP):
        return start
    try:
        with gzip.open(path, "rb") as fh:
            return fh.read(size)
    except (OSError, EOFError):
        return b""


def open_text(path):
    """A log file as text, decompressed if it is gzip."""
    with open(path, "rb") as fh:
        compressed = fh.read(2) == GZIP
    if compressed:
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def _json_path(text):
    """Which log a JSON-lines head is ("conn", "dns", "other"), or None if it isn't Zeek's."""
    first = text.lstrip().split("\n", 1)[0]
    try:
        rec = json.loads(first)
    except ValueError:
        rec = None
    if isinstance(rec, dict):
        keys = set(rec) | {f"id.{k}" for k in (rec.get("id") or {})} if isinstance(rec.get("id"), dict) else set(rec)
        if rec.get("_path") in ("conn", "dns"):
            return rec["_path"]
        if "id.orig_h" not in keys:
            return None
        if "conn_state" in keys or {"orig_pkts", "resp_pkts", "orig_ip_bytes"} & keys:
            return "conn"
        if "query" in keys or "answers" in keys:
            return "dns"
        return "other"
    # A first line longer than the head: tell by the keys it shows.
    if '"id.orig_h"' not in text:
        return None
    if '"conn_state"' in text or '"orig_pkts"' in text:
        return "conn"
    if '"query"' in text:
        return "dns"
    return "other"


def kind(start):
    """"conn", "dns" or "other" (another Zeek log) for a file's first bytes (decompressed),
    else None."""
    text = start.decode("utf-8", errors="replace")
    m = re.search(r"^#path\t(\S+)", text, re.M)
    if m and text.startswith("#separator"):
        return m.group(1) if m.group(1) in ("conn", "dns") else "other"
    if text.lstrip().startswith("{"):
        return _json_path(text)
    return None


def _unescape(value):
    """A header value as Zeek escapes it: "\\x09" is a tab."""
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), value)


def records(path):
    """The records of a Zeek log as dicts, fields that are unset left out; a set or vector
    field (e.g. answers) as a list."""
    sep, set_sep, unset, empty, fields, types = "\t", ",", "-", "(empty)", None, {}
    with open_text(path) as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if not line:
                continue
            if line.startswith("{"):
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict):
                    if isinstance(rec.get("id"), dict):          # nested: {"id": {"orig_h": ...}}
                        rec.update({f"id.{k}": v for k, v in rec.pop("id").items()})
                    yield rec
                continue
            if line.startswith("#"):
                if line.startswith("#separator "):
                    sep = _unescape(line.split(" ", 1)[1])
                    continue
                name, _, value = line[1:].partition(sep)
                if name == "set_separator":
                    set_sep = _unescape(value)
                elif name == "unset_field":
                    unset = value
                elif name == "empty_field":
                    empty = value
                elif name == "fields":
                    fields = value.split(sep)
                elif name == "types":
                    types = dict(zip(fields or [], value.split(sep)))
                continue
            if not fields:
                continue
            rec = {}
            for name, value in zip(fields, line.split(sep)):
                if value == unset:
                    continue
                if types.get(name, "").startswith(("set[", "vector[")):
                    rec[name] = [] if value == empty else value.split(set_sep)
                else:
                    rec[name] = "" if value == empty else value
            yield rec


def _time(value):
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


def _address(value):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _int(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _sum(*values):
    known = [v for v in map(_int, values) if v is not None]
    return sum(known) if known else None


def service(named, proto, dport, sport):
    """A flow's protocol from Zeek's service field (module docstring)."""
    names = protocols.split(", ".join(named) if isinstance(named, list) else named)
    main = next((n for n in names if n not in HELPERS), names[0] if names else None)
    return main or protocols.name(proto, 0, dport, sport)


def conn_flows(path):
    """(flows, refused left out, records unreadable) from one conn.log."""
    out, refused, bad, name = [], 0, 0, path
    for rec in records(path):
        src, dst, ts = _address(rec.get("id.orig_h")), _address(rec.get("id.resp_h")), _time(rec.get("ts"))
        proto = str(rec.get("proto") or "").lower()
        if not src or not dst or ts is None or not proto:
            bad += 1
            continue
        if rec.get("conn_state") in REFUSED:
            refused += 1
            continue
        if proto == "icmp":
            sport = dport = 0
        else:
            sport, dport = _int(rec.get("id.orig_p")), _int(rec.get("id.resp_p"))
        duration = _time(rec.get("duration")) or 0.0
        out.append(Flow(src, dst, sport, dport, proto, ts, ts + duration,
                        _sum(rec.get("orig_pkts"), rec.get("resp_pkts")),
                        _sum(rec.get("orig_ip_bytes"), rec.get("resp_ip_bytes")),
                        name, service(rec.get("service") or "", proto, dport, sport)))
    return out, refused, bad


def _name(value):
    return str(value).rstrip(".").lower()


def dns_answers(path, dns):
    """Add one dns.log's answers to `dns` ({name: {ip: [first, last]}})."""
    for rec in records(path):
        rcode = rec.get("rcode_name", rec.get("rcode"))
        answers, query, ts = rec.get("answers"), rec.get("query"), _time(rec.get("ts"))
        if str(rcode) not in ("NOERROR", "0") or not answers or not query or ts is None:
            continue
        if isinstance(answers, str):
            answers = answers.split(",")
        ips = {a for a in map(_address, answers) if a}
        names = {_name(query)} | {_name(a) for a in answers if not _address(a) and a}
        names.discard("")
        for name in names:
            known = dns.setdefault(name, {})
            for ip in ips:
                if ip in known:
                    known[ip][0], known[ip][1] = min(known[ip][0], ts), max(known[ip][1], ts)
                else:
                    known[ip] = [ts, ts]


def read_conn(paths, workers, stage, in_order):
    """Flows from conn.log files, up to `workers` read at once (in_order from workers.py)."""
    flows, refused, bad = [], 0, 0
    files = sorted(paths)
    for i, (path, (found, left, unreadable)) in enumerate(in_order(conn_flows, files, workers), 1):
        flows.extend(found)
        refused, bad = refused + left, bad + unreadable
        log.info("%s: %d connections", path, len(found))
        stage(os.path.getsize(path), f"Zeek log {i} of {len(files)}, {len(flows):,} connections")
    if refused:
        log.info("%d refused connection(s) left out", refused)
    if bad:
        log.warning("%d Zeek conn record(s) without addresses, a time or a protocol left out", bad)
    return flows
