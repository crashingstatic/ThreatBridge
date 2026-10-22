"""Input validation, time-window math and query builders (Elasticsearch + SOC OQL)."""
import ipaddress
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

DIRECTIONS = {
    # "in":  who connected TO the host, looking back in time from the anchor
    # "out": who the host connected TO, looking forward in time from the anchor
    "in": "inbound-past",
    "out": "outbound-future",
}

_WINDOW_RE = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


class ValidationError(ValueError):
    pass


def parse_ip(value):
    if not isinstance(value, str):
        raise ValidationError(f"invalid IP address: {value!r}")
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        raise ValidationError(f"invalid IP address: {value!r}")
    if getattr(addr, "scope_id", None):   # "%..." can hold any text, quotes included
        raise ValidationError(f"IPv6 scope not allowed: {value!r}")
    return str(addr)


def parse_direction(value):
    value = (value or "").strip().lower()
    if value not in DIRECTIONS:
        raise ValidationError("direction must be 'in' or 'out'")
    return value


def parse_window(value):
    m = _WINDOW_RE.match(value if isinstance(value, str) else "")
    if not m:
        raise ValidationError(f"invalid window {value!r}; use e.g. 30m, 24h, 7d")
    try:
        return timedelta(**{_UNITS[m.group(2).lower()]: int(m.group(1))})
    except OverflowError:
        raise ValidationError(f"window {value!r} is too large")


def parse_time(value):
    """Parse an ISO-8601 timestamp or epoch (s/ms). Empty means now. Returns aware UTC."""
    if value is None or str(value).strip() == "":
        return datetime.now(timezone.utc)
    value = str(value).strip()
    if re.fullmatch(r"\d{10,13}(\.\d+)?", value):
        num = float(value)
        if num > 1e11:
            num /= 1000.0
        return datetime.fromtimestamp(num, timezone.utc)
    iso = value.replace("Z", "+00:00").replace("z", "+00:00")
    # Trim sub-microsecond precision (Zeek/ES can emit nanoseconds).
    iso = re.sub(r"(\.\d{6})\d+", r"\1", iso)
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        raise ValidationError(f"invalid timestamp: {value!r}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fmt_time(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def time_range(anchor, direction, window):
    if direction == "in":
        return anchor - window, anchor
    return anchor, anchor + window


def clip(start, end, bounds):
    """[start, end] narrowed to the analyst's range `bounds` (lo, hi); None is an open end.
    The result is empty (start > end) when they don't overlap."""
    lo, hi = bounds
    return (max(start, lo) if lo else start), (min(end, hi) if hi else end)


ORDERS = ("top", "bottom")


def parse_order(value):
    value = (value or "top").strip().lower()
    if value not in ORDERS:
        raise ValidationError("order must be 'top' or 'bottom'")
    return value


def parse_network(value):
    """Validate an exclude entry (IP or CIDR); returns canonical string."""
    if not isinstance(value, str) or "%" in value:   # no IPv6 scopes (see parse_ip)
        raise ValidationError(f"invalid IP/CIDR: {value!r}")
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        raise ValidationError(f"invalid IP/CIDR: {value!r}")
    return str(net.network_address) if net.num_addresses == 1 else str(net)


_LABEL = r"(?!-)[a-z0-9_-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(\*\.)?(?:{_LABEL}\.)*{_LABEL}$")


def parse_exclude(value):
    """An exclude entry: IP, CIDR, or domain name (optionally "*.suffix"); canonical string."""
    if not isinstance(value, str):
        raise ValidationError(f"invalid IP, CIDR or domain name: {value!r}")
    try:
        return parse_network(value)
    except ValidationError:
        pass
    raw = value.strip()
    name = raw.lower().rstrip(".")
    if len(name) > 253 or not _DOMAIN_RE.match(name) or name.rsplit(".", 1)[-1].isdigit():
        raise ValidationError(f"invalid IP, CIDR or domain name: {raw!r}")
    if name.startswith("*.") and "." not in name[2:]:
        raise ValidationError("a wildcard needs at least two labels, e.g. *.example.com")
    return name


def is_domain(entry):
    """True for a domain-name exclude entry, False for an IP/CIDR."""
    try:
        ipaddress.ip_network(entry, strict=False)
        return False
    except ValueError:
        return True


def peer_fields(cfg, direction):
    """(field matching the host, field holding the peer)."""
    return (cfg.f_dst, cfg.f_src) if direction == "in" else (cfg.f_src, cfg.f_dst)


def es_filter(cfg, ip, direction, start, end, exclude, peers=None):
    match_field, peer_field = peer_fields(cfg, direction)
    filters = [
        {"term": {match_field: ip}},
        {"range": {cfg.f_ts: {"gte": fmt_time(start), "lte": fmt_time(end),
                              "format": "strict_date_optional_time"}}},
    ]
    if cfg.datasets:
        filters.append({"terms": {cfg.f_dataset: cfg.datasets}})
    if peers is not None:
        filters.append({"terms": {peer_field: list(peers)}})
    # term on an ip field accepts CIDR notation.
    must_not = [{"term": {peer_field: e}} for e in exclude]
    return {"bool": {"filter": filters, "must_not": must_not}}


def _detail_aggs(cfg):
    return {
        "first_seen": {"min": {"field": cfg.f_ts}},
        "last_seen": {"max": {"field": cfg.f_ts}},
        "ports": {"terms": {"field": cfg.f_dport, "size": 5}},
    }


def es_top_body(cfg, ip, direction, start, end, limit, exclude):
    """Most frequent peers, with details, plus approximate distinct-peer count."""
    _, peer_field = peer_fields(cfg, direction)
    return {
        "size": 0,
        "track_total_hits": False,
        "query": es_filter(cfg, ip, direction, start, end, exclude),
        "aggs": {
            "peers": {
                "terms": {"field": peer_field, "size": limit, "order": {"_count": "desc"}},
                "aggs": _detail_aggs(cfg),
            },
            "distinct": {"cardinality": {"field": peer_field}},
        },
    }


def es_scan_body(cfg, ip, direction, start, end, exclude, page_size, after=None):
    """One page of an exact per-peer count scan (composite aggregation)."""
    _, peer_field = peer_fields(cfg, direction)
    comp = {"size": page_size, "sources": [{"peer": {"terms": {"field": peer_field}}}]}
    if after:
        comp["after"] = after
    return {
        "size": 0,
        "track_total_hits": False,
        "query": es_filter(cfg, ip, direction, start, end, exclude),
        "aggs": {"scan": {"composite": comp}},
    }


def es_details_body(cfg, ip, direction, start, end, peers, exclude):
    """Details (first/last seen, ports) for an explicit list of peers."""
    _, peer_field = peer_fields(cfg, direction)
    return {
        "size": 0,
        "track_total_hits": False,
        "query": es_filter(cfg, ip, direction, start, end, exclude, peers=peers),
        "aggs": {"peers": {"terms": {"field": peer_field, "size": max(len(peers), 1)},
                           "aggs": _detail_aggs(cfg)}},
    }


def es_flows_body(cfg, src, dst, start, end, offset, size):
    """One page of the flows src -> dst that started within [start, end], oldest first."""
    return {
        "from": offset,
        "size": size,
        "track_total_hits": True,
        "sort": [{cfg.f_ts: "asc"}],
        "_source": False,
        "fields": [{"field": cfg.f_ts, "format": "strict_date_optional_time"}, cfg.f_sport,
                   cfg.f_dport, cfg.f_proto, cfg.f_duration, *cfg.f_packets, *cfg.f_bytes],
        "query": es_filter(cfg, src, "out", start, end, [], peers=[dst]),
    }


def _oql_value(ip):
    # Values are already validated IPs; quote so IPv6 colons are not parsed as syntax.
    return '"' + ip + '"'


def _oql_time(cfg, since, until):
    """' AND @timestamp:[since TO until]', open ends as *; empty when there are no limits."""
    if not cfg.pivot_time_clause or (since is None and until is None):
        return ""
    since, until = (f'"{fmt_time(t)}"' if t else "*" for t in (since, until))
    return f" AND {cfg.f_ts}:[{since} TO {until}]"


def soc_pivot_query(cfg, a, b, until=None, since=None):
    """OQL for every conversation between a and b (either direction), optionally limited to
    [since, until]."""
    s, d = cfg.f_src, cfg.f_dst
    q = (f"(({s}:{_oql_value(a)} AND {d}:{_oql_value(b)}) OR "
         f"({s}:{_oql_value(b)} AND {d}:{_oql_value(a)}))")
    q += _oql_time(cfg, since, until)
    q += f" | groupby {s} {d} {cfg.f_dport}"
    return q


def soc_host_query(cfg, ip, since=None, until=None):
    v = _oql_value(ip)
    return (f"({cfg.f_src}:{v} OR {cfg.f_dst}:{v}){_oql_time(cfg, since, until)}"
            f" | groupby {cfg.f_src} {cfg.f_dst} {cfg.f_dport}")


def soc_url(cfg, query):
    return cfg.soc_url + cfg.soc_path.replace("{query}", quote(query, safe=""))
