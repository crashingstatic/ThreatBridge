"""Input validation, time-window math and query builders (Elasticsearch + SOC OQL)."""
import ipaddress
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlencode

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
    value = "" if value is None else str(value).strip()
    if not value:
        return datetime.now(timezone.utc)
    if re.fullmatch(r"\d{10,13}(\.\d+)?", value):      # epoch: 13 digits are milliseconds
        num = float(value)
        return datetime.fromtimestamp(num / 1000.0 if num > 1e11 else num, timezone.utc)
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
    # A name whose last label is a number is a mistyped address, not a domain.
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


def es_filter(cfg, ip, direction, start, end, exclude, peers=None, scope=None):
    """The records a query counts: the host's (every host's if `ip` is None). `scope`: a clause
    they must also match (the analyst's filters, backends.es_scope), or None."""
    match_field, peer_field = peer_fields(cfg, direction)
    filters = [{"range": {cfg.f_ts: {"gte": fmt_time(start), "lte": fmt_time(end),
                                     "format": "strict_date_optional_time"}}}]
    if ip is not None:
        filters.insert(0, {"term": {match_field: ip}})
    if cfg.datasets:
        filters.append({"terms": {cfg.f_dataset: cfg.datasets}})
    if peers is not None:
        filters.append({"terms": {peer_field: list(peers)}})
    if scope is not None:
        filters.append(scope)
    # term on an ip field accepts CIDR notation.
    must_not = [{"term": {peer_field: e}} for e in exclude]
    if cfg.f_conn_state:
        # Refused connections (Zeek's REJ): a single port scan would swamp the map. A match
        # query finds the value whether the field is mapped as keyword or as text.
        must_not.append({"match": {cfg.f_conn_state: "REJ"}})
    return {"bool": {"filter": filters, "must_not": must_not}}


def _aggs_only(query, aggs):
    """A search that returns only aggregations."""
    return {"size": 0, "track_total_hits": False, "query": query, "aggs": aggs}


def _detail_aggs(cfg):
    aggs = {
        "first_seen": {"min": {"field": cfg.f_ts}},
        "last_seen": {"max": {"field": cfg.f_ts}},
        "ports": {"terms": {"field": cfg.f_dport, "size": 5}},
    }
    if cfg.f_service:
        aggs["protocols"] = _protocol_aggs(cfg, 20)
    return aggs


def _protocol_aggs(cfg, size):
    """The protocols Zeek recognized; records where it named none ("") are told apart by their
    transport: ICMP, or unknown. Without Zeek's names (TB_FIELD_SERVICE=), the transports only."""
    transports = {"terms": {"field": cfg.f_proto, "size": 5}}
    if not cfg.f_service:
        return transports
    return {"terms": {"field": cfg.f_service, "size": size, "missing": ""}, "aggs": {"transports": transports}}


def es_protocols_body(cfg, start, end, scope=None):
    """How many records name each protocol in [start, end], every host's (D20)."""
    return _aggs_only(es_filter(cfg, None, "out", start, end, [], scope=scope), {"protocols": _protocol_aggs(cfg, 500)})


def es_top_body(cfg, ip, direction, start, end, limit, exclude, scope=None):
    """Most frequent peers, with details, plus approximate distinct-peer count."""
    _, peer_field = peer_fields(cfg, direction)
    return _aggs_only(es_filter(cfg, ip, direction, start, end, exclude, scope=scope), {
        "peers": {"terms": {"field": peer_field, "size": limit, "order": {"_count": "desc"}},
                  "aggs": _detail_aggs(cfg)},
        "distinct": {"cardinality": {"field": peer_field}}})


def es_scan_body(cfg, ip, direction, start, end, exclude, page_size, after=None, scope=None):
    """One page of an exact per-peer count scan (composite aggregation)."""
    _, peer_field = peer_fields(cfg, direction)
    comp = {"size": page_size, "sources": [{"peer": {"terms": {"field": peer_field}}}]}
    if after:
        comp["after"] = after
    return _aggs_only(es_filter(cfg, ip, direction, start, end, exclude, scope=scope), {"scan": {"composite": comp}})


def es_details_body(cfg, ip, direction, start, end, peers, exclude, scope=None):
    """Details (first/last seen, ports) for an explicit list of peers."""
    _, peer_field = peer_fields(cfg, direction)
    return _aggs_only(es_filter(cfg, ip, direction, start, end, exclude, peers=peers, scope=scope), {
        "peers": {"terms": {"field": peer_field, "size": max(len(peers), 1)}, "aggs": _detail_aggs(cfg)}})


def es_flows_body(cfg, src, dst, start, end, offset, size, scope=None):
    """One page of the flows src -> dst that started within [start, end], oldest first."""
    return {
        "from": offset,
        "size": size,
        "track_total_hits": True,
        "sort": [{cfg.f_ts: "asc"}],
        "_source": False,
        "fields": [{"field": cfg.f_ts, "format": "strict_date_optional_time"}, cfg.f_sport,
                   cfg.f_dport, cfg.f_proto, cfg.f_duration, *cfg.f_packets, *cfg.f_bytes,
                   *([cfg.f_service] if cfg.f_service else [])],
        "query": es_filter(cfg, src, "out", start, end, [], peers=[dst], scope=scope),
    }


DNS_ADDRESSES = 1000   # addresses per domain entry from Zeek's DNS records


def es_dns_body(cfg, entries):
    """The addresses each domain entry ("name" or "*.suffix", subdomains only) resolved to in
    the sensors' DNS records, with when each was first and last seen: one request for all."""
    def match(entry):
        kind = "wildcard" if entry.startswith("*.") else "term"
        return {kind: {cfg.f_dns_query: {"value": entry, "case_insensitive": True}}}
    filters = [{"exists": {"field": cfg.f_dns_ip}}]
    if cfg.dns_datasets:
        filters.append({"terms": {cfg.f_dataset: cfg.dns_datasets}})
    return _aggs_only({"bool": {"filter": filters}}, {"entries": {
        "filters": {"filters": {e: match(e) for e in entries}},
        "aggs": {"ips": {"terms": {"field": cfg.f_dns_ip, "size": DNS_ADDRESSES},
                         "aggs": {"first": {"min": {"field": cfg.f_ts}}, "last": {"max": {"field": cfg.f_ts}}}}}}})


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


_ES_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,512}$")


def parse_es_id(value):
    """An Elasticsearch document ID, as Security Onion generates them."""
    if not isinstance(value, str) or not _ES_ID_RE.match(value):
        raise ValidationError(f"invalid document ID: {value!r}")
    return value


def soc_pcap_url(cfg, doc_id, start):
    """SOC's own PCAP action for a connection log: SOC has the sensor extract the packets."""
    return f"{cfg.soc_url}/joblookup?" + urlencode({"esid": doc_id, "time": start})
