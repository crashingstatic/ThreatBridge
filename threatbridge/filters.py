"""Filter expressions: which flows the map shows (D17).

    (SMB || TLS) && sport 42000
    NOT dport 53 AND bytes > 10000
    host 10.0.0.0/8 OR proto icmp

parse() reads one expression; combine() joins the analyst's list of them with AND. Each is kept
as its canonical text and as a tree of simple tests on a flow's values ("core"), which
matches() evaluates in Python, to_sql() translates for the case store and to_es() for
Elasticsearch, so the three agree.

A flow here is a mapping with "src", "dst", "sport", "dport", "proto" ("tcp", "udp", "icmp"
or a number), "start" (epoch seconds), "duration" (seconds), "packets", "bytes" and
"protocols" (service names, protocols.py); any but src, dst, start and protocols may be None,
and a comparison on a missing value is false.
"""
import ipaddress
import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import NamedTuple

from . import protocols
from .query import ValidationError, parse_time

MAX_LENGTH = 500      # characters in one expression
MAX_FILTERS = 20      # expressions applied at once
MAX_DEPTH = 50        # nested parentheses and NOTs

FIELDS = ("sport", "dport", "port", "src", "dst", "host", "proto", "packets", "bytes",
          "duration", "time")
_NUMBERS = {"sport": 65535, "dport": 65535, "port": 65535, "packets": None, "bytes": None}
_EITHER = {"port": ("sport", "dport"), "host": ("src", "dst")}
_COMPARISONS = ("==", "!=", "<", ">", "<=", ">=")
_AND, _OR, _NOT = ("AND", "&&"), ("OR", "||"), ("NOT", "!")
TRANSPORTS = ("tcp", "udp", "icmp")

# Each protocol name the map shows, with the service names it stands for (aliases included).
NAMES = {}
for _service, _name in protocols.DISPLAY.items():
    NAMES[_name] = [_service] + sorted(a for a, s in protocols.ALIASES.items() if s == _service)
# Words that look like a protocol but aren't one, and what to write instead.
_HINTS = {"https": "TLS", **{s: protocols.display_name(s) for s in protocols.DISPLAY},
          **{a: protocols.display_name(s) for a, s in protocols.ALIASES.items()}}
_OTHER_SERVICE = re.compile(r"[A-Z0-9][A-Z0-9_-]*")
_TOKEN = re.compile(r"\s*(?:(&&|\|\||==|!=|<=|>=|[()<>!])|([^\s()!&|=<>]+))")
_INT = re.compile(r"\d{1,15}")
_DECIMAL = re.compile(r"\d{1,15}(?:\.\d{1,9})?")


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class FilterError(ValidationError):
    pass


class Filter(NamedTuple):
    """One expression: `text`, canonical, and `core`, the tree of tests (see the module doc)."""
    text: str
    core: tuple


# ---- reading an expression ----------------------------------------------------------------

def _tokens(text):
    out, pos = [], 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            if text[pos:].strip():
                bad = text[pos:].lstrip()[0]
                raise FilterError(f"at character {len(text) - len(text[pos:].lstrip()) + 1}: "
                                  f"unexpected {bad!r}")
            break
        out.append((m.group(1) or m.group(2), m.start(m.lastindex) + 1))
        pos = m.end()
    return out


class _Parser:
    def __init__(self, text):
        self.tokens = _tokens(text)
        self.i = 0
        self.depth = 0

    def peek(self):
        return self.tokens[self.i][0] if self.i < len(self.tokens) else None

    def where(self):
        if self.i < len(self.tokens):
            return f"at character {self.tokens[self.i][1]}"
        return "at the end"

    def take(self):
        token = self.tokens[self.i][0]
        self.i += 1
        return token

    def fail(self, message):
        raise FilterError(f"{self.where()}: {message}")

    def expression(self):
        node = self.either()
        token = self.peek()
        if token is not None:
            if token == ")":
                self.fail("a ')' without its '('")
            if token.lower() in ("and", "or", "not"):
                self.fail(f"operators are in capitals: write {token.upper()}")
            self.fail(f"expected AND or OR before {token!r}")
        return node

    def either(self):
        items = [self.both()]
        while self.peek() in _OR:
            self.take()
            items.append(self.both())
        return items[0] if len(items) == 1 else ("or", items)

    def both(self):
        items = [self.negated()]
        while self.peek() in _AND:
            self.take()
            items.append(self.negated())
        return items[0] if len(items) == 1 else ("and", items)

    def negated(self):
        if self.peek() in _NOT:
            self.take()
            return ("not", self.nested(self.negated))
        return self.term()

    def nested(self, parse):
        self.depth += 1
        if self.depth > MAX_DEPTH:
            self.fail(f"more than {MAX_DEPTH} levels of parentheses or NOT")
        node = parse()
        self.depth -= 1
        return node

    def term(self):
        """A term: an expression in parentheses, a comparison, or a protocol."""
        token = self.peek()
        if token is None:
            self.fail("expected a protocol, a field or '('")
        if token == "(":
            self.take()
            node = self.nested(self.either)
            if self.peek() != ")":
                self.fail("expected ')'")
            self.take()
            return ("group", node)
        if token in _COMPARISONS or token in _AND + _OR + (")",):
            self.fail(f"expected a protocol, a field or '(' instead of {token!r}")
        if token in FIELDS:
            return self.comparison()
        return self.protocol()

    def comparison(self):
        """field [op] value, op == if left out."""
        field = self.take()
        op = "=="
        if self.peek() in _COMPARISONS:
            op = self.take()
        value = self.peek()
        if value is None or value in _COMPARISONS or value in ("(", ")", "!", "&&", "||"):
            self.fail(f"{field} needs a value")
        where = self.where()
        self.take()
        try:
            return ("cmp", field, op, value, _value(field, op, value))
        except FilterError as e:
            raise FilterError(f"{where}: {e}")

    def protocol(self):
        """A protocol as the map names it. A near miss (another case, another name for it, a
        field or operator in capitals) is refused with what to write instead."""
        where, word = self.where(), self.take()
        if word in NAMES:
            return ("service", word, NAMES[word])
        low = word.lower()
        hint = next((name for name in NAMES if name.lower() == low), None)
        if hint:
            raise FilterError(f"{where}: protocol names are case-sensitive: write {hint}")
        if low in _HINTS:
            raise FilterError(f"{where}: write {_HINTS[low]} for {word}")
        if low in FIELDS:
            raise FilterError(f"{where}: fields are in lower case: write {low}")
        if low in ("and", "or", "not"):
            raise FilterError(f"{where}: operators are in capitals: write {word.upper()}")
        if _OTHER_SERVICE.fullmatch(word) and re.search("[A-Z]", word):
            return ("service", word, [low])         # another service Zeek names, in capitals
        raise FilterError(f"{where}: unknown term {word!r}: write a protocol as the map shows "
                          "it (e.g. SMB, TLS, Kerberos), or a field (sport, dport, port, src, dst, "
                          "host, proto, packets, bytes, duration, time)")


def _number(text, field):
    """An int (or, for duration, a float) for `field`, checked against its range."""
    pattern = _DECIMAL if field == "duration" else _INT
    if not pattern.fullmatch(text):
        what = "a number of seconds" if field == "duration" else "a whole number"
        raise FilterError(f"{field} takes {what}, not {text!r}")
    value = float(text) if field == "duration" else int(text)
    top = _NUMBERS.get(field)
    if top is not None and value > top:
        raise FilterError(f"{field} is at most {top}, not {text}")
    return value


def _value(field, op, text):
    """The value of a comparison, checked: a number or (lo, hi) range, an IP network, a
    transport, or a time in epoch milliseconds: a branch per kind of field."""
    if field in ("src", "dst", "host"):
        if op not in ("==", "!="):
            raise FilterError(f"{field} takes == or != (inside or outside an address or CIDR)")
        if "%" in text:
            raise FilterError(f"{field}: no IPv6 scopes")
        try:
            return ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise FilterError(f"{field} takes an IP address or CIDR, not {text!r}")
    if field == "proto":
        if op not in ("==", "!="):
            raise FilterError("proto takes == or !=")
        if text in TRANSPORTS or (_INT.fullmatch(text) and int(text) <= 255):
            return text
        raise FilterError(f"proto is tcp, udp, icmp or an IP protocol number, not {text!r}")
    if field == "time":                         # ISO-8601, or epoch seconds or milliseconds
        try:
            if re.match(r"\d{4}-\d\d-\d\d|\d{10,13}(\.\d+)?$", text):
                return (parse_time(text) - _EPOCH) // timedelta(milliseconds=1)
        except (ValidationError, OverflowError):
            pass
        raise FilterError(f"time takes an ISO-8601 time (UTC unless it says), not {text!r}")
    if "-" in text.strip("-"):
        lo, hi = text.split("-", 1)
        if op not in ("==", "!="):
            raise FilterError(f"a range takes == or != (inside or outside), not {op}")
        lo, hi = _number(lo, field), _number(hi, field)
        if lo > hi:
            raise FilterError(f"the range {text} is backwards")
        return (lo, hi)
    return _number(text, field)


# ---- the tests a comparison stands for ------------------------------------------------------

def _core(node):
    """The tests a parsed node stands for: a comparison becomes a range, net or proto test,
    != a NOT, and port or host a test of either end."""
    kind = node[0]
    if kind == "group":
        return _core(node[1])
    if kind in ("and", "or"):
        return (kind, [_core(n) for n in node[1]])
    if kind == "not":
        return ("not", _core(node[1]))
    if kind == "service":
        return node
    _, field, op, _, value = node
    if op == "!=":
        return ("not", _core(("cmp", field, "==", None, value)))
    if field in _EITHER:                    # either end; with != (above), neither
        return ("or", [_core(("cmp", f, op, None, value)) for f in _EITHER[field]])
    if field in ("src", "dst"):
        return ("net", field, value)
    if field == "proto":
        return ("proto", value)
    if field == "time":                     # a time stands for its millisecond
        lo, hi = value, value + 1
        return {"==": ("range", "time", lo, False, hi, True),
                "<": ("range", "time", None, False, lo, True),
                "<=": ("range", "time", None, False, hi, True),
                ">": ("range", "time", hi, False, None, False),
                ">=": ("range", "time", lo, False, None, False)}[op]
    lo, hi = value if isinstance(value, tuple) else (value, value)
    return {"==": ("range", field, lo, False, hi, False),
            "<": ("range", field, None, False, lo, True),
            "<=": ("range", field, None, False, hi, False),
            ">": ("range", field, lo, True, None, False),
            ">=": ("range", field, lo, False, None, False)}[op]


def _text(node):
    """The parsed node written back canonically: operators in capitals, == spelled out, a
    network as its network address."""
    kind = node[0]
    if kind == "group":
        return f"({_text(node[1])})"
    if kind in ("and", "or"):
        return f" {kind.upper()} ".join(_text(n) for n in node[1])
    if kind == "not":
        return f"NOT {_text(node[1])}"
    if kind == "service":
        return node[1]
    _, field, op, raw, value = node
    if isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        raw = str(value.network_address) if value.num_addresses == 1 else str(value)
    return f"{field} {op} {raw}"


def parse(text):
    """One expression as a Filter; FilterError (a ValidationError) says what's wrong, where."""
    if not isinstance(text, str) or not text.strip():
        raise FilterError("a filter needs an expression, e.g. SMB AND dport 445")
    if len(text) > MAX_LENGTH:
        raise FilterError(f"a filter is at most {MAX_LENGTH} characters")
    node = _Parser(text).expression()
    return Filter(_text(node), _core(node))


def combine(texts):
    """The analyst's filters, all of which a flow must pass: a Filter, or None for none."""
    if texts is None:
        return None
    if not isinstance(texts, list) or not all(isinstance(t, str) for t in texts):
        raise FilterError("filters are a list of expressions")
    if len(texts) > MAX_FILTERS:
        raise FilterError(f"at most {MAX_FILTERS} filters at once")
    found = []
    for i, text in enumerate(texts, 1):
        try:
            found.append(parse(text))
        except FilterError as e:
            raise FilterError(f"filter {i} ({text.strip()[:60]!r}) {e}" if len(texts) > 1 else str(e))
    if not found:
        return None
    if len(found) == 1:
        return found[0]
    return Filter(" AND ".join(f"({f.text})" for f in found), ("and", [f.core for f in found]))


# ---- testing a flow -------------------------------------------------------------------------

@lru_cache(maxsize=65536)
def _address(ip):
    try:
        return ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None


def _in(value, lo, lo_open, hi, hi_open):
    """Whether value is within the bounds (None: no bound; open: the bound itself is out)."""
    if value is None:
        return False
    if lo is not None and (value <= lo if lo_open else value < lo):
        return False
    if hi is not None and (value >= hi if hi_open else value > hi):
        return False
    return True


def matches(core, flow):
    """Whether `flow` passes the tests `core` (a Filter's core): a branch per kind of node, as
    in to_sql and to_es."""
    kind = core[0]
    if kind == "and":
        return all(matches(c, flow) for c in core[1])
    if kind == "or":
        return any(matches(c, flow) for c in core[1])
    if kind == "not":
        return not matches(core[1], flow)
    if kind == "service":
        return any(p in core[2] for p in flow["protocols"])
    if kind == "proto":
        return flow.get("proto") is not None and str(flow["proto"]) == core[1]
    if kind == "net":
        addr = _address(flow.get(core[1]))
        return addr is not None and addr in core[2]
    _, field, lo, lo_open, hi, hi_open = core
    if field == "time":                      # in seconds, as the case store compares them
        return _in(flow.get("start"), _seconds(lo), lo_open, _seconds(hi), hi_open)
    return _in(flow.get(field), lo, lo_open, hi, hi_open)


def _seconds(ms):
    return None if ms is None else ms / 1000.0


# ---- the case store (SQLite) ------------------------------------------------------------------

def in_network(ip, network):
    """SQLite function ip_in_net(ip, network): 1 if the address is in the network."""
    addr = _address(ip)
    return int(addr is not None and addr in _network(network))


@lru_cache(maxsize=1024)
def _network(text):
    return ipaddress.ip_network(text)


def to_sql(core, prefix=""):
    """(SQL condition, parameters) on the flow table's columns, each prefixed with `prefix`
    (e.g. "f."): a branch per kind of node, as in matches(). It needs ip_in_net (in_network)
    registered on the connection."""
    kind = core[0]
    if kind in ("and", "or"):
        parts = [to_sql(c, prefix) for c in core[1]]
        return (f" {kind.upper()} ".join(f"({sql})" for sql, _ in parts),
                [p for _, params in parts for p in params])
    if kind == "not":
        sql, params = to_sql(core[1], prefix)
        return f"NOT ({sql})", params
    if kind == "service":
        return (f"coalesce({prefix}service IN ({', '.join('?' * len(core[2]))}), 0)", list(core[2]))
    if kind == "proto":
        return f"coalesce({prefix}proto = ?, 0)", [core[1]]
    if kind == "net":
        return f"ip_in_net({prefix}{core[1]}, ?)", [str(core[2])]
    _, field, lo, lo_open, hi, hi_open = core
    column = {"duration": f"({prefix}end_ts - {prefix}start_ts)", "time": f"{prefix}start_ts"}.get(
        field, prefix + field)
    if field == "time":
        lo, hi = _seconds(lo), _seconds(hi)
    tests, params = [f"{column} IS NOT NULL"], []
    if lo is not None:
        tests.append(f"{column} {'>' if lo_open else '>='} ?")
        params.append(lo)
    if hi is not None:
        tests.append(f"{column} {'<' if hi_open else '<='} ?")
        params.append(hi)
    return " AND ".join(tests), params


# ---- Elasticsearch ------------------------------------------------------------------------

_SUM_SCRIPT = (
    "double t = 0; boolean any = false; "
    "for (String f : params.fields) { if (doc.containsKey(f) && doc[f].size() > 0) "
    "{ t += doc[f].value; any = true; } } "
    "if (!any) { return false; } "
    "if (params.lo != null && (params.lo_open ? t <= params.lo : t < params.lo)) { return false; } "
    "if (params.hi != null && (params.hi_open ? t >= params.hi : t > params.hi)) { return false; } "
    "return true;")


def _all(items):
    return {"bool": {"filter": items}}


def _any(items):
    return {"bool": {"should": items, "minimum_should_match": 1}}


def _none(item):
    return {"bool": {"must_not": [item]}}


def _no_service(cfg):
    """Records Zeek named no protocol in."""
    f = cfg.f_service
    return _any([_none({"exists": {"field": f}}), {"terms": {f: ["", "-"]}}])


def _service(cfg, keys):
    if not cfg.f_service:     # protocols unknown (TB_FIELD_SERVICE=): only ICMP and Unknown
        if "icmp" in keys:
            return {"term": {cfg.f_proto: "icmp"}}
        if protocols.UNKNOWN in keys:
            return _none({"term": {cfg.f_proto: "icmp"}})
        return {"match_none": {}}
    f, tests = cfg.f_service, []
    for key in keys:
        if key == "icmp":
            tests.append(_all([_no_service(cfg), {"term": {cfg.f_proto: "icmp"}}]))
        elif key == protocols.UNKNOWN:
            tests.append(_all([_no_service(cfg), _none({"term": {cfg.f_proto: "icmp"}})]))
        # Zeek lists several as "smb,ntlm,gssapi" in one value.
        tests.append({"term": {f: {"value": key, "case_insensitive": True}}})
        tests += [{"wildcard": {f: {"value": pattern, "case_insensitive": True}}}
                  for pattern in (f"{key},*", f"*,{key}", f"*,{key},*")]
    return _any(tests)


def to_es(core, cfg):
    """An Elasticsearch query clause for `core`, on the configured fields: a branch per kind of
    node, as in matches()."""
    kind = core[0]
    if kind == "and":
        return _all([to_es(c, cfg) for c in core[1]])
    if kind == "or":
        return _any([to_es(c, cfg) for c in core[1]])
    if kind == "not":
        return _none(to_es(core[1], cfg))
    if kind == "service":
        return _service(cfg, core[2])
    if kind == "proto":
        return {"term": {cfg.f_proto: core[1]}}
    if kind == "net":
        return {"term": {cfg.f_src if core[1] == "src" else cfg.f_dst: str(core[2])}}
    _, field, lo, lo_open, hi, hi_open = core
    if field in ("packets", "bytes"):       # both directions' counts, added up
        fields = cfg.f_packets if field == "packets" else cfg.f_bytes
        return {"script": {"script": {"source": _SUM_SCRIPT, "lang": "painless", "params": {
            "fields": list(fields), "lo": lo, "lo_open": lo_open, "hi": hi, "hi_open": hi_open}}}}
    name = {"sport": cfg.f_sport, "dport": cfg.f_dport, "duration": cfg.f_duration,
            "time": cfg.f_ts}[field]
    bounds = {}
    if lo is not None:
        bounds["gt" if lo_open else "gte"] = lo
    if hi is not None:
        bounds["lt" if hi_open else "lte"] = hi
    if field == "time":
        bounds["format"] = "epoch_millis"
    return {"range": {name: bounds}}
