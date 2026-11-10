"""Filter expressions (D17): reading them, what they match, and that the case store's SQL and
Elasticsearch's query match exactly the same flows as the Python test."""
import fnmatch
import ipaddress
import json
import os
import random
from datetime import datetime, timezone

import pytest

from threatbridge import filters as F
from threatbridge.backends import ElasticBackend
from threatbridge.config import Config
from threatbridge.model import Flow
from threatbridge.query import fmt_time
from threatbridge.store import FlowStore

T = 1_714_564_800.0


# ---- reading expressions ------------------------------------------------------------------

@pytest.mark.parametrize("text,canonical", [
    ("(SMB || TLS) && sport 42000", "(SMB OR TLS) AND sport == 42000"),
    ("(SMB OR TLS) AND sport == 42000", "(SMB OR TLS) AND sport == 42000"),
    ("!DNS", "NOT DNS"),
    ("NOT NOT DNS", "NOT NOT DNS"),
    ("sport 40000-42000", "sport == 40000-42000"),
    ("port!=445", "port != 445"),
    ("src 10.0.0.5/24", "src == 10.0.0.0/24"),          # a CIDR as its network
    ("host 10.0.0.5/32", "host == 10.0.0.5"),
    ("dst != 2001:DB8::/32", "dst != 2001:db8::/32"),
    ("proto icmp OR proto 47", "proto == icmp OR proto == 47"),
    ("packets >= 10 AND bytes < 100 AND duration <= 1.5", "packets >= 10 AND bytes < 100 AND duration <= 1.5"),
    ("time > 2024-05-01T12:00:00Z", "time > 2024-05-01T12:00:00Z"),
    ("Kerberos OR DCE-RPC OR MSSQL OR VNC OR FTP OR Unknown OR ICMP", None),
    ("QUIC OR MQTT_V5", "QUIC OR MQTT_V5"),              # other Zeek services, in capitals
    ("SMB  ", "SMB"),                                    # spaces after the last term
    ("sport 5-5", "sport == 5-5"),                       # a range of one
    ("proto 255", "proto == 255"),
    (" OR ".join(["SMB"] * 72), None),                   # 500 characters, the most there may be
])
def test_expressions_read(text, canonical):
    assert F.parse(text).text == (canonical or text)


def test_precedence_not_then_and_then_or():
    assert F.parse("SMB OR DNS AND HTTP").core == F.parse("SMB OR (DNS AND HTTP)").core
    assert F.parse("NOT SMB AND DNS").core == F.parse("(NOT SMB) AND DNS").core
    assert F.parse("SMB || DNS && !HTTP").core == F.parse("SMB OR (DNS AND (NOT HTTP))").core
    assert F.parse("(SMB OR DNS) AND HTTP").core != F.parse("SMB OR DNS AND HTTP").core


@pytest.mark.parametrize("text,error", [
    ("", "a filter needs an expression"),
    ("   ", "a filter needs an expression"),
    ("smb", "at character 1: protocol names are case-sensitive: write SMB"),
    ("KERBEROS", "write Kerberos"),
    ("SSL", "write TLS for SSL"),
    ("HTTPS", "write TLS for HTTPS"),
    ("https", "write TLS for https"),
    ("FTP-DATA", "write FTP for FTP-DATA"),
    ("DCE_RPC", "write DCE-RPC for DCE_RPC"),
    ("SPORT 5", "fields are in lower case: write sport"),
    ("SMB and DNS", "at character 5: operators are in capitals: write AND"),
    ("sport", "at the end: sport needs a value"),
    ("sport ==", "at the end: sport needs a value"),
    ("sport x", "at character 7: sport takes a whole number, not 'x'"),
    ("sport -5", "sport takes a whole number"),
    ("sport 70000", "sport is at most 65535"),
    ("sport 5-3", "the range 5-3 is backwards"),
    ("sport < 5-9", "a range takes == or !="),
    ("duration abc", "duration takes a number of seconds"),
    ("src < 10.0.0.1", "src takes == or !="),
    ("host 10.0.0.300", "host takes an IP address or CIDR"),
    ("src fe80::1%eth0", "no IPv6 scopes"),
    ("proto TCP", "proto is tcp, udp, icmp or an IP protocol number"),
    ("proto > 6", "proto takes == or !="),
    ("time 5", "time takes an ISO-8601 time"),
    ("time 2024-13-01", "time takes an ISO-8601 time"),
    ("(SMB", "at the end: expected ')'"),
    ("SMB)", "at character 4: a ')' without its '('"),
    ("SMB DNS", "at character 5: expected AND or OR before 'DNS'"),
    ("SMB & DNS", "at character 5: unexpected '&'"),
    ("SMB = DNS", "unexpected '='"),
    ("SMB AND", "at the end: expected a protocol"),
    ("AND SMB", "at character 1: expected a protocol, a field or '(' instead of 'AND'"),
    ("== 5", "instead of '=='"),
    ("()", "instead of ')'"),
    ("445", "unknown term '445'"),
    ("42000-43000", "unknown term"),
    ("10.0.0.5", "unknown term"),
    ("x" * (F.MAX_LENGTH + 1), "at most 500 characters"),
    ("(" * (F.MAX_DEPTH + 1) + "SMB" + ")" * (F.MAX_DEPTH + 1), "more than 50 levels"),
    ("NOT " * (F.MAX_DEPTH + 1) + "SMB", "more than 50 levels"),
])
def test_invalid_expressions_say_what_and_where(text, error):
    with pytest.raises(F.FilterError) as e:
        F.parse(text)
    assert error in str(e.value)


def test_the_deepest_nesting_allowed():
    assert F.parse("(" * F.MAX_DEPTH + "SMB" + ")" * F.MAX_DEPTH).text.count("(") == F.MAX_DEPTH


def test_nesting_counts_only_what_encloses_a_term():
    deep = "(" * F.MAX_DEPTH + "SMB" + ")" * F.MAX_DEPTH
    assert F.parse(" AND ".join(["(SMB)", "NOT DNS", "(HTTP)", deep])).text.count("(") == F.MAX_DEPTH + 2
    with pytest.raises(F.FilterError, match="more than 50 levels"):
        F.parse("(SMB) AND (DNS) AND (" + deep + ")")


@pytest.mark.parametrize("text,error", [
    ("", "a filter needs an expression, e.g. SMB AND dport 445"),
    ("x" * (F.MAX_LENGTH + 1), "a filter is at most 500 characters"),
    ("sport (", "at character 7: sport needs a value"),
    ("sport )", "at character 7: sport needs a value"),
    ("sport !", "at character 7: sport needs a value"),
    ("sport &&", "at character 7: sport needs a value"),
    ("sport ||", "at character 7: sport needs a value"),
    ("SMB or DNS", "at character 5: operators are in capitals: write OR"),
    ("SMB not DNS", "at character 5: operators are in capitals: write NOT"),
    ("and SMB", "at character 1: operators are in capitals: write AND"),
    ("Or SMB", "at character 1: operators are in capitals: write OR"),
    ("not SMB", "at character 1: operators are in capitals: write NOT"),
    ("proto > 6", "at character 9: proto takes == or !="),
    ("proto 256", "at character 7: proto is tcp, udp, icmp or an IP protocol number, not '256'"),
    ("sport -5", "at character 7: sport takes a whole number, not '-5'"),
    ("sport 5-", "at character 7: sport takes a whole number, not '5-'"),
    ("sport X-5", "at character 7: sport takes a whole number, not 'X'"),
    ("sport 1-2-3", "at character 7: sport takes a whole number, not '2-3'"),
    ("sport 1.5", "at character 7: sport takes a whole number, not '1.5'"),
    ("445", "at character 1: unknown term '445': write a protocol as the map shows it (e.g. SMB, TLS, "
            "Kerberos), or a field (sport, dport, port, src, dst, host, proto, packets, bytes, duration, time)"),
])
def test_error_messages_in_full(text, error):
    with pytest.raises(F.FilterError) as e:
        F.parse(text)
    assert str(e.value) == error


def test_values_keep_their_type_and_times_their_millisecond():
    assert type(F.parse("bytes 10").core[2]) is int and type(F.parse("duration 10").core[2]) is float
    assert F.parse("time 2024-05-01T12:00:00.1239Z").core == F.parse("time 2024-05-01T12:00:00.123Z").core




def test_several_filters_combine_with_and():
    assert F.combine(None) is None and F.combine([]) is None
    one = F.combine(["SMB"])
    assert one.text == "SMB"
    both = F.combine(["SMB OR DNS", "sport 42000"])
    assert both.text == "(SMB OR DNS) AND (sport == 42000)"
    assert F.matches(both.core, flow_dict(protocols=["dns"], sport=42000))
    assert not F.matches(both.core, flow_dict(protocols=["dns"], sport=1))
    with pytest.raises(F.FilterError, match=r"filter 2 \('smb'\) at character 1"):
        F.combine(["SMB", "smb"])
    with pytest.raises(F.FilterError) as e:                 # one filter: just what's wrong
        F.combine(["smb"])
    assert str(e.value) == "at character 1: protocol names are case-sensitive: write SMB"
    with pytest.raises(F.FilterError) as e:                 # a long one, cut short
        F.combine(["SMB", "  " + "x" * 70])
    assert str(e.value).startswith(f"filter 2 ('{'x' * 60}') at character 3: unknown term")
    with pytest.raises(F.FilterError, match="at most 20 filters"):
        F.combine(["SMB"] * (F.MAX_FILTERS + 1))
    assert F.combine(["SMB"] * F.MAX_FILTERS) is not None
    with pytest.raises(F.FilterError, match="a list of expressions"):
        F.combine("SMB")
    with pytest.raises(F.FilterError, match="a list of expressions"):
        F.combine([1])


def test_the_sql_a_filter_stands_for():
    assert F.to_sql(F.parse("NOT (SMB OR sport 5)").core, "f.") == (
        "NOT ((coalesce(f.service IN (?), 0)) OR (f.sport IS NOT NULL AND f.sport >= ? AND f.sport <= ?))",
        ["smb", 5, 5])
    assert F.to_sql(F.parse("sport 5").core) == ("sport IS NOT NULL AND sport >= ? AND sport <= ?", [5, 5])


# ---- the vocabulary clients are given (D20) -------------------------------------------------

EXAMPLES = {"port": ("445", "40000-42000"), "count": ("10", "1-5"), "seconds": ("1.5", "0.5-2"),
            "address": ("10.0.0.0/8", None), "transport": ("tcp", None), "time": ("2024-05-01T12:00:00Z", None)}


def parses(text):
    try:
        F.parse(text)
        return True
    except F.FilterError:
        return False


def test_the_vocabulary_says_what_the_parser_takes():
    v = F.vocabulary()
    assert [f["name"] for f in v["fields"]] == list(F.FIELDS)
    assert set(v["kinds"]) == {f["kind"] for f in v["fields"]} == set(EXAMPLES)
    for field in v["fields"]:
        one, span = EXAMPLES[field["kind"]]
        for op in ("==", "!=", "<", ">", "<=", ">="):
            assert parses(f"{field['name']} {op} {one}") == (op in field["comparisons"]), (field, op)
        assert parses(f"{field['name']} {span or '1-2'}") == field["ranges"], field
        assert field["either_end"] == (field["name"] in ("port", "host"))
    for name in v["protocols"]:
        assert parses(name), name
    assert set(v["protocols"]) == set(F.NAMES)
    assert v["operators"] == {"not": ["NOT", "!"], "and": ["AND", "&&"], "or": ["OR", "||"]}
    for spelling in sum(v["operators"].values(), []):
        assert parses(f"SMB {spelling} DNS" if spelling not in ("NOT", "!") else f"{spelling} SMB")


def test_the_grammar_is_the_one_in_the_api_reference():
    with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "API.md"),
              encoding="utf-8") as fh:
        assert F.GRAMMAR in fh.read()
    assert F.vocabulary()["grammar"] == F.GRAMMAR


# ---- what they match ----------------------------------------------------------------------

def flow_dict(**kw):
    out = {"src": "10.0.0.5", "dst": "10.0.0.9", "sport": 50000, "dport": 445, "proto": "tcp",
           "start": T, "duration": 1.0, "packets": 10, "bytes": 1000, "protocols": ["smb"]}
    out.update(kw)
    return out


@pytest.mark.parametrize("text,flow,expect", [
    ("SMB", {}, True), ("DNS", {}, False), ("Unknown", {"protocols": ["unknown"]}, True),
    ("Kerberos", {"protocols": ["krb_tcp"]}, True),      # aliases count
    ("FTP", {"protocols": ["ftp-data"]}, True),
    ("TLS", {"protocols": ["ssl"]}, True),
    ("QUIC", {"protocols": ["quic"]}, True),
    ("sport 50000", {}, True), ("sport 49999", {}, False), ("dport 445", {}, True),
    ("sport 49000-50000", {}, True), ("sport 50000-50001", {}, True), ("sport 50001-50002", {}, False),
    ("sport != 49000-50000", {}, False),
    ("port 445", {}, True), ("port 50000", {}, True), ("port 80", {}, False),
    ("port != 445", {}, False),                          # neither end: 445 is one
    ("port != 80", {}, True),
    ("port < 1024", {}, True), ("port > 50000", {}, False), ("port >= 50000", {}, True),
    ("dport < 445", {}, False), ("dport <= 445", {}, True), ("dport > 444", {}, True), ("dport >= 446", {}, False),
    ("src 10.0.0.5", {}, True), ("src 10.0.0.0/24", {}, True), ("src 10.0.1.0/24", {}, False),
    ("dst != 10.0.0.0/24", {}, False), ("host 10.0.0.9", {}, True), ("host != 10.0.0.9", {}, False),
    ("host != 10.0.0.7", {}, True), ("src ::1", {}, False),
    ("host 2001:db8::/32", {"src": "2001:db8::5"}, True),
    ("proto tcp", {}, True), ("proto udp", {}, False), ("proto != udp", {}, True),
    ("proto 47", {"proto": "47"}, True),
    ("packets 10", {}, True), ("packets > 10", {}, False), ("bytes >= 1000 AND bytes <= 1000", {}, True),
    ("duration > 0.5", {}, True), ("duration < 1", {}, False), ("duration <= 1", {}, True),
    ("duration == 0.5-1.5", {}, True),
    # A missing value fails every comparison on it; NOT of that passes.
    ("packets > 0", {"packets": None}, False), ("NOT packets > 0", {"packets": None}, True),
    ("duration < 5", {"duration": None}, False), ("sport 0-65535", {"sport": None}, False),
    ("proto tcp", {"proto": None}, False), ("src 0.0.0.0/0", {"src": "not-an-ip"}, False),
    # time is the flow's start, to the millisecond.
    ("time 2024-05-01T12:00:00.123Z", {"start": T + 0.1239}, True),
    ("time 2024-05-01T12:00:00.123Z", {"start": T + 0.124}, False),
    ("time 2024-05-01T12:00:00.123Z", {"start": T + 0.1229}, False),
    ("time < 2024-05-01T12:00:00.123Z", {"start": T + 0.1229}, True),
    ("time < 2024-05-01T12:00:00.123Z", {"start": T + 0.123}, False),
    ("time <= 2024-05-01T12:00:00.123Z", {"start": T + 0.1239}, True),
    ("time > 2024-05-01T12:00:00.123Z", {"start": T + 0.1239}, False),
    ("time > 2024-05-01T12:00:00.123Z", {"start": T + 0.124}, True),
    ("time >= 2024-05-01T12:00:00.123Z", {"start": T + 0.123}, True),
    ("time != 2024-05-01T14:00:00.123+02:00", {"start": T + 0.123}, False),     # an offset is honoured
    ("time >= 1714564800", {"start": T}, True),
    # The user story's example: one flow is SMB or TLS and has source port 42000.
    ("(SMB || TLS) && sport 42000", {"sport": 42000}, True),
    ("(SMB || TLS) && sport 42000", {"sport": 42000, "protocols": ["ssl"]}, True),
    ("(SMB || TLS) && sport 42000", {"sport": 42000, "protocols": ["dns"]}, False),
    ("(SMB || TLS) && sport 42000", {}, False),
])
def test_what_expressions_match(text, flow, expect):
    assert F.matches(F.parse(text).core, flow_dict(**flow)) is expect


# ---- the store's SQL and Elasticsearch's query agree with matches() ------------------------

PEERS = ["10.0.0.5", "10.0.0.9", "10.0.1.7", "192.168.5.5", "2001:db8::5", "2001:db8:1::9"]
PORTS = [0, 22, 53, 80, 443, 445, 3389, 42000, 50000, 65535]
SERVICES = ["smb", "ssl", "dns", "http", "krb", "dce_rpc", "ftp", "icmp", "unknown", "quic"]


def flow_values(f):
    """A case flow (model.Flow) as matches() reads it."""
    return {"src": f.src, "dst": f.dst, "sport": f.sport, "dport": f.dport, "proto": f.proto,
            "start": f.start, "duration": f.end - f.start, "packets": f.packets,
            "bytes": f.bytes, "protocols": [f.service]}


def random_flow(rng):
    start = T + rng.choice([0, 0.123, 0.1239, 0.124, 1, 60, 3600]) + rng.choice([0, 0.0005])
    return Flow(rng.choice(PEERS), rng.choice(PEERS), rng.choice(PORTS), rng.choice(PORTS),
                rng.choice(["tcp", "udp", "icmp", "47"]), start, start + rng.choice([0, 0.5, 1, 1.5, 30]),
                rng.choice([1, 2, 10, 11, 1000]), rng.choice([60, 1000, 1001, 10 ** 6]), "x.pcap",
                rng.choice(SERVICES))


def random_term(rng):
    kind = rng.random()
    if kind < 0.3:
        return rng.choice(["SMB", "TLS", "DNS", "HTTP", "Kerberos", "DCE-RPC", "FTP", "ICMP", "Unknown", "QUIC"])
    field = rng.choice(F.FIELDS)
    if field in ("src", "dst", "host"):
        value = rng.choice(["10.0.0.5", "10.0.0.0/24", "10.0.0.0/8", "2001:db8::/32", "192.168.5.5", "::/0"])
        return f"{field} {rng.choice(['', '== ', '!= '])}{value}"
    if field == "proto":
        return f"proto {rng.choice(['', '== ', '!= '])}{rng.choice(['tcp', 'udp', 'icmp', '47', '6'])}"
    if field == "time":
        value = fmt_time(datetime.fromtimestamp(T + rng.choice([0, 0.123, 0.124, 1, 60]), timezone.utc))
        return f"time {rng.choice(['', '== ', '!= ', '< ', '<= ', '> ', '>= '])}{value}"
    pool = {"duration": ["0", "0.5", "1", "1.5", "30"], "packets": ["1", "2", "10", "11", "1000"],
            "bytes": ["60", "1000", "1001", "1000000"]}.get(field, [str(p) for p in PORTS])
    if rng.random() < 0.25:
        a, b = sorted(rng.sample(pool, 2), key=float)
        return f"{field} {rng.choice(['', '== ', '!= '])}{a}-{b}"
    return f"{field} {rng.choice(['', '== ', '!= ', '< ', '<= ', '> ', '>= '])}{rng.choice(pool)}"


def random_expression(rng, depth=0):
    roll = rng.random()
    if depth > 2 or roll < 0.4:
        return random_term(rng)
    if roll < 0.55:
        return f"{rng.choice(['NOT ', '!'])}{random_expression(rng, depth + 1)}"
    if roll < 0.7:
        return f"({random_expression(rng, depth + 1)})"
    op = rng.choice(["AND", "&&", "OR", "||"])
    return f"{random_expression(rng, depth + 1)} {op} {random_expression(rng, depth + 1)}"


@pytest.fixture(scope="module")
def stored(tmp_path_factory):
    rng = random.Random(7)
    flows = [random_flow(rng) for _ in range(400)]
    store = FlowStore(str(tmp_path_factory.mktemp("filters") / "case.db"))
    store.write(flows, {}, [])
    return store, flows


@pytest.mark.parametrize("seed", range(300))
def test_the_store_matches_the_same_flows(stored, seed):
    store, flows = stored
    rng = random.Random(seed)
    f = F.combine([random_expression(rng) for _ in range(rng.randint(1, 2))])
    sql, params = F.to_sql(f.core, "f.")
    got = sorted(r for (r,) in store._db().execute(f"SELECT rowid FROM flow AS f WHERE {sql}", params))
    want = [i for i, fl in enumerate(flows, 1) if F.matches(f.core, flow_values(fl))]
    assert got == want, f.text


# A small interpreter of the Elasticsearch query clauses to_es() writes, over Security Onion
# conn records, to check they mean what matches() means.

def es_values(doc, field):
    v = doc.get(field)
    return [] if v is None else (v if isinstance(v, list) else [v])


def es_bool(body, doc):
    assert set(body) <= {"filter", "should", "must_not", "minimum_should_match"}, body
    ok = all(es_eval(c, doc) for c in body.get("filter", []))
    if "should" in body:
        need = body.get("minimum_should_match", 0 if "filter" in body else 1)
        ok = ok and sum(es_eval(c, doc) for c in body["should"]) >= need
    return ok and not any(es_eval(c, doc) for c in body.get("must_not", []))


def es_script(body, doc):
    """The packets/bytes sum script, as its painless source says."""
    script, = body.values()
    assert set(body) == {"script"} and set(script) == {"source", "lang", "params"}, body
    assert script["lang"] == "painless" and script["source"] == F._SUM_SCRIPT
    p = script["params"]
    found = [v for f in p["fields"] for v in es_values(doc, f)]
    if not found:
        return False
    t = float(sum(found))
    above = p["lo"] is None or (t > p["lo"] if p["lo_open"] else t >= p["lo"])
    return above and (p["hi"] is None or (t < p["hi"] if p["hi_open"] else t <= p["hi"]))


def es_term(field, test, values):
    want, nocase = (test["value"], test.get("case_insensitive")) if isinstance(test, dict) else (test, False)
    if field in ("source.ip", "destination.ip"):         # an ip field: an address or a network
        net = ipaddress.ip_network(want)
        return any(ipaddress.ip_address(v) in net for v in values)
    return any((str(v).lower() == str(want).lower()) if nocase else v == want for v in values)


def es_wildcard(field, test, values):
    fold = str.lower if test.get("case_insensitive") else str
    return any(fnmatch.fnmatchcase(fold(str(v)), fold(test["value"])) for v in values)


def es_range(field, test, values):
    if test.get("format") == "epoch_millis":
        values = [datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp() * 1000 for v in values]
    return any(all({"gt": v > b, "gte": v >= b, "lt": v < b, "lte": v <= b}[k] for k, b in test.items() if k != "format")
               for v in values)


ES_CLAUSES = {"bool": es_bool, "match_none": lambda body, doc: False, "script": es_script,
              "exists": lambda body, doc: bool(es_values(doc, body["field"]))}
ES_FIELD_CLAUSES = {"terms": lambda field, test, values: any(v in test for v in values),
                    "term": es_term, "wildcard": es_wildcard, "range": es_range}


def es_eval(q, doc):
    """Whether `doc` matches the clause `q`. Like Elasticsearch, it refuses a clause with a key
    it doesn't know."""
    (kind, body), = q.items()
    if kind in ES_CLAUSES:
        return ES_CLAUSES[kind](body, doc)
    assert kind in ES_FIELD_CLAUSES, f"unexpected clause {kind}"
    (field, test), = body.items()
    if kind in ("term", "wildcard") and isinstance(test, dict):
        assert set(test) <= {"value", "case_insensitive"}, test
    return ES_FIELD_CLAUSES[kind](field, test, es_values(doc, field))


def random_record(rng):
    """A Security Onion conn record: fields as Elasticsearch returns them, some missing."""
    start = T + rng.choice([0, 0.123, 0.124, 1, 60])
    doc = {"source.ip": rng.choice(PEERS), "destination.ip": rng.choice(PEERS),
           "source.port": rng.choice(PORTS), "destination.port": rng.choice(PORTS),
           "network.transport": rng.choice(["tcp", "udp", "icmp"]),
           "@timestamp": fmt_time(datetime.fromtimestamp(start, timezone.utc)),
           "event.duration": rng.choice([0, 0.5, 1, 1.5, 30, None]),
           "client.packets": rng.choice([1, 5, 10, None]), "server.packets": rng.choice([0, 1, None]),
           "client.ip_bytes": rng.choice([60, 1000, None]), "server.ip_bytes": rng.choice([0, 1, None]),
           "network.protocol": rng.choice(["smb", "smb,ntlm,gssapi", "ntlm,smb", "SMB,NTLM", "NTLM,SMB,GSSAPI",
                                           "ssl", "dns", "krb_tcp", "ftp-data", "DCE_RPC", "quic", "", "-",
                                           None, None])}
    return {k: v for k, v in doc.items() if v is not None}


@pytest.mark.parametrize("seed", range(300))
def test_elasticsearch_matches_the_same_records(seed):
    rng = random.Random(1000 + seed)
    cfg = Config()
    backend = ElasticBackend(cfg)
    records = [random_record(rng) for _ in range(60)]
    f = F.combine([random_expression(rng) for _ in range(rng.randint(1, 2))])
    query = F.to_es(f.core, cfg)
    for doc in records:
        flow = backend._flow({"fields": {k: [v] for k, v in doc.items()}})
        flow["start"] = datetime.fromisoformat(flow["start"].replace("Z", "+00:00")).timestamp()
        flow.update(src=doc["source.ip"], dst=doc["destination.ip"])
        assert es_eval(query, doc) == F.matches(f.core, flow), (f.text, doc)


def test_elasticsearch_without_zeek_service_names_only_icmp_and_unknown():
    cfg = Config(f_service="")
    icmp, tcp = {"network.transport": "icmp"}, {"network.transport": "tcp", "network.protocol": "smb"}
    assert es_eval(F.to_es(F.parse("ICMP").core, cfg), icmp) and not es_eval(F.to_es(F.parse("ICMP").core, cfg), tcp)
    assert es_eval(F.to_es(F.parse("Unknown").core, cfg), tcp)
    assert not es_eval(F.to_es(F.parse("Unknown").core, cfg), icmp)
    assert F.to_es(F.parse("SMB").core, cfg) == {"match_none": {}}


def test_elasticsearch_fields_follow_the_config():
    cfg = Config(f_sport="s.p", f_dport="d.p", f_duration="dur", f_ts="ts", f_src="s.ip", f_dst="d.ip",
                 f_proto="tr", f_packets=["pk"], f_bytes=["by1", "by2"])
    assert json.dumps(F.to_es(F.parse("sport 5").core, cfg)) == '{"range": {"s.p": {"gte": 5, "lte": 5}}}'
    assert F.to_es(F.parse("dport > 5").core, cfg) == {"range": {"d.p": {"gt": 5}}}
    assert F.to_es(F.parse("duration < 2").core, cfg) == {"range": {"dur": {"lt": 2.0}}}
    assert F.to_es(F.parse("time 2024-05-01T12:00:00Z").core, cfg) == \
        {"range": {"ts": {"gte": 1714564800000, "lt": 1714564800001, "format": "epoch_millis"}}}
    assert F.to_es(F.parse("src 10.0.0.0/8").core, cfg) == {"term": {"s.ip": "10.0.0.0/8"}}
    assert F.to_es(F.parse("dst 10.0.0.1").core, cfg) == {"term": {"d.ip": "10.0.0.1/32"}}
    assert F.to_es(F.parse("proto udp").core, cfg) == {"term": {"tr": "udp"}}
    assert F.to_es(F.parse("bytes 1").core, cfg)["script"]["script"]["params"]["fields"] == ["by1", "by2"]
    assert F.to_es(F.parse("packets 1").core, cfg)["script"]["script"]["params"]["fields"] == ["pk"]
