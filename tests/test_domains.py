"""Domain names on the exclude list (FIL-2): validation, DNS answers in captures, lookups."""
import time

import pytest

from evidence import dns_answer, tcp, udp, write_pcap, SYN
from threatbridge import sources
from threatbridge.app import create_app
from threatbridge.backends import CaseBackend
from threatbridge.config import Config
from threatbridge.domains import DomainResolver, system_lookup
from threatbridge.excludes import ExcludeStore
from threatbridge.query import ValidationError, is_domain, parse_exclude

T = 1_714_564_800.0
C, RESOLVER = "10.0.0.9", "10.0.0.53"


@pytest.mark.parametrize("raw,expected", [
    ("10.0.0.7/24", "10.0.0.0/24"), ("10.0.0.7", "10.0.0.7"), ("2001:db8::1", "2001:db8::1"),
    ("Updates.Example.COM.", "updates.example.com"), ("*.windowsupdate.com", "*.windowsupdate.com"),
    ("fileserver", "fileserver"), ("_ldap._tcp.corp.local", "_ldap._tcp.corp.local"),
])
def test_parse_exclude(raw, expected):
    assert parse_exclude(raw) == expected
    assert is_domain(expected) == (not expected[0].isdigit() and ":" not in expected)


@pytest.mark.parametrize("bad", ["", "-bad.com", "a..b", "10.0.0", "*.com", "*.*.x.com",
                                 "exa mple.com", "a" * 64 + ".com", "x." * 127 + "com"])
def test_parse_exclude_rejects(bad):
    with pytest.raises(ValidationError):
        parse_exclude(bad)


def test_dns_answers_are_collected_from_pcaps(tmp_path):
    write_pcap(tmp_path / "dns.pcap", [
        (T, udp(C, RESOLVER, 40000, 53, b"q")),
        (T + 0.01, udp(RESOLVER, C, 53, 40000, dns_answer("WWW.Example.com", [   # case-insensitive
            ("WWW.Example.com", "CNAME", "cdn.example.net"),
            ("cdn.example.net", "A", "93.184.216.34"),
            ("cdn.example.net", "AAAA", "2001:db8::34")]))),
        (T + 60, udp(RESOLVER, C, 53, 40001, dns_answer("www.example.com", [
            ("www.example.com", "A", "93.184.216.35")]))),
        (T + 70, udp(RESOLVER, C, 53, 40002, dns_answer("gone.example.com", [], rcode=3))),
        (T + 80, udp(RESOLVER, C, 53, 40003, b"\x00garbage")),
    ])
    dns = {}
    flows = sources.load([str(tmp_path)], dns=dns)
    assert len(flows) == 4                     # DNS traffic is still traffic
    assert dns["www.example.com"] == {"93.184.216.34": [T + 0.01, T + 0.01],
                                      "2001:db8::34": [T + 0.01, T + 0.01],
                                      "93.184.216.35": [T + 60, T + 60]}
    assert set(dns["cdn.example.net"]) == {"93.184.216.34", "2001:db8::34"}
    assert "gone.example.com" not in dns       # NXDOMAIN


PASSIVE = {"www.example.com": {"93.184.216.34": [T, T]},
           "a.cdn.example.net": {"192.0.2.1": [T, T]}, "b.cdn.example.net": {"192.0.2.2": [T, T]}}


def test_resolver_combines_capture_and_live_dns():
    calls = []

    def lookup(name):
        calls.append(name)
        if name == "missing.example.com":
            raise OSError(-2, "Name or service not known")
        return ["93.184.216.99"]

    r = DomainResolver(PASSIVE, lookup=lookup)
    entries = ["10.0.0.0/8", "www.example.com", "*.cdn.example.net", "missing.example.com"]
    d = r.describe(entries)
    assert d["www.example.com"] == {"capture": ["93.184.216.34"], "dns": ["93.184.216.99"], "error": None}
    assert d["*.cdn.example.net"] == {"capture": ["192.0.2.1", "192.0.2.2"], "dns": [], "error": None}
    assert d["missing.example.com"]["error"] == "DNS lookup failed: Name or service not known"
    assert r.expand(entries) == ["10.0.0.0/8", "93.184.216.34", "93.184.216.99", "192.0.2.1", "192.0.2.2"]
    assert sorted(calls) == ["missing.example.com", "www.example.com"]   # wildcard: capture only


def test_resolver_caches_for_ttl_and_times_out():
    now = [0.0]
    calls = []
    r = DomainResolver({}, ttl=300, lookup=lambda n: calls.append(n) or ["192.0.2.9"],
                       clock=lambda: now[0])
    r.expand(["x.example"]); r.expand(["x.example"])
    now[0] = 301
    r.expand(["x.example"])
    assert calls == ["x.example", "x.example"]
    slow = DomainResolver({}, timeout=0.2, lookup=lambda n: time.sleep(1) or ["192.0.2.1"])
    t = time.monotonic()
    assert slow.describe(["a.example", "b.example"]) == {
        "a.example": {"capture": [], "dns": [], "error": "DNS lookup timed out"},
        "b.example": {"capture": [], "dns": [], "error": "DNS lookup timed out"}}
    assert time.monotonic() - t < 0.8          # lookups run in parallel


def test_live_dns_can_be_disabled():
    r = DomainResolver(PASSIVE, live=False, lookup=lambda n: pytest.fail("looked up"))
    assert r.expand(["www.example.com"]) == ["93.184.216.34"]


def test_system_lookup_localhost():
    assert "127.0.0.1" in system_lookup("localhost")


def test_domain_excludes_apply_to_maps_and_paths(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    write_pcap(d / "cap.pcap", [
        (T, udp(C, RESOLVER, 40000, 53, b"q")),
        (T + 0.01, udp(RESOLVER, C, 53, 40000, dns_answer("updates.example.com", [
            ("updates.example.com", "A", "10.0.0.77")]))),
        (T + 1, tcp("10.0.0.77", C, 50000, 443, SYN)),
        (T + 2, tcp("10.0.0.5", C, 50001, 445, SYN)),
    ])
    cfg = Config(backend="case", case_paths=[str(d)], live_dns=False,
                 exclude_file=str(tmp_path / "ex.json"), compromised_file=str(tmp_path / "c.json"))
    c = create_app(cfg).test_client()
    assert c.get("/api/config").get_json()["case"]["dns_names"] == 1
    q = f"/api/neighbors?ip={C}&direction=in&ts=2024-05-01T13:00:00Z"
    assert {p["peer"] for p in c.get(q).get_json()["peers"]} == {"10.0.0.5", "10.0.0.77"}
    r = c.post("/api/excludes", json={"entry": "Updates.Example.com"}, headers={"X-ThreatBridge": "1"})
    assert r.get_json() == {"entry": "updates.example.com", "entries": ["updates.example.com"], "resolved": {
        "updates.example.com": {"capture": ["10.0.0.77"], "dns": [], "error": None}}}
    assert {p["peer"] for p in c.get(q).get_json()["peers"]} == {"10.0.0.5"}
    r = c.get(f"/api/threatline?a=10.0.0.5&b={C}&from=2024-05-01T12:00:02Z").get_json()
    assert "10.0.0.77" not in {n["id"] for n in r["nodes"]}


# ---- edge cases ---------------------------------------------------------------------------

def test_a_lookup_failing_oddly_never_breaks_the_map():
    def lookup(name):
        raise UnicodeError("label empty or too long")
    d = DomainResolver({}, lookup=lookup).describe(["x.example"])
    assert d["x.example"]["dns"] == [] and d["x.example"]["error"].startswith("DNS lookup failed")


def test_wildcards_match_whole_labels_only():
    r = DomainResolver({"a.example.com": {"192.0.2.1": [T, T]}, "badexample.com": {"192.0.2.2": [T, T]},
                        "example.com": {"192.0.2.3": [T, T]}}, live=False)
    assert r.captured("*.example.com") == ["192.0.2.1"]


# ---- gaps found by mutation testing -------------------------------------------------------

def test_live_answers_expire_exactly_at_the_ttl():
    now, calls = [0.0], []
    r = DomainResolver({}, ttl=300, lookup=lambda n: calls.append(n) or ["192.0.2.9"], clock=lambda: now[0])
    r.expand(["x.example"])
    now[0] = 299.9
    r.expand(["x.example"])
    now[0] = 300.0
    r.expand(["x.example"])
    assert len(calls) == 2


def test_capture_answers_are_in_address_order():
    seen = {"192.0.2.10": [T, T], "192.0.2.9": [T, T], "2001:db8::1": [T, T], "10.0.0.1": [T, T]}
    r = DomainResolver({"x.example": seen}, live=False)
    assert r.captured("x.example") == ["10.0.0.1", "192.0.2.9", "192.0.2.10", "2001:db8::1"]
