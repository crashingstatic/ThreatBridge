"""Community ID v1 against the specification's published test vectors (seed 0):
https://github.com/corelight/community-id-spec, baseline/baseline_deflt.json."""
import pytest

from threatbridge.communityid import community_id

V6_A, V6_B = "2001:470:e5bf:dead:4957:2174:e82c:4887", "2607:f8b0:400c:c03::1a"


@pytest.mark.parametrize("proto, src, dst, sport, dport, expected", [
    ("tcp", "128.232.110.120", "66.35.250.204", 34855, 80, "1:LQU9qZlK+B5F3KDmev6m5PMibrg="),
    ("tcp", "66.35.250.204", "128.232.110.120", 80, 34855, "1:LQU9qZlK+B5F3KDmev6m5PMibrg="),
    ("udp", "192.168.1.52", "8.8.8.8", 54585, 53, "1:d/FP5EW3wiY1vCndhwleRRKHowQ="),
    ("udp", "8.8.8.8", "192.168.1.52", 53, 54585, "1:d/FP5EW3wiY1vCndhwleRRKHowQ="),
    ("tcp", V6_A, V6_B, 63943, 25, "1:/qFaeAR+gFe1KYjMzVDsMv+wgU4="),
    ("tcp", V6_B, V6_A, 25, 63943, "1:/qFaeAR+gFe1KYjMzVDsMv+wgU4="),
    ("46", "10.1.12.1", "10.1.12.2", 0, 0, "1:KHlLkgoJW7ifUTyTSgyVfkFHzKw="),     # no ports
    ("46", "10.1.12.2", "10.1.12.1", 0, 0, "1:KHlLkgoJW7ifUTyTSgyVfkFHzKw="),
])
def test_published_vectors(proto, src, dst, sport, dport, expected):
    assert community_id(src, dst, proto, sport, dport) == expected


def test_protocol_numbers_and_names_agree():
    assert community_id("10.0.0.5", "10.0.0.9", "6", 50000, 445) == community_id("10.0.0.5", "10.0.0.9", "tcp",
                                                                                  "50000", "445")


def test_equal_addresses_are_ordered_by_port():
    assert community_id("10.0.0.5", "10.0.0.5", "tcp", 2000, 1000) == community_id("10.0.0.5", "10.0.0.5", "tcp",
                                                                                   1000, 2000)


@pytest.mark.parametrize("src, dst, proto, sport, dport", [
    ("10.0.0.5", "10.0.0.9", "icmp", 0, 0),          # type and code not kept
    ("2001:db8::5", "2001:db8::9", "58", 0, 0),
    ("10.0.0.5", "10.0.0.9", "132", 0, 0),           # SCTP: ports not kept
    ("10.0.0.5", "2001:db8::9", "tcp", 1, 2),        # mixed families
    ("10.0.0.5", "nope", "tcp", 1, 2),
    ("10.0.0.5", "10.0.0.9", "tcp", None, 2),
    ("10.0.0.5", "10.0.0.9", "tcp", 70000, 2),
    ("10.0.0.5", "10.0.0.9", "ipx", 0, 0),
    ("10.0.0.5", "10.0.0.9", "300", 0, 0),
    ("10.0.0.5", "10.0.0.9", None, 0, 0),
])
def test_flows_without_one(src, dst, proto, sport, dport):
    assert community_id(src, dst, proto, sport, dport) is None
