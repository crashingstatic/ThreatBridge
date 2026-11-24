"""Which machine held which address when (item 5, D27): Windows DHCP server audit logs, ISC
dhcpd leases, Zeek's dhcp.log, and DHCP messages in captures, from samples written by hand."""
import json
import logging
from datetime import datetime, timezone

import pytest

from evidence import ACK, SYN, dhcp_message, tcp, udp, write_pcap
from threatbridge import sources
from threatbridge.backends import CaseBackend
from threatbridge.config import Config
from threatbridge.model import SourceError
from threatbridge.sources import dhcp

T = 1_714_564_800.0                       # 2024-05-01T12:00:00Z
A, B = "00:11:22:33:44:55", "66:77:88:99:aa:bb"
UTC = dhcp.timezone_named("UTC")


def at(text):
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc).timestamp()


WINDOWS = """\t\tMicrosoft DHCP Service Activity Log


Event ID  Meaning
00\tThe log was started.
10\tA new IP address was leased to a client.

ID,Date,Time,Description,IP Address,Host Name,MAC Address,User Name, TransactionID, QResult,Probationtime, CorrelationID,Dhcid,VendorClass(Hex),VendorClass(ASCII),UserClass(Hex),UserClass(ASCII),RelayAgentInformation,DnsRegError.
24,05/01/24,00:00:15,Database Cleanup Begin,,,,,0,6,,,,,,,,,0
10,05/01/24,07:00:00,Assign,10.0.0.5,WS-042.corp.example,001122334455,,3141592653,0,,,,0x4D53465420352E30,MSFT 5.0,,,,0
11,05/01/24,09:30:00,Renew,10.0.0.5,WS-042.corp.example,001122334455,,3141592654,0,,,,,,,,,0
12,05/01/24,10:00:00,Release,10.0.0.5,WS-042.corp.example,001122334455,,3141592655,0,,,,,,,,,0
10,05/01/24,10:05:00,Assign,10.0.0.5,LAPTOP-7.corp.example,66778899AABB,,3141592656,0,,,,,,,,,0
30,05/01/24,10:05:01,DNS Update Request,10.0.0.5,LAPTOP-7.corp.example,,,0,6,,,,,,,,,0
"""

ISC = """# The format of this file is documented in the dhcpd.leases(5) manual page.
# This lease file was written by isc-dhcp-4.4.1

lease 10.0.0.7 {
  starts 3 2024/05/01 08:00:00;
  ends 3 2024/05/01 20:00:00;
  binding state active;
  hardware ethernet 00:11:22:33:44:55;
  client-hostname "ws-042";
}
lease 10.0.0.7 {
  starts epoch 1714575600; # Wed May 01 15:00:00 2024
  ends never;
  hardware ethernet 66:77:88:99:aa:bb;
}
lease 10.0.0.8 {
  starts 3 2024/05/01 08:00:00;
  ends 3 2024/05/01 09:00:00;
}
"""

ZEEK_TSV = """#separator \\x09
#set_separator\t,
#path\tdhcp
#fields\tts\tuids\tclient_addr\tserver_addr\tmac\thost_name\tclient_fqdn\tdomain\trequested_addr\tassigned_addr\tlease_time\tclient_message\tserver_message\tmsg_types\tduration
#types\ttime\tset[string]\taddr\taddr\tstring\tstring\tstring\tstring\taddr\taddr\tinterval\tstring\tstring\tvector[string]\tinterval
1714564800.000000\tCx\t-\t10.0.0.1\t00:11:22:33:44:55\tws-042\t-\tcorp.example\t10.0.0.9\t10.0.0.9\t3600.000000\t-\t-\tREQUEST,ACK\t0.01
1714570000.000000\tCy\t10.0.0.9\t10.0.0.1\t00:11:22:33:44:55\t-\t-\t-\t-\t-\t-\t-\t-\tRELEASE\t0
"""


def test_windows_audit_log_in_its_servers_time_zone():
    obs = dhcp.read_windows(WINDOWS, dhcp.timezone_named("America/Chicago"))      # CDT: UTC-5
    assert [(o[0], o[1], o[2], o[3], o[5]) for o in obs] == [
        ("10.0.0.5", A, "WS-042.corp.example", at("2024-05-01T12:00:00"), "assign"),
        ("10.0.0.5", A, "WS-042.corp.example", at("2024-05-01T14:30:00"), "assign"),
        ("10.0.0.5", A, "WS-042.corp.example", at("2024-05-01T15:00:00"), "release"),
        ("10.0.0.5", B, "LAPTOP-7.corp.example", at("2024-05-01T15:05:00"), "assign")]
    held = dhcp.holdings([o + ("win.log",) for o in obs])
    assert [(h[1], h[2], h[3], h[4]) for h in held] == [
        (A, "WS-042.corp.example", at("2024-05-01T12:00:00"), at("2024-05-01T15:00:00")),      # released
        (B, "LAPTOP-7.corp.example", at("2024-05-01T15:05:00"), None)]                          # still open
    with pytest.raises(SourceError, match="TB_DHCP_TIMEZONE: unknown time zone 'Mars/Olympus'"):
        dhcp.timezone_named("Mars/Olympus")


def test_isc_leases():
    held = dhcp.holdings([o + ("dhcpd.leases",) for o in dhcp.read_isc(ISC)])
    assert [(h[0], h[1], h[2], h[3], h[4]) for h in held] == [
        ("10.0.0.7", A, "ws-042", at("2024-05-01T08:00:00"), at("2024-05-01T15:00:00")),   # handed over
        ("10.0.0.7", B, None, at("2024-05-01T15:00:00"), None)]          # ends never; 10.0.0.8 has no MAC


def test_zeek_dhcp_log_as_tsv_and_json():
    tsv = dhcp.read_zeek(ZEEK_TSV)
    rec = {"ts": "2024-05-01T12:00:00.000000Z", "mac": A, "host_name": "ws-042", "assigned_addr": "10.0.0.9",
           "lease_time": 3600.0, "msg_types": ["REQUEST", "ACK"]}
    assert dhcp.read_zeek(json.dumps(rec) + "\n") == [tsv[0]]
    assert tsv == [("10.0.0.9", A, "ws-042", T, T + 3600, "assign"), ("10.0.0.9", A, None, T + 5200, None, "release")]
    [h] = dhcp.holdings([o + ("dhcp.log",) for o in tsv])
    assert (h[3], h[4]) == (T, T + 3600)                    # released after the lease had ended


def test_holdings_renewals_expiry_and_handover():
    obs = [("10.0.0.5", A, "a", T, T + 100, "assign", "x"), ("10.0.0.5", A, None, T + 50, T + 150, "assign", "y"),
           ("10.0.0.5", A, "a", T + 400, T + 500, "assign", "x"),       # after the lease ended: a new holding
           ("10.0.0.5", B, "b", T + 450, None, "assign", "z")]          # another machine: the first ends
    assert dhcp.holdings(obs) == [("10.0.0.5", A, "a", T, T + 150, ["x", "y"]),
                                  ("10.0.0.5", A, "a", T + 400, T + 450, ["x"]),
                                  ("10.0.0.5", B, "b", T + 450, None, ["z"])]
    held = dhcp.holdings(obs)
    assert dhcp.at(held, T + 120)[1] == A and dhcp.at(held, T + 300) is None and dhcp.at(held, T + 9999)[1] == B


def test_dhcp_in_a_capture(tmp_path):
    packets = [(T, udp("0.0.0.0", "255.255.255.255", 68, 67, dhcp_message(3, A, hostname="WS-042"))),
               (T + 0.01, udp("10.0.0.1", "10.0.0.5", 67, 68, dhcp_message(5, A, yiaddr="10.0.0.5", lease=86400))),
               (T + 60, tcp("10.0.0.5", "10.0.0.9", 50000, 445, SYN)),
               (T + 60.001, tcp("10.0.0.9", "10.0.0.5", 445, 50000, SYN | ACK)),
               (T + 900, udp("10.0.0.5", "10.0.0.1", 68, 67, dhcp_message(7, A, ciaddr="10.0.0.5"))),
               (T + 901, udp("10.0.0.1", "10.0.0.6", 67, 68, dhcp_message(5, B, yiaddr="10.0.0.5", lease=600))),
               (T + 902, udp("10.0.0.1", "10.0.0.7", 67, 68, b"\x02junk"))]          # not DHCP: ignored
    path = tmp_path / "cap.pcap"
    write_pcap(path, packets)
    obs = []
    sources.read(sources.find([str(path)]), None, 1, None, obs)
    assert dhcp.holdings(dhcp.named(obs)) == [
        ("10.0.0.5", A, "WS-042", T + 0.01, T + 900, [str(path)]),
        ("10.0.0.5", B, None, T + 901, T + 1501, [str(path)])]


def test_a_case_keeps_who_held_each_address(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    d = tmp_path / "case"
    d.mkdir()
    write_pcap(d / "cap.pcap", [(T, tcp("10.0.0.5", "10.0.0.9", 50000, 445, SYN)),
                                (T + 0.001, tcp("10.0.0.9", "10.0.0.5", 445, 50000, SYN | ACK))])
    (d / "DhcpSrvLog-Wed.log").write_text(WINDOWS)
    (d / "dhcpd.leases").write_text(ISC)
    (d / "dhcp.log").write_text(ZEEK_TSV)
    found = sources.find([str(d)])
    assert [p.rsplit("/", 1)[1] for p in found["dhcp"]] == ["DhcpSrvLog-Wed.log", "dhcp.log", "dhcpd.leases"]
    cfg = Config(backend="case", case_paths=[str(d)], case_db=str(tmp_path / "case.db"), dhcp_timezone="America/Chicago")
    leases = CaseBackend(cfg).store.leases()
    assert [(ip, mac) for ip, mac, *_ in leases] == [("10.0.0.5", A), ("10.0.0.5", B), ("10.0.0.7", A),
                                                     ("10.0.0.7", B), ("10.0.0.9", A)]
    assert leases[0][5] == [str(d / "DhcpSrvLog-Wed.log")]
    # Reopened while the evidence is unchanged: the same, without reading again; a changed DHCP
    # log rebuilds the case.
    assert CaseBackend(cfg).store.leases() == leases
    (d / "dhcpd.leases").write_text(ISC.replace("ws-042", "ws-043"))
    assert any(name == "ws-043" for _, _, name, *_ in CaseBackend(cfg).store.leases())
