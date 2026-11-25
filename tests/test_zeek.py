"""Zeek logs as evidence (D36): conn.log and dns.log, tab-separated or JSON lines, plain or
gzip-compressed, from samples written in the format real Zeek output has (headers copied from
Zeek 6 logs). Checked by hand on a real Zeek conn.log of 1,021,950 records (Brim's sample data):
its 223,175 refused connections left out, the other 798,775 read as flows."""
import gzip
import json
import logging

import pytest

from threatbridge import sources
from threatbridge.app import create_app
from threatbridge.backends import CaseBackend
from threatbridge.config import Config
from threatbridge.model import SourceError
from threatbridge.sources import zeek

HEADER = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\t{path}
#open\t2024-05-01-12-00-00
#fields\t{fields}
#types\t{types}
"""
CONN_FIELDS = ("ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state "
               "local_orig local_resp missed_bytes history orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes tunnel_parents")
CONN_TYPES = ("time string addr port addr port enum string interval count count string bool bool count string count "
              "count count count set[string]")
CONN_ROWS = [
    "1714564800.255387 CMwJl820SlYyy434c8 10.0.0.5 50000 10.0.0.9 445 tcp smb,ntlm,gssapi 1.5 97 19 SF T T 0 ShADadFf 10 730 6 342 -",
    "1714564801.411148 CCVM7z3Nk2qYvqMtU9 10.0.0.5 50817 10.0.0.9 23189 tcp - 0.000486 0 0 REJ T T 0 Sr 2 104 2 80 -",
    "1714564802.000000 C3 10.0.0.5 8 10.0.0.1 0 icmp - 0.001 64 64 OTH T T 0 - 1 92 1 92 -",
    "1714564803.000000 C4 2001:db8::5 50001 2001:db8::9 3389 tcp - - - - S0 T T 0 S 1 80 0 0 -",
    "1714564804.000000 C5 10.0.0.5 50002 203.0.113.7 443 tcp gssapi,ntlm 2 1 1 SF T F 0 ShADadFf - - - - (empty)",
    "1714564805.000000 C6 not-an-address 1 10.0.0.9 445 tcp - - - - S0 T T 0 S 1 60 0 0 -",
]
DNS_FIELDS = ("ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto trans_id rtt query qclass qclass_name qtype qtype_name "
              "rcode rcode_name AA TC RD RA Z answers TTLs rejected")
DNS_TYPES = ("time string addr port addr port enum count interval string count string count string count string bool "
             "bool bool bool count vector[string] vector[interval] bool")
DNS_ROWS = [
    "1714564700.865716 Cq 10.0.0.5 41772 10.0.0.53 53 udp 36329 0.000870 Updates.Example.COM 1 C_INTERNET 1 A 0 NOERROR "
    "F F T T 0 cdn.example.net,10.0.0.77,10.0.0.78 2230.000000,41830.000000,41830.000000 F",
    "1714564900.000000 Cr 10.0.0.5 41773 10.0.0.53 53 udp 36330 0.000870 updates.example.com. 1 C_INTERNET 1 A 0 NOERROR "
    "F F T T 0 10.0.0.77 60.000000 F",
    "1714564728.388994 CG 10.0.0.5 29644 10.0.0.53 53 udp 7183 - nowhere.example 1 C_INTERNET 1 A 3 NXDOMAIN "
    "F F T F 0 - - T",
]


def tsv(path, rows, fields, types):
    tab = lambda s: s.replace(" ", "\t")
    return HEADER.format(path=path, fields=tab(fields), types=tab(types)) + "".join(tab(r) + "\n" for r in rows) + \
        "#close\t2024-05-01-13-00-00\n"


def conn_json(rows):
    """The same records as Zeek's JSON lines (unset fields left out, numbers as numbers)."""
    out = []
    for row in rows:
        rec = {}
        for name, value, typ in zip(CONN_FIELDS.split(), row.split(), CONN_TYPES.split()):
            if value == "-":
                continue
            if typ in ("time", "interval"):
                value = float(value)
            elif typ in ("count", "port"):
                value = int(value) if value.isdigit() else value
            elif typ.startswith("set["):
                value = [] if value == "(empty)" else value.split(",")
            rec[name] = value
        out.append(json.dumps(rec))
    return "\n".join(out) + "\n"


def flows_of(path):
    found, refused, bad = zeek.conn_flows(str(path))
    return [(f.src, f.dst, f.sport, f.dport, f.proto, f.start, round(f.end - f.start, 6), f.packets, f.bytes, f.service)
            for f in found], refused, bad


EXPECTED = ([
    ("10.0.0.5", "10.0.0.9", 50000, 445, "tcp", 1714564800.255387, 1.5, 16, 1072, "smb"),       # not ntlm or gssapi
    ("10.0.0.5", "10.0.0.1", 0, 0, "icmp", 1714564802.0, 0.001, 2, 184, "icmp"),                # ICMP: no ports
    ("2001:db8::5", "2001:db8::9", 50001, 3389, "tcp", 1714564803.0, 0.0, 1, 80, "rdp"),        # by its port
    ("10.0.0.5", "203.0.113.7", 50002, 443, "tcp", 1714564804.0, 2.0, None, None, "gssapi")],   # only helpers
    1, 1)                                                                                         # REJ, a bad address


def test_conn_log_as_tsv(tmp_path):
    p = tmp_path / "conn.log"
    p.write_text(tsv("conn", CONN_ROWS, CONN_FIELDS, CONN_TYPES))
    assert flows_of(p) == EXPECTED
    assert zeek.conn_flows(str(p))[0][0].source == str(p)


def test_conn_log_as_json_lines_dotted_nested_and_iso_times(tmp_path):
    p = tmp_path / "conn.json"
    p.write_text(conn_json(CONN_ROWS))
    assert flows_of(p) == EXPECTED
    nested = tmp_path / "nested.log"
    rec = {"ts": "2024-05-01T12:00:00.255387Z", "uid": "C1", "id": {"orig_h": "10.0.0.5", "orig_p": 50000,
                                                                     "resp_h": "10.0.0.9", "resp_p": 445},
           "proto": "tcp", "service": "smb", "duration": 1.5, "conn_state": "SF", "orig_pkts": 10, "orig_ip_bytes": 730,
           "resp_pkts": 6, "resp_ip_bytes": 342}
    nested.write_text(json.dumps(rec) + "\n{not json\n")
    assert flows_of(nested) == ([EXPECTED[0][0][:5] + (1714564800.255387, 1.5, 16, 1072, "smb")], 0, 0)


def test_gzip_as_zeek_archives_its_logs(tmp_path):
    p = tmp_path / "conn.12:00:00-13:00:00.log.gz"
    with gzip.open(p, "wt") as fh:
        fh.write(tsv("conn", CONN_ROWS, CONN_FIELDS, CONN_TYPES))
    assert flows_of(p) == EXPECTED
    assert sources._kind(str(p)) == "zeek"


def test_dns_log_answers(tmp_path):
    p = tmp_path / "dns.log"
    p.write_text(tsv("dns", DNS_ROWS, DNS_FIELDS, DNS_TYPES))
    found = {}
    zeek.dns_answers(str(p), found)
    t1, t2 = 1714564700.865716, 1714564900.0
    assert found == {"updates.example.com": {"10.0.0.77": [t1, t2], "10.0.0.78": [t1, t1]},      # the query, twice
                     "cdn.example.net": {"10.0.0.77": [t1, t1], "10.0.0.78": [t1, t1]}}        # the CNAME on the way
    j = tmp_path / "dns.json"
    j.write_text(json.dumps({"ts": t1, "uid": "Cq", "id.orig_h": "10.0.0.5", "id.orig_p": 1, "id.resp_h": "10.0.0.53",
                             "id.resp_p": 53, "proto": "udp", "query": "a.example", "rcode_name": "NOERROR",
                             "answers": ["10.0.0.80"]}) + "\n")
    assert sources._kind(str(j)) == "zeek_dns"
    found = {}
    zeek.dns_answers(str(j), found)
    assert found == {"a.example": {"10.0.0.80": [t1, t1]}}


def test_which_files_are_zeek_logs(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    d = tmp_path / "logs"
    d.mkdir()
    (d / "conn.log").write_text(tsv("conn", CONN_ROWS, CONN_FIELDS, CONN_TYPES))
    (d / "dns.log").write_text(tsv("dns", DNS_ROWS, DNS_FIELDS, DNS_TYPES))
    (d / "http.log").write_text(tsv("http", [], "ts uid id.orig_h", "time string addr"))
    (d / "ssl.json").write_text(json.dumps({"ts": 1.0, "uid": "C1", "id.orig_h": "10.0.0.5", "version": "TLSv12"}) + "\n")
    with gzip.open(d / "dhcp.log.gz", "wt") as fh:
        fh.write("#separator \\x09\n#path\tdhcp\n#fields\tts\tmac\tassigned_addr\tmsg_types\n"
                 "#types\ttime\tstring\taddr\tvector[string]\n1714564800.0\t00:11:22:33:44:55\t10.0.0.5\tREQUEST,ACK\n")
    found = sources.find([str(d)])
    names = {k: [p.rsplit("/", 1)[1] for p in v] for k, v in found.items() if v}
    assert names == {"zeek": ["conn.log"], "zeek_dns": ["dns.log"], "dhcp": ["dhcp.log.gz"]}
    assert "skipping" in caplog.text and "http.log: a Zeek log ThreatBridge doesn't use" in caplog.text
    # Named directly, a Zeek log the map doesn't use is skipped too, not refused; alone, it's no case.
    with pytest.raises(SourceError, match="no pcap, pcapng, nfcapd or Zeek conn log files found"):
        sources.find([str(d / "http.log")])
    assert sources.find([str(d / "http.log"), str(d / "conn.log")])["zeek"] == [str(d / "conn.log")]
    obs = []
    sources.read(found, {}, 1, None, obs)
    assert [(o[0], o[1]) for o in obs] == [("10.0.0.5", "00:11:22:33:44:55")]       # the gzipped DHCP log


def test_both_captures_and_conn_logs_are_read_with_a_warning(tmp_path, caplog):
    from evidence import ACK, SYN, tcp, write_pcap
    d = tmp_path / "case"
    d.mkdir()
    write_pcap(d / "cap.pcap", [(1714564800.0, tcp("10.0.0.6", "10.0.0.9", 40000, 445, SYN)),
                                (1714564800.001, tcp("10.0.0.9", "10.0.0.6", 445, 40000, SYN | ACK))])
    (d / "conn.log").write_text(tsv("conn", CONN_ROWS, CONN_FIELDS, CONN_TYPES))
    caplog.set_level(logging.WARNING)
    found = sources.find([str(d)])
    assert "counted twice" in caplog.text
    flows = sources.read(found)
    assert len(flows) == 5 and flows == sorted(flows, key=lambda f: (f.start, f.src, f.dst, f.sport, f.dport))


def test_a_case_from_zeek_logs(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    with gzip.open(d / "conn.log.gz", "wt") as fh:
        fh.write(tsv("conn", CONN_ROWS, CONN_FIELDS, CONN_TYPES))
    (d / "dns.log").write_text(tsv("dns", DNS_ROWS, DNS_FIELDS, DNS_TYPES))
    cfg = Config(backend="case", case_paths=[str(d)], case_db=str(tmp_path / "case.db"), live_dns=False,
                 compromised_file=str(tmp_path / "c.json"), exclude_file=str(tmp_path / "ex.json"))
    backend = CaseBackend(cfg)
    assert backend.summary()["flows"] == 4 and backend.summary()["dns_names"] == 2
    c = create_app(cfg, backend).test_client()
    r = c.get("/api/neighbors?ip=10.0.0.9&direction=in&ts=2024-05-01T12:00:00.255Z&window=1h").get_json()
    assert [(p["peer"], p["ports"], p["protocols"]) for p in r["peers"]] == [("10.0.0.5", [445], ["smb"])]
    r = c.get("/api/flows?src=10.0.0.5&dst=10.0.0.9&from=2024-05-01T12:00:00Z&to=2024-05-01T12:01:00Z").get_json()
    assert [(f["packets"], f["bytes"], f["duration"]) for f in r["flows"]] == [(16, 1072, 1.5)]
    # A domain on the exclude list stands for what Zeek saw it resolve to.
    r = c.post("/api/excludes", json={"entry": "updates.example.com"}, headers={"X-ThreatBridge": "1"}).get_json()
    assert r["resolved"]["updates.example.com"]["capture"] == ["10.0.0.77", "10.0.0.78"]
    # Reopened while unchanged: the same; a changed log rebuilds the case.
    assert CaseBackend(cfg).summary() == backend.summary()
    (d / "dns.log").write_text(tsv("dns", DNS_ROWS[2:], DNS_FIELDS, DNS_TYPES))      # only the NXDOMAIN
    assert CaseBackend(cfg).summary()["dns_names"] == 0


def test_heads_that_are_not_zeek():
    assert zeek.kind(b"hello") is None
    assert zeek.kind(b'{"Event": {"System": {}}}') is None
    assert zeek.kind(b'{"ts": 1, "uid": "C1", "id.orig_h": "10.0.0.5", "conn_state": "SF"') == "conn"   # cut short
    assert zeek.kind(b'{"_path": "dns", "ts": 1}\n') == "dns"


def test_several_conn_logs_read_at_once(tmp_path):
    for hour, rows in ((12, CONN_ROWS[:3]), (13, CONN_ROWS[3:])):
        (tmp_path / f"conn.{hour}:00:00-{hour + 1}:00:00.log").write_text(tsv("conn", rows, CONN_FIELDS, CONN_TYPES))
    found = sources.find([str(tmp_path)])
    assert len(found["zeek"]) == 2
    assert sources.read(found, workers=2) == sources.read(found, workers=1)
    assert len(sources.read(found, workers=2)) == 4
