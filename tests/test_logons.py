"""Which account made a connection (item 4, D28): Windows Security events 4624, 4648, 4768 and
4769, from samples written by hand in the shape evtx_dump and the evtx library give."""
import json
import logging
import sys
import types
from datetime import datetime, timedelta, timezone

import pytest

from evidence import ACK, SYN, tcp, write_pcap
from threatbridge import sources
from threatbridge.backends import CaseBackend
from threatbridge.config import Config
from threatbridge.model import Flow, SourceError
from threatbridge.sources import logons

T = 1_714_564_800.0                       # 2024-05-01T12:00:00Z
WS, FS, DC = "10.0.0.5", "10.0.0.9", "10.0.0.2"
SMB = logons.NETWORK_LOGONS[3]


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f0Z")    # as Windows writes it


def event(number, computer, t, **data):
    return {"Event": {"#attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"},
                      "System": {"EventID": number, "TimeCreated": {"#attributes": {"SystemTime": iso(t)}},
                                 "Computer": computer},
                      "EventData": data}}


def logon(computer, t, user, ip, logon_type=3, domain="CORP"):
    return event(4624, computer, t, TargetUserName=user, TargetDomainName=domain, LogonType=logon_type,
                 IpAddress=ip, IpPort="50000")


def test_network_logons():
    [c] = logons.claims_of(logon("FS01.corp.example", T, "alice", WS), "sec.evtx")
    assert c == (WS, ("name", "FS01.corp.example"), T, "CORP\\alice", 4624, 3, SMB, "sec.evtx")
    # Remote desktop, from an IPv4-mapped address; the event ID as the evtx library gives some.
    rdp = logon("DC01", T, "admin", "::ffff:10.0.0.9", 10)
    rdp["Event"]["System"]["EventID"] = {"#attributes": {"Qualifiers": 0}, "#text": 4624}
    assert logons.claims_of(rdp)[0][:7] == (FS, ("name", "DC01"), T, "CORP\\admin", 4624, 10, {3389})
    # Left out: an interactive logon, the host itself, no address, a machine account, an
    # anonymous logon, other events, and records without a time or host.
    for rec in (logon("FS01", T, "alice", WS, 2), logon("FS01", T, "alice", "127.0.0.1"),
                logon("FS01", T, "alice", "::1"), logon("FS01", T, "alice", "-"), logon("FS01", T, "WS-042$", WS),
                logon("FS01", T, "ANONYMOUS LOGON", WS, domain="NT AUTHORITY"), logon("FS01", T, "-", WS),
                event(4625, "FS01", T, TargetUserName="alice", LogonType=3, IpAddress=WS),
                logon("", T, "alice", WS), {"Event": {"System": {"EventID": 4624}}}, {"Event": {"System": "x"}},
                {"Event": {"System": {"EventID": "x"}}}, {}):
        assert logons.claims_of(rec) == []
    bad_time = logon("FS01", T, "alice", WS)
    bad_time["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"] = "yesterday"
    assert logons.claims_of(bad_time) == []


def test_explicit_credentials_and_kerberos():
    # 4648, on the host the account came from: to an address, or to a server named.
    explicit = event(4648, "FS01.corp.example", T, TargetUserName="admin", TargetDomainName="CORP",
                     TargetServerName="dc01", IpAddress="-")
    assert logons.claims_of(explicit)[0][:6] == (("name", "FS01.corp.example"), ("name", "dc01"), T, "CORP\\admin",
                                                 4648, None)
    explicit["Event"]["EventData"]["IpAddress"] = DC
    assert logons.claims_of(explicit)[0][1] == DC
    local = event(4648, "FS01", T, TargetUserName="admin", TargetServerName="localhost", IpAddress="127.0.0.1")
    assert logons.claims_of(local) == []
    # 4768, a ticket-granting ticket from the domain controller to the client.
    tgt = event(4768, "DC01.corp.example", T, TargetUserName="alice", TargetDomainName="CORP.EXAMPLE",
                IpAddress="::ffff:10.0.0.5")
    assert logons.claims_of(tgt) == [(WS, ("name", "DC01.corp.example"), T, "CORP.EXAMPLE\\alice", 4768, None,
                                      {88}, "")]
    # 4769, a service ticket: the client to the controller, and the client to the service's host.
    ticket = event(4769, "DC01", T, TargetUserName="alice@CORP.EXAMPLE", TargetDomainName="CORP.EXAMPLE",
                   ServiceName="FS01$", IpAddress=WS)
    assert [(c[1], c[3], c[6]) for c in logons.claims_of(ticket)] == [
        (("name", "DC01"), "alice@CORP.EXAMPLE", {88}), (("name", "FS01"), "alice@CORP.EXAMPLE", set())]
    ticket["Event"]["EventData"]["ServiceName"] = "cifs/fs01.corp.example"
    assert logons.claims_of(ticket)[1][1::5] == (("name", "fs01.corp.example"), {445, 139})
    ticket["Event"]["EventData"]["ServiceName"] = "krbtgt"
    assert len(logons.claims_of(ticket)) == 1
    ticket["Event"]["EventData"]["IpAddress"] = "::1"
    assert logons.claims_of(ticket) == []


# ---- names to addresses ----------------------------------------------------------------------

A, B = "00:11:22:33:44:55", "66:77:88:99:aa:bb"


def test_names_from_dhcp_dns_and_a_hosts_file(tmp_path):
    held = [(WS, A, "WS-042.corp.example", T, T + 3600, ["dhcpd.leases"]),
            (WS, B, "laptop-7", T + 3600, None, ["dhcpd.leases"]),
            ("10.0.0.6", A, "ws-042", T + 7200, None, ["dhcpd.leases"]),
            ("10.0.0.7", B, "LAPTOP-7", T + 7200, None, ["dhcpd.leases"])]       # two at once: unsure
    dns = {"fs01.corp.example.": {FS: [T, T + 60]},
           "web.corp.example": {"10.0.0.20": [T, T + 10], "10.0.0.21": [T + 1000, T + 1010]}}
    hosts = tmp_path / "hosts"
    hosts.write_text("# the client's names\n10.0.0.2  dc01.corp.example dc01   # the controller\n"
                     "10.0.0.30 split\n10.0.0.31 split\nnot-an-address x\n\n")
    names = logons.Names(held, dns, logons.read_hosts(hosts))
    assert logons.read_hosts(hosts) == {"dc01.corp.example": [DC], "dc01": [DC], "split": ["10.0.0.30", "10.0.0.31"],
                                        }
    assert [names.resolve(n, t) for n, t in [
        ("ws-042", T + 60), ("WS-042.corp.example", T + 60), ("WS-042$", T + 60),   # its lease, by short name
        ("ws-042", T + 7300),                                                        # a later lease
        ("laptop-7", T + 4000), ("laptop-7", T + 7300),                              # held two at once
        ("FS01.corp.example", T + 9999), ("fs01", T),                                # DNS, at any time
        ("web.corp.example", T + 5), ("web", T + 1005), ("web", T + 600),           # the nearest answer
        ("DC01", T), ("dc01.corp.example.", T), ("split", T), ("nowhere", T)]] == [
        WS, WS, WS, "10.0.0.6", WS, None, FS, FS, "10.0.0.20", "10.0.0.21", "10.0.0.21", DC, DC, None, None]


def test_each_claim_labels_the_flow_that_fits_it_best():
    flows = {(WS, FS): [(T + 5, 50001, 80, "tcp"), (T + 30, 50002, 445, "tcp"), (T + 200, 50003, 445, "tcp")],
             (FS, DC): [(T + 50, 50010, 3389, "tcp")]}

    def between(src, dst, lo, hi):
        return [f for f in flows.get((src, dst), []) if lo <= f[0] <= hi]

    names = logons.Names(hosts={"fs01": [FS], "dc01": [DC], "ws-042": [WS]})
    claims = [(WS, ("name", "FS01"), T, "CORP\\alice", 4624, 3, SMB, "a"),          # SMB, though further
              (WS, ("name", "FS01"), T + 0.01, "CORP\\alice", 4624, 3, SMB, "b"),   # logged twice: one label
              (WS, ("name", "FS01"), T, "CORP\\bob", 4769, None, set(), "c"),      # no port: the nearest
              (("name", "fs01"), ("name", "dc01"), T + 45, "CORP\\admin", 4648, None, {3389}, "d"),
              (WS, ("name", "FS01"), T - 500, "CORP\\carol", 4624, 3, SMB, "e"),   # no flow near it
              (WS, ("name", "nowhere"), T, "CORP\\dave", 4624, 3, SMB, "f"),       # a name not known
              (WS, ("name", "ws-042"), T, "CORP\\erin", 4624, 3, SMB, "g")]        # to itself
    assert logons.match(claims, names, between, 120) == [
        (WS, FS, T + 30, 50002, 445, "tcp", "CORP\\alice", 4624, 3, T, "FS01", "a"),
        (WS, FS, T + 5, 50001, 80, "tcp", "CORP\\bob", 4769, None, T, "FS01", "c"),
        (FS, DC, T + 50, 50010, 3389, "tcp", "CORP\\admin", 4648, None, T + 45, "fs01", "d")]
    # Closer in time, the only flow near alice's logon is not on a port it prefers: still hers.
    assert [m[2:7] for m in logons.match(claims, names, between, 10)][:2] == [
        (T + 5, 50001, 80, "tcp", "CORP\\alice"), (T + 5, 50001, 80, "tcp", "CORP\\bob")]


# ---- reading files ---------------------------------------------------------------------------

def jsonl(*records):
    return "".join(json.dumps(r) + "\n" for r in records)


def test_json_lines_and_evtx_files(tmp_path, monkeypatch, caplog):
    path = tmp_path / "security.jsonl"
    path.write_text(jsonl(logon("FS01", T, "alice", WS), event(4672, "FS01", T)) + "{broken\nnot json\n")
    assert logons.kind(path.read_bytes()[:4096]) == "jsonl"
    assert [c[3] for c in logons.read_file(path)] == ["CORP\\alice"]
    # .evtx through the evtx library, here a stand-in that gives records as the library does.
    evtx = tmp_path / "Security.evtx"
    evtx.write_bytes(logons.MAGIC + bytes(4088))

    class Parser:
        def __init__(self, path, skip_errors=False):
            assert path == str(evtx) and skip_errors

        def records_json(self):
            yield {"event_record_id": 1, "timestamp": iso(T), "data": json.dumps(logon("FS01", T, "bob", WS))}
            yield {"event_record_id": 2, "data": "{not json"}
            yield {"event_record_id": 3}

    monkeypatch.setitem(sys.modules, "evtx", types.SimpleNamespace(PyEvtxParser=Parser))
    assert [c[3] for c in logons.read_file(evtx)] == ["CORP\\bob"]

    class Broken(Parser):
        def records_json(self):
            raise RuntimeError("bad header")
            yield

    monkeypatch.setitem(sys.modules, "evtx", types.SimpleNamespace(PyEvtxParser=Broken))
    with pytest.raises(SourceError, match="not a readable .evtx file"):
        logons.read_file(evtx)

    class Empty(Parser):
        def records_json(self):
            return iter(())

    monkeypatch.setitem(sys.modules, "evtx", types.SimpleNamespace(PyEvtxParser=Empty))
    caplog.set_level(logging.WARNING)
    assert logons.read_file(evtx) == []
    assert "no event records could be read" in caplog.text
    other = tmp_path / "notes.txt"
    other.write_text('{"Event": 1}\n')
    with pytest.raises(SourceError, match="not a Windows event log"):
        logons.read_file(other)


def test_the_real_evtx_library_reads_what_it_can():
    pytest.importorskip("evtx")
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".evtx") as fh:
        fh.write(logons.MAGIC + bytes(8192))                 # a header and nothing readable
        fh.flush()
        assert logons.read_file(fh.name) == []


# ---- a case ----------------------------------------------------------------------------------

def handshake(t, src, dst, sport, dport):
    return [(t, tcp(src, dst, sport, dport, SYN)), (t + 0.001, tcp(dst, src, dport, sport, SYN | ACK))]


def case_dir(tmp_path):
    """WS-042 to FS01 over SMB as alice, then FS01 to DC01 over remote desktop as admin."""
    d = tmp_path / "case"
    d.mkdir()
    write_pcap(d / "cap.pcap", handshake(T + 60, WS, FS, 50000, 445) + handshake(T + 600, FS, DC, 50100, 3389)
               + handshake(T + 3000, FS, DC, 50101, 3389))
    (d / "Security-FS01.jsonl").write_text(jsonl(logon("FS01.corp.example", T + 61, "alice", WS)))
    (d / "Security-DC01.jsonl").write_text(jsonl(
        logon("DC01.corp.example", T + 605, "admin", FS, 10),
        event(4648, "FS01.corp.example", T + 598, TargetUserName="admin", TargetDomainName="CORP",
              TargetServerName="dc01", IpAddress="-")))
    hosts = tmp_path / "hosts"
    hosts.write_text(f"{FS} fs01.corp.example\n{DC} dc01.corp.example\n")
    return d, hosts


def test_a_case_labels_each_hop_with_its_account(tmp_path):
    d, hosts = case_dir(tmp_path)
    found = sources.find([str(d)])
    assert [p.rsplit("/", 1)[1] for p in found["events"]] == ["Security-DC01.jsonl", "Security-FS01.jsonl"]
    cfg = Config(backend="case", case_paths=[str(d)], case_db=str(tmp_path / "case.db"), hosts_file=str(hosts))
    backend = CaseBackend(cfg)
    assert backend.summary()["logons"] == 3
    [path] = backend.paths_between(WS, DC, None, None, timedelta(hours=1), 6, [])["paths"]
    assert [(h["source"], h["dport"], h["accounts"]) for h in path["hops"]] == [
        (WS, 445, ["CORP\\alice"]), (FS, 3389, ["CORP\\admin"])]
    page = backend.flows(FS, DC, datetime.fromtimestamp(T, timezone.utc),
                         datetime.fromtimestamp(T + 3600, timezone.utc), 0, 10)
    assert [f["accounts"] for f in page["flows"]] == [[
        {"account": "CORP\\admin", "event": 4648, "logon_type": None, "time": "2024-05-01T12:09:58.000Z",
         "host": "FS01.corp.example"},
        {"account": "CORP\\admin", "event": 4624, "logon_type": 10, "time": "2024-05-01T12:10:05.000Z",
         "host": "DC01.corp.example"}], []]                # the second session: no event near it
    # Reopened while the evidence is unchanged: the same; a changed hosts file rebuilds the case.
    assert CaseBackend(cfg).summary()["logons"] == 3
    tight = Config(**{**cfg.__dict__, "logon_tolerance": "3s"})        # a changed tolerance rebuilds it
    assert CaseBackend(tight).summary()["logons"] == 2
    assert CaseBackend(cfg).summary()["logons"] == 3
    hosts.write_text(f"{FS} fs01.corp.example\n")
    assert CaseBackend(cfg).summary()["logons"] == 1         # DC01's name is no longer known
    hosts.unlink()
    with pytest.raises(SourceError, match="TB_HOSTS_FILE: can't read"):
        CaseBackend(cfg)


def test_a_tighter_tolerance_labels_fewer_flows(tmp_path):
    d, hosts = case_dir(tmp_path)
    cfg = Config(backend="case", case_paths=[str(d)], hosts_file=str(hosts), logon_tolerance="3s")
    assert CaseBackend(cfg).summary()["logons"] == 2          # the remote desktop logon came 5 s after


# ---- the accounts API ------------------------------------------------------------------------

def accounts_client(tmp_path):
    from threatbridge.app import create_app
    flows = [Flow(WS, FS, 50000, 445, "tcp", T + 60, T + 61, 2, 120, "x.pcap", "smb"),
             Flow(WS, FS, 50001, 445, "tcp", T + 900, T + 901, 2, 120, "x.pcap", "smb"),
             Flow(WS, FS, 50002, 445, "tcp", T + 7200, T + 7201, 2, 120, "x.pcap", "smb")]
    events = [logon("FS01", T + 61, "alice", WS), logon("FS01", T + 902, "alice", WS),
              event(4769, "DC01", T + 899, TargetUserName="alice@CORP.EXAMPLE", ServiceName="cifs/fs01", IpAddress=WS),
              logon("FS01", T + 7200, "bob", WS)]
    cfg = Config(backend="case", live_dns=False, compromised_file=str(tmp_path / "c.json"),
                 exclude_file=str(tmp_path / "ex.json"))
    backend = CaseBackend(cfg, flows=flows, dns={"fs01.corp.example": {FS: [T, T + 9000]}}, events=events)
    return create_app(cfg, backend).test_client()


def test_the_accounts_that_made_a_connections_flows(tmp_path):
    c = accounts_client(tmp_path)
    assert c.get("/api/config").get_json()["case"]["logons"] == 4
    q = f"/api/accounts?src={WS}&dst={FS}&from=2024-05-01T12:00:00Z&to=2024-05-01T14:00:00Z"
    assert c.get(q).get_json() == {
        "src": WS, "dst": FS, "start": "2024-05-01T12:00:00.000Z", "end": "2024-05-01T14:00:00.000Z", "accounts": [
            {"account": "CORP\\alice", "flows": 2, "first_seen": "2024-05-01T12:01:00.000Z",
             "last_seen": "2024-05-01T12:15:00.000Z", "events": [4624]},
            {"account": "alice@CORP.EXAMPLE", "flows": 1, "first_seen": "2024-05-01T12:15:00.000Z",
             "last_seen": "2024-05-01T12:15:00.000Z", "events": [4769]},
            {"account": "CORP\\bob", "flows": 1, "first_seen": "2024-05-01T14:00:00.000Z",
             "last_seen": "2024-05-01T14:00:00.000Z", "events": [4624]}]}
    # The 4624 at 12:15:02 and the 4769 at 12:14:59 both name the flow at 12:15.
    r = c.get(f"/api/flows?src={WS}&dst={FS}&from=2024-05-01T12:10:00Z&to=2024-05-01T12:20:00Z").get_json()
    assert [(a["account"], a["event"]) for a in r["flows"][0]["accounts"]] == [
        ("alice@CORP.EXAMPLE", 4769), ("CORP\\alice", 4624)]
    # A time range narrows the answer; POST takes the same.
    r = c.post("/api/accounts", json={"src": WS, "dst": FS, "from": "2024-05-01T12:00:00Z",
                                      "to": "2024-05-01T14:00:00Z", "range_to": "2024-05-01T12:10:00Z"},
               headers={"X-ThreatBridge": "1"}).get_json()
    assert [a["account"] for a in r["accounts"]] == ["CORP\\alice"]
    assert c.get(f"/api/accounts?src={FS}&dst={WS}&from=2024-05-01T12:00:00Z&to=2024-05-01T14:00:00Z"
                 ).get_json()["accounts"] == []
    assert c.get(f"/api/accounts?src=x&dst={FS}&from=2024-05-01T12:00:00Z&to=2024-05-01T14:00:00Z"
                 ).status_code == 400


def test_accounts_need_the_case_backend(tmp_path):
    from threatbridge.app import create_app
    from threatbridge.backends import DemoBackend
    cfg = Config(backend="demo", live_dns=False, compromised_file=str(tmp_path / "c.json"))
    demo = create_app(cfg, DemoBackend(cfg)).test_client()
    assert demo.get(f"/api/accounts?src={WS}&dst={FS}&from=2024-05-01T12:00:00Z&to=2024-05-01T14:00:00Z"
                    ).status_code == 501
