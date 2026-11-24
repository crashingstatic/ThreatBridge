"""The evidence files' SHA-256 for the report (item 9, D31): hashed when asked, in the
background, kept until a file changes."""
import hashlib
import os
import time

from evidence import ACK, SYN, tcp, write_pcap
from threatbridge.app import create_app
from threatbridge.backends import CaseBackend, DemoBackend
from threatbridge.config import Config

T = 1_714_564_800.0


def until_done(client):
    for _ in range(200):
        r = client.get("/api/evidence").get_json()
        if r["done"]:
            return r
        time.sleep(0.02)
    raise AssertionError("hashing never finished")


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def test_the_evidence_files_and_their_digests(tmp_path, monkeypatch):
    from threatbridge import hashing
    monkeypatch.setattr(hashing, "CHUNK", 64)              # several reads per file
    d = tmp_path / "case"
    d.mkdir()
    write_pcap(d / "cap.pcap", [(T, tcp("10.0.0.5", "10.0.0.9", 50000, 445, SYN)),
                                (T + 0.001, tcp("10.0.0.9", "10.0.0.5", 445, 50000, SYN | ACK))])
    (d / "dhcpd.leases").write_text("lease 10.0.0.5 {\n  starts 3 2024/05/01 08:00:00;\n"
                                    "  hardware ethernet 00:11:22:33:44:55;\n}\n")
    hosts = tmp_path / "hosts"
    hosts.write_text("10.0.0.9 fs01\n")
    cfg = Config(backend="case", case_paths=[str(d)], hosts_file=str(hosts), live_dns=False,
                 compromised_file=str(tmp_path / "c.json"), exclude_file=str(tmp_path / "ex.json"))
    client = create_app(cfg, CaseBackend(cfg)).test_client()
    r = until_done(client)
    paths = [str(d / "cap.pcap"), str(d / "dhcpd.leases"), str(hosts)]
    assert [f["path"] for f in r["files"]] == sorted(paths)
    assert all(f["state"] == "unchanged" and f["sha256"] == sha(f["path"]) for f in r["files"])
    assert r["total"] == r["hashed"] == sum(os.path.getsize(p) for p in paths)
    assert r["settings"] == {"TB_DHCP_TIMEZONE": "UTC", "TB_LOGON_TOLERANCE": "2m"}
    assert r["files"][0]["modified"].endswith("Z")
    # Asked again while nothing changed: the same digests, not hashed again.
    assert client.get("/api/evidence").get_json() == r
    # A file changed since the case was built: hashed again, its digest of what it holds now.
    with open(d / "dhcpd.leases", "a") as fh:
        fh.write("# edited\n")
    os.utime(d / "dhcpd.leases", ns=(time.time_ns(), time.time_ns() + 10**9))
    r = until_done(client)
    changed = {f["path"]: f for f in r["files"]}[str(d / "dhcpd.leases")]
    assert changed["state"] == "changed" and changed["sha256"] == sha(d / "dhcpd.leases")
    assert changed["size"] == os.path.getsize(d / "dhcpd.leases")
    # A file gone: missing, without a digest.
    os.remove(hosts)
    r = until_done(client)
    gone = {f["path"]: f for f in r["files"]}[str(hosts)]
    assert (gone["state"], gone["sha256"], gone["size"]) == ("missing", None, len("10.0.0.9 fs01\n"))


def test_a_case_given_flows_has_no_files(tmp_path):
    from threatbridge.model import Flow
    cfg = Config(backend="case", live_dns=False, compromised_file=str(tmp_path / "c.json"))
    flows = [Flow("10.0.0.5", "10.0.0.9", 50000, 445, "tcp", T, T + 1, 2, 120, "x", "smb")]
    client = create_app(cfg, CaseBackend(cfg, flows=flows)).test_client()
    assert until_done(client) == {"done": True, "hashed": 0, "total": 0, "files": [], "settings": {}}


def test_evidence_needs_the_case_backend(tmp_path):
    cfg = Config(backend="demo", live_dns=False, compromised_file=str(tmp_path / "c.json"))
    assert create_app(cfg, DemoBackend(cfg)).test_client().get("/api/evidence").status_code == 501
