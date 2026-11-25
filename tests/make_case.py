"""Write a small attack-chain capture for the case-mode UI test.

    python tests/make_case.py OUTDIR

203.0.113.66 -> 10.0.0.5 (443) -> 10.0.0.9 (445) -> 10.0.0.20 (3389), ten minutes apart,
a shortcut 10.0.0.5 -> 10.0.0.20 (5985) in between, traffic that is not on the chain, and a
DNS answer: updates.example.com -> 10.0.0.77.

Apart from the chain (no connection to it): 10.0.1.1 -> 10.0.1.2, 120 connections ten seconds
apart, to page through; 12 two-hop routes 10.0.2.1 -> 10.0.2.10..21 -> 10.0.2.2; and, for marks
and filters (ui_marks.mjs), the timeline E -> A -> X -> B, X -> C, B -> F, A -> Y (10.9.0.1-7),
with 10.9.1.1 -> 10.9.1.2 on its own.

DHCP (dhcpd.leases): 10.0.0.5 was ws-042's until 12:30, then laptop-7's.

Windows Security events (Security.jsonl), the servers named by DNS answers (fs01.corp.example
is 10.0.0.9, dc01.corp.example is 10.0.0.20): CORP\\alice logged on to FS01 over SMB and to DC01
over WinRM from 10.0.0.5, then CORP\\admin to DC01 over remote desktop from 10.0.0.9.

And on hosts of their own: a beacon, 10.8.0.5 -> 198.51.100.9 (443) about every minute (10%
jitter, 30 times, from 13:23:20), and a long connection, 10.8.0.6 -> 198.51.100.10 (22), kept
alive for two hours from 13:40.
"""
import json
import random
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # for threatbridge
from evidence import ACK, SYN, dns_answer, tcp, udp, write_pcap  # noqa: E402

T = 1_714_564_800.0  # 2024-05-01T12:00:00Z
CONNECTIONS = [
    ("203.0.113.66", "10.0.0.5", 443, T),
    ("10.0.0.5", "10.0.0.9", 445, T + 600),
    ("10.0.0.9", "10.0.0.20", 3389, T + 1200),
    ("10.0.0.20", "10.0.0.30", 22, T - 600),    # before 10.0.0.20 was reached
    ("10.0.0.77", "10.0.0.9", 80, T + 1800),     # into 10.0.0.9, after the 445 hop
    ("10.0.0.5", "10.0.0.20", 5985, T + 900),    # a second way to 10.0.0.20
]
BUSY = [("10.0.1.1", "10.0.1.2", 8443, T + 3000 + 10 * i) for i in range(120)]
FAN = [("10.0.2.1", f"10.0.2.{10 + i}", 445, T + 100 + i) for i in range(12)] + \
      [(f"10.0.2.{10 + i}", "10.0.2.2", 3389, T + 200 + i) for i in range(12)]
STORY = [("10.9.0.1", "10.9.0.2", 443, T + 100),    # E -> A, TLS
         ("10.9.0.2", "10.9.0.3", 445, T + 400),    # A -> X, SMB
         ("10.9.0.3", "10.9.0.4", 3389, T + 700),   # X -> B, RDP
         ("10.9.0.3", "10.9.0.5", 445, T + 1000),   # X -> C, SMB
         ("10.9.0.4", "10.9.0.6", 22, T + 1300),    # B -> F, SSH
         ("10.9.0.2", "10.9.0.7", 80, T + 1900),    # A -> Y, HTTP
         ("10.9.0.2", "10.9.0.7", 53, T + 1960),    # A -> Y, DNS
         ("10.9.1.1", "10.9.1.2", 445, T + 500)]    # a part of the map of its own


LEASES = """# The format of this file is documented in the dhcpd.leases(5) manual page.
lease 10.0.0.5 {
  starts 3 2024/05/01 06:00:00;
  ends 3 2024/05/01 18:00:00;
  hardware ethernet 00:11:22:33:44:55;
  client-hostname "ws-042";
}
lease 10.0.0.5 {
  starts 3 2024/05/01 12:30:00;
  ends never;
  hardware ethernet 66:77:88:99:aa:bb;
  client-hostname "laptop-7";
}
"""


def logon(computer, t, user, ip, logon_type):
    """A 4624 record as evtx_dump writes it, one JSON line."""
    when = datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f0Z")
    return json.dumps({"Event": {"System": {"EventID": 4624, "TimeCreated": {"#attributes": {"SystemTime": when}},
                                            "Computer": computer},
                                 "EventData": {"TargetUserName": user, "TargetDomainName": "CORP",
                                               "LogonType": logon_type, "IpAddress": ip, "IpPort": "50001"}}})


EVENTS = [logon("FS01.corp.example", T + 601, "alice", "10.0.0.5", 3),
          logon("DC01.corp.example", T + 901, "alice", "10.0.0.5", 3),
          logon("DC01.corp.example", T + 1203, "admin", "10.0.0.9", 10)]


def beacon():
    rng, t, out = random.Random(5), T + 5000, []
    for _ in range(30):
        out.append(("10.8.0.5", "198.51.100.9", 443, t))
        t += 60 * (1 + rng.uniform(-0.1, 0.1))
    return out


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    packets = []
    for i, (c, s, port, t) in enumerate(CONNECTIONS + BUSY + FAN + STORY + beacon()):
        packets += [(t, tcp(c, s, 50000 + i, port, SYN)), (t + 0.001, tcp(s, c, port, 50000 + i, SYN | ACK))]
    # The long connection: a keep-alive every 4 minutes, under TCP's 5-minute idle timeout.
    long_c, long_s, start = "10.8.0.6", "198.51.100.10", T + 6000
    packets += [(start, tcp(long_c, long_s, 41000, 22, SYN)), (start + 0.001, tcp(long_s, long_c, 22, 41000, SYN | ACK))]
    packets += [(start + 240 * k, tcp(long_c, long_s, 41000, 22, ACK, b"k")) for k in range(1, 31)]
    # Before the chain, so it is not on any threat line: one flow of DNS questions and answers.
    for k, (name, ip) in enumerate([("updates.example.com", "10.0.0.77"), ("fs01.corp.example", "10.0.0.9"),
                                    ("dc01.corp.example", "10.0.0.20")]):
        packets += [(T - 1200 + k, udp("10.0.0.9", "10.0.0.53", 40000, 53, b"q")),
                    (T - 1199.99 + k, udp("10.0.0.53", "10.0.0.9", 53, 40000, dns_answer(name, [(name, "A", ip)])))]
    write_pcap(os.path.join(outdir, "chain.pcap"), sorted(packets, key=lambda p: p[0]))
    with open(os.path.join(outdir, "dhcpd.leases"), "w") as fh:
        fh.write(LEASES)
    with open(os.path.join(outdir, "Security.jsonl"), "w") as fh:
        fh.write("".join(e + "\n" for e in EVENTS))


if __name__ == "__main__":
    main(sys.argv[1])
