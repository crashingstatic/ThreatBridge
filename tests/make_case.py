"""Write a small attack-chain capture for the case-mode UI test.

    python tests/make_case.py OUTDIR

203.0.113.66 -> 10.0.0.5 (443) -> 10.0.0.9 (445) -> 10.0.0.20 (3389), ten minutes apart,
a shortcut 10.0.0.5 -> 10.0.0.20 (5985) in between, traffic that is not on the chain, and a
DNS answer: updates.example.com -> 10.0.0.77.

Apart from the chain (no connection to it): 10.0.1.1 -> 10.0.1.2, 120 connections ten seconds
apart, to page through; and 12 two-hop routes 10.0.2.1 -> 10.0.2.10..21 -> 10.0.2.2.
"""
import os
import sys

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


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    packets = []
    for i, (c, s, port, t) in enumerate(CONNECTIONS + BUSY + FAN):
        packets += [(t, tcp(c, s, 50000 + i, port, SYN)), (t + 0.001, tcp(s, c, port, 50000 + i, SYN | ACK))]
    # Before the chain, so it is not on any threat line.
    packets += [(T - 1200, udp("10.0.0.9", "10.0.0.53", 40000, 53, b"q")),
                (T - 1199.99, udp("10.0.0.53", "10.0.0.9", 53, 40000, dns_answer(
                    "updates.example.com", [("updates.example.com", "A", "10.0.0.77")])))]
    write_pcap(os.path.join(outdir, "chain.pcap"), sorted(packets, key=lambda p: p[0]))


if __name__ == "__main__":
    main(sys.argv[1])
