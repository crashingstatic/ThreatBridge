import os
import time

import pytest

from evidence import (ACK, FIN, PSH, RST, SYN, have_nfdump, icmp_echo, ip_bytes, make_nfcapd,
                      tcp, udp, write_pcap)
from threatbridge import sources
from threatbridge.model import Flow, SourceError
from threatbridge.sources.netflow import pair_records, parse_pipe_line

C, S, R = "10.0.0.5", "10.0.0.9", "8.8.8.8"
T = 1_714_564_800.0


def handshake(c=C, s=S, cport=50000, sport=445, t=T):
    """Full TCP connection c -> s: handshake, data both ways, FIN both ways."""
    return [
        (t + 0.000, tcp(c, s, cport, sport, SYN)),
        (t + 0.001, tcp(s, c, sport, cport, SYN | ACK)),
        (t + 0.002, tcp(c, s, cport, sport, ACK)),
        (t + 0.003, tcp(c, s, cport, sport, PSH | ACK, b"x" * 100)),
        (t + 0.004, tcp(s, c, sport, cport, PSH | ACK, b"y" * 200)),
        (t + 0.005, tcp(c, s, cport, sport, FIN | ACK)),
        (t + 0.006, tcp(s, c, sport, cport, FIN | ACK)),
        (t + 0.007, tcp(c, s, cport, sport, ACK)),
    ]


def load_packets(tmp_path, packets, **kw):
    path = tmp_path / "cap.pcap"
    write_pcap(path, packets, **kw)
    return sources.load([str(path)])


def endpoints(flows):
    return [(f.src, f.sport, f.dst, f.dport, f.proto) for f in flows]


# ---- pcap -------------------------------------------------------------------------------

def test_tcp_connection_is_one_flow_from_initiator(tmp_path):
    pkts = handshake()
    [f] = load_packets(tmp_path, pkts)
    assert (f.src, f.sport, f.dst, f.dport, f.proto) == (C, 50000, S, 445, "tcp")
    assert f.packets == 8 and f.bytes == ip_bytes(pkts) == 8 * 40 + 300
    assert f.start == pytest.approx(T) and f.end == pytest.approx(T + 0.007)
    assert f.source == str(tmp_path / "cap.pcap")


def test_orientation_without_syn(tmp_path):
    # Capture starts at the SYN-ACK: the receiver of the SYN-ACK is the initiator.
    syn_ack = load_packets(tmp_path, handshake()[1:])
    # Capture starts mid-stream with the server talking: port heuristic.
    midstream = load_packets(tmp_path, [(T, tcp(S, C, 443, 51000, ACK)),
                                        (T + 1, tcp(C, S, 51000, 443, ACK))])
    assert endpoints(syn_ack) == [(C, 50000, S, 445, "tcp")]
    assert endpoints(midstream) == [(C, 51000, S, 443, "tcp")]


def test_udp_idle_timeout_splits_and_lone_reply_is_flipped(tmp_path):
    pkts = [
        (T, udp(C, R, 53000, 53, b"q")), (T + 0.01, udp(R, C, 53, 53000, b"a")),
        (T + 120, udp(C, R, 53000, 53, b"q")),       # > 60 s idle: a new flow
        (T + 200, udp(R, C, 53, 53001, b"a")),       # response whose query was not captured
    ]
    flows = load_packets(tmp_path, pkts)
    assert endpoints(flows) == [(C, 53000, R, 53, "udp")] * 2 + [(C, 53001, R, 53, "udp")]
    assert [f.packets for f in flows] == [2, 1, 1]


def test_rst_and_port_reuse_start_new_flows(tmp_path):
    pkts = [(T, tcp(C, S, 50000, 80, SYN)), (T + 0.1, tcp(S, C, 80, 50000, RST | ACK))]
    pkts += handshake(sport=80, t=T + 1)              # same 5-tuple after the RST
    pkts += handshake(sport=80, t=T + 2)              # and again after FINs
    flows = load_packets(tmp_path, pkts)
    assert [f.packets for f in flows] == [2, 8, 8]
    assert set(endpoints(flows)) == {(C, 50000, S, 80, "tcp")}


def test_icmp_and_ipv6(tmp_path):
    a6, b6 = "2001:db8::5", "2001:db8::9"
    pkts = [(T, icmp_echo(C, R)), (T + 0.02, icmp_echo(R, C, reply=True))]
    pkts += handshake(a6, b6, t=T + 1)
    flows = load_packets(tmp_path, pkts)
    assert endpoints(flows) == [(C, 0, R, 0, "icmp"), (a6, 50000, b6, 445, "tcp")]
    assert flows[1].bytes == 8 * 60 + 300


@pytest.mark.parametrize("linktype,nano", [(101, False), (113, False), (276, False), (1, True)])
def test_link_types_and_nanosecond_pcap(tmp_path, linktype, nano):
    flows = load_packets(tmp_path, handshake(), linktype=linktype, nano=nano)
    assert endpoints(flows) == [(C, 50000, S, 445, "tcp")]
    assert flows[0].bytes == 8 * 40 + 300


def test_non_ip_frames_are_ignored(tmp_path):
    arp = bytes.fromhex("ffffffffffff001122334455" "0806") + bytes(28)
    flows = load_packets(tmp_path, [(T - 1, arp)] + handshake())
    assert len(flows) == 1


def test_rotated_captures_are_read_in_time_order(tmp_path):
    pkts = handshake()
    d = tmp_path / "caps"
    d.mkdir()
    # tcpdump -C/-G rotation; names deliberately sort opposite to capture order.
    write_pcap(d / "b.pcap", pkts[:4])
    write_pcap(d / "a.pcap", pkts[4:])
    [f] = sources.load([str(d)])
    assert f.packets == 8 and f.source == str(d / "b.pcap")


def test_directory_walk_and_errors(tmp_path):
    d = tmp_path / "evidence"
    (d / "sub").mkdir(parents=True)
    write_pcap(d / "sub" / "one.pcap", handshake())
    (d / "notes.txt").write_text("not evidence")
    (d / ".hidden.pcap").write_bytes(b"junk")
    assert len(sources.load([str(d)])) == 1

    with pytest.raises(SourceError, match="not a pcap or nfcapd"):
        sources.load([str(d / "notes.txt")])
    (d / "x.pcapng").write_bytes(bytes.fromhex("0a0d0d0a") + bytes(28))
    with pytest.raises(SourceError, match="pcapng is not supported"):
        sources.load([str(d)])
    with pytest.raises(SourceError, match="no pcap or nfcapd"):
        sources.load([str(tmp_path / "evidence" / "sub" / "..")] if False else [str(_empty(tmp_path))])
    with pytest.raises(SourceError, match="no such file"):
        sources.load([str(tmp_path / "missing")])


def _empty(tmp_path):
    e = tmp_path / "empty"
    e.mkdir()
    return e


# ---- NetFlow (nfdump) ---------------------------------------------------------------------

# Real `nfdump -q -o pipe` output from nfdump 1.7.3.
PIPE_V4 = "2|1792437101000|1792437111000|6|0|0|0|167772165|50000|0|0|0|167772169|445|0|0|0|0|27|0|10|1500"
PIPE_V6 = ("10|1792437238000|1792437242000|6|536939960|2863315899|3435978205|4008574977|51000|"
           "536939960|286335522|858997828|1431660134|22|0|0|0|0|0|0|5|400")


def test_parse_pipe_lines():
    assert parse_pipe_line(PIPE_V4) == (1792437101.0, 1792437111.0, "tcp", C, 50000, S, 445, 10, 1500)
    rec = parse_pipe_line(PIPE_V6)
    assert rec[3] == "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"
    assert rec[5] == "2001:db8:1111:2222:3333:4444:5555:6666"
    icmp = parse_pipe_line("2|0|0|1|0|0|0|167772165|0|0|0|0|134744072|2048|0|0|0|0|0|0|1|84")
    assert (icmp[2], icmp[4], icmp[6]) == ("icmp", 0, 0)
    with pytest.raises(SourceError, match="unexpected nfdump output"):
        parse_pipe_line("2|1|2|6")


def rec(src, sport, dst, dport, start, end, packets=1, nbytes=100, proto="tcp"):
    return (start, end, proto, src, sport, dst, dport, packets, nbytes, "nf")


def test_pairing_merges_halves_and_orients():
    halves = [rec(S, 445, C, 50000, T, T + 10, 8, 9000), rec(C, 50000, S, 445, T, T + 10, 10, 1500)]
    for records in (halves, halves[::-1]):    # same millisecond: port heuristic decides
        [f] = pair_records(records)
        assert (f.src, f.dst, f.packets, f.bytes) == (C, S, 18, 10500)
    # A strictly earlier half wins over the port heuristic.
    [f] = pair_records([rec(S, 443, C, 50000, T, T + 1), rec(C, 50000, S, 443, T + 0.5, T + 1)])
    assert (f.src, f.dst) == (S, C)
    # Only the reply was exported: port heuristic.
    [f] = pair_records([rec(R, 53, C, 53000, T, T, proto="udp")])
    assert (f.src, f.sport, f.dst, f.dport) == (C, 53000, R, 53)


def test_pairing_rejoins_exporter_splits_but_not_idle_gaps():
    split = [rec(C, 50000, S, 22, T, T + 1800), rec(S, 22, C, 50000, T, T + 1800),
             rec(C, 50000, S, 22, T + 1800, T + 2000), rec(S, 22, C, 50000, T + 1800, T + 2000)]
    [f] = pair_records(split)
    assert (f.src, f.packets, f.end) == (C, 4, T + 2000)
    gap = [rec(C, 50000, S, 22, T, T + 1), rec(C, 50000, S, 22, T + 1000, T + 1001)]
    assert len(pair_records(gap)) == 2


# CI installs nfdump, so there a missing binary fails the test instead of skipping it.
@pytest.mark.skipif(not have_nfdump() and not os.environ.get("CI"),
                    reason="nfdump/nfcapd not installed")
def test_real_nfcapd_file(tmp_path):
    now = int(time.time())
    t = now - 100
    path = make_nfcapd(tmp_path, [
        (C, S, 50000, 445, 6, 10, 1500, t, t + 10),
        (S, C, 445, 50000, 6, 8, 9000, t, t + 10),
        (C, R, 53000, 53, 17, 1, 70, t + 50, t + 50),
    ], now)
    flows = sources.load([str(tmp_path)])    # directory: skips nfcapd's hidden stat file
    assert [(f.src, f.dst, f.dport, f.proto, f.packets, f.bytes) for f in flows] == [
        (C, S, 445, "tcp", 18, 10500), (C, R, 53, "udp", 1, 70)]
    assert flows[0].start == t and flows[0].end == t + 10
    assert flows[0].source == path and os.path.basename(path).startswith("nfcapd.")


def test_flow_is_compact():
    f = Flow(C, S, 1, 2, "tcp", T, T, 1, 1, "x")
    assert not hasattr(f, "__dict__")
