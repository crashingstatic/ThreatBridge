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


# ---- edge cases ---------------------------------------------------------------------------

import socket  # noqa: E402
import struct  # noqa: E402

import dpkt  # noqa: E402

from evidence import MAC, dns_answer  # noqa: E402
from threatbridge.sources.netflow import read_records  # noqa: E402
from threatbridge.sources.pcap import record_dns  # noqa: E402


def frame(pkt):
    ip, etype, _ = pkt
    return bytes(dpkt.ethernet.Ethernet(src=MAC, dst=MAC, type=etype, data=ip))


def test_a_capture_cut_off_inside_a_record_keeps_what_came_before(tmp_path):
    path = tmp_path / "cut.pcap"
    write_pcap(path, handshake())
    path.write_bytes(path.read_bytes() + b"\0" * 8)          # tcpdump killed mid-write
    assert endpoints(sources.load([str(path)])) == [(C, 50000, S, 445, "tcp")]
    only_junk = tmp_path / "junk.pcap"
    write_pcap(only_junk, [])
    only_junk.write_bytes(only_junk.read_bytes() + b"\0" * 8)
    assert sources.load([str(only_junk)]) == []


def test_header_only_capture_has_no_flows(tmp_path):
    assert load_packets(tmp_path, []) == []


def test_idle_timeout_is_exclusive(tmp_path):
    q = lambda t: (t, udp(C, R, 53000, 53, b"q"))  # noqa: E731
    flows = load_packets(tmp_path, [q(T), q(T + 60), q(T + 120.001)])   # 60 s apart: same flow
    assert [(f.start, f.end) for f in flows] == [(T, T + 60), (T + 120.001, T + 120.001)]
    [f] = pair_records([rec(C, 53000, R, 53, T, T, proto="udp"),
                        rec(C, 53000, R, 53, T + 60, T + 60, proto="udp")])
    assert f.end == T + 60
    assert len(pair_records([rec(C, 53000, R, 53, T, T, proto="udp"),
                             rec(C, 53000, R, 53, T + 60.001, T + 61, proto="udp")])) == 2


def test_vlan_tagged_frames(tmp_path):
    tagged = [(t, (lambda b: b[:12] + struct.pack("!HH", 0x8100, 42) + b[12:])(frame(p)))
              for t, p in handshake()]
    [f] = load_packets(tmp_path, tagged)
    assert (f.src, f.dst, f.dport, f.packets) == (C, S, 445, 8)


def test_ip_total_length_zero_is_counted_by_size(tmp_path):
    # Captured on the sending host with segmentation offload: IPv4 total length reads 0.
    pkt = tcp(C, S, 50000, 445, PSH | ACK, b"z" * 100)
    raw = frame(pkt)
    [f] = load_packets(tmp_path, [(T, raw[:16] + b"\0\0" + raw[18:])])
    assert (f.sport, f.dport, f.bytes) == (50000, 445, 140)


def test_a_transport_header_cut_by_the_snap_length(tmp_path):
    # tcpdump -s: the ports (first 4 bytes) survive, so the packet still counts in its flow.
    cut = frame(tcp(C, S, 50000, 445, SYN))[:14 + 20 + 8]
    flows = load_packets(tmp_path, [(T, cut)] + handshake(t=T + 1))
    assert endpoints(flows) == [(C, 50000, S, 445, "tcp")] and flows[0].packets == 9
    # Too short to hold the ports: skipped, never a flow on port 0.
    stub = frame(udp(C, R, 53000, 53, b"q"))[:14 + 20 + 2]
    assert load_packets(tmp_path, [(T, stub)]) == []


def ipv6_fragment(offset, payload, more=True):
    src, dst = (socket.inet_pton(socket.AF_INET6, a) for a in ("2001:db8::5", "2001:db8::9"))
    # next header, reserved, offset in 8-byte units << 3 | more-fragments flag, id
    frag = struct.pack("!BBHI", 6, 0, ((offset // 8) << 3) | int(more), 9)
    ip6 = dpkt.ip6.IP6(src=src, dst=dst, nxt=44, hlim=64, data=frag + payload)
    ip6.plen = 8 + len(payload)
    return bytes(dpkt.ethernet.Ethernet(src=MAC, dst=MAC, type=dpkt.ethernet.ETH_TYPE_IP6,
                                        data=bytes(ip6)))


def test_ipv6_fragments(tmp_path):
    first = bytes(dpkt.tcp.TCP(sport=50000, dport=445, flags=SYN | ACK, off=5)) + b"a" * 32
    flows = load_packets(tmp_path, [(T, ipv6_fragment(0, first)),
                                    (T + 0.001, ipv6_fragment(1000, b"\xaa" * 48, more=False))])
    # The first fragment carries the ports; a later one is payload only and adds no flow.
    assert endpoints(flows) == [("2001:db8::9", 445, "2001:db8::5", 50000, "tcp")]


def test_dns_answers_only_follow_the_question():
    dns = {}
    record_dns(dns_answer("evil.test", [
        ("cdn.test", "A", "6.6.6.6"),                          # chain listed out of order
        ("evil.test", "CNAME", "cdn.test"),
        ("updates.example.com", "A", "6.6.6.7"),               # not part of the answer to evil.test
    ]), T, dns)
    assert dns == {"evil.test": {"6.6.6.6": [T, T]}, "cdn.test": {"6.6.6.6": [T, T]}}


@pytest.mark.parametrize("line", [
    "0|0|0|6|0|0|0|1|50000|0|0|0|2|445|0|0|0|0|0|0|1|1",        # unknown address family
    "2|x|0|6|0|0|0|1|50000|0|0|0|2|445|0|0|0|0|0|0|1|1",        # not a number
])
def test_unreadable_nfdump_lines_are_source_errors(line):
    with pytest.raises(SourceError, match="unexpected nfdump output"):
        parse_pipe_line(line)


def fake_nfdump(tmp_path, monkeypatch, script):
    exe = tmp_path / "nfdump"
    exe.write_text("#!/bin/sh\n" + script)
    exe.chmod(0o755)
    monkeypatch.setenv("TB_NFDUMP", str(exe))


def test_nfdump_errors(tmp_path, monkeypatch):
    fake_nfdump(tmp_path, monkeypatch, 'echo "Corrupt data file" >&2\nexit 3\n')
    with pytest.raises(SourceError, match="nfdump failed: Corrupt data file"):
        list(read_records("x"))
    fake_nfdump(tmp_path, monkeypatch, 'echo "Summary: 1 flow"\nexec sleep 30\n')
    t = time.monotonic()
    with pytest.raises(SourceError, match="unexpected nfdump output"):
        list(read_records("x"))
    assert time.monotonic() - t < 5                          # nfdump is stopped, not waited for
    monkeypatch.setenv("TB_NFDUMP", str(tmp_path / "missing"))
    with pytest.raises(SourceError, match="nfdump not found"):
        list(read_records("x"))


def test_the_same_file_named_twice_is_read_once(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    write_pcap(d / "cap.pcap", handshake())
    os.symlink(d / "cap.pcap", tmp_path / "link.pcap")
    paths = [str(d), str(d / "cap.pcap"), str(tmp_path / "link.pcap")]
    assert sources.find(paths)["pcap"] == [str(d / "cap.pcap")]
    assert len(sources.load(paths)) == 1


def test_files_that_are_not_evidence(tmp_path):
    (tmp_path / "empty").write_bytes(b"")
    with pytest.raises(SourceError, match="not a pcap or nfcapd file"):
        sources.find([str(tmp_path / "empty")])
    live = tmp_path / "nfcapd.current.4242"
    live.write_bytes(bytes.fromhex("0ca5") + b"\0" * 30)
    with pytest.raises(SourceError, match="still being written"):
        sources.find([str(live)])


# ---- gaps found by mutation testing -------------------------------------------------------

from threatbridge import model  # noqa: E402


def test_model_helpers():
    assert (model.idle_timeout("tcp"), model.idle_timeout("udp"), model.idle_timeout("icmp")) == (300, 60, 60)
    assert model.idle_timeout("47") == 60                                   # anything else
    assert (model.proto_name(6), model.proto_name(58), model.proto_name(47)) == ("tcp", "icmp", "47")
    assert model.looks_reversed(1023, 1024) and not model.looks_reversed(1024, 1024)
    assert not model.looks_reversed(80, 1023) and model.looks_reversed(0, 65535)


def test_tcp_idle_timeout_is_five_minutes(tmp_path):
    a = lambda t: (t, tcp(C, S, 50000, 445, PSH | ACK, b"x"))  # noqa: E731
    flows = load_packets(tmp_path, [a(T), a(T + 300), a(T + 600.001)])
    assert [(f.start, f.end) for f in flows] == [(T, T + 300), (T + 600.001, T + 600.001)]


def test_other_ip_protocols_are_flows_too(tmp_path):
    gre = dpkt.ip.IP(src=socket.inet_aton(C), dst=socket.inet_aton(S), p=47, ttl=64, data=b"\0" * 24)
    gre.len = 44
    raw = bytes(dpkt.ethernet.Ethernet(src=MAC, dst=MAC, type=0x0800, data=gre))
    [f] = load_packets(tmp_path, [(T, raw), (T + 30, raw)])
    assert (f.proto, f.sport, f.dport, f.packets) == ("47", 0, 0, 2)


def test_skipped_packets_do_not_stop_the_capture(tmp_path):
    later_v4 = dpkt.ip.IP(src=socket.inet_aton(C), dst=socket.inet_aton(S), p=6, ttl=64,
                          data=b"\xbb" * 40, offset=800)
    later_v4.len = 60
    junk = [
        b"\x01\x02",                                                       # undecodable frame
        bytes(dpkt.ethernet.Ethernet(src=MAC, dst=MAC, type=0x0800, data=bytes(later_v4))),
        ipv6_fragment(1000, b"\xaa" * 48, more=False),                     # later IPv6 fragment
        frame(udp(C, R, 53000, 53, b"q"))[:14 + 20 + 2],                  # header too short for ports
    ]
    flows = load_packets(tmp_path, [(T + i * 0.001, j) for i, j in enumerate(junk)] + handshake(t=T + 1))
    assert endpoints(flows) == [(C, 50000, S, 445, "tcp")]


def test_snap_length_boundaries(tmp_path):
    # Exactly 4 bytes: the ports. 14 bytes: the TCP flags too, so a lone SYN-ACK still
    # shows who the server was.
    ports_only = frame(tcp(C, S, 50000, 445, SYN))[:14 + 20 + 4]
    [f] = load_packets(tmp_path, [(T, ports_only)])
    assert (f.sport, f.dport) == (50000, 445)
    synack = frame(tcp(S, C, 445, 50000, SYN | ACK))[:14 + 20 + 14]
    [f] = load_packets(tmp_path, [(T, synack)])
    assert (f.src, f.sport, f.dst, f.dport) == (C, 50000, S, 445)


def test_raw_ip_captures_with_ipv6(tmp_path):
    [f] = load_packets(tmp_path, [(T, tcp("2001:db8::5", "2001:db8::9", 50000, 22, SYN))], linktype=101)
    assert (f.src, f.dst, f.dport) == ("2001:db8::5", "2001:db8::9", 22)


def test_flow_start_and_source_with_packets_out_of_order(tmp_path):
    # Captured on two interfaces and merged: the SYN-ACK is written before the SYN.
    pkts = [(T + 0.002, tcp(S, C, 445, 50000, SYN | ACK)), (T + 0.001, tcp(C, S, 50000, 445, SYN))]
    path = tmp_path / "cap.pcap"
    write_pcap(path, pkts)
    [f] = sources.load([str(path)])
    assert (f.src, f.start, f.end, f.source) == (C, T + 0.001, T + 0.002, str(path))


def test_dns_chains_needing_several_passes_and_seen_times():
    dns = {}
    answer = dns_answer("a.test", [("b.test", "CNAME", "c.test"), ("a.test", "CNAME", "b.test"),
                                   ("c.test", "A", "192.0.2.7")])
    record_dns(answer, T + 50, dns)
    record_dns(answer, T + 10, dns)
    record_dns(answer, T + 90, dns)
    assert dns == {n: {"192.0.2.7": [T + 10, T + 90]} for n in ("a.test", "b.test", "c.test")}


def test_dns_ignores_unrelated_records_before_the_chain():
    dns = {}
    record_dns(dns_answer("evil.test", [("other.test", "A", "6.6.6.7"), ("evil.test", "A", "6.6.6.6")]),
               T, dns)
    assert dns == {"evil.test": {"6.6.6.6": [T, T]}}


def test_only_port_53_answers_count(tmp_path):
    path = tmp_path / "cap.pcap"
    answer = dns_answer("printer.local", [("printer.local", "A", "10.0.0.66")])
    write_pcap(path, [(T, udp("10.0.0.66", "224.0.0.251", 5353, 5353, answer))])   # mDNS
    dns = {}
    sources.read(sources.find([str(path)]), dns)
    assert dns == {}


def test_nfdump_failing_silently(tmp_path, monkeypatch):
    fake_nfdump(tmp_path, monkeypatch, "exit 4\n")
    with pytest.raises(SourceError, match="nfdump failed: exit 4"):
        list(read_records("x"))


def test_pairing_sorts_records_and_keeps_tcp_open_five_minutes():
    out_of_order = [rec(S, 445, C, 50000, T + 0.5, T + 1), rec(C, 50000, S, 445, T, T + 1)]
    [f] = pair_records(out_of_order)
    assert (f.src, f.dst) == (C, S)                                    # the earlier half initiated
    [f] = pair_records([rec(C, 50000, S, 445, T, T + 1), rec(C, 50000, S, 445, T + 200, T + 201)])
    assert f.end == T + 201                                            # 199 s gap: same TCP connection
    split = pair_records([rec(C, 50000, S, 445, T, T + 1), rec(C, 50000, S, 445, T + 400, T + 401)])
    assert [(x.start, x.end) for x in split] == [(T, T + 1), (T + 400, T + 401)]


def test_a_duplicate_does_not_stop_the_walk(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    write_pcap(d / "a.pcap", handshake())
    write_pcap(d / "b.pcap", handshake(cport=50001, t=T + 10))
    found = sources.find([str(d / "a.pcap"), str(d)])
    assert found["pcap"] == [str(d / "a.pcap"), str(d / "b.pcap")]


def test_unknown_address_family_is_named():
    with pytest.raises(SourceError, match="unknown address family 0"):
        parse_pipe_line("0|0|0|6|0|0|0|1|50000|0|0|0|2|445|0|0|0|0|0|0|1|1")


def test_a_cname_target_of_sixteen_bytes_is_not_an_address():
    # "abcdefghij.net" encodes to 16 bytes, the size of an IPv6 address.
    dns = {}
    record_dns(dns_answer("x.test", [("x.test", "CNAME", "abcdefghij.net"),
                                     ("abcdefghij.net", "A", "192.0.2.1")]), T, dns)
    assert dns == {"x.test": {"192.0.2.1": [T, T]}, "abcdefghij.net": {"192.0.2.1": [T, T]}}


def test_damaged_and_unsupported_captures(tmp_path):
    good = tmp_path / "good.pcap"
    write_pcap(good, handshake())
    damaged = tmp_path / "damaged.pcap"
    damaged.write_bytes(good.read_bytes()[:12])              # the global header is cut short
    with pytest.raises(SourceError, match="damaged.pcap: not a readable pcap file"):
        sources.load([str(damaged)])
    radiotap = tmp_path / "wifi.pcap"
    with open(radiotap, "wb") as fh:
        dpkt.pcap.Writer(fh, linktype=127).writepkt(b"\0" * 40, ts=T)   # 802.11 radiotap
    with pytest.raises(SourceError, match="wifi.pcap: unsupported link type 127"):
        sources.load([str(radiotap)])


def test_raw_ip_packets_that_are_neither_v4_nor_v6(tmp_path):
    bogus = b"\x50" + b"\0" * 39                             # version nibble 5
    flows = load_packets(tmp_path, [(T, bogus), (T + 1, tcp(C, S, 50000, 445, SYN))], linktype=101)
    assert endpoints(flows) == [(C, 50000, S, 445, "tcp")]


def test_a_live_nfcapd_file_in_a_directory_is_skipped(tmp_path):
    d = tmp_path / "netflow"
    d.mkdir()
    (d / "nfcapd.current.4242").write_bytes(bytes.fromhex("0ca5") + b"\0" * 30)
    write_pcap(d / "cap.pcap", handshake())
    assert sources.find([str(d)]) == {"pcap": [str(d / "cap.pcap")], "nfcapd": []}
