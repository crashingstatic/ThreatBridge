"""Evidence readers: finding the files, pcap decoding and connection tracking, DNS answers,
NetFlow (nfdump)."""
import logging
import os
import random
import socket
import struct
import time

import dpkt
import pytest

from evidence import (ACK, FIN, MAC, PSH, RST, SYN, dns_answer, have_nfdump, icmp_echo, ip_bytes, load,
                      make_nfcapd, tcp, udp, write_bulk_pcap, write_pcap)
from threatbridge import model, protocols, sources
from threatbridge.model import Flow, SourceError
from threatbridge.sources import netflow, pcap, workers
from threatbridge.sources.netflow import pair_records, parse_pipe_line, read_records
from threatbridge.sources.pcap import record_dns


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
    return load([str(path)])


def endpoints(flows):
    return [(f.src, f.sport, f.dst, f.dport, f.proto) for f in flows]


def frame(pkt):
    ip, etype, _ = pkt
    return bytes(dpkt.ethernet.Ethernet(src=MAC, dst=MAC, type=etype, data=ip))


def ipv6_fragment(offset, payload, more=True):
    src, dst = (socket.inet_pton(socket.AF_INET6, a) for a in ("2001:db8::5", "2001:db8::9"))
    # next header, reserved, offset in 8-byte units << 3 | more-fragments flag, id
    frag = struct.pack("!BBHI", 6, 0, ((offset // 8) << 3) | int(more), 9)
    ip6 = dpkt.ip6.IP6(src=src, dst=dst, nxt=44, hlim=64, data=frag + payload)
    ip6.plen = 8 + len(payload)
    return bytes(dpkt.ethernet.Ethernet(src=MAC, dst=MAC, type=dpkt.ethernet.ETH_TYPE_IP6,
                                        data=bytes(ip6)))


def rec(src, sport, dst, dport, start, end, packets=1, nbytes=100, proto="tcp", flags=0):
    return (start, end, proto, src, sport, dst, dport, packets, nbytes, flags, "nf")


def fake_nfdump(tmp_path, monkeypatch, script):
    exe = tmp_path / "nfdump"
    exe.write_text("#!/bin/sh\n" + script)
    exe.chmod(0o755)
    monkeypatch.setenv("TB_NFDUMP", str(exe))


# ---- finding evidence files ---------------------------------------------------------------

def test_directory_walk_and_errors(tmp_path):
    d = tmp_path / "evidence"
    (d / "sub").mkdir(parents=True)
    write_pcap(d / "sub" / "one.pcap", handshake())
    (d / "notes.txt").write_text("not evidence")
    (d / ".hidden.pcap").write_bytes(b"junk")
    assert len(load([str(d)])) == 1

    with pytest.raises(SourceError, match="not a pcap or nfcapd"):
        load([str(d / "notes.txt")])
    (d / "x.pcapng").write_bytes(bytes.fromhex("0a0d0d0a") + bytes(28))
    with pytest.raises(SourceError, match="pcapng is not supported"):
        load([str(d)])
    (tmp_path / "empty").mkdir()
    with pytest.raises(SourceError, match="no pcap or nfcapd"):
        load([str(tmp_path / "empty")])
    with pytest.raises(SourceError, match="no such file"):
        load([str(tmp_path / "missing")])


def test_the_same_file_named_twice_is_read_once(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    write_pcap(d / "cap.pcap", handshake())
    os.symlink(d / "cap.pcap", tmp_path / "link.pcap")
    paths = [str(d), str(d / "cap.pcap"), str(tmp_path / "link.pcap")]
    assert sources.find(paths)["pcap"] == [str(d / "cap.pcap")]
    assert len(load(paths)) == 1


def test_a_duplicate_does_not_stop_the_walk(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    write_pcap(d / "a.pcap", handshake())
    write_pcap(d / "b.pcap", handshake(cport=50001, t=T + 10))
    found = sources.find([str(d / "a.pcap"), str(d)])
    assert found["pcap"] == [str(d / "a.pcap"), str(d / "b.pcap")]


def test_files_that_are_not_evidence(tmp_path):
    (tmp_path / "empty").write_bytes(b"")
    with pytest.raises(SourceError, match="not a pcap or nfcapd file"):
        sources.find([str(tmp_path / "empty")])
    live = tmp_path / "nfcapd.current.4242"
    live.write_bytes(bytes.fromhex("0ca5") + b"\0" * 30)
    with pytest.raises(SourceError, match="still being written"):
        sources.find([str(live)])


def test_a_live_nfcapd_file_in_a_directory_is_skipped(tmp_path):
    d = tmp_path / "netflow"
    d.mkdir()
    (d / "nfcapd.current.4242").write_bytes(bytes.fromhex("0ca5") + b"\0" * 30)
    write_pcap(d / "cap.pcap", handshake())
    assert sources.find([str(d)]) == {"pcap": [str(d / "cap.pcap")], "nfcapd": []}


def test_damaged_and_unsupported_captures(tmp_path):
    good = tmp_path / "good.pcap"
    write_pcap(good, handshake())
    damaged = tmp_path / "damaged.pcap"
    damaged.write_bytes(good.read_bytes()[:12])              # the global header is cut short
    with pytest.raises(SourceError, match="damaged.pcap: not a readable pcap file"):
        load([str(damaged)])
    radiotap = tmp_path / "wifi.pcap"
    with open(radiotap, "wb") as fh:
        dpkt.pcap.Writer(fh, linktype=127).writepkt(b"\0" * 40, ts=T)   # 802.11 radiotap
    with pytest.raises(SourceError, match="wifi.pcap: unsupported link type 127"):
        load([str(radiotap)])


def test_rotated_captures_are_read_in_time_order(tmp_path):
    pkts = handshake()
    d = tmp_path / "caps"
    d.mkdir()
    # tcpdump -C/-G rotation; names deliberately sort opposite to capture order.
    write_pcap(d / "b.pcap", pkts[:4])
    write_pcap(d / "a.pcap", pkts[4:])
    [f] = load([str(d)])
    assert f.packets == 8 and f.source == str(d / "b.pcap")


# ---- pcap: connections --------------------------------------------------------------------

def test_tcp_connection_is_one_flow_from_initiator(tmp_path):
    pkts = handshake()
    [f] = load_packets(tmp_path, pkts)
    assert (f.src, f.sport, f.dst, f.dport, f.proto) == (C, 50000, S, 445, "tcp")
    assert f.packets == 8 and f.bytes == ip_bytes(pkts) == 8 * 40 + 300
    assert f.start == pytest.approx(T) and f.end == pytest.approx(T + 0.007)
    assert f.source == str(tmp_path / "cap.pcap")


def test_who_started_it_time_then_flags_then_ports_then_both_ways(tmp_path):
    # Time first, when both sides were seen: the side seen first, even when the capture starts
    # at the SYN-ACK, or mid-stream with the server talking.
    syn_ack = load_packets(tmp_path, handshake()[1:])
    midstream = load_packets(tmp_path, [(T, tcp(S, C, 443, 51000, ACK)),
                                        (T + 1, tcp(C, S, 51000, 443, ACK))])
    assert endpoints(syn_ack) == [(S, 445, C, 50000, "tcp")]
    assert endpoints(midstream) == [(S, 443, C, 51000, "tcp")]
    # When time can't tell (both sides' first packets at the same time, or one side alone), the
    # flags of each side's first packet. A SYN without ACK is the client's ...
    seen = lambda *pkts: endpoints(load_packets(tmp_path, [(T, p) for p in pkts]))  # noqa: E731
    assert seen(tcp(S, C, 49668, 50000, ACK), tcp(C, S, 50000, 49668, SYN)) == [(C, 50000, S, 49668, "tcp")]
    assert seen(tcp(C, S, 50000, 49668, SYN)) == [(C, 50000, S, 49668, "tcp")]          # a SYN scan
    # ... a SYN-ACK answered by the handshake is the server's, even where the ports say otherwise ...
    assert seen(tcp(S, C, 49668, 50000, SYN | ACK), tcp(C, S, 50000, 49668, ACK)) == [(C, 50000, S, 49668, "tcp")]
    assert seen(tcp(C, S, 3000, 40000, SYN), tcp(S, C, 40000, 3000, SYN | ACK)) == [(C, 3000, S, 40000, "tcp")]
    # ... but one reset by its target (RST, no ACK) is a SYN-ACK scan: its sender started it,
    # even from a well-known port.
    assert seen(tcp(S, C, 80, 50000, SYN | ACK), tcp(C, S, 50000, 80, RST)) == [(S, 80, C, 50000, "tcp")]
    # Echo requests and replies count as a SYN and a SYN-ACK.
    assert seen(icmp_echo(C, S)) == [(C, 0, S, 0, "icmp")]                              # unanswered
    assert seen(icmp_echo(S, C, reply=True), icmp_echo(C, S)) == [(C, 0, S, 0, "icmp")]
    # Each side's first packet settles it, not later ones.
    assert seen(tcp(S, C, 49668, 50000, SYN | ACK), tcp(C, S, 50000, 49668, ACK),
                tcp(C, S, 50000, 49668, RST)) == [(C, 50000, S, 49668, "tcp")]
    # Then the ports. A SYN-ACK nobody answered can't be told from a scan, so they decide.
    assert seen(tcp(S, C, 443, 51000, SYN | ACK)) == [(C, 51000, S, 443, "tcp")]
    assert seen(tcp(S, C, 443, 51000, ACK), tcp(C, S, 51000, 443, ACK)) == [(C, 51000, S, 443, "tcp")]
    assert seen(udp(S, C, 3389, 50000)) == [(C, 50000, S, 3389, "udp")]
    # Failing them too, the connection is taken both ways: two identical flows.
    both = load_packets(tmp_path, [(T, udp(S, C, 49668, 50000)), (T, udp(C, S, 50000, 49668))])
    assert sorted(endpoints(both)) == [(C, 50000, S, 49668, "udp"), (S, 49668, C, 50000, "udp")]
    assert [(f.start, f.end, f.packets, f.bytes) for f in both] == [(T, T, 2, both[0].bytes)] * 2
    assert sorted(seen(icmp_echo(S, C, reply=True))) == [(C, 0, S, 0, "icmp"), (S, 0, C, 0, "icmp")]


def test_flow_start_and_source_with_packets_out_of_order(tmp_path):
    # Captured on two interfaces and merged: the SYN-ACK is written before the SYN.
    pkts = [(T + 0.002, tcp(S, C, 445, 50000, SYN | ACK)), (T + 0.001, tcp(C, S, 50000, 445, SYN))]
    path = tmp_path / "cap.pcap"
    write_pcap(path, pkts)
    [f] = load([str(path)])
    assert (f.src, f.start, f.end, f.source) == (C, T + 0.001, T + 0.002, str(path))


def test_rst_and_port_reuse_start_new_flows(tmp_path):
    pkts = [(T, tcp(C, S, 50000, 80, SYN)), (T + 0.05, tcp(S, C, 80, 50000, SYN | ACK)),
            (T + 0.1, tcp(S, C, 80, 50000, RST | ACK))]
    pkts += handshake(sport=80, t=T + 1)              # same 5-tuple after the RST
    pkts += handshake(sport=80, t=T + 2)              # and again after FINs
    flows = load_packets(tmp_path, pkts)
    assert [f.packets for f in flows] == [3, 8, 8]
    assert set(endpoints(flows)) == {(C, 50000, S, 80, "tcp")}


def test_refused_connections_are_left_out(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="threatbridge")
    # A port scan: each closed port answers the SYN with a RST. None of these is mapped ...
    pkts = []
    for i, port in enumerate(range(1000, 1100)):
        pkts += [(T + i * 0.01, tcp(C, S, 50000, port, SYN)),
                 (T + i * 0.01 + 0.001, tcp(S, C, port, 50000, RST | ACK))]
    # ... but an open port it found is: the server answered with a SYN-ACK, the scanner reset.
    pkts += [(T + 2, tcp(C, S, 50000, 445, SYN)), (T + 2.001, tcp(S, C, 445, 50000, SYN | ACK)),
             (T + 2.002, tcp(C, S, 50000, 445, RST))]
    # So are a SYN nobody answered and a SYN-ACK scan's reset: neither is an attempt refused.
    pkts += [(T + 3, tcp(C, S, 50001, 81, SYN)),
             (T + 4, tcp(R, S, 80, 50002, SYN | ACK)), (T + 4.001, tcp(S, R, 50002, 80, RST))]
    flows = load_packets(tmp_path, pkts)
    assert sorted(endpoints(flows)) == [(C, 50000, S, 445, "tcp"), (C, 50001, S, 81, "tcp"),
                                       (R, 80, S, 50002, "tcp")]
    assert "100 refused connection(s) left out" in caplog.text


def test_udp_idle_timeout_splits_and_lone_reply_is_flipped(tmp_path):
    pkts = [
        (T, udp(C, R, 53000, 53, b"q")), (T + 0.01, udp(R, C, 53, 53000, b"a")),
        (T + 120, udp(C, R, 53000, 53, b"q")),       # > 60 s idle: a new flow
        (T + 200, udp(R, C, 53, 53001, b"a")),       # response whose query was not captured
    ]
    flows = load_packets(tmp_path, pkts)
    assert endpoints(flows) == [(C, 53000, R, 53, "udp")] * 2 + [(C, 53001, R, 53, "udp")]
    assert [f.packets for f in flows] == [2, 1, 1]


def test_idle_timeout_is_exclusive(tmp_path):
    q = lambda t: (t, udp(C, R, 53000, 53, b"q"))  # noqa: E731
    flows = load_packets(tmp_path, [q(T), q(T + 60), q(T + 120.001)])   # 60 s apart: same flow
    assert [(f.start, f.end) for f in flows] == [(T, T + 60), (T + 120.001, T + 120.001)]
    [f] = pair_records([rec(C, 53000, R, 53, T, T, proto="udp"),
                        rec(C, 53000, R, 53, T + 60, T + 60, proto="udp")])
    assert f.end == T + 60
    assert len(pair_records([rec(C, 53000, R, 53, T, T, proto="udp"),
                             rec(C, 53000, R, 53, T + 60.001, T + 61, proto="udp")])) == 2


def test_tcp_idle_timeout_is_five_minutes(tmp_path):
    a = lambda t: (t, tcp(C, S, 50000, 445, PSH | ACK, b"x"))  # noqa: E731
    flows = load_packets(tmp_path, [a(T), a(T + 300), a(T + 600.001)])
    assert [(f.start, f.end) for f in flows] == [(T, T + 300), (T + 600.001, T + 600.001)]


def test_icmp_and_ipv6(tmp_path):
    a6, b6 = "2001:db8::5", "2001:db8::9"
    pkts = [(T, icmp_echo(C, R)), (T + 0.02, icmp_echo(R, C, reply=True))]
    pkts += handshake(a6, b6, t=T + 1)
    flows = load_packets(tmp_path, pkts)
    assert endpoints(flows) == [(C, 0, R, 0, "icmp"), (a6, 50000, b6, 445, "tcp")]
    assert flows[1].bytes == 8 * 60 + 300


def test_other_ip_protocols_are_flows_too(tmp_path):
    gre = dpkt.ip.IP(src=socket.inet_aton(C), dst=socket.inet_aton(S), p=47, ttl=64, data=b"\0" * 24)
    gre.len = 44
    raw = bytes(dpkt.ethernet.Ethernet(src=MAC, dst=MAC, type=0x0800, data=gre))
    flows = load_packets(tmp_path, [(T, raw), (T + 30, raw)])
    # One side only, no flags, no ports: nothing tells who started it, so both ways.
    assert [(f.src, f.dst, f.proto, f.sport, f.dport, f.packets) for f in flows] == \
        [(C, S, "47", 0, 0, 2), (S, C, "47", 0, 0, 2)]


# ---- pcap: decoding packets ---------------------------------------------------------------

@pytest.mark.parametrize("linktype,nano", [(101, False), (113, False), (276, False), (1, True)])
def test_link_types_and_nanosecond_pcap(tmp_path, linktype, nano):
    flows = load_packets(tmp_path, handshake(), linktype=linktype, nano=nano)
    assert endpoints(flows) == [(C, 50000, S, 445, "tcp")]
    assert flows[0].bytes == 8 * 40 + 300


def test_raw_ip_captures_with_ipv6(tmp_path):
    [f] = load_packets(tmp_path, [(T, tcp("2001:db8::5", "2001:db8::9", 50000, 22, SYN))], linktype=101)
    assert (f.src, f.dst, f.dport) == ("2001:db8::5", "2001:db8::9", 22)


def test_raw_ip_packets_that_are_neither_v4_nor_v6(tmp_path):
    bogus = b"\x50" + b"\0" * 39                             # version nibble 5
    flows = load_packets(tmp_path, [(T, bogus), (T + 1, tcp(C, S, 50000, 445, SYN))], linktype=101)
    assert endpoints(flows) == [(C, 50000, S, 445, "tcp")]


def test_non_ip_frames_are_ignored(tmp_path):
    arp = bytes.fromhex("ffffffffffff001122334455" "0806") + bytes(28)
    flows = load_packets(tmp_path, [(T - 1, arp)] + handshake())
    assert len(flows) == 1


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


def test_snap_length_boundaries(tmp_path):
    # Exactly 4 bytes: the ports. 14 bytes: the TCP flags too.
    ports_only = frame(tcp(C, S, 50000, 445, SYN))[:14 + 20 + 4]
    [f] = load_packets(tmp_path, [(T, ports_only)])
    assert (f.sport, f.dport) == (50000, 445)
    # Both sides at the same time, on ports that can't tell (a server on an ephemeral port,
    # e.g. Windows RPC): the SYN-ACK's flags decide ...
    synack, ack = frame(tcp(S, C, 49668, 50000, SYN | ACK)), tcp(C, S, 50000, 49668, ACK)
    [f] = load_packets(tmp_path, [(T, synack[:14 + 20 + 14]), (T, ack)])
    assert (f.src, f.dst) == (C, S)
    # ... unless they were cut off too (13 bytes): then nothing tells, and it goes both ways.
    flows = load_packets(tmp_path, [(T, synack[:14 + 20 + 13]), (T, ack)])
    assert sorted((f.src, f.dst) for f in flows) == [(C, S), (S, C)]


def test_ipv6_fragments(tmp_path):
    first = bytes(dpkt.tcp.TCP(sport=50000, dport=445, flags=SYN, off=5)) + b"a" * 32
    flows = load_packets(tmp_path, [(T, ipv6_fragment(0, first)),
                                    (T + 0.001, ipv6_fragment(1000, b"\xaa" * 48, more=False))])
    # The first fragment carries the ports; a later one is payload only and adds no flow.
    assert endpoints(flows) == [("2001:db8::5", 50000, "2001:db8::9", 445, "tcp")]


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


def test_a_capture_cut_off_inside_a_record_keeps_what_came_before(tmp_path):
    path = tmp_path / "cut.pcap"
    write_pcap(path, handshake())
    path.write_bytes(path.read_bytes() + b"\0" * 8)          # tcpdump killed mid-write
    assert endpoints(load([str(path)])) == [(C, 50000, S, 445, "tcp")]
    only_junk = tmp_path / "junk.pcap"
    write_pcap(only_junk, [])
    only_junk.write_bytes(only_junk.read_bytes() + b"\0" * 8)
    assert load([str(only_junk)]) == []


def test_header_only_capture_has_no_flows(tmp_path):
    assert load_packets(tmp_path, []) == []


# ---- DNS answers in captures --------------------------------------------------------------

def test_dns_answers_only_follow_the_question():
    dns = {}
    record_dns(dns_answer("evil.test", [
        ("cdn.test", "A", "6.6.6.6"),                          # chain listed out of order
        ("evil.test", "CNAME", "cdn.test"),
        ("updates.example.com", "A", "6.6.6.7"),               # not part of the answer to evil.test
    ]), T, dns)
    assert dns == {"evil.test": {"6.6.6.6": [T, T]}, "cdn.test": {"6.6.6.6": [T, T]}}


def test_dns_ignores_unrelated_records_before_the_chain():
    dns = {}
    record_dns(dns_answer("evil.test", [("other.test", "A", "6.6.6.7"), ("evil.test", "A", "6.6.6.6")]),
               T, dns)
    assert dns == {"evil.test": {"6.6.6.6": [T, T]}}


def test_dns_chains_needing_several_passes_and_seen_times():
    dns = {}
    answer = dns_answer("a.test", [("b.test", "CNAME", "c.test"), ("a.test", "CNAME", "b.test"),
                                   ("c.test", "A", "192.0.2.7")])
    record_dns(answer, T + 50, dns)
    record_dns(answer, T + 10, dns)
    record_dns(answer, T + 90, dns)
    assert dns == {n: {"192.0.2.7": [T + 10, T + 90]} for n in ("a.test", "b.test", "c.test")}


def test_a_cname_target_of_sixteen_bytes_is_not_an_address():
    # "abcdefghij.net" encodes to 16 bytes, the size of an IPv6 address.
    dns = {}
    record_dns(dns_answer("x.test", [("x.test", "CNAME", "abcdefghij.net"),
                                     ("abcdefghij.net", "A", "192.0.2.1")]), T, dns)
    assert dns == {"x.test": {"192.0.2.1": [T, T]}, "abcdefghij.net": {"192.0.2.1": [T, T]}}


def test_only_port_53_answers_count(tmp_path):
    path = tmp_path / "cap.pcap"
    answer = dns_answer("printer.local", [("printer.local", "A", "10.0.0.66")])
    write_pcap(path, [(T, udp("10.0.0.66", "224.0.0.251", 5353, 5353, answer))])   # mDNS
    dns = {}
    sources.read(sources.find([str(path)]), dns)
    assert dns == {}


# ---- NetFlow (nfdump) ---------------------------------------------------------------------

# Real `nfdump -q -o pipe` output from nfdump 1.7.3.
PIPE_V4 = "2|1792437101000|1792437111000|6|0|0|0|167772165|50000|0|0|0|167772169|445|0|0|0|0|27|0|10|1500"


PIPE_V6 = ("10|1792437238000|1792437242000|6|536939960|2863315899|3435978205|4008574977|51000|"
           "536939960|286335522|858997828|1431660134|22|0|0|0|0|0|0|5|400")


def test_parse_pipe_lines():
    assert parse_pipe_line(PIPE_V4) == (1792437101.0, 1792437111.0, "tcp", C, 50000, S, 445, 10, 1500,
                                        FIN | SYN | PSH | ACK)
    rec = parse_pipe_line(PIPE_V6)
    assert rec[3] == "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"
    assert rec[5] == "2001:db8:1111:2222:3333:4444:5555:6666"
    icmp = parse_pipe_line("2|0|0|1|0|0|0|167772165|0|0|0|0|134744072|2048|0|0|0|0|0|0|1|84")
    assert (icmp[2], icmp[4], icmp[6], icmp[9]) == ("icmp", 0, 0, SYN)       # an echo request
    with pytest.raises(SourceError, match="unexpected nfdump output"):
        parse_pipe_line("2|1|2|6")


@pytest.mark.parametrize("line", [
    "0|0|0|6|0|0|0|1|50000|0|0|0|2|445|0|0|0|0|0|0|1|1",        # unknown address family
    "2|x|0|6|0|0|0|1|50000|0|0|0|2|445|0|0|0|0|0|0|1|1",        # not a number
])
def test_unreadable_nfdump_lines_are_source_errors(line):
    with pytest.raises(SourceError, match="unexpected nfdump output"):
        parse_pipe_line(line)


def test_unknown_address_family_is_named():
    with pytest.raises(SourceError, match="unknown address family 0"):
        parse_pipe_line("0|0|0|6|0|0|0|1|50000|0|0|0|2|445|0|0|0|0|0|0|1|1")


def test_pairing_merges_halves_and_orients():
    halves = [rec(S, 445, C, 50000, T, T + 10, 8, 9000), rec(C, 50000, S, 445, T, T + 10, 10, 1500)]
    for records in (halves, halves[::-1]):    # same millisecond: port heuristic decides
        [f] = pair_records(records)
        assert (f.src, f.dst, f.packets, f.bytes) == (C, S, 18, 10500)
    # A strictly earlier half wins over the port heuristic.
    [f] = pair_records([rec(S, 443, C, 50000, T, T + 1), rec(C, 50000, S, 443, T + 0.5, T + 1)])
    assert (f.src, f.dst) == (S, C)
    # Only the reply was exported: time can't tell, nor flags; the ports can.
    [f] = pair_records([rec(R, 53, C, 53000, T, T, proto="udp")])
    assert (f.src, f.sport, f.dst, f.dport) == (C, 53000, R, 53)
    # One half alone with a SYN but no ACK: an unanswered SYN, from the client.
    [f] = pair_records([rec(S, 50000, C, 49668, T, T, flags=SYN)])
    assert (f.src, f.sport) == (S, 50000)
    # Same millisecond (softflowd gives both halves one start): the flags first. A half with a
    # SYN but no ACK is the client's (one that never finished the handshake), even where the
    # ports would say otherwise (a server on an ephemeral port) ...
    odd = [rec(C, 3000, S, 40000, T, T, flags=SYN), rec(S, 40000, C, 3000, T, T, flags=SYN | ACK)]
    for records in (odd, odd[::-1]):
        [f] = pair_records(records)
        assert (f.src, f.sport) == (C, 3000)
    # A refused connection (a SYN answered only by a RST) isn't mapped at all.
    refused = [rec(S, 49668, C, 50000, T, T, flags=RST | ACK), rec(C, 50000, S, 49668, T, T, flags=SYN)]
    for records in (refused, refused[::-1]):
        assert pair_records(records) == []
    # ... but both halves of a completed connection carry SYN and ACK: then the ports. No
    # well-known port: the half from an ephemeral port is the client's.
    done = FIN | SYN | PSH | ACK
    rdp = [rec(S, 3389, C, 51000, T, T + 10, flags=done), rec(C, 51000, S, 3389, T, T + 10, flags=done)]
    for records in (rdp, rdp[::-1]):
        [f] = pair_records(records)
        assert (f.src, f.sport, f.dst, f.dport) == (C, 51000, S, 3389)
    # A SYN-ACK scan: one half SYN-ACK only, reset by the other (RST, no ACK). The scanner
    # started it, though it used port 80.
    scan = [rec(S, 80, C, 50000, T, T, flags=SYN | ACK), rec(C, 50000, S, 80, T, T, flags=RST)]
    for records in (scan, scan[::-1]):
        [f] = pair_records(records)
        assert (f.src, f.sport, f.dst, f.dport) == (S, 80, C, 50000)
    # Both ports ephemeral and no flags to go by: both ways, two identical flows.
    flows = pair_records([rec(S, 49668, C, 50000, T, T + 1, 3), rec(C, 50000, S, 49668, T, T + 1, 4)])
    assert [(f.src, f.sport, f.dst, f.dport, f.packets) for f in flows] == \
        [(S, 49668, C, 50000, 7), (C, 50000, S, 49668, 7)]
    # Time comes before the flags: a strictly earlier half wins whatever they say.
    [f] = pair_records([rec(S, 49668, C, 50000, T, T + 1, flags=SYN | ACK),
                        rec(C, 50000, S, 49668, T + 0.5, T + 1, flags=SYN)])
    assert (f.src, f.sport) == (S, 49668)


def test_refused_netflow_connections_are_left_out(caplog):
    caplog.set_level(logging.INFO, logger="threatbridge")
    scan = [r for port in range(1000, 1050)
            for r in (rec(C, 50000, S, port, T, T, flags=SYN), rec(S, port, C, 50000, T, T, flags=RST | ACK))]
    done = FIN | SYN | PSH | ACK
    kept = [rec(C, 50001, S, 445, T, T + 1, flags=done), rec(S, 445, C, 50001, T, T + 1, flags=done)]
    assert [(f.src, f.dport) for f in pair_records(scan + kept)] == [(C, 445)]
    assert "50 refused connection(s) left out" in caplog.text


def test_pairing_rejoins_exporter_splits_but_not_idle_gaps():
    split = [rec(C, 50000, S, 22, T, T + 1800), rec(S, 22, C, 50000, T, T + 1800),
             rec(C, 50000, S, 22, T + 1800, T + 2000), rec(S, 22, C, 50000, T + 1800, T + 2000)]
    [f] = pair_records(split)
    assert (f.src, f.packets, f.end) == (C, 4, T + 2000)
    gap = [rec(C, 50000, S, 22, T, T + 1), rec(C, 50000, S, 22, T + 1000, T + 1001)]
    assert len(pair_records(gap)) == 2


def test_pairing_sorts_records_and_keeps_tcp_open_five_minutes():
    out_of_order = [rec(S, 445, C, 50000, T + 0.5, T + 1), rec(C, 50000, S, 445, T, T + 1)]
    [f] = pair_records(out_of_order)
    assert (f.src, f.dst) == (C, S)                                    # the earlier half initiated
    [f] = pair_records([rec(C, 50000, S, 445, T, T + 1), rec(C, 50000, S, 445, T + 200, T + 201)])
    assert f.end == T + 201                                            # 199 s gap: same TCP connection
    split = pair_records([rec(C, 50000, S, 445, T, T + 1), rec(C, 50000, S, 445, T + 400, T + 401)])
    assert [(x.start, x.end) for x in split] == [(T, T + 1), (T + 400, T + 401)]


def test_nfdump_errors(tmp_path, monkeypatch):
    fake_nfdump(tmp_path, monkeypatch, 'echo "Corrupt data file" >&2\nexit 3\n')
    with pytest.raises(SourceError, match="nfdump failed: Corrupt data file"):
        list(read_records("x"))
    fake_nfdump(tmp_path, monkeypatch, "exit 4\n")                 # fails without saying why
    with pytest.raises(SourceError, match="nfdump failed: exit 4"):
        list(read_records("x"))
    fake_nfdump(tmp_path, monkeypatch, 'echo "Summary: 1 flow"\nexec sleep 30\n')
    t = time.monotonic()
    with pytest.raises(SourceError, match="unexpected nfdump output"):
        list(read_records("x"))
    assert time.monotonic() - t < 5                          # nfdump is stopped, not waited for
    monkeypatch.setenv("TB_NFDUMP", str(tmp_path / "missing"))
    with pytest.raises(SourceError, match="nfdump not found"):
        list(read_records("x"))


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
    flows = load([str(tmp_path)])    # directory: skips nfcapd's hidden stat file
    assert [(f.src, f.dst, f.dport, f.proto, f.packets, f.bytes) for f in flows] == [
        (C, S, 445, "tcp", 18, 10500), (C, R, 53, "udp", 1, 70)]
    assert flows[0].start == t and flows[0].end == t + 10
    assert flows[0].source == path and os.path.basename(path).startswith("nfcapd.")


# ---- reading files in parallel -----------------------------------------------------------

def random_capture(seed):
    """Packets on a few host pairs and ports: handshakes, data, FINs, RSTs, reused ports, idle
    gaps longer than the timeouts, UDP, DNS answers and an IPv6 pair."""
    rng = random.Random(seed)
    pairs = [("10.0.0.5", "10.0.0.9"), ("10.0.0.6", "10.0.0.9"), ("2001:db8::5", "2001:db8::9")]
    flags = [SYN, SYN | ACK, ACK, PSH | ACK, FIN | ACK, RST, RST | ACK]
    t, packets = T, []
    for _ in range(rng.randint(40, 160)):
        t += rng.choice([0.001, 0.5, 30, 61, 299, 301, 900])
        a, b = rng.choice(pairs)
        a, b = (a, b) if rng.random() < 0.6 else (b, a)
        ports = rng.choice([(50000, 445), (50001, 445), (50000, 22)])
        sport, dport = ports if a < b else ports[::-1]
        kind = rng.random()
        if kind < 0.7:
            packets.append((t, tcp(a, b, sport, dport, rng.choice(flags))))
        elif kind < 0.85:
            packets.append((t, udp(a, b, 53000 + sport % 3, 53, b"q")))
        else:
            ip = rng.choice(["192.0.2.7", "192.0.2.8"])
            packets.append((t, udp(b, a, 53, 53000, dns_answer("x.test", [("x.test", "A", ip)]))))
    return packets


def split_into_files(tmp_path, packets, n, rng, overlapping=False):
    """The packets in n capture files: rotated (consecutive), or interleaved like two
    interfaces captured at the same time."""
    d = tmp_path / "caps"
    d.mkdir()
    if overlapping:
        parts = [[] for _ in range(n)]
        for p in packets:
            rng.choice(parts).append(p)
    else:
        cuts = sorted(rng.sample(range(1, len(packets)), n - 1))
        parts = [packets[i:j] for i, j in zip([0] + cuts, cuts + [len(packets)])]
    for i, part in enumerate(parts):
        write_pcap(d / f"cap{i:02d}.pcap", part)
    return [str(p) for p in sorted(d.iterdir())]


def in_process(func, items, workers, *args):
    """workers.in_order without the processes: what each worker would send back, in order."""
    for item in items:
        yield item, func(item, *args)


@pytest.mark.parametrize("seed", range(40))
def test_parallel_reading_gives_the_same_flows(tmp_path, monkeypatch, seed):
    rng = random.Random(seed)
    files = split_into_files(tmp_path, random_capture(seed), rng.randint(2, 5), rng, overlapping=seed % 4 == 0)
    one_dns, many_dns = {}, {}
    one_at_a_time = pcap.read_pcaps(files, one_dns, workers=1)
    monkeypatch.setattr(pcap, "in_order", in_process)
    in_parallel = pcap.read_pcaps(files, many_dns, workers=4)
    assert in_parallel == one_at_a_time and many_dns == one_dns
    assert list(many_dns["x.test"]) == list(one_dns["x.test"])          # same order too


def test_a_close_spanning_two_rotated_files(tmp_path, monkeypatch):
    # FIN at the end of one file, the last ACK and then a new SYN on the same ports in the
    # next: the new SYN starts a second connection either way.
    first = handshake()[:6]                                  # ... up to the server's FIN
    second = [(T + 0.007, tcp(C, S, 50000, 445, ACK))] + handshake(t=T + 5)
    files = split_into_files(tmp_path, first + second, 2, random.Random(0))
    expect = pcap.read_pcaps(files, workers=1)
    assert [f.packets for f in expect] == [7, 8]
    monkeypatch.setattr(pcap, "in_order", in_process)
    assert pcap.read_pcaps(files, workers=2) == expect


def test_worker_processes_read_pcaps_and_report_errors(tmp_path):
    files = split_into_files(tmp_path, random_capture(7), 3, random.Random(7))
    dns = {}
    assert pcap.read_pcaps(files, dns, workers=3) == pcap.read_pcaps(files, workers=1)
    assert set(dns) == {"x.test"}
    with open(files[1], "r+b") as fh:                         # a damaged file in the middle
        fh.truncate(12)
    with pytest.raises(SourceError, match="cap01.pcap: not a readable pcap file"):
        pcap.read_pcaps(files, workers=3)


def test_worker_processes_read_nfcapd_files_in_order(tmp_path, monkeypatch):
    # A stand-in nfdump that prints the lines kept next to each "nfcapd" file.
    fake_nfdump(tmp_path, monkeypatch, 'cat "$5.lines"\n')     # nfdump -q -o pipe -r FILE
    files = []
    for i, start in enumerate([1792437101000, 1792437101000, 1792437201000]):
        path = tmp_path / f"nfcapd.20260101000{i}"
        path.write_bytes(b"\x0c\xa5")
        sport = 50000 + i % 2
        path.with_name(path.name + ".lines").write_text(
            f"2|{start}|{start + 1000}|6|0|0|0|167772165|{sport}|0|0|0|167772169|445|0|0|0|0|27|0|10|1500\n")
        files.append(str(path))
    one = netflow.read_nfcapd(files, workers=1)
    # Files 0 and 2 hold the same connection 100 s apart (TCP idle timeout: 5 min): one flow.
    assert [(f.sport, f.start, f.end, f.packets, f.source) for f in one] == [
        (50000, 1792437101.0, 1792437202.0, 20, files[0]), (50001, 1792437101.0, 1792437102.0, 10, files[1])]
    assert netflow.read_nfcapd(files, workers=3) == one


class FakePool:
    """Stands in for ProcessPoolExecutor: runs each call at once and notes what happens."""
    events = []

    def __init__(self, workers, mp_context):
        FakePool.events = [("pool", workers, mp_context.get_start_method())]

    def submit(self, func, *args):
        from concurrent.futures import Future
        FakePool.events.append(("submit", args[0]))
        future = Future()
        future.set_result(func(*args))
        return future

    def shutdown(self, wait, cancel_futures):
        FakePool.events.append(("shutdown", wait, cancel_futures))


def test_the_workers_run_a_bounded_way_ahead(monkeypatch):
    monkeypatch.setattr(workers, "ProcessPoolExecutor", FakePool)
    out = []
    for item, result in workers.in_order(pow, [3, 1, 4, 1, 5], 2, 2):
        FakePool.events.append(("used", item))
        out.append(result)
    assert out == [9, 1, 16, 1, 25]
    assert FakePool.events == [
        ("pool", 2, "spawn"), ("submit", 3), ("submit", 1),           # two running ...
        ("submit", 4), ("used", 3),                                   # ... one more as each is used
        ("submit", 1), ("used", 1), ("submit", 5), ("used", 4), ("used", 1), ("used", 5),
        ("shutdown", True, True)]
    list(workers.in_order(pow, [1, 2], 8, 2))
    assert FakePool.events[0] == ("pool", 2, "spawn")                # no more workers than items


def test_the_workers_run_ahead_but_hand_results_back_in_order():
    assert list(workers.in_order(pow, [3, 1, 4, 1, 5], 2, 2)) == [(3, 9), (1, 1), (4, 16), (1, 1), (5, 25)]
    assert list(workers.in_order(pow, [2], 8, 3)) == [(2, 8)]                # one item: no processes
    assert list(workers.in_order(pow, [], 4, 2)) == []
    with pytest.raises(ZeroDivisionError):
        list(workers.in_order(divmod, [1, 0, 2], 2, 0))


def test_progress_reports_as_it_goes_and_logs_each_file(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="threatbridge.sources")
    d = tmp_path / "caps"
    d.mkdir()
    big, small = d / "big.pcap", d / "small.pcap"
    write_bulk_pcap(big, 2 * pcap.REPORT_EVERY + 100)
    junk = [(T + 9000, b"\x01\x02")]                               # undecodable
    write_pcap(small, junk + [(T + 9001, tcp(C, S, 50000, 445, SYN))])
    small.write_bytes(small.read_bytes() + b"\0" * 8)               # cut off at the end
    odd = d / "odd.pcap"                                           # two undecodable, one too short for ports
    write_pcap(odd, [(T + 9100, b"\x01\x02"), (T + 9101, b"\x03"), (T + 9102, frame(udp(C, R, 53000, 53, b"q"))[:14 + 20 + 2])])
    files = [str(big), str(small), str(odd)]
    expect_logs = [f"{big}: 8292 packets, 0 undecodable", f"{small}: capture is cut off after its last whole packet",
                   f"{small}: 2 packets, 1 undecodable", f"{odd}: 3 packets, 3 undecodable"]
    for parallel in (False, True):
        seen = []
        caplog.clear()
        if parallel:
            monkeypatch.setattr(pcap, "in_order", in_process)
        pcap.read_pcaps(files, workers=2 if parallel else 1, stage=lambda n, note=None: seen.append((n, note)))
        notes = [note for _, note in seen]
        if parallel:      # whole files decoded first: the counts are known up front
            assert notes == ["file 1 of 3, 8,292 packets"] * 3 + ["file 2 of 3, 8,294 packets",
                                                                  "file 3 of 3, 8,297 packets"]
            assert [round(n) for n, _ in seen[:3]] == [round(os.path.getsize(big) * k / 8292) for k in (4096, 4096, 100)]
        else:
            assert notes == ["file 1 of 3, 4,096 packets", "file 1 of 3, 8,192 packets",
                             "file 1 of 3, 8,292 packets", "file 2 of 3, 8,294 packets", "file 3 of 3, 8,297 packets"]
        assert sum(n for n, _ in seen) == pytest.approx(sum(os.path.getsize(f) for f in files))
        assert [r.getMessage() for r in caplog.records if r.name == "threatbridge.sources.pcap"] == expect_logs


def test_nfcapd_progress_and_logs_through_read(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="threatbridge.sources")
    fake_nfdump(tmp_path, monkeypatch, 'cat "$5.lines"\n')
    for name, lines in (("nfcapd.202601010000", 1), ("nfcapd.202601010001", 2)):
        (tmp_path / name).write_bytes(b"\x0c\xa5" + b"\0" * lines)
        (tmp_path / (name + ".lines")).write_text("".join(
            f"2|1792437101000|1792437102000|6|0|0|0|167772165|{50000 + i}|0|0|0|167772169|445|0|0|0|0|27|0|10|1500\n"
            for i in range(lines)))
    seen = []
    flows = sources.read(sources.find([str(tmp_path / "nfcapd.202601010000"), str(tmp_path / "nfcapd.202601010001")]),
                         workers=1, stage=lambda n, note=None: seen.append((n, note)))
    assert len(flows) == 2 and seen == [(3, "file 1 of 2, 1 records"), (4, "file 2 of 2, 3 records")]
    assert [r.getMessage() for r in caplog.records if r.name == "threatbridge.sources.netflow"] == [
        f"{tmp_path / 'nfcapd.202601010000'}: 1 records", f"{tmp_path / 'nfcapd.202601010001'}: 2 records"]


def test_progress_counts_every_byte_of_every_file(tmp_path, monkeypatch):
    files = split_into_files(tmp_path, random_capture(3), 3, random.Random(3))
    write_bulk_pcap(tmp_path / "caps" / "zbulk.pcap", pcap.REPORT_EVERY + 100)   # reported part-way
    write_pcap(tmp_path / "caps" / "zempty.pcap", [])
    files += [str(tmp_path / "caps" / "zbulk.pcap"), str(tmp_path / "caps" / "zempty.pcap")]
    total = sum(os.path.getsize(f) for f in files)
    for parallel in (False, True):
        seen = []
        if parallel:
            monkeypatch.setattr(pcap, "in_order", in_process)
        pcap.read_pcaps(files, workers=3 if parallel else 1, stage=lambda n, note=None: seen.append((n, note)))
        assert sum(n for n, _ in seen) == pytest.approx(total)
        assert seen[-1][1].startswith("file 5 of 5, ") and seen[-1][1].endswith(" packets")


# ---- the flow record ----------------------------------------------------------------------

def test_flow_is_compact():
    f = Flow(C, S, 1, 2, "tcp", T, T, 1, 1, "x")
    assert not hasattr(f, "__dict__")


def test_model_helpers():
    assert (model.idle_timeout("tcp"), model.idle_timeout("udp"), model.idle_timeout("icmp")) == (300, 60, 60)
    assert model.idle_timeout("47") == 60                                   # anything else
    assert (model.proto_name(6), model.proto_name(58), model.proto_name(47)) == ("tcp", "icmp", "47")
    # Ports: a well-known port facing one of 1024 or above is the server's ...
    ports = model.ports_say_reversed
    assert ports(1023, 1024) is True and ports(1024, 1023) is False and ports(0, 65535) is True
    assert ports(1024, 1024) is None and ports(80, 1023) is None
    # ... failing that, a port in the ephemeral ranges facing one outside is the client's.
    assert ports(3389, 50000) is True and ports(32767, 32768) is True
    assert ports(5985, 60999) is True and ports(8443, 65535) is True
    assert ports(50000, 3389) is False and ports(32768, 32767) is False
    assert ports(8080, 9000) is None and ports(49668, 40000) is None    # neither; both (Windows RPC)
    # TCP flags: a SYN without ACK is the client's; in one packet, an answered SYN-ACK the
    # server's; a SYN-ACK reset (RST, no ACK) is a scan, the client's.
    say = model.flags_say_reversed
    assert say(0, SYN) is True and say(SYN, 0) is False and say(SYN, SYN) is None
    assert say(SYN, None) is False and say(None, SYN) is True and say(None, ACK) is None
    assert say(SYN | ACK, ACK) is None and say(SYN | ACK, ACK, packets=True) is True
    assert say(SYN | ACK, None, packets=True) is None                    # unanswered: maybe a scan
    assert say(SYN | ACK, RST) is False and say(RST, SYN | ACK, packets=True) is True
    assert say(SYN | ACK, RST | ACK, packets=True) is True
    assert say(SYN, SYN | ACK, packets=True) is False and say(SYN | ACK, SYN, packets=True) is True
    assert say(SYN | ACK, SYN | ACK, packets=True) is None
    assert say(FIN | SYN | ACK, FIN | SYN | ACK) is None and say(RST | ACK, SYN) is True
    # Refused: a SYN answered only by a RST (Zeek's REJ).
    assert model.refused(SYN, RST | ACK) and model.refused(RST, SYN) and model.refused(RST | ACK, SYN)
    assert not model.refused(SYN, SYN | ACK | RST)                     # it sent a SYN-ACK first
    assert not model.refused(SYN | ACK | RST, SYN | ACK)               # established, then reset
    assert not model.refused(SYN | ACK, RST)                           # a SYN-ACK scan's reset
    assert not model.refused(SYN, 0) and not model.refused(SYN | RST, SYN | ACK)  # unanswered; half-open
    # ICMP echo requests and replies count as a SYN and a SYN-ACK.
    assert [model.icmp_flags(1, t) for t in (8, 0, 3)] == [SYN, SYN | ACK, 0]
    assert [model.icmp_flags(58, t) for t in (128, 129, 0)] == [SYN, SYN | ACK, 0]
    assert model.settle(None, None, 49668, 50000) is None and model.settle(SYN, None, 49668, 50000) is False


# ---- which protocol a connection carries ---------------------------------------------------

def dns_query(name="www.example.org", qclass=1):
    return (struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0) +
            b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" +
            struct.pack("!HH", 1, qclass))


TLS_HELLO = b"\x16\x03\x01\x00\x50\x01" + b"\0" * 20


@pytest.mark.parametrize("tcp_,payload,ports,expect", [
    (True, TLS_HELLO, (51000, 443), protocols.SSL),
    (True, b"\x16\x03\x03\x00\x50\x02" + b"\0" * 8, (443, 51000), protocols.SSL),   # ServerHello
    (True, b"\x16\x03\x03\x00\x50\x0b" + b"\0" * 8, (443, 51000), 0),               # a certificate
    (True, b"\x17\x03\x03\x00\x50\x01", (443, 51000), 0),                           # application data
    (True, b"\x16\x03\x05\x00\x50\x01", (443, 51000), 0),                           # no such version
    (True, b"SSH-2.0-OpenSSH_9.6\r\n", (51000, 22), protocols.SSH),
    (True, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", (51000, 8000), protocols.HTTP),
    (True, b"HTTP/1.1 200 OK\r\n", (8000, 51000), protocols.HTTP),
    (True, b"POST /wsman HTTP/1.1\r\n", (51000, 5985), protocols.HTTP),
    (True, b"GETS / HTTP/1.1\r\n", (51000, 8000), 0),
    (True, b"\x00\x00\x00\x45\xfeSMB" + b"\0" * 8, (51000, 445), protocols.SMB),
    (True, b"\x00\x00\x00\x45\xffSMB" + b"\0" * 8, (51000, 445), protocols.SMB),
    (True, b"\x81\x00\x00\x44\xfeSMB", (51000, 139), 0),                            # session request
    (True, b"\x03\x00\x00\x13\x0e\xe0\x00\x00", (51000, 3389), protocols.RDP),
    (True, b"\x03\x00\x00\x13\x0e\xd0\x00\x00", (3389, 51000), protocols.RDP),
    (True, b"\x03\x00\x00\x16\x11\xe0\x00\x00", (51000, 102), 0),                   # S7 on ISO-TSAP
    (True, b"\x03\x00\x00\x16\x11\xe0\x00\x00", (102, 51000), 0),
    (True, len(dns_query()).to_bytes(2, "big") + dns_query(), (51000, 53), protocols.DNS),
    (True, dns_query(), (51000, 53), 0),                                            # no length first
    (True, b"\x00\x05" + dns_query(), (51000, 53), 0),                             # a wrong length
    (False, dns_query(), (51000, 53), protocols.DNS),
    (False, dns_query(), (40000, 40001), protocols.DNS),                            # on any port
    (False, dns_answer("www.example.org", [("www.example.org", "A", "10.0.0.7")]), (53, 51000), protocols.DNS),
    (False, dns_query(qclass=0x8001), (5353, 5353), protocols.DNS),                 # mDNS, unicast bit
    (False, dns_query(qclass=2), (51000, 53), 0),                                   # no such class
    (False, dns_query()[:4] + b"\x00\x02" + dns_query()[6:], (51000, 53), 0),       # two questions
    (False, dns_query()[:2] + b"\x08\x00" + dns_query()[4:], (51000, 53), 0),       # opcode 1
    (False, dns_query()[:6] + b"\x00\xff" + dns_query()[8:], (51000, 53), 0),       # 255 answers
    (False, dns_query()[:12] + b"\x40" + b"a" * 64 + b"\0\0\1\0\1", (51000, 53), 0),   # a label > 63
    (False, dns_query("." .join(["a" * 63] * 5)), (51000, 53), 0),                 # name > 255
    (False, dns_query()[:20], (51000, 53), 0),                                      # cut off in the name
    (False, dns_query()[:-2], (51000, 53), 0),                                      # cut off in the class
    (False, b"\0" * 20, (1024, 53), 0),
    (False, b"\0" * 236 + b"\x63\x82\x53\x63" + b"\0" * 8, (68, 67), protocols.DHCP),
    (False, b"\0" * 236 + b"\x63\x82\x53", (68, 67), 0),
    (True, b"SSH", (51000, 22), 0),                                                 # too short
])
def test_protocols_from_the_payload(tcp_, payload, ports, expect):
    assert protocols.from_payload(tcp_, *ports, payload) == expect


def test_protocol_names():
    assert protocols.name("tcp", protocols.HTTP, 443, 51000) == "http"       # the payload first
    assert protocols.name("icmp", 0, 0, 0) == "icmp"
    assert protocols.name("tcp", 0, 445, 51000) == "smb"                     # then the server's port
    assert protocols.name("udp", 0, 51000, 53) == "dns"                      # then the client's
    assert protocols.name("tcp", 0, 445, 443) == "smb"                       # the server's first
    assert protocols.name("tcp", 0, 49668, 50000) == "unknown"
    assert protocols.split("smb,ntlm, GSSAPI") == ["smb", "ntlm", "gssapi"]
    assert protocols.split("krb_tcp") == ["krb"] and protocols.split("-") == [] and protocols.split("") == []
    assert protocols.split(None) == []


def test_a_capture_names_protocols_by_payload_then_port(tmp_path, monkeypatch):
    pkts = [
        # HTTP on an unusual port: the payload tells.
        (T, tcp(C, S, 51000, 8000, SYN)), (T + 0.01, tcp(S, C, 8000, 51000, SYN | ACK)),
        (T + 0.02, tcp(C, S, 51000, 8000, ACK | PSH, b"GET / HTTP/1.1\r\n\r\n")),
        # On 443 but not TLS: the port is all there is.
        (T + 1, tcp(C, S, 51001, 443, ACK | PSH, b"\x00\x01beacon")), (T + 1.01, tcp(S, C, 443, 51001, ACK)),
        # The server's banner, seen before the client says anything.
        (T + 2, tcp(C, S, 51002, 2222, SYN)), (T + 2.01, tcp(S, C, 2222, 51002, SYN | ACK)),
        (T + 2.02, tcp(S, C, 2222, 51002, ACK | PSH, b"SSH-2.0-OpenSSH_9.6\r\n")),
        (T + 3, icmp_echo(C, S)), (T + 3.01, icmp_echo(S, C, reply=True)),
        (T + 4, udp(C, S, 51003, 49999, b"\0" * 20)), (T + 4.01, udp(S, C, 49999, 51003, b"\0" * 20)),
        # Through a proxy: the first payload recognized names it (HTTP CONNECT, then TLS).
        (T + 5, tcp(C, S, 51004, 3128, ACK | PSH, b"CONNECT x.example:443 HTTP/1.1\r\n\r\n")),
        (T + 5.01, tcp(C, S, 51004, 3128, ACK | PSH, TLS_HELLO)),
        # Both ports well-known, the server seen first and told by its SYN-ACK: the server's port.
        (T + 6, tcp(S, C, 445, 443, SYN | ACK)), (T + 6, tcp(C, S, 443, 445, ACK)),
    ]
    files = split_into_files(tmp_path, pkts, 2, random.Random(1))
    flows = pcap.read_pcaps(files, workers=1)
    assert [(f.dport, f.service) for f in flows] == [(8000, "http"), (443, "ssl"), (2222, "ssh"),
                                                     (0, "icmp"), (49999, "unknown"), (3128, "http"),
                                                     (445, "smb")]
    monkeypatch.setattr(pcap, "in_order", in_process)          # packed by worker processes
    assert pcap.read_pcaps(files, workers=2) == flows


def test_netflow_names_protocols_by_port():
    done = FIN | SYN | PSH | ACK
    flows = pair_records([
        rec(C, 51000, S, 445, T, T + 1, flags=done), rec(S, 445, C, 51000, T, T + 1, flags=done),
        rec(S, 53, C, 51001, T, T, proto="udp"),                                  # the reply alone
        rec(C, 0, S, 0, T, T, proto="icmp", flags=SYN),
        rec(C, 50000, S, 49668, T, T + 1), rec(S, 49668, C, 50000, T, T + 1),     # both ways
        # Both ports well-known; the server's half listed first, the client told by its SYN.
        rec(S, 445, C, 443, T, T, flags=SYN | ACK), rec(C, 443, S, 445, T, T, flags=SYN)])
    assert sorted((f.src, f.dport, f.service) for f in flows) == [
        (C, 0, "icmp"), (C, 53, "dns"), (C, 445, "smb"), (C, 445, "smb"), (C, 49668, "unknown"),
        (S, 50000, "unknown")]


# ---- FTP: data connections named from the control connection, as Zeek names them ----------

@pytest.mark.parametrize("payload,expect", [
    (b"PORT 10,0,0,5,195,80\r\n", (protocols.FTP_PORT, "10.0.0.5", 50000)),
    (b"port 10, 0, 0, 5, 195, 80\r\n", (protocols.FTP_PORT, "10.0.0.5", 50000)),   # any case, spaces
    (b"PORT 10,0,0,256,195,80\r\n", None),                                          # not an address
    (b"PORT 10,0,0,5,0,0\r\n", None),                                               # port 0
    (b"PORT 10,0,0,5\r\n", None),
    (b"EPRT |1|10.0.0.5|50000|\r\n", (protocols.FTP_PORT, "10.0.0.5", 50000)),
    (b"EPRT !2!2001:DB8::5!50000!\r\n", (protocols.FTP_PORT, "2001:db8::5", 50000)),  # any delimiter
    (b"EPRT |1|2001:db8::5|50000|\r\n", None),                                      # IPv4 said, IPv6 given
    (b"EPRT |1|10.0.0.5|70000|\r\n", None),
    (b"227 Entering Passive Mode (10,0,0,9,19,137).\r\n", (protocols.FTP_PASV, "10.0.0.9", 5001)),
    (b"227 =10,0,0,9,19,137\r\n", (protocols.FTP_PASV, "10.0.0.9", 5001)),
    (b"229 Entering Extended Passive Mode (|||6446|)\r\n", (protocols.FTP_PASV, None, 6446)),
    (b"229 Entering Extended Passive Mode (|||0|)\r\n", None),
    (b"220 ProFTPD Server ready.\r\n", (protocols.FTP_GREETING, None, None)),
    (b"\r\n120 Ready in 5 minutes\r\n", (protocols.FTP_GREETING, None, None)),
    (b"220", None),
    (b"2200 x\r\n", None),
    (b"331 Password required\r\n", (protocols.FTP_LOGIN, None, None)),
    (b"230 Logged in\r\n", (protocols.FTP_LOGIN, None, None)),
    (b"USER anonymous\r\n", (protocols.FTP_USER, None, None)),
    (b"user anonymous\r\n", (protocols.FTP_USER, None, None)),
    (b"+OK POP3 ready\r\n", None),
    (b"EHLO mail.example\r\n", None),
    (b"", None),
])
def test_ftp_control_messages(payload, expect):
    assert protocols.ftp_signal(payload) == expect


FTP_C, FTP_S, OTHER = "10.0.0.5", "10.0.0.21", "10.0.0.66"


def ftp_control(t, port=21, cport=40000, then=(), greet=b"220 FTP ready\r\n", user=b"USER bob\r\n"):
    """An FTP control connection FTP_C:cport -> FTP_S:port: handshake, greeting and login, then
    `then`: [(who, payload)], who "c" (client) or "s" (server), 0.01 s apart."""
    c, s = FTP_C, FTP_S
    out = [(t, tcp(c, s, cport, port, SYN)), (t + 0.001, tcp(s, c, port, cport, SYN | ACK)),
           (t + 0.002, tcp(c, s, cport, port, ACK))]
    said = [("s", greet), ("c", user), ("s", b"331 Password required\r\n"), ("c", b"PASS x\r\n"),
            ("s", b"230 Logged in\r\n"), *then]
    for i, (who, data) in enumerate(said, 1):
        out.append((t + 0.01 * i, tcp(s, c, port, cport, PSH | ACK, data) if who == "s"
                    else tcp(c, s, cport, port, PSH | ACK, data)))
    return out


def ftp_data(t, src, sport, dst, dport, payload=b"x" * 50, syn=True):
    """A data connection src -> dst; without `syn`, the capture begins at the responder's
    SYN-ACK."""
    out = [(t + 0.001, tcp(dst, src, dport, sport, SYN | ACK)),
           (t + 0.002, tcp(src, dst, sport, dport, PSH | ACK, payload)),
           (t + 0.003, tcp(src, dst, sport, dport, FIN | ACK)),
           (t + 0.004, tcp(dst, src, dport, sport, FIN | ACK))]
    return ([(t, tcp(src, dst, sport, dport, SYN))] if syn else []) + out


def test_ftp_data_connections_are_named_from_the_control_connection(tmp_path, monkeypatch):
    pasv = [("c", b"PASV\r\n"), ("s", b"227 Entering Passive Mode (10,0,0,21,19,137).\r\n")]
    pkts = (
        # Passive, on port 21: the client connects to the port the server's 227 named. The
        # payload looks like TLS: the announcement still names it.
        ftp_control(T, then=pasv) + ftp_data(T + 1, FTP_C, 40100, FTP_S, 5001, TLS_HELLO)
        # Active: the server connects to the port the client's PORT named, from no port 20.
        + ftp_control(T + 10, cport=40001, then=[("c", b"PORT 10,0,0,5,195,81\r\n"), ("s", b"200 OK\r\n")])
        + ftp_data(T + 11, FTP_S, 30000, FTP_C, 50001)
        # EPSV on port 2121, told by the greeting, USER and login (Zeek's signature): the control
        # connection is FTP, and the data connection goes to the control server's address.
        + ftp_control(T + 20, port=2121, cport=40002,
                      then=[("c", b"EPSV\r\n"), ("s", b"229 Entering Extended Passive Mode (|||6446|)\r\n")])
        + ftp_data(T + 21, FTP_C, 40102, FTP_S, 6446, syn=False)        # the capture missed the SYN
        # A mail server greets with 220 too, but nobody sends USER: not FTP, and its "227" says nothing.
        + ftp_control(T + 30, port=2525, cport=40003, user=b"EHLO mail\r\n",
                      then=[("s", b"227 (10,0,0,21,19,138)\r\n")])
        + ftp_data(T + 31, FTP_C, 40103, FTP_S, 5002)
        # Announced, but the data connection comes from another host, then from the client too late.
        + ftp_control(T + 40, cport=40004, then=[("s", b"227 Entering Passive Mode (10,0,0,21,19,140).\r\n")])
        + ftp_data(T + 41, OTHER, 40104, FTP_S, 5004)
        + ftp_data(T + 40.05 + protocols.FTP_DATA_WAIT + 1, FTP_C, 40105, FTP_S, 5004)
        # Announced once, used once.
        + ftp_control(T + 400, cport=40006, then=[("s", b"227 Entering Passive Mode (10,0,0,21,19,141).\r\n")])
        + ftp_data(T + 401, FTP_C, 40106, FTP_S, 5005)
        + ftp_data(T + 402, FTP_C, 40107, FTP_S, 5005)
        # On port 21 the client must send PORT, and the server the 227.
        + ftp_control(T + 500, cport=40008, then=[("s", b"PORT 10,0,0,5,195,90\r\n"),
                                                   ("c", b"227 Entering Passive Mode (10,0,0,21,19,142).\r\n")])
        + ftp_data(T + 501, FTP_S, 30001, FTP_C, 50010) + ftp_data(T + 502, FTP_C, 40108, FTP_S, 5006)
    )
    pkts.sort(key=lambda p: p[0])
    files = split_into_files(tmp_path, pkts, 3, random.Random(2))
    flows = pcap.read_pcaps(files, workers=1)
    named = {(f.src, f.sport, f.dst, f.dport): f.service for f in flows}
    assert named == {
        (FTP_C, 40000, FTP_S, 21): "ftp", (FTP_C, 40100, FTP_S, 5001): "ftp",
        (FTP_C, 40001, FTP_S, 21): "ftp", (FTP_S, 30000, FTP_C, 50001): "ftp",
        (FTP_C, 40002, FTP_S, 2121): "ftp",
        (FTP_S, 6446, FTP_C, 40102): "ftp",          # seen first, the server is taken as initiator (D7)
        (FTP_C, 40003, FTP_S, 2525): "unknown", (FTP_C, 40103, FTP_S, 5002): "unknown",
        (FTP_C, 40004, FTP_S, 21): "ftp", (OTHER, 40104, FTP_S, 5004): "unknown",
        (FTP_C, 40105, FTP_S, 5004): "unknown",
        (FTP_C, 40006, FTP_S, 21): "ftp", (FTP_C, 40106, FTP_S, 5005): "ftp",
        (FTP_C, 40107, FTP_S, 5005): "unknown",
        (FTP_C, 40008, FTP_S, 21): "ftp", (FTP_S, 30001, FTP_C, 50010): "unknown",
        (FTP_C, 40108, FTP_S, 5006): "unknown",
    }
    monkeypatch.setattr(pcap, "in_order", in_process)          # packed by worker processes
    assert pcap.read_pcaps(files, workers=2) == flows


def test_ftp_announcements_are_capped_and_expire():
    tracker = pcap.FlowTracker()
    monkey = pcap.MAX_EXPECTED
    try:
        pcap.MAX_EXPECTED = 2
        for i, port in enumerate((5001, 5002, 5003)):
            tracker._expect(FTP_S, port, FTP_C, T + i)
        assert set(tracker.expected) == {(FTP_S, 5001), (FTP_S, 5002)}
        tracker._expect(FTP_S, 5002, OTHER, T + 5)              # a known spot is renewed
        assert tracker.expected[(FTP_S, 5002)] == (OTHER, T + 5 + protocols.FTP_DATA_WAIT)
    finally:
        pcap.MAX_EXPECTED = monkey
    tracker.add(T + 2 + protocols.FTP_DATA_WAIT, C, S, "udp", 1, 2, 10, 0, "x")    # sweeps
    assert set(tracker.expected) == {(FTP_S, 5002)}          # only what is past its time


def test_ftp_by_port_and_in_netflow_and_security_onion():
    assert protocols.name("tcp", 0, 20, 50000) == protocols.name("tcp", 0, 2811, 50000) == "ftp"
    assert protocols.split("ftp-data") == ["ftp"] and protocols.split("ftp,ftp-data") == ["ftp", "ftp"]
    flows = pair_records([rec(S, 20, C, 50000, T, T + 1, flags=SYN), rec(C, 50000, S, 20, T, T + 1, flags=SYN | ACK)])
    assert [(f.src, f.service) for f in flows] == [(S, "ftp")]
    assert protocols.display_name("ftp") == "FTP" and protocols.display_name("quic") == "QUIC"
