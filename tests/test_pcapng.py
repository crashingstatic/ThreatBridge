"""pcapng captures (ING-6): every interface with its own link type and clock, both byte orders,
several sections, the blocks that carry packets and those that don't, and damaged files. The
files are written byte by byte (evidence.pcapng_section), not with the reader's library."""
import dataclasses
import logging
import os
import shutil
import subprocess

import pytest

from evidence import (ACK, FIN, PSH, SYN, pcapng_block, pcapng_section, tcp, udp, write_pcap, write_pcapng)
from threatbridge import sources
from threatbridge.model import SourceError
from threatbridge.sources import pcap

T = 1_714_564_800.0
C, S, D = "10.0.0.5", "10.0.0.9", "10.0.0.53"
ETHERNET, RAW, WIFI = 1, 101, 105


def handshake(c=C, s=S, cport=50000, sport=445, t=T):
    return [(t + 0.000, tcp(c, s, cport, sport, SYN)), (t + 0.001, tcp(s, c, sport, cport, SYN | ACK)),
            (t + 0.002, tcp(c, s, cport, sport, ACK)), (t + 0.003, tcp(c, s, cport, sport, PSH | ACK, b"x" * 100)),
            (t + 0.004, tcp(s, c, sport, cport, FIN | ACK)), (t + 0.005, tcp(c, s, cport, sport, FIN | ACK))]


def read(*paths, workers=1):
    return sources.read(sources.find([str(p) for p in paths]), workers=workers)


def without_source(flows):
    return [dataclasses.replace(f, source="") for f in flows]


def conn(flows, dport):
    [f] = [f for f in flows if f.dport == dport]
    return f


def test_a_pcapng_gives_the_flows_its_pcap_gives(tmp_path):
    packets = handshake() + handshake(cport=50001, t=T + 5) + [(T + 9, udp(C, D, 53000, 53, b"q" * 30))]
    write_pcap(tmp_path / "a.pcap", packets)
    write_pcapng(tmp_path / "a.pcapng", packets)
    pcapng = read(tmp_path / "a.pcapng")
    assert len(pcapng) == 3 and without_source(pcapng) == without_source(read(tmp_path / "a.pcap"))
    assert {f.source for f in pcapng} == {str(tmp_path / "a.pcapng")}


def test_each_interface_has_its_own_link_type_and_clock(tmp_path):
    # Ethernet in microseconds; raw IP in nanoseconds, from an offset; raw IP in 1/1024 s.
    interfaces = [(ETHERNET, None, None), (RAW, 9, 1_700_000_000), (RAW, 0x8A, None)]
    blocks = [("epb", 0, ts, p) for ts, p in handshake(t=T)]
    blocks += [("epb", 1, ts, p) for ts, p in handshake(cport=50001, sport=22, t=T + 1.123456789)]
    blocks += [("epb", 2, ts, p) for ts, p in handshake(cport=50002, sport=3389, t=T + 2.5)]
    (tmp_path / "three.pcapng").write_bytes(pcapng_section("<", interfaces, sorted(blocks, key=lambda b: b[2])))
    flows = read(tmp_path / "three.pcapng")
    assert [(f.dport, f.packets) for f in flows] == [(445, 6), (22, 6), (3389, 6)]
    assert conn(flows, 445).start == T
    assert conn(flows, 22).start == pytest.approx(T + 1.123456789, abs=1e-6)
    assert conn(flows, 3389).start == T + 2.5                   # exact in 1/1024 s


def test_sections_in_both_byte_orders_each_number_their_interfaces(tmp_path):
    # Interface 0 is Ethernet in the first (big-endian) section and raw IP in the second.
    first = pcapng_section(">", [(ETHERNET, None, None)], [("epb", 0, ts, p) for ts, p in handshake()])
    second = pcapng_section("<", [(RAW, 6, None)], [("epb", 0, ts, p) for ts, p in handshake(cport=50001, t=T + 10)])
    (tmp_path / "two.pcapng").write_bytes(first + second)
    flows = read(tmp_path / "two.pcapng")
    assert [(f.sport, f.start, f.packets) for f in flows] == [(50000, T, 6), (50001, T + 10, 6)]


def test_blocks_that_carry_no_timed_packet(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="threatbridge.sources.pcap")
    p = handshake()
    blocks = [("block", 4, b"\0" * 4),                           # name resolution
              ("epb", 0, *p[0]), ("opb", 0, *p[1]),              # an obsolete packet block counts
              ("spb", 0, p[2][1]),                               # no timestamp: left out
              ("block", 0x00000BAD, b"custom data"),             # custom block
              ("epb", 7, T + 0.0025, p[2][1]),                   # an interface never described
              *[("epb", 0, ts, pkt) for ts, pkt in p[3:]],
              ("block", 5, b"\0" * 16)]                          # interface statistics
    path = tmp_path / "blocks.pcapng"
    path.write_bytes(pcapng_section("<", [(ETHERNET, None, None)], blocks))
    [f] = read(path)
    assert (f.src, f.dst, f.packets) == (C, S, 5)
    logs = [r.getMessage() for r in caplog.records]
    assert f"{path}: 1 packet(s) without a timestamp (pcapng simple packet blocks) left out" in logs
    assert f"{path}: 5 packets, 1 undecodable" in logs


def test_a_cut_off_pcapng_keeps_what_came_before(tmp_path, caplog):
    data = pcapng_section("<", [(ETHERNET, None, None)], [("epb", 0, ts, p) for ts, p in handshake()])
    path = tmp_path / "cut.pcapng"
    path.write_bytes(data[:-10])                                 # the last block cut short
    [f] = read(path)
    assert f.packets == 5
    assert f"{path}: capture is cut off after its last whole packet" in caplog.text


def test_a_damaged_pcapng_keeps_what_came_before(tmp_path, caplog):
    good = pcapng_section("<", [(ETHERNET, None, None)], [("epb", 0, ts, p) for ts, p in handshake()])
    rest = pcapng_section("<", [(ETHERNET, None, None)],
                          [("epb", 0, ts, p) for ts, p in handshake(cport=50001, t=T + 10)])
    for damage in (b"\x06\0\0\0\x0d\0\0\0" + b"\0" * 8,             # a block 13 bytes long
                   pcapng_block("<", 6, b"\0" * 24)[:-4] + b"\x99\0\0\0"):   # lengths disagree
        path = tmp_path / "damaged.pcapng"
        path.write_bytes(good + damage + rest)
        caplog.clear()
        [f] = read(path)
        assert f.sport == 50000
        assert f"{path}: capture is damaged at byte {len(good)}; the packets before it are read" in caplog.text


@pytest.mark.parametrize("data, why", [
    (b"\x0a\x0d\x0d\x0a" + b"\0" * 28, "unknown byte order"),
    (pcapng_section("<", [], [], version=2), "pcapng version 2"),
    (b"\x0a\x0d\x0d\x0a\x0d\0\0\0\x4d\x3c\x2b\x1a" + b"\0" * 16, "block length 13"),
    (pcapng_section("<", [], [])[:20], "cut off in its section header"),
])
def test_files_that_are_not_readable_pcapng(tmp_path, data, why):
    path = tmp_path / "bad.pcapng"
    path.write_bytes(data)
    with pytest.raises(SourceError, match=f"bad.pcapng: not a readable pcapng file .*{why}"):
        read(path)


def test_interfaces_of_a_link_type_not_decoded(tmp_path, caplog):
    wifi = [("epb", 0, T + 1, b"\x80\0" + b"\0" * 30)] * 3      # 802.11 frames: no decoder
    path = tmp_path / "mixed.pcapng"
    path.write_bytes(pcapng_section("<", [(WIFI, None, None), (ETHERNET, None, None)],
                                    wifi + [("epb", 1, ts, p) for ts, p in handshake(t=T + 2)]))
    [f] = read(path)
    assert f.packets == 6
    assert f"{path}: 3 packet(s) of unsupported link type 105 left out" in caplog.text
    only = tmp_path / "wifi.pcapng"
    only.write_bytes(pcapng_section("<", [(WIFI, None, None)], wifi))
    with pytest.raises(SourceError, match="wifi.pcapng: unsupported link type 105"):
        read(only)


def test_rotated_pcapng_files_in_worker_processes(tmp_path):
    # One connection across two files, named against capture order; read one at a time and in
    # worker processes: the same single flow.
    p = handshake()
    write_pcapng(tmp_path / "b.pcapng", p[:3])
    write_pcapng(tmp_path / "a.pcapng", p[3:], resol=9)
    one = read(tmp_path, workers=1)
    assert [(f.sport, f.packets, f.source) for f in one] == [(50000, 6, str(tmp_path / "b.pcapng"))]
    assert read(tmp_path, workers=2) == one


def test_first_timestamp_orders_pcapng_with_pcap(tmp_path):
    write_pcap(tmp_path / "late.pcap", handshake(t=T + 100))
    write_pcapng(tmp_path / "early.pcapng", handshake())
    assert pcap._first_timestamp(str(tmp_path / "early.pcapng")) == T
    assert sorted([str(tmp_path / "late.pcap"), str(tmp_path / "early.pcapng")],
                  key=pcap._first_timestamp)[0].endswith("early.pcapng")


# CI installs Wireshark's command-line tools, so there a missing one fails the test instead of
# skipping it.
@pytest.mark.skipif(not (shutil.which("mergecap") and shutil.which("editcap")) and not os.environ.get("CI"),
                    reason="Wireshark's mergecap and editcap not installed")
def test_pcapng_written_by_wireshark(tmp_path):
    # editcap turns a pcap into pcapng; mergecap merges captures of two link types (Ethernet in
    # microseconds, raw IP in nanoseconds) into one pcapng with an interface for each.
    write_pcap(tmp_path / "eth.pcap", handshake())
    write_pcap(tmp_path / "raw.pcap", handshake(cport=50001, sport=22, t=T + 0.0105), linktype=RAW, nano=True)
    one, merged = tmp_path / "one.pcapng", tmp_path / "merged.pcapng"
    subprocess.run(["editcap", "-F", "pcapng", str(tmp_path / "eth.pcap"), str(one)], check=True)
    subprocess.run(["mergecap", "-F", "pcapng", "-w", str(merged), str(tmp_path / "eth.pcap"),
                    str(tmp_path / "raw.pcap")], check=True)
    assert one.read_bytes()[:4] == merged.read_bytes()[:4] == bytes.fromhex("0a0d0d0a")
    assert without_source(read(one)) == without_source(read(tmp_path / "eth.pcap"))
    flows = read(merged)
    assert [(f.dport, f.packets) for f in flows] == [(445, 6), (22, 6)]
    assert conn(flows, 22).start == pytest.approx(T + 0.0105, abs=1e-6)
