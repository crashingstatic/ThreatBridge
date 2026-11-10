"""Build small evidence files for tests: tcpdump-style pcaps and real nfcapd files."""
import os
import shutil
import signal
import socket
import struct
import subprocess
import time

import dpkt

from threatbridge import sources

MAC = bytes.fromhex("001122334455")
SYN, ACK, FIN, RST, PSH = (dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_FIN, dpkt.tcp.TH_RST,
                           dpkt.tcp.TH_PUSH)


def _ip(src, dst, proto, payload):
    """(IP packet, ethertype, IP-layer length)."""
    if ":" in src:
        ip = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, src),
                          dst=socket.inet_pton(socket.AF_INET6, dst), nxt=proto, hlim=64,
                          data=payload)
        ip.plen = len(payload)
        return ip, dpkt.ethernet.ETH_TYPE_IP6, 40 + len(payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=proto, ttl=64,
                    data=payload)
    ip.len = 20 + len(payload)
    return ip, dpkt.ethernet.ETH_TYPE_IP, ip.len


def tcp(src, dst, sport, dport, flags, payload=b""):
    return _ip(src, dst, 6, dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, off=5,
                                         data=payload))


def udp(src, dst, sport, dport, payload=b""):
    dg = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    dg.ulen = 8 + len(payload)
    return _ip(src, dst, 17, dg)


def dns_answer(qname, answers, rcode=0):
    """A DNS response payload. answers: [(name, "A"|"AAAA"|"CNAME", value)]."""
    msg = dpkt.dns.DNS(id=7, qr=dpkt.dns.DNS_R, rcode=rcode)
    msg.qd = [dpkt.dns.DNS.Q(name=qname, type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN)]
    msg.an = []
    for name, rtype, value in answers:
        rr = dpkt.dns.DNS.RR(name=name, cls=dpkt.dns.DNS_IN, ttl=60)
        if rtype == "A":
            rr.type, rr.ip = dpkt.dns.DNS_A, socket.inet_aton(value)
        elif rtype == "AAAA":
            rr.type, rr.ip6 = dpkt.dns.DNS_AAAA, socket.inet_pton(socket.AF_INET6, value)
        else:
            rr.type, rr.cname = dpkt.dns.DNS_CNAME, value
        msg.an.append(rr)
    return bytes(msg)


def icmp_echo(src, dst, reply=False):
    msg = dpkt.icmp.ICMP(type=0 if reply else 8, code=0,
                         data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"ping"))
    return _ip(src, dst, 1, msg)


def write_pcap(path, packets, linktype=1, nano=False):
    """packets: [(ts, packet)] with packets from tcp()/udp()/icmp_echo(), or raw frames (bytes)."""
    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh, linktype=linktype, nano=nano)
        for ts, pkt in packets:
            if isinstance(pkt, bytes):
                frame = pkt
            else:
                ip, etype, _ = pkt
                if linktype == 1:
                    frame = dpkt.ethernet.Ethernet(src=MAC, dst=MAC, type=etype, data=ip)
                elif linktype == 101:
                    frame = ip
                elif linktype == 113:
                    frame = dpkt.sll.SLL(type=0, hrd=1, hlen=6, hdr=MAC + b"\0\0", ethtype=etype, data=ip)
                elif linktype == 276:
                    frame = dpkt.sll2.SLL2(ethtype=etype, hdr=MAC + b"\0\0", data=ip)
                else:
                    raise ValueError(linktype)
            w.writepkt(bytes(frame), ts=ts)


def load(paths, dns=None):
    """Flows from every pcap and nfcapd file under `paths`, read as the case backend reads them."""
    return sources.read(sources.find(paths), dns)


def ip_bytes(packets):
    return sum(p[2] for _, p in packets if not isinstance(p, bytes))


# ---- NetFlow ------------------------------------------------------------------------------

def netflow_v5(records, unix_secs, uptime_ms=10_000_000):
    """One NetFlow v5 export packet. records: (src, dst, sport, dport, proto, packets, bytes,
    start_epoch, end_epoch)."""
    out = struct.pack("!HHIIIIBBH", 5, len(records), uptime_ms, unix_secs, 0, 1, 0, 0, 0)
    for src, dst, sport, dport, proto, pkts, octets, start, end in records:
        first = uptime_ms - round((unix_secs - start) * 1000)
        last = uptime_ms - round((unix_secs - end) * 1000)
        out += struct.pack("!4s4s4sHHIIIIHHBBBBHHBBH", socket.inet_aton(src), socket.inet_aton(dst),
                           bytes(4), 0, 0, pkts, octets, first, last, sport, dport, 0, 0x1b, proto,
                           0, 0, 0, 0, 0, 0)
    return out


def have_nfdump():
    return bool(shutil.which("nfcapd") and shutil.which("nfdump"))


def make_nfcapd(directory, records, unix_secs):
    """Write a real nfcapd file into `directory` by exporting NetFlow v5 to a local nfcapd."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(["nfcapd", "-w", str(directory), "-b", "127.0.0.1", "-p", str(port),
                             "-t", "3600"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while not any(n.startswith("nfcapd.current.") for n in os.listdir(directory)):
            if time.monotonic() > deadline or proc.poll() is not None:
                raise RuntimeError("nfcapd did not start")
            time.sleep(0.05)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(netflow_v5(records, unix_secs), ("127.0.0.1", port))
        time.sleep(1)  # let nfcapd read the datagram before it is told to stop
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
    files = [n for n in os.listdir(directory) if n.startswith("nfcapd.") and "current" not in n]
    if len(files) != 1:
        raise RuntimeError(f"expected one nfcapd file, found {files}")
    return os.path.join(directory, files[0])


def write_bulk_pcap(path, n, seed=7):
    """n single-packet UDP flows (distinct 5-tuples), written directly for speed.
    About 78 bytes per packet: the most flows a pcap of a given size can hold."""
    import random
    rng = random.Random(seed)
    eth = MAC + MAC + b"\x08\x00"
    t0 = 1_714_564_800
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i in range(n):
            src = bytes((10, rng.randint(0, 3), rng.randint(0, 255), rng.randint(1, 254)))
            dst = bytes((10, rng.randint(0, 3), rng.randint(0, 255), rng.randint(1, 254)))
            dgram = struct.pack("!HHHH", 1024 + i % 60000, 53 + i // 60000, 28, 0) + bytes(20)
            frame = eth + struct.pack("!BBHHHBBH4s4s", 0x45, 0, 48, 0, 0, 64, 17, 0, src, dst) + dgram
            usec = i * 10_000
            fh.write(struct.pack("<IIII", t0 + usec // 1_000_000, usec % 1_000_000,
                                 len(frame), len(frame)) + frame)
