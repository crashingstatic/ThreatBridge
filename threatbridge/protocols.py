"""Which protocol a connection carries, named as Zeek names its services (conn.log `service`,
`network.protocol` in Security Onion), so case files and Security Onion agree.

In a capture, from the first payload whose bytes show it (from_payload). Failing that, and in
NetFlow, which has no payload, from a well-known port. "icmp" for ICMP; "unknown" when
neither tells.
"""
import struct

# Codes from_payload returns: an index into NAMES (0: nothing recognized).
NAMES = (None, "dns", "http", "ssl", "ssh", "smb", "rdp", "dhcp")
DNS, HTTP, SSL, SSH, SMB, RDP, DHCP = range(1, len(NAMES))

UNKNOWN = "unknown"

# Well-known ports, by the name Zeek gives the service usually found there.
PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp",
    68: "dhcp", 80: "http", 88: "krb", 110: "pop3", 123: "ntp", 135: "dce_rpc", 139: "smb",
    143: "imap", 161: "snmp", 162: "snmp", 389: "ldap", 443: "ssl", 445: "smb", 465: "ssl",
    514: "syslog", 587: "smtp", 636: "ssl", 993: "ssl", 995: "ssl", 1433: "tds", 1812: "radius",
    3268: "ldap", 3306: "mysql", 3389: "rdp", 5353: "dns", 5355: "dns", 5432: "postgresql",
    5900: "rfb", 5985: "http", 5986: "ssl", 8080: "http", 8443: "ssl",
}

# Zeek's names that mean the same as another.
ALIASES = {"krb_tcp": "krb"}

_HTTP = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ",
         b"TRACE ", b"HTTP/1.")
_SMB = (b"\xffSMB", b"\xfeSMB", b"\xfdSMB")       # SMB1, SMB2/3, SMB3 encrypted
_DHCP_COOKIE = b"\x63\x82\x53\x63"


def from_payload(tcp, sport, dport, data):
    """The protocol a TCP (`tcp` true) or UDP payload's first bytes show, as a code (an index
    into NAMES), or 0."""
    n = len(data)
    if n < 4:
        return 0
    if tcp:
        if data[0] == 0x16 and data[1] == 3 and data[2] <= 4 and n >= 6 and data[5] in (1, 2):
            return SSL                       # a TLS handshake record: ClientHello, ServerHello
        if data.startswith(b"SSH-"):
            return SSH
        if data.startswith(_HTTP):
            return HTTP
        if n >= 8 and data[0] == 0 and data[4:8] in _SMB:
            return SMB                       # a NetBIOS session message carrying SMB
        if n >= 7 and data[:2] == b"\x03\x00" and data[5] in (0xE0, 0xD0) and 102 not in (sport, dport):
            return RDP                       # TPKT, X.224 connection request or confirm (102: S7)
        if int.from_bytes(data[:2], "big") == n - 2 and _dns(data, 2):
            return DNS                       # over TCP: a 2-byte length first
        return 0
    if n >= 240 and data[236:240] == _DHCP_COOKIE:
        return DHCP
    return DNS if _dns(data, 0) else 0


def _dns(data, off):
    """Whether data[off:] looks like a DNS message: one question, a standard opcode, sane
    counts, and a well-formed question name and class."""
    if len(data) < off + 17:
        return False
    opcode = (data[off + 2] >> 3) & 0xF
    qd, an, ns, ar = struct.unpack_from("!HHHH", data, off + 4)
    if qd != 1 or opcode not in (0, 4, 5) or max(an, ns, ar) > 100:
        return False
    i, total = off + 12, 0
    while data[i]:                           # labels of 1-63 bytes, 255 in all
        if data[i] > 63:
            return False
        total += data[i] + 1
        i += data[i] + 1
        if total > 255 or i >= len(data):
            return False
    if i + 5 > len(data):
        return False
    qclass = int.from_bytes(data[i + 3:i + 5], "big") & 0x7FFF      # top bit: mDNS unicast
    return qclass in (1, 3, 4, 254, 255)


def name(proto, code, server_port, client_port):
    """A connection's protocol: from its payload's code if any, else "icmp" for ICMP, else the
    service of its server's (then its client's) well-known port, else "unknown"."""
    if code:
        return NAMES[code]
    if proto == "icmp":
        return "icmp"
    return PORTS.get(server_port) or PORTS.get(client_port) or UNKNOWN


def split(value):
    """Zeek's service field ("smb,ntlm,gssapi"), as names; [] when empty."""
    names = (ALIASES.get(v, v) for v in (s.strip().lower() for s in str(value or "").split(",")))
    return [v for v in names if v and v != "-"]
