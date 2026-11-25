"""Which protocol a connection carries, named as Zeek names its services (conn.log `service`,
`network.protocol` in Security Onion), so case files and Security Onion agree.

In a capture, from the first payload whose bytes show it (from_payload), or, for an FTP data
connection, from the control connection that announced it (ftp_signal, and the tracker in
sources/pcap.py). Failing that, and in NetFlow, which has no payload, from a well-known port.
"icmp" for ICMP; "unknown" when neither tells.
"""
import re
import socket
import struct

# Codes from_payload returns: an index into NAMES (0: nothing recognized).
NAMES = (None, "dns", "http", "ssl", "ssh", "smb", "rdp", "dhcp", "ftp")
DNS, HTTP, SSL, SSH, SMB, RDP, DHCP, FTP = range(1, len(NAMES))

# What an FTP control message says (ftp_signal), as codes beyond NAMES: the server's greeting
# (120/220) and its answer to a login (230/331), the client's USER, and a data connection
# announced by the client's PORT/EPRT or the server's 227/229 answer to PASV/EPSV.
FTP_GREETING, FTP_LOGIN, FTP_USER, FTP_PORT, FTP_PASV = range(100, 105)
FTP_PORTS = (21, 2811)        # Zeek's FTP::ports
FTP_DATA_WAIT = 300.0         # seconds an announced data connection is expected (Zeek: 5 min)

UNKNOWN = "unknown"

# Well-known ports, by the name Zeek gives the service usually found there.
PORTS = {
    20: "ftp", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp",
    68: "dhcp", 80: "http", 88: "krb", 110: "pop3", 123: "ntp", 135: "dce_rpc", 139: "smb",
    143: "imap", 161: "snmp", 162: "snmp", 389: "ldap", 443: "ssl", 445: "smb", 465: "ssl",
    514: "syslog", 587: "smtp", 636: "ssl", 993: "ssl", 995: "ssl", 1433: "tds", 1812: "radius",
    2811: "ftp", 3268: "ldap", 3306: "mysql", 3389: "rdp", 5353: "dns", 5355: "dns",
    5432: "postgresql", 5900: "rfb", 5985: "http", 5986: "ssl", 8080: "http", 8443: "ssl",
}

# Zeek's names that mean the same as another. An FTP data connection is FTP.
ALIASES = {"krb_tcp": "krb", "ftp-data": "ftp"}

# Each protocol as the map shows it: one word, case as written. Another service shows in
# capitals (display_name).
DISPLAY = {
    "dns": "DNS", "http": "HTTP", "ssl": "TLS", "ssh": "SSH", "smb": "SMB", "rdp": "RDP",
    "dhcp": "DHCP", "krb": "Kerberos", "dce_rpc": "DCE-RPC", "ntlm": "NTLM", "gssapi": "GSSAPI",
    "ldap": "LDAP", "ntp": "NTP", "snmp": "SNMP", "ftp": "FTP", "smtp": "SMTP", "pop3": "POP3",
    "imap": "IMAP", "telnet": "Telnet", "syslog": "Syslog", "tds": "MSSQL", "mysql": "MySQL",
    "postgresql": "PostgreSQL", "rfb": "VNC", "radius": "RADIUS", "icmp": "ICMP",
    "unknown": "Unknown",
}


def display_name(service):
    return DISPLAY.get(service) or service.upper()


_HTTP = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ",
         b"TRACE ", b"HTTP/1.")
_SMB = (b"\xffSMB", b"\xfeSMB", b"\xfdSMB")       # SMB1, SMB2/3, SMB3 encrypted
_DHCP_COOKIE = b"\x63\x82\x53\x63"


def from_payload(tcp, sport, dport, data):
    """The protocol a TCP (`tcp` true) or UDP payload's first bytes show, as a code (an index
    into NAMES), or 0. Each test is one protocol's signature; the first that matches wins."""
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


_FTP_FIRST = frozenset(b"123PEUpeu \r\n")
_FTP_GREETING = re.compile(rb"[\r\n ]*(?:120|220)[^0-9]")
_FTP_LOGIN = re.compile(rb" *(?:230|331)[^0-9]")
_FTP_USER = re.compile(rb" *USER ", re.I)
_SIX = rb" *(\d{1,3}) *, *(\d{1,3}) *, *(\d{1,3}) *, *(\d{1,3}) *, *(\d{1,3}) *, *(\d{1,3})"
_FTP_PORT = re.compile(rb" *PORT +" + _SIX, re.I)
_FTP_227 = re.compile(rb" *227[ -][^\r\n]*?" + _SIX)
_FTP_EPRT = re.compile(rb" *EPRT +([!-~])([12])\1([0-9A-Fa-f.:]+)\1(\d{1,5})\1", re.I)
_FTP_229 = re.compile(rb" *229[ -][^\r\n]*?\(([!-~])\1\1(\d{1,5})\1\)")


def _six_numbers(code):
    """A reader for PORT and 227: an address and port as six numbers, each 0 to 255."""
    def read(m):
        *octets, p1, p2 = (int(x) for x in m.groups())
        port = p1 * 256 + p2
        return (code, ".".join(map(str, octets)), port) if max(*octets, p1, p2) <= 255 and port else None
    return read


def _eprt(m):
    family = socket.AF_INET if m.group(2) == b"1" else socket.AF_INET6
    try:
        host = socket.inet_ntop(family, socket.inet_pton(family, m.group(3).decode()))
    except (OSError, ValueError):
        return None
    port = int(m.group(4))
    return (FTP_PORT, host, port) if 0 < port < 65536 else None


def _epsv(m):
    port = int(m.group(2))
    return (FTP_PASV, None, port) if 0 < port < 65536 else None


# Each FTP control message ftp_signal knows, tried in turn, with what reads it.
_FTP_MESSAGES = ((_FTP_PORT, _six_numbers(FTP_PORT)), (_FTP_227, _six_numbers(FTP_PASV)), (_FTP_EPRT, _eprt),
                 (_FTP_229, _epsv), (_FTP_GREETING, lambda m: (FTP_GREETING, None, None)),
                 (_FTP_LOGIN, lambda m: (FTP_LOGIN, None, None)), (_FTP_USER, lambda m: (FTP_USER, None, None)))


def ftp_signal(data):
    """What a TCP payload says if it is an FTP control message: (code, host, port), with a
    code from FTP_GREETING to FTP_PASV and, for a data connection announced (FTP_PORT,
    FTP_PASV), its address (None: the control connection's server) and port; or None. The
    first message that matches decides, even if its numbers are out of range."""
    if not data or data[0] not in _FTP_FIRST:       # a quick no for most payloads
        return None
    for pattern, read in _FTP_MESSAGES:
        m = pattern.match(data)
        if m:
            return read(m)
    return None


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
