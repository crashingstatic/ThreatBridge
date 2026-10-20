"""Evidence readers: tcpdump captures and nfdump (nfcapd) files -> Flow records."""
import logging
import os

from ..model import SourceError
from .netflow import read_nfcapd
from .pcap import read_pcaps

__all__ = ["SourceError", "kind", "load"]

log = logging.getLogger(__name__)

_PCAP_MAGICS = {bytes.fromhex(m) for m in ("a1b2c3d4", "d4c3b2a1", "a1b23c4d", "4d3cb2a1")}
_PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")
_NFCAPD_MAGIC = bytes.fromhex("0ca5")  # 0xA50C, little-endian


def kind(path):
    """"pcap", "nfcapd", or None for anything else."""
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head in _PCAP_MAGICS:
        return "pcap"
    if head == _PCAPNG_MAGIC:
        raise SourceError(f"{path}: pcapng is not supported; convert it with: editcap -F pcap IN OUT")
    if head[:2] == _NFCAPD_MAGIC:
        if os.path.basename(path).startswith("nfcapd.current."):
            return None  # still being written by a running nfcapd
        return "nfcapd"
    return None


def _files(paths):
    """(path, named_explicitly) for each file, walking directories recursively."""
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, names in os.walk(path):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                for name in sorted(names):
                    if not name.startswith("."):
                        yield os.path.join(root, name), False
        elif os.path.isfile(path):
            yield path, True
        else:
            raise SourceError(f"{path}: no such file or directory")


def load(paths, dns=None):
    """Read every pcap and nfcapd file under `paths`; flows sorted by start time.

    If `dns` is a dict, it is filled with the DNS answers seen in the pcaps:
    {name: {ip: [first seen, last seen]}}. NetFlow carries no DNS content."""
    found = {"pcap": [], "nfcapd": []}
    for path, explicit in _files(paths):
        k = kind(path)
        if k:
            found[k].append(path)
        elif explicit:
            raise SourceError(f"{path}: not a pcap or nfcapd file")
        else:
            log.info("skipping %s: not a pcap or nfcapd file", path)
    if not found["pcap"] and not found["nfcapd"]:
        raise SourceError("no pcap or nfcapd files found in: " + ", ".join(paths))
    flows = []
    if found["pcap"]:
        flows.extend(read_pcaps(found["pcap"], dns))
    if found["nfcapd"]:
        flows.extend(read_nfcapd(found["nfcapd"]))
    flows.sort(key=lambda f: (f.start, f.src, f.dst, f.sport, f.dport))
    return flows
