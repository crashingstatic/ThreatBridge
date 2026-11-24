"""Evidence readers: packet captures (pcap, pcapng) and nfdump (nfcapd) files -> Flow records;
DHCP logs -> who held which address when (dhcp.py)."""
import logging
import os

from ..model import SourceError
from . import dhcp
from .netflow import read_nfcapd
from .pcap import read_pcaps

__all__ = ["SourceError", "find", "manifest", "read"]

log = logging.getLogger(__name__)

_PCAP_MAGICS = {bytes.fromhex(m) for m in ("a1b2c3d4", "d4c3b2a1", "a1b23c4d", "4d3cb2a1")}
_PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")
_NFCAPD_MAGIC = bytes.fromhex("0ca5")  # 0xA50C, little-endian


def _kind(path):
    """"pcap", "nfcapd", "dhcp", or None for anything else."""
    with open(path, "rb") as fh:
        head = fh.read(dhcp.SNIFF)
    if head[:4] in _PCAP_MAGICS or head[:4] == _PCAPNG_MAGIC:   # both read by pcap.py
        return "pcap"
    if head[:2] == _NFCAPD_MAGIC:
        return "nfcapd"
    if dhcp.kind(head):
        return "dhcp"
    return None


def _being_written(path):
    return os.path.basename(path).startswith("nfcapd.current.")  # by a running nfcapd


def _problem(path, kind):
    """Why a file of this kind can't be read as evidence, or None if it can."""
    if not kind:
        return "not a pcap, pcapng, nfcapd or DHCP log file"
    if kind == "nfcapd" and _being_written(path):
        return "nfcapd is still being written to; use the files it has already rotated"
    return None


def _files(paths):
    """(path, named_explicitly) for each file, walking directories recursively (hidden files
    and directories left out)."""
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


def find(paths):
    """{"pcap": [...], "nfcapd": [...], "dhcp": [...]}: the evidence files under `paths`, each
    once however many times it is named (directly, through its directory, or through a
    symlink). A file named itself that can't be read is an error; one found in a directory is
    skipped."""
    found, seen = {"pcap": [], "nfcapd": [], "dhcp": []}, set()
    for path, explicit in _files(paths):
        real = os.path.realpath(path)
        if real in seen:
            continue
        seen.add(real)
        k = _kind(path)
        problem = _problem(path, k)
        if not problem:
            found[k].append(path)
        elif explicit:
            raise SourceError(f"{path}: {problem}")
        else:
            log.info("skipping %s: %s", path, problem)
    if not found["pcap"] and not found["nfcapd"]:
        raise SourceError("no pcap, pcapng or nfcapd files found in: " + ", ".join(paths))
    return found


def manifest(found):
    """[(absolute path, size, mtime_ns)] for the files in `found`: what a case was built from."""
    out = []
    for path in found["pcap"] + found["nfcapd"] + found.get("dhcp", []):
        st = os.stat(path)
        out.append((os.path.abspath(path), st.st_size, st.st_mtime_ns))
    return out


def read(found, dns=None, workers=1, stage=None, dhcp_observations=None, dhcp_tz=None):
    """Flows from the files in `found`, sorted by start time.

    If `dns` is a dict, it is filled with the DNS answers seen in the pcaps:
    {name: {ip: [first seen, last seen]}}. NetFlow carries no DNS content. If
    `dhcp_observations` is a list, it gets what the DHCP logs and the DHCP messages in the
    pcaps tell (dhcp.py), Windows logs read in zone `dhcp_tz`.
    workers: how many files to read at once, in worker processes. `stage` (see progress.py)
    is told the bytes read."""
    stage = stage or (lambda amount=0, note=None: None)
    flows = []
    if dhcp_observations is not None:
        for path in found.get("dhcp", []):
            dhcp_observations.extend(dhcp.read_file(path, dhcp_tz or dhcp.timezone_named("UTC")))
            stage(os.path.getsize(path), f"DHCP log {os.path.basename(path)}")
    if found["pcap"]:
        flows.extend(read_pcaps(found["pcap"], dns, workers, stage, dhcp_observations))
    if found["nfcapd"]:
        flows.extend(read_nfcapd(found["nfcapd"], workers, stage))
    flows.sort(key=lambda f: (f.start, f.src, f.dst, f.sport, f.dport))
    return flows
