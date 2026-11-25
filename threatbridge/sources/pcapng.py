"""Read pcapng captures (Wireshark's default format) packet by packet.

Every interface is read, each with its own link type, timestamp resolution and offset, in either
byte order, over any number of sections. (dpkt's reader takes the first interface's link type and
resolution for every packet, which misreads a capture on two interfaces.) Enhanced and obsolete
packet blocks are read; simple packet blocks carry no timestamp, so they are counted and
skipped; every other block is skipped.
"""
import struct

from ..model import SourceError

MAGIC = b"\x0a\x0d\x0d\x0a"        # section header block: the same bytes in both byte orders
_IDB, _OPB, _SPB, _EPB = 1, 2, 3, 6
_OPT_END, _OPT_TSRESOL, _OPT_TSOFFSET = 0, 9, 14
MAX_BLOCK = 64 * 1024 * 1024       # a longer block is taken as damage, not read into memory


class Damaged(Exception):
    """The file is damaged at a byte offset; what came before it is good."""

    def __init__(self, offset, why):
        super().__init__(f"damaged at byte {offset} ({why})")
        self.offset = offset


class _Interface:
    __slots__ = ("linktype", "ticks", "offset")

    def __init__(self, linktype, ticks, offset):
        self.linktype, self.ticks, self.offset = linktype, ticks, offset


def _options(data, order):
    """{code: value} of an options list."""
    out, i = {}, 0
    while i + 4 <= len(data):
        code, length = struct.unpack_from(order + "HH", data, i)
        if code == _OPT_END:
            break
        out.setdefault(code, data[i + 4:i + 4 + length])
        i += 4 + length + (-length % 4)
    return out


def _interface(body, order):
    if len(body) < 8:
        raise ValueError("interface description too short")
    linktype, _, _ = struct.unpack_from(order + "HHI", body)
    opts = _options(body[8:], order)
    ticks = 10 ** 6                                        # microseconds unless it says otherwise
    resol = opts.get(_OPT_TSRESOL)
    if resol:
        ticks = 2 ** (resol[0] & 0x7F) if resol[0] & 0x80 else 10 ** resol[0]
    offset = opts.get(_OPT_TSOFFSET)
    seconds = struct.unpack(order + "q", offset[:8])[0] if offset and len(offset) >= 8 else 0
    return _Interface(linktype, ticks, seconds)


def _blocks(fh):
    """(offset, byte order, block type, body) for each block, the byte order taken from each
    section header. Ends quietly at a block cut off by the end of the file (the second value
    of the final item is None then); raises Damaged where the structure is broken."""
    order, offset = None, 0
    while True:
        head = fh.read(8)
        if not head:
            return
        if len(head) < 8:
            yield offset, None, None, None
            return
        if head[:4] == MAGIC:
            bom = fh.read(4)
            if len(bom) < 4:
                yield offset, None, None, None
                return
            order = {b"\x1a\x2b\x3c\x4d": ">", b"\x4d\x3c\x2b\x1a": "<"}.get(bom)
            if order is None:
                raise Damaged(offset, "unknown byte order")
            head += bom
        elif order is None:
            raise Damaged(offset, "no section header")
        btype, length = struct.unpack(order + "II", head[:8])
        if length < 12 or length % 4 or length > MAX_BLOCK or (btype == struct.unpack(order + "I", MAGIC)[0]
                                                                and length < 28):
            raise Damaged(offset, f"block length {length}")
        rest = fh.read(length - len(head))
        if len(rest) < length - len(head):
            yield offset, None, None, None
            return
        block = head + rest
        if struct.unpack_from(order + "I", block, length - 4)[0] != length:
            raise Damaged(offset, "block lengths disagree")
        yield offset, order, btype, block[8:-4]
        offset += length


def read(fh, counts, path):
    """(timestamp, link type, frame) for each packet of an open pcapng file at `path`. A file cut off
    inside a block ends at the last whole one (counts.cut_off); one damaged further in ends at
    the damage (counts.damaged: its byte offset). Packets without a timestamp, or of an
    interface never described, are counted in counts.untimed and counts.skipped."""
    interfaces = []
    try:
        for offset, order, btype, body in _blocks(fh):
            if order is None:
                if offset == 0:
                    raise SourceError(f"{path}: not a readable pcapng file (cut off in its section header)")
                counts.cut_off = True
                return
            if btype == struct.unpack(order + "I", MAGIC)[0]:
                major = struct.unpack_from(order + "H", body, 4)[0]
                if major != 1:
                    raise Damaged(offset, f"pcapng version {major}")
                interfaces = []                            # interface numbers start again
            elif btype == _IDB:
                try:
                    interfaces.append(_interface(body, order))
                except (ValueError, struct.error) as e:
                    raise Damaged(offset, str(e))
            elif btype in (_EPB, _OPB):
                if len(body) < 20:
                    raise Damaged(offset, "packet block too short")
                if btype == _EPB:
                    number, high, low, captured = struct.unpack_from(order + "IIII", body)
                else:
                    number, _, high, low, captured = struct.unpack_from(order + "HHIII", body)
                frame = body[20:20 + captured]
                if len(frame) < captured:
                    raise Damaged(offset, "packet longer than its block")
                if number >= len(interfaces):
                    counts.skipped += 1
                    continue
                i = interfaces[number]
                yield ((high << 32) | low) / i.ticks + i.offset, i.linktype, frame
            elif btype == _SPB:
                counts.untimed += 1
    except Damaged as e:
        counts.damaged = e.offset
        if not interfaces and e.offset == 0:
            raise SourceError(f"{path}: not a readable pcapng file ({e})")
