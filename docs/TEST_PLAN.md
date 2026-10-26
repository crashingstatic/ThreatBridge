# ThreatBridge GUI test plan

This plan lets an operator check, in the browser, that each feature and requirement behaves as
specified. Every test is something a person does in the map and something they can see there. It
does not check source code. Requirement IDs refer to [REQUIREMENTS.md](REQUIREMENTS.md).

Contents:

1. [How to use this plan](#1-how-to-use-this-plan)
2. [Test environments](#2-test-environments)
3. [Tests](#3-tests)
4. [Requirement coverage](#4-requirement-coverage)
5. [Not verifiable in the GUI](#5-not-verifiable-in-the-gui)

## 1. How to use this plan

- **Title and Proves.** Each test's title names what it proves. Each step's *Proves* column says
  which feature or requirement that step shows. A test passes when every step's *Expect* holds.
  Write P (pass) or F (fail) in the *Result* column, and for an F, note what you saw.
- **Starting state** is what must be true before step 1. *Fresh state* means the server was
  started from the environment's commands with a new, empty work directory (`$W`). Tests within
  a section can run back to back unless a starting state says otherwise.
- **Toolbar defaults:** Host / IOC IP blank, Anchor time blank, Direction *Inbound*, Window
  `24h`, Range from/to blank, Peers *Top*, N `50`.
- **"Map X inbound"** means: type X in *Host / IOC IP*, choose Direction *Inbound: who connected to
  the host (past)*, leave the other fields as the step says (otherwise as they are), and click
  **Map**. *Outbound* is *Outbound: who the host connected to (future)*.
- **Status line** is the text at the right end of the toolbar. "Red" means it is shown as an
  error and "amber" as a warning; otherwise it is the normal colour.
- **Side panel** is the right-hand panel. **Details** is its top part.
- **Edge label** is the text on a connection: `count · ports`, e.g. `1 · 445`.
- **Colours** are those of the legend at the bottom of the side panel:

  | Legend entry | Look |
  |---|---|
  | IOC host | large red node |
  | inbound (past) | blue arrow |
  | outbound (future) | orange arrow |
  | compromised | dark red node, light red border |
  | attack path | thick red arrow |
  | path between two hosts | thick pink arrow |
  | threat line: earlier | violet arrow, violet node border |
  | threat line: later | teal arrow, teal node border |

  On a threat line the clicked connection is white, and everything not on the line is faded.
- Exact texts are in `code`. A `…` in them marks a part that varies or doesn't matter. The map
  itself shows a `…` only in the menu items `Find paths from this host…` and `Find paths to this
  host…`, the busy indicator `Working… N s`, and statuses shown while a request runs (e.g.
  `Asking the sensor for the packets of A → B at T…`). Capitals such as A, B, T and N, and words
  in <angle brackets>, stand for values the step names. Times are UTC.
- Use Chrome or Chromium; [PRG-01](#prg-01--busy-indicator-cancel-and-writes-in-quick-succession-prf-s3-atk-4)
  uses its DevTools. Keep DevTools' Console open. A step whose result is a red status also logs
  `Failed to load resource: the server responded with a status of 4xx/5xx`; that is expected.
  Any other console error (an uncaught exception, a Content Security Policy violation) is a
  failure of the step that caused it.

## 2. Test environments

Run the commands from the repository root. Install the dependencies once with
`python -m pip install -r requirements.txt pytest` (Python 3.11 or later). Stop a server with
Ctrl+C. To restart one "with the same state", run the same command again with the same `$W`.

### ENV-DEMO: demo backend (stands in for Security Onion)

Deterministic fake data. It has SOC pivots and *PCAP in SOC* links, but no threat lines or paths.
Live DNS lookups are on.

```bash
export W=$(mktemp -d)
TB_BACKEND=demo TB_SOC_URL=https://so.example \
TB_EXCLUDE_FILE=$W/exclude.json TB_COMPROMISED_FILE=$W/compromised.json TB_SESSIONS_DIR=$W/sessions \
python -m threatbridge --port 5055
# browse to http://127.0.0.1:5055/
```

`so.example` is a placeholder, so pages opened on it don't load. The tests check their
addresses, not their content.

### ENV-CASE: the generated attack-chain case (post-mortem mode)

```bash
export W=$(mktemp -d)
python tests/make_case.py $W/case
TB_LIVE_DNS=false TB_MAX_PATHS=11 \
TB_EXCLUDE_FILE=$W/exclude.json TB_COMPROMISED_FILE=$W/compromised.json TB_SESSIONS_DIR=$W/sessions \
python -m threatbridge --case $W/case --port 5056
# browse to http://127.0.0.1:5056/
```

`TB_MAX_PATHS=11` lowers the path cap so that a test can reach it. The capture
(`$W/case/chain.pcap`) holds these connections, all on 2024-05-01 (151 flows, 23 hosts):

| Time | Connection | Port | Role |
|---|---|---|---|
| 11:40:00 | 10.0.0.9 → 10.0.0.53 | 53/udp | DNS answer: `updates.example.com` = 10.0.0.77 |
| 11:50:00 | 10.0.0.20 → 10.0.0.30 | 22 | before the attacker reached 10.0.0.20 |
| 12:00:00 | 203.0.113.66 → 10.0.0.5 | 443 | the chain, hop 1 |
| 12:01:40 – 12:01:51 | 10.0.2.1 → 10.0.2.10 … 10.0.2.21, one per second | 445 | fan-out |
| 12:03:20 – 12:03:31 | 10.0.2.10 … 10.0.2.21 → 10.0.2.2, one per second | 3389 | fan-in: 12 two-hop routes |
| 12:10:00 | 10.0.0.5 → 10.0.0.9 | 445 | the chain, hop 2 |
| 12:15:00 | 10.0.0.5 → 10.0.0.20 | 5985 | a shortcut |
| 12:20:00 | 10.0.0.9 → 10.0.0.20 | 3389 | the chain, hop 3 |
| 12:30:00 | 10.0.0.77 → 10.0.0.9 | 80 | into 10.0.0.9, after hop 2 |
| 12:50:00 – 13:09:50 | 10.0.1.1 → 10.0.1.2, 120 connections 10 s apart | 8443 | to page through |

The data runs from `2024-05-01T11:40:00.000Z` to `2024-05-01T13:09:50.001Z`.

### ENV-EVIDENCE: capture-reading rules

Save this script as `$W/make_evidence.py`. It is run from the repository root.

```bash
export W=$(mktemp -d)
cat > $W/make_evidence.py <<'EOF'
"""Evidence for the reading tests: python make_evidence.py OUTDIR (run from the repository root)."""
import os
import sys

sys.path[:0] = ["tests", "."]
from evidence import ACK, FIN, PSH, RST, SYN, tcp, udp, write_pcap  # noqa: E402

T = 1_714_564_800.0                                    # 2024-05-01T12:00:00Z


def conn(c, s, sport, dport, t, flags, data=b"", back=False):
    return (t, tcp(s, c, dport, sport, flags, data) if back else tcp(c, s, sport, dport, flags, data))


def main(d):
    os.makedirs(d, exist_ok=True)
    a = ("10.0.0.5", "10.0.0.9", 50000, 445)
    # One connection split across two rotated files, named so that name order is the reverse
    # of capture order.
    write_pcap(os.path.join(d, "b-first.pcap"), [
        conn(*a, T, SYN), conn(*a, T + 0.001, SYN | ACK, back=True), conn(*a, T + 0.002, ACK)])
    write_pcap(os.path.join(d, "a-second.pcap"), [
        conn(*a, T + 1, PSH | ACK, b"x" * 100), conn(*a, T + 1.5, PSH | ACK, b"y" * 200, back=True),
        conn(*a, T + 2, FIN | ACK), conn(*a, T + 2.001, FIN | ACK, back=True), conn(*a, T + 2.002, ACK)])
    idle = ("10.0.0.6", "10.0.0.9", 50001, 22)
    rst = ("10.0.0.7", "10.0.0.9", 50002, 445)
    write_pcap(os.path.join(d, "rules.pcap"), sorted([
        conn(*idle, T + 10, SYN), conn(*idle, T + 10.001, SYN | ACK, back=True),
        conn(*idle, T + 20, PSH | ACK, b"z"),                 # then 6 minutes idle: a new flow
        conn(*idle, T + 380, PSH | ACK, b"z"),
        (T + 30, udp("10.0.0.6", "10.0.0.53", 40000, 53, b"q")),
        (T + 60, udp("10.0.0.6", "10.0.0.53", 40000, 53, b"q")),   # 30 s later: same flow
        (T + 130, udp("10.0.0.6", "10.0.0.53", 40000, 53, b"q")),  # 70 s idle: a new flow
        conn(*rst, T + 40, SYN), conn(*rst, T + 40.001, RST | ACK, back=True),
        conn(*rst, T + 41, SYN),                              # same ports after the RST: a new flow
    ], key=lambda p: p[0]))
    # Link types other than Ethernet, one connection each, and nanosecond timestamps.
    os.makedirs(os.path.join(d, "linktypes"), exist_ok=True)
    for name, linktype, nano, host in [("sll.pcap", 113, False, "10.0.3.1"), ("sll2.pcap", 276, False, "10.0.3.2"),
                                       ("raw.pcap", 101, False, "10.0.3.3"), ("nano.pcap", 1, True, "10.0.3.4")]:
        write_pcap(os.path.join(d, "linktypes", name), [conn(host, "10.0.3.100", 50003, 80, T + 50.123456789, SYN)],
                   linktype=linktype, nano=nano)
    # tcpdump killed mid-write: the file ends inside a packet's record header.
    cut = os.path.join(d, "cut.pcap")
    write_pcap(cut, [conn("10.0.0.8", "10.0.0.9", 50004, 80, T + 70, SYN),
                     conn("10.0.0.8", "10.0.0.9", 50004, 80, T + 70.001, SYN | ACK, back=True)])
    with open(cut, "ab") as fh:
        fh.write(b"\0" * 8)
    with open(os.path.join(d, "notes.txt"), "w") as fh:
        fh.write("not evidence: skipped\n")


if __name__ == "__main__":
    main(sys.argv[1])
EOF
python $W/make_evidence.py $W/ev
# The directory and one of its files are both named: that file must be read once.
TB_LIVE_DNS=false TB_EXCLUDE_FILE=$W/exclude.json TB_COMPROMISED_FILE=$W/compromised.json TB_SESSIONS_DIR=$W/sessions \
python -m threatbridge --case $W/ev $W/ev/b-first.pcap --port 5057
# browse to http://127.0.0.1:5057/
```

Variant **ENV-EVIDENCE-1**: the same command with `TB_READ_WORKERS=1` in front, which reads one
file at a time instead of in parallel worker processes.

### ENV-NETFLOW: an nfcapd file

This needs `nfcapd` and `nfdump` (`apt install nfdump`).

```bash
export W=$(mktemp -d)
cat > $W/make_netflow.py <<'EOF'
"""NetFlow evidence for the reading tests: python make_netflow.py OUTDIR (needs nfcapd and nfdump)."""
import os
import sys

sys.path[:0] = ["tests", "."]
from evidence import make_nfcapd  # noqa: E402

T = 1_714_564_800                                       # 2024-05-01T12:00:00Z

if __name__ == "__main__":
    os.makedirs(sys.argv[1], exist_ok=True)
    print(make_nfcapd(sys.argv[1], [
        # (src, dst, sport, dport, protocol, packets, bytes, start, end)
        ("10.0.0.5", "10.0.0.9", 50000, 445, 6, 10, 1500, T, T + 10),     # the two halves of
        ("10.0.0.9", "10.0.0.5", 445, 50000, 6, 8, 9000, T, T + 10),      # one TCP connection
        ("10.0.0.5", "10.0.0.53", 53000, 53, 17, 1, 70, T + 50, T + 50),  # a one-way UDP query
        ("10.0.0.9", "10.0.0.20", 445, 51000, 6, 5, 400, T + 120, T + 125),    # reply half first,
        ("10.0.0.20", "10.0.0.9", 51000, 445, 6, 6, 900, T + 120, T + 125),    # same millisecond
    ], T + 600))
EOF
python $W/make_netflow.py $W/nf          # prints the nfcapd file's name
TB_LIVE_DNS=false TB_EXCLUDE_FILE=$W/exclude.json TB_COMPROMISED_FILE=$W/compromised.json TB_SESSIONS_DIR=$W/sessions \
python -m threatbridge --case $W/nf --port 5058
# browse to http://127.0.0.1:5058/
```

### ENV-BIG: 1.25 million flows in a 93 MiB capture

```bash
export W=$(mktemp -d)
python -c "import sys; sys.path[:0] = ['tests']; from evidence import write_bulk_pcap; write_bulk_pcap(sys.argv[1], 1_250_000)" $W/bulk.pcap
ls -l $W/bulk.pcap                       # 97,500,024 bytes
TB_LIVE_DNS=false TB_EXCLUDE_FILE=$W/exclude.json TB_COMPROMISED_FILE=$W/compromised.json TB_SESSIONS_DIR=$W/sessions \
python -m threatbridge --case $W/bulk.pcap --db $W/bulk.db --port 5059
# browse to http://127.0.0.1:5059/ (the page loads once the case is built)
```

### ENV-BUSY: a busy office week (1M flows, a 100k-flow connection)

The same synthetic week the performance test uses: 2,000 workstations, 500 outside hosts, three
servers everyone talks to (10.0.0.1, 10.0.0.53, 10.0.0.80), and 10.1.0.7 → 10.0.0.80 with
100,071 flows.

```bash
export W=$(mktemp -d)
cat > $W/busy.py <<'EOF'
"""A busy week of office traffic (1M flows) served on port 5065. Run from the repository root."""
import sys

sys.path[:0] = ["tests", "."]
from test_perf import busy_week  # noqa: E402
from threatbridge.app import create_app  # noqa: E402
from threatbridge.backends import CaseBackend  # noqa: E402
from threatbridge.config import Config  # noqa: E402

if __name__ == "__main__":
    cfg = Config.from_env()
    cfg.backend = "case"
    create_app(cfg, CaseBackend(cfg, flows=busy_week())).run(port=5065)
EOF
TB_LIVE_DNS=false TB_EXCLUDE_FILE=$W/exclude.json TB_COMPROMISED_FILE=$W/compromised.json TB_SESSIONS_DIR=$W/sessions \
python $W/busy.py
# browse to http://127.0.0.1:5065/ (about 15 s to build; Chrome refuses port 5060)
```

### ENV-MTLS: the container with mutual TLS

This needs Docker, openssl, and sudo for Docker.

```bash
export P12_PASS=test-only                  # export password of the .p12 files
scripts/make-certs.sh ca
scripts/make-certs.sh server localhost 127.0.0.1
scripts/make-certs.sh client alice         # certs/alice.p12: signed by the ThreatBridge CA
CERT_DIR=./certs-foreign scripts/make-certs.sh ca
CERT_DIR=./certs-foreign scripts/make-certs.sh client mallory   # certs-foreign/mallory.p12: another CA
printf 'TB_BACKEND=demo\nTB_SOC_URL=https://so.example\n' > deploy/threatbridge.env
sudo SO_CA="$PWD/certs/ca.crt" deploy/run.sh
# browse to https://localhost:5443/ ; clean up afterwards: sudo docker rm -f threatbridge
```

### ENV-SO: a Security Onion 2.4 deployment

ThreatBridge is deployed on the manager as the README describes (*Deploy on the Security Onion
manager*), with the default `elastic` backend. Both SOC actions from
`securityonion/soc-actions.json` are added to SOC. The analyst's browser trusts `certs/ca.crt`
and holds a client certificate. The sensors have recorded Zeek conn and DNS logs.
[TEST_RANGE_PROMPT.md](TEST_RANGE_PROMPT.md) is a prompt for an agent to build such a range on
Proxmox, with traffic that reproduces the ENV-CASE attack chain.

Variant **ENV-SO-PRO**: also a SOC API client in `deploy/threatbridge.env` (`TB_SOC_CLIENT_ID`,
`TB_SOC_CLIENT_SECRET`). This needs Security Onion Pro 2.4.120 or later, Hydra enabled, and the
permissions `events/read`, `jobs/read` and `jobs/write` (README, *PCAP for a flow*).

## 3. Tests

### UI-01 · The page, its controls and the side panel for Security Onion-style data (GRA-2, GRA-4)

**Environment:** ENV-DEMO. **Starting state:** fresh state; the page has not been opened.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Open `http://127.0.0.1:5055/`. | Toolbar: *Host / IOC IP*, *Anchor time (UTC)* (placeholder `2024-05-01T12:00:00Z (blank = now)`), *Direction* (Inbound), *Window* `24h`, *Range from (UTC)* and *Range to (UTC)* (placeholder `blank = no limit`), *Peers* (Top), *N* `50`, buttons **Map**, **Fit**, **Clear**. Status line empty. | Controls present; window and N defaults come from the server (`TB_WINDOW`, `TB_LIMIT`). | |
| 2 | Look at the side panel. | *Details* with the hint text starting `Left-click a host to expand it…`; *Compromised hosts* with a form (**Mark**); *Saved maps* with `No saved maps yet.`, **Save**, **Save to file**, **Open file**; *Shared exclude list* with **Add**; the legend with the 8 entries listed in section 1. | Side panel features present. | |
| 3 | Check that *Attack paths* and *Paths between two hosts* are **not** shown. | Neither heading appears. | These need the whole graph, so they exist for case files only (D8). | |
| 4 | Check the DevTools Console. | No errors (no Content Security Policy violations). | The page runs under its CSP. | |

### UI-02 · Case summary and post-mortem controls (D1, GRA-1)

**Environment:** ENV-CASE. **Starting state:** fresh state.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Open `http://127.0.0.1:5056/`. | Status: `Case: 151 flows between 23 hosts, 2024-05-01T11:40:00.000Z → 2024-05-01T13:09:50.001Z`. | The whole capture was read into one graph (GRA-1), and its summary is shown. | |
| 2 | Look at the placeholders. | Anchor time: `blank = end of data (inbound) / start (outbound)`; Range from: `blank = start of data`; Range to: `blank = end of data`. | The case backend's default anchor and range. | |
| 3 | Look at the side panel. | *Attack paths* is shown with `Mark at least two hosts as compromised.`; *Paths between two hosts* is shown with its form (**Find paths**). | Analysis features are on for case files. | |

### MAP-01 · Launch from a SOC-style link; the URL keeps the map (EXT-1, INT-S2)

**Environment:** ENV-DEMO. **Starting state:** server running; no tab open on it.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Open `http://127.0.0.1:5055/?ip=10.0.0.5&ts=2024-05-01T12:00:00Z&dir=out` (the form of the SOC action link). | Host `10.0.0.5`, Anchor `2024-05-01T12:00:00Z`, Direction *Outbound*. Without any click the map draws 10.0.0.5 as the IOC host with 12 orange arrows to its peers. Status: `10.0.0.5: showing top 12 of 12 distinct peer(s), 2024-05-01T12:00:00.000Z → 2024-05-02T12:00:00.000Z`. | A SOC action opens the map at the event's IP, time and direction (EXT-1). | |
| 2 | Look at the address bar. | It now carries `ip=10.0.0.5`, `ts=2024-05-01T12:00:00.000Z` (the colons may show as `%3A`), `dir=out`, `window=24h` and `order=top`. | The map's root and settings are kept in the URL (INT-S2). | |
| 3 | Reload the page. | The same map is drawn again with the same status. Anchor now shows `2024-05-01T12:00:00.000Z`, the anchor the map used. | A reload or a shared link reopens the map. | |
| 4 | Open `http://127.0.0.1:5055/?ip=10.0.0.5&ts=2024-05-01T12:00:00Z&dir=in`. | Direction *Inbound*; 5 blue arrows into 10.0.0.5. Status: `10.0.0.5: showing top 5 of 5 distinct peer(s), 2024-04-30T12:00:00.000Z → 2024-05-01T12:00:00.000Z`. | The inbound SOC action looks back from the event. | |

### MAP-02 · Inbound looks back, outbound looks forward, from the end and start of the data (GRA-1, GRA-2, ATK-3)

**Environment:** ENV-CASE. **Starting state:** page open, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Map `10.0.0.9` inbound. | 10.0.0.9 as a large red node. Blue arrows *into* it from 10.0.0.5 (`1 · 445`) and 10.0.0.77 (`1 · 80`). Status: `10.0.0.9: showing top 2 of 2 distinct peer(s), 2024-04-30T13:09:50.001Z → 2024-05-01T13:09:50.001Z`. | Nodes are hosts and edges are connections, drawn initiator → responder (GRA-1, GRA-2). With no anchor, inbound looks back from the end of the data. | |
| 2 | Map `10.0.0.9` outbound. | Orange arrows *from* 10.0.0.9 to 10.0.0.20 (`1 · 3389`) and 10.0.0.53 (`1 · 53`). Status: `10.0.0.9: showing top 2 of 2 distinct peer(s), 2024-05-01T11:40:00.000Z → 2024-05-02T11:40:00.000Z`. | Outbound looks forward from the start of the data; it shows successors (ATK-3). | |
| 3 | Right-click 10.0.0.20. | Details: Host `10.0.0.20`, Anchor `2024-05-01T12:20:00.000Z`, IOC root `no`, Compromised `no`, Hops from IOC `1`, Inbound expanded `no`, Outbound expanded `no`, Degree `1`. A menu opens; press Escape. | Host details. A peer's anchor is when it was reached. | |
| 4 | Left-click the arrow 10.0.0.9 → 10.0.0.20. | Details: Source `10.0.0.9`, Destination `10.0.0.20`, Direction `outbound (future)`, Connections `1`, Top dst ports `3389`, First seen and Last seen `2024-05-01T12:20:00.000Z`. | Connection details (GRA-4). | |

### MAP-03 · Outbound time chaining: each hop starts when the host was reached (GRA-3, ATK-3)

**Environment:** ENV-CASE. **Starting state:** page open, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Map `203.0.113.66` outbound. | One orange arrow to 10.0.0.5 (`1 · 443`). Status ends `2024-05-01T11:40:00.000Z → 2024-05-02T11:40:00.000Z`. | | |
| 2 | Left-click 10.0.0.5. | Arrows to 10.0.0.20 (`1 · 5985`) and 10.0.0.9 (`1 · 445`). Status: `10.0.0.5: showing top 2 of 2 distinct peer(s), 2024-05-01T12:00:00.000Z → 2024-05-02T12:00:00.000Z`. | The hop starts at 12:00, when 10.0.0.5 was first contacted. Left-click expands in the selected direction (GRA-4). | |
| 3 | Left-click 10.0.0.9. | Only one new arrow: 10.0.0.9 → 10.0.0.20 (`1 · 3389`). **No** arrow to 10.0.0.53. Status: `10.0.0.9: showing top 1 of 1 distinct peer(s), 2024-05-01T12:10:00.000Z → 2024-05-02T12:10:00.000Z`. | Time chaining: 10.0.0.9's 11:40 DNS query came before it was reached at 12:10, so it is left out. MAP-02 step 2 showed it with no chaining (GRA-3). | |
| 4 | Left-click 10.0.0.20. | Nothing is added. Status: `10.0.0.20: showing top 0 of 0 distinct peer(s), 2024-05-01T12:15:00.000Z → 2024-05-02T12:15:00.000Z`. | 10.0.0.20's SSH to 10.0.0.30 at 11:50 came before 12:15, when it was first reached (over the 5985 shortcut), so it is not shown. | |
| 5 | Right-click 10.0.0.20; press Escape. | Details: Anchor `2024-05-01T12:15:00.000Z`, Hops from IOC `2`, Outbound expanded `yes`. Expanded hosts have a light border. | Each host keeps the anchor of the hop that reached it. | |

### MAP-04 · Inbound time chaining (GRA-3, ATK-3)

**Environment:** ENV-CASE. **Starting state:** page open, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Map `10.0.0.20` inbound. | Blue arrows from 10.0.0.5 (`1 · 5985`) and 10.0.0.9 (`1 · 3389`). | Predecessors (ATK-3). | |
| 2 | Left-click 10.0.0.9. | One new arrow, from 10.0.0.5 (`1 · 445`). **No** arrow from 10.0.0.77. Status: `10.0.0.9: showing top 1 of 1 distinct peer(s), 2024-04-30T12:20:00.000Z → 2024-05-01T12:20:00.000Z`. | The hop ends at 12:20, when 10.0.0.9 last reached 10.0.0.20. 10.0.0.77's connection at 12:30 came later, so it is left out (GRA-3). | |
| 3 | Left-click 10.0.0.5. | One new arrow, from 203.0.113.66 (`1 · 443`). Status: `10.0.0.5: showing top 1 of 1 distinct peer(s), 2024-04-30T12:15:00.000Z → 2024-05-01T12:15:00.000Z`. | Chaining back to the entry point. | |

### MAP-05 · Both directions on one map, from the host menu (ATK-3, GRA-4)

**Environment:** ENV-CASE. **Starting state:** page open, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Anchor `2024-05-01T12:10:00Z`; map `10.0.0.5` inbound. | A blue arrow from 203.0.113.66 (`1 · 443`). Status: `10.0.0.5: showing top 1 of 1 distinct peer(s), 2024-04-30T12:10:00.000Z → 2024-05-01T12:10:00.000Z`. | | |
| 2 | Right-click 10.0.0.5. | A menu titled `10.0.0.5 @ 2024-05-01T12:10:00.000Z`, with these items in order: `Expand inbound: who connected to it (past)`, `Expand outbound: who it connected to (future)`, a separator, `Mark compromised at 2024-05-01T12:10:00.000Z`, `Mark compromised (time unknown)`, `Find paths from this host…`, `Find paths to this host…`, `Remove from map`, `Add to shared exclude list`. There is **no** `Open host in SOC dashboard`. | The host menu for case files, without SOC pivots. | |
| 3 | Choose `Expand outbound: who it connected to (future)`. | Orange arrows to 10.0.0.9 (`1 · 445`) and 10.0.0.20 (`1 · 5985`). Status: `10.0.0.5: showing top 2 of 2 distinct peer(s), 2024-05-01T12:10:00.000Z → 2024-05-02T12:10:00.000Z`. 10.0.0.5 now has a thicker white border. | Expanding the other way from the same anchor: predecessors and successors together (ATK-3). | |
| 4 | Right-click 10.0.0.5 again, then click the empty map background. | Details: Inbound expanded `yes`, Outbound expanded `yes`. The menu closes. | Expansion state per direction. The menu closes on a click elsewhere. | |

### MAP-06 · Window per hop and anchor time formats (GRA-S2)

**Environment:** ENV-CASE. **Starting state:** page open, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Anchor `2024-05-01T12:35:00Z`, Window `30m`; map `10.0.0.9` inbound. | Arrows from 10.0.0.5 and 10.0.0.77. Status: `10.0.0.9: showing top 2 of 2 distinct peer(s), 2024-05-01T12:05:00.000Z → 2024-05-01T12:35:00.000Z`. | The window sets how far a hop looks. | |
| 2 | Window `10m`; Map. | Only 10.0.0.77. Status ends `2024-05-01T12:25:00.000Z → 2024-05-01T12:35:00.000Z`. | A narrower window shows fewer peers. | |
| 3 | Anchor `2024-05-01T14:35:00+02:00`; Map. | The same as step 2. | A time with an offset is converted to UTC. | |
| 4 | Anchor `1714566900`; Map. Then right-click 10.0.0.9 and press Escape. | The same as step 2. Details: Anchor `2024-05-01T12:35:00.000Z`. | Epoch seconds are accepted. | |
| 5 | Window `banana`; Map. | Red: `invalid window 'banana'; use e.g. 30m, 24h, 7d`. | Invalid input is refused with a reason. | |
| 6 | Window `31d`; Map. | Red: `window exceeds maximum of 30d`. | The window's limit (`TB_MAX_WINDOW`). | |
| 7 | Window `24h`, Anchor `soon`; Map. | Red: `invalid timestamp: 'soon'`. | | |

### MAP-07 · Top N and Bottom N (rarest) peers (GRA-4, peer selection)

**Environment:** ENV-DEMO. **Starting state:** page open, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Anchor `2024-05-01T12:00:00Z`; map `10.0.0.5` outbound. | 12 peers. Their edge labels start with these counts: 469, 460, 163, 3, 3, 2, 2, 2, 2, 2, 1, 1. Higher counts draw thicker arrows. | All peers within N = 50. | |
| 2 | N `3`; Map. | Only 10.1.6.3 (469), 10.1.7.8 (460) and 10.2.2.21 (163). Status: `10.0.0.5: showing top 3 of 12 distinct peer(s), …`. | Top N keeps the busiest peers and still counts all of them. | |
| 3 | Peers *Bottom (rarest)*; Map. | Only 10.2.1.9 (1), 10.3.3.10 (1) and 10.0.5.7 (2). Status: `10.0.0.5: showing rarest 3 of 12 distinct peer(s), …`. The address bar carries `order=bottom`. | Bottom N picks the rarest peers. | |
| 4 | Reload the page. | Peers is still *Bottom (rarest)*, and the map is redrawn. N is back to `50` (N is not kept in the URL), so the status reads `10.0.0.5: showing rarest 12 of 12 distinct peer(s), …`. | The peer order is kept in the URL. | |
| 5 | N `abc`; Map. | Red: `limit must be an integer`. | | |

### MAP-08 · Input errors are reported (usability)

**Environment:** ENV-DEMO. **Starting state:** page open, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Leave Host blank; Map. | Red: `Enter an IP address`. | | |
| 2 | Host `nope`; Map. | Red: `invalid IP address: 'nope'`. The map is empty. | Invalid IPs are refused. | |
| 3 | Host `2001:DB8::1`; Map. | The IOC host is labelled `2001:db8::1`, with peers. | IPv6 is accepted, in normalised form. | |
| 4 | Host `10.0.0.5`, Range from `2024-05-02T00:00:00Z`, Range to `2024-05-01T00:00:00Z`; Map. | Red: `range_to is before range_from`. | A reversed range is refused. | |

### MAP-09 · Remove from map, Fit and Clear (INT-3, GRA-4)

**Environment:** ENV-CASE. **Starting state:** page open; `10.0.0.9` mapped inbound (as MAP-02 step 1).

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Right-click 10.0.0.77 → `Remove from map`. | 10.0.0.77 and its arrow disappear. | Pruning the map (INT-3). | |
| 2 | Right-click 10.0.0.9 (the IOC host) → `Remove from map`. | Nothing changes. | The IOC host cannot be removed. | |
| 3 | Zoom out with the mouse wheel and drag the map off to one side; click **Fit**. | The whole graph is centred in view again. | Fit. | |
| 4 | Click **Clear**. | The map is empty and the status line is blank. | Clear. | |

### FLW-01 · A connection's flows in time order, with their metadata (GRA-3, GRA-S3, ING-4)

**Environment:** ENV-CASE. **Starting state:** page open; `10.0.0.9` mapped inbound.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Left-click the arrow 10.0.0.5 → 10.0.0.9. | Details: Source `10.0.0.5`, Destination `10.0.0.9`, Direction `inbound (past)`, Connections `1`, Top dst ports `445`, First/Last seen `2024-05-01T12:10:00.000Z`. Below that, *Flows, oldest first*: `1–1 of 1`, with **First**, **Older**, **Newer** and **Last** all disabled. Flow 1: `2024-05-01T12:10:00.000Z`, with `tcp 50001 → 445 · 0.001 s · 2 pkts · 80 B` below it. There are no PCAP links. | Per-flow start, protocol, ports, duration, packets and bytes (ING-4, GRA-S3). PCAP links are only for Security Onion (D12). | |
| 2 | Right-click the same arrow. | The details show the connection; **no** menu opens. | SOC pivots are hidden for case files. | |

### FLW-02 · Paging through 120 flows, 50 at a time, oldest first (GRA-3)

**Environment:** ENV-CASE. **Starting state:** page open, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Map `10.0.1.2` inbound. | One arrow from 10.0.1.1, `120 · 8443`. | | |
| 2 | Left-click it. | `1–50 of 120`. Rows are numbered 1 to 50. Row 1 is `2024-05-01T12:50:00.000Z` (`tcp 50006 → 8443 · 0.001 s · 2 pkts · 80 B`), and each row is 10 s after the one before. **First** and **Older** are disabled; **Newer** and **Last** are enabled. | Flows oldest first, numbered, 50 per page (D10). | |
| 3 | Click **Newer**. | `51–100 of 120`; row 51 is `2024-05-01T12:58:20.000Z`. All four buttons are enabled. | | |
| 4 | Click **Last**. | `101–120 of 120`, rows 101 to 120, from `2024-05-01T13:06:40.000Z` to `2024-05-01T13:09:50.000Z`. **Newer** and **Last** are disabled. | | |
| 5 | Click **Older**, then **First**. | `51–100 of 120`, then `1–50 of 120`. | Paging both ways. | |

### RNG-01 · The time range limits expansions, counts and flow lists, and is kept in the URL (GRA-S2, D10)

**Environment:** ENV-CASE. **Starting state:** page open, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Range from `2024-05-01T13:00:00Z`; map `10.0.1.2` inbound. | The arrow from 10.0.1.1 is `60 · 8443`, not `120`. Status: `10.0.1.2: showing top 1 of 1 distinct peer(s), 2024-05-01T13:00:00.000Z → 2024-05-01T13:09:50.001Z`. | Only flows that started inside the range count (GRA-S2). | |
| 2 | Left-click the arrow. | `1–50 of 60`; row 1 is `2024-05-01T13:00:00.000Z`. | The range limits the flow list. | |
| 3 | Look at the address bar, then reload. | The URL carries `range_from=2024-05-01T13:00:00Z` (colons may show as `%3A`). After the reload, Range from is filled in, Anchor shows `2024-05-01T13:09:50.001Z`, and the arrow is `60 · 8443` again. | The range is kept in the URL. | |
| 4 | Range from `2024-05-01T14:00:00Z`; left-click the same arrow again (without Map). | The flow list shows `none in the time range`. | The range applies at once to every query. | |

### RNG-02 · The default anchor follows the time range; an empty window says so (D10)

**Environment:** ENV-CASE. **Starting state:** page open, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Range to `2024-05-01T12:25:00Z`; map `10.0.0.9` inbound. | Only 10.0.0.5, not 10.0.0.77. Status: `10.0.0.9: showing top 1 of 1 distinct peer(s), 2024-04-30T12:25:00.000Z → 2024-05-01T12:25:00.000Z`. | With no anchor, inbound looks back from the end of the range. | |
| 2 | Clear Range to. Range from `2024-05-01T12:05:00Z`; map `10.0.0.5` outbound. | 10.0.0.20 and 10.0.0.9. Status ends `2024-05-01T12:05:00.000Z → 2024-05-02T12:05:00.000Z`. | Outbound looks forward from the start of the range. | |
| 3 | Range from `2024-05-01T12:00:00Z`, Anchor `2024-05-01T11:00:00Z`; map `10.0.0.9` inbound. | No peers. Status: `10.0.0.9: showing top 0 of 0 distinct peer(s) — the window is outside the time range`. | A window outside the range is reported, not silently empty. | |

### SOC-01 · SOC Dashboards pivots up to the IOC time, the time range in pivots, and copying the query (D3, EXT-1)

**Environment:** ENV-DEMO. **Starting state:** page open, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Anchor `2024-05-01T12:00:00Z`; map `10.0.0.5` inbound. Right-click the arrow 10.1.0.26 → 10.0.0.5. | The connection's details. A menu titled `10.1.0.26 ↔ 10.0.0.5`, with `Filter SOC Dashboards: all conversations up to IOC time` and `Copy SOC query`. | The connection menu (D3). | |
| 2 | Choose `Filter SOC Dashboards: all conversations up to IOC time`. | A new tab opens on `https://so.example/#/dashboards?q=…`; the browser says the site can't be reached but keeps that address in the address bar. The status is `Opened SOC filter: ` followed by query **Q1** below. The URL-decoded `q` is the same query. | The pivot covers both directions and ends at the IOC time (EXT-1). | |
| 3 | Close that tab. Left-click 10.1.0.26 (it expands), then right-click any arrow into 10.1.0.26 → `Filter SOC Dashboards: …`. | The query names that pair, and still ends `TO "2024-05-01T12:00:00.000Z"]`. | Pivots stop at the IOC (root) time, not at the hop's own time. | |
| 4 | Range from `2024-04-30T00:00:00Z`. Right-click the arrow 10.1.0.26 → 10.0.0.5 → `Copy SOC query`. Paste into the Host field, read it, then clear the field. | Status: `SOC query copied to clipboard`. The pasted text is query **Q2**. | The time range bounds pivots; copy to clipboard. | |
| 5 | Clear Range from. Right-click 10.0.0.5 → `Open host in SOC dashboard`. | A new tab opens; the decoded `q` is query **Q3**. | Host pivot. | |
| 6 | Range from `2024-04-30T00:00:00Z`; repeat step 5. | The decoded `q` is query **Q4**. | The time range bounds the host pivot too. | |
| 7 | *(Optional)* Restart ENV-DEMO with `TB_PIVOT_TIME_CLAUSE=false` added. Repeat steps 1–2. | The query has no `@timestamp` clause. | The time clause can be switched off. | |

```text
Q1  ((source.ip:"10.1.0.26" AND destination.ip:"10.0.0.5") OR (source.ip:"10.0.0.5" AND destination.ip:"10.1.0.26")) AND @timestamp:[* TO "2024-05-01T12:00:00.000Z"] | groupby source.ip destination.ip destination.port
Q2  ((source.ip:"10.1.0.26" AND destination.ip:"10.0.0.5") OR (source.ip:"10.0.0.5" AND destination.ip:"10.1.0.26")) AND @timestamp:["2024-04-30T00:00:00.000Z" TO "2024-05-01T12:00:00.000Z"] | groupby source.ip destination.ip destination.port
Q3  (source.ip:"10.0.0.5" OR destination.ip:"10.0.0.5") | groupby source.ip destination.ip destination.port
Q4  (source.ip:"10.0.0.5" OR destination.ip:"10.0.0.5") AND @timestamp:["2024-04-30T00:00:00.000Z" TO *] | groupby source.ip destination.ip destination.port
```

### SOC-02 · *PCAP in SOC* on every flow (ING-S2, D12)

**Environment:** ENV-DEMO (no SOC API client). **Starting state:** page open, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Anchor `2024-05-01T12:00:00Z`; map `10.0.0.5` outbound. Left-click the arrow to 10.1.6.3. | `1–50 of 469`. Every row has a **PCAP in SOC** link, and there is **no** **Download PCAP** button. There is no threat line (demo). | Each flow links to SOC's own PCAP job. Download needs an API client. | |
| 2 | Hover over row 1's **PCAP in SOC**. | Its target is `https://so.example/joblookup?esid=demod668d4e6ff6b69c4&time=2024-05-02T04%3A16%3A47.188Z`; the time is row 1's start. | The link names the flow's record and start time (SOC's `/joblookup` action). | |
| 3 | Click it. | A new tab opens on that address. | | |

### EXC-01 · Excluding an IP: hidden from every analyst, kept across restarts (FIL-1, FIL-S2)

**Environment:** ENV-CASE. **Starting state:** fresh state; `10.0.0.9` mapped inbound.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Right-click 10.0.0.77 → `Add to shared exclude list`. | 10.0.0.77 leaves the map. Status: `Excluded 10.0.0.77 for everyone; re-expand hosts to apply CIDRs`. The exclude list shows `10.0.0.77` with **Remove**. | Excluding a host (FIL-1). | |
| 2 | Map again. | Only 10.0.0.5. Status: `10.0.0.9: showing top 1 of 1 distinct peer(s), …`. | Excluded hosts are left out of expansions. | |
| 3 | Open `http://127.0.0.1:5056/` in a private window (a second analyst). | Its exclude list shows `10.0.0.77`. | The list is shared. | |
| 4 | Restart the server with the same `$W`; reload the first window. | The list still shows `10.0.0.77`. | The list persists (FIL-S2). | |
| 5 | Right-click 10.0.0.9 → `Add to shared exclude list`. | 10.0.0.9 stays on the map (it is the IOC host); the list shows it. Then click its **Remove**. | The IOC host is never removed from the map. | |
| 6 | Click **Remove** next to `10.0.0.77`; Map. | Status: `Removed 10.0.0.77 from exclude list`, then the map shows both peers again. | Removing an entry. | |

### EXC-02 · CIDR entries: normalised, applied on the next expansion (FIL-S1, FIL-1)

**Environment:** ENV-CASE. **Starting state:** page open, empty exclude list, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Map `10.0.2.1` outbound. | 12 orange arrows to 10.0.2.10 … 10.0.2.21. Status: `10.0.2.1: showing top 12 of 12 distinct peer(s), 2024-05-01T11:40:00.000Z → 2024-05-02T11:40:00.000Z`. | | |
| 2 | In the side panel's exclude field, enter `10.0.2.5/24`; **Add**. | The list shows `10.0.2.0/24`. Status: `Excluded 10.0.2.0/24 for everyone; re-expand hosts to apply CIDRs`. The 12 peers are still on the map. | CIDR notation, normalised to its network (FIL-S1). | |
| 3 | Map. | No peers: `showing top 0 of 0 distinct peer(s)`. The IOC host 10.0.2.1 stays. | The CIDR applies from the next expansion. | |
| 4 | Add `2001:db8::/32`. | Listed as `2001:db8::/32`. | IPv6 CIDRs. | |
| 5 | Add `10.0.0.0/33`. | Red: `invalid IP, CIDR or domain name: '10.0.0.0/33'`. | Validation. | |
| 6 | Remove both entries; Map. | The 12 peers are back. | | |

### EXC-03 · Domain names from the capture's DNS answers, and wildcards (FIL-2, D9)

**Environment:** ENV-CASE (live DNS off). **Starting state:** page open, empty exclude list; `10.0.0.9` mapped inbound (10.0.0.77 is shown).

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Add `Updates.Example.COM`. | Listed as `updates.example.com`, with `capture: 10.0.0.77` below it. 10.0.0.77 leaves the map. Status: `Excluded updates.example.com (1 address(es)) for everyone`. | A domain stands for the addresses in the capture's DNS answers. Names are case-insensitive (FIL-2). | |
| 2 | Add `*.example.com`. | Listed with `capture: 10.0.0.77`. Status: `Excluded *.example.com (1 address(es)) for everyone`. | Wildcards match capture answers. | |
| 3 | Add `nothing.example.org`. | Listed with `no addresses found`. Status: `Excluded nothing.example.org (0 address(es)) for everyone`. | A name that resolves to nothing says so. | |
| 4 | Add `*.com`. | Red: `a wildcard needs at least two labels, e.g. *.example.com`. | Overly broad wildcards are refused. | |
| 5 | Add `nope!`. | Red: `invalid IP, CIDR or domain name: 'nope!'`. | | |
| 6 | Remove all entries; Map. | 10.0.0.77 is back. | | |

### EXC-04 · Live DNS lookups, alone and combined with capture answers (FIL-2, D9)

**Environment:** ENV-DEMO (live DNS on), then ENV-CASE without `TB_LIVE_DNS=false`. **Starting state:** empty exclude list.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | ENV-DEMO: add `localhost`. | Listed with `DNS: 127.0.0.1` (some systems also list `::1`). | Live resolution (FIL-2). | |
| 2 | Add `does-not-exist.invalid`. | Listed with `DNS lookup failed: …` (the resolver's reason, e.g. `Name or service not known`). | Lookup errors are shown, not hidden. | |
| 3 | Remove both. Restart ENV-CASE without `TB_LIVE_DNS=false` (fresh `$W`); add `updates.example.com`. | Listed with `capture: 10.0.0.77`, then ` · ` and the live lookup's result: `DNS: …` if the name resolves where you are, otherwise `DNS lookup failed: …` or `DNS lookup timed out`. | Capture answers first, then live DNS, combined (D9). | |

### EXC-05 · Excluded hosts are never crossed by threat lines or attack paths (FIL-3)

**Environment:** ENV-CASE. **Starting state:** fresh state; `10.0.0.20` mapped inbound.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Side panel *Compromised hosts*: mark `203.0.113.66` (time blank), then `10.0.0.20` at `2024-05-01T12:20:00Z`. | *Attack paths*: `203.0.113.66 → 10.0.0.20: 2 path(s)`; red arrows on the map. | Baseline. | |
| 2 | Add `10.0.0.5` to the exclude list. | 10.0.0.5 leaves the map. *Attack paths*: `No time-consistent path between the marked hosts.`; no red arrows. | Attack paths don't cross excluded hosts (FIL-3). | |
| 3 | Left-click the arrow 10.0.0.9 → 10.0.0.20. | Status starts `Threat line through 10.0.0.9 → 10.0.0.20: 0 earlier host(s) (violet), 0 later host(s) (teal)`. | Threat lines don't cross excluded hosts. | |
| 4 | Remove `10.0.0.5`; Map; left-click 10.0.0.9 → 10.0.0.20. | *Attack paths* is back to `2 path(s)`. Status starts `Threat line through 10.0.0.9 → 10.0.0.20: 2 earlier host(s) (violet), 0 later host(s) (teal)`. | Removing the exclusion restores both. | |

### THR-01 · Clicking a connection highlights its threat line: earlier hosts violet, later teal (INT-1, INT-2, D3, D8)

**Environment:** ENV-CASE. **Starting state:** page open, no hosts excluded or marked; `10.0.0.9` mapped inbound.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Left-click the arrow 10.0.0.5 → 10.0.0.9. | 203.0.113.66 and 10.0.0.20 are added. 203.0.113.66 → 10.0.0.5 and 203.0.113.66's border are violet. 10.0.0.9 → 10.0.0.20 and 10.0.0.20's border are teal. The clicked arrow is white. 10.0.0.77 and its arrow are faded. The status is S1 below. The flow list is shown too. | Left-clicking an edge shows its whole threat line (INT-1), with earlier and later communication (INT-2). Hosts not yet on the map are added. | |
| 2 | Click the empty background. | All colours return to normal. | Clearing the highlight. | |
| 3 | Left-click 203.0.113.66 → 10.0.0.5. | Status starts `Threat line through 203.0.113.66 → 10.0.0.5: 0 earlier host(s) (violet), 2 later host(s) (teal)`. 10.0.0.9 and 10.0.0.20 are teal. | Later hosts follow the chain forward in time. | |
| 4 | Left-click 10.0.0.9 → 10.0.0.20. | Status starts `…: 2 earlier host(s) (violet), 0 later host(s) (teal)`. 10.0.0.5 and 203.0.113.66 are violet. | Earlier hosts follow it back. | |

S1: `Threat line through 10.0.0.5 → 10.0.0.9: 1 earlier host(s) (violet), 1 later host(s) (teal); ≤ 6 hops, ≤ 24h between hops. Click the background to clear.`

### THR-02 · Threat lines follow time order, the Window and the time range (D8, INT-2, GRA-S2)

**Environment:** ENV-CASE. **Starting state:** page open, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Map `10.0.0.20` outbound. Left-click the arrow 10.0.0.20 → 10.0.0.30 (`1 · 22`). | Status starts `Threat line through 10.0.0.20 → 10.0.0.30: 0 earlier host(s) (violet), 0 later host(s) (teal)`. | The 11:50 SSH came before the attacker reached 10.0.0.20, so nothing links to it (D8). | |
| 2 | Map `10.0.0.9` inbound; Window `5m`; left-click 10.0.0.5 → 10.0.0.9. | Status: `Threat line through 10.0.0.5 → 10.0.0.9: 0 earlier host(s) (violet), 0 later host(s) (teal); ≤ 6 hops, ≤ 5m between hops. Click the background to clear.` | Hops must follow within the Window (10 min apart here). | |
| 3 | Window `24h`, Range from `2024-05-01T12:05:00Z`; left-click 10.0.0.5 → 10.0.0.9. | Status starts `…: 0 earlier host(s) (violet), 1 later host(s) (teal)`. | The 12:00 hop is outside the range, so it is ignored. | |

### CMP-01 · Marking and unmarking compromised hosts: menu, side panel, shared list (ATK-4)

**Environment:** ENV-CASE. **Starting state:** fresh state; `203.0.113.66` mapped outbound, and 10.0.0.5 left-clicked (expanded).

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Right-click 203.0.113.66 → `Mark compromised (time unknown)`. | 203.0.113.66 turns dark red with a light red border. The list shows `203.0.113.66 @ time unknown`. Status: `0 attack path(s) between 1 compromised host(s)`. | Marking from the host menu (ATK-4). | |
| 2 | Right-click 203.0.113.66. | Details: Compromised `yes, time unknown`. The menu offers `Unmark compromised` instead of the two Mark items. Press Escape. | | |
| 3 | Right-click 10.0.0.5 → `Mark compromised at 2024-05-01T12:00:00.000Z`. | The list adds `10.0.0.5 @ 2024-05-01T12:00:00.000Z`. | Marking at the host's anchor time. | |
| 4 | Side panel: IP `10.0.0.20`, time `2024-05-01T12:20:00Z`; **Mark**. | The fields clear, and the list reads in this order: `203.0.113.66 @ time unknown`, `10.0.0.5 @ 2024-05-01T12:00:00.000Z`, `10.0.0.20 @ 2024-05-01T12:20:00.000Z`. | Marking at a time you enter. The list is sorted by time, unknown first. | |
| 5 | Mark `10.0.0.20` again at `2024-05-01T12:21:00Z`. | Still one `10.0.0.20` line, now `@ 2024-05-01T12:21:00.000Z`. | Marking again replaces the entry. | |
| 6 | Mark IP `nope`; then IP `10.0.0.30` with time `soon`. | Red: `invalid IP address: 'nope'`, then red `invalid timestamp: 'soon'`. Neither is listed. | Validation. | |
| 7 | Open the page in a private window. | The same three hosts are listed. | The list is shared. | |
| 8 | Restart the server with the same `$W`; reload. | The same three hosts. | The list persists (`compromised.json`). | |
| 9 | Click **Remove** next to 10.0.0.5. Right-click 203.0.113.66 → `Unmark compromised`. | Both leave the list, and 203.0.113.66 turns back to the IOC host's red. Status: `0 attack path(s) between 1 compromised host(s)`. | Unmarking from the side panel and from the menu. | |
| 10 | *(ENV-DEMO)* Map any host, right-click a peer → `Mark compromised (time unknown)`. | Status: `Marked <peer> compromised (time unknown)`; the peer is listed. | Marking works with Security Onion-style data too (no attack paths there). | |

### CMP-02 · Attack paths are recomputed and redrawn on every change, in time order (ATK-1, INT-3, INT-4, D8)

**Environment:** ENV-CASE. **Starting state:** fresh state; `10.0.0.9` mapped inbound.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Mark `203.0.113.66` (time blank) and `10.0.0.20` at `2024-05-01T12:20:00Z`. | As soon as the second is marked: *Attack paths* shows `203.0.113.66 → 10.0.0.20: 2 path(s)`, then `203.0.113.66 → 10.0.0.5 → 10.0.0.20` (`2024-05-01T12:00:00.000Z → 2024-05-01T12:15:00.000Z`) and `203.0.113.66 → 10.0.0.5 → 10.0.0.9 → 10.0.0.20` (`2024-05-01T12:00:00.000Z → 2024-05-01T12:20:00.000Z`). Missing hosts are added, and the arrows of both paths are red. Status: `2 attack path(s) between 2 compromised host(s)`. | Every path between compromised hosts, shortest first (ATK-1), drawn as soon as a host is marked (INT-4). | |
| 2 | Click the second path in the list. | Everything except that path is faded. Status: `Attack path 203.0.113.66 → 10.0.0.20, 3 hop(s). Click the background to clear.` Click the background. | Focusing on one path. | |
| 3 | Mark `10.0.0.20` at `2024-05-01T12:17:00Z`. | `1 path(s)`: only `203.0.113.66 → 10.0.0.5 → 10.0.0.20`. The arrow 10.0.0.9 → 10.0.0.20 is no longer red. Status: `1 attack path(s) between 2 compromised host(s)`. | A path must reach the host by its compromise time (D8). | |
| 4 | Mark `10.0.0.20` at `2024-05-01T12:12:00Z`. | `No time-consistent path between the marked hosts.`; no red arrows. Status: `0 attack path(s) between 2 compromised host(s)`. | | |
| 5 | Mark `10.0.0.20` at `2024-05-01T12:20:00Z`; Window `10m`; Map. | `1 path(s)`: `203.0.113.66 → 10.0.0.5 → 10.0.0.9 → 10.0.0.20` (hops 10 min apart). The 15-min shortcut is gone. | Paths follow the Window. | |
| 6 | Window `9m`; Map. | `No time-consistent path between the marked hosts.` | | |
| 7 | Window `24h`, Range from `2024-05-01T12:05:00Z`; Map. | `No time-consistent path between the marked hosts.` | The time range applies to paths. | |
| 8 | Clear Range from; Map. In the list, click **Remove** next to 203.0.113.66. | `Mark at least two hosts as compromised.`; no red arrows. Status: `0 attack path(s) between 1 compromised host(s)`. | Unmarking recomputes too (INT-3, INT-4). | |
| 9 | Mark `203.0.113.66` again (time blank), and mark `10.0.0.20` with the time blank. | Only the pair `203.0.113.66 → 10.0.0.20` is listed, with no `10.0.0.20 → 203.0.113.66`. | Paths are directional: each hop is opened by the host the attacker is on. | |

### CMP-03 · The first 10 paths per pair, *Show all*, and narrowing (D11, ATK-1)

**Environment:** ENV-CASE (`TB_MAX_PATHS=11`). **Starting state:** fresh state; page open.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Mark `10.0.2.1` (time blank) and `10.0.2.2` at `2024-05-01T13:00:00Z`. | `10.0.2.1 → 10.0.2.2: first 10 paths` with a **Show all** button, then 10 two-hop paths, first `10.0.2.1 → 10.0.2.10 → 10.0.2.2` (`2024-05-01T12:01:40.000Z → 2024-05-01T12:03:20.000Z`). Status: `10+ attack path(s) between 2 compromised host(s)`. | At most 10 per pair, saying there are more. | |
| 2 | Click **Show all**. | *Paths between two hosts* is filled in: from `10.0.2.1` (IOC time blank), to `10.0.2.2` (IOC time `2024-05-01T13:00:00.000Z`). The list shows 11 paths, with the summary `First 11 paths from 10.0.2.1 to 10.0.2.2, shortest first. There are more: narrow them with the Window, the time range or the exclude list.` The status is amber: that summary plus ` At most 6 hops, 24h between hops. Click the background to clear.` The arrows are pink. | *Show all* opens every path, up to `TB_MAX_PATHS`, and warns when there are more (D11). | |
| 3 | Add `10.0.2.10` to the exclude list; click **Find paths**. | Summary `11 path(s) from 10.0.2.1 to 10.0.2.2.`, not amber. *Attack paths* still says `first 10 paths`. | Narrowing with the exclude list. | |
| 4 | Add `10.0.2.11` to the exclude list. | *Attack paths*: `10.0.2.1 → 10.0.2.2: 10 path(s)`, with no **Show all**. | | |

### PTH-01 · Every path between two hosts: side panel, host menu, optional IOC times (D11, ATK-1)

**Environment:** ENV-CASE. **Starting state:** fresh state; `10.0.0.5` mapped inbound at Anchor `2024-05-01T12:10:00Z`, then expanded outbound from the host menu (as MAP-05).

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | *Paths between two hosts*: from `203.0.113.66`, to `10.0.0.20`; **Find paths**. | Summary `2 path(s) from 203.0.113.66 to 10.0.0.20.`, and the same two paths as CMP-02 step 1, with pink arrows and everything else faded. Status: `2 path(s) from 203.0.113.66 to 10.0.0.20. At most 6 hops, 24h between hops. Click the background to clear.` | Paths between any two hosts, not only compromised ones (D11). | |
| 2 | From's IOC time `2024-05-01T12:05:00Z`; **Find paths**. | `0 path(s) from 203.0.113.66 to 10.0.0.20.`, with `No time-consistent path.` in the list. | The first hop must leave the first host after its IOC time. | |
| 3 | Clear it. To's IOC time `2024-05-01T12:17:00Z`; **Find paths**. | `1 path(s) …`: `203.0.113.66 → 10.0.0.5 → 10.0.0.20`. | The path must reach the second host by its IOC time. | |
| 4 | Clear it. Swap the hosts: from `10.0.0.20`, to `203.0.113.66`. | `0 path(s) from 10.0.0.20 to 203.0.113.66.` | Direction matters. | |
| 5 | Clear the To host; **Find paths**. | Red: `Enter both hosts to find the paths between them`. | | |
| 6 | Clear both forms' fields. Right-click 203.0.113.66 → `Find paths from this host…`. | From is `203.0.113.66`; the cursor is in To. Status: `Now enter the host to find paths to (side panel)`. | Setting one end from the host menu. | |
| 7 | Right-click 10.0.0.9 → `Find paths to this host…`. | The search runs by itself: `1 path(s) from 203.0.113.66 to 10.0.0.9.` with `203.0.113.66 → 10.0.0.5 → 10.0.0.9`. | Both ends from the map. | |
| 8 | Click that path in the list. | Status: `Path 203.0.113.66 → 10.0.0.9, 2 hop(s). Click the background to clear.` | | |
| 9 | Mark `10.0.0.9` compromised at `2024-05-01T12:10:00Z`. Clear the route fields; right-click 10.0.0.9 → `Find paths to this host…`. | To's IOC time is filled with `2024-05-01T12:10:00.000Z`. Status: `Now enter the host to find paths from (side panel)`. | A compromised host's time is used as its IOC time. | |

### PTH-02 · The hop limit (D8)

**Environment:** ENV-CASE restarted with `TB_THREAT_HOPS=2` added (fresh `$W`). **Starting state:** page open.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Paths from `203.0.113.66` to `10.0.0.20`. | `1 path(s) …`: only `203.0.113.66 → 10.0.0.5 → 10.0.0.20`. Status includes `At most 2 hops`. | Searches stop at `TB_THREAT_HOPS` hops. | |
| 2 | Map `10.0.0.9` inbound; left-click 10.0.0.5 → 10.0.0.9. | The status includes `≤ 2 hops`. | | |

### SAV-01 · Saving a map for everyone and reopening it exactly (INT-S2)

**Environment:** ENV-CASE. **Starting state:** fresh state; page open.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Map `10.0.0.9` inbound; left-click 10.0.0.5 → 10.0.0.9 (threat line). Drag 10.0.0.77 to the far left. Zoom in one notch. Set Peers *Bottom (rarest)* and N `7`. In *Paths between two hosts*, type from `203.0.113.66`, to `10.0.0.20` (don't search). | A map of 5 hosts with the threat-line colours. | Building a state to save. | |
| 2 | *Saved maps*: name `incident 42`; **Save**. | Status: `Saved the map "incident 42" for everyone`. The list shows `incident 42`, `saved 2026-…Z` (now, UTC) and **Delete**. | Saving under a name. | |
| 3 | Click **Clear**. Set Peers *Top*, N `50`, Host blank, and clear the route fields. | The map is empty. | | |
| 4 | Click `incident 42` in the list. | Status: `Opened "incident 42" (saved …): 5 host(s), 4 connection(s)`. Every host is where it was (10.0.0.77 far left), at the same zoom. The violet/teal/white colours and the fading are back. Host `10.0.0.9`, Peers *Bottom (rarest)*, N `7`, and the route fields are restored. The address bar carries `ip=10.0.0.9`. | Hosts with their positions, connections, highlights, view and toolbar are restored. | |
| 5 | Click the background. | The highlight clears. | The highlights are live, not a picture. | |
| 6 | In a private window, open the page. | *Saved maps* lists `incident 42`; clicking it opens the same map. | Saved maps are shared. | |
| 7 | Restart the server with the same `$W`; reload. | `incident 42` is still listed and opens. | Saved maps persist (`TB_SESSIONS_DIR`). | |

### SAV-02 · Replacing and deleting saved maps asks first; names are checked (INT-S2)

**Environment:** ENV-CASE. **Starting state:** `incident 42` saved (SAV-01); a map is shown.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Name `second map`; **Save**. | Listed first, above `incident 42` (newest first). | | |
| 2 | Name `incident 42`; **Save**. | A dialog: `Replace the saved map "incident 42"?`. Click **Cancel**. | Saving under an existing name asks first. | |
| 3 | Read the status. | Red: `a map called 'incident 42' is already saved`. The saved time is unchanged. | Nothing was overwritten. | |
| 4 | **Save** again; click **OK**. | Status: `Replaced the map "incident 42" for everyone`. Its saved time is now, and it is listed first. | Replacing. | |
| 5 | Clear the name; **Save**. | Red: `Enter a name for the map`. | | |
| 6 | Paste this name (101 characters) and **Save**: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` | Red: `a map's name is 1 to 100 printable characters`. | Name limits. | |
| 7 | Click **Delete** next to `second map`; click **Cancel**. | The dialog `Delete the saved map "second map" for everyone?` closes, and the map stays listed. | Deleting asks first. | |
| 8 | **Delete** again; click **OK**. | Status: `Deleted the saved map "second map"`. It is gone here and, after a reload, in the private window. | | |
| 9 | Delete `incident 42` too. | `No saved maps yet.` | | |

### SAV-03 · Maps saved to and opened from a file; bad files are refused; paths are recomputed (INT-S2)

**Environment:** ENV-CASE. **Starting state:** fresh state; the SAV-01 step 1 map is shown; name field `incident 42`.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Click **Save to file**. | The browser downloads `threatbridge-incident_42.json`. Status: `Saved the map to a file`. | A file keeps a map for yourself or to pass on. | |
| 2 | Clear the name field; **Save to file**. | It downloads `threatbridge-10.0.0.9.json` (named after the IOC host). | | |
| 3 | **Clear**; **Open file** → choose `threatbridge-incident_42.json`. | Status: `Opened threatbridge-incident_42.json: 5 host(s), 4 connection(s)` (if the browser renamed the download, e.g. `… (1).json`, the status shows that name). The map is as it was when saved in step 1: same positions, zoom, highlights and toolbar. | Opening a file. | |
| 4 | Create `notamap.json` containing `{"version": 2, "nodes": [], "edges": []}`, and `hello.json` containing `hello`. Open each. | Red: `notamap.json is not a ThreatBridge map`, then `hello.json is not a ThreatBridge map`. The map is unchanged. | Bad files are refused without touching the map. | |
| 5 | Mark `203.0.113.66` (time blank) and `10.0.0.20` at `2024-05-01T12:20:00Z` (red attack arrows appear); **Save to file** (name field blank). Then **Remove** 203.0.113.66 from the compromised list; **Open file** → the file just saved. | The map opens without red arrows. *Attack paths* says `Mark at least two hosts as compromised.`, and the compromised list still holds only 10.0.0.20. | Attack paths come from the current compromised list, not the file. | |

### PRG-01 · Busy indicator, Cancel, and writes in quick succession (PRF-S3, ATK-4)

**Environment:** ENV-DEMO in Chrome or Chromium. **Starting state:** page open; `10.0.0.5` mapped inbound at Anchor `2024-05-01T12:00:00Z` with no throttling.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Use the map normally for a minute (expand, click connections). | The `Working…` indicator never appears, since every answer comes in under a second. | The indicator is only for slow requests. | |
| 2 | DevTools → Network: add a custom throttling profile with **5000 ms latency** and select it. Left-click 10.1.0.26. | After about 1 s, `Working… 1 s` and a **Cancel** button appear by the status line; the count rises once a second. | A request still running after a second shows its elapsed time (PRF-S3). | |
| 3 | Click **Cancel** before it finishes. | The indicator disappears. Status: `Cancelled`, in the normal colour (not red). No new peers are added. | Cancel stops the request. | |
| 4 | Left-click 10.1.0.26 again and wait. | The indicator counts up to about 5 s, then disappears as the peers appear. | The indicator clears when the request completes. | |
| 5 | Still throttled, in *Compromised hosts*: type `10.0.0.2` and click **Mark**. Straight away type `10.0.0.3` and click **Mark**. Then type `10.0.0.4` and leave it. Wait about 15 s. | After about 5 s `10.0.0.2 @ time unknown` is listed; after about 10 s `10.0.0.3 @ time unknown` too, and the status reads `Marked 10.0.0.3 compromised (time unknown)`. The IP field still shows `10.0.0.4`. | Writes made in quick succession are all stored, one after the other, and what you type while one is being stored is kept. | |
| 6 | Select *No throttling* again. Click **Remove** next to both hosts and clear the IP field. | | | |

### PRF-01 · 1.25 million flows built within 5 minutes; reopened from `--db` (PRF-1, PRF-2)

**Environment:** ENV-BIG. **Starting state:** `bulk.pcap` written; no `bulk.db` yet.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Start a stopwatch as you start the server. Reload `http://127.0.0.1:5059/` until it loads, then stop the stopwatch. | It loads in under 5 minutes (35–50 s on the test machines). Status: `Case: 1250000 flows between 260064 hosts, 2024-05-01T12:00:00.000Z → 2024-05-01T15:28:19.990Z`. | A pcap of at least 1M flows (PRF-1), under 100 MB, built within 5 minutes (PRF-2). | |
| 2 | Map `10.2.49.20` inbound, then outbound. | Each answers within about a second. Statuses: `10.2.49.20: showing top 11 of 11 distinct peer(s), …` and `10.2.49.20: showing top 15 of 15 distinct peer(s), …`. | The map is usable on that case. | |
| 3 | Stop the server; start it again with the same command and time it the same way. | It loads sooner than in step 1 (reused `bulk.db`), with the same status. | `--db` reuses the parsed case. | |

### PRF-02 · Responsive on a busy week: big hubs, a 100k-flow connection, attack paths in the background (PRF-3)

**Environment:** ENV-BUSY. **Starting state:** fresh state; page open. Status:
`Case: 1000000 flows between 2503 hosts, 2024-05-01T12:00:01.117Z → 2024-05-08T12:00:00.727Z`.

The time limits come from PRF-3: under 3 s for what the analyst waits on, and under 10 s for
attack paths, which are recomputed in the background.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Map `10.0.0.80` inbound. | In under 3 s: `10.0.0.80: showing top 50 of 2000 distinct peer(s), 2024-05-07T12:00:00.727Z → 2024-05-08T12:00:00.727Z`; the top arrow is from 10.1.0.7, `14123 · 3128`. | Expanding the busiest server. | |
| 2 | Window `8d`; Map. | In under 3 s, the arrow from 10.1.0.7 is `100071 · 3128`. | | |
| 3 | Left-click that arrow. | In under 3 s (about 2 s on the test machines): `1–50 of 100,071`, and the threat line, with about 600 hosts added and the amber status `Threat line through 10.1.0.7 → 10.0.0.80: 298 earlier host(s) (violet), 299 later host(s) (teal); ≤ 6 hops, ≤ 8d between hops. Click the background to clear. WARNING: stopped at the host limit; the line is incomplete.` | A threat line through the busiest connection stays fast and warns when capped at `TB_THREAT_MAX_HOSTS`. | |
| 4 | Click **Last**. | In under 3 s: `100051–100071 of 100,071`; the last row is `2024-05-08T11:59:52.354Z`. | The last page of a 100k-flow connection. | |
| 5 | **Clear**; Window `24h`. Paths from `10.0.0.80` to `10.0.0.53`. | In under 3 s, amber: `First 500 paths from 10.0.0.80 to 10.0.0.53, shortest first. There are more: …`. | Paths between two busy hosts. | |
| 6 | Mark these hosts compromised, one at a time, at these times: 10.0.0.80 `2024-05-05T00:00:00Z`, 10.0.0.53 `…T01:00:00Z`, 10.0.0.1 `…T02:00:00Z`, 10.1.4.24 `…T03:00:00Z`, 10.1.3.235 `…T04:00:00Z`, 10.1.3.92 `…T05:00:00Z`, 10.1.1.42 `…T06:00:00Z`, 10.1.1.237 `…T07:00:00Z`, 10.1.3.110 `…T08:00:00Z`, 10.1.5.138 `…T09:00:00Z` (all on 2024-05-05). | Each mark recomputes the attack paths, and the later ones show `Working… N s`. After the tenth, in under 10 s (about 6 s on the test machines): `78+ attack path(s) between 10 compromised host(s)`. | Attack paths among the ten busiest hosts, with IOC times. | |
| 7 | While step 6's last recomputation runs (`Working… N s` shown), pan and zoom, right-click a host, and map `10.0.0.53` inbound. | The map pans and zooms smoothly. The details appear at once. The expansion answers in under 3 s (under a second on the test machines), before the paths finish. | The map stays usable while paths are computed (PRF-3). | |

### EVD-01 · Reading captures: rotated files, idle timeouts, RST, cut-off files, link types; the same flows with or without parallel workers (ING-1, ING-3, ING-4, D6, D7, D13)

**Environment:** ENV-EVIDENCE, then ENV-EVIDENCE-1. **Starting state:** page open.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Read the status. | `Case: 12 flows between 11 hosts, 2024-05-01T12:00:00.000Z → 2024-05-01T12:06:20.000Z`. `notes.txt` was skipped and the server started. | Pcap files in a directory, searched recursively (ING-1, ING-3). Non-evidence files are skipped. | |
| 2 | Map `10.0.0.9` inbound. | Status: `10.0.0.9: showing top 4 of 4 distinct peer(s), 2024-04-30T12:06:20.000Z → 2024-05-01T12:06:20.000Z`. Arrows from 10.0.0.6 (`2 · 22`), 10.0.0.7 (`2 · 445`), 10.0.0.5 (`1 · 445`) and 10.0.0.8 (`1 · 80`). | | |
| 3 | Left-click 10.0.0.5 → 10.0.0.9. | `1–1 of 1`: `2024-05-01T12:00:00.000Z`, `tcp 50000 → 445 · 2.002 s · 8 pkts · 620 B`. | One connection split across two rotated files (`b-first.pcap` then `a-second.pcap`) is one flow: they are read in capture order, not name order (ING-3). `b-first.pcap` was named twice but read once (not 16 packets). | |
| 4 | Left-click 10.0.0.6 → 10.0.0.9. | Two flows: `2024-05-01T12:00:10.000Z` `tcp 50001 → 22 · 10.000 s · 3 pkts · 121 B`, and `2024-05-01T12:06:20.000Z` `tcp 50001 → 22 · 0.000 s · 1 pkts · 41 B`. | A TCP connection idle more than 5 minutes ends (D7). | |
| 5 | Left-click 10.0.0.7 → 10.0.0.9. | Two flows: `2024-05-01T12:00:40.000Z` `tcp 50002 → 445 · 0.001 s · 2 pkts · 80 B`, and `2024-05-01T12:00:41.000Z` `tcp 50002 → 445 · 0.000 s · 1 pkts · 40 B`. | A RST ends a connection (D7). | |
| 6 | Left-click 10.0.0.8 → 10.0.0.9. | `2024-05-01T12:01:10.000Z` `tcp 50004 → 80 · 0.001 s · 2 pkts · 80 B`. | A capture cut off mid-write is read up to its last whole packet. | |
| 7 | Map `10.0.0.6` outbound; left-click 10.0.0.6 → 10.0.0.53. | Two flows: `2024-05-01T12:00:30.000Z` `udp 40000 → 53 · 30.000 s · 2 pkts · 58 B`, and `2024-05-01T12:02:10.000Z` `udp 40000 → 53 · 0.000 s · 1 pkts · 29 B`. | UDP ends after 1 minute idle (D7). | |
| 8 | Map `10.0.3.100` inbound. | Four arrows, from 10.0.3.1, 10.0.3.2, 10.0.3.3 and 10.0.3.4, each `1 · 80`. Right-click one → Details Anchor `2024-05-01T12:00:50.123Z`. | Linux `any` (SLL, SLL2), raw IP and nanosecond captures are read (D6). | |
| 9 | Restart as ENV-EVIDENCE-1 (`TB_READ_WORKERS=1`). Repeat steps 1–8. | Every expected result is identical. | Reading in parallel worker processes gives exactly the flows of reading one file at a time (D13, PRF-S1). | |

### EVD-02 · NetFlow: the two halves of a connection are merged (ING-2, D7)

**Environment:** ENV-NETFLOW. **Starting state:** page open.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Read the status. | `Case: 3 flows between 4 hosts, 2024-05-01T12:00:00.000Z → 2024-05-01T12:02:05.000Z` (5 NetFlow records in, 3 connections out). | nfcapd files are read (ING-2). | |
| 2 | Map `10.0.0.9` inbound. | Arrows from 10.0.0.5 (`1 · 445`) and 10.0.0.20 (`1 · 445`). | | |
| 3 | Left-click 10.0.0.5 → 10.0.0.9. | `2024-05-01T12:00:00.000Z` `tcp 50000 → 445 · 10.000 s · 18 pkts · 10,500 B`. | The two one-way records are one connection, with packets and bytes summed (D7). | |
| 4 | Left-click 10.0.0.20 → 10.0.0.9. | `2024-05-01T12:02:00.000Z` `tcp 51000 → 445 · 5.000 s · 11 pkts · 1,300 B`. | When both halves start in the same millisecond, the well-known port (445) marks the responder, even though the reply half came first. | |
| 5 | Map `10.0.0.9` outbound. | `10.0.0.9: showing top 0 of 0 distinct peer(s), …`. | No reverse arrows are left over from the reply halves. | |
| 6 | Map `10.0.0.5` outbound; left-click 10.0.0.5 → 10.0.0.53. | `2024-05-01T12:00:50.000Z` `udp 53000 → 53 · 0.000 s · 1 pkts · 70 B`. | A one-way flow with no reply. | |
| 7 | Stop the server. Copy the nfcapd file in `$W/nf` to `$W/nf/nfcapd.current.12345`; start the server again. | The status is unchanged (3 flows). | The file nfcapd is still writing (`nfcapd.current.*`) is skipped. | |

### SO-01 · SOC actions open the map at the event's IP and time (EXT-1)

**Environment:** ENV-SO. **Starting state:** logged in to SOC; ThreatBridge reachable with the analyst's certificate.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | In SOC Hunt, find a Zeek conn event (`event.dataset:conn`); click its `source.ip` value. | The action menu offers `ThreatBridge: inbound (past)` and `ThreatBridge: outbound (future)`. | The SOC actions are installed (EXT-1). | |
| 2 | Choose `ThreatBridge: inbound (past)`. | A new tab opens the map with Host = that IP, Anchor time = the event's time (UTC), Direction *Inbound*, and the map drawn. The status ends `<anchor − 24h> → <anchor>`. If the Anchor is blank and the status ends at the current time, `{:soc_timestamp}` did not come through: record F (README, *Things to verify*, item 1). | | |
| 3 | Back in SOC, choose `ThreatBridge: outbound (future)` for the same value. | Direction *Outbound*; the status starts at the event's time. | | |

### SO-02 · Conn records from Elasticsearch: counts, flow fields, the 10,000-flow limit, the rarest-peer cap (GRA-1, ING-4, GRA-S3, FIL-1)

**Environment:** ENV-SO. **Starting state:** a map open on a host with traffic.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Right-click an arrow A → B and note *Connections*, *First seen* and *Last seen*. In SOC Hunt, query `event.dataset:conn AND source.ip:"A" AND destination.ip:"B"` over the hop's window (the status line's times). | Hunt's count equals *Connections*, and its first and last events match. | The map is built from the conn records (GRA-1). | |
| 2 | Left-click the arrow. | Flows oldest first. Each row shows protocol, source → destination port, duration, packets and bytes, none blank. They match the conn records (duration; packets and IP bytes of both sides added). | The flow list's field names hold on this install (ING-4, GRA-S3; README, *Things to verify*, item 7). | |
| 3 | Find a connection with more than 10,000 flows in the window (e.g. a workstation to a DNS server over `7d`); left-click it; click **Last**. | Red: `Security Onion lists only the first 10000 flows of a connection; narrow the time range to see later ones`. Set Range from to a later time and click the arrow again: the later flows are listed. | The 10,000-flow limit is reported, and the time range reaches past it (GRA-3). | |
| 4 | Add one peer's /24 to the exclude list; Map again. | Peers in that /24 no longer appear. | Excludes apply to Elasticsearch queries (FIL-1). | |
| 5 | Add `TB_RARE_SCAN_CAP=5` to `deploy/threatbridge.env` and re-run `deploy/run.sh`. Peers *Bottom (rarest)*; map a host with more than 5 distinct peers. | Amber status ending `— WARNING: scan hit the peer cap; rarest list may be incomplete`. Remove the setting and redeploy afterwards. | Bottom N is exact up to the cap, and warns beyond it. | |

### SO-03 · Zeek DNS records resolve domain names on the exclude list (ING-S2, FIL-2)

**Environment:** ENV-SO. **Starting state:** empty exclude list.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | In SOC Hunt, query `event.dataset:dns` and note a `dns.query.name` (e.g. `www.example.org`) and its `dns.resolved_ip` values. | | | |
| 2 | In ThreatBridge, add that name in mixed case. | Listed in lower case, with `capture: <those addresses>` (four at most, then `+N more`) and, with live DNS on, ` · DNS: …`. Hosts at those addresses leave the map. | In Security Onion mode, the sensors' Zeek DNS records supply the capture answers (ING-S2, FIL-2; README, *Things to verify*, item 9). | |
| 3 | Add `*.` plus the name's parent domain (e.g. `*.example.org`). | `capture:` lists the addresses of every matching name seen by the sensors. | Wildcards against Zeek DNS records. | |

### SO-04 · *PCAP in SOC* opens SOC's PCAP job for the flow (ING-S2, D12)

**Environment:** ENV-SO. **Starting state:** a connection's flow list is shown.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Click a flow's **PCAP in SOC**. | SOC opens (log in if asked) and runs a PCAP job. When it finishes, it shows the packets of that connection (same addresses, ports and start time). | Each flow gets its packets from the sensor that saw it (README, *Things to verify*, item 10). | |

### SO-05 · *Download PCAP* through the SOC API client, and its errors (ING-S2, D12)

**Environment:** ENV-SO-PRO. **Starting state:** a connection's flow list is shown.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Look at a flow row. | **Download PCAP** sits next to **PCAP in SOC**. | Download appears only with an API client. | |
| 2 | Click **Download PCAP**. | Status: `Asking the sensor for the packets of A → B at T…`. After a second, `Working… N s`. Then a file named `A_B_T.pcap` is saved, with `:` replaced by `-` (e.g. `10.0.0.5_10.0.0.9_2024-05-01T12-10-00.000Z.pcap`). Status: `PCAP of A → B at T: N B`. | ThreatBridge has the sensor extract the packets and hands over the file. | |
| 3 | Open the file in Wireshark. | It holds that connection's packets. | | |
| 4 | Change the client's secret in `deploy/threatbridge.env` to a wrong one; redeploy; click **Download PCAP**. | Red: `SOC refused the API client credentials (HTTP 401)`. | | |
| 5 | Restore the secret. In SOC, remove `jobs/write` from the client; redeploy; click **Download PCAP**. | Red: `the SOC API client lacks a permission it needs (events/read, jobs/read, jobs/write)`. Restore the permission. | Missing permissions are named. | |
| 6 | Set `TB_PCAP_TIMEOUT=1`; redeploy; click **Download PCAP** on a long connection. | Red: `the sensor has not finished after 1 s; the job may still complete in SOC: https://…/#/job/<id>`. Remove the setting afterwards. | A slow extraction is reported with a link to the job. | |

### SO-06 · SOC accepts the Dashboards pivots (EXT-1)

**Environment:** ENV-SO. **Starting state:** a map open with a known IOC time.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Right-click an arrow → `Filter SOC Dashboards: all conversations up to IOC time`. Widen the Dashboards time picker to cover the history. | SOC Dashboards opens with the query in its search bar. It shows only conversations between the two hosts, in both directions, and none after the IOC time. | SOC accepts `@timestamp:[* TO "…"]` (README, *Things to verify*, item 2). | |
| 2 | Set both Range from and Range to; repeat step 1. | Only conversations inside the range (and before the IOC time). | SOC accepts `["…" TO "…"]` (README item 8). | |
| 3 | Right-click a host → `Open host in SOC dashboard`. | Dashboards shows everything to or from that host. | Host pivot. | |

### TLS-01 · Mutual TLS: only certificates from the ThreatBridge CA get in (authentication)

**Environment:** ENV-MTLS. **Starting state:** container running. Use a separate browser profile for each certificate: browsers remember the certificate chosen for a site.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Profile 1: import `certs/ca.crt` as a trusted authority, with no client certificate. Open `https://localhost:5443/`. | The page does not load. The browser reports a TLS/SSL error (e.g. `ERR_BAD_SSL_CLIENT_AUTH_CERT` in Chrome), and no ThreatBridge content appears. | A connection without a client certificate fails at the handshake. | |
| 2 | Profile 2: trust `certs/ca.crt` and import `certs-foreign/mallory.p12` (password `test-only`). Open the page and choose mallory's certificate. | The page does not load (TLS error). | A certificate from another CA is refused. | |
| 3 | Profile 3: trust `certs/ca.crt` and import `certs/alice.p12`. Open the page and choose alice's certificate. | The map loads with no certificate warning. Map `10.0.0.5` works as in ENV-DEMO. | A certificate from the ThreatBridge CA is accepted. | |

### ROB-01 · Text from saved maps, files and entries is shown as text, never run as HTML (security)

**Environment:** ENV-CASE. **Starting state:** page open; `10.0.0.9` mapped inbound.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Save the map under the name `<img src=x onerror=alert(1)>`. | No alert box. The list shows the name as literal text. Status: `Saved the map "<img src=x onerror=alert(1)>" for everyone`. Delete it afterwards: the confirm dialog shows the literal text. | Names are rendered as text. | |
| 2 | Create `evil.json` containing `{"version": 1, "nodes": [{"id": "<img src=x onerror=alert(1)>", "position": {"x": 0, "y": 0}}], "edges": []}`. Open it, then right-click its host and press Escape. | No alert box. Status: `Opened evil.json: 1 host(s), 0 connection(s)`. The host's label, the menu title and Details' Host show the literal text. | A map file from someone else cannot inject markup. | |
| 3 | Add `<b>x</b>` to the exclude list. | Red: `invalid IP, CIDR or domain name: '<b>x</b>'`, shown literally. | | |

### ROB-02 · A damaged shared file is reported and left as it is; a lost server is reported

**Environment:** ENV-CASE. **Starting state:** page open; empty exclude list.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | With the server running, write `{` into `$W/exclude.json` (`printf '{' > $W/exclude.json`). Add `10.0.0.1` to the exclude list. | Red: `<W>/exclude.json is not valid JSON (Expecting property name enclosed in double quotes: line 1 column 2 (char 1)); fix or remove it`. The file still contains only `{`. | A damaged shared file is reported and never overwritten. | |
| 2 | Delete `$W/exclude.json`; add `10.0.0.1` again. | It is added. | | |
| 3 | Stop the server; click **Map**. | Red: the browser's network error (`Failed to fetch` in Chrome). | A lost server is reported, not ignored. | |

## 4. Requirement coverage

| Requirement or decision | Tests |
|---|---|
| ING-1 PCAP ingest | UI-02, EVD-01 |
| ING-2 NetFlow ingest | EVD-02 |
| ING-3 Directory of pcaps (rotated captures) | EVD-01 |
| ING-4 Addresses, ports, times, protocol | FLW-01, EVD-01, EVD-02, SO-02 |
| ING-S2 Security Onion integration | SOC-02, SO-03, SO-04, SO-05 |
| GRA-1 Directed graph | UI-02, MAP-02, SO-02 |
| GRA-2 Hosts and connections displayed | UI-01, MAP-02 |
| GRA-3 Temporal ordering | MAP-03, MAP-04, FLW-01, FLW-02, SO-02 |
| GRA-4 Interactive, clickable | UI-01, MAP-02, MAP-03, MAP-05, MAP-07, MAP-09 |
| GRA-S2 Time-range filtering | MAP-06, RNG-01, RNG-02, THR-02, CMP-02 |
| GRA-S3 Connection metadata | FLW-01, SO-02 |
| ATK-1 Attack paths between compromised hosts | CMP-02, CMP-03, PTH-01 |
| ATK-3 Predecessors and successors | MAP-02, MAP-03, MAP-04, MAP-05 |
| ATK-4 Mark hosts compromised | CMP-01, PRG-01 |
| INT-1 Threat line on edge click | THR-01 |
| INT-2 Earlier and later communications | THR-01, THR-02 |
| INT-3 Iterative refinement | MAP-09, CMP-02, EXC-05 |
| INT-4 Real-time update on new indicators | CMP-02 |
| INT-S2 Save and restore sessions | MAP-01, MAP-07, RNG-01, SAV-01, SAV-02, SAV-03 |
| FIL-1 IP exclude list | EXC-01, EXC-02, SO-02 |
| FIL-2 Domain names with DNS resolution | EXC-03, EXC-04, SO-03 |
| FIL-3 Excluded traffic out of path calculations | EXC-05 |
| FIL-S1 CIDR | EXC-02 |
| FIL-S2 Exclude list persists | EXC-01 |
| PRF-1 1M flows | PRF-01, PRF-02 |
| PRF-2 Build within 5 minutes under 100 MB | PRF-01 |
| PRF-3 Responsive during traversal | PRF-02, PRG-01 |
| PRF-S1 Parallel reading | EVD-01 step 9 (same results; for speed, see section 5) |
| PRF-S3 Progress | PRG-01 |
| EXT-1 Security Onion workflows | MAP-01, SOC-01, SO-01, SO-06 |
| D3 Edge left-click / right-click | SOC-01, THR-01 |
| D6 Classic pcap, nfdump | EVD-01, EVD-02 |
| D7 Connection rules | EVD-01, EVD-02 |
| D8 Time-ordered searches, hop limit | THR-01, THR-02, CMP-02, PTH-02 |
| D9 Capture DNS, then live DNS | EXC-03, EXC-04 |
| D10 Flows in time order; time range | FLW-02, RNG-01, RNG-02 |
| D11 Paths between two hosts | CMP-03, PTH-01 |
| D12 PCAP from the sensors | FLW-01, SOC-02, SO-04, SO-05 |
| D13 Parallel reading, exact flows | EVD-01 step 9 |
| Mutual TLS | TLS-01 |

## 5. Not verifiable in the GUI

These have no behaviour an operator can check in the map. They are covered elsewhere:

| Item | Why not here | Covered by |
|---|---|---|
| PRF-S1 speed of parallel reading | A timing of evidence reading, not a GUI behaviour (EVD-01 checks that the results are equal) | README's measurements; `tests/test_sources.py` (equal flows, sharing files) |
| PRF-S3 progress while a case is built | Shown on the terminal or in the log, before the map is reachable | `tests/test_progress.py` |
| EXT-S2 stable API | An HTTP interface for scripts | `docs/API.md`; `tests/test_integration.py` keeps it in step with the routes |
| Writes need the `X-ThreatBridge` header (CSRF) | The map always sends it | `tests/mtls_check.sh` (CI), `tests/test_api.py` |
| pcapng refused; an unreadable evidence file | The server refuses to start, with a message on the terminal | `tests/test_sources.py`, `tests/test_case.py` |
| Hand-edited entries skipped with a warning | Logged on the server | `tests/test_stores.py`, `tests/test_api.py` |
| DNS answers that try to tie a benign name to another address | Needs crafted captures; the result is an address *not* listed | `tests/test_sources.py` (CNAME chains, out-of-chain answers) |
| Requirements not built: ING-S1 (out of scope), ING-S3, GRA-S1, ATK-2 and EXT-2 (deferred, D5), ATK-S1–S3, INT-S1, INT-S3, FIL-S3, FIL-S4, PRF-S2, EXT-S1, EXT-S3 | Nothing to test yet | [REQUIREMENTS.md](REQUIREMENTS.md) |
