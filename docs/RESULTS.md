# Results

How well ThreatBridge finds an attack, measured as [REQUIREMENTS.md](REQUIREMENTS.md) D35
describes. Each run records the version, the date and the machine. Add runs at the top of
their section.

## How to read the tables

Each chain is looked for from two indicators an analyst could have: the victim's first contact
with its command-and-control address (the victim and that time), and an alert on the chain's
last hop.

- **Hops seen in flows**: the chain's hops with a flow of their host pair near their time.
  A hop not seen can't be found by anything.
- **Suspect hops / hosts**: with the victim marked compromised at its first contact, the
  chain's hops that are suspect at their times, and how many hosts the suspect connections
  touch. The second number is what the analyst is pointed at.
- **Path hops / chain listed / paths / path hosts**: attack paths from the victim at its first
  contact to the last hop's target at its time. A hop counts when its host pair is on a listed
  path (a path shows the earliest flow of a pair that keeps the order, which may not be the
  attacker's own). *Chain listed*: the chain's own route is one of the paths. A `+` after the
  paths means more than the limit (500).
- **Chain hosts on the line / line hosts**: the threat line through the alerted connection. The
  command-and-control address is reached only by the victim's own outbound flow, which that
  line doesn't follow back, so it is missing by design.
- **Active hosts**: hosts with a flow from a Window before the chain's first contact to a
  Window after its last hop.

## Synthetic case (CI)

`python -m threatbridge.measure`; CI holds floors on it (`tests/test_detection.py`).

### 0.1.0, 2026-11-24, Linux x86_64, 4 CPUs, Python 3.13 (cloud container)

A seeded day of office traffic: 300 workstations, a domain controller, DNS, a proxy, a file
server, ten application servers and five administrators' jump hosts, 30,000 flows. Three chains
through the busiest workstations on common ports (445, 3389) and three through the quietest on
rarer ones (5985, 22); each an outbound contact, then three hops 10 to 40 minutes apart. Window
24 h, at most 6 hops.

| Chain | Active hosts | Hops seen in flows | Suspect hops | Suspect hosts | Path hops | Chain listed | Paths | Path hosts | Chain hosts on the line | Line hosts | Milliseconds (suspects, paths, line) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| busy 1 | 525 | 4/4 | 4/4 | 232 | 3/3 | yes | 3 | 4 | 4/5 | 4 | 1, 1, 0 |
| busy 2 | 525 | 4/4 | 4/4 | 223 | 3/3 | yes | 3 | 4 | 4/5 | 10 | 1, 1, 0 |
| busy 3 | 525 | 4/4 | 4/4 | 216 | 3/3 | yes | 3 | 4 | 4/5 | 4 | 1, 1, 0 |
| quiet 1 | 525 | 4/4 | 4/4 | 236 | 3/3 | yes | 1 | 4 | 4/5 | 5 | 1, 0, 0 |
| quiet 2 | 525 | 4/4 | 4/4 | 222 | 3/3 | yes | 1 | 4 | 4/5 | 4 | 1, 0, 0 |
| quiet 3 | 525 | 4/4 | 4/4 | 239 | 3/3 | yes | 1 | 4 | 4/5 | 6 | 2, 0, 0 |

What it says: every hop is found, by suspect connections and by paths, and each chain is listed
as a path. Paths and threat lines point at a handful of hosts. Marking the victim alone points
at about 230 of 525 active hosts: with a 24-hour Window, a workstation's ordinary traffic to the
domain controller and the file server makes most of the network reachable. Paths between two
marked hosts are the sharp tool.

The same chains at shorter Windows (every hop still found, every chain still listed, since these
chains' hops are at most 40 minutes apart):

| Window | Suspect hosts (fewest to most) |
|---|---|
| 24 h | 216 to 239 |
| 6 h | 212 to 221 |
| 2 h | 172 to 201 |
| 1 h | 6 to 152 |

## LANL 2015

Kent (2015), *Comprehensive, Multi-Source Cyber-Security Events*, Los Alamos National
Laboratory, <https://csr.lanl.gov/data/cyber1/> (CC0). Download `flows.txt.gz` (1.1 GB) and
`redteam.txt.gz` from there; the site asks for an e-mail address and the intended use.

```bash
python -m threatbridge.lanl flows.txt.gz redteam.txt.gz --hours 6 --details
```

It reads the flows from an hour before the first red-team logon to `--hours` after it, and
measures every host the red team reached from that first source within the slice. Logons are
authentication events, and LANL's flows are not every connection, so expect some hops not seen
in flows. A day of flows is a few million: allow several GB of memory for `--hours 24`.

Not yet run: it needs the data downloaded.

## DARPA OpTC

Not loaded. Its red-team ground truth is a written report (`OpTCRedTeamGroundTruth.pdf` in
<https://github.com/FiveDirections/OpTC-data>), not labels, and its network flows are Zeek logs
within about a terabyte of data, which the case backend doesn't read. A Zeek `conn.log` reader
and labels transcribed from the report would come first.
