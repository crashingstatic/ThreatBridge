# Requirements and status

Status last updated 2026-10-25. **Done**, **Partial**, **Missing**, **Unverified**,
**TODO** (deferred by decision), **Out of scope** (by decision).

## Decisions

| ID | Decision |
|---|---|
| D1 | One shared core with several data sources: PCAP files, NetFlow files, and Security Onion (Elasticsearch). |
| D2 | Post-mortem tool. No live capture or live collectors. |
| D3 | Left-click an edge: highlight the threat line. Right-click an edge: menu with the SOC Dashboards pivot (and PCAP export, once D5 is lifted). |
| D4 | Graph storage: NetworkX `DiGraph`, one edge per host pair, carrying the sorted start times of its flows; the flows themselves in SQLite. |
| D5 | PCAP export (ATK-2, EXT-2) deferred. |
| D6 | File inputs: tcpdump captures (classic pcap) and nfcapd files read with nfdump (tested with 1.7.3). |
| D7 | A flow is one connection, oriented initiator -> responder like a Zeek conn record. Who started it is decided by time, then TCP flags, then ports; when none tells, it is recorded as two identical flows, one each way. Idle timeouts are 5 min for TCP and 1 min for UDP/ICMP, and the two halves of a NetFlow connection are merged. Details in the README, "Post-mortem mode". |
| D8 | Attack paths and threat lines follow time order: a hop must start after the previous one, and within the map's Window of it. Limits: 6 hops, 300 hosts per threat-line direction. Post-mortem (case) backend only. The searches are exact: every arrival time at a host is kept, not only the earliest, because a later arrival can allow a hop an earlier one can't (its Window ends later). |
| D9 | Domain names on the exclude list resolve from DNS answers in the capture first, then live DNS, and the two are combined. |
| D10 | GRA-3 means: a connection's flows can be listed in time order (oldest first, paged), and an optional time range (from/to) limits every query. A flow is in the range if it started in it. Both work with all data sources. |
| D11 | Paths between two hosts: every path from A to B in the evidence, no host twice, each hop opened by the host the attacker is on (initiator -> responder), following D8. A's and B's IOC times are optional. Listed shortest first, up to `TB_MAX_PATHS` (500). The compromised list shows the first 10 per pair, with "Show all". |
| D12 | Security Onion integration (ING-S2): Zeek DNS records resolve domain names on the exclude list, and each flow gets its PCAP from its sensor through SOC: SOC's own PCAP job link always, and a download through ThreatBridge when a SOC API client (Security Onion Pro) is configured. PCAP export from case files and along attack paths stays deferred (D5). |
| D13 | Reading in parallel (PRF-S1): worker processes decode evidence files, one per CPU; connections are followed in capture order in one process, so the flows are exactly those of reading one file at a time. Distributing work across machines is out of scope. |

## Data ingestion

| ID | Requirement | Status | Notes |
|---|---|---|---|
| ING-1 | SHALL ingest PCAP files and parse network conversations | Done | `sources/pcap.py` (D6, D7). pcapng not supported. |
| ING-2 | SHALL ingest NetFlow data formats | Done | `sources/netflow.py`: nfcapd files via nfdump (D6). |
| ING-3 | SHALL process multiple PCAP files from a specified directory | Done | Recursive; rotated captures are read in capture order. |
| ING-4 | SHALL extract source/destination IP addresses, ports, timestamps, and protocol information | Done | File sources: all of them, plus packets and bytes. Security Onion: the same fields from Zeek conn records, shown in a connection's flow list (field names unverified, README). |
| ING-S1 | SHOULD support real-time ingestion of live network captures | Out of scope | D2 |
| ING-S2 | SHOULD integrate with Security Onion sensor data extraction mechanisms | Done | Zeek conn records for the map, Zeek DNS records for domain excludes, and each flow's PCAP from its sensor: SOC's PCAP job link, or a download through the SOC Connect API (D12). Field names and the Connect API are unverified on a live install (README). |
| ING-S3 | SHOULD support additional network data formats (sFlow, IPFIX) | Missing | |

## Graph construction and visualization

| ID | Requirement | Status | Notes |
|---|---|---|---|
| GRA-1 | SHALL construct a directed graph representing network conversations between hosts | Done | Files: whole dataset in a `DiGraph` of host pairs (D4). Security Onion: built one hop at a time as the analyst expands. |
| GRA-2 | SHALL display nodes representing network hosts and edges representing communications | Done | |
| GRA-3 | SHALL maintain temporal ordering of network conversations | Done | Per D10. Clicking a connection lists its flows oldest first, numbered, 50 per page. Hops are time-chained, and threat lines and attack paths follow time order (D8). Security Onion lists at most the first 10,000 flows of a connection; the time range reaches later ones. |
| GRA-4 | SHALL provide interactive graph visualization with clickable nodes and edges | Done | |
| GRA-S1 | SHOULD provide multiple graph layout algorithms | Missing | One layout (breadthfirst). |
| GRA-S2 | SHOULD support graph filtering by time ranges, protocols, or traffic volume | Done | Time range (from/to) on every query, plus the per-hop window. No protocol or volume filter. |
| GRA-S3 | SHOULD display connection metadata (packet counts, byte volumes, duration) | Done | Per connection: count, ports, first/last seen. Per flow, in the flow list: duration, packets, bytes, protocol, ports. Security Onion field names are unverified (README). |

## Attack path analysis

| ID | Requirement | Status | Notes |
|---|---|---|---|
| ATK-1 | SHALL perform graph traversal to identify potential attack paths between compromised hosts | Done | Case backend: every path between hosts marked compromised, recomputed on every change, and every path between any two hosts on request (D8, D11). Checked against brute force on random graphs. |
| ATK-2 | SHALL generate filtered PCAP output containing only conversations along identified attack paths | TODO | D5 |
| ATK-3 | SHALL support bidirectional path analysis (predecessors and successors) | Done | Inbound (past) and outbound (future) expansion; threat lines go both ways. |
| ATK-4 | SHALL allow analysts to mark hosts as compromised and update path calculations | Done | Mark/unmark from the host menu or side panel, with a time or time unknown; shared list in `compromised.json`. |
| ATK-S1 | SHOULD highlight suspicious communication patterns from external networks | Missing | |
| ATK-S2 | SHOULD rank attack paths by likelihood or risk scoring | Missing | |
| ATK-S3 | SHOULD support manual annotation of attack techniques along paths | Missing | |

## Interactive analysis

| ID | Requirement | Status | Notes |
|---|---|---|---|
| INT-1 | SHALL highlight complete threat lines when an analyst clicks on a graph edge | Done | Case backend: left-click a connection (D3, D8). |
| INT-2 | SHALL show temporal relationships (earlier and later communications) relative to selected edges | Done | Case backend: the threat line colours earlier hosts violet and later hosts teal. |
| INT-3 | SHALL allow iterative refinement of attack path analysis based on analyst feedback | Done | Expand, remove, exclude, mark/unmark compromised; paths are recomputed after each change. |
| INT-4 | SHALL update graph visualization in real-time as new compromise indicators are added | Done | Case backend: attack paths are redrawn as soon as a host is marked or unmarked. |
| INT-S1 | SHOULD provide undo/redo for analysis iterations | Missing | |
| INT-S2 | SHOULD save and restore analysis sessions | Done | Saved maps: hosts with their positions, connections, highlights, view and toolbar, shared under a name or saved to a file. Exclude and compromised lists persist; `--db` keeps the parsed case; the URL keeps the root IP, time, direction, window, peer order and time range. |
| INT-S3 | SHOULD export analysis results in standard formats (JSON, XML, CSV) | Missing | |

## Filtering and whitelisting

| ID | Requirement | Status | Notes |
|---|---|---|---|
| FIL-1 | SHALL accept a list of IP addresses to exclude from graph analysis | Done | Shared list of IPs, CIDRs and domain names. Hosts it names are removed from the map; a CIDR applies from the next expansion. |
| FIL-2 | SHALL provide domain name whitelisting with real-time DNS resolution | Done | A domain stands for its addresses from the capture's DNS answers plus a live lookup (cached 5 min, can be switched off). `*.suffix` matches capture answers. In Security Onion mode the capture answers come from the sensors' Zeek DNS records. |
| FIL-3 | SHALL exclude whitelisted communications from attack path calculations | Done | Excluded hosts are never crossed by threat lines or attack paths. |
| FIL-S1 | SHOULD support CIDR notation | Done | |
| FIL-S2 | SHOULD keep whitelist configuration across sessions | Done | `exclude.json` |
| FIL-S3 | SHOULD suggest whitelist entries for common legitimate traffic | Missing | |
| FIL-S4 | SHOULD support time-based whitelisting rules | Missing | |

## Performance and scalability

| ID | Requirement | Status | Notes |
|---|---|---|---|
| PRF-1 | SHALL process PCAP files containing at least 1 million network flows | Done | 1.25M flows; `TB_PERF=1 pytest tests/test_perf.py`. |
| PRF-2 | SHALL complete initial graph construction within 5 minutes for datasets under 100MB | Done | Worst case, a 93 MiB pcap of 1.25M minimum-size packets: built in 35 s, reopened from `--db` in 13 s (one test machine). |
| PRF-3 | SHALL keep user interaction responsive during graph traversal | Done | Tested in CI (`tests/test_perf.py`) on an office-like week of 1M flows with busy servers and a 100k-flow connection. Queries an analyst waits on take under 1 s (threshold 3 s). Attack paths among the ten busiest hosts take 0.33 s, or 4.9 s with IOC times on all ten (threshold 10 s); they are recomputed in the background. Requests are asynchronous. |
| PRF-S1 | SHOULD support distributed processing for large datasets | Done | Security Onion: Elasticsearch does the aggregation. Files: read on every CPU (D13); 8 rotated captures, 538 MB, read in 4.2 s on 4 CPUs instead of 15.5 s. |
| PRF-S2 | SHOULD support incremental graph updates for continuous monitoring | Missing | Possibly out of scope under D2; not decided. |
| PRF-S3 | SHOULD show progress for long-running operations | Done | The map shows the elapsed time of any request running over a second, with Cancel. Building a case shows each stage, the file, how far it has got and the time left (terminal or log). |

## Integration and extensibility

| ID | Requirement | Status | Notes |
|---|---|---|---|
| EXT-1 | SHALL provide plugin architecture compatible with Security Onion workflows | Partial | SOC action links and the Dashboards pivot. SOC action configuration not verified on a live install. |
| EXT-2 | SHALL export identified attack paths as filtered PCAP files | TODO | D5 |
| EXT-S1 | SHOULD integrate with common SIEM platforms for alert enrichment | Missing | Launched from SOC; does not enrich alerts. |
| EXT-S2 | SHOULD support API endpoints for programmatic access | Done | JSON API for neighbours, flows, threat lines, paths, pivots, PCAP, excludes, compromised hosts and saved maps (mutual TLS), documented as a stable interface in [API.md](API.md); a test keeps it in step with the routes. |
| EXT-S3 | SHOULD provide webhook notifications | Missing | |
