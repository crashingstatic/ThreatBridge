# Requirements and status

Status last updated 2026-10-21. **Done**, **Partial**, **Missing**, **Unverified**,
**TODO** (deferred by decision), **Out of scope** (by decision).

## Decisions

| ID | Decision |
|---|---|
| D1 | One shared core with several data sources: PCAP files, NetFlow files, and Security Onion (Elasticsearch). |
| D2 | Post-mortem tool. No live capture or live collectors. |
| D3 | Left-click an edge: highlight the threat line. Right-click an edge: menu with the SOC Dashboards pivot (and PCAP export, once D5 is lifted). |
| D4 | Graph storage: NetworkX `DiGraph`, one edge per host pair, carrying the sorted start times of its flows; the flows themselves in SQLite. Changed from `MultiDiGraph` (one edge per flow) on 2026-10-20 for PRF-3: same results, 27x faster attack paths. |
| D5 | PCAP export (ATK-2, EXT-2) deferred. |
| D6 | File inputs: tcpdump captures (classic pcap) and nfcapd files read with nfdump (tested with 1.7.3). |
| D7 | A flow is one connection, oriented initiator -> responder like a Zeek conn record. Idle timeouts are 5 min for TCP and 1 min for UDP/ICMP, and the two halves of a NetFlow connection are merged. Details in the README, "Post-mortem mode". |
| D8 | Attack paths and threat lines follow time order: a hop must start after the previous one, and within the map's Window of it. Limits: 6 hops, 300 hosts per threat-line direction. Post-mortem (case) backend only. Since 2026-10-21 the searches are exact: every arrival time at a host is kept, not only the earliest. Before, a path that needed a later arrival (whose Window ends later) could be missed. |
| D9 | Domain names on the exclude list resolve from DNS answers in the capture first, then live DNS, and the two are combined. |
| D10 | GRA-3 means: a connection's flows can be listed in time order (oldest first, paged), and an optional time range (from/to) limits every query. A flow is in the range if it started in it. Both work with all data sources. |
| D11 | Paths between two hosts: every path from A to B in the evidence, no host twice, each hop opened by the host the attacker is on (initiator -> responder), following D8. A's and B's IOC times are optional. Listed shortest first, up to `TB_MAX_PATHS` (500). The compromised list shows the first 10 per pair, with "Show all". |

## Data ingestion

| ID | Requirement | Status | Notes |
|---|---|---|---|
| ING-1 | SHALL ingest PCAP files and parse network conversations | Done | `sources/pcap.py` (D6, D7). pcapng not supported. |
| ING-2 | SHALL ingest NetFlow data formats | Done | `sources/netflow.py`: nfcapd files via nfdump (D6). |
| ING-3 | SHALL process multiple PCAP files from a specified directory | Done | Recursive; rotated captures are read in capture order. |
| ING-4 | SHALL extract source/destination IP addresses, ports, timestamps, and protocol information | Done | File sources: all of them, plus packets and bytes. The Security Onion source has no source port or protocol. |
| ING-S1 | SHOULD support real-time ingestion of live network captures | Out of scope | D2 |
| ING-S2 | SHOULD integrate with Security Onion sensor data extraction mechanisms | Partial | Reads Zeek conn records from Security Onion's Elasticsearch. |
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
| INT-S2 | SHOULD save and restore analysis sessions | Partial | Exclude and compromised lists persist; `--db` keeps the parsed case; the URL keeps the root IP and time. The map layout is not saved. |
| INT-S3 | SHOULD export analysis results in standard formats (JSON, XML, CSV) | Missing | |

## Filtering and whitelisting

| ID | Requirement | Status | Notes |
|---|---|---|---|
| FIL-1 | SHALL accept a list of IP addresses to exclude from graph analysis | Done | Shared list of IPs, CIDRs and domain names. Hosts it names are removed from the map; a CIDR applies from the next expansion. |
| FIL-2 | SHALL provide domain name whitelisting with real-time DNS resolution | Done | A domain stands for its addresses from the capture's DNS answers plus a live lookup (cached 5 min, can be switched off). `*.suffix` matches capture answers. Security Onion mode uses the live lookup only. |
| FIL-3 | SHALL exclude whitelisted communications from attack path calculations | Done | Excluded hosts are never crossed by threat lines or attack paths. |
| FIL-S1 | SHOULD support CIDR notation | Done | |
| FIL-S2 | SHOULD keep whitelist configuration across sessions | Done | `exclude.json` |
| FIL-S3 | SHOULD suggest whitelist entries for common legitimate traffic | Missing | |
| FIL-S4 | SHOULD support time-based whitelisting rules | Missing | |

## Performance and scalability

| ID | Requirement | Status | Notes |
|---|---|---|---|
| PRF-1 | SHALL process PCAP files containing at least 1 million network flows | Done | 1.25M flows; `TB_PERF=1 pytest tests/test_perf.py`. |
| PRF-2 | SHALL complete initial graph construction within 5 minutes for datasets under 100MB | Done | Worst case, 93 MB pcap of 1.25M minimum-size packets: built in 58 s, reopened from `--db` in 24 s (one test machine). |
| PRF-3 | SHALL keep user interaction responsive during graph traversal | Done | 975k flows: threat line 0.06 s; attack paths among 10 busy hosts (721 paths) 0.7 s; every path between two of them at most 0.2 s; expanding the busiest host 0.26 s. Requests are asynchronous. |
| PRF-S1 | SHOULD support distributed processing for large datasets | Partial | Security Onion source only: Elasticsearch does the aggregation. |
| PRF-S2 | SHOULD support incremental graph updates for continuous monitoring | Missing | Possibly out of scope under D2; not decided. |
| PRF-S3 | SHOULD show progress for long-running operations | Partial | Status line during queries. |

## Integration and extensibility

| ID | Requirement | Status | Notes |
|---|---|---|---|
| EXT-1 | SHALL provide plugin architecture compatible with Security Onion workflows | Partial | SOC action links and the Dashboards pivot. SOC action configuration not verified on a live install. |
| EXT-2 | SHALL export identified attack paths as filtered PCAP files | TODO | D5 |
| EXT-S1 | SHOULD integrate with common SIEM platforms for alert enrichment | Missing | Launched from SOC; does not enrich alerts. |
| EXT-S2 | SHOULD support API endpoints for programmatic access | Partial | JSON API for neighbours, flows, threat lines, paths, pivots and excludes (mutual TLS). Not documented as a stable interface. |
| EXT-S3 | SHOULD provide webhook notifications | Missing | |
