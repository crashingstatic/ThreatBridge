# Requirements and status

Status last updated 2026-10-19. **Done**, **Partial**, **Missing**, **Unverified**,
**TODO** (deferred by decision), **Out of scope** (by decision).

## Decisions

| ID | Decision |
|---|---|
| D1 | One shared core with several data sources: PCAP files, NetFlow files, and Security Onion (Elasticsearch). |
| D2 | Post-mortem tool. No live capture or live collectors. |
| D3 | Left-click an edge: highlight the threat line. Right-click an edge: menu with the SOC Dashboards pivot (and PCAP export, once D5 is lifted). |
| D4 | Graph storage: NetworkX `MultiDiGraph`, one edge per flow, the `Flow` stored as an edge attribute. (`DiGraph` per host pair plus a SQLite flow table was benchmarked and declined.) |
| D5 | PCAP export (ATK-2, EXT-2) deferred. |
| D6 | File inputs: tcpdump captures (classic pcap) and nfcapd files read with nfdump (tested with 1.7.3). |
| D7 | Proposed, to confirm: a flow is one connection, oriented initiator -> responder like a Zeek conn record. Idle timeouts are 5 min for TCP and 1 min for UDP/ICMP, and the two halves of a NetFlow connection are merged. Details in the README, "Post-mortem mode". |

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
| GRA-1 | SHALL construct a directed graph representing network conversations between hosts | Done | Files: whole dataset in a `MultiDiGraph`. Security Onion: built one hop at a time as the analyst expands. |
| GRA-2 | SHALL display nodes representing network hosts and edges representing communications | Done | |
| GRA-3 | SHALL maintain temporal ordering of network conversations | Partial | Hops are time-chained (first/last seen); individual flows are not ordered. |
| GRA-4 | SHALL provide interactive graph visualization with clickable nodes and edges | Done | |
| GRA-S1 | SHOULD provide multiple graph layout algorithms | Missing | One layout (breadthfirst). |
| GRA-S2 | SHOULD support graph filtering by time ranges, protocols, or traffic volume | Partial | Per-hop time window only. |
| GRA-S3 | SHOULD display connection metadata (packet counts, byte volumes, duration) | Partial | Connection count, ports, first/last seen. File flows carry packets and bytes, but the UI doesn't show them yet. |

## Attack path analysis

| ID | Requirement | Status | Notes |
|---|---|---|---|
| ATK-1 | SHALL perform graph traversal to identify potential attack paths between compromised hosts | Missing | Manual expansion from a single IOC host. |
| ATK-2 | SHALL generate filtered PCAP output containing only conversations along identified attack paths | TODO | D5 |
| ATK-3 | SHALL support bidirectional path analysis (predecessors and successors) | Done | Inbound (past) and outbound (future) expansion. |
| ATK-4 | SHALL allow analysts to mark hosts as compromised and update path calculations | Missing | |
| ATK-S1 | SHOULD highlight suspicious communication patterns from external networks | Missing | |
| ATK-S2 | SHOULD rank attack paths by likelihood or risk scoring | Missing | |
| ATK-S3 | SHOULD support manual annotation of attack techniques along paths | Missing | |

## Interactive analysis

| ID | Requirement | Status | Notes |
|---|---|---|---|
| INT-1 | SHALL highlight complete threat lines when an analyst clicks on a graph edge | Missing | See D3. |
| INT-2 | SHALL show temporal relationships (earlier and later communications) relative to selected edges | Partial | Details panel shows first/last seen; nothing highlighted. |
| INT-3 | SHALL allow iterative refinement of attack path analysis based on analyst feedback | Partial | Expand, remove node, exclude. |
| INT-4 | SHALL update graph visualization in real-time as new compromise indicators are added | Missing | |
| INT-S1 | SHOULD provide undo/redo for analysis iterations | Missing | |
| INT-S2 | SHOULD save and restore analysis sessions | Missing | The URL keeps only the root IP and time. |
| INT-S3 | SHOULD export analysis results in standard formats (JSON, XML, CSV) | Missing | |

## Filtering and whitelisting

| ID | Requirement | Status | Notes |
|---|---|---|---|
| FIL-1 | SHALL accept a list of IP addresses to exclude from graph analysis | Done | Shared list. Adding an IP removes it from the map; a CIDR applies from the next expansion. |
| FIL-2 | SHALL provide domain name whitelisting with real-time DNS resolution | Missing | |
| FIL-3 | SHALL exclude whitelisted communications from attack path calculations | Partial | Applied to every neighbour query; no path calculation exists yet. |
| FIL-S1 | SHOULD support CIDR notation | Done | |
| FIL-S2 | SHOULD keep whitelist configuration across sessions | Done | `exclude.json` |
| FIL-S3 | SHOULD suggest whitelist entries for common legitimate traffic | Missing | |
| FIL-S4 | SHOULD support time-based whitelisting rules | Missing | |

## Performance and scalability

| ID | Requirement | Status | Notes |
|---|---|---|---|
| PRF-1 | SHALL process PCAP files containing at least 1 million network flows | Done | 1.25M flows; `TB_PERF=1 pytest tests/test_perf.py`. |
| PRF-2 | SHALL complete initial graph construction within 5 minutes for datasets under 100MB | Done | 93 MB pcap of minimum-size packets: 42 s, about 1 GB RAM (one test machine). |
| PRF-3 | SHALL keep user interaction responsive during graph traversal | Unverified | |
| PRF-S1 | SHOULD support distributed processing for large datasets | Partial | Security Onion source only: Elasticsearch does the aggregation. |
| PRF-S2 | SHOULD support incremental graph updates for continuous monitoring | Missing | Possibly out of scope under D2; not decided. |
| PRF-S3 | SHOULD show progress for long-running operations | Partial | Status line during queries. |

## Integration and extensibility

| ID | Requirement | Status | Notes |
|---|---|---|---|
| EXT-1 | SHALL provide plugin architecture compatible with Security Onion workflows | Partial | SOC action links and the Dashboards pivot. SOC action configuration not verified on a live install. |
| EXT-2 | SHALL export identified attack paths as filtered PCAP files | TODO | D5 |
| EXT-S1 | SHOULD integrate with common SIEM platforms for alert enrichment | Missing | Launched from SOC; does not enrich alerts. |
| EXT-S2 | SHOULD support API endpoints for programmatic access | Partial | JSON API for neighbours, pivots and excludes (mutual TLS). |
| EXT-S3 | SHOULD provide webhook notifications | Missing | |
