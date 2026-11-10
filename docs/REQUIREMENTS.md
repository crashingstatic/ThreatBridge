# Requirements and status

Status last updated 2026-10-28. **Done**, **Partial**, **Missing**, **Unverified**,
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
| D7 | A flow is one connection, oriented initiator -> responder like a Zeek conn record. Who started it is decided by time, then TCP flags, then ports; when none tells, it is recorded as two identical flows, one each way. Refused connections (a SYN answered only by a RST; Zeek's REJ) aren't mapped, so a port scan doesn't swamp the map. Idle timeouts are 5 min for TCP and 1 min for UDP/ICMP, and the two halves of a NetFlow connection are merged. Details in the README, "Post-mortem mode". |
| D8 | Attack paths and threat lines follow time order: a hop must start after the previous one, and within the map's Window of it. Limits: 6 hops, 300 hosts per threat-line direction. Post-mortem (case) backend only. The searches are exact: every arrival time at a host is kept, not only the earliest, because a later arrival can allow a hop an earlier one can't (its Window ends later). |
| D9 | Domain names on the exclude list resolve from DNS answers in the capture first, then live DNS, and the two are combined. |
| D10 | GRA-3 means: a connection's flows can be listed in time order (oldest first, paged), and an optional time range (from/to) limits every query. A flow is in the range if it started in it. Both work with all data sources. |
| D11 | Paths between two hosts: every path from A to B in the evidence, no host twice, each hop opened by the host the attacker is on (initiator -> responder), following D8. A's and B's IOC times are optional. Listed shortest first, up to `TB_MAX_PATHS` (500). The compromised list shows the first 10 per pair, with "Show all". |
| D12 | Security Onion integration (ING-S2): Zeek DNS records resolve domain names on the exclude list, and each flow gets its PCAP from its sensor through SOC: SOC's own PCAP job link always, and a download through ThreatBridge when a SOC API client (Security Onion Pro) is configured. PCAP export from case files and along attack paths stays deferred (D5). |
| D13 | Reading in parallel (PRF-S1): worker processes decode evidence files, one per CPU; connections are followed in capture order in one process, so the flows are exactly those of reading one file at a time. Distributing work across machines is out of scope. |
| D14 | Protocols: each connection's is named as Zeek names services, so both modes agree. Security Onion: Zeek's own (`network.protocol`). Case files: from the payload (DNS, HTTP, TLS, SSH, SMB, RDP, DHCP), then by the server's well-known port; NetFlow by port only. FTP data connections are FTP: Security Onion's `ftp-data` reads as FTP, and captures follow Zeek: a control connection (port 21 or 2811, or any port where the server greets with 120/220, the client sends `USER` and the server answers 230/331) announces data connections with `PORT`/`EPRT` commands and 227/229 replies to `PASV`/`EPSV`; the first connection to the announced address and port, from the expected side, within 5 minutes is FTP. NetFlow names port 20 FTP. Names are single words, as the map shows them: DNS, HTTP, TLS, SSH, SMB, RDP, DHCP, Kerberos, DCE-RPC, NTLM, GSSAPI, LDAP, NTP, SNMP, FTP, SMTP, POP3, IMAP, Telnet, Syslog, MSSQL, MySQL, PostgreSQL, VNC, RADIUS, ICMP, Unknown; any other Zeek service in capitals (e.g. QUIC). The map's drop-down lists the protocols on the map; choosing one highlights the connections carrying it and fades the rest. |
| D15 | Marks are on hosts or on single flows, and they are the shared compromised list (ATK-4). A host is marked at a time or with the time unknown. Marking a flow locks it in (no filter hides it) and marks its two hosts through it, reached at the flow's start. A host stays marked while its mark count is above 0: its own mark plus the marked flows it is an end of. It was reached at the earliest known of those times. Unmarking a host removes its own mark and every marked flow it is an end of; unmarking a flow removes only that flow. Every analyst's map shows the shared marks within 5 seconds. |
| D16 | Suspect connections. In a part of the map that holds a marked host, a flow drawn on the map is *suspect* if it lies on a time-ordered line that ends at a marked host (a way the attacker could have reached it) or starts at one (where they could have gone next), every flow after the attacker reached it included. The rules are those of attack paths (D8): each hop starts no earlier than the hop before and within the Window of it, at most 6 hops, excluded hosts never crossed, and flows outside the time range or failing the filters ignored. A line into a marked host reaches it no later than the time it was reached (any time when unknown); a line out of it leaves within the Window after that time (any time when unknown). Only marked and suspect flows stay in that part: other connections are hidden, and so are hosts left with none, unless marked; the map's IOC host always stays. A connection that stays counts only its marked and suspect flows. Hidden elements come back when the marks change. A part of the map is the set of hosts joined by drawn connections; a part with no marked host is left as it is. Only what is drawn is used. Case backend only (FTODO-1). |
| D17 | Filter expressions, matched against each flow. Terms: protocol names as the map shows them (D14); fields `sport`, `dport`, `port` (either end), `src`, `dst`, `host` (either end), `proto` (`tcp`, `udp`, `icmp` or an IP protocol number), `packets`, `bytes`, `duration` (seconds) and `time` (the flow's start, ISO-8601 UTC, to the millisecond). Comparisons `==` (also when none is written), `!=`, `<`, `>`, `<=`, `>=`. Values: numbers, inclusive ranges `a-b` for numbers, IPs and CIDRs (`==` means inside, `!=` outside; no other comparison). `port` and `host` with `!=` mean neither end. Operators `NOT`/`!`, then `AND`/`&&`, then `OR`/`||`, and parentheses. Words are case-sensitive: operators in capitals, fields in lower case, protocols as shown. A flow missing a value fails every comparison on it. Each expression is applied with Enter and added to a list of filters, combined with AND, each removable on its own. Filters apply to every query: expansions, flow lists, threat lines, attack paths and paths between hosts. Marked flows always pass, and marked hosts on the map stay with no flow left. Adding or removing a filter re-runs the queries the map was built from (each with the Window, N and order it had), then lays the map out again. Filters stay until removed, also across *Map*; they are not kept in the URL. SOC pivots are not filtered. |
| D18 | How hiding and highlighting combine: filters and marks hide first; the protocol preview's dimming, and a focus's fading (threat line, path), apply to what is left. *Clear* resets only the protocol preview. Filters and the preview are each analyst's own; marks, and what they hide, are shared. |
| D19 | Saved maps keep the filters, the marks, and the queries the map was built from (map document version 2). An opened map shows its own marks, not the shared ones: marking and unmarking change only the map's marks, and other analysts' marks don't appear, until the analyst chooses *Share*, which replaces the shared marks with the map's after a confirmation. *Map* (a fresh map) or reloading the page returns to the shared marks. A version 1 map opens with no marks, and filters re-query it connection by connection. |
| D20 | The API describes itself for scripts, MCP servers and data tools (EXT-S5). `GET /api/config` and `GET /healthz` carry `api_version`, an integer (1 now) that goes up only when something is removed or changes meaning; additions (endpoints, parameters, response fields) leave it as it is and are listed in API.md's *Changes*. The OpenAPI document's `info.version` is the same number. `GET /api/config` also has `limits` (every other bound a request is held to; the existing `max_*` fields stay where they are) and `filter`, the filter vocabulary: each field with its type, comparisons and whether it takes a range, the operators, the protocol names and the grammar, all taken from the parser itself. `GET /api/protocols` counts the flows of each protocol in a time range (and filters): a case's whole span by default, Security Onion's last `TB_MAX_WINDOW`. |
| D21 | The API is described in OpenAPI 3.1 (EXT-S4), generated from the code: the request and response shapes are pydantic models in `threatbridge/apidoc.py`, with each field's description, and the paths and methods are the Flask app's routes. `python -m threatbridge.apidoc` writes `threatbridge/openapi.json`, which is committed and served at `GET /api/openapi.json`. A route without a description there, or a description without a route, stops it. pydantic is needed only to generate and test the document, not to run the service. Every response schema lists every field (no others allowed). Tests check that the committed file is exactly what the generator writes, that it is valid OpenAPI, that every response the API tests get matches its schema, and that every example in it matches its schema. API.md keeps what a schema can't say: the conventions (authentication, times, windows, the time range, filters, queries as POST, writes, errors), the version and its changes, the filter grammar, what marks and suspect connections mean, the map document in prose, and an index of the endpoints, one line each, which a test holds to the document's operations. Parameters and fields are described only in the document. |
| D22 | The saved-map format (map document version 2, D19) is a stable interface (EXT-S6): a JSON Schema in the OpenAPI document (`MapDocument`, generated like the rest) and a section of API.md; changes are listed in API.md's *Changes*. The server keeps a map as it is sent: it is not checked against the schema, as the map itself reads only what it understands. |

## Data ingestion

| ID | Requirement | Status | Notes |
|---|---|---|---|
| ING-1 | SHALL ingest PCAP files and parse network conversations | Done | `sources/pcap.py` (D6, D7). pcapng not supported. |
| ING-2 | SHALL ingest NetFlow data formats | Done | `sources/netflow.py`: nfcapd files via nfdump (D6). |
| ING-3 | SHALL process multiple PCAP files from a specified directory | Done | Recursive; rotated captures are read in capture order. |
| ING-4 | SHALL extract source/destination IP addresses, ports, timestamps, and protocol information | Done | File sources: all of them, plus packets and bytes. Security Onion: the same fields from Zeek conn records, shown in a connection's flow list (field names unverified, README). |
| ING-5 | SHOULD name FTP data connections in captures as Zeek does, from the control connection's `PORT`/`EPRT` commands and 227/229 replies | Done | D14. Control connection by port (21, 2811) or Zeek's signature; announcements expire after 5 minutes and are used once. Checked against crafted captures (active, passive, EPSV, a non-FTP 220 greeting, wrong side, too late), not yet against a real FTP session and Zeek (TEST_PLAN REAL-01). |
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
| GRA-S2 | SHOULD support graph filtering by time ranges, protocols, or traffic volume | Done | Time range (from/to) on every query, plus the per-hop window. Protocols, ports, hosts, packets, bytes, duration and time: filter expressions (FIL-S5). |
| GRA-S3 | SHOULD display connection metadata (packet counts, byte volumes, duration) | Done | Per connection: count, ports, first/last seen. Per flow, in the flow list: duration, packets, bytes, protocol, ports. Security Onion field names are unverified (README). |

## Attack path analysis

| ID | Requirement | Status | Notes |
|---|---|---|---|
| ATK-1 | SHALL perform graph traversal to identify potential attack paths between compromised hosts | Done | Case backend: every path between hosts marked compromised, recomputed on every change, and every path between any two hosts on request (D8, D11). Checked against brute force on random graphs. |
| ATK-2 | SHALL generate filtered PCAP output containing only conversations along identified attack paths | TODO | D5 |
| ATK-3 | SHALL support bidirectional path analysis (predecessors and successors) | Done | Inbound (past) and outbound (future) expansion; threat lines go both ways. |
| ATK-4 | SHALL allow analysts to mark hosts as compromised and update path calculations | Done | Mark/unmark from the host menu or side panel, with a time or time unknown; shared list in `compromised.json`. Hosts marked through flows (ATK-5) count too, reached at the earliest of their times (D15). |
| ATK-5 | SHALL allow analysts to mark a single flow as compromised: it is locked in, and its two hosts are marked through it | Done | D15. From a connection's flow list, or the menu of a single-flow connection. Locked in: every query passes it whatever the filters. |
| ATK-6 | SHALL keep a host marked while any mark holds it (its own, or a marked flow it is an end of), and unmark it with all of them | Done | D15. The count is worked out from the stored marks, so it can't drift. |
| ATK-7 | SHALL hide, restorably, the connections and hosts in a part of the map that holds marks when they are not on a time-ordered line to or from a mark, and leave parts without marks as they are | Done | D16. Case backend only (FTODO-1). Checked against brute force on random graphs. |
| ATK-8 | SHALL share marks with every analyst: each map shows them, and hides by them, within 5 seconds of a change | Done | D15, D16. Each map checks every 5 seconds; a browser test has a second analyst see a mark and its hiding appear and go. |
| ATK-9 | SHALL use only the flows that pass the filters, plus marked flows, for threat lines, attack paths and paths between two hosts | Done | D17. Case backend: a graph of the flows that pass, built once per filters and marked flows, the last 4 kept. |
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
| INT-5 | SHOULD let *Clear* reset only the protocol preview, leaving the map, filters and marks | Done | D18 |
| INT-6 | SHOULD apply the protocol being previewed as a filter in one click (*Apply as filter*) | Done | D17 |
| INT-7 | SHOULD draw marked connections solid and suspect ones dashed, both dark red with a light-red outline, with legend entries, and say how many connections the marks hid | Done | D16. Attack paths and paths between two hosts keep their own colour, dashed or solid the same way. How they look is checked by hand (TEST_PLAN VIS-02, VIS-03). |
| INT-8 | SHOULD offer *Mark compromised* and *Unmark* on each flow of a connection's flow list, and in the menu of a connection that holds a single flow | Done | D15 |
| INT-9 | SHOULD ask for confirmation before any action that replaces or wipes the shared marks | Done | D19. *Share* is the only such action. |
| INT-10 | SHOULD lay the map out again after it is re-queried | Done | D17 |
| INT-S1 | SHOULD provide undo/redo for analysis iterations | Missing | |
| INT-S2 | SHOULD save and restore analysis sessions | Done | Saved maps (version 2): hosts with their positions, connections, highlights, view and toolbar, and the filters, the marks and the queries the map was built from, shared under a name or saved to a file; an opened map keeps its own marks until shared (D19). Exclude and compromised lists persist; `--db` keeps the parsed case; the URL keeps the root IP, time, direction, window, peer order and time range. |
| INT-S3 | SHOULD export analysis results in standard formats (JSON, XML, CSV) | Done | Maps as JSON files; *Export CSV*: the marked hosts, and the marked and suspect flows on the map, as two CSV files (cells that would read as formulas are prefixed with `'`). No XML. |

## Filtering and whitelisting

| ID | Requirement | Status | Notes |
|---|---|---|---|
| FIL-1 | SHALL accept a list of IP addresses to exclude from graph analysis | Done | Shared list of IPs, CIDRs and domain names. Hosts it names are removed from the map; a CIDR applies from the next expansion. |
| FIL-2 | SHALL provide domain name whitelisting with real-time DNS resolution | Done | A domain stands for its addresses from the capture's DNS answers plus a live lookup (cached 5 min, can be switched off). `*.suffix` matches capture answers. In Security Onion mode the capture answers come from the sensors' Zeek DNS records. |
| FIL-3 | SHALL exclude whitelisted communications from attack path calculations | Done | Excluded hosts are never crossed by threat lines or attack paths. |
| FIL-S1 | SHOULD support CIDR notation | Done | |
| FIL-S5 | SHOULD filter the map with typed boolean expressions over flows | Done | D17. Read once on the server; matched in Python, SQL (case files) and Elasticsearch, checked to agree on random flows and expressions. |
| FIL-S6 | SHOULD keep a list of applied filters, combined with AND and each removable on its own; an invalid expression is not applied, and its box turns light red with the reason | Done | D17. Up to 20, each up to 500 characters. |
| FIL-S7 | SHOULD apply filters to everything the map shows, by re-running the queries it was built from, keeping marked hosts and flows | Done | D17. SOC pivots are not filtered. |
| FIL-S8 | SHOULD filter in both Security Onion and case modes | Done | D17. Security Onion queries are unverified on a live install (README, *Things to verify* 13). |
| FIL-S2 | SHOULD keep whitelist configuration across sessions | Done | `exclude.json` |
| FIL-S3 | SHOULD suggest whitelist entries for common legitimate traffic | Missing | |
| FIL-S4 | SHOULD support time-based whitelisting rules | Missing | |

## Performance and scalability

| ID | Requirement | Status | Notes |
|---|---|---|---|
| PRF-1 | SHALL process PCAP files containing at least 1 million network flows | Done | 1.25M flows; `TB_PERF=1 pytest tests/test_perf.py`. |
| PRF-2 | SHALL complete initial graph construction within 5 minutes for datasets under 100MB | Done | Worst case, a 93 MiB pcap of 1.25M minimum-size packets: built in 35 s, reopened from `--db` in 13 s (one test machine). |
| PRF-3 | SHALL keep user interaction responsive during graph traversal | Done | Tested in CI (`tests/test_perf.py`) on an office-like week of 1M flows with busy servers and a 100k-flow connection. Queries an analyst waits on take under 1 s (threshold 3 s). Attack paths among the ten busiest hosts take 0.33 s, or 4.9 s with IOC times on all ten (threshold 10 s); they are recomputed in the background. Requests are asynchronous. With filters: the first query with a new filter takes 3.8 s when nearly all 1M flows pass (0.7 s for one port), later ones 0.4 s; what the marks keep of a 300-connection map, 0.6 s (another machine, slower than the one above). |
| PRF-S1 | SHOULD support distributed processing for large datasets | Done | Security Onion: Elasticsearch does the aggregation. Files: read on every CPU (D13); 8 rotated captures, 538 MB, read in 4.2 s on 4 CPUs instead of 15.5 s. |
| PRF-S2 | SHOULD support incremental graph updates for continuous monitoring | Missing | Possibly out of scope under D2; not decided. |
| PRF-S3 | SHOULD show progress for long-running operations | Done | The map shows the elapsed time of any request running over a second, with Cancel. Building a case shows each stage, the file, how far it has got and the time left (terminal or log). |

## Integration and extensibility

| ID | Requirement | Status | Notes |
|---|---|---|---|
| EXT-1 | SHALL provide plugin architecture compatible with Security Onion workflows | Partial | SOC action links and the Dashboards pivot. SOC action configuration not verified on a live install. |
| EXT-2 | SHALL export identified attack paths as filtered PCAP files | TODO | D5 |
| EXT-S1 | SHOULD integrate with common SIEM platforms for alert enrichment | Missing | Launched from SOC; does not enrich alerts. |
| EXT-S2 | SHOULD support API endpoints for programmatic access | Done | JSON API for neighbours, flows, threat lines, paths, pivots, PCAP, excludes, compromised hosts and saved maps (mutual TLS), documented as a stable interface in [API.md](API.md) and the OpenAPI document (D21); tests keep both in step with the routes. |
| EXT-S3 | SHOULD provide webhook notifications | Missing | |
| EXT-S4 | SHOULD describe the API in a machine-readable form, kept in step with the code | Done | D21. Generated from the code; every API response the tests get is checked against it. |
| EXT-S5 | SHOULD let a client find out, from the API, what it needs to build valid requests: the API version, every limit, the filter vocabulary and the protocols in the data | Done | D20. The vocabulary is checked against what the parser takes. |
| EXT-S6 | SHOULD document the saved-map format as a stable interface | Done | D22. The maps the browser tests save are checked against it. |

## Future work

| ID | Item | Status | Notes |
|---|---|---|---|
| FTODO-1 | Re-architect ThreatBridge as a standalone tool that uses Security Onion only to import network traffic, so threat lines, attack paths and suspect connections (D16) work on Security Onion data too | TODO | Today these need the whole graph, which only case files give. |
| FTODO-2 | Bulk data for data tools and MCP servers: the connection graph, flows, hosts and DNS answers in a time range, without a query per host or per connection | TODO | Questions to answer first: below. |

### FTODO-2: questions to answer before it starts

1. **What to offer.** (a) A connection graph: one row per host pair. (b) Flows. (c) Hosts: one row each, with first and last seen, peers in and out, flows, bytes and protocols. (d) The capture's DNS answers. Which?
2. **Backends.** Case files only, or Security Onion too (the graph from a composite aggregation, flows paged with point-in-time search, which also lifts its 10,000-flow limit)? The demo backend?
3. **Scope.** Is a time range required, or is the default all the data? Do filters apply? Does the exclude list apply as on the map, or is it optional? Do marked flows still pass every filter?
4. **Format.** JSON pages with a cursor, NDJSON streamed, CSV streamed, or Parquet (adds `pyarrow`)? More than one?
5. **Size.** A cap per request, like the export's 200,000, or unlimited streaming? A long stream ties up one of the server's request threads (2 workers × 4 by default) while it runs; acceptable?
6. **Flows whose direction can't be told.** A case stores these twice, once each way (D7), so bulk output double-counts them. Flag each row (`oriented: false`), emit it once, or leave it as now? A flag means storing it, so every case is rebuilt once.
7. **Columns.** Graph rows: totals for packets and bytes, and all ports with counts or the top 5? Addresses with their DNS names from the capture? Counts split into time buckets (per hour or day) for time series?
8. **Marks.** Should rows say whether a host or flow is marked, and whether it is suspect against the marks across all the data? The suspect part can be slow on a large case.
9. **For agents.** Should the graph and host outputs take a sort (count, bytes, first seen) and a top N, so an agent can ask for "the busiest 50 pairs"?
