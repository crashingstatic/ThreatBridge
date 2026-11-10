# Prior art, and what it suggests for ThreatBridge

Reviewed 2026-11-10. This is a targeted review, not a systematic literature or patent search.
Each source says how far it was checked:

- **read**: the paper or claims were read in this review;
- **abstract**: only the abstract, a vendor page or documentation page was read;
- **search**: only a search result's summary was seen; treat the details as unconfirmed.

Nothing here is legal advice.

## What the prior art says, in short

1. **The core rule is published.** Chaining flows where each starts at the host the last one
   reached, in time order, within a maximum delay, was formalised for network flows in 2017
   (Apruzzese et al.), with path ranking. Hopper (2021) uses the same shape on logins with a
   24-hour limit. ThreatBridge's own contribution is narrower: exact reachability over interval
   sets (it never enumerates every flow sequence), both directions from a host the analyst
   picks, long windows, and marks that prune the map.
2. **Reachability is never the signal.** Every system that reports results on real networks adds
   two things ThreatBridge lacks: *rarity against history* (has this pair, port or path been
   seen before?) and *identity* (which account, and did it change along the path?). Without
   them these systems drown in benign paths; with them Hopper reports 94.5% detection at under
   9 alerts a day.
3. **Active patents cover time-ordered connection paths** (Rapid7, VMware, Microsoft). Several
   recite scoring or ranking the paths, which ThreatBridge does not do today and which the
   first improvement below would add. Have a patent attorney look before selling.
4. **The platform has moved.** Security Onion 2.4 reached end of life on 2026-10-01. Security
   Onion 3 drops Stenographer, ships Elasticsearch 9, and sells an MCP server, an external API
   and AI agents in its Pro edition.

## Improvements, ranked

| # | Improvement | Mainly from | Would close |
|---|---|---|---|
| 1 | Rank peers, suspect connections and paths by rarity against a baseline | Apruzzese, Hopper, NoDoze, Rapid7 patent, Arkime, ExtraHop | ATK-S2, ATK-S1 |
| 2 | Put accounts on hops, and flag a change of account along a path | Hopper, Latte, Defender for Identity | new |
| 3 | Resolve addresses to hosts over time | Zeek DHCP and known-devices logs | new |
| 4 | Give hosts roles (bastion, proxy, scanner, domain controller) with path rules, instead of only excluding them | Hopper, Rapid7 patent, Apruzzese, Zhang and Paxson | FIL-S3, part of FIL-S4 |
| 5 | Search in priority order within a time budget | PrioTracker, Wu et al., Hopper | handoff H3 |
| 6 | A "carries data both ways" pre-filter, and connection states kept as data | Apruzzese, Zeek | handoff M2 |
| 7 | Expand from an outside address or name to every inside host that used it; show beacons and long connections | Vectra, RITA | ATK-S1 |
| 8 | Compare a window with an earlier one: what is new | Arkime, ExtraHop | ATK-S1 |
| 9 | Interoperate: Community ID on flows, IPFIX biflows, pcapng | Community ID, RFC 5103 | ING-S3, EXT-S1 |
| 10 | Stable incremental layout, and a timeline view of a path | fCoSE, dynamic graph drawing research, Vectra | GRA-S1, handoff U2 |
| 11 | Evaluate on labelled data and publish the numbers | Apruzzese's method, LANL and OpTC data | handoff H4 |
| 12 | Move to Security Onion 3 | Security Onion release posts | EXT-1 |

### 1. Rank by rarity against a baseline

Today every time-consistent path is equal. The prior art ranks, and the ranking is what makes
the output usable.

- **Apruzzese et al.** score each path 0 to 5 as the sum of five indicators: *path novelty*
  (share of its host-and-port pairs never seen in earlier runs), *reconnaissance* (share of its
  hosts involved in scanning), *involved LANs* (share of hosts in different subnets), *uncommon
  ports* (both ports uncommon), and *anomalous data transfer* (a boxplot test on bytes against
  the recent past). On 657M flows among 8,198 hosts over 160 days, injected attacks ranked on
  average in the top 3 each day, and in the top 5 on 93% to 100% of days.
- **Hopper** uses three rarity features per path: the fewest days any earlier hop's exact edge
  was seen in history, the same for the later hops, and the days on which any path joined the
  first and last machine. Each becomes a tail probability against the last 30 days of paths;
  their product is the score, and an alert budget picks how many to show.
- **NoDoze** scores a path by multiplying, hop by hop, how regular each transition has been.
- **Rapid7's patent** lists path metrics: links, distinct protocols, new nodes, new links, data
  transferred, a host using a protocol for the first time.
- **Arkime** and **ExtraHop** let the analyst compare a window with an earlier baseline and
  show only what is new.

For ThreatBridge: keep, per host pair and port, the first time and the number of days seen
(the case store already holds every flow); score each hop and path from that; sort attack
paths, paths between two hosts and suspect connections by score; show "first seen" on a
connection. Security Onion mode can get the same from a date histogram per pair. Read the
patents section before building this.

### 2. Accounts on hops

Hopper's two attack properties are that the path *switches credentials* and *reaches a machine
its first user never accessed*. Latte works from logon events, and Defender for Identity from
sessions and permissions. Flows alone cannot see either.

Security Onion already has network-derived identity: Zeek writes Kerberos, NTLM, SMB, RDP and
SSH logs (the Kerberos log's `client` and `service` fields were confirmed in Zeek's
documentation; the NTLM log's field names were not checked). Joining those to connections by
time and endpoints would label a hop with its account without host agents. Case mode would
need Zeek run over the capture, or its own parsers; that is a larger decision.

### 3. Addresses to hosts over time

Zeek's `dhcp.log` holds the client's MAC address and host name with each lease, and
`known_devices.log` holds MAC and DHCP host name. An interval table (address, MAC, name, from,
to) built from them would let the map show a host under one identity when its address changes,
and stop two hosts that held one address from being joined. Zeek's own forum notes that
address-only tracking "will not work correctly" with re-used addresses.

### 4. Host roles instead of only excludes

Excluding a hub removes it from every path, real ones included. The prior art treats hubs by
role:

- **Hopper:** a login from a hardened bastion starts a new path (the bastion vouches for the
  user); machines under a week old, provisioning servers and approved service accounts are
  benign scenarios; identical paths are collapsed to one per day.
- **Rapid7 patent:** scanners and whitelisted connections are left out when graphs are built.
- **Apruzzese et al.:** with the delay limit at 1 second, every path found on the real network
  was a genuine relay: SSH tunnelling or proxying. That is a cheap way to *find* relays and
  propose them to the analyst (FIL-S3).
- **Zhang and Paxson:** stepping-stone detection needs "a significant policy component" to
  tell allowed relays from covert ones.

For ThreatBridge: let a host carry a role with a rule ("paths start here, never pass
through", "never a source", "count only new destinations"), and suggest roles from the data.

### 5. Search in priority order within a budget

The review measured attack paths at 76 s for 40 marked hosts, with no bound (handoff H3).

- **PrioTracker** tracks dependencies under a time limit by always expanding the event with
  the highest priority, a weighted sum of *rareness* and *low fan-out*; it reports attack
  traces other trackers missed and up to 100× less analysis time.
- **Wu et al.** give one-pass algorithms for earliest-arrival, latest-departure, fastest and
  shortest temporal paths; the "which hosts can reach which" half of attack paths needs only
  the first two, not enumeration.
- **Hopper** keeps a watch-list of partial paths and extends it by one step per new event.
- Index structures for temporal reachability exist (for example TILL-Index) if cases grow.

For ThreatBridge: expand rare, low-fan-out pairs first so a budgeted search returns the most
interesting paths; answer "is there any path" with a single earliest-arrival pass before
enumerating.

### 6. Pre-filter and connection states

Apruzzese et al. drop flows below a minimum duration and minimum bytes *in both directions*
before searching, which they say removes up to 90% of edges, because an interactive hop needs
both. ThreatBridge's filters can express this; a preset would make it one click. Zeek records a
state for every connection (`S0` attempt unanswered, `REJ` rejected, and others) and a history
string; keeping the state as a field, not dropping refused connections, is the handoff's M2.

### 7. Outside endpoints, beacons, long connections

- **Vectra** (vendor-stated) expands a command-and-control detection to every entity tied to
  the same outside domain or address.
- **RITA** scores beaconing from 0 to 1 and lists long connections from Zeek logs.

For ThreatBridge: from an outside address, or a name through the DNS answers it already
keeps, show every inside host that used it; mark connections that beacon or run long. This is
the part of initial access the map can see (ATK-S1).

### 8. What is new in this window

Arkime's connection graph can compare against a baseline window and show nodes present only
now; ExtraHop's activity maps colour connections that appear only in the later interval. A
toggle "only what is new since …" on an expansion would use the same first-seen data as item 1.

### 9. Interoperate

- **Community ID** is a version prefix and a base64 SHA-1 of a seeded 5-tuple, implemented by
  Zeek and Suricata and documented by Security Onion. Putting it on every flow lets an analyst
  pivot to Security Onion, Suricata or Arkime by string match.
- **RFC 5103** defines IPFIX biflows: one record for both directions. Reading them would
  remove the pairing of one-way NetFlow halves and its direction guesses (ING-S3).
- pcapng is what Wireshark saves by default; today it must be converted.

### 10. Layout

fCoSE, a Cytoscape.js layout, supports fixed-position constraints and incremental layout,
which its release notes present as a way to keep the user's mental map. User studies on layout
stability are mixed, but
the review's finding was simpler: positions the analyst set are thrown away (handoff U2).
Vectra offers a tree, a timeline and a graph of one incident; a timeline of a chosen path
would address GRA-S1.

### 11. Evaluate on labelled data

No number says how much ThreatBridge narrows an investigation or whether true paths survive.

- **Method:** Apruzzese et al. inject attack flows into real traffic, once using very active
  hosts and once using quiet ones, and report the attack's rank each day.
- **Data:** LANL 2015 (58 days; flows, authentication, DNS, processes, and labelled red-team
  logins; CC0 on request); LANL 2017 (about 90 days of NetFlow and Windows logs with no known
  attack: a benign background to inject into); DARPA OpTC (host telemetry plus Zeek events,
  three attacks, two with lateral movement, with a ground-truth document). Apruzzese et al.
  say part of their own flow data is public.

### 12. Security Onion 3

From Security Onion's release posts (read):

- "Security Onion 2.4 will reach End Of Life (EOL) on October 1, 2026." ThreatBridge's README
  is written for 2.4.
- 3.0.0 (2026-03-31): "3.0 no longer includes Stenographer and so full packet capture is
  handled by Suricata." The PCAP paths (D12) need checking against that.
- 3.2.0 ships Elasticsearch 9.3.7 and Zeek 8.0.9; 3.3.0 Elasticsearch 9.4.5. The posts say
  nothing about changes to the connection records' fields.
- Pro features listed include "MCP Server", "External API", "Onion AI", an agentic framework
  and "Agent Studio". A separate MCP server for ThreatBridge (FTODO-2) would sit beside one
  the platform already sells; exposing ThreatBridge's queries *to* it may be the better fit.

## Patents seen (not a search, not legal advice)

| Patent | Holder | Priority | Status shown | What it covers, as read |
|---|---|---|---|---|
| US11770387B1, "Graph-based detection of lateral movement in computer networks" (continuation US11956260B2) | Rapid7 | 2020-07-17 | active, to 2041-03-20 | **read (claim 1 verbatim).** Connection data with times; connection graphs with anomalies; graphs ranked by a metric based on highest node degree; "a series of nodes linked by a sequence of time-ordered connections"; a path metric decides suspected attack paths; output. Dependent claims: new protocol or destination as anomalies, scanners and whitelisted connections excluded, SSH/WinRM/RDP/SMB, ranking by links, protocols, new nodes, new links. The description's example uses "within 24 hours". |
| US11831667B2, "Identification of time-ordered sets of connections to identify threats to a datacenter" | VMware | 2021-07-09 | active, to 2041-08-16 | **abstract (claim summarised, not verbatim).** Datacenter nodes; each edge has the time period its connection was active; on an anomalous event, paths whose edges are ordered so each period encompasses the next. |
| US10505954B2, "Detecting malicious lateral movement across a computer network" | Microsoft | 2017-06-14 | active, to 2037-12-26 | **abstract (claim summarised, not verbatim).** Graph of computers and accounts from connections and logons; edge weights by rarity; paths filtered by time constraints and ranked by a path-rate score. The Latte paper's system. |
| Others | LANL (path scanning, US9560065 and family), NEC (PrioTracker application), GWU (US11856013), and US10462169B2, US11658992B2, US11997120 | | | **search** only. |

Two facts a patent attorney will want: the time-ordered flow-sequence rule with a maximum
delay, and path ranking by novelty, ports and subnets, were published in October 2017
(Apruzzese et al.); and ThreatBridge today has no anomaly scoring or ranking, which several of
these claims recite. Whether any claim reads on the product, now or after item 1, is a legal
question this review cannot answer.

## Sources, by theme

**The same rule on flows**
- Apruzzese, Pierazzi, Colajanni, Marchetti, "Detection and Threat Prioritization of Pivoting
  Attacks in Large Networks", IEEE TETC 8(2), 2020 (online 2017). **read.** A pivoting flow
  sequence: consecutive flows adjacent, each host once, in time order, at most ε_max apart.
  Worst case O(m^Lmax · log m · τ); most runs under 2 minutes for 12 hours of traffic.
  <https://cris.unibo.it/handle/11585/811586>
- Husák, Apruzzese, Yang, Werner, "Towards an Efficient Detection of Pivoting Activity",
  IFIP/IEEE IM 2021. **abstract.** Extending the method to external traffic "produces
  overwhelming entries, most of which unrelated to pivoting"; they reduce false positives with
  expert rules and machine learning. <https://www.muni.cz/en/research/publications/1753378>
- Neil et al., "Scan Statistics for the Online Detection of Locally Anomalous Subgraphs",
  Technometrics 2013. **search.** Path-shaped scan windows over LANL NetFlow.

**Paths over logins**
- Ho et al., "Hopper: Modeling and Detecting Lateral Movement", USENIX Security 2021.
  **read** (sections 4 to 6). A login causes another if it reached the other's source machine
  within the 24 hours before. <https://www.usenix.org/conference/usenixsecurity21/presentation/ho>
- Liu, Stokes et al., "Latte: Large-Scale Lateral Movement Detection", MILCOM. **abstract.**
  Forensic analysis from a known infected machine; rare paths filtered by a remote-execution
  detector. <https://www.microsoft.com/en-us/research/publication/latte-large-scale-lateral-movement-detection/>
- Bowman et al., RAID 2020; King and Huang, "Euler", NDSS 2022; Khoury et al., "Jbeil", IEEE
  S&P 2024. **search.** Learned link prediction on authentication graphs. Useful later as a
  scoring signal; they need training data ThreatBridge does not have.

**Causal tracking on hosts**
- King and Chen, "Backtracking Intrusions", SOSP 2003. **search.** Backward from a detection
  point through process and file dependencies to the entry point.
- Liu et al., "Towards a Timely Causality Analysis for Enterprise Security" (PrioTracker),
  NDSS 2018. **search** (authors' slides).
- Hassan et al., "NoDoze", NDSS 2019. **search** (authors' slides).
  <https://www.ndss-symposium.org/ndss-paper/nodoze-combatting-threat-alert-fatigue-with-automated-provenance-triage>
- Li et al., "Threat Detection and Investigation with System-level Provenance Graphs: A
  Survey", 2020. **search.** On dependency explosion. <https://arxiv.org/abs/2006.01722>

**Temporal graphs**
- Kempe, Kleinberg, Kumar, "Connectivity and Inference Problems for Temporal Networks", JCSS
  2002. **search.** Defines time-respecting paths.
- Wu et al., "Path Problems in Temporal Graphs", VLDB 2014. **search.**
  <https://www.microsoft.com/en-us/research/publication/path-problems-in-temporal-graphs/>
- Zhang and Paxson, "Detecting Stepping Stones", USENIX Security 2000. **abstract.**
  <https://www.usenix.org/legacy/events/sec00/zhangstepping.html>

**Tools and products**
- Arkime, Connections page. **search** (the baseline options come from third-party
  integration documentation). <https://arkime.com/>
- ExtraHop activity maps. **abstract** (product documentation, version 9.4).
  <https://docs.extrahop.com/9.4/activity-maps-faq>
- Vectra attack graphs. **abstract** (vendor blog and release notes).
  <https://www.vectra.ai/blog/vectra-ai-platform-visualizes-multi-domain-modern-attacks-with-attack-graphs>
- Microsoft Defender for Identity, lateral movement paths. **abstract.** Possible paths to
  sensitive accounts from permissions and sessions, per 48 hours.
  <https://learn.microsoft.com/defender-for-identity/understand-lateral-movement-paths>
- BloodHound. **search.** Possible paths from directory relationships, not from traffic.
- RITA. **abstract.** <https://github.com/activecm/rita>
- Community ID. **abstract.** <https://docs.securityonion.net/en/2.4/community-id.html>
- Zeek logs. **abstract.** <https://docs.zeek.org/en/master/logs/known-and-software.html>,
  <https://docs.zeek.org/en/master/logs/smb.html>
- RFC 5103, bidirectional flow export. **abstract.** <https://www.rfc-editor.org/rfc/rfc5103>
- cytoscape-fcose. **abstract.** <https://blog.js.cytoscape.org/2021/02/08/fcose-2.0.0-release/>

**Platform**
- Security Onion 3.0.0, 3.2.0, 3.3.0 release posts. **read.**
  <https://blog.securityonion.net/2026/03/security-onion-300-now-available-with.html>,
  <https://blog.securityonion.net/2026/07/security-onion-320-now-available-with.html>,
  <https://blog.securityonion.net/2026/09/>

**Data**
- LANL, "Comprehensive, Multi-Source Cyber-Security Events", 2015. **abstract.**
  <https://csr.lanl.gov/data/cyber1/>
- LANL, "Unified Host and Network Data Set", 2017. **abstract.** <https://csr.lanl.gov/data/2017/>
- DARPA OpTC. **search.** <https://github.com/FiveDirections/OpTC-data>

**Patents**
- <https://patents.google.com/patent/US11770387B1/en>,
  <https://patents.google.com/patent/US11831667B2/en>,
  <https://patents.google.com/patent/US10505954B2/en>

## What this review did not cover

- No systematic patent search, and no reading of any claim set beyond those marked.
- Commercial products are described from their vendors' pages; none was used.
- Husák et al. (2021) and its 2024 follow-up could not be read in full: they are the most
  direct account of what makes flow-based path finding noisy, and worth getting.
- Security Onion 3.4.0's post and the 3.x documentation for its API and MCP server were not
  read.
- Nothing was searched on visual encodings for time on graphs beyond layout stability.
