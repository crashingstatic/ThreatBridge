# ThreatBridge

A companion tool for **Security Onion 2.4**. When an analyst finds an IOC in SOC, they send the IP (and the event's time) to a connection map. The map shows either:

- **Inbound (past)**: hosts that connected **to** the IOC host in the window **before** the event.
- **Outbound (future)**: hosts the IOC host connected **to** in the window **after** the event.

Click any host to expand it. Hops are *time-chained*: an outbound peer's next hop starts at the time it was first contacted, and an inbound peer's next hop ends at the time it was last seen. This lets you follow a lateral-movement chain forward or an entry path backward.

**Click a connection (edge)** to list its flows in time order; in Security Onion mode each flow can fetch its packets from the sensor that saw it. **Right-click it** → *Filter SOC Dashboards*. This opens SOC Dashboards filtered to every conversation between those two hosts, in either direction, **up to the IOC time**.

Data sources: Zeek `conn` records in Security Onion's Elasticsearch (`event.dataset` = `conn` / `zeek.conn`), or, for post-mortem work, tcpdump captures and nfdump (nfcapd) files. See [Post-mortem mode](#post-mortem-mode-pcap-and-netflow-files).

## Features

| | |
|---|---|
| Launch from SOC | Two SOC actions on an IP value: *inbound (past)* and *outbound (future)*. You can switch direction on the map. |
| Peer selection | **Top N** (most connections) or **Bottom N** (rarest). Default N = 50. Bottom N is **exact**: it counts every distinct peer, up to 10,000 (`TB_RARE_SCAN_CAP`). Beyond that the map shows a warning that the list may be incomplete. |
| Exclude list | Shared across all analysts and editable in the UI (side panel, or right-click a host). Takes IPs, CIDRs or domain names (see [Domain names](#domain-names-on-the-exclude-list)). Applied to both Top and Bottom. Stored in `/data/exclude.json`. No audit trail. Invalid entries from a hand edit are skipped with a warning; a file that is not valid JSON is reported and never overwritten. |
| Time window | 24h per hop by default. Adjustable on the map, up to `TB_MAX_WINDOW` (30d). |
| Time range | Optional *Range from* / *Range to* (UTC) on the map. It limits everything: expansions, the default anchor, flow lists, threat lines, attack paths and SOC pivots. Kept in the map's URL. |
| Flow list | Clicking a connection lists its flows oldest first, 50 per page, with start, protocol, ports, duration, packets and bytes. Security Onion returns at most the first 10,000 flows of a connection; narrow the time range to page past them. |
| PCAP | Security Onion mode: each flow links to SOC's PCAP job for it, and with a SOC API client ThreatBridge downloads the PCAP itself. See [PCAP for a flow](#pcap-for-a-flow). |
| Saved maps | Side panel → *Saved maps*: save the map under a name for every analyst (`TB_SESSIONS_DIR`), or to a JSON file to keep or pass on. Opening one brings back the hosts where they were, the connections, the highlights, the view and the toolbar; attack paths are recomputed from the current compromised list. Saving under a name that exists asks first. |
| Progress | A request still running after a second shows its elapsed time and a *Cancel* button. Building a case shows each stage, the file being read, and the time left, on the terminal or in the log. |
| API | The JSON API behind the map is documented as a stable interface in [docs/API.md](docs/API.md). |
| Auth | **Mutual TLS.** Connections without a client cert signed by the ThreatBridge CA fail at the TLS handshake. |

## Post-mortem mode (PCAP and NetFlow files)

```bash
pip install -r requirements.txt
python -m threatbridge --case /cases/incident-42/      # files or directories, in any mix
# --db /work/incident-42.db keeps the parsed flows and reuses them while the evidence is unchanged
# browse to http://127.0.0.1:5055/
```

- **Inputs.** tcpdump captures in classic pcap format, and nfcapd files.
  - Supported pcap link types: Ethernet, Linux `any` (SLL/SLL2), raw IP and loopback, with µs or ns timestamps.
  - pcapng is not supported; convert it with `editcap -F pcap in.pcapng out.pcap`.
  - Directories are searched recursively; other files are skipped. A file named more than once (directly, through its directory, or through a symlink) is read once.
  - A capture cut off mid-packet (tcpdump killed) is read up to its last whole packet.
  - Packets cut by the snap length (`tcpdump -s`) still count, as long as the ports were captured. IPv4 and IPv6 fragments after the first are skipped.
  - nfcapd files are read with the `nfdump` binary (tested with 1.7.3). Set `TB_NFDUMP` if it is not on `PATH`. The file nfcapd is still writing (`nfcapd.current.*`) is skipped.
- **One edge per connection,** from initiator to responder, like a Zeek conn record.
  - A TCP connection ends at a RST, at a new SYN after a FIN, or after 5 minutes idle. UDP and ICMP end after 1 minute idle.
  - Rotated captures (`tcpdump -C` / `-G`) are read in capture order, so a connection that spans files stays one flow.
- **Several files are read at once,** one per CPU (`TB_READ_WORKERS`; `1` reads one at a time).
  - Worker processes decode the packets; the connections are then followed packet by packet in capture order, so the flows are exactly those of reading one file at a time. One large file is read by one process.
  - In testing on 4 CPUs, 8 rotated captures of TCP traffic (538 MB) were read in 4.2 s instead of 15.5 s. With every packet a connection of its own (1.2M), 12.5 s instead of 23.7 s: following the connections is then most of the work.
  - While a case is built, the terminal shows the stage, the file, how far it has got and the time left, e.g. `Reading 8 evidence file(s): 41%, file 4 of 8, 612,330 packets, about 3 s left`. Without a terminal (gunicorn, Docker) the same goes to the log every 10 seconds.
- **NetFlow records are one-way, so the two halves are merged.** The half that started first is the initiator.
  - Sometimes timing can't tell: both halves start in the same millisecond, or one half is missing.
  - Then a well-known port (<1024) talking to an ephemeral port marks the responder.
- **Default anchor.** With no anchor time, the map looks back from the end of the data (inbound) or forward from its start (outbound). With a time range set, from the range's end or start when it lies inside the data.
- **SOC pivots** are hidden in this mode.

### Domain names on the exclude list

Enter a name such as `updates.example.com` and it stands for every address it resolved to.

- **Capture answers:** what the name pointed to during the incident, taken from the DNS answers in the pcaps (UDP port 53). CNAME chains are followed: a name and its aliases share all addresses in the answer. Answer records for names outside the question's chain are ignored, so a crafted response can't tie a benign name to an attacker's address.
- **In Security Onion mode** the capture answers come from the sensors' Zeek DNS records in Elasticsearch (`event.dataset` `dns` or `zeek.dns`; the question in `dns.query.name`, the addresses in `dns.resolved_ip`; see `TB_DNS_DATASETS`, `TB_FIELD_DNS_QUERY`, `TB_FIELD_DNS_IP`). All domain entries are looked up in one request, cached for `TB_DNS_TTL`, up to 1,000 addresses each. Zeek records every address in an answer without its owner name, so the CNAME-chain check above can't be made there: a crafted response can tie a name to any address.
- **Live lookup:** done through the system resolver and cached for 5 minutes (`TB_DNS_TTL`, `TB_DNS_TIMEOUT`).
  - A name behind a CDN may resolve differently now than during the incident, which is why the capture answers come first.
  - Set `TB_LIVE_DNS=false` on an isolated analysis machine; otherwise each lookup waits for its timeout (2 s).
- **Wildcards:** `*.example.com` matches subdomains in the capture answers only, since a live lookup can't expand a wildcard.
- **Where to see it:** the side panel shows what each name resolved to and from which source. Hosts at those addresses leave the map.
- **Caution:** excluding a name excludes its addresses for all traffic. On shared hosting or a CDN that can hide unrelated hosts, attacker infrastructure included.

### Threat lines, compromised hosts and attack paths

These need the whole graph, so they work in post-mortem mode only.

All of them follow one rule: a hop A → B counts only if A opened the connection, after the attacker could have been on A, and within the **Window** of that. That is the rule you apply by hand when you expand hosts. Searches stop after 6 hops (`TB_THREAT_HOPS`). Excluded hosts are never crossed, and flows outside the time range are ignored.

The searches are exact under that rule. An attacker may have reached a host at several times, and a later arrival can allow a hop an earlier one can't (its Window ends later), so every arrival time is kept, not only the earliest.

- **Threat line: left-click a connection.**
  - *Earlier hosts (violet):* those that could have reached its source before the connection.
  - *Later hosts (teal):* those its destination could have reached afterwards.
  - Hosts not yet on the map are added, everything else is faded, and clicking the background clears it.
  - Each host is drawn with one hop: the fewest hops from the connection, then the earliest arrival going forward or the latest departure going back.
  - A line stops at 300 hosts per direction (`TB_THREAT_MAX_HOSTS`) and says so when it does.
- **Compromised hosts: right-click a host, or use the side panel.**
  - Mark a host at its anchor time, at a time you enter, or with the time unknown.
  - The list is shared and kept in `compromised.json` (`TB_COMPROMISED_FILE`).
- **Attack paths:** recomputed after every change to the compromised or exclude lists, and drawn in red.
  - A path from A to B must leave A after A's compromise time and reach B no later than B's.
  - With A's time unknown, its first hop may happen at any point in the data.
  - Every path counts, not just the best one. The side panel groups them by pair of hosts and lists the first 10 of each, shortest first; *Show all* opens the rest in *Paths between two hosts*.
  - Click a path in the side panel to focus on it.
- **Paths between two hosts: side panel, or right-click a host → *Find paths from / to this host*.**
  - For example: 10.4.0.2 is compromised, and later 10.5.0.3, on another subnet, matches a different IOC. Enter both and the map draws, in pink, every way an attacker on 10.4.0.2 could have reached 10.5.0.3 over connections in the evidence.
  - A path never visits a host twice. Each is listed with one chain of flows that proves it: the earliest arrival, and before each hop the latest flow that leads to it.
  - The IOC times are optional. With a time for the first host, its first hop must start within the Window after it; with one for the second, the path must reach it by then.
  - Shortest paths first, up to 500 (`TB_MAX_PATHS`). When there are more, the panel says so; narrow them with the Window, the hop limit, the time range or the exclude list.
- **Timing in testing** (`TB_PERF=1 pytest -s tests/test_perf.py`, also run in CI) on an office-like week: 1M flows, 2,500 hosts, three servers everyone talks to, and one connection with 100k flows.
  - Expanding the busiest host took 0.15 s, and the last page of that connection's flows 0.01 s.
  - A threat line through that connection took 0.6 s; every path between two busy hosts, 0.08 s.
  - Attack paths among the ten busiest hosts took 0.33 s. With an IOC time on each they took 4.9 s, recomputed in the background while the map stays usable.
- **Storage.** The flows go into a SQLite file. The map and searches use a graph holding one edge per host pair, with the start times of that pair's flows.
  - Without `--db` (`TB_CASE_DB`) the file is temporary. With it, the case reopens without re-reading the evidence until a file is added or changed.
  - Nothing is written to the evidence directories. Keep the `--db` file with your working files. Next to it, `<file>.lock` lets several workers share it: one builds it, the others wait and reuse it.
- **Loading time and memory in testing** (same test): the worst case is every flow between a different pair of hosts. A 93 MiB capture of 1.25M minimum-size packets took 35 s to build and 13 s to reopen with `--db`, and peaked at 1.6 GiB of memory.
- **Don't load overlapping evidence.** A pcap and NetFlow of the same traffic are counted twice.
- **The command above serves plain HTTP on 127.0.0.1.** To share the map, run it under gunicorn with mutual TLS, as for Security Onion. Use `TB_BACKEND=case TB_CASE_PATHS=/cases/incident-42 TB_WORKERS=1`; each worker loads its own copy of the data (with `TB_CASE_DB` set, they share the parsed flows).

## Deploy on the Security Onion manager

```bash
git clone <this repo> /opt/threatbridge && cd /opt/threatbridge

# 1. PKI (private CA). Keep certs/ca.key safe, offline if possible.
scripts/make-certs.sh ca
scripts/make-certs.sh server so-manager.example.internal 192.0.2.10
scripts/make-certs.sh client alice      # -> certs/alice.p12 (prompts for an export password)

# 2. Config
cp deploy/threatbridge.env.example deploy/threatbridge.env && chmod 600 deploy/threatbridge.env
$EDITOR deploy/threatbridge.env         # ES user/pass (existing SO account), TB_SOC_URL

# 3. Build and run (host networking, read-only rootfs, all caps dropped)
SO_CA=/etc/pki/ca.crt deploy/run.sh
```

Each analyst imports their `.p12` into the browser and trusts `certs/ca.crt`. Then they browse to `https://<manager>:5443/`.

### Add the SOC actions

Edit `securityonion/soc-actions.json`: replace `THREATBRIDGE_HOST` with the server cert's DNS name. Then add both entries to SOC's action list (SOC → Administration → Configuration; search for `actions`). After that, clicking an IP value in Alerts, Hunt or Dashboards offers *ThreatBridge: inbound (past)* and *ThreatBridge: outbound (future)*.

### PCAP for a flow

Each flow in a connection's flow list has a **PCAP in SOC** link. It is SOC's own PCAP action (`/joblookup?esid=…&time=…`): SOC finds the connection log, has the sensor that saw it (`observer.name`) extract the packets, and shows them under the analyst's SOC login.

With a SOC API client, a **Download PCAP** button also appears: ThreatBridge has the sensor extract the packets through SOC's Connect API and hands the analyst the PCAP file.

1. This needs a Security Onion Pro licence with the API feature (2.4.120 or later) and Hydra enabled (SOC → Configuration → `hydra > enabled`).
2. Create the client in SOC → Administration → API Clients, with the permissions `events/read`, `jobs/read` and `jobs/write` only.
3. Put its ID and secret in `deploy/threatbridge.env` (`TB_SOC_CLIENT_ID`, `TB_SOC_CLIENT_SECRET`). `TB_SOC_CA` is the CA of SOC's certificate if it is not the one in `TB_ES_CA`.
4. A download waits for the sensor for up to `TB_PCAP_TIMEOUT` seconds (90). A job that takes longer may still finish in SOC; the message links to it.

Anyone with a ThreatBridge client certificate can fetch PCAP through this API client.

### Things to verify on your install

Deployment on a live Security Onion install has **not been tested**. These points came from memory of SO 2.4 and need checking:

1. **Where custom SOC actions are configured** in your 2.4.x release, and the `{:soc_timestamp}` placeholder in the action link. If the timestamp doesn't come through, the map falls back to "now".
2. **Whether SOC Dashboards accepts `@timestamp:[* TO "…"]`** in the `q=` URL parameter. The Dashboards time picker also still applies, so widen it to cover the history you want. Set `TB_PIVOT_TIME_CLAUSE=false` to drop the clause.
3. **`event.dataset` values** for Zeek conn logs (`TB_DATASETS`, default `conn,zeek.conn`). Also `TB_ES_INDEX` (default `logs-*`).
4. **The CA that signed Elasticsearch's cert** (`SO_CA`, default `/etc/pki/ca.crt`).
5. **The host firewall:** port 5443/tcp must be allowed from analyst workstations in SO's firewall configuration.
6. **Which existing SO Elasticsearch account to reuse.** It needs read access to the conn indices. A dedicated read-only role would limit the blast radius if the env file leaks.
7. **The fields the flow list reads:** `source.port`, `network.transport`, `event.duration` (seconds), `client.packets` + `server.packets`, and `client.ip_bytes` + `server.ip_bytes`. Values that are missing show as blank. Override with `TB_FIELD_SPORT`, `TB_FIELD_PROTO`, `TB_FIELD_DURATION`, `TB_FIELD_PACKETS` and `TB_FIELD_BYTES` (comma-separated, summed).
8. **Whether SOC Dashboards accepts `@timestamp:["…" TO "…"]` and `["…" TO *]`,** which pivots carry when a time range is set.
9. **The Zeek DNS records** (`event.dataset` `dns`, `dns.query.name`, `dns.resolved_ip`; taken from Security Onion's 2.4 ingest parser). The question name must be a keyword field: names are matched exactly and case-insensitively, `*.suffix` with a wildcard query.
10. **The PCAP links:** *PCAP in SOC* uses the same `/joblookup` link as SOC's own PCAP action. *Download PCAP* follows SOC's Connect API as published in its source (token, `/connect/joblookup/`, `/connect/job/{id}`, `/connect/stream/{id}`); it was tested against a stand-in, not a real SOC.

## Configuration (env vars)

| Var | Default | |
|---|---|---|
| `TB_BACKEND` | `elastic` | `elastic` (Security Onion), `case` (files), `demo` |
| `TB_CASE_PATHS` | – | `case` backend: files/directories, separated by `:` |
| `TB_CASE_DB` | – (temporary) | `case` backend: SQLite file for the flows, reused while the evidence is unchanged |
| `TB_READ_WORKERS` | `0` (one per CPU) | `case` backend: evidence files read at once, in worker processes; `1` reads one at a time |
| `TB_NFDUMP` | `nfdump` | nfdump binary for nfcapd files |
| `TB_ES_URL` / `TB_ES_USER` / `TB_ES_PASS` | `https://localhost:9200` | Elasticsearch |
| `TB_ES_CA` / `TB_ES_VERIFY` | – / `true` | TLS verification for Elasticsearch |
| `TB_ES_TIMEOUT` | `30` | seconds per Elasticsearch request |
| `TB_ES_INDEX` | `logs-*` | |
| `TB_DATASETS` | `conn,zeek.conn` | empty = no dataset filter |
| `TB_FIELD_SRC/DST/TS/DPORT/DATASET` | ECS names | |
| `TB_FIELD_SPORT/PROTO/DURATION` | `source.port` / `network.transport` / `event.duration` | flow list |
| `TB_FIELD_PACKETS` / `TB_FIELD_BYTES` | `client.packets,server.packets` / `client.ip_bytes,server.ip_bytes` | flow list; the fields are summed |
| `TB_DNS_DATASETS` | `dns,zeek.dns` | Zeek DNS records, for domain names on the exclude list; empty = no dataset filter |
| `TB_FIELD_DNS_QUERY` / `TB_FIELD_DNS_IP` | `dns.query.name` / `dns.resolved_ip` | their question name and answer addresses |
| `TB_SOC_URL` / `TB_SOC_PATH` | `https://securityonion` / `/#/dashboards?q={query}` | pivot target; also SOC's PCAP job links |
| `TB_SOC_CLIENT_ID` / `TB_SOC_CLIENT_SECRET` | – | SOC API client (Security Onion Pro): ThreatBridge downloads a flow's PCAP itself |
| `TB_SOC_CA` | `TB_ES_CA` | CA of SOC's certificate |
| `TB_PCAP_TIMEOUT` | `90` | seconds to wait for a sensor to extract a flow's PCAP |
| `TB_PIVOT_TIME_CLAUSE` | `true` | bound pivots at the IOC time and the time range |
| `TB_WINDOW` / `TB_MAX_WINDOW` | `24h` / `30d` | |
| `TB_LIMIT` / `TB_MAX_LIMIT` | `50` / `200` | |
| `TB_RARE_SCAN_CAP` | `10000` | exact Bottom-N scan limit |
| `TB_EXCLUDE_FILE` | `/data/exclude.json` (container) | |
| `TB_LIVE_DNS` / `TB_DNS_TTL` / `TB_DNS_TIMEOUT` | `true` / `300` / `2` | live lookups of domain names on the exclude list |
| `TB_COMPROMISED_FILE` | `/data/compromised.json` (container) | hosts marked compromised |
| `TB_SESSIONS_DIR` | `/data/sessions` (container) | saved maps, one JSON file each |
| `TB_THREAT_HOPS` / `TB_THREAT_MAX_HOSTS` | `6` / `300` | threat line and attack path limits |
| `TB_MAX_PATHS` | `500` | paths listed between two hosts |
| `TB_TLS_CERT` / `TB_TLS_KEY` / `TB_TLS_CLIENT_CA` | `/certs/…` | mTLS (gunicorn) |
| `TB_PORT` | `5443` (gunicorn) / `5055` (`python -m threatbridge`) | listening port |
| `TB_HOST` | `127.0.0.1` | listening address of `python -m threatbridge` (gunicorn binds all) |
| `TB_WORKERS` | `2` | gunicorn worker processes; each loads its own copy of a case |

## Requirements

Requirement IDs, current status and design decisions: [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md).
A step-by-step GUI test plan for every feature and requirement: [docs/TEST_PLAN.md](docs/TEST_PLAN.md).

## Development

```bash
pip install -r requirements.txt pytest
python -m pytest
TB_BACKEND=demo python -m threatbridge --port 5055   # fake data, plain HTTP, localhost only
TB_PERF=1 python -m pytest -s tests/test_perf.py    # PRF-1/2/3: 1.25M flows, a busy week; about a minute
```

The nfcapd test needs `nfdump` installed (`apt install nfdump`); without it, it is skipped locally.

### Mutation testing

[mutmut](https://github.com/boxed/mutmut) makes small changes to the code (a `<` becomes `<=`, a `continue` a `break`, an argument `None`) and checks that some test fails for each. Settings are in `setup.cfg`.

```bash
pip install mutmut
mutmut run --max-children 4        # ~7 minutes; results in mutants/ (ignored by git)
mutmut results                     # the survivors; `mutmut show <name>` for one
```

On 2026-10-25: 4,815 of 5,239 mutants caught (91.9%). The 424 survivors were reviewed. None is a missing test that matters; they change:

- text only: log messages and their arguments, error message wording, SQL keyword case, command-line help;
- performance only: caches, pruning in the path search, work skipped when the answer is already known, and whether files are read in worker processes or one at a time (both give the same flows, by design);
- the demo backend's random data;
- names nobody reads back: temporary files, and how a saved map's name is spelled on disk;
- nothing observable, e.g. a default value no caller relies on, a tie-break between equal choices, or an end point the interval code is allowed to repeat.

Run it again after changing the analysis or the readers, and look at the new survivors.

### CI

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | Checks |
|---|---|
| Unit tests | pytest on Python 3.11 and 3.12, including reading a real nfcapd file (nfdump from apt), files read in parallel giving the same flows as one at a time, worker processes sharing files, the command line, SOC's Connect API against a stand-in, and the README, `docs/API.md`, env example and SOC actions staying in step with the code |
| Performance | `TB_PERF=1 tests/test_perf.py`: 1.25M flows built within 5 minutes (PRF-1/2), and the interactive queries timed on a busy case (PRF-3) |
| Shellcheck | `scripts/`, `deploy/`, `tests/` shell scripts |
| Security scan | `pip-audit` (known-vulnerable dependencies), `bandit -ll` (medium+ Python security issues) |
| Docker build + mTLS | Generates a throwaway PKI, builds and starts the container with `deploy/run.sh` (demo backend), then `tests/mtls_check.sh`. No cert and foreign-CA certs must be refused, a valid cert accepted, and writes without the CSRF header rejected. |
| UI tests | Headless Chromium. Every script fails on any unexpected console/CSP error, and screenshots are uploaded as an artifact. `tests/ui_smoke.mjs` (demo backend) loads the map as a SOC action would, expands a hop, right-clicks an edge, checks the SOC pivot URL and the flows' PCAP links and download, and round-trips the exclude list. `tests/ui_case.mjs` runs post-mortem mode on a pcap made by `tests/make_case.py`: it traces a threat line, marks two hosts compromised, checks the attack path, then unmarks one. `tests/ui_actions.mjs` covers the rest: opening without parameters, errors, slow writes kept in order, left-click expansion, every host-menu action, the compromised form, attack paths answered out of order, "Show all" paths, paging flows, a time range from the URL, a failing server, a slow request cancelled, saved maps (shared and as a file), Fit and Clear. The job ends with `tests/js_coverage.mjs`, which lists what of `app.js` no browser test ran. |

CI cannot reach a real Security Onion, so the items under *Things to verify on your install* still need a manual check.

Layout:

| Path | Contents |
|---|---|
| `threatbridge/query.py` | Input validation, Elasticsearch and SOC query builders |
| `threatbridge/model.py` | The `Flow` record shared by the file readers |
| `threatbridge/sources/` | pcap and nfcapd readers; `workers.py` reads several files at once |
| `threatbridge/store.py` | The flows, in SQLite: counts, ports and details behind each edge |
| `threatbridge/graph.py` | The NetworkX `DiGraph`: one edge per host pair, with that pair's flow start times |
| `threatbridge/analysis.py` | Time-ordered searches: threat lines and attack paths |
| `threatbridge/excludes.py`, `compromised.py`, `jsonstore.py` | Shared lists, stored as JSON files that several workers can write |
| `threatbridge/sessions.py` | Saved maps, one JSON file each |
| `threatbridge/soc.py` | SOC's Connect API: a flow's PCAP from its sensor |
| `threatbridge/progress.py` | Progress of building a case, on the terminal or in the log |
| `threatbridge/domains.py` | Domain names on the exclude list, resolved from the capture and live DNS |
| `threatbridge/backends.py` | The data backends behind the map: Elasticsearch, case (files) and demo |
| `threatbridge/config.py` | Settings from the `TB_*` environment variables |
| `threatbridge/app.py` | The HTTP API (documented in `docs/API.md`) and the command line |
| `threatbridge/static/` | The Cytoscape.js UI, vendored so it works air-gapped |

## License

MIT. Cytoscape.js is MIT licensed; see `threatbridge/static/vendor/cytoscape.LICENSE`.
