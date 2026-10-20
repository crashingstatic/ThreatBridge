# ThreatBridge

A companion tool for **Security Onion 2.4**. When an analyst finds an IOC in SOC, they send the IP (and the event's time) to a connection map. The map shows either:

- **Inbound (past)**: hosts that connected **to** the IOC host in the window **before** the event.
- **Outbound (future)**: hosts the IOC host connected **to** in the window **after** the event.

Click any host to expand it. Hops are *time-chained*: an outbound peer's next hop starts at the time it was first contacted, and an inbound peer's next hop ends at the time it was last seen. This lets you follow a lateral-movement chain forward or an entry path backward.

**Right-click a connection (edge)** → *Filter SOC Dashboards*. This opens SOC Dashboards filtered to every conversation between those two hosts, in either direction, **up to the IOC time**.

Data sources: Zeek `conn` records in Security Onion's Elasticsearch (`event.dataset` = `conn` / `zeek.conn`), or, for post-mortem work, tcpdump captures and nfdump (nfcapd) files. See [Post-mortem mode](#post-mortem-mode-pcap-and-netflow-files).

## Features

| | |
|---|---|
| Launch from SOC | Two SOC actions on an IP value: *inbound (past)* and *outbound (future)*. You can switch direction on the map. |
| Peer selection | **Top N** (most connections) or **Bottom N** (rarest). Default N = 50. Bottom N is **exact**: it counts every distinct peer, up to 10,000 (`TB_RARE_SCAN_CAP`). Beyond that the map shows a warning that the list may be incomplete. |
| Exclude list | Shared across all analysts and editable in the UI (side panel, or right-click a host). Takes IPs or CIDRs. Applied to both Top and Bottom. Stored in `/data/exclude.json`. No audit trail. |
| Time window | 24h per hop by default. Adjustable on the map, up to `TB_MAX_WINDOW` (30d). |
| Auth | **Mutual TLS.** Connections without a client cert signed by the ThreatBridge CA fail at the TLS handshake. |

## Post-mortem mode (PCAP and NetFlow files)

```bash
pip install -r requirements.txt
python -m threatbridge --case /cases/incident-42/      # files or directories, in any mix
# browse to http://127.0.0.1:5055/
```

- **Inputs.** tcpdump captures in classic pcap format, and nfcapd files.
  - Supported pcap link types: Ethernet, Linux `any` (SLL/SLL2), raw IP and loopback, with µs or ns timestamps.
  - pcapng is not supported; convert it with `editcap -F pcap in.pcapng out.pcap`.
  - Directories are searched recursively; other files are skipped.
  - nfcapd files are read with the `nfdump` binary (tested with 1.7.3). Set `TB_NFDUMP` if it is not on `PATH`.
- **One edge per connection,** from initiator to responder, like a Zeek conn record.
  - A TCP connection ends at a RST, at a new SYN after a FIN, or after 5 minutes idle. UDP and ICMP end after 1 minute idle.
  - Rotated captures (`tcpdump -C` / `-G`) are read in capture order, so a connection that spans files stays one flow.
- **NetFlow records are one-way, so the two halves are merged.** The half that started first is the initiator.
  - Sometimes timing can't tell: both halves start in the same millisecond, or one half is missing.
  - Then a well-known port (<1024) talking to an ephemeral port marks the responder.
- **Default anchor.** With no anchor time, the map looks back from the end of the data (inbound) or forward from its start (outbound).
- **SOC pivots** are hidden in this mode.

### Threat lines, compromised hosts and attack paths

These need the whole graph, so they work in post-mortem mode only.

All three follow one rule: a hop A → B counts only if it starts after the attacker could have been on A, and within the **Window** of that. That is the rule you apply by hand when you expand hosts. Searches stop after 6 hops (`TB_THREAT_HOPS`). Excluded hosts are never crossed.

- **Threat line: left-click a connection.**
  - *Earlier hosts (violet):* those that could have reached its source before the connection.
  - *Later hosts (teal):* those its destination could have reached afterwards.
  - Hosts not yet on the map are added, everything else is faded, and clicking the background clears it.
  - Each host is shown with its single best hop: the earliest arrival going forward, the latest departure going back.
  - A line stops at 300 hosts per direction (`TB_THREAT_MAX_HOSTS`) and says so when it does.
- **Compromised hosts: right-click a host, or use the side panel.**
  - Mark a host at its anchor time, at a time you enter, or with the time unknown.
  - The list is shared and kept in `compromised.json` (`TB_COMPROMISED_FILE`).
- **Attack paths:** recomputed after every change to the compromised or exclude lists, and drawn in red.
  - A path from A to B must leave A after A's compromise time and reach B no later than B's.
  - With A's time unknown, its first hop may happen at any point in the data.
  - Click a path in the side panel to focus on it.
- **Timing in testing:** 975k flows between 2,910 hosts, with one host pair holding 106k of them.
  - A threat line through that busiest connection took 0.45 s.
  - Paths among 10 very busy compromised hosts took 4.4 s.
- **Everything is held in memory.** A 93 MB capture of 1.25M flows took 42 s and about 1 GB of RAM in testing.
- **Don't load overlapping evidence.** A pcap and NetFlow of the same traffic are counted twice.
- **The command above serves plain HTTP on 127.0.0.1.** To share the map, run it under gunicorn with mutual TLS, as for Security Onion. Use `TB_BACKEND=case TB_CASE_PATHS=/cases/incident-42 TB_WORKERS=1`; each worker loads its own copy of the data.

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

### Things to verify on your install

Deployment on a live Security Onion install has **not been tested**. These points came from memory of SO 2.4 and need checking:

1. **Where custom SOC actions are configured** in your 2.4.x release, and the `{:soc_timestamp}` placeholder in the action link. If the timestamp doesn't come through, the map falls back to "now".
2. **Whether SOC Dashboards accepts `@timestamp:[* TO "…"]`** in the `q=` URL parameter. The Dashboards time picker also still applies, so widen it to cover the history you want. Set `TB_PIVOT_TIME_CLAUSE=false` to drop the clause.
3. **`event.dataset` values** for Zeek conn logs (`TB_DATASETS`, default `conn,zeek.conn`). Also `TB_ES_INDEX` (default `logs-*`).
4. **The CA that signed Elasticsearch's cert** (`SO_CA`, default `/etc/pki/ca.crt`).
5. **The host firewall:** port 5443/tcp must be allowed from analyst workstations in SO's firewall configuration.
6. **Which existing SO Elasticsearch account to reuse.** It needs read access to the conn indices. A dedicated read-only role would limit the blast radius if the env file leaks.

## Configuration (env vars)

| Var | Default | |
|---|---|---|
| `TB_BACKEND` | `elastic` | `elastic` (Security Onion), `case` (files), `demo` |
| `TB_CASE_PATHS` | – | `case` backend: files/directories, separated by `:` |
| `TB_NFDUMP` | `nfdump` | nfdump binary for nfcapd files |
| `TB_ES_URL` / `TB_ES_USER` / `TB_ES_PASS` | `https://localhost:9200` | Elasticsearch |
| `TB_ES_CA` / `TB_ES_VERIFY` | – / `true` | TLS verification for Elasticsearch |
| `TB_ES_INDEX` | `logs-*` | |
| `TB_DATASETS` | `conn,zeek.conn` | empty = no dataset filter |
| `TB_FIELD_SRC/DST/TS/DPORT/DATASET` | ECS names | |
| `TB_SOC_URL` / `TB_SOC_PATH` | `https://securityonion` / `/#/dashboards?q={query}` | pivot target |
| `TB_PIVOT_TIME_CLAUSE` | `true` | bound pivots at the IOC time |
| `TB_WINDOW` / `TB_MAX_WINDOW` | `24h` / `30d` | |
| `TB_LIMIT` / `TB_MAX_LIMIT` | `50` / `200` | |
| `TB_RARE_SCAN_CAP` | `10000` | exact Bottom-N scan limit |
| `TB_EXCLUDE_FILE` | `/data/exclude.json` (container) | |
| `TB_COMPROMISED_FILE` | `/data/compromised.json` (container) | hosts marked compromised |
| `TB_THREAT_HOPS` / `TB_THREAT_MAX_HOSTS` | `6` / `300` | threat line and attack path limits |
| `TB_TLS_CERT` / `TB_TLS_KEY` / `TB_TLS_CLIENT_CA` | `/certs/…` | mTLS (gunicorn) |

## Requirements

Requirement IDs, current status and design decisions: [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md).

## Development

```bash
pip install -r requirements.txt pytest
python -m pytest
TB_BACKEND=demo python -m threatbridge --port 5055   # fake data, plain HTTP, localhost only
TB_PERF=1 python -m pytest -s tests/test_perf.py    # PRF-1/PRF-2: 1.25M flows, ~1 minute
```

The nfcapd test needs `nfdump` installed (`apt install nfdump`); without it, it is skipped locally.

### CI

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | Checks |
|---|---|
| Unit tests | pytest on Python 3.11 and 3.12, including reading a real nfcapd file (nfdump from apt) |
| Shellcheck | `scripts/`, `deploy/`, `tests/` shell scripts |
| Security scan | `pip-audit` (known-vulnerable dependencies), `bandit -ll` (medium+ Python security issues) |
| Docker build + mTLS | Generates a throwaway PKI, builds and starts the container with `deploy/run.sh` (demo backend), then `tests/mtls_check.sh`. No cert and foreign-CA certs must be refused, a valid cert accepted, and writes without the CSRF header rejected. |
| UI tests | Headless Chromium. Both scripts fail on any console/CSP error, and screenshots are uploaded as an artifact. `tests/ui_smoke.mjs` (demo backend) loads the map as a SOC action would, expands a hop, right-clicks an edge, checks the SOC pivot URL and round-trips the exclude list. `tests/ui_case.mjs` runs post-mortem mode on a pcap made by `tests/make_case.py`: it traces a threat line, marks two hosts compromised, checks the attack path, then unmarks one. |

CI cannot reach a real Security Onion, so the items under *Things to verify on your install* still need a manual check.

Layout:

| Path | Contents |
|---|---|
| `threatbridge/query.py` | Input validation, Elasticsearch and SOC query builders |
| `threatbridge/model.py` | The `Flow` record shared by the file readers |
| `threatbridge/sources/` | pcap and nfcapd readers |
| `threatbridge/graph.py` | The NetworkX `MultiDiGraph`, one edge per flow |
| `threatbridge/analysis.py` | Time-ordered searches: threat lines and attack paths |
| `threatbridge/excludes.py`, `compromised.py` | Shared lists, stored as JSON files |
| `threatbridge/backends.py` | The data backends behind the map: Elasticsearch, case (files) and demo |
| `threatbridge/app.py` | The HTTP API |
| `threatbridge/static/` | The Cytoscape.js UI, vendored so it works air-gapped |

## Legacy

The original offline PCAP visualiser (Tkinter/Scapy/Bokeh) is in `legacy/PCAPMap.py`.

## License

MIT. Cytoscape.js is MIT licensed; see `threatbridge/static/vendor/cytoscape.LICENSE`.
