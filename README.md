# ThreatBridge

A companion tool for **Security Onion 2.4**. When an analyst finds an IOC in SOC, they send the IP (and the event's time) to a connection map. The map shows either:

- **Inbound (past)**: hosts that connected **to** the IOC host in the window **before** the event.
- **Outbound (future)**: hosts the IOC host connected **to** in the window **after** the event.

Click any host to expand it. Hops are *time-chained*: an outbound peer's next hop starts at the time it was first contacted, and an inbound peer's next hop ends at the time it was last seen. This lets you follow a lateral-movement chain forward or an entry path backward.

**Right-click a connection (edge)** → *Filter SOC Dashboards*. This opens SOC Dashboards filtered to every conversation between those two hosts, in either direction, **up to the IOC time**.

Data source: Zeek `conn` records in Elasticsearch (`event.dataset` = `conn` / `zeek.conn`).

## Features

| | |
|---|---|
| Launch from SOC | Two SOC actions on an IP value: *inbound (past)* and *outbound (future)*. You can switch direction on the map. |
| Peer selection | **Top N** (most connections) or **Bottom N** (rarest). Default N = 50. Bottom N is **exact**: it counts every distinct peer, up to 10,000 (`TB_RARE_SCAN_CAP`). Beyond that the map shows a warning that the list may be incomplete. |
| Exclude list | Shared across all analysts and editable in the UI (side panel, or right-click a host). Takes IPs or CIDRs. Applied to both Top and Bottom. Stored in `/data/exclude.json`. No audit trail. |
| Time window | 24h per hop by default. Adjustable on the map, up to `TB_MAX_WINDOW` (30d). |
| Auth | **Mutual TLS.** Connections without a client cert signed by the ThreatBridge CA fail at the TLS handshake. |

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
| `TB_TLS_CERT` / `TB_TLS_KEY` / `TB_TLS_CLIENT_CA` | `/certs/…` | mTLS (gunicorn) |

## Requirements

Requirement IDs, current status and design decisions: [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md).

## Development

```bash
pip install -r requirements.txt pytest
python -m pytest
TB_BACKEND=demo python -m threatbridge --port 5055   # fake data, plain HTTP, localhost only
```

### CI

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | Checks |
|---|---|
| Unit tests | pytest on Python 3.11 and 3.12 |
| Shellcheck | `scripts/`, `deploy/`, `tests/` shell scripts |
| Security scan | `pip-audit` (known-vulnerable dependencies), `bandit -ll` (medium+ Python security issues) |
| Docker build + mTLS | Generates a throwaway PKI, builds and starts the container with `deploy/run.sh` (demo backend), then `tests/mtls_check.sh`. No cert and foreign-CA certs must be refused, a valid cert accepted, and writes without the CSRF header rejected. |
| UI smoke test | Headless Chromium (`tests/ui_smoke.mjs`). Loads the map as a SOC action would, expands a hop, right-clicks an edge, checks the SOC pivot URL, round-trips the exclude list, and fails on any console/CSP error. Screenshots are uploaded as an artifact. |

CI cannot reach a real Security Onion, so the items under *Things to verify on your install* still need a manual check.

Layout: `threatbridge/query.py` holds the input validation and the Elasticsearch and SOC query builders. `backends.py` holds the Elasticsearch backend (and a demo backend), `app.py` the HTTP API, and `static/` the Cytoscape.js UI (vendored, so it works air-gapped).

## Legacy

The original offline PCAP visualiser (Tkinter/Scapy/Bokeh) is in `legacy/PCAPMap.py`.

## License

MIT. Cytoscape.js is MIT licensed; see `threatbridge/static/vendor/cytoscape.LICENSE`.
