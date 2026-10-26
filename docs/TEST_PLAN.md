# ThreatBridge manual test plan

The automated tests run in CI on every push (`.github/workflows/ci.yml`):

- pytest, including the performance tests;
- three headless-browser suites against the map;
- the container with mutual TLS, checked with curl and in a browser.

[Section 4](#4-where-each-requirement-is-tested) lists where each requirement is tested. This
plan holds only what those tests can't check, and why:

- **How the map looks** (VIS-01, VIS-02). The browser tests check which colour class each host
  and connection gets, but whether the colours match the legend, and whether the map is
  readable, takes a person looking at it.
- **How the browser feels on a large case** (PRF-01). CI times the server's answers (PRF-3), but
  not how fast a real browser draws hundreds of hosts, or whether panning stays smooth while
  attack paths are recomputed.
- **A real Security Onion** (SO-01 to SO-06). CI can't reach one. It tests the Elasticsearch
  queries and SOC's Connect API against stand-ins. Field names, SOC actions, pivots, Zeek DNS
  records and PCAP jobs on a real install are only proven here. Setting up ENV-SO and running
  these tests covers the README's *Things to verify on your install*.

Contents:

1. [How to use this plan](#1-how-to-use-this-plan)
2. [Test environments](#2-test-environments)
3. [Tests](#3-tests)
4. [Where each requirement is tested](#4-where-each-requirement-is-tested)

## 1. How to use this plan

- **Title and Proves.** Each test's title names what it proves. Each step's *Proves* column says
  which feature or requirement that step shows. A test passes when every step's *Expect* holds.
  Write P (pass) or F (fail) in the *Result* column, and for an F, note what you saw.
- **Starting state** is what must be true before step 1. *Fresh state* means the server was
  started from the environment's commands with a new, empty work directory (`$W`).
- **Toolbar defaults:** Host / IOC IP blank, Anchor time blank, Direction *Inbound*, Window
  `24h`, Range from/to blank, Peers *Top*, N `50`.
- **"Map X inbound"** means: type X in *Host / IOC IP*, choose Direction *Inbound: who connected to
  the host (past)*, leave the other fields as the step says (otherwise as they are), and click
  **Map**. *Outbound* is *Outbound: who the host connected to (future)*.
- **Status line** is the line of text along the bottom of the toolbar. **Side panel** is the
  right-hand panel. An **edge label** is the text on a connection: `count · ports`, e.g. `1 · 445`.
- Exact texts are in `code`. A `…` in them marks a part that varies or doesn't matter, except in
  `Working… N s` and `Asking the sensor for the packets of A → B at T…`, where the map shows it.
  Capitals such as A, B, T and N, and words in <angle brackets>, stand for values the step names.
  Times are UTC.
- Use a desktop browser (Chrome, Chromium, Firefox or Edge) at a normal window size.

## 2. Test environments

Run the commands from the repository root. Install the dependencies once with
`python -m pip install -r requirements.txt pytest` (Python 3.11 or later). Stop a server with
Ctrl+C.

### ENV-DEMO: demo backend

Deterministic fake data.

```bash
export W=$(mktemp -d)
TB_BACKEND=demo TB_SOC_URL=https://so.example \
TB_EXCLUDE_FILE=$W/exclude.json TB_COMPROMISED_FILE=$W/compromised.json TB_SESSIONS_DIR=$W/sessions \
python -m threatbridge --port 5055
# browse to http://127.0.0.1:5055/
```

### ENV-CASE: the generated attack-chain case

```bash
export W=$(mktemp -d)
python tests/make_case.py $W/case
TB_LIVE_DNS=false TB_MAX_PATHS=11 \
TB_EXCLUDE_FILE=$W/exclude.json TB_COMPROMISED_FILE=$W/compromised.json TB_SESSIONS_DIR=$W/sessions \
python -m threatbridge --case $W/case --port 5056
# browse to http://127.0.0.1:5056/
```

The capture holds an attack chain on 2024-05-01:

1. 203.0.113.66 → 10.0.0.5:443 at 12:00;
2. 10.0.0.5 → 10.0.0.9:445 at 12:10;
3. 10.0.0.9 → 10.0.0.20:3389 at 12:20;

and, off the chain:

- a shortcut, 10.0.0.5 → 10.0.0.20:5985 at 12:15;
- 10.0.0.77 → 10.0.0.9:80 at 12:30;
- twelve two-hop routes from 10.0.2.1 to 10.0.2.2 (`tests/make_case.py` describes the rest).

`TB_MAX_PATHS=11` lowers the path cap so that a test can reach it.

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

### VIS-01 · The map is drawn as the legend says: hosts, directions, counts, borders, menu, errors (GRA-2, GRA-4)

**Environment:** ENV-DEMO. **Starting state:** page open, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Anchor `2024-05-01T12:00:00Z`; map `10.0.0.5` outbound. | 10.0.0.5 is drawn larger than the rest, in the red of the legend's *IOC host*, at the top. Its 12 peers are grey, in a row below it. Orange arrows, the legend's *outbound (future)*, run from 10.0.0.5 to each peer. Every edge label can be read; zoom in if they crowd. | Hosts, connections and their direction are drawn as the legend says (GRA-2), as a tree by hop. | |
| 2 | Compare the arrows labelled `469 · …`, `460 · …` and `163 · …` with those labelled `1 · …` and `2 · …`. | The busier connections are drawn visibly thicker. | Line width shows the number of connections. | |
| 3 | Set Direction *Inbound*; left-click the peer 10.1.6.3. | Blue arrows, the legend's *inbound (past)*, point into 10.1.6.3 from its new peers, which are drawn in a row below it. 10.1.6.3 now has a thin light border. | Inbound colour; an expanded host is marked. | |
| 4 | Right-click 10.1.6.3. | The menu opens at the pointer. Its first line (the host and its anchor) is smaller and grey, a line separates the expand items from the rest, and every item can be read. | The menu (GRA-4). | |
| 5 | Choose `Expand outbound: who it connected to (future)`. | 10.1.6.3's border becomes thicker and white, clearly different from the thin light border of a host expanded one way. | A host expanded both ways stands out. | |
| 6 | Host `nope`; Map. | The status line turns red. | Errors stand out. | |

### VIS-02 · Threat lines, compromised hosts and paths are drawn as the legend says (INT-1, INT-2, ATK-1, ATK-4)

**Environment:** ENV-CASE. **Starting state:** fresh state; page open, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Map `10.0.0.9` inbound; left-click the arrow 10.0.0.5 → 10.0.0.9. | 203.0.113.66's border and the arrow 203.0.113.66 → 10.0.0.5 are violet, the legend's *threat line: earlier*. 10.0.0.20's border and the arrow 10.0.0.9 → 10.0.0.20 are teal, *threat line: later*. The clicked arrow is white. 10.0.0.77 and its arrow are faded but still visible. | The threat line and its time relations can be seen at a glance (INT-1, INT-2). | |
| 2 | Click the background. Mark `203.0.113.66` (time blank) and `10.0.0.20` at `2024-05-01T12:20:00Z` in the side panel. | Both hosts are dark red with a light red ring, the legend's *compromised*. The arrows of the two attack paths are thick and red, *attack path*. | Compromised hosts (ATK-4) and attack paths (ATK-1) stand out. | |
| 3 | *Paths between two hosts*: from `203.0.113.66` to `10.0.0.20`; **Find paths**. | The same arrows as in step 2 are now thick and pink, *path between two hosts*, clearly different from step 2's red. The rest of the map is faded. | Paths between two hosts stand out. | |
| 4 | Remove both compromised hosts. Mark `10.0.2.1` (time blank) and `10.0.2.2` at `2024-05-01T13:00:00Z`; click **Show all**. | The status line is amber, clearly different from an error's red, and says `First 11 paths from 10.0.2.1 to 10.0.2.2, shortest first. There are more: …`. | Warnings stand out from errors. | |
| 5 | Remove both compromised hosts. | | | |

### PRF-01 · The browser stays responsive on a busy week: big expansions, a 600-host threat line, 500 paths, attack paths in the background (PRF-3)

**Environment:** ENV-BUSY. **Starting state:** fresh state; page open. Status:
`Case: 1000000 flows between 2503 hosts, 2024-05-01T12:00:01.117Z → 2024-05-08T12:00:00.727Z`.

CI times the server's answers on this dataset (`tests/test_perf.py`). This test times what the
analyst sees: from the click until the map is drawn and can be used. The limits come from
PRF-3: under 3 s for what the analyst waits on, and under 10 s for attack paths, which are
recomputed in the background.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Map `10.0.0.80` inbound. | Within 3 s the map shows 50 peers and the status `10.0.0.80: showing top 50 of 2000 distinct peer(s), 2024-05-07T12:00:00.727Z → 2024-05-08T12:00:00.727Z`. Panning and zooming are smooth. | A busy host draws quickly. | |
| 2 | Window `8d`; Map. Then left-click the arrow from 10.1.0.7 (`100071 · 3128`). | Within 3 s the flow list shows `1–50 of 100,071`, and the threat line is drawn: about 600 hosts, with the amber status `Threat line through 10.1.0.7 → 10.0.0.80: 298 earlier host(s) (violet), 299 later host(s) (teal); ≤ 6 hops, ≤ 8d between hops. Click the background to clear. WARNING: stopped at the host limit; the line is incomplete.` Panning and zooming stay smooth, and the browser never reports the page as unresponsive. | A 600-host threat line stays usable. | |
| 3 | Click **Last**. | Within 3 s: `100051–100071 of 100,071`. | | |
| 4 | **Clear**; Window `24h`. Paths from `10.0.0.80` to `10.0.0.53`. | Within 3 s, 500 pink paths are drawn, and the amber status starts `First 500 paths from 10.0.0.80 to 10.0.0.53, shortest first.` Panning and zooming stay smooth. | 500 paths stay usable. | |
| 5 | Mark these hosts compromised, one at a time, at these times: 10.0.0.80 `2024-05-05T00:00:00Z`, 10.0.0.53 `…T01:00:00Z`, 10.0.0.1 `…T02:00:00Z`, 10.1.4.24 `…T03:00:00Z`, 10.1.3.235 `…T04:00:00Z`, 10.1.3.92 `…T05:00:00Z`, 10.1.1.42 `…T06:00:00Z`, 10.1.1.237 `…T07:00:00Z`, 10.1.3.110 `…T08:00:00Z`, 10.1.5.138 `…T09:00:00Z` (all on 2024-05-05). | Each mark recomputes the attack paths, and the later ones show `Working… N s`. After the tenth, within 10 s: `78+ attack path(s) between 10 compromised host(s)`, with the paths drawn. | Attack paths among the ten busiest hosts, with IOC times. | |
| 6 | While step 5's last recomputation runs (`Working… N s` shown), pan and zoom, right-click a host, and map `10.0.0.53` inbound. | Panning and zooming stay smooth. The details appear at once. The new map is drawn within 3 s, before the paths finish. | The map stays usable while paths are computed (PRF-3). | |

### SO-01 · SOC actions open the map at the event's IP and time (EXT-1)

**Environment:** ENV-SO. **Starting state:** logged in to SOC; ThreatBridge reachable with the analyst's certificate.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | In SOC Hunt, find a Zeek conn event (`event.dataset:conn`); click its `source.ip` value. | The action menu offers `ThreatBridge: inbound (past)` and `ThreatBridge: outbound (future)`. | The SOC actions are installed (EXT-1). | |
| 2 | Choose `ThreatBridge: inbound (past)`. | A new tab opens the map with Host = that IP, Anchor time = the event's time (UTC), Direction *Inbound*, and the map drawn. The status ends `<anchor − 24h> → <anchor>`. If the Anchor is blank and the status ends at the current time, `{:soc_timestamp}` did not come through: record F (README, *Things to verify*, item 1). | | |
| 3 | Back in SOC, choose `ThreatBridge: outbound (future)` for the same value. | Direction *Outbound*; the status starts at the event's time. | | |

### SO-02 · Conn records from Elasticsearch: counts, flow fields, the 10,000-flow limit, excludes, the rarest-peer cap (GRA-1, GRA-3, ING-4, GRA-S3, FIL-1)

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

## 4. Where each requirement is tested

*Automated* names the tests in `tests/` that check the requirement on every CI run. The browser
suites are `ui_smoke.mjs` (demo data), `ui_case.mjs` and `ui_actions.mjs` (the generated case)
and `ui_mtls.mjs` (the container). *Manual* names the tests above.

| Requirement or decision | Automated | Manual |
|---|---|---|
| ING-1 PCAP ingest | `test_sources.py`, `test_case.py`; the case in `ui_case.mjs`, `ui_actions.mjs` | |
| ING-2 NetFlow ingest | `test_sources.py` (record pairing; a real nfcapd file through nfdump), `test_integration.py` (pcap and NetFlow in one case) | |
| ING-3 Directories of pcaps, rotated captures | `test_sources.py` | |
| ING-4 Addresses, ports, times, protocol | `test_sources.py`, `test_case.py`, `test_backends.py` (Elasticsearch fields, configurable); flow lines in `ui_case.mjs`, `ui_actions.mjs` | SO-02 (field names on a live install) |
| ING-S2 Security Onion integration | `test_domains.py`, `test_backends.py` (Zeek DNS records); `test_soc.py` (Connect API against a stand-in); `ui_smoke.mjs` (PCAP links and download) | SO-03, SO-04, SO-05 |
| GRA-1 Directed graph | `test_case.py`, `test_backends.py`; `ui_actions.mjs` | SO-02 |
| GRA-2 Hosts and connections displayed | `ui_smoke.mjs`, `ui_case.mjs`, `ui_actions.mjs` (elements, labels, layout) | VIS-01 |
| GRA-3 Temporal ordering | `test_case.py`, `test_analysis.py`; `ui_actions.mjs` (time-chained hops, flows paged oldest first) | SO-02 (10,000-flow limit) |
| GRA-4 Interactive, clickable | `ui_smoke.mjs`, `ui_case.mjs`, `ui_actions.mjs` (clicks, menus, details) | VIS-01 |
| GRA-S2 Time-range filtering | `test_case.py`, `test_api.py`; `ui_smoke.mjs`, `ui_case.mjs`, `ui_actions.mjs` | |
| GRA-S3 Connection metadata | `test_sources.py`, `test_backends.py`; `ui_case.mjs`, `ui_actions.mjs` | SO-02 |
| ATK-1 Attack paths | `test_analysis.py` (against brute force), `test_case.py`; `ui_case.mjs`, `ui_actions.mjs` | VIS-02 |
| ATK-3 Predecessors and successors | `test_case.py`; `ui_smoke.mjs`, `ui_actions.mjs` | |
| ATK-4 Mark hosts compromised | `test_case.py`, `test_stores.py`; `ui_smoke.mjs`, `ui_case.mjs`, `ui_actions.mjs` | VIS-02 |
| INT-1 Threat line on edge click | `test_analysis.py`, `test_case.py`; `ui_case.mjs`, `ui_actions.mjs` | VIS-02 |
| INT-2 Earlier and later communications | `test_analysis.py`; `ui_case.mjs`, `ui_actions.mjs` | VIS-02 |
| INT-3 Iterative refinement | `ui_case.mjs`, `ui_actions.mjs` | |
| INT-4 Real-time update on new indicators | `test_case.py`; `ui_case.mjs`, `ui_actions.mjs` (redrawn on every change, answers out of order) | |
| INT-S2 Save and restore sessions | `test_sessions.py`; `ui_actions.mjs` (shared and as a file), `ui_smoke.mjs` (the URL) | |
| FIL-1 IP exclude list | `test_api.py`, `test_query.py`; `ui_smoke.mjs`, `ui_actions.mjs` | SO-02 |
| FIL-2 Domain names with DNS resolution | `test_domains.py`, `test_sources.py`; `ui_case.mjs`, `ui_smoke.mjs` (what each entry resolved to) | SO-03 |
| FIL-3 Excluded traffic out of path calculations | `test_analysis.py`, `test_domains.py`; `ui_case.mjs`, `ui_actions.mjs` | |
| FIL-S1 CIDR | `test_query.py`, `test_case.py`; `ui_smoke.mjs`, `ui_actions.mjs` | |
| FIL-S2 Exclude list kept and shared | `test_stores.py`, `test_integration.py`; `ui_actions.mjs` (seen by another analyst) | |
| PRF-1 1M flows | `test_perf.py` (CI performance job) | |
| PRF-2 Built within 5 minutes under 100 MB | `test_perf.py` | |
| PRF-3 Responsive during traversal | `test_perf.py` (server timings); `ui_actions.mjs`, `ui_smoke.mjs` (requests in the background, Cancel, answers out of order) | PRF-01 |
| PRF-S1 Parallel reading | `test_sources.py` (the same flows as one at a time), `test_case.py` | |
| PRF-S3 Progress | `test_progress.py` (terminal and log); `ui_smoke.mjs`, `ui_actions.mjs` (busy indicator, Cancel) | |
| EXT-1 Security Onion workflows | `test_integration.py` (SOC actions open the map), `test_query.py` (pivots, configurable); `ui_smoke.mjs` | SO-01, SO-06 |
| EXT-S2 API | `test_integration.py` (every endpoint documented), the API tests | |
| Mutual TLS | `mtls_check.sh`, `ui_mtls.mjs` (CI Docker job) | ENV-SO uses it |
| D3 Edge left-click / right-click | `ui_smoke.mjs`, `ui_case.mjs`, `ui_actions.mjs` | |
| D6, D7 Inputs, connection rules | `test_sources.py` | |
| D8 Time order, hop limit | `test_analysis.py`, `test_case.py` | |
| D9 Capture DNS, then live DNS | `test_domains.py`; `ui_smoke.mjs` | SO-03 |
| D10 Flows in time order; time range | `test_case.py`; `ui_actions.mjs` | |
| D11 Paths between two hosts | `test_analysis.py`, `test_case.py`; `ui_case.mjs`, `ui_actions.mjs` | |
| D12 PCAP from the sensors | `test_soc.py`, `test_backends.py`; `ui_smoke.mjs` | SO-04, SO-05 |
| D13 Parallel reading, exact flows | `test_sources.py` | |

Not built, so nothing to test: ING-S1 (out of scope), ING-S3, GRA-S1, ATK-2 and EXT-2
(deferred, D5), ATK-S1–S3, INT-S1, INT-S3, FIL-S3, FIL-S4, PRF-S2, EXT-S1, EXT-S3
([REQUIREMENTS.md](REQUIREMENTS.md)).
