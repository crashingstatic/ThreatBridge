# ThreatBridge manual test plan

The automated tests run in CI on every push (`.github/workflows/ci.yml`):

- pytest, including the performance tests;
- four headless-browser suites against the map;
- the container with mutual TLS, checked with curl and in a browser.

[Section 4](#4-where-each-requirement-is-tested) lists where each requirement is tested. This
plan holds only what those tests can't check, and why:

- **How the map looks** (VIS-01, VIS-02, VIS-03). The browser tests check which colour class
  and line style each host and connection gets, but whether they match the legend, and whether
  the map is readable, takes a person looking at it.
- **Browsers and terminals CI doesn't use** (XB-01, TLS-01, TERM-01).
  - CI's browser tests run only in headless Chromium.
  - `ui_mtls.mjs` hands the client certificate to Playwright, which presents it itself, so a
    browser's own certificate store and prompt are never used.
  - The progress tests simulate a terminal; real terminals wrap, resize and reflow.
- **Real evidence** (REAL-01, REAL-02). CI reads captures and NetFlow records that the tests
  generate. Real ones can hold what the generator doesn't, so they are compared with what Zeek,
  read independently, makes of the same traffic. NetFlow often reaches back further than full
  packet capture, so it may be the only evidence of how an incident began.
- **How the browser feels on a large case** (PRF-01). CI times the server's answers (PRF-3), but
  not how fast a real browser draws hundreds of hosts, or whether panning stays smooth while
  attack paths are recomputed.
- **A real Security Onion and its deployment** (SO-01 to SO-07). CI can't reach one. It tests
  the Elasticsearch queries and SOC's Connect API against stand-ins, and runs the container
  only once. Field names, SOC actions, pivots, Zeek DNS records, PCAP jobs, the rarest-peer scan
  on a real install, and state kept across a redeploy are only proven here. Setting up ENV-SO
  and running these tests covers the README's *Things to verify on your install*.

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
- twelve two-hop routes from 10.0.2.1 to 10.0.2.2 (`tests/make_case.py` describes the rest);
- for marks and filters, apart from the rest: 10.9.0.1 → 10.9.0.2:443 at 12:01:40, 10.9.0.2 →
  10.9.0.3:445 at 12:06:40, 10.9.0.3 → 10.9.0.4:3389 at 12:11:40, 10.9.0.3 → 10.9.0.5:445 at
  12:16:40, 10.9.0.4 → 10.9.0.6:22 at 12:21:40, and 10.9.0.2 → 10.9.0.7 on ports 80 and 53 at
  12:31:40 and 12:32:40.

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

### ENV-BIG: 1.25 million flows in a 93 MiB capture

Big enough that building the case takes about a minute, so its progress can be watched.

```bash
export W=$(mktemp -d)
python -c "import sys; sys.path[:0] = ['tests']; from evidence import write_bulk_pcap; write_bulk_pcap(sys.argv[1], 1_250_000)" $W/bulk.pcap
```

### ENV-MTLS: the container with mutual TLS

This needs Docker, openssl, and sudo for Docker.

```bash
export P12_PASS=test-only                  # export password of the .p12 files
scripts/make-certs.sh ca
scripts/make-certs.sh server localhost 127.0.0.1
scripts/make-certs.sh client alice         # certs/alice.p12: signed by the ThreatBridge CA
printf 'TB_BACKEND=demo\nTB_SOC_URL=https://so.example\n' > deploy/threatbridge.env
sudo SO_CA="$PWD/certs/ca.crt" deploy/run.sh
# browse to https://localhost:5443/ ; clean up afterwards: sudo docker rm -f threatbridge
```

### ENV-REAL: a real capture and NetFlow of the same traffic, and Zeek's reading of the capture

Use 10–15 minutes of varied traffic: a busy workstation, a server, or the lab network of the
range in [TEST_RANGE_PROMPT.md](TEST_RANGE_PROMPT.md), whose `real-traffic` playbook makes the
capture and the NetFlow files for you. A NetFlow exporter (softflowd) and collector (nfcapd) run
the whole time tcpdump does (packages `tcpdump`, `softflowd` and `nfdump`). Zeek runs from its
official container image, `zeek/zeek` (put `sudo` before `docker` if your user isn't in the
`docker` group).

```bash
export W=$(mktemp -d); echo $W
# In two more terminals, with W set to the same directory: first the collector, then the exporter.
mkdir $W/nf; nfcapd -w $W/nf -p 9995
sudo softflowd -i <interface> -n 127.0.0.1:9995 -v 9 -d
# Then the capture:
sudo tcpdump -i <interface> -s 0 -w $W/real.pcap          # Ctrl+C after 10-15 minutes; note the drops it reports
# Then: sudo softflowctl statistics (note "Packets dropped by libpcap"); Ctrl+C softflowd, which
# exports every flow it still holds; wait 5 s; Ctrl+C nfcapd, which closes its file.
sudo chown $USER $W/real.pcap
docker run --rm -v $W:/w -w /w zeek/zeek zeek -C -r real.pcap     # writes conn.log, dns.log, ... into $W
zc() { docker run --rm -i -v $W:/w -w /w zeek/zeek zeek-cut "$@"; }   # zeek-cut, e.g. zc ts < $W/conn.log
TB_LIVE_DNS=false TB_EXCLUDE_FILE=$W/exclude.json TB_COMPROMISED_FILE=$W/compromised.json TB_SESSIONS_DIR=$W/sessions \
python -m threatbridge --case $W/real.pcap --port 5056
# browse to http://127.0.0.1:5056/
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

### VIS-01 · The map is drawn as the legend says: hosts, directions, counts, menu, protocol highlight, errors (GRA-2, GRA-4)

**Environment:** ENV-DEMO. **Starting state:** page open, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Anchor `2024-05-01T12:00:00Z`; map `10.0.0.5` outbound. | 10.0.0.5 is drawn larger than the rest, in the red of the legend's *IOC host*. Its 12 peers are grey. Orange arrows, the legend's *outbound (future)*, run from 10.0.0.5 to each peer. Every edge label can be read; zoom in if they crowd. | Hosts, connections and their direction are drawn as the legend says (GRA-2). | |
| 2 | Compare the arrows labelled `469 · …`, `460 · …` and `163 · …` with those labelled `1 · …` and `2 · …`. | The busier connections are drawn visibly thicker. | Line width shows the number of connections. | |
| 3 | Set Direction *Inbound*; left-click the peer 10.1.6.3. | Blue arrows, the legend's *inbound (past)*, point into 10.1.6.3 from its new peers. | Inbound colour. | |
| 4 | Right-click 10.1.6.3. | The menu opens at the pointer. Its first line (the host and its anchor) is smaller and grey, a line separates the expand items from the rest, and every item can be read. | The menu (GRA-4). | |
| 5 | *Highlight protocol*: choose the first protocol listed. Then *All*. | The connections carrying it glow pale yellow around their own colour (blue or orange still shows), and their arrows and labels can be read; every other connection is faded but can still be made out. With *All*, the map is as before. | The protocol highlight stands out (D14). | |
| 6 | Host `nope`; Map. | The status line turns red. | Errors stand out. | |

### VIS-02 · Threat lines, compromised hosts and paths are drawn as the legend says (INT-1, INT-2, ATK-1, ATK-4)

**Environment:** ENV-CASE. **Starting state:** fresh state; page open, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Map `10.0.0.9` inbound; left-click the arrow 10.0.0.5 → 10.0.0.9. | 203.0.113.66's border and the arrow 203.0.113.66 → 10.0.0.5 are violet, the legend's *threat line: earlier*. 10.0.0.20's border and the arrow 10.0.0.9 → 10.0.0.20 are teal, *threat line: later*. The clicked arrow is white. 10.0.0.77 and its arrow are faded but still visible. | The threat line and its time relations can be seen at a glance (INT-1, INT-2). | |
| 2 | Click the background. Mark `203.0.113.66` (time blank) and `10.0.0.20` at `2024-05-01T12:20:00Z` in the side panel. | Both hosts are dark red with a light red ring, the legend's *compromised*. The arrows of the two attack paths are thick and red, *attack path*, dashed (no flow on them is marked). 10.0.0.77 and its arrow disappear, and the status line ends `1 connection(s) hidden by marks` in amber. | Compromised hosts (ATK-4), attack paths (ATK-1), and what marks hide (ATK-7) stand out. | |
| 3 | *Paths between two hosts*: from `203.0.113.66` to `10.0.0.20`; **Find paths**. | The same arrows as in step 2 are now thick and pink, *path between two hosts*, clearly different from step 2's red. The rest of the map is faded. | Paths between two hosts stand out. | |
| 4 | Remove both compromised hosts. Mark `10.0.2.1` (time blank) and `10.0.2.2` at `2024-05-01T13:00:00Z`; click **Show all**. | The status line is amber, clearly different from an error's red, and says `First 11 paths from 10.0.2.1 to 10.0.2.2, shortest first. There are more: …`. | Warnings stand out from errors. | |
| 5 | Remove both compromised hosts. | | | |

### VIS-03 · Marks and filters are drawn as the legend says: marked and suspect connections, what is hidden, a refused filter (INT-7, ATK-5, ATK-7, FIL-S6)

**Environment:** ENV-CASE. **Starting state:** fresh state; page open, toolbar defaults.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Anchor `2024-05-01T12:00:00Z`, Window `1h`; map `10.9.0.2` outbound. Left-click the arrow 10.9.0.2 → 10.9.0.3; click the background. | Seven hosts: 10.9.0.1 → 10.9.0.2, then 10.9.0.3, 10.9.0.4, 10.9.0.5, 10.9.0.6 and 10.9.0.7. | | |
| 2 | Right-click 10.9.0.4 → `Mark compromised (time unknown)`. | 10.9.0.5, 10.9.0.7 and their arrows disappear. The arrows 10.9.0.1 → 10.9.0.2 → 10.9.0.3 → 10.9.0.4 → 10.9.0.6 are dark red and dashed, with a thin light red outline, like the legend's *suspect connection*; the dashes are clear at the normal zoom. The status line ends `2 connection(s) hidden by marks`, in amber. | Suspect connections, and what the marks hide, can be seen at a glance (INT-7, ATK-7). | |
| 3 | Right-click the arrow 10.9.0.2 → 10.9.0.3 → `Mark compromised`. | 10.9.0.2 and 10.9.0.3 turn dark red with a light red ring. The arrow 10.9.0.2 → 10.9.0.3 is solid, like the legend's *marked connection*, drawn in the attack paths' red, as is 10.9.0.3 → 10.9.0.4, which stays dashed. 10.9.0.5 and 10.9.0.7 come back, their arrows dashed. | Marked and suspect connections can be told apart, on attack paths too (INT-7, ATK-5). | |
| 4 | Type `smb` in *Filter*; press Enter. | The box turns light red, its text still readable; the status line, red, says `at character 1: protocol names are case-sensitive: write SMB`. Typing in the box makes it white again. | A refused filter stands out (FIL-S6). | |
| 5 | Type `SMB`; press Enter. | `SMB` appears beside the box with an ×, readable on the toolbar; the box is empty. Click the ×. | | |
| 6 | Remove the marks in the side panel. | | | |

### XB-01 · The map works in other browsers: menus, new tabs, clipboard, dialogs, saving and opening files (GRA-4, INT-S2)

CI's browser tests run only in Chromium. Run this in each other browser the analysts use: Firefox
at least, and Safari or Edge if they're used.

**Environment:** ENV-DEMO. **Starting state:** fresh state; the browser under test, with its
console open (Firefox: Web Console).

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Open `http://127.0.0.1:5055/?ip=10.0.0.5&ts=2024-05-01T12:00:00Z&dir=in`. | The map is drawn. Status: `10.0.0.5: showing top 5 of 5 distinct peer(s), 2024-04-30T12:00:00.000Z → 2024-05-01T12:00:00.000Z`. | Launch from a link. | |
| 2 | Left-click 10.1.0.26, then right-click it; press Escape. | It expands (blue arrows into it). Right-click opens ThreatBridge's menu, not the browser's own, and Escape closes it. | Clicks and menus. | |
| 3 | Right-click the arrow 10.1.0.26 → 10.0.0.5 → `Filter SOC Dashboards: all conversations up to IOC time`. | A new tab opens on `https://so.example/#/dashboards?q=…` (the site itself won't load). If the browser blocks it as a pop-up, record F. | Opening SOC in a new tab. | |
| 4 | Right-click the same arrow → `Copy SOC query`; paste into *Host / IOC IP*, then clear it. | Status `SOC query copied to clipboard`. The pasted text starts `((source.ip:"10.1.0.26" AND destination.ip:"10.0.0.5")`. | The clipboard. | |
| 5 | Left-click the arrow; click a flow's **PCAP in SOC**. | The flow list appears. A new tab opens on `https://so.example/joblookup?esid=…`. | | |
| 6 | *Saved maps*: name `xb`, **Save**; then **Save** again and choose Cancel in the dialog. | `Saved the map "xb" for everyone`. The browser's own dialog asks `Replace the saved map "xb"?`. After Cancel: red `a map called 'xb' is already saved`. | Saving, and the browser's confirm dialog. | |
| 7 | **Save to file**; **Open file** and choose the saved file. | The browser saves `threatbridge-xb.json` (to its download folder, or after asking where). The file chooser offers `.json` files. Opening the file: `Opened threatbridge-xb.json: …`, the map is as before, and the side panel says it shows the marks saved with `threatbridge-xb.json`. | Downloads and the file chooser. | |
| 7b | **Share** (side panel); choose Cancel. Then **Export CSV**. | The browser's dialog asks `Replace the 0 shared mark(s) with this map's 0? Every analyst's map will show them.`; after Cancel nothing changes. Export saves two files, `threatbridge-xb-hosts.csv` and `threatbridge-xb-flows.csv` (the browser may ask once to allow several downloads). | The confirmation before sharing; several downloads at once. | |
| 8 | Click **Delete** next to `xb`; choose OK. | The dialog asks `Delete the saved map "xb" for everyone?`. Then: `Deleted the saved map "xb"`. | | |
| 9 | Look at the browser's console. | No errors, apart from step 6's refused save (HTTP 409). | The page runs under its Content Security Policy in this browser. | |

### TLS-01 · A browser's own certificate store: the `.p12` imports, and the map opens over HTTPS without warnings (authentication)

CI checks that the server refuses no certificate and one from another CA (`mtls_check.sh`,
`ui_mtls.mjs`), and runs the map over HTTPS. It hands Playwright the certificate, though, so
importing the `.p12`, trusting the CA, and how a browser offers and remembers the certificate
are only checked here. Run this in each browser the analysts use.

**Environment:** ENV-MTLS, or the ENV-SO deployment (then use its address, and a client
certificate made for this test in place of alice's). **Starting state:** container running.

Use a new, empty certificate store. Firefox keeps one per profile: make a new profile
(`firefox -P`). Chrome, Chromium and Edge use the operating system user's store (on Linux,
`~/.pki/nssdb`), which all their profiles share: use another OS user, or, on Linux, start
Chromium with an empty home of its own, e.g. `HOME=$(mktemp -d) chromium`.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | In the new store, trust `certs/ca.crt` as an authority and import `certs/alice.p12` (ENV-MTLS's password: `test-only`). Open `https://localhost:5443/`. | The import succeeds. The browser asks which certificate to use, or uses alice's. With alice's, the map loads without warnings. | The `.p12` and the CA work in this browser's store; the server's certificate is trusted through the CA. | |
| 2 | Quit and restart the browser; open the page again. | The browser asks again or remembers the choice; either way the map loads with alice's certificate. | | |

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

### TERM-01 · In a real terminal, narrow or resized, the progress line stays on one row (PRF-S3)

`tests/test_progress.py` checks the progress against a simulated terminal: one line per stage,
cut to the terminal's width, log lines on lines of their own, and a log line every 10 s without
a terminal. A real terminal also wraps, resizes and reflows. Run this in each terminal emulator
the analysts use.

**Environment:** ENV-BIG, in a terminal window (not an editor's output pane). **Starting state:**
`$W/bulk.pcap` written.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Make the window about 40 columns wide. Run `TB_LIVE_DNS=false TB_EXCLUDE_FILE=$W/exclude.json TB_COMPROMISED_FILE=$W/compromised.json TB_SESSIONS_DIR=$W/sessions python -m threatbridge --case $W/bulk.pcap --port 5059`. While `Reading 1 evidence file(s)` runs, widen and narrow the window a few times. | At any steady width the updating line fits on one row, cut short with `…`, and leaves no trail of partial lines as it updates. Each narrowing may leave behind one row of the line that was on screen (a terminal that reflows wraps it); after that the line again stays on one row. Each stage (`Reading 1 evidence file(s)`, `Saving the flows`, `Indexing the flows`, `Building the graph`) ends with a complete `…: done in N s` line, which may wrap. | Progress in narrow and resized terminals. | |

### REAL-01 · A real capture is read as Zeek reads it: connections, orientation, packets, bytes, DNS answers, protocols (ING-1, ING-4, GRA-S3, D7, FIL-2, D14)

CI's evidence is generated by the tests. This test compares ThreatBridge's reading of a real
capture with Zeek's. Both end a TCP connection after 5 minutes idle (Zeek's
`tcp_inactivity_timeout`), and both take the sender of the SYN as its initiator (D7). They
differ in these cases:

- Zeek keeps SSH, FTP, telnet and rlogin connections (ports 21, 22, 23 and 513, or detected as
  SSH or FTP) for up to 1 hour idle (`base/protocols/conn/inactivity.zeek`).
- Zeek keeps a connection for 5 s after a reset or a close (`tcp_reset_delay`,
  `tcp_close_delay`). ThreatBridge ends it at the reset; after a FIN, it ends it at the next SYN.
- UDP and ICMP have no SYN, nor has a TCP connection already open when the capture started.
  Zeek then goes by the first sender and its own list of server ports, ThreatBridge by the
  first sender when both sides were seen (README, *Post-mortem mode*).

So the comparison is for pairs of hosts all of whose Zeek records, either way, are TCP
connections seen from the handshake (`history` starts with `Sh`) to the close (`conn_state`
`SF`), with no reset (no `R` or `r` in `history`), and none of those services. This lists the
five busiest such pairs, as `<connections> <initiator> <responder>`:

```bash
zc id.orig_h id.resp_h proto id.resp_p service conn_state history < $W/conn.log | awk -F'\t' '
  { pair = $1 < $2 ? $1 " " $2 : $2 " " $1
    if ($3 == "tcp" && $6 == "SF" && $7 ~ /^Sh/ && $7 !~ /[Rr]/ && $5 !~ /ssh|ftp/ &&
        $4 != 21 && $4 != 22 && $4 != 23 && $4 != 513) n[$1 " " $2]++; else bad[pair] = 1 }
  END { for (k in n) { split(k, h, " "); if (!((h[1] < h[2] ? k : h[2] " " h[1]) in bad)) print n[k], k } }' |
  sort -rn | head -5
```

**Environment:** ENV-REAL. **Starting state:** the capture taken, Zeek run on it, ThreatBridge
serving it; page open.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | For each pair A → B the command lists: set N to `200` (the most it allows) and map B inbound. | An arrow runs from A to B, and its count is the command's. | Connections per initiator → responder pair (ING-1, D7). | |
| 2 | For one pair, left-click the arrow. List Zeek's records in the same form: `zc ts id.orig_h id.orig_p id.resp_h id.resp_p duration orig_pkts resp_pkts orig_ip_bytes resp_ip_bytes < $W/conn.log \| awk -F'\t' -v a=A -v b=B '$2 == a && $4 == b {printf "%s tcp %s → %s · %.3f s · %d pkts · %d B\n", $1, $3, $5, $6, $7 + $8, $9 + $10}' \| sort -n \| while read ts rest; do echo "$(date -u -d @$ts +%FT%T.%3NZ) $rest"; done`. Compare the first page of flows, and the last (**Last**), with those lines. | Each flow matches a line: the same start, ports, protocol, packets and bytes (IP bytes of both sides), and the same duration give or take 0.001 s. | Per-flow fields (ING-4, GRA-S3). | |
| 3 | List the names answered over UDP port 53, with their answers: `zc proto id.resp_p rcode_name query answers < $W/dns.log \| awk -F'\t' '$1 == "udp" && $2 == 53 && $3 == "NOERROR" {print tolower($4), $5}' \| sort -u`. Pick a name whose lines hold one to four IP addresses in all, and that is no other name's alias: `zc answers < $W/dns.log \| grep -Fiwc <name>` prints `0`. Add it to the exclude list. | The entry shows `capture: ` and exactly the IP addresses on that name's lines (not the names among the answers), IPv4 before IPv6, each in numeric order. An address on the lines but not in the entry is F, unless Wireshark shows the response gave it for an unrelated name (ThreatBridge ignores those). | Domain names from real DNS answers, through CNAMEs (FIL-2). | |
| 4 | Find connections Zeek named with `dns`, `http`, `ssl`, `ssh` and `smb`, if the capture has them: `zc id.orig_h id.resp_h id.resp_p service < $W/conn.log \| awk -F'\t' '$4 != "-"' \| sort -u \| head -40`. Map each one's responder inbound, left-click the arrow from its originator, and read the protocol at the start of each flow's line. | ThreatBridge names what Zeek names (`TLS` for Zeek's `ssl`), including on ports where the service doesn't usually run. A connection Zeek names nothing for is named by its server's port, or Unknown. | Protocols recognized from real payloads (D14). | |
| 5 | Find FTP sessions (on the range: active, passive and extended passive downloads from 10.0.5.1): `zc id.orig_h id.orig_p id.resp_h id.resp_p service < $W/conn.log \| awk -F'\t' '$5 ~ /ftp/'`. Map each data connection's responder inbound (for an active transfer the client, which the server connects to), left-click its arrow, and read its flows' protocol. Do the same for the control connection. | Every connection Zeek names `ftp` or `ftp-data` is `FTP`, the passive transfer's (both ports high) included. | FTP data connections are named from the control connection's `PORT`/`PASV`, as Zeek does (ING-5, D14). | |

### REAL-02 · NetFlow from a real exporter is read as Zeek reads the same traffic: connections, orientation, packets (ING-2, D7)

CI exports NetFlow records that the tests make up through a real nfcapd and nfdump, so a real
exporter's records are only checked here. This test reads a real exporter's records of
REAL-01's traffic, and compares them with Zeek's reading of the capture.

softflowd follows each connection as one two-way flow, and exports it as two one-way records
with the same start time. Time then can't tell ThreatBridge which side started the connection,
so it goes by the TCP flags, then the ports, and failing both records the connection both ways
(README, *Post-mortem mode*). The flags can't tell
for a completed connection, whose two halves both carry SYN and ACK, so this test uses
connections the ports decide: to a port below 1024, or to one below 32768 from the ephemeral
range 32768–65535. It doesn't compare bytes with Zeek: softflowd counts each packet's length on
the wire less its link header, which includes any Ethernet padding, where Zeek counts IP
lengths.

**Environment:** ENV-REAL. **Starting state:** REAL-01 done, and its pair listing at hand. The
NetFlow served on another port, and `http://127.0.0.1:5057/` open:
`TB_LIVE_DNS=false TB_EXCLUDE_FILE=$W/ex2.json TB_COMPROMISED_FILE=$W/c2.json TB_SESSIONS_DIR=$W/s2 python -m threatbridge --case $W/nf --port 5057`

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | From REAL-01's listing, take the pairs A → B whose connections all go to one port that the port rule decides: `zc id.orig_h id.orig_p id.resp_h id.resp_p < $W/conn.log \| awk -F'\t' -v a=A -v b=B '$1 == a && $3 == b {ok = ($2 >= 1024 && $4 < 1024) \|\| ($2 >= 32768 && $4 < 32768); print ok ? "ok" : "no", $4}' \| sort -u` prints one line, starting `ok`. For each, set N to `200` and map B inbound. | An arrow runs from A to B, and its count is the listing's. A higher count is right only if each extra flow lies partly outside the capture: it began before tcpdump started, or ended after it stopped (softflowd runs longer). | Each connection's two records become one flow, initiator → responder (ING-2, D7). | |
| 2 | Left-click the arrow. List Zeek's records with REAL-01 step 2's command, and compare the first page of flows, and the last (**Last**), with those lines. | Each line matches a flow: the same ports and packets, and a start and duration that agree to within 0.01 s (the exporter keeps times in milliseconds). NetFlow has no payload, so each flow's protocol is the one its server's port is known for (e.g. `HTTP` for 80 and 8080). Packets may differ only if tcpdump or softflowd reported dropped packets (ENV-REAL). | Per-flow fields from NetFlow (ING-4, GRA-S3). | |
| 3 | For one flow, from port P, list its records: `TZ=UTC nfdump -R $W/nf -N -o long 'proto tcp and host A and host B and port P'`. | Two records, one each way, with the same *Date first seen*. The flow's packets and bytes are the sums of the two records'; its start is their *Date first seen*. | The two one-way records are merged (ING-2). | |
| 4 | Find REAL-01 step 5's FTP connections here. | The control connections, and active-mode data connections (from port 20), are `FTP`; a passive transfer's data connection, both ports high, is `Unknown`: NetFlow has no payload to follow `PASV` in. | FTP in NetFlow is named by port only (D14). | |

### SO-01 · SOC actions open the map at the event's IP and time (EXT-1)

**Environment:** ENV-SO. **Starting state:** logged in to SOC; ThreatBridge reachable with the analyst's certificate.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | In SOC Hunt, find a Zeek conn event (`event.dataset:conn`); click its `source.ip` value. | The action menu offers `ThreatBridge: inbound (past)` and `ThreatBridge: outbound (future)`. | The SOC actions are installed (EXT-1). | |
| 2 | Choose `ThreatBridge: inbound (past)`. | A new tab opens the map with Host = that IP, Anchor time = the event's time (UTC), Direction *Inbound*, and the map drawn. The status ends `<anchor − 24h> → <anchor>`. If the Anchor is blank and the status ends at the current time, `{:soc_timestamp}` did not come through: record F (README, *Things to verify*, item 1). | | |
| 3 | Back in SOC, choose `ThreatBridge: outbound (future)` for the same value. | Direction *Outbound*; the status starts at the event's time. | | |

### SO-02 · Conn records from Elasticsearch: counts, flow fields, the 10,000-flow limit, excludes, refused connections, the rarest peers (GRA-1, GRA-3, ING-4, GRA-S3, FIL-1)

**Environment:** ENV-SO. **Starting state:** a map open on a host with traffic.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Right-click an arrow A → B and note *Connections*, *First seen* and *Last seen*. In SOC Hunt, query `event.dataset:conn AND source.ip:"A" AND destination.ip:"B"` over the hop's window (the status line's times). | Hunt's count equals *Connections*, and its first and last events match. | The map is built from the conn records (GRA-1). | |
| 2 | Left-click the arrow. | Flows oldest first. Each row shows protocol, source → destination port, duration, packets and bytes, none blank. They match the conn records (duration; packets and IP bytes of both sides added). | The flow list's field names hold on this install (ING-4, GRA-S3; README, *Things to verify*, item 7). | |
| 3 | Find a connection with more than 10,000 flows in the window (e.g. a workstation to a DNS server over `7d`); left-click it; click **Last**. | Red: `Security Onion lists only the first 10000 flows of a connection; narrow the time range to see later ones`. Set Range from to a later time and click the arrow again: the later flows are listed. | The 10,000-flow limit is reported, and the time range reaches past it (GRA-3). | |
| 4 | Add one peer's /24 to the exclude list; Map again. | Peers in that /24 no longer appear. | Excludes apply to Elasticsearch queries (FIL-1). | |
| 5 | Remove step 4's /24 from the exclude list. Find a port scan in Hunt: `event.dataset:conn AND connection.state:REJ \| groupby source.ip destination.ip` (on the range of [TEST_RANGE_PROMPT.md](TEST_RANGE_PROMPT.md), 10.0.2.1 → 10.0.2.10). Map its target inbound, and compare the scanner's arrow with Hunt's records between the two (`event.dataset:conn AND source.ip:"A" AND destination.ip:"B"`). | The arrow counts only the records whose `connection.state` isn't `REJ` (on the range, 2: the fan-out connection to 445, and the scan's hit on 445). | Refused connections aren't mapped on this install (README, *Things to verify*, item 11). | |
| 6 | Peers *Bottom (rarest)*, N `5`. Map inbound a host H with 6 to 20 distinct peers in the window (on the range of [TEST_RANGE_PROMPT.md](TEST_RANGE_PROMPT.md), 10.0.3.1). In SOC Hunt, query `event.dataset:conn AND destination.ip:"H" \| groupby source.ip` over the status line's times, and sort the groups by count, fewest first. | The map shows the five peers with the fewest connections, each arrow's count equal to Hunt's. Among peers tied on a count, those first in text order are shown (`10.0.0.10` before `10.0.0.9`). The status starts `H: showing rarest 5 of N distinct peer(s)`, N being Hunt's number of groups. On the range: 10.0.3.10, 10.0.3.9, 10.0.3.11, 10.0.3.2 and 10.0.3.3, of 11 (10.0.3.4 is tied with the last three, but after them in text order). | Bottom N is exact on a live install: every peer's connections are counted (README, *Peer selection*). | |
| 7 | Peers *Bottom (rarest)*, N `5`. Map inbound a host with more than 1,000 distinct peers in the window (on the range, 10.0.1.3). Then choose Peers *Top* and map it again. | Bottom: the status says `of N distinct peer(s)` with N over 1000, the host's number of distinct peers. Top's status gives Elasticsearch's estimate, which is the same or very close. The five shown have the fewest connections, ties in text order. On the range: N is 1101, and the five are 10.0.10.1, 10.0.10.10, 10.0.10.100, 10.0.10.101 and 10.0.10.102. | The scan reads past its first page of 1,000 peers. | |
| 8 | Map a host with varied traffic (e.g. a DNS server, or on the range 10.0.0.9 inbound and outbound). Open *Highlight protocol*, and compare it with Hunt: `event.dataset:conn AND destination.ip:"H" \| groupby source.ip network.protocol`. Choose each protocol in turn. | Mapping works (an Elasticsearch error here means `network.protocol` can't be aggregated: README, *Things to verify*, item 12). The drop-down lists Hunt's protocols for the connections drawn (`TLS` for Zeek's `ssl`; `Unknown` where Zeek named none, `ICMP` for ICMP). Each choice highlights the connections whose records carry it. | Zeek's protocols reach the map on this install (D14). | |
| 9 | On step 8's map, apply each of these filters alone (*Filter*, Enter; then its ×): `SMB`, `NOT DNS`, `bytes > 10000`, `packets <= 3`, `host <a peer's /24>`, `duration > 1`. For each, compare an arrow's count with Hunt's for the same pair and window, adding the same condition (`AND network.protocol:smb`, `AND NOT network.protocol:dns`, and for bytes and packets, the records whose two fields add up as said). | Each filter is applied (no Elasticsearch error: a script error on `bytes` or `packets` means scripts are not allowed: README, *Things to verify*, item 13), and every count matches Hunt's. | Filters work against Security Onion's records (FIL-S8). | |

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

### SO-07 · The shared lists and saved maps outlive a redeploy; a second workstation reaches them through SO's firewall, and sees marks as they are made (FIL-S2, INT-S2, ATK-8)

CI runs the container once, and opens the map from the machine it runs on.

**Environment:** ENV-SO, and a second analyst workstation. **Starting state:** a map open on the
first workstation.

| # | Do | Expect | Proves | Result |
|---|---|---|---|---|
| 1 | Add `192.0.2.77` to the exclude list; mark `192.0.2.78` compromised (time blank); save the map as `redeploy`. | All three are listed. | | |
| 2 | On the manager, re-run `SO_CA=/etc/pki/ca.crt deploy/run.sh` (it replaces the container). Reload the page. | `192.0.2.77` is still excluded, `192.0.2.78` still compromised, and opening `redeploy` restores the map. | The state is kept in the `threatbridge-data` volume, not the container (FIL-S2, INT-S2). | |
| 3 | On the manager, make a certificate for the second analyst: `scripts/make-certs.sh client <name>`. On the second workstation, trust `certs/ca.crt`, import `certs/<name>.p12`, and browse to `https://<manager>:5443/`. | The map opens, and shows step 1's three entries. | SO's firewall lets analysts reach port 5443, and every analyst sees the same lists and saved maps (README, *Things to verify*, item 5; FIL-S2). | |
| 4 | On the second workstation, map a host with traffic and left-click an arrow; on its first flow, **Mark compromised**. | Within 5 seconds, the first workstation's side panel lists the flow under *Marked flows* and its two hosts under the compromised hosts. Nothing is hidden on either map: in Security Onion mode marks hide nothing (README). | Marks reach every analyst through the deployment (ATK-8). | |
| 5 | Clean up: **Remove** `192.0.2.77` and `192.0.2.78` and the marked flow from their lists; **Delete** `redeploy`. | The lists are as before step 1, on both workstations within 5 seconds. | | |

## 4. Where each requirement is tested

*Automated* names the tests in `tests/` that check the requirement on every CI run. The browser
suites are `ui_smoke.mjs` (demo data), `ui_case.mjs`, `ui_actions.mjs` and `ui_marks.mjs` (the
generated case) and `ui_mtls.mjs` (the container). *Manual* names the tests above.

| Requirement or decision | Automated | Manual |
|---|---|---|
| ING-1 PCAP ingest | `test_sources.py`, `test_case.py`; the case in `ui_case.mjs`, `ui_actions.mjs` | REAL-01 (a real capture) |
| ING-2 NetFlow ingest | `test_sources.py` (record pairing; a real nfcapd file through nfdump), `test_integration.py` (pcap and NetFlow in one case) | REAL-02 (a real exporter, against Zeek) |
| ING-3 Directories of pcaps, rotated captures | `test_sources.py` | |
| ING-4 Addresses, ports, times, protocol | `test_sources.py`, `test_case.py`, `test_backends.py` (Elasticsearch fields, configurable); flow lines in `ui_case.mjs`, `ui_actions.mjs` | REAL-01, REAL-02, SO-02 (field names on a live install) |
| ING-5 FTP data connections, as Zeek names them | `test_sources.py` (control messages; active, passive and EPSV transfers; a non-FTP greeting, the wrong side, too late, used once; read in worker processes) | REAL-01 step 5, REAL-02 step 4 (a real FTP session against Zeek) |
| ING-S2 Security Onion integration | `test_domains.py`, `test_backends.py` (Zeek DNS records); `test_soc.py` (Connect API against a stand-in); `ui_smoke.mjs` (PCAP links and download) | SO-03, SO-04, SO-05 |
| GRA-1 Directed graph | `test_case.py`, `test_backends.py`; `ui_actions.mjs` | SO-02 |
| GRA-2 Hosts and connections displayed | `ui_smoke.mjs`, `ui_case.mjs`, `ui_actions.mjs` (elements, labels, layout) | VIS-01 |
| GRA-3 Temporal ordering | `test_case.py`, `test_analysis.py`; `ui_actions.mjs` (time-chained hops, flows paged oldest first) | SO-02 (10,000-flow limit) |
| GRA-4 Interactive, clickable | `ui_smoke.mjs`, `ui_case.mjs`, `ui_actions.mjs` (clicks, menus, details) | VIS-01, XB-01 (other browsers) |
| GRA-S2 Time-range filtering | `test_case.py`, `test_api.py`; `ui_smoke.mjs`, `ui_case.mjs`, `ui_actions.mjs` | |
| GRA-S3 Connection metadata | `test_sources.py`, `test_backends.py`; `ui_case.mjs`, `ui_actions.mjs` | REAL-01, REAL-02, SO-02 |
| Bottom N exact (README, *Peer selection*) | `test_backends.py` (the paged scan, the cap), `test_case.py`; `ui_smoke.mjs` (rarest and the cap warning in the status) | SO-02 steps 6, 7 |
| ATK-1 Attack paths | `test_analysis.py` (against brute force), `test_case.py`; `ui_case.mjs`, `ui_actions.mjs` | VIS-02 |
| ATK-3 Predecessors and successors | `test_case.py`; `ui_smoke.mjs`, `ui_actions.mjs` | |
| ATK-4 Mark hosts compromised | `test_case.py`, `test_stores.py`, `test_marks.py` (hosts marked through flows, reached times, attack paths); `ui_smoke.mjs`, `ui_case.mjs`, `ui_actions.mjs`, `ui_marks.mjs` | VIS-02 |
| ATK-5 Mark a single flow | `test_marks.py` (store, API, locked in through filters); `ui_marks.mjs` (flow list, single-flow menu) | VIS-03 |
| ATK-6 Marked while any mark holds it | `test_marks.py` (counts, cascade); `ui_marks.mjs` | |
| ATK-7 Hide what isn't on a line through the marks | `test_analysis.py` (the user story's timeline; against brute force), `test_marks.py` (`/api/suspect`: parts, Window, time range, filters, sent marks); `ui_marks.mjs`, `ui_case.mjs` | VIS-02 step 2, VIS-03 |
| ATK-8 Marks shared within 5 seconds | `test_marks.py` (versions); `ui_marks.mjs` (a second analyst's page, both ways) | SO-07 step 4 (two workstations through the deployment) |
| ATK-9 Filters in threat lines and paths | `test_marks.py` (threat line, paths between hosts, attack paths, marked flows passing) | |
| INT-1 Threat line on edge click | `test_analysis.py`, `test_case.py`; `ui_case.mjs`, `ui_actions.mjs` | VIS-02 |
| INT-2 Earlier and later communications | `test_analysis.py`; `ui_case.mjs`, `ui_actions.mjs` | VIS-02 |
| INT-3 Iterative refinement | `ui_case.mjs`, `ui_actions.mjs` | |
| INT-4 Real-time update on new indicators | `test_case.py`; `ui_case.mjs`, `ui_actions.mjs` (redrawn on every change, answers out of order) | |
| INT-5 Clear resets only the preview | `ui_actions.mjs`, `ui_marks.mjs` | |
| INT-6 Apply as filter | `ui_marks.mjs` | |
| INT-7 Marked and suspect connections drawn; hidden count | `ui_marks.mjs` (classes, line styles, colours, legend, status), `ui_case.mjs` | VIS-02 step 2, VIS-03 |
| INT-8 Mark and unmark flows | `ui_marks.mjs`, `ui_actions.mjs` (the single-flow menu) | VIS-03 step 3 |
| INT-9 Confirmation before replacing the shared marks | `ui_marks.mjs` (Cancel, then OK) | XB-01 step 7b |
| INT-10 Laid out again after re-querying | `ui_marks.mjs` | |
| INT-S2 Save and restore sessions | `test_sessions.py`; `ui_actions.mjs` (shared and as a file; an opened map's own marks), `ui_marks.mjs` (filters, marks and queries saved; version 1 maps; Share), `ui_smoke.mjs` (the URL) | XB-01 (dialogs and files in other browsers), SO-07 (kept across a redeploy) |
| INT-S3 Export (JSON maps, CSV) | `test_marks.py` (`/api/export`, its limit); `ui_marks.mjs` (two CSV files, quoting, no formulas); `ui_actions.mjs` (map files) | XB-01 step 7b |
| FIL-1 IP exclude list | `test_api.py`, `test_query.py`; `ui_smoke.mjs`, `ui_actions.mjs` | SO-02 |
| FIL-2 Domain names with DNS resolution | `test_domains.py`, `test_sources.py`; `ui_case.mjs`, `ui_smoke.mjs` (what each entry resolved to) | REAL-01 (real DNS answers), SO-03 |
| FIL-3 Excluded traffic out of path calculations | `test_analysis.py`, `test_domains.py`; `ui_case.mjs`, `ui_actions.mjs` | |
| FIL-S1 CIDR | `test_query.py`, `test_case.py`; `ui_smoke.mjs`, `ui_actions.mjs` | |
| FIL-S5 Filter expressions | `test_filters.py` (grammar, errors, what they match; SQL and Elasticsearch against the Python test on random flows and expressions) | |
| FIL-S6 Filter list; a refused filter | `test_marks.py` (`/api/filter`, limits); `ui_marks.mjs` | VIS-03 steps 4, 5 |
| FIL-S7 Filters in every query; re-querying | `test_marks.py` (expansions, flow lists, connections, threat lines, paths; the filtered graph kept); `ui_marks.mjs` (replayed queries, skipped ones, marked hosts kept) | |
| FIL-S8 Both modes | `test_marks.py` (Elasticsearch bodies, demo backend), `test_filters.py` (Elasticsearch clauses) | SO-02 step 9 |
| FIL-S2 Exclude list kept and shared | `test_stores.py`, `test_integration.py`; `ui_actions.mjs` (seen by another analyst) | SO-07 (kept across a redeploy; a second workstation) |
| PRF-1 1M flows | `test_perf.py` (CI performance job) | |
| PRF-2 Built within 5 minutes under 100 MB | `test_perf.py` | |
| PRF-3 Responsive during traversal | `test_perf.py` (server timings, with filters and marks too); `ui_actions.mjs`, `ui_smoke.mjs` (requests in the background, Cancel, answers out of order) | PRF-01 |
| PRF-S1 Parallel reading | `test_sources.py` (the same flows as one at a time), `test_case.py` | |
| PRF-S3 Progress | `test_progress.py` (a simulated terminal, and the log); `ui_smoke.mjs`, `ui_actions.mjs` (busy indicator, Cancel) | TERM-01 (a real terminal) |
| EXT-1 Security Onion workflows | `test_integration.py` (SOC actions open the map), `test_query.py` (pivots, configurable); `ui_smoke.mjs` | SO-01, SO-06 |
| EXT-S2 API | `test_openapi.py` (every endpoint in API.md's index and in OpenAPI), the API tests | |
| EXT-S4 OpenAPI | `test_openapi.py` (the committed document is what `threatbridge/apidoc.py` generates; valid OpenAPI 3.1; the same operations as the routes and API.md's index; its examples match its schemas), `conftest.py` (every API response the tests get matches its schema) | |
| EXT-S5 Self-description | `test_openapi.py` (version, limits), `test_filters.py` (the vocabulary is what the parser takes), `test_case.py`, `test_backends.py` (protocol counts) | |
| EXT-S6 Map format | `test_openapi.py` (the format, and the maps the browser tests save) | |
| Mutual TLS | `mtls_check.sh`, `ui_mtls.mjs` (CI Docker job) | TLS-01 (a browser's own certificate store); ENV-SO uses it |
| D3 Edge left-click / right-click | `ui_smoke.mjs`, `ui_case.mjs`, `ui_actions.mjs` | XB-01 (other browsers) |
| D14 Protocols, and the highlight | `test_sources.py` (payload signatures, ports, FTP data connections, both readers), `test_case.py`, `test_backends.py`, `test_query.py` (Zeek's `network.protocol`); `ui_case.mjs`, `ui_actions.mjs`, `ui_smoke.mjs` (drop-down, highlight, saved maps) | VIS-01 step 5; REAL-01 steps 4, 5; REAL-02 steps 2, 4; SO-02 step 8 |
| D6, D7 Inputs, connection rules; refused connections left out | `test_sources.py`; `test_query.py`, `test_config.py` (Zeek's `REJ` in Elasticsearch) | REAL-01, REAL-02 (against Zeek); SO-02 step 5 |
| D8 Time order, hop limit | `test_analysis.py`, `test_case.py` | |
| D9 Capture DNS, then live DNS | `test_domains.py`; `ui_smoke.mjs` | SO-03 |
| D10 Flows in time order; time range | `test_case.py`; `ui_actions.mjs` | |
| D11 Paths between two hosts | `test_analysis.py`, `test_case.py`; `ui_case.mjs`, `ui_actions.mjs` | |
| D12 PCAP from the sensors | `test_soc.py`, `test_backends.py`; `ui_smoke.mjs` | SO-04, SO-05 |
| D13 Parallel reading, exact flows | `test_sources.py` | |
| D15 Marks on hosts and flows | `test_marks.py`, `test_stores.py`; `ui_marks.mjs` | VIS-03, SO-07 step 4 |
| D16 Suspect connections | `test_analysis.py`, `test_marks.py`; `ui_marks.mjs` | VIS-03 |
| D17 Filter expressions | `test_filters.py`, `test_marks.py`; `ui_marks.mjs` | SO-02 step 9 |
| D18 Hiding before dimming; Clear | `ui_marks.mjs` (hidden connections leave the drop-down; Clear), `ui_actions.mjs` | |
| D19 Saved maps and the shared marks | `ui_marks.mjs`, `ui_actions.mjs` | XB-01 step 7 |

Not built, so nothing to test: ING-S1 (out of scope), ING-S3, GRA-S1, ATK-2 and EXT-2
(deferred, D5), ATK-S1–S3, INT-S1, FIL-S3, FIL-S4, PRF-S2, EXT-S1, EXT-S3, FTODO-1, FTODO-2
([REQUIREMENTS.md](REQUIREMENTS.md)).
