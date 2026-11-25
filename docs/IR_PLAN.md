# Plan: making ThreatBridge work for incident response teams

Written 2026-11-24. ThreatBridge is going open source for third-party incident response
("smoke jumper") teams. They arrive after an intrusion and work from whatever the client kept:
packet captures, NetFlow, DHCP and Windows logs, from many devices. Nothing was recording
beforehand, so there is no baseline. That makes the mode that reads evidence files (case mode)
the core product; the live Security Onion mode is secondary.

This plan covers nine items chosen from the earlier review. They keep the numbers they had in
that list:

| No. | Item |
|---|---|
| 2 | Show how they got in |
| 4 | Show which account made each hop |
| 5 | Track which machine had which IP address over time |
| 6 | Read more formats |
| 9 | Deliverables: stable layout, path timeline, report |
| 11 | Login and Host-header check in local mode |
| 12 | Pin dependencies and sign releases |
| 13 | Measure it |
| 14 | Usability fixes |

## How the work is done

- The map's text stays plain: no explanatory hints in menus or labels (the owner's preference,
  2026-11-24).

- For each item: ask the owner the open decisions (listed per item, each with a
  recommendation), write the requirement into `docs/REQUIREMENTS.md`, write the tests, then the
  code. Nothing below is decided until the owner answers.
- One commit (or a few) per item, pushed to `claude/hopeful-brahmagupta-53h6a6`. CI must be
  green before the next item starts.
- Before every push: the unit tests, pyflakes, bandit, the browser suites, and the OpenAPI
  document regenerated after any API change (see `docs/REVIEW_HANDOFF.md`, "How to work in this
  repository").
- The status table at the end is kept up to date.

## Order of work

| Phase | Item | Why here |
|---|---|---|
| 1 | 11. Login and Host check | Small. Analysts will run this on laptops inside compromised networks. |
| 1 | 12. Pin dependencies (signing once the release target is decided) | Small. Later items add dependencies, which should go through the lock file. |
| 2 | 6. Formats | Well defined. pcapng is Wireshark's default, so it is the commonest input refused today. |
| 3 | 2. How they got in | The question IR teams are hired to answer. |
| 4 | 5. Machines behind addresses | Item 4 needs it to turn the computer names in Windows logs into addresses. |
| 5 | 4. Accounts on hops | Builds on 5. |
| 6 | 9 and 14. Deliverables and usability | Both change the map's code; doing them together avoids reworking it twice. |
| 7 | 13. Measure it | Measures the finished features; the synthetic part can start earlier. |

---

## 11. Login and Host check in local mode

**Problem.** `python -m threatbridge --case …` serves plain HTTP with no login. The review
showed that a request with a foreign `Host` header could read the marks and add an exclude.
A web page that rebinds its DNS name to 127.0.0.1 could therefore use the API from the
analyst's browser, and so could anyone else logged in to the same machine.

**Plan.**
- Refuse any request whose `Host` header names neither the address being served nor
  `localhost`, `127.0.0.1`, `[::1]` or a name in a new `TB_ALLOWED_HOSTS` setting (421
  Misdirected Request, JSON).
- Login (after the owner's choice below): at start-up, print a URL with a random one-time token.
  Opening it sets a cookie (`HttpOnly`, `SameSite=Strict`) and redirects to the map without the
  token. Every other request needs the cookie, or the token in an `Authorization: Bearer`
  header (for scripts). Compared in constant time.
- The container behind mutual TLS is unchanged.

**Tests.** A foreign Host gets 421 on reads and writes; the real one works; no cookie gets 401;
the token URL sets the cookie; a wrong token is refused; the mutual TLS checks in CI still pass;
the browser suites log in through the token URL.

**Decided 2026-11-24.** Token in the start-up URL, then a cookie. `--no-login` switches it
off, with a warning.

## 12. Pin dependencies and sign releases

**Problem.** The base image and dependency ranges are unpinned, and there is no lock file with
hashes. IR teams will install this inside client networks.

**Plan.**
- Python packages are managed with uv. `pyproject.toml` lists the dependencies (as ranges)
  and the test dependencies; `uv.lock` holds the exact versions and hashes of every package.
  The container and CI install from the lock file (`uv sync --frozen`).
- No requirements files are kept (Dependabot updates only `uv.lock`, so exported copies would
  go stale). `pip-audit` and each release export one from the lock file with hashes; pip users
  can do the same (`uv export`).
- Playwright for the browser tests is locked in `package.json` and `package-lock.json`
  (`npm ci`).
- The base image pinned by digest in the `Dockerfile`.
- GitHub Actions pinned to commit hashes instead of tags.
- Dependabot opens pull requests to update the lock file, the image digest and the Actions.
- Releases: on a version tag, a workflow builds the source archives (`.tar.gz` and `.zip`),
  signs them with Sigstore (keyless, through GitHub's identity, so there is no key to keep),
  records a build provenance attestation, and attaches the archives, their signatures and a
  list of the locked dependencies to the GitHub release. No container image is published (CI
  still builds one to test it). The README says how to verify a release.

**Tests.** CI installs from the lock files; `tests/test_supply_chain.py` fails if an Action,
a base image or Playwright is unpinned, if the uv versions disagree, or if `uv.lock` is out of
step with `pyproject.toml`; the workflows are checked with `actionlint`. Publishing itself can
only be tried on a real tag.

**Decided 2026-11-24.** Signed source archives only. A lock file for the container and CI,
with uv managing Python packages.

## 6. Read more formats

**pcapng.**
- Today a pcapng file is refused with advice to convert it.
- dpkt's own pcapng reader uses only the first interface's link type and timestamp resolution;
  a Wireshark capture on two interfaces would be misread. So: a small block reader of our own,
  covering section headers (several sections, either byte order), interface descriptions (link
  type, timestamp resolution and offset per interface), enhanced, simple and obsolete packet
  blocks, and skipping all other blocks.
- Packets go to the existing decoder, so everything else (refused connections, FTP, DNS answers,
  a file cut off mid-packet) works as for pcap.
- Tests: pcapng written by hand from raw bytes (not by the reader's own library), with two
  interfaces of different link types and timestamp resolutions, big-endian, a cut-off last
  block, and the same packets as an existing pcap test giving the same flows.

**Community ID** (a standard hash of a connection's addresses, ports and protocol that Zeek,
Suricata, Arkime and Security Onion all record, so a connection can be found in each by one
string).
- Version 1 as published, seed 0.
- Security Onion mode uses the value Zeek already recorded.
- ICMP flows have none in case mode: the readers keep no ICMP type and code.
- Tests: the published test vectors for TCP, UDP, IPv4 and IPv6.

**Two-way IPFIX records** (RFC 5103: one record covers both directions of a connection).
- nfdump prints reverse packet and byte counts (`%opkt`, `%obyt`).
- First check whether nfcapd keeps them from an IPFIX export with reverse fields, by sending it
  one.
- If it does, a record with reverse counts is taken as a whole connection, oriented as
  exported, without the pairing of one-way halves. If it doesn't, the README says so and the
  item stops there.
- Checked 2026-11-24: nfcapd 1.7.3 keeps them (and the `post*` counters) as "out" packets and
  bytes, so two-way records are read.

**Decided 2026-11-24.** Community ID is computed when shown (flow list, CSV export, report),
not stored. pcapng packets from all interfaces are read as one capture.

## 2. Show how they got in

**Problem.** The map follows only connections the compromised host opened. Phishing, drive-by
downloads and reverse shells are the victim connecting *out*, so the trace back stops at the
first internal host. And there is no way to start from an outside address.

**Plan.**
1. **"Inside".** A setting listing the client's internal networks, by default the private
   ranges (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, and link-local). Used below and
   shown in the map's settings.
2. **Outbound before, and inbound after.** Today "inbound" means peers that connected to the
   host before the anchor time, and "outbound" means hosts it connected to after it. The
   neighbours query gets a `time` parameter (`before` or `after`), so all four combinations
   exist. The host menu gains "Outbound before" and "Inbound after". The attack-path and
   threat-line rules stay as they are (each hop opened by the host the attacker is on).
3. **Who talked to it.** Given an outside address, a network, or a domain name, list every
   inside host that exchanged traffic with it, in either direction, over the whole time range:
   first and last seen, number of flows, bytes each way. They can be added to the map.
   - A domain name means the addresses the capture's DNS answers gave it (Zeek's DNS records
     in Security Onion mode).
   - Live DNS answers today's addresses, not those at the time, so it is not used here.
4. **Beacons and long connections.**
   - A beacon score per source, destination and port: how regular the times between
     connections are and how alike their sizes are.
   - A long connection is one longer than a threshold. NetFlow splits long connections into
     pieces; the existing pairing rejoins them.
   - Shown as a mark on connections and in the details panel, as a list ("Beacons and long
     connections"), and as filter terms.
   - Case mode first; Security Onion mode would need aggregations of its own.
   - Written from the published descriptions of RITA's method, not its code (RITA is GPL; this
     project is MIT).

**Tests.** A synthetic case with a victim that connects out to a staging server before the
IOC time, then moves laterally:
- the outbound-before expansion finds the staging server;
- "who talked to" the staging server finds the victim and a second infected host;
- a beacon with jitter scores high, random traffic scores low;
- a connection split into NetFlow pieces counts as one long connection.

Plus API, OpenAPI and browser tests.

**Decided 2026-11-24.**
1. Inside networks: a setting, with the private ranges above as default.
2. Outbound before: a `time` parameter and two menu items, "Outbound before" and "Inbound
   after", with no explanatory hints in the menu (the owner finds them clutter).
3. Who talked to it: up to N hosts added to the map, the rest in a list.
4. Beacon scores computed when the case is built (existing cases are rebuilt once); a
   connection is long from 1 hour (a setting).

## 5. Track which machine had which IP address over time

**Problem.** Over weeks, addresses change hands. A chain can then join two different machines,
or break when one machine changes address.

**Plan.**
- Read DHCP leases into a table: address, MAC address, host name, from, to. Sources:
  - Windows DHCP server audit logs (`DhcpSrvLog-*.log`);
  - Zeek's `dhcp.log`;
  - DHCP replies seen in the captures.
- On the map, a host shows the name and MAC address it had at the time of each connection.
- A host whose address was held by more than one machine within the map's time range gets a
  warning, and the details panel lists who held it when.
- The same table resolves computer names to addresses for item 4.

**Tests.** Each log format, from real-format samples written by hand; an address handed from
one machine to another, warned about; leases that overlap or are renewed.

**Decided 2026-11-24.**
1. Inputs: Windows DHCP server audit logs, Zeek `dhcp.log`, DHCP in the captures, and ISC
   dhcpd leases files.
2. Scope: names and warnings only; hosts stay keyed by address.

## 4. Show which account made each hop

**Patent note.** Microsoft's patent US10505954B2 covers a graph of computers and accounts from
connections and logons, with edges weighted by rarity and paths ranked by a score. This item
labels hops with accounts only: no rarity weights, no scores, no ranking. Whether that is
enough is a legal question; get a patent attorney's view before release.

**Plan.**
- Read Windows Security events:
  - 4624 (logon), and 4625 (failed logon) if wanted, recorded on the host logged on to;
  - 4648 (logon with explicit credentials), recorded on the host the account came from;
  - 4768 and 4769 (Kerberos tickets), recorded on the domain controller.
- Match each event to flows:
  - by the addresses in it, or computer names turned into addresses through item 5's table,
    the capture's DNS answers, or a hosts file the analyst gives;
  - by time, within a tolerance for clock differences;
  - by port, for example SMB, RPC, RDP and WinRM for a network logon.
- Show the accounts on a connection in the details panel, per flow in the flow list, per hop in
  path timelines (item 9), and in the export and report.
- On a path, a change of account between hops is flagged.

**Tests.** Events written by hand in the input format chosen, matched and not matched (wrong
time, wrong port, unknown computer); an account change flagged along a path.

**Decided 2026-11-24.**
1. Input: raw `.evtx` files through the `evtx` library, plus JSON lines of the same events.
2. Events: 4624, 4648, 4768 and 4769; not 4625.
3. Time tolerance between an event and its flow: 2 minutes by default, a setting.
4. A filter term for accounts: not asked; later.

**Built.** `.evtx` reading was checked by hand on public sample logs (a WMI and a
scheduled-task lateral movement from EVTX-ATTACK-SAMPLES): the network logons became claims,
and machine accounts and anonymous logons were left out. Those samples have no capture, so
matching to flows on real logs waits for TEST_PLAN WIN-01. Windows can log one logon twice at
the same instant; such duplicates give one label.

## 9. Deliverables

1. **Keep hosts where the analyst put them.** Today every expansion lays the whole map out
   again.
   - Existing hosts stay put; new ones go in free space next to the host they came from.
   - A *Tidy* button lays everything out again.
   - Saved maps already keep positions.
2. **A timeline of a path.** For an attack path, a path between two hosts, or a threat line: one
   row per hop with its time, the gap since the previous hop, ports, protocol, bytes and the
   accounts (item 4). It can be copied as text and goes into the report.
3. **A report.**
   - A single self-contained file of the analysis: the case (evidence files, time span, flows),
     an image of the map, marked hosts with times and notes, marked and suspect flows, paths
     with their timelines, the filters and excludes in force, the settings, and the tool's
     version.
   - Generated in the browser from what the map holds, plus one server call for the case
     summary.

**Tests.** Browser tests: a moved host stays put after another expansion, and *Tidy* re-lays
everything out; the timeline's rows match the path; the report contains each section and
escapes what it shows (addresses and notes come from evidence and analysts).

**Decisions.**
1. Placement: our own code for placing new hosts (recommended; no new library), or the fcose
   layout plugin (three new vendored files)?
2. Report format: (a) self-contained HTML, which prints to PDF from any browser (recommended);
   (b) Markdown; (c) both.
3. Evidence hashes (SHA-256) in the report? They make the report usable for chain of custody,
   but hashing gigabytes takes time. Recommended: compute them when the case is built and keep
   them in the case database (existing cases are rebuilt once).

**Decided 2026-11-24.**
1. Placement: our own code; no new library.
2. Report format: both, a self-contained HTML file and a Markdown file.
3. Evidence hashes: computed when the report is made, not when the case is built.

## 14. Usability fixes

From the review, each reproduced in a browser:

1. **Pressing Enter in a toolbar box wipes the map without asking.** Proposed:
   - Enter in *Window*, *N* or the time range only changes later expansions; only *Map* starts
     afresh.
   - Ask before discarding a map with more than its first expansion.
   - Keep the working map in the browser, so a reload restores it.
2. **No confirmation for shared, far-reaching actions.** *Add to shared exclude list* (it sits
   under *Remove from map*), and *Remove* on a marked host (which also removes its marked flows
   for everyone). Proposed: confirm both, naming what else goes.
3. **Keyboard and labels.**
   - Menus, saved-map names and path entries work only with a mouse.
   - Eight inputs have no label, and *Open file* can't be reached from the keyboard.
   - Proposed: menus open from the keyboard (the context-menu key or Shift+F10 on the selected
     host or connection) and work with the arrow keys; every input labelled; a "Find host"
     box to select a host without the mouse.
4. **Three reds mean three things.** The IOC host, attack paths and compromised hosts are all
   red. Proposed: the IOC host gets its own shape (a diamond with a white border) as well as its
   colour.
5. **Labels overlap** at around 40 hosts, and timestamps in the details panel break mid-value.
   Proposed:
   - address labels hidden when zoomed out and shown on hover and selection;
   - spacing that grows with the number of hosts;
   - timestamps that never wrap.

**Tests.** In the browser suites, one per fix. How it looks is checked by hand.

**Decisions.** Each proposal above, accept or change.

**Decided 2026-11-24.**
1. Enter, asking before discarding, restoring after a reload: as proposed.
2. Confirm *Remove* on a marked host (naming the marked flows that go with it). *Add to shared
   exclude list* stays as it is.
3. Keyboard and labels: as proposed.
4. and 5. The IOC host's shape, labels and timestamps: as proposed.

## 13. Measure it

**Plan.**
1. **Synthetic injection, runs in CI.**
   - Generate a benign background (office-like traffic, as the performance test does) and
     inject attack chains: initial access by an outbound connection, then lateral movement.
     Two variants: busy hosts and quiet hosts, after Apruzzese et al.
   - Report for each chain, from its first host and time:
     - the share of the true hops found by threat lines, suspect connections and paths;
     - how many hosts the analyst would look at, against how many were active;
     - the time taken.
   - CI fails if the numbers drop below a floor.
2. **Public data with ground truth.** A loader for the LANL 2015 data (NetFlow plus labelled
   red-team logons; computer names mapped to stable made-up addresses), and for DARPA OpTC's
   network events if practical.
   - The owner downloads the data; its terms are the owner's to accept.
   - Results go into `docs/RESULTS.md` with the version, date and machine.
3. **Statuses that mean what they say.** Mark the requirements never run against real data as
   *Unverified* until they are, and add a results table to `docs/TEST_PLAN.md`.
4. **A pilot kit for IR teams**, `docs/PILOT.md`:
   - how to install and run it on a closed case;
   - what to record: time to scope, hosts it pointed at against hosts confirmed, what it missed,
     what got in the way;
   - a feedback template.

**Decisions.**
1. Is a CI floor wanted, and at what level? Recommended: set it at the first measured numbers
   minus a margin, and raise it as features land.
2. Which public dataset first? Recommended: LANL 2015, which has labelled lateral movement.
3. Mark untested rows *Unverified* (recommended)?

**Decided 2026-11-24.**
1. CI floor: at the first measured numbers minus a margin, raised as features land.
2. Datasets: both; LANL 2015 first, then DARPA OpTC's network events if practical.
3. Statuses: requirements stay *Done*; their notes say what hasn't been tried on real data.

**Built.** The synthetic measurement runs in CI with floors; its first numbers are in
`docs/RESULTS.md`. The LANL 2015 loader is tested on files written in its format but not yet run
on the real data, which the owner downloads. OpTC is not loaded: its ground truth is a written
report (a PDF), and its flows are Zeek logs, which the case backend doesn't read; a Zeek
`conn.log` reader and transcribed labels would come first. The pilot kit is `docs/PILOT.md`.

## Follow-ups (owner, 2026-11-25)

1. **Zeek logs MUST be parsed.** conn.log and dns.log as evidence, TSV or JSON, plain or gzip
   (D36, ING-12).
2. **Labels shrink when the map zooms out**, instead of being hidden (D34 changed).
3. **The map is redrawn only when the analyst asks**: *Tidy* (toolbar, or right-click the map's
   background), *Fit* likewise; new hosts still get a place, and nothing else moves or rescales.
4. **Remove from map asks first.** The owner's reason was that it affects other analysts'
   views; it doesn't (it changes only this map, until the map is saved), but the question is
   kept as asked. *Add to shared exclude list* is the action that does change everyone's view.

---

## Status

| Item | Decisions | Requirement | Tests | Code | CI |
|---|---|---|---|---|---|
| 11. Login and Host check | decided | done (D23, SEC-1, SEC-2) | done | done | green |
| 12. Pin and sign | decided | done (D24, SEC-3 to SEC-5) | done | done | green |
| 6. Formats | decided | done (D6, ING-6 to ING-8) | done | done | green |
| 2. How they got in | decided | done (D25, D26, ATK-10 to ATK-12) | done | done | green |
| 5. Machines behind addresses | decided | done (D27, ING-9, ING-10) | done | done | green |
| 4. Accounts on hops | decided | done (D28, ING-11, ATK-13) | done | done | green |
| 9. Deliverables | decided | done (D29 to D31, INT-10, INT-11, ATK-14) | done | done | green |
| 14. Usability | decided | done (D32 to D34, INT-12 to INT-14, GRA-5) | done | done | green |
| 13. Measure it | decided | done (D35, EVA-1, EVA-2) | done | done | green |
| Follow-up 1. Zeek logs | given | done (D36, ING-12) | done | done | green |
| Follow-ups 2 to 4. Map | given | done (D29, D32 to D34, GRA-5, INT-10, INT-13) | done | done | green |
