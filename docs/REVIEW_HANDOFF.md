# Handoff: fixes and tests from the 2026-11-10 adversarial review

For whoever picks this up next. It lists what the review found, how to reproduce each finding,
where the code is, the tests to write first, and the decisions that belong to the owner.
Nothing here has been fixed yet. Line numbers are as of commit `e2d1f31`.

## How to work in this repository

- **Process, per item:** ask the owner about any design choice (the *Decide first* lines below),
  then write the requirement into `docs/REQUIREMENTS.md`, then the test, then the code. Do not
  assume a design choice; each one below comes with a recommendation, not a decision.
- **Branch:** `claude/hopeful-brahmagupta-53h6a6`. Commit and push there. No pull request unless
  asked.
- **Checks before every push:**

  ```bash
  pip install -r requirements.txt -r requirements-test.txt
  python -m pytest -q                                   # 1635 passed, 4 skipped at e2d1f31
  python -m pyflakes threatbridge tests
  python -m bandit -q -ll -r threatbridge
  python -m threatbridge.apidoc                         # after any API change: regenerate openapi.json
  TB_PERF=1 python -m pytest -q -s tests/test_perf.py   # about 2 minutes
  ```

  The four browser suites run as in `.github/workflows/ci.yml` (job *UI tests*): a demo server on
  5055, a case server on 5056 from `tests/make_case.py`, then `tests/ui_*.mjs`.
- **Every API response in the tests is checked against `threatbridge/openapi.json`**
  (`tests/conftest.py`). A new status code or field must be added in `threatbridge/apidoc.py`
  first, or the tests fail.
- **To try something under gunicorn without TLS,** start it from another directory with
  `PYTHONPATH` set to the repository. Started from the repository root it loads
  `gunicorn.conf.py`, which needs the certificates.

## Order of work

| Batch | Items | Why first |
|---|---|---|
| 1. Evidence can be trusted | H1, H2, M2, L1, L3 | A capture that won't load, or a map an attacker can edit, defeats the tool |
| 2. The service stays up | H3, M3, M5, M6, L5 | One analyst, or one bad input, can stall or break it for everyone |
| 3. Who did what | H5, M1, M7 | Shared state with no identity or history |
| 4. The map | M4, U1 to U6, L2 | Analysts lose work or are misled |
| 5. Spec and tests | H4, S1 to S4, C1 to C3 | So the statuses mean what they say |

Severity: **H** high, **M** medium, **L** low, **U** UX, **S** spec, **C** codebase.
*Ran* means the review reproduced it; *read* means it comes from reading the code only.

---

## H1. One IPv6 IPsec packet makes a capture unloadable (ran)

- **What happens.** Any well-formed IPv6 ESP packet (next header 50) stops the case from loading:
  `AttributeError: 'IP6' object has no attribute 'p'`, and `python -m threatbridge --case` exits 1.
  dpkt sets `p` only when an extension header names a next header; ESP's is encrypted.
- **Where.** `threatbridge/sources/pcap.py:363` reads `ip.p`. The per-packet `except` at
  `pcap.py:340` covers only `dpkt.Error`, `IndexError` and `struct.error`, and only the decode call.
- **A second crash,** crafted only: an IPv6 frame with a fragment header (next header 44) and a
  corrupt version nibble raises `AttributeError` inside dpkt (`'IP6HopOptsHeader' object has no
  attribute 'frag_off'`).
- **Reproduce.**

  ```python
  import socket, struct, dpkt
  from threatbridge.sources import pcap as P
  src, dst = (socket.inet_pton(socket.AF_INET6, a) for a in ("2001:db8::1", "2001:db8::2"))
  esp = b"\x00\x00\x10\x01" + b"\x00\x00\x00\x07" + bytes(range(64))        # SPI, sequence, ciphertext
  ip6 = b"\x60\x00\x00\x00" + struct.pack("!HBB", len(esp), 50, 64) + src + dst + esp
  with open("/tmp/esp.pcap", "wb") as fh:
      dpkt.pcap.Writer(fh, linktype=1).writepkt(b"\x00" * 6 + b"\x11" * 6 + b"\x86\xdd" + ip6, ts=1714564800)
  list(P._decoded("/tmp/esp.pcap", {}, P._Counts()))                        # raises
  ```

- **Fix direction.** No single packet may stop a case. Wrap everything done per packet (decode,
  size, classification, DNS, FTP) so that any exception counts the packet as skipped. For IPv6,
  take the protocol from the last extension header when `p` is missing, so ESP becomes a flow
  with protocol `50` and no ports, as IPv4 ESP already does.
- **Tests first.**
  - The packet above gives one flow, protocol `50`.
  - The crafted fragment-header packet is skipped and the capture's other flows load.
  - A seeded fuzz test (20,000 mutated frames over the six link types, a few seconds) asserts
    that nothing raises past `_decoded`. The review's fuzzer mutated bytes, truncated, inserted
    bytes, swapped the ethertype and planted DNS compression pointers; 1.2M packets found only
    the two crashes above.
  - Build these packets from raw bytes, not with dpkt: every capture in `tests/` is written by
    the library the reader uses, so they share its blind spots (see C1).
- **Decide first.** Should skipped packets be reported in the map (the case summary), not only
  in the log? Recommended: yes, a count in `GET /api/config`'s `case`.

## H2. A forged DNS answer hides an attacker behind an excluded name (ran)

- **What happens.** `record_dns` (`pcap.py:297`) takes any UDP packet from port 53 that parses as
  a response. It needs no matching query and does not care who sent it. One unsolicited answer
  from the attacker's own host, `updates.vendor.com A 203.0.113.66`, ties that name to the
  attacker. With the name on the exclude list, the attacker left the victim's inbound peers and
  `GET /api/paths` went from 1 path to 0.
- **The README is wrong here:** `README.md:81` says a crafted response can't tie a benign name
  to an attacker's address. The check it describes only covers extra records inside one answer.
- **Security Onion mode has the same weakness,** and the README admits it there: Zeek logs every
  DNS transaction, including a host asking an attacker's own server.
- **Reproduce.** With the helpers in `tests/evidence.py`: a capture of
  `203.0.113.66 -> 10.0.0.9:445`, `10.0.0.9 -> 10.0.0.20:445`, and one packet
  `udp("203.0.113.66", "10.0.0.250", 53, 40000, dns_answer("updates.vendor.com", [("updates.vendor.com", "A", "203.0.113.66")]))`.
  Load it, `POST /api/excludes {"entry": "updates.vendor.com"}`, then ask for the inbound peers
  of `10.0.0.9`.
- **Fix direction.** Matching answers to queries is not enough: malware can ask its own server.
  The answer has to come from a resolver the analysts trust.
- **Decide first.**
  1. Which answers count? (a) Only from resolvers listed in a new setting (recommended; Security
     Onion mode filters on the DNS record's server address the same way). (b) Any answer that
     matches a query seen just before, from the server that was asked. (c) Both.
  2. With no resolver list set: use no capture answers, or all of them with a warning in the
     side panel? Recommended: all, with the warning, so today's behaviour doesn't change silently.
  3. Should the side panel show which server gave each address? Recommended: yes.
- **Tests first.** The forged answer is ignored when resolvers are listed; an answer from a
  listed resolver still works; the side panel names the server; the same in the Elasticsearch
  query (`query.es_dns_body`). Then correct `README.md:81`.

## H3. Attack-path searches grow steeply with marks, and nothing bounds them (ran)

- **Measured** on the perf test's week of 1M flows (`tests/test_perf.py::busy_week`), calling
  `CaseBackend.attack_paths` with a time on each mark:

  | Marked hosts | The busiest hosts | Workstations |
  |---|---|---|
  | 10 | 5.3 s | 2.7 s |
  | 20 | 17.6 s | – |
  | 40 | 75.9 s | 26 s |
  | 100 | – | stopped at 240 s |

- **Why it hurts.**
  - Every open map asks for this again on every change to the marks or excludes
    (`threatbridge/static/app.js:1095`), so each analyst multiplies it.
  - *Cancel* only aborts the browser's request. The server keeps computing.
  - `gunicorn.conf.py:8` (`timeout = 120`) does not stop a request: with threaded workers the
    timeout is the worker's heartbeat. A 12 s CPU-bound request survived `--timeout 4`.
  - One running search slowed a host expansion in the same process from 0.16 s to 0.62 s.
  - `MAX_STEPS` (`analysis.py:199`) bounds one pair, not the request; marks go up to 10,000
    (`compromised.py:17`).
- **Fix direction.** Three independent parts:
  1. A time budget per request, checked inside the search loops (`spread`, `_layer`,
     `paths_between`); when it runs out the answer is marked truncated.
  2. One computation per state: cache the attack-path answer by marks version, filters, window,
     hop limit, time range and excludes, so ten maps cost one search.
  3. The map asks less often: once per change after a short pause, and not at all when the
     marks it already drew are unchanged.
- **Decide first.**
  1. The budget: a setting with what default? Recommended: 10 s, the perf test's own threshold.
  2. When the budget runs out: a truncated answer with a warning (recommended), or an error?
  3. Should all-pairs attack paths stop being automatic above some number of marks (a button
     instead)? Recommended: automatic up to 20 marked hosts.
- **Tests first.** The budget with an injected clock; a second identical request does not search
  again; the perf test gains 40 marked hosts and asserts the budget holds; a browser test that
  two marks made quickly cause one request. Correct the comment in `gunicorn.conf.py`.

## H4. "Done" for what has never run against the real thing (read)

- **What.** The README says deployment on a live Security Onion is untested, and every capture
  in the tests is generated. Yet ING-4, ING-S2, GRA-S3 and FIL-S8 are *Done*; the *Unverified*
  status in the legend of `docs/REQUIREMENTS.md` is never used. `docs/TEST_PLAN.md` has 16
  manual tests and no recorded result for any.
- **Fix direction.** Requirements only: mark those rows *Unverified* until SO-01 to SO-07 and
  REAL-01/02 have a recorded pass; add a results table (date, tester, version, outcome) to the
  test plan.
- **Decide first.** Whether *Done* may ever mean "tested against a stand-in". Recommended: no.

## H5. Shared state has no identity, history or undo (read)

- **What.** Any certificate holder can replace every mark (`compromised.py:170`), delete any
  saved map (`sessions.py:103`), exclude a host for everyone, and pull PCAP through the one SOC
  API client (`app.py:460`). `gunicorn.conf.py:10` logs requests without the client's identity,
  and the app's own log lines name no one. Certificates last 825 days
  (`scripts/make-certs.sh`) and nothing can revoke one.
- **Fix direction.**
  - Identity: under gunicorn the client socket is in the WSGI environment (`gunicorn.socket`,
    present in gunicorn 23); its `getpeercert()` should give the subject. Not tried under TLS.
  - An append-only log of every write: who, when, what changed, the state before.
  - Revocation: a CRL checked by the TLS context (gunicorn's `ssl_context` hook, present in
    gunicorn 23).
- **Decide first.**
  1. Is the audit log a file beside the shared lists, or log lines only? Recommended: a file,
     one JSON object per line, so an undo can be built on it.
  2. Should marks and saved maps record who made them, and show it? Recommended: yes.
  3. Undo for *Share*, *Unmark* and *Delete*: in scope now, or the log only? Recommended: log
     now, undo later (INT-S1 is already *Missing*).
  4. Revocation by CRL file, or shorter-lived certificates? Recommended: CRL file.
- **Tests first.** `tests/mtls_check.sh` gains: each write appears in the audit log with the
  certificate's name; a revoked certificate is refused at the handshake.

---

## Medium

### M1. Local mode has no authentication and no Host check (ran)
- `python -m threatbridge --case` (the documented post-mortem flow, `app.py:515`) serves plain
  HTTP on 127.0.0.1. A request with `Host: evil.example` read the marks and wrote an exclude,
  so a page that rebinds its DNS name to 127.0.0.1 can use the API from a browser without
  private-network checks. Other users of the same machine can too. The review did not run a
  live rebinding attack.
- **Fix direction.** Refuse requests whose Host is not the address being served
  (`127.0.0.1`, `localhost`, `[::1]`, plus a setting). **Decide first:** also print a one-time
  token in the URL at start-up for local mode? Recommended: Host check now, token only if asked.
- **Tests first.** A foreign Host gets 400 on reads and writes; the real one works; the mTLS
  container is unaffected.

### M2. Refused connections are discarded when a capture is read (ran)
- `model.refused` (`model.py:89`) drops any TCP exchange of SYN-without-ACK answered only by
  RST. Ten SYN packets with payload, each answered by a RST with payload, gave 0 flows: data can
  cross unseen. A compromised host's port scans vanish the same way. Case mode has no switch;
  Security Onion mode has `TB_FIELD_CONN_STATE=`.
- **Decide first.** (a) Keep refused connections as flows carrying a state, left out by default
  and brought in by a filter term (recommended; the store's version goes up, so cases rebuild).
  (b) Keep them only when they carry payload. (c) Leave as is and document it.
- **Tests first.** The SYN/RST capture above under the chosen rule; a scan still does not swamp
  the default map.

### M3. A backend failure during re-query is reported as a filter result (ran)
- `requery` (`app.js:390`) counts every failed query as skipped (`app.js:401`) and says
  "found nothing that passes them". With one 502 injected, a host left the map and the status
  showed no error.
- **Fix direction.** Tell "no flows" (400 from a threat line) from failures; report failures in
  the error style and say the map is incomplete.
- **Tests first.** `tests/ui_actions.mjs`: route one `/api/neighbors` call to a 502 during a
  re-query and assert the wording and the error class.

### M4. Elasticsearch partial results look complete (read)
- `ElasticBackend._post` (`backends.py:149`) ignores `_shards.failed` and `timed_out`.
- **Decide first.** Fail the request (502), or answer with a warning the map shows?
  Recommended: answer, with a `partial` flag and a warning in the status line.
- **Tests first.** Stand-in responses with failed shards and with `timed_out: true`.

### M5. gunicorn rejects long filter lists (ran)
- The map sends filters in the query string (`app.js:169`). Eight filters of about 500
  characters (4.6 KB) got gunicorn's HTML 400 "Request Line is too large"; the documented limit
  is 20 filters of 500 characters.
- **Fix direction.** `ask` (`app.js:163`) uses POST whenever there are filters.
- **Tests first.** A browser test with 20 filters of 500 characters, run through the container
  in the CI job *Docker build + mTLS* (the development server the other suites use accepts
  far longer request lines, so they would pass either way).

### M6. Inputs with no bound (ran)
- **Request bodies:** no `MAX_CONTENT_LENGTH`; a 50 MB body was read whole (`app.py:90`).
- **Exclude list:** no size limit (`excludes.py:30`); 3,000 entries went in, and adding them
  took 85 s because each add re-reads and re-checks the whole list.
- **Saved-map names:** a name of 100 non-ASCII characters returned 500 and left an orphan
  temporary file in the sessions directory, because the base64 file name exceeds 255 bytes
  (`sessions.py:38`, `jsonstore.py:60`).
- **Fix direction.** A body limit sized for the largest legitimate request (20,000 drawn
  connections plus 100,000 `within` intervals: measure it); an exclude limit in `limits`; file
  names from a hash of the name; `write_atomically` removes its temporary file on failure.
- **Decide first.** The exclude limit (recommended 5,000) and whether existing longer lists are
  refused or grandfathered.
- **Tests first.** Each bound returns a JSON 400 (413 for the body); the sessions directory is
  clean after a failed save; `limits` in `/api/config` lists the new bounds.

### M7. `TB_ES_VERIFY=false` also turns off certificate checks for SOC (read)
- `soc.py:33`: `verify = cfg.soc_ca or cfg.es_ca or cfg.es_verify`. The request it protects
  sends the API client secret.
- **Fix direction.** A separate `TB_SOC_VERIFY`, default true. **Tests first:** in
  `tests/test_soc.py`, and the README's settings table (a test keeps it in step).

---

## Low

### L1. Malformed input returns HTML 500s (ran)
- `GET /api/neighbors?ip=10.0.0.9&ts=0001-01-01T00:00:00%2B23:59` (`query.py:68`), the same
  with `ts=0001-01-02T00:00:00Z&window=30d` (anchor minus window), and a window of 5,000 digits
  (`query.py:46`) all return 500. Unknown routes and wrong methods answer in HTML; a body that
  is not JSON is treated as empty (`app.py:90`).
- **Fix direction.** `OverflowError` and over-long numbers become `ValidationError`; JSON
  handlers for 404, 405 and unexpected errors; a non-JSON body is a 400 that says so.
- **Tests first.** One per case; add the statuses to `apidoc.py`.

### L2. A mark dated before year 1000 is accepted, then dropped (ran)
- `POST /api/compromised {"ip": "10.0.0.9", "time": "0900-06-01T00:00:00Z"}` returns 200 with
  no mark: `fmt_time` (`query.py:72`) writes the year unpadded, and the reader rejects it on
  every later read. The bad entry stays in the file.
- **Fix direction.** Pad the year, or refuse times outside a sane range. **Decide first:**
  which range? Recommended: 1970 to 2100.

### L3. `proto 6` matches nothing (ran)
- `filters._transport_value` (`filters.py:239`) accepts protocol numbers, but flows store
  `tcp`, `udp` and `icmp` by name (`model.py:4`), so `proto 6`, `proto 17` and `proto 1` never
  match. **Decide first:** read them as the names (recommended; the canonical text then says
  `proto == tcp`), or refuse them with a hint.

### L4. Notes on marks exist only in the API (ran)
- The API stores a `note`; the map never shows one and has nowhere to type one
  (`app.js:896`). The CSV export's note column is always empty from the map.
- **Decide first.** Add notes to the map (recommended), or remove them from the API (a breaking
  change: the API version goes up).

### L5. A PCAP download holds a request thread for up to 90 s (read)
- `SocClient.pcap` (`soc.py:40`) polls inside the request; there are 8 threads by default.
  Each download also leaves a job in SOC. **Fix direction:** at most N downloads at once, the
  rest answered 503 with a retry hint. **Decide first:** N (recommended 2).

---

## UX

All reproduced in headless Chromium against the case server unless marked.

- **U1. Enter in a toolbar box restarts the map without asking** (`app.js:673`, `app.js:345`).
  Changing *Window* to 12h and pressing Enter took a map from 4 hosts to 3. Opening a saved map
  wipes the current one the same way (`app.js:1261`); a reload keeps only the root.
  **Decide first:** (a) Enter in *Window*, *N* and the range applies to later expansions only,
  and only *Map* restarts; (b) ask before discarding a map with more than its root expansion;
  (c) keep the working map in the browser's storage. Recommended: all three.
- **U2. Every expansion discards manual layout** (`app.js:203`). A host moved to (987, 654) was
  back at (452, 450) after another host was expanded. **Decide first:** keep existing hosts
  where they are and place only new ones (recommended), with a *Tidy* button for a full layout.
  This revisits INT-10.
- **U3. Shared, far-reaching actions have no confirmation** (read). *Add to shared exclude list*
  sits under *Remove from map* (`app.js:632`); *Remove* on a marked host also removes its marked
  flows for everyone (`app.js:880`). **Decide first:** confirm both, naming what else goes
  (recommended). INT-9 currently limits confirmation to *Share*.
- **U4. Keyboard and labelling.** Menu items, saved-map names, path entries and the graph are
  mouse-only; 8 inputs have a placeholder but no label; *Open file* hides its input from the
  keyboard (`display: none`).
- **U5. Three reds mean three things.** IOC root against attack path is 1.21:1, root against
  compromised 1.67:1. Recommended: a shape or border for the root, not only a colour.
- **U6. Labels overlap at modest size.** At 38 hosts the bottom row of addresses was unreadable;
  the default is 50 peers per expansion. Timestamps in the details panel break mid-value.

Tests for these go in `tests/ui_actions.mjs` and `tests/ui_marks.mjs`; looks stay manual
(TEST_PLAN VIS-01 to VIS-03).

---

## Spec

- **S1.** D8 and D16 give "6 hops" as a fixed limit; the API takes 1 to 20 (`TB_THREAT_HOPS` is
  the default). Reword.
- **S2.** ATK-2 and EXT-2 are SHALL requirements parked under *TODO*. Say so in a summary of
  open SHALLs at the top.
- **S3.** There are no security requirements (who may do what, audit, limits on input) and no
  threat model for hostile evidence. H1, H2, M2 and H5 each need a requirement to hang on;
  suggested IDs `SEC-1` onward.
- **S4.** PRF-3 is tested with one user. H3 needs a requirement for several analysts at once.

## Codebase

- **C1. Tests share the reader's library.** Every capture is written with dpkt and read with
  dpkt. Add fixtures built from raw bytes or with another writer, and at least one small real
  capture with IPv6, IPsec, VLAN tags and a tunnel.
- **C2. Durability** (read). `write_atomically` (`jsonstore.py:60`) does not fsync before
  renaming. The case database is built with journalling off (`store.py:103`); a build cut
  short can leave a file the next start refuses to overwrite instead of rebuilding.
- **C3. Supply chain** (read). The base image and the dependency ranges are unpinned and there
  is no lock file with hashes. `pip-audit` on `requirements.txt` found nothing on 2026-11-10.
- **C4. Memory** (ran). Each distinct filter keeps a graph of its own: 198 MiB grew to 697 MiB
  after four filters, per worker (`backends.py:451`). Document it, or bound the views by size.
- **C5. Not covered by any test:** concurrent requests, fuzzing, and the time model's limits
  (flow start times only; no tolerance for clock skew between sensors; evidence identified by
  path, size and modification time, not a hash: `sources/__init__.py:83`).

## Checked and found sound

Do not spend time here: SQL is parameterised throughout; the map renders through `textContent`
under a strict CSP; saved-map names cannot traverse paths; writes need the `X-ThreatBridge`
header; filter terms cannot inject Elasticsearch wildcards; the FTP patterns stay linear on
worst-case payloads (0.16 ms for a full-size packet).
