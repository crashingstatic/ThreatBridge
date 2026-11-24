# Piloting ThreatBridge on a closed case

This kit is for incident response teams who want to know whether ThreatBridge would have helped
on a case they have already worked. You run it on that case's evidence, starting from what you
knew at the start, and compare what it points at with what you confirmed. It needs no baseline
and no sensor: it reads the evidence files you already have.

Nothing in this kit sends data anywhere. The feedback template asks for counts and short
descriptions only; never include client data, evidence, or a report ThreatBridge produced from
it unless your client has agreed.

## 1. Install

You need Python 3.11 or later and [uv](https://docs.astral.sh/uv/).

```bash
git clone <the ThreatBridge repository> && cd threatbridge
uv sync --frozen --no-default-groups      # the locked versions, without the test tools
```

A release archive works the same way; its signature can be checked as README.md, *Releases*,
describes.

## 2. Load the case

Put the evidence in one directory (subdirectories are fine): packet captures (pcap or pcapng),
nfcapd files, DHCP logs (Windows DHCP server audit logs, ISC dhcpd leases, Zeek `dhcp.log`), and
Windows Security event logs (`.evtx`, or JSON lines from `evtx_dump`). ThreatBridge recognises
each by its content and skips anything else.

```bash
TB_CASE_DB=/path/to/work/case.db TB_DHCP_TIMEZONE=<the DHCP server's zone> \
TB_EXCLUDE_FILE=/path/to/work/exclude.json TB_COMPROMISED_FILE=/path/to/work/compromised.json \
TB_SESSIONS_DIR=/path/to/work/maps \
uv run python -m threatbridge --case /path/to/evidence
```

Open the address it prints. Building the case shows its progress; with `TB_CASE_DB` set, a
second start on the same evidence opens at once. Keep the work directory outside the evidence
directory, and on the analyst's machine.

## 3. Work the case again

1. Note the clock time you start.
2. Map the first indicator you had in the original investigation (the host and time of the
   first alert), as you would have on day one. Don't use what you learned later.
3. Work outward: expand hosts, click connections for threat lines and timelines, mark hosts
   compromised as the evidence on the map convinces you, and let attack paths join them.
4. When you would have written the scope down (the hosts you'd report as compromised, and
   when), note the clock time and save the map (*Saved maps* → *Save*) and the report
   (*Report*).
5. Compare with the scope the original investigation confirmed.

## 4. What to record

- **Time to scope**: minutes from step 1 to step 4, and how long the original investigation
  took to reach the same scope (roughly is fine).
- **Hosts**: how many hosts ThreatBridge led you to mark; of them, how many the original
  investigation confirmed; how many confirmed hosts you didn't reach.
- **What it missed, and why**: for each confirmed host not reached, whether its traffic was in
  the evidence at all, and if so what hid it (an exclude, a filter, the Window, the hop limit, an
  address that changed hands, something else).
- **What got in the way**: files it refused or misread, waits longer than a few seconds, steps
  that took more clicks than they should, anything confusing.

## 5. Feedback template

Copy this, fill it in, and send it to the project (an issue in its repository, or however the
maintainers ask). Leave out anything that identifies the client.

```markdown
## ThreatBridge pilot

- ThreatBridge version (`/api/config` → version):
- Evidence: kinds (pcap / pcapng / nfcapd / DHCP / Windows events), total size, time span
- Network: about how many hosts were active
- Starting indicator: the kind of alert (e.g. EDR alert on a workstation, firewall alert)

### Time to scope
- With ThreatBridge: ___ minutes
- Original investigation: about ___ hours/days

### Hosts
- Marked with ThreatBridge: ___
- Of those, confirmed by the original investigation: ___
- Confirmed but not reached with ThreatBridge: ___

### Missed hosts
| Host (anonymised, e.g. "server 3") | Its traffic in the evidence? | What hid it |
|---|---|---|

### What got in the way
-

### What helped most
-
```
