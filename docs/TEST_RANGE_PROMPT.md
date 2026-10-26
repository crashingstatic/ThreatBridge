# Prompt: build the ThreatBridge test range on Proxmox VE 9.2

Give the text below, from "You are building" to the end, to an agent that can run commands
against the Proxmox host and work in a clone of the ThreatBridge repository.

---

You are building an isolated test range on a **Proxmox VE 9.2** hypervisor, using
**OpenTofu** for the infrastructure and **Ansible** for the configuration. Its purpose is to let
a human tester run every test in `docs/TEST_PLAN.md` of the ThreatBridge repository. That
includes the Security Onion tests (ENV-SO, ENV-SO-PRO), which need a real Security Onion 2.4
sensor that sees real traffic.

Read these first:

- `README.md`, especially *Deploy on the Security Onion manager*, *PCAP for a flow* and
  *Things to verify on your install*.
- `docs/TEST_PLAN.md`, especially section 2 (the environments) and the SO- tests.
- `tests/make_case.py`: the attack-chain dataset the range's traffic must reproduce.

## What ThreatBridge is (for context)

ThreatBridge is a companion to Security Onion 2.4. It runs as a container on the SO manager
(`deploy/run.sh`), reads Zeek conn and DNS records from SO's Elasticsearch, and serves a map
over mutual TLS on port 5443. Analysts launch it from SOC actions. It also has a post-mortem
mode that reads pcap and nfcapd files, which the tester runs on a workstation.

## Facts to rely on, and what to check yourself

Checked when this prompt was written (October 2026). Re-check anything you depend on against
the current documentation before using it.

- **Proxmox VE 9.2:** Debian 13.5 "Trixie", Linux 7.0, QEMU 11.0, LXC 7.0.
- **Privileges in PVE 9:** `VM.Monitor` no longer exists (removed in 9.0). Basic monitor access
  is `Sys.Audit`, and guest-agent operations are `VM.GuestAgent.*`. Build the API token's role
  from the PVE 9.2 privilege list, not from older guides.
- **OpenTofu provider:** use `bpg/proxmox`, which supports PVE 9.x. Not Telmate: it hard-codes
  the `VM.Monitor` check and fails on PVE 9. Pin the newest release you have verified.
  - Importing disk images needs the `import` content type on the target storage.
  - Downloading ISOs, images and container templates: use `proxmox_download_file`.
  - Custom cloud-init user data needs the `snippets` content type, and the provider's SSH
    access to the node.
  - Read the provider's docs for the SSH settings it needs. Releases before 0.93.1 documented
    an unsafe sudoers line (CVE-2026-25499).
- **Security Onion 2.4 minimums:**

  | Node | Cores | RAM | Storage | NICs |
  |---|---|---|---|---|
  | Standalone | 4 | 24 GB | 200 GB | 2 |
  | Eval | 4 | 8 GB | 200 GB | 2 |

  - Build a Standalone node with 8 vCPU, 32 GB RAM and 300 GB disk. Use Eval only if the host
    can't spare that, and say so in your report.
  - Eval writes full packet capture with Suricata. Standalone describes Stenographer. Check
    which one your install runs.
  - The sniffing NIC has no IP. The installer turns off offloading (tso, gso, gro) on it.
  - SO 2.4 is x86-64 only and is based on Oracle Linux 9, which needs x86-64-v2. Use CPU type
    `host` (or at least `x86-64-v2-AES`).
  - Install **2.4**, the newest 2.4.x release: ThreatBridge targets 2.4, and the docs also
    describe a later major version. Verify the ISO's checksum and signature as SO's
    documentation describes.
- **No documented unattended install for SO 2.4 was found.** Look in the 2.4 setup scripts
  (`so-setup` and its automation files in the Security-Onion-Solutions repository) for a
  supported answer-file mode. If there is none, don't script around the installer: stop and
  give the operator an exact checklist for the interactive setup (every screen and answer),
  then continue once they confirm.

When a fact matters and you can't verify it, say so in your report instead of guessing.

## Before you change anything, ask the operator for

1. The PVE API URL, node name, and an API token (or permission to create a dedicated user,
   role and token).
2. Which storages to use for disks, ISOs, container templates and snippets.
3. A VMID range reserved for the range (e.g. 9100–9199), and the address range for the
   management network.
4. How the management network reaches the internet for installs (an existing bridge with NAT,
   or one you create). The lab network gets **no** uplink.
5. Optionally, a Security Onion Pro licence. Without one, skip ENV-SO-PRO (the SOC API client)
   and say so.

Show the operator your plan, including every change to the Proxmox host's network
configuration, before applying it. Host network changes can cut the host off: keep the existing
bridges untouched, add new ones, and use `ifreload -a` only after showing the diff. Never modify
VMs, containers, bridges or storages you didn't create. Tag everything you create
`threatbridge-range`.

## The range to build

### Networks

| Bridge | Purpose | Addresses | Uplink |
|---|---|---|---|
| `tbmgmt` (new) | Management: the SO manager's management NIC, the tester workstation, Ansible | Operator's range | NAT to the internet, for installs only |
| `tblab` (new) | The monitored segment: lab hosts, and the SO sniffing NIC | Those of the attack chain (below); no IP on the host | None |

The SO sniffing NIC must see **all** traffic between lab hosts. Use a Linux bridge with
`bridge-ageing 0`: it learns no MAC addresses and floods every frame to every port. An Open
vSwitch mirror port is the alternative; if you use one, explain why. Turn the Proxmox firewall
off on the sniffing NIC. Prove the mirroring works: during a ping between two lab hosts,
`tcpdump` on the sensor's sniffing interface must show it.

Run every guest on UTC, with the clock synced (chrony) from the management network or the
Proxmox host. ThreatBridge's results depend on time order.

### Guests

| Guest | Type | Size | NICs | Role |
|---|---|---|---|---|
| `tb-so` | VM from the SO 2.4 ISO | 8 vCPU (`host`), 32 GB, 300 GB | `tbmgmt` (management), `tblab` (sniffing, no IP) | Security Onion Standalone. ThreatBridge runs here as the README describes. |
| `tb-tester` | VM, Debian 13 cloud image + cloud-init, desktop (e.g. XFCE) | 4 vCPU, 8 GB, 60 GB | `tbmgmt` | The tester's workstation (below) |
| Lab hosts | LXC containers, Debian 13 template, unprivileged | 1 core, 256–512 MB, 4 GB each | `tblab` only | One per address of the attack chain (below) |

**Lab hosts** reproduce the hosts of `tests/make_case.py`, one container per address:

- 203.0.113.66 (the outside attacker);
- 10.0.0.5, 10.0.0.9, 10.0.0.20, 10.0.0.30, 10.0.0.53 (DNS) and 10.0.0.77;
- 10.0.1.1, 10.0.1.2, and 10.0.1.3 (an extra host for the 10,000-flow test);
- 10.0.2.1, 10.0.2.2, and 10.0.2.10 to 10.0.2.21.

They share one L2 segment. Give each an on-link route to the other lab subnets (10.0.0.0/8 and
203.0.113.0/24 on `eth0`) and **no default route**.

Manage the containers without putting them on `tbmgmt`, e.g. through the Proxmox host with
`pct exec`. Check that a supported Ansible connection plugin for this exists in the
`community.proxmox` / `community.general` collections. If none fits, give each container a
second NIC on `tbmgmt` with only its own subnet route, and make sure lab traffic still leaves
by `eth0`.

On the lab hosts, run listeners that complete the TCP handshake (a real service, or a small
listener that accepts and closes), as the scenario needs:

- 443 on 10.0.0.5;
- 445 on 10.0.0.9 and on 10.0.2.10–21;
- 80 on 10.0.0.9;
- 3389 on 10.0.0.20 and 10.0.2.2;
- 5985 on 10.0.0.20;
- 22 on 10.0.0.30 (sshd);
- 8443 on 10.0.1.2;
- 9000 on 10.0.1.3.

10.0.0.53 runs dnsmasq (or similar) answering:

- `updates.example.com` → 10.0.0.77;
- `cdn.example.com` as a CNAME to `edge.example.com`, which → 10.0.0.77;
- `api.example.com` → 10.0.0.5.

**Tester workstation (`tb-tester`):**

- The ThreatBridge repository cloned, `python -m pip install -r requirements.txt pytest`
  (Python 3.11 or later), `nfdump`, and Chromium.
- It can run the plan's other environments (ENV-DEMO, ENV-CASE, ENV-BUSY).
- The ThreatBridge client certificate (`.p12`) for the SO deployment is in a Chromium profile,
  with the ThreatBridge CA and SO's CA trusted, so the tester opens
  `https://<tb-so>:5443/` without warnings.
- The tester reaches the desktop through the Proxmox console or a remote desktop on `tbmgmt`.

### Security Onion and ThreatBridge on `tb-so`

After SO setup (Standalone, management NIC on `tbmgmt`, sniffing NIC on `tblab`), automate
over SSH with Ansible:

1. Wait until all SO services are up (`so-status`).
2. Allow the tester workstation to reach SOC (443) and ThreatBridge (5443) through SO's
   firewall, using the mechanism SO 2.4 documents (hostgroups in SOC's configuration, or its
   CLI). Record which you used.
3. Deploy ThreatBridge exactly as the README says. Clone it to `/opt/threatbridge`.
   - Run `scripts/make-certs.sh ca`, then `server <tb-so FQDN> <management IP>`, then
     `client tester`.
   - Fill `deploy/threatbridge.env` with an Elasticsearch account that can read the conn and DNS
     indices (prefer a dedicated read-only one), and `TB_SOC_URL=https://<tb-so>`.
   - Run `SO_CA=<SO's CA path> deploy/run.sh`. Verify that CA path on the install.
   - Keep `deploy/threatbridge.env` mode 600, and never commit it.
4. Add both SOC actions from `securityonion/soc-actions.json`, with `THREATBRIDGE_HOST`
   replaced, where SO 2.4 keeps custom actions. Automate this only through a documented
   mechanism; otherwise give the operator the exact steps.
5. With a Pro licence: enable Hydra, create the API client with `events/read`, `jobs/read` and
   `jobs/write`, and set `TB_SOC_CLIENT_ID` / `TB_SOC_CLIENT_SECRET`.
6. Make redeploying cheap: SO-02 and SO-05 change `deploy/threatbridge.env` and re-run
   `deploy/run.sh`. Provide a playbook (or tag) that sets one variable and redeploys.

### The traffic scenario

A playbook (or a script the playbook starts) replays the attack chain of `tests/make_case.py`
on the lab hosts, each connection from its real source host. Times are minutes after the start:

| Time | From → to | Port | What |
|---|---|---|---|
| +0:00 | 10.0.0.9 → 10.0.0.53 | 53/udp | Queries for `updates.example.com`, `cdn.example.com`, `api.example.com` |
| +10:00 | 10.0.0.20 → 10.0.0.30 | 22 | |
| +20:00 | 203.0.113.66 → 10.0.0.5 | 443 | Chain, hop 1 |
| +21:40 | 10.0.2.1 → each of 10.0.2.10–21, one per second | 445 | Fan-out |
| +23:20 | each of 10.0.2.10–21 → 10.0.2.2, one per second | 3389 | Fan-in |
| +30:00 | 10.0.0.5 → 10.0.0.9 | 445 | Chain, hop 2 |
| +35:00 | 10.0.0.5 → 10.0.0.20 | 5985 | Shortcut |
| +40:00 | 10.0.0.9 → 10.0.0.20 | 3389 | Chain, hop 3 |
| +50:00 | 10.0.0.77 → 10.0.0.9 | 80 | |
| +70:00 to +89:50 | 10.0.1.1 → 10.0.1.2, 120 connections 10 s apart | 8443 | Paging |
| +90:00 on | 10.0.1.1 → 10.0.1.3, 12,000 short connections | 9000 | More than SOC's 10,000-flow page limit (SO-02) |

Requirements for the scenario:

- A **time scale** parameter (1 = as above; e.g. 0.1 for a 9-minute run). Order and spacing scale
  together. The 12,000 connections may run as fast as is reliable.
- Each connection is a full TCP connection (handshake, a few bytes, close), so Zeek logs it
  normally.
- Write a **manifest** to the tester workstation (CSV and JSON): source, destination, port,
  protocol, and the actual start time in UTC to the millisecond, for every connection except
  the 12,000. Write them as one summary line with their first and last times.
- While the scenario runs, capture `tblab` on the Proxmox host (`tcpdump -i tblab`), and copy
  the pcap to the tester workstation. With it, the post-mortem tests can also run on real
  traffic (`python -m threatbridge --case <pcap>`).
- Optionally, run `softflowd` on the bridge, exporting to `nfcapd` on the tester, for a real
  NetFlow file.

### Snapshots and reset

- Take snapshots `baseline` (provisioned, before any scenario) and `scenario-done` of `tb-so`,
  `tb-tester` and the lab hosts.
- Provide a reset playbook that rolls back to either one.
- The test plan's "fresh state" means empty ThreatBridge state files. Provide a task that
  empties them on `tb-so` (the `threatbridge-data` volume) and restarts the container.

## Deliverables

Put everything in `range/` in the ThreatBridge repository (or wherever the operator says):

- `range/tofu/`: providers and versions (pinned), variables (no secrets in defaults), the
  bridges if the provider can manage them (otherwise Ansible does it), the VMs, the containers,
  downloads, and outputs Ansible's inventory is built from.
- `range/ansible/`: inventory from the tofu outputs, and playbooks or roles for:
  - the Proxmox host (bridges, `bridge-ageing 0` or the OVS mirror, NAT for `tbmgmt`, chrony);
  - the lab hosts (addresses, routes, listeners, DNS);
  - the tester workstation;
  - Security Onion post-install and ThreatBridge deployment;
  - the scenario, snapshots and reset.
- `range/README.md`: prerequisites, the secrets the operator provides and where, and the
  commands to build, run the scenario, reset and destroy. Also list every manual step, with
  exact instructions.
- `range/VERIFY.md`: what you found for each item of the README's *Things to verify on your
  install*, with evidence (commands and output). If you couldn't settle an item, say what is
  still open.
- `.gitignore` entries for state, plans, secret variable files, certificates and `.p12` files.

**Secrets:**

- Never commit, print or log secrets: the PVE token, SO and Elasticsearch passwords, `.p12`
  passwords, and the SOC client secret.
- Pass them through environment variables, an Ansible Vault, or files the operator keeps.
- OpenTofu state holds secrets: enable OpenTofu's state encryption, or keep the state outside
  the repository, and say which.

## Acceptance checks

Run all of these and put the results in your report:

1. **Idempotent:** `tofu plan` after `tofu apply` shows no changes, and a second Ansible run
   (scenario excluded) reports `changed=0`.
2. **Lab isolated:** lab hosts can't reach the internet or `tbmgmt`.
3. **Mirroring:** the sensor's sniffing interface sees lab traffic (`tcpdump`).
4. **Zeek records after one scenario run (SO Hunt, or `so-elasticsearch-query` on the manager):**
   - a conn record 203.0.113.66 → 10.0.0.5:443;
   - DNS records for `updates.example.com` with `dns.resolved_ip` 10.0.0.77;
   - over 10,000 conn records 10.0.1.1 → 10.0.1.3:9000;
   - conn counts per pair that match the manifest. Explain any difference.
5. **ThreatBridge, from the tester workstation:**
   - with the client certificate, `https://<tb-so>:5443/healthz` answers
     `{"backend": "elastic", "status": "ok"}`;
   - without one, the TLS handshake fails;
   - mapping 10.0.0.9 inbound at a time after the scenario shows 10.0.0.5 and 10.0.0.77;
   - a flow's *PCAP in SOC* link opens SOC's PCAP job and shows that connection's packets.
6. **SOC actions:** clicking an IP in SOC Hunt offers *ThreatBridge: inbound (past)* and
   *ThreatBridge: outbound (future)*, and they open the map at that event's IP and time.
7. **Reset:** the reset playbook rolls back to `baseline`, and step 4 passes again after a new
   scenario run.
8. **Teardown:** `tofu destroy` (plus the documented Ansible cleanup of host network changes)
   leaves the Proxmox host as it was.

## Report

End with a short report:

- what you built (guests, addresses, versions you pinned);
- what you automated, and each manual step the operator did or still has to do;
- the acceptance check results with evidence;
- the `VERIFY.md` findings;
- any deviation from this prompt, and why.

## References

- ThreatBridge: `README.md`, `docs/TEST_PLAN.md`, `docs/API.md`, `tests/make_case.py`,
  `deploy/run.sh`, `scripts/make-certs.sh`, `securityonion/soc-actions.json`
- Proxmox VE 9.2 announcement and roadmap: https://pve.proxmox.com/wiki/Roadmap
- PVE 9 privilege change (`VM.Monitor` removed):
  https://forum.proxmox.com/threads/proxmox-9-terraform-provider-missing-vm-monitor-permission-but-it-doesnt-exist.170212/
- `bpg/proxmox` provider: https://github.com/bpg/terraform-provider-proxmox
- Security Onion 2.4 hardware: https://docs.securityonion.net/en/2.4/hardware.html
- Security Onion 2.4 getting started: https://docs.securityonion.net/en/2.4/getting-started.html
