"""Runtime configuration, read from TB_* environment variables."""
import os
from dataclasses import dataclass, field, fields


@dataclass
class Config:
    backend: str = "elastic"  # "elastic", "case" or "demo"

    # Post-mortem ("case") backend: tcpdump pcap / nfdump nfcapd files or directories.
    case_paths: list = field(default_factory=list)
    # SQLite file for the case's flows, reused while the evidence is unchanged. None: temporary.
    case_db: str = None
    # Evidence files read at once, in worker processes. 0: one per CPU.
    read_workers: int = 0

    # Elasticsearch (Security Onion 2.4 stores Zeek conn logs here)
    es_url: str = "https://localhost:9200"
    es_user: str = None
    es_pass: str = None
    es_verify: bool = True
    es_ca: str = None
    es_index: str = "logs-*"
    es_timeout: int = 30
    # Only count connection records. Empty list disables the filter.
    datasets: list = field(default_factory=lambda: ["conn", "zeek.conn"])

    # ECS field names
    f_src: str = "source.ip"
    f_dst: str = "destination.ip"
    f_ts: str = "@timestamp"
    f_dport: str = "destination.port"
    f_dataset: str = "event.dataset"
    # Zeek's conn_state: records of refused connections (REJ) are left out. Empty: no filter.
    f_conn_state: str = "connection.state"
    # Zeek's service (the protocols it recognized, e.g. "smb,ntlm"). Empty: protocols unknown.
    f_service: str = "network.protocol"
    # Shown in a connection's flow list. Defaults: Security Onion 2.4's Zeek conn records,
    # duration in seconds; packets and bytes add up the listed fields (both directions).
    f_sport: str = "source.port"
    f_proto: str = "network.transport"
    f_duration: str = "event.duration"
    f_packets: list = field(default_factory=lambda: ["client.packets", "server.packets"])
    f_bytes: list = field(default_factory=lambda: ["client.ip_bytes", "server.ip_bytes"])
    # Zeek DNS records: what domain names on the exclude list resolved to, as the sensors saw it.
    # Empty dataset list disables the filter.
    dns_datasets: list = field(default_factory=lambda: ["dns", "zeek.dns"])
    f_dns_query: str = "dns.query.name"
    f_dns_ip: str = "dns.resolved_ip"

    # SOC pivot. {query} is replaced with the URL-encoded OQL query.
    soc_url: str = "https://securityonion"
    soc_path: str = "/#/dashboards?q={query}"
    # Append "AND @timestamp:[<from> TO <to>]" to pivots: up to the IOC time, within the
    # analyst's time range.
    pivot_time_clause: bool = True
    # SOC Connect API client (Security Onion Pro, 2.4.120+), for ThreatBridge to fetch a flow's
    # PCAP from the sensor itself. Unset: flows link to SOC's PCAP job instead. soc_ca: the CA
    # of SOC's certificate (default: es_ca). pcap_timeout: seconds to wait for the sensor.
    soc_client_id: str = None
    soc_client_secret: str = None
    soc_ca: str = None
    pcap_timeout: int = 90

    default_window: str = "24h"
    max_window: str = "30d"
    default_limit: int = 50
    max_limit: int = 200

    # Bottom-N (rarest peers) scans every distinct peer exactly, up to this many.
    rare_scan_cap: int = 10000

    # Shared exclude list (IPs, CIDRs, domain names), editable in the UI.
    exclude_file: str = "exclude.json"
    # Hosts marked as compromised, editable in the UI.
    compromised_file: str = "compromised.json"
    # Saved maps, one JSON file each, shared by all analysts.
    sessions_dir: str = "sessions"
    # Domain names on the exclude list are also looked up live (system resolver), cached for
    # dns_ttl seconds. Answers seen in the capture are always used.
    live_dns: bool = True
    dns_ttl: int = 300
    dns_timeout: float = 2.0

    # Threat lines and attack paths (case backend): hop limit, size cap per threat line, and
    # how many paths to list per pair of hosts.
    threat_hops: int = 6
    threat_max_hosts: int = 300
    max_paths: int = 500

    @classmethod
    def from_env(cls):
        """The settings from their variables (env_name), each unset one at its default. An empty
        variable counts as unset, except for a list (no items) and the settings it turns off."""
        values = {}
        for f in fields(cls):
            raw = os.environ.get(env_name(f.name))
            if raw is not None and (raw or f.type is list or f.name in _MAY_BE_EMPTY):
                values[f.name] = _parse(f, raw)
        return cls(**values)


# Settings an empty variable turns off: refused connections kept, protocols unknown.
_MAY_BE_EMPTY = {"f_conn_state", "f_service"}


def env_name(setting):
    """A setting's variable: TB_ and its name in capitals, with FIELD_ for f_ (f_src:
    TB_FIELD_SRC); TB_WINDOW and TB_LIMIT for the defaults."""
    name = {"default_window": "window", "default_limit": "limit"}.get(setting, setting)
    return "TB_" + (f"field_{name[2:]}" if name.startswith("f_") else name).upper()


def _parse(f, raw):
    if f.name == "case_paths":                     # paths, as in PATH
        return [p for p in raw.split(os.pathsep) if p]
    if f.type is list:                             # comma-separated
        return [v.strip() for v in raw.split(",") if v.strip()]
    if f.type is bool:
        return raw.strip().lower() in ("1", "true", "yes", "on")
    return raw.rstrip("/") if f.name == "soc_url" else f.type(raw)
