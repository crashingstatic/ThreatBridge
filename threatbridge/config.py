"""Runtime configuration, read from TB_* environment variables."""
import os
from dataclasses import dataclass, field


def _env(name, default=None):
    value = os.environ.get(name)
    return default if value is None or value == "" else value


def _env_bool(name, default):
    value = _env(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env_list(name, default):
    value = _env(name)
    if value is None:
        return list(default)
    return [v.strip() for v in value.split(",") if v.strip()]


@dataclass
class Config:
    backend: str = "elastic"  # "elastic", "case" or "demo"

    # Post-mortem ("case") backend: tcpdump pcap / nfdump nfcapd files or directories.
    case_paths: list = field(default_factory=list)
    # SQLite file for the case's flows, reused while the evidence is unchanged. None: temporary.
    case_db: str = None

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
    # Shown in a connection's flow list. Defaults: Security Onion 2.4's Zeek conn records,
    # duration in seconds; packets and bytes add up the listed fields (both directions).
    f_sport: str = "source.port"
    f_proto: str = "network.transport"
    f_duration: str = "event.duration"
    f_packets: list = field(default_factory=lambda: ["client.packets", "server.packets"])
    f_bytes: list = field(default_factory=lambda: ["client.ip_bytes", "server.ip_bytes"])

    # SOC pivot. {query} is replaced with the URL-encoded OQL query.
    soc_url: str = "https://securityonion"
    soc_path: str = "/#/dashboards?q={query}"
    # Append "AND @timestamp:[<from> TO <to>]" to pivots: up to the IOC time, within the
    # analyst's time range.
    pivot_time_clause: bool = True

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
        return cls(
            backend=_env("TB_BACKEND", "elastic"),
            case_paths=[p for p in (_env("TB_CASE_PATHS") or "").split(os.pathsep) if p],
            case_db=_env("TB_CASE_DB"),
            es_url=_env("TB_ES_URL", cls.es_url),
            es_user=_env("TB_ES_USER"),
            es_pass=_env("TB_ES_PASS"),
            es_verify=_env_bool("TB_ES_VERIFY", True),
            es_ca=_env("TB_ES_CA"),
            es_index=_env("TB_ES_INDEX", cls.es_index),
            es_timeout=int(_env("TB_ES_TIMEOUT", cls.es_timeout)),
            datasets=_env_list("TB_DATASETS", ["conn", "zeek.conn"]),
            f_src=_env("TB_FIELD_SRC", cls.f_src),
            f_dst=_env("TB_FIELD_DST", cls.f_dst),
            f_ts=_env("TB_FIELD_TS", cls.f_ts),
            f_dport=_env("TB_FIELD_DPORT", cls.f_dport),
            f_dataset=_env("TB_FIELD_DATASET", cls.f_dataset),
            f_sport=_env("TB_FIELD_SPORT", cls.f_sport),
            f_proto=_env("TB_FIELD_PROTO", cls.f_proto),
            f_duration=_env("TB_FIELD_DURATION", cls.f_duration),
            f_packets=_env_list("TB_FIELD_PACKETS", ["client.packets", "server.packets"]),
            f_bytes=_env_list("TB_FIELD_BYTES", ["client.ip_bytes", "server.ip_bytes"]),
            soc_url=_env("TB_SOC_URL", cls.soc_url).rstrip("/"),
            soc_path=_env("TB_SOC_PATH", cls.soc_path),
            pivot_time_clause=_env_bool("TB_PIVOT_TIME_CLAUSE", True),
            default_window=_env("TB_WINDOW", cls.default_window),
            max_window=_env("TB_MAX_WINDOW", cls.max_window),
            default_limit=int(_env("TB_LIMIT", cls.default_limit)),
            max_limit=int(_env("TB_MAX_LIMIT", cls.max_limit)),
            rare_scan_cap=int(_env("TB_RARE_SCAN_CAP", cls.rare_scan_cap)),
            exclude_file=_env("TB_EXCLUDE_FILE", cls.exclude_file),
            compromised_file=_env("TB_COMPROMISED_FILE", cls.compromised_file),
            live_dns=_env_bool("TB_LIVE_DNS", True),
            dns_ttl=int(_env("TB_DNS_TTL", cls.dns_ttl)),
            dns_timeout=float(_env("TB_DNS_TIMEOUT", cls.dns_timeout)),
            threat_hops=int(_env("TB_THREAT_HOPS", cls.threat_hops)),
            threat_max_hosts=int(_env("TB_THREAT_MAX_HOSTS", cls.threat_max_hosts)),
            max_paths=int(_env("TB_MAX_PATHS", cls.max_paths)),
        )
