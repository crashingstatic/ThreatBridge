"""Settings from TB_* environment variables, and the command line."""
import os
import sys
from datetime import datetime, timezone

import pytest

from threatbridge import app as app_mod
from threatbridge import query as q
from threatbridge.config import Config


@pytest.fixture
def no_settings(monkeypatch):
    for k in list(os.environ):
        if k.startswith("TB_"):
            monkeypatch.delenv(k)


def test_config_from_the_environment(monkeypatch, no_settings):
    assert Config.from_env() == Config()                     # nothing set: the documented defaults
    env = {
        "TB_BACKEND": "case", "TB_CASE_PATHS": os.pathsep.join(["/cases/a", "", "/cases/b"]),
        "TB_CASE_DB": "/work/case.db", "TB_ES_URL": "https://es:9200", "TB_ES_USER": "u",
        "TB_ES_PASS": "p", "TB_ES_VERIFY": "no", "TB_ES_CA": "/ca.pem", "TB_ES_INDEX": "so-*",
        "TB_ES_TIMEOUT": "9", "TB_DATASETS": "conn, ,zeek.conn", "TB_FIELD_SRC": "s", "TB_FIELD_DST": "d",
        "TB_FIELD_TS": "ts", "TB_FIELD_DPORT": "dp", "TB_FIELD_DATASET": "ds", "TB_FIELD_SPORT": "sp",
        "TB_FIELD_PROTO": "pr", "TB_FIELD_DURATION": "du", "TB_FIELD_PACKETS": "p1,p2",
        "TB_FIELD_BYTES": "b1", "TB_SOC_URL": "https://so/", "TB_SOC_PATH": "/x?q={query}",
        "TB_PIVOT_TIME_CLAUSE": "false", "TB_WINDOW": "1h", "TB_MAX_WINDOW": "7d", "TB_LIMIT": "9",
        "TB_MAX_LIMIT": "99", "TB_RARE_SCAN_CAP": "77", "TB_EXCLUDE_FILE": "/d/ex.json",
        "TB_COMPROMISED_FILE": "/d/c.json", "TB_LIVE_DNS": "0", "TB_DNS_TTL": "11",
        "TB_DNS_TIMEOUT": "0.5", "TB_THREAT_HOPS": "4", "TB_THREAT_MAX_HOSTS": "50", "TB_MAX_PATHS": "20",
        "TB_READ_WORKERS": "3", "TB_DNS_DATASETS": "dns", "TB_FIELD_DNS_QUERY": "dq", "TB_FIELD_DNS_IP": "di",
        "TB_SOC_CLIENT_ID": "tb", "TB_SOC_CLIENT_SECRET": "s3", "TB_SOC_CA": "/soc.pem",
        "TB_PCAP_TIMEOUT": "30", "TB_SESSIONS_DIR": "/d/sessions", "TB_FIELD_CONN_STATE": "cs",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert Config.from_env() == Config(
        backend="case", case_paths=["/cases/a", "/cases/b"], case_db="/work/case.db",
        es_url="https://es:9200", es_user="u", es_pass="p", es_verify=False, es_ca="/ca.pem",
        es_index="so-*", es_timeout=9, datasets=["conn", "zeek.conn"], f_src="s", f_dst="d", f_ts="ts",
        f_dport="dp", f_dataset="ds", f_sport="sp", f_proto="pr", f_duration="du", f_packets=["p1", "p2"],
        f_bytes=["b1"], soc_url="https://so", soc_path="/x?q={query}", pivot_time_clause=False,
        default_window="1h", max_window="7d", default_limit=9, max_limit=99, rare_scan_cap=77,
        exclude_file="/d/ex.json", compromised_file="/d/c.json", live_dns=False, dns_ttl=11,
        dns_timeout=0.5, threat_hops=4, threat_max_hosts=50, max_paths=20, read_workers=3,
        dns_datasets=["dns"], f_dns_query="dq", f_dns_ip="di", soc_client_id="tb", soc_client_secret="s3",
        soc_ca="/soc.pem", pcap_timeout=30, sessions_dir="/d/sessions", f_conn_state="cs")
    for value, expected in (("1", True), ("TRUE", True), ("yes", True), ("on", True), ("off", False), ("", True)):
        monkeypatch.setenv("TB_ES_VERIFY", value)
        assert Config.from_env().es_verify is expected, value
    # Set but empty means "none" (README: "empty = no dataset filter"); unset means the default.
    monkeypatch.setenv("TB_DATASETS", "")
    assert Config.from_env().datasets == []
    monkeypatch.setenv("TB_FIELD_CONN_STATE", "")                   # keep refused connections
    assert Config.from_env().f_conn_state == ""
    t = datetime(2024, 5, 1, 12, 0, tzinfo=timezone.utc)
    filters = q.es_filter(Config.from_env(), "10.0.0.5", "in", t, t, [])["bool"]["filter"]
    assert not any("event.dataset" in f.get("terms", {}) for f in filters)
    monkeypatch.delenv("TB_DATASETS")
    assert Config.from_env().datasets == ["conn", "zeek.conn"]


def test_main(monkeypatch, capsys, no_settings):
    seen = {}

    class FakeApp:
        def run(self, host, port):
            seen["run"] = (host, port)

    def fake_create_app(cfg):
        seen["cfg"] = cfg
        return FakeApp()
    monkeypatch.setattr(app_mod, "create_app", fake_create_app)
    monkeypatch.setattr(sys, "argv", ["threatbridge", "--case", "/c/a", "/c/b", "--db", "/w/x.db",
                                      "--host", "0.0.0.0", "--port", "6000"])
    app_mod.main()
    assert (seen["cfg"].backend, seen["cfg"].case_paths, seen["cfg"].case_db) == ("case", ["/c/a", "/c/b"], "/w/x.db")
    assert seen["run"] == ("0.0.0.0", 6000)
    monkeypatch.setattr(sys, "argv", ["threatbridge", "--demo"])
    app_mod.main()
    assert seen["cfg"].backend == "demo" and seen["cfg"].case_db is None and seen["run"] == ("127.0.0.1", 5055)

    def failing(cfg):
        raise app_mod.SourceError("no pcap or nfcapd files found in: /c")
    monkeypatch.setattr(app_mod, "create_app", failing)
    monkeypatch.setattr(sys, "argv", ["threatbridge", "--case", "/c"])
    with pytest.raises(SystemExit) as e:
        app_mod.main()
    assert e.value.code == 2
    assert capsys.readouterr().err == "error: no pcap or nfcapd files found in: /c\n"
