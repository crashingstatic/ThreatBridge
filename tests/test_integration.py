"""Whole-system checks: several processes sharing files, mixed evidence, the entry point, and
the shipped configuration staying in step with the code and the README."""
import json
import multiprocessing
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

from evidence import ACK, SYN, have_nfdump, load, make_nfcapd, tcp, write_pcap
from threatbridge import sources
from threatbridge.app import create_app
from threatbridge.backends import CaseBackend, DemoBackend
from threatbridge.config import Config
from threatbridge.excludes import ExcludeStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
T = 1_714_564_800.0
FORK = multiprocessing.get_context("fork")   # gunicorn workers are forked processes too


# ---- several processes --------------------------------------------------------------------

def _add_entries(path, worker):
    store = ExcludeStore(path)
    for i in range(10):
        store.add(f"10.{worker}.0.{i}")


def test_worker_processes_share_the_exclude_list(tmp_path):
    path = str(tmp_path / "exclude.json")
    procs = [FORK.Process(target=_add_entries, args=(path, w)) for w in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
    assert [p.exitcode for p in procs] == [0, 0, 0, 0]
    assert sorted(ExcludeStore(path).list()) == sorted(f"10.{w}.0.{i}" for w in range(4) for i in range(10))


def _load_case(cfg, out):
    with open(out, "w") as fh:
        fh.write(str(CaseBackend(cfg).summary()["flows"]))


def test_worker_processes_share_one_case_database(tmp_path, monkeypatch):
    d = tmp_path / "case"
    d.mkdir()
    write_pcap(d / "cap.pcap", [(T, tcp("10.0.0.5", "10.0.0.9", 50000, 445, SYN)),
                                (T + 0.001, tcp("10.0.0.9", "10.0.0.5", 445, 50000, SYN | ACK))])
    reads = tmp_path / "reads"
    real_read = sources.read

    def slow_read(*a, **k):         # inherited by the forked workers
        with open(reads, "a") as fh:
            fh.write("read\n")
        time.sleep(0.5)
        return real_read(*a, **k)
    monkeypatch.setattr(sources, "read", slow_read)
    cfg = Config(backend="case", case_paths=[str(d)], case_db=str(tmp_path / "case.db"))
    outs = [str(tmp_path / f"out{i}") for i in range(2)]
    procs = [FORK.Process(target=_load_case, args=(cfg, out)) for out in outs]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
    assert [p.exitcode for p in procs] == [0, 0]
    assert [open(o).read() for o in outs] == ["1", "1"]
    assert reads.read_text() == "read\n"                         # built once, then reused


# ---- mixed evidence -----------------------------------------------------------------------

# CI installs nfdump, so there a missing binary fails the test instead of skipping it.
@pytest.mark.skipif(not have_nfdump() and not os.environ.get("CI"), reason="nfdump/nfcapd not installed")
def test_pcap_and_netflow_in_one_case(tmp_path):
    now = int(time.time())
    t = now - 100
    d = tmp_path / "case"
    (d / "netflow").mkdir(parents=True)
    nf = make_nfcapd(d / "netflow", [("10.0.0.5", "10.0.0.20", 50001, 22, 6, 4, 400, t + 10, t + 11)], now)
    write_pcap(d / "cap.pcap", [(t, tcp("10.0.0.5", "10.0.0.9", 50000, 445, SYN)),
                                (t + 0.001, tcp("10.0.0.9", "10.0.0.5", 445, 50000, SYN | ACK))])
    flows = load([str(d)])
    assert [(f.src, f.dst, f.dport, f.source) for f in flows] == [
        ("10.0.0.5", "10.0.0.9", 445, str(d / "cap.pcap")), ("10.0.0.5", "10.0.0.20", 22, nf)]
    be = CaseBackend(Config(backend="case", case_paths=[str(d)]))
    assert be.summary()["flows"] == 2 and be.graph.has_edge("10.0.0.5", "10.0.0.20")


# ---- the entry point ----------------------------------------------------------------------

def run(*args):
    return subprocess.run([sys.executable, "-m", "threatbridge", *args], cwd=ROOT,
                          capture_output=True, text=True, timeout=60)


def test_command_line():
    r = run("--help")
    assert r.returncode == 0 and "--case PATH" in r.stdout and "--db FILE" in r.stdout
    r = run("--case", "/nonexistent/evidence")
    assert r.returncode == 2 and r.stderr.strip().endswith("error: /nonexistent/evidence: no such file or directory")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_serving_a_case_read_by_worker_processes(tmp_path):
    # Several files: worker processes read them, and one server serves the case.
    d = tmp_path / "case"
    d.mkdir()
    for i in range(3):
        write_pcap(d / f"cap{i}.pcap", [(T + i, tcp("10.0.0.5", f"10.0.0.{9 + i}", 50000, 445, SYN)),
                                        (T + i + 0.001, tcp(f"10.0.0.{9 + i}", "10.0.0.5", 445, 50000, SYN | ACK))])
    port = free_port()
    env = dict(os.environ, TB_READ_WORKERS="3", TB_LIVE_DNS="false",
               TB_EXCLUDE_FILE=str(tmp_path / "ex.json"), TB_COMPROMISED_FILE=str(tmp_path / "c.json"))
    proc = subprocess.Popen([sys.executable, "-m", "threatbridge", "--case", str(d), "--port", str(port)],
                            cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.monotonic() + 60
        while True:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/config", timeout=1) as r:
                    case = json.load(r)["case"]
                break
            except OSError:
                assert proc.poll() is None and time.monotonic() < deadline, "server did not start"
                time.sleep(0.2)
        assert (case["flows"], case["hosts"]) == (3, 4)
    finally:
        proc.terminate()
        output = proc.communicate(timeout=30)[0]
    assert "Reading 3 evidence file(s): done" in output
    assert output.count("Running on") == 1, output


# ---- shipped configuration ----------------------------------------------------------------

def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def code_vars():
    """TB_* variables something actually reads."""
    files = [os.path.join(dp, f) for dp, _, fs in os.walk(os.path.join(ROOT, "threatbridge"))
             for f in fs if f.endswith(".py")]
    files += [os.path.join(ROOT, p) for p in ("gunicorn.conf.py", "Dockerfile")]
    files += [os.path.join(ROOT, "deploy", f) for f in os.listdir(os.path.join(ROOT, "deploy")) if f.endswith(".sh")]
    found = set()
    for path in files:
        with open(path, encoding="utf-8") as fh:
            found |= set(re.findall(r"\b(TB_[A-Z_]+)\b", fh.read()))
    return found


def readme_vars():
    """TB_* variables in the README's configuration table; TB_A/B/C stands for TB_A, TB_B, TB_C."""
    table = read("README.md").split("## Configuration", 1)[1].split("\n## ", 1)[0]
    found = set()
    for cell in re.findall(r"`(TB_[A-Z_/]+)`", table):
        first, *rest = cell.split("/")
        found.add(first)
        prefix = first.rsplit("_", 1)[0] + "_"
        found |= {prefix + r for r in rest}
    return found


def test_every_setting_is_documented_and_every_documented_setting_exists():
    used, documented = code_vars(), readme_vars()
    assert used - documented == set(), "read by the code but missing from the README table"
    assert documented - used == set(), "in the README table but read by nothing"


def test_the_env_example_only_sets_real_settings():
    keys = {line.split("=", 1)[0] for line in read("deploy", "threatbridge.env.example").splitlines()
            if line and not line.startswith("#")}
    assert keys and keys <= code_vars()


def test_soc_actions_open_the_map_with_what_it_reads():
    actions = json.loads(read("securityonion", "soc-actions.json"))
    app_js = read("threatbridge", "static", "app.js")
    for name in ("ip", "ts", "dir"):
        assert f'q.get("{name}")' in app_js
    assert {a["name"] for a in actions} == {"ThreatBridge: inbound (past)", "ThreatBridge: outbound (future)"}
    for a in actions:
        [link] = a["links"]
        direction = "in" if "inbound" in a["name"] else "out"
        assert link == f"https://THREATBRIDGE_HOST:5443/?ip={{value}}&ts={{:soc_timestamp}}&dir={direction}"


def test_every_endpoint_is_documented_and_every_documented_endpoint_exists(tmp_path):
    cfg = Config(backend="demo", live_dns=False, exclude_file=str(tmp_path / "ex.json"),
                 compromised_file=str(tmp_path / "c.json"))
    app = create_app(cfg, DemoBackend(cfg))
    served = {(m, r.rule) for r in app.url_map.iter_rules() for m in r.methods - {"HEAD", "OPTIONS"}
              if not r.rule.startswith("/static/") and r.rule != "/"}   # the UI itself
    documented = set(re.findall(r"^### `(GET|POST|PUT|DELETE) (/\S*)`$", read("docs", "API.md"), re.M))
    assert served - documented == set(), "served but not in docs/API.md"
    assert documented - served == set(), "in docs/API.md but not served"
