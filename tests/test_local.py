"""Local mode's guards (D23): the Host check and the login token of `python -m threatbridge`."""
import os
import sys

import pytest
from flask.testing import FlaskClient

from threatbridge import app as app_mod
from threatbridge.app import create_app
from threatbridge.backends import DemoBackend
from threatbridge.config import Config
from threatbridge.local import LocalAccess, host_name

TOKEN = "t0ken-for-tests-0123456789"
WRITE = {"X-ThreatBridge": "1"}
EXCLUDE = {"entry": "10.9.9.9"}


def make_client(tmp_path, token=TOKEN, host="127.0.0.1", allowed=("analyst-laptop.example",)):
    cfg = Config(backend="demo", live_dns=False, exclude_file=str(tmp_path / "ex.json"),
                 compromised_file=str(tmp_path / "c.json"), sessions_dir=str(tmp_path / "maps"))
    local = LocalAccess.serving(host, 5055, list(allowed), token)
    return create_app(cfg, DemoBackend(cfg), local=local).test_client()


@pytest.fixture
def client(tmp_path):
    return make_client(tmp_path)


def bearer(token=TOKEN):
    return {"Authorization": f"Bearer {token}"}


def test_host_names():
    assert host_name("127.0.0.1:5055") == "127.0.0.1"
    assert host_name("LocalHost:5055") == "localhost"
    assert host_name("[::1]:5055") == "[::1]"
    assert host_name("::1") == "[::1]"                 # a setting may leave out the brackets
    assert host_name("analyst-laptop.example") == "analyst-laptop.example"
    assert host_name("") == ""


def test_a_foreign_host_is_refused_before_anything_else(client):
    # A page that rebinds its DNS name to 127.0.0.1 sends its own name as the Host.
    for r in (client.get("/api/compromised", headers={"Host": "evil.example:5055", **bearer()}),
              client.post("/api/excludes", json=EXCLUDE, headers={"Host": "evil.example", **WRITE, **bearer()}),
              client.get("/", headers={"Host": "evil.example"})):
        assert r.status_code == 421
        assert "TB_ALLOWED_HOSTS" in r.get_json()["error"]
    r = client.get("/api/excludes", headers={"Host": "127.0.0.1:5055", **bearer()})
    assert r.status_code == 200 and r.get_json()["entries"] == []       # the write above never happened


@pytest.mark.parametrize("host", ["127.0.0.1:5055", "localhost:5055", "[::1]:5055", "ANALYST-laptop.example:5055"])
def test_served_names_are_accepted(client, host):
    assert client.get("/api/config", headers={"Host": host, **bearer()}).status_code == 200


def test_the_listening_address_is_served_unless_it_means_every_interface(tmp_path):
    assert make_client(tmp_path, host="192.0.2.7").get(
        "/api/config", headers={"Host": "192.0.2.7:5055", **bearer()}).status_code == 200
    assert make_client(tmp_path, host="0.0.0.0").get(
        "/api/config", headers={"Host": "0.0.0.0:5055", **bearer()}).status_code == 421


def test_requests_without_the_token_are_refused(client):
    r = client.get("/api/config")
    assert r.status_code == 401 and "printed when it started" in r.get_json()["error"]
    assert client.get("/api/config", headers=bearer("wrong-token-0123456789")).status_code == 401
    assert client.get("/api/config", headers={"Authorization": TOKEN}).status_code == 401   # no "Bearer"
    assert client.post("/api/excludes", json=EXCLUDE, headers=WRITE).status_code == 401
    page = client.get("/")
    assert page.status_code == 401 and page.mimetype == "text/html" and b"Login needed" in page.data
    assert client.get("/static/app.js").status_code == 401
    assert client.get("/healthz").status_code == 401


def test_scripts_send_the_token_as_a_bearer_header(client):
    assert client.get("/api/config", headers=bearer()).status_code == 200
    assert client.get("/api/config", headers={"Authorization": f"bearer  {TOKEN}"}).status_code == 200
    r = client.post("/api/excludes", json=EXCLUDE, headers={**WRITE, **bearer()})
    assert r.status_code == 200 and r.get_json()["entries"] == ["10.9.9.9"]
    # The write header is still needed: the token doesn't replace it.
    assert client.post("/api/excludes", json=EXCLUDE, headers=bearer()).status_code == 403


def test_the_printed_address_logs_the_browser_in(client):
    r = client.get(f"/?ip=10.0.0.5&token={TOKEN}&dir=in")
    assert r.status_code == 303
    assert r.headers["Location"] == "/?ip=10.0.0.5&dir=in"           # the token leaves the address bar
    cookie = r.headers["Set-Cookie"]
    assert cookie.startswith(f"tb_token_5055={TOKEN};")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie and "Path=/" in cookie
    assert client.get("/?ip=10.0.0.5&dir=in").status_code == 200       # the cookie is sent from now on
    assert client.get("/api/config").status_code == 200
    assert client.post("/api/excludes", json=EXCLUDE, headers=WRITE).status_code == 200


def test_logging_in_never_redirects_off_the_site(client):
    # A raw request line "GET //evil.example/?token=..." (the test client would read it as a
    # host). Not an API path, so not checked against the OpenAPI document.
    raw = FlaskClient(client.application, client.application.response_class)
    r = raw.get("/", query_string={"token": TOKEN}, environ_overrides={"PATH_INFO": "//evil.example/"})
    assert r.status_code == 303 and r.headers["Location"] == "/evil.example/"


def test_a_wrong_token_in_the_address_logs_nobody_in(client):
    r = client.get("/?token=wrong-token-0123456789")
    assert r.status_code == 401 and "Set-Cookie" not in r.headers
    assert client.get("/api/config").status_code == 401


def test_a_cookie_for_another_port_or_value_is_not_enough(client):
    client.set_cookie("tb_token_5056", TOKEN)
    assert client.get("/api/config").status_code == 401
    client.set_cookie("tb_token_5055", "wrong-token-0123456789")
    assert client.get("/api/config").status_code == 401
    client.set_cookie("tb_token_5055", TOKEN)
    assert client.get("/api/config").status_code == 200


def test_login_off_still_checks_the_host(tmp_path):
    c = make_client(tmp_path, token=None)
    assert c.get("/api/config").status_code == 200
    assert c.get("/api/config", headers={"Host": "evil.example"}).status_code == 421


def test_the_container_has_neither_guard(tmp_path):
    cfg = Config(backend="demo", live_dns=False, exclude_file=str(tmp_path / "ex.json"),
                 compromised_file=str(tmp_path / "c.json"))
    c = create_app(cfg, DemoBackend(cfg)).test_client()    # gunicorn and mutual TLS
    assert c.get("/api/config", headers={"Host": "threatbridge.example"}).status_code == 200


def test_printed_address():
    a = LocalAccess.serving("127.0.0.1", 5055, [], "a/b+c=" + "x" * 20)
    assert a.url("127.0.0.1", 5055) == "http://127.0.0.1:5055/?token=a%2Fb%2Bc%3D" + "x" * 20
    assert LocalAccess.serving("0.0.0.0", 6000, [], None).url("0.0.0.0", 6000) == "http://127.0.0.1:6000/"
    assert LocalAccess.serving("::1", 6000, [], None).url("::1", 6000) == "http://[::1]:6000/"


# ---- start-up --------------------------------------------------------------------------

class FakeApp:
    def run(self, host, port):
        pass


@pytest.fixture
def started(monkeypatch):
    for k in list(os.environ):
        if k.startswith("TB_"):
            monkeypatch.delenv(k)
    seen = {}

    def fake_create_app(cfg, backend=None, local=None):
        seen["local"] = local
        return FakeApp()
    monkeypatch.setattr(app_mod, "create_app", fake_create_app)

    def start(*args):
        monkeypatch.setattr(sys, "argv", ["threatbridge", "--demo", *args])
        app_mod.main()
        return seen["local"]
    return start


def test_start_up_prints_an_address_with_a_new_token(started, capsys):
    first = started()
    printed = capsys.readouterr().err
    assert f"Open http://127.0.0.1:5055/?token={first.token}" in printed
    assert len(first.token) >= 40 and first.cookie == "tb_token_5055"
    assert started().token != first.token                                  # a new one each start


def test_tb_token_fixes_the_token(started, monkeypatch, capsys):
    monkeypatch.setenv("TB_TOKEN", TOKEN)
    assert started("--port", "5056").token == TOKEN
    assert f"Open http://127.0.0.1:5056/?token={TOKEN}" in capsys.readouterr().err
    monkeypatch.setenv("TB_TOKEN", "short")
    with pytest.raises(SystemExit) as e:
        started()
    assert e.value.code == 2 and "at least 20 characters" in capsys.readouterr().err


def test_no_login_warns(started, caplog, capsys):
    local = started("--no-login")
    assert local.token is None
    assert "login is off" in caplog.text
    assert "Open http://127.0.0.1:5055/\n" in capsys.readouterr().err


def test_allowed_hosts_and_listening_on_every_interface(started, monkeypatch, caplog):
    monkeypatch.setenv("TB_ALLOWED_HOSTS", "ir-laptop.example, 192.0.2.7")
    local = started("--host", "0.0.0.0")
    assert {"ir-laptop.example", "192.0.2.7", "localhost"} <= local.hosts and "0.0.0.0" not in local.hosts
    assert "other machines can reach it" in caplog.text
