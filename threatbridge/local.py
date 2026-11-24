"""Local mode's guards (D23). `python -m threatbridge` serves plain HTTP, without the mutual TLS
of the container, so it checks two things on every request:

- the Host header names this server, so a web page that points its own DNS name at 127.0.0.1
  (DNS rebinding) can't use the API from the analyst's browser;
- the request carries the login token printed at start-up: as a cookie, set by opening the
  printed URL, or in an `Authorization: Bearer` header (scripts).
"""
import hmac
import ipaddress
from dataclasses import dataclass
from urllib.parse import quote, urlencode

from flask import Response, jsonify, redirect, request

MIN_TOKEN = 20          # characters of a token given in TB_TOKEN
LOOPBACK = frozenset({"localhost", "127.0.0.1", "[::1]"})
# Listening addresses that mean every interface: compared against, never bound to.
WILDCARDS = {"", "0.0.0.0", "::", "[::]"}   # nosec B104

LOGIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>ThreatBridge: login needed</title></head>
<body><h1>Login needed</h1>
<p>Open the address ThreatBridge printed when it started: it carries a login token. If
ThreatBridge was restarted, it printed a new one.</p></body></html>
"""


def host_name(value):
    """The name in a Host header (or a setting), lower case and without the port; an IPv6
    address in brackets, as a Host header writes it."""
    value = (value or "").strip().lower()
    if value.startswith("["):
        end = value.find("]")
        return value[:end + 1] if end > 0 else value
    try:
        if ipaddress.ip_address(value).version == 6:      # a setting may leave out the brackets
            return f"[{value}]"
    except ValueError:
        pass
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


@dataclass(frozen=True)
class LocalAccess:
    hosts: frozenset     # names the Host header may carry
    token: str = None    # None: login switched off (--no-login)
    cookie: str = "tb_token"

    @classmethod
    def serving(cls, host, port, allowed=(), token=None):
        """For a server listening on `host`:`port`: the loopback names, the listening address
        unless it means every interface, and the `allowed` names (TB_ALLOWED_HOSTS). The cookie
        is named after the port, so two servers on one machine keep their logins apart."""
        names = set(LOOPBACK) | {host_name(a) for a in allowed if a.strip()}
        if host.strip() not in WILDCARDS:
            names.add(host_name(host))
        return cls(frozenset(names), token, f"tb_token_{port}")

    def url(self, host, port):
        """The address to print at start-up: with the token, unless login is off."""
        shown = "127.0.0.1" if host.strip() in WILDCARDS else host_name(host)
        return f"http://{shown}:{port}/" + (f"?token={quote(self.token, safe='')}" if self.token else "")


def _same(given, token):
    return hmac.compare_digest(given.encode(), token.encode())


def _login_needed():
    if request.path == "/":                       # the map's page: say what to do
        return Response(LOGIN_PAGE, 401, mimetype="text/html")
    return jsonify(error="login needed: open the address ThreatBridge printed when it started (it carries a "
                         "token), or send the header Authorization: Bearer <token>"), 401


def install(app, access):
    """Check every request of `app` against `access` before anything else runs."""

    @app.before_request
    def _local_guard():
        if host_name(request.host) not in access.hosts:
            return jsonify(error=f"not served under the name {host_name(request.host)!r}; add it to "
                                 "TB_ALLOWED_HOSTS if it is this machine's"), 421
        token = access.token
        if token is None:
            return None
        given = request.args.get("token")
        if given is not None and request.method == "GET":    # the printed address: log in
            if not _same(given, token):
                return _login_needed()
            rest = [(k, v) for k, v in request.args.items(multi=True) if k != "token"]
            path = "/" + request.path.lstrip("/")         # never "//host": that leaves the site
            resp = redirect(path + (f"?{urlencode(rest)}" if rest else ""), 303)
            resp.set_cookie(access.cookie, token, httponly=True, samesite="Lax", path="/")
            return resp
        cookie = request.cookies.get(access.cookie)
        auth = request.headers.get("Authorization", "")
        bearer = auth[7:].strip() if auth[:7].lower() == "bearer " else None
        if any(v and _same(v, token) for v in (cookie, bearer)):
            return None
        return _login_needed()
