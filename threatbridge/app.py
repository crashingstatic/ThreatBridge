"""ThreatBridge web service: temporal connection map for Security Onion IOCs."""
import logging
import os

from flask import Flask, jsonify, request, send_from_directory

from .backends import BackendError, make_backend
from .compromised import CompromisedStore
from .config import Config
from .domains import DomainResolver
from .excludes import ExcludeStore
from .model import SourceError
from .query import (DIRECTIONS, ORDERS, ValidationError, clip, fmt_time, parse_direction,
                    parse_exclude, parse_ip, parse_order, parse_time, parse_window,
                    soc_host_query, soc_pivot_query, soc_url, time_range)

log = logging.getLogger("threatbridge")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
MAX_HOPS = 20
MAX_FLOW_PAGE = 500


class NotSupported(Exception):
    pass


def create_app(cfg=None, backend=None, excludes=None, compromised=None, resolver=None):
    # Authentication is mutual TLS, enforced by gunicorn (see gunicorn.conf.py).
    cfg = cfg or Config.from_env()
    backend = backend or make_backend(cfg)
    excludes = excludes or ExcludeStore(cfg.exclude_file)
    compromised = compromised or CompromisedStore(cfg.compromised_file)
    resolver = resolver or DomainResolver(getattr(backend, "dns", None), live=cfg.live_dns,
                                          ttl=cfg.dns_ttl, timeout=cfg.dns_timeout)

    def exclusions():
        """The exclude list as IPs/CIDRs: domain names replaced by their addresses."""
        return resolver.expand(excludes.list())

    def excludes_body(entries, **extra):
        return jsonify(entries=entries, resolved=resolver.describe(entries), **extra)
    max_window = parse_window(cfg.max_window)

    def window_arg(value):
        window = parse_window(value or cfg.default_window)
        if window > max_window:
            raise ValidationError(f"window exceeds maximum of {cfg.max_window}")
        return window

    def int_arg(name, default):
        value = request.args.get(name)
        try:
            return int(value) if value not in (None, "") else default
        except ValueError:
            raise ValidationError(f"{name} must be an integer")

    def range_arg():
        """The analyst's time range (range_from, range_to): datetimes, None for an open end.
        Every query is limited to it."""
        lo, hi = (parse_time(request.args[k]) if (request.args.get(k) or "").strip() else None
                  for k in ("range_from", "range_to"))
        if lo and hi and hi < lo:
            raise ValidationError("range_to is before range_from")
        return lo, hi

    def hops_arg():
        hops = int_arg("hops", cfg.threat_hops)
        if not 1 <= hops <= MAX_HOPS:
            raise ValidationError(f"hops must be between 1 and {MAX_HOPS}")
        return hops

    def require(method):
        if not hasattr(backend, method):
            raise NotSupported(f"not available with the {cfg.backend} backend; "
                               "load PCAP/NetFlow files with --case")

    app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")
    app.config["TB"] = cfg

    @app.before_request
    def _csrf():
        # Browsers send the client cert on cross-site requests too. Require a custom
        # header on writes: cross-origin pages cannot set it without a CORS preflight,
        # which this app never approves.
        if request.method not in ("GET", "HEAD", "OPTIONS") and \
                request.headers.get("X-ThreatBridge") != "1":
            return jsonify(error="missing X-ThreatBridge header"), 403
        return None

    @app.after_request
    def _headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; "
            "img-src 'self' data:; frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.errorhandler(ValidationError)
    def _bad_request(e):
        return jsonify(error=str(e)), 400

    @app.errorhandler(NotSupported)
    def _not_supported(e):
        return jsonify(error=str(e)), 501

    @app.errorhandler(BackendError)
    def _backend_error(e):
        log.warning("backend error: %s", e)
        return jsonify(error=str(e)), 502

    @app.get("/")
    def index():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok", backend=cfg.backend)

    @app.get("/api/config")
    def api_config():
        summary = getattr(backend, "summary", None)
        return jsonify(default_window=cfg.default_window, max_window=cfg.max_window,
                       default_limit=cfg.default_limit, max_limit=cfg.max_limit,
                       directions=DIRECTIONS, orders=ORDERS, backend=cfg.backend,
                       rare_scan_cap=cfg.rare_scan_cap,
                       soc_pivots=cfg.backend != "case",
                       analysis=hasattr(backend, "threat_line"), threat_hops=cfg.threat_hops,
                       live_dns=cfg.live_dns,
                       case=summary() if summary else None)

    @app.get("/api/resolve")
    def api_resolve():
        ip = parse_ip(request.args.get("ip"))
        ts = (request.args.get("ts") or "").strip()
        if ts:
            anchor = parse_time(ts)
        else:
            # Look back from the end of what can be shown (inbound) or forward from its start
            # (outbound): the analyst's time range and the evidence's span (files), else now.
            direction = parse_direction(request.args.get("direction", "in"))
            lo, hi = range_arg()
            first, last = getattr(backend, "span", None) or (None, None)
            if direction == "in":
                anchor = min((t for t in (hi, last) if t), default=None)
            else:
                anchor = max((t for t in (lo, first) if t), default=None)
            anchor = anchor or parse_time(None)
        return jsonify(ip=ip, anchor=fmt_time(anchor))

    @app.get("/api/neighbors")
    def api_neighbors():
        args = request.args
        ip = parse_ip(args.get("ip"))
        direction = parse_direction(args.get("direction", "in"))
        anchor = parse_time(args.get("ts"))
        window = window_arg(args.get("window"))
        limit = max(1, min(int_arg("limit", cfg.default_limit), cfg.max_limit))
        order = parse_order(args.get("order"))

        start, end = clip(*time_range(anchor, direction, window), range_arg())
        res = (backend.neighbors(ip, direction, start, end, limit, order, exclusions())
               if start <= end else {"peers": [], "distinct_peers": 0, "truncated": False})
        return jsonify(ip=ip, direction=direction, order=order, anchor=fmt_time(anchor),
                       start=fmt_time(start), end=fmt_time(end), **res)

    @app.get("/api/flows")
    def api_flows():
        """One page of the flows src -> dst that started within [from, to], oldest first."""
        args = request.args
        src, dst = parse_ip(args.get("src")), parse_ip(args.get("dst"))
        if not args.get("from"):
            raise ValidationError("from (start of the first flow) is required")
        start, end = clip(parse_time(args["from"]), parse_time(args.get("to") or args["from"]),
                          range_arg())
        offset = max(0, int_arg("offset", 0))
        limit = max(1, min(int_arg("limit", 50), MAX_FLOW_PAGE))
        res = (backend.flows(src, dst, start, end, offset, limit)
               if start <= end else {"total": 0, "flows": []})
        return jsonify(src=src, dst=dst, start=fmt_time(start), end=fmt_time(end), offset=offset,
                       **res)

    @app.get("/api/excludes")
    def api_excludes():
        return excludes_body(excludes.list())

    @app.post("/api/excludes")
    def api_excludes_add():
        body = request.get_json(silent=True) or {}
        entry = parse_exclude(body.get("entry"))
        entries = excludes.add(entry)
        log.info("exclude added: %s", entry)
        return excludes_body(entries, entry=entry)

    @app.delete("/api/excludes")
    def api_excludes_remove():
        body = request.get_json(silent=True) or {}
        entries = excludes.remove(body.get("entry"))
        log.info("exclude removed: %s", body.get("entry"))
        return excludes_body(entries)

    @app.get("/api/compromised")
    def api_compromised():
        return jsonify(hosts=compromised.list())

    @app.post("/api/compromised")
    def api_compromised_mark():
        body = request.get_json(silent=True) or {}
        hosts = compromised.mark(body.get("ip"), body.get("time"), body.get("note"))
        log.info("marked compromised: %s at %s", body.get("ip"), body.get("time") or "unknown time")
        return jsonify(hosts=hosts)

    @app.delete("/api/compromised")
    def api_compromised_unmark():
        body = request.get_json(silent=True) or {}
        hosts = compromised.unmark(body.get("ip"))
        log.info("unmarked compromised: %s", body.get("ip"))
        return jsonify(hosts=hosts)

    @app.get("/api/threatline")
    def api_threatline():
        require("threat_line")
        args = request.args
        a, b = parse_ip(args.get("a")), parse_ip(args.get("b"))
        if not args.get("from"):
            raise ValidationError("from (start of the conversation) is required")
        first = parse_time(args["from"])
        last = parse_time(args.get("to") or args["from"])
        if last < first:
            raise ValidationError("to is before from")
        bounds = range_arg()
        first, last = clip(first, last, bounds)
        if last < first:
            raise ValidationError("the conversation is outside the time range")
        res = backend.threat_line(a, b, first, last, window_arg(args.get("window")),
                                  hops_arg(), exclusions(), cfg.threat_max_hosts, bounds)
        return jsonify(a=a, b=b, **res)

    @app.get("/api/paths")
    def api_paths():
        require("attack_paths")
        res = backend.attack_paths(compromised.times(), window_arg(request.args.get("window")),
                                   hops_arg(), exclusions(), range_arg())
        return jsonify(**res)

    @app.get("/api/pivot")
    def api_pivot():
        a = parse_ip(request.args.get("a"))
        b = request.args.get("b")
        lo, hi = range_arg()
        if b:
            b = parse_ip(b)
            until = parse_time(request.args["until"]) if request.args.get("until") else None
            q = soc_pivot_query(cfg, a, b, min((t for t in (until, hi) if t), default=None), lo)
        else:
            q = soc_host_query(cfg, a, lo, hi)
        return jsonify(query=q, url=soc_url(cfg, q))

    return app


def main():
    import argparse
    p = argparse.ArgumentParser(description="ThreatBridge temporal connection map")
    p.add_argument("--host", default=os.environ.get("TB_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("TB_PORT", "5055")))
    p.add_argument("--demo", action="store_true", help="use the fake demo backend")
    p.add_argument("--case", nargs="+", metavar="PATH",
                   help="post-mortem mode: tcpdump pcap and nfdump nfcapd files or directories")
    p.add_argument("--db", metavar="FILE",
                   help="keep the case's flows in this SQLite file and reuse it next time "
                        "while the evidence is unchanged (default: temporary)")
    a = p.parse_args()
    logging.basicConfig(level=logging.INFO)
    cfg = Config.from_env()
    if a.demo:
        cfg.backend = "demo"
    if a.case:
        cfg.backend, cfg.case_paths = "case", a.case
    if a.db:
        cfg.case_db = a.db
    try:
        app = create_app(cfg)
    except SourceError as e:
        p.exit(2, f"error: {e}\n")
    app.run(host=a.host, port=a.port)


if __name__ == "__main__":
    main()
