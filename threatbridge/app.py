"""ThreatBridge web service: temporal connection map for Security Onion IOCs."""
import logging
import os

from flask import Flask, jsonify, request, send_from_directory

from .backends import BackendError, make_backend
from .config import Config
from .excludes import ExcludeStore
from .query import (DIRECTIONS, ORDERS, ValidationError, fmt_time, parse_direction, parse_ip,
                    parse_order, parse_time, parse_window, soc_host_query, soc_pivot_query,
                    soc_url, time_range)

log = logging.getLogger("threatbridge")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


def create_app(cfg=None, backend=None, excludes=None):
    # Authentication is mutual TLS, enforced by gunicorn (see gunicorn.conf.py).
    cfg = cfg or Config.from_env()
    backend = backend or make_backend(cfg)
    excludes = excludes or ExcludeStore(cfg.exclude_file)
    max_window = parse_window(cfg.max_window)

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
        return jsonify(default_window=cfg.default_window, max_window=cfg.max_window,
                       default_limit=cfg.default_limit, max_limit=cfg.max_limit,
                       directions=DIRECTIONS, orders=ORDERS, backend=cfg.backend,
                       rare_scan_cap=cfg.rare_scan_cap)

    @app.get("/api/resolve")
    def api_resolve():
        return jsonify(ip=parse_ip(request.args.get("ip")),
                       anchor=fmt_time(parse_time(request.args.get("ts"))))

    @app.get("/api/neighbors")
    def api_neighbors():
        args = request.args
        ip = parse_ip(args.get("ip"))
        direction = parse_direction(args.get("direction", "in"))
        anchor = parse_time(args.get("ts"))
        window = parse_window(args.get("window", cfg.default_window))
        if window > max_window:
            raise ValidationError(f"window exceeds maximum of {cfg.max_window}")
        try:
            limit = int(args.get("limit", cfg.default_limit))
        except ValueError:
            raise ValidationError("limit must be an integer")
        limit = max(1, min(limit, cfg.max_limit))
        order = parse_order(args.get("order"))

        start, end = time_range(anchor, direction, window)
        res = backend.neighbors(ip, direction, start, end, limit, order, excludes.list())
        return jsonify(ip=ip, direction=direction, order=order, anchor=fmt_time(anchor),
                       start=fmt_time(start), end=fmt_time(end), **res)

    @app.get("/api/excludes")
    def api_excludes():
        return jsonify(entries=excludes.list())

    @app.post("/api/excludes")
    def api_excludes_add():
        body = request.get_json(silent=True) or {}
        entries = excludes.add(body.get("entry"))
        log.info("exclude added: %s", body.get("entry"))
        return jsonify(entries=entries)

    @app.delete("/api/excludes")
    def api_excludes_remove():
        body = request.get_json(silent=True) or {}
        entries = excludes.remove(body.get("entry"))
        log.info("exclude removed: %s", body.get("entry"))
        return jsonify(entries=entries)

    @app.get("/api/pivot")
    def api_pivot():
        a = parse_ip(request.args.get("a"))
        b = request.args.get("b")
        if b:
            b = parse_ip(b)
            until = parse_time(request.args["until"]) if request.args.get("until") else None
            q = soc_pivot_query(cfg, a, b, until)
        else:
            q = soc_host_query(cfg, a)
        return jsonify(query=q, url=soc_url(cfg, q))

    return app


def main():
    import argparse
    p = argparse.ArgumentParser(description="ThreatBridge temporal connection map")
    p.add_argument("--host", default=os.environ.get("TB_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("TB_PORT", "5055")))
    p.add_argument("--demo", action="store_true", help="use the fake demo backend")
    a = p.parse_args()
    logging.basicConfig(level=logging.INFO)
    cfg = Config.from_env()
    if a.demo:
        cfg.backend = "demo"
    create_app(cfg).run(host=a.host, port=a.port)


if __name__ == "__main__":
    main()
