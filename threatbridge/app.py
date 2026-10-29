"""ThreatBridge web service: temporal connection map for Security Onion IOCs."""
import argparse
import logging
import os

from flask import Flask, Response, g, jsonify, request, send_from_directory

from . import compromised as compromised_mod
from . import filters, protocols, sessions as sessions_mod
from .backends import ES_MAX_RESULTS, BackendError, Scope, make_backend
from .compromised import CompromisedStore, parse_marks, reached
from .config import Config
from .domains import DomainResolver
from .excludes import ExcludeStore
from .jsonstore import StoreError
from .model import SourceError
from .query import (DIRECTIONS, ORDERS, ValidationError, clip, fmt_time, parse_direction,
                    parse_es_id, parse_exclude, parse_ip, parse_order, parse_time, parse_window,
                    soc_host_query, soc_pivot_query, soc_url, time_range)
from .sessions import Conflict, NotFound, SessionStore
from .soc import SocClient

log = logging.getLogger("threatbridge")
API_VERSION = 1   # D20: goes up only when something is removed or changes meaning
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
OPENAPI = os.path.join(os.path.dirname(__file__), "openapi.json")   # D21
MAX_HOPS = 20
MAX_FLOW_PAGE = 500
PATHS_PER_PAIR = 10  # attack paths between compromised hosts: a preview per pair
MAX_EDGES = 20_000   # connections a map may send (suspect connections, exports)
MAX_WITHIN = 100_000  # intervals a flow list may be limited to (a kept connection's "within")
MAX_EXPORT = 200_000  # flows in an export
MARKS_POLL = 5       # seconds between the map's checks for other analysts' marks (D15)


class _Body:
    """A POST request's JSON object, read like a query string: values as text."""

    def __init__(self, body):
        self.body = body

    def get(self, name, default=None):
        value = self.body.get(name)
        if value is None:
            return default
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            raise ValidationError(f"{name} must be text or a number")
        return str(value)

    def __getitem__(self, name):
        value = self.get(name)
        if value is None:
            raise KeyError(name)
        return value


class NotSupported(Exception):
    pass


def create_app(cfg=None, backend=None, excludes=None, compromised=None, resolver=None, soc=None,
               sessions=None):
    # Authentication is mutual TLS, enforced by gunicorn (see gunicorn.conf.py).
    cfg = cfg or Config.from_env()
    backend = backend or make_backend(cfg)
    excludes = excludes or ExcludeStore(cfg.exclude_file)
    compromised = compromised or CompromisedStore(cfg.compromised_file)
    sessions = sessions or SessionStore(cfg.sessions_dir)
    resolver = resolver or DomainResolver(getattr(backend, "dns", None), live=cfg.live_dns,
                                          ttl=cfg.dns_ttl, timeout=cfg.dns_timeout,
                                          answers=getattr(backend, "dns_answers", None))
    if soc is None and cfg.backend == "elastic" and cfg.soc_client_id and cfg.soc_client_secret:
        soc = SocClient(cfg)

    max_window = parse_window(cfg.max_window)

    def exclusions():
        """The exclude list as IPs/CIDRs: domain names replaced by their addresses."""
        return resolver.expand(excludes.list())

    def excludes_body(entries, **extra):
        return jsonify(entries=entries, resolved=resolver.describe(entries), **extra)

    def window_arg(value):
        window = parse_window(value or cfg.default_window)
        if window > max_window:
            raise ValidationError(f"window exceeds maximum of {cfg.max_window}")
        return window

    def json_body():
        body = request.get_json(silent=True)
        if body is None:
            return {}
        if not isinstance(body, dict):
            raise ValidationError("the request body must be a JSON object")
        return body

    def args():
        """The request's parameters: its query string, or (POST) its JSON object."""
        if "args" not in g:
            g.args = request.args if request.method == "GET" else _Body(json_body())
        return g.args

    def int_arg(name, default):
        value = args().get(name)
        try:
            return int(value) if value not in (None, "") else default
        except ValueError:
            raise ValidationError(f"{name} must be an integer")

    def time_arg(name):
        """An optional time parameter: a datetime, or None when absent or blank."""
        value = (args().get(name) or "").strip()
        return parse_time(value) if value else None

    def marks_arg():
        """(hosts marked themselves, marked flows): those a POST sends ("marks", an opened
        map's: D19), else the shared ones."""
        if request.method == "POST" and "marks" in json_body():
            return parse_marks(json_body()["marks"])
        return compromised.marks()

    def scope_arg():
        """The analyst's filters (D17), "filter" parameters or a POST's "filters" list, with
        the marked flows they never hide: a Scope, or None without filters."""
        if request.method == "POST":
            found = filters.combine(json_body().get("filters"))
        else:
            found = filters.combine(request.args.getlist("filter"))
        return Scope(found, marks_arg()[1]) if found else None

    def within_arg():
        """POST "within": [[from, to], ...], the intervals a kept connection's flows are in
        (from /api/suspect), as epoch seconds; None if not sent."""
        if request.method != "POST" or json_body().get("within") is None:
            return None
        within = json_body()["within"]
        if not isinstance(within, list) or len(within) > MAX_WITHIN or not all(
                isinstance(w, list) and len(w) == 2 and all(isinstance(t, str) and t for t in w) for w in within):
            raise ValidationError("within is a list of [from, to] times")
        return [(parse_time(a).timestamp(), parse_time(b).timestamp()) for a, b in within]

    def edges_arg():
        """The drawn connections a POST sends: [(src, dst, first, last)], epoch seconds."""
        edges = json_body().get("edges")
        if not isinstance(edges, list) or len(edges) > MAX_EDGES:
            raise ValidationError(f"edges is a list of at most {MAX_EDGES} connections")
        out = []
        for e in edges:
            if not isinstance(e, dict) or not isinstance(e.get("from"), str) or not e["from"].strip():
                raise ValidationError("each connection is {source, target, from, to}")
            first = parse_time(e["from"])
            last = parse_time(e["to"]) if isinstance(e.get("to"), str) and e["to"].strip() else first
            if last < first:
                raise ValidationError("a connection's to is before its from")
            out.append((parse_ip(e.get("source")), parse_ip(e.get("target")), first.timestamp(),
                        last.timestamp()))
        return out

    def range_arg():
        """The analyst's time range (range_from, range_to): datetimes, None for an open end.
        Every query is limited to it."""
        lo, hi = time_arg("range_from"), time_arg("range_to")
        if lo and hi and hi < lo:
            raise ValidationError("range_to is before range_from")
        return lo, hi

    def from_to_args(what):
        """The required `from` and optional `to` (default: `from`) of a connection's flows."""
        if not args().get("from"):
            raise ValidationError(f"from ({what}) is required")
        first = parse_time(args()["from"])
        last = parse_time(args().get("to") or args()["from"])
        if last < first:
            raise ValidationError("to is before from")
        return first, last

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

    for error, status in ((ValidationError, 400), (NotFound, 404), (Conflict, 409), (NotSupported, 501)):
        app.register_error_handler(error, lambda e, status=status: (jsonify(error=str(e)), status))

    @app.errorhandler(StoreError)
    def _store_error(e):
        log.error("%s", e)
        return jsonify(error=str(e)), 500

    @app.errorhandler(BackendError)
    def _backend_error(e):
        log.warning("backend error: %s", e)
        return jsonify(error=str(e)), 502

    @app.get("/")
    def index():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok", backend=cfg.backend, api_version=API_VERSION)

    # Every bound a request is held to, besides max_window, max_limit and max_filters (D20).
    limits = {"hops": MAX_HOPS, "threat_line_hosts": cfg.threat_max_hosts, "paths": cfg.max_paths,
              "paths_per_pair": PATHS_PER_PAIR, "flow_page": MAX_FLOW_PAGE,
              "connection_flows": ES_MAX_RESULTS if cfg.backend == "elastic" else None,
              "filter_length": filters.MAX_LENGTH, "filter_depth": filters.MAX_DEPTH, "edges": MAX_EDGES,
              "within": MAX_WITHIN, "export_flows": MAX_EXPORT, "marks": compromised_mod.MAX_MARKS,
              "note": compromised_mod.MAX_NOTE, "saved_maps": sessions_mod.MAX_SESSIONS,
              "map_bytes": sessions_mod.MAX_BYTES, "map_name": sessions_mod.MAX_NAME}

    @app.get("/api/config")
    def api_config():
        summary = getattr(backend, "summary", None)
        return jsonify(api_version=API_VERSION, limits=limits, filter=filters.vocabulary(),
                       default_window=cfg.default_window, max_window=cfg.max_window,
                       default_limit=cfg.default_limit, max_limit=cfg.max_limit,
                       directions=DIRECTIONS, orders=ORDERS, backend=cfg.backend,
                       rare_scan_cap=cfg.rare_scan_cap,
                       soc_pivots=cfg.backend != "case",
                       analysis=hasattr(backend, "threat_line"), threat_hops=cfg.threat_hops,
                       suspects=hasattr(backend, "suspects"), marks_poll=MARKS_POLL,
                       protocol_names=protocols.DISPLAY, max_filters=filters.MAX_FILTERS,
                       live_dns=cfg.live_dns, pcap_download=soc is not None,
                       case=summary() if summary else None)

    @app.get("/api/openapi.json")
    def api_openapi():
        return send_from_directory(os.path.dirname(OPENAPI), os.path.basename(OPENAPI), mimetype="application/json")

    @app.route("/api/protocols", methods=["GET", "POST"])
    def api_protocols():
        """How many flows carry each protocol in the time range, of those that pass the filters
        (D20); most first."""
        start, end, counts = backend.protocols(*range_arg(), scope_arg())
        return jsonify(start=start and fmt_time(start), end=end and fmt_time(end), protocols=[
            {"protocol": p, "name": protocols.display_name(p), "flows": n}
            for p, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))])

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

    @app.route("/api/neighbors", methods=["GET", "POST"])
    def api_neighbors():
        a = args()
        ip = parse_ip(a.get("ip"))
        direction = parse_direction(a.get("direction", "in"))
        anchor = parse_time(a.get("ts"))
        window = window_arg(a.get("window"))
        limit = max(1, min(int_arg("limit", cfg.default_limit), cfg.max_limit))
        order = parse_order(a.get("order"))

        start, end = clip(*time_range(anchor, direction, window), range_arg())
        res = (backend.neighbors(ip, direction, start, end, limit, order, exclusions(), scope_arg())
               if start <= end else {"peers": [], "distinct_peers": 0, "truncated": False})
        return jsonify(ip=ip, direction=direction, order=order, anchor=fmt_time(anchor),
                       start=fmt_time(start), end=fmt_time(end), **res)

    @app.route("/api/flows", methods=["GET", "POST"])
    def api_flows():
        """One page of the flows src -> dst that started within [from, to], oldest first."""
        a = args()
        src, dst = parse_ip(a.get("src")), parse_ip(a.get("dst"))
        start, end = clip(*from_to_args("start of the first flow"), range_arg())
        offset = max(0, int_arg("offset", 0))
        limit = max(1, min(int_arg("limit", 50), MAX_FLOW_PAGE))
        res = (backend.flows(src, dst, start, end, offset, limit, scope_arg(), within_arg())
               if start <= end else {"total": 0, "flows": []})
        return jsonify(src=src, dst=dst, start=fmt_time(start), end=fmt_time(end), offset=offset,
                       **res)

    @app.route("/api/edge", methods=["GET", "POST"])
    def api_edge():
        """One connection: the count, times, ports and protocols of the flows src -> dst that
        started within [from, to]."""
        a = args()
        src, dst = parse_ip(a.get("src")), parse_ip(a.get("dst"))
        start, end = clip(*from_to_args("start of the first flow"), range_arg())
        if start > end:
            return jsonify(source=src, target=dst, count=0, first_seen=None, last_seen=None,
                           ports=[], protocols=[])
        return jsonify(**backend.edge(src, dst, start, end, scope_arg()))

    @app.get("/api/filter")
    def api_filter():
        """Check one filter expression (D17): its canonical text, or 400 saying what's wrong."""
        return jsonify(filter=filters.parse(request.args.get("filter", "")).text)

    @app.get("/api/excludes")
    def api_excludes():
        return excludes_body(excludes.list())

    @app.post("/api/excludes")
    def api_excludes_add():
        body = json_body()
        entry = parse_exclude(body.get("entry"))
        entries = excludes.add(entry)
        log.info("exclude added: %s", entry)
        return excludes_body(entries, entry=entry)

    @app.delete("/api/excludes")
    def api_excludes_remove():
        body = json_body()
        entries = excludes.remove(body.get("entry"))
        log.info("exclude removed: %s", body.get("entry"))
        return excludes_body(entries)

    @app.get("/api/compromised")
    def api_compromised():
        return jsonify(**compromised.list())

    @app.post("/api/compromised")
    def api_compromised_mark():
        body = json_body()
        marks = compromised.mark(body.get("ip"), body.get("time"), body.get("note"))
        log.info("marked compromised: %s at %s", body.get("ip"), body.get("time") or "unknown time")
        return jsonify(**marks)

    @app.delete("/api/compromised")
    def api_compromised_unmark():
        body = json_body()
        marks = compromised.unmark(body.get("ip"))
        log.info("unmarked compromised, with its marked flows: %s", body.get("ip"))
        return jsonify(**marks)

    @app.put("/api/compromised")
    def api_compromised_replace():
        marks = compromised.replace(json_body())
        log.info("shared marks replaced: %d host(s), %d flow(s)", len(marks["marked"]), len(marks["flows"]))
        return jsonify(**marks)

    @app.post("/api/compromised/flows")
    def api_compromised_mark_flow():
        body = json_body()
        marks = compromised.mark_flow(body)
        log.info("marked compromised: the flow %s -> %s at %s", body.get("src"), body.get("dst"), body.get("start"))
        return jsonify(**marks)

    @app.delete("/api/compromised/flows")
    def api_compromised_unmark_flow():
        body = json_body()
        marks = compromised.unmark_flow(body)
        log.info("unmarked compromised: the flow %s -> %s at %s", body.get("src"), body.get("dst"), body.get("start"))
        return jsonify(**marks)

    @app.get("/api/sessions")
    def api_sessions():
        """The saved maps, or with ?name= the one saved under that name."""
        if "name" in request.args:
            return jsonify(**sessions.get(request.args["name"]))
        return jsonify(sessions=sessions.list())

    @app.post("/api/sessions")
    def api_sessions_save():
        body = json_body()
        saved = sessions.save(body.get("name"), body.get("map"), overwrite=body.get("overwrite") is True)
        log.info("map saved: %s", saved["name"])
        return jsonify(**saved, sessions=sessions.list())

    @app.delete("/api/sessions")
    def api_sessions_delete():
        body = json_body()
        sessions.delete(body.get("name"))
        log.info("saved map deleted: %s", body.get("name"))
        return jsonify(sessions=sessions.list())

    @app.route("/api/threatline", methods=["GET", "POST"])
    def api_threatline():
        require("threat_line")
        a, b = parse_ip(args().get("a")), parse_ip(args().get("b"))
        bounds = range_arg()
        first, last = clip(*from_to_args("start of the conversation"), bounds)
        if last < first:
            raise ValidationError("the conversation is outside the time range")
        res = backend.threat_line(a, b, first, last, window_arg(args().get("window")),
                                  hops_arg(), exclusions(), cfg.threat_max_hosts, bounds,
                                  scope=scope_arg())
        return jsonify(a=a, b=b, **res)

    @app.route("/api/paths", methods=["GET", "POST"])
    def api_paths():
        """Every time-respecting path from src to dst (each optionally with the time it was
        compromised), up to cfg.max_paths; or, without them, the first PATHS_PER_PAIR between
        each pair of compromised hosts."""
        require("attack_paths")
        a = args()
        window, hops, bounds = window_arg(a.get("window")), hops_arg(), range_arg()
        scope = scope_arg()
        if not (a.get("src") or a.get("dst")):
            return jsonify(**backend.attack_paths(reached(*marks_arg()), window, hops, exclusions(),
                                                  bounds, PATHS_PER_PAIR, scope=scope))
        src, dst = parse_ip(a.get("src")), parse_ip(a.get("dst"))
        if src == dst:
            raise ValidationError("src and dst are the same host")
        res = backend.paths_between(src, dst, time_arg("src_time"), time_arg("dst_time"), window, hops,
                                    exclusions(), bounds, cfg.max_paths, scope=scope)
        return jsonify(src=src, dst=dst, **res)

    @app.post("/api/suspect")
    def api_suspect():
        """What the marks keep of the drawn connections (D16), connection by connection."""
        require("suspects")
        hosts, flows = marks_arg()
        return jsonify(**backend.suspects(edges_arg(), hosts, flows, window_arg(args().get("window")),
                                          hops_arg(), exclusions(), range_arg(), scope=scope_arg()))

    @app.post("/api/export")
    def api_export():
        """The marked hosts, and the marked and suspect flows on the drawn connections."""
        hosts, flows = marks_arg()
        return jsonify(**backend.export(edges_arg(), hosts, flows, MAX_EXPORT,
                                        window=window_arg(args().get("window")), max_hops=hops_arg(),
                                        exclude=exclusions(), bounds=range_arg(), scope=scope_arg()))

    @app.post("/api/pcap")
    def api_pcap():
        """The PCAP of one Security Onion flow ({"id", "time"} from the flow list), extracted by
        its sensor through SOC's Connect API."""
        if soc is None:
            raise NotSupported("downloading PCAP needs Security Onion and a SOC API client: set "
                               "TB_SOC_CLIENT_ID and TB_SOC_CLIENT_SECRET (Security Onion Pro)")
        body = json_body()
        doc_id = parse_es_id(body.get("id"))
        if not (isinstance(body.get("time"), str) and body["time"].strip()):
            raise ValidationError("time (the flow's start) is required")
        when = fmt_time(parse_time(body["time"]))
        chunks = soc.pcap(doc_id, when)
        log.info("PCAP of %s (%s) from the sensor", doc_id, when)
        return Response(chunks, mimetype="application/vnd.tcpdump.pcap", headers={
            "Content-Disposition": f'attachment; filename="threatbridge-{doc_id}.pcap"'})

    @app.get("/api/pivot")
    def api_pivot():
        a = parse_ip(request.args.get("a"))
        b = request.args.get("b")
        lo, hi = range_arg()
        if b:
            b = parse_ip(b)
            until = min((t for t in (time_arg("until"), hi) if t), default=None)
            q = soc_pivot_query(cfg, a, b, until, lo)
        else:
            q = soc_host_query(cfg, a, lo, hi)
        return jsonify(query=q, url=soc_url(cfg, q))

    return app


def main():
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
