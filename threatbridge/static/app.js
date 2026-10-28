/* ThreatBridge map UI. All data rendered via textContent; no HTML injection. */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const statusEl = $("status");
  const menu = $("menu");
  let iocTime = null;          // anchor of the root (IOC) event; upper bound for SOC pivots
  let cfg = {};                // /api/config
  let compromised = new Map(); // ip -> {ip, time, note, direct, count}: every marked host (D15)
  let markedFlows = new Map(); // flowKey -> marked flow
  let markedPairs = new Set(); // "src->dst" of the connections holding a marked flow
  let marks = { hosts: [], flows: [] };   // the marks shown: hosts marked themselves, and flows
  let shared = null;           // the shared marks as last read: {hosts, marked, flows, version}
  let localMap = null;         // the opened map whose own marks are shown (D19), or null
  let filters = [];            // the analyst's filter expressions, combined with AND (D17)
  let queries = [];            // the queries the map was built from, to re-run with the filters
  let detailsFor = null;       // host shown in the details panel
  let flowsFor = null;         // connection whose flows the details panel lists
  let lastFlows = null;        // the page of flows listed, to redraw when marks change
  const FLOW_PAGE = 50;
  const WRITE_HEADERS = { "Content-Type": "application/json", "X-ThreatBridge": "1" };
  const COLORS = { root: "#e5484d", in: "#3e9bff", out: "#f5a524", node: "#9aa7bd",
                   up: "#a78bfa", down: "#2dd4bf", attack: "#ff4d5e", compromised: "#b4232a",
                   outline: "#ff8a8a", route: "#f472b6", protocol: "#ffe066" };

  const cy = cytoscape({
    container: $("cy"),
    wheelSensitivity: 0.3,
    maxZoom: 1.6,
    style: [
      { selector: "node", style: {
          "background-color": COLORS.node, label: "data(id)", color: "#d8dee9",
          "font-size": 10, "text-valign": "bottom", "text-margin-y": 4, width: 18, height: 18 } },
      { selector: "node[?root]", style: { "background-color": COLORS.root, width: 28, height: 28 } },
      { selector: "node[?expandedIn], node[?expandedOut]", style: { "border-width": 2, "border-color": "#d8dee9" } },
      { selector: "node[?expandedIn][?expandedOut]", style: { "border-width": 3, "border-color": "#fff" } },
      { selector: "edge", style: {
          width: "mapData(logCount, 0, 4, 1, 7)", "curve-style": "bezier",
          "target-arrow-shape": "triangle", "arrow-scale": 0.9, label: "data(label)",
          "font-size": 8, color: "#8a94a6", "text-rotation": "autorotate", "text-background-color": "#11151c",
          "text-background-opacity": 0.8, "text-background-padding": 1 } },
      { selector: "edge[direction = 'in']", style: { "line-color": COLORS.in, "target-arrow-color": COLORS.in } },
      { selector: "edge[direction = 'out']", style: { "line-color": COLORS.out, "target-arrow-color": COLORS.out } },
      { selector: "node[?compromised]", style: {
          "background-color": COLORS.compromised, "border-width": 3, "border-color": COLORS.outline } },
      // Marked connections (solid) and suspect ones (dashed): dark red, outlined light red (D16).
      // An attack path or a path between two hosts keeps its own colour, dashed or solid as above.
      { selector: "edge.marked, edge.suspect", style: {
          width: "mapData(logCount, 0, 4, 3, 8)", "line-color": COLORS.compromised,
          "target-arrow-color": COLORS.compromised, "line-outline-width": 1.5, "line-outline-color": COLORS.outline,
          "z-index": 9 } },
      { selector: "edge.suspect", style: { "line-style": "dashed", "line-dash-pattern": [10, 6] } },
      { selector: "edge.marked", style: { "line-style": "solid" } },
      // Attack paths, paths between two hosts, and the threat line through a clicked edge.
      { selector: "edge.attack", style: {
          "line-color": COLORS.attack, "target-arrow-color": COLORS.attack, width: 6, "z-index": 10 } },
      { selector: "edge.route", style: {
          "line-color": COLORS.route, "target-arrow-color": COLORS.route, width: 6, "z-index": 10 } },
      { selector: "edge.up", style: {
          "line-color": COLORS.up, "target-arrow-color": COLORS.up, width: 5, "z-index": 11 } },
      { selector: "edge.down", style: {
          "line-color": COLORS.down, "target-arrow-color": COLORS.down, width: 5, "z-index": 11 } },
      { selector: "edge.line-selected", style: {
          "line-color": "#ffffff", "target-arrow-color": "#ffffff", width: 6, "z-index": 12 } },
      { selector: "node.up", style: { "border-width": 4, "border-color": COLORS.up } },
      { selector: "node.down", style: { "border-width": 4, "border-color": COLORS.down } },
      { selector: ".faded", style: { opacity: 0.15 } },
      // The protocol filter (toolbar): edges carrying the chosen protocol glow, the rest fade.
      { selector: "edge.proto-dim", style: { opacity: 0.2 } },
      { selector: "edge.proto-hit", style: {
          opacity: 1, "underlay-color": COLORS.protocol, "underlay-opacity": 0.55, "underlay-padding": 4,
          "z-index": 20 } },
      // Hidden by the marks: restored when they change (D16). Hiding comes before any dimming.
      { selector: ".mark-hidden", style: { display: "none" } },
      { selector: ":selected", style: { "overlay-color": "#fff", "overlay-opacity": 0.15 } },
    ],
  });

  window.threatbridge = { cy }; // handle for debugging / UI tests

  // Protocols as the server names them (Zeek's service names), as the map shows them (D14).
  const PROTOCOL_ALIASES = { "ftp-data": "ftp", krb_tcp: "krb" };
  const protocolName = (p) => (cfg.protocol_names || {})[p] || p.toUpperCase();

  function setStatus(msg, isError, isWarn) {
    statusEl.textContent = msg || "";
    statusEl.classList.toggle("error", !!isError);
    statusEl.classList.toggle("warn", !!isWarn && !isError);
  }

  function fail(err) { setStatus(err.message, !err.cancelled); }

  // An element with properties (textContent, className, ...) and children.
  function el(tag, props, ...children) {
    const node = Object.assign(document.createElement(tag), props);
    node.append(...children);
    return node;
  }

  // A button doing `action`; what goes wrong is shown in the status bar.
  function button(label, action, props) {
    const b = el("button", Object.assign({ type: "button", textContent: label }, props));
    b.addEventListener("click", () => Promise.resolve(action()).catch(fail));
    return b;
  }

  // A list entry: its text, a note in small type under it (if any), and a button.
  function listEntry(text, note, label, action) {
    const span = el("span", { textContent: text });
    if (note) span.append(el("small", { className: "resolved", textContent: note }));
    return el("li", {}, span, button(label, action));
  }

  const hintItem = (text) => el("li", { className: "hint", textContent: text });

  // The analyst's time range (toolbar): sent with every query, which it limits. Blank = open.
  function withRange(params) {
    const lo = $("range-from").value.trim(), hi = $("range-to").value.trim();
    if (lo) params.set("range_from", lo);
    if (hi) params.set("range_to", hi);
    return params;
  }

  // ---- requests: one still running after a second shows its time and can be cancelled ---
  const inFlight = new Set();   // AbortControllers
  let busySince = 0, busyTimer = null;

  function showBusy() {
    const secs = Math.floor((Date.now() - busySince) / 1000);
    $("busy").hidden = !inFlight.size || secs < 1;
    $("busy-text").textContent = `Working… ${secs} s`;
    if (!inFlight.size) { clearInterval(busyTimer); busyTimer = null; }
  }

  // The response read as `read` ("json" or "blob"); an error answer becomes an Error with
  // the server's message and the HTTP status.
  async function request(url, opts, read) {
    const controller = new AbortController();
    if (!inFlight.size) { busySince = Date.now(); busyTimer = setInterval(showBusy, 250); }
    inFlight.add(controller);
    try {
      const r = await fetch(url, Object.assign({ credentials: "same-origin", signal: controller.signal }, opts || {}));
      if (!r.ok) {
        let body = null;
        try { body = await r.json(); } catch (_) { /* not JSON */ }
        throw Object.assign(new Error((body && body.error) || `HTTP ${r.status}`), { status: r.status });
      }
      return await r[read]();
    } catch (err) {
      if (err.name === "AbortError") throw Object.assign(new Error("Cancelled"), { cancelled: true });
      throw err;
    } finally {
      inFlight.delete(controller);
      showBusy();
    }
  }

  const getJSON = (url, opts) => request(url, opts, "json");

  // A query about the map's data, with the analyst's filters (D17). An opened map's own marks
  // (D19), and `extra` fields, go in a POST; otherwise a GET says it all.
  function ask(path, params, extra) {
    if (localMap || extra) {
      const body = Object.assign(Object.fromEntries(params.entries()), extra || {}, { filters });
      if (localMap) body.marks = marks;
      return getJSON(path, { method: "POST", headers: WRITE_HEADERS, body: JSON.stringify(body) });
    }
    for (const f of filters) params.append("filter", f);
    return getJSON(`${path}?${params}`);
  }

  $("cancel").addEventListener("click", () => { for (const c of inFlight) c.abort(); });

  // Writes to a shared list go one at a time, in the order made, so each answer includes the
  // writes before it (the server may run two at once and answer them in either order).
  const writing = {};   // url -> the last write to it
  function write(url, method, body) {
    const payload = JSON.stringify(body);
    const sent = (writing[url] || Promise.resolve()).then(() =>
      getJSON(url, { method, headers: WRITE_HEADERS, body: payload }));
    writing[url] = sent.catch(() => {});
    return sent;
  }

  // Once a submitted entry is stored, empty its form, unless the analyst has typed something
  // else in it meanwhile.
  function clearForm(ids, submitted) {
    if (ids.every((id, i) => $(id).value.trim() === submitted[i])) for (const id of ids) $(id).value = "";
  }

  // Offer `blob` to the analyst as a file called `name`.
  function saveFile(blob, name) {
    const a = el("a", { href: URL.createObjectURL(blob), download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 60000);
  }

  // Tree by hop distance from the IOC host (top row), each host's peers placed under it.
  // What the marks hide is left out.
  function relayout() {
    const shown = cy.elements().not(".mark-hidden");
    const root = shown.nodes("[?root]");
    shown.layout({
      name: "breadthfirst", circle: false, directed: false, roots: root.length ? root : undefined,
      animate: false, fit: true, padding: 40, spacingFactor: 1.1, avoidOverlap: true,
    }).run();
  }

  function addNode(ip, anchor, extra) {
    let n = cy.getElementById(ip);
    if (n.empty()) {
      n = cy.add({ group: "nodes", data: Object.assign(
        { id: ip, anchor: anchor, compromised: compromised.has(ip) }, extra || {}) });
    }
    return n;
  }

  // An edge's data: what a query said of it ("full"), and what is shown, the same until the
  // marks narrow it to its marked and suspect flows (shown()).
  function edgeData(src, dst, direction, count, ports, first, last, protocols) {
    const full = { count, ports, protocols, first_seen: first, last_seen: last };
    return Object.assign({ id: `${src}->${dst}`, source: src, target: dst, direction, full }, shown(full));
  }

  function shown(d) {
    return { count: d.count, ports: d.ports, protocols: d.protocols, first_seen: d.first_seen,
             last_seen: d.last_seen, logCount: Math.log10(d.count + 1),
             label: `${d.count}${d.ports.length ? " · " + d.ports.join(",") : ""}` };
  }

  // Add an edge unless the map already shows it (keep the data from the expansion).
  function mergeEdge(src, dst, direction, count, ports, first, last, protocols) {
    const e = cy.getElementById(`${src}->${dst}`);
    if (e.nonempty()) return e;
    return cy.add({ group: "edges", data: edgeData(src, dst, direction, count, ports, first, last, protocols) });
  }

  // ---- protocol filter: edges carrying the chosen protocol glow, the others fade -----------
  const protocolSelect = $("protocol");

  function applyProtocol() {
    const want = protocolSelect.value;
    cy.batch(() => {
      cy.edges().removeClass("proto-hit proto-dim");
      if (!want) return;
      for (const e of cy.edges().not(".mark-hidden")) {
        e.addClass(e.data("protocols").includes(want) ? "proto-hit" : "proto-dim");
      }
    });
    $("apply-protocol").disabled = !want;
  }

  // The drop-down lists every protocol on the map's edges, by name. A choice holds until
  // another is made (or Clear): while no edge carries it, it says so, and every edge fades.
  function refreshProtocols() {
    const found = new Set(cy.edges().not(".mark-hidden").map((e) => e.data("protocols")).flat());
    const chosen = protocolSelect.value;
    const options = [...found].sort((a, b) => protocolName(a).localeCompare(protocolName(b)))
      .map((p) => new Option(protocolName(p), p));
    if (chosen && !found.has(chosen)) options.unshift(new Option(`${protocolName(chosen)} (not on the map)`, chosen));
    protocolSelect.replaceChildren(new Option("All", ""), ...options);
    protocolSelect.value = chosen;
    applyProtocol();
  }

  // Once per change to the map, however many edges it added, removed or updated.
  let protocolsDue = false;
  cy.on("add remove data", "edge", () => {
    if (protocolsDue) return;
    protocolsDue = true;
    queueMicrotask(() => { protocolsDue = false; refreshProtocols(); });
  });
  protocolSelect.addEventListener("change", refreshProtocols);

  function clearHighlight() {
    cy.elements().removeClass("up down line-selected faded");
  }

  function focus(elements) {
    clearHighlight();
    cy.elements().not(elements).addClass("faded");
  }

  // ---- the queries the map is built from: each is logged, to re-run with the filters -------
  // The toolbar's Window, N and peer order, as a query uses them.
  function settingsNow() {
    return { window: $("window").value.trim(), limit: $("limit").value.trim(), order: $("order").value };
  }

  // direction "in": peer -> host, anchored in the past; "out": host -> peer, anchored in the future.
  async function expand(ip, direction) {
    const node = cy.getElementById(ip);
    const anchor = node.nonempty() ? node.data("anchor") : $("ts").value.trim();
    const q = Object.assign({ op: "expand", ip, direction, anchor }, settingsNow());
    queries.push(q);
    return expandWith(q, true);
  }

  // One expansion: the host's peers as hosts and connections (one already drawn takes the new
  // counts). With `say`, the map is laid out again and the status bar tells what was found.
  async function expandWith(q, say) {
    const params = withRange(new URLSearchParams({ ip: q.ip, direction: q.direction, window: q.window,
                                                   limit: q.limit, order: q.order }));
    if (q.anchor) params.set("ts", q.anchor);
    if (say) setStatus(`Querying ${q.direction === "in" ? "inbound (past)" : "outbound (future)"} for ${q.ip}…`);
    const res = await ask("/api/neighbors", params);
    const direction = q.direction;

    const host = addNode(res.ip, res.anchor, { depth: 0 });
    const depth = (host.data("depth") || 0) + 1;
    if (!host.data("anchor")) host.data("anchor", res.anchor);
    host.data(direction === "in" ? "expandedIn" : "expandedOut", true);

    cy.batch(() => {
      for (const p of res.peers) {
        // Carry time forward/backward so the next hop follows the chain of activity.
        const peerAnchor = direction === "out" ? p.first_seen : p.last_seen;
        addNode(p.peer, peerAnchor, { depth });
        const src = direction === "in" ? p.peer : res.ip;
        const dst = direction === "in" ? res.ip : p.peer;
        const data = edgeData(src, dst, direction, p.count, p.ports, p.first_seen, p.last_seen, p.protocols);
        const e = cy.getElementById(data.id);
        if (e.nonempty()) e.data(data); else cy.add({ group: "edges", data });
      }
    });
    if (!say) return res;
    relayout();
    hidingDue();
    const which = res.order === "top" ? "top" : "rarest";
    let msg = `${res.ip}: showing ${which} ${res.peers.length}`;
    if (res.distinct_peers != null) msg += ` of ${res.distinct_peers} distinct peer(s)`;
    msg += res.start <= res.end ? `, ${res.start} → ${res.end}` : " — the window is outside the time range";
    if (res.truncated) msg += " — WARNING: scan hit the peer cap; rarest list may be incomplete";
    setStatus(msg, false, res.truncated);
    return res;
  }

  // Map: a fresh map, with the shared marks again (D19) and the filters still applied.
  async function start() {
    const ip = $("ip").value.trim();
    if (!ip) { setStatus("Enter an IP address", true); return; }
    cy.elements().remove();
    queries = [];
    if (localMap) leaveLocal();
    const ts = $("ts").value.trim();
    try {
      const q = Object.assign({ op: "root", ip, ts, direction: $("direction").value }, settingsNow());
      queries.push(q);
      const res = await rootWith(q, true);
      rememberInUrl(res.ip);
      await refreshPaths(true);
    } catch (err) { fail(err); }
  }

  // The map's root and settings in the page's URL, so a reload or a shared link reopens it.
  function rememberInUrl(ip) {
    const q = withRange(new URLSearchParams({ ip, ts: iocTime || "", dir: $("direction").value,
                                              window: $("window").value.trim(), order: $("order").value }));
    history.replaceState(null, "", `?${q}`);
  }

  async function rootWith(q, say) {
    // Normalise IP/anchor server-side; the root anchor is the IOC time used for pivots.
    const params = withRange(new URLSearchParams({ ip: q.ip, direction: q.direction }));
    if (q.ts) params.set("ts", q.ts);
    const r = await getJSON(`/api/resolve?${params}`);
    iocTime = r.anchor;
    addNode(r.ip, r.anchor, { root: true, depth: 0 });
    return expandWith(Object.assign({}, q, { op: "expand", ip: r.ip, anchor: r.anchor }), say);
  }

  // A connection of a map saved before filters (version 1), fetched again as it was drawn.
  async function edgeWith(q) {
    const r = await ask("/api/edge", withRange(new URLSearchParams({ src: q.source, dst: q.target,
                                                                      from: q.from, to: q.to })));
    if (!r.count) return;
    for (const ip of [q.source, q.target]) addNode(ip, null, {});
    mergeEdge(q.source, q.target, q.direction, r.count, r.ports, r.first_seen, r.last_seen, r.protocols);
  }

  // Re-run every query the map was built from with the filters (D17), then lay it out again.
  // Marked hosts on the map stay, even with no flow left; with filters, other hosts left with
  // no connection go.
  async function requery() {
    const log = queries.slice();
    const keep = cy.nodes().filter((n) => compromised.has(n.id())).map((n) => [n.id(), n.data("anchor")]);
    cy.elements().remove();
    setStatus(`Re-running ${log.length} quer${log.length === 1 ? "y" : "ies"} with ${filters.length} filter(s)…`);
    let skipped = 0;
    for (const q of log) {
      try {
        await run(q);
      } catch (err) {
        if (err.cancelled) throw err;
        skipped += 1;
      }
    }
    for (const [ip, anchor] of keep) addNode(ip, anchor, {});
    if (filters.length) {
      cy.nodes().filter((n) => n.degree() === 0 && !compromised.has(n.id()) && !n.data("root")).remove();
    }
    markEdges();
    relayout();
    await refreshPaths(true);
    await refreshHiding();
    setStatus(`Re-ran ${log.length - skipped} of ${log.length} quer${log.length === 1 ? "y" : "ies"} with ` +
              `${filters.length} filter(s): ${cy.nodes().length} host(s), ${cy.edges().length} connection(s)` +
              (skipped ? `; ${skipped} found nothing that passes them` : ""));
  }

  // One logged query, run again (requery).
  function run(q) {
    switch (q.op) {
      case "root": return rootWith(q, false);
      case "expand": return expandWith(q, false);
      case "threatline": return threatLineWith(q, false);
      case "routes": return routesWith(q, false);
      case "node": addNode(q.id, q.data.anchor || null, q.data); return null;   // a version 1 map's host
      case "edge": return edgeWith(q);
      case "remove": {
        const n = cy.getElementById(q.ip);
        if (n.nonempty() && !n.data("root")) n.remove();
        return null;
      }
      default: return null;
    }
  }

  function showDetails(rows) {
    flowsFor = null;
    lastFlows = null;
    const dl = el("dl");
    for (const [k, v] of rows) dl.append(el("dt", { textContent: k }), el("dd", { textContent: v == null ? "—" : String(v) }));
    $("detail-body").replaceChildren(dl);
  }

  function refreshDetails(ip) {
    const n = cy.getElementById(ip);
    if (detailsFor === ip && n.nonempty()) nodeDetails(n);
  }

  function compromisedText(ip) {
    const h = compromised.get(ip);
    if (!h) return "no";
    const time = h.time || "yes, time unknown";
    const through = h.count - (h.direct ? 1 : 0);
    return through ? `${time} (through ${through} marked flow(s))` : time;
  }

  function nodeDetails(n) {
    detailsFor = n.id();
    showDetails([
      ["Host", n.id()], ["Anchor", n.data("anchor")], ["IOC root", n.data("root") ? "yes" : "no"],
      ["Compromised", compromisedText(n.id())],
      ["Hops from IOC", n.data("depth")],
      ["Inbound expanded", n.data("expandedIn") ? "yes" : "no"],
      ["Outbound expanded", n.data("expandedOut") ? "yes" : "no"],
      ["Degree", n.degree()],
    ]);
  }

  function edgeDetails(e) {
    detailsFor = null;
    const rows = [
      ["Source", e.data("source")], ["Destination", e.data("target")],
      ["Direction", e.data("direction") === "in" ? "inbound (past)" : "outbound (future)"],
      ["Connections", e.data("count")], ["Top dst ports", (e.data("ports") || []).join(", ")],
      ["Protocols", e.data("protocols").map(protocolName).join(", ")],
      ["First seen", e.data("first_seen")], ["Last seen", e.data("last_seen")],
    ];
    if (e.data("kept")) rows.push(["Marks keep", `${e.data("kept").marked} marked, ${e.data("kept").suspect} suspect ` +
                                                 `of ${e.data("full").count}`]);
    showDetails(rows);
    flowsFor = { src: e.data("source"), dst: e.data("target"), from: e.data("first_seen"), to: e.data("last_seen"),
                 within: e.data("kept") ? e.data("kept").within : null };
    loadFlows(flowsFor, 0).catch((err) => fail(err));
  }

  // ---- a connection's flows, oldest first, a page at a time -----------------
  async function loadFlows(conn, offset) {
    const params = withRange(new URLSearchParams({ src: conn.src, dst: conn.dst, from: conn.from,
                                                   to: conn.to, offset, limit: FLOW_PAGE }));
    const r = await ask("/api/flows", params, conn.within ? { within: conn.within } : null);
    if (flowsFor === conn) renderFlows(conn, r); // else another element was clicked meanwhile
  }

  // "SMB · tcp 51234 → 445 · 1.204 s · 12 pkts · 3,410 B"; missing values are left out.
  function flowMeta(f) {
    const ports = f.proto === "tcp" || f.proto === "udp" ? ` ${f.sport} → ${f.dport}` : "";
    const n = (v) => v.toLocaleString("en-US");
    return [f.protocols.map(protocolName).join("/"), `${f.proto || "?"}${ports}`,
            f.duration == null ? null : `${f.duration.toFixed(3)} s`,
            f.packets == null ? null : `${n(f.packets)} pkts`,
            f.bytes == null ? null : `${n(f.bytes)} B`].filter((x) => x).join(" · ");
  }

  function renderFlows(conn, r) {
    lastFlows = r;
    let section = $("flows");
    if (!section) $("detail-body").append(section = el("section", { id: "flows" }));
    const page = (label, offset, enabled) => button(label, () => loadFlows(conn, offset), { disabled: !enabled });
    const last = Math.max(0, Math.floor((r.total - 1) / FLOW_PAGE) * FLOW_PAGE);
    const info = el("span", { textContent: r.flows.length
      ? `${r.offset + 1}–${r.offset + r.flows.length} of ${r.total.toLocaleString("en-US")}`
      : "none in the time range" });
    const pager = el("div", { className: "pager" }, page("First", 0, r.offset > 0),
                     page("Older", Math.max(0, r.offset - FLOW_PAGE), r.offset > 0), info,
                     page("Newer", r.offset + FLOW_PAGE, r.offset + FLOW_PAGE < r.total),
                     page("Last", last, r.offset < last));
    const list = el("ol", { className: "flows", start: r.offset + 1 }, ...r.flows.map((f) => {
      const li = el("li", { textContent: f.start }, el("small", { textContent: flowMeta(f) }));
      const actions = flowActions(conn, f);
      if (actions) li.append(actions);
      return li;
    }));
    section.replaceChildren(el("h3", { textContent: "Flows, oldest first" }), pager, list);
  }

  // A flow's own actions: mark it compromised (D15), and in Security Onion mode its packets.
  function flowActions(conn, f) {
    const span = el("span", { className: "actions" });
    const key = flowOf(conn, f);
    if (key) {
      const marked = markedFlows.has(flowKey(key));
      span.append(button(marked ? "Unmark" : "Mark compromised", () => (marked ? unmarkFlow(key) : markFlow(key)),
                         { className: "mark" }));
    }
    if (f.id && cfg.soc_pivots !== false) {
      if (f.soc_pcap) {
        span.append(el("a", { href: f.soc_pcap, target: "_blank", rel: "noopener noreferrer", textContent: "PCAP in SOC" }));
      }
      if (cfg.pcap_download) span.append(button("Download PCAP", () => downloadPcap(conn, f)));
    }
    return span.childElementCount ? span : null;
  }

  async function downloadPcap(conn, f) {
    setStatus(`Asking the sensor for the packets of ${conn.src} → ${conn.dst} at ${f.start}…`);
    const blob = await request("/api/pcap", { method: "POST", headers: WRITE_HEADERS,
                                              body: JSON.stringify({ id: f.id, time: f.start }) }, "blob");
    saveFile(blob, `${conn.src}_${conn.dst}_${f.start}.pcap`.replace(/[:]/g, "-"));
    setStatus(`PCAP of ${conn.src} → ${conn.dst} at ${f.start}: ${blob.size.toLocaleString("en-US")} B`);
  }

  // ---- context menu ---------------------------------------------------------
  function hideMenu() { menu.hidden = true; menu.replaceChildren(); }

  function showMenu(x, y, items) {
    menu.replaceChildren(...items.map((it) => {
      if (it === "-") return el("li", { className: "sep" });
      if (it.title) return el("li", { className: "title", textContent: it.title });
      const li = el("li", { textContent: it.label });
      li.addEventListener("click", () => { hideMenu(); Promise.resolve(it.action()).catch(fail); });
      return li;
    }));
    menu.hidden = false;
    const r = menu.getBoundingClientRect();
    menu.style.left = `${Math.min(x, window.innerWidth - r.width - 4)}px`;
    menu.style.top = `${Math.min(y, window.innerHeight - r.height - 4)}px`;
  }

  async function pivot(a, b, until) {
    const params = withRange(new URLSearchParams({ a }));
    if (b) params.set("b", b);
    if (until) params.set("until", until);
    return getJSON(`/api/pivot?${params}`);
  }

  async function openPivot(a, b, until) {
    const p = await pivot(a, b, until);
    window.open(p.url, "_blank", "noopener");
    setStatus(`Opened SOC filter: ${p.query}`);
  }

  async function copyPivot(a, b, until) {
    const p = await pivot(a, b, until);
    await navigator.clipboard.writeText(p.query);
    setStatus("SOC query copied to clipboard");
  }

  cy.on("cxttap", "edge", (evt) => {
    const e = evt.target;
    const [a, b, until] = [e.data("source"), e.data("target"), iocTime];
    edgeDetails(e);
    const oe = evt.originalEvent;
    const items = [];
    if (e.data("count") === 1) {     // one flow: mark it here (D15); otherwise in the flow list
      items.push({ label: markedPairs.has(e.id()) ? "Unmark compromised" : "Mark compromised",
                   action: () => toggleOnlyFlow(e) });
    }
    if (cfg.soc_pivots !== false) {
      items.push({ label: `Filter SOC Dashboards: all conversations up to IOC time`, action: () => openPivot(a, b, until) },
                 { label: "Copy SOC query", action: () => copyPivot(a, b, until) });
    }
    if (items.length) showMenu(oe.clientX, oe.clientY, [{ title: `${a} ↔ ${b}` }, ...items]);
  });

  // The flow of a single-flow connection, marked or unmarked.
  async function toggleOnlyFlow(e) {
    const conn = { src: e.data("source"), dst: e.data("target"), from: e.data("first_seen"), to: e.data("last_seen") };
    const params = withRange(new URLSearchParams({ src: conn.src, dst: conn.dst, from: conn.from, to: conn.to,
                                                   offset: 0, limit: 1 }));
    const kept = e.data("kept");
    const r = await ask("/api/flows", params, kept ? { within: kept.within } : null);
    const key = r.flows.length ? flowOf(conn, r.flows[0]) : null;
    if (!key) throw new Error(`No flow of ${conn.src} → ${conn.dst} to mark`);
    return markedFlows.has(flowKey(key)) ? unmarkFlow(key) : markFlow(key);
  }

  cy.on("cxttap", "node", (evt) => {
    const n = evt.target;
    nodeDetails(n);
    const oe = evt.originalEvent;
    showMenu(oe.clientX, oe.clientY, [
      { title: `${n.id()} @ ${n.data("anchor") || "now"}` },
      { label: "Expand inbound: who connected to it (past)", action: () => expand(n.id(), "in") },
      { label: "Expand outbound: who it connected to (future)", action: () => expand(n.id(), "out") },
      "-",
      ...(cfg.soc_pivots === false ? [] :
        [{ label: "Open host in SOC dashboard", action: () => openPivot(n.id(), null, null) }]),
      ...compromiseItems(n),
      ...(cfg.analysis ? [
        { label: "Find paths from this host…", action: () => routeEnd(n.id(), "src") },
        { label: "Find paths to this host…", action: () => routeEnd(n.id(), "dst") }] : []),
      { label: "Remove from map", action: () => removeHost(n) },
      { label: "Add to shared exclude list", action: () => addExclude(n.id()) },
    ]);
  });

  function removeHost(n) {
    if (n.data("root")) return;
    queries.push({ op: "remove", ip: n.id() });
    n.remove();
  }

  function compromiseItems(n) {
    if (compromised.has(n.id())) {
      return [{ label: "Unmark compromised", action: () => unmarkCompromised(n.id()) }];
    }
    const items = [];
    if (n.data("anchor")) {
      items.push({ label: `Mark compromised at ${n.data("anchor")}`,
                   action: () => markCompromised(n.id(), n.data("anchor")) });
    }
    items.push({ label: "Mark compromised (time unknown)", action: () => markCompromised(n.id(), "") });
    return items;
  }

  cy.on("tap", "node", (evt) => {
    nodeDetails(evt.target);
    expand(evt.target.id(), $("direction").value).catch((e) => fail(e));
  });
  cy.on("tap", "edge", (evt) => {
    edgeDetails(evt.target);
    if (cfg.analysis) showThreatLine(evt.target).catch((e) => fail(e));
  });
  cy.on("tap", (evt) => { if (evt.target === cy) { hideMenu(); clearHighlight(); } });
  cy.on("cxttap", (evt) => { if (evt.target === cy) hideMenu(); });
  document.addEventListener("click", (e) => { if (!menu.contains(e.target)) hideMenu(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") hideMenu(); });

  $("go").addEventListener("click", start);
  $("fit").addEventListener("click", () => cy.fit(cy.elements().not(".mark-hidden"), 40));
  // Clear resets the protocol preview, nothing else (D18).
  $("clear").addEventListener("click", () => { protocolSelect.value = ""; refreshProtocols(); });
  for (const id of ["ip", "ts", "window", "limit", "range-from", "range-to"]) {
    $(id).addEventListener("keydown", (e) => { if (e.key === "Enter") start(); });
  }

  // ---- filters (D17): typed expressions, applied with Enter, each removable -----------------
  const filterInput = $("filter");

  function renderFilters() {
    $("filter-list").replaceChildren(...filters.map((f, i) => el("li", {}, el("span", { textContent: f }),
      button("×", () => removeFilter(i), { title: `Remove the filter ${f}` }))));
  }

  async function addFilter(text) {
    const r = await getJSON(`/api/filter?${new URLSearchParams({ filter: text })}`).catch((err) => {
      filterInput.classList.add("invalid");
      throw err;
    });
    if (!filters.includes(r.filter)) {
      if (filters.length >= (cfg.max_filters || 20)) throw new Error(`At most ${cfg.max_filters || 20} filters at once`);
      filters.push(r.filter);
      renderFilters();
      await requery();
    }
    return r.filter;
  }

  async function removeFilter(i) {
    filters.splice(i, 1);
    renderFilters();
    await requery();
  }

  filterInput.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    const text = filterInput.value;
    if (!text.trim()) return;
    addFilter(text).then(() => clearForm(["filter"], [text.trim()])).catch(fail);
  });
  filterInput.addEventListener("input", () => filterInput.classList.remove("invalid"));

  // The protocol previewed, as a filter (INT-6).
  $("apply-protocol").addEventListener("click", () => {
    const want = protocolSelect.value;
    if (!want) return;
    protocolSelect.value = "";
    refreshProtocols();
    addFilter(protocolName(want)).catch(fail);
  });

  // ---- shared exclude list --------------------------------------------------
  // What a domain entry stands for: DNS answers seen in the capture, and a live lookup.
  function resolutionText(r) {
    const list = (ips) => (ips.length > 4 ? `${ips.slice(0, 4).join(", ")} +${ips.length - 4} more`
                                          : ips.join(", "));
    const parts = [];
    if (r.capture.length) parts.push(`capture: ${list(r.capture)}`);
    if (r.dns.length) parts.push(`DNS: ${list(r.dns)}`);
    if (r.error) parts.push(r.error);
    if (!r.capture.length && !r.dns.length && !r.error) parts.push("no addresses found");
    return parts.join(" · ");
  }

  function renderExcludes(r) {
    $("exclude-list").replaceChildren(...r.entries.map((entry) => {
      const resolved = (r.resolved || {})[entry];
      return listEntry(entry, resolved && resolutionText(resolved), "Remove", () => removeExclude(entry));
    }));
  }

  // Excluded for everyone: the hosts it stands for leave the map, and the paths are found again.
  async function addExclude(entry) {
    const r = await write("/api/excludes", "POST", { entry });
    renderExcludes(r);
    const added = r.entry;   // canonical form, e.g. lower-cased domain
    const resolved = (r.resolved || {})[added];
    const hosts = resolved ? [...resolved.capture, ...resolved.dns] : [added];
    for (const ip of hosts) {
      const n = cy.getElementById(ip);
      if (n.nonempty() && !n.data("root")) n.remove();
    }
    setStatus(resolved
      ? `Excluded ${added} (${hosts.length} address(es)) for everyone`
      : `Excluded ${added} for everyone; re-expand hosts to apply CIDRs`);
    refreshPaths(true).catch(fail);   // in the background: the map stays usable meanwhile
  }

  async function removeExclude(entry) {
    const r = await write("/api/excludes", "DELETE", { entry });
    renderExcludes(r);
    setStatus(`Removed ${entry} from exclude list`);
    refreshPaths(true).catch(fail);
  }

  $("exclude-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const v = $("exclude-input").value.trim();
    if (!v) return;
    addExclude(v).then(() => clearForm(["exclude-input"], [v])).catch((err) => fail(err));
  });

  // ---- threat line through a clicked edge (PCAP/NetFlow cases) --------------
  // Earlier hosts that could have led to the edge's source, and later hosts its target
  // could have reached, following time order with at most `window` between hops.
  async function showThreatLine(e) {
    const q = { op: "threatline", a: e.data("source"), b: e.data("target"), from: e.data("first_seen"),
                to: e.data("last_seen"), window: $("window").value.trim() };
    queries.push(q);
    return threatLineWith(q, true);
  }

  async function threatLineWith(q, say) {
    const { a, b } = q;
    const params = withRange(new URLSearchParams({ a, b, from: q.from, to: q.to, window: q.window }));
    if (say) setStatus(`Tracing the threat line through ${a} → ${b}…`);
    const r = await ask("/api/threatline", params);
    let line = cy.collection();
    cy.batch(() => {
      for (const n of r.nodes) line = line.union(addNode(n.id, n.time, {}));
      for (const ed of r.edges) {
        line = line.union(mergeEdge(ed.source, ed.target, ed.role === "up" ? "in" : "out",
                                    ed.count, ed.ports, ed.first_seen, ed.last_seen, ed.protocols));
      }
    });
    if (!say) return;
    relayout();
    focus(line);
    const ROLES = { up: "up", down: "down", both: "up down" };
    cy.batch(() => {
      for (const n of r.nodes) if (ROLES[n.role]) cy.getElementById(n.id).addClass(ROLES[n.role]);
      for (const ed of r.edges) {
        cy.getElementById(`${ed.source}->${ed.target}`)
          .addClass(ed.role === "selected" ? "line-selected" : ed.role);
      }
    });
    const up = r.nodes.filter((n) => n.role === "up" || n.role === "both").length;
    const down = r.nodes.filter((n) => n.role === "down" || n.role === "both").length;
    let msg = `Threat line through ${a} → ${b}: ${up} earlier host(s) (violet), ` +
              `${down} later host(s) (teal); ≤ ${cfg.threat_hops} hops, ≤ ${q.window} ` +
              "between hops. Click the background to clear.";
    if (r.truncated) msg += " WARNING: stopped at the host limit; the line is incomplete.";
    setStatus(msg, false, r.truncated);
  }

  // ---- marks (D15): hosts and flows marked compromised, shared or an opened map's own -----
  const flowKey = (f) => [f.src, f.dst, f.start, f.sport, f.dport, f.proto].join("|");

  // A listed flow as a mark names it; null if it lacks what a mark needs.
  function flowOf(conn, f) {
    if (!Number.isInteger(f.sport) || !Number.isInteger(f.dport) || f.proto == null) return null;
    return { src: conn.src, dst: conn.dst, start: f.start, sport: f.sport, dport: f.dport, proto: String(f.proto) };
  }

  // Every marked host, as the server works them out (compromised.marked_hosts).
  function markedHosts(hosts, flows) {
    const out = new Map(hosts.map((h) => [h.ip, { ip: h.ip, time: h.time, note: h.note || "", direct: true, count: 1 }]));
    for (const f of flows) {
      for (const ip of new Set([f.src, f.dst])) {
        if (!out.has(ip)) out.set(ip, { ip, time: null, note: "", direct: false, count: 0 });
        const row = out.get(ip);
        row.count += 1;
        if (row.time == null || f.start < row.time) row.time = f.start;
      }
    }
    const cmp = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
    return [...out.values()].sort((a, b) => cmp(a.time || "", b.time || "") || cmp(a.ip, b.ip));
  }

  function markEdges() {
    cy.edges().forEach((e) => { e.toggleClass("marked", markedPairs.has(e.id())); });
  }

  function setMarks(hosts, flows) {
    marks = { hosts: hosts.map((h) => ({ ip: h.ip, time: h.time, note: h.note || "" })), flows: flows.slice() };
    const rows = markedHosts(marks.hosts, marks.flows);
    compromised = new Map(rows.map((h) => [h.ip, h]));
    markedFlows = new Map(marks.flows.map((f) => [flowKey(f), f]));
    markedPairs = new Set(marks.flows.map((f) => `${f.src}->${f.dst}`));
    cy.batch(() => {
      cy.nodes().forEach((n) => { n.data("compromised", compromised.has(n.id())); });
      markEdges();
    });
    renderCompromised(rows);
  }

  // The marks changed: show them, and redo what depends on them.
  function marksChanged(hosts, flows, quiet) {
    const before = new Set(compromised.keys());
    setMarks(hosts, flows);
    if (detailsFor) refreshDetails(detailsFor);
    if (flowsFor && lastFlows) renderFlows(flowsFor, lastFlows);
    if (filters.length) {          // shown only for its mark, a host with no flow left goes (C2)
      cy.nodes().filter((n) => before.has(n.id()) && !compromised.has(n.id()) && n.degree() === 0 &&
                               !n.data("root")).remove();
    }
    refreshPaths(quiet).catch(fail);   // in the background: the map stays usable meanwhile
    refreshHiding().catch(fail);
  }

  function showShared(view, quiet) {
    shared = view;
    marksChanged(view.marked, view.flows, quiet);
  }

  function renderCompromised(rows) {
    $("compromised-list").replaceChildren(...rows.map((h) => {
      const through = h.count - (h.direct ? 1 : 0);
      return listEntry(`${h.ip} @ ${h.time || "time unknown"}`,
                       through && `${h.direct ? "marked, and " : ""}through ${through} marked flow(s)`,
                       "Remove", () => unmarkCompromised(h.ip));
    }));
    $("marked-flow-list").replaceChildren(...marks.flows.map((f) => listEntry(
      `${f.src} → ${f.dst} @ ${f.start}`, `${f.proto} ${f.sport} → ${f.dport}`, "Remove", () => unmarkFlow(f))));
  }

  // A change to the marks: written to the shared list, or, with an opened map, to its own.
  async function changeMarks(sharedWrite, localChange) {
    if (localMap) {
      localChange();
      marksChanged(marks.hosts, marks.flows);
    } else {
      showShared(await sharedWrite());
    }
  }

  async function markCompromised(ip, time) {
    let local = null;
    if (localMap) {      // checked and written as the server would (an IP, a time to the ms)
      const params = new URLSearchParams({ ip });
      if (time) params.set("ts", time);
      const r = await getJSON(`/api/resolve?${params}`);
      local = { ip: r.ip, time: time ? r.anchor : null, note: "" };
    }
    await changeMarks(() => write("/api/compromised", "POST", { ip, time }),
                      () => { marks.hosts = marks.hosts.filter((h) => h.ip !== local.ip).concat([local]); });
    refreshDetails(ip);
    setStatus(`Marked ${ip} compromised${time ? " at " + time : " (time unknown)"}`);
  }

  async function unmarkCompromised(ip) {
    await changeMarks(() => write("/api/compromised", "DELETE", { ip }), () => {
      marks.hosts = marks.hosts.filter((h) => h.ip !== ip);
      marks.flows = marks.flows.filter((f) => f.src !== ip && f.dst !== ip);
    });
    refreshDetails(ip);
    setStatus(`Unmarked ${ip}`);
  }

  async function markFlow(key) {
    await changeMarks(() => write("/api/compromised/flows", "POST", key), () => {
      marks.flows = marks.flows.filter((f) => flowKey(f) !== flowKey(key)).concat([Object.assign({ note: "" }, key)]);
    });
    setStatus(`Marked the flow ${key.src} → ${key.dst} at ${key.start} compromised`);
  }

  async function unmarkFlow(key) {
    await changeMarks(() => write("/api/compromised/flows", "DELETE", key), () => {
      marks.flows = marks.flows.filter((f) => flowKey(f) !== flowKey(key));
    });
    setStatus(`Unmarked the flow ${key.src} → ${key.dst} at ${key.start}`);
  }

  $("compromised-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const ip = $("compromised-ip").value.trim(), time = $("compromised-time").value.trim();
    if (!ip) return;
    markCompromised(ip, time).then(() => clearForm(["compromised-ip", "compromised-time"], [ip, time]))
      .catch((err) => fail(err));
  });

  // Other analysts' marks appear within a few seconds (D15); an opened map keeps its own.
  async function pollMarks() {
    try {
      const r = await fetch("/api/compromised", { credentials: "same-origin" });
      if (!r.ok) return;
      const view = await r.json();
      if (shared && view.version === shared.version) return;
      if (localMap) shared = view; else showShared(view, true);
    } catch (_) { /* the next check will tell */ }
  }

  // ---- an opened map's own marks, until shared (D19) ------------------------------------------
  function showLocal() {
    $("local-marks").hidden = !localMap;
    $("local-marks-name").textContent = localMap || "";
  }

  function leaveLocal() {
    localMap = null;
    showLocal();
    if (shared) showShared(shared, true);
  }

  async function shareMarks() {
    const now = shared ? shared.marked.length + shared.flows.length : 0;
    const mine = marks.hosts.length + marks.flows.length;
    if (!confirm(`Replace the ${now} shared mark(s) with this map's ${mine}? Every analyst's map will show them.`)) return;
    const r = await write("/api/compromised", "PUT", { hosts: marks.hosts, flows: marks.flows });
    localMap = null;
    showLocal();
    showShared(r, true);
    setStatus(`Shared this map's ${mine} mark(s) with every analyst`);
  }

  $("share-marks").addEventListener("click", () => shareMarks().catch(fail));

  // ---- hiding by the marks (D16): only marked and suspect connections stay in their part -----
  let hidingAsked = 0, hidingTimer = null, hidingWaiting = false, hidingBusy = 0;

  function hidingDue() {
    clearTimeout(hidingTimer);
    hidingWaiting = true;
    hidingTimer = setTimeout(() => { hidingWaiting = false; refreshHiding().catch(fail); }, 30);
  }

  // Whether the hiding is still being worked out (the map may yet be laid out again).
  window.threatbridge.settling = () => hidingWaiting || hidingBusy > 0;

  cy.on("add remove", "edge", () => { if (cfg.suspects) hidingDue(); });
  cy.on("add", "edge", (evt) => { evt.target.toggleClass("marked", markedPairs.has(evt.target.id())); });

  async function refreshHiding() {
    if (!cfg.suspects) return;
    const asked = ++hidingAsked;
    const edges = cy.edges();
    if (edges.empty() || !cy.nodes().some((n) => compromised.has(n.id()))) { applyHiding(null); return; }
    hidingBusy += 1;
    try {
      const r = await ask("/api/suspect", windowParams(), { edges: drawn(edges) });
      if (asked === hidingAsked) applyHiding(r.edges);
    } finally {
      hidingBusy -= 1;
    }
  }

  // The toolbar's Window and time range, as a query sends them.
  const windowParams = () => withRange(new URLSearchParams({ window: $("window").value.trim() }));

  // Connections as first drawn, before the marks narrowed them.
  const drawn = (edges) => edges.map((e) => ({ source: e.data("source"), target: e.data("target"),
                                               from: e.data("full").first_seen, to: e.data("full").last_seen }));

  // Show what /api/suspect said of each connection (null: nothing hidden): a hidden one goes, a
  // kept one shows only its marked and suspect flows (dashed if none is marked), and a host
  // left with no connection in a part of the map the marks affect goes too, unless marked.
  function applyHiding(entries) {
    const hiddenNow = () => cy.elements(".mark-hidden").map((x) => x.id()).sort().join(" ");
    const before = hiddenNow();
    cy.batch(() => {
      cy.elements().removeClass("mark-hidden suspect");
      for (const e of cy.edges()) if (e.data("kept")) { e.removeData("kept"); e.data(shown(e.data("full"))); }
      if (!entries) return;
      const affected = new Set();
      for (const x of entries) {
        const e = cy.getElementById(`${x.source}->${x.target}`);
        if (e.empty() || x.status === "unaffected") continue;
        affected.add(x.source); affected.add(x.target);
        if (x.status === "hidden") { e.addClass("mark-hidden"); continue; }
        e.data(Object.assign(shown(x), { kept: { marked: x.marked, suspect: x.suspect, within: x.within } }));
        if (!x.marked) e.addClass("suspect");
      }
      for (const n of cy.nodes()) {
        if (affected.has(n.id()) && !compromised.has(n.id()) && !n.data("root") &&
            n.connectedEdges().not(".mark-hidden").empty()) n.addClass("mark-hidden");
      }
    });
    const hidden = cy.edges(".mark-hidden").length;
    $("hidden-note").textContent = hidden ? `${hidden} connection(s) hidden by marks` : "";
    if (hiddenNow() !== before) relayout();
    refreshProtocols();
  }

  // ---- attack paths between marked hosts -------------------------------------------------
  function pathElements(p) {
    let els = cy.collection();
    for (const h of p.hops) {
      els = els.union(cy.getElementById(h.source)).union(cy.getElementById(h.target))
        .union(cy.getElementById(`${h.source}->${h.target}`));
    }
    return els;
  }

  // Put paths on the map, their connections marked with `cls`.
  function drawPaths(paths, cls) {
    cy.batch(() => {
      cy.edges().removeClass(cls);
      for (const p of paths) {
        for (const h of p.hops) {
          addNode(h.source, h.start, {});
          addNode(h.target, h.start, {});
          const ports = h.proto === "tcp" || h.proto === "udp" ? [h.dport] : [];
          mergeEdge(h.source, h.target, "out", 1, ports, h.start, h.start, h.protocols).addClass(cls);
        }
      }
      markEdges();
    });
    if (paths.length) relayout();
  }

  // "a → b → c", and below it the first and last hop's times; click to focus on the path.
  function pathItem(p, what) {
    const hosts = [p.hops[0].source, ...p.hops.map((h) => h.target)];
    // In spans: a timestamp wraps as a whole.
    const [first, last] = [p.hops[0], p.hops[p.hops.length - 1]].map((h) => el("span", { textContent: h.start }));
    const li = el("li", { className: "path", textContent: hosts.join(" → ") }, el("small", {}, first, " → ", last));
    li.addEventListener("click", () => {
      focus(pathElements(p));
      setStatus(`${what} ${hosts[0]} → ${hosts[hosts.length - 1]}, ${p.hops.length} hop(s). ` +
                "Click the background to clear.");
    });
    return li;
  }

  // Re-run after every change to compromised hosts or excludes; draws the paths in red.
  // The server sends the first few paths per pair of hosts; "Show all" lists the rest.
  let pathsAsked = 0;   // answers to calls before the latest are out of date
  async function refreshPaths(quiet) {
    if (!cfg.analysis) return;
    const asked = ++pathsAsked;
    const r = await ask("/api/paths", windowParams());
    if (asked !== pathsAsked) return;
    const paths = r.pairs.flatMap((pair) => pair.paths);
    drawPaths(paths, "attack");
    const ul = $("path-list");
    ul.replaceChildren(...r.pairs.flatMap((pair) => {
      const head = el("li", { className: "pair" }, el("span", { textContent: `${pair.from} → ${pair.to}: ` +
        (pair.truncated ? `first ${pair.paths.length} paths` : `${pair.paths.length} path(s)`) }));
      if (pair.truncated) head.append(button("Show all", () => findRoutesBetween(pair.from, pair.to)));
      return [head, ...pair.paths.map((p) => pathItem(p, "Attack path"))];
    }));
    if (!r.pairs.length) {
      ul.append(hintItem(compromised.size < 2 ? "Mark at least two hosts as compromised."
                                              : "No time-consistent path between the marked hosts."));
    }
    const more = r.pairs.some((pair) => pair.truncated) ? "+" : "";
    if (!quiet) setStatus(`${paths.length}${more} attack path(s) between ${compromised.size} compromised host(s)`);
  }

  // ---- every path between two hosts -----------------------------------------
  function compromiseTime(ip) {
    const h = compromised.get(ip);
    return (h && h.time) || "";
  }

  // From the host menu: set one end (with its compromise time, if marked); search once both are set.
  function routeEnd(ip, end) {
    const other = end === "src" ? "dst" : "src";
    $(`route-${end}`).value = ip;
    $(`route-${end}-time`).value = compromiseTime(ip);
    const otherIp = $(`route-${other}`).value.trim();
    if (otherIp && otherIp !== ip) return findRoutes();
    $(`route-${other}`).focus();
    setStatus(`Now enter the host to find paths ${end === "src" ? "to" : "from"} (side panel)`);
    return null;
  }

  async function findRoutesBetween(src, dst) {
    for (const [end, ip] of [["src", src], ["dst", dst]]) {
      $(`route-${end}`).value = ip;
      $(`route-${end}-time`).value = compromiseTime(ip);
    }
    await findRoutes();
  }

  async function findRoutes() {
    const src = $("route-src").value.trim(), dst = $("route-dst").value.trim();
    if (!src || !dst) { setStatus("Enter both hosts to find the paths between them", true); return; }
    const q = { op: "routes", src, dst, src_time: $("route-src-time").value.trim(),
                dst_time: $("route-dst-time").value.trim(), window: $("window").value.trim() };
    queries.push(q);
    await routesWith(q, true);
  }

  // Every path between two hosts, drawn and listed. With `say`, the paths are focused on and
  // the status bar tells how many.
  async function routesWith(q, say) {
    const { src, dst } = q;
    const params = withRange(new URLSearchParams({ src, dst, window: q.window }));
    if (q.src_time) params.set("src_time", q.src_time);
    if (q.dst_time) params.set("dst_time", q.dst_time);
    if (say) setStatus(`Finding every path from ${src} to ${dst}…`);
    const r = await ask("/api/paths", params);
    drawPaths(r.paths, "route");
    const ul = $("route-list");
    ul.replaceChildren(...r.paths.map((p) => pathItem(p, "Path")));
    if (!r.paths.length) ul.append(hintItem("No time-consistent path."));
    const summary = r.truncated
      ? `First ${r.paths.length} paths from ${r.src} to ${r.dst}, shortest first. There are more: ` +
        "narrow them with the Window, the time range or the exclude list."
      : `${r.paths.length} path(s) from ${r.src} to ${r.dst}.`;
    $("route-summary").textContent = summary;
    if (!say) return;
    if (r.paths.length) {
      const edges = cy.edges(".route");
      focus(edges.union(edges.connectedNodes()));
    }
    setStatus(`${summary} At most ${cfg.threat_hops} hops, ${q.window} between hops.` +
              (r.paths.length ? " Click the background to clear." : ""), false, r.truncated);
  }

  $("route-form").addEventListener("submit", (e) => {
    e.preventDefault();
    findRoutes().catch((err) => fail(err));
  });

  // ---- export: the marked hosts, and the marked and suspect flows on the map, as CSV -------
  // A CSV cell: quoted when it must be, and never read as a formula by a spreadsheet.
  function csvCell(v) {
    let s = v == null ? "" : Array.isArray(v) ? v.join("/") : String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
    return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  }

  function csv(columns, rows) {
    return [columns.join(","), ...rows.map((r) => columns.map((c) => csvCell(r[c])).join(","))].join("\r\n") + "\r\n";
  }

  async function exportCsv() {
    const r = await ask("/api/export", windowParams(), { edges: drawn(cy.edges()) });
    const name = ($("session-name").value.trim() || cy.nodes("[?root]").map((n) => n.id())[0] || "map")
      .replace(/[^\w.-]+/g, "_");
    saveFile(new Blob([csv(["ip", "time", "note", "marked", "count"], r.hosts)], { type: "text/csv" }),
             `threatbridge-${name}-hosts.csv`);
    saveFile(new Blob([csv(["start", "end", "src", "sport", "dst", "dport", "proto", "protocols", "packets", "bytes",
                            "status"], r.flows)], { type: "text/csv" }), `threatbridge-${name}-flows.csv`);
    setStatus(`Exported ${r.hosts.length} marked host(s) and ${r.flows.length} marked or suspect flow(s)` +
              (r.truncated ? " (the first ones only)" : ""), false, r.truncated);
  }

  $("export-csv").addEventListener("click", () => exportCsv().catch(fail));

  // ---- saved maps: shared on the server, or as a file -----------------------
  // A map document (version 2) keeps the hosts and their positions, the connections, the
  // highlights, the view and the toolbar, and the filters, the marks and the queries the map
  // was built from (D19). Opening one takes only the fields below from it; version 1 too.
  const MAP_VERSION = 2;
  const NODE_FIELDS = ["anchor", "root", "depth", "expandedIn", "expandedOut"];
  const EDGE_FIELDS = ["first_seen", "last_seen"];
  const HIGHLIGHTS = ["up", "down", "line-selected", "faded", "attack", "route"];
  const SETTINGS = ["ip", "ts", "direction", "window", "range-from", "range-to", "order", "limit",
                    "route-src", "route-src-time", "route-dst", "route-dst-time"];
  const QUERY_FIELDS = ["op", "ip", "ts", "direction", "anchor", "window", "limit", "order", "a", "b", "from", "to",
                        "src", "dst", "src_time", "dst_time", "id", "source", "target"];

  function pick(from, fields) {
    const out = {};
    for (const k of fields) {
      const v = from[k];
      if (typeof v === "string" || typeof v === "boolean" || Number.isFinite(v)) out[k] = v;
    }
    return out;
  }

  function mapDocument() {
    return {
      version: MAP_VERSION, iocTime,
      settings: Object.fromEntries(SETTINGS.map((id) => [id, $(id).value])),
      nodes: cy.nodes().map((n) => Object.assign({ id: n.id(), position: n.position(), classes: n.classes() },
                                                 pick(n.data(), NODE_FIELDS))),
      edges: cy.edges().map((e) => Object.assign({ source: e.data("source"), target: e.data("target"),
                                                   direction: e.data("direction"), count: e.data("full").count,
                                                   ports: e.data("full").ports, protocols: e.data("full").protocols,
                                                   classes: e.classes() },
                                                 pick(e.data("full"), EDGE_FIELDS))),
      view: { zoom: cy.zoom(), pan: cy.pan() },
      filters: filters.slice(),
      marks: { hosts: marks.hosts, flows: marks.flows },
      queries,
    };
  }

  function highlight(element, classes) {
    if (Array.isArray(classes)) element.addClass(classes.filter((c) => HIGHLIGHTS.includes(c)).join(" "));
  }

  const isText = (v) => typeof v === "string";

  // Open a map document: draw it as saved, with its toolbar, filters and queries, and its own
  // marks, shown until shared (D19).
  async function openMap(doc, what) {
    if (!doc || (doc.version !== 1 && doc.version !== MAP_VERSION) || !Array.isArray(doc.nodes) ||
        !Array.isArray(doc.edges)) {
      throw new Error(`${what} is not a ThreatBridge map`);
    }
    cy.elements().remove();
    const settings = doc.settings || {};
    for (const id of SETTINGS) if (isText(settings[id])) $(id).value = settings[id];
    iocTime = isText(doc.iocTime) ? doc.iocTime : null;
    drawSaved(doc);
    filters = doc.version !== 1 && Array.isArray(doc.filters) ? doc.filters.filter(isText).slice(0, cfg.max_filters || 20) : [];
    renderFilters();
    queries = savedQueries(doc);
    localMap = what;
    showLocal();
    setMarks(...savedMarks(doc));
    restoreView(doc.view || {});
    const root = cy.nodes("[?root]");
    if (root.nonempty()) rememberInUrl(root.id());
    await refreshPaths(true);
    await refreshHiding();
    setStatus(`Opened ${what}: ${cy.nodes().length} host(s), ${cy.edges().length} connection(s)`);
  }

  // A saved map's hosts, where they were, and its connections, with their highlights; what
  // isn't well formed is left out.
  function drawSaved(doc) {
    cy.batch(() => {
      for (const n of doc.nodes) {
        if (!isText(n.id) || !n.id || cy.getElementById(n.id).nonempty()) continue;
        const data = pick(n, NODE_FIELDS);
        const p = n.position || {};
        const node = addNode(n.id, data.anchor || null, data);
        node.position(Number.isFinite(p.x) && Number.isFinite(p.y) ? { x: p.x, y: p.y } : { x: 0, y: 0 });
        highlight(node, n.classes);
      }
      for (const e of doc.edges) {
        if (isText(e.source) && isText(e.target) && cy.getElementById(e.source).nonempty() &&
            cy.getElementById(e.target).nonempty()) highlight(savedEdge(e), e.classes);
      }
    });
  }

  function savedEdge(e) {
    const ports = Array.isArray(e.ports) ? e.ports.filter(Number.isInteger) : [];
    const protocols = Array.isArray(e.protocols)
      ? [...new Set(e.protocols.filter((p) => isText(p) && p.length > 0 && p.length <= 40)
        .map((p) => PROTOCOL_ALIASES[p] || p))] : [];
    const t = pick(e, EDGE_FIELDS);
    return mergeEdge(e.source, e.target, e.direction === "in" ? "in" : "out", Number.isFinite(e.count) ? e.count : 0,
                     ports, t.first_seen, t.last_seen, protocols);
  }

  // A saved view, if well formed; else the whole map.
  function restoreView(view) {
    if (Number.isFinite(view.zoom) && view.pan && Number.isFinite(view.pan.x) && Number.isFinite(view.pan.y)) {
      cy.viewport({ zoom: view.zoom, pan: { x: view.pan.x, y: view.pan.y } });
    } else {
      cy.fit(undefined, 40);
    }
  }

  // The queries a map was built from; for a map saved before them (version 1), its hosts and
  // connections as drawn.
  function savedQueries(doc) {
    if (doc.version !== 1 && Array.isArray(doc.queries)) {
      return doc.queries.filter((q) => q && typeof q === "object" && isText(q.op) && (q.op !== "node" || isText(q.id)))
        .map((q) => Object.assign(pick(q, QUERY_FIELDS), q.op === "node" ? { data: pick(q.data || {}, NODE_FIELDS) } : {}));
    }
    return [...cy.nodes().map((n) => ({ op: "node", id: n.id(), data: pick(n.data(), NODE_FIELDS) })),
            ...cy.edges().map((e) => ({ op: "edge", source: e.data("source"), target: e.data("target"),
                                        direction: e.data("direction"), from: e.data("first_seen"), to: e.data("last_seen") }))
              .filter((q) => q.from)];
  }

  // A map's own marks, [hosts, flows], those well formed.
  function savedMarks(doc) {
    const saved = (doc.version !== 1 && doc.marks) || {};
    const list = (v) => (Array.isArray(v) ? v : []);
    const isFlow = (f) => f && isText(f.src) && isText(f.dst) && isText(f.start) && Number.isInteger(f.sport) &&
      Number.isInteger(f.dport) && isText(f.proto);
    return [list(saved.hosts).filter((h) => h && isText(h.ip))
              .map((h) => ({ ip: h.ip, time: isText(h.time) ? h.time : null, note: isText(h.note) ? h.note : "" })),
            list(saved.flows).filter(isFlow).map((f) => pick(f, ["src", "dst", "start", "sport", "dport", "proto", "note"]))];
  }

  function renderSessions(list) {
    const ul = $("session-list");
    ul.replaceChildren(...list.map((saved) => {
      const li = listEntry(saved.name, `saved ${saved.saved}`, "Delete", () => deleteSession(saved.name));
      li.firstChild.className = "session";     // click the name to open it
      li.firstChild.addEventListener("click", () => openSession(saved.name).catch(fail));
      return li;
    }));
    if (!list.length) ul.append(hintItem("No saved maps yet."));
  }

  // Saved for everyone; a name already taken is replaced only once the analyst agrees.
  async function saveSession(name, overwrite) {
    try {
      const r = await write("/api/sessions", "POST", { name, map: mapDocument(), overwrite: !!overwrite });
      renderSessions(r.sessions);
      setStatus(`${overwrite ? "Replaced" : "Saved"} the map "${r.name}" for everyone`);
    } catch (err) {
      if (err.status === 409 && !overwrite && confirm(`Replace the saved map "${name}"?`)) {
        return saveSession(name, true);
      }
      throw err;
    }
    return null;
  }

  async function openSession(name) {
    const r = await getJSON(`/api/sessions?${new URLSearchParams({ name })}`);
    $("session-name").value = r.name;
    await openMap(r.map, `"${r.name}" (saved ${r.saved})`);
  }

  async function deleteSession(name) {
    if (!confirm(`Delete the saved map "${name}" for everyone?`)) return;
    const r = await write("/api/sessions", "DELETE", { name });
    renderSessions(r.sessions);
    setStatus(`Deleted the saved map "${name}"`);
  }

  $("session-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const name = $("session-name").value.trim();
    if (!name) { setStatus("Enter a name for the map", true); return; }
    saveSession(name).catch(fail);
  });

  $("session-download").addEventListener("click", () => {
    const name = $("session-name").value.trim() || cy.nodes("[?root]").map((n) => n.id())[0] || "map";
    saveFile(new Blob([JSON.stringify(mapDocument(), null, 1)], { type: "application/json" }),
             `threatbridge-${name}.json`.replace(/[^\w.-]+/g, "_"));
    setStatus("Saved the map to a file");
  });

  $("session-file").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    e.target.value = "";
    if (!file) return;
    let doc = null;
    try { doc = JSON.parse(await file.text()); } catch (_) { /* reported below */ }
    openMap(doc, file.name).catch(fail);
  });

  // ---- bootstrap from URL (Security Onion action link) ----------------------
  (async function init() {
    try {
      cfg = await getJSON("/api/config");
      $("window").value = cfg.default_window;
      $("limit").value = cfg.default_limit;
      if (cfg.case) {
        $("ts").placeholder = "blank = end of data (inbound) / start (outbound)";
        $("range-from").placeholder = "blank = start of data";
        $("range-to").placeholder = "blank = end of data";
        setStatus(`Case: ${cfg.case.flows} flows between ${cfg.case.hosts} hosts, ` +
                  `${cfg.case.start} → ${cfg.case.end}`);
      }
    } catch (_) { /* keep HTML defaults */ }
    getJSON("/api/excludes").then(renderExcludes).catch(() => {});
    $("paths").hidden = !cfg.analysis;
    $("routes").hidden = !cfg.analysis;
    try { showShared(await getJSON("/api/compromised"), true); } catch (_) { /* none */ }
    setInterval(pollMarks, (cfg.marks_poll || 5) * 1000);
    getJSON("/api/sessions").then((r) => renderSessions(r.sessions)).catch(() => {});
    // The map a link names (rememberInUrl): its fields, and a choice only if it is one.
    const q = new URLSearchParams(location.search);
    const fields = { ip: "ip", ts: "ts", window: "window", range_from: "range-from", range_to: "range-to" };
    for (const [param, id] of Object.entries(fields)) if (q.get(param)) $(id).value = q.get(param);
    if (["in", "out"].includes(q.get("dir"))) $("direction").value = q.get("dir");
    if (["top", "bottom"].includes(q.get("order"))) $("order").value = q.get("order");
    if (q.get("ip")) start();
    else refreshPaths(true).catch((e) => fail(e));
  })();
})();
