/* ThreatBridge map UI. All data rendered via textContent; no HTML injection. */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const statusEl = $("status");
  const menu = $("menu");
  let iocTime = null; // anchor of the root (IOC) event; upper bound for SOC pivots
  let cfg = {};       // /api/config
  let compromised = new Map(); // ip -> {time, note}
  const COLORS = { root: "#e5484d", in: "#3e9bff", out: "#f5a524", node: "#9aa7bd",
                   up: "#a78bfa", down: "#2dd4bf", attack: "#ff4d5e", compromised: "#b4232a" };

  const cy = cytoscape({
    container: $("cy"),
    wheelSensitivity: 0.3,
    maxZoom: 1.6,
    style: [
      { selector: "node", style: {
          "background-color": COLORS.node, label: "data(id)", color: "#d8dee9",
          "font-size": 10, "text-valign": "bottom", "text-margin-y": 4, width: 18, height: 18 } },
      { selector: "node[?root]", style: { "background-color": COLORS.root, width: 28, height: 28 } },
      { selector: "node[?expandedIn][?expandedOut]", style: { "border-width": 3, "border-color": "#fff" } },
      { selector: "node[?expandedIn], node[?expandedOut]", style: { "border-width": 2, "border-color": "#d8dee9" } },
      { selector: "edge", style: {
          width: "mapData(logCount, 0, 4, 1, 7)", "curve-style": "bezier",
          "target-arrow-shape": "triangle", "arrow-scale": 0.9, label: "data(label)",
          "font-size": 8, color: "#8a94a6", "text-rotation": "autorotate", "text-background-color": "#11151c",
          "text-background-opacity": 0.8, "text-background-padding": 1 } },
      { selector: "edge[direction = 'in']", style: { "line-color": COLORS.in, "target-arrow-color": COLORS.in } },
      { selector: "edge[direction = 'out']", style: { "line-color": COLORS.out, "target-arrow-color": COLORS.out } },
      { selector: "node[?compromised]", style: {
          "background-color": COLORS.compromised, "border-width": 3, "border-color": "#ff8a8a" } },
      // Attack paths between compromised hosts, and the threat line through a clicked edge.
      { selector: "edge.attack", style: {
          "line-color": COLORS.attack, "target-arrow-color": COLORS.attack, width: 6, "z-index": 10 } },
      { selector: "edge.up", style: {
          "line-color": COLORS.up, "target-arrow-color": COLORS.up, width: 5, "z-index": 11 } },
      { selector: "edge.down", style: {
          "line-color": COLORS.down, "target-arrow-color": COLORS.down, width: 5, "z-index": 11 } },
      { selector: "edge.line-selected", style: {
          "line-color": "#ffffff", "target-arrow-color": "#ffffff", width: 6, "z-index": 12 } },
      { selector: "node.up", style: { "border-width": 4, "border-color": COLORS.up } },
      { selector: "node.down", style: { "border-width": 4, "border-color": COLORS.down } },
      { selector: ".faded", style: { opacity: 0.15 } },
      { selector: ":selected", style: { "overlay-color": "#fff", "overlay-opacity": 0.15 } },
    ],
  });

  // Cytoscape caches the container's position; keep it in sync when the page reflows.
  new ResizeObserver(() => cy.resize()).observe($("cy"));
  window.addEventListener("scroll", () => cy.resize(), { passive: true });
  window.threatbridge = { cy }; // handle for debugging / UI tests

  function setStatus(msg, isError, isWarn) {
    statusEl.textContent = msg || "";
    statusEl.classList.toggle("error", !!isError);
    statusEl.classList.toggle("warn", !!isWarn && !isError);
  }

  async function getJSON(url, opts) {
    const r = await fetch(url, Object.assign({ credentials: "same-origin" }, opts || {}));
    let body = null;
    try { body = await r.json(); } catch (_) { /* non-JSON error */ }
    if (!r.ok) throw new Error((body && body.error) || `HTTP ${r.status}`);
    return body;
  }

  // Tree by hop distance from the IOC host (top row), each host's peers placed under it.
  function relayout() {
    const root = cy.nodes("[?root]");
    cy.layout({
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

  function edgeData(src, dst, direction, count, ports, first, last) {
    return {
      id: `${src}->${dst}`, source: src, target: dst, direction, count, ports,
      first_seen: first, last_seen: last, logCount: Math.log10(count + 1),
      label: `${count}${ports.length ? " · " + ports.join(",") : ""}`,
    };
  }

  // Add an edge unless the map already shows it (keep the data from the expansion).
  function mergeEdge(src, dst, direction, count, ports, first, last) {
    const e = cy.getElementById(`${src}->${dst}`);
    if (e.nonempty()) return e;
    return cy.add({ group: "edges", data: edgeData(src, dst, direction, count, ports, first, last) });
  }

  function clearHighlight() {
    cy.elements().removeClass("up down line-selected faded");
  }

  function focus(elements) {
    clearHighlight();
    cy.elements().not(elements).addClass("faded");
  }

  // direction "in": peer -> host, anchored in the past; "out": host -> peer, anchored in the future.
  async function expand(ip, direction) {
    const node = cy.getElementById(ip);
    const anchor = node.nonempty() ? node.data("anchor") : $("ts").value.trim();
    const params = new URLSearchParams({
      ip, direction, window: $("window").value.trim(), limit: $("limit").value.trim(),
      order: $("order").value,
    });
    if (anchor) params.set("ts", anchor);
    setStatus(`Querying ${direction === "in" ? "inbound (past)" : "outbound (future)"} for ${ip}…`);
    const res = await getJSON(`/api/neighbors?${params}`);

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
        const data = edgeData(src, dst, direction, p.count, p.ports, p.first_seen, p.last_seen);
        const e = cy.getElementById(data.id);
        if (e.nonempty()) e.data(data); else cy.add({ group: "edges", data });
      }
    });
    relayout();
    const which = res.order === "top" ? "top" : "rarest";
    let msg = `${res.ip}: showing ${which} ${res.peers.length}`;
    if (res.distinct_peers != null) msg += ` of ${res.distinct_peers} distinct peer(s)`;
    msg += `, ${res.start} → ${res.end}`;
    if (res.truncated) msg += " — WARNING: scan hit the peer cap; rarest list may be incomplete";
    setStatus(msg, false, res.truncated);
    return res;
  }

  async function start() {
    const ip = $("ip").value.trim();
    if (!ip) { setStatus("Enter an IP address", true); return; }
    cy.elements().remove();
    const ts = $("ts").value.trim();
    try {
      const res = await expandRoot(ip, ts, $("direction").value);
      const q = new URLSearchParams({ ip: res.ip, ts: iocTime, dir: $("direction").value,
                                      window: $("window").value.trim(), order: $("order").value });
      history.replaceState(null, "", `?${q}`);
      await refreshPaths(true);
    } catch (err) { setStatus(err.message, true); }
  }

  async function expandRoot(ip, ts, direction) {
    // Normalise IP/anchor server-side; the root anchor is the IOC time used for pivots.
    const params = new URLSearchParams({ ip, direction });
    if (ts) params.set("ts", ts);
    const r = await getJSON(`/api/resolve?${params}`);
    iocTime = r.anchor;
    addNode(r.ip, r.anchor, { root: true, depth: 0 });
    return expand(r.ip, direction);
  }

  function showDetails(rows) {
    const body = $("detail-body");
    body.replaceChildren();
    const dl = document.createElement("dl");
    for (const [k, v] of rows) {
      const dt = document.createElement("dt"); dt.textContent = k;
      const dd = document.createElement("dd"); dd.textContent = v == null ? "—" : String(v);
      dl.append(dt, dd);
    }
    body.append(dl);
  }

  let detailsFor = null; // host shown in the details panel

  function refreshDetails(ip) {
    const n = cy.getElementById(ip);
    if (detailsFor === ip && n.nonempty()) nodeDetails(n);
  }

  function nodeDetails(n) {
    detailsFor = n.id();
    showDetails([
      ["Host", n.id()], ["Anchor", n.data("anchor")], ["IOC root", n.data("root") ? "yes" : "no"],
      ["Compromised", compromised.has(n.id())
        ? (compromised.get(n.id()).time || "yes, time unknown") : "no"],
      ["Hops from IOC", n.data("depth")],
      ["Inbound expanded", n.data("expandedIn") ? "yes" : "no"],
      ["Outbound expanded", n.data("expandedOut") ? "yes" : "no"],
      ["Degree", n.degree()],
    ]);
  }

  function edgeDetails(e) {
    detailsFor = null;
    showDetails([
      ["Source", e.data("source")], ["Destination", e.data("target")],
      ["Direction", e.data("direction") === "in" ? "inbound (past)" : "outbound (future)"],
      ["Connections", e.data("count")], ["Top dst ports", (e.data("ports") || []).join(", ")],
      ["First seen", e.data("first_seen")], ["Last seen", e.data("last_seen")],
    ]);
  }

  // ---- context menu -------------------------------------------------------
  function hideMenu() { menu.hidden = true; menu.replaceChildren(); }

  function showMenu(x, y, items) {
    menu.replaceChildren();
    for (const it of items) {
      const li = document.createElement("li");
      if (it === "-") { li.className = "sep"; }
      else if (it.title) { li.className = "title"; li.textContent = it.title; }
      else {
        li.textContent = it.label;
        li.addEventListener("click", () => { hideMenu(); Promise.resolve(it.action()).catch((e) => setStatus(e.message, true)); });
      }
      menu.append(li);
    }
    menu.hidden = false;
    const r = menu.getBoundingClientRect();
    menu.style.left = `${Math.min(x, window.innerWidth - r.width - 4)}px`;
    menu.style.top = `${Math.min(y, window.innerHeight - r.height - 4)}px`;
  }

  async function pivot(a, b, until) {
    const params = new URLSearchParams({ a });
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
    if (cfg.soc_pivots === false) return;
    showMenu(oe.clientX, oe.clientY, [
      { title: `${a} ↔ ${b}` },
      { label: `Filter SOC Dashboards: all conversations up to IOC time`, action: () => openPivot(a, b, until) },
      { label: "Copy SOC query", action: () => copyPivot(a, b, until) },
    ]);
  });

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
      { label: "Remove from map", action: () => { if (!n.data("root")) { n.remove(); } } },
      { label: "Add to shared exclude list", action: () => addExclude(n.id()) },
    ]);
  });

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
    expand(evt.target.id(), $("direction").value).catch((e) => setStatus(e.message, true));
  });
  cy.on("tap", "edge", (evt) => {
    edgeDetails(evt.target);
    if (cfg.analysis) showThreatLine(evt.target).catch((e) => setStatus(e.message, true));
  });
  cy.on("tap", (evt) => { if (evt.target === cy) { hideMenu(); clearHighlight(); } });
  cy.on("cxttap", (evt) => { if (evt.target === cy) hideMenu(); });
  document.addEventListener("click", (e) => { if (!menu.contains(e.target)) hideMenu(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") hideMenu(); });
  $("cy").addEventListener("contextmenu", (e) => e.preventDefault());

  $("go").addEventListener("click", start);
  $("fit").addEventListener("click", () => cy.fit(undefined, 40));
  $("clear").addEventListener("click", () => { cy.elements().remove(); iocTime = null; setStatus(""); });
  for (const id of ["ip", "ts", "window", "limit"]) {
    $(id).addEventListener("keydown", (e) => { if (e.key === "Enter") start(); });
  }

  // ---- shared exclude list -------------------------------------------------
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
    const ul = $("exclude-list");
    ul.replaceChildren();
    for (const entry of r.entries) {
      const li = document.createElement("li");
      const span = document.createElement("span"); span.textContent = entry;
      const resolved = (r.resolved || {})[entry];
      if (resolved) {
        const small = document.createElement("small");
        small.className = "resolved";
        small.textContent = resolutionText(resolved);
        span.append(small);
      }
      const btn = document.createElement("button"); btn.type = "button"; btn.textContent = "Remove";
      btn.addEventListener("click", () => removeExclude(entry).catch((e) => setStatus(e.message, true)));
      li.append(span, btn);
      ul.append(li);
    }
  }

  const WRITE_HEADERS = { "Content-Type": "application/json", "X-ThreatBridge": "1" };

  async function addExclude(entry) {
    const r = await getJSON("/api/excludes", { method: "POST", headers: WRITE_HEADERS,
                                              body: JSON.stringify({ entry }) });
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
    await refreshPaths(true);
  }

  async function removeExclude(entry) {
    const r = await getJSON("/api/excludes", { method: "DELETE", headers: WRITE_HEADERS,
                                              body: JSON.stringify({ entry }) });
    renderExcludes(r);
    setStatus(`Removed ${entry} from exclude list`);
    await refreshPaths(true);
  }

  $("exclude-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const v = $("exclude-input").value.trim();
    if (!v) return;
    addExclude(v).then(() => { $("exclude-input").value = ""; })
      .catch((err) => setStatus(err.message, true));
  });

  // ---- threat line through a clicked edge (PCAP/NetFlow cases) ---------------
  // Earlier hosts that could have led to the edge's source, and later hosts its target
  // could have reached, following time order with at most `window` between hops.
  async function showThreatLine(e) {
    const [a, b] = [e.data("source"), e.data("target")];
    const params = new URLSearchParams({ a, b, from: e.data("first_seen"),
                                         to: e.data("last_seen"), window: $("window").value.trim() });
    setStatus(`Tracing the threat line through ${a} → ${b}…`);
    const r = await getJSON(`/api/threatline?${params}`);
    let line = cy.collection();
    cy.batch(() => {
      for (const n of r.nodes) line = line.union(addNode(n.id, n.time, {}));
      for (const ed of r.edges) {
        const el = mergeEdge(ed.source, ed.target, ed.role === "up" ? "in" : "out",
                             ed.count, ed.ports, ed.first_seen, ed.last_seen);
        line = line.union(el);
      }
    });
    relayout();
    focus(line);
    cy.batch(() => {
      for (const n of r.nodes) {
        if (n.role === "up" || n.role === "both") cy.getElementById(n.id).addClass("up");
        if (n.role === "down" || n.role === "both") cy.getElementById(n.id).addClass("down");
      }
      for (const ed of r.edges) {
        cy.getElementById(`${ed.source}->${ed.target}`)
          .addClass(ed.role === "selected" ? "line-selected" : ed.role);
      }
    });
    const up = r.nodes.filter((n) => n.role === "up" || n.role === "both").length;
    const down = r.nodes.filter((n) => n.role === "down" || n.role === "both").length;
    let msg = `Threat line through ${a} → ${b}: ${up} earlier host(s) (violet), ` +
              `${down} later host(s) (teal); ≤ ${cfg.threat_hops} hops, ≤ ${$("window").value.trim()} ` +
              "between hops. Click the background to clear.";
    if (r.truncated) msg += " WARNING: stopped at the host limit; the line is incomplete.";
    setStatus(msg, false, r.truncated);
  }

  // ---- compromised hosts and the attack paths between them ------------------
  function renderCompromised(hosts) {
    compromised = new Map(hosts.map((h) => [h.ip, h]));
    cy.nodes().forEach((n) => { n.data("compromised", compromised.has(n.id())); });
    const ul = $("compromised-list");
    ul.replaceChildren();
    for (const h of hosts) {
      const li = document.createElement("li");
      const span = document.createElement("span");
      span.textContent = `${h.ip} @ ${h.time || "time unknown"}`;
      const btn = document.createElement("button"); btn.type = "button"; btn.textContent = "Remove";
      btn.addEventListener("click", () => unmarkCompromised(h.ip).catch((e) => setStatus(e.message, true)));
      li.append(span, btn);
      ul.append(li);
    }
  }

  async function markCompromised(ip, time) {
    const r = await getJSON("/api/compromised", { method: "POST", headers: WRITE_HEADERS,
                                                 body: JSON.stringify({ ip, time }) });
    renderCompromised(r.hosts);
    refreshDetails(ip);
    setStatus(`Marked ${ip} compromised${time ? " at " + time : " (time unknown)"}`);
    await refreshPaths();
  }

  async function unmarkCompromised(ip) {
    const r = await getJSON("/api/compromised", { method: "DELETE", headers: WRITE_HEADERS,
                                                 body: JSON.stringify({ ip }) });
    renderCompromised(r.hosts);
    refreshDetails(ip);
    setStatus(`Unmarked ${ip}`);
    await refreshPaths();
  }

  $("compromised-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const ip = $("compromised-ip").value.trim();
    if (!ip) return;
    markCompromised(ip, $("compromised-time").value.trim())
      .then(() => { $("compromised-ip").value = ""; $("compromised-time").value = ""; })
      .catch((err) => setStatus(err.message, true));
  });

  function pathElements(p) {
    let els = cy.collection();
    for (const h of p.hops) {
      els = els.union(cy.getElementById(h.source)).union(cy.getElementById(h.target))
        .union(cy.getElementById(`${h.source}->${h.target}`));
    }
    return els;
  }

  // Re-run after every change to compromised hosts or excludes; draws the paths in red.
  async function refreshPaths(quiet) {
    if (!cfg.analysis) return;
    const params = new URLSearchParams({ window: $("window").value.trim() });
    const r = await getJSON(`/api/paths?${params}`);
    cy.batch(() => {
      cy.edges().removeClass("attack");
      for (const p of r.paths) {
        for (const h of p.hops) {
          addNode(h.source, h.start, {});
          addNode(h.target, h.start, {});
          const ports = h.proto === "tcp" || h.proto === "udp" ? [h.dport] : [];
          mergeEdge(h.source, h.target, "out", 1, ports, h.start, h.start).addClass("attack");
        }
      }
    });
    if (r.paths.length) relayout();
    const ul = $("path-list");
    ul.replaceChildren();
    for (const p of r.paths) {
      const li = document.createElement("li");
      const hosts = [p.hops[0].source, ...p.hops.map((h) => h.target)];
      li.textContent = `${hosts.join(" → ")} (${p.hops[0].start} → ${p.hops[p.hops.length - 1].start})`;
      li.className = "path";
      li.addEventListener("click", () => {
        focus(pathElements(p));
        setStatus(`Attack path ${p.from} → ${p.to}, ${p.hops.length} hop(s). Click the background to clear.`);
      });
      ul.append(li);
    }
    if (!r.paths.length) {
      const li = document.createElement("li");
      li.className = "hint";
      li.textContent = compromised.size < 2 ? "Mark at least two hosts as compromised."
                                            : "No time-consistent path between the marked hosts.";
      ul.append(li);
    }
    if (!quiet) setStatus(`${r.paths.length} attack path(s) between ${compromised.size} compromised host(s)`);
  }

  // ---- bootstrap from URL (Security Onion action link) ----------------------
  (async function init() {
    try {
      cfg = await getJSON("/api/config");
      $("window").value = cfg.default_window;
      $("limit").value = cfg.default_limit;
      if (cfg.case) {
        $("ts").placeholder = "blank = end of data (inbound) / start (outbound)";
        setStatus(`Case: ${cfg.case.flows} flows between ${cfg.case.hosts} hosts, ` +
                  `${cfg.case.start} → ${cfg.case.end}`);
      }
    } catch (_) { /* keep HTML defaults */ }
    getJSON("/api/excludes").then(renderExcludes).catch(() => {});
    $("paths").hidden = !cfg.analysis;
    try { renderCompromised((await getJSON("/api/compromised")).hosts); } catch (_) { /* none */ }
    const q = new URLSearchParams(location.search);
    if (q.get("ip")) $("ip").value = q.get("ip");
    if (q.get("ts")) $("ts").value = q.get("ts");
    if (q.get("window")) $("window").value = q.get("window");
    const dir = q.get("dir") || q.get("direction");
    if (dir === "in" || dir === "out") $("direction").value = dir;
    const order = q.get("order");
    if (order === "top" || order === "bottom") $("order").value = order;
    if (q.get("ip")) start();
    else refreshPaths(true).catch((e) => setStatus(e.message, true));
  })();
})();
