/* ThreatBridge map UI. All data rendered via textContent; no HTML injection. */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const statusEl = $("status");
  const menu = $("menu");
  let iocTime = null; // anchor of the root (IOC) event; upper bound for SOC pivots
  const COLORS = { root: "#e5484d", in: "#3e9bff", out: "#f5a524", node: "#9aa7bd" };

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
      n = cy.add({ group: "nodes", data: Object.assign({ id: ip, anchor: anchor }, extra || {}) });
    }
    return n;
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
        const id = `${src}->${dst}`;
        const data = {
          id, source: src, target: dst, direction, count: p.count, ports: p.ports,
          first_seen: p.first_seen, last_seen: p.last_seen,
          logCount: Math.log10(p.count + 1),
          label: `${p.count}${p.ports.length ? " · " + p.ports.join(",") : ""}`,
        };
        const e = cy.getElementById(id);
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
    } catch (err) { setStatus(err.message, true); }
  }

  async function expandRoot(ip, ts, direction) {
    // Normalise IP/anchor server-side; the root anchor is the IOC time used for pivots.
    const params = new URLSearchParams({ ip });
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

  function nodeDetails(n) {
    showDetails([
      ["Host", n.id()], ["Anchor", n.data("anchor")], ["IOC root", n.data("root") ? "yes" : "no"],
      ["Hops from IOC", n.data("depth")],
      ["Inbound expanded", n.data("expandedIn") ? "yes" : "no"],
      ["Outbound expanded", n.data("expandedOut") ? "yes" : "no"],
      ["Degree", n.degree()],
    ]);
  }

  function edgeDetails(e) {
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
      { label: "Open host in SOC dashboard", action: () => openPivot(n.id(), null, null) },
      { label: "Remove from map", action: () => { if (!n.data("root")) { n.remove(); } } },
      { label: "Add to shared exclude list", action: () => addExclude(n.id()) },
    ]);
  });

  cy.on("tap", "node", (evt) => {
    nodeDetails(evt.target);
    expand(evt.target.id(), $("direction").value).catch((e) => setStatus(e.message, true));
  });
  cy.on("tap", "edge", (evt) => edgeDetails(evt.target));
  cy.on("tap", (evt) => { if (evt.target === cy) hideMenu(); });
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
  function renderExcludes(entries) {
    const ul = $("exclude-list");
    ul.replaceChildren();
    for (const entry of entries) {
      const li = document.createElement("li");
      const span = document.createElement("span"); span.textContent = entry;
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
    renderExcludes(r.entries);
    const n = cy.getElementById(entry);
    if (n.nonempty() && !n.data("root")) n.remove();
    setStatus(`Excluded ${entry} for everyone; re-expand hosts to apply CIDRs`);
  }

  async function removeExclude(entry) {
    const r = await getJSON("/api/excludes", { method: "DELETE", headers: WRITE_HEADERS,
                                              body: JSON.stringify({ entry }) });
    renderExcludes(r.entries);
    setStatus(`Removed ${entry} from exclude list`);
  }

  $("exclude-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const v = $("exclude-input").value.trim();
    if (!v) return;
    addExclude(v).then(() => { $("exclude-input").value = ""; })
      .catch((err) => setStatus(err.message, true));
  });

  // ---- bootstrap from URL (Security Onion action link) ----------------------
  (async function init() {
    try {
      const cfg = await getJSON("/api/config");
      $("window").value = cfg.default_window;
      $("limit").value = cfg.default_limit;
    } catch (_) { /* keep HTML defaults */ }
    getJSON("/api/excludes").then((r) => renderExcludes(r.entries)).catch(() => {});
    const q = new URLSearchParams(location.search);
    if (q.get("ip")) $("ip").value = q.get("ip");
    if (q.get("ts")) $("ts").value = q.get("ts");
    if (q.get("window")) $("window").value = q.get("window");
    const dir = q.get("dir") || q.get("direction");
    if (dir === "in" || dir === "out") $("direction").value = dir;
    const order = q.get("order");
    if (order === "top" || order === "bottom") $("order").value = order;
    if (q.get("ip")) start();
  })();
})();
