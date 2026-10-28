// Headless browser test of the map's actions in post-mortem mode, beyond ui_case.mjs:
// opening without parameters, errors, slow writes kept in order, left-click expansion, the
// details panel, the layout, the host menu and how menus close, connections without a menu,
// the compromised form, attack paths answered out of order, CIDRs, "Show all" paths, paging a
// connection's flows, time-chained hops, the time range from the URL, a slow request cancelled,
// threat lines, saved maps (shared and as a file), clicks after a resize or scroll, Fit, Clear.
//   python tests/make_case.py DIR
//   TB_MAX_PATHS=11 python -m threatbridge --case DIR --port 5056
//   TB_URL=http://127.0.0.1:5056 node tests/ui_actions.mjs [screenshot-dir]
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { checkpoint, finish, launch } from "./ui_helpers.mjs";

const BASE = process.env.TB_URL || "http://127.0.0.1:5056";
const SHOTS = process.argv[2];
// The errors this test provokes on purpose (HTTP 400, 409 and 502, an aborted request) are expected.
const { browser, ctx, page, errors, at } = await launch({ expected: /status of (400|409|502)|ERR_FAILED/ });

const cyEval = (fn, arg) => page.evaluate(fn, arg);
const ids = () => cyEval(() => window.threatbridge.cy.nodes().map((n) => n.id()).sort());
const node = (ip) => `node[id = "${ip}"]`;
const edge = (a, b) => `edge[id = "${a}->${b}"]`;
const menu = async (selector, item) => {
  const p = await at(selector);
  await page.mouse.click(p.x, p.y, { button: "right" });
  await page.locator("#menu li", { hasText: item }).first().click();
};
const menuItems = () => page.$$eval("#menu li", (l) => l.map((x) => x.textContent));
const menuHidden = () => page.locator("#menu").isHidden();
const status = () => page.textContent("#status");
const statusIs = (cls) => page.$eval("#status", (s, c) => s.classList.contains(c), cls);
const waitStatus = (re) => page.waitForFunction(
  (src) => new RegExp(src).test(document.getElementById("status").textContent), re.source);
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
const map = async (ip, direction = "in") => {
  await page.fill("#ip", ip);
  await page.selectOption("#direction", direction);
  await page.click("#go");
  await waitStatus(new RegExp(`^${esc(ip)}: showing`));
};
const rows = () => page.$$eval("#detail-body dl > *", (l) => l.map((x) => x.textContent));
const anchor = (ip) => cyEval((i) => window.threatbridge.cy.getElementById(i).data("anchor"), ip);
const pager = () => page.textContent("#flows .pager span");
const shot = (name) => SHOTS && page.screenshot({ path: `${SHOTS}/${name}.png` });
// What another analyst sees in a list on opening the map: the shared lists are the server's.
const othersSee = async (selector) => {
  const other = await ctx.newPage();
  await other.goto(BASE);
  await other.waitForSelector(selector);
  const seen = await other.$$eval(selector, (l) => l.map((x) => x.firstChild.textContent));
  await other.close();
  return seen;
};
const ROUTE_FIELDS = ["route-src", "route-src-time", "route-dst", "route-dst-time"];
const clearRouteFields = async () => { for (const id of ROUTE_FIELDS) await page.fill(`#${id}`, ""); };

try {
  // Start clean: no hosts marked compromised, entries excluded or maps saved by an earlier
  // test on this server.
  await page.goto(BASE);
  await page.evaluate(async () => {
    const headers = { "Content-Type": "application/json", "X-ThreatBridge": "1" };
    const { hosts } = await (await fetch("/api/compromised")).json();
    for (const h of hosts) {
      await fetch("/api/compromised", { method: "DELETE", body: JSON.stringify({ ip: h.ip }), headers });
    }
    const { entries } = await (await fetch("/api/excludes")).json();
    for (const entry of entries) {
      await fetch("/api/excludes", { method: "DELETE", body: JSON.stringify({ entry }), headers });
    }
    const { sessions } = await (await fetch("/api/sessions")).json();
    for (const s of sessions) {
      await fetch("/api/sessions", { method: "DELETE", body: JSON.stringify({ name: s.name }), headers });
    }
  });

  // 1. Opened without parameters: the case summary, an empty map, the paths hint, and the
  //    placeholders of a case (the default anchor and range are those of the data).
  await page.goto(BASE);
  await waitStatus(/^Case: \d+ flows between \d+ hosts, 2024-/);
  assert.deepEqual(await ids(), []);
  await page.waitForSelector("#path-list li.hint");
  assert.equal(await page.textContent("#path-list li.hint"), "Mark at least two hosts as compromised.");
  await page.waitForSelector("#session-list li.hint");
  assert.equal(await page.textContent("#session-list li.hint"), "No saved maps yet.");
  assert.equal(await page.getAttribute("#ts", "placeholder"), "blank = end of data (inbound) / start (outbound)");
  assert.equal(await page.getAttribute("#range-from", "placeholder"), "blank = start of data");
  assert.equal(await page.getAttribute("#range-to", "placeholder"), "blank = end of data");

  // 2. Errors reach the status line, marked as errors.
  await page.fill("#ip", "not-an-ip");
  await page.click("#go");
  await waitStatus(/invalid IP address/);
  assert.equal(await status(), "invalid IP address: 'not-an-ip'");
  assert.ok(await statusIs("error"));
  await page.fill("#exclude-input", "not valid!");
  await page.press("#exclude-input", "Enter");
  await waitStatus(/invalid IP, CIDR or domain name/);
  await page.fill("#exclude-input", "");

  // 2b. Writes to a shared list go one at a time, and what the analyst types while one is
  // on its way is kept. Another analyst sees the list.
  const sent = [];
  await page.route("**/api/excludes", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const { entry } = JSON.parse(route.request().postData());
    sent.push(`> ${entry}`);
    if (entry === "192.0.2.30") await sleep(1000);
    const response = await route.fetch();
    sent.push(`< ${entry}`);
    return route.fulfill({ response });
  });
  await page.fill("#exclude-input", "192.0.2.30");
  await page.press("#exclude-input", "Enter");
  await page.fill("#exclude-input", "192.0.2.31");
  await page.press("#exclude-input", "Enter");               // while the first is on its way
  await page.fill("#exclude-input", "192.0.2.32");           // typed, not added yet
  await page.waitForSelector("#exclude-list li >> text=192.0.2.31");
  assert.deepEqual(sent, ["> 192.0.2.30", "< 192.0.2.30", "> 192.0.2.31", "< 192.0.2.31"]);
  assert.deepEqual(await page.$$eval("#exclude-list li span", (s) => s.map((x) => x.textContent)),
                   ["192.0.2.30", "192.0.2.31"]);
  assert.equal(await page.inputValue("#exclude-input"), "192.0.2.32");
  await page.unroute("**/api/excludes");
  assert.deepEqual(await othersSee("#exclude-list li span"), ["192.0.2.30", "192.0.2.31"]);
  for (const entry of ["192.0.2.30", "192.0.2.31"]) {
    await page.click(`#exclude-list li:has-text('${entry}') button`);
  }
  await page.waitForSelector("#exclude-list li", { state: "detached" });
  await page.fill("#exclude-input", "");

  // 3. Left-click a host: it expands in the selected direction.
  await map("10.0.0.9", "in");
  assert.deepEqual(await ids(), ["10.0.0.5", "10.0.0.77", "10.0.0.9"]);
  const p5 = await at(node("10.0.0.5"));
  await page.mouse.click(p5.x, p5.y);
  await page.waitForFunction(() => window.threatbridge.cy.getElementById("203.0.113.66").nonempty());
  assert.equal(await page.textContent("#detail-body dd"), "10.0.0.5");
  assert.ok(await cyEval(() => window.threatbridge.cy.getElementById("10.0.0.5").data("expandedIn")));
  const border = (ip) => cyEval((id) => {
    const n = window.threatbridge.cy.getElementById(id);
    return `${n.style("border-width")} ${n.style("border-color")}`;
  }, ip);
  assert.equal(await border("10.0.0.5"), "2px rgb(216,222,233)");   // expanded one way
  // Each connection is labelled with its count and destination ports.
  assert.deepEqual(await cyEval(() => window.threatbridge.cy.edges().map((e) => `${e.id()} ${e.data("label")}`).sort()), [
    "10.0.0.5->10.0.0.9 1 · 445", "10.0.0.77->10.0.0.9 1 · 80", "203.0.113.66->10.0.0.5 1 · 443"]);
  // The tree: the IOC host on top, each hop a row further down.
  const y = (ip) => cyEval((i) => window.threatbridge.cy.getElementById(i).position("y"), ip);
  const [y9, y5, y77, y66] = [await y("10.0.0.9"), await y("10.0.0.5"), await y("10.0.0.77"), await y("203.0.113.66")];
  assert.ok(y9 < y5 && y5 === y77 && y77 < y66, JSON.stringify([y9, y5, y77, y66]));
  // The details panel: right-click shows a host's without expanding it.
  let q = await at(node("10.0.0.5"));
  await page.mouse.click(q.x, q.y, { button: "right" });
  assert.deepEqual(await rows(), ["Host", "10.0.0.5", "Anchor", "2024-05-01T12:10:00.000Z", "IOC root", "no",
    "Compromised", "no", "Hops from IOC", "1", "Inbound expanded", "yes", "Outbound expanded", "no", "Degree", "2"]);
  await page.keyboard.press("Escape");
  q = await at(node("10.0.0.9"));
  await page.mouse.click(q.x, q.y, { button: "right" });
  assert.deepEqual(await rows(), ["Host", "10.0.0.9", "Anchor", "2024-05-01T13:09:50.001Z", "IOC root", "yes",
    "Compromised", "no", "Hops from IOC", "0", "Inbound expanded", "yes", "Outbound expanded", "no", "Degree", "2"]);
  await page.keyboard.press("Escape");

  // 3b. Right-clicking a connection of a case shows its details and flows, and no menu (no SOC
  //     pivots for case files) but, when it holds a single flow, marking it compromised. The
  //     flows shown are those of the connection clicked last.
  await page.route("**/api/flows?*", async (route) => {
    if (route.request().url().includes("src=10.0.0.5")) await sleep(1000);
    await route.continue().catch(() => {});
  });
  for (const id of ["10.0.0.5->10.0.0.9", "10.0.0.77->10.0.0.9"]) {
    const e = await at(`edge[id = "${id}"]`, "edge");
    await page.keyboard.press("Escape");                    // the last menu might cover it
    await page.mouse.click(e.x, e.y, { button: "right" });
  }
  assert.deepEqual(await menuItems(), ["10.0.0.77 ↔ 10.0.0.9", "Mark compromised"]);
  await page.keyboard.press("Escape");
  assert.deepEqual(await rows(), ["Source", "10.0.0.77", "Destination", "10.0.0.9", "Direction", "inbound (past)",
    "Connections", "1", "Top dst ports", "80", "Protocols", "HTTP", "First seen", "2024-05-01T12:30:00.000Z",
    "Last seen", "2024-05-01T12:30:00.000Z"]);
  await sleep(1300);                                        // the first connection's flows arrive late
  assert.deepEqual(await page.$$eval("#flows ol.flows li", (l) => l.map((x) => x.firstChild.textContent)),
                   ["2024-05-01T12:30:00.000Z"]);
  await page.unroute("**/api/flows?*");

  // 3c. The host menu of a case: no SOC pivot, paths instead. It opens at the pointer, closes
  //     on Escape, on a click elsewhere and on the map's background, stays inside the window,
  //     and the browser's own menu never opens over the map.
  const openMenu = async (ip) => {
    const p = await at(node(ip));
    await page.mouse.click(p.x, p.y, { button: "right" });
    return p;
  };
  const m5 = await openMenu("10.0.0.5");
  assert.deepEqual(await menuItems(), ["10.0.0.5 @ 2024-05-01T12:10:00.000Z",
    "Expand inbound: who connected to it (past)", "Expand outbound: who it connected to (future)", "",
    "Mark compromised at 2024-05-01T12:10:00.000Z", "Mark compromised (time unknown)",
    "Find paths from this host…", "Find paths to this host…", "Remove from map", "Add to shared exclude list"]);
  const box = await page.locator("#menu").boundingBox();
  assert.ok(Math.abs(box.x - m5.x) < 1 && Math.abs(box.y - m5.y) < 1, JSON.stringify([box, m5]));
  await page.keyboard.press("Escape");
  assert.ok(await menuHidden());
  await openMenu("10.0.0.5");
  await page.click("#details h2");                          // elsewhere on the page
  assert.ok(await menuHidden());
  const cyBox = await page.locator("#cy").boundingBox();
  await openMenu("10.0.0.5");
  await page.mouse.click(cyBox.x + 5, cyBox.y + 5);          // the map's background
  assert.ok(await menuHidden());
  await openMenu("10.0.0.5");
  await page.mouse.click(cyBox.x + 5, cyBox.y + 5, { button: "right" });
  assert.ok(await menuHidden());
  await cyEval(() => {                                       // the host near the bottom-right corner
    const cy = window.threatbridge.cy, p = cy.getElementById("10.0.0.5").renderedPosition();
    cy.panBy({ x: cy.width() - 4 - p.x, y: cy.height() - 4 - p.y });
  });
  await openMenu("10.0.0.5");
  const corner = await page.locator("#menu").boundingBox();
  const viewport = page.viewportSize();
  assert.ok(corner.x + corner.width <= viewport.width && corner.y + corner.height <= viewport.height,
            JSON.stringify(corner));
  await page.keyboard.press("Escape");
  await page.click("#fit");
  assert.equal(await page.evaluate(() => document.getElementById("cy").dispatchEvent(
    new MouseEvent("contextmenu", { bubbles: true, cancelable: true }))), false);

  // 4. The host menu: expand both ways, remove, exclude, mark and unmark.
  await menu(node("10.0.0.9"), "Expand outbound");
  await waitStatus(/^10\.0\.0\.9: showing top 0 of 0 distinct peer/);
  assert.equal(await border("10.0.0.9"), "3px rgb(255,255,255)");   // both ways
  await menu(node("10.0.0.9"), "Expand inbound");
  await waitStatus(/^10\.0\.0\.9: showing top 2 of 2 distinct peer/);
  await menu(node("10.0.0.77"), "Remove from map");
  assert.ok(!(await ids()).includes("10.0.0.77"));
  await menu(node("10.0.0.9"), "Remove from map");                  // the IOC host stays
  assert.ok((await ids()).includes("10.0.0.9"));
  await menu(node("203.0.113.66"), "Add to shared exclude list");
  await page.waitForSelector("#exclude-list li >> text=203.0.113.66");
  assert.equal(await status(), "Excluded 203.0.113.66 for everyone; re-expand hosts to apply CIDRs");
  assert.ok(!(await ids()).includes("203.0.113.66"));
  await page.click("#exclude-list li:has-text('203.0.113.66') button");
  await waitStatus(/^Removed 203\.0\.113\.66 from exclude list$/);
  await page.waitForSelector("#exclude-list li", { state: "detached" });
  await menu(node("10.0.0.9"), "Add to shared exclude list");       // the IOC host stays on the map
  await page.waitForSelector("#exclude-list li >> text=10.0.0.9");
  assert.ok((await ids()).includes("10.0.0.9"));
  await page.click("#exclude-list li:has-text('10.0.0.9') button");
  await page.waitForSelector("#exclude-list li", { state: "detached" });
  await menu(node("10.0.0.5"), "Mark compromised (time unknown)");
  await page.waitForSelector("#compromised-list li >> text=10.0.0.5 @ time unknown");
  await menu(node("10.0.0.5"), "Unmark compromised");
  await page.waitForSelector("#compromised-list li", { state: "detached" });
  await waitStatus(/^0 attack path\(s\) between 0 compromised host\(s\)$/);

  // 5. "Find paths from this host" with no destination yet: asks for one. A compromised
  //    host's time becomes its IOC time.
  await clearRouteFields();
  await menu(node("10.0.0.9"), "Find paths from this host");
  assert.equal(await page.inputValue("#route-src"), "10.0.0.9");
  assert.equal(await status(), "Now enter the host to find paths to (side panel)");
  assert.equal(await page.evaluate(() => document.activeElement.id), "route-dst");
  await menu(node("10.0.0.5"), "Mark compromised at");
  await waitStatus(/^0 attack path\(s\) between 1 compromised host\(s\)$/);
  await clearRouteFields();
  await menu(node("10.0.0.5"), "Find paths to this host");
  assert.equal(await page.inputValue("#route-dst"), "10.0.0.5");
  assert.equal(await page.inputValue("#route-dst-time"), "2024-05-01T12:10:00.000Z");
  assert.equal(await status(), "Now enter the host to find paths from (side panel)");
  await menu(node("10.0.0.5"), "Unmark compromised");
  await page.waitForSelector("#compromised-list li", { state: "detached" });
  await waitStatus(/^0 attack path\(s\) between 0 compromised host\(s\)$/);
  await clearRouteFields();

  // 6. The compromised form, with a time; more paths than the preview; "Show all" to the cap.
  await page.fill("#compromised-ip", "nope");
  await page.click("#compromised-form button");
  await waitStatus(/invalid IP address: 'nope'/);
  await page.fill("#compromised-ip", "10.0.2.1");
  await page.click("#compromised-form button");
  await page.waitForSelector("#compromised-list li >> text=10.0.2.1 @ time unknown");
  await page.fill("#compromised-ip", "10.0.2.2");
  await page.fill("#compromised-time", "2024-05-01T12:00:00Z");      // before any path reaches it
  await page.click("#compromised-form button");
  await page.waitForSelector("#path-list li.hint >> text=No time-consistent path between the marked hosts.");
  await waitStatus(/^0 attack path\(s\) between 2 compromised host\(s\)$/);
  await page.fill("#compromised-ip", "10.0.2.2");
  await page.fill("#compromised-time", "2024-05-01T13:00:00Z");
  await page.click("#compromised-form button");
  await page.waitForSelector("#compromised-list li >> text=10.0.2.2 @ 2024-05-01T13:00:00.000Z");
  assert.equal(await page.inputValue("#compromised-ip"), "");
  assert.equal(await page.inputValue("#compromised-time"), "");
  await page.waitForSelector("#path-list li.pair button");
  await waitStatus(/^10\+ attack path\(s\) between 2 compromised host\(s\)$/);
  assert.equal(await page.textContent("#path-list li.pair span"), "10.0.2.1 → 10.0.2.2: first 10 paths");
  assert.equal(await page.$$eval("#path-list li.path", (l) => l.length), 10);
  assert.ok((await ids()).includes("10.0.2.2") && (await ids()).includes("10.0.2.10"), "paths add their hosts");
  assert.deepEqual(await othersSee("#compromised-list li span"),
                   ["10.0.2.1 @ time unknown", "10.0.2.2 @ 2024-05-01T13:00:00.000Z"]);
  // Attack paths answered out of order: an earlier answer that arrives last is ignored.
  const attackDrawn = () => cyEval(() => window.threatbridge.cy.edges(".attack").nonempty());
  let held = null;
  const holding = new Promise((seen) => page.route("**/api/paths?*", (route) => {
    if (held) return route.continue();
    held = route;                                            // answered below, after the next one
    return seen();
  }));
  await page.fill("#ip", "10.0.2.1");
  await page.selectOption("#direction", "out");
  await page.click("#go");                                   // its paths are held back
  await holding;
  await page.click("#go");                                   // its paths are answered
  await page.waitForFunction(() => window.threatbridge.cy.edges(".attack").nonempty());
  await held.fulfill({ json: { pairs: [] } });
  await page.waitForTimeout(300);
  await page.unroute("**/api/paths?*");
  assert.equal(await page.textContent("#path-list li.pair span"), "10.0.2.1 → 10.0.2.2: first 10 paths");
  assert.ok(await attackDrawn());
  // A CIDR applies to the attack paths at once, and to the map from the next expansion.
  await page.fill("#exclude-input", "10.0.2.0/24");
  await page.press("#exclude-input", "Enter");
  await waitStatus(/^Excluded 10\.0\.2\.0\/24 for everyone; re-expand hosts to apply CIDRs$/);
  await page.waitForSelector("#path-list li.hint >> text=No time-consistent path between the marked hosts.");
  assert.ok((await ids()).includes("10.0.2.10"), "still on the map");
  await page.click("#go");
  await waitStatus(/^10\.0\.2\.1: showing top 0 of 0 distinct peer/);
  assert.ok(!(await ids()).includes("10.0.2.10"), "gone once expanded again");
  await page.click("#exclude-list li:has-text('10.0.2.0/24') button");
  await page.waitForSelector("#path-list li.pair button");
  await page.click("#path-list li.pair button");
  await page.waitForFunction(() => document.querySelectorAll("#route-list li.path").length === 11);
  assert.equal(await page.inputValue("#route-dst-time"), "2024-05-01T13:00:00.000Z");
  assert.match(await page.textContent("#route-summary"),
    /^First 11 paths from 10\.0\.2\.1 to 10\.0\.2\.2, shortest first\. There are more/);
  assert.ok(await statusIs("warn"));
  await shot("show-all");
  for (const ip of ["10.0.2.1", "10.0.2.2"]) {
    await page.click(`#compromised-list li:has-text('${ip}') button`);
  }
  await page.waitForSelector("#compromised-list li", { state: "detached" });
  await clearRouteFields();

  // 7. Page through a connection's 120 flows. Going back, the next hop from 10.0.1.1 ends
  //    when it was last seen; going forward, the next hop from 10.0.1.2 starts when it was
  //    first contacted.
  await map("10.0.1.2", "in");
  assert.equal(await anchor("10.0.1.1"), "2024-05-01T13:09:50.000Z");
  let p = await at(edge("10.0.1.1", "10.0.1.2"), "edge");
  await page.mouse.click(p.x, p.y);
  await page.waitForFunction(() => document.querySelector("#flows .pager span"));
  const buttons = () => page.$$eval("#flows .pager button", (b) => b.map((x) => `${x.textContent}:${x.disabled ? "off" : "on"}`));
  assert.equal(await pager(), "1–50 of 120");
  assert.deepEqual(await buttons(), ["First:off", "Older:off", "Newer:on", "Last:on"]);
  assert.equal(await page.$eval("#flows li", (li) => li.firstChild.textContent), "2024-05-01T12:50:00.000Z");
  const turn = async (label, expect) => {
    await page.click(`#flows .pager button:text("${label}")`);
    await page.waitForFunction((t) => document.querySelector("#flows .pager span").textContent === t, expect);
  };
  await turn("Newer", "51–100 of 120");
  await turn("Last", "101–120 of 120");
  assert.deepEqual(await buttons(), ["First:on", "Older:on", "Newer:off", "Last:off"]);
  assert.equal(await page.$eval("#flows ol", (o) => o.start), 101);
  assert.equal(await page.$$eval("#flows li", (l) => l.at(-1).firstChild.textContent), "2024-05-01T13:09:50.000Z");
  await turn("Older", "51–100 of 120");
  await turn("First", "1–50 of 120");
  await shot("flow-pages");
  await map("10.0.1.1", "out");
  assert.equal(await anchor("10.0.1.2"), "2024-05-01T12:50:00.000Z");
  p = await at(edge("10.0.1.1", "10.0.1.2"), "edge");
  await page.mouse.click(p.x, p.y, { button: "right" });
  assert.deepEqual((await rows()).slice(4, 6), ["Direction", "outbound (future)"]);

  // 8. Narrow the range after mapping: the old connection now has no flows in it.
  await page.fill("#range-to", "2024-05-01T12:00:00Z");
  p = await at(edge("10.0.1.1", "10.0.1.2"), "edge");
  await page.mouse.click(p.x, p.y);
  await page.waitForFunction(() => document.querySelector("#flows .pager span")?.textContent === "none in the time range");
  await page.fill("#range-to", "");

  // 8b. A flow's line leaves out what is unknown, and large numbers are grouped.
  await page.route("**/api/flows?*", (route) => route.fulfill({ json: {
    src: "10.0.1.1", dst: "10.0.1.2", start: "2024-05-01T12:50:00.000Z", end: "2024-05-01T13:09:50.000Z",
    offset: 0, total: 100071, flows: [
      { start: "2024-05-01T12:50:00.000Z", proto: "icmp", sport: null, dport: null, duration: null,
        packets: 1234, bytes: 3410, protocols: ["icmp"] },
      { start: "2024-05-01T12:51:00.000Z", proto: null, sport: null, dport: null, duration: 0.5,
        packets: null, bytes: null, protocols: ["smb", "ntlm"] }] } }));
  p = await at(edge("10.0.1.1", "10.0.1.2"), "edge");
  await page.mouse.click(p.x, p.y, { button: "right" });
  await page.waitForFunction(() => document.querySelector("#flows .pager span")?.textContent === "1–2 of 100,071");
  assert.deepEqual(await page.$$eval("#flows ol.flows li small", (l) => l.map((x) => x.textContent)),
                   ["ICMP · icmp · 1,234 pkts · 3,410 B", "SMB/NTLM · ? · 0.500 s"]);
  await page.unroute("**/api/flows?*");

  // 8c. Hops are time-chained. Going forward, 10.0.0.9's DNS query at 11:40 came before it
  //     was reached at 12:10; going back, 10.0.0.77's connection at 12:30 came after 10.0.0.9
  //     left at 12:20. Neither is shown.
  const expandByClick = async (ip, re) => {
    const n = await at(node(ip));
    await page.mouse.click(n.x, n.y);
    await waitStatus(re);
  };
  await map("203.0.113.66", "out");
  await expandByClick("10.0.0.5", /^10\.0\.0\.5: showing top 2 of 2 distinct peer/);
  await expandByClick("10.0.0.9", /^10\.0\.0\.9: showing/);
  assert.equal(await status(), "10.0.0.9: showing top 1 of 1 distinct peer(s), 2024-05-01T12:10:00.000Z → 2024-05-02T12:10:00.000Z");
  assert.ok(!(await ids()).includes("10.0.0.53"));
  await map("10.0.0.20", "in");
  await expandByClick("10.0.0.9", /^10\.0\.0\.9: showing/);
  assert.equal(await status(), "10.0.0.9: showing top 1 of 1 distinct peer(s), 2024-04-30T12:20:00.000Z → 2024-05-01T12:20:00.000Z");
  assert.ok(!(await ids()).includes("10.0.0.77"));
  // A window outside the time range says so. The map's settings go into its URL.
  await page.fill("#range-from", "2024-05-01T12:00:00Z");
  await page.fill("#ts", "2024-05-01T11:00:00Z");
  await page.fill("#ip", "10.0.0.9");
  await page.click("#go");
  await waitStatus(/^10\.0\.0\.9: showing top 0 of 0 distinct peer\(s\) — the window is outside the time range$/);
  assert.deepEqual(Object.fromEntries(new URL(page.url()).searchParams), {
    ip: "10.0.0.9", ts: "2024-05-01T11:00:00.000Z", dir: "in", window: "24h", order: "top",
    range_from: "2024-05-01T12:00:00Z"});
  await page.fill("#range-from", "");
  await page.fill("#ts", "");

  // 9. A map link that carries a time range.
  await checkpoint(page, "actions-1");
  await page.goto(`${BASE}/?ip=10.0.1.2&dir=in&range_from=2024-05-01T13:00:00Z`);
  await waitStatus(/^10\.0\.1\.2: showing/);
  assert.equal(await page.inputValue("#range-from"), "2024-05-01T13:00:00Z");
  assert.equal(await cyEval(() => window.threatbridge.cy.getElementById("10.0.1.1->10.0.1.2").data("count")), 60);

  // 10. A server failure while working is shown, not swallowed.
  await page.route("**/api/flows?*", (r) => r.fulfill({ status: 502, contentType: "application/json",
                                                       body: JSON.stringify({ error: "Elasticsearch returned HTTP 503" }) }));
  await page.route("**/api/threatline?*", (r) => r.abort());
  p = await at(edge("10.0.1.1", "10.0.1.2"), "edge");
  await page.mouse.click(p.x, p.y);
  await waitStatus(/Elasticsearch returned HTTP 503|Failed to fetch/);
  assert.ok(await statusIs("error"));
  await page.unroute("**/api/flows?*");
  await page.unroute("**/api/threatline?*");

  // 11. A slow request shows how long it has taken, and Cancel stops it without an error.
  await page.route("**/api/paths?*", async (route) => {
    await sleep(5000);
    route.continue().catch(() => {});                       // cancelled meanwhile
  });
  await page.fill("#route-src", "10.0.2.1");
  await page.fill("#route-dst", "10.0.2.2");
  await page.click("#route-form button");
  await page.waitForFunction(() => !document.getElementById("busy").hidden &&
    /^Working… [1-4] s$/.test(document.getElementById("busy-text").textContent));
  await page.click("#cancel");
  await waitStatus(/^Cancelled$/);
  assert.ok(!(await statusIs("error")));
  await page.waitForFunction(() => document.getElementById("busy").hidden);
  await page.unroute("**/api/paths?*");
  await clearRouteFields();

  // 11b. A threat line follows the Window and the time range, and says when it was cut short.
  await page.fill("#range-from", "");                          // set from the URL in step 9
  await map("10.0.0.9", "in");
  const lineSays = async (text) => {
    const e = await at(edge("10.0.0.5", "10.0.0.9"), "edge");
    await page.mouse.click(e.x, e.y);
    await waitStatus(new RegExp(`^${esc(text)}$`));
  };
  await page.fill("#window", "5m");
  await lineSays("Threat line through 10.0.0.5 → 10.0.0.9: 0 earlier host(s) (violet), 0 later host(s) (teal); " +
                 "≤ 6 hops, ≤ 5m between hops. Click the background to clear.");
  await page.fill("#window", "24h");
  await page.fill("#range-from", "2024-05-01T12:05:00Z");
  await lineSays("Threat line through 10.0.0.5 → 10.0.0.9: 0 earlier host(s) (violet), 1 later host(s) (teal); " +
                 "≤ 6 hops, ≤ 24h between hops. Click the background to clear.");
  await page.fill("#range-from", "");
  const T5 = "2024-05-01T12:10:00.000Z";
  await page.route("**/api/threatline?*", (route) => route.fulfill({ json: { a: "10.0.0.5", b: "10.0.0.9", truncated: true,
    nodes: [{ id: "10.0.0.5", role: "selected", time: T5, hops: 0 }, { id: "10.0.0.9", role: "selected", time: T5, hops: 0 },
            { id: "192.0.2.50", role: "both", time: T5, hops: 1 }],
    edges: [{ source: "192.0.2.50", target: "10.0.0.5", role: "up", count: 1, first_seen: T5, last_seen: T5, ports: [22],
              protocols: ["ssh"] },
            { source: "10.0.0.9", target: "192.0.2.50", role: "down", count: 1, first_seen: T5, last_seen: T5, ports: [22],
              protocols: ["ssh"] }] } }));
  await lineSays("Threat line through 10.0.0.5 → 10.0.0.9: 1 earlier host(s) (violet), 1 later host(s) (teal); " +
                 "≤ 6 hops, ≤ 24h between hops. Click the background to clear. " +
                 "WARNING: stopped at the host limit; the line is incomplete.");
  assert.ok(await statusIs("warn"));
  assert.deepEqual((await cyEval(() => window.threatbridge.cy.getElementById("192.0.2.50").classes())).sort(), ["down", "up"]);
  await page.unroute("**/api/threatline?*");

  // 12. Save the map for everyone, change it, and open it again as it was: hosts and their
  //     positions, connections, highlights, the view and the toolbar.
  await map("10.0.0.9", "in");
  p = await at(edge("10.0.0.5", "10.0.0.9"), "edge");
  await page.mouse.click(p.x, p.y);
  await waitStatus(/^Threat line/);
  const elements = () => cyEval(() => window.threatbridge.cy.elements().map((e) => [
    e.id(), e.isNode() ? e.position() : [e.data("count"), e.data("ports"), e.data("first_seen"), e.data("protocols")],
    e.data("anchor") ?? null, e.data("root") ?? null, e.classes().sort()]).sort());
  const settings = () => page.evaluate(() => ["ip", "ts", "direction", "window", "range-from", "range-to", "order",
    "limit", "route-src", "route-src-time", "route-dst", "route-dst-time"].map((id) => document.getElementById(id).value));
  const view = () => cyEval(() => [window.threatbridge.cy.zoom(), window.threatbridge.cy.pan()]);
  await page.selectOption("#order", "bottom");
  await page.fill("#limit", "7");
  await page.fill("#range-to", "2030-01-01T00:00:00Z");
  await page.fill("#route-src", "203.0.113.66");
  await page.fill("#route-dst", "10.0.0.20");
  await cyEval(() => { window.threatbridge.cy.zoom(1.25); window.threatbridge.cy.pan({ x: 30, y: 40 }); });
  const before = await elements(), savedSettings = await settings(), savedView = await view();
  assert.ok(before.some(([, , , , classes]) => classes.includes("faded")), "the threat line is highlighted");
  await page.fill("#session-name", "incident 42");
  await page.click("#session-form button");
  await waitStatus(/^Saved the map "incident 42" for everyone$/);
  await page.waitForSelector("#session-list .session >> text=incident 42");
  assert.match(await page.textContent("#session-list li small"), /^saved \d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
  // The same name again asks first: Cancel keeps the saved one, OK replaces it.
  let [dialog] = await Promise.all([page.waitForEvent("dialog"), page.click("#session-form button")]);
  assert.equal(dialog.message(), 'Replace the saved map "incident 42"?');
  await dialog.dismiss();
  await waitStatus(/^a map called 'incident 42' is already saved$/);
  assert.ok(await statusIs("error"));
  [dialog] = await Promise.all([page.waitForEvent("dialog"), page.click("#session-form button")]);
  await dialog.accept();
  await waitStatus(/^Replaced the map "incident 42" for everyone$/);
  assert.equal(await page.locator("#session-list li").count(), 1);
  assert.deepEqual(await othersSee("#session-list .session"), ["incident 42"]);
  // Clear resets the protocol preview, and only that: the map and its protocols stay (D18).
  const options = await page.$$eval("#protocol option", (l) => l.length);
  await page.selectOption("#protocol", await page.$eval("#protocol option:nth-child(2)", (o) => o.value));
  await page.click("#clear");
  assert.equal(await page.inputValue("#protocol"), "");
  assert.equal(await page.$$eval("#protocol option", (l) => l.length), options);
  assert.equal(await cyEval(() => window.threatbridge.cy.$(".proto-hit, .proto-dim").length), 0);
  assert.deepEqual(await elements(), before);
  await page.fill("#window", "1h");
  await page.selectOption("#order", "top");
  await page.fill("#limit", "50");
  await page.fill("#range-to", "");
  await clearRouteFields();
  await page.click("#session-list .session >> text=incident 42");
  await waitStatus(/^Opened "incident 42" \(saved .*\): \d+ host\(s\), \d+ connection\(s\)$/);
  assert.deepEqual(await elements(), before);
  assert.deepEqual(await settings(), savedSettings);
  assert.deepEqual(await view(), savedView);
  assert.match(page.url(), /ip=10\.0\.0\.9/);
  await shot("saved-map");

  // ... and as a file, to keep or pass on.
  const [mapFile] = await Promise.all([page.waitForEvent("download"), page.click("#session-download")]);
  assert.equal(mapFile.suggestedFilename(), "threatbridge-incident_42.json");
  const doc = JSON.parse(await readFile(await mapFile.path(), "utf8"));
  assert.equal(doc.version, 2);
  assert.deepEqual([doc.filters, doc.marks], [[], { hosts: [], flows: [] }]);
  assert.deepEqual(doc.queries.map((q) => q.op), ["root", "threatline"]);
  const openFile = async (name, content) => {
    await page.setInputFiles("#session-file", { name, mimeType: "application/json",
                                                buffer: Buffer.from(typeof content === "string" ? content : JSON.stringify(content)) });
  };
  await openFile("incident.json", doc);
  await waitStatus(/^Opened incident\.json: /);
  assert.deepEqual(await elements(), before);
  await openFile("notes.json", "not a map");
  await waitStatus(/^notes\.json is not a ThreatBridge map$/);
  await openFile("v3.json", Object.assign({}, doc, { version: 3 }));
  await waitStatus(/^v3\.json is not a ThreatBridge map$/);
  assert.deepEqual(await elements(), before, "a refused file leaves the map alone");
  const noView = Object.assign({}, doc);
  delete noView.view;                                          // no view saved: fit the map
  await openFile("no-view.json", noView);
  await waitStatus(/^Opened no-view\.json: /);
  // Only what a map holds is taken from a file: hosts need a name, connections two known ends.
  await openFile("odd.json", { version: 1,
    nodes: [{ id: "10.0.0.1", position: { x: 1, y: 2 } }, { id: "10.0.0.1" }, { id: "" }, { id: 5 }, { position: "x" },
            { id: "10.0.0.2", position: "here" }],
    edges: [{ source: "10.0.0.1", target: "10.0.0.2", count: "many", ports: ["x", 80], direction: "sideways",
              protocols: ["quic", 7, "x".repeat(41), ""] },
            { source: "10.0.0.1", target: "nowhere" }, { source: 1, target: 2 }] });
  await waitStatus(/^Opened odd\.json: 2 host\(s\), 1 connection\(s\)$/);
  assert.deepEqual(await cyEval(() => {
    const cy = window.threatbridge.cy, e = cy.edges()[0];
    return [e.id(), e.data("count"), e.data("ports"), e.data("direction"), e.data("label"), e.data("protocols"),
            cy.getElementById("10.0.0.1").position(), cy.getElementById("10.0.0.2").position()];
  }), ["10.0.0.1->10.0.0.2", 0, [80], "out", "0 · 80", ["quic"], { x: 1, y: 2 }, { x: 0, y: 0 }]);
  // A protocol ThreatBridge has no name for is shown as it came, in capitals.
  await page.waitForFunction(() => document.querySelector("#protocol option:nth-child(2)")?.value === "quic");
  assert.equal(await page.textContent("#protocol option:nth-child(2)"), "QUIC");
  // Without a name, the file is named after the IOC host, or "map" for an empty map.
  await openFile("incident.json", doc);
  await waitStatus(/^Opened incident\.json: /);
  await page.fill("#session-name", "");
  let [named] = await Promise.all([page.waitForEvent("download"), page.click("#session-download")]);
  assert.equal(named.suggestedFilename(), "threatbridge-10.0.0.9.json");
  await checkpoint(page, "actions-2");
  await page.goto(BASE);                                     // a page with no map yet
  await page.waitForFunction(() => document.querySelector("#session-list li"));
  [named] = await Promise.all([page.waitForEvent("download"), page.click("#session-download")]);
  assert.equal(named.suggestedFilename(), "threatbridge-map.json");
  // An opened map shows its own marks, and marking changes only them (D19): the shared list
  // stays as it was, and the attack paths come from the map's marks.
  await openFile("incident.json", doc);
  await waitStatus(/^Opened incident\.json: /);
  assert.equal(await page.textContent("#local-marks-name"), "incident.json");
  assert.ok(await page.locator("#local-marks").isVisible());
  await page.fill("#compromised-ip", "203.0.113.66");
  await page.click("#compromised-form button");
  await page.fill("#compromised-ip", "10.0.0.20");
  await page.fill("#compromised-time", "2024-05-01T12:20:00Z");
  await page.click("#compromised-form button");
  await page.waitForFunction(() => window.threatbridge.cy.edges(".attack").nonempty());
  assert.deepEqual((await (await page.request.get(`${BASE}/api/compromised`)).json()).hosts, []);
  const [withPaths] = await Promise.all([page.waitForEvent("download"), page.click("#session-download")]);
  const pathsDoc = JSON.parse(await readFile(await withPaths.path(), "utf8"));
  assert.ok(pathsDoc.edges.some((e) => e.classes.includes("attack")));
  assert.deepEqual(pathsDoc.marks.hosts.map((h) => [h.ip, h.time]),
                   [["203.0.113.66", null], ["10.0.0.20", "2024-05-01T12:20:00.000Z"]]);
  await page.click("#compromised-list li:has-text('203.0.113.66') button");
  await page.waitForSelector("#path-list li.hint >> text=Mark at least two hosts as compromised.");
  assert.ok(!(await attackDrawn()));
  await openFile("with-paths.json", pathsDoc);              // its marks, so its paths, come back
  await waitStatus(/^Opened with-paths\.json: /);
  await page.waitForFunction(() => window.threatbridge.cy.edges(".attack").nonempty());
  assert.equal(await page.locator("#compromised-list li").count(), 2);
  await page.click("#compromised-list li:has-text('10.0.0.20') button");
  await page.click("#compromised-list li:has-text('203.0.113.66') button");
  await page.waitForSelector("#compromised-list li", { state: "detached" });
  // Names and hosts from saved maps and files are shown as text, never run as HTML.
  const markup = '<img src=x onerror="window.injected=1">';
  await page.fill("#session-name", markup);
  await page.click("#session-form button");
  await waitStatus(new RegExp(`^Saved the map "${esc(markup)}" for everyone$`));
  const names = await page.$$eval("#session-list .session", (l) => l.map((x) => x.firstChild.textContent));
  assert.ok(names.includes(markup), names);
  let asked = null;
  page.once("dialog", (d) => { asked = d.message(); d.accept(); });
  await page.locator("#session-list li").nth(names.indexOf(markup)).locator("button").click();
  assert.equal(asked, `Delete the saved map "${markup}" for everyone?`);
  await waitStatus(new RegExp(`^Deleted the saved map "${esc(markup)}"$`));
  await openFile("markup.json", { version: 1, nodes: [{ id: markup, position: { x: 0, y: 0 } }], edges: [] });
  await waitStatus(/^Opened markup\.json: 1 host\(s\), 0 connection\(s\)$/);
  const mp = await cyEval((id) => {
    const p = window.threatbridge.cy.getElementById(id).renderedPosition(), b = document.getElementById("cy").getBoundingClientRect();
    return { x: p.x + b.left, y: p.y + b.top };
  }, markup);
  await page.mouse.click(mp.x, mp.y, { button: "right" });
  assert.deepEqual(await menuItems(), [`${markup} @ now`, "Expand inbound: who connected to it (past)",
    "Expand outbound: who it connected to (future)", "", "Mark compromised (time unknown)",
    "Find paths from this host…", "Find paths to this host…", "Remove from map", "Add to shared exclude list"]);
  assert.equal(await page.textContent("#detail-body dd"), markup);
  await page.keyboard.press("Escape");
  assert.equal(await page.evaluate(() => window.injected), undefined);
  assert.equal(await page.locator("img").count(), 0);
  // The name must fit; deleting asks first.
  await page.fill("#session-name", "x".repeat(101));
  await page.click("#session-form button");
  await waitStatus(/^a map's name is 1 to 100 printable characters$/);
  assert.ok(await statusIs("error"));
  page.once("dialog", (d) => d.dismiss());
  await page.click("#session-list li:has-text('incident 42') button");
  await page.waitForTimeout(300);
  assert.equal(await page.locator("#session-list .session").count(), 1, "Cancel keeps it");
  page.once("dialog", (d) => d.accept());
  await page.click("#session-list li:has-text('incident 42') button");
  await waitStatus(/^Deleted the saved map "incident 42"$/);
  await page.waitForSelector("#session-list li.hint");
  await page.selectOption("#order", "top");
  await page.fill("#limit", "50");
  await page.fill("#range-to", "");
  await clearRouteFields();

  // 12b. After the window is resized, or the page scrolled, a click still lands on the host
  //      under the pointer.
  await page.setViewportSize({ width: 1100, height: 380 });     // short enough for the page to scroll
  await map("10.0.0.9", "in");
  assert.ok(await page.evaluate(() => document.documentElement.scrollHeight > innerHeight), "the page scrolls");
  await page.evaluate(() => window.scrollTo(0, 100));
  await page.waitForTimeout(200);
  const onScreen = async () => {
    for (const ip of await ids()) {
      const n = await at(node(ip));
      if (n.y > 10 && n.y < page.viewportSize().height - 10) return n;
    }
    throw new Error("no host on screen");
  };
  let target = await onScreen();
  await page.mouse.click(target.x, target.y, { button: "right" });
  assert.equal(await page.textContent("#detail-body dd"), target.id);
  await page.keyboard.press("Escape");
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.setViewportSize({ width: 1400, height: 850 });
  await page.waitForTimeout(300);
  for (const ip of ["10.0.0.5", "10.0.0.77"]) {
    target = await at(node(ip));
    await page.mouse.click(target.x, target.y, { button: "right" });
    assert.equal(await page.textContent("#detail-body dd"), ip);
    await page.keyboard.press("Escape");
  }

  // 13. Fit brings every host back into view; Clear leaves the map as it is.
  await cyEval(() => window.threatbridge.cy.pan({ x: -5000, y: -5000 }));
  await page.click("#fit");
  assert.ok(await cyEval(() => {
    const cy = window.threatbridge.cy;
    return cy.nodes().every((n) => {
      const r = n.renderedPosition();
      return r.x >= 0 && r.y >= 0 && r.x <= cy.width() && r.y <= cy.height();
    });
  }), "all hosts in view after Fit");
  const shownBefore = await ids();
  await page.click("#clear");
  assert.deepEqual(await ids(), shownBefore);

  assert.deepEqual(errors, [], "browser console errors");
  console.log("UI actions test passed");
} finally {
  await finish(browser, page, "actions");
}
