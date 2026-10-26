// Headless browser test against a demo-backend server: the toolbar and its URL, launching as
// a SOC action would, Top and Bottom N, SOC pivots, flows and their PCAP, the exclude list,
// marking hosts compromised, the busy indicator, and what the status line says.
//   TB_URL=http://127.0.0.1:5055 node tests/ui_smoke.mjs [screenshot-dir]
// Needs the `playwright` npm package (see ui_helpers.mjs).
import assert from "node:assert/strict";
import { checkpoint, finish, launch } from "./ui_helpers.mjs";

const BASE = process.env.TB_URL || "http://127.0.0.1:5055";
const SHOTS = process.argv[2];
const SOC = "https://so.example";   // must match TB_SOC_URL of the server under test
const IOC = "10.0.0.5", IOC_TIME = "2024-05-01T12:00:00Z";

// The error answers this test provokes on purpose (HTTP 502) are expected.
const { browser, ctx, page, errors, at } = await launch(
  { context: { permissions: ["clipboard-read", "clipboard-write"] }, expected: /status of 502/ });
await ctx.route(`${SOC}/**`, (r) => r.fulfill({ body: "SOC stub" }));
const menuItems = () => page.$$eval("#menu li", (l) => l.map((x) => x.textContent));
const status = () => page.textContent("#status");
const statusIs = (cls) => page.$eval("#status", (s, c) => s.classList.contains(c), cls);
const waitStatus = (re) => page.waitForFunction(
  (src) => new RegExp(src).test(document.getElementById("status").textContent), re.source);
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
const anchorOf = (id) => page.evaluate((i) => window.threatbridge.cy.getElementById(i).data("anchor"), id);
const detail = (name) => page.$$eval("#detail-body dt", (dts, n) => {
  const dt = dts.find((d) => d.textContent === n);
  return dt ? dt.nextElementSibling.textContent : null;
}, name);
const choose = (label) => page.locator("#menu li", { hasText: label }).first().click();
const clipboard = async () => {
  for (let i = 0; i < 50; i++) {
    const text = await page.evaluate(() => navigator.clipboard.readText());
    if (text) return text;
    await sleep(100);
  }
  throw new Error("nothing was copied");
};
const popupQuery = async (click) => {
  const [popup] = await Promise.all([ctx.waitForEvent("page"), click()]);
  const url = popup.url();
  await popup.close();
  return url;
};

try {
  // 0. Opened without a map: the toolbar's defaults come from the server, and the threat-line
  //    and path sections are hidden (they need case files). Map with no host says so.
  await page.route("**/api/config", async (route) => {
    const r = await route.fetch();
    await route.fulfill({ response: r, json: Object.assign(await r.json(), { default_window: "12h", default_limit: 30 }) });
  });
  await page.goto(BASE);
  await page.waitForFunction(() => document.getElementById("window").value === "12h");
  assert.equal(await page.inputValue("#limit"), "30");
  assert.equal(await page.getAttribute("#ts", "placeholder"), "2024-05-01T12:00:00Z (blank = now)");
  assert.ok(await page.locator("#paths").isHidden());
  assert.ok(await page.locator("#routes").isHidden());
  await page.unroute("**/api/config");
  await page.click("#go");
  await waitStatus(/^Enter an IP address$/);
  assert.ok(await statusIs("error"));
  await checkpoint(page, "smoke-0");

  // 1. Launch the way a SOC action does.
  await page.goto(`${BASE}/?ip=${IOC}&ts=${IOC_TIME}&dir=in`);
  await page.waitForFunction(() => window.threatbridge.cy.edges().length > 0);
  assert.match(await status(), /showing top/);
  assert.ok(await page.evaluate(() => window.threatbridge.cy.edges("[direction='out']").length === 0));

  // 2. Right-click a peer: its menu, for Security Onion data; then expand outbound (future).
  const peer = await at("node[!root]", "node");
  const peerAnchor = await anchorOf(peer.id);
  await page.mouse.click(peer.x, peer.y, { button: "right" });
  assert.deepEqual(await menuItems(), [
    `${peer.id} @ ${peerAnchor}`, "Expand inbound: who connected to it (past)",
    "Expand outbound: who it connected to (future)", "", "Open host in SOC dashboard",
    `Mark compromised at ${peerAnchor}`, "Mark compromised (time unknown)", "Remove from map",
    "Add to shared exclude list"]);
  await page.click("text=Expand outbound");
  await page.waitForFunction(() => window.threatbridge.cy.edges("[direction='out']").length > 0);
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/map.png` });

  // 3. Right-click the IOC's inbound edge -> SOC pivot bounded at the IOC time.
  const edge = await at(`edge[direction='in'][target='${IOC}']`, "edge");
  await page.mouse.click(edge.x, edge.y, { button: "right" });
  const [a, b] = edge.id.split("->");
  assert.equal((await menuItems())[0], `${a} ↔ ${b}`, "edge menu belongs to clicked edge");
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/edge-menu.png` });
  const url = decodeURIComponent(await popupQuery(() => page.click("text=Filter SOC Dashboards")));
  assert.ok(url.startsWith(`${SOC}/#/dashboards?q=`), url);
  assert.ok(url.includes(`(source.ip:"${a}" AND destination.ip:"${b}")`), url);
  assert.ok(url.includes(`(source.ip:"${b}" AND destination.ip:"${a}")`), url);
  assert.ok(url.includes('@timestamp:[* TO "2024-05-01T12:00:00.000Z"]'), url);
  assert.equal(await status(), `Opened SOC filter: ${url.split("?q=")[1]}`);

  // The details panel lists the connection's flows, oldest first.
  await page.waitForSelector("#flows ol.flows li");
  const starts = await page.$$eval("#flows ol.flows li", (l) => l.map((x) => x.firstChild.textContent));
  assert.deepEqual(starts, [...starts].sort());
  assert.match(await page.textContent("#flows .pager span"), /^1–\d+ of [\d,]+$/);

  // Each flow links to SOC's PCAP job for it; no download without a SOC API client.
  const pcap = page.locator("#flows ol.flows li").first().locator("a", { hasText: "PCAP in SOC" });
  const pcapUrl = new URL(await pcap.getAttribute("href"));
  assert.equal(`${pcapUrl.origin}${pcapUrl.pathname}`, `${SOC}/joblookup`);
  assert.match(pcapUrl.searchParams.get("esid"), /^demo[0-9a-f]{16}$/);
  assert.equal(pcapUrl.searchParams.get("time"), starts[0]);
  assert.equal(await pcap.getAttribute("target"), "_blank");
  assert.ok((await popupQuery(() => pcap.click())).startsWith(`${SOC}/joblookup?esid=`));
  assert.equal(await page.locator("#flows button", { hasText: "Download PCAP" }).count(), 0);

  // 3b. The same menu copies the query instead; the host menu opens the host in SOC.
  // (The status line now holds the long query and wraps, moving the map: find the edge again.)
  const again = await at(`edge[id = "${edge.id}"]`, "edge");
  await page.mouse.click(again.x, again.y, { button: "right" });
  await page.click("text=Copy SOC query");
  await page.waitForFunction(() => document.getElementById("status").textContent === "SOC query copied to clipboard");
  const copied = await clipboard();
  assert.ok(copied.startsWith(`((source.ip:"${a}" AND destination.ip:"${b}")`), copied);
  let host = await at("node[?root]", "node");
  await page.mouse.click(host.x, host.y, { button: "right" });
  let hostUrl = decodeURIComponent(await popupQuery(() => page.click("text=Open host in SOC dashboard")));
  assert.ok(hostUrl.includes(`(source.ip:"${IOC}" OR destination.ip:"${IOC}") | groupby`), hostUrl);

  // 3c. The time range bounds the pivots, and a pivot from further along the chain still ends
  //     at the IOC time.
  await page.fill("#range-from", "2024-04-30T00:00:00Z");
  await page.evaluate(() => navigator.clipboard.writeText(""));
  const deeper = await at("edge[direction='out']", "edge");
  await page.mouse.click(deeper.x, deeper.y, { button: "right" });
  await page.click("text=Copy SOC query");
  const [da, db] = deeper.id.split("->");
  const deepQuery = await clipboard();
  assert.ok(deepQuery.startsWith(`((source.ip:"${da}" AND destination.ip:"${db}")`), deepQuery);
  assert.ok(deepQuery.includes('@timestamp:["2024-04-30T00:00:00.000Z" TO "2024-05-01T12:00:00.000Z"]'), deepQuery);
  host = await at("node[?root]", "node");
  await page.mouse.click(host.x, host.y, { button: "right" });
  hostUrl = decodeURIComponent(await popupQuery(() => page.click("text=Open host in SOC dashboard")));
  assert.ok(hostUrl.includes(`(source.ip:"${IOC}" OR destination.ip:"${IOC}") AND ` +
                             '@timestamp:["2024-04-30T00:00:00.000Z" TO *] | groupby'), hostUrl);
  await page.fill("#range-from", "");

  // 4. Shared exclude list round-trip through the UI.
  await page.fill("#exclude-input", "10.200.0.0/16");
  await page.click("#exclude-form button");
  await waitStatus(/^Excluded 10\.200\.0\.0\/16 for everyone; re-expand hosts to apply CIDRs$/);
  await page.waitForSelector("#exclude-list li >> text=10.200.0.0/16");
  await page.click("#exclude-list li:has-text('10.200.0.0/16') button");
  await waitStatus(/^Removed 10\.200\.0\.0\/16 from exclude list$/);
  await page.waitForSelector("#exclude-list li >> text=10.200.0.0/16", { state: "detached" });

  // 4b. Marking a host compromised from its menu, with the time unknown or at its anchor: the
  //     status line, the details panel, the menu and the side panel follow.
  const victim = await at("node[!root]", "node");
  const victimAnchor = await anchorOf(victim.id);
  const rightClickVictim = async () => {
    const p = await at(`node[id = "${victim.id}"]`, "node");
    await page.mouse.click(p.x, p.y, { button: "right" });
  };
  await rightClickVictim();
  await choose("Mark compromised (time unknown)");
  await waitStatus(new RegExp(`^Marked ${esc(victim.id)} compromised \\(time unknown\\)$`));
  assert.equal(await detail("Compromised"), "yes, time unknown");
  assert.equal(await page.textContent("#compromised-list li span"), `${victim.id} @ time unknown`);
  await rightClickVictim();
  const marked = await menuItems();
  assert.ok(marked.includes("Unmark compromised"), marked);
  assert.ok(!marked.some((item) => item.startsWith("Mark compromised")), marked);
  await choose("Unmark compromised");
  await waitStatus(new RegExp(`^Unmarked ${esc(victim.id)}$`));
  assert.equal(await detail("Compromised"), "no");
  await page.waitForSelector("#compromised-list li", { state: "detached" });
  await rightClickVictim();
  await choose("Mark compromised at");
  await waitStatus(new RegExp(`^Marked ${esc(victim.id)} compromised at ${esc(victimAnchor)}$`));
  assert.equal(await detail("Compromised"), victimAnchor);
  assert.equal(await page.textContent("#compromised-list li span"), `${victim.id} @ ${victimAnchor}`);
  await page.click("#compromised-list li button");
  await waitStatus(new RegExp(`^Unmarked ${esc(victim.id)}$`));
  await page.waitForSelector("#compromised-list li", { state: "detached" });

  // 5. A time range narrows the next map.
  await page.fill("#range-from", "2024-05-01T11:00:00Z");
  await page.press("#range-from", "Enter");
  await page.waitForFunction(() => document.getElementById("status").textContent
    .includes("2024-05-01T11:00:00.000Z → 2024-05-01T12:00:00.000Z"));

  // 5b. Bottom N (rarest) and Top N, with the toolbar's settings read from and kept in the URL.
  await checkpoint(page, "smoke-1");
  await page.goto(`${BASE}/?ip=${IOC}&ts=${IOC_TIME}&dir=in&window=48h&order=bottom&range_to=2024-05-01T11:00:00Z`);
  await waitStatus(/showing rarest/);
  assert.equal(await page.inputValue("#window"), "48h");
  assert.equal(await page.inputValue("#order"), "bottom");
  assert.equal(await page.inputValue("#range-to"), "2024-05-01T11:00:00Z");
  assert.equal(await status(),
    "10.0.0.5: showing rarest 5 of 5 distinct peer(s), 2024-04-29T12:00:00.000Z → 2024-05-01T11:00:00.000Z");
  const counts = () => page.evaluate(() => window.threatbridge.cy.edges().map((e) => e.data("count")).sort());
  await page.fill("#limit", "2");
  await page.click("#go");
  await waitStatus(/^10\.0\.0\.5: showing rarest 2 of 5 distinct peer/);
  assert.deepEqual(await counts(), [1, 1]);
  await page.selectOption("#order", "top");
  await page.click("#go");
  await waitStatus(/^10\.0\.0\.5: showing top 2 of 5 distinct peer/);
  assert.deepEqual(await counts(), [2, 2]);
  assert.deepEqual(Object.fromEntries(new URL(page.url()).searchParams), {
    ip: IOC, ts: "2024-05-01T12:00:00.000Z", dir: "in", window: "48h", order: "top",
    range_to: "2024-05-01T11:00:00Z"});
  await page.fill("#limit", "50");
  await page.fill("#window", "24h");
  await page.fill("#range-to", "");

  // 5c. What the status line says when the server can't count the peers and the rarest scan
  //     stopped at its cap, and when an error answer isn't JSON.
  await page.route("**/api/neighbors?*", async (route) => {
    const r = await route.fetch();
    await route.fulfill({ response: r, json: Object.assign(await r.json(), { distinct_peers: null, truncated: true }) });
  });
  await page.click("#go");
  await waitStatus(/WARNING/);
  assert.equal(await status(), "10.0.0.5: showing top 5, 2024-04-30T12:00:00.000Z → 2024-05-01T12:00:00.000Z" +
                               " — WARNING: scan hit the peer cap; rarest list may be incomplete");
  assert.ok(await statusIs("warn"));
  await page.unroute("**/api/neighbors?*");
  await page.route("**/api/neighbors?*", (route) => route.fulfill(
    { status: 502, contentType: "text/html", body: "<html><body>Bad gateway</body></html>" }));
  await page.click("#go");
  await waitStatus(/^HTTP 502$/);
  assert.ok(await statusIs("error"));
  await page.unroute("**/api/neighbors?*");

  // 5d. The busy indicator: not for an answer within a second; shown, then gone, for a slower one.
  await page.evaluate(() => {
    window.busySeen = false;
    const busy = document.getElementById("busy");
    new MutationObserver(() => { if (!busy.hidden) window.busySeen = true; }).observe(busy, { attributes: true });
  });
  const slowNeighbors = (ms) => page.route("**/api/neighbors?*", async (route) => {
    await sleep(ms);
    await route.continue().catch(() => {});
  });
  await slowNeighbors(400);
  await page.click("#go");
  await waitStatus(/^Querying inbound \(past\) for 10\.0\.0\.5…$/);
  await waitStatus(/^10\.0\.0\.5: showing top/);
  assert.equal(await page.evaluate(() => window.busySeen), false);
  await page.unroute("**/api/neighbors?*");
  await slowNeighbors(1800);
  await page.click("#go");
  await page.waitForFunction(() => !document.getElementById("busy").hidden &&
    document.getElementById("busy-text").textContent === "Working… 1 s");
  await waitStatus(/^10\.0\.0\.5: showing top/);
  assert.ok(await page.locator("#busy").isHidden());
  await page.unroute("**/api/neighbors?*");

  // 5e. What each entry on the exclude list stands for: the capture's DNS answers, a live
  //     lookup, both, an error, nothing, or more addresses than fit.
  await checkpoint(page, "smoke-2");
  await page.route("**/api/excludes", (route) => (route.request().method() !== "GET" ? route.continue() :
    route.fulfill({ json: {
      entries: ["10.0.0.0/24", "both.test", "live.test", "many.test", "none.test", "slow.test"],
      resolved: {
        "both.test": { capture: ["10.0.0.77"], dns: ["192.0.2.2"], error: null },
        "live.test": { capture: [], dns: ["192.0.2.1"], error: null },
        "many.test": { capture: ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"],
                       dns: [], error: null },
        "none.test": { capture: [], dns: [], error: null },
        "slow.test": { capture: ["10.0.0.9"], dns: [], error: "DNS lookup timed out" } } } })));
  await page.goto(BASE);
  await page.waitForSelector("#exclude-list li");
  assert.deepEqual(await page.$$eval("#exclude-list li", (lis) => lis.map((li) => [
    li.querySelector("span").firstChild.textContent, li.querySelector("small")?.textContent ?? null])), [
    ["10.0.0.0/24", null],
    ["both.test", "capture: 10.0.0.77 · DNS: 192.0.2.2"],
    ["live.test", "DNS: 192.0.2.1"],
    ["many.test", "capture: 10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4 +2 more"],
    ["none.test", "no addresses found"],
    ["slow.test", "capture: 10.0.0.9 · DNS lookup timed out"]]);
  await page.unroute("**/api/excludes");

  // 6. With a SOC API client, ThreatBridge downloads a flow's PCAP itself.
  await page.route("**/api/config", async (route) => {
    const r = await route.fetch();
    route.fulfill({ response: r, json: Object.assign(await r.json(), { pcap_download: true }) });
  });
  let asked = null;
  await page.route("**/api/pcap", async (route) => {
    asked = route.request().postDataJSON();
    await sleep(800);
    route.fulfill({ status: 200, contentType: "application/vnd.tcpdump.pcap", body: Buffer.from("d4c3b2a1" + "00".repeat(20), "hex") });
  });
  await checkpoint(page, "smoke-3");
  await page.goto(`${BASE}/?ip=${IOC}&ts=${IOC_TIME}&dir=in`);
  await page.waitForFunction(() => window.threatbridge.cy.edges().length > 0);
  const inbound = await at(`edge[direction='in'][target='${IOC}']`, "edge");
  await page.mouse.click(inbound.x, inbound.y);
  const download = page.locator("#flows ol.flows li").first().locator("button", { hasText: "Download PCAP" });
  await download.waitFor();
  const first = await page.$eval("#flows ol.flows li", (li) => li.firstChild.textContent);
  const [src, dst] = inbound.id.split("->");
  const downloading = page.waitForEvent("download");
  await download.click();
  await waitStatus(new RegExp(`^Asking the sensor for the packets of ${esc(src)} → ${esc(dst)} at ${esc(first)}…$`));
  const file = await downloading;
  assert.equal(file.suggestedFilename(), `${src}_${dst}_${first}.pcap`.replace(/:/g, "-"));
  assert.equal(asked.time, first);
  assert.match(asked.id, /^demo[0-9a-f]{16}$/);
  await waitStatus(new RegExp(`^PCAP of ${esc(src)} → ${esc(dst)} at ${esc(first)}: 24 B$`));
  await page.unroute("**/api/config");
  await page.unroute("**/api/pcap");

  // 7. No CSP violations or script errors anywhere above.
  assert.deepEqual(errors, [], "browser console errors");
  console.log("UI smoke test passed");
} finally {
  await finish(browser, page, "smoke");
}
