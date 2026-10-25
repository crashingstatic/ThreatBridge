// Headless browser smoke test against a demo-backend server.
//   TB_URL=http://127.0.0.1:5055 node tests/ui_smoke.mjs [screenshot-dir]
// Needs the `playwright` npm package (see ui_helpers.mjs).
import assert from "node:assert/strict";
import { checkpoint, finish, launch } from "./ui_helpers.mjs";

const BASE = process.env.TB_URL || "http://127.0.0.1:5055";
const SHOTS = process.argv[2];
const SOC = "https://so.example";   // must match TB_SOC_URL of the server under test
const IOC = "10.0.0.5", IOC_TIME = "2024-05-01T12:00:00Z";

const { browser, ctx, page, errors, at } = await launch(
  { context: { permissions: ["clipboard-read", "clipboard-write"] } });
await ctx.route(`${SOC}/**`, (r) => r.fulfill({ body: "SOC stub" }));
const menuItems = () => page.$$eval("#menu li", (l) => l.map((x) => x.textContent));

try {
  // 1. Launch the way a SOC action does.
  await page.goto(`${BASE}/?ip=${IOC}&ts=${IOC_TIME}&dir=in`);
  await page.waitForFunction(() => window.threatbridge.cy.edges().length > 0);
  assert.match(await page.textContent("#status"), /showing top/);
  assert.ok(await page.evaluate(() => window.threatbridge.cy.edges("[direction='out']").length === 0));

  // 2. Right-click a peer -> expand outbound (future).
  const peer = await at("node[!root]", "node");
  await page.mouse.click(peer.x, peer.y, { button: "right" });
  assert.equal((await menuItems())[0].split(" @ ")[0], peer.id, "node menu belongs to clicked node");
  await page.click("text=Expand outbound");
  await page.waitForFunction(() => window.threatbridge.cy.edges("[direction='out']").length > 0);
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/map.png` });

  // 3. Right-click the IOC's inbound edge -> SOC pivot bounded at the IOC time.
  const edge = await at(`edge[direction='in'][target='${IOC}']`, "edge");
  await page.mouse.click(edge.x, edge.y, { button: "right" });
  const [a, b] = edge.id.split("->");
  assert.equal((await menuItems())[0], `${a} ↔ ${b}`, "edge menu belongs to clicked edge");
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/edge-menu.png` });
  const [popup] = await Promise.all([ctx.waitForEvent("page"),
                                      page.click("text=Filter SOC Dashboards")]);
  const url = decodeURIComponent(popup.url());
  assert.ok(url.startsWith(`${SOC}/#/dashboards?q=`), url);
  assert.ok(url.includes(`(source.ip:"${a}" AND destination.ip:"${b}")`), url);
  assert.ok(url.includes(`(source.ip:"${b}" AND destination.ip:"${a}")`), url);
  assert.ok(url.includes('@timestamp:[* TO "2024-05-01T12:00:00.000Z"]'), url);

  // The details panel lists the connection's flows, oldest first.
  await page.waitForSelector("#flows ol.flows li");
  const starts = await page.$$eval("#flows ol.flows li", (l) => l.map((x) => x.firstChild.textContent));
  assert.deepEqual(starts, [...starts].sort());
  assert.match(await page.textContent("#flows .pager span"), /^1–\d+ of [\d,]+$/);
  await popup.close();

  // Each flow links to SOC's PCAP job for it; no download without a SOC API client.
  const pcap = page.locator("#flows ol.flows li").first().locator("a", { hasText: "PCAP in SOC" });
  const pcapUrl = new URL(await pcap.getAttribute("href"));
  assert.equal(`${pcapUrl.origin}${pcapUrl.pathname}`, `${SOC}/joblookup`);
  assert.match(pcapUrl.searchParams.get("esid"), /^demo[0-9a-f]{16}$/);
  assert.equal(pcapUrl.searchParams.get("time"), starts[0]);
  assert.equal(await pcap.getAttribute("target"), "_blank");
  const [pcapPopup] = await Promise.all([ctx.waitForEvent("page"), pcap.click()]);
  assert.ok(pcapPopup.url().startsWith(`${SOC}/joblookup?esid=`));
  await pcapPopup.close();
  assert.equal(await page.locator("#flows button", { hasText: "Download PCAP" }).count(), 0);

  // 3b. The same menu copies the query instead; the host menu opens the host in SOC.
  // (The status line now holds the long query and wraps, moving the map: find the edge again.)
  const again = await at(`edge[id = "${edge.id}"]`, "edge");
  await page.mouse.click(again.x, again.y, { button: "right" });
  await page.click("text=Copy SOC query");
  await page.waitForFunction(() => document.getElementById("status").textContent === "SOC query copied to clipboard");
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  assert.ok(copied.startsWith(`((source.ip:"${a}" AND destination.ip:"${b}")`), copied);
  const host = await at("node[?root]", "node");
  await page.mouse.click(host.x, host.y, { button: "right" });
  const [hostPopup] = await Promise.all([ctx.waitForEvent("page"),
                                          page.click("text=Open host in SOC dashboard")]);
  const hostUrl = decodeURIComponent(hostPopup.url());
  assert.ok(hostUrl.includes(`(source.ip:"${IOC}" OR destination.ip:"${IOC}") | groupby`), hostUrl);
  await hostPopup.close();

  // 4. Shared exclude list round-trip through the UI.
  await page.fill("#exclude-input", "10.200.0.0/16");
  await page.click("#exclude-form button");
  await page.waitForSelector("#exclude-list li >> text=10.200.0.0/16");
  await page.click("#exclude-list li:has-text('10.200.0.0/16') button");
  await page.waitForSelector("#exclude-list li >> text=10.200.0.0/16", { state: "detached" });

  // 5. A time range narrows the next map.
  await page.fill("#range-from", "2024-05-01T11:00:00Z");
  await page.press("#range-from", "Enter");
  await page.waitForFunction(() => document.getElementById("status").textContent
    .includes("2024-05-01T11:00:00.000Z → 2024-05-01T12:00:00.000Z"));

  // 6. With a SOC API client, ThreatBridge downloads a flow's PCAP itself.
  await page.route("**/api/config", async (route) => {
    const r = await route.fetch();
    route.fulfill({ response: r, json: Object.assign(await r.json(), { pcap_download: true }) });
  });
  let asked = null;
  await page.route("**/api/pcap", (route) => {
    asked = route.request().postDataJSON();
    route.fulfill({ status: 200, contentType: "application/vnd.tcpdump.pcap", body: Buffer.from("d4c3b2a1" + "00".repeat(20), "hex") });
  });
  await checkpoint(page, "smoke-1");
  await page.goto(`${BASE}/?ip=${IOC}&ts=${IOC_TIME}&dir=in`);
  await page.waitForFunction(() => window.threatbridge.cy.edges().length > 0);
  const inbound = await at(`edge[direction='in'][target='${IOC}']`, "edge");
  await page.mouse.click(inbound.x, inbound.y);
  const download = page.locator("#flows ol.flows li").first().locator("button", { hasText: "Download PCAP" });
  await download.waitFor();
  const first = await page.$eval("#flows ol.flows li", (li) => li.firstChild.textContent);
  const [file] = await Promise.all([page.waitForEvent("download"), download.click()]);
  assert.equal(file.suggestedFilename(), `${inbound.id.replace("->", "_")}_${first}.pcap`.replace(/:/g, "-"));
  assert.equal(asked.time, first);
  assert.match(asked.id, /^demo[0-9a-f]{16}$/);
  await page.waitForFunction(() => /: 24 B$/.test(document.getElementById("status").textContent));
  await page.unroute("**/api/config");
  await page.unroute("**/api/pcap");

  // 7. No CSP violations or script errors anywhere above.
  assert.deepEqual(errors, [], "browser console errors");
  console.log("UI smoke test passed");
} finally {
  await finish(browser, page, "smoke");
}
