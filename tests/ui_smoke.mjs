// Headless browser smoke test against a demo-backend server.
//   TB_URL=http://127.0.0.1:5055 node tests/ui_smoke.mjs [screenshot-dir]
// Needs the `playwright` npm package. Set CHROMIUM_PATH to use a preinstalled browser.
import { chromium } from "playwright";
import assert from "node:assert/strict";

const BASE = process.env.TB_URL || "http://127.0.0.1:5055";
const SHOTS = process.argv[2];
const SOC = "https://so.example";   // must match TB_SOC_URL of the server under test
const IOC = "10.0.0.5", IOC_TIME = "2024-05-01T12:00:00Z";

const browser = await chromium.launch(
  process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
const ctx = await browser.newContext({ viewport: { width: 1400, height: 850 } });
await ctx.route(`${SOC}/**`, (r) => r.fulfill({ body: "SOC stub" }));
const page = await ctx.newPage();
const errors = [];
page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
page.on("pageerror", (e) => errors.push(String(e)));

// Screen coordinates of a graph element (node centre or edge midpoint).
const at = (selector, kind) => page.evaluate(([sel, k]) => {
  const el = window.threatbridge.cy.$(sel)[0];
  const p = k === "edge" ? el.renderedMidpoint() : el.renderedPosition();
  const box = document.getElementById("cy").getBoundingClientRect();
  return { x: p.x + box.left, y: p.y + box.top, id: el.id() };
}, [selector, kind]);
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

  // 6. No CSP violations or script errors anywhere above.
  assert.deepEqual(errors, [], "browser console errors");
  console.log("UI smoke test passed");
} finally {
  await browser.close();
}
