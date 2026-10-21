// Headless browser test of post-mortem mode: threat line, compromised hosts, attack paths,
// paths between two hosts, flow list, domain excludes and the time range.
//   python tests/make_case.py DIR && python -m threatbridge --case DIR --port 5056
//   TB_URL=http://127.0.0.1:5056 node tests/ui_case.mjs [screenshot-dir]
import { chromium } from "playwright";
import assert from "node:assert/strict";

const BASE = process.env.TB_URL || "http://127.0.0.1:5056";
const SHOTS = process.argv[2];
const browser = await chromium.launch(
  process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
const page = await browser.newPage({ viewport: { width: 1400, height: 850 } });
const errors = [];
page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
page.on("pageerror", (e) => errors.push(String(e)));

const cyEval = (fn, arg) => page.evaluate(fn, arg);
const at = (selector, kind) => cyEval(([sel, k]) => {
  const el = window.threatbridge.cy.$(sel)[0];
  const p = k === "edge" ? el.renderedMidpoint() : el.renderedPosition();
  const box = document.getElementById("cy").getBoundingClientRect();
  return { x: p.x + box.left, y: p.y + box.top };
}, [selector, kind]);
const classes = (id) => cyEval((i) => window.threatbridge.cy.getElementById(i).classes(), id);
const menuClick = async (text) => {
  const item = page.locator("#menu li", { hasText: text });
  await item.first().click();
};
const shot = (name) => SHOTS && page.screenshot({ path: `${SHOTS}/${name}.png` });

try {
  await page.goto(`${BASE}/?ip=10.0.0.9&dir=in`);
  await page.waitForFunction(() => window.threatbridge.cy.nodes().length >= 3);

  // Left-click the 10.0.0.5 -> 10.0.0.9 edge: the threat line runs back to the external
  // host and forward to 10.0.0.20, which was not on the map yet.
  let p = await at("edge#10\\.0\\.0\\.5-\\>10\\.0\\.0\\.9", "edge");
  await page.mouse.click(p.x, p.y);
  await page.waitForFunction(() => document.getElementById("status").textContent.startsWith("Threat line"));
  assert.match(await page.textContent("#status"), /1 earlier host\(s\).*1 later host\(s\)/);
  assert.ok((await classes("203.0.113.66")).includes("up"));
  assert.ok((await classes("10.0.0.20")).includes("down"));
  assert.ok((await classes("10.0.0.5->10.0.0.9")).includes("line-selected"));
  assert.ok((await classes("10.0.0.77")).includes("faded"), "inbound peer after the hop is not on the line");
  // The same click lists the connection's flows, oldest first.
  await page.waitForSelector("#flows ol.flows li");
  assert.equal(await page.textContent("#flows .pager span"), "1–1 of 1");
  assert.equal(await page.$eval("#flows ol.flows li", (li) => li.firstChild.textContent),
               "2024-05-01T12:10:00.000Z");
  assert.match(await page.textContent("#flows ol.flows li small"), /^tcp 50001 → 445 · 0\.001 s · 2 pkts · \d+ B$/);
  await shot("threat-line");

  // Clicking the background clears the highlight.
  const box = await page.locator("#cy").boundingBox();
  await page.mouse.click(box.x + 5, box.y + 5);
  assert.equal(await cyEval(() => window.threatbridge.cy.$(".faded, .up, .down").length), 0);

  // Mark the external host (time unknown) and 10.0.0.20 (at its anchor) compromised.
  p = await at("node#203\\.0\\.113\\.66");
  await page.mouse.click(p.x, p.y, { button: "right" });
  await menuClick("Mark compromised (time unknown)");
  await page.waitForFunction(() => document.querySelectorAll("#compromised-list li").length === 1);
  p = await at("node#10\\.0\\.0\\.20");
  await page.mouse.click(p.x, p.y, { button: "right" });
  await menuClick("Mark compromised at");
  await page.waitForFunction(() => document.querySelector("#path-list li.path"));
  assert.deepEqual(await page.$$eval("#path-list li", (l) => l.map((x) => x.innerText.split("\n"))), [
    ["203.0.113.66 → 10.0.0.20: 2 path(s)"],
    ["203.0.113.66 → 10.0.0.5 → 10.0.0.20", "2024-05-01T12:00:00.000Z → 2024-05-01T12:15:00.000Z"],
    ["203.0.113.66 → 10.0.0.5 → 10.0.0.9 → 10.0.0.20", "2024-05-01T12:00:00.000Z → 2024-05-01T12:20:00.000Z"]]);
  assert.equal(await cyEval(() => window.threatbridge.cy.edges(".attack").length), 4);
  assert.ok(await cyEval(() => window.threatbridge.cy.getElementById("10.0.0.20").data("compromised")));
  await page.locator("#path-list li.path").nth(1).click();
  assert.ok((await classes("10.0.0.77")).includes("faded"));
  assert.ok(!(await classes("10.0.0.9")).includes("faded"));
  await shot("attack-path");

  // Unmarking recomputes: no path left.
  await page.locator("#compromised-list li", { hasText: "10.0.0.20" }).locator("button").click();
  await page.waitForFunction(() => !document.querySelector("#path-list li.path"));
  assert.equal(await cyEval(() => window.threatbridge.cy.edges(".attack").length), 0);

  // Every path between two hosts, from the side panel...
  await page.fill("#route-src", "203.0.113.66");
  await page.fill("#route-dst", "10.0.0.20");
  await page.click("#route-form button");
  await page.waitForFunction(() => document.querySelectorAll("#route-list li.path").length === 2);
  assert.equal(await page.textContent("#route-summary"), "2 path(s) from 203.0.113.66 to 10.0.0.20.");
  assert.equal(await cyEval(() => window.threatbridge.cy.edges(".route").length), 4);
  assert.ok((await classes("10.0.0.77")).includes("faded"));
  await shot("paths-between");
  // ... and from the host menu: paths to 10.0.0.9 from the host already entered.
  p = await at("node#10\\.0\\.0\\.9");
  await page.mouse.click(p.x, p.y, { button: "right" });
  await menuClick("Find paths to this host");
  await page.waitForFunction(() => document.getElementById("route-summary").textContent.includes("to 10.0.0.9"));
  assert.deepEqual(await page.$$eval("#route-list li.path", (l) => l.map((x) => x.innerText.split("\n"))), [
    ["203.0.113.66 → 10.0.0.5 → 10.0.0.9", "2024-05-01T12:00:00.000Z → 2024-05-01T12:10:00.000Z"]]);
  await page.mouse.click(box.x + 5, box.y + 5);

  // Exclude a domain: it resolves to 10.0.0.77 from the capture's DNS answers.
  assert.ok(await cyEval(() => window.threatbridge.cy.getElementById("10.0.0.77").nonempty()));
  await page.fill("#exclude-input", "Updates.Example.com");
  await page.press("#exclude-input", "Enter");
  await page.waitForFunction(() => document.querySelector("#exclude-list li"));
  assert.match(await page.textContent("#exclude-list li"), /^updates\.example\.comcapture: 10\.0\.0\.77/);
  assert.ok(await cyEval(() => window.threatbridge.cy.getElementById("10.0.0.77").empty()));
  await shot("domain-exclude");
  await page.locator("#exclude-list li button").click();
  await page.waitForFunction(() => !document.querySelector("#exclude-list li"));

  // A time range limits the map: from 12:20 only the later inbound connection is left.
  await page.fill("#range-from", "2024-05-01T12:20:00Z");
  await page.press("#range-from", "Enter");
  await page.waitForFunction(() => /showing top/.test(document.getElementById("status").textContent));
  assert.match(await page.textContent("#status"),
    /^10\.0\.0\.9: showing top 1 of 1 distinct peer\(s\), 2024-05-01T12:20:00\.000Z → /);
  assert.deepEqual(await cyEval(() => window.threatbridge.cy.nodes().map((n) => n.id()).sort()),
                   ["10.0.0.77", "10.0.0.9"]);
  assert.match(page.url(), /range_from=2024-05-01T12%3A20%3A00Z/);
  await shot("time-range");

  assert.deepEqual(errors, [], "browser console errors");
  console.log("Case-mode UI test passed");
} finally {
  await browser.close();
}
