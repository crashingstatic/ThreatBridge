// Headless browser test of the map's actions in post-mortem mode, beyond ui_case.mjs:
// opening without parameters, errors, left-click expansion, the host menu, the compromised
// form, "Show all" paths, paging a connection's flows, the time range from the URL, Fit, Clear.
//   python tests/make_case.py DIR
//   TB_MAX_PATHS=11 python -m threatbridge --case DIR --port 5056
//   TB_URL=http://127.0.0.1:5056 node tests/ui_actions.mjs [screenshot-dir]
import assert from "node:assert/strict";
import { finish, launch } from "./ui_helpers.mjs";

const BASE = process.env.TB_URL || "http://127.0.0.1:5056";
const SHOTS = process.argv[2];
// The errors this test provokes on purpose (HTTP 400 and 502, an aborted request) are expected.
const { browser, page, errors, at } = await launch({ expected: /status of (400|502)|ERR_FAILED/ });

const cyEval = (fn, arg) => page.evaluate(fn, arg);
const ids = () => cyEval(() => window.threatbridge.cy.nodes().map((n) => n.id()).sort());
const node = (ip) => `node[id = "${ip}"]`;
const edge = (a, b) => `edge[id = "${a}->${b}"]`;
const menu = async (selector, item) => {
  const p = await at(selector);
  await page.mouse.click(p.x, p.y, { button: "right" });
  await page.locator("#menu li", { hasText: item }).first().click();
};
const status = () => page.textContent("#status");
const waitStatus = (re) => page.waitForFunction(
  (src) => new RegExp(src).test(document.getElementById("status").textContent), re.source);
const map = async (ip, direction = "in") => {
  await page.fill("#ip", ip);
  await page.selectOption("#direction", direction);
  await page.click("#go");
  await waitStatus(new RegExp(`^${ip.replace(/\./g, "\\.")}: showing`));
};
const pager = () => page.textContent("#flows .pager span");
const shot = (name) => SHOTS && page.screenshot({ path: `${SHOTS}/${name}.png` });

try {
  // Start clean: no hosts left marked compromised by an earlier test on this server.
  await page.goto(BASE);
  await page.evaluate(async () => {
    const { hosts } = await (await fetch("/api/compromised")).json();
    for (const h of hosts) {
      await fetch("/api/compromised", { method: "DELETE", body: JSON.stringify({ ip: h.ip }),
        headers: { "Content-Type": "application/json", "X-ThreatBridge": "1" } });
    }
  });

  // 1. Opened without parameters: the case summary, an empty map, and the paths hint.
  await page.goto(BASE);
  await waitStatus(/^Case: \d+ flows between \d+ hosts, 2024-/);
  assert.deepEqual(await ids(), []);
  await page.waitForSelector("#path-list li.hint");
  assert.equal(await page.textContent("#path-list li.hint"), "Mark at least two hosts as compromised.");

  // 2. Errors reach the status line, marked as errors.
  await page.fill("#ip", "not-an-ip");
  await page.click("#go");
  await waitStatus(/invalid IP address/);
  assert.equal(await status(), "invalid IP address: 'not-an-ip'");
  assert.ok(await page.$eval("#status", (s) => s.classList.contains("error")));
  await page.fill("#exclude-input", "not valid!");
  await page.press("#exclude-input", "Enter");
  await waitStatus(/invalid IP, CIDR or domain name/);
  await page.fill("#exclude-input", "");

  // 3. Left-click a host: it expands in the selected direction.
  await map("10.0.0.9", "in");
  assert.deepEqual(await ids(), ["10.0.0.5", "10.0.0.77", "10.0.0.9"]);
  const p5 = await at(node("10.0.0.5"));
  await page.mouse.click(p5.x, p5.y);
  await page.waitForFunction(() => window.threatbridge.cy.getElementById("203.0.113.66").nonempty());
  assert.equal(await page.textContent("#detail-body dd"), "10.0.0.5");
  assert.ok(await cyEval(() => window.threatbridge.cy.getElementById("10.0.0.5").data("expandedIn")));

  // 4. The host menu: expand inbound, remove, exclude, mark and unmark.
  await menu(node("10.0.0.9"), "Expand inbound");
  await waitStatus(/^10\.0\.0\.9: showing top 2 of 2 distinct peer/);
  await menu(node("10.0.0.77"), "Remove from map");
  assert.ok(!(await ids()).includes("10.0.0.77"));
  await menu(node("10.0.0.9"), "Remove from map");                  // the IOC host stays
  assert.ok((await ids()).includes("10.0.0.9"));
  await menu(node("203.0.113.66"), "Add to shared exclude list");
  await page.waitForSelector("#exclude-list li >> text=203.0.113.66");
  assert.ok(!(await ids()).includes("203.0.113.66"));
  await page.click("#exclude-list li:has-text('203.0.113.66') button");
  await page.waitForSelector("#exclude-list li", { state: "detached" });
  await menu(node("10.0.0.5"), "Mark compromised (time unknown)");
  await page.waitForSelector("#compromised-list li >> text=10.0.0.5 @ time unknown");
  await menu(node("10.0.0.5"), "Unmark compromised");
  await page.waitForSelector("#compromised-list li", { state: "detached" });

  // 5. "Find paths from this host" with no destination yet: asks for one.
  await page.fill("#route-src", "");
  await page.fill("#route-dst", "");
  await menu(node("10.0.0.9"), "Find paths from this host");
  assert.equal(await page.inputValue("#route-src"), "10.0.0.9");
  assert.equal(await status(), "Now enter the host to find paths to (side panel)");
  assert.equal(await page.evaluate(() => document.activeElement.id), "route-dst");

  // 6. The compromised form, with a time; more paths than the preview; "Show all" to the cap.
  await page.fill("#compromised-ip", "nope");
  await page.click("#compromised-form button");
  await waitStatus(/invalid IP address: 'nope'/);
  await page.fill("#compromised-ip", "10.0.2.1");
  await page.click("#compromised-form button");
  await page.waitForSelector("#compromised-list li >> text=10.0.2.1 @ time unknown");
  await page.fill("#compromised-ip", "10.0.2.2");
  await page.fill("#compromised-time", "2024-05-01T13:00:00Z");
  await page.click("#compromised-form button");
  await page.waitForSelector("#compromised-list li >> text=10.0.2.2 @ 2024-05-01T13:00:00.000Z");
  assert.equal(await page.inputValue("#compromised-ip"), "");
  assert.equal(await page.inputValue("#compromised-time"), "");
  await page.waitForSelector("#path-list li.pair button");
  assert.equal(await page.textContent("#path-list li.pair span"), "10.0.2.1 → 10.0.2.2: first 10 paths");
  assert.equal(await page.$$eval("#path-list li.path", (l) => l.length), 10);
  await page.click("#path-list li.pair button");
  await page.waitForFunction(() => document.querySelectorAll("#route-list li.path").length === 11);
  assert.equal(await page.inputValue("#route-dst-time"), "2024-05-01T13:00:00.000Z");
  assert.match(await page.textContent("#route-summary"),
    /^First 11 paths from 10\.0\.2\.1 to 10\.0\.2\.2, shortest first\. There are more/);
  assert.ok(await page.$eval("#status", (s) => s.classList.contains("warn")));
  await shot("show-all");
  for (const ip of ["10.0.2.1", "10.0.2.2"]) {
    await page.click(`#compromised-list li:has-text('${ip}') button`);
  }
  await page.waitForSelector("#compromised-list li", { state: "detached" });

  // 7. Page through a connection's 120 flows.
  await map("10.0.1.2", "in");
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

  // 8. Narrow the range after mapping: the old connection now has no flows in it.
  await page.fill("#range-to", "2024-05-01T12:00:00Z");
  p = await at(edge("10.0.1.1", "10.0.1.2"), "edge");
  await page.mouse.click(p.x, p.y);
  await page.waitForFunction(() => document.querySelector("#flows .pager span")?.textContent === "none in the time range");
  await page.fill("#range-to", "");

  // 9. A map link that carries a time range.
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
  assert.ok(await page.$eval("#status", (s) => s.classList.contains("error")));
  await page.unroute("**/api/flows?*");
  await page.unroute("**/api/threatline?*");

  // 11. Fit brings every host back into view; Clear empties the map.
  await cyEval(() => window.threatbridge.cy.pan({ x: -5000, y: -5000 }));
  await page.click("#fit");
  assert.ok(await cyEval(() => {
    const cy = window.threatbridge.cy;
    return cy.nodes().every((n) => {
      const q = n.renderedPosition();
      return q.x >= 0 && q.y >= 0 && q.x <= cy.width() && q.y <= cy.height();
    });
  }), "all hosts in view after Fit");
  await page.click("#clear");
  assert.deepEqual(await ids(), []);
  assert.equal(await status(), "");

  assert.deepEqual(errors, [], "browser console errors");
  console.log("UI actions test passed");
} finally {
  await finish(browser, page, "actions");
}
