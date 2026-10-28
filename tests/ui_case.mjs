// Headless browser test of post-mortem mode: threat line, compromised hosts, attack paths,
// paths between two hosts, flow list, domain excludes and the time range.
//   python tests/make_case.py DIR && python -m threatbridge --case DIR --port 5056
//   TB_URL=http://127.0.0.1:5056 node tests/ui_case.mjs [screenshot-dir]
import assert from "node:assert/strict";
import { finish, launch } from "./ui_helpers.mjs";

const BASE = process.env.TB_URL || "http://127.0.0.1:5056";
const SHOTS = process.argv[2];
const { browser, page, errors, at } = await launch();

const cyEval = (fn, arg) => page.evaluate(fn, arg);
const classes = (id) => cyEval((i) => window.threatbridge.cy.getElementById(i).classes(), id);
const menuClick = async (text) => {
  const item = page.locator("#menu li", { hasText: text });
  await item.first().click();
};
const shot = (name) => SHOTS && page.screenshot({ path: `${SHOTS}/${name}.png` });
const status = () => page.textContent("#status");
const waitStatus = (re) => page.waitForFunction(
  (src) => new RegExp(src).test(document.getElementById("status").textContent), re.source);
const pathList = () => page.$$eval("#path-list li", (l) => l.map((x) => x.innerText.split("\n")));
const routeList = () => page.$$eval("#route-list li", (l) => l.map((x) => x.innerText.split("\n")));
const findRoutes = async (src, srcTime, dst, dstTime) => {
  await page.fill("#route-src", src);
  await page.fill("#route-src-time", srcTime);
  await page.fill("#route-dst", dst);
  await page.fill("#route-dst-time", dstTime);
  await page.$eval("#route-summary", (s) => { s.textContent = ""; });     // to see the new answer arrive
  await page.click("#route-form button");
  await page.waitForFunction(([s, d]) => document.getElementById("route-summary").textContent
    .includes(` from ${s} to ${d}.`), [src, dst]);
};
const remap = async () => {          // Map again; its attack paths are recomputed too
  await page.click("#go");
  await waitStatus(/^10\.0\.0\.9: showing/);
};
const TWO_PATHS = [
  ["203.0.113.66 → 10.0.0.20: 2 path(s)"],
  ["203.0.113.66 → 10.0.0.5 → 10.0.0.20", "2024-05-01T12:00:00.000Z → 2024-05-01T12:15:00.000Z"],
  ["203.0.113.66 → 10.0.0.5 → 10.0.0.9 → 10.0.0.20", "2024-05-01T12:00:00.000Z → 2024-05-01T12:20:00.000Z"]];

const protocolOptions = () => page.$$eval("#protocol option", (l) => l.map((o) => [o.value, o.textContent]));
const style = (id, prop) => cyEval(([i, p]) => window.threatbridge.cy.getElementById(i).style(p), [id, prop]);

try {
  await page.goto(`${BASE}/?ip=10.0.0.9&dir=in`);
  await page.waitForFunction(() => window.threatbridge.cy.nodes().length >= 3);

  // The protocol drop-down lists the protocols on the map's connections, by name. Choosing one
  // makes the connections carrying it glow and the others fade.
  await page.waitForFunction(() => document.querySelectorAll("#protocol option").length === 3);
  assert.deepEqual(await protocolOptions(), [["", "All"], ["http", "HTTP"], ["smb", "SMB"]]);
  await page.selectOption("#protocol", "smb");
  assert.ok((await classes("10.0.0.5->10.0.0.9")).includes("proto-hit"));
  assert.ok((await classes("10.0.0.77->10.0.0.9")).includes("proto-dim"));
  assert.equal(await style("10.0.0.77->10.0.0.9", "opacity"), "0.2");
  assert.equal(await style("10.0.0.5->10.0.0.9", "underlay-color"), "rgb(255,224,102)");
  // Expanded again, a connection already drawn may carry more (say, the analyst changed the
  // window): the drop-down follows, with no connection added or removed.
  await page.route("**/api/neighbors?*", async (route) => {
    const r = await route.fetch();
    const json = await r.json();
    for (const peer of json.peers) if (peer.peer === "10.0.0.5") peer.protocols = ["dce_rpc", "smb"];
    await route.fulfill({ response: r, json });
  });
  const root = await at("node#10\\.0\\.0\\.9");
  await page.mouse.click(root.x, root.y, { button: "right" });
  await menuClick("Expand inbound: who connected to it (past)");
  await page.waitForFunction(() => document.querySelectorAll("#protocol option").length === 4);
  assert.deepEqual(await protocolOptions(), [["", "All"], ["dce_rpc", "DCE-RPC"], ["http", "HTTP"], ["smb", "SMB"]]);
  assert.equal(await page.inputValue("#protocol"), "smb");
  await remap();                                                    // mapping again keeps the choice
  assert.equal(await page.inputValue("#protocol"), "smb");
  // A choice no connection carries any more holds, says so, and fades every connection, until
  // another is chosen.
  await page.selectOption("#protocol", "dce_rpc");
  await page.unroute("**/api/neighbors?*");
  await remap();
  await page.waitForFunction(() => document.querySelector("#protocol option[value=dce_rpc]")?.textContent ===
                                   "DCE-RPC (not on the map)");
  assert.equal(await page.inputValue("#protocol"), "dce_rpc");
  assert.equal(await cyEval(() => window.threatbridge.cy.edges().not(".proto-dim").length), 0);
  await page.selectOption("#protocol", "smb");
  assert.deepEqual(await protocolOptions(), [["", "All"], ["http", "HTTP"], ["smb", "SMB"]]);

  // Left-click the 10.0.0.5 -> 10.0.0.9 edge: the threat line runs back to the external
  // host and forward to 10.0.0.20, which was not on the map yet.
  let p = await at("edge#10\\.0\\.0\\.5-\\>10\\.0\\.0\\.9", "edge");
  await page.mouse.click(p.x, p.y);
  await page.waitForFunction(() => document.getElementById("status").textContent.startsWith("Threat line"));
  assert.equal(await status(), "Threat line through 10.0.0.5 → 10.0.0.9: 1 earlier host(s) (violet), " +
    "1 later host(s) (teal); ≤ 6 hops, ≤ 24h between hops. Click the background to clear.");
  assert.ok((await classes("203.0.113.66")).includes("up"));
  assert.ok((await classes("10.0.0.20")).includes("down"));
  assert.ok((await classes("10.0.0.5->10.0.0.9")).includes("line-selected"));
  assert.ok((await classes("10.0.0.77")).includes("faded"), "inbound peer after the hop is not on the line");
  // The line's new connections join the drop-down, and the choice holds: SMB still glows (even
  // where the line fades the map), the new ones fade.
  await page.waitForFunction(() => document.querySelectorAll("#protocol option").length === 5);
  assert.deepEqual(await protocolOptions(),
                   [["", "All"], ["http", "HTTP"], ["rdp", "RDP"], ["smb", "SMB"], ["ssl", "TLS"]]);
  assert.equal(await page.inputValue("#protocol"), "smb");
  assert.ok((await classes("203.0.113.66->10.0.0.5")).includes("proto-dim"));
  assert.ok((await classes("10.0.0.9->10.0.0.20")).includes("proto-dim"));
  await page.selectOption("#protocol", "ssl");
  assert.deepEqual([await style("203.0.113.66->10.0.0.5", "opacity"), await style("10.0.0.5->10.0.0.9", "opacity")],
                   ["1", "0.2"]);
  await page.selectOption("#protocol", "http");                    // glows though the line faded it
  assert.ok((await classes("10.0.0.77->10.0.0.9")).includes("faded"));
  assert.equal(await style("10.0.0.77->10.0.0.9", "opacity"), "1");
  await page.selectOption("#protocol", "");                       // All: no filter
  assert.equal(await cyEval(() => window.threatbridge.cy.$(".proto-hit, .proto-dim").length), 0);
  // The same click lists the connection's flows, oldest first.
  await page.waitForSelector("#flows ol.flows li");
  assert.equal(await page.textContent("#flows .pager span"), "1–1 of 1");
  assert.equal(await page.$eval("#flows ol.flows li", (li) => li.firstChild.textContent),
               "2024-05-01T12:10:00.000Z");
  assert.match(await page.textContent("#flows ol.flows li small"), /^SMB · tcp 50001 → 445 · 0\.001 s · 2 pkts · \d+ B$/);
  assert.equal(await page.locator("#flows a, #flows button:has-text('PCAP')").count(), 0);   // no PCAP for case files
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
  assert.deepEqual(await pathList(), TWO_PATHS);
  await waitStatus(/^2 attack path\(s\) between 2 compromised host\(s\)$/);
  assert.equal(await cyEval(() => window.threatbridge.cy.edges(".attack").length), 4);
  assert.ok(await cyEval(() => window.threatbridge.cy.getElementById("10.0.0.20").data("compromised")));
  await page.locator("#path-list li.path").nth(1).click();
  assert.ok((await classes("10.0.0.77")).includes("faded"));
  assert.ok(!(await classes("10.0.0.9")).includes("faded"));
  assert.equal(await status(), "Attack path 203.0.113.66 → 10.0.0.20, 3 hop(s). Click the background to clear.");
  await shot("attack-path");

  // Excluded hosts are never crossed: without 10.0.0.5 there is no path, and back with it.
  await page.fill("#exclude-input", "10.0.0.5");
  await page.press("#exclude-input", "Enter");
  await page.waitForSelector("#path-list li.hint >> text=No time-consistent path between the marked hosts.");
  assert.equal(await cyEval(() => window.threatbridge.cy.edges(".attack").length), 0);
  assert.ok(await cyEval(() => window.threatbridge.cy.getElementById("10.0.0.5").empty()));
  await page.click("#exclude-list li:has-text('10.0.0.5') button");
  await page.waitForFunction(() => document.querySelectorAll("#path-list li.path").length === 2);
  assert.deepEqual(await pathList(), TWO_PATHS);

  // The Window and the time range limit the attack paths: hops 10 min apart pass a 10m Window,
  // the 15-min shortcut doesn't, and none start after 12:05.
  await page.fill("#window", "10m");
  await remap();
  await page.waitForFunction(() => document.querySelectorAll("#path-list li.path").length === 1);
  assert.deepEqual(await pathList(), [["203.0.113.66 → 10.0.0.20: 1 path(s)"], TWO_PATHS[2]]);
  await page.fill("#window", "24h");
  await page.fill("#range-from", "2024-05-01T12:05:00Z");
  await remap();
  await page.waitForSelector("#path-list li.hint >> text=No time-consistent path between the marked hosts.");
  await page.fill("#range-from", "");
  await remap();
  await page.waitForFunction(() => document.querySelectorAll("#path-list li.path").length === 2);

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
  assert.equal(await status(), "2 path(s) from 203.0.113.66 to 10.0.0.20. At most 6 hops, 24h between hops. " +
                               "Click the background to clear.");
  assert.equal(await cyEval(() => window.threatbridge.cy.edges(".route").length), 4);
  assert.ok((await classes("10.0.0.77")).includes("faded"));
  await shot("paths-between");
  // The IOC times: the first hop must leave after the first's, the path reach the second by its.
  await findRoutes("203.0.113.66", "2024-05-01T12:05:00Z", "10.0.0.20", "");
  assert.equal(await page.textContent("#route-summary"), "0 path(s) from 203.0.113.66 to 10.0.0.20.");
  assert.deepEqual(await routeList(), [["No time-consistent path."]]);
  assert.equal(await status(), "0 path(s) from 203.0.113.66 to 10.0.0.20. At most 6 hops, 24h between hops.");
  assert.equal(await cyEval(() => window.threatbridge.cy.edges(".route").length), 0);
  await findRoutes("203.0.113.66", "", "10.0.0.20", "2024-05-01T12:17:00Z");
  assert.equal(await page.textContent("#route-summary"), "1 path(s) from 203.0.113.66 to 10.0.0.20.");
  assert.deepEqual(await routeList(), [TWO_PATHS[1]]);
  await findRoutes("10.0.0.20", "", "203.0.113.66", "");                 // the other way: none
  assert.equal(await page.textContent("#route-summary"), "0 path(s) from 10.0.0.20 to 203.0.113.66.");
  await page.fill("#route-dst", "");
  await page.click("#route-form button");
  await waitStatus(/^Enter both hosts to find the paths between them$/);
  assert.ok(await page.$eval("#status", (s) => s.classList.contains("error")));
  await findRoutes("203.0.113.66", "", "10.0.0.20", "");
  // ... and from the host menu: paths to 10.0.0.9 from the host already entered.
  p = await at("node#10\\.0\\.0\\.9");
  await page.mouse.click(p.x, p.y, { button: "right" });
  await menuClick("Find paths to this host");
  await page.waitForFunction(() => document.getElementById("route-summary").textContent.includes("to 10.0.0.9"));
  assert.deepEqual(await page.$$eval("#route-list li.path", (l) => l.map((x) => x.innerText.split("\n"))), [
    ["203.0.113.66 → 10.0.0.5 → 10.0.0.9", "2024-05-01T12:00:00.000Z → 2024-05-01T12:10:00.000Z"]]);
  assert.equal(await cyEval(() => window.threatbridge.cy.edges(".route").length), 2);   // the old ones cleared
  await page.locator("#route-list li.path").click();
  assert.equal(await status(), "Path 203.0.113.66 → 10.0.0.9, 2 hop(s). Click the background to clear.");
  await page.mouse.click(box.x + 5, box.y + 5);

  // Exclude a domain: it resolves to 10.0.0.77 from the capture's DNS answers.
  assert.ok(await cyEval(() => window.threatbridge.cy.getElementById("10.0.0.77").nonempty()));
  await page.fill("#exclude-input", "Updates.Example.com");
  await page.press("#exclude-input", "Enter");
  await page.waitForFunction(() => document.querySelector("#exclude-list li"));
  assert.match(await page.textContent("#exclude-list li"), /^updates\.example\.comcapture: 10\.0\.0\.77/);
  assert.ok(await cyEval(() => window.threatbridge.cy.getElementById("10.0.0.77").empty()));
  assert.equal(await status(), "Excluded updates.example.com (1 address(es)) for everyone");
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
  await finish(browser, page, "case");
}
