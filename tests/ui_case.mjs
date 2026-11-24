// Headless browser test of post-mortem mode: threat line, compromised hosts, attack paths,
// paths between two hosts, flow list, domain excludes and the time range.
//   python tests/make_case.py DIR && python -m threatbridge --case DIR --port 5056
//   TB_URL=http://127.0.0.1:5056 node tests/ui_case.mjs [screenshot-dir]
import assert from "node:assert/strict";
import { finish, launch } from "./ui_helpers.mjs";

const BASE = process.env.TB_URL || "http://127.0.0.1:5056";
const SHOTS = process.argv[2];
const { browser, page, errors, at } = await launch({ base: BASE });

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
// A timeline's rows: [part, time, gap, hosts, flow, account] (D30).
const timeline = (within) => page.$$eval(`${within} ol.timeline li`, (l) => l.map((li) => [
  li.className, li.querySelector(".time").textContent, li.querySelector(".gap")?.textContent || "",
  li.querySelector("div").textContent, li.querySelector("small").textContent,
  li.querySelector("small.accounts")?.textContent || ""]));
// What a Copy button puts on the clipboard.
const copied = async (selector) => {
  await page.evaluate(() => { window.copiedText = null; navigator.clipboard.writeText = async (t) => { window.copiedText = t; }; });
  await page.click(selector);
  await page.waitForFunction(() => window.copiedText !== null);
  return page.evaluate(() => window.copiedText);
};
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
  ["203.0.113.66 → 10.0.0.5 → 10.0.0.20", "2024-05-01T12:00:00.000Z → 2024-05-01T12:15:00.000Z", "? → CORP\\alice"],
  ["203.0.113.66 → 10.0.0.5 → 10.0.0.9 → 10.0.0.20", "2024-05-01T12:00:00.000Z → 2024-05-01T12:20:00.000Z",
   "? → CORP\\alice → CORP\\admin"]];

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

  // Machines behind addresses (D27): 10.0.0.5 changed hands at 12:30, so it has a dashed
  // outline; at its time (12:10) it was ws-042, and its details list both machines.
  const outline = (id) => cyEval((i) => {
    const n = window.threatbridge.cy.getElementById(i);
    return `${n.style("outline-width")} ${n.style("outline-style")}`;
  }, id);
  await page.waitForFunction(() => window.threatbridge.cy.getElementById("10.0.0.5").data("shared") === true);
  assert.equal(await outline("10.0.0.5"), "2px dashed");
  assert.equal(await outline("10.0.0.9"), "0px solid");
  const m5 = await at("node#10\\.0\\.0\\.5");
  await page.mouse.click(m5.x, m5.y, { button: "right" });
  await page.keyboard.press("Escape");
  await page.waitForFunction(() => [...document.querySelectorAll("#detail-body dt")].filter((d) => d.textContent === "Held by").length === 2);
  const machineRows = await page.$$eval("#detail-body dt", (dts) => dts.filter((d) => ["Machine", "Held by"].includes(d.textContent))
    .map((d) => [d.textContent, d.nextElementSibling.textContent]));
  assert.deepEqual(machineRows, [
    ["Machine", "ws-042 (00:11:22:33:44:55)"],
    ["Held by", "ws-042 (00:11:22:33:44:55), 2024-05-01T06:00:00.000Z → 2024-05-01T12:30:00.000Z"],
    ["Held by", "laptop-7 (66:77:88:99:aa:bb), 2024-05-01T12:30:00.000Z → end"]]);
  assert.ok(await page.locator("#legend-shared").isVisible());

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
  // Its Community ID: the string Zeek, Suricata and Arkime record for 10.0.0.5:50001 -> 10.0.0.9:445/tcp.
  assert.equal(await page.textContent("#flows ol.flows li code.cid"), "1:8MBOhLc7pAkGPTFKiKHeNLwIK0Q=");
  // The account that made it (D28), from the Windows event on FS01, and the connection's accounts.
  assert.equal(await page.textContent("#flows ol.flows li small.accounts"), "Account: CORP\\alice");
  assert.equal(await page.getAttribute("#flows ol.flows li small.accounts", "title"),
               "CORP\\alice: 4624 (type 3) on FS01.corp.example at 2024-05-01T12:10:01.000Z");
  await page.waitForSelector("#detail-body dd.accounts");
  assert.equal(await page.textContent("#detail-body dd.accounts"), "CORP\\alice (1 flow)");
  // The threat line's timeline (D30), folded under the details: its connections in time order,
  // each with the gap since the one before, its part of the line and its accounts.
  await page.waitForSelector("#line-timeline summary");
  assert.equal(await page.textContent("#line-timeline summary"), "Threat line timeline (3)");
  await page.click("#line-timeline summary");
  assert.deepEqual(await timeline("#line-timeline"), [
    ["up", "2024-05-01T12:00:00.000Z", "", "203.0.113.66 → 10.0.0.5", "1 flow · 443 · TLS", ""],
    ["selected", "2024-05-01T12:10:00.000Z", "+10 min", "10.0.0.5 → 10.0.0.9", "1 flow · 445 · SMB", "Account: CORP\\alice"],
    ["down", "2024-05-01T12:20:00.000Z", "+10 min", "10.0.0.9 → 10.0.0.20", "1 flow · 3389 · RDP", "Account: CORP\\admin"]]);
  assert.deepEqual((await copied("#line-timeline button.copy")).split("\n").slice(0, 2), [
    "First flow\tLast flow\tGap\tFrom\tTo\tPart\tFlows\tDst ports\tProtocols\tAccounts",
    "2024-05-01T12:00:00.000Z\t2024-05-01T12:00:00.000Z\t\t203.0.113.66\t10.0.0.5\tearlier\t1\t443\tTLS\t"]);
  assert.equal(await status(), "Threat line through 10.0.0.5 → 10.0.0.9: timeline copied to clipboard");
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
  // The account changes on the second path's last hop: highlighted.
  assert.deepEqual(await page.$$eval("#path-list li.path", (l) => l.map((x) => x.classList.contains("account-change"))),
                   [false, true]);
  assert.deepEqual(await page.$$eval("#path-list .changed", (l) => l.map((x) => x.textContent)), ["CORP\\admin"]);
  assert.equal(await cyEval(() => window.threatbridge.cy.edges(".attack").length), 4);
  assert.ok(await cyEval(() => window.threatbridge.cy.getElementById("10.0.0.20").data("compromised")));
  await page.locator("#path-list li.path").nth(1).click();
  assert.ok((await classes("10.0.0.77")).includes("faded"));
  assert.ok(!(await classes("10.0.0.9")).includes("faded"));
  assert.equal(await status(), "Attack path 203.0.113.66 → 10.0.0.20, 3 hop(s). Click the background to clear.");
  // Its timeline (D30) in the details panel: each hop's flow, the gap since the hop before, and
  // its account; copied as tab-separated text.
  assert.equal(await page.textContent("#detail-body .timeline-title"),
               "Attack path 203.0.113.66 → 10.0.0.5 → 10.0.0.9 → 10.0.0.20");
  const hops = await timeline("#detail-body");
  assert.deepEqual(hops.map((h) => [h[1], h[2], h[3], h[5]]), [
    ["2024-05-01T12:00:00.000Z", "", "203.0.113.66 → 10.0.0.5", ""],
    ["2024-05-01T12:10:00.000Z", "+10 min", "10.0.0.5 → 10.0.0.9", "Account: CORP\\alice"],
    ["2024-05-01T12:20:00.000Z", "+10 min", "10.0.0.9 → 10.0.0.20", "Account: CORP\\admin"]]);
  assert.match(hops[1][4], /^SMB · tcp 50001 → 445 · 2 pkts · \d+ B$/);
  const tsv = (await copied("#detail-body button.copy")).trimEnd().split("\n").map((l) => l.split("\t"));
  assert.deepEqual(tsv[0], ["Time", "Gap", "From", "To", "Proto", "Src port", "Dst port", "Protocol", "Packets", "Bytes",
                            "Accounts"]);
  assert.deepEqual(tsv.slice(1).map((r) => [r[1], r[2], r[3], r[5], r[6], r[7], r[10]]), [
    ["", "203.0.113.66", "10.0.0.5", "50000", "443", "TLS", ""],
    ["+10 min", "10.0.0.5", "10.0.0.9", "50001", "445", "SMB", "CORP\\alice"],
    ["+10 min", "10.0.0.9", "10.0.0.20", "50002", "3389", "RDP", "CORP\\admin"]]);
  assert.ok(tsv.slice(1).every((r) => r.length === 11 && /^\d+$/.test(r[9])), "bytes as plain numbers");
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
    ["203.0.113.66 → 10.0.0.5 → 10.0.0.9", "2024-05-01T12:00:00.000Z → 2024-05-01T12:10:00.000Z",
     "? → CORP\\alice"]]);
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

  // Outbound in the past and inbound in the future: 10.0.0.20 at 12:17 connected out to
  // 10.0.0.30 at 11:50, and 10.0.0.9 connected to it at 12:20. Each new host is anchored at
  // the connection's time on that side: the last seen going back, the first going forward.
  await page.fill("#range-from", "");
  await page.fill("#ip", "10.0.0.20");
  await page.fill("#ts", "2024-05-01T12:17:00Z");
  await page.selectOption("#direction", "in");
  await page.click("#go");
  await waitStatus(/^10\.0\.0\.20: showing top 1 of 1 distinct peer\(s\)/);
  const anchorOf = (id) => cyEval((i) => window.threatbridge.cy.getElementById(i).data("anchor"), id);
  for (const [item, edge, peer, anchor, span] of [
    ["Expand outbound: who it connected to (past)", "10.0.0.20->10.0.0.30", "10.0.0.30", "2024-05-01T11:50:00.000Z",
     "2024-04-30T12:17:00.000Z → 2024-05-01T12:17:00.000Z"],
    ["Expand inbound: who connected to it (future)", "10.0.0.9->10.0.0.20", "10.0.0.9", "2024-05-01T12:20:00.000Z",
     "2024-05-01T12:17:00.000Z → 2024-05-02T12:17:00.000Z"]]) {
    const host = await at("node#10\\.0\\.0\\.20");
    await page.mouse.click(host.x, host.y, { button: "right" });
    await menuClick(item);
    await waitStatus(new RegExp(`^10\\.0\\.0\\.20: showing top 1 of 1 distinct peer\\(s\\), ${span}$`));
    assert.ok(await cyEval((id) => window.threatbridge.cy.getElementById(id).nonempty(), edge), edge);
    assert.equal(await anchorOf(peer), anchor);
  }

  // Who talked to it (ATK-11). 10.0.0.20 talked with 10.0.0.30 (11:50), 10.0.0.5 (12:15) and
  // 10.0.0.9 (12:20): with N at 1 the earliest goes on the map and the other two are listed;
  // one of them is added from the list.
  await page.fill("#limit", "1");
  await page.fill("#contact-target", "10.0.0.20");
  await page.click("#contact-form button");
  await waitStatus(/^10\.0\.0\.20: 3 inside host\(s\) talked to it/);
  assert.equal(await status(), "10.0.0.20: 3 inside host(s) talked to it, the first at 2024-05-01T11:50:00.000Z; " +
               "1 on the map, 2 listed");
  assert.equal(await page.textContent("#contact-summary"), "10.0.0.20: 3 inside host(s), 2 not on the map:");
  const listed = await page.$$eval("#contact-list li", (l) => l.map((x) => x.innerText.split("\n")[0]));
  assert.deepEqual(listed, ["10.0.0.5", "10.0.0.9"]);
  await page.locator("#contact-list li", { hasText: "10.0.0.5" }).locator("button").click();
  await waitStatus(/^Added 10\.0\.0\.5$/);
  assert.ok(await cyEval(() => window.threatbridge.cy.getElementById("10.0.0.5->10.0.0.20").nonempty()));
  assert.deepEqual(await page.$$eval("#contact-list li", (l) => l.map((x) => x.innerText.split("\n")[0])), ["10.0.0.9"]);
  // From a host's menu, and for a domain through the capture's DNS answers.
  await page.fill("#limit", "50");
  const outside = await at("node#10\\.0\\.0\\.30");
  await page.mouse.click(outside.x, outside.y, { button: "right" });
  await menuClick("Inside hosts that talked to it");
  await waitStatus(/^10\.0\.0\.30: 1 inside host\(s\) talked to it, the first at 2024-05-01T11:50:00\.000Z$/);
  await page.fill("#contact-target", "updates.example.com");
  await page.click("#contact-form button");
  await waitStatus(/^updates\.example\.com: 1 inside host\(s\) talked to it, the first at 2024-05-01T12:30:00\.000Z$/);
  assert.ok(await cyEval(() => window.threatbridge.cy.getElementById("10.0.0.77->10.0.0.9").nonempty()));
  await page.fill("#contact-target", "nothing.example");
  await page.click("#contact-form button");
  await waitStatus(/^nothing\.example: no inside host talked to it \(no address for it in the capture's DNS answers\)$/);

  // Beacons and long connections (ATK-12): listed, added from the list, marked halfway along the
  // connection, and described in its details.
  const entries = (id) => page.$$eval(`#${id} li`, (l) => l.map((x) => x.innerText.split("\n")));
  // The 120 connections ten seconds apart are a beacon too, and a more regular one: first.
  const beacons = await entries("beacon-list");
  assert.deepEqual(beacons.map((e) => e[0]), ["10.0.1.1 → 10.0.1.2", "10.8.0.5 → 198.51.100.9"]);
  assert.equal(beacons[0][1], "every 10 s (±0%) to 8443/tcp, 120 flows, score 1.00");
  assert.match(beacons[1][1], /^every (5[4-9]|6[0-6]) s \(±\d+%\) to 443\/tcp, 30 flows, score 0\.9\d$/);
  assert.deepEqual(await entries("long-list"), [["10.8.0.6 → 198.51.100.10", "1 long flow(s), the longest 2 h", "Add"]]);
  await page.locator("#beacon-list li", { hasText: "10.8.0.5" }).locator("button").click();
  await waitStatus(/^Added 10\.8\.0\.5 → 198\.51\.100\.9$/);
  await page.locator("#long-list li button").click();
  await waitStatus(/^Added 10\.8\.0\.6 → 198\.51\.100\.10$/);
  const marker = (id) => cyEval((i) => window.threatbridge.cy.getElementById(i).style("mid-target-arrow-shape"), id);
  assert.equal(await marker("10.8.0.5->198.51.100.9"), "diamond");
  assert.equal(await marker("10.8.0.6->198.51.100.10"), "square");
  assert.equal(await marker("10.0.0.20->10.0.0.30"), "none");
  const b = await at("edge#10\\.8\\.0\\.5-\\>198\\.51\\.100\\.9", "edge");
  await page.mouse.click(b.x, b.y);
  await page.waitForFunction(() => [...document.querySelectorAll("#detail-body dt")].some((d) => d.textContent === "Beacon"));
  assert.match(await page.$eval("#detail-body", (d) => {
    const dt = [...d.querySelectorAll("dt")].find((x) => x.textContent === "Beacon");
    return dt.nextElementSibling.textContent;
  }), /^every (5[4-9]|6[0-6]) s \(±\d+%\) to 443\/tcp, 30 flows, score 0\.9\d$/);

  assert.deepEqual(errors, [], "browser console errors");
  console.log("Case-mode UI test passed");
} finally {
  await finish(browser, page, "case");
}
