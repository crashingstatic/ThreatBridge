// Headless browser test of marks, suspect connections and filters (case mode): marking hosts
// and single flows, what the marks hide and how it looks, unmarking, typed filters and their
// list, re-running the map's queries, Apply as filter, Clear, the CSV export, other analysts'
// marks appearing, and an opened map's own marks until shared.
//   python tests/make_case.py DIR && python -m threatbridge --case DIR --port 5056
//   TB_URL=http://127.0.0.1:5056 node tests/ui_marks.mjs [screenshot-dir]
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { finish, keepMap, launch } from "./ui_helpers.mjs";

const BASE = process.env.TB_URL || "http://127.0.0.1:5056";
const SHOTS = process.argv[2];
// The invalid filter this test types is answered with HTTP 400, on purpose.
const { browser, ctx, page, errors, at } = await launch({ expected: /status of 400/ });

const E = "10.9.0.1", A = "10.9.0.2", X = "10.9.0.3", B = "10.9.0.4", C = "10.9.0.5", F = "10.9.0.6", Y = "10.9.0.7";
const R1 = "10.9.1.1", R2 = "10.9.1.2";
const cyEval = (fn, arg) => page.evaluate(fn, arg);
const edge = (a, b) => `edge[id = "${a}->${b}"]`;
const node = (ip) => `node[id = "${ip}"]`;
const classes = (id) => cyEval((i) => window.threatbridge.cy.getElementById(i).classes(), id);
const style = (id, prop) => cyEval(([i, p]) => window.threatbridge.cy.getElementById(i).style(p), [id, prop]);
const waitStatus = (re) => page.waitForFunction(
  (src) => new RegExp(src).test(document.getElementById("status").textContent), re.source);
const settled = () => page.waitForFunction(() => !window.threatbridge.settling());
const hiddenNote = async () => { await settled(); return page.textContent("#hidden-note"); };
const hidden = () => cyEval(() => window.threatbridge.cy.elements(".mark-hidden").map((e) => e.id()).sort());
const edgeIds = () => cyEval(() => window.threatbridge.cy.edges().map((e) => e.id()).sort());
const nodeIds = () => cyEval(() => window.threatbridge.cy.nodes().map((n) => n.id()).sort());
const listed = (sel) => page.$$eval(sel, (l) => l.map((x) => x.innerText.split("\n").filter((t) => t)));
const menuItems = () => page.$$eval("#menu li", (l) => l.map((x) => x.textContent));
const menu = async (selector, item, kind) => {
  const p = await at(selector, kind);
  await page.mouse.click(p.x, p.y, { button: "right" });
  await page.locator("#menu li", { hasText: item }).first().click();
};
const shared = async () => (await (await page.request.get(`${BASE}/api/compromised`)).json());
const shot = (name) => SHOTS && page.screenshot({ path: `${SHOTS}/${name}.png` });
const DARK_RED = "rgb(180,35,42)";
const ALL = [`${A}->${X}`, `${A}->${Y}`, `${B}->${F}`, `${E}->${A}`, `${R1}->${R2}`, `${X}->${B}`, `${X}->${C}`].sort();
const typeFilter = async (text) => {
  await page.fill("#filter", text);
  await page.press("#filter", "Enter");
};

try {
  // Start clean: no marks or saved maps left by an earlier test on this server.
  await page.request.put(`${BASE}/api/compromised`, { headers: { "X-ThreatBridge": "1" }, data: {} });
  await page.request.delete(`${BASE}/api/sessions`, { headers: { "X-ThreatBridge": "1" }, data: { name: "story" } });
  await page.goto(BASE);
  await page.waitForFunction(() => /^Case: /.test(document.getElementById("status").textContent));

  // The map: A's connections out from 12:00, the threat line through A -> X (E before it, B, C
  // and F after), and the path 10.9.1.1 -> 10.9.1.2, a part of the map of its own.
  await page.fill("#ip", A);
  await page.fill("#ts", "2024-05-01T12:00:00Z");
  await page.selectOption("#direction", "out");
  await page.fill("#window", "1h");
  await page.click("#go");
  await waitStatus(/^10\.9\.0\.2: showing top 2 of 2 distinct peer/);
  let p = await at(edge(A, X), "edge");
  await page.mouse.click(p.x, p.y);
  await waitStatus(/^Threat line through 10\.9\.0\.2 → 10\.9\.0\.3/);
  const box = await page.locator("#cy").boundingBox();
  await page.mouse.click(box.x + 5, box.y + 5);
  await page.fill("#route-src", R1);
  await page.fill("#route-dst", R2);
  await page.click("#route-form button");
  await page.waitForFunction(() => document.getElementById("route-summary").textContent.startsWith("1 path(s)"));
  await page.mouse.click(box.x + 5, box.y + 5);
  assert.deepEqual(await edgeIds(), ALL);
  assert.equal(await hiddenNote(), "");

  // Marking B: only the line into it (E -> A -> X -> B) and on from it (B -> F) stay, dashed
  // dark red, outlined light red. X -> C and A -> Y are hidden, and C and Y with them; the
  // other part of the map is left as it is (ATK-7, INT-7).
  await menu(node(B), "Mark compromised (time unknown)");
  await page.waitForSelector(`#compromised-list li >> text=${B} @ time unknown`);
  assert.equal(await hiddenNote(), "2 connection(s) hidden by marks");
  assert.deepEqual(await hidden(), [`${A}->${Y}`, `${X}->${C}`, C, Y].sort());
  for (const id of [`${E}->${A}`, `${A}->${X}`, `${X}->${B}`, `${B}->${F}`]) {
    assert.ok((await classes(id)).includes("suspect"), id);
    assert.deepEqual([await style(id, "line-style"), await style(id, "line-color"), await style(id, "line-outline-color")],
                     ["dashed", DARK_RED, "rgb(255,138,138)"], id);
  }
  assert.ok(!(await classes(`${R1}->${R2}`)).includes("suspect"));
  assert.equal(await style(`${X}->${C}`, "display"), "none");
  // Hidden connections leave the protocol drop-down too.
  assert.deepEqual(await page.$$eval("#protocol option", (l) => l.map((o) => o.value)), ["", "rdp", "smb", "ssh", "ssl"]);
  // The legend says what each line is.
  assert.deepEqual(await page.$$eval(".legend > span", (l) => l.map((x) => x.textContent.trim()).slice(3, 6)),
                   ["compromised", "marked connection", "suspect connection"]);
  await shot("marked-host");

  // A single-flow connection's menu marks its flow: A -> X turns solid, and A and X are
  // marked through it, reached at its start. From A and X, A -> Y and X -> C came after:
  // nothing is hidden now (ATK-5, INT-8).
  await menu(edge(A, X), "Mark compromised", "edge");
  await page.waitForSelector(`#marked-flow-list li >> text=${A} → ${X} @ 2024-05-01T12:06:40.000Z`);
  assert.equal(await hiddenNote(), "");
  assert.ok((await classes(`${A}->${X}`)).includes("marked"));
  assert.ok(!(await classes(`${A}->${X}`)).includes("suspect"));
  assert.equal(await style(`${A}->${X}`, "line-style"), "solid");
  assert.equal(await style(`${A}->${X}`, "line-outline-color"), "rgb(255,138,138)");
  // On the attack paths now between A, X and B, it is drawn in their red; solid, as marked.
  assert.equal(await style(`${A}->${X}`, "line-color"), "rgb(255,77,94)");
  assert.equal(await style(`${X}->${B}`, "line-style"), "dashed");
  assert.deepEqual(await listed("#compromised-list li"), [
    [`${B} @ time unknown`, "Remove"],
    [`${A} @ 2024-05-01T12:06:40.000Z`, "through 1 marked flow(s)", "Remove"],
    [`${X} @ 2024-05-01T12:06:40.000Z`, "through 1 marked flow(s)", "Remove"]]);
  assert.deepEqual(await listed("#marked-flow-list li"),
                   [[`${A} → ${X} @ 2024-05-01T12:06:40.000Z`, "tcp 50151 → 445", "Remove"]]);
  p = await at(edge(A, X), "edge");
  await page.mouse.click(p.x, p.y, { button: "right" });
  assert.deepEqual(await menuItems(), [`${A} ↔ ${X}`, "Unmark compromised"]);
  await page.keyboard.press("Escape");
  const rows = await page.$$eval("#detail-body dl > *", (l) => l.map((x) => x.textContent));
  assert.deepEqual(rows.slice(-2), ["Marks keep", "1 marked, 0 suspect of 1"]);
  await shot("marked-flow");

  // In a connection's flow list, each flow can be marked and unmarked (INT-8).
  p = await at(edge(B, F), "edge");
  await page.mouse.click(p.x, p.y, { button: "right" });
  await page.keyboard.press("Escape");
  await page.click("#flows ol.flows li button.mark");
  await page.waitForSelector(`#marked-flow-list li >> text=${B} → ${F}`);
  assert.equal(await page.textContent("#flows ol.flows li button.mark"), "Unmark");
  assert.ok((await shared()).flows.some((f) => f.src === B && f.dst === F));
  await page.click("#flows ol.flows li button.mark");
  await page.waitForFunction(() => document.querySelectorAll("#marked-flow-list li").length === 1);
  assert.equal(await page.textContent("#flows ol.flows li button.mark"), "Mark compromised");

  // Unmarking X takes its marked flow with it, so A goes too: back to B's lines (ATK-6).
  await menu(node(X), "Unmark compromised");
  await page.waitForFunction(() => document.querySelectorAll("#compromised-list li").length === 1);
  assert.deepEqual((await shared()).flows, []);
  assert.equal(await hiddenNote(), "2 connection(s) hidden by marks");

  // A filter that can't be read is not applied: the box turns light red and the status says
  // why. Typing again clears the red (FIL-S6).
  await typeFilter("smb");
  await waitStatus(/^at character 1: protocol names are case-sensitive: write SMB$/);
  assert.ok(await page.$eval("#status", (s) => s.classList.contains("error")));
  assert.ok(await page.$eval("#filter", (i) => i.classList.contains("invalid")));
  assert.equal(await page.$eval("#filter", (i) => getComputedStyle(i).backgroundColor), "rgb(255, 205, 210)");
  assert.equal(await page.locator("#filter-list li").count(), 0);
  assert.deepEqual(await edgeIds(), ALL);
  await page.type("#filter", "x");
  assert.ok(!(await page.$eval("#filter", (i) => i.classList.contains("invalid"))));

  // A filter re-runs the map's queries: without RDP, the threat line stops at X; B, marked,
  // stays with no connection; F goes. The map is laid out again (FIL-S7, INT-10).
  await typeFilter("NOT RDP");
  await waitStatus(/^Re-ran 3 of 3 queries with 1 filter\(s\): 8 host\(s\), 5 connection\(s\)$/);
  assert.equal(await page.inputValue("#filter"), "");
  assert.deepEqual(await listed("#filter-list li"), [["NOT RDP", "×"]]);
  assert.deepEqual(await edgeIds(), [`${A}->${X}`, `${A}->${Y}`, `${E}->${A}`, `${R1}->${R2}`, `${X}->${C}`].sort());
  assert.deepEqual(await nodeIds(), [E, A, X, B, C, Y, R1, R2].sort());
  assert.equal(await hiddenNote(), "");                 // B is a part of its own, with nothing to hide
  const spots = await cyEval(() => new Set(window.threatbridge.cy.nodes().map((n) => `${n.position().x},${n.position().y}`)).size);
  assert.equal(spots, 8, "laid out: every host has its own place");
  await shot("filtered");
  // Removing it brings the map back, with B's lines and what they hide.
  await page.click("#filter-list li button");
  await waitStatus(/^Re-ran 3 of 3 queries with 0 filter\(s\): 9 host\(s\), 7 connection\(s\)$/);
  assert.deepEqual(await edgeIds(), ALL);
  assert.equal(await hiddenNote(), "2 connection(s) hidden by marks");

  // Apply as filter: the protocol previewed becomes a filter, and the preview goes back to All
  // (INT-6). With TLS only, the threat line's connection doesn't pass: that query is skipped.
  assert.ok(await page.$eval("#apply-protocol", (b) => b.disabled));
  await page.selectOption("#protocol", "ssl");
  await page.click("#apply-protocol");
  await waitStatus(/^Re-ran 2 of 3 queries with 1 filter\(s\): 2 host\(s\), 0 connection\(s\); 1 found nothing that passes them$/);
  assert.deepEqual(await listed("#filter-list li"), [["TLS", "×"]]);
  assert.equal(await page.inputValue("#protocol"), "");
  assert.deepEqual(await nodeIds(), [A, B]);           // the IOC host, and B for its mark
  await page.click("#filter-list li button");
  await waitStatus(/^Re-ran 3 of 3 queries with 0 filter\(s\)/);

  // Clear resets only the preview (INT-5).
  await typeFilter("port 445 OR port 443 OR port 3389 OR port 22 OR port 80 OR port 53");
  await waitStatus(/^Re-ran 3 of 3 queries with 1 filter\(s\): 9 host\(s\), 7 connection\(s\)$/);
  await page.selectOption("#protocol", "smb");
  assert.ok((await classes(`${A}->${X}`)).includes("proto-hit"));
  await page.click("#clear");
  assert.equal(await page.inputValue("#protocol"), "");
  assert.equal(await cyEval(() => window.threatbridge.cy.$(".proto-hit, .proto-dim").length), 0);
  assert.equal(await page.locator("#filter-list li").count(), 1);
  assert.deepEqual(await edgeIds(), ALL);
  await page.click("#filter-list li button");
  await waitStatus(/^Re-ran 3 of 3 queries with 0 filter\(s\)/);

  // Export CSV: the marked hosts, and the marked and suspect flows on the map (INT-S3). A note
  // is quoted as CSV needs, and never read as a formula.
  await page.request.post(`${BASE}/api/compromised`, { headers: { "X-ThreatBridge": "1" },
                                                       data: { ip: B, note: '=1+1, "x"' } });
  const downloads = [];
  const collect = (d) => downloads.push(d);
  page.on("download", collect);
  await page.click("#export-csv");
  for (let i = 0; i < 100 && downloads.length < 2; i++) await page.waitForTimeout(50);
  page.off("download", collect);
  const [hostsFile, flowsFile] = downloads;
  assert.equal(hostsFile.suggestedFilename(), `threatbridge-${A}-hosts.csv`);
  assert.equal(flowsFile.suggestedFilename(), `threatbridge-${A}-flows.csv`);
  assert.equal(await readFile(await hostsFile.path(), "utf8"),
               `ip,time,note,marked,count\r\n${B},,"'=1+1, ""x""",direct,1\r\n`);
  const flowLines = (await readFile(await flowsFile.path(), "utf8")).trim().split("\r\n");
  assert.equal(flowLines[0], "start,end,src,sport,dst,dport,proto,protocols,packets,bytes,status");
  assert.deepEqual(flowLines.slice(1).map((l) => l.split(",")).map((c) => [c[2], c[4], c[7], c[10]]).sort(), [
    [E, A, "ssl", "suspect"], [A, X, "smb", "suspect"], [X, B, "rdp", "suspect"], [B, F, "ssh", "suspect"]]);
  await waitStatus(/^Exported 1 marked host\(s\) and 4 marked or suspect flow\(s\)$/);

  // Another analyst's marks appear within seconds, and what they hide (ATK-8).
  const other = await ctx.newPage();
  await other.goto(BASE);
  await other.waitForSelector(`#compromised-list li >> text=${B} @ time unknown`);
  await page.fill("#compromised-ip", C);
  await page.click("#compromised-form button");
  await other.waitForSelector(`#compromised-list li >> text=${C} @ time unknown`, { timeout: 8000 });
  assert.equal(await hiddenNote(), "1 connection(s) hidden by marks");          // X -> C is on C's line
  await other.click(`#compromised-list li:has-text('${C}') button`);
  await page.waitForFunction(() => document.getElementById("hidden-note").textContent === "2 connection(s) hidden by marks",
                             null, { timeout: 8000 });
  assert.deepEqual(await listed("#compromised-list li"), [[`${B} @ time unknown`, "Remove"]]);

  // Saved, the map keeps its filters, marks and queries. Opened, it shows its own marks: marking
  // changes only them, until shared; sharing asks first (D19, INT-9).
  await typeFilter("NOT DNS");
  await waitStatus(/^Re-ran 3 of 3 queries with 1 filter\(s\)/);
  await page.fill("#session-name", "story");
  await page.click("#session-form button");
  await waitStatus(/^Saved the map "story" for everyone$/);
  const saved = await (await page.request.get(`${BASE}/api/sessions?name=story`)).json();
  assert.equal(saved.map.version, 2);
  assert.deepEqual(saved.map.filters, ["NOT DNS"]);
  assert.deepEqual(saved.map.marks, { hosts: [{ ip: B, time: null, note: '=1+1, "x"' }], flows: [] });
  assert.deepEqual(saved.map.queries.map((q) => q.op), ["root", "threatline", "routes"]);
  await page.click("#filter-list li button");
  await waitStatus(/^Re-ran 3 of 3 queries with 0 filter\(s\)/);
  await page.click("#session-list .session >> text=story");
  await waitStatus(/^Opened "story" \(saved .*\): /);
  assert.deepEqual(await listed("#filter-list li"), [["NOT DNS", "×"]]);
  assert.ok(await page.locator("#local-marks").isVisible());
  await page.fill("#compromised-ip", Y);
  await page.click("#compromised-form button");
  await page.waitForSelector(`#compromised-list li >> text=${Y} @ time unknown`);
  assert.deepEqual((await shared()).hosts.map((h) => h.ip), [B]);
  await page.waitForTimeout(6000);                       // other analysts don't see it
  assert.equal(await other.locator(`#compromised-list li >> text=${Y}`).count(), 0);
  let asked = null;
  page.once("dialog", (d) => { asked = d.message(); d.dismiss(); });
  await page.click("#share-marks");
  await page.waitForTimeout(300);
  assert.equal(asked, "Replace the 1 shared mark(s) with this map's 2? Every analyst's map will show them.");
  assert.ok(await page.locator("#local-marks").isVisible());
  assert.deepEqual((await shared()).hosts.map((h) => h.ip), [B]);
  page.once("dialog", (d) => d.accept());
  await page.click("#share-marks");
  await waitStatus(/^Shared this map's 2 mark\(s\) with every analyst$/);
  assert.ok(await page.locator("#local-marks").isHidden());
  assert.deepEqual((await shared()).hosts.map((h) => h.ip).sort(), [B, Y]);
  await other.waitForSelector(`#compromised-list li >> text=${Y} @ time unknown`, { timeout: 8000 });
  // Opened again, then Map: back to the shared marks.
  await page.click("#session-list .session >> text=story");
  await waitStatus(/^Opened "story"/);
  assert.ok(await page.locator("#local-marks").isVisible());
  await page.click("#go");
  await waitStatus(/^10\.9\.0\.2: showing/);
  assert.ok(await page.locator("#local-marks").isHidden());
  assert.deepEqual((await listed("#compromised-list li")).map((r) => r[0]).sort(),
                   [`${B} @ time unknown`, `${Y} @ time unknown`]);
  await other.close();

  // A map saved before filters (version 1) is re-queried connection by connection. Opened, its
  // marks (none) are its own: marked flows too, and they are saved with it.
  const openFile = (name, doc) => page.setInputFiles("#session-file", {
    name, mimeType: "application/json", buffer: Buffer.from(JSON.stringify(doc)) });
  const T1 = "2024-05-01T12:06:40.000Z", T2 = "2024-05-01T12:31:40.000Z", T3 = "2024-05-01T12:32:40.000Z";
  await openFile("v1.json", { version: 1,
    nodes: [{ id: A, root: true, anchor: "2024-05-01T12:00:00.000Z", position: { x: 0, y: 0 } },
            { id: X, anchor: T1, position: { x: 50, y: 50 } }, { id: Y, position: { x: -50, y: 50 } }],
    edges: [{ source: A, target: X, direction: "out", count: 1, ports: [445], protocols: ["smb"], first_seen: T1, last_seen: T1 },
            { source: A, target: Y, direction: "out", count: 2, ports: [53, 80], protocols: ["dns", "http"], first_seen: T2,
              last_seen: T3 }] });
  await waitStatus(/^Opened v1\.json: 3 host\(s\), 2 connection\(s\)$/);
  assert.equal(await page.locator("#compromised-list li").count(), 0);
  await page.fill("#compromised-ip", Y);
  await page.click("#compromised-form button");
  await page.waitForSelector(`#compromised-list li >> text=${Y} @ time unknown`);
  await typeFilter("SMB");
  await waitStatus(/^Re-ran 5 of 5 queries with 1 filter\(s\): 3 host\(s\), 1 connection\(s\)$/);
  assert.deepEqual(await nodeIds(), [A, X, Y]);          // Y, marked, stays with no connection
  await page.click(`#compromised-list li:has-text('${Y}') button`);
  await page.waitForFunction(() => window.threatbridge.cy.nodes().length === 2);   // then it goes (C2)
  await menu(edge(A, X), "Mark compromised", "edge");
  await page.waitForSelector(`#marked-flow-list li >> text=${A} → ${X} @ ${T1}`);
  assert.deepEqual((await shared()).flows, []);
  await page.click("#marked-flow-list li button");
  await page.waitForSelector("#marked-flow-list li", { state: "detached" });
  await menu(edge(A, X), "Mark compromised", "edge");
  await page.waitForSelector("#marked-flow-list li");
  await menu(node(A), "Unmark compromised");             // takes its marked flow with it
  await page.waitForSelector("#marked-flow-list li", { state: "detached" });
  await menu(edge(A, X), "Mark compromised", "edge");
  await page.waitForSelector("#marked-flow-list li");
  const [v2File] = await Promise.all([page.waitForEvent("download"), page.click("#session-download")]);
  const v2 = JSON.parse(await readFile(await v2File.path(), "utf8"));
  keepMap("marked-flow", v2);
  assert.deepEqual(v2.marks.flows, [{ src: A, dst: X, start: T1, sport: 50151, dport: 445, proto: "tcp", note: "" }]);
  assert.deepEqual(v2.queries.map((q) => q.op), ["node", "node", "node", "edge", "edge"]);
  // Expansions and removals are re-run too.
  await menu(node(X), "Expand outbound");
  await waitStatus(/^10\.9\.0\.3: showing top 1 of 1 distinct peer/);     // X -> C, SMB
  await menu(node(X), "Remove from map");
  await page.click("#filter-list li button");
  await waitStatus(/^Re-ran 7 of 7 queries with 0 filter\(s\)/);
  // The expansion brought C back; removing X took its connections (the attack path between the
  // marked A and X draws X again).
  assert.ok((await nodeIds()).includes(C) && (await nodeIds()).includes(Y));
  assert.deepEqual(await edgeIds(), [`${A}->${X}`, `${A}->${Y}`]);
  await openFile("v2.json", Object.assign({}, v2, { queries: [...v2.queries, { op: "something new" }] }));
  await waitStatus(/^Opened v2\.json: /);
  assert.deepEqual(await listed("#marked-flow-list li"), [[`${A} → ${X} @ ${T1}`, "tcp 50151 → 445", "Remove"]]);
  assert.deepEqual(await listed("#filter-list li"), [["SMB", "×"]]);
  await page.click("#filter-list li button");
  await waitStatus(/^Re-ran 6 of 6 queries/);             // a query it doesn't know does nothing
  await page.click("#go");
  await waitStatus(/^10\.9\.0\.2: showing/);

  // Clean up for the next test on this server.
  for (const ip of [B, Y]) await page.click(`#compromised-list li:has-text('${ip}') button`);
  await page.waitForSelector("#compromised-list li", { state: "detached" });
  page.once("dialog", (d) => d.accept());
  await page.click("#session-list li:has-text('story') button");
  await waitStatus(/^Deleted the saved map "story"$/);

  assert.deepEqual(errors, [], "browser console errors");
  console.log("Marks and filters UI test passed");
} finally {
  await finish(browser, page, "marks");
}
