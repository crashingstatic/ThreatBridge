// Headless browser test through mutual TLS (the CI "Docker build + mTLS" job): with a client
// certificate from the ThreatBridge CA the map works over HTTPS, writes included; without one
// the browser can't open it.
//   P12_PASS=... TB_URL=https://localhost:5443 node tests/ui_mtls.mjs <cert-dir> <client-name>
// Expects <cert-dir>/<client-name>.p12 (password $P12_PASS), as made by scripts/make-certs.sh.
import assert from "node:assert/strict";
import { chromium } from "playwright";

const BASE = process.env.TB_URL || "https://localhost:5443";
const [DIR, CLIENT] = process.argv.slice(2);
const browser = await chromium.launch(
  process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});

try {
  // Without a client certificate the connection is refused, so nothing of the map loads.
  const bare = await browser.newContext({ ignoreHTTPSErrors: true });
  const refused = await (await bare.newPage()).goto(BASE).then(() => null, (e) => e.message);
  assert.match(refused ?? "the page loaded", /net::ERR_/);
  await bare.close();

  // With one, the map works: launched as a SOC action would, and writing to a shared list.
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, clientCertificates: [
    { origin: BASE, pfxPath: `${DIR}/${CLIENT}.p12`, passphrase: process.env.P12_PASS }] });
  const page = await ctx.newPage();
  const errors = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  const opened = await page.goto(`${BASE}/?ip=10.0.0.5&ts=2024-05-01T12:00:00Z&dir=in`);
  assert.equal(opened.status(), 200, "the certificate is accepted");
  await page.waitForFunction(() => window.threatbridge.cy.edges().length > 0);
  assert.match(await page.textContent("#status"), /^10\.0\.0\.5: showing top \d+ of \d+ distinct peer/);
  await page.fill("#exclude-input", "192.0.2.99");
  await page.click("#exclude-form button");
  await page.waitForSelector("#exclude-list li >> text=192.0.2.99");
  await page.click("#exclude-list li:has-text('192.0.2.99') button");
  await page.waitForSelector("#exclude-list li >> text=192.0.2.99", { state: "detached" });
  assert.deepEqual(errors, [], "browser console errors");
  console.log("UI mTLS test passed");
} finally {
  await browser.close();
}
