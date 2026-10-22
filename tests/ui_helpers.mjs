// Shared setup for the browser tests: a Chromium page that collects console errors, screen
// positions of graph elements, and JavaScript coverage when JS_COVERAGE is set:
//   JS_COVERAGE=DIR node tests/ui_case.mjs ...   writes DIR/<test>.json (V8 block coverage)
//   node tests/js_coverage.mjs DIR                lists the parts of app.js no test ran
// Set CHROMIUM_PATH to use a preinstalled browser.
import { mkdirSync, writeFileSync } from "node:fs";
import { chromium } from "playwright";

const COVERAGE_DIR = process.env.JS_COVERAGE;

// A page in a new browser. `errors` collects page exceptions and console errors, except
// console messages matching `expected`. `at(selector, kind)` gives the screen position (and
// id) of a node's centre, or of an edge's midpoint with kind "edge".
export async function launch({ context = {}, expected = null } = {}) {
  const browser = await chromium.launch(
    process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 850 }, ...context });
  const page = await ctx.newPage();
  if (COVERAGE_DIR) await page.coverage.startJSCoverage({ resetOnNavigation: false });
  const errors = [];
  page.on("console", (m) => {
    if (m.type() === "error" && !(expected && expected.test(m.text()))) errors.push(m.text());
  });
  page.on("pageerror", (e) => errors.push(String(e)));
  const at = (selector, kind) => page.evaluate(([sel, k]) => {
    const el = window.threatbridge.cy.$(sel)[0];
    const p = k === "edge" ? el.renderedMidpoint() : el.renderedPosition();
    const box = document.getElementById("cy").getBoundingClientRect();
    return { x: p.x + box.left, y: p.y + box.top, id: el.id() };
  }, [selector, kind]);
  return { browser, ctx, page, errors, at };
}

// Save what the page ran of app.js (when JS_COVERAGE is set) and close the browser.
export async function finish(browser, page, name) {
  if (COVERAGE_DIR) {
    const entries = await page.coverage.stopJSCoverage();
    mkdirSync(COVERAGE_DIR, { recursive: true });
    writeFileSync(`${COVERAGE_DIR}/${name}.json`,
                  JSON.stringify(entries.filter((e) => e.url.endsWith("/static/app.js"))));
  }
  await browser.close();
}
