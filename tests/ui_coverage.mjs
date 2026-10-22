// Optional coverage of the map's JavaScript during the browser tests.
//   JS_COVERAGE=DIR node tests/ui_case.mjs ...   writes DIR/<test>.json (V8 block coverage)
//   node tests/js_coverage.mjs DIR                lists the parts of app.js no test ran
import { mkdirSync, writeFileSync } from "node:fs";

const DIR = process.env.JS_COVERAGE;

export async function startCoverage(page) {
  if (DIR) await page.coverage.startJSCoverage({ resetOnNavigation: false });
}

export async function saveCoverage(page, name) {
  if (!DIR) return;
  const entries = await page.coverage.stopJSCoverage();
  mkdirSync(DIR, { recursive: true });
  writeFileSync(`${DIR}/${name}.json`, JSON.stringify(entries.filter((e) => e.url.endsWith("/static/app.js"))));
}
