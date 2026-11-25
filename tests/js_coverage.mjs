// Merge the coverage written by the browser tests (see ui_helpers.mjs) and list the lines
// of app.js that no test ran, grouped into blocks, then the functions that never ran.
//   node tests/js_coverage.mjs DIR
import { readdirSync, readFileSync } from "node:fs";

const dir = process.argv[2];
const entries = readdirSync(dir).filter((n) => n.endsWith(".json"))
  .flatMap((name) => JSON.parse(readFileSync(`${dir}/${name}`, "utf8")));
const source = entries[0].source;

// Lines: a character ran if any test ran it. Ranges nest and the innermost decides, so paint
// the largest first and let the inner ones overwrite them.
const covered = new Array(source.length).fill(0);
for (const entry of entries) {
  const counts = new Array(source.length).fill(1);
  const ranges = entry.functions.flatMap((f) => f.ranges)
    .sort((a, b) => (b.endOffset - b.startOffset) - (a.endOffset - a.startOffset));
  for (const r of ranges) counts.fill(r.count > 0 ? 1 : 0, r.startOffset, r.endOffset);
  counts.forEach((c, i) => { covered[i] ||= c; });
}
const lines = source.split("\n");
let offset = 0, total = 0, missed = 0, block = [];
const flush = () => {
  if (block.length) console.log(block.map(([n, l]) => `${String(n).padStart(4)}  ${l}`).join("\n") + "\n");
  block = [];
};
lines.forEach((line, i) => {
  const code = line.trim();
  const idx = line.search(/\S/);
  if (code && !code.startsWith("//") && code !== "}" && code !== "});" && code !== ");") {
    total += 1;
    if (!covered[offset + idx]) { missed += 1; block.push([i + 1, line]); } else flush();
  }
  offset += line.length + 1;
});
flush();
console.log(`app.js: ${total - missed} of ${total} code lines ran (${(100 * (total - missed) / total).toFixed(1)}%)`);

// Functions (event handlers included) that never ran in any test.
const ran = new Map();
for (const entry of entries) {
  for (const f of entry.functions) {
    const r = f.ranges[0];
    ran.set(r.startOffset, (ran.get(r.startOffset) || 0) + r.count);
  }
}
const never = [...ran].filter(([, n]) => n === 0).map(([start]) => start).sort((a, b) => a - b);
console.log(`\nfunctions that never ran: ${never.length} of ${ran.size}`);
for (const start of never) {
  const line = source.slice(0, start).split("\n").length;
  console.log(`${String(line).padStart(4)}  ${source.slice(start, start + 90).split("\n")[0]}`);
}
