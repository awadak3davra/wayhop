// i18n-apply-review.mjs — fold a per-language review pass into the source dictionaries.
//
// Input is one fix-<lang>.json per language holding ONLY the entries the reviewer wants changed:
//   { "<english key>": { "to": "<replacement>", "why": "<one line>" } }
//
// Everything below is checked before anything is written, and all languages are written or none.
// Two of these checks exist because the looser version would have let something through:
//   • placeholders are compared over EVERY {n} the English key contains, not just {0} and {1}. The
//     connection-collision string carries {2}, and both the CI gate and the first merge script only
//     ever looked at {0}/{1} — so a replacement could drop {2} and pass twice.
//   • a "fix" whose replacement equals the value already stored is rejected rather than skipped: it
//     means the reviewer was reading a different tree than the one being written, and the rest of
//     that language's proposals cannot be trusted either.
//
// Usage: node scripts/i18n-apply-review.mjs <dir-with-fix-<lang>.json> [--write]
import fs from 'node:fs';
import path from 'node:path';

const DIR = process.argv[2];
const WRITE = process.argv.includes('--write');
if (!DIR) { console.error('usage: node scripts/i18n-apply-review.mjs <dir> [--write]'); process.exit(2); }

const DICTS = 'web/i18n';
const KEYS = path.join(DIR, 'keys.json');
if (!fs.existsSync(KEYS)) {
  console.error(`${KEYS} is missing — without the authoritative key list this script cannot tell a `
    + 'reviewed string from an arbitrary one, and would happily rewrite the wrong entries.');
  process.exit(1);
}
const keys = new Set(JSON.parse(fs.readFileSync(KEYS, 'utf8')));

const placeholders = (s) => (s.match(/\{\d+\}/g) || []);
const tally = (s) => placeholders(s).reduce((m, p) => (m[p] = (m[p] || 0) + 1, m), {});
const sameTally = (a, b) => {
  const x = tally(a), y = tally(b);
  const all = new Set([...Object.keys(x), ...Object.keys(y)]);
  for (const p of all) if ((x[p] || 0) !== (y[p] || 0)) return false;
  return true;
};

const langs = fs.readdirSync(DICTS).filter((f) => f.endsWith('.json')).map((f) => f.slice(0, -5)).sort();
const problems = [];
const staged = [];

for (const lang of langs) {
  const file = path.join(DIR, `fix-${lang}.json`);
  if (!fs.existsSync(file)) { problems.push(`${lang}: ${file} is missing`); continue; }
  let fix;
  try { fix = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { problems.push(`${lang}: not valid JSON — ${e.message}`); continue; }

  const dictFile = path.join(DICTS, `${lang}.json`);
  const dict = JSON.parse(fs.readFileSync(dictFile, 'utf8'));
  const changes = [];
  for (const [k, v] of Object.entries(fix)) {
    if (!keys.has(k)) { problems.push(`${lang}: ${JSON.stringify(k).slice(0, 60)} is not one of the reviewed strings`); continue; }
    if (!(k in dict)) { problems.push(`${lang}: ${JSON.stringify(k).slice(0, 60)} is not in the dictionary`); continue; }
    const to = v && typeof v === 'object' ? v.to : v;
    if (typeof to !== 'string' || to.trim() === '') { problems.push(`${lang}: empty replacement for ${JSON.stringify(k).slice(0, 60)}`); continue; }
    if (to === dict[k]) { problems.push(`${lang}: replacement equals the stored value for ${JSON.stringify(k).slice(0, 60)} — the reviewer read a different tree`); continue; }
    if (!sameTally(k, to)) {
      problems.push(`${lang}: placeholder mismatch ${JSON.stringify(placeholders(k))} vs ${JSON.stringify(placeholders(to))} `
        + `in ${JSON.stringify(k).slice(0, 55)} -> ${JSON.stringify(to).slice(0, 55)}`);
      continue;
    }
    changes.push({ k, from: dict[k], to, why: (v && v.why) || '' });
  }
  staged.push({ lang, dictFile, dict, changes, proposed: Object.keys(fix).length });
}

for (const s of staged) {
  console.log(`  ${s.lang.padEnd(3)} ${String(s.changes.length).padStart(3)} of ${String(s.proposed).padStart(3)} proposed change(s) accepted`);
}

if (problems.length) {
  console.error(`\nREFUSED (${problems.length} problem(s)):`);
  for (const p of problems.slice(0, 30)) console.error(`  ${p}`);
  process.exit(1);
}
if (staged.length !== langs.length) {
  console.error(`\nREFUSED: staged ${staged.length} of ${langs.length} languages`);
  process.exit(1);
}

const total = staged.reduce((a, s) => a + s.changes.length, 0);
console.log(`\nall ${staged.length} languages pass every check; ${total} replacement(s) ready`);
if (!WRITE) {
  console.log('\ndry run — a sample of what would change:');
  for (const s of staged.slice(0, 4)) {
    for (const c of s.changes.slice(0, 2)) {
      console.log(`  [${s.lang}] ${JSON.stringify(c.k).slice(0, 58)}`);
      console.log(`        from ${JSON.stringify(c.from).slice(0, 70)}`);
      console.log(`        to   ${JSON.stringify(c.to).slice(0, 70)}`);
      if (c.why) console.log(`        why  ${c.why.slice(0, 90)}`);
    }
  }
  console.log('\npass --write to apply');
  process.exit(0);
}

for (const s of staged) {
  const merged = { ...s.dict };
  for (const c of s.changes) merged[c.k] = c.to;
  fs.writeFileSync(s.dictFile, JSON.stringify(merged, null, 2) + '\n', 'utf8');
}
let bad = 0;
for (const s of staged) {
  const back = JSON.parse(fs.readFileSync(s.dictFile, 'utf8'));
  const ok = s.changes.every((c) => back[c.k] === c.to);
  if (!ok) { console.error(`  ${s.lang}: READ-BACK MISMATCH`); bad++; }
  else console.log(`  ${s.lang}: ${s.changes.length} applied, ${Object.keys(back).length} keys total`);
}
if (bad) process.exit(1);
console.log(`\napplied ${total} reviewed replacement(s) across ${staged.length} dictionaries`);
