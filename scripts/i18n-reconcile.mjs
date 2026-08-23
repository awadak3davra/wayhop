// i18n-reconcile.mjs — make web/i18n a true superset of what actually ships.
//
// `.claude/i18n/generate.mjs` says the dicts are the source of truth and rebuilds web/dist/i18n.js from
// them. They are not: the shipped bundle carries 15 languages while the dicts hold 13 — Belarusian and
// Ukrainian have no dict at all — and even for a shared language the bundle holds keys the dict lacks.
// Running the documented command therefore DELETES two languages and thousands of strings, which is what
// happened here before this script existed.
//
// This reads the per-language files that actually ship and folds them back into the dicts, so the dicts
// become what the generator already believes they are. Reports first, writes only with --write.
//
// Usage: node scripts/i18n-reconcile.mjs [--write]
import fs from 'node:fs';
import path from 'node:path';

const WRITE = process.argv.includes('--write');
const SPLIT_DIR = path.join('web', 'dist', 'i18n');
const DICT_DIR = path.join('.claude', 'i18n', 'dicts');

// The split files are `;(function (w) { var D = {...}; ... })(window)`. Take the object literal between
// `var D = ` and the `};` that closes it, which is plain JSON.
function readShipped(file) {
  const text = fs.readFileSync(file, 'utf8');
  const start = text.indexOf('var D = ');
  if (start < 0) return null;
  const open = text.indexOf('{', start);
  if (open < 0) return null;
  // Walk the braces so a `}` inside a translated string cannot end the object early.
  let depth = 0, inStr = false, esc = false, end = -1;
  for (let i = open; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === '\\') esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; continue; }
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) { end = i + 1; break; } }
  }
  if (end < 0) return null;
  try { return JSON.parse(text.slice(open, end)); } catch (e) { return { __error: e.message }; }
}

const files = fs.readdirSync(SPLIT_DIR).filter((f) => f.endsWith('.js'));
let totalMissing = 0, totalConflict = 0, newLangs = 0;
const plan = [];

for (const f of files) {
  const lang = f.replace(/\.js$/, '');
  const shipped = readShipped(path.join(SPLIT_DIR, f));
  if (!shipped) { console.error(`  ${lang}: could not find the dictionary object — skipped`); continue; }
  if (shipped.__error) { console.error(`  ${lang}: unparsable (${shipped.__error}) — skipped`); continue; }

  const dictFile = path.join(DICT_DIR, `${lang}.json`);
  const exists = fs.existsSync(dictFile);
  const dict = exists ? JSON.parse(fs.readFileSync(dictFile, 'utf8')) : {};
  if (!exists) newLangs++;

  const missing = [], conflict = [];
  for (const [k, v] of Object.entries(shipped)) {
    if (dict[k] === undefined) missing.push(k);
    else if (dict[k] !== v) conflict.push(k);
  }
  const onlyInDict = Object.keys(dict).filter((k) => shipped[k] === undefined);
  totalMissing += missing.length;
  totalConflict += conflict.length;
  plan.push({ lang, exists, shipped: Object.keys(shipped).length, dict: Object.keys(dict).length,
              missing, conflict, onlyInDict: onlyInDict.length });
}

console.log(`  ${plan.length} shipped language(s), ${newLangs} with no dictionary at all\n`);
for (const p of plan) {
  console.log(`  ${p.lang.padEnd(3)} shipped ${String(p.shipped).padStart(5)}  dict ${String(p.dict).padStart(5)}` +
              `  missing from dict ${String(p.missing.length).padStart(5)}` +
              `  only in dict ${String(p.onlyInDict).padStart(4)}` +
              `  value conflicts ${String(p.conflict.length).padStart(4)}` +
              `${p.exists ? '' : '   <-- NO DICTIONARY'}`);
  if (p.conflict.length) {
    for (const k of p.conflict.slice(0, 3)) console.log(`        conflict: "${k.slice(0, 44)}"`);
  }
}
console.log(`\n  total: ${totalMissing} key(s) would be lost by regenerating today, ${totalConflict} value conflict(s)`);

if (!WRITE) { console.log('  (report only — pass --write to fold the shipped strings into the dicts)'); process.exit(0); }

// Write. The SHIPPED value wins for a key both sides have, because that is what users see today; a key
// only the dict has is new work and is kept.
let wrote = 0;
for (const p of plan) {
  const shipped = readShipped(path.join(SPLIT_DIR, `${p.lang}.js`));
  const dictFile = path.join(DICT_DIR, `${p.lang}.json`);
  const dict = fs.existsSync(dictFile) ? JSON.parse(fs.readFileSync(dictFile, 'utf8')) : {};
  const merged = { ...dict };
  for (const [k, v] of Object.entries(shipped)) merged[k] = v;
  // Re-apply the dict's own keys that the bundle does not carry, so new translations survive.
  for (const [k, v] of Object.entries(dict)) if (shipped[k] === undefined) merged[k] = v;
  fs.writeFileSync(dictFile, JSON.stringify(merged, null, 1) + '\n');
  wrote++;
  console.log(`  ${p.lang}: dict now ${Object.keys(merged).length} keys`);
}
console.log(`\n  ${wrote} dictionary(s) written`);
