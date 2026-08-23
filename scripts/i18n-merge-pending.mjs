// i18n-merge-pending.mjs — fold a batch of finished translations into the source dictionaries.
//
// The dictionaries under web/i18n/ are the source of truth; web/dist/i18n.js is generated
// from them. This takes one {english: translation} file per language, checks it hard, and only then
// writes — all fifteen or none. A half-applied batch would leave some languages complete and others
// not, and the only signal would be a CI failure naming one string.
//
// Every check below exists because its absence would let something through silently:
//   • key set equality, not key COUNT: 260 keys can be 260 wrong keys.
//   • placeholder counts, not presence: "{0} of {0}" for "{0} of {1}" contains both and is nonsense.
//   • an existing key with a DIFFERENT value is refused rather than overwritten: these strings are
//     supposed to be new, so a collision means the batch is about a dictionary I did not expect.
//   • identical-to-English values are reported, never rejected: for "UUID" that is correct.
//
// Usage: node scripts/i18n-merge-pending.mjs <dir-with-new-<lang>.json> [--write]
//        without --write it reports and changes nothing.
import fs from 'node:fs';
import path from 'node:path';

const SRC_DIR = process.argv[2];
const WRITE = process.argv.includes('--write');
if (!SRC_DIR) {
  console.error('usage: node scripts/i18n-merge-pending.mjs <dir> [--write]');
  process.exit(2);
}

const DICTS = 'web/i18n';
const PENDING = 'scripts/i18n-pending.json';

const pending = JSON.parse(fs.readFileSync(PENDING, 'utf8')).pending;
if (!Array.isArray(pending) || !pending.length) {
  console.error(`${PENDING}: .pending is empty or not an array — nothing to merge, and a run that `
    + 'merges nothing while reporting success is worse than one that stops.');
  process.exit(1);
}
const pendingSet = new Set(pending);
// langs.json is the language LIST the picker renders ({"langs":[{code,name},…]}), not a dictionary.
// Treating it as one made this tool demand a new-langs.json that can never exist and refuse every
// batch — "staged 9 of 10 languages" — for a file that has no strings to translate.
const NOT_A_DICTIONARY = new Set(['langs']);
const langs = fs.readdirSync(DICTS)
  .filter((f) => f.endsWith('.json'))
  .map((f) => f.slice(0, -5))
  .filter((l) => !NOT_A_DICTIONARY.has(l))
  .sort();

const count = (s, sub) => s.split(sub).length - 1;
const problems = [];
const staged = [];

for (const lang of langs) {
  const file = path.join(SRC_DIR, `new-${lang}.json`);
  if (!fs.existsSync(file)) { problems.push(`${lang}: ${file} is missing`); continue; }

  let incoming;
  try { incoming = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { problems.push(`${lang}: ${file} is not valid JSON — ${e.message}`); continue; }

  const keys = Object.keys(incoming);
  const missing = pending.filter((k) => !(k in incoming));
  const extra = keys.filter((k) => !pendingSet.has(k));
  if (missing.length) problems.push(`${lang}: ${missing.length} pending string(s) absent, first: ${JSON.stringify(missing[0])}`);
  if (extra.length) problems.push(`${lang}: ${extra.length} key(s) that are not in the pending list, first: ${JSON.stringify(extra[0])}`);

  let empties = 0, ph = 0, same = 0;
  for (const k of pending) {
    const v = incoming[k];
    if (typeof v !== 'string' || v.trim() === '') { empties++; continue; }
    for (const p of ['{0}', '{1}']) {
      if (count(k, p) !== count(v, p)) {
        ph++;
        if (ph <= 3) problems.push(`${lang}: ${p} count ${count(v, p)} vs ${count(k, p)} in ${JSON.stringify(k)} -> ${JSON.stringify(v)}`);
      }
    }
    if (v === k) same++;
  }
  if (empties) problems.push(`${lang}: ${empties} empty value(s)`);
  if (ph > 3) problems.push(`${lang}: ${ph} placeholder mismatch(es) in total`);

  const dictFile = path.join(DICTS, `${lang}.json`);
  const dict = JSON.parse(fs.readFileSync(dictFile, 'utf8'));
  const collisions = pending.filter((k) => k in dict && dict[k] !== incoming[k]);
  if (collisions.length) {
    problems.push(`${lang}: ${collisions.length} pending string(s) ALREADY in the dictionary with a `
      + `different value — these were supposed to be new; first: ${JSON.stringify(collisions[0])}`);
  }

  staged.push({ lang, dictFile, dict, incoming, before: Object.keys(dict).length, same });
}

for (const s of staged) {
  console.log(`  ${s.lang.padEnd(3)} ${String(s.before).padStart(5)} keys -> `
    + `${String(s.before + pending.filter((k) => !(k in s.dict)).length).padStart(5)}   `
    + `${s.same} value(s) identical to English`);
}

if (problems.length) {
  console.error(`\nmerge REFUSED (${problems.length} problem(s)):`);
  for (const p of problems.slice(0, 25)) console.error(`  ${p}`);
  process.exit(1);
}
if (staged.length !== langs.length) {
  console.error(`\nmerge REFUSED: staged ${staged.length} of ${langs.length} languages`);
  process.exit(1);
}

console.log(`\nall ${staged.length} languages pass every check for all ${pending.length} strings`);
if (!WRITE) { console.log('dry run — pass --write to apply'); process.exit(0); }

for (const s of staged) {
  fs.copyFileSync(s.dictFile, s.dictFile + '.bak');
  const merged = { ...s.dict };
  for (const k of pending) merged[k] = s.incoming[k];
  fs.writeFileSync(s.dictFile, JSON.stringify(merged, null, 2) + '\n', 'utf8');
}

// Read back rather than trust the writes.
let bad = 0;
for (const s of staged) {
  const back = JSON.parse(fs.readFileSync(s.dictFile, 'utf8'));
  const ok = pending.every((k) => back[k] === s.incoming[k]);
  if (!ok) { console.error(`  ${s.lang}: READ-BACK MISMATCH`); bad++; }
  else console.log(`  ${s.lang}: ${Object.keys(back).length} keys, all ${pending.length} present`);
}
if (bad) process.exit(1);
console.log(`\nmerged ${pending.length} strings into ${staged.length} dictionaries (.bak kept beside each)`);
