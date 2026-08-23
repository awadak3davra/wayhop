// i18n-merge.mjs — merge a batch of translations into the dictionaries, refusing bad ones.
//
// The 218 redesign strings have to reach 13 dictionaries, and a translation that silently drops a
// placeholder or leaves the English in place is worse than an untranslated string: the string still LOOKS
// handled, and `check-i18n` will not flag it because it is listed as pending. So every entry is checked
// before it is written, and the run refuses the whole batch if any entry fails — a half-applied batch is
// the state nobody can reason about later.
//
// Input is a JSON file: { "<lang>": { "<english source>": "<translation>", ... }, ... }
//
// Usage: node scripts/i18n-merge.mjs <batch.json> [--dry]
import fs from 'node:fs';
import path from 'node:path';

const BATCH = process.argv[2];
const DRY = process.argv.includes('--dry');
if (!BATCH) { console.error('usage: node scripts/i18n-merge.mjs <batch.json> [--dry]'); process.exit(2); }

const DICT_DIR = path.join('.claude', 'i18n', 'dicts');
const PENDING = JSON.parse(fs.readFileSync(path.join('scripts', 'i18n-pending.json'), 'utf8')).pending;
const pendingSet = new Set(PENDING);

// Strings that are legitimately identical in every language: bare parameter names the UI shows verbatim.
const IDENTICAL_OK = new Set(['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4',
  'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5']);
// A string with no letters at all — "{0} — {1}" and its kind — is a format, not prose. There is nothing in
// it to translate, so an identical "translation" is the correct answer rather than a missed one. Found by
// the check refusing a batch over exactly that string.
const nothingToTranslate = (s) => !/\p{L}/u.test(s);

const placeholders = (s) => (s.match(/\{\d+\}/g) || []).sort().join(',');

const batch = JSON.parse(fs.readFileSync(BATCH, 'utf8'));
const problems = [];
let entries = 0;

for (const [lang, pairs] of Object.entries(batch)) {
  const file = path.join(DICT_DIR, `${lang}.json`);
  if (!fs.existsSync(file)) { problems.push(`${lang}: no dictionary at ${file}`); continue; }
  for (const [src, tr] of Object.entries(pairs)) {
    entries++;
    const where = `${lang} "${src.slice(0, 40)}"`;
    if (typeof tr !== 'string' || !tr.trim()) { problems.push(`${where}: empty translation`); continue; }
    if (placeholders(src) !== placeholders(tr)) {
      problems.push(`${where}: placeholders differ — source has [${placeholders(src) || 'none'}], ` +
        `translation has [${placeholders(tr) || 'none'}]`);
    }
    if (tr.trim() === src.trim() && !IDENTICAL_OK.has(src.trim()) && !nothingToTranslate(src)) {
      problems.push(`${where}: left in English`);
    }
    if (!pendingSet.has(src)) {
      problems.push(`${where}: not in the pending list — either it is already translated or the source text drifted`);
    }
  }
}

if (problems.length) {
  console.error(`refusing the batch, ${problems.length} problem(s) in ${entries} entry(s):`);
  for (const p of problems.slice(0, 25)) console.error(`  ${p}`);
  if (problems.length > 25) console.error(`  … and ${problems.length - 25} more`);
  process.exit(1);
}

// Write. Keys keep the dictionary's existing order and new ones are appended, so a diff shows only additions.
let written = 0;
for (const [lang, pairs] of Object.entries(batch)) {
  const file = path.join(DICT_DIR, `${lang}.json`);
  const dict = JSON.parse(fs.readFileSync(file, 'utf8'));
  let added = 0;
  for (const [src, tr] of Object.entries(pairs)) { if (dict[src] === undefined) added++; dict[src] = tr; }
  if (!DRY) fs.writeFileSync(file, JSON.stringify(dict, null, 1) + '\n');
  written += added;
  console.log(`  ${lang}: +${added} (${Object.keys(dict).length} keys total)${DRY ? '  [dry run]' : ''}`);
}

// Report what is left, per language, so progress is a number rather than a feeling.
console.log(`\n  ${entries} entry(s) accepted, ${written} newly added${DRY ? ' (nothing written)' : ''}`);
const langs = fs.readdirSync(DICT_DIR).filter((f) => f.endsWith('.json')).map((f) => f.replace('.json', ''));
const remaining = langs.map((l) => {
  const d = JSON.parse(fs.readFileSync(path.join(DICT_DIR, `${l}.json`), 'utf8'));
  return { l, missing: PENDING.filter((s) => d[s] === undefined).length };
});
console.log(`  still untranslated of ${PENDING.length} pending: ` +
  remaining.map((r) => `${r.l}=${r.missing}`).join(' '));
