// i18n-topup.mjs — bring ONE dictionary level with the others, and touch nothing else.
//
// i18n-merge-pending.mjs folds a batch into every language at once, which is right for strings that
// were held back everywhere. It is the wrong tool when one dictionary falls behind: a workstream adds
// strings to the nine dictionaries it knows about, and the tenth (zh-CN, added later) is left without
// them — check-i18n then fails INCOMPLETE for that language only. This lists exactly what that one
// language lacks, and merges the filled list back under the same checks the other merge tools apply.
//
//   node scripts/i18n-topup.mjs <lang> --todo <out.json>       write {"<english>": ""} for every key
//                                                               ALL other dictionaries carry and <lang> lacks
//   node scripts/i18n-topup.mjs <lang> <filled.json>           check a filled list (dry run)
//   node scripts/i18n-topup.mjs <lang> <filled.json> --write   check, then merge into web/i18n/<lang>.json
//
// Then: node scripts/i18n-generate.mjs && node scripts/check-i18n.mjs
//
// What is refused, and why each check exists:
//   • a key the language already has: that is a review, and i18n-apply-review.mjs is the tool that
//     shows the old value beside the new one. Overwriting here would do it silently.
//   • a key that is not missing (not carried by every other dictionary): either a typo or source text
//     that drifted since the todo was written — both mean the batch describes a different tree.
//   • every {n} the English carries, counted: {2} and {3} exist, and a check that looks only at {0}/{1}
//     has let a dropped {2} through before. A plural key ("a|b") keeps the same SET of placeholders,
//     because a language with fewer forms legitimately writes one form.
//   • markup and line breaks, which the UI renders and a translation must not invent or lose.
// A value identical to the English is reported, not refused: for "MTU" that is the right answer.
import fs from 'node:fs';
import path from 'node:path';

const DICTS = 'web/i18n';
const args = process.argv.slice(2);
const lang = args[0];
const todoAt = args.indexOf('--todo');
const WRITE = args.includes('--write');
const usage = 'usage: node scripts/i18n-topup.mjs <lang> --todo <out.json> | <lang> <filled.json> [--write]';
if (!lang || lang.startsWith('-')) { console.error(usage); process.exit(2); }

const dictFile = path.join(DICTS, `${lang}.json`);
if (!fs.existsSync(dictFile)) { console.error(`${dictFile} does not exist`); process.exit(1); }
const read = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));
const target = read(dictFile);
const others = fs.readdirSync(DICTS)
  .filter((f) => f.endsWith('.json') && f !== 'langs.json' && f !== `${lang}.json`)
  .map((f) => read(path.join(DICTS, f)));
if (!others.length) { console.error('no other dictionary to compare with'); process.exit(1); }

// Missing = carried by EVERY other dictionary. A key only some carry (an extra one translator added)
// is not something this language owes; the order is the first dictionary's, so a todo reads in the
// order the strings were written.
const missing = Object.keys(others[0]).filter((k) => !(k in target) && others.every((d) => k in d));
const orphans = Object.keys(target).filter((k) => !others.some((d) => k in d));

if (todoAt >= 0) {
  const out = args[todoAt + 1];
  if (!out) { console.error(usage); process.exit(2); }
  fs.writeFileSync(out, JSON.stringify(Object.fromEntries(missing.map((k) => [k, ''])), null, 2) + '\n', 'utf8');
  console.log(`${lang}: ${missing.length} key(s) missing, written to ${out} — fill every value, then run`);
  console.log(`  node scripts/i18n-topup.mjs ${lang} ${out} --write`);
  if (orphans.length) {
    console.log(`${lang}: ${orphans.length} key(s) no other dictionary carries (left alone; propose removal if dead), `
      + `first: ${JSON.stringify(orphans[0]).slice(0, 70)}`);
  }
  process.exit(0);
}

const batchFile = args.find((a, i) => i > 0 && !a.startsWith('--'));
if (!batchFile) { console.error(usage); process.exit(2); }
let batch;
try { batch = read(batchFile); } catch (e) { console.error(`${batchFile}: ${e.message}`); process.exit(1); }

const missingSet = new Set(missing);
const ph = (s) => s.match(/\{\d+\}/g) || [];
const tally = (s) => JSON.stringify(ph(s).sort());
const tags = (s) => (s.match(/<\/?[a-z][^>]*>/gi) || []).join('');
const lines = (s) => (s.match(/\n/g) || []).length;
const problems = [];
let same = 0;
for (const [k, v] of Object.entries(batch)) {
  const where = JSON.stringify(k).slice(0, 60);
  if (k in target) { problems.push(`${where}: already in ${lang} — use i18n-apply-review.mjs to change it`); continue; }
  if (!missingSet.has(k)) { problems.push(`${where}: not a missing key (typo, or the source drifted)`); continue; }
  if (typeof v !== 'string' || !v.trim()) { problems.push(`${where}: empty`); continue; }
  if (k.includes('|')) {
    const want = [...new Set(ph(k.split('|').pop()))].sort().join();
    const got = [...new Set(ph(v))].sort().join();
    if (want !== got) problems.push(`${where}: placeholders [${want}] vs [${got}]`);
  } else if (tally(k) !== tally(v)) {
    problems.push(`${where}: placeholders ${tally(k)} vs ${tally(v)}`);
  }
  if (tags(k) !== tags(v)) problems.push(`${where}: markup ${tags(k)} vs ${tags(v)}`);
  if (lines(k) !== lines(v)) problems.push(`${where}: ${lines(k)} line break(s) vs ${lines(v)}`);
  if (v === k && /\p{L}/u.test(k)) same++;
}
const left = missing.filter((k) => !(k in batch));
console.log(`${lang}: ${Object.keys(batch).length} entr(ies) offered for ${missing.length} missing key(s); `
  + `${left.length} still missing after this batch; ${same} identical to English`);
if (problems.length) {
  console.error(`\nREFUSED (${problems.length} problem(s)):`);
  for (const p of problems.slice(0, 30)) console.error(`  ${p}`);
  process.exit(1);
}
if (!WRITE) { console.log('every entry passes — pass --write to merge'); process.exit(0); }

fs.writeFileSync(dictFile, JSON.stringify({ ...target, ...batch }, null, 2) + '\n', 'utf8');
const back = read(dictFile);
if (!Object.entries(batch).every(([k, v]) => back[k] === v)) { console.error('READ-BACK MISMATCH'); process.exit(1); }
console.log(`merged into ${dictFile}: ${Object.keys(back).length} keys. Next: node scripts/i18n-generate.mjs && node scripts/check-i18n.mjs`);
