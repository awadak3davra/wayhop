// check-i18n.mjs — CI + local guard for the embedded UI dictionaries.
//
// A missing key or a dropped {0}/{1} placeholder in one language silently breaks that language's UI at
// runtime — the Go build can't catch it. This runs each dict file in a minimal window shim and asserts:
//   • web/dist/iptv-i18n.js (the IPTV plugin dict, one index-aligned array per lang) — STRICT: >=13
//     languages, every language has the SAME complete key set, non-empty, {0}/{1} preserved.
//   • web/dist/i18n.js (the core panel dict) — LENIENT: >=13 languages, and for every key a language
//     DOES have: non-empty + {0}/{1} preserved. (No completeness check — ~hundreds of keys are
//     intentionally left English per that file's header, so completeness would false-positive.)
//
// Usage: node scripts/check-i18n.mjs   (exit 1 on any problem)
import fs from 'node:fs';

const problems = [];

// load runs a dict file (window.WR_DICTS = {...} or the IIFE-merge form) and returns WR_DICTS.
function load(file) {
  const src = fs.readFileSync(file, 'utf8');
  const win = { WR_DICTS: {} };
  new Function('window', src)(win);
  return win.WR_DICTS || {};
}

function checkDict(file, lang, dict, keys) {
  for (const k of keys) {
    const tr = dict[k];
    if (tr == null) { problems.push(`${file} [${lang}]: MISSING ${JSON.stringify(k)}`); continue; }
    if (String(tr).trim() === '') { problems.push(`${file} [${lang}]: EMPTY ${JSON.stringify(k)}`); continue; }
    for (const p of ['{0}', '{1}']) {
      if (k.includes(p) && !String(tr).includes(p)) problems.push(`${file} [${lang}]: dropped ${p} in ${JSON.stringify(k)} -> ${JSON.stringify(tr)}`);
    }
  }
}

// iptv-i18n.js — strict: all languages complete against the union of every language's keys.
{
  const D = load('web/dist/iptv-i18n.js');
  const langs = Object.keys(D);
  if (langs.length < 13) problems.push(`iptv-i18n.js: expected >=13 languages, got ${langs.length}: ${langs.join(',')}`);
  const ref = new Set();
  for (const l of langs) for (const k of Object.keys(D[l])) ref.add(k);
  const refKeys = [...ref];
  for (const lang of langs) checkDict('iptv-i18n.js', lang, D[lang], refKeys);
}

// i18n.js — lenient: placeholder-parity + non-empty over each language's own keys.
{
  const D = load('web/dist/i18n.js');
  const langs = Object.keys(D);
  if (langs.length < 13) problems.push(`i18n.js: expected >=13 languages, got ${langs.length}: ${langs.join(',')}`);
  for (const lang of langs) checkDict('i18n.js', lang, D[lang], Object.keys(D[lang]));
}

if (problems.length) {
  console.error(`i18n check FAILED (${problems.length}):\n` + problems.slice(0, 40).join('\n'));
  process.exit(1);
}
console.log('i18n OK: iptv-i18n.js (13 langs, complete, placeholders) + i18n.js (placeholder-parity, non-empty) — clean.');
