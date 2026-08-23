// check-i18n.mjs — CI + local guard for the embedded UI dictionaries.
//
// A missing key or a dropped {0}/{1} placeholder in one language silently breaks that language's UI at
// runtime — the Go build can't catch it. This runs each dict file in a minimal window shim and asserts:
//   • deferred/features/plugins-iptv/ui/iptv-i18n.js in the development repository (the deferred IPTV dictionary) — STRICT when
//     present: >=MIN_LANGS languages, the SAME complete key set in each, non-empty, {0}/{1} preserved.
//     Published trees drop deferred/, so its absence is announced and skipped, never silently passed.
//   • web/i18n/*.json (the tracked source of truth) — >=MIN_LANGS languages, every entry non-empty + {0}/{1}
//     preserved, AND completeness: every STATIC t("literal") key used in the UI code is present in
//     every language (the dicts reached full coverage in 0.5.3 — this locks it so a new untranslated
//     string fails CI). Dynamic t(`...${x}...`) keys can't be pre-translated and are not checked.
//   • web/dist/i18n/<lang>.js (what the browser downloads) — must match the source exactly.
//
// Usage: node scripts/check-i18n.mjs   (exit 1 on any problem)
import fs from 'node:fs';

// MIN_LANGS is the floor, and it is a fact about what the panel PROMISES, not a target to grow.
//
// It was 13 while the panel shipped 15. The operator narrowed the set to CIS, Europe and the two
// circumvention markets that matter here — Turkey and Iran — and the CJK/Indic/Arabic dictionaries
// were deleted rather than left to rot: a language in the picker that nobody maintains is a promise
// the panel cannot keep. Nine dictionaries ship now (be, de, es, fa, fr, pt, ru, tr, uk) plus
// English as the source language. The floor still exists so a regeneration cannot quietly drop one.
const MIN_LANGS = 9;

const problems = [];
let deferredChecked = false;

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

// Keep the deferred IPTV dictionary healthy so the feature can be restored without translation loss.
//
// It lives under deferred/, which the DEVELOPMENT tree carries and the published one does not — the
// whole point of deferring it. So its absence is stated and skipped rather than failed: in the dev
// tree the file is there and every assertion below runs, and in a public clone there is nothing to
// assert about a feature that is not shipped. What is NOT allowed is the file being present and
// incomplete; that still fails, which is the case this block exists for.
{
  const file = 'deferred/features/plugins-iptv/ui/iptv-i18n.js';
  if (!fs.existsSync(file)) {
    console.log('i18n: deferred IPTV dictionary not in this tree (published trees drop deferred/) — '
      + 'its checks are skipped, the core dictionaries below are not.');
  } else {
  const D = load(file);
  const langs = Object.keys(D);
  if (langs.length < MIN_LANGS) problems.push(`${file}: expected >=${MIN_LANGS} languages, got ${langs.length}: ${langs.join(',')}`);
  const ref = new Set();
  for (const l of langs) for (const k of Object.keys(D[l])) ref.add(k);
  const refKeys = [...ref];
  for (const lang of langs) checkDict(file, lang, D[lang], refKeys);
  deferredChecked = true;
  }
}

// loadSource reads the TRACKED source of truth, web/i18n/<lang>.json.
//
// This used to read web/dist/i18n.js — a generated 2.1 MB monolith built from `.claude/i18n/dicts/`,
// a dev-only directory that never reached the published tree. So the gate validated an artefact
// nobody could reproduce, the monolith was embedded into the binary by //go:embed and served to
// nobody (index.html loads i18n-meta.js + one i18n/<lang>.js), and a public clone could read the
// dictionaries but never regenerate them. Source, gate and shipped files now all point at one place.
function loadSource() {
  const dir = 'web/i18n';
  if (!fs.existsSync(dir)) {
    problems.push(`${dir} is missing — it is the source of truth for every dictionary, and without it `
      + 'this check would pass by having nothing to compare.');
    return {};
  }
  const out = {};
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith('.json') || f === 'langs.json') continue;
    out[f.slice(0, -5)] = JSON.parse(fs.readFileSync(`${dir}/${f}`, 'utf8'));
  }
  return out;
}

// placeholder-parity + non-empty over each language's own keys, then a completeness gate.
{
  const D = loadSource();
  const langs = Object.keys(D);
  if (langs.length < MIN_LANGS) problems.push(`i18n.js: expected >=${MIN_LANGS} languages, got ${langs.length}: ${langs.join(',')}`);
  for (const lang of langs) checkDict('i18n.js', lang, D[lang], Object.keys(D[lang]));

  // COMPLETENESS: every static t("literal") key rendered by the UI code must exist in every language.
  const interpret = (b) => b.replace(/\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)/g, (_w, e) => {
    switch (e[0]) {
      case 'n': return '\n'; case 't': return '\t'; case 'r': return '\r';
      case '\\': return '\\'; case '"': return '"'; case "'": return "'"; case '`': return '`'; case '/': return '/';
      case 'u': case 'x': return String.fromCharCode(parseInt(e.slice(1), 16));
      default: return e;
    }
  });
  const used = new Set();
  // (?<![\w.$]) so a method/identifier call like `obj.t(` or `dt(` isn't harvested as a
  // translator key (which would wrong-FAIL CI). A bare t("…") in a comment is a rare residual.
  const reT = /(?<![\w.$])t\(\s*(["'`])((?:\\.|(?!\1).)*)\1/g;
  // A string is not always translated where it is written. A table of labels is built at module load,
  // before the language is known, so it holds English and goes through t() at render instead — and
  // matching only `t("…")` made every one of those literals invisible here. The consequence was not a
  // missing translation but a WRONG VERDICT: a label plainly on screen was reported as "no longer
  // used", i.e. as a translation to delete in fifteen languages (AUD-199).
  //
  // L() is the identity function web/dist/app.js uses to mark exactly that case. Same lookbehind as
  // above, so an identifier ending in L — `URL(`, `htmlL(` — is not harvested.
  const reL = /(?<![\w.$])L\(\s*(["'`])((?:\\.|(?!\1).)*)\1/g;
  // tn() is t() for a phrase that carries a count: its key holds the plural forms separated by
  // "|" and the count picks one. The key stays the FIRST argument, deliberately, so it is
  // harvested exactly like a t() key — a helper whose key sat in second place would be invisible
  // to this scan, and an untranslated counter would ship in English in nine languages with
  // nothing going red.
  const reTn = /(?<![\w.$])tn\(\s*(["'`])((?:\\.|(?!\1).)*)\1/g;
  // Route-scoped chunks (web/dist/page-*.js) are discovered rather than listed. They hold real UI
  // strings, and a hard-coded file list stops seeing them the moment a page is split out: the first
  // split moved 13 strings into page-diagnostics.js and this check immediately called them "no longer
  // used", which is the instruction to DELETE their translations in 15 languages.
  const chunks = fs.existsSync('web/dist')
    ? fs.readdirSync('web/dist').filter((f) => /^page-.*\.js$/.test(f)).map((f) => 'web/dist/' + f)
    : [];
  for (const f of ['web/dist/app.js', 'web/dist/nav.js', ...chunks]) {
    if (!fs.existsSync(f)) continue;
    const s = fs.readFileSync(f, 'utf8');
    reT.lastIndex = 0; // shared regex objects, and /g keeps lastIndex between files
    reL.lastIndex = 0;
    let m;
    while ((m = reT.exec(s)) !== null) used.add(interpret(m[2]));
    while ((m = reL.exec(s)) !== null) used.add(interpret(m[2]));
    reTn.lastIndex = 0;
    while ((m = reTn.exec(s)) !== null) used.add(interpret(m[2]));
  }
  // Making the thirteen current labels visible is not the same as making the NEXT one visible. L() is
  // a convention, and a convention that only a comment enforces is one rebuild away from being broken
  // silently: an unmarked label is invisible here, so an untranslated one ships in English in fifteen
  // languages without a single check going red. So require the shape rather than trust it.
  //
  // The map's keys are bare identifiers, which is what lets this read every quoted literal in the
  // block as a value. And the absence of the block is a FAILURE, not a pass — a check that goes green
  // when its subject is gone would quietly stop covering the rename that comes after the next one.
  const appSrc = fs.existsSync('web/dist/app.js') ? fs.readFileSync('web/dist/app.js', 'utf8') : '';
  const mapAt = appSrc.indexOf('const HC_LABEL = {');
  const mapEnd = mapAt < 0 ? -1 : appSrc.indexOf('\n};', mapAt);
  if (mapAt < 0 || mapEnd < 0) {
    problems.push('web/dist/app.js: the HC_LABEL block this check reads is gone or reshaped — if the '
      + 'Diagnostics labels moved, point this check at their new home; do not let it pass by absence.');
  } else {
    const body = appSrc.slice(mapAt, mapEnd)
      .split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n');
    // Walk the literals in order and look at what precedes each OPENING quote. A lookbehind on the
    // quote itself cannot do this: it also fires on the closing quote of a properly wrapped label, and
    // then pairs it with the opening quote of the next one — which reported nine perfectly good labels
    // as bare, quoting fragments like `), internet: L(` as their text.
    const bare = [];
    const reLit = /(["'`])((?:\\.|(?!\1).)*)\1/g;
    let lm;
    while ((lm = reLit.exec(body)) !== null) {
      if (body.slice(Math.max(0, lm.index - 2), lm.index) === 'L(') continue;
      bare.push(lm[2]);
    }
    if (bare.length) {
      problems.push(`web/dist/app.js: ${bare.length} Diagnostics label(s) are written as a bare string `
        + `and are therefore invisible to this check — wrap each in L() so it can be seen and, if it `
        + `is new, recorded as awaiting translation: ${bare.map((s) => JSON.stringify(s)).join(', ')}`);
    }
  }

  // Strings the redesign introduced are held back from translation on purpose: the wording is still
  // moving, and translating a sentence twice wastes thirteen languages' worth of work. They are
  // listed explicitly rather than skipped by a pattern, so the gate still fails for a string somebody
  // simply forgot — that list is the whole difference between "deferred" and "missed".
  //
  // Every entry must be translated before the redesign ships; the file is the ship checklist.
  const pending = new Set(JSON.parse(fs.readFileSync('scripts/i18n-pending.json', 'utf8')).pending);
  const stale = [...pending].filter(k => !used.has(k));
  if (stale.length) {
    problems.push(`scripts/i18n-pending.json lists ${stale.length} string(s) the UI no longer uses — `
      + `drop them so the list keeps meaning something: ${stale.map(s => JSON.stringify(s)).join(', ')}`);
  }
  let deferred = 0;
  for (const lang of langs) for (const k of used) {
    const tr = D[lang][k];
    if (tr != null && String(tr).trim() !== '') continue;
    if (pending.has(k)) { deferred++; continue; }
    problems.push(`i18n.js [${lang}]: INCOMPLETE — UI key not translated: ${JSON.stringify(k)}`);
  }
  if (deferred) {
    console.log(`i18n: ${pending.size} redesign string(s) awaiting translation across `
      + `${langs.length} languages (${deferred} slots) — see scripts/i18n-pending.json`);
  }
}

// THE FILES CHECKED ABOVE ARE NOT THE FILES THE PANEL LOADS.
//
// index.html loads i18n-meta.js and i18n-loader.js, and the loader document.write()s
// `i18n/<lang>.js` — one dictionary per language, generated by scripts/i18n-generate.mjs. So every
// check above can be green while the browser is served something else entirely, and it was: 260
// strings were translated into fifteen languages, merged, regenerated, committed and DEPLOYED to the
// router, and the panel went on showing the previous dictionaries, because only the (then existing)
// monolith had been rebuilt. The shipped files were three days stale — ru held 1488 keys where the
// source held 1530 — and nothing here could see it.
//
// So the generated files are compared against the SOURCE, key for key and value for value. Their
// absence is a FAILURE rather than a skip: if generation is ever dropped, this must go red.
{
  const D = loadSource();
  const dir = 'web/dist/i18n';
  if (!fs.existsSync(dir)) {
    problems.push(`${dir} is missing — the panel loads i18n/<lang>.js, so with this directory gone `
      + 'there is nothing to serve and nothing here would have noticed.');
  } else {
    for (const lang of Object.keys(D)) {
      const f = `${dir}/${lang}.js`;
      if (!fs.existsSync(f)) { problems.push(`${f} is missing — ${lang} would fall back to English in the browser`); continue; }
      const shipped = load(f)[lang];
      if (!shipped) { problems.push(`${f} does not define WR_DICTS.${lang}`); continue; }
      const src = D[lang];
      const missing = Object.keys(src).filter((k) => !(k in shipped));
      const differ = Object.keys(src).filter((k) => k in shipped && shipped[k] !== src[k]);
      if (missing.length || differ.length) {
        problems.push(`${f} is STALE against web/i18n/${lang}.json: ${missing.length} key(s) absent, `
          + `${differ.length} value(s) different (e.g. ${JSON.stringify((missing[0] || differ[0] || '').slice(0, 50))}). `
          + 'Run `node scripts/i18n-generate.mjs` and commit the result.');
      }
    }
  }
}

if (problems.length) {
  console.error(`i18n check FAILED (${problems.length}):\n` + problems.slice(0, 40).join('\n'));
  process.exit(1);
}
// The success line names only what was actually examined. It used to claim the deferred IPTV
// dictionary was complete even in a tree that does not contain it — a verdict wider than its
// measurement, which is the fault this whole check exists to catch elsewhere.
console.log(`i18n OK: ${deferredChecked ? 'deferred IPTV dictionary + ' : ''}active core dictionaries `
  + 'are complete and placeholder-safe, and the per-language files the browser actually loads match '
  + `them.${deferredChecked ? '' : ' The deferred IPTV dictionary is not in this tree and was not checked.'}`);
