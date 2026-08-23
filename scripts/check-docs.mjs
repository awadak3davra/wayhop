// check-docs.mjs — the audit and deliverables documents are deliverables too, so they get a gate.
//
// Two properties, both structural (no parsing of prose, no judgement calls):
//
//   1. No audit row may claim a flat `Pass` while naming a manual router test that has not been
//      run. This discipline held by hand across 48 findings, and a hand-held discipline is one
//      distraction away from lapsing — the first review of this table found ELEVEN rows claiming
//      more than their evidence column showed.
//   2. Every string the audit lists for the post-acceptance translation pass must still exist in
//      the source. A stale entry sends that pass chasing text nobody can find.
//   3. Every test deleted by the strict Apply cutover has one parity-table row, and every replacement
//      named by that row is an executable test that still exists.
//
// Deliberately NOT checked: the reverse of (2) — that every new literal in the code appears in the
// table. Doing it soundly needs a real JS/Go string tokenizer; three regex attempts over the diff
// returned mostly code fragments, and a check that reports garbage is worse than no check. The
// table is maintained by hand as strings are introduced, and that limit is stated in the audit
// rather than papered over with a check that looks rigorous and is not.
import fs from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const AUDIT = path.join(ROOT, 'docs', 'AUDIT_0.5.5.md');
const APP = path.join(ROOT, 'web', 'dist', 'app.js');
const INTERNAL = path.join(ROOT, 'internal');

let fails = 0;
const fail = (msg) => { console.error('FAIL  ' + msg); fails++; };

// publish/scrub-rules.json in the development repository drops `docs/` wholesale — session audits
// and working notes are not redistributed — and drops `publish/` itself, while `scripts/` ships
// unfiltered. So this gate reached the published tree where its subject deliberately does not
// exist, exited 1 on its first statement, and `node scripts/verify.mjs` there scored 12/14 with
// "the audit is missing" read as a defect in the audit rather than as a gate running somewhere it
// does not apply.
//
// The presence of the publish rules IS the discriminator: they are what removes the documents, and
// they are removed along with them. In the development tree the audit is a deliverable and its
// absence stays a failure. In a redistribution tree the absence is announced and the contracts that
// depend on it are skipped — the same way check-i18n.mjs handles the deferred IPTV dictionary.
// Never a silent pass either way.
const DEV_TREE = fs.existsSync(path.join(ROOT, 'publish', 'scrub-rules.json'));

if (!fs.existsSync(AUDIT)) {
  if (DEV_TREE) {
    console.error(`FAIL  ${AUDIT} is missing — the audit is a deliverable`);
    process.exit(1);
  }
  console.log('check-docs: the audit is not in this tree (published trees drop docs/) — every '
    + 'assertion here reads it, so all of them are skipped and none is reported as passing.');
  process.exit(0);
}
const audit = fs.readFileSync(AUDIT, 'utf8');

// ---- 0. deleted-test parity is complete and points at executable evidence -------------------
const DELETED_APPLY_TESTS = [
  'TestRestoreNativeBaseline_RemovesTheInterfaceThisWindowWrote',
  'TestRestoreNativeBaseline_KeepsAnInterfaceThatPredatesTheWindow',
  'TestRestoreNativeBaseline_IgnoresEndpointsWithNoNativeInterface',
  'TestSyncNativeInterfaces_WritesTheInterfaceForAnAmneziaWGEndpoint',
  'TestSyncNativeInterfaces_ASecondApplyWritesNothing',
  'TestSyncNativeInterfaces_RefusesToWriteWhenTheRouterCannotBeRead',
  'TestSyncNativeInterfaces_OnlyOnOpenWrtAndNotInDemo',
  'TestSyncNativeInterfaces_LeavesPlainWireGuardToTheExplicitPath',
  'TestSyncPlugins_BringsUpFromProfile',
  'TestSyncPlugins_DemoNoop',
  'TestHandlePBRApply_ModeGated',
  'TestPass4_BootSyncInstallsHybrid',
  'TestPass4_BootSyncOrphanTeardown',
  'TestNetvpnMutationRoutesAreDarkUntilStrictNativeExecutionIsWired',
];
const parityStart = audit.indexOf('### Deleted-test coverage parity');
const parityEnd = audit.indexOf('\n## ', parityStart + 3);
if (parityStart < 0 || parityEnd < 0) {
  fail('the deleted-test coverage parity table is missing or unterminated');
} else {
  const parity = audit.slice(parityStart, parityEnd);
  const testSource = (() => {
    const readTests = (dir) => fs.readdirSync(dir, { withFileTypes: true }).map((entry) => {
      const item = path.join(dir, entry.name);
      if (entry.isDirectory()) return readTests(item);
      return entry.name.endsWith('_test.go') ? fs.readFileSync(item, 'utf8') : '';
    }).join('\n');
    return readTests(INTERNAL);
  })();
  const rows = parity.split('\n').filter((line) => line.startsWith('| `Test'));
  const documented = new Set();
  for (const row of rows) {
    const cells = row.split(' | ');
    const removed = cells[0]?.replace(/^\| `|`$/g, '');
    if (!removed || documented.has(removed)) {
      fail(`duplicate or malformed deleted-test parity row: ${row.slice(0, 100)}`);
      continue;
    }
    documented.add(removed);
    const replacements = [...(cells[2] || '').matchAll(/`(Test[A-Za-z0-9_]+)`/g)].map((m) => m[1]);
    if (replacements.length === 0) {
      fail(`${removed} names no executable replacement or refusal test`);
    }
    for (const replacement of replacements) {
      if (!testSource.includes(`func ${replacement}(`)) {
        fail(`${removed} cites missing replacement test ${replacement}`);
      }
    }
  }
  for (const removed of DELETED_APPLY_TESTS) {
    if (!documented.has(removed)) fail(`deleted test ${removed} has no coverage-parity row`);
  }
  for (const removed of documented) {
    if (!DELETED_APPLY_TESTS.includes(removed)) fail(`unexpected deleted-test parity row ${removed}`);
  }
  console.log(`deleted-test parity: ${documented.size}/${DELETED_APPLY_TESTS.length} rows verified`);
}

// ---- 1. no row claims more than its evidence -----------------------------------------------
// Table B rows are `| AUD-nn | proposed | enforcement | tests | manual | result | evidence |`.
const tbStart = audit.indexOf('## Table B');
const tbEnd = audit.indexOf('## The one defect');
const rows = audit.slice(tbStart, tbEnd > 0 ? tbEnd : undefined)
  .split('\n').filter((l) => l.startsWith('| AUD-'));

if (rows.length === 0) fail('no Table B rows found — has the audit format changed?');

// Row shape. Two tables here carry `| AUD-nnn |` rows with DIFFERENT column counts, and an anchored
// insert matched the first table while carrying the second one's shape — the rows landed in Table A
// looking like Table B and nothing noticed, because every count this file checks was derived from
// Table B alone. A literal `|` inside a code span does the same damage by accident: AUD-50 held one
// and rendered as eleven cells, tearing its issue text across three columns and pushing its severity
// out of the severity column. Both are the same check — a row must have as many cells as its header.
// `\|` is how GFM carries a literal pipe inside a cell, so it is NOT a separator. Counting it as one
// made this check reject the very escaping it asks for — it flagged a row, and then flagged the fix.
const cellCount = (l) => l.split(/(?<!\\)\|/).length - 2;
for (const [label, start, end] of [['A', audit.indexOf('## Table A'), tbStart],
                                   ['B', tbStart, tbEnd > 0 ? tbEnd : audit.length]]) {
  if (start < 0) { fail(`Table ${label} heading not found — has the audit format changed?`); continue; }
  const lines = audit.slice(start, end).split('\n');
  const header = lines.find((l) => l.startsWith('| ID |'));
  if (!header) { fail(`Table ${label} has no header row`); continue; }
  const want = cellCount(header);
  for (const r of lines.filter((l) => l.startsWith('| AUD-'))) {
    const got = cellCount(r);
    if (got !== want) {
      fail(`Table ${label} row ${r.slice(2, r.indexOf(' |', 2))} has ${got} cells, header has ${want}` +
        (got > want ? ' — an unescaped `|` inside a cell renders as extra columns' : ''));
    }
  }
}

// Rows whose manual test genuinely WAS performed; each is justified in its evidence column.
// Rows whose named hardware test has actually been run. Listed explicitly rather than inferred
// from wording: this gate must not start reading prose to decide whether a claim is backed.
// AUD-55/75/76/77 were verified on the AX3000T after the 0.5.5 install was authorised.
// AUD-43: the detector's output on the AX3000T was compared line by line against `nft list
// ruleset` there — the :53 redirect, the :853 handling and the leak verdict all matched the
// firewall it was read from. That same comparison produced AUD-225.
// AUD-174: the missing obfuscation fields were observed on the AX3000T's own panel, and the form carrying
// them was inspected there after deploying this build — all 16 present with the right input types.
const VERIFIED_ON_HARDWARE = new Set(['AUD-43', 'AUD-174', 'AUD-160', 'AUD-161', 'AUD-144', 'AUD-145', 'AUD-142', 'AUD-137', 'AUD-138', 'AUD-11', 'AUD-12', 'AUD-55', 'AUD-75', 'AUD-76', 'AUD-77',
  'AUD-78', 'AUD-79', 'AUD-80', 'AUD-81', 'AUD-82', 'AUD-83', 'AUD-84', 'AUD-86', 'AUD-87', 'AUD-89', 'AUD-90', 'AUD-91', 'AUD-92', 'AUD-96', 'AUD-97', 'AUD-98', 'AUD-99', 'AUD-101', 'AUD-102', 'AUD-103', 'AUD-104', 'AUD-106', 'AUD-107', 'AUD-108', 'AUD-109', 'AUD-110', 'AUD-111', 'AUD-112', 'AUD-113', 'AUD-114', 'AUD-115', 'AUD-116', 'AUD-117', 'AUD-118', 'AUD-119', 'AUD-120', 'AUD-121']);

// The deliverables spell small counts out, so several claims here have to read a word as a number.
// ONE table for all of them: this file already records what two copies cost — the list was extended
// to reach "Twenty-one" while a pattern elsewhere still could not match a hyphen, and that check went
// quietly inert at exactly the point the table was taught the case it needed.
const NUMBER_WORDS = { No: 0, None: 0, Zero: 0, One: 1, Two: 2, Three: 3, Four: 4, Five: 5, Six: 6,
  Seven: 7, Eight: 8, Nine: 9, Ten: 10, Eleven: 11, Twelve: 12, Thirteen: 13, Fourteen: 14,
  Fifteen: 15, Sixteen: 16, Seventeen: 17, Eighteen: 18, Nineteen: 19, Twenty: 20,
  'Twenty-one': 21, 'Twenty-two': 22, 'Twenty-three': 23, 'Twenty-four': 24,
  'Twenty-five': 25, 'Twenty-six': 26, 'Twenty-seven': 27, 'Twenty-eight': 28,
  'Twenty-nine': 29, Thirty: 30, 'Thirty-one': 31 };
// Returns undefined for a word the table does not know, so a caller can tell "wrong number" from
// "number I cannot read" — those deserve different failures.
const wordNum = (s) => {
  if (/^\d+$/.test(s)) return Number(s);
  const key = Object.keys(NUMBER_WORDS).find((w) => w.toLowerCase() === String(s).toLowerCase());
  return key === undefined ? undefined : NUMBER_WORDS[key];
};

let flat = 0, coded = 0, open = 0;
const openIds = [];
for (const row of rows) {
  const cells = row.split(' | ');
  // Shape first. These tables are edited by pattern replacement, and one insertion meant for
  // Table A matched in Table B instead, overwriting a row's proposed-change cell with fragments
  // of a Table A row — leaving 8 cells where 7 belong. It survived several passes because every
  // other check skipped malformed rows rather than reporting them.
  if (cells.length !== 7) {
    fail(`${cells[0].replace(/[|\s]/g, '')} has ${cells.length} cells, expected 7 — the row is malformed`);
    continue;
  }
  const id = cells[0].replace(/[|\s]/g, '');
  const manual = cells[cells.length - 3].trim();
  const result = cells[cells.length - 2].trim();

  const namesRouterTest = manual !== '—' && manual !== '' && manual !== 'n/a';
  const isPassCode = result.includes('Pass (code)');
  const isFlatPass = result.includes('Pass') && !isPassCode;

  if (isPassCode) coded++; else if (isFlatPass) flat++;
  // Counted here rather than in the deliverables, for the reason the Open claim below states.
  if (result.includes('Open')) { open++; openIds.push(id); }

  if (namesRouterTest && isFlatPass && !VERIFIED_ON_HARDWARE.has(id)) {
    fail(`${id} claims a flat Pass but names a manual router test that has not been run: "${manual.slice(0, 60)}…"`);
  }
  if (result.includes('Open') && isPassCode) {
    fail(`${id} says both Pass (code) and Open — pick one`);
  }
}
console.log(`audit rows: ${rows.length}  (Pass ${flat}, Pass (code) ${coded}, Open ${open})`);

// ---- 2. every listed translation string still exists ----------------------------------------
const readAll = (dir) => {
  let out = '';
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out += readAll(p);
    else if (e.name.endsWith('.go') && !e.name.endsWith('_test.go')) out += fs.readFileSync(p, 'utf8');
  }
  return out;
};
const chunkSrc = fs.existsSync(path.join(ROOT, 'web', 'dist'))
  ? fs.readdirSync(path.join(ROOT, 'web', 'dist')).filter((f) => /^page-.*\.js$/.test(f))
      .map((f) => fs.readFileSync(path.join(ROOT, 'web', 'dist', f), 'utf8')).join('\n')
  : '';
const haystack = (fs.existsSync(APP) ? fs.readFileSync(APP, 'utf8') : '') + chunkSrc +
  (fs.existsSync(INTERNAL) ? readAll(INTERNAL) : '');

const tblStart = audit.indexOf('| string | where |');
let listed = 0;
if (tblStart < 0) {
  fail('the new-strings table is missing — the translation pass depends on it');
} else {
  for (const line of audit.slice(tblStart).split('\n')) {
    if (!line.startsWith('| `')) continue;
    for (const m of line.split(' | ')[0].matchAll(/`([^`]+)`/g)) {
      const s = m[1].trim();
      // Entries describing a COMPOSED name (placeholders, ellipses) have no verbatim form.
      if (/[<…]/.test(s) || s.startsWith('(') || /\b[NXM] of [NM]\b/.test(s)) continue;
      listed++;
      const probe = s.split('—')[0].trim().slice(0, 40);
      if (probe && !haystack.includes(probe)) {
        fail(`the audit lists a string that no longer exists in the source: "${s.slice(0, 70)}"`);
      }
    }
  }
}
console.log(`translation strings checked: ${listed}`);

// ---- 3. the deliverables document's numeric claims must match measurement -------------------
// Every number in that table was wrong at least once when maintained by hand: it claimed 30
// findings after there were 48, "13 of 30" Pass (code) after there were 26 of 48, six new gates
// when four are new, and a migration section that did not exist. It is sent to the operator, so
// the numbers are re-derived here rather than trusted.
const DELIV = path.join(ROOT, 'docs', 'DELIVERABLES_0.5.5.md');
if (!fs.existsSync(DELIV)) {
  fail('docs/DELIVERABLES_0.5.5.md is missing — it is a deliverable');
} else {
  const deliv = fs.readFileSync(DELIV, 'utf8');
  const claim = (re, what, actual) => {
    const m = deliv.match(re);
    if (!m) { fail(`the deliverables document no longer states ${what} — the check cannot verify it`); return; }
    const stated = Number(m[1]);
    if (stated !== actual) fail(`deliverables claims ${stated} ${what}, measured ${actual}`);
  };

  // EVERY occurrence, not the first one that matches. This used to read a single bolded sentence,
  // so a second statement of the same number went unchecked: "31 rows carry `Pass (code)`", sitting
  // in a table whose own evidence column cites "audit, Result column", stayed at 31 while the
  // measured value walked to 58 — and this gate printed "documents are internally consistent" over
  // the top of it. A number is not verified because one instance of it is; the instance the gate
  // does not read is exactly the one that drifts.
  const everyClaim = (re, what, actual, group = 1) => {
    const hits = [...deliv.matchAll(re)];
    if (!hits.length) {
      fail(`the deliverables document no longer states ${what} — the check cannot verify it`);
      return;
    }
    for (const m of hits) {
      if (m[group] === undefined) continue;
      if (Number(m[group]) !== actual) {
        fail(`deliverables claims ${m[group]} ${what}, measured ${actual} — in "${m[0].trim().slice(0, 64)}"`);
      }
    }
    console.log(`  ${hits.length} statement(s) of ${what} checked against measurement`);
  };

  everyClaim(/\*{0,2}(\d+)\*{0,2} findings/g, 'audit findings', rows.length);
  everyClaim(/\*{0,2}(\d+)\*{0,2}(?:\s+of\s+\*{0,2}\d+\*{0,2})?\s+rows carry\s+`Pass \(code\)`/g,
    'Pass (code) rows', coded);
  everyClaim(/\*{0,2}\d+\*{0,2}\s+of\s+\*{0,2}(\d+)\*{0,2}\s+rows carry\s+`Pass \(code\)`/g,
    'total rows (in the Pass (code) claim)', rows.length);
  everyClaim(/The other \*{0,2}(\d+)\*{0,2}/g, 'rows that are not `Pass (code)`', rows.length - coded);
  everyClaim(/(\d+) flat `Pass` rows/g, 'flat Pass rows', flat);
  // The Open count, because the sentence that used to stand here — "no audit row carries an `Open`
  // result" — was FALSE for as long as AUD-161 has existed, and nothing read it. Every other number
  // in this document is derived; the one making the strongest claim was the one still written by
  // hand, and a claim of "nothing outstanding" is exactly the claim that has to be measured.
  // `carry|carries`, because the count can legitimately be 1 and English then says "1 audit row
  // CARRIES" — a pattern matching only the plural stops matching exactly when the good news
  // arrives. The same shape of bug as the `\w`-versus-hyphen one this file already carries.
  everyClaim(/\*{0,2}(\d+)\*{0,2} audit rows? (?:carry|carries) an `Open` result/g, 'rows with an `Open` result', open);

  // The same claim is also made in prose, further down, and it escaped the gate above by spelling the
  // number as a WORD and naming the row: "One audit row is still `Open` — AUD-161". That sentence was
  // FALSE while AUD-199 was also open — the document said one and measured two — and it is the very
  // sentence the numeric gate was written for. A gate whose name says it derives the Open claim, and
  // whose pattern covers a single spelling of it, is the class of defect this audit is about.
  //
  // Naming the rows is checked too, not just counting them: "One audit row is still Open — AUD-161"
  // stays true by the count alone if AUD-161 closes on the same day another row opens, and a reader
  // sent to the wrong row is worse served than one sent nowhere.
  // Stop at the end of the SENTENCE, not the end of the line. Reading to the newline swallowed the
  // sentence that follows — which says AUD-187 CLOSED — and the check then accused the document of
  // naming a closed row as open. Widening the text under a claim until it includes a different claim
  // is the same mistake this check exists to catch, so it is worth the lookahead.
  const proseHits = [...deliv.matchAll(/\b([\w-]+) audit rows? (?:is|are) still `Open`(.*?)(?=\.\s|\n|$)/gi)];
  if (!proseHits.length) {
    fail('the deliverables document no longer states in prose which audit rows are still `Open` — '
      + 'the check cannot verify it, and its absence is not the same as nothing being open');
  }
  for (const m of proseHits) {
    const stated = wordNum(m[1]);
    if (stated === undefined) {
      fail(`deliverables says "${m[1]} audit row(s) still Open" and this check cannot read "${m[1]}" `
        + `as a number — teach NUMBER_WORDS rather than leaving the claim unread`);
      continue;
    }
    if (stated !== open) {
      fail(`deliverables says "${m[1]} audit row(s) still Open", measured ${open} (${openIds.join(', ') || 'none'})`);
      continue;
    }
    const named = [...new Set(m[2].match(/AUD-\d+/g) || [])];
    if (open > 0 && !named.length) {
      fail(`deliverables states ${open} row(s) still Open but names none — say which: ${openIds.join(', ')}`);
    } else if (named.length && (named.length !== openIds.length || named.some((id) => !openIds.includes(id)))) {
      fail(`deliverables names ${named.join(', ')} as the Open row(s); measured ${openIds.join(', ') || 'none'}`);
    }
  }
  if (proseHits.length) console.log(`  ${proseHits.length} prose statement(s) of which rows are `
    + `\`Open\` checked against measurement (${openIds.join(', ') || 'none open'})`);

  // Gate count: what verify.mjs actually registers, split by whether --apply was passed.
  const verify = fs.readFileSync(path.join(ROOT, 'scripts', 'verify.mjs'), 'utf8');
  const defined = (verify.match(/\{ name: '/g) || []).length;
  const applyGates = (verify.match(/name: 'apply faults'/g) || []).length;
  claim(/(\d+) gates without `--apply`/, 'gates without --apply', defined - applyGates);
  claim(/gates without `--apply` \((\d+) with it\)/, 'gates with --apply', defined);

  // Fault-injection checks: record() call sites, minus the if/else pairs that report one check.
  const faults = fs.readFileSync(path.join(ROOT, 'scripts', 'ui-faults.mjs'), 'utf8');
  const sites = (faults.match(/^\s*record\(/gm) || []).length;
  claim(/\((\d+) `record\(\)` call sites/, 'record() call sites', sites);

  // "Four are new" — the ui-*.mjs scripts written during this work.
  // Gate scripts written during this work. check-docs.mjs counts itself: a check that quietly
  // excluded itself from the tally it enforces would be its own first violation.
  // ui-controls.mjs joined this list only after the redesign finished. It existed throughout, but
  // was never registered in verify.mjs, so it ran by hand or not at all — which is why "written"
  // and "enforced" are checked separately below.
  const NEW_GATES = ['ui-names.mjs', 'ui-density.mjs', 'ui-page-structure.mjs',
    'ui-rule-order.mjs', 'check-docs.mjs', 'ui-controls.mjs', 'check-skips.mjs',
    'check-dom.mjs', 'check-target-fresh.mjs', 'ui-chunk-fallback.mjs', 'seed-stress.mjs',
    'seed-hostile.mjs', 'ui-injection.mjs', 'ui-render-time.mjs', 'ui-narrow.mjs', 'ui-contrast.mjs',
    'ui-keyboard.mjs', 'ui-rtl.mjs', 'ui-wrap.mjs', 'ui-columns.mjs', 'check-css.mjs', 'ui-wide.mjs',
    'check-dependency-pins.mjs', 'check-apk-signing.sh', 'check-interaction-fixes.mjs'];
  const present = NEW_GATES.filter((f) => fs.existsSync(path.join(ROOT, 'scripts', f))).length;
  // Existing is not the same as running. ui-controls.mjs was written for the redesign's one hard
  // constraint, sat in scripts/ for the whole of it, and was never referenced by verify.mjs — so the
  // documents credited a gate that the suite never executed. A gate outside the runner is a habit,
  // and this check is what stops the next one being written and forgotten.
  const runner = fs.readFileSync(path.join(ROOT, 'scripts', 'verify.mjs'), 'utf8');
  const unwired = NEW_GATES.filter((f) => f !== 'check-docs.mjs' && !runner.includes(f));
  if (unwired.length) {
    fail(`gate script(s) exist but verify.mjs never runs them: ${unwired.join(', ')}`);
  }
  if (present !== NEW_GATES.length) {
    fail(`the deliverables document credits ${NEW_GATES.length} new gates but only ${present} exist`);
  }
  // `[\w-]`, not `\w`. The pattern was `\*\*(\w+)\*\* are new`, and `\w` does not match a hyphen, so
  // it stopped matching the moment the count reached "Twenty-one" — and because the comparison was
  // guarded by `if (m && …)`, no match meant no failure. The check went quietly inert at exactly the
  // point the WORDS table below was extended to handle it, and stayed green while the sentence said
  // twenty-one and twenty-two gates existed. A claim the check cannot find is now a failure.
  const m = deliv.match(/\*\*([\w-]+)\*\* are new/);
  if (!m) {
    fail('deliverables no longer states how many gates are new in the form this check reads');
  } else if (wordNum(m[1]) !== present) {
    fail(`deliverables says ${m[1]} gates are new, ${present} exist`);
  }
  // The gate counts above are already derived from verify.mjs. The evidence-floor count was not: it
  // was still maintained by hand and had drifted to "seven" while ten floors were declared. The
  // floors are the reason a gate exiting 0 is not by itself a pass, so a wrong count here understates
  // the very mechanism the row is claiming credit for. Derive it too.
  const floors = (runner.match(/evidence: \{/g) || []).length;
  // [\w-] rather than \w: NUMBER_WORDS reaches Twenty-four, and `\w` cannot match the hyphen, so the
  // count going past twenty made this pattern miss entirely. The note above the table records the
  // same pairing costing a check its subject once already — that time it went quietly inert, this
  // time it failed loudly, which is the difference the "cannot read it" branch exists to make.
  const fm = deliv.match(/\*\*evidence\*\*: ([\w-]+) gates must print/);
  if (!fm) fail('deliverables no longer states the evidence-floor count in the form this check reads');
  else if (wordNum(fm[1]) !== floors) {
    fail(`deliverables says ${fm[1]} gates carry an evidence floor, verify.mjs declares ${floors}`);
  }
  if (!fails) console.log('deliverables numeric claims verified against measurement');
}

if (fails) {
  console.error(`\n${fails} documentation problem(s).`);
  process.exit(1);
}
console.log('audit and deliverables documents are internally consistent');
