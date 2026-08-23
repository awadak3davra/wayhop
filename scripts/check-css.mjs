// check-css.mjs — does the stylesheet actually parse?
//
// A CSS parse error is silent. The browser discards what it cannot read and renders the rest, so a
// broken stylesheet looks like a fix that "didn't work" rather than like an error. That happened
// here: revising a comment left its closing `*/` in place and added a second one, so the prose
// between them became stray tokens, the `.nt-row` rules after it were dropped, and the layout fix
// was built, deployed to two routers and screenshotted before a DOM measurement showed
// `display: block` where `display: grid` was written. Nothing in the suite looks at CSS validity —
// every UI gate measures the RESULT, and a dropped rule changes the result into something the gate
// has no opinion about.
//
// Four structural properties, no judgement:
//   1. every `/*` is closed, and no `*/` appears outside a comment;
//   2. braces balance;
//   3. the file declares at least a floor of rules — a check that passes on an empty or truncated
//      stylesheet would prove nothing.
//   4. the `hidden` attribute is honoured globally. This one is not about parsing: `[hidden]` is a
//      UA rule at the bottom of the cascade, so any explicit `display` in this file silently beats
//      it and an element the code marked hidden stays on screen. Measured on the router: the
//      diagnostics filter set `hidden` on the 21 checks that did not match the query and all 21
//      remained visible, because `.health-row` is `display:flex` — the field read as dead. Two
//      earlier one-selector patches for the same defeat are still in the file, which is the
//      evidence that per-selector fixes do not hold.
//
// Limitation, stated rather than hidden: comment markers inside a string or url() would be miscounted.
// There are none in this file today and the check reports the line, so a false positive would be
// obvious rather than mysterious. A real tokenizer would be the fix if that ever changes.
import fs from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const FILES = ['web/dist/styles.css'];
const MIN_RULES = 400;

let fails = 0;
const fail = (msg) => { console.error('FAIL  ' + msg); fails++; };
let rulesTotal = 0;

for (const rel of FILES) {
  const file = path.join(ROOT, rel);
  if (!fs.existsSync(file)) { fail(`${rel} is missing`); continue; }
  const src = fs.readFileSync(file, 'utf8');

  let inComment = false, depth = 0, line = 1, rules = 0, opened = 0;
  for (let i = 0; i < src.length; i++) {
    if (src[i] === '\n') { line++; continue; }
    if (inComment) {
      if (src[i] === '*' && src[i + 1] === '/') { inComment = false; i++; }
      continue;
    }
    if (src[i] === '/' && src[i + 1] === '*') { inComment = true; opened = line; i++; continue; }
    if (src[i] === '*' && src[i + 1] === '/') {
      fail(`${rel}:${line} has a \`*/\` outside a comment — everything after it until the parser ` +
        'recovers is discarded, silently');
      i++;
      continue;
    }
    if (src[i] === '{') { depth++; if (depth === 1) rules++; }
    else if (src[i] === '}') {
      depth--;
      if (depth < 0) { fail(`${rel}:${line} closes a brace that was never opened`); depth = 0; }
    }
  }
  if (inComment) fail(`${rel}: a comment opened on line ${opened} is never closed`);
  if (depth !== 0) fail(`${rel}: ${depth} unclosed brace(s) at end of file`);
  rulesTotal += rules;
  console.log(`  ${rel}: ${rules} top-level rule(s)`);
}

// Property 4. `!important` is load-bearing here rather than a shortcut: without it the rule sits at
// the same origin as every `display` in this file and loses to all of them on specificity. The gate
// therefore pins the declaration, not just the selector.
{
  const rel = FILES[0];
  const text = fs.readFileSync(path.join(ROOT, rel), 'utf8');
  const rule = text.match(/^[ \t]*\[hidden\][ \t]*\{([^}]*)\}/m);
  if (!rule) {
    fail(`${rel}: no global \`[hidden]\` rule. The UA stylesheet's own \`[hidden]\` loses to every ` +
      'explicit `display` here, so marking an element hidden would leave it on screen.');
  } else {
    const body = rule[1].replace(/\s+/g, ' ').trim();
    if (!/display\s*:\s*none/.test(body)) {
      fail(`${rel}: the global \`[hidden]\` rule does not set \`display:none\` (${body})`);
    } else if (!/!important/.test(body)) {
      fail(`${rel}: the global \`[hidden]\` rule lacks \`!important\` (${body}), so any explicit ` +
        '`display` in this file outranks it and hidden elements stay visible');
    } else {
      console.log(`  ${rel}: global [hidden] honoured — ${body}`);
    }
  }
}

if (rulesTotal < MIN_RULES) {
  fail(`only ${rulesTotal} rule(s) parsed, below the floor of ${MIN_RULES} — the stylesheet is ` +
    'truncated or this check is reading the wrong file');
}

if (fails) {
  console.error(`\n${fails} stylesheet problem(s). A rule the browser discards is not a rule that ` +
    'failed to work — it is one that was never read.');
  process.exit(1);
}
console.log('\nstylesheet parses: comments closed, braces balanced');
console.log(`subjects: ${rulesTotal} top-level rules checked`);
