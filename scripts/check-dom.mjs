// Static guard for one specific, silent, whole-page-killing mistake.
//
// el() drops null children, so `el("div", {}, cond ? x : null)` is a correct and common idiom in this
// file. appendChild() does NOT: it throws "parameter 1 is not of type 'Node'". Because renderers are
// async and route() wraps them in a try/catch, the throw does not show up as a broken widget — it
// aborts the rest of the render and leaves a page that LOOKS finished while every control after the
// throw is missing. That is how the Updater page lost all of its engine rows on a router whose
// package manager owned an engine, while the demo (which owns nothing through a package manager)
// rendered perfectly. The UI gates only caught it because it happened to be flaky.
//
// So: the ternary-with-null idiom is fine inside el(...) and banned as a direct argument to
// appendChild/append/insertBefore/replaceChild/prepend.
import fs from 'node:fs';

// app.js AND every route-scoped chunk: a null reaching appendChild aborts a render just as
// completely from page-connections.js as from app.js, and the chunks are where the page-specific
// DOM building now lives — exactly the code this gate exists to police.
const FILES = ['web/dist/app.js', ...(fs.existsSync('web/dist')
  ? fs.readdirSync('web/dist').filter((f) => /^page-.*\.js$/.test(f)).map((f) => 'web/dist/' + f)
  : [])];
const METHODS = ['appendChild', 'append', 'prepend', 'insertBefore', 'replaceChild'];

// Walk the argument list of each call with a paren counter so nested el(...) calls, template strings
// and arrow bodies do not confuse a regex. Only the TOP level of the argument list is inspected: a
// null inside a nested el(...) is the legitimate idiom, a null at the top level reaches the DOM API.
function findings(src, file) {
  const out = [];
  for (const m of METHODS) {
    let from = 0;
    for (;;) {
      const at = src.indexOf('.' + m + '(', from);
      if (at < 0) break;
      from = at + m.length + 2;
      let depth = 1, i = from, top = '';
      while (i < src.length && depth > 0) {
        const c = src[i];
        if (c === '(') depth++;
        else if (c === ')') depth--;
        if (depth === 1 && c !== ')') top += c;
        i++;
      }
      // A bare `null`/`undefined` operand at the top level of the argument list, i.e. not nested
      // inside a helper call that would filter it. Split on the operators that separate operands
      // rather than pattern-matching one shape of ternary: the first cut of this check looked for
      // `cond ? x : null` and sailed straight past the real defect, which was `cond ? null : x`.
      const operands = top.split(/[?:,|&]+/).map((s) => s.trim());
      if (operands.some((s) => s === 'null' || s === 'undefined')) {
        const line = src.slice(0, at).split('\n').length;
        out.push({ file, line, m, snippet: top.replace(/\s+/g, ' ').trim().slice(0, 90) });
      }
    }
  }
  return out;
}

// el() carries an `html` key that assigns innerHTML. It is currently used NOWHERE, and that is the
// only reason hostile text is safe here: every name reaches the DOM through textContent. Endpoint
// names are not all user-typed — the importer parses share links fetched from a remote subscription
// URL — so the first use of this hatch with a dynamic value would hand the panel to whoever runs that
// subscription. Verified empirically by scripts/ui-injection.mjs; this keeps the property from being
// undone by a one-line change that looks harmless.
function htmlHatch(src, file) {
  const out = [];
  for (const m of src.matchAll(/\bhtml:\s*/g)) {
    const line = src.slice(0, m.index).split('\n').length;
    out.push({ file, line, m: 'el', snippet: src.slice(m.index, m.index + 60).split('\n')[0] });
  }
  return out;
}

let bad = [];
let hatch = [];
for (const f of FILES) {
  if (!fs.existsSync(f)) { console.error(`check-dom: ${f} not found`); process.exit(2); }
  const src = fs.readFileSync(f, 'utf8');
  bad = bad.concat(findings(src, f));
  hatch = hatch.concat(htmlHatch(src, f));
}

if (hatch.length) {
  console.error('el()\'s `html:` key assigns innerHTML. It is unused today, and the UI is injection-safe');
  console.error('only because every value reaches the DOM as text:\n');
  for (const h of hatch) console.error(`  ${h.file}:${h.line}  ${h.snippet}`);
  console.error('\nIf the value is a fixed literal, inline the markup as elements instead. If it is data,');
  console.error('do not: endpoint names can arrive from a remote subscription.');
  process.exit(1);
}

if (bad.length) {
  console.error('null reaching a DOM insertion point — appendChild throws on null and the throw');
  console.error('aborts the whole async render, leaving a page that looks complete:\n');
  for (const b of bad) console.error(`  ${b.file}:${b.line}  .${b.m}(${b.snippet})`);
  console.error('\nGuard the call with an if instead, or build the child through el(), which drops nulls.');
  process.exit(1);
}
console.log(`no null reaches appendChild/append/prepend/insertBefore/replaceChild in ${FILES.join(', ')}`);
