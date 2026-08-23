// check-chunks.mjs — a function declared in one route chunk must not be called from another.
//
// Route chunks are loaded by loadChunk() the first time their route is opened. So a helper declared in
// page-server.js and called from page-diagnostics.js exists only for a visitor who happened to open
// Set up Server first. Everyone else gets a ReferenceError — and because these are render paths, the
// error takes the whole page's content with it.
//
// This is not hypothetical. `mono` was exactly that: declared in page-server.js, called from
// page-diagnostics.js:329, and opening Diagnostics directly threw `ReferenceError: mono is not
// defined`, rendered ZERO health rows and left "Run all checks" disabled forever, while the daemon
// had answered in 1.3 seconds with thirteen results. Measured on a live router and on the
// demo.
//
// The page sweep never caught it because it visits `server` second and `diagnostics` eighth: the
// chunk that defined the helper was always already loaded. A pass that depends on the order of the
// walk is not a pass about the code.
import fs from 'node:fs';
import path from 'node:path';

const DIST = path.join(process.cwd(), 'web', 'dist');
const problems = [];

// A NUL byte anywhere in the shipped frontend makes every text tool treat the file as BINARY and
// stop reading it — ripgrep, grep, gitleaks, and this gate's own regex sweep. web/dist/app.js
// carried exactly one, typed as a join separator in settingValueOf, and 456 KB of the panel was
// therefore invisible to search: the cross-chunk analysis below ran against a file its own tooling
// could not fully see. Checked FIRST, because everything after it depends on these files being text.
for (const f of fs.existsSync(DIST) ? fs.readdirSync(DIST) : []) {
  if (!/\.(js|css|html|json|svg)$/.test(f)) continue;
  const buf = fs.readFileSync(path.join(DIST, f));
  const nul = buf.filter((b) => b === 0).length;
  if (nul) {
    problems.push(`web/dist/${f} contains ${nul} NUL byte(s) — every scanner classifies it as binary `
      + 'and stops reading, so this gate and any secret scan silently cover less than they report. '
      + 'Write the escape ("\\u0000") instead of the raw byte.');
  }
}

const chunkFiles = fs.existsSync(DIST)
  ? fs.readdirSync(DIST).filter((f) => /^page-.*\.js$/.test(f)).sort()
  : [];
if (chunkFiles.length < 2) {
  console.error(`chunk check: found ${chunkFiles.length} route chunk(s) under web/dist — with fewer than two `
    + 'there is nothing to compare, and a green result here would mean the check stopped looking rather '
    + 'than that the code is sound.');
  process.exit(1);
}

// Top-level declarations. Indentation is the discriminator: these files are hand-written with
// top-level functions at column 0, and a nested helper is indented.
const declRe = /^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)|^(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/gm;
const declsOf = (src) => {
  const out = new Set();
  let m;
  declRe.lastIndex = 0;
  while ((m = declRe.exec(src)) !== null) out.add(m[1] || m[2]);
  return out;
};

const src = {};
const decls = {};
for (const f of chunkFiles) {
  src[f] = fs.readFileSync(path.join(DIST, f), 'utf8');
  decls[f] = declsOf(src[f]);
}

// Comments are stripped before looking for uses: this file's own explanation names `mono` several
// times, and a check that flagged its own prose would be noise.
const stripComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^\s*\/\/.*$/gm, ' ');

// A call or a reference, not a mention: require the identifier to stand alone and not be a
// property (`x.mono`), which would be somebody else's method.
const usesName = (body, name) => new RegExp(`(^|[^\\w$.])${name}\\s*\\(`, 'm').test(body);

let checked = 0;
for (const owner of chunkFiles) {
  for (const name of decls[owner]) {
    for (const other of chunkFiles) {
      if (other === owner) continue;
      checked++;
      if (usesName(stripComments(src[other]), name)) {
        problems.push(`${other} calls ${name}(), which is declared in ${owner}. Route chunks load on `
          + `first visit, so this throws ReferenceError for anyone who opens that page without opening `
          + `${owner.replace(/^page-|\.js$/g, '')} first. Move ${name} to web/dist/app.js.`);
      }
    }
  }
}

// The loop above compares chunks to each other and stops there, which left the hazard's other shape
// uncovered — and that is the shape that shipped. A SHARED helper declared in app.js, called from
// chunk X, whose own body reaches for a name declared in chunk Y: opening X alone loads neither Y
// nor any reason to, so the helper throws.
//
// Measured, not supposed: copyText() lives in app.js, page-diagnostics.js calls it from four Copy
// buttons, and its fallback rung execCopy() was declared in page-connections.js. On the AX3000T the
// panel is served over plain HTTP, so navigator.clipboard is undefined and that fallback is the ONLY
// path — `copyText("probe")` on #diagnostics answered `ReferenceError: execCopy is not defined`, and
// "Copy report" produced no text, no toast and no visible error.
//
// The blunt version of this check — "app.js must never name anything a chunk declares" — reports 34
// sites and is wrong for this codebase: renderers live in app.js and their helpers live in the chunk,
// and route() awaits loadChunk() before calling a renderer, so those resolve every time. Restricting
// it to helpers that CHUNKS call keeps exactly the cases where the caller's chunk cannot vouch for
// the callee's, and it is computed rather than judged.
const APP = path.join(DIST, 'app.js');
if (!fs.existsSync(APP)) {
  console.error('chunk check: web/dist/app.js is missing — the shared-helper half of this check would '
    + 'pass by having no subject, which proves nothing.');
  process.exit(1);
}
const appSrc = fs.readFileSync(APP, 'utf8');
const appOwn = declsOf(appSrc);
const appLines = appSrc.split(/\r?\n/);

// Top-level declarations by line, so a helper's body can be sliced as "until the next one".
const topAt = [];
appLines.forEach((l, i) => {
  const m = /^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/.exec(l)
    || /^(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function|\()/.exec(l);
  if (m) topAt.push({ line: i, name: m[1] });
});
const bodyOf = (idx) => {
  const start = topAt[idx].line;
  const end = idx + 1 < topAt.length ? topAt[idx + 1].line : appLines.length;
  return stripComments(appLines.slice(start, end).join('\n'));
};

// Which chunk declares each name (names app.js declares itself resolve to app.js, so skip those).
const ownerOf = new Map();
for (const f of chunkFiles) for (const n of decls[f]) if (!appOwn.has(n)) ownerOf.set(n, f);

let sharedChecked = 0;
for (let i = 0; i < topAt.length; i++) {
  const helper = topAt[i].name;
  const callers = chunkFiles.filter((f) => usesName(stripComments(src[f]), helper));
  if (!callers.length) continue; // not shared with any chunk — the renderer case, and it is fine
  const body = bodyOf(i);
  for (const [name, owner] of ownerOf) {
    if (name === helper) continue;
    sharedChecked++;
    if (!usesName(body, name)) continue;
    const orphans = callers.filter((c) => c !== owner);
    if (!orphans.length) continue; // only the declaring chunk calls it, so the name is always there
    problems.push(`${orphans.join(', ')} call(s) ${helper}() in app.js, and ${helper} calls ${name}(), `
      + `which is declared in ${owner}. Those chunks load without ${owner}, so ${helper} throws `
      + `ReferenceError there. Move ${name} to web/dist/app.js beside ${helper}.`);
  }
}

// The suite requires this line to state what was examined, and matches "<n> cross-chunk name
// comparisons" to get it. Rewording it to "<n> cross-chunk + <n> shared-helper name comparisons"
// broke that match and the gate was failed for being unable to say what it looked at — which is the
// right call, so the original phrase stays intact and the new count is appended after it.
console.log(`chunk check: ${chunkFiles.length} route chunks, ${checked} cross-chunk name comparisons`
  + ` and ${sharedChecked} shared-helper name comparisons`);
if (problems.length) {
  console.error(`\n${problems.length} cross-chunk reference(s):`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log('no route chunk calls a function declared in another route chunk');
