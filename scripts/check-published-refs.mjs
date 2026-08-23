// check-published-refs.mjs — a file that ships must not send its reader to a file that does not.
//
// publish/scrub-rules.json in the development repository drops docs/, design/, deferred/, publish/
// and the tree's working notes, and publishes scripts/, internal/ and web/. Source comments and the
// design documents point at those dropped notes by path — "See docs/NATIVE_P4_DESIGN.md (development repository) §h in the
// development repository" is one. In the development tree such a path resolves. In the tree the
// public actually gets it is a dead pointer, and the reader has no way to tell whether the document
// was renamed, forgotten, or deliberately withheld.
//
// The rule here is not "never mention them" — the pointer is worth keeping, a maintainer reading
// internal/pbr/pbr.go wants the name of the note. It is "say where it lives": a line that names a
// dropped path must also carry the words `development repository`. That is checked at the point of
// use, by the person writing it, rather than gathered into a list of exceptions somewhere else.
//
// Scope is comments and markdown prose. A path inside a string literal is data, not a pointer:
// extract_version_more_test.go builds a fake archive whose entries include a top-level readme, and
// check-i18n.mjs / check-docs.mjs name their subjects in order to announce and skip when a
// published tree does not carry them (both proven to do so). Marking those would be false
// precision. They are out of scope structurally, not by exemption.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const ROOT = process.cwd();
const RULES = path.join(ROOT, 'publish', 'scrub-rules.json');

// The rules are themselves dropped, so a published tree has nothing to compare against. Announce
// it and skip; a gate that cannot see its subject must not report as one that passed.
if (!fs.existsSync(RULES)) {
  console.log('check-published-refs: publish/scrub-rules.json is not in this tree, so the published '
    + 'set cannot be computed — every assertion here needs it, and all of them are skipped.');
  process.exit(0);
}

const rules = JSON.parse(fs.readFileSync(RULES, 'utf8'));
const dropExact = new Set(rules.dropExact || []);
const dropPrefix = rules.dropPrefix || [];
const keepExact = new Set(rules.keepExact || []);

// Tracked plus new-but-not-ignored. `git ls-files` alone omits a file that has not been added, and
// this gate met that the day it was written: it passed on itself while untracked and failed the
// moment it was committed, because its own header names dropped paths and an untracked file is not
// in the published set to scan. A check whose subject changes at `git add` is measuring the index,
// not the tree.
const tracked = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'],
  { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 })
  .split('\n').map((s) => s.trim()).filter(Boolean);

const isPublished = (p) => {
  if (keepExact.has(p)) return true;
  if (dropExact.has(p)) return false;
  return !dropPrefix.some((pre) => p.startsWith(pre));
};

const trackedSet = new Set(tracked);
const published = tracked.filter(isPublished);
const dropped = new Set(tracked.filter((p) => !isPublished(p)));

// Only a path this repository TRACKS can dangle. Everything else that looks path-shaped is either
// prose about something that never existed here or a Go symbol wearing a dot — `internal/traffic.Hub`
// and `internal/cidrfeed.ParseList(text)` both matched a first draft of this, and neither is a file.
const CAND = /(?<![\w/.-])([\w.-]+(?:\/[\w.+-]+)*\.[A-Za-z0-9_+-]+)/g;
const MARK = 'development repository';

const SLASH = new Set(['.go', '.js', '.mjs', '.css']);
const HASH = new Set(['.sh', '.yml', '.yaml']);
const PROSE = new Set(['.md']);

// The prose part of a line: everything a reader reads as English rather than as code. `://` is
// excluded so a URL does not open a comment that was never there.
function proseOf(line, ext) {
  if (PROSE.has(ext)) return line;
  if (SLASH.has(ext)) {
    const m = line.match(/(^|[^:])\/\/(.*)$/);
    return m ? m[2] : '';
  }
  if (HASH.has(ext)) {
    const i = line.indexOf('#');
    return i >= 0 ? line.slice(i + 1) : '';
  }
  return '';
}

const findings = [];
let marked = 0;
let scanned = 0;

for (const p of published) {
  const ext = path.extname(p);
  if (!SLASH.has(ext) && !HASH.has(ext) && !PROSE.has(ext)) continue;
  let src;
  try { src = fs.readFileSync(path.join(ROOT, p), 'utf8'); } catch { continue; }
  scanned += 1;
  // Split on either ending. Splitting on '\n' alone leaves a '\r' that JavaScript's `.` will not
  // match, so `(.*)$` never reached the end of a line and the comment extractor below returned
  // nothing for every CRLF file in the tree. The gate reported 25 of 27 pointers and looked
  // healthy; it was found only because an independent count of the same thing disagreed.
  const lines = src.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const prose = proseOf(lines[i], ext);
    if (!prose) continue;
    for (const m of prose.matchAll(CAND)) {
      const ref = m[1];
      if (!dropped.has(ref)) continue;
      // The marker is accepted on the reference's line or the one directly after it, because a
      // comment sentence wraps: at this tree's ~100-column convention several of these pointers
      // cannot hold both the path and the words on one physical line. One line of slack models a
      // wrapped sentence and nothing more — it is deliberately not "somewhere in the comment
      // block", which would let a newly added pointer ride on a marker written for another one.
      if (lines[i].includes(MARK) || (lines[i + 1] || '').includes(MARK)) { marked += 1; continue; }
      findings.push({ file: p, line: i + 1, ref, text: lines[i].trim() });
    }
  }
}

if (!trackedSet.size || !scanned) {
  console.error('check-published-refs: nothing was scanned — the file list or the published set is '
    + 'empty, so this would pass without measuring anything.');
  process.exit(2);
}

for (const f of findings) {
  console.error(`FAIL  ${f.file}:${f.line} points at ${f.ref}, which the published tree drops`);
  console.error(`      ${f.text.slice(0, 120)}`);
}
if (findings.length) {
  console.error(`\n${findings.length} pointer(s) into dropped paths do not say where the document lives.`);
  console.error(`Add "(${MARK})" on the same line, so a reader of the public tree is told the note `
    + 'exists elsewhere rather than left to conclude it is missing.');
  process.exit(1);
}

console.log(`published pointers: ${marked} references into dropped paths across ${scanned} published `
  + 'files, every one of them stating where the document lives');
