// check-target-fresh.mjs — does the instance the UI gates point at actually serve THIS tree?
//
// Written after a full session's UI gates ran green against a demo binary from the previous day.
// A stale process held the port; the freshly built one could not bind, exited without a word, and
// every UI gate happily measured yesterday's UI and reported PASS. Nothing in the suite noticed,
// because every gate was asking "is the page correct?" and none was asking "is this the page I
// just built?"
//
// That is the same defect the audit keeps finding, aimed at the harness: a check whose subject is
// not what its name implies proves nothing. So before any UI gate runs, compare the assets the
// target serves against the assets on disk, byte for byte.
//
// Usage: node scripts/check-target-fresh.mjs <url>
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const URL_ARG = process.argv[2];
if (!URL_ARG) {
  console.error('usage: node scripts/check-target-fresh.mjs <url>');
  process.exit(2);
}
const base = URL_ARG.replace(/\/+$/, '');
const DIST = path.join(process.cwd(), 'web', 'dist');

// Everything the binary embeds, walked rather than listed.
//
// A chunk that 404s is the specific failure that started this — the page would render an error and
// the density gate would happily record a short page. But the list written for that was six eager
// files plus the page-*.js glob: eleven of the twenty-eight files under web/dist. The gate is named
// "target is this build" and the suite prints its count, so the number was honest and the NAME was
// not — and every UI gate's verdict rests on this one.
//
// What the hand list left out is not incidental. `i18n.js` is the dictionary, 1.8 MB of it, and
// `i18n/<lang>.js` is fifteen more: edit a translation, forget the rebuild, and the panel under test
// answers in the OLD wording while check-i18n gates the new file — the two gates disagreeing about
// which tree they are looking at, with nothing to say so.
//
// Measured before widening: all 28 are served and byte-identical, so comparing everything is not a
// gate that will cry wolf over a build artefact the daemon never hands out.
const walk = (dir, prefix = '') => {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...walk(path.join(dir, e.name), rel));
    else out.push(rel);
  }
  return out;
};
const want = walk(DIST);
// An empty or near-empty tree means the walk found nothing to compare, and a gate that passes because
// it looked at nothing is worse than one that fails.
if (want.length < 10) {
  console.error(`FAIL  only ${want.length} file(s) found under ${DIST} — nothing meaningful to compare`);
  process.exit(1);
}

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex').slice(0, 12);
let bad = 0;
for (const f of want) {
  const local = fs.readFileSync(path.join(DIST, f));
  let res;
  try {
    res = await fetch(`${base}/${f}`, { headers: { 'Accept-Encoding': 'identity' } });
  } catch (e) {
    console.error(`FAIL  ${f}: could not be fetched from ${base} — ${e.message}`);
    bad++;
    continue;
  }
  if (!res.ok) {
    console.error(`FAIL  ${f}: ${base} answered ${res.status}. ` +
      (f.startsWith('page-')
        ? 'A route-scoped chunk that 404s means that page cannot render — rebuild and restart the target.'
        : 'Rebuild and restart the target.'));
    bad++;
    continue;
  }
  const served = Buffer.from(await res.arrayBuffer());
  if (!served.equals(local)) {
    console.error(`FAIL  ${f}: served ${served.length} B (${sha(served)}) but disk has ` +
      `${local.length} B (${sha(local)}) — the target is NOT running this tree's build.`);
    bad++;
  }
}

if (bad) {
  console.error(`\n${bad} asset(s) differ. Every UI gate below this point would be measuring some ` +
    `other build.\nCheck for a stale process holding the port (a new one that cannot bind exits ` +
    `silently), then rebuild and restart.`);
  process.exit(1);
}
// The assets are the source of truth and stay so: they are what the binary actually serves, and a
// byte comparison cannot be talked out of. The reported commit is a SECOND, independent signal, and
// it catches a case the bytes cannot — a target built from a different commit whose web/dist happens
// to be identical, which is every commit that changed only Go code. The audit found a production
// binary built from a commit that no longer existed; this is where that becomes visible.
//
// Only compared when BOTH sides know their commit. An unstamped target reports "unknown" and a
// checkout outside a repository has nothing to compare, and inventing a verdict from either would be
// the vacuous pass this gate exists to prevent — so it says which side was silent instead.
let commitNote = '';
try {
  const health = await (await fetch(`${base}/api/health`)).json();
  const reported = (health && health.build && health.build.commit) || '';
  const dirty = (health && health.build && health.build.dirty) || '';
  const { execFileSync } = await import('node:child_process');
  let local = '';
  try { local = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(); } catch { local = ''; }

  if (!reported || reported === 'unknown') {
    commitNote = 'the target reports no commit (an unstamped build) — assets compared, identity not';
  } else if (!local) {
    commitNote = `the target reports ${reported.slice(0, 12)} but this tree has no git commit to compare`;
  } else if (reported !== local) {
    console.error(`FAIL  the target serves this tree's assets but reports commit ${reported.slice(0, 12)}, ` +
      `and this tree is at ${local.slice(0, 12)}. The bytes under web/dist match, so this is a build ` +
      'from different Go source — restart the target with the binary you just built.');
    process.exit(1);
  } else if (dirty === 'true') {
    commitNote = `commit ${reported.slice(0, 12)} matches, and the target was built from a DIRTY tree`;
  } else {
    commitNote = `commit ${reported.slice(0, 12)} matches`;
  }
} catch (e) {
  commitNote = `the target's build identity could not be read (${e.message}) — assets compared, identity not`;
}

// The chunk count is still called out separately: a missing route chunk is the failure this gate was
// written for, and it would otherwise be one number among twenty-eight.
const chunkCount = want.filter((f) => /^page-.*\.js$/.test(f)).length;
const langCount = want.filter((f) => f.startsWith('i18n/')).length;
console.log(`target serves this tree's build (${want.length} assets byte-identical, ` +
  `${chunkCount} route chunk(s) reachable, ${langCount} language file(s) compared; ${commitNote})`);
