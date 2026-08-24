// check-scrub-output.mjs — the code that ships is not the code that was tested.
//
// publish/scrub-rules.json in the development repository applies 85 literal substitutions to every
// kept text file on the way out:
// real addresses become RFC 5737 documentation ones, personal endpoint names become generic. That is
// not confined to prose. Measured after the K5 device-specific migration retirement, the rules
// rewrite 108 published Go files, and 71 distinct rules fire 530 times inside Go source.
//
// The suite proves the DEVELOPMENT text compiles and passes. Nothing proved the same of the text the
// public receives, and the gap is exactly wide enough to hide a real failure: a rule that rewrites a
// literal inside a test fixture leaves the fixture disagreeing with a value the code still computes
// the old way, so the test fails in the published repository and nowhere else. Verifying it by hand
// after a publish is not the same as a gate — a hand-run check is one distraction from not happening.
//
// So: build the published set into a scratch tree with the substitutions applied, then compile, vet
// and test that tree, and run this project's own self-contained gates over it. No clone, no publish
// machinery, no network; the scrub is a pure text transform and this runs it the way
// Publish-Public.ps1 in the development repository does.
//
// The rules are literal and know nothing about the files they edit, which is its own failure mode: a
// replacement carrying a quote turns a dictionary into invalid JSON, and only a gate that reads that
// dictionary will say so.
//
// Needs a Go toolchain. Without one this exits 2 and says so — a build nobody ran must not report as
// one that passed.
import { execFileSync, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const ROOT = process.cwd();
const RULES = path.join(ROOT, 'publish', 'scrub-rules.json');
// This binds not only the rule definitions but every published Go path and occurrence count they
// transform. A broad rule shrinking from thirty files to one must fail even though it still belongs
// to the same matched-rule set. Update only after reviewing the changed publish subject.
// Re-pinned when the routing-list failover owner landed: internal/server/listfailover_test.go is one
// more published Go file the scrub rewrites (a single 192.168.50.1 -> 192.168.50.1 in its fixture), and
// the surrounding edits moved occurrence counts in files already covered. Reviewed as a GAIN — 109
// files / 581 substitutions against the 108 / 530 floors below — not a rule that stopped matching.
// Re-pinned when the Failover card learned which members the KERNEL can elect. Two rules newly fire
// — group-failover -> group-failover and tunnel-a -> tunnel-a — in internal/server/listfailover.go and
// internal/server/l5_kernelmembers_test.go, where the operator's real group and tunnel are named
// while explaining the defect the code fixes. Reviewed occurrence by occurrence: both are inside //
// comments, ZERO outside them, so the publish rewrites prose and touches neither a computed value
// nor a fixture a test compares against — which is the failure this fingerprint exists to catch.
// Re-pinned after a run of behaviour fixes touched published Go files the scrub rules match, which
// moves the per-file occurrence counts this hash covers: internal/server/dnsbypass.go (client
// counting), internal/server/config.go (the nil-safe demoMode accessor), internal/pbr/pbr.go (the
// extracted zone ordering) among them. Reviewed rather than rubber-stamped: the coverage map still
// lists 227 (rule, path) entries across the same rule set, and both reviewed floors —
// MIN_REWRITTEN_GO_FILES and MIN_GO_SUBSTITUTIONS — still pass, so this is a shift in counts, not a
// rule that stopped matching.
// Moved again, deliberately: l5_lansource_test.go stopped containing "192.168.50.1". That literal
// is rewritten by a SUBSTRING rule, which turned the test's LAN hosts into 192.168.1.x while the
// prefix they are matched against stayed 192.168.0.0/24 — so the test passed here and failed in the
// published tree, which is exactly the divergence this gate exists to catch. Its addresses now
// avoid the rule, and this hash follows them.
// Moved again, deliberately: four values were added to the scrub after scripts/check-pii.mjs found
// them by SHAPE rather than by name — a WireGuard peer key still sitting in a Keenetic
// running-config fixture whose endpoint had already been genericised by hand, and three public
// addresses whose provenance was the owner's own traffic (a conntrack destination, a routing
// trace, a panel screenshot). One of those four then came straight back out: mapping the traced
// address into 203.0.113.x put it INSIDE a prefix the same test uses as a non-match, so the
// published tree failed where the dev tree passed — this gate's whole purpose. That address is
// now a documentation literal at the source and needs no rule at all.
// Moved once more, same pass: comparing the publishable tree against the operator's LIVE profile
// names turned up their connection names, their group name and its id sitting in test fixtures and
// gate comments written from measurements. Seven rules for those; no detector could have found
// them, because a name has no shape.
// Moved a third time, and the reason is worth keeping: the name sweep above was run against the
// names visible in ONE reading of the live profile, so it scrubbed two members of a measured
// group and missed the third. Re-running it later against a fuller list caught that third member
// sitting in a health check, its two gates and a comment; a personal tunnel description caught
// with it touches no Go file. Hence exactly 7 new substitutions across 5 Go files here. The
// lesson the fingerprint records: a name sweep is only as complete as the name list it was fed.
// Moved a fourth time, by the widest margin yet, and the reason is the point of the number. An
// adversarial sweep run before publication found values the shape detectors cannot see — private
// LAN and tunnel prefixes, private tooling names, a legacy product's CI secret names — because a
// private address has no shape that distinguishes one household from another. Thirty replacement
// rules were added at once, so the coverage over published Go source moved accordingly. The lesson
// this pin records: a scrub list grows by being ATTACKED, not by being reviewed.
const EXPECTED_GO_COVERAGE_SHA256 = '7543c3742f34aa0ff1b3abff0b330b33c7af6ef5721a1955870ad761f896f40a';
// K5 intentionally retired seven more personal-device-derived Keenetic migration/cutover Go files.
// Their scrub matches disappeared with the code; pin the reduced subject so any further loss fails.
const MIN_REWRITTEN_GO_FILES = 108;
const MIN_GO_SUBSTITUTIONS = 530;

const scrubCoverageFingerprint = (replace, coverage) => {
  const payload = [...coverage.entries()].sort((a, b) => a[0] - b[0]).map(([ruleIndex, files]) => ({
    rule_index: ruleIndex,
    rule: replace[ruleIndex],
    matches: [...files.entries()].sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)
      .map(([file, count]) => ({ file, count })),
  }));
  return crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
};

// Negative fixtures for the original bypass: the rule set is identical in every case, but losing
// files or occurrences must change the fingerprint. This is intentionally pure and cheap enough to
// run on every invocation before the expensive transformed-tree build.
const coverageFixtureRules = [{ from: 'private-a', to: 'public-a' }, { from: 'private-b', to: 'public-b' }];
const coverageFixture = new Map([
  [0, new Map([['a.go', 5], ['b.go', 2]])],
  [1, new Map([['c.go', 1]])],
]);
const coverageFixtureHash = scrubCoverageFingerprint(coverageFixtureRules, coverageFixture);
for (const [name, changed] of [
  ['lost path', new Map([[0, new Map([['a.go', 5]])], [1, new Map([['c.go', 1]])]])],
  ['lost occurrences', new Map([[0, new Map([['a.go', 1], ['b.go', 2]])], [1, new Map([['c.go', 1]])]])],
]) {
  if (scrubCoverageFingerprint(coverageFixtureRules, changed) === coverageFixtureHash) {
    console.error(`scrub coverage self-test did not detect ${name}`);
    process.exit(2);
  }
}

if (!fs.existsSync(RULES)) {
  console.log('check-scrub-output: publish/scrub-rules.json is not in this tree, so there is no '
    + 'transform to apply — every assertion here needs it, and all of them are skipped.');
  process.exit(0);
}

const rules = JSON.parse(fs.readFileSync(RULES, 'utf8'));
const dropExact = new Set(rules.dropExact || []);
const dropPrefix = rules.dropPrefix || [];
const keepExact = new Set(rules.keepExact || []);
const replace = rules.replace || [];
if (replace.length === 0) {
  console.error('the rules carry no substitutions — this check would compile an unmodified copy and '
    + 'prove nothing about the transform');
  process.exit(2);
}

// Tracked plus new-but-not-ignored: a file being added is part of the next publish, and a check that
// reads only the index measures a different tree before and after `git add`.
const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'],
  { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 })
  .split('\n').map((s) => s.trim()).filter(Boolean);

const published = files.filter((p) => {
  if (keepExact.has(p)) return true;
  if (dropExact.has(p)) return false;
  return !dropPrefix.some((pre) => p.startsWith(pre));
});

// Which files the substitutions may touch. Everything else is copied byte for byte: rewriting inside
// a signing key or a PNG would corrupt it, and the publish script draws the same line.
const TEXT = new Set(['.go', '.mod', '.sum', '.mjs', '.js', '.json', '.md', '.sh', '.yml', '.yaml',
  '.html', '.css', '.tmpl', '.txt', '.init', '.conf']);

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'wayhop-scrub-'));
let rewrittenGo = 0;
const matchedGoRules = new Set();
const goCoverage = new Map();
let goSubstitutions = 0;
let substitutions = 0;
let nodeGatesRun = 0;
let reformatted = 0;
try {
  for (const rel of published) {
    const src = path.join(ROOT, rel);
    if (!fs.existsSync(src) || fs.statSync(src).isDirectory()) continue;
    const dst = path.join(work, rel);
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    if (!TEXT.has(path.extname(rel))) { fs.copyFileSync(src, dst); continue; }

    let text = fs.readFileSync(src, 'utf8');
    const before = text;
    for (const [ruleIndex, r] of replace.entries()) {
      if (!text.includes(r.from)) continue;
      const matchCount = text.split(r.from).length - 1;
      if (rel.endsWith('.go')) {
        matchedGoRules.add(ruleIndex);
        goSubstitutions += matchCount;
        if (!goCoverage.has(ruleIndex)) goCoverage.set(ruleIndex, new Map());
        goCoverage.get(ruleIndex).set(rel, matchCount);
      }
      substitutions += matchCount;
      text = text.split(r.from).join(r.to);
    }
    if (rel.endsWith('.go') && text !== before) rewrittenGo += 1;
    fs.writeFileSync(dst, text);
  }

  if (rewrittenGo === 0) {
    console.error('the substitutions changed no Go file, so compiling the result proves nothing '
      + 'about them. Either the rules stopped matching or the published set is wrong — both are '
      + 'failures of this check\'s subject, not a pass.');
    process.exit(2);
  }
  if (matchedGoRules.size === 0) {
    console.error('no scrub rule matched published Go source, so the transformed Go test is vacuous');
    process.exit(2);
  }
  if (rewrittenGo < MIN_REWRITTEN_GO_FILES || goSubstitutions < MIN_GO_SUBSTITUTIONS) {
    console.error(`Go scrub coverage fell below its reviewed floor: ${rewrittenGo}/${MIN_REWRITTEN_GO_FILES} `
      + `files, ${goSubstitutions}/${MIN_GO_SUBSTITUTIONS} substitutions`);
    process.exit(1);
  }
  const goCoverageSHA256 = scrubCoverageFingerprint(replace, goCoverage);
  if (goCoverageSHA256 !== EXPECTED_GO_COVERAGE_SHA256) {
    console.error('the exact scrub coverage over published Go source changed. Review the matched '
      + 'paths and occurrence counts and update its pinned fingerprint deliberately; observed SHA-256: '
      + goCoverageSHA256);
    process.exit(1);
  }

  const env = { ...process.env, GOTOOLCHAIN: process.env.GOTOOLCHAIN || 'local' };

  // What ships is gofmt(scrub(source)), not scrub(source): Publish-Public.ps1 re-formats the tree
  // after substituting, and that step is load-bearing rather than tidy — a replacement of a
  // different width breaks the alignment gofmt imposes inside struct literals and comment blocks.
  // Measured here, 5 files come out needing it. Testing the unformatted intermediate would be
  // testing a tree nobody receives, and would leave the publish step's removal invisible until the
  // public repository failed its own gofmt gate.
  const before = spawnSync('gofmt', ['-l', '.'], { cwd: work, encoding: 'utf8', env });
  if (before.error) {
    console.error(`could not run gofmt on the scrubbed tree: ${before.error.message}`);
    process.exit(2);
  }
  reformatted = (before.stdout || '').trim().split('\n').filter(Boolean).length;
  const fmt = spawnSync('gofmt', ['-w', '.'], { cwd: work, encoding: 'utf8', env });
  if (fmt.status !== 0) {
    console.error(`gofmt could not rewrite the scrubbed tree:\n${fmt.stdout}${fmt.stderr}`);
    process.exit(1);
  }
  // And it has to have worked: this is the property the published repository's own gofmt gate
  // checks, so if the step ever stops achieving it the failure belongs here and not after a publish.
  const after = spawnSync('gofmt', ['-l', '.'], { cwd: work, encoding: 'utf8', env });
  if ((after.stdout || '').trim() !== '') {
    console.error('the scrubbed tree is still unformatted after gofmt -w, so the published tree '
      + `would fail its own format gate:\n${after.stdout}`);
    process.exit(1);
  }
  // Tests, not just a build. The failure this exists to catch is a substitution that rewrites an
  // expected literal while the value the code computes stays as it was — the two disagree and the
  // compiler is perfectly happy. Building and vetting alone would have made this gate narrower than
  // the risk named at the top of the file, which is the defect it is meant to prevent elsewhere.
  // The lines that say WHAT WENT WRONG, not the first ones off the wire.
  //
  // This printed slice(0, 25), and `go test ./...` opens with a long column of "ok" — so a real
  // failure was reported as twenty-five passing packages and nothing else. Diagnosing one cost two
  // sittings: the gate was right that the scrubbed tree failed, and silent about the test that did
  // it (a LAN fixture whose addresses the scrub rewrites). Go prints the diagnosis LAST, so keep
  // the tail of what is left once the per-package noise is dropped, and fall back to the raw tail
  // when nothing matches — a panic or a linker error has no "ok" lines to drop.
  const whatFailed = (out) => {
    const all = out.split(String.fromCharCode(10));
    // A passing test may print as much as a failing one: internal/server's updater tests log every
    // simulated remove, and a plain tail buried the "--- FAIL" line under them. So prefer the lines
    // that ARE a diagnosis — the failing test and its assertion, a panic, a compiler or vet
    // complaint — and show the FIRST of those, because the first failure is the one to read.
    const diag = all.filter((l) => /^s*--- FAIL/.test(l) || /^FAIL/.test(l) || /^panic:/.test(l)
      || /_test.go:d+:/.test(l) || /^#s/.test(l) || /.go:d+:d+:/.test(l));
    if (diag.length) return diag.slice(0, 25).join(String.fromCharCode(10));
    const signal = all.filter((l) => l.trim() && !/^(ok |[?] {3})/.test(l));
    return (signal.length ? signal : all).slice(-25).join(String.fromCharCode(10));
  };
  for (const [label, verb, args] of [
    ['build', 'compile', ['build', './...']],
    ['vet', 'pass vet', ['vet', './...']],
    ['test', 'pass its tests', ['test', './...', '-count=1']]]) {
    const r = spawnSync('go', args, { cwd: work, encoding: 'utf8', env });
    if (r.error) {
      console.error(`could not run go ${label} on the scrubbed tree: ${r.error.message}`);
      process.exit(2);
    }
    if (r.status !== 0) {
      console.error(`the scrubbed tree does not ${verb}. The development tree does, so this is the `
        + 'transform, not the source — a substitution rewrote something the compiler or vet reads:\n'
        + whatFailed(r.stdout + r.stderr));
      process.exit(1);
    }
  }
  // Go is not all the scrub rewrites. On this tree it also touches 16 dictionaries, 16 UI scripts
  // and 5 of these gate scripts themselves. The dictionaries are the sharp case: `i18n reproducible`
  // regenerates web/dist from web/i18n and compares, so a substitution that lands on one side and
  // not the other — different escaping, a different spelling — produces a tree that fails in the
  // published repository and nowhere else.
  //
  // Only the self-contained gates. The rest need a daemon, a browser or Docker, and a gate that
  // quietly skipped the ones it could not run would report a narrower check than its name.
  const NODE_GATES = [
    ['scripts/check-i18n.mjs'],
    ['scripts/i18n-generate.mjs', '--check'],
    ['scripts/check-chunks.mjs'],
    ['scripts/check-dom.mjs'],
    ['scripts/check-a11y.mjs'],
    ['scripts/check-perf-budget.mjs'],
    // These two have no subject in a published tree and must ANNOUNCE that rather than pass;
    // running them here is how that path is exercised at all.
    ['scripts/check-docs.mjs'],
    ['scripts/check-published-refs.mjs'],
  ];
  for (const argv of NODE_GATES) {
    if (!fs.existsSync(path.join(work, argv[0]))) {
      console.error(`${argv[0]} is not in the published set, so the scrubbed tree cannot be held to `
        + 'it — either the publish rules changed or this list is stale');
      process.exit(2);
    }
    const r = spawnSync('node', argv, { cwd: work, encoding: 'utf8', env });
    if (r.error) {
      console.error(`could not run ${argv[0]} on the scrubbed tree: ${r.error.message}`);
      process.exit(2);
    }
    if (r.status !== 0) {
      console.error(`${argv.join(' ')} fails on the scrubbed tree and passes on this one, so a `
        + 'substitution changed something it reads:\n'
        + (r.stdout + r.stderr).split('\n').slice(0, 20).join('\n'));
      process.exit(1);
    }
    nodeGatesRun += 1;
  }

  // Those three gates read artefacts that exist only in the development repository. Their scripts
  // ship — the published workflows invoke them by name — and each announces that its subject is
  // absent instead of passing. What must not happen is the RUNNER counting those announcements
  // among its passes, so the published runner is asked, in the published tree, what it would run.
  const ran = spawnSync('node', ['scripts/verify.mjs', '--only', 'chunk refs'],
    { cwd: work, encoding: 'utf8', env });
  if (!/measure the development repository/.test(ran.stdout)) {
    console.error('the published runner does not say that three of its gates have no subject there, '
      + 'so a reader of that tally cannot tell it covers a smaller suite:\n'
      + ran.stdout.slice(0, 400));
    process.exit(1);
  }
  for (const name of ['docs', 'scrub output', 'published pointers']) {
    if (ran.stdout.includes(`\u2026 ${name} `)) {
      console.error(`the published runner ran ${name}, whose subject is not in that tree`);
      process.exit(1);
    }
  }
  nodeGatesRun += 1; // the runner's own two-tree behaviour, exercised in the tree it is about
} finally {
  fs.rmSync(work, { recursive: true, force: true });
}

console.log('scrub coverage self-test: 2 loss cases refused');
console.log(`scrub output: ${rewrittenGo} rewritten Go file(s) out of ${published.length} published; `
  + `${matchedGoRules.size} distinct Go scrub rule(s), ${goSubstitutions} Go substitutions, `
  + `${substitutions} total substitutions applied; `
  + 'the result builds, vets and passes its tests, and '
  + `${nodeGatesRun} of this project's own gates run clean on it; ${reformatted} file(s) needed `
  + 'the re-format the publish step applies');
