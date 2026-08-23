// check-skips.mjs — a green test run must not quietly contain tests that proved nothing.
//
// `go test ./...` prints ok for a package whose tests all skipped. The set varies by platform and
// installed tools, and the suite used to report PASS without saying what proved nothing. The
// deliverables then credited a green Go suite, which is true and misleading in exactly the way this
// project keeps having to correct: a weaker result presented as the strong one.
//
// This does not try to make them run; most need a binary that is not on a Windows dev box. It makes
// the inertness VISIBLE and PINNED:
//
//   • every skip must be in the manifest, so a newly-inert test cannot slip in unnoticed — that is
//     the case that matters, because a test that starts skipping (a renamed env var, an added
//     t.Skip) looks identical to one that passes;
//   • an expected skip must carry the reviewed reason, not merely the same test name;
//   • when a condition does NOT hold, the test must be present in the `=== RUN` set and must not
//     skip, so a build tag, rename, or deletion cannot make an exemption disappear silently;
//   • every manifest entry must still satisfy that contract, so the manifest cannot rot.
//
// Usage: node scripts/check-skips.mjs
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const MANIFEST = path.join(process.cwd(), 'scripts', 'expected-skips.json');

// CI already runs the whole suite. Running it again here to re-read output it has just produced
// would double the slowest job in the workflow, and that cost is the reason this gate reached CI in
// no job at all. WAYHOP_GOTEST_LOG points at that run's `-v` output and this reads it instead.
//
// It is an environment variable and not a flag on purpose. check-gate-parity.mjs compares the whole
// invocation between the runner and CI, and a flag would make those two commands differ — which is
// exactly the signal that check must keep, so the input's origin belongs in the environment rather
// than in the command. The guards below do not relax either way: a log with no test in it proves
// exactly as little as a run that never started, whoever wrote it. The log must come from THIS
// host; the conditions below are evaluated here, so a log carried over from another platform would
// be judged against the wrong facts.
const fromFile = process.env.WAYHOP_GOTEST_LOG || null;
let res;
let out;
if (fromFile) {
  if (!fs.existsSync(fromFile)) {
    console.error(`WAYHOP_GOTEST_LOG=${fromFile}: no such file — it names a run to read the skip `
      + 'list from, and there is none there');
    process.exit(2);
  }
  out = fs.readFileSync(fromFile, 'utf8');
  // Keep the "did the run fail" signal the spawned path gets, so a fed log of a failing suite is
  // not read as a trustworthy picture of what skipped.
  res = { status: /^FAIL/m.test(out) ? 1 : 0 };
} else {
  res = spawnSync('go', ['test', './...', '-count=1', '-v'], {
    encoding: 'utf8',
    env: { ...process.env, GOTOOLCHAIN: 'local' },
  });
  out = (res.stdout || '') + (res.stderr || '');
}
if (!out.trim()) {
  console.error('go test produced no output — cannot tell what ran, which is worse than a failure');
  process.exit(2);
}

// The run has to have HAPPENED before its skip list means anything.
//
// Emptiness was the only thing guarded here, and a missing toolchain is not empty: with `go` off PATH
// the shell writes its own not-found message, so `out` has content, no line matches `--- SKIP`, and
// every manifest entry is then reported as "listed as an expected skip but did not skip — trim the
// manifest". Following that advice deletes twelve correct exemptions because the toolchain was absent.
// So require positive evidence of a test binary running, and name what was actually seen instead.
if (res.error) {
  console.error(`could not run go test: ${res.error.message}\n` +
    'the skip manifest cannot be checked against a run that never started');
  process.exit(2);
}
if (!/^\s*=== RUN/m.test(out) && !/^(ok|FAIL|---)\s/m.test(out)) {
  console.error('go test never ran a test: no "=== RUN" and no package result in its output. ' +
    'The skip manifest proves nothing here, so this is not a manifest problem. It said:\n' +
    out.split('\n').filter((l) => l.trim()).slice(0, 3).map((l) => '  ' + l.trim()).join('\n'));
  process.exit(2);
}

// "--- SKIP: TestName (0.00s)" does not always immediately follow the t.Skip message: table-driven
// subtests may report all reasons first and all summaries later. Bind each reason to the active RUN
// or CONT test instead of relying only on adjacency.
const parseTestLog = (text) => {
  const lines = text.split('\n');
  const found = new Map(); // test name -> reason
  const ran = new Set();
  const reasonByTest = new Map();
  let activeTest = '';
  for (let i = 0; i < lines.length; i++) {
    const active = /^\s*=== (?:RUN|CONT)\s+(\S+)/.exec(lines[i]);
    if (active) {
      activeTest = active[1];
      ran.add(activeTest);
    }
    const reasonLine = /\.go:\d+:\s*(.+)$/.exec(lines[i]);
    if (reasonLine && activeTest) reasonByTest.set(activeTest, reasonLine[1].trim());
    const m = /^\s*--- SKIP: (\S+)/.exec(lines[i]);
    if (!m) continue;
    let reason = reasonByTest.get(m[1]) || '';
    for (let j = i - 1; j >= 0 && j > i - 4; j--) {
      const nearby = /\.go:\d+:\s*(.+)$/.exec(lines[j]);
      if (!reason && nearby) { reason = nearby[1].trim(); break; }
    }
    found.set(m[1], reason);
  }
  return { found, ran };
};

const { found, ran } = parseTestLog(out);

if (!fs.existsSync(MANIFEST)) {
  const seed = { note: 'Tests that do not run on this host, and why. Regenerate deliberately, never automatically.', skips: {} };
  [...found.entries()].sort().forEach(([k, v]) => { seed.skips[k] = v; });
  fs.writeFileSync(MANIFEST, JSON.stringify(seed, null, 1) + '\n');
  console.log(`wrote ${MANIFEST} with ${found.size} entries — review it, then commit it`);
  process.exit(0);
}

const manifest = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));

// An entry is either a plain reason, or a reason plus the CONDITION under which the skip is
// expected. The flat form is precisely why this gate ran in no workflow: two of its entries hold
// only on Windows, so on an ubuntu runner they read as exemptions to trim, and wiring it in
// unchanged would have added a gate that is wrong there. A condition the gate can evaluate itself
// replaces "this host" with something checkable anywhere.
//
//   env:NAME     expected to skip while NAME is unset or empty
//   tool:A|B     expected to skip while NONE of those is on PATH. The alternatives matter: netdiag
//                runs `tracert` on Windows and `traceroute` everywhere else, so naming one binary
//                would predict a skip on the platform that has the other.
//   os:NAME      expected to skip on that platform (win32, linux, darwin) and to RUN elsewhere
//   cap:nft      expected to skip while this host cannot syntax-check an nftables ruleset: either
//                nft is not on PATH, or it is and refuses to initialize its netlink cache, which is
//                what an unprivileged container does. Those are one fact to the test that needs it,
//                and a plain tool: condition sees only the first - so a runner carrying the binary
//                without the privilege reported a legitimate skip as an undeclared one, and the
//                suite failed on an environment change rather than on anything in the code.
const onPath = (exe) => {
  const names = process.platform === 'win32' ? [exe, `${exe}.exe`] : [exe];
  return (process.env.PATH || '').split(path.delimiter).filter(Boolean)
    .some((d) => names.some((n) => fs.existsSync(path.join(d, n))));
};
// Probing costs one nft invocation and only when the manifest asks for it. The markers match the
// test's own escape hatch: anything else (a syntax error in the probe itself) is deliberately NOT
// treated as "cannot check here", so a broken probe surfaces instead of silently excusing skips.
let nftCap = null;
const nftCheckUnavailable = () => {
  if (nftCap !== null) return nftCap;
  if (!onPath('nft')) { nftCap = true; return nftCap; }
  const f = path.join(os.tmpdir(), 'wayhop-nft-probe.nft');
  fs.writeFileSync(f, 'table inet wayhop_probe { }' + String.fromCharCode(10));
  const r = spawnSync('nft', ['-c', '-f', f], { encoding: 'utf8' });
  fs.rmSync(f, { force: true });
  const out = `${r.stdout || ''}${r.stderr || ''}`;
  nftCap = r.status !== 0
    && (out.includes('Operation not permitted') || out.includes('cache initialization failed'));
  return nftCap;
};

const holds = (when) => {
  const i = when.indexOf(':');
  const kind = i < 0 ? when : when.slice(0, i);
  const value = i < 0 ? '' : when.slice(i + 1);
  if (kind === 'env') return !process.env[value];
  if (kind === 'tool') return !value.split('|').some((t) => onPath(t.trim()));
  if (kind === 'os') return process.platform === value;
  if (kind === 'cap' && value === 'nft') return nftCheckUnavailable();
  return null;
};

const entries = Object.entries(manifest.skips || {}).map(([name, v]) => ({
  name,
  why: typeof v === 'string' ? v : (v.why || ''),
  when: typeof v === 'string' ? null : (v.when || null),
  reasonRe: typeof v === 'string' ? null : (v.reason_re || null),
}));
const badCondition = entries.filter((e) => e.when && holds(e.when) === null);
if (badCondition.length) {
  console.error('the manifest uses a condition this check cannot evaluate, so it cannot say what '
    + 'should have skipped:\n' + badCondition.map((e) => `  ${e.name}: ${e.when}`).join('\n'));
  process.exit(2);
}
for (const e of entries) e.expected = e.when ? holds(e.when) : true;

const normalizeReason = (value) => String(value || '').trim().replace(/\s+/g, ' ');
const reasonMatches = (entry, actual) => {
  const got = normalizeReason(actual);
  if (!got || !normalizeReason(entry.why)) return false;
  if (!entry.reasonRe) return got === normalizeReason(entry.why);
  try {
    return new RegExp(`^(?:${entry.reasonRe})$`).test(got);
  } catch {
    return false;
  }
};

const invalidReasons = entries.filter((e) => {
  if (!normalizeReason(e.why)) return true;
  if (!e.reasonRe) return false;
  try { new RegExp(`^(?:${e.reasonRe})$`); return false; } catch { return true; }
});
if (invalidReasons.length) {
  console.error('the manifest has an empty reason or invalid reason_re:\n'
    + invalidReasons.map((e) => `  ${e.name}`).join('\n'));
  process.exit(2);
}

const validateSkipContract = (contractEntries, skipped, runSet) => {
  const contractProblems = [];
  const byName = new Map(contractEntries.map((e) => [e.name, e]));
  for (const [name, reason] of skipped) {
    const e = byName.get(name);
    if (!e) {
      contractProblems.push(`${name} skipped and is not in the manifest — it proves nothing now: "${reason}"`);
    } else if (!e.expected) {
      contractProblems.push(`${name} skipped, but \`${e.when}\` says it should RUN here — either the `
        + 'condition is wrong or the test acquired a second reason to be inert');
    } else if (!reasonMatches(e, reason)) {
      contractProblems.push(`${name} skipped for an unreviewed reason: got "${reason}", expected `
        + (e.reasonRe ? `/${e.reasonRe}/ (${e.why})` : `"${e.why}"`));
    }
  }
  for (const e of contractEntries) {
    if (!runSet.has(e.name)) {
      contractProblems.push(`${e.name} is absent from the === RUN set — a build tag, rename, `
        + `deletion, or truncated log may have removed the test (condition: ${e.when || 'always'})`);
    } else if (e.expected && !skipped.has(e.name)) {
      contractProblems.push(`${e.name} is expected to skip here${e.when ? ` (\`${e.when}\`)` : ''} and did `
        + 'not — trim the manifest or fix the condition; an exemption that no longer applies hides '
        + 'the next real one');
    }
  }
  return contractProblems;
};

const selfCases = [
  ['matching reason', [{ name: 'T', why: 'expected', when: null, expected: true }],
    new Map([['T', 'expected']]), new Set(['T']), true],
  ['reviewed dynamic reason', [{ name: 'T', why: 'dynamic fixture', reasonRe: 'dynamic \\d+', expected: true }],
    new Map([['T', 'dynamic 42']]), new Set(['T']), true],
  ['wrong reason', [{ name: 'T', why: 'expected', when: null, expected: true }],
    new Map([['T', 'unrelated']]), new Set(['T']), false],
  ['truncated expected run', [{ name: 'T', why: 'expected', when: null, expected: true }],
    new Map([['T', 'expected']]), new Set(['Other']), false],
  ['missing required run', [{ name: 'T', why: 'only elsewhere', when: 'os:elsewhere', expected: false }],
    new Map(), new Set(['Other']), false],
  ['required run present', [{ name: 'T', why: 'only elsewhere', when: 'os:elsewhere', expected: false }],
    new Map(), new Set(['T']), true],
  ['unexpected skip', [], new Map([['T', 'new skip']]), new Set(['T']), false],
];
for (const [name, testEntries, testSkipped, testRan, wantPass] of selfCases) {
  const passed = validateSkipContract(testEntries, testSkipped, testRan).length === 0;
  if (passed !== wantPass) {
    console.error(`skip-contract self-test ${name} ${passed ? 'passed' : 'failed'} unexpectedly`);
    process.exit(2);
  }
}

const delayedSubtests = parseTestLog([
  '=== RUN   TestTable',
  '=== RUN   TestTable/first',
  '    table_test.go:10: first unavailable',
  '=== RUN   TestTable/second',
  '    table_test.go:10: second unavailable',
  '--- PASS: TestTable (0.00s)',
  '    --- SKIP: TestTable/first (0.00s)',
  '    --- SKIP: TestTable/second (0.00s)',
].join('\n'));
if (delayedSubtests.found.get('TestTable/first') !== 'first unavailable'
    || delayedSubtests.found.get('TestTable/second') !== 'second unavailable') {
  console.error('skip-log parser self-test failed to bind delayed subtest reasons');
  process.exit(2);
}

const problems = validateSkipContract(entries, found, ran);

// A failing run is the go test gate's job, not this one's, but a run that did not complete cannot
// support any claim about skips either.
if (/^FAIL/m.test(out) && res.status !== 0) {
  console.error('the test run failed, so its skip list is not a reliable picture; fix the failures first');
  process.exit(1);
}

const byReason = new Map();
for (const [, reason] of found) {
  const key = /WR_SINGBOX/.test(reason) ? 'needs a sing-box binary (WR_SINGBOX)'
    : /WR_MIHOMO/.test(reason) ? 'needs a mihomo binary (WR_MIHOMO)'
      : /nft not in PATH/.test(reason) ? 'needs nft'
        : /traceroute binary not installed/i.test(reason) ? 'needs traceroute'
        : /WR_NATIVEDNS_FIXTURE/.test(reason) ? 'needs a captured-device fixture'
          : /ledger/i.test(reason) ? 'Linux Apply-ledger security contract'
            : /POSIX|executable identity|nft fixture/i.test(reason) ? 'POSIX executable/tool semantics'
              : /windows/i.test(reason) ? 'not meaningful on Windows'
                : 'other';
  byReason.set(key, (byReason.get(key) || 0) + 1);
}

if (problems.length) {
  console.error(`skip manifest FAILED (${problems.length}):\n` + problems.map((p) => '  ' + p).join('\n'));
  process.exit(1);
}
console.log(`skip contract: ${selfCases.length} contract cases and 1 delayed-subtest parser case passed`);
console.log(`${found.size} test(s) are inert on this host and all are accounted for:`);
[...byReason.entries()].sort((a, b) => b[1] - a[1])
  .forEach(([k, n]) => console.log(`  ${String(n).padStart(2)} × ${k}`));
console.log('a green Go suite on this host does NOT cover these — see scripts/expected-skips.json');
