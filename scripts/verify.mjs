// verify.mjs — run every gate this project has, in one command, and report one verdict.
//
// The checks accumulated one at a time (formatting, vet, unit tests, i18n completeness, a11y,
// payload budget, the page sweep, fault injection) and were being run by hand, in whatever order the
// person remembered. That is how a gate silently stops being run: nobody notices the one command
// they stopped typing. This runs all of them and fails if ANY fails.
//
//   node scripts/verify.mjs                          # static gates only (no running daemon needed)
//   node scripts/verify.mjs --ui http://ROUTER:8088/ # also sweep + fault-inject a live instance
//   node scripts/verify.mjs --ui URL --apply URL     # also fault-inject the APPLY path
//
// --apply must point at a DISPOSABLE demo instance. ui-apply-faults.mjs enforces localhost itself;
// the warning here is so nobody reaches for it casually against a router.
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const args = process.argv.slice(2);
const flag = (name) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : null;
};
const uiURL = flag('--ui');
const applyURL = flag('--apply');

// Evidence baseline: how much each measuring gate examined on a recorded green run. A gate whose
// subject count collapses relative to this is failed even though it exits 0 and clears its absolute
// floor — see the note at the evidence check for the run that made this necessary.
//
// SHRINK is deliberately loose. Legitimate run-to-run variation here is a few percent (contrast moved
// 4730 -> 5184, narrow viewport 9821 -> 11613 as seeding varied); the failure being caught was 4x. A
// tight threshold would turn ordinary variation into noise, and noise is how a gate stops being read.
const SHRINK = 0.6;
const BASELINE_PATH = path.join(process.cwd(), 'scripts', 'evidence-baseline.json');
const updateBaseline = args.includes('--update-baseline');
let baseline = {};
try { baseline = JSON.parse(fs.readFileSync(BASELINE_PATH, 'utf8')).counts || {}; } catch (_) {}
// Only a full UI run may record a baseline: without --ui most measuring gates never run, and writing
// their absence as the new normal would erase the very numbers this is meant to protect.
if (updateBaseline && !uiURL) {
  console.error('--update-baseline needs --ui: a run without the UI gates would record an empty baseline');
  process.exit(2);
}
const seen = {};
// Gates that had to be retried after dying before they ran anything. Reported at the end whether or
// not the retry succeeded — a green suite that needed a retry is not the same claim as a green suite.
const retried = [];
// --only <substring> runs just the gates whose name matches. Added because verifying a three-line
// change to the runner itself otherwise costs a fifteen-minute full sweep, and the first attempt to
// prove the shrink check above did not prove it: the chosen gate failed on its own timeout before the
// evidence block ran, and every Go gate failed because that shell had no toolchain on PATH. A filtered
// run makes that kind of mistake visible in seconds. It always prints what it skipped — a partial run
// reported as if it were the whole suite is the same lie this file exists to prevent.
const only = flag('--only');
// A comma-separated list, so a caller can name a SET of gates rather than one. CI needs this: a pull
// request runs a small, fast subset while main and release run everything, and expressing that subset
// as a list keeps it derived from the names in this array instead of hand-copied into YAML.
const onlyList = only ? only.split(',').map((s) => s.trim()).filter(Boolean) : [];
const matches = (c) => onlyList.length === 0 || onlyList.some((o) => c.name.includes(o));

// Go needs the pinned toolchain; inherit whatever the caller set rather than guessing a path, but
// default GOTOOLCHAIN so a stray go.mod directive cannot pull a different compiler mid-verify.
const env = { ...process.env, GOTOOLCHAIN: process.env.GOTOOLCHAIN || 'local' };

// The Go files gofmt is held to. Derived once, and from git rather than from a directory list,
// because the two spellings that existed measured different trees: this runner checked `internal`
// and `cmd`, so it never saw packaging/feed/usigntool or the deferred feature, while CI's
// `git ls-files '*.go'` saw those and not a file that had yet to be added. That second gap is not
// hypothetical — a test file committed earlier in this session was unformatted, and the check run
// before `git add` could not see it because an untracked file is not in `git ls-files`.
//
// `--cached --others --exclude-standard` is tracked plus new-but-not-ignored, which is every Go
// file a change can be in.
//
// A published tarball is not a git checkout, and neither is the scratch copy the scrub gate
// builds. There git exits 128, and this used to end the run with a Node stack trace — a runner
// that cannot say why it stopped. The fallback walks the tree for the same files and reports
// which list gofmt is being held to, because the two are not identical: git omits ignored files
// and a walk does not.
function goFilesFromGit() {
  return execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '*.go'],
    { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 })
    .split('\n').map((s) => s.trim()).filter((file) => file && fs.existsSync(file));
}
function goFilesFromWalk(dir, acc = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === '.git' || e.name === 'node_modules') continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) goFilesFromWalk(full, acc);
    else if (e.name.endsWith('.go')) {
      acc.push(path.relative(process.cwd(), full).split(path.sep).join('/'));
    }
  }
  return acc;
}
let goFiles;
try {
  goFiles = goFilesFromGit();
} catch {
  goFiles = goFilesFromWalk(process.cwd());
  console.log(`note: this tree is not a git checkout, so the ${goFiles.length} Go file(s) gofmt `
    + 'is held to were found by walking it rather than by asking git.');
}
if (goFiles.length === 0) {
  console.error('no Go files found to format-check — gofmt would pass over an empty list, which is '
    + 'the vacuous pass this runner exists to prevent');
  process.exit(2);
}

const checks = [
  { name: 'gofmt', cmd: 'gofmt', args: ['-l', ...goFiles],
    // gofmt exits 0 even when it lists unformatted files; the FILE LIST is the failure signal.
    ok: (r) => r.status === 0 && r.stdout.trim() === '',
    detail: (r) => (r.stdout.trim() ? `unformatted:\n${r.stdout.trim()}` : '') },
  { name: 'go vet', cmd: 'go', args: ['vet', './...'] },
  { name: 'go test', cmd: 'go', args: ['test', './...', '-count=1'] },
  { name: 'go test -race', cmd: 'go', args: ['test', '-race', '-count=1',
      './internal/platform/', './internal/server/', './internal/changeset/'] },
  // The suite otherwise runs entirely on the Windows dev box, where every *_linux.go file and every
  // linux build tag is invisible. The product ships to mipsle/mips/arm/arm64 routers, so a change
  // that compiles here can still be broken on every real target. vet for the router platform first
  // (it type-checks the TEST files too, which a plain build skips), then build the binary.
  { name: 'router vet', cmd: 'go', args: ['vet', './...'],
    env: { CGO_ENABLED: '0', GOOS: 'linux', GOARCH: 'arm64' } },
  { name: 'router build', cmd: 'go',
    args: ['build', '-trimpath', '-o', process.platform === 'win32' ? 'NUL' : '/dev/null', './cmd/wayhop'],
    env: { CGO_ENABLED: '0', GOOS: 'linux', GOARCH: 'mipsle' } },
  // The AmneziaWG 3 component, built exactly as CI builds it: pinned to a tag AND a full commit, every
  // router arch WayHop ships. It clones upstream, so it needs the network; with a warm Go build cache
  // the whole run is a few seconds. Fewer than five arches is a failure, not a shorter pass.
  { name: 'amneziawg-go build', cmd: 'sh', args: ['scripts/build-amneziawg-go.sh'],
    evidence: { re: /(\d+) arches built/, min: 5, what: 'amneziawg-go arches' } },
  { name: 'i18n', cmd: 'node', args: ['scripts/check-i18n.mjs'] },
  // The dictionaries the browser downloads must be exactly what web/i18n/ produces. Without this the
  // two can drift silently, and they did: a translation pass was merged, committed and deployed while
  // every language served stayed three days old, because regenerating was a step someone had to
  // remember. `--check` makes it a fact the suite asserts rather than a habit.
  // One per shipped dictionary plus the meta file: 10 today, after the CJK/Indic/Arabic dictionaries
  // were retired and the list was cut to the markets WayHop serves. Move it with web/i18n/langs.json,
  // never to make a red run green — the floor is here so a generator that quietly stops writing
  // dictionaries fails instead of reporting a smaller success.
  { name: 'i18n reproducible', cmd: 'node', args: ['scripts/i18n-generate.mjs', '--check'],
    evidence: { re: /(\d+) generated file\(s\) match/, min: 10, what: 'generated dictionaries matched to source' } },
  { name: 'a11y', cmd: 'node', args: ['scripts/check-a11y.mjs'] },
  { name: 'interaction regressions', cmd: 'node', args: ['scripts/check-interaction-fixes.mjs'],
    evidence: { re: /interaction regressions OK: (\d+) assertions/, min: 20,
      what: 'focused interaction regression assertions' } },
  { name: 'perf budget', cmd: 'node', args: ['scripts/check-perf-budget.mjs'] },
  // devTree: the subject is an artefact of the development repository. This one reads
  // docs/AUDIT_0.5.5.md, which lives in the development repository and is dropped on publish, and
  // every assertion in the gate reads it — so in a redistribution tree it has nothing to measure. It
  // used to exit 0 there and be counted among the passes; a tally is a claim about what was
  // measured, and that one covered a gate that measured nothing.
  { name: 'docs', cmd: 'node', args: ['scripts/check-docs.mjs'], devTree: true },
  { name: 'auth routes', cmd: 'node', args: ['scripts/check-auth-routes.mjs'],
    evidence: { re: /auth routes: (\d+) classified routes; negative fixture rejected/, min: 50,
      what: 'explicitly classified HTTP routes' } },
  { name: 'ui auth', cmd: 'node', args: ['scripts/check-ui-auth.mjs'],
    evidence: { re: /ui auth: (\d+) contracts pass/,
      min: 1, what: 'headless authentication contract' } },
  // Static, and it has to be: the browser gates below cannot see this one. They walk the routes in a
  // fixed order, so a chunk that defines a helper another chunk calls is always already loaded by the
  // time the second page renders — the sweep passed for as long as `mono` was broken.
  { name: 'chunk refs', cmd: 'node', args: ['scripts/check-chunks.mjs'],
    evidence: { re: /(\d+) cross-chunk name comparisons/, min: 20, what: 'cross-chunk name comparisons' } },
  // `go test ./...` prints ok for a package whose tests all skipped, so a green suite can contain
  // tests that proved nothing. This names them and pins the list, so a newly-inert test — the case
  // that actually matters, because it looks exactly like a passing one — cannot slip in.
  { name: 'inert tests', cmd: 'node', args: ['scripts/check-skips.mjs'] },
  { name: 'dom nulls', cmd: 'node', args: ['scripts/check-dom.mjs'] },
  // A release/feed job must package exactly the event tag's commit. The self-test pins both the
  // accepted shape and every refusal that prevents branch builds, moved tags, version drift and
  // shell-shaped workflow input from becoming signed artefacts.
  { name: 'release source', cmd: 'node', args: ['scripts/check-release-source.mjs', '--self-test'],
    evidence: { re: /release source: (\d+) refusal\/acceptance checks passed/, min: 12,
      what: 'release source refusal/acceptance checks' } },
  // Tags on actions and container images can move after review. This rejects every external action
  // without a full commit SHA and every image in the package/sign/test trust boundary without a
  // sha256 digest, with subject-count floors so an empty scan cannot pass.
  { name: 'dependency pins', cmd: 'node', args: ['scripts/check-dependency-pins.mjs'],
    evidence: { re: /dependency pins: (\d+) external actions and (\d+) production\/test image references verified/,
      min: 20, what: 'external action pins' } },
  // This array is the project's gate list; CI keeps its own in YAML. They had drifted by four gates
  // with nothing to notice it, so the comparison is itself a gate.
  // It compares invocations now, not just filenames, so it has a subject to count — and a floor,
  // because a regex that stopped matching the workflows would otherwise report agreement between
  // the runner and nothing at all.
  { name: 'gate parity', cmd: 'node', args: ['scripts/check-gate-parity.mjs'],
    // 18 covered the script gates alone, which was all this gate compared. It now compares the
    // six builtin ones too — the two compiles, the two test runs, vet and gofmt — so the floor is
    // the whole suite: 25. A number that no longer matches the line the gate prints is worse than
    // a stale one, because the run reports "printed no subject count" and the reason reads as a
    // broken gate rather than a moved one.
    evidence: { re: /gate parity: (\d+) gates compared/, min: 25, what: 'gates compared against CI' } },
  // The installers' health probe only proves SOMETHING answered on the port; this is the matcher
  // that tells the installed build from a stale daemon still holding it, and the cases that must NOT
  // pass are the point of the gate.
  { name: 'installer identity', cmd: 'sh', args: ['scripts/check-installer-identity.sh'],
    evidence: { re: /(\d+) cases/, min: 7, what: 'installer identity cases' } },
  // The feed advertises apk for OpenWrt 25.x, which has no opkg — so a run that publishes no apk
  // packages publishes nothing for the platform the support matrix leads with. These are the cases
  // the completeness check must refuse.
  // A feature that stopped shipping left its data directory behind. The cases that matter are the
  // ones where the migration must REFUSE: an operator's own file, and an archive it already made.
  // The package guarantees an operator's config depends on — protection by omission, the seed-only-
  // when-absent rule, a remove that keeps user data. All correct today, which is why they are pinned.
  // The manifests audit reads the packaging; this RUNS it — the shipped packer's own .ipk handed
  // to a real opkg. It is what found that every .ipk this project published was malformed.
  // And the same on the release a live router actually runs: OpenWrt 25.x has apk and no
  // opkg at all, which is the blind spot the broken .ipk sat in for its whole published life.
  { name: 'apk lifecycle', cmd: 'sh', args: ['scripts/check-package-install-apk.sh'],
    evidence: { re: /(\d+) checks on a real apk/, min: 15, what: 'apk lifecycle checks' } },
  { name: 'package lifecycle', cmd: 'sh', args: ['scripts/check-package-install.sh'],
    evidence: { re: /(\d+) checks on a real opkg/, min: 60, what: 'opkg lifecycle checks across the supported releases' } },
  // The audit and its fault cases are two gates, and only the fault half was here: a local run
  // exercised the things the audit must REFUSE and never the positive guarantees it asserts, while CI
  // ran both. Found by asking the parity check the question it did not ask — which gates does CI
  // have that the runner does not.
  { name: 'package guarantees', cmd: 'sh', args: ['scripts/check-package-manifests.sh'],
    evidence: { re: /(\d+) guarantees hold/, min: 49, what: 'packaging guarantees across three formats' } },
  { name: 'package manifests', cmd: 'sh', args: ['scripts/check-package-manifests-faults.sh'],
    evidence: { re: /(\d+) cases/, min: 22, what: 'package manifest fault cases' } },
  { name: 'iptv retirement', cmd: 'sh', args: ['scripts/check-retire-iptv.sh'],
    evidence: { re: /(\d+) cases/, min: 13, what: 'iptv retirement cases' } },
  { name: 'feed completeness', cmd: 'sh', args: ['scripts/check-feed-completeness.sh'],
    evidence: { re: /(\d+) cases/, min: 9, what: 'feed completeness cases' } },
  // The one-command bootstrap is the release trust entrypoint. These cases prove mandatory digest
  // parsing plus capability-conditional signature refusal before install.sh can run.
  { name: 'bootstrap trust', cmd: 'sh', args: ['packaging/test/bootstrap_harness.sh'],
    evidence: { re: /(\d+) passed, 0 failed/, min: 19, what: 'bootstrap trust and handoff cases' } },
  // Entware's stock rc.func discards daemon stdout/stderr. The shipped Keenetic init script owns
  // that lifecycle so startup recovery and native-adapter failures reach the native system log.
  { name: 'keenetic init logging', cmd: 'sh', args: ['packaging/test/s99wayhop_harness.sh'],
    evidence: { re: /s99wayhop: (\d+) lifecycle and log-sink checks passed/, min: 10,
      what: 'Keenetic init lifecycle and native-log checks' } },
  // The index is the only thing an opkg client reads before it fetches anything, and the indexer is
  // a READER of the container the packer writes. Correcting the packer broke it, and no gate
  // noticed, because the indexer had never been run by one — the lifecycle gates install a .ipk
  // they are handed, and never ask where a client would have learned about it.
  { name: 'feed index', cmd: 'sh', args: ['scripts/check-feed-index.sh'],
    evidence: { re: /(\d+) checks on a real packed \.ipk/, min: 20, what: 'feed index checks' } },
  // apk adbsign can report a per-file error while returning success. Exercise the exact pinned,
  // network-disabled signing boundary with two disposable keypairs and require post-sign crypto
  // verification, including wrong-key and tamper refusals.
  { name: 'apk signing', cmd: 'sh', args: ['scripts/check-apk-signing.sh'],
    evidence: { re: /apk signing: (\d+) real-crypto checks passed/, min: 5, what: 'apk signing checks' } },
  // The publish rules drop docs/ and design/ and keep scripts/ and internal/, so a comment citing
  // one of those design notes by path resolves here and dangles in the tree the public gets. The
  // pointer is worth keeping; what it has to do is say where the document lives. (This very entry
  // named such a note as an example, and the gate caught it — which is the behaviour wanted.)
  // The publish rules rewrite Go source on the way out, so the suite above proves the development
  // text and not the text anyone receives. This compiles, vets and tests the transform's output.
  // Bind each rule to the exact published Go paths and occurrence counts it transforms, while also
  // retaining the conservative rewritten-file and substitution floors. The script's negative
  // fixtures prove that losing either a path or occurrences changes the fingerprint, then the full
  // transformed tree is compiled, vetted and tested.
  { name: 'scrub output', cmd: 'node', args: ['scripts/check-scrub-output.mjs'], devTree: true,
    // 112 until the strict-Apply ledger stack (45 files) was replaced by a six-file one; the floor
    // tracks the file count that actually exists so a scrub that quietly stops rewriting still fails.
    evidence: { re: /scrub output: (\d+) rewritten Go file/, min: 108, what: 'Go files scrubbed and verified' } },
  // The scrub gate above proves the KNOWN personal strings are rewritten. This one asks the other
  // question: does anything with the SHAPE of personal data survive into the publishable set — an
  // address, a hostname, a key, a token, a MAC, an email that nobody thought to add to the deny
  // list? It found a WireGuard peer key left in a Keenetic running-config fixture whose endpoint had
  // already been genericised by hand, which is precisely the miss a blocklist cannot cover.
  { name: 'pii shapes', cmd: 'node', args: ['scripts/check-pii.mjs'], devTree: true,
    // The floor is the publishable file count: a scan that quietly stops reading files would
    // otherwise report zero hits and pass, which is the same green as a clean tree.
    evidence: { re: /pii OK: (\d+) publishable file/, min: 800, what: 'publishable files scanned for PII shapes' } },
  { name: 'published pointers', cmd: 'node', args: ['scripts/check-published-refs.mjs'], devTree: true,
    // 30 before the three development-tree gates above stopped being published; the marked
    // pointers in their headers left the published set with the files that carried them.
    evidence: { re: /published pointers: (\d+) references/, min: 28, what: 'pointers into dropped paths' } },
];

if (uiURL) {
  // FIRST, before anything measures that instance: is it even serving this tree's build? A whole
  // session of UI gates once ran green against a demo binary from the previous day — a stale process
  // held the port, the newly built one could not bind and exited silently, and every gate below
  // dutifully measured the wrong UI. None of them could notice, because each was asking whether the
  // page was correct and none was asking whose page it was.
  checks.push({ name: 'target is this build', cmd: 'node', args: ['scripts/check-target-fresh.mjs', uiURL] });
  // Then make the profile deterministic. A demo holds its profile in memory, so every restart hands
  // the gates 4 objects where the seeded run had 14 — and pages whose height and controls grow with
  // the profile then measure small and pass. Seeding here makes a gate run self-contained instead of
  // depending on someone having remembered. It steps aside for a router.
  checks.push({ name: 'demo seeded', cmd: 'node', args: ['scripts/seed-demo.mjs', uiURL, '--skip-if-not-demo'] });
  checks.push({ name: 'page sweep', cmd: 'node', args: ['scripts/ui-sweep.mjs', uiURL] });
  // scripts/router-cold.mjs and scripts/router-edit-dialogs.mjs are deliberately NOT registered here.
  //
  // Both are worth running — the first opens every route in its own fresh browser, which is the only
  // way to see a page that works solely because an earlier one loaded a chunk it needs (that is how a
  // dead Diagnostics battery survived every sweep), and the second asserts that Edit dialogs come up
  // FILLED, which found an endpoint that could not be edited at all. But `cold routes` launches ELEVEN
  // browsers in one gate, and added to the fifteen this suite already runs the host stopped being able
  // to create processes: a run went from a stable 39/39 to 25/39 with fourteen gates failing at 0.0s
  // with 0xC0000142 (DLL init failed — the Windows shape of "no resources to start a process").
  //
  // A suite that becomes unreliable is worse than one that covers less, because the first thing an
  // unreliable suite costs is the habit of reading it. Run them by hand, against the demo or a router:
  //   node scripts/router-cold.mjs        http://192.168.2.1:8088/
  //   node scripts/router-edit-dialogs.mjs http://192.168.2.1:8088/ --max 4
  checks.push({ name: 'fault injection', cmd: 'node', args: ['scripts/ui-faults.mjs', uiURL] });
  // This one was watched passing on nothing: with its selector pointed at a class that does not
  // exist it exited 0 and printed "button names unique on all 9 routes" — nine being a constant, not
  // a measurement. A duplicate-detector has nothing to say about an empty set, which is exactly why
  // the floor belongs in the runner rather than in the gate.
  checks.push({ name: 'button names', cmd: 'node', args: ['scripts/ui-names.mjs', uiURL],
    evidence: { re: /subjects: (\d+) named controls examined/, min: 40, what: 'named controls examined' } });
  checks.push({ name: 'page density', cmd: 'node', args: ['scripts/ui-density.mjs', uiURL],
    evidence: { re: /subjects: (\d+) rendered nodes/, min: 400, what: 'nodes measured' } });
  checks.push({ name: 'page structure', cmd: 'node', args: ['scripts/ui-page-structure.mjs', uiURL] });
  checks.push({ name: 'rule order', cmd: 'node', args: ['scripts/ui-rule-order.mjs', uiURL] });
  // Control preservation. This gate was written for the redesign's one hard constraint — lose no
  // function, drop no button — and then was never added here, so for the whole redesign it ran only
  // when somebody remembered to run it by hand. A gate outside the suite is not a gate; it is a
  // habit, and habits are exactly what the suite exists to replace.
  checks.push({ name: 'control preservation', cmd: 'node', args: ['scripts/ui-controls.mjs', uiURL],
    evidence: { re: /checked (\d+) controls/, min: 40, what: 'controls compared' } });
  // Route-scoped chunks added a failure mode the single bundle never had: a page's code can fail to
  // arrive. This blocks one chunk and checks the page degrades to the ordinary error rather than a
  // permanent skeleton or a page that looks finished with its controls missing, then unblocks and
  // checks the next visit retries instead of staying broken for the session.
  checks.push({ name: 'chunk fallback', cmd: 'node', args: ['scripts/ui-chunk-fallback.mjs', uiURL] });
  // A component the kernel already carries must not be offered for install. The state cannot occur on
  // a dev box, so the gate stubs the engine list and asserts against the DOM the real app builds.
  checks.push({ name: 'kernel-carried', cmd: 'node', args: ['scripts/ui-kernel-carried.mjs', uiURL],
    evidence: { re: /(\d+) checks across/, min: 36, what: 'kernel-carried checks' } });
  // LAST, because it deliberately leaves the demo holding an oversized profile. Eight times now a
  // page has broken its height budget for the same reason — it draws one row per configured object,
  // and every profile used during design was smaller than a real one. Finding those one at a time,
  // whenever some profile happened to be big enough that day, is whack-a-mole: it catches instances,
  // never the class, and it silently regresses when the test profile shrinks. This seeds a profile
  // past any plausible deployment and re-measures, so "bounded" is something the suite checks rather
  // than something the last fix happened to achieve. Skipped against a router.
  checks.push({ name: 'stress seeded', cmd: 'node', args: ['scripts/seed-stress.mjs', uiURL, '--skip-if-not-demo'] });
  checks.push({ name: 'density at scale', cmd: 'node', args: ['scripts/ui-density.mjs', uiURL],
    evidence: { re: /subjects: (\d+) rendered nodes/, min: 1500, what: 'nodes measured' } });
  // Then hostile CONTENT, as opposed to hostile counts. Endpoint names are not all typed by the user:
  // the importer parses share links fetched from a remote subscription URL, so their `#name` fragment
  // is controlled by whoever runs that subscription. The daemon stores markup in a name without
  // complaint (measured: 10 of 10 payloads accepted), which leaves the UI as the only thing standing
  // between a hostile subscription and script execution on the box that routes the household's
  // traffic. Left last because it seeds objects the other gates should not see; the next run's
  // `demo seeded` step removes them, since that now clears anything it did not create.
  // Render cost, at whatever scale the profile currently holds — which after the two seeds above is
  // the stress one, so this is the expensive case. The budget is on time-to-content and
  // time-to-control, never on wall time: the dashboard waits on a public-IP lookup per exit, an
  // internet round trip the panel does not own, and gating that would be gating someone else's
  // network. What the design IS answerable for is showing structure and becoming operable fast.
  checks.push({ name: 'render time', cmd: 'node', args: ['scripts/ui-render-time.mjs', uiURL] });
  // A router panel is opened from a phone at least as often as from a desktop, usually while standing
  // next to the router because something is broken. Every other measurement here is taken at 1280x900.
  // Runs after the stress and hostile seeds so it sees long names, which is what actually breaks a
  // narrow layout.
  checks.push({ name: 'narrow viewport', cmd: 'node', args: ['scripts/ui-narrow.mjs', uiURL],
    evidence: { re: /subjects: (\d+) element boxes/, min: 400, what: 'element boxes' } });
  // Every gate above this line renders the panel in English. check-i18n proves the other fourteen
  // languages have every key; it cannot say what those strings do to the page, and the 260 strings
  // the redesign added shipped without anyone having SEEN one of them rendered. A German compound in
  // a fixed-width chip or an RTL line that pushes the body sideways passes every check in this file.
  // One browser, language switched through localStorage exactly as the Settings selector does, with
  // English measured first so a control that already clips is the layout's fault and not counted
  // against fifteen languages.
  // The floor is the shipped set minus the English baseline (web/i18n/langs.json): 9 today, after the
  // CJK/Indic/Arabic dictionaries were retired and the list was cut to the markets WayHop serves. It
  // is here so a gate that quietly stops measuring languages fails — move it with langs.json, never to
  // make a red run green.
  checks.push({ name: 'language fit', cmd: 'node', args: ['scripts/ui-lang-fit.mjs', uiURL],
    evidence: { re: /(\d+) languages, \d+ routes/, min: 9, what: 'languages rendered and measured' } });
  // The other end, and the bigger hole. The widths every gate above renders at were collected rather
  // than assumed: 1280 for all of them, plus 375-1040 in `narrow viewport`. NOTHING looked above
  // 1280, while the operator's viewport is 1883px and `.app` runs to 1720 — so the whole regime the
  // panel is actually used in was unmeasured, and a track rebalance regressed the Routing table at
  // 1440px straight through a green suite. Runs after the stress seed for the same reason as the
  // narrow gate: long names are what expose a width problem.
  checks.push({ name: 'wide viewport', cmd: 'node', args: ['scripts/ui-wide.mjs', uiURL],
    evidence: { re: /subjects: (\d+) page renders/, min: 40, what: 'page renders' } });
  // Contrast, in BOTH themes. The a11y gate checks structure — aria-current, label wiring, roles —
  // and structure is not legibility. [data-theme=light] existed for the whole redesign without a
  // single automated look at it, and a token correct in dark and wrong in light is invisible to
  // every other gate here. WCAG AA is arithmetic, so this is an assertion rather than a taste.
  // Anything whose job is to be one line and is taking two: a stat value broken between a number and
  // its unit, a card title split in half. Reads as broken rather than as full, and the operator saw
  // it before any gate did.
  checks.push({ name: 'line wrapping', cmd: 'node', args: ['scripts/ui-wrap.mjs', uiURL],
    evidence: { re: /subjects: (\d+) single-line elements/, min: 20, what: 'single-line elements' } });
  checks.push({ name: 'contrast', cmd: 'node', args: ['scripts/ui-contrast.mjs', uiURL],
    evidence: { re: /subjects: (\d+) text elements/, min: 300, what: 'text elements' } });
  // Keyboard, the other half of the a11y story. The a11y gate wires labels and roles; the contrast
  // gate makes text readable; neither presses Tab. WCAG 2.1.1 (operable from a keyboard) and 2.4.7
  // (focus visible) had never been exercised. It matters here in particular because seven <details>
  // folds were added to bound page heights, and folding moves controls out of the tab order until
  // the summary is opened — the control-preservation gate counts a folded control as present, which
  // is true and is not the same claim as reachable.
  // RTL. The panel ships Arabic and Persian and sets dir="rtl" for them, so this is a live path for
  // real users — and nothing here had ever rendered it. styles.css is built from 73 physical
  // direction properties and zero logical ones, which do not flip with direction. The gate measures
  // each route in LTR first and compares, because "nothing overflows" is not the same claim as "the
  // same page rendered": a route that quietly drops content in RTL passes an overflow check.
  checks.push({ name: 'rtl layout', cmd: 'node', args: ['scripts/ui-rtl.mjs', uiURL],
    evidence: { re: /subjects: (\d+) element boxes measured in RTL/, min: 400, what: 'element boxes in RTL' } });
  checks.push({ name: 'keyboard', cmd: 'node', args: ['scripts/ui-keyboard.mjs', uiURL],
    evidence: { re: /subjects: (\d+) controls reached/, min: 50, what: 'controls reached' } });
  // Column tracks. Routing's headings sat 192px off the data they named, and DNS's query path had the
  // same bug at 188px — both because two sibling grids resolved a content-sized track differently.
  // Neither was caught by anything here: the operator saw the routing one, and the gate written for it
  // then found the DNS one, which is the argument for the gate existing. It compares RESOLVED tracks
  // between structurally identical rows, so a shared rule that resolves two ways is the failure, and a
  // control that sizes itself inside an agreed track is not a subject.
  // The stylesheet itself. A parse error is silent — the browser drops what it cannot read and
  // renders the rest, so a dropped rule looks like a fix that did not work. One stray `*/` disabled
  // a layout fix that was then built, deployed to two routers and screenshotted before a DOM
  // measurement caught it. This runs without a browser and takes milliseconds.
  checks.push({ name: 'stylesheet parses', cmd: 'node', args: ['scripts/check-css.mjs'],
    evidence: { re: /subjects: (\d+) top-level rules checked/, min: 400, what: 'top-level CSS rules' } });
  checks.push({ name: 'column tracks', cmd: 'node', args: ['scripts/ui-columns.mjs', uiURL],
    evidence: { re: /subjects: (\d+) row groups measured/, min: 4, what: 'row groups measured' } });
  checks.push({ name: 'hostile seeded', cmd: 'node', args: ['scripts/seed-hostile.mjs', uiURL, '--skip-if-not-demo'] });
  checks.push({ name: 'injection', cmd: 'node', args: ['scripts/ui-injection.mjs', uiURL],
    evidence: { re: /seen rendered (\d+) times/, min: 5, what: 'payloads rendered as text' } });
}
if (applyURL) {
  checks.push({ name: 'apply faults', cmd: 'node', args: ['scripts/ui-apply-faults.mjs', applyURL],
    evidence: { re: /(\d+)\/\d+ apply fault checks passed/, min: 16, what: 'apply-path fault checks' } });
}

// A gate's tier is decided by what it needs, not by where it sits in the array: a gate carrying the
// UI url cannot run without a live daemon, and one carrying the apply url needs a disposable instance.
const tierOf = (c) => (uiURL && c.args.includes(uiURL) ? 'ui' : applyURL && c.args.includes(applyURL) ? 'apply' : 'static');

// --ui-only keeps just the gates that need a running instance. CI's dynamic job wants exactly those:
// the Go and static gates already run in their own jobs, and re-running them here would double the
// build time to re-prove what another job just proved. Deriving the set from the tier means the job
// never carries a hand-copied list of gate names that can fall behind this array.
if (args.includes('--ui-only')) {
  if (!uiURL) {
    console.error('--ui-only needs --ui <url>: without one there are no UI gates to keep, and an empty',
      'run reported as a pass is the failure this runner exists to prevent');
    process.exit(2);
  }
  const kept = checks.filter((c) => tierOf(c) !== 'static');
  checks.length = 0;
  checks.push(...kept);
}

// --list prints the resolved gate list and runs nothing. This file is the only place the full,
// ordered set of gates exists, and CI had drifted from it silently: four static gates — the i18n
// reproducibility check, chunk refs, dom nulls and the skip manifest — were in this array and in no
// workflow at all, so a green badge covered a smaller suite than the one this runner defines.
// Emitting the list makes the drift measurable by scripts/check-gate-parity.mjs instead of noticed
// by accident. The tier says what a gate needs, because that is what decides where it can run.
if (process.argv.includes('--list')) {
  for (const c of checks) {
    const tier = tierOf(c);
    // Fourth column: the environment the gate is run with, so a reader of this list — and the
    // parity check that consumes it — can tell `router build` from a host build. Empty for the
    // gates that need none, which keeps the first three columns exactly where they were.
    const env = Object.entries(c.env || {}).map(([k, v]) => `${k}=${v}`).join(' ');
    console.log([tier, c.name, [c.cmd, ...c.args].join(' '), env].join('\t'));
  }
  process.exit(0);
}

// A gate marked devTree measures something that exists only in the development repository. In THIS
// tree it is required: if its script has gone missing the run fails, because a gate that quietly
// stops existing is how a suite shrinks without anyone deciding to shrink it. In a redistribution
// tree — where publish/scrub-rules.json (development repository) and the artefacts it drops are both
// absent — the gate is removed from the run and NAMED, so the tally below is a claim about gates
// that were actually exercised rather than one padded with three that could not be. --list is
// deliberately left whole: it is what this runner DEFINES, which is what the parity check holds
// CI to, and that does not change with the tree the runner is sitting in.
const DEV_TREE = fs.existsSync(path.join(process.cwd(), 'publish', 'scrub-rules.json'));
const devOnly = checks.filter((c) => c.devTree);
if (DEV_TREE) {
  const missing = devOnly.filter((c) => c.cmd === 'node' && !fs.existsSync(c.args[0]));
  if (missing.length) {
    console.error(`this is the development tree, where ${missing.map((c) => c.name).join(', ')} `
      + 'must run, and the script(s) behind them are not here. A gate that cannot be found is not a '
      + 'gate that passed.');
    process.exit(2);
  }
} else {
  for (const c of devOnly) checks.splice(checks.indexOf(c), 1);
  console.log(`note: ${devOnly.length} gate(s) measure the development repository’s own artefacts `
    + `and are not run here: ${devOnly.map((c) => c.name).join(', ')}. Their subjects are dropped on `
    + 'publish, so they are excluded from the count below rather than counted as passing.');
}

const results = [];
const skipped = only ? checks.filter((c) => !matches(c)).map((c) => c.name) : [];
// EVERY term has to match something, not just one of them. The guard here used to fire only when
// the whole list matched nothing, which is the rarest way for this to go wrong; the common way is
// one name in a list of five going stale after a gate is renamed. CI passes exactly such a list on
// a pull request — `--only 'target is this build,demo seeded,page sweep,button names,page
// structure'` — so a rename would have quietly reduced that run to four gates and reported green.
//
// A term naming a gate that exists only with --ui or --apply gets its own message: the caller asked
// for something this invocation cannot run, and dropping it silently is the same defect.
const CONDITIONAL = { ui: '--ui', apply: '--apply' };
const dead = onlyList.filter((o) => !checks.some((c) => c.name.includes(o)));
if (dead.length) {
  for (const o of dead) {
    const tier = uiURL ? null : (/page|sweep|density|viewport|contrast|keyboard|rtl|injection|render|language|chunk fallback|rule order|control preservation|kernel-carried|seeded|target is this build|stylesheet|column|line wrapping|button names/.test(o) ? 'ui'
      : /apply/.test(o) ? 'apply' : null);
    console.error(tier
      ? `--only term "${o}" names a gate that only exists with ${CONDITIONAL[tier]}; pass it or drop the term`
      : `--only term "${o}" matched no gate`);
  }
  console.error(`names are: ${checks.map((c) => c.name).join(', ')}`);
  process.exit(2);
}
for (const c of checks) {
  if (!matches(c)) continue;
  process.stdout.write(`… ${c.name}`.padEnd(24));
  const started = process.hrtime.bigint();
  let r = spawnSync(c.cmd, c.args, { encoding: 'utf8', env: { ...env, ...(c.env || {}) }, shell: false });
  let secs = Number(process.hrtime.bigint() - started) / 1e9;

  // One retry, and ONLY for a gate that died before running anything.
  //
  // Four times now a gate has died in seconds with exit 3221226505 (0xC0000409, the Windows fastfail
  // status) having printed nothing at all — `narrow viewport`, `button names`, `line wrapping`,
  // `render time`, each passing immediately on its own afterwards. Measured across seven consecutive
  // full runs the rate was 2 in 7.
  //
  // An earlier version of this comment called it "the fast-fail Chrome uses for a startup it cannot
  // complete". That attribution does not survive reading the gates: they exit 0 or 1 and never
  // propagate the browser's status, so this code belongs to the gate's own process — or to the
  // cmd.exe that wraps it, since Windows spawns go through a shell here. Which of the two is what
  // the probe below now measures, because two iterations were spent investigating Chrome on the
  // strength of a guess written down as a fact.
  //
  // Ruled out by measurement, in this order: the gates run sequentially (no concurrent launches);
  // all 19 debug ports are distinct; no Chrome process or listener survives a run; each gate takes a
  // fresh mkdtemp profile; and the temp debris is 12 directories, not a disk-pressure story. It
  // remains unexplained.
  //
  // Also ruled out, and this one cost 240 process launches: it is not the gate's own startup. The
  // crash lands at ~0.4s, far inside the 3s window this code calls a startup crash, so a run does not
  // have to finish to be a sample — launch it, give it three seconds, tree-kill whatever is still
  // alive. 120 samples of `density at scale` that way, interleaved with 120 of a node process that
  // launches no browser at all, produced ZERO fastfails on either. Against a prior rate of 2 in 7 full
  // suite runs, that says the trigger is not in launching this gate; it is something the suite
  // accumulates across the thirty gates before it. Which is a narrower unexplained than the last one,
  // and the reason the retry stays: a cause that needs a whole suite to appear cannot be reproduced by
  // the gate that suffers it.
  //
  // One more datum, and it is attribution rather than cause. Twice in one session a gate run here
  // ended with libuv's own `Assertion failed: !(handle->flags & UV_HANDLE_CLOSING)` on stderr — node
  // aborting during teardown — and on Windows abort() goes through __fastfail, which is what 0xC0000409
  // IS. So the status is node killing itself, not the OS killing node. That does not explain the
  // crashes seen here, and it must not be written down as if it did: both of those printed the
  // assertion, while every retried gate printed nothing at all, which is a different failure. What it
  // does rule out is the reading that something external reaped the process.
  //
  // The narrow condition matters. This retries only when the gate produced NO output and died fast
  // with a status that is not 1 — a crash before any check ran, which the runner already
  // distinguishes from a failed check. A gate that ran and reported a failure is never retried, and a
  // retry that happens is announced here and again in the summary, because a suite that quietly
  // re-rolls its dice is worse than one that goes red: the point of the red is that somebody looks.
  const startupCrash = () => !r.error && r.status !== 0 && r.status !== 1 && secs < 3 &&
    !((r.stdout || '') + (r.stderr || '')).trim();
  if (startupCrash()) {
    // Before retrying, ask the question the retry cannot: does it happen AGAIN, straight away?
    //
    // This probe is what produced the only evidence there is. It was added when gates were still
    // spawned through cmd.exe, to say whether the fastfail was the shell's or the gate's; the first
    // real occurrence answered `status=0, stderr empty` — the same gate, run again seconds later,
    // completing silently and successfully. So the gate's own code is not what dies, and the shell
    // is now gone from the launch path entirely (it was never needed: node, go and gofmt all
    // resolve without it, and Node 24 deprecates passing args through it).
    //
    // It stays because "did it reproduce immediately" is worth recording on every occurrence, and it
    // costs one extra gate run only on the rare crash.
    const probe = spawnSync(c.cmd, c.args, { encoding: 'utf8', env: { ...env, ...(c.env || {}) }, shell: false });
    const probeNote = probe.error
      ? `probe could not run: ${probe.error.code || probe.error.message}`
      : `probe(no shell) status=${probe.status}, ` +
        ((probe.stderr || '').trim()
          ? `stderr: ${JSON.stringify((probe.stderr || '').trim().slice(0, 300))}`
          : 'stderr empty');

    process.stdout.write(`retry(startup crash ${r.status}) `);
    retried.push({ name: c.name, status: r.status, secs, probe: probeNote });
    const t2 = process.hrtime.bigint();
    r = spawnSync(c.cmd, c.args, { encoding: 'utf8', env: { ...env, ...(c.env || {}) }, shell: false });
    secs = Number(process.hrtime.bigint() - t2) / 1e9;
  }

  if (r.error) {
    results.push({ name: c.name, pass: false, detail: `could not run ${c.cmd}: ${r.error.message}`, secs });
    console.log(`ERROR  (${secs.toFixed(1)}s)`);
    continue;
  }
  let pass = c.ok ? c.ok(r) : r.status === 0;
  const raw = ((r.stdout || '') + (r.stderr || '')).trim();

  // EVIDENCE: exit 0 is not the same as "examined something". Every gate in this suite has, at some
  // point, passed for the wrong reason — a page measured before it rendered, a tab walk truncated at
  // its ceiling, an injection detector scoped to the wrong element, an overflow check reading the one
  // property a clipping ancestor hides. Every single one was caught by two measurements DISAGREEING,
  // never by a gate going red on its own, which means the suite had no way to notice a gate that had
  // quietly stopped looking at anything.
  //
  // So a gate that declares `evidence` must not merely exit 0: it must print how much it examined, and
  // that number must clear a floor. This is the "a check that passes when its subject is ABSENT proves
  // nothing" rule moved out of a human's head and into the runner.
  let evidence = '';
  if (pass && c.evidence) {
    const m = raw.match(c.evidence.re);
    const n = m ? Number(m[1]) : NaN;
    if (!m) {
      pass = false;
      evidence = `passed but printed no subject count — expected ${c.evidence.re} in its output.\n` +
        'A gate that cannot say what it examined cannot be believed when it says it is happy.';
    } else if (!(n >= c.evidence.min)) {
      pass = false;
      evidence = `passed having examined ${n} ${c.evidence.what}, below the floor of ${c.evidence.min}.\n` +
        'That is a vacuous pass: the subject was absent or truncated, so the gate proved nothing.';
    } else if (baseline[c.name] && n < Math.round(baseline[c.name] * SHRINK)) {
      // A floor only catches a subject that vanished. It does not catch one that SHRANK, and that is
      // the case this suite actually hit: a crashed fault-injection run left an armed failsafe whose
      // rollback later reverted the seeded profile, so from that point on `keyboard` examined 167
      // controls instead of 722, `rtl layout` 1851 boxes instead of 5951, and `density at scale` 9437
      // nodes instead of 11104. Every one of those gates reported PASS, because every count was still
      // far above its floor. The suite spent a whole run measuring a fifth of the page and said it was
      // happy — the exact failure the floors were introduced to prevent, one size down.
      //
      // The baseline is a recorded green run, not a running average: an average would ratchet down as
      // the counts decayed, which is how a regression detector becomes a regression.
      pass = false;
      evidence = `passed having examined ${n} ${c.evidence.what}, against a recorded ` +
        `${baseline[c.name]} — ${Math.round((1 - n / baseline[c.name]) * 100)}% fewer.\n` +
        'The gate is looking at a fraction of what it looked at when this baseline was taken, which is ' +
        'a pass about a smaller page, not about this one. Re-record with --update-baseline once the ' +
        'drop is understood and intended.';
    } else {
      evidence = `${n} ${c.evidence.what}`;
      seen[c.name] = n;
    }
  }
  // The terminal gets a short tail; the persisted report gets everything. A flaky `go test -race`
  // was left unidentifiable because the tail held the daemon's log chatter while the
  // "--- FAIL: TestName" line had already scrolled past it — the one line the report exists for.
  const lines = raw.split('\n');
  // Verdict lines lead, so a noisy tail can never bury the name of what failed.
  const verdicts = lines.filter((l) => /^\s*(---\s+(FAIL|SKIP)|FAIL\s|WARNING: DATA RACE|panic:)/.test(l));
  const tail = c.detail ? c.detail(r) : lines.slice(-12).join('\n');
  let detail = verdicts.length ? verdicts.slice(0, 20).join('\n') + '\n---\n' + tail : tail;
  // A gate can fail having printed NOTHING — seen once here: fault injection exited after 0.5s with
  // empty stdout and stderr, and the report had an empty section, which reads like a missing report
  // rather than the finding it is. Say so, and give the exit status and duration: "crashed on
  // startup" and "ran the checks and one failed" are different problems with different fixes.
  if (!pass && !raw) {
    detail = `the gate produced no output at all — exit status ${r.status}` +
      `${r.signal ? `, signal ${r.signal}` : ''}, after ${secs.toFixed(1)}s.\n` +
      'That usually means it died before running any check (a tool missing from PATH, a debugging ' +
      'port still held by a previous run), not that a check failed. Re-run it on its own to see.';
  }
  // An evidence failure replaces the detail: the gate's own output says it is happy, and repeating
  // that would bury the actual reason it is being failed.
  if (evidence && !pass) detail = evidence;
  results.push({ name: c.name, pass, detail: pass ? '' : detail, full: pass ? '' : raw, secs });
  // Print WHAT it examined next to the pass, so a shrinking subject is visible in the normal output
  // rather than only when it crosses a floor.
  console.log(`${pass ? 'PASS' : 'FAIL'}   (${secs.toFixed(1)}s)` + (pass && evidence ? `  ${evidence}` : ''));
}

const failed = results.filter((r) => !r.pass);
if (failed.length) {
  console.log('\n' + '='.repeat(70));
  for (const f of failed) {
    console.log(`\nFAILED: ${f.name}\n${'-'.repeat(70)}\n${f.detail || '(no output)'}`);
  }
  // Persist it. Twice now a transient failure here has been lost because the caller piped this
  // through `tail`, which keeps the summary and discards the diagnosis printed directly above it.
  // A report that only survives an untruncated terminal is not a report.
  const out = path.join(os.tmpdir(), `wayhop-verify-fail-${process.pid}.txt`);
  try {
    fs.writeFileSync(out, results.map((r) =>
      `${r.pass ? 'PASS' : 'FAIL'}  ${r.name}  (${r.secs.toFixed(1)}s)\n${r.full || r.detail || ''}`).join('\n\n'));
    console.error(`verify FAILED (${failed.map((f) => f.name).join(', ')}) — full output: ${out}`);
  } catch (e) {
    console.error(`verify FAILED (${failed.map((f) => f.name).join(', ')}); could not write report: ${e.message}`);
  }
}
// Record only from a fully green run. A baseline taken from a failed run would bake in whatever the
// failure did to the page — in the run that prompted this, a rolled-back profile that shrank five
// gates' subjects by up to 4x. Recording that would make the broken state the new normal, and this
// check would then defend it.
// Which recorded gates this run produced no count for. Empty on a first-ever baseline, so recording
// one still works.
const missingFromRun = Object.keys(baseline).filter((k) => !(k in seen));
if (updateBaseline) {
  if (failed.length) {
    console.error('\nbaseline NOT updated: this run failed, and a baseline from a failed run records ' +
      'the failure as normal');
  } else if (missingFromRun.length) {
    // "Only a full UI run may record a baseline" is the rule written above the flag; the guard up
    // there enforces the --ui half of it and never consults --only. Measured:
    // `--only stylesheet --ui … --update-baseline` replaced a 12-gate baseline with a 1-gate one and
    // printed "evidence baseline updated" — the note saying 34 gates had not run came AFTER. The
    // eleven erased gates then have no recorded count, the shrink check short-circuits on
    // `baseline[c.name] &&` being undefined, and they pass on their absolute floors alone. That is
    // exactly the 722-to-167 regression above, with the detector that catches it switched off and
    // nothing saying so.
    //
    // Derived from what the run MEASURED rather than from which flags it was given, so any future way
    // of running a subset is covered by the same check.
    console.error(`\nbaseline NOT updated: this run recorded ${Object.keys(seen).length} gate(s) while the ` +
      `baseline holds ${Object.keys(baseline).length}, so writing it would erase the recorded count for ` +
      `${missingFromRun.length}: ${missingFromRun.join(', ')}.` +
      (only ? `\nThis run was filtered by --only ${only}.` : '') +
      '\nRe-record from a full run, or — if a gate was removed on purpose — drop its entry from ' +
      'scripts/evidence-baseline.json first.');
  } else {
    fs.writeFileSync(BASELINE_PATH, JSON.stringify(
      { recorded: new Date().toISOString().slice(0, 10), gates: results.length, counts: seen }, null, 2) + '\n');
    console.log(`\nevidence baseline updated: ${Object.keys(seen).length} gate(s) recorded`);
  }
}
const total = results.reduce((a, r) => a + r.secs, 0);
console.log(`\n${results.length - failed.length}/${results.length} gates passed in ${total.toFixed(0)}s`);
if (retried.length) {
  console.log(`note: ${retried.length} gate(s) died before running anything and were retried once — ` +
    retried.map((x) => `${x.name} (exit ${x.status} after ${x.secs.toFixed(1)}s)`).join(', ') +
    '. The cause is unexplained; this run is green WITH a retry, which is a weaker claim than green.');
  for (const x of retried) {
    if (x.probe) console.log(`      ${x.name}: ${x.probe}`);
  }
}
if (only) {
  console.log(`note: --only ${only} ran ${results.length} of ${checks.length} gates; ` +
    `${skipped.length} NOT run: ${skipped.join(', ')}`);
}
if (!uiURL) console.log('note: UI gates skipped (pass --ui <url> to include the sweep and fault injection)');
if (!applyURL) console.log('note: apply-path faults skipped (pass --apply <localhost url> to a demo instance)');
process.exit(failed.length ? 1 : 0);
