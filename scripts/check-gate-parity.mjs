// check-gate-parity.mjs — the local suite and CI must require the same gates.
//
// scripts/verify.mjs holds the only ordered list of what this project checks. CI holds its own, in
// YAML, written by hand. Nothing compared them, and they had drifted: four static gates —
// `i18n reproducible`, `chunk refs`, `dom nulls` and `inert tests` — existed in the runner and in no
// workflow at all. A green badge therefore covered a smaller suite than the one the runner defines,
// which is the same defect the audit keeps finding one level up: a result whose scope is narrower
// than the claim printed over it.
//
// SCOPE, stated rather than implied: this compares the SCRIPT gates — node and shell — matched by filename
// in the workflow text. Go gates (gofmt, vet, test, the router cross-builds) are driven by their own
// jobs with their own flags and arch matrices, and matching those by command string would report
// differences that are not drift. Extending this to them means giving the workflows a machine-readable
// gate list, not loosening the match here.
//
// Usage: node scripts/check-gate-parity.mjs
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const WORKFLOWS = path.join(ROOT, '.github', 'workflows');
const EXEMPT = path.join(ROOT, 'scripts', 'gate-parity-exemptions.json');

let listing;
try {
  listing = execFileSync('node', ['scripts/verify.mjs', '--list'], { encoding: 'utf8', cwd: ROOT });
} catch (e) {
  console.error(`FAIL  could not read the gate list from verify.mjs (${e.message})`);
  process.exit(2);
}

const gates = listing.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => {
  const [tier, name, cmd, env] = l.split('\t');
  return { tier, name, cmd, env: env || '' };
});
// A run where verify listed nothing, or no static gate, is not a pass — it means the list did not
// load and every assertion below would be vacuously true.
const statics = gates.filter((g) => g.tier === 'static');
if (statics.length === 0) {
  console.error(`FAIL  verify.mjs --list returned ${gates.length} gate(s) and none static — ` +
    'this check would prove nothing');
  process.exit(2);
}

// Script gates are the comparable set: each is one file, named once, either present in a workflow or
// absent from every workflow.
//
// This covered .mjs only, and that scope note turned into a hole. Five shell gates were added after
// it was written; four reached CI and the fifth did not, and this reported green throughout — the
// drift it exists to catch, hidden by its own stated limit. A shell gate is exactly as decidable as
// a node one, so there was never a reason for the line to be there.
const nodeGates = statics
  .map((g) => ({ ...g, script: (g.cmd.match(/scripts[\\/]([\w.-]+\.(?:mjs|sh))/) || [])[1] }))
  .filter((g) => /^(node|sh) /.test(g.cmd) && g.script);

if (!fs.existsSync(WORKFLOWS)) {
  console.error(`FAIL  ${WORKFLOWS} is missing — there is nothing to compare the runner against`);
  process.exit(2);
}
const yml = fs.readdirSync(WORKFLOWS).filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'));
if (yml.length === 0) {
  console.error('FAIL  no workflow files found — this check would prove nothing');
  process.exit(2);
}
const workflowRaw = yml.map((f) => fs.readFileSync(path.join(WORKFLOWS, f), 'utf8')).join('\n');

// Comments are stripped before anything is looked for. A workflow that merely TALKS about a gate
// does not run it, and this check was satisfied by the talk: the negative test for the tier rule
// below passed with the flag deleted from the command, because the comment explaining the flag
// still contained it. The same hole sat in the coverage test above — a script named only in a
// comment counted as covered.
const workflowText = workflowRaw.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');

const exemptions = fs.existsSync(EXEMPT) ? JSON.parse(fs.readFileSync(EXEMPT, 'utf8')) : { exempt: {} };
const exempt = exemptions.exempt || {};

const missing = [];
const covered = [];
for (const g of nodeGates) {
  if (workflowText.includes(g.script)) { covered.push(g); continue; }
  if (exempt[g.script]) continue;
  missing.push(g);
}

// A shared filename is not a shared check. `node scripts/i18n-generate.mjs --check` verifies that the
// dictionaries are reproducible from source; the same file with no flag REWRITES them. One name, two
// behaviours — and a parity check that compares only names would call CI and the runner identical
// while one of them asserted nothing. So compare what is actually run, both directions: an argument
// the runner passes and CI does not is a weaker CI, and one CI passes and the runner does not is a
// gate nobody can reproduce locally.
//
// Every invocation in the workflows, cut at the shell metacharacters that end a command.
//
// A script only counts as a gate here if the workflow RUNS it as a command. scripts/buildinfo.sh
// appears inside `$( … )` in the release builds, where it emits linker flags and asserts nothing;
// treating it as a gate would demand the runner "check" a string substitution. That is decided by
// where the call sits, not by a list of names to ignore.
const ciCalls = new Map();
for (const m of workflowText.matchAll(/\b(node|sh) +(scripts\/[\w.-]+\.(?:mjs|sh))([^\n|&;)]*)/g)) {
  const lineStart = workflowText.lastIndexOf('\n', m.index) + 1;
  const before = workflowText.slice(lineStart, m.index);
  if (before.includes('$(') || before.includes('`')) continue;
  const invocation = `${m[1]} ${m[2]}${m[3].replace(/\s+/g, ' ').replace(/\s+$/, '')}`;
  if (!ciCalls.has(m[2])) ciCalls.set(m[2], new Set());
  ciCalls.get(m[2]).add(invocation);
}

// The other direction, which this check did not ask and which hid a real gap: a gate CI runs and the
// runner does not means `node scripts/verify.mjs` on a developer's machine is weaker than the badge.
// check-package-manifests.sh was in exactly that state — CI asserted 27 packaging guarantees that no
// local run ever touched. verify.mjs itself is excluded because it IS the runner; a list that
// contained itself would be a tautology, not a comparison.
const runnerScripts = new Set(nodeGates.map((g) => `scripts/${g.script}`));
const ciOnly = [...ciCalls.keys()]
  .filter((s) => s !== 'scripts/verify.mjs' && !runnerScripts.has(s));

// Some gates only EXIST when verify.mjs is given a url: the UI tier needs --ui, the apply tier needs
// --apply. Listing without those flags therefore describes a smaller suite than the runner can run,
// and everything above compares against that smaller list — which is how the apply-path fault
// harness came to run in no workflow while this check reported agreement. It covers the one action
// with real consequences, and nothing was passing --apply.
//
// So ask the runner what it can produce, and require CI to reach each tier.
const TIER_FLAG = { ui: '--ui', apply: '--apply' };
let full;
try {
  full = execFileSync('node',
    ['scripts/verify.mjs', '--list', '--ui', 'http://127.0.0.1:1/', '--apply', 'http://127.0.0.1:2/'],
    { encoding: 'utf8', cwd: ROOT });
} catch (e) {
  console.error(`FAIL  could not list the conditional gates (${e.message})`);
  process.exit(2);
}
const tiers = new Set(full.split('\n').map((l) => l.split('\t')[0]).filter(Boolean));
const tierGaps = [];
for (const [tier, flagName] of Object.entries(TIER_FLAG)) {
  if (!tiers.has(tier)) continue;                       // the runner defines no gate of this tier
  const count = full.split('\n').filter((l) => l.startsWith(`${tier}\t`)).length;
  if (!workflowText.includes(flagName)) tierGaps.push({ tier, flagName, count });
}
if (!tiers.has('static')) {
  console.error('FAIL  listing with the tier flags produced no static gate — the list did not load, '
    + 'and every tier conclusion below would be drawn from nothing');
  process.exit(2);
}

const argDrift = [];
for (const g of covered) {
  const wanted = g.cmd.replace(/\s+/g, ' ').trim();
  const seen = ciCalls.get(`scripts/${g.script}`);
  if (!seen || seen.has(wanted)) continue;
  argDrift.push({ name: g.name, wanted, found: [...seen] });
}

// An exemption for a gate CI now runs is a rule that has outlived its reason, and leaving it there
// means the next real gap gets waved through by a stale entry.
const stale = Object.keys(exempt).filter((s) => workflowText.includes(s));
const unknown = Object.keys(exempt).filter((s) => !nodeGates.some((g) => g.script === s));

// The six gates that are not a script — gofmt, vet, the two test runs and the two router-target
// compiles — were compared against nothing at all. "Script gates are the comparable set" was true
// of how this check was written and not of what its name promises: delete the `go test -race` step
// from a workflow and it stayed green, having compared nineteen gates and reported so.
//
// They are decidable too, just not by filename. The requirement is DERIVED from each gate's own
// definition — the tool, its subcommand, the flag that makes it that gate rather than another one,
// and the target architecture it sets — so there is no second spelling here to drift from the
// first. A gate whose CI counterpart cannot be found is a failure, not an entry in an exempt list:
// the exemption is what turned the last hole into a silent one.
const builtins = statics.filter((g) => !/^(node|sh) /.test(g.cmd));
const builtinNeeds = builtins.map((g) => {
  const parts = g.cmd.split(/\s+/);
  const tool = parts[0];
  const sub = tool === 'go' ? parts[1] : '';
  const race = / -race\b/.test(g.cmd);
  const arch = (g.env.match(/GOARCH=(\S+)/) || [])[1] || '';
  // What a workflow has to contain for this gate to be running in CI as well as here.
  const want = [tool === 'go' ? `go ${sub}` : tool];
  if (race) want.push('-race');
  return { name: g.name, want, arch };
});
const builtinGaps = [];
for (const b of builtinNeeds) {
  // Every term on the same line: `go test` elsewhere in a workflow does not make `go test -race`
  // run, which is exactly the substitution that would let the strongest of the six vanish.
  const line = workflowText.split(/\r?\n/).some((l) => b.want.every((w) => l.includes(w)));
  if (!line) { builtinGaps.push({ ...b, why: `no workflow line runs \`${b.want.join(' … ')}\`` }); continue; }
  // A router gate names an architecture this host is not. CI has to cross-compile for it
  // somewhere, or the only thing standing between the product and a target-only break is the
  // developer box.
  //
  // The architecture has to appear where an architecture is SET — a matrix `goarch:` entry or a
  // `GOARCH=` / `GOARCH:` assignment — not merely somewhere in the file. Searching the whole text
  // matched the loops that copy artefacts by name (`for n in mipsle mips arm64`), which name every
  // target while building none, so the requirement was satisfied by files that could have stopped
  // compiling for it entirely. What this asserts is that CI builds that target somewhere, not that
  // it does so on the same trigger the runner does.
  const setsArch = workflowText.split(/\r?\n/).some((l) => new RegExp(
    `go_?arch\\s*[:=]\\s*["']?${b.arch}\\b`, 'i').test(l));
  if (b.arch && !setsArch) {
    builtinGaps.push({ ...b, why: `no workflow sets GOARCH to ${b.arch}` });
  }
}

console.log(`script gates in verify.mjs: ${nodeGates.length} — ${covered.length} run in CI, ` +
  `${Object.keys(exempt).length} exempt`);
for (const [s, why] of Object.entries(exempt)) console.log(`  exempt: ${s} — ${why}`);

let fails = 0;
for (const d of argDrift) {
  console.error(`FAIL  gate "${d.name}" runs as \`${d.wanted}\` locally, and CI runs ` +
    `${d.found.map((f) => `\`${f}\``).join(' and ')} — same file, different check`);
  fails++;
}
for (const s of ciOnly) {
  console.error(`FAIL  ${s} runs in a workflow and is in no gate in verify.mjs — ` +
    'the runner requires less than CI does');
  fails++;
}
for (const g of tierGaps) {
  console.error(`FAIL  verify.mjs defines ${g.count} gate(s) that exist only with ${g.flagName}, and ` +
    `no workflow passes it — the "${g.tier}" tier runs nowhere in CI`);
  fails++;
}
for (const g of missing) {
  console.error(`FAIL  gate "${g.name}" runs locally (${g.cmd}) and in no workflow — ` +
    'CI requires less than the runner does');
  fails++;
}
for (const s of stale) {
  console.error(`FAIL  ${s} is listed as exempt but a workflow runs it — drop the exemption`);
  fails++;
}
for (const s of unknown) {
  console.error(`FAIL  ${s} is exempt but verify.mjs no longer lists it — drop the exemption`);
  fails++;
}
for (const b of builtinGaps) {
  console.error(`FAIL  gate "${b.name}" runs locally and ${b.why} — `
    + 'CI requires less than the runner does');
  fails++;
}
if (fails > 0) {
  console.error(`${fails} parity problem(s) between scripts/verify.mjs and .github/workflows/`);
  process.exit(1);
}
console.log(`gate parity: ${covered.length + builtinNeeds.length} gates compared against CI — `
  + `${covered.length} script gates by name and by the arguments they are run with, `
  + `${builtinNeeds.length} builtin gates by the tool, flag and target architecture derived from `
  + `their own definitions, plus every tier the runner can produce `
  + `(${[...tiers].sort().join(', ')}), against every workflow`);
