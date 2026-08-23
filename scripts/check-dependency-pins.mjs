// check-dependency-pins.mjs — release code must not execute a moving action or container image.
//
// Human-friendly tags stay in comments for Renovate-style review, but every executable GitHub
// action is selected by a full commit SHA and every production/package-test container default is
// selected by a sha256 digest. A tag can be moved after review; these identifiers cannot.
import fs from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const WORKFLOWS = path.join(ROOT, '.github', 'workflows');
const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
  const full = path.join(dir, entry.name);
  return entry.isDirectory() ? walk(full) : [full];
});
let failures = 0;
const fail = (message) => {
  failures++;
  console.error(`FAIL  ${message}`);
};

const definitionQueue = walk(path.join(ROOT, '.github')).filter((file) => /\.ya?ml$/.test(file)).sort();
const definitionFiles = [];
const seenDefinitions = new Set();
if (definitionQueue.length === 0) {
  fail('no workflow files found; the action-pin check would prove nothing');
}

let externalActions = 0;
let pinnedGoTools = 0;
for (let cursor = 0; cursor < definitionQueue.length; cursor++) {
  const full = path.resolve(definitionQueue[cursor]);
  if (seenDefinitions.has(full)) continue;
  seenDefinitions.add(full);
  definitionFiles.push(full);
  const rel = path.relative(ROOT, full).replaceAll('\\', '/');
  const lines = fs.readFileSync(full, 'utf8').split('\n');
  lines.forEach((line, index) => {
    const goInstall = line.match(/\bgo\s+install\s+([^\s@]+)@([^\s;]+)/);
    if (goInstall) {
      if (goInstall[2] === 'latest') {
        fail(`${rel}:${index + 1} Go release tool uses mutable @latest: ${goInstall[1]}`);
      } else if (/^v\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(goInstall[2])) {
        pinnedGoTools++;
      } else {
        fail(`${rel}:${index + 1} Go release tool has an unreviewable version: ${goInstall[0]}`);
      }
    }
    const match = line.match(/^\s*(?:-\s*)?uses:\s*([^\s#]+)/);
    if (!match) return;
    const ref = match[1];
    if (ref.startsWith('./')) {
      const target = path.resolve(ROOT, ref);
      const candidates = fs.existsSync(target) && fs.statSync(target).isDirectory()
        ? [path.join(target, 'action.yml'), path.join(target, 'action.yaml')]
        : [target];
      const localDefinition = candidates.find((candidate) => fs.existsSync(candidate));
      if (!localDefinition || !/\.ya?ml$/.test(localDefinition)) {
        fail(`${rel}:${index + 1} local action/workflow definition does not exist: ${ref}`);
      } else {
        definitionQueue.push(localDefinition);
      }
      return;
    }
    externalActions++;
    if (!/^[^@\s]+@[0-9a-f]{40}$/.test(ref)) {
      fail(`${rel}:${index + 1} external action is not pinned to a full commit SHA: ${ref}`);
    }
  });
}
if (externalActions < 20) {
  fail(`only ${externalActions} external action reference(s) were found; expected at least 20`);
}
if (pinnedGoTools < 1) {
  fail('no semver-pinned Go release tool was found; the tool-pin check would prove nothing');
}

// Container refs are discovered from every workflow plus every shell script, not from an allow-list
// of today's registries. Otherwise adding `ubuntu:latest`, a GHCR builder, or a seventh script would
// bypass the gate while the old count floor stayed green. We inspect three machine-readable shapes:
// *_IMAGE(S) defaults, workflow `image:` keys, and logical `docker run/pull` commands. Docker commands
// must use an *_IMAGE variable, which makes their reviewed, digest-pinned default visible here.
const shellFiles = walk(path.join(ROOT, 'scripts')).filter((file) => file.endsWith('.sh'));
const imageFiles = [
  ...definitionFiles,
  ...shellFiles,
];
const candidateRef = /(?<![A-Za-z0-9_.\/])([a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)*(?:(?::[A-Za-z0-9._-]+)?@sha256:[0-9A-Fa-f]+|:[A-Za-z0-9._-]+))/g;
const pinnedRef = /^[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)*(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$/;
const workflowImagePattern = /^\s*(?:image|container):\s*([^\s#]+)\s*(?:#.*)?$/;
const extractRefs = (text) => [...text.matchAll(candidateRef)].map((match) => match[1]);
const declaredImageVar = (name, declarations) => declarations.has(name)
  || (name.endsWith('_IMAGE') && declarations.has(`${name}S`));

// Negative self-checks keep the discovery logic from silently narrowing back to known registries.
for (const mutable of ['ubuntu:latest', 'evil.example/builder:latest', 'ghcr.io/acme/build:v1']) {
  const refs = extractRefs(mutable);
  if (refs.length !== 1 || pinnedRef.test(refs[0])) {
    fail(`internal image parser did not identify mutable fixture: ${mutable}`);
  }
}
const pinnedFixture = `ghcr.io/acme/build:v1@sha256:${'a'.repeat(64)}`;
if (extractRefs(pinnedFixture)[0] !== pinnedFixture || !pinnedRef.test(pinnedFixture)) {
  fail('internal image parser did not accept a digest-pinned registry fixture');
}
if (declaredImageVar('EVIL_IMAGE', new Set(['GOOD_IMAGE']))) {
  fail('internal image-variable resolver accepted an undeclared image variable');
}
if (!declaredImageVar('OPENWRT_IMAGE', new Set(['OPENWRT_IMAGES']))) {
  fail('internal image-variable resolver rejected a singular loop variable backed by a pinned list');
}
if (workflowImagePattern.exec('  container: ubuntu:latest')?.[1] !== 'ubuntu:latest') {
  fail('internal workflow parser did not identify mutable container shorthand');
}

let imageRefs = 0;
let dockerCommands = 0;
for (const full of imageFiles) {
  const rel = path.relative(ROOT, full).replaceAll('\\', '/');
  const lines = fs.readFileSync(full, 'utf8').split('\n');
  const declarations = new Set();
  lines.forEach((line, index) => {
    if (/^\s*#/.test(line)) return;
    const assignment = line.match(/^\s*(?:export\s+)?([A-Z][A-Z0-9_]*IMAGES?)\s*(?::|=)\s*(.*)$/);
    const workflowImage = line.match(workflowImagePattern);
    if (!assignment && !workflowImage) return;
    const value = assignment ? assignment[2] : workflowImage[1];
    const refs = extractRefs(value);
    if (refs.length === 0) {
      fail(`${rel}:${index + 1} image declaration has no literal digest-pinned default`);
      return;
    }
    for (const ref of refs) {
      imageRefs++;
      if (!pinnedRef.test(ref)) {
        fail(`${rel}:${index + 1} container image is mutable or has an invalid digest: ${ref}`);
      }
    }
    if (assignment && refs.every((ref) => pinnedRef.test(ref))) declarations.add(assignment[1]);
  });

  // Join POSIX backslash continuations so a literal image on the line after `docker run` cannot hide
  // from the same-command policy. Workflow prose and CSS are outside these logical commands.
  let logical = '';
  let start = 0;
  const flush = () => {
    if (!/\bdocker\s+(?:run|pull)\b/.test(logical)) { logical = ''; return; }
    dockerCommands++;
    const variables = [...logical.matchAll(/\$(?:\{)?([A-Z][A-Z0-9_]*IMAGES?)(?:\})?/g)]
      .map((match) => match[1]);
    if (variables.length === 0) {
      fail(`${rel}:${start + 1} docker command does not select its image through an *_IMAGE variable`);
    }
    for (const name of variables) {
      if (!declaredImageVar(name, declarations)) {
        fail(`${rel}:${start + 1} docker command uses image variable without a pinned declaration: $${name}`);
      }
    }
    for (const ref of extractRefs(logical)) {
      if (!pinnedRef.test(ref)) {
        fail(`${rel}:${start + 1} docker command contains a mutable literal image: ${ref}`);
      }
    }
    logical = '';
  };
  lines.forEach((line, index) => {
    if (!logical) start = index;
    if (/^\s*#/.test(line)) return;
    logical += ` ${line.trim().replace(/\\\s*$/, '')}`;
    if (!/\\\s*$/.test(line)) flush();
  });
  if (logical) flush();
}
if (imageRefs < 10) {
  fail(`only ${imageRefs} production/test image reference(s) were found; expected at least 10`);
}
if (dockerCommands < 10) {
  fail(`only ${dockerCommands} docker run/pull command(s) were found; expected at least 10`);
}

if (failures) {
  console.error(`\n${failures} dependency pin problem(s).`);
  process.exit(1);
}
console.log(`dependency pins: ${externalActions} external actions and ${imageRefs} production/test image references verified (${dockerCommands} docker commands bound to pinned image variables; ${pinnedGoTools} Go release tool pinned)`);
