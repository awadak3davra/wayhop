#!/usr/bin/env node

// A release/feed build is allowed to package only the exact commit named by the
// event's immutable tag. Keep the decision here rather than duplicating subtly
// different shell checks in build.yml and feed.yml.

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const RELEASE_TAG = /^v((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))(?:-r([1-9]\d*))?$/;
const COMMIT = /^[0-9a-f]{40}$/i;

function refuse(message) {
  throw new Error(message);
}

export function parseReleaseTag(tag) {
  const match = RELEASE_TAG.exec(String(tag || ''));
  if (!match) {
    refuse(`release tag ${JSON.stringify(String(tag || ''))} must be vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-rN`);
  }
  const release = match[2] ? Number(match[2]) : 1;
  if (match[2] && release < 2) refuse('-r1 is an alias of the base tag and is not allowed');
  if (!Number.isSafeInteger(release) || release > 9999) refuse('package release must be an integer from 1 to 9999');
  const baseVersion = match[1];
  return {
    baseVersion,
    packageRelease: release,
    artifactVersion: release === 1 ? baseVersion : `${baseVersion}-r${release}`,
  };
}

export function validateReleaseSource(facts) {
  const tag = String(facts.tag || '');
  const expected = String(facts.expectedCommit || '').toLowerCase();
  const head = String(facts.headCommit || '').toLowerCase();
  const tagged = String(facts.tagCommit || '').toLowerCase();
  const version = String(facts.version || '');
  const parsed = parseReleaseTag(tag);

  if (facts.refType !== 'tag') {
    refuse(`release workflow must run from a tag, not ${JSON.stringify(facts.refType || 'unknown')}`);
  }
  if (facts.refName !== tag) {
    refuse(`requested tag ${tag} does not match event ref ${JSON.stringify(facts.refName || '')}`);
  }
  if (!COMMIT.test(expected)) refuse('event commit is not a full 40-character Git SHA');
  if (!COMMIT.test(head)) refuse('checked-out HEAD is not a full 40-character Git SHA');
  if (!COMMIT.test(tagged)) refuse(`${tag} does not resolve to a full commit SHA`);
  if (head !== expected) refuse(`checked-out HEAD ${head} does not match event commit ${expected}`);
  if (tagged !== expected) refuse(`${tag} resolves to ${tagged}, not event commit ${expected}`);
  if (version !== parsed.baseVersion) {
    refuse(`${tag} has base version ${parsed.baseVersion}, but internal/version/version.go is ${JSON.stringify(version)}`);
  }

  return { tag, ...parsed, commit: expected };
}

function git(...args) {
  return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function currentVersion() {
  const source = fs.readFileSync(path.join(ROOT, 'internal', 'version', 'version.go'), 'utf8');
  const match = source.match(/\bVersion\s*=\s*"([^"]+)"/);
  if (!match) refuse('internal/version/version.go has no Version constant');
  return match[1];
}

function runSelfTest() {
  const sha = 'a'.repeat(40);
  const base = {
    tag: 'v0.5.5-r2', refType: 'tag', refName: 'v0.5.5-r2', expectedCommit: sha,
    headCommit: sha, tagCommit: sha, version: '0.5.5',
  };
  const cases = [
    ['valid revised release source', base, true],
    ['valid first release source', { ...base, tag: 'v0.6.0', refName: 'v0.6.0', version: '0.6.0' }, true],
    ['revision-one alias', { ...base, tag: 'v0.5.5-r1', refName: 'v0.5.5-r1' }, false],
    ['oversized revision', { ...base, tag: 'v0.5.5-r10000', refName: 'v0.5.5-r10000' }, false],
    ['arbitrary prerelease', { ...base, tag: 'v0.5.5-rc1', refName: 'v0.5.5-rc1' }, false],
    ['shell-shaped tag', { ...base, tag: 'v0.5.5;echo-pwned', refName: 'v0.5.5;echo-pwned' }, false],
    ['branch dispatch', { ...base, refType: 'branch' }, false],
    ['different event ref', { ...base, refName: 'v0.5.4' }, false],
    ['abbreviated event SHA', { ...base, expectedCommit: 'a'.repeat(12) }, false],
    ['different checkout', { ...base, headCommit: 'b'.repeat(40) }, false],
    ['moved tag', { ...base, tagCommit: 'b'.repeat(40) }, false],
    ['version drift', { ...base, version: '0.5.4' }, false],
  ];

  let passed = 0;
  for (const [name, facts, shouldPass] of cases) {
    let ok = true;
    try { validateReleaseSource(facts); } catch { ok = false; }
    if (ok !== shouldPass) refuse(`self-test ${JSON.stringify(name)} ${ok ? 'accepted' : 'refused'} unexpectedly`);
    passed++;
  }
  const revised = validateReleaseSource(base);
  if (revised.baseVersion !== '0.5.5' || revised.packageRelease !== 2 || revised.artifactVersion !== '0.5.5-r2') {
    refuse('self-test did not split the revised tag into base version, package release and artifact version');
  }
  console.log(`release source: ${passed} refusal/acceptance checks passed`);
}

function main() {
  if (process.argv.includes('--self-test')) {
    runSelfTest();
    return;
  }

  const tag = process.env.WAYHOP_RELEASE_TAG || '';
  parseReleaseTag(tag); // validate before the tag is ever passed to git

  const dirty = git('status', '--porcelain', '--untracked-files=no');
  if (dirty) refuse('release checkout contains tracked modifications');

  let tagCommit;
  try {
    tagCommit = git('rev-parse', `refs/tags/${tag}^{commit}`);
  } catch {
    refuse(`${tag} is not present in the checked-out repository`);
  }

  const result = validateReleaseSource({
    tag,
    refType: process.env.WAYHOP_GITHUB_REF_TYPE,
    refName: process.env.WAYHOP_GITHUB_REF_NAME,
    expectedCommit: process.env.WAYHOP_EXPECTED_SHA,
    headCommit: git('rev-parse', 'HEAD^{commit}'),
    tagCommit,
    version: currentVersion(),
  });

  const output = process.env.GITHUB_OUTPUT;
  if (output) {
    fs.appendFileSync(output, `tag=${result.tag}\nbase_version=${result.baseVersion}\n`
      + `package_release=${result.packageRelease}\nartifact_version=${result.artifactVersion}\ncommit=${result.commit}\n`);
  }
  console.log(`release source verified: ${result.tag} -> ${result.commit}`);
}

if (path.resolve(process.argv[1] || '') === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) {
    console.error(`release source REFUSED: ${error.message}`);
    process.exitCode = 1;
  }
}
