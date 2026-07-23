#!/usr/bin/env node
// check-a11y.mjs — static accessibility CONTRACT checks over web/dist. Not a DOM audit
// (no browser in CI): it locks the load-bearing ARIA wiring against regressions the same
// way check-i18n locks translations. Each check names the user-facing behaviour it protects.
// Exit 1 with a list of violations; silent-ish OK otherwise.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (f) => fs.readFileSync(path.join(root, 'web', 'dist', f), 'utf8');

const html = read('index.html');
const app = read('app.js');
const nav = read('nav.js');

const errs = [];
const must = (ok, what) => { if (!ok) errs.push(what); };

// --- mobile menu: a real, stateful button (WCAG 4.1.2 name/role/value) ---
const burger = html.match(/<button[^>]*class="nav-burger"[^>]*>/);
must(burger, 'index.html: the mobile burger must be a <button class="nav-burger"> (a label is not keyboard-operable)');
if (burger) {
  must(/aria-expanded=/.test(burger[0]), 'index.html: nav-burger must carry aria-expanded (menu state for AT)');
  must(/aria-controls=/.test(burger[0]), 'index.html: nav-burger must carry aria-controls');
  must(/aria-label=/.test(burger[0]), 'index.html: nav-burger must carry aria-label (it has no text content)');
}
must(/aria-expanded/.test(nav), 'nav.js: must sync aria-expanded when the drawer opens/closes');

// --- apply banner: persistent live region, never toast-only ---
must(/id="apply-banner"/.test(html), 'index.html: the persistent #apply-banner container must exist');
must(/renderApplyBanner/.test(app), 'app.js: renderApplyBanner (persistent apply state) must exist');
must(/setAttribute\("aria-live"/.test(app), 'app.js: the apply banner must set aria-live (status/alert announcements)');
must(/"role", role\)|setAttribute\("role"/.test(app), 'app.js: the apply banner must set a role (status/alert)');
// cold-load: the banner must be populated on boot, not only after a page calls loadProfile()
const initBody = app.slice(app.indexOf('async function init()'));
must(/refreshApplyState\(\)/.test(initBody), 'app.js: init() must call refreshApplyState() (banner correct on cold load of any page)');

// --- toasts + failsafe: announced to AT ---
must(/id="toasts"[^>]*role="status"/.test(html), 'index.html: #toasts must be role="status" aria-live');
must(/id="failsafe-banner"[^>]*role="alert"/.test(html), 'index.html: #failsafe-banner must be role="alert"');

// --- navigation: current page + keyboard nav ---
must(/aria-current/.test(app), 'app.js: route() must mark the active nav item with aria-current');
must(/associateLabels/.test(app), 'app.js: associateLabels (label→control wiring for forms) must exist and be used');

// --- nav guard: shared registry, browser close included ---
must(/registerDirtyCheck\(/.test(app), 'app.js: the shared nav-guard registry (registerDirtyCheck) must exist');
must(/beforeunload/.test(app), 'app.js: a beforeunload hook must protect unsaved form edits on close/reload');

// --- import errors: secrets never echoed verbatim ---
must(/redactSecrets/.test(app), 'app.js: friendlyImportError must run technical details through redactSecrets');

// --- decorative glyphs hidden from AT ---
must(/"aria-hidden": "true"/.test(app) || /aria-hidden="true"/.test(app), 'app.js: decorative glyphs must be aria-hidden');

if (errs.length) {
  console.error('a11y contract FAILED:\n  - ' + errs.join('\n  - '));
  process.exit(1);
}
console.log('a11y OK: burger button+aria-expanded, apply-banner live region + cold-load, toasts/failsafe roles, aria-current, label wiring, nav-guard registry + beforeunload, secret redaction.');
