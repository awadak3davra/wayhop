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
// The a11y assertions are about the SHIPPED front-end, not about one file of it. Once a page moves
// to a route-scoped chunk its code is still shipped, so concatenate app.js with every page-*.js —
// otherwise these checks quietly start passing (or failing) for the wrong reason as pages move.
const app = ['app.js', ...fs.readdirSync(path.join(root, 'web', 'dist'))
  .filter((f) => /^page-.*\.js$/.test(f))].map(read).join('\n');
const nav = read('nav.js');
const diagnostics = read('page-diagnostics.js');

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

// --- authentication gate: aria-modal must be true in behaviour, not name only ---
const authGate = app.slice(app.indexOf('function showAuthGate'), app.indexOf('async function ensureAuthenticated'));
must(/setAttribute\("inert", ""\)/.test(authGate),
  'app.js: the authentication gate must make the background inert');
must(/setAttribute\("aria-hidden", "true"\)/.test(authGate),
  'app.js: the authentication gate must hide the background from assistive technology');
must(/document\.addEventListener\("keydown", onAuthKey\)/.test(authGate) && /event\.key !== "Tab"/.test(authGate),
  'app.js: the authentication gate must trap Tab focus inside its aria-modal dialog');
must(/document\.removeEventListener\("keydown", onAuthKey\)/.test(authGate),
  'app.js: the authentication gate must detach its focus trap after login');

// --- import errors: secrets never echoed verbatim ---
must(/redactSecrets/.test(app), 'app.js: friendlyImportError must run technical details through redactSecrets');

// --- decorative glyphs hidden from AT ---
must(/"aria-hidden": "true"/.test(app) || /aria-hidden="true"/.test(app), 'app.js: decorative glyphs must be aria-hidden');

// --- repeated Routing actions: the item name is part of the accessible name ---
must(/"aria-label": t\("Add"\) \+ " " \+ p\.name/.test(app),
  'page-routing.js: each preset Add button must include the visible preset name in its accessible name');
must(/const deviceLabel = d\.hostname \|\| d\.ip \|\| d\.mac/.test(app)
  && /"aria-label": t\("Add"\) \+ " " \+ deviceLabel/.test(app),
  'app.js: each device-picker + button must include that device visible label in its accessible name');


// A control minted inside a loop must name what it acts on. Both Copy buttons on Diagnostics are
// minted that way — one per battery row, one per protocol the router does not build in — and both
// shipped with "Copy" as their entire accessible name. Measured on a live Keenetic: six
// buttons called "Copy", nothing to say which check or which command each one takes. The object was
// already in hand at both sites (hcLabel for the row, proto for the command).
must(diagnostics.includes('"aria-label": t("Copy") + " " + t(hcLabel(id, r))'),
  'page-diagnostics.js: the battery row Copy button must name its check');
must(diagnostics.includes('"aria-label": t("Copy command") + " " + proto'),
  'page-diagnostics.js: the copy-command button must name its protocol');

if (errs.length) {
  console.error('a11y contract FAILED:\n  - ' + errs.join('\n  - '));
  process.exit(1);
}
console.log('a11y OK: burger button+aria-expanded, apply-banner live region + cold-load, toasts/failsafe roles, aria-current, label wiring, nav-guard registry + beforeunload, auth-gate focus/inert isolation, secret redaction, contextual Routing action names, and Diagnostics Copy buttons naming their object.');
