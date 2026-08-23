// ui-page-structure.mjs — the grouping added to Settings and Diagnostics, and the correctness
// question the Settings navigator raises.
//
// Only the active section is attached to the DOM. If Save read values out of the DOM, every field in
// a section the user never opened would submit as blank and silently wipe that setting. Save is
// supposed to read the element objects renderSettings holds in closures, which survive detachment.
// That is a claim about behaviour, so it gets measured against the real daemon, not assumed.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { authenticateCDP } from './ui-auth.mjs';

// closeChrome ends the browser and removes its throwaway profile.
//
// kill() only delivers the signal; the process is still alive and still holding the profile open
// when it returns, so removing right after it failed every time on Windows and left the directory
// behind. Six hundred of them, and 9.3 GB, was enough to fill the system drive and make an unrelated
// gate fail at the linker with "not enough space on the disk".
//
// Bounded wait, then a best-effort removal: a wedged browser must not hang a gate, and failing to
// tidy up must not fail one either.
async function closeChrome(child, dir) {
  if (child && child.exitCode === null && !child.killed) child.kill();
  if (child) {
    await Promise.race([
      new Promise((r) => child.once('exit', r)),
      new Promise((r) => setTimeout(r, 3000)),
    ]);
  }
  if (!dir) return;
  for (let i = 0; i < 12; i++) {
    try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 4, retryDelay: 150 }); return; }
    catch (_) { await new Promise((r) => setTimeout(r, 250)); }
  }
  // Falling out of that loop used to be silent, so a profile dir that could not be removed — and the
  // browser that may still be holding it — went unnoticed until somebody counted /tmp. Enough of them
  // starve a later gate run.
  console.error(`note: could not remove the Chrome profile dir ${dir}`);
}

const URL_ARG = process.argv[2] || 'http://127.0.0.1:8097/';
const PORT = Number(process.env.CDP_PORT || 9516);
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const httpJSON = async (u) => (await fetch(u)).json();

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wayhop-sec-'));
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
  `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`, '--window-size=1280,900', 'about:blank'],
  { stdio: 'ignore' });

let fails = 0;
const check = (name, ok, detail) => {
  if (!ok) fails++;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '   [' + detail + ']' : ''}`);
};

try {
  for (let i = 0; i < 60; i++) {
    try { await httpJSON(`http://127.0.0.1:${PORT}/json/version`); break; } catch { await sleep(250); }
  }
  const targets = await httpJSON(`http://127.0.0.1:${PORT}/json/list`);
  const ws = new WebSocket((targets.find((t) => t.type === 'page') || targets[0]).webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  let id = 0; const waiting = new Map();
  ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); } };
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const myId = ++id;
    const _to = setTimeout(() => { waiting.delete(myId); reject(new Error(`CDP ${method} got no reply in 30000ms`)); }, 30000);
    waiting.set(myId, (_m) => { clearTimeout(_to); ((m) => (m.error ? reject(new Error(m.error.message)) : resolve(m.result)))(_m); });
    ws.send(JSON.stringify({ id: myId, method, params }));
  });
  const ev = async (x) => {
    const r = await send('Runtime.evaluate', { expression: x, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || 'eval failed');
    return r.result.value;
  };

  await send('Page.enable'); await send('Runtime.enable');
  await send('Page.navigate', { url: URL_ARG });
  for (let i = 0; i < 160; i++) {
    if (await ev('typeof route === "function"').catch(() => false)) break;
    await sleep(250);
  }
  await authenticateCDP({ send, evaluate: ev, url: URL_ARG });
  await ev(`location.hash = '#settings'`);
  await sleep(2200);

  // The Settings page is one searchable index, not a tablist. These assert the properties that
  // replaced the tabs — and one the tabs never had: that hiding each field's own label in favour of
  // the row's name did not leave the control without an accessible name.
  const idx = await ev(`(() => {
    const rows = [...document.querySelectorAll('.sx-row')];
    const host = document.querySelector('.route-view') || document.querySelector('#view');
    return {
      rows: rows.length,
      // Every card the page builds must have been consumed into the index. One left behind means a
      // setting that exists twice, or one the search can never find.
      leftoverCards: document.querySelectorAll('.card[data-section]').length,
      strayCards: [...host.children].filter(n => n.classList.contains('card')).length,
      search: !!document.querySelector('.sx-search'),
      facets: document.querySelectorAll('.sx-facet').length,
      unnamed: rows.filter(r => {
        const c = r.querySelector('input, select, textarea');
        if (!c) return false;
        // A control that is not rendered is not in the accessibility tree at all, so it cannot be
        // an unnamed control to anyone. The hidden file input behind "Restore from file…" is the
        // case: it is opened by a button that IS named, and naming it too would announce a control
        // no one can reach.
        if (!c.offsetParent && getComputedStyle(c).position !== 'fixed') return false;
        if (c.getAttribute('aria-label') || c.getAttribute('aria-labelledby')) return false;
        const lab = (c.id && document.querySelector('label[for="' + CSS.escape(c.id) + '"]')) || c.closest('label');
        if (!lab) return true;
        return getComputedStyle(lab).display === 'none';
      }).map(r => (r.querySelector('.sx-name') || {}).textContent),
    };
  })()`);
  check('every setting is a row in one index', idx.rows >= 15, `rows=${idx.rows}`);
  check('no settings card was left outside the index',
    idx.leftoverCards === 0 && idx.strayCards === 0,
    `leftover=${idx.leftoverCards} stray=${idx.strayCards}`);
  check('the index offers a search field and facet filters', idx.search && idx.facets >= 4,
    `search=${idx.search} facets=${idx.facets}`);
  // Hiding the per-field label to avoid printing the name twice is only safe if the control is
  // named some other way; otherwise the row is readable and the control is anonymous.
  check('every control in the index has an accessible name', idx.unnamed.length === 0,
    idx.unnamed.length ? idx.unnamed.join(', ') : 'all named');

  // The search and the facets have to actually narrow the list. A filter that renders but filters
  // nothing is the same class of defect as a check that passes without measuring anything.
  const filt = await ev(`(async () => {
    const visible = () => [...document.querySelectorAll('.sx-row')].filter(r => r.style.display !== 'none').length;
    const all = visible();
    const s = document.querySelector('.sx-search');
    s.value = 'zzzzz-nothing-matches';
    s.dispatchEvent(new Event('input', { bubbles: true }));
    await new Promise(r => setTimeout(r, 120));
    const none = visible();
    s.value = '';
    s.dispatchEvent(new Event('input', { bubbles: true }));
    await new Promise(r => setTimeout(r, 120));
    const restored = visible();
    const narrowed = [];
    for (const b of [...document.querySelectorAll('.sx-facet')]) {
      b.click();
      await new Promise(r => setTimeout(r, 120));
      narrowed.push({ label: b.textContent, shown: visible(), pressed: b.getAttribute('aria-pressed') });
      b.click();
      await new Promise(r => setTimeout(r, 120));
    }
    return { all, none, restored, narrowed };
  })()`);
  check('search narrows the index and clearing restores it',
    filt.all > 0 && filt.none === 0 && filt.restored === filt.all,
    `all=${filt.all} noMatch=${filt.none} restored=${filt.restored}`);
  check('every facet filters and reports its pressed state',
    filt.narrowed.length >= 4
      && filt.narrowed.every(f => f.pressed === 'true' && f.shown < filt.all && f.shown >= 0),
    filt.narrowed.map(f => `${f.label}:${f.shown}`).join(' '));

  // ---- the real hazard -------------------------------------------------------------------
  // Edit a field in one section, never open the others, save, and confirm the daemon still holds
  // the untouched sections' values rather than blanks.
  const before = await (await fetch(URL_ARG.replace(/\/$/, '') + '/api/config')).json();
  const saved = await ev(`(async () => {
    // Named explicitly. A heuristic "first text input with a dot in it" picked the panel's own
    // listen address, and saving that moved the daemon off the port under test.
    const row = [...document.querySelectorAll('.sx-row')]
      .find(r => /connectivity-check target/i.test((r.querySelector('.sx-name') || {}).textContent || ''));
    if (!row) return { edited: false };
    const target = row.querySelector('input');
    if (!target) return { edited: false };
    target.value = '9.9.9.9';
    target.dispatchEvent(new Event('input', { bubbles: true }));
    // Filter the index so the edited row is no longer displayed when Save is pressed. The tabbed
    // page detached whole sections; the index hides rows. The hazard is identical either way: a
    // save that gathered only what was on screen would blank everything else.
    const s = document.querySelector('.sx-search');
    s.value = 'theme';
    s.dispatchEvent(new Event('input', { bubbles: true }));
    await new Promise(r => setTimeout(r, 250));
    const hiddenAtSave = row.style.display === 'none';
    const btn = [...document.querySelectorAll('#view button')].find(b => /save settings/i.test(b.textContent));
    if (!btn) return { edited: true, savedClicked: false, hiddenAtSave };
    btn.click();
    await new Promise(r => setTimeout(r, 2500));
    return { edited: true, savedClicked: true, hiddenAtSave };
  })()`);
  check('a field could be edited and saved while filtered out of view',
    saved.edited && saved.savedClicked && saved.hiddenAtSave,
    `edited=${saved.edited} saved=${saved.savedClicked} hiddenAtSave=${saved.hiddenAtSave}`);

  const after = await (await fetch(URL_ARG.replace(/\/$/, '') + '/api/config')).json();
  // Nothing that was never visited may have been blanked by the save.
  const blanked = [];
  const walk = (a, b, p) => {
    if (a && typeof a === 'object' && !Array.isArray(a)) {
      Object.keys(a).forEach(k => walk(a[k], b ? b[k] : undefined, p ? p + '.' + k : k));
      return;
    }
    const wasSet = a !== '' && a !== null && a !== undefined && a !== 0;
    const nowEmpty = b === '' || b === null || b === undefined;
    if (wasSet && nowEmpty) blanked.push(`${p}: ${JSON.stringify(a)} -> ${JSON.stringify(b)}`);
  };
  walk(before, after, '');
  check('saving from one section does not blank the others',
    blanked.length === 0, blanked.length ? blanked.slice(0, 6).join(' | ') : 'no field lost');

  // ---- Diagnostics: grouped, not hidden ---------------------------------------------------
  // Diagnostics is a toolbox, so its cards are separated by heading rather than by tab. The
  // requirement is that every card lands in a group and the acting ones come first.
  await ev(`location.hash = '#diagnostics'`);
  await sleep(2600);
  const diag = await ev(`(() => {
    const host = document.querySelector('.route-view') || document.querySelector('#view');
    const seq = [...host.children]
      .filter(n => n.classList.contains('page-group') || n.classList.contains('card'))
      .map(n => n.classList.contains('page-group')
        ? 'G:' + n.querySelector('.page-group-title').textContent.trim()
        : 'c:' + (n.getAttribute('data-group') || '-'));
    return { seq, groups: host.querySelectorAll('.page-group').length,
             ungrouped: [...host.children].filter(n => n.classList.contains('card') && !n.hasAttribute('data-group')).length };
  })()`);
  check('diagnostics is split into groups', diag.groups >= 2, `groups=${diag.groups}`);
  check('every diagnostics card belongs to a group', diag.ungrouped === 0, `ungrouped=${diag.ungrouped}`);
  // The tools group must come first: it is what the page is for.
  check('the acting tools come before the reporting cards',
    diag.seq[0] === 'G:Checks and tools' && diag.seq.indexOf('c:reports') > diag.seq.lastIndexOf('c:tools'),
    diag.seq.join(' '));

  ws.close();
} finally {
  await closeChrome(chrome, dir);
}

console.log(fails ? `\n${fails} check(s) failed` : '\nall section checks passed');
process.exit(fails ? 1 : 0);
