// ui-sweep.mjs — visit EVERY page of a running WayHop and report what actually happens (§3).
//
// The interaction inventory says which controls exist; this says whether the pages carrying them
// render at all. For each route it navigates, waits for content, and records: JS exceptions, console
// errors, failed network requests, how many interactive controls rendered, and whether the view is
// empty. A page that throws, logs an error, or renders nothing is a defect — and previously nothing
// in CI or in a shell would have noticed.
//
// It also exercises the modal contract the a11y gate cannot check statically: Escape closes, and
// focus returns to the element that opened it.
//
// Usage: node scripts/ui-sweep.mjs <url>
// longToken builds the "looks like a credential" fixture this scenario needs, instead of storing a
// key-shaped literal that a history-wide secret scan flags forever. The redaction under test only
// cares that the value is long and random-looking.
const LONG_TOKEN = Buffer.alloc(32, 0x33).toString("base64").replace(/=+$/, "");

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

const URL_ARG = process.argv[2] || 'http://127.0.0.1:8088/';
const PORT = Number(process.env.CDP_PORT || 9333);
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const PAGES = (process.env.PAGES || 'dashboard,server,connections,failover,routing,dns,updater,diagnostics,settings').split(',');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const httpJSON = async (u) => (await fetch(u)).json();

async function startChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wayhop-sweep-'));
  const child = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
    '--disable-extensions', '--disable-background-networking',
    `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`, '--window-size=1280,900', 'about:blank'],
    { stdio: 'ignore' });
  child.profileDir = dir; // so the caller, which owns the kill, can also tidy up
  for (let i = 0; i < 60; i++) {
    try { await httpJSON(`http://127.0.0.1:${PORT}/json/version`); return child; } catch { await sleep(250); }
  }
  child.kill();
  throw new Error('chrome did not start');
}

async function connect(wsUrl) {
  const ws = new WebSocket(wsUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  let id = 0;
  const waiting = new Map();
  const events = [];
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); return; }
    if (m.method) events.push(m);
  };
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const myId = ++id;
    const _to = setTimeout(() => { waiting.delete(myId); reject(new Error(`CDP ${method} got no reply in 30000ms`)); }, 30000);
    waiting.set(myId, (_m) => { clearTimeout(_to); ((m) => (m.error ? reject(new Error(m.error.message)) : resolve(m.result)))(_m); });
    ws.send(JSON.stringify({ id: myId, method, params }));
  });
  return {
    send, events, close: () => ws.close(),
    async eval(expr) {
      const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
      if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || 'eval failed');
      return r.result.value;
    },
  };
}

const report = { url: URL_ARG, pages: [], modal: null, dashboardExits: null,
  connectionSelection: null, summary: {} };
const chrome = await startChrome();
try {
  const targets = await httpJSON(`http://127.0.0.1:${PORT}/json/list`);
  const c = await connect((targets.find((t) => t.type === 'page') || targets[0]).webSocketDebuggerUrl);
  await c.send('Page.enable');
  await c.send('Runtime.enable');
  await c.send('Log.enable');
  await c.send('Network.enable');

  await c.send('Page.navigate', { url: URL_ARG });
  // Wait for app.js to have EXECUTED, not merely for nav.js to have painted a nav item. Keying
  // readiness off the DOM raced the bundle: the first scenario would call an undefined
  // openReviewChanges, the ReferenceError would be swallowed, and the run reported a UI defect that
  // was purely a harness artifact. The symbol under test is the only honest readiness signal.
  let ready = false;
  for (let i = 0; i < 120; i++) {
    if (await c.eval('typeof openReviewChanges === "function"').catch(() => false)) { ready = true; break; }
    await sleep(250);
  }
  if (!ready) throw new Error('app.js did not finish loading: openReviewChanges never became defined');
  await authenticateCDP({
    send: (method, params) => c.send(method, params), evaluate: expression => c.eval(expression),
    url: URL_ARG, readyExpression: 'typeof openReviewChanges === "function"',
  });
  await sleep(1200);

  for (const page of PAGES) {
    const before = c.events.length;
    await c.eval(`location.hash = '#${page}'`);
    // Wait for the view to actually change rather than a fixed delay.
    for (let i = 0; i < 40; i++) {
      const n = await c.eval(`(document.querySelector('#view')||document.body).children.length`).catch(() => 0);
      if (n > 0) break;
      await sleep(150);
    }
    await sleep(1200); // let async data land

    const info = await c.eval(`(() => {
      const v = document.querySelector('#view') || document.body;
      return {
        controls: v.querySelectorAll('button, input, select, [role=button], .toggle, .switch').length,
        nodes: v.querySelectorAll('*').length,
        text: (v.textContent || '').trim().length,
        loading: /loading/i.test((v.textContent || '').slice(0, 400)),
        // Which nav entry the app marked active for this route. Stable across visits, unlike the
        // rendered text (which carries live RAM/CPU/uptime values and never compares equal).
        current: (() => {
          const a = document.querySelector('[aria-current]');
          return a ? (a.getAttribute('href') || a.textContent.trim()) : null;
        })(),
      };
    })()`);

    // Errors raised while this page was rendering.
    const fresh = c.events.slice(before);
    const jsErrors = fresh.filter((e) => e.method === 'Runtime.exceptionThrown')
      .map((e) => (e.params.exceptionDetails?.exception?.description || 'exception').split('\n')[0]);
    const consoleErrors = fresh.filter((e) => e.method === 'Log.entryAdded' && e.params.entry.level === 'error')
      .map((e) => `${e.params.entry.text}`.slice(0, 160));
    const failedReqs = fresh.filter((e) => e.method === 'Network.loadingFailed')
      .map((e) => e.params.errorText).filter((t) => t && !/ERR_ABORTED/.test(t));
    // A 4xx/5xx is not a "loadingFailed" event — capture it explicitly, otherwise a broken URL shows
    // up only as an opaque console line with no way to tell WHICH request broke.
    const badStatus = fresh.filter((e) => e.method === 'Network.responseReceived' && e.params.response.status >= 400)
      .map((e) => `${e.params.response.status} ${e.params.response.url.replace(/^https?:\/\/[^/]+/, '')}`);

    report.pages.push({
      page, controls: info.controls, nodes: info.nodes, textLen: info.text, current: info.current,
      stuckLoading: info.loading, jsErrors, consoleErrors, failedReqs, badStatus,
      ok: jsErrors.length === 0 && badStatus.length === 0 && info.nodes > 5 && !info.loading,
    });
  }

  // An UNKNOWN route still renders — the app falls back to a default view rather than erroring — so
  // "the page rendered something" is NOT evidence that the requested page rendered. Confirmed
  // against this build: '#__wayhop_sweep_unknown__' paints a full view (474 nodes) and leaves
  // aria-current unset, while every real route marks its nav entry. Without this check a route that
  // silently degraded to the fallback counted as a pass, and the sweep's "N/N ok" claimed more than
  // it had proven.
  await c.eval(`location.hash = '#__wayhop_sweep_unknown__'`);
  await sleep(1800);
  report.unknownRouteCurrent = await c.eval(`(() => {
    const a = document.querySelector('[aria-current]');
    return a ? (a.getAttribute('href') || a.textContent.trim()) : null;
  })()`);

  const byCurrent = new Map();
  for (const p of report.pages) {
    if (!p.current) {                 // the app did not recognise this route
      p.routeNotRecognised = true;
      p.ok = false;
      continue;
    }
    if (byCurrent.has(p.current)) {   // two routes resolving to one nav entry means one is aliasing
      p.aliasesRoute = byCurrent.get(p.current);
      p.ok = false;
    } else {
      byCurrent.set(p.current, p.page);
    }
  }

  // Dashboard exit addresses are primary information, not overflow content. Verify the real layout:
  // five equal compact cards fit the operator's measured 947px Keenetic dashboard content width,
  // every card remains visible inside one centred wrapping surface, and a constrained partial final
  // row stays centred.
  report.dashboardExits = await c.eval(`(async () => {
    location.hash = '#dashboard';
    await new Promise(r => setTimeout(r, 1800));
    const grid = document.getElementById('exit-grid');
    const tiles = grid ? [...grid.querySelectorAll('.exit-tile')] : [];
    if (!grid || tiles.length < 2) return { skipped: 'need at least two rendered exit-address cards' };
    const priorWidth = grid.style.width;
    const priorMaxWidth = grid.style.maxWidth;
    // The fixture may expose fewer than five exits. Clone presentation-only samples so this remains
    // a geometry test rather than silently skipping the exact five-card contract it claims to hold.
    const samples = [...tiles];
    const clones = [];
    while (samples.length < 5) {
      const clone = tiles[samples.length % tiles.length].cloneNode(true);
      clone.removeAttribute('id');
      grid.appendChild(clone);
      samples.push(clone);
      clones.push(clone);
    }
    grid.style.width = '947px';
    grid.style.maxWidth = 'none';
    await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
    const wideBounds = grid.getBoundingClientRect();
    const wideRects = samples.slice(0, 5).map(tile => tile.getBoundingClientRect());
    const wideTop = Math.round(wideRects[0].top);
    const fiveFitWide = wideRects.every(r => Math.round(r.top) === wideTop);
    const wideWidths = wideRects.map(r => r.width);
    const fiveEqualWide = Math.max(...wideWidths) - Math.min(...wideWidths) <= 1;
    const fiveCompactWide = Math.max(...wideWidths) <= 180;
    const wideNoOverflow = Math.min(...wideRects.map(r => r.left)) >= wideBounds.left - 1 &&
      Math.max(...wideRects.map(r => r.right)) <= wideBounds.right + 1;
    const wideGaps = wideRects.slice(1).map((r, i) => r.left - wideRects[i].right);
    const twelvePixelGaps = wideGaps.every(gap => Math.abs(gap - 12) <= 1);
    // A compact card still has to show the complete IPv4 address that motivated this dashboard
    // surface. Measure a presentation-only probe at the real computed card width.
    const ipProbe = samples[0].cloneNode(true);
    ipProbe.style.position = 'absolute';
    ipProbe.style.visibility = 'hidden';
    ipProbe.style.width = wideWidths[0] + 'px';
    const probeIP = ipProbe.querySelector('.exit-ip');
    if (probeIP) probeIP.textContent = '203.0.113.206';
    grid.appendChild(ipProbe);
    await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
    const compactIPv4Fits = !!probeIP && probeIP.scrollWidth <= probeIP.clientWidth + 1;
    // "Fits" is not enough, and clientWidth cannot see that: a flex item shrink-wraps its text, so
    // the address measured exactly as wide as the box it was given and the check passed with zero
    // pixels to spare. It then failed on a Linux runner, where the same 15px string is wider in
    // DejaVu Sans than in Segoe UI - not a regression, a coin toss the gate had been winning.
    // Measure the room the ROW actually offers and require real headroom, so the contract holds on
    // whatever machine an operator opens the panel from.
    const midRow = ipProbe.querySelector('.exit-mid');
    const flagEl = ipProbe.querySelector('.exit-flag');
    const midGap = midRow ? (parseFloat(getComputedStyle(midRow).gap) || 0) : 0;
    const rowGives = midRow
      ? midRow.getBoundingClientRect().width - (flagEl ? flagEl.getBoundingClientRect().width : 0) - midGap
      : 0;
    const compactIPv4Headroom = probeIP && probeIP.scrollWidth
      ? Math.round((rowGives - probeIP.scrollWidth) / probeIP.scrollWidth * 1000) / 1000
      : -1;
    // The runner's own font decides whether "fits" means anything: this passed for months on a
    // machine with Segoe UI and failed the first time it ran where sans-serif is DejaVu. So measure
    // the same string again in the widest sans-serif THIS machine has, and require that to fit too.
    // Windows resolves it to Verdana, a Linux runner to DejaVu Sans - each the realistic worst case
    // for an operator on that platform, which is what the assertion is actually about.
    let compactIPv4WideFontFits = null;
    if (probeIP) {
      const priorFamily = probeIP.style.fontFamily;
      probeIP.style.fontFamily = 'Verdana, "DejaVu Sans", "Liberation Sans", sans-serif';
      void probeIP.getBoundingClientRect();
      compactIPv4WideFontFits = probeIP.scrollWidth <= rowGives + 1;
      probeIP.style.fontFamily = priorFamily;
    }
    ipProbe.remove();

    grid.style.width = 'min(680px, 100%)';
    grid.style.maxWidth = 'none';
    await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
    const style = getComputedStyle(grid);
    const grouped = new Map();
    for (const tile of samples) {
      const r = tile.getBoundingClientRect();
      const top = Math.round(r.top);
      if (!grouped.has(top)) grouped.set(top, []);
      grouped.get(top).push(r);
    }
    const rows = [...grouped.entries()].sort((a, b) => a[0] - b[0]).map(([, rs]) => rs);
    const last = rows[rows.length - 1];
    const bounds = grid.getBoundingClientRect();
    const left = Math.min(...last.map(r => r.left));
    const right = Math.max(...last.map(r => r.right));
    const result = {
      tileCount: tiles.length,
      directChildren: tiles.every(tile => tile.parentElement === grid),
      allVisible: tiles.every(tile => !!tile.offsetParent),
      overflowControlAbsent: !grid.querySelector('details, summary'),
      display: style.display,
      wrap: style.flexWrap,
      justify: style.justifyContent,
      fiveFitWide,
      fiveEqualWide,
      fiveCompactWide,
      wideNoOverflow,
      twelvePixelGaps,
      compactIPv4Fits,
      compactIPv4Headroom,
      compactIPv4WideFontFits,
      wideCardWidths: wideWidths.map(width => Math.round(width * 100) / 100),
      wideGaps: wideGaps.map(gap => Math.round(gap * 100) / 100),
      rowCount: rows.length,
      lastRowCentered: Math.abs(((left + right) / 2) - ((bounds.left + bounds.right) / 2)) <= 2,
    };
    clones.forEach(clone => clone.remove());
    grid.style.width = priorWidth;
    grid.style.maxWidth = priorMaxWidth;
    return result;
  })()`);

  // Connections is a master-detail inspector. Choosing a row must update only the selected state
  // and detail panel; a full route rebuild is visibly disruptive on router hardware and discards
  // keyboard focus. Hold references to the live nodes and count API reads while selecting a row.
  report.connectionSelection = await c.eval(`(async () => {
    location.hash = '#connections';
    await new Promise(r => setTimeout(r, 1800));
    const view = document.querySelector('#view');
    const list = view && view.querySelector('.insp-list');
    const rows = list ? [...list.querySelectorAll('.insp-row')] : [];
    const panel = view && view.querySelector('.insp-panel');
    if (rows.length < 2 || !panel) return { skipped: 'need at least two connection rows and a detail panel' };
    const target = rows.find(row => !row.classList.contains('sel'));
    if (!target) return { skipped: 'no unselected connection row' };
    const realGet = api.get;
    let reads = 0;
    api.get = async function(...args) { reads++; return realGet.apply(api, args); };
    target.focus();
    target.click();
    await new Promise(r => setTimeout(r, 500));
    api.get = realGet;
    const liveList = view.querySelector('.insp-list');
    const liveRows = [...liveList.querySelectorAll('.insp-row')];
    const livePanel = view.querySelector('.insp-panel');
    return {
      apiReads: reads,
      listPreserved: liveList === list,
      rowsPreserved: liveRows.length === rows.length && liveRows.every((row, i) => row === rows[i]),
      panelReplaced: livePanel !== panel,
      targetSelected: target.classList.contains('sel') && target.getAttribute('aria-current') === 'true',
      selectedCount: liveRows.filter(row => row.classList.contains('sel')).length,
      focusPreserved: document.activeElement === target,
    };
  })()`);

  // Modal contract: Escape must close, and focus must return to the opener (§4.1 keyboard/focus).
  report.modal = await c.eval(`(async () => {
    if (typeof openReviewChanges !== 'function') return { skipped: 'no panel' };
    const opener = document.querySelector('.nav-item') || document.body;
    opener.focus && opener.focus();
    const before = document.activeElement;
    // The modal contract is a browser contract, so give only the panel's plan request a known-good
    // answer (the GET /api/apply/plan shape of docs/APPLY_REDESIGN.md in the development repository) instead of depending on the
    // demo's pending state. All other requests keep using the real API.
    const fixture = {
      rev: '${'a'.repeat(64)}', pending: true, nothing_configured: false, applied_rev: '', applied_at: '',
      verdict: 'ready', findings: [],
      changes: { baseline_available: true, baseline_rev: '${'b'.repeat(64)}', count: 1, may_interrupt: false, requires_apply: true,
        by_subsystem: { routing: [{ id: 'rl1', object_name: 'sweep-list', field: 'enabled', before: 'off', after: 'on',
          secret: false, impact: '', action: 'modified', may_interrupt: false, requires_service_restart: false, requires_reboot: false, warnings: [] }] },
        changes: [] },
      window: { open: false, phase: 'idle', seconds_left: 0 },
      probe: { at: 0, age_s: 0, stale: false, error: '' },
      platform: { name: 'demo', core_available: true, core_running: false, kernel_plane: false, native_vpn: false },
    };
    const realGet = api.get;
    api.get = async function(path, ...args) {
      if (String(path).startsWith('/api/apply/plan')) return fixture;
      return realGet.call(api, path, ...args);
    };
    try { await openReviewChanges(); }
    finally { api.get = realGet; }
    await new Promise(r => setTimeout(r, 700));
    const opened = !!document.querySelector('.modal');
    const focusMovedIn = document.activeElement !== before;
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    await new Promise(r => setTimeout(r, 500));
    const closed = !document.querySelector('.modal');
    return { opened, focusMovedIn, closedByEscape: closed, focusRestored: document.activeElement === before };
  })()`);

  // Live accessibility facts the static gate cannot establish. check-a11y.mjs greps the source, so
  // it passes on the WORD: deleting the nav's aria-current behaviour and leaving the comment that
  // mentions it kept that gate green, while the gate's success line still listed "aria-current" as
  // verified. These assert the rendered result instead.
  report.a11y = await c.eval(`(async () => {
    location.hash = '#routing';
    await new Promise(r => setTimeout(r, 1200));
    const marked = [...document.querySelectorAll('.nav-item[aria-current]')];
    const active = document.querySelector('.nav-item.active');
    const toasts = document.getElementById('toasts');
    const failsafe = document.getElementById('failsafe-banner');
    // Every visible form control must resolve to a name. associateLabels exists to guarantee this;
    // the static gate only checks that the function is mentioned.
    const view = document.querySelector('.route-view') || document.querySelector('#view');
    const unnamed = [...(view ? view.querySelectorAll('input, select, textarea') : [])].filter((c) => {
      if (!c.offsetParent && getComputedStyle(c).position !== 'fixed') return false;
      if (c.getAttribute('aria-label') || c.getAttribute('aria-labelledby')) return false;
      const lab = (c.id && document.querySelector('label[for="' + CSS.escape(c.id) + '"]')) || c.closest('label');
      return !lab || getComputedStyle(lab).display === 'none';
    }).length;
    // The mobile drawer's state must reach assistive tech. The static gate only checks that the
    // string "aria-expanded" appears in nav.js, which a comment would satisfy; this drives the
    // control and reads the attribute back.
    const burger = document.querySelector('.nav-burger');
    const drawer = {};
    if (burger) {
      drawer.before = burger.getAttribute('aria-expanded');
      burger.click();
      await new Promise(r => setTimeout(r, 300));
      drawer.afterOpen = burger.getAttribute('aria-expanded');
      burger.click();
      await new Promise(r => setTimeout(r, 300));
      drawer.afterClose = burger.getAttribute('aria-expanded');
    }
    // redactSecrets decides whether a user's VPN credential ends up in a toast. Its only coverage
    // anywhere was a regex test for its NAME in app.js — the word, not the behaviour. These drive the
    // real function with material of each kind it claims to mask and assert the secret is gone.
    const redaction = [];
    if (typeof redactSecrets === 'function') {
      const cases = [
        ['url userinfo', 'dial trojan://SuperSecret123@example.net:443 failed', 'SuperSecret123'],
        ['short userinfo password', 'parse ss://aes-256-gcm:abc@1.2.3.4:8388', 'abc'],
        ['query password', 'bad link vless://x@h:443?password=hunter2&sni=a.b', 'hunter2'],
        ['query token', 'sub fetch failed https://p.example/x?token=t0ps3cr3t', 't0ps3cr3t'],
        ['uuid', 'invalid uuid 2f1b7c94-6d3a-4f5e-8b12-0a9c7e4d1f60 for vmess', '2f1b7c94-6d3a-4f5e-8b12-0a9c7e4d1f60'],
        // Built in Node and INLINED, not called here: this block is serialised and evaluated inside
        // the page, where a helper defined in the script's own module scope does not exist. Calling
        // it here threw a ReferenceError for the helper and failed the whole sweep.
        ['long token', 'key ${LONG_TOKEN} rejected', '${LONG_TOKEN}'],
      ];
      for (const [name, input, secret] of cases) {
        const out = redactSecrets(input);
        if (String(out).includes(secret)) redaction.push(name);
      }
    } else {
      redaction.push('redactSecrets is not a function');
    }
    return {
      redactionLeaks: redaction,
      currentMarked: marked.length,
      currentIsActive: marked.length === 1 && active === marked[0],
      toastsRole: toasts ? toasts.getAttribute('role') : null,
      failsafeRole: failsafe ? failsafe.getAttribute('role') : null,
      unnamedControls: unnamed,
      burgerPresent: !!burger,
      drawer,
    };
  })()`);

  // The unsaved-edit guard, driven rather than grepped. The static gate asserts that the strings
  // "registerDirtyCheck" and "beforeunload" appear in app.js; neither says the guard fires. This
  // makes a real edit, then navigates away twice — once declining, once accepting — because a guard
  // that always blocks is as broken as one that never does, and only the pair distinguishes them.
  report.navGuard = await c.eval(`(async () => {
    location.hash = '#settings';
    await new Promise(r => setTimeout(r, 2500));
    // Scope to a SETTING, not to the index's own search box — that was the first visible text
    // input on the page, and editing it is not an unsaved edit. The check reported a product defect
    // that was entirely its own aim.
    const field = [...document.querySelectorAll('#view .sx-row input[type="text"], #view .sx-row input:not([type])')]
      .find(i => i.offsetParent && !i.classList.contains('sx-search'));
    if (!field) return { skipped: 'no editable settings field on screen' };
    const original = field.value;
    field.value = original + 'x';
    field.dispatchEvent(new Event('input', { bubbles: true }));
    await new Promise(r => setTimeout(r, 300));
    const dirtySeen = typeof hasUnsavedPageEdits === 'function' ? hasUnsavedPageEdits('#settings') : null;

    const realConfirm = window.confirm;
    window.confirm = () => false;              // "no, keep my edits"
    location.hash = '#dashboard';
    await new Promise(r => setTimeout(r, 900));
    const blockedAt = location.hash;

    window.confirm = () => true;               // "yes, leave without saving"
    location.hash = '#dashboard';
    await new Promise(r => setTimeout(r, 900));
    const allowedAt = location.hash;
    window.confirm = realConfirm;
    return { dirtySeen, blockedAt, allowedAt };
  })()`);

  c.close();
} finally {
  await closeChrome(chrome, chrome.profileDir);
}

const bad = report.pages.filter((p) => !p.ok);

// The modal contract and the live a11y facts were COLLECTED and never judged: `bad` only ever
// looked at pages, so both blocks were printed into the report and ignored. A measurement nobody
// compares against anything is a note, not a check — and this suite spent a whole redesign
// reporting green while these two proved nothing.
const contract = [];
const m = report.modal || {};
if (!m.skipped) {
  if (!m.opened) contract.push('the review modal did not open, so nothing below it was exercised');
  else {
    if (!m.focusMovedIn) contract.push('opening the modal did not move focus into it');
    if (!m.closedByEscape) contract.push('Escape did not close the modal');
    if (!m.focusRestored) contract.push('focus did not return to the opener after the modal closed');
  }
}
const de = report.dashboardExits || {};
if (de.skipped) {
  contract.push(`Dashboard exit-card layout could not be exercised: ${de.skipped}`);
} else {
  if (!de.directChildren || !de.allVisible) contract.push('Dashboard hides or nests some exit-address cards');
  if (!de.overflowControlAbsent) contract.push('Dashboard still puts exit-address cards behind an overflow control');
  if (de.display !== 'flex' || de.wrap !== 'wrap' || de.justify !== 'center') {
    contract.push(`Dashboard exit layout is ${de.display}/${de.wrap}/${de.justify}, want flex/wrap/center`);
  }
  if (!de.fiveFitWide || !de.fiveEqualWide || !de.fiveCompactWide || !de.wideNoOverflow || !de.twelvePixelGaps) {
    contract.push(`Dashboard does not fit five equal compact exit cards at 947px without overflow (fit=${de.fiveFitWide}, equal=${de.fiveEqualWide}, compact=${de.fiveCompactWide}, contained=${de.wideNoOverflow}, gaps=${de.wideGaps})`);
  }
  if (!de.compactIPv4Fits) contract.push('Dashboard compact exit card truncates a full IPv4 address at 947px');
  // 8% is about half the spread between the narrowest and widest sans-serif an operator's machine is
  // likely to pick for this stack, so a pass here means the address fits on their screen too.
  if (de.compactIPv4WideFontFits === false) {
    contract.push('Dashboard compact exit card truncates a full IPv4 address at 947px in the widest '
      + 'sans-serif this machine has (the panel is opened from Windows, Linux and macOS alike)');
  }
  if (de.compactIPv4Headroom >= 0 && de.compactIPv4Headroom < 0.08) {
    contract.push(`Dashboard compact exit card fits a full IPv4 address with no room to spare at 947px `
      + `(headroom ${Math.round(de.compactIPv4Headroom * 100)}%, want 8% so a wider font still fits)`);
  }
  if (de.rowCount < 2) contract.push('Dashboard exit cards did not wrap in the constrained-width check');
  if (!de.lastRowCentered) contract.push(`Dashboard final exit-card row is not centred (${de.rowCount} row(s))`);
}
const cs = report.connectionSelection || {};
if (cs.skipped) {
  contract.push(`Connections selection could not be exercised: ${cs.skipped}`);
} else {
  if (cs.apiReads !== 0) contract.push(`Connections selection issued ${cs.apiReads} API read(s) instead of updating locally`);
  if (!cs.listPreserved || !cs.rowsPreserved) contract.push('Connections selection rebuilt the list or its rows');
  if (!cs.panelReplaced) contract.push('Connections selection did not replace the detail panel');
  if (!cs.targetSelected || cs.selectedCount !== 1) contract.push(`Connections selection state is inconsistent (selected=${cs.selectedCount})`);
  if (!cs.focusPreserved) contract.push('Connections selection discarded keyboard focus');
}
const a = report.a11y || {};
if (a.currentMarked !== 1) {
  contract.push(`exactly one nav item must carry aria-current, found ${a.currentMarked}`);
} else if (!a.currentIsActive) {
  contract.push('aria-current is on a different nav item than the active one');
}
if (a.toastsRole !== 'status') contract.push(`#toasts must be role=status, found ${a.toastsRole}`);
if (a.failsafeRole !== 'alert') contract.push(`#failsafe-banner must be role=alert, found ${a.failsafeRole}`);
if (a.unnamedControls > 0) contract.push(`${a.unnamedControls} rendered control(s) have no accessible name`);
const g = report.navGuard || {};
if (g.skipped) {
  contract.push(`the unsaved-edit guard could not be exercised: ${g.skipped}`);
} else {
  if (!g.dirtySeen) contract.push('editing a settings field did not mark the page dirty, so the guard had nothing to act on');
  if (g.blockedAt !== '#settings') contract.push(`declining the leave prompt must keep you on the page, ended up at ${g.blockedAt}`);
  if (g.allowedAt !== '#dashboard') contract.push(`accepting the leave prompt must let you go, ended up at ${g.allowedAt}`);
}
if ((a.redactionLeaks || []).length) {
  contract.push(`redactSecrets let credential material through: ${a.redactionLeaks.join(', ')}`);
}
if (!a.burgerPresent) {
  contract.push('the mobile nav burger is missing, so its state contract could not be exercised');
} else {
  const d = a.drawer || {};
  if (d.afterOpen !== 'true') contract.push(`opening the nav drawer must set aria-expanded=true, got ${d.afterOpen}`);
  if (d.afterClose !== 'false') contract.push(`closing the nav drawer must set aria-expanded=false, got ${d.afterClose}`);
}
report.contract = contract;

report.summary = { total: report.pages.length, ok: report.pages.length - bad.length,
  failing: bad.map((p) => p.page), contractProblems: contract };
console.log(JSON.stringify(report, null, 2));

// Persist the FULL report whenever anything failed. A rare flake is only diagnosable if its detail
// survives, and stdout does not always: a caller that pipes this through a summary filter throws the
// per-page badStatus/consoleErrors away, which is exactly how one diagnostics failure was lost.
// Writing it here makes that impossible regardless of how the script is invoked.
if (bad.length || contract.length) {
  const out = path.join(os.tmpdir(), `wayhop-sweep-fail-${process.pid}.json`);
  try {
    fs.writeFileSync(out, JSON.stringify(report, null, 2));
    contract.forEach((c) => console.error(`  contract: ${c}`));
    console.error(`sweep FAILED (pages: ${bad.map((p) => p.page).join(', ') || 'none'}; contract problems: ${contract.length}) — full report: ${out}`);
  } catch (e) {
    console.error(`sweep FAILED (${bad.map((p) => p.page).join(', ')}); could not write report: ${e.message}`);
  }
}
process.exit(bad.length || contract.length ? 1 : 0);
