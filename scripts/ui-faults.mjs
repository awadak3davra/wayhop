// ui-faults.mjs — §3 failure-mode testing: break the backend on purpose and check the UI tells the
// truth about it.
//
// Rendering a page proves nothing about what happens when the router says 500, times out, or drops
// the connection mid-Apply. Those are exactly the paths where a panel silently claims success, or
// leaves the user believing a change landed when it did not. This intercepts specific requests over
// CDP and asserts the UI's observable reaction.
//
// Each scenario states what MUST be true; a scenario that cannot prove its claim fails rather than
// passing quietly.
//
// Usage: node scripts/ui-faults.mjs <url>
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
  // Falling out of that loop used to be silent, so a profile dir that could not be removed —
  // and the browser that may still hold it — went unnoticed until somebody counted /tmp.
  console.error(`note: could not remove the Chrome profile dir ${dir}`);
}

const URL_ARG = process.argv[2] || 'http://127.0.0.1:8088/';
const PORT = Number(process.env.CDP_PORT || 9444);
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const httpJSON = async (u) => (await fetch(u)).json();

// Wait for a condition the PAGE can answer, rather than for a number of milliseconds.
//
// A fixed sleep puts a check's verdict on a stopwatch. Scenario 7f went red in a full suite run and
// then passed alone in the same 173.7s, because a build running on the same machine pushed one fetch
// past a flat sleep(3000). The damage is not the lost time, it is that `marked=false` reads exactly
// the same whether the panel stopped marking an uncomparable tag or the request had simply not landed
// yet — so the single failure that scenario exists to catch became indistinguishable from a busy
// laptop. Returns whether the condition became true within the budget, so the caller can say which.
const waitUntil = async (c, expr, ms = 12000) => {
  const deadline = Date.now() + ms;
  for (;;) {
    if (await c.eval(`!!(${expr})`).catch(() => false)) return true;
    if (Date.now() >= deadline) return false;
    await sleep(200);
  }
};

async function startChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wayhop-faults-'));
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
  const handlers = [];
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); return; }
    if (m.method) handlers.forEach((h) => h(m));
  };
  // A CDP command that never gets a reply used to hang the entire run: node exited 13, "unsettled
  // top-level await", with no results printed and nothing to point at. That is the worst failure
  // mode this harness has — it cannot even say which scenario it died in. A lost reply is now a
  // loud, locatable error instead of silence.
  const send = (method, params = {}, timeoutMs = 30000) => new Promise((resolve, reject) => {
    const myId = ++id;
    const timer = setTimeout(() => {
      waiting.delete(myId);
      reject(new Error(`CDP ${method} got no reply in ${timeoutMs}ms`));
    }, timeoutMs);
    waiting.set(myId, (m) => {
      clearTimeout(timer);
      if (m.error) reject(new Error(m.error.message)); else resolve(m.result);
    });
    ws.send(JSON.stringify({ id: myId, method, params }));
  });
  return {
    send, close: () => ws.close(), on: (h) => handlers.push(h),
    async eval(expr, _retry) {
      // "Inspected target navigated or closed" is not a harness failure when the harness caused the
      // navigation. Retry once against the new document; a second one is a real problem and is
      // allowed to propagate.
      let r;
      try {
        r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
      } catch (e) {
        if (_retry || !/navigated or closed|Target closed|Session closed/i.test(e.message)) throw e;
        await new Promise((x) => setTimeout(x, 750));
        return this.eval(expr, true);
      }
      if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || 'eval failed');
      return r.result.value;
    },
  };
}

const results = [];
const record = (name, pass, detail) => { results.push({ name, pass, detail }); };

// require asserts a PRECONDITION: the thing a scenario is about must actually be on screen.
//
// Several checks here are written as `!subjectWasFrozen || itSaidSo` — correct when the subject
// exists, and trivially TRUE when it does not. So a card that stopped rendering, a button that got
// renamed, or a demo profile too small to produce the case would turn the check green while
// measuring nothing. That is exactly the failure this harness was itself caught committing twice
// (a selector left over from the pre-redesign markup, and one armed fault silently disarming
// another). Preconditions are therefore recorded as their own checks and fail LOUDLY.
const require = (name, ok, whyItMatters) => {
  record(name, !!ok, ok ? 'present' : `NOT MEASURED — ${whyItMatters}`);
  return !!ok;
};

const chrome = await startChrome();
try {
  const targets = await httpJSON(`http://127.0.0.1:${PORT}/json/list`);
  const c = await connect((targets.find((t) => t.type === 'page') || targets[0]).webSocketDebuggerUrl);
  await c.send('Page.enable');
  await c.send('Runtime.enable');

  // fault holds the currently-armed injection; the interceptor consults it per request.
  let fault = null;
  // Requests deliberately left unanswered by the 'hang' fault. They MUST be released before the run
  // ends, or the page is wedged and every later scenario measures the wedge instead of the app.
  const held = [];
  const releaseHeld = async () => {
    while (held.length) {
      try { await c.send('Fetch.continueRequest', { requestId: held.pop() }); } catch { /* gone */ }
    }
  };
  // Clearing a fault is not the end of it. When the injected failure was broad enough to trip the
  // daemon-unreachable overlay, the app reloads ITSELF: showReconnect polls /api/health every 1500ms
  // and calls location.reload() 400ms after the first success (app.js showReconnect). So the window
  // here has to outlast one poll plus that delay, and the wait has to tolerate the navigation rather
  // than be killed by it.
  //
  // Readiness is keyed on performance.timeOrigin, which is replaced along with the document: a
  // reload is therefore observable rather than assumed, and the helper reports whether one happened
  // so a scenario can say so instead of silently measuring a different page.
  let reloadsWaited = 0;
  const note = () => console.log(`  waited out a self-inflicted reload (#${++reloadsWaited})`);
  // MIN_WATCH is the floor, and it is the whole point. The first cut of this returned as soon as the
  // page had looked stable for 750ms — which is shorter than the reconnect poll interval, so it
  // regularly concluded "no reload is coming" about 1.5s BEFORE the reload came, and the run then
  // hung on an eval issued into a navigating document. A page that has not yet been reloaded looks
  // exactly like one that never will; only time distinguishes them, and the time required is one
  // full poll (1500ms) plus the reload delay (400ms) plus slack.
  const MIN_WATCH = 3000;
  const clearFault = async (grace = 12000) => {
    const was = fault;
    fault = null;
    await releaseHeld();
    // Only a NETWORK-level failure can trip the overlay: showReconnect keys off the TypeError a dead
    // fetch throws, not off an HTTP status. A 500, a synthetic 200, a delayed response and a held
    // request all leave the app connected and no reload follows.
    //
    // The first version of this waited after EVERY clear, which moved every later assertion three
    // seconds downstream and broke four checks that measure what the screen looks like immediately
    // after recovery — the app had re-polled and repainted by the time they looked. A fix whose blast
    // radius is wider than the defect is its own defect; this one now applies exactly where a reload
    // is possible.
    if (!was || was.kind !== 'fail') return false;
    const before = await c.eval('performance.timeOrigin').catch(() => null);
    const t0 = Date.now();
    let stable = 0, seen = before, reloaded = false;
    while (Date.now() - t0 < grace) {
      await sleep(250);
      // A navigation in flight rejects this; that is the event being waited for, not an error.
      const now = await c.eval('typeof route === "function" ? performance.timeOrigin : 0')
        .catch(() => null);
      if (!now) { stable = 0; continue; }
      if (now !== seen) { seen = now; if (before !== null) reloaded = true; stable = 0; continue; }
      // Three consecutive identical samples with the app defined: the document is not being
      // replaced under us. One sample is also what a page looks like 200ms before it reloads.
      if (Date.now() - t0 < MIN_WATCH) continue;
      if (++stable >= 3) {
        if (reloaded) note();
        return reloaded;
      }
    }
    // Fell out of the window. Say so: a clear that never settled means the scenarios after it are
    // measuring an unknown state, which is worth a line in the output rather than silence.
    if (reloaded) note();
    else console.log(`  note: page did not settle within ${grace}ms after clearing a fault`);
    return reloaded;
  };

  await c.send('Fetch.enable', { patterns: [{ urlPattern: '*/api/*' }] });
  c.on(async (m) => {
    if (m.method !== 'Fetch.requestPaused') return;
    const { requestId, request } = m.params;
    try {
      // match may be one pattern or several. It used to be a single string, and a scenario that
      // needed two feeds down at once silently revived the first when it armed the second — the
      // check then passed against a fully live app, proving nothing.
      //
      // `payloads` is the next step of the same problem: one page can need two endpoints answered
      // DIFFERENTLY at the same time. The Updater page reads /api/updater/self AND
      // /api/updater/engines on every render, and a scenario about the engine table that leaves the
      // self row on the live daemon has its verdict decided by whether GitHub happened to answer —
      // which is a check whose subject is the network, not the panel. Keys are matched as
      // substrings in declaration order; `match` still wins when both are given.
      const patterns = fault
        ? (fault.match ? (Array.isArray(fault.match) ? fault.match : [fault.match])
                       : Object.keys(fault.payloads || {}))
        : [];
      if (fault && patterns.some((m) => request.url.includes(m))) {
        if (fault.kind === 'fail') {
          await c.send('Fetch.failRequest', { requestId, errorReason: 'ConnectionRefused' });
          return;
        }
        if (fault.kind === 'status') {
          await c.send('Fetch.fulfillRequest', {
            requestId, responseCode: fault.code,
            responseHeaders: [{ name: 'Content-Type', value: 'application/json' }],
            // A 4xx body is not always just a sentence: the package-manager path answers a running
            // core with `{error, needs_stop:true}` and the page branches on the flag. Serving only
            // {error} could never exercise that branch, so a scenario about it would have been
            // testing the harness's idea of a refusal rather than the daemon's.
            body: Buffer.from(JSON.stringify(fault.payload || { error: fault.body || 'injected failure' })).toString('base64'),
          });
          return;
        }
        // 'hang' never answers at all — the request that goes out and never comes back. Distinct
        // from 'delay' (slow but eventual): nothing will ever resolve this promise, so it reveals
        // whether the UI can be left waiting forever with no feedback.
        if (fault.kind === 'hang') {
          held.push(requestId);
          return;
        }
        // 'delay' holds the request open before letting it through, so a response can be made to
        // land AFTER the user has already navigated somewhere else.
        if (fault.kind === 'delay') {
          await sleep(fault.ms);
          await c.send('Fetch.continueRequest', { requestId });
          return;
        }
        // 'payload' serves a synthetic 200. Used to exercise UI states that depend on a router
        // condition we cannot (and must not) create on a live box — e.g. a platform that would
        // silently discard part of the configuration.
        if (fault.kind === 'payload') {
          const per = fault.payloads
            ? Object.entries(fault.payloads).find(([k]) => request.url.includes(k)) : null;
          await c.send('Fetch.fulfillRequest', {
            requestId, responseCode: 200,
            responseHeaders: [{ name: 'Content-Type', value: 'application/json' }],
            body: Buffer.from(JSON.stringify(per ? per[1] : fault.payload)).toString('base64'),
          });
          return;
        }
      }
      await c.send('Fetch.continueRequest', { requestId });
    } catch { /* the request may already be gone; nothing to do */ }
  });

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
  if (!ready) {
    // A bare "never became defined" cannot tell a SLOW load from a BROKEN one, and the difference
    // decides whether the run found a defect or the harness lost a race. This timed out once inside a
    // full suite while the same gate passed 79/79 standalone minutes later, and answering "was app.js
    // even served?" cost a whole re-run. So say what the page actually looks like at the moment of
    // giving up: which bundles executed, what the document is doing, and any error the page recorded.
    // typeof on a BARE identifier, never globalThis[name]: app.js declares api/PAGES with const, and
    // a top-level const in a classic script lives in script scope rather than on globalThis. Probing
    // the object reported them absent on a fully loaded page — a diagnostic that invents failures is
    // worse than none, since it would send the next reader after the wrong file.
    const state = await c.eval(`JSON.stringify({
      readyState: document.readyState,
      scripts: [...document.querySelectorAll('script[src]')].map(s => s.getAttribute('src')),
      app: typeof openReviewChanges, api: typeof api, el: typeof el, t: typeof t, pages: typeof PAGES,
      bodyChars: (document.body ? document.body.innerHTML.length : 0),
    })`).catch((e) => `unavailable: ${e && e.message}`);
    throw new Error('app.js did not finish loading: openReviewChanges never became defined. Page at ' +
      `timeout: ${state}`);
  }
  await authenticateCDP({
    send: (method, params) => c.send(method, params), evaluate: expression => c.eval(expression),
    url: URL_ARG, readyExpression: 'typeof openReviewChanges === "function"',
  });
  await sleep(1500);

  // Recovery scenarios need a known-good response whose truth does not depend on the disposable
  // demo's state. Keep this fixture minimal (the GET /api/apply/plan shape of docs/APPLY_REDESIGN.md in the development repository)
  // so these checks measure UI recovery only.
  const RECOVERY_PLAN = {
    rev: 'r'.repeat(64), pending: true, nothing_configured: false, applied_rev: '', applied_at: '',
    verdict: 'ready', findings: [],
    changes: { baseline_available: true, baseline_rev: 'b'.repeat(64), count: 1, may_interrupt: false, requires_apply: true,
      by_subsystem: { routing: [{ id: 'rl1', object_name: 'recovery-list', field: 'enabled', before: 'off', after: 'on',
        secret: false, impact: '', action: 'modified', may_interrupt: false, requires_service_restart: false, requires_reboot: false, warnings: [] }] },
      changes: [] },
    window: { open: false, phase: 'idle', seconds_left: 0 },
    probe: { at: 0, age_s: 0, stale: false, error: '' },
    platform: { name: 'demo', core_available: true, core_running: false, kernel_plane: false, native_vpn: false },
  };

  // --- Scenario 1: the review panel's data endpoint returns 500 -------------------------------
  // MUST: no modal claiming an empty/committed state, and the user is told something went wrong.
  fault = { kind: 'status', match: '/api/apply/plan', code: 500, body: 'injected backend failure' };
  const s1 = await c.eval(`(async () => {
    document.querySelectorAll('.modal, .modal-backdrop').forEach(m => m.remove());
    const toastsBefore = document.querySelectorAll('.toast, .toasts > *').length;
    try { await openReviewChanges(); } catch (_) {}
    await new Promise(r => setTimeout(r, 1200));
    return {
      modalShown: !!document.querySelector('.modal'),
      panelShown: !!document.querySelector('.cs-panel'),
      toastsAfter: document.querySelectorAll('.toast, .toasts > *').length,
      toastsBefore,
    };
  })()`);
  record('changeset 500 -> no false empty panel',
    !s1.panelShown, `panelShown=${s1.panelShown} modalShown=${s1.modalShown}`);
  record('changeset 500 -> user is notified',
    s1.toastsAfter > s1.toastsBefore, `toasts ${s1.toastsBefore} -> ${s1.toastsAfter}`);

  // --- Scenario 2: connection refused (router unreachable mid-session) ------------------------
  // MUST: surface an error, never render a panel implying "no pending changes".
  fault = { kind: 'fail', match: '/api/apply/plan' };
  const s2 = await c.eval(`(async () => {
    document.querySelectorAll('.modal, .modal-backdrop').forEach(m => m.remove());
    try { await openReviewChanges(); } catch (_) {}
    await new Promise(r => setTimeout(r, 1200));
    const panel = document.querySelector('.cs-panel');
    return { panelShown: !!panel, text: panel ? panel.textContent.slice(0, 120) : null };
  })()`);
  record('network drop -> no panel claiming "no pending changes"',
    !s2.panelShown || !/no pending changes/i.test(s2.text || ''), `text=${JSON.stringify(s2.text)}`);

  // --- Scenario 3: recovery — once the fault clears, the UI works again -----------------------
  // A UI that latches into a broken state after one failure is its own defect.
  await clearFault();
  fault = { kind: 'payload', match: '/api/apply/plan', payload: RECOVERY_PLAN };
  const s3 = await c.eval(`(async () => {
    document.querySelectorAll('.modal, .modal-backdrop').forEach(m => m.remove());
    await openReviewChanges();
    await new Promise(r => setTimeout(r, 1200));
    return { panelShown: !!document.querySelector('.cs-panel'),
             closeBtn: !!document.querySelector('.cs-footer .btn') };
  })()`);
  record('recovers after the fault clears', s3.panelShown && s3.closeBtn,
    `panelShown=${s3.panelShown} footer=${s3.closeBtn}`);

  // --- Scenario 4: repeated clicks must not stack modals --------------------------------------
  const s4 = await c.eval(`(async () => {
    document.querySelectorAll('.modal, .modal-backdrop').forEach(m => m.remove());
    await Promise.all([openReviewChanges(), openReviewChanges(), openReviewChanges()]);
    await new Promise(r => setTimeout(r, 1000));
    return { modals: document.querySelectorAll('.modal').length };
  })()`);
  // Exactly one — not "at most one". 0 would mean nothing opened at all, which is how an earlier
  // version of this check passed while the guard was in fact latched shut.
  record('repeated open yields exactly one modal', s4.modals === 1, `modals=${s4.modals}`);

  // --- Scenario 5: the platform preflight renders before Apply --------------------------------
  // The test router's own configuration is fully supported, so it reports nothing. Rather than
  // change a live router's settings to manufacture a warning, serve the response such a router
  // WOULD send and check the panel surfaces it: severity wording (not colour alone), a plain title,
  // and the remedy without exposing internal setting syntax.
  // Finding shape per docs/APPLY_REDESIGN.md in the development repository: a hard blocker (blocks=apply), a finding that needs an
  // acknowledgement (blocks=feature), and an informational note (blocks=optimisation) that must fold
  // away rather than sit beside the decisions.
  fault = {
    kind: 'payload', match: '/api/apply/plan',
    payload: Object.assign({}, RECOVERY_PLAN, {
      rev: 'i'.repeat(64), verdict: 'blocked',
      findings: [
        { id: 'routing_mode=fast', code: 'ROUTING_MODE_UNAVAILABLE', severity: 'blocked', blocks: 'apply',
          ack_required: false, acked: false, count: 1, items: [],
          title: 'Routing mode cannot work as requested',
          detail: 'INJECTED: no kernel plane, so no traffic would be routed.',
          remedy: 'INJECTED: use "tun" on this router.' },
        { id: 'endpoint.engine.olcrtc', code: 'ENGINE_UNAVAILABLE', severity: 'degraded', blocks: 'feature',
          ack_required: true, acked: false, count: 2, items: ['olc-1', 'olc-2'],
          title: 'olcRTC connections will not start',
          detail: 'INJECTED: the engine binary is not installed.', remedy: 'INJECTED: install it in Updater.' },
        { id: 'kernel_plane.fallback', code: 'KERNEL_PLANE_FALLBACK', severity: 'info', blocks: 'optimisation',
          ack_required: false, acked: false, count: 1, items: [],
          title: 'Rules use the userspace fallback', detail: 'INJECTED: fine, just slower.', remedy: '' },
      ],
    }),
  };
  const s5 = await c.eval(`(async () => {
    document.querySelectorAll('.modal, .modal-backdrop').forEach(m => m.remove());
    await openReviewChanges();
    await new Promise(r => setTimeout(r, 1200));
    const box = document.querySelector('.cs-preflight');
    // The VISIBLE text: technical identifiers (finding id / code) stay folded under <details>, so they
    // are excluded before asking whether internal setting syntax leaked into the prose.
    const visible = box ? (() => { const cl = box.cloneNode(true); cl.querySelectorAll('.cs-preflight-tech').forEach(n => n.remove()); return cl.textContent; })() : '';
    const txt = box ? box.textContent : '';
    const notes = box ? box.querySelector('details.cs-notes') : null;
    return {
      shown: !!box,
      rows: document.querySelectorAll('.cs-preflight-row:not(.cs-note)').length,
      // Severity must be readable as text, not conveyed by colour alone.
      hasBlockedLabel: /blocks apply|\\u0431\\u043b\\u043e\\u043a\\u0438\\u0440/i.test(txt),
      hasReason: txt.includes('INJECTED'),
      hasRemedy: txt.includes('use "tun"'),
      // A finding that stops Apply must say so, not merely look severe.
      namesBlockedAction: /blocks apply/i.test(txt),
      hidesInternalSetting: !visible.includes('routing_mode'),
      // The acknowledgement is a real checkbox, unticked (nothing acknowledged yet), and the affected
      // items are named.
      ackBox: !!box.querySelector('.cs-preflight-ack input[type=checkbox]:not(:checked)'),
      namesItems: /olc-1/.test(txt) && /olc-2/.test(txt),
      // The informational note folds: present, closed, and its row is not counted among the decisions.
      notesFolded: !!notes && !notes.open && /1 note/i.test(notes.querySelector('summary')?.textContent || ''),
      // Both actions are disabled while a hard blocker exists, and the panel says why.
      actionsDisabled: [...document.querySelectorAll('.cs-footer .btn')].filter(b => /test safely|apply & save/i.test(b.textContent))
        .every(b => b.getAttribute('aria-disabled') === 'true'),
      note: (document.querySelector('.cs-apply-note') || {}).textContent || '',
      // Ordered above the change list, where it cannot be missed.
      aboveChanges: (() => {
        const p = document.querySelector('.cs-panel'); if (!p || !box) return false;
        const g = p.querySelector('.cs-group, .cs-nobase');
        return !g || (box.compareDocumentPosition(g) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
      })(),
    };
  })()`);
  record('preflight findings render in the review panel (blocker + acknowledgement as decisions)', s5.shown && s5.rows === 2,
    `shown=${s5.shown} rows=${s5.rows}`);
  record('preflight states severity as text, not colour alone', s5.hasBlockedLabel,
    `hasBlockedLabel=${s5.hasBlockedLabel}`);
  record('preflight states the issue and remedy without internal setting syntax',
    s5.hidesInternalSetting && s5.hasReason && s5.hasRemedy,
    `hidesInternalSetting=${s5.hidesInternalSetting} reason=${s5.hasReason} remedy=${s5.hasRemedy}`);
  record('a finding that stops Apply says so', s5.namesBlockedAction,
    `namesBlockedAction=${s5.namesBlockedAction}`);
  record('an acknowledgement is an unticked checkbox and the affected items are named', s5.ackBox && s5.namesItems,
    `ackBox=${s5.ackBox} namesItems=${s5.namesItems}`);
  record('informational findings fold away under "N notes"', s5.notesFolded, `notesFolded=${s5.notesFolded}`);
  record('a hard blocker disables both actions and the panel says why', s5.actionsDisabled && /blocking/i.test(s5.note),
    `actionsDisabled=${s5.actionsDisabled} note=${JSON.stringify(s5.note.slice(0, 80))}`);
  record('preflight sits above the change list', s5.aboveChanges, `aboveChanges=${s5.aboveChanges}`);

  // A capability probe that FAILS must not take the review panel down with it, and must not read as
  // "all clear": the panel says the check failed and offers a re-check.
  fault = { kind: 'payload', match: '/api/apply/plan',
    payload: Object.assign({}, RECOVERY_PLAN, { rev: 'u'.repeat(64), verdict: 'blocked',
      probe: { at: 0, age_s: 900, stale: true, error: 'INJECTED: ndmc timed out' },
      findings: [{ id: 'core.unavailable', code: 'CORE_UNAVAILABLE', severity: 'blocked', blocks: 'apply', ack_required: false, acked: false,
        count: 1, items: [], title: 'The proxy core is required but not runnable', detail: 'INJECTED: sing-box is missing.', remedy: 'INJECTED: install it in Updater.' }] }) };
  const s6 = await c.eval(`(async () => {
    document.querySelectorAll('.modal, .modal-backdrop').forEach(m => m.remove());
    await openReviewChanges();
    await new Promise(r => setTimeout(r, 1200));
    const box = document.querySelector('.cs-preflight');
    return { panelShown: !!document.querySelector('.cs-panel'),
             saysFailed: !!box && /capability check failed|could not|failed/i.test(box.textContent) && /ndmc timed out/.test(box.textContent),
             recheck: !!box && [...box.querySelectorAll('button')].some(b => /re-check/i.test(b.textContent)),
             blocked: !!box && /blocks apply/i.test(box.textContent) };
  })()`);
  record('a failed capability probe is stated (with a re-check), not hidden, and the blocker still shows',
    s6.panelShown && s6.saysFailed && s6.recheck && s6.blocked,
    `panel=${s6.panelShown} saysFailed=${s6.saysFailed} recheck=${s6.recheck} blocked=${s6.blocked}`);

  // --- Scenario 7: a slow response must not paint over a page the user has since left ----------
  // The classic stale-request bug: leave a page while its fetch is in flight, and the late response
  // renders into whatever view is showing now. Detected by signature rather than by guessing at
  // page-specific markup — capture what a clean #settings looks like, then check the raced load
  // ends up identical.
  await clearFault();
  // Leading text AND control count. Measured on this build, #routing signs as "Routing…|4" and
  // #settings as "Settings…|30", so the signature genuinely discriminates the two pages — a
  // comparison that could not tell them apart would pass regardless of stale paint.
  const signature = `(() => {
    const v = document.querySelector('#view') || document.body;
    return (v.textContent || '').trim().slice(0, 40) + '|' + v.querySelectorAll('button, input, select').length;
  })()`;

  await c.eval(`location.hash = '#settings'`);
  await sleep(2500);
  const clean = await c.eval(signature);

  // Now race it: start #routing with every API call held open, switch to #settings immediately,
  // and let the stale routing responses land afterwards.
  fault = { kind: 'delay', match: '/api/', ms: 2000 };
  await c.eval(`location.hash = '#routing'`);
  await sleep(250);
  await c.eval(`location.hash = '#settings'`);
  await sleep(6000);
  await clearFault();
  const raced = await c.eval(signature);

  record('a stale response does not paint over the current page', raced === clean,
    `clean=${JSON.stringify(clean)} raced=${JSON.stringify(raced)}`);

  // --- Scenario 7b: the dashboard's live figures go stale ---------------------------------------
  // /api/system is best-effort in the 5s poll (.catch(() => null)), and paintSystem(null) leaves the
  // strip untouched. So when only that feed fails, RAM / CPU / uptime / throughput keep displaying
  // their last successful values. The endpoints feed still answers, so the reconnect banner never
  // appears. The question this measures: is a figure that stopped updating still presented as current?
  await clearFault();
  await c.eval(`location.hash = '#dashboard'`);
  await sleep(3000);
  const readStrip = `(() => {
    const s = document.querySelector('#sys-strip');
    if (!s) return { present: false };
    const val = k => { const n = s.querySelector('[data-sys="' + k + '"] .sys-v'); return n ? n.textContent.trim() : null; };
    return { present: true, ram: val('ram'), cpu: val('cpu'), thru: val('thru'),
             // Anything at all telling the reader these numbers stopped updating.
             stale: /stale|not updating|no data|last seen|unavailable/i.test(s.textContent),
             staleAttr: s.hasAttribute('data-stale'),
             banner: !!document.querySelector('.reconnect, #reconnect, .reconnect-banner') };
  })()`;
  const beforeStale = await c.eval(readStrip);
  fault = { kind: 'fail', match: '/api/system' };
  // The strip is deliberately not alarmed by one dropped sample: the threshold is 12 s against a
  // 5 s poll, so the mark lands on the third consecutive miss (~15 s). Measured at 13 s this read
  // as a failure when the behaviour was correct — the window has to clear the threshold.
  await sleep(22000);
  const afterStale = await c.eval(readStrip);
  await clearFault();

  require('the system strip was on screen to begin with', beforeStale.present,
    'no #sys-strip rendered — the staleness checks below would pass without measuring anything');
  record('the system strip survives a failed /api/system feed',
    !beforeStale.present || afterStale.present,
    `present ${beforeStale.present} -> ${afterStale.present}`);
  // The figures are allowed to keep their last value. What is not allowed is presenting them
  // as current with nothing to say they have stopped.
  const frozen = beforeStale.present && afterStale.present &&
    afterStale.ram === beforeStale.ram && afterStale.cpu === beforeStale.cpu;
  record('a live figure that stopped updating says so',
    !frozen || afterStale.stale || afterStale.staleAttr || afterStale.banner,
    `frozen=${frozen} ram="${beforeStale.ram}"->"${afterStale.ram}" saysStale=${afterStale.stale || afterStale.staleAttr} banner=${afterStale.banner}`);

  // --- Scenario 7c: the health feed dies, two different ways ------------------------------------
  // The endpoint pills ("alive" / "down"), the exit tiles and the Failover cards are all painted
  // from healthMap, refilled by the same 5 s poll. Its catch raises the reconnect banner only when
  // isNetworkError() says so — which is true for a dropped connection and FALSE for an HTTP 500.
  // So the two failures are measured separately: the second is the one that can go quiet.
  await clearFault();
  await c.eval(`location.hash = '#connections'`);
  // Wait for the pills to exist rather than assuming 3s was enough: under load this page has
  // rendered late, and the scenario then measured an empty page and blamed the app.
  for (let i = 0; i < 40; i++) {
    if (await c.eval(`document.querySelectorAll('[data-health]').length > 0`)) break;
    await sleep(250);
  }
  const readPills = `(() => {
    const pills = [...document.querySelectorAll('[data-health]')].map(n => n.textContent.replace(/\s+/g, ' ').trim());
    const banner = !!document.querySelector('.wr-reconnect, .reconnect, #reconnect, .reconnect-banner');
    const strip = document.querySelector('#sys-strip');
    // Check the marker the app sets, not a phrase — matching on wording made this report a
    // failure when the mark was present and only the sentence differed.
    return { pills, banner,
             stale: document.body.hasAttribute('data-health-stale') || !!document.getElementById('health-stale'),
             staleAttr: !!(strip && strip.hasAttribute('data-stale')) };
  })()`;
  const pillsBefore = await c.eval(readPills);

  // (a) connection dropped — the case isNetworkError does catch.
  fault = { kind: 'fail', match: '/api/health/endpoints' };
  // The banner appears on the first failed 5s poll; poll for it rather than sampling once, so a
  // slow tick reads as "later" instead of "never".
  let afterDrop = null;
  for (let i = 0; i < 60; i++) {
    afterDrop = await c.eval(readPills);
    if (afterDrop.banner) break;
    await sleep(500);
  }
  await clearFault();
  record('a dropped health feed raises the reconnect banner',
    afterDrop.banner, `banner=${afterDrop.banner} pills=${JSON.stringify(afterDrop.pills.slice(0, 2))}`);

  // Let it recover so the second case starts from a live page, and clear the banner.
  await c.eval(`(() => { const b = document.querySelector('.wr-reconnect, .reconnect, #reconnect, .reconnect-banner'); if (b) b.remove(); })()`);
  await sleep(6000);

  // (b) the daemon answers, but with an error. No TypeError, so no banner — do the pills admit
  // they have stopped being refreshed, or do they keep asserting "alive"?
  fault = { kind: 'status', match: '/api/health/endpoints', code: 500 };
  await sleep(22000);
  const after500 = await c.eval(readPills);
  await clearFault();
  require('connection states were on screen to begin with', pillsBefore.pills.length > 0,
    'no [data-health] pills rendered — the staleness check below would pass without measuring anything');
  const pillsFrozen = pillsBefore.pills.length > 0 &&
    JSON.stringify(after500.pills) === JSON.stringify(pillsBefore.pills);
  record('a health feed erroring out does not keep asserting stale state as current',
    !pillsFrozen || after500.banner || after500.stale,
    `frozen=${pillsFrozen} banner=${after500.banner} saysStale=${after500.stale} pills=${JSON.stringify(after500.pills.slice(0, 2))}`);

  // --- Scenario 7d: the traffic graph after its feeds stop --------------------------------------
  // drawGraph anchors its 5-minute window on the NEWEST sample across all series (tMax), so when
  // samples stop arriving tMax stops advancing, the window stops moving, and every existing point
  // stays in-window. The plot therefore holds the last five minutes of traffic indefinitely — and
  // it is only redrawn when new data lands, so it will not even repaint itself away. A frozen plot
  // reads as current throughput. Measured rather than assumed.
  await clearFault();
  await c.eval(`location.hash = '#dashboard'`);
  await sleep(6000);
  const readGraph = `(() => {
    const canvas = document.getElementById('g-canvas');
    const ymax = document.getElementById('g-ymax');
    // Series the graph considers drawable right now, straight from its own state.
    let drawn = 0, newest = 0;
    try {
      for (const nm of ifaceOrder) {
        const ser = ifaceSeries[nm];
        if (ser && ser.length) { drawn++; newest = Math.max(newest, ser[ser.length - 1].t); }
      }
    } catch (_) { /* graph globals absent */ }
    return { present: !!canvas, ymax: ymax ? ymax.textContent.trim() : null, drawn,
             ageSec: newest ? Math.round(Date.now() / 1000 - newest) : null,
             // Whatever marker the app uses to say the plot is no longer live.
             stale: !!document.querySelector('[data-graph-stale], .graph-stale') };
  })()`;
  const graphBefore = await c.eval(readGraph);

  // Cut every feed the graph draws from.
  // Both feeds at once, and long enough that the newest sample is unmistakably old.
  fault = { kind: 'fail', match: ['/api/system', '/api/traffic/outbounds'] };
  await sleep(25000);
  const graphAfter = await c.eval(readGraph);
  await clearFault();

  require('the traffic graph was on screen to begin with', graphBefore.present,
    'no #g-canvas rendered — the freeze check below would pass without measuring anything');
  record('the traffic graph has data to begin with',
    !graphBefore.present || graphBefore.drawn > 0,
    `present=${graphBefore.present} series=${graphBefore.drawn} ymax=${graphBefore.ymax}`);
  // Either the plot stops claiming to be live, or it must not still be showing stale series.
  const graphFrozen = graphAfter.present && graphAfter.drawn > 0 && graphAfter.ageSec !== null && graphAfter.ageSec > 15;
  record('a frozen traffic graph does not read as live throughput',
    !graphFrozen || graphAfter.stale,
    `frozen=${graphFrozen} series=${graphAfter.drawn} newestAge=${graphAfter.ageSec}s saysStale=${graphAfter.stale}`);

  // --- Scenario 7e: Failover with one member unreachable and no authoritative state -------------
  // "Test all" probes every member concurrently. A member whose probe fails is simply skipped, so
  // its PREVIOUS health stays in healthMap — and the summary used to count "alive" over every
  // member and announce "Tested N members", folding stale state into a number presented as this
  // run's result. Fault ONE member's probe so the run is genuinely partial.
  await clearFault();
  await c.eval(`location.hash = '#failover'`);
  await sleep(3000);
  const hasGroup = await c.eval(`!!document.querySelector('.fo-chain')`);
  // Which member to fault has to come from the profile, not from a literal. The scenario used to
  // fault "vless_a" — an id from an older demo profile — so once the profile changed the probe
  // it broke belonged to nothing, every member answered, and the run it called partial was complete.
  // The assertion then measured a full run and passed or failed on the wrong thing entirely.
  const victim = await c.eval(`(async () => {
    const p = await (await fetch('/api/profile')).json();
    const g = (p.groups || [])[0];
    return g && (g.members || [])[0] || null;
  })()`);
  if (hasGroup && !victim) {
    record('a partly-completed group test does not read as a completed one', false,
      'NOT MEASURED: the first failover group has no members, so no probe could be faulted');
  } else if (hasGroup) {
    fault = { kind: 'fail', match: '/api/health/test/' + victim };
    const partial = await c.eval(`(async () => {
      const btn = [...document.querySelectorAll('#view button')].find(b => /test all/i.test(b.textContent));
      if (!btn) return { ran: false };
      btn.click();
      // Toasts self-remove after ~4.2s; sampling once at the end reliably found none. Collect
      // every toast that appears while the run is in flight instead.
      const seen = new Set();
      for (let i = 0; i < 40; i++) {
        document.querySelectorAll('.toast').forEach(n => seen.add(n.textContent.trim()));
        await new Promise(r => setTimeout(r, 200));
      }
      return { ran: true, toasts: [...seen] };
    })()`);
    fault = null;
    require('the group test button was found', partial.ran,
      'no "Test all" button on the failover page — the partial-run check below would pass without running it');
    const said = (partial.toasts || []).join(' | ');
    record('a partly-completed group test does not read as a completed one',
      !partial.ran || /of \d+ members|could not probe/i.test(said),
      `toasts=${JSON.stringify(partial.toasts || [])}`);
  } else {
    record('a partly-completed group test does not read as a completed one', false,
      'NOT MEASURED: the demo profile has no failover group — seed one rather than passing vacuously');
  }

  // The daemon's failover truth (which member is ACTUALLY routed) is best-effort: on any error the
  // page falls back to an empty elected map and shows only the client-side latency guess. The guess
  // is worded as a guess, but the FAILURE is silent — nothing says the authoritative answer is
  // missing rather than simply not decided yet.
  fault = { kind: 'fail', match: '/api/failover/state' };
  await c.eval(`location.hash = '#dashboard'`);
  await sleep(600);
  await c.eval(`location.hash = '#failover'`);
  await sleep(3500);
  const noState = await c.eval(`(() => {
    const exit = document.querySelector('.fo-g-exit');
    return {
      rendered: !!document.querySelector('.fo-chain'),
      // The wrong claim this guards: asserting the group has no healthy member when the election
      // simply could not be read.
      // Two wrong claims to guard against: asserting no healthy member, and printing the
      // client-side latency guess under the authoritative "Live exit" label.
      claimsNoHealthy: !!exit && /no healthy member/i.test(exit.textContent),
      claimsLiveExit: !!exit && /live exit/i.test(exit.textContent),
      saysUnknown: !!document.querySelector('[data-failover-unknown]'),
    };
  })()`);
  await clearFault();
  record('an unreadable failover state is neither "no healthy member" nor a guess called "Live exit"',
    noState.rendered && !noState.claimsNoHealthy && !noState.claimsLiveExit && noState.saysUnknown,
    `rendered=${noState.rendered} claimsNoHealthy=${noState.claimsNoHealthy} claimsLiveExit=${noState.claimsLiveExit} saysUnknown=${noState.saysUnknown}`);

  // --- Scenario 7g: a DNS query path whose firewall could not be read ---------------------------
  // The detector reports rules_unknown when neither iptables nor nft could be read, which is exactly
  // the state AUD-43 exists for: hijack53=false is then an absence of evidence, not evidence of
  // absence. The Query path draws the runtime half of the picture from those fields, so it must not
  // render an unread firewall as an enforced one — nor as a confirmed leak, which would send someone
  // chasing a problem nothing measured.
  // Wait for #view to STOP CHANGING, rather than for a fixed 3200ms.
  //
  // Provenance, stated honestly because it is weaker than it looks: "a firewall that was read and
  // has no redirect is stated as a real finding" failed ONCE, with claimsEscapable=false, on a run
  // started immediately after a mid-flight suite and all of its Chrome processes were force-killed.
  // It has passed on every run since — including three runs of the ORIGINAL fixed sleep under
  // deliberate contention from five competing Chrome instances. So the flake was NOT reproduced and
  // this is NOT a proven fix; it is hardening. What is true regardless is that a fixed 3200ms is an
  // assumption about the machine rather than a measurement of the page, and the settle loop usually
  // returns sooner. If the check fails again, this comment is the record that the cause is still
  // unknown — do not read a green run as having explained it.
  //
  // The condition is deliberately NEUTRAL: it waits for the DOM to settle, never for the value the
  // caller is about to assert. Waiting for the expected text would turn every check here into a
  // tautology that cannot fail.
  const settleView = async (cap = 12000) => {
    const t0 = Date.now();
    let prev = null, streak = 0;
    while (Date.now() - t0 < cap) {
      await sleep(200);
      // A polling eval must never be able to kill the run. The app reloads ITSELF here (showReconnect
      // after a cleared fault), and an evaluate issued as the document is replaced can get no reply at
      // all — not an error, silence. The harness turns that into a loud 30s failure everywhere else,
      // which is right for an assertion and wrong for a poll: this loop's answer to "no reply" is
      // "not settled yet". The first version of this crashed a whole suite run that way, having been
      // added to make a different flake less likely.
      const d = await Promise.race([
        c.eval(`(() => { const v = document.querySelector('#view');
          return v ? v.scrollHeight + ':' + v.querySelectorAll('*').length : null; })()`).catch(() => null),
        sleep(1500).then(() => null),
      ]);
      if (!d) { streak = 0; continue; }
      streak = (d === prev) ? streak + 1 : 0;
      prev = d;
      if (streak >= 4) return true;   // five identical samples, ~1s of no change
    }
    console.log(`  note: #view did not settle within ${cap}ms — the reading below is of an unknown state`);
    return false;
  };

  const dnsPath = async (effective, label) => {
    fault = { kind: 'payload', match: '/api/dns/native',
      payload: { available: true, platform: 'openwrt',
                 native: { servers: [], upstreams: [] }, effective } };
    await c.eval(`location.hash = '#dashboard'`);
    await sleep(600);
    await c.eval(`location.hash = '#dns'`);
    await settleView();
    const r = await c.eval(`(() => {
      const stage = [...document.querySelectorAll('.qp-stage')].find(s => /port 53/i.test(s.textContent));
      const foot = document.querySelector('.qp-foot');
      return {
        drew: !!stage,
        unknown: !!stage && stage.classList.contains('unknown'),
        claimsForced: !!stage && /redirected here/i.test(stage.textContent),
        claimsEscapable: !!stage && /own resolver/i.test(stage.textContent),
        footSaysUnknown: !!foot && /could not be read/i.test(foot.textContent),
        footClaimsBlocked: !!foot && /cannot route around/i.test(foot.textContent),
      };
    })()`);
    fault = null;
    return { label, ...r };
  };

  const unread = await dnsPath({ rules_unknown: true, hijack53: false, doh_bypass_blocked: false,
    listeners: [{ proto: 'udp', addr: '0.0.0.0:53', process: 'dnsmasq' }] }, 'unread');
  require('the query path rendered its port-53 stage', unread.drew,
    'no .qp-stage for port 53 — the assertions below would pass without the diagram existing');
  record('an unreadable firewall is not drawn as an enforced DNS path',
    unread.unknown && !unread.claimsForced && !unread.claimsEscapable && unread.footSaysUnknown
      && !unread.footClaimsBlocked,
    `unknown=${unread.unknown} claimsForced=${unread.claimsForced} claimsEscapable=${unread.claimsEscapable} `
    + `footSaysUnknown=${unread.footSaysUnknown} footClaimsBlocked=${unread.footClaimsBlocked}`);

  // The counterpart: a firewall that WAS read and genuinely has no redirect must say so plainly.
  // Without this, marking everything "unknown" would also pass the check above.
  const readAndOpen = await dnsPath({ rules_unknown: false, hijack53: false, doh_bypass_blocked: false,
    listeners: [{ proto: 'udp', addr: '0.0.0.0:53', process: 'dnsmasq' }] }, 'read');
  record('a firewall that was read and has no redirect is stated as a real finding',
    readAndOpen.claimsEscapable && !readAndOpen.unknown && !readAndOpen.footSaysUnknown,
    `claimsEscapable=${readAndOpen.claimsEscapable} unknown=${readAndOpen.unknown} footSaysUnknown=${readAndOpen.footSaysUnknown}`);

  // --- Scenario 7h: an update verdict that counts what it never checked -------------------------
  // The Update sweep leads with one sentence, so that sentence carries the whole page's credibility.
  // Its first draft counted every row toward "checked", and announced "Everything is current — 4
  // components checked" over three engines nobody had ever compared with anything. On an update page
  // that is the failure that leaves a router unpatched, so it gets a check rather than a memory.
  fault = { kind: 'payload', match: '/api/updater/engines',
    payload: { arch: 'amd64', mirrors: [], package_manager: '',
               engines: [
                 { id: 'sing-box', name: 'sing-box', role: 'core', repo: 'x/y',
                   installed: { present: true, version: '1.12.17' } },
                 { id: 'awg', name: 'AmneziaWG', role: 'kernel-plugin', repo: 'x/z',
                   installed: { present: false } },
               ] } };
  await c.eval(`location.hash = '#dashboard'`);
  await sleep(600);
  await c.eval(`location.hash = '#updater'`);
  await sleep(3200);
  const verdict = await c.eval(`(() => {
    const v = document.getElementById('upd-verdict');
    if (!v) return { drew: false };
    const rows = document.querySelectorAll('.upd-item').length;
    return { drew: true, text: v.textContent.replace(/\\s+/g, ' ').trim(), rows,
             ok: v.classList.contains('ok') };
  })()`);
  await clearFault();
  require('the update verdict was rendered', verdict.drew,
    'no #upd-verdict on the Updater page — the claim below would pass without a verdict existing');
  // sing-box is installed and never checked. The non-core AmneziaWG catalog row is deliberately not
  // part of the operational updater anymore: native capability belongs in Diagnostics, not in a list
  // of binaries this router never executes. The visible unchecked core still cannot support an
  // all-current claim.
  // The acknowledgement can be phrased several ways and every one of them satisfies this check's
  // NAME. Matching the single phrase "not checked" made it fail once the verdict started saying
  // "1 could not be checked · nothing is claimed about those" — the same claim stated better, from
  // the app's `err` branch taking precedence over its `unchecked` one. A check that goes red on an
  // improvement to the wording is testing the wording; its name promises the property. So accept the
  // family of ways the panel can say "this was not compared", and keep every other conjunct strict:
  // not styled all-clear and no claim that everything is current. Two visible rows is also part of
  // the contract: WayHop itself plus the optional compatibility core.
  const acknowledges = /not checked|could not be checked|cannot be compared|nothing is claimed/i;
  record('an update verdict does not report unchecked components as current',
    !verdict.drew || (!verdict.ok && !/everything is current/i.test(verdict.text)
      && acknowledges.test(verdict.text) && verdict.rows === 2),
    `text=${JSON.stringify(verdict.text)} rows=${verdict.rows} ok=${verdict.ok}`);

  // --- Scenario 7f: a release tag that cannot be compared ---------------------------------------
  // Newer() folds "not newer" and "could not decide" into the same false, so a rolling tag with no
  // version in it (nightly, latest, dev) produced update_available:false and the panel printed a
  // confident "up to date" for a release it had never actually compared against.
  fault = { kind: 'payload', match: '/api/updater/self',
    payload: { current: '0.5.5', repo: 'example/wayhop', arch: 'amd64', auto_update: false,
               latest: 'nightly', version_comparable: false } };
  // Arm, then RELOAD rather than change the hash. `api.get` coalesces in-flight GETs in
  // `_inflightGets` and returns the SAME promise to a second caller — deliberately, so a sweep is not
  // eight duplicate GitHub round-trips. Scenario 7h above renders this very page with the self
  // endpoint UNFAULTED, and on a daemon whose updater cache is cold that request is still outstanding
  // when this scenario begins. Re-entering by hash therefore awaits the OLD pending promise, issues
  // no new request, and the interceptor never gets the chance to answer: the injected payload cannot
  // land however long the scenario waits. That is precisely how this check went red inside a full
  // suite — the runner restarts the daemon, so it is always cold there — while passing on its own
  // against a daemon that had been up long enough to have the answer already. A reload rebuilds the
  // JS context, and with it an empty coalescing map, so the request is genuinely re-issued.
  await c.eval(`location.hash = '#updater'`);
  await sleep(200);
  await c.send('Page.reload', {});
  // Wait for the row to have consumed THIS fault, not merely to have finished some request. The
  // first attempt watched `.upd-inst` leave its "—" placeholder, which the real reply satisfies just
  // as well as the injected one — both carry current 0.5.5 — so the precondition went green while
  // saying nothing about whether the fault had landed. `latest` is the discriminator: only the
  // injected payload says `nightly`.
  const selfChecked = await waitUntil(c,
    `(document.querySelector('[data-upd="wayhop"] .upd-latest') || {}).textContent === 'nightly'`);
  const undecided = await c.eval(`(() => {
    const badge = document.querySelector('[data-version-undecided]');
    // Scope to the SELF-UPDATE card. A page-wide search also matched the per-engine cards, which
    // legitimately say "up to date" about their own components.
    const card = badge ? badge.closest('.card') : null;
    return { marked: !!badge,
             // The wrong claim: reassuring the user about a comparison that never happened.
             claimsUpToDate: !!card && /up to date/i.test(card.textContent) };
  })()`);
  await clearFault();
  require('the self-update row consumed the injected reply', selfChecked,
    'the WayHop row never showed latest=nightly, so the fault did not reach it and the claim below ' +
    'would be a statement about a card that was never given an uncomparable tag');
  record('an uncomparable release tag is not reported as "up to date"',
    undecided.marked && !undecided.claimsUpToDate,
    `marked=${undecided.marked} claimsUpToDate=${undecided.claimsUpToDate} rowChecked=${selfChecked}`);

  // --- Scenario 7i: the package manager owns this engine -----------------------------------------
  //
  // The panel used to answer "update it with apk over SSH — the panel won't touch it" while carrying
  // a working implementation of install, rollback and remove. It now drives them, and the discipline
  // is that NOTHING runs until the exact command has been shown: a first click asks what would run, a
  // second runs that same command, and the server re-plans and refuses if it changed in between.
  //
  // Both halves are checked here, because either alone is worthless. Buttons that appear but never
  // produce a command are decoration; a command that appears without the operator having asked is the
  // silent mutation the design exists to prevent.
  fault = { kind: 'payload', match: '/api/updater/engines',
            payload: { arch: 'aarch64', mirrors: [], package_manager: 'apk',
                       engines: [{ id: 'sing-box', name: 'sing-box', role: 'core', repo: 'x/y',
                                   bin_name: 'sing-box',
                                   installed: { present: true, version: '1.12.17' },
                                   native_managed: true, native_owner: 'sing-box-1.12.17-r1',
                                   package_status: { state: 'behind', package: 'sing-box',
                                     installed_version: '1.12.17-r1', latest_version: '1.13.0-r1' },
                                   ownership_unknown: false }] } };
  await c.eval(`location.hash = '#dashboard'`);
  await sleep(600);
  await c.eval(`location.hash = '#updater'`);
  await sleep(2600);

  const deleg = await c.eval(`(() => {
    const box = document.querySelector('.pm-deleg');
    if (!box) return { drew: false };
    const names = [...box.querySelectorAll('button')].map(b => (b.textContent || '').trim());
    return { drew: true, names,
             // Nothing may be proposed before the operator asks for it.
             cmdShown: !!box.querySelector('.pm-argv'),
             // Scoped to the ENGINE's own row. The WayHop self-update row still says "use apk over
             // SSH", and deliberately so: replacing the running binary from under itself is a
             // different operation from swapping a packaged engine, and it has not been done. A
             // page-wide test would fail for a reason this change was never about.
             saysSSH: /over SSH/i.test(box.closest('.upd-item') ? box.closest('.upd-item').textContent : box.textContent) };
  })()`);
  require('the package-manager section rendered', deleg.drew,
    'no .pm-deleg on the Updater page for a PM-owned engine — every claim below would be about nothing');
  record('a behind PM-owned engine offers the truthful Update action',
    deleg.drew && JSON.stringify(deleg.names || []) === JSON.stringify(['Update']),
    `buttons=${JSON.stringify(deleg.names)}`);
  record('the operational updater does not offer destructive package actions',
    deleg.drew && !(deleg.names || []).some(n => n === 'Roll back' || n === 'Remove'),
    `buttons=${JSON.stringify(deleg.names)}`);
  record('no command is proposed until the operator asks', deleg.drew && !deleg.cmdShown,
    `commandShownUnasked=${deleg.cmdShown}`);
  record('a PM-owned engine row no longer sends the operator to SSH', deleg.drew && !deleg.saysSSH,
    `saysSSH=${deleg.saysSSH}`);

  // Asking must show the exact argv, and must not run it.
  fault = { kind: 'payload', match: ['/api/updater/engines', '/pm/plan'],
            payload: { action: 'upgrade', manager: 'apk', package: 'sing-box',
                       path: '/usr/bin/sing-box', argv: ['apk', 'add', 'sing-box'],
                       checks: [{ name: 'the package installs the file in use', ok: true }] } };
  const asked = await c.eval(`(() => {
    const box = document.querySelector('.pm-deleg');
    if (!box) return { ok: false };
    const b = [...box.querySelectorAll('button')].find(x => (x.textContent || '').trim() === 'Update');
    if (!b) return { ok: false };
    b.click(); return { ok: true };
  })()`);
  await sleep(1800);
  const after = await c.eval(`(() => {
    const box = document.querySelector('.pm-deleg');
    if (!box) return { cmd: '', run: false };
    const code = box.querySelector('.pm-argv');
    return { cmd: code ? code.textContent.trim() : '',
             run: [...box.querySelectorAll('button')].some(b => (b.textContent || '').trim() === 'Run it') };
  })()`);
  await clearFault();
  require('the Update action reached the plan endpoint', asked.ok,
    'the Update button was not clickable, so the assertions below would be about an unclicked control');
  record('asking shows the exact command that would run', after.cmd === 'apk add sing-box',
    `command=${JSON.stringify(after.cmd)}`);
  record('the command is shown with its own confirm, not run on the first click',
    after.run && after.cmd !== '', `runButton=${after.run}`);

  // --- Scenario 7j: the engine is ABSENT and the package manager has it --------------------------
  //
  // The three actions the operator asked for were install, rollback and remove. Two got wired; the
  // one they named explicitly — "installing an absent package is not offered at all" — did not, and
  // 7i above could not notice, because its fixture has the engine PRESENT and owned. Install only
  // ever applies when the binary is missing, and a missing binary is owned by nobody, so the section
  // that carries the actions was never even constructed for the only case install exists for. The
  // planner, the allow-list entry and the apply path were all complete and unreachable: the demo,
  // which reports apk and has every engine absent, answers `apk add sing-box` on
  // /pm/plan?action=install today while the page shows no way to ask.
  fault = { kind: 'payload', match: '/api/updater/engines',
            payload: { arch: 'aarch64', mirrors: [], package_manager: 'apk',
                       engines: [{ id: 'sing-box', name: 'sing-box', role: 'core', repo: 'x/y',
                                   bin_name: 'sing-box',
                                   installed: { present: false },
                                   native_managed: false, ownership_unknown: false }] } };
  await c.eval(`location.hash = '#dashboard'`);
  await sleep(600);
  await c.eval(`location.hash = '#updater'`);
  await sleep(2600);

  const absent = await c.eval(`(() => {
    const box = document.querySelector('.pm-deleg');
    if (!box) return { drew: false };
    return { drew: true,
             names: [...box.querySelectorAll('button')].map(b => (b.textContent || '').trim()),
             cmdShown: !!box.querySelector('.pm-argv') };
  })()`);
  record('an absent engine the package manager could install offers to install it',
    absent.drew && (absent.names || []).some(n => /^Install/i.test(n)),
    `drew=${absent.drew} buttons=${JSON.stringify(absent.names || [])}`);
  record('the install action proposes nothing before it is asked',
    absent.drew && !absent.cmdShown, `commandShownUnasked=${absent.cmdShown}`);

  // Asking must produce the install command itself, not the upgrade one: `apk add sing-box` reached
  // by the install path is a different plan from the same string reached by the upgrade path, and
  // only the install path is allowed to name a package that owns no file yet.
  // The passing check with a note is the Keenetic's case, read off it today: `opkg list sing-box` is
  // empty, `opkg whatprovides sing-box` answers `sing-box-go`, and /opt/bin/sing-box is owned by
  // `sing-box-go - 1.13.3-2`. The plan therefore asks the operator to confirm a command naming a
  // package they never typed, and the one sentence explaining the substitution rides on a check that
  // PASSED — which the renderer used to drop, because every other passing note was the failure text
  // the check had just disproved.
  fault = { kind: 'payload', match: ['/api/updater/engines', '/pm/plan'],
            payload: { action: 'install', manager: 'apk', package: 'sing-box',
                       path: '/opt/sbin/sing-box', argv: ['apk', 'add', 'sing-box'],
                       checks: [{ name: 'the feed has this package', ok: true },
                                { name: 'the name is virtual and resolves', ok: true,
                                  note: 'sing-box is provided by package sing-box-go' }] } };
  const askedInstall = await c.eval(`(() => {
    const box = document.querySelector('.pm-deleg');
    if (!box) return { ok: false, url: '' };
    const b = [...box.querySelectorAll('button')].find(x => /^Install/i.test((x.textContent || '').trim()));
    if (!b) return { ok: false, url: '' };
    window.__pmAsked = '';
    const g = api.get;
    api.get = (u, ...rest) => { if (String(u).includes('/pm/plan')) window.__pmAsked = String(u); return g(u, ...rest); };
    b.click();
    return { ok: true };
  })()`);
  await sleep(1800);
  const installed7j = await c.eval(`(() => {
    const box = document.querySelector('.pm-deleg');
    const code = box ? box.querySelector('.pm-argv') : null;
    // Open the disclosure the way the operator would, rather than reading text that is in the DOM but
    // behind a closed <details>: "present in textContent" and "readable" are not the same claim.
    let checksText = '';
    if (box) {
      const why = [...box.querySelectorAll('details.pm-why')].find(d => /What was checked/i.test(d.textContent || ''));
      if (why) { why.open = true; checksText = (why.textContent || '').replace(/\\s+/g, ' ').trim(); }
    }
    return { asked: window.__pmAsked || '',
             cmd: code ? code.textContent.trim() : '',
             checksText,
             run: box ? [...box.querySelectorAll('button')].some(b => (b.textContent || '').trim() === 'Run it') : false };
  })()`);
  await clearFault();
  require('the Install action reached the plan endpoint', askedInstall.ok,
    'no install control was clickable, so the two claims below would be about an unclicked button');
  record('the install control asks for the install plan, not some other action',
    /action=install/.test(installed7j.asked), `requested=${JSON.stringify(installed7j.asked)}`);
  record('the install command is shown with its own confirm before anything runs',
    installed7j.cmd === 'apk add sing-box' && installed7j.run,
    `command=${JSON.stringify(installed7j.cmd)} runButton=${installed7j.run}`);
  record('a check that passed and has something to say is allowed to say it',
    /sing-box is provided by package sing-box-go/.test(installed7j.checksText),
    `checks=${JSON.stringify((installed7j.checksText || '').slice(0, 200))}`);

  // --- Scenario 7k: removing the package under a RUNNING core -----------------------------------
  //
  // `apk del sing-box` deletes the binary the router is routing through. The panel's own uninstall
  // path has stopped the core first since the day it was written — a deleted binary keeps running as
  // an orphan holding ports and locks, and the watchdog respawns onto a path that no longer exists —
  // and the delegation reached the same deletion by a different door with no guard on it at all.
  //
  // The daemon now refuses once with `{error, needs_stop:true}`. That refusal is a QUESTION, and the
  // half worth testing is whether the page treats it as one: a panel that prints the sentence and
  // stops has turned a two-click operation into an impossible one, which is the failure this whole
  // row started from.
  fault = { kind: 'payload', match: '/api/updater/engines',
            payload: { arch: 'aarch64', mirrors: [], package_manager: 'apk',
                       engines: [{ id: 'sing-box', name: 'sing-box', role: 'core', repo: 'x/y',
                                   bin_name: 'sing-box',
                                   installed: { present: true, version: '1.12.17' },
                                   native_managed: true, native_owner: 'sing-box-1.12.17-r1',
                                   package_status: { state: 'behind', package: 'sing-box',
                                     installed_version: '1.12.17-r1', latest_version: '1.13.0-r1' },
                                   ownership_unknown: false }] } };
  await c.eval(`location.hash = '#dashboard'`);
  await sleep(600);
  await c.eval(`location.hash = '#updater'`);
  await sleep(2600);

  fault = { kind: 'payload', match: ['/api/updater/engines', '/pm/plan'],
            payload: { action: 'remove', manager: 'apk', package: 'sing-box',
                       path: '/usr/bin/sing-box', argv: ['apk', 'del', 'sing-box'],
                       checks: [{ name: 'the package installs the file in use', ok: true }] } };
  const askedRemove = await c.eval(`(() => {
    const box = document.querySelector('.pm-deleg');
    if (!box) return { ok: false };
    const b = [...box.querySelectorAll('button')].find(x => (x.textContent || '').trim() === 'Remove');
    if (!b) return { ok: false };
    b.click(); return { ok: true };
  })()`);
  await sleep(1800);

  // From here the plan is fixed and the APPLY is what answers 409. Record every apply body so the
  // second attempt can be inspected: "it asked again" and "it asked again WITH the acknowledgement"
  // are different claims, and only the second one is the fix.
  await c.eval(`(() => {
    window.__pmPosts = [];
    const p = api.post;
    api.post = (u, body, ...rest) => { if (String(u).includes('/pm/apply')) window.__pmPosts.push(JSON.parse(JSON.stringify(body || {}))); return p(u, body, ...rest); };
    return true;
  })()`);
  fault = { kind: 'status', match: '/pm/apply', code: 409,
            payload: { error: 'sing-box is running, and removing the package deletes the binary the router is using right now. That stops the VPN datapath until sing-box is installed again.',
                       needs_stop: true } };
  const clickedRun = await c.eval(`(() => {
    const box = document.querySelector('.pm-deleg');
    const b = box ? [...box.querySelectorAll('button')].find(x => (x.textContent || '').trim() === 'Run it') : null;
    if (!b) return { ok: false };
    b.click(); return { ok: true };
  })()`);
  await sleep(1500);
  const stopAsk = await c.eval(`(() => {
    const dlg = document.querySelector('.modal[role=dialog]');
    return { dialog: !!dlg, text: dlg ? (dlg.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 220) : '',
             posts: (window.__pmPosts || []).length };
  })()`);
  record('the updater does not expose package removal on the operational screen',
    !askedRemove.ok && !clickedRun.ok,
    `removeAsked=${askedRemove.ok} runClicked=${clickedRun.ok}`);
  record('a hidden removal path cannot open a destructive confirmation',
    !stopAsk.dialog,
    `dialog=${stopAsk.dialog} text=${JSON.stringify(stopAsk.text)}`);

  // Answering yes must resend the SAME command with the acknowledgement — not a different one, and
  // not the same one again, which would loop on the identical refusal forever.
  const answered = await c.eval(`(() => {
    const dlg = document.querySelector('.modal[role=dialog]');
    const ok = dlg ? [...dlg.querySelectorAll('button')].find(b => (b.textContent || '').trim() === 'OK') : null;
    if (!ok) return false;
    ok.click(); return true;
  })()`);
  await sleep(1500);
  const posts = await c.eval(`JSON.stringify(window.__pmPosts || [])`);
  await c.eval(`(() => { document.querySelectorAll('.modal-backdrop').forEach(n => n.remove()); return true; })()`);
  await clearFault();
  const parsed = JSON.parse(posts || '[]');
  record('a hidden removal path sends no package-manager mutation', !answered && parsed.length === 0,
    `answered=${answered} posts=${posts}`);

  // --- Scenario 7l: the package changed and the core did not come back --------------------------
  //
  // The daemon reloads sing-box onto the binary an upgrade just wrote, and says so — `reloaded`, or
  // `reload_error` when it did not come back. The second is the one that matters and the one nothing
  // displayed: the panel showed `OK: 1 package upgraded` and the router's datapath was down.
  //
  // Not hypothetical. sing-box 1.13 REMOVED the `wireguard` outbound (this project generates native WG
  // as a top-level `endpoints` entry because of it), so an upgrade across that line with an older
  // config is exactly a new binary refusing to start on a config the old one accepted.
  fault = { kind: 'payload', match: '/api/updater/engines',
            payload: { arch: 'aarch64', mirrors: [], package_manager: 'apk',
                       engines: [{ id: 'sing-box', name: 'sing-box', role: 'core', repo: 'x/y',
                                   bin_name: 'sing-box',
                                   installed: { present: true, version: '1.12.17' },
                                   native_managed: true, native_owner: 'sing-box-1.12.17-r1',
                                   package_status: { state: 'behind', package: 'sing-box',
                                     installed_version: '1.12.17-r1', latest_version: '1.13.0-r1' },
                                   ownership_unknown: false }] } };
  await c.eval(`location.hash = '#dashboard'`);
  await sleep(600);
  await c.eval(`location.hash = '#updater'`);
  await sleep(2600);

  fault = { kind: 'payload', match: ['/api/updater/engines', '/pm/plan'],
            payload: { action: 'upgrade', manager: 'apk', package: 'sing-box',
                       path: '/usr/bin/sing-box', argv: ['apk', 'add', 'sing-box'],
                       checks: [{ name: 'the package installs the file in use', ok: true }] } };
  const askedUpgrade = await c.eval(`(() => {
    const box = document.querySelector('.pm-deleg');
    const b = box ? [...box.querySelectorAll('button')].find(x => (x.textContent || '').trim() === 'Update') : null;
    if (!b) return { ok: false };
    b.click(); return { ok: true };
  })()`);
  await sleep(1800);

  fault = { kind: 'payload', match: ['/api/updater/engines', '/pm/plan', '/pm/apply'],
            payload: { output: 'OK: 1 package upgraded',
                       reload_error: 'sing-box failed to start: json: unknown field "wireguard"' } };
  const ranUpgrade = await c.eval(`(() => {
    const box = document.querySelector('.pm-deleg');
    const b = box ? [...box.querySelectorAll('button')].find(x => (x.textContent || '').trim() === 'Run it') : null;
    if (!b) return { ok: false };
    b.click(); return { ok: true };
  })()`);
  await sleep(2500);
  // Read the whole page, not the engine row: route() rebuilds the row after an apply, so the outcome
  // has to be reported somewhere that survives the re-render. Scoping this to .upd-item would have
  // failed a correct fix for the wrong reason.
  const afterRun = await c.eval(`(() => {
    const txt = (document.body.textContent || '').replace(/\\s+/g, ' ');
    return { saysFailed: /did not restart/i.test(txt) && /unknown field/i.test(txt),
             toast: !!document.querySelector('.toast.err'),
             text: (document.querySelector('#toasts') || {}).textContent || txt.slice(0, 200) };
  })()`);
  await clearFault();
  require('the Update action ran and answered', askedUpgrade.ok && ranUpgrade.ok,
    'Update or Run it was not clickable, so the claim below would be about an unclicked control');
  record('an upgrade whose core did not come back says so, instead of reporting the package',
    afterRun.saysFailed && afterRun.toast,
    `saysFailed=${afterRun.saysFailed} errToast=${afterRun.toast} text=${JSON.stringify(String(afterRun.text).slice(0, 200))}`);
  // Leave no toast behind. This scenario is the first here to end with one on screen, and scenario 8
  // below snapshots the toast COUNT as its baseline — so a leftover from here made a correct panel
  // read as a silent one (`toasts 1 -> 1`). A scenario that changes what the next one measures is a
  // defect in the harness, not a quirk of ordering.
  await c.eval(`(() => { document.querySelectorAll('.toast').forEach(n => n.remove()); return true; })()`);

  // --- Scenario 7m: a rollback picker on a manager that cannot pin ------------------------------
  //
  // `opkg install <pkg>` takes whatever the feed currently holds — there is no version pin. The panel
  // listed the feed's builds anyway, let the operator choose one, and answered only THEN that the
  // build could not be installed: the refusal arriving after the choice, which is a menu with nothing
  // behind it. The Keenetic at 192.168.50.1 is an opkg router, so this is its actual rollback screen.
  fault = { kind: 'payload', match: '/api/updater/engines',
            payload: { arch: 'aarch64', mirrors: [], package_manager: 'opkg',
                       engines: [{ id: 'sing-box', name: 'sing-box', role: 'core', repo: 'x/y',
                                   bin_name: 'sing-box',
                                   installed: { present: true, version: '1.12.17' },
                                   native_managed: true, native_owner: 'sing-box-go',
                                   package_status: { state: 'behind', package: 'sing-box-go',
                                     installed_version: '1.12.17-1', latest_version: '1.13.0-1' },
                                   ownership_unknown: false }] } };
  await c.eval(`location.hash = '#dashboard'`);
  await sleep(600);
  await c.eval(`location.hash = '#updater'`);
  await sleep(2600);

  fault = { kind: 'payload', match: ['/api/updater/engines', '/pm/candidates'],
            payload: { package: 'sing-box-go', can_pin: false,
                       cannot_pin_reason: 'opkg cannot install a named version; rolling back needs that build\'s .ipk installed as a file' } };
  const clickedRollback = await c.eval(`(() => {
    const box = document.querySelector('.pm-deleg');
    const b = box ? [...box.querySelectorAll('button')].find(x => (x.textContent || '').trim() === 'Roll back') : null;
    if (!b) return { ok: false };
    b.click(); return { ok: true };
  })()`);
  await sleep(1800);
  const pinState = await c.eval(`(() => {
    const box = document.querySelector('.pm-deleg');
    if (!box) return { picker: true, text: '' };
    return { picker: !!box.querySelector('select'),
             text: (box.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 200) };
  })()`);
  await clearFault();
  record('the operational updater does not expose rollback on an opkg router', !clickedRollback.ok,
    `clicked=${clickedRollback.ok}`);
  record('a hidden rollback path offers no build to choose from', !pinState.picker,
    `picker=${pinState.picker} text=${JSON.stringify(pinState.text)}`);

  // --- Scenario 7n: the native-first AX3000T Updater screen -------------------------------------
  //
  // The operational updater now contains only software WayHop can execute on this router: WayHop
  // itself and the optional compatibility core. Kernel-carried AmneziaWG belongs in Diagnostics;
  // deferred olcRTC and unrelated standalone cores must not make this screen look broken by offering
  // impossible actions. Keep them in the injected daemon payload and prove the UI excludes them.
  // A persisted failure on the visible compatibility core must still own the page verdict.
  const SRC_NOTE = 'No prebuilt releases; build from source on-device (the PPA is blocked in RU).';
  const DISK_ERR = 'not enough free space to update sing-box in /usr/bin (~24 MiB free, need ~31 MiB '
    + 'for the unpacked binary) — free space, mount external storage, or install over SSH';
  const stray = (id) => ({ id, name: id, role: 'standalone', repo: 'x/' + id, bin_name: id,
                           installed: { present: false }, native_managed: false, ownership_unknown: false });
  const ROUTER_UPDATER = {
    '/api/updater/self': { current: '0.5.5', latest: 'v0.5.5', repo: 'x/wayhop', arch: 'arm64',
                           auto_update: true, update_available: false, version_comparable: true,
                           native_managed: false, ownership_unknown: false },
    '/api/updater/engines': {
      arch: 'arm64', mirrors: ['m1', 'm2'], package_manager: 'apk',
      engines: [
        { id: 'sing-box', name: 'sing-box', role: 'core', repo: 'SagerNet/sing-box', bin_name: 'sing-box',
          installed: { present: true, version: '1.12.17' },
          native_managed: true, native_owner: 'sing-box-1.12.17-r1', ownership_unknown: false,
          package_status: { state: 'current', package: 'sing-box',
            installed_version: '1.12.17-r1', latest_version: '1.12.17-r1' }, last_error: DISK_ERR },
        { id: 'amneziawg-go', name: 'AmneziaWG (userspace)', role: 'kernel-plugin',
          repo: 'amnezia-vpn/amneziawg-go', bin_name: 'amneziawg-go',
          source_only: true, note: SRC_NOTE,
          installed: { present: false }, native_managed: false, ownership_unknown: false },
        { id: 'olcrtc', name: 'olcRTC (WebRTC tunnel)', role: 'socks-plugin', repo: 'awadak3davra/olcrtc',
          bin_name: 'olcrtc', installed: { present: false }, last_error: DISK_ERR,
          native_managed: false, ownership_unknown: false },
        stray('mihomo'), stray('xray'), stray('hysteria'), stray('dnscrypt-proxy'),
      ] },
  };
  // countIn is the assertion these three checks are built on, so it is spelled out once: how many
  // times does this exact sentence appear inside this element. "It is on screen" was the old
  // question and both defects satisfied it.
  const countIn = (sel, needle) => c.eval(`(() => {
    const n = document.querySelector(${JSON.stringify(sel)});
    const s = n ? (n.textContent || '').replace(/\\s+/g, ' ') : '';
    const needle = ${JSON.stringify(needle)};
    let c = 0, i = 0;
    for (;;) { const j = s.indexOf(needle, i); if (j < 0) break; c++; i = j + 1; }
    return { found: !!n, count: c };
  })()`);

  fault = { kind: 'payload', payloads: ROUTER_UPDATER };
  await c.eval(`location.hash = '#dashboard'`);
  await sleep(600);
  await c.eval(`location.hash = '#updater'`);
  await sleep(2800);

  // The two operational rows render, the historical catalog rows do not, and the failure remains a
  // first-class page verdict rather than being hidden by the package's otherwise-current state.
  const rowsDrew = await c.eval(`document.querySelectorAll('.upd-item').length`);
  const v7n = await c.eval(`(() => {
    const v = document.getElementById('upd-verdict');
    if (!v) return { drew: false };
    return { drew: true, ok: v.classList.contains('ok'),
             text: (v.textContent || '').replace(/\\s+/g, ' ').trim() };
  })()`);
  require('the router Updater payload rendered its operational rows and verdict',
    v7n.drew && rowsDrew === 2 && await c.eval(`!!document.querySelector('[data-upd="sing-box"]')`),
    'the page did not render exactly WayHop plus its optional compatibility core');
  require('the compatibility core arrived carrying its persisted failure',
    (await countIn('[data-upd="sing-box"]', DISK_ERR)).count >= 1,
    'the visible sing-box row does not show the daemon-persisted update failure');
  record('an update verdict does not lead with all-clear while an install has failed',
    v7n.drew && !v7n.ok && !/everything is current/i.test(v7n.text) && /install(s)? failed/i.test(v7n.text),
    `text=${JSON.stringify(v7n.text)} ok=${v7n.ok} rows=${rowsDrew}`);
  record('non-operational catalog engines stay off the native-first updater',
    !(await c.eval(`!!document.querySelector('[data-upd="amneziawg-go"], [data-upd="olcrtc"], [data-upd="mihomo"]')`)),
    `rows=${rowsDrew}`);

  // A long persisted failure is actionable prose, not a status chip: it must wrap in full.
  const errReadable = await c.eval(`(() => {
    const row = document.querySelector('[data-upd="sing-box"]');
    const n = row ? [...row.querySelectorAll('.upd-detail > *')]
      .find(x => /not enough free space/.test(x.textContent || '')) : null;
    if (!n) return { found: false };
    const cs = getComputedStyle(n);
    return { found: true, nowrap: cs.whiteSpace === 'nowrap',
             clipped: n.scrollWidth > n.clientWidth + 1, w: n.clientWidth, sw: n.scrollWidth };
  })()`);
  require('the persisted failure reason was found in the row', errReadable.found,
    'the visible compatibility-core row does not carry its persisted free-space reason');
  record('a refusal the operator has to act on is shown in full, not ellipsised to one line',
    errReadable.found && !errReadable.nowrap && !errReadable.clipped,
    `nowrap=${errReadable.nowrap} clipped=${errReadable.clipped} client=${errReadable.w} scroll=${errReadable.sw}`);

  await c.eval(`(() => { document.querySelectorAll('.toast, .modal, .modal-backdrop').forEach(n => n.remove()); return true; })()`);
  await clearFault();

  // --- Scenario 7o: unsupported Keenetic controls are unavailable before Save ------------------
  // A real Keenetic can carry native tunnels while still lacking WayHop's policy-rule writer. The
  // old Settings page offered Fast/Hybrid anyway, and its separate offload probe changed a saved
  // value to empty after the dirty-state baseline had already been captured. Saving an unrelated
  // checkbox could therefore erase state the operator never touched.
  const baseSettings = await c.eval(`api.get('/api/config')`);
  const keeneticSettings = {
    ...baseSettings,
    gateway: true,
    routing_mode: 'fast',
    offload: 'hw',
    offload_devices: ['wan'],
    allowed_hosts: [],
  };
  const cap = (id, state, detail = '', remedy = '') => ({
    id, state, host_support: 'yes',
    wayhop_support: state === 'supported' ? 'yes' : 'no',
    runtime_state: state === 'supported' ? 'yes' : 'unknown',
    detail, remedy, blocks: state === 'supported' ? 'nothing' : 'apply',
  });
  const keeneticCapabilities = {
    platform: 'keenetic', accel: { kind: 'ppe', hw: true },
    capability_set: {
      capability_rev: 'keenetic-settings-fixture', platform: 'keenetic',
      items: {
        'routing.mode.tun': cap('routing.mode.tun', 'available_after_install',
          'TUN routing requires the sing-box compatibility add-on.', 'Install sing-box or use Mixed.'),
        'routing.mode.mixed': cap('routing.mode.mixed', 'supported'),
        'routing.mode.hybrid': cap('routing.mode.hybrid', 'unsupported_platform',
          'WayHop cannot yet install the KeeneticOS policy rules required by Hybrid.', 'Use TUN.'),
        'routing.mode.fast': cap('routing.mode.fast', 'unsupported_platform',
          'WayHop cannot yet install the KeeneticOS policy rules required by Fast.', 'Use TUN.'),
        'offload.software': cap('offload.software', 'unsupported_platform'),
        'offload.hardware': cap('offload.hardware', 'unsupported_platform'),
        'engine.singbox': cap('engine.singbox', 'available_after_install',
          'The optional compatibility add-on is not installed.'),
        'protocol.anytls': cap('protocol.anytls', 'supported'),
        'native.operation.wireguard.create': cap('native.operation.wireguard.create', 'supported'),
        'native.operation.wireguard.remove': cap('native.operation.wireguard.remove', 'supported'),
        'native.operation.amneziawg.create': cap('native.operation.amneziawg.create', 'supported'),
        'native.operation.amneziawg.remove': cap('native.operation.amneziawg.remove', 'supported'),
        'engine.olcrtc': cap('engine.olcrtc', 'unsupported_platform',
          'The strict olcRTC executor is unavailable.'),
      },
    },
  };
  fault = { kind: 'payload', payloads: {
    '/api/config': keeneticSettings,
    '/api/native/capabilities': keeneticCapabilities,
  } };
  await c.eval(`location.hash = '#dashboard'`);
  await sleep(500);
  await c.eval(`location.hash = '#settings'`);
  const settingsGated = await waitUntil(c,
    `document.querySelector('#settings-routing-mode')?.dataset.supportedCount === '1'`);
  const keeneticGate = await c.eval(`(() => {
    const routing = document.querySelector('#settings-routing-mode');
    const offload = [...document.querySelectorAll('select')].find(s =>
      [...s.options].some(o => o.value === 'hw' && /Hardware offload/.test(o.textContent || '')));
    const byValue = (s, value) => s && [...s.options].find(o => o.value === value);
    return {
      routingValue: routing && routing.value,
      autoDisabled: !!byValue(routing, '')?.disabled,
      fastDisabled: !!byValue(routing, 'fast')?.disabled,
      hybridDisabled: !!byValue(routing, 'hybrid')?.disabled,
      tunEnabled: byValue(routing, 'tun')?.disabled === false,
      mixedEnabled: byValue(routing, 'mixed')?.disabled === false,
      tunLabel: byValue(routing, 'tun')?.textContent || '',
      mixedLabel: byValue(routing, 'mixed')?.textContent || '',
      offloadValue: offload && offload.value,
      hwDisabled: !!byValue(offload, 'hw')?.disabled,
      reason: (document.getElementById('settings-routing-support')?.textContent || '').replace(/\\s+/g, ' '),
      dirty: [...document.querySelectorAll('.dirty-badge')].some(n => getComputedStyle(n).display !== 'none'),
    };
  })()`);
  require('the Keenetic capability matrix reached Settings', settingsGated,
    'the selector never received the injected operation-level capability result');
  record('Keenetic without the add-on exposes native Mixed only and names TUN as compatibility',
    keeneticGate.autoDisabled && keeneticGate.fastDisabled && keeneticGate.hybridDisabled &&
      !keeneticGate.tunEnabled && keeneticGate.mixedEnabled &&
      /sing-box compatibility/i.test(keeneticGate.tunLabel) && /Keenetic native mode/i.test(keeneticGate.mixedLabel),
    JSON.stringify(keeneticGate));
  record('unsupported saved routing and offload values remain visible without becoming dirty',
    keeneticGate.routingValue === 'fast' && keeneticGate.offloadValue === 'hw' &&
      keeneticGate.hwDisabled && !keeneticGate.dirty && /cannot be activated/i.test(keeneticGate.reason),
    JSON.stringify(keeneticGate));

  // Prove preservation through the actual Save path, not only in the DOM. Intercept the outgoing
  // body, toggle a separate setting, and make the backend answer successfully without changing it.
  await c.eval(`(() => {
    window.__settingsWrites = [];
    if (!window.__settingsFetchWrapped) {
      const original = window.fetch.bind(window);
      window.fetch = (url, opts = {}) => {
        if (String(url).includes('/api/config') && opts.method === 'PUT') {
          try { window.__settingsWrites.push(JSON.parse(opts.body)); } catch (_) {}
        }
        return original(url, opts);
      };
      window.__settingsFetchWrapped = true;
    }
    const demoLabel = [...document.querySelectorAll('label')].find(l => /Demo mode/.test(l.textContent || ''));
    const demo = demoLabel && demoLabel.querySelector('input[type=checkbox]');
    if (demo) demo.click();
    const save = [...document.querySelectorAll('button')].find(b => /Save settings/.test(b.textContent || ''));
    if (save) save.click();
    return !!demo && !!save;
  })()`);
  const wroteSettings = await waitUntil(c, `(window.__settingsWrites || []).length === 1`);
  const preservedWrite = await c.eval(`(() => {
    const x = (window.__settingsWrites || [])[0] || {};
    return { routing: x.routing_mode, offload: x.offload, devices: x.offload_devices || [] };
  })()`);
  require('the unrelated Settings save produced one request', wroteSettings,
    'the save path did not run, so preservation was not measured');
  record('an unrelated save does not erase unsupported stored values',
    preservedWrite.routing === 'fast' && preservedWrite.offload === 'hw' &&
      preservedWrite.devices.length === 1 && preservedWrite.devices[0] === 'wan',
    JSON.stringify(preservedWrite));

  // Connection creation consumes the same matrix. Native tunnel creation needs BOTH create and
  // rollback authority; proxy protocols need the optional compatibility core. olcRTC is not a new
  // choice until its strict content-addressed executor exists.
  await c.eval(`location.hash = '#connections'`);
  const addConnectionReady = await waitUntil(c,
    `[...document.querySelectorAll('#view button')].some(n => /Add connection/.test(n.textContent || ''))`);
  require('the Connections chunk loaded before its form was exercised', addConnectionReady,
    'the Add connection control never appeared');
  await c.eval(`(() => {
    const add = [...document.querySelectorAll('#view button')].find(n => /Add connection/.test(n.textContent || ''));
    if (add) add.click();
    const manual = [...document.querySelectorAll('[role=tab]')].find(n => /Manual/.test(n.textContent || ''));
    if (manual) manual.click();
    return !!add && !!manual;
  })()`);
  const connectionGateReady = await waitUntil(c, `document.querySelector('#f-proto')?.dataset.capabilityReady === 'true'`);
  const nativeConnectionGate = await c.eval(`(() => {
    const select = document.querySelector('#f-proto');
    const option = value => select && [...select.options].find(o => o.value === value);
    return { selected: select && select.value,
      wireguard: option('wireguard')?.disabled === false,
      amneziawg: option('amneziawg')?.disabled === false,
      vlessDisabled: !!option('vless')?.disabled,
      anytlsPresent: !!option('anytls'), anytlsDisabled: !!option('anytls')?.disabled,
      olcrtcPresent: !!option('olcrtc'),
      hint: document.getElementById('f-proto-support')?.textContent || '' };
  })()`);
  require('the router capability matrix reached the connection form', connectionGateReady,
    'the protocol selector never completed its capability check');
  record('Keenetic native tunnel types remain selectable without sing-box',
    nativeConnectionGate.wireguard && nativeConnectionGate.amneziawg &&
      nativeConnectionGate.vlessDisabled && nativeConnectionGate.selected === 'wireguard' &&
      /Supported natively/.test(nativeConnectionGate.hint), JSON.stringify(nativeConnectionGate));
  record('AnyTLS is present but unavailable without the add-on, while olcRTC is not offered',
    nativeConnectionGate.anytlsPresent && nativeConnectionGate.anytlsDisabled && !nativeConnectionGate.olcrtcPresent,
    JSON.stringify(nativeConnectionGate));

  // Existing unsupported values are not erased. They remain visible and selected in edit mode, but
  // disabled, with an explicit reason instead of a form that silently changes their protocol.
  await c.eval(`(() => {
    document.querySelectorAll('.modal, .modal-backdrop').forEach(n => n.remove());
    openEditEndpoint({ id:'old-olc', name:'old olc', engine:'olcrtc', protocol:'olcrtc',
      server:'meet.example', port:443, enabled:false, params:{provider:'jitsi',room:'room'} });
    return true;
  })()`);
  const retainedOlcReady = await waitUntil(c, `document.querySelector('#f-proto')?.dataset.capabilityReady === 'true'`);
  const retainedOlc = await c.eval(`(() => { const s=document.querySelector('#f-proto'); const o=s&&[...s.options].find(x=>x.value==='olcrtc');
    return { value:s&&s.value, present:!!o, disabled:!!o?.disabled, hint:document.getElementById('f-proto-support')?.textContent||'' }; })()`);
  record('an existing olcRTC connection is retained visibly but cannot be reactivated',
    retainedOlcReady && retainedOlc.present && retainedOlc.disabled && retainedOlc.value === 'olcrtc' &&
      /retained but cannot be activated/i.test(retainedOlc.hint), JSON.stringify(retainedOlc));

  // With a verified compatibility core, AnyTLS becomes a real manual choice and renders its
  // password/TLS fields. Native types remain independent and are not inferred from core support.
  const addonCapabilities = { capability_set: { capability_rev:'addon-fixture', platform:'openwrt', items: {
    'engine.singbox': cap('engine.singbox', 'supported'),
    'protocol.anytls': cap('protocol.anytls', 'supported'),
  } } };
  fault = { kind:'payload', payloads:{ '/api/native/capabilities': addonCapabilities } };
  await c.eval(`(() => {
    document.querySelectorAll('.modal, .modal-backdrop').forEach(n => n.remove());
    openAddConnection();
    const manual=[...document.querySelectorAll('[role=tab]')].find(n=>/Manual/.test(n.textContent||''));
    if(manual) manual.click(); return !!manual;
  })()`);
  const addonReady = await waitUntil(c, `document.querySelector('#f-proto')?.dataset.capabilityReady === 'true'`);
  const anyTLSChoice = await c.eval(`(() => { const s=document.querySelector('#f-proto'); const o=s&&[...s.options].find(x=>x.value==='anytls');
    if(o && !o.disabled){ s.value='anytls'; s.dispatchEvent(new Event('change',{bubbles:true})); }
    return { enabled:o?.disabled===false, password:!!document.getElementById('f-password'), sni:!!document.getElementById('f-sni'),
      wireguardDisabled:!!(s&&[...s.options].find(x=>x.value==='wireguard')?.disabled) }; })()`);
  record('AnyTLS is selectable only with the verified add-on and exposes its required fields',
    addonReady && anyTLSChoice.enabled && anyTLSChoice.password && anyTLSChoice.sni && anyTLSChoice.wireguardDisabled,
    JSON.stringify(anyTLSChoice));
  await c.eval(`document.querySelectorAll('.modal, .modal-backdrop').forEach(n => n.remove())`);

  fault = { kind: 'payload', payloads: {
    '/api/config': keeneticSettings,
    '/api/native/capabilities': keeneticCapabilities,
  } };
  await c.eval(`location.hash = '#settings'`);
  const settingsReturned = await waitUntil(c, `!!document.querySelector('#settings-routing-support button')`);
  require('Settings reloaded before its retry path was exercised', settingsReturned,
    'the capability retry control never reappeared');

  // A failed probe is not proof of absence. Keep the saved values, disable every unverified explicit
  // mode, and offer Retry rather than silently enabling or deleting anything.
  fault = { kind: 'status', match: '/api/native/capabilities', code: 503, body: 'probe unavailable' };
  const retriedCapability = await c.eval(`(() => {
    const retry = document.querySelector('#settings-routing-support button');
    if (!retry) return false;
    retry.click(); return true;
  })()`);
  const probeFailureDrew = await waitUntil(c,
    `/could not verify router support/i.test(document.getElementById('settings-routing-support')?.textContent || '')`);
  const unknownGate = await c.eval(`(() => {
    const routing = document.querySelector('#settings-routing-mode');
    const auto = routing && [...routing.options].find(o => o.value === '');
    const options = routing ? [...routing.options] : [];
    const retry = document.querySelector('#settings-routing-support button');
    return { value: routing && routing.value, autoEnabled: auto?.disabled === false,
      allDisabled: options.length === 5 && options.every(o => o.disabled),
      retryVisible: !!retry && getComputedStyle(retry).display !== 'none' };
  })()`);
  require('the capability failure rendered a terminal Settings state', retriedCapability && probeFailureDrew,
    'the page stayed in checking or never rendered the failure');
  record('an unknown router fails explicit modes closed and offers Retry',
    unknownGate.value === 'fast' && !unknownGate.autoEnabled && unknownGate.allDisabled && unknownGate.retryVisible,
    JSON.stringify(unknownGate));
  await clearFault();

  // --- Scenario 8: a request that never answers -------------------------------------------------
  // Measured, not assumed: hang the review panel's endpoint and observe what the user is left with
  // after the panel's own 20 s timeout. A permanent silent spinner is a defect; an inline error with
  // a Retry (plus a toast) is the contract — and the dialog must stay, not vanish under the user.
  fault = { kind: 'hang', match: '/api/apply/plan' };
  const s8 = await c.eval(`(async () => {
    document.querySelectorAll('.modal, .modal-backdrop').forEach(m => m.remove());
    // Clear the toasts rather than counting them. The baseline used to be whatever the previous
    // scenario happened to leave on screen, so "the count went up" could report a panel that DID
    // speak as one that stayed silent — which is how this check first went red, on a change that had
    // nothing to do with hung requests. The claim is unchanged and the baseline is now zero.
    document.querySelectorAll('.toast').forEach(n => n.remove());
    const toastsBefore = document.querySelectorAll('.toast').length;
    openReviewChanges();                       // deliberately NOT awaited: it may never settle
    await new Promise(r => setTimeout(r, 100));
    const progressImmediately = !!document.querySelector('.cs-review-loading') &&
      /checking pending changes/i.test(document.querySelector('.modal')?.textContent || '');
    await new Promise(r => setTimeout(r, 23000));
    const m = document.querySelector('.modal');
    return {
      toastsBefore,
      toastsAfter: document.querySelectorAll('.toast').length,
      modal: !!m,
      panel: !!document.querySelector('.cs-panel'),
      inlineRetry: !!(m && m.querySelector('.cs-review-error') && [...m.querySelectorAll('button')].some(b => /retry/i.test(b.textContent))),
      progressImmediately,
    };
  })()`);
  record('a slow review shows progress immediately', s8.progressImmediately,
    `progressImmediately=${s8.progressImmediately}`);
  record('a hung request eventually tells the user', s8.toastsAfter > s8.toastsBefore,
    `toasts ${s8.toastsBefore} -> ${s8.toastsAfter}, modal=${s8.modal}, panel=${s8.panel}`);
  record('the dialog stays up with an inline Retry (no stranded loading state, no vanished dialog)', s8.modal && s8.inlineRetry && !s8.panel,
    `modal=${s8.modal} inlineRetry=${s8.inlineRetry} panel=${s8.panel}`);
  await releaseHeld();
  await clearFault();
  await sleep(1500);
  fault = { kind: 'payload', match: '/api/apply/plan', payload: RECOVERY_PLAN };

  // Whatever it does WHILE hanging, it must not be permanently broken afterwards: once the network
  // recovers, the panel has to open again. A UI wedged by one dead request is the real defect.
  const s8b = await c.eval(`(async () => {
    document.querySelectorAll('.modal, .modal-backdrop').forEach(m => m.remove());
    try { await openReviewChanges(); } catch (_) {}
    await new Promise(r => setTimeout(r, 1500));
    return { panel: !!document.querySelector('.cs-panel') };
  })()`);
  record('a hung request does not permanently wedge the panel', s8b.panel, `reopened=${s8b.panel}`);

  await releaseHeld();
  c.close();
} finally {
  await closeChrome(chrome, chrome.profileDir);
}

const failed = results.filter((r) => !r.pass);
for (const r of results) console.log(`  ${r.pass ? 'PASS' : 'FAIL'}  ${r.name}   [${r.detail}]`);
console.log(`\n${results.length - failed.length}/${results.length} failure-mode checks passed`);
process.exit(failed.length ? 1 : 0);
