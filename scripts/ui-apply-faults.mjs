// ui-apply-faults.mjs — fault injection on the APPLY path (§3).
//
// Apply is the one action with real consequences, and the spec's central rule is that the UI must
// never report "Applied" unless the server said applied:true. That rule is only meaningful if Apply
// fails, so this breaks it deliberately — every answer the new contract can give (docs/APPLY_REDESIGN.md in the development repository):
// a bare 5xx, an unverifiable 200, 409 REV_STALE (with the current plan), 409 ACK_REQUIRED, 422 BLOCKED,
// 400 INVALID_CONFIG, 500 APPLY_FAILED, 503 BUSY, a POST that never answers, and a double-click. The
// fail-safe window gets the same treatment: a failed Keep or Roll back must never look like a completed one.
//
// It must be pointed at a DISPOSABLE instance — a demo-mode daemon on a scratch data dir — never at
// a live router. Applying to a real box under injected faults would be a genuinely destructive test.
//
// Usage: node scripts/ui-apply-faults.mjs http://127.0.0.1:8096/
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

const URL_ARG = process.argv[2] || 'http://127.0.0.1:8096/';
const PORT = Number(process.env.CDP_PORT || 9466);
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';

if (!/127\.0\.0\.1|localhost/.test(URL_ARG)) {
  console.error(`refusing to run against ${URL_ARG}: apply fault injection is for a local disposable instance only`);
  process.exit(2);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const httpJSON = async (u) => (await fetch(u)).json();

async function startChrome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wayhop-apply-'));
  const child = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
    '--disable-extensions', '--disable-background-networking',
    `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`, '--window-size=1280,900', 'about:blank'],
    { stdio: 'ignore' });
  child.profileDir = dir; // the caller owns the kill, so it needs the path too
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
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const myId = ++id;
    const _to = setTimeout(() => { waiting.delete(myId); reject(new Error(`CDP ${method} got no reply in 30000ms`)); }, 30000);
    waiting.set(myId, (_m) => { clearTimeout(_to); ((m) => (m.error ? reject(new Error(m.error.message)) : resolve(m.result)))(_m); });
    ws.send(JSON.stringify({ id: myId, method, params }));
  });
  return {
    send, close: () => ws.close(), on: (h) => handlers.push(h),
    async eval(expr) {
      const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
      if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || 'eval failed');
      return r.result.value;
    },
  };
}

const results = [];
const record = (name, pass, detail) => results.push({ name, pass, detail });

// The fail-safe window reads the same toasts, but it needs their SEVERITY, not just their text.
//
// What stood here was `toasts.length > 0` under the name "tells the user" — that something, anything,
// was said. The section that uses it states the danger in its own header: a failed confirm must not
// leave the user believing they are safe. A toast reading "Kept & committed" is something; it is also
// exactly the outcome that has to fail. So the old measurement passed hardest in the one case it
// existed to catch, and would have passed on a panel that reported every failed confirm as a success.
//
// Severity rather than wording, deliberately. The failure path toasts the SERVER's message
// (`toast(t("Rollback failed: {0}", e.message), "err")` in failsafeKeep / failsafeRollback), which
// can say anything at all — today it happens to read "injected apply failure" and matching on words
// like "fail" would go red on a rephrase and green on a silent success claim. The `err` class is the
// PANEL's own statement that this went wrong, which is the thing the check is actually about.
const FAILSAFE_OBSERVE = `(() => {
  const b = document.querySelector('#failsafe-banner');
  return { shown: !!b && b.offsetParent !== null,
           text: b ? b.textContent.replace(/\\s+/g, ' ').trim().slice(0, 200) : null,
           buttons: b ? [...b.querySelectorAll('button')].map(x => x.textContent.trim()) : [],
           toasts: [...document.querySelectorAll('.toast')].map(n => ({
             text: n.textContent.trim(), err: n.classList.contains('err') })) };
})()`;
// The success wordings of the two actions, from app.js: "Kept & committed" and "Rolled back to
// previous config". Either one appearing after a 500 means the user was told the opposite of the truth.
const SUCCESS_CLAIM = /kept|committed|rolled back/i;
const toldOfFailure = (toasts) =>
  toasts.some((x) => x.err) && !toasts.some((x) => SUCCESS_CLAIM.test(x.text));
const fmtToasts = (toasts) =>
  `toasts=${JSON.stringify(toasts.map((x) => (x.err ? '[err] ' : '[ok] ') + x.text))}`;

// Reads what the user can actually see: the toasts, the inline apply error, the review panel, and
// whether the button has recovered. "Applied" claimed in a toast is the assertion that matters most.
const OBSERVE = `(() => {
  const toastNodes = [...document.querySelectorAll('.toast')];
  const toasts = toastNodes.map(n => n.textContent.trim());
  const btn = document.querySelector('#applybtn');
  const err = document.querySelector('#apply-error');
  const banner = document.querySelector('#apply-banner');
  const panel = document.querySelector('.cs-panel');
  return {
    toasts,
    errToast: toastNodes.some(n => n.classList.contains('err')),
    okToast: toastNodes.some(n => n.classList.contains('ok')),
    claimsApplied: toasts.some(x => /^applied\\b|applied live|applied & saved|applied and saved/i.test(x)),
    saysProblem: toasts.some(x => /problem|attention|fail|reject|busy|did not answer/i.test(x)),
    // #apply-error is hyphenated and is toggled via display, so presence alone proves nothing —
    // the box exists in the markup at all times. offsetParent is null while it is display:none.
    errorShown: !!err && err.offsetParent !== null && err.textContent.trim().length > 0,
    errorText: err ? err.textContent.replace(/\\s+/g, ' ').trim().slice(0, 240) : null,
    errorButtons: err ? [...err.querySelectorAll('button')].map(b => b.textContent.trim()) : [],
    errorHasPre: !!(err && err.querySelector('pre')),
    bannerText: banner && !banner.hidden ? banner.textContent.replace(/\\s+/g, ' ').trim().slice(0, 200) : null,
    bannerClass: banner ? banner.className : null,
    panel: !!panel,
    panelNotice: panel && panel.querySelector('.cs-notice') ? panel.querySelector('.cs-notice').textContent.trim().slice(0, 160) : null,
    preflightClass: panel && panel.querySelector('.cs-preflight') ? panel.querySelector('.cs-preflight').className : null,
    preflightText: panel && panel.querySelector('.cs-preflight') ? panel.querySelector('.cs-preflight').textContent.replace(/\\s+/g, ' ').trim().slice(0, 240) : null,
    ackBoxes: document.querySelectorAll('.cs-preflight-ack input[type=checkbox]').length,
    ackFocused: !!(document.activeElement && document.activeElement.matches && document.activeElement.matches('.cs-preflight-ack input')),
    footerDisabled: [...document.querySelectorAll('.cs-footer .btn')].filter(b => /test safely|apply & save/i.test(b.textContent)).map(b => b.getAttribute('aria-disabled')),
    btnDisabled: btn ? btn.hasAttribute('disabled') : null,
    btnBusy: btn ? btn.getAttribute('aria-busy') : null,
  };
})()`;

const chrome = await startChrome();
try {
  const targets = await httpJSON(`http://127.0.0.1:${PORT}/json/list`);
  const c = await connect((targets.find((t) => t.type === 'page') || targets[0]).webSocketDebuggerUrl);
  await c.send('Page.enable');
  await c.send('Runtime.enable');

  let faults = [];                       // longest `match` wins; see pickFault
  const setFault = (f) => { faults = f ? (Array.isArray(f) ? f : [f]) : []; };
  const pickFault = (url) => faults
    .filter((f) => url.includes(f.match))
    .sort((a, b) => b.match.length - a.match.length)[0] || null;
  let applyPosts = 0;
  let lastApplyPayload = null;
  const held = [];
  const releaseHeld = async () => {
    while (held.length) {
      try { await c.send('Fetch.continueRequest', { requestId: held.pop() }); } catch { /* gone */ }
    }
  };

  await c.send('Fetch.enable', { patterns: [{ urlPattern: '*/api/*' }] });
  c.on(async (m) => {
    if (m.method !== 'Fetch.requestPaused') return;
    const { requestId, request } = m.params;
    try {
      // Count only the apply POST itself, not the status polls that follow it.
      if (/\/api\/apply$/.test(new URL(request.url).pathname) && request.method === 'POST') {
        applyPosts++;
        try { lastApplyPayload = JSON.parse(request.postData || '{}'); } catch { lastApplyPayload = null; }
      }
      const fault = pickFault(request.url);
      if (fault) {
        if (fault.kind === 'hang') { held.push(requestId); return; }
        if (fault.kind === 'status' || fault.kind === 'payload') {
          await c.send('Fetch.fulfillRequest', {
            requestId, responseCode: fault.code || 200,
            responseHeaders: [{ name: 'Content-Type', value: 'application/json' }],
            body: Buffer.from(JSON.stringify(fault.payload || { error: 'injected apply failure' })).toString('base64'),
          });
          return;
        }
      }
      await c.send('Fetch.continueRequest', { requestId });
    } catch { /* request already gone */ }
  });

  await c.send('Page.navigate', { url: URL_ARG });
  let ready = false;
  for (let i = 0; i < 120; i++) {
    if (await c.eval('typeof applyConfig === "function"').catch(() => false)) { ready = true; break; }
    await sleep(250);
  }
  if (!ready) throw new Error('app.js did not finish loading: applyConfig never became defined');
  await authenticateCDP({
    send: (method, params) => c.send(method, params), evaluate: expression => c.eval(expression),
    url: URL_ARG, readyExpression: 'typeof applyConfig === "function"',
  });
  await sleep(1500);

  const REV = 'a'.repeat(64);
  const clearToasts = `document.querySelectorAll('.toast').forEach(n => n.remove())`;
  const closePanels = `document.querySelectorAll('.modal, .modal-backdrop').forEach(m => m.remove()); hideApplyError();`;
  // The plan the panel would have shown: the ONLY thing Apply is pinned to is its rev; the ticked
  // acknowledgements ride along as `ack`. Seeded straight into the module state the panel writes.
  const PLAN = {
    rev: REV, pending: true, nothing_configured: false, applied_rev: 'b'.repeat(64), applied_at: '2026-08-15T10:00:00Z',
    verdict: 'warning',
    findings: [
      { id: 'endpoint.engine.olcrtc', code: 'ENGINE_UNAVAILABLE', severity: 'degraded', blocks: 'feature',
        ack_required: true, acked: false, title: 'INJECTED: olcRTC connections will not start',
        detail: 'INJECTED: the engine binary is not installed.', remedy: 'INJECTED: install it in Updater.',
        count: 1, items: ['olc-1'] },
    ],
    changes: { baseline_available: true, baseline_rev: 'c'.repeat(64), count: 1, may_interrupt: false, requires_apply: true,
      by_subsystem: { connections: [{ id: 'ep1', object_name: 'demo-reality', field: 'enabled', before: 'off', after: 'on',
        secret: false, impact: '', action: 'modified', may_interrupt: false, requires_service_restart: false, requires_reboot: false, warnings: [] }] },
      changes: [] },
    window: { open: false, phase: 'idle', seconds_left: 0 },
    probe: { at: 0, age_s: 0, stale: false, error: '' },
    platform: { name: 'demo', core_available: true, core_running: true, kernel_plane: false, native_vpn: false },
  };
  const seed = `(() => { reviewedPlan = ${JSON.stringify(PLAN)}; ackedFindings.clear(); ackedFindings.add('endpoint.engine.olcrtc'); })()`;
  const OK200 = { applied: true, ok: true, saved: false, rev: REV, duration_ms: 12, failsafe: { pending: false, phase: 'idle' },
    summary: {}, problems: [], warnings: [] };

  // --- 1. Apply returns a bare 500 ---------------------------------------------------------------
  // The POST failed, so the previous configuration is still live. Claiming "Applied" here would be
  // the single most damaging lie the UI could tell.
  await c.eval(clearToasts); await c.eval(closePanels);
  await c.eval(seed);
  setFault({ kind: 'status', match: '/api/apply', code: 500 });
  await c.eval(`applyConfig(false); void 0;`);
  await sleep(3000);
  const a1 = await c.eval(OBSERVE);
  record('apply 500 -> never claims "Applied"', !a1.claimsApplied, `toasts=${JSON.stringify(a1.toasts)}`);
  record('apply 500 -> the failure is visible (card + .toast.err)', a1.errorShown && a1.errToast,
    `errorShown=${a1.errorShown} errToast=${a1.errToast} text=${JSON.stringify(a1.errorText)}`);
  record('apply 500 -> the button recovers', a1.btnDisabled === false, `disabled=${a1.btnDisabled}`);

  // --- 2. HTTP 200 without applied:true ---------------------------------------------------------
  // Transport succeeded, but the contract says a success carries applied:true. Anything else is not one.
  await c.eval(clearToasts); await c.eval(closePanels);
  await c.eval(seed);
  setFault({ kind: 'payload', match: '/api/apply', code: 200, payload: { applied: false, saved: false } });
  await c.eval(`applyConfig(false); void 0;`);
  await sleep(3000);
  const a2 = await c.eval(OBSERVE);
  record('unverified 200 -> never claims "Applied"', !a2.claimsApplied, `toasts=${JSON.stringify(a2.toasts)}`);
  record('unverified 200 -> the failure is visible', (a2.errorShown || a2.saysProblem) && a2.errToast,
    `errorShown=${a2.errorShown} errToast=${a2.errToast} toasts=${JSON.stringify(a2.toasts)}`);

  // --- 3. Double-click must not fire two applies; the body is {save, rev, ack} ---------------------
  await c.eval(clearToasts); await c.eval(closePanels);
  await c.eval(seed);
  setFault({ kind: 'payload', match: '/api/apply', code: 200, payload: OK200 });
  applyPosts = 0;
  lastApplyPayload = null;
  await c.eval(`applyConfig(false); applyConfig(false); applyConfig(false); void 0;`);
  await sleep(4000);
  record('rapid clicks fire exactly one apply', applyPosts === 1, `posts=${applyPosts}`);
  record('Apply posts {save, rev, ack} — the reviewed rev and the ticked acknowledgements',
    !!lastApplyPayload && lastApplyPayload.save === false && lastApplyPayload.rev === REV
      && Array.isArray(lastApplyPayload.ack) && lastApplyPayload.ack.includes('endpoint.engine.olcrtc')
      && Object.keys(lastApplyPayload).sort().join(',') === 'ack,rev,save',
    `payload=${JSON.stringify(lastApplyPayload)}`);
  // (The two swallowed clicks toast "Apply in progress" as .err — that is the re-entry guard speaking,
  // not the apply's verdict — so only the ok toast and the absence of the error card are asserted.)
  const a3 = await c.eval(OBSERVE);
  record('a real success is announced as one (ok toast, no error card)', a3.okToast && !a3.errorShown,
    `toasts=${JSON.stringify(a3.toasts)} errorShown=${a3.errorShown}`);

  // --- 4. Apply that never answers -------------------------------------------------------------
  // Measured, not assumed. A spinner that stays up is honest while the request is genuinely still
  // open; what must NOT happen is a claim of success, or a button that never comes back once the
  // request finally resolves.
  await c.eval(clearToasts); await c.eval(closePanels);
  await c.eval(seed);
  setFault({ kind: 'hang', match: '/api/apply' });
  await c.eval(`applyConfig(false); void 0;`);
  await sleep(15000);
  const a4 = await c.eval(OBSERVE);
  record('hung apply -> never claims "Applied"', !a4.claimsApplied, `toasts=${JSON.stringify(a4.toasts)}`);
  record('hung apply -> the banner says an apply is in progress', /applying/i.test(a4.bannerText || ''),
    `banner=${JSON.stringify(a4.bannerText)}`);
  console.log(`  note  hung apply after 15s: btnDisabled=${a4.btnDisabled} busy=${a4.btnBusy} toasts=${JSON.stringify(a4.toasts)}`);

  await releaseHeld();
  setFault(null);
  await sleep(4000);
  const a5 = await c.eval(OBSERVE);
  record('after the hung apply resolves, the button recovers', a5.btnDisabled === false,
    `disabled=${a5.btnDisabled}`);

  // --- 4b. The browser gives up waiting: no answer within the timeout ------------------------------
  // The status endpoint is then the only honest source: the browser says "the apply may still be
  // running", offers Retry, and follows GET /api/apply/status until in_progress is false. It must NOT
  // turn a lost answer into a success.
  await c.eval(clearToasts); await c.eval(closePanels);
  await c.eval(seed);
  await c.eval(`applyPostTimeoutMs = 3000; void 0;`);
  setFault([
    { kind: 'hang', match: '/api/apply' },
    { kind: 'payload', match: '/api/apply/status', code: 200, payload: { pending: false, phase: 'idle', in_progress: false } },
  ]);
  await c.eval(`applyConfig(false); void 0;`);
  await sleep(6500);
  const a6 = await c.eval(OBSERVE);
  record('no answer within the timeout -> "may still be running" card + Retry, never "Applied"',
    !a6.claimsApplied && a6.errorShown && /did not answer|still be running/i.test(a6.errorText || '')
      && a6.errorButtons.some((b) => /retry/i.test(b)) && a6.errToast && a6.btnDisabled === false,
    `errorShown=${a6.errorShown} text=${JSON.stringify(a6.errorText)} buttons=${JSON.stringify(a6.errorButtons)} errToast=${a6.errToast} disabled=${a6.btnDisabled}`);
  await c.eval(`applyPostTimeoutMs = 90000; void 0;`);
  await releaseHeld();
  setFault(null);
  await sleep(1500);

  // --- 5. 409 REV_STALE: information, not an error ------------------------------------------------
  // The configuration moved since the panel was opened. The server sends the current plan; the panel
  // must re-open with it and a notice, and the button must be usable again — no dead end, no toast
  // claiming success.
  await c.eval(clearToasts); await c.eval(closePanels);
  await c.eval(seed);
  const stalePlan = Object.assign({}, PLAN, { rev: 'd'.repeat(64), findings: [] });
  setFault({ kind: 'status', match: '/api/apply', code: 409, payload: { code: 'REV_STALE', error: 'the configuration changed since the review', plan: stalePlan } });
  await c.eval(`applyConfig(false); void 0;`);
  await sleep(3000);
  const a7 = await c.eval(OBSERVE);
  record('REV_STALE -> the panel re-opens with the server\'s plan and a stale notice',
    a7.panel && /changed while you were reviewing/i.test(a7.panelNotice || '') && !a7.claimsApplied && a7.btnDisabled === false,
    `panel=${a7.panel} notice=${JSON.stringify(a7.panelNotice)} toasts=${JSON.stringify(a7.toasts)}`);
  const staleRev = await c.eval(`reviewedPlan && reviewedPlan.rev`);
  record('REV_STALE -> the next Apply is pinned to the NEW rev', staleRev === 'd'.repeat(64), `rev=${String(staleRev).slice(0, 8)}…`);

  // --- 6. 409 ACK_REQUIRED: show the checkboxes, focus the first unchecked one -------------------
  await c.eval(clearToasts); await c.eval(closePanels);
  await c.eval(seed);
  await c.eval(`ackedFindings.clear(); void 0;`);
  setFault({ kind: 'status', match: '/api/apply', code: 409, payload: { code: 'ACK_REQUIRED', error: 'acknowledge the findings first', findings: PLAN.findings } });
  await c.eval(`applyConfig(false); void 0;`);
  await sleep(3000);
  const a8 = await c.eval(OBSERVE);
  record('ACK_REQUIRED -> the panel shows the acknowledgement box, focused, and Apply stays disabled until ticked',
    a8.panel && a8.ackBoxes >= 1 && a8.ackFocused && a8.footerDisabled.every((v) => v === 'true') && a8.errToast && !a8.claimsApplied,
    `panel=${a8.panel} boxes=${a8.ackBoxes} focused=${a8.ackFocused} footerDisabled=${JSON.stringify(a8.footerDisabled)} errToast=${a8.errToast}`);

  // --- 7. 422 BLOCKED: the router cannot execute it; retrying cannot help ------------------------
  await c.eval(clearToasts); await c.eval(closePanels);
  await c.eval(seed);
  const blocker = { id: 'routing_mode=fast', code: 'ROUTING_MODE_UNAVAILABLE', severity: 'blocked', blocks: 'apply', ack_required: false, acked: false,
    title: 'INJECTED: Routing mode cannot work as requested', detail: 'INJECTED: no kernel plane, so no traffic would be routed.', remedy: 'INJECTED: use "tun" on this router.', count: 1, items: [] };
  setFault({ kind: 'status', match: '/api/apply', code: 422, payload: { code: 'BLOCKED', error: 'blocked by 1 finding', findings: [blocker] } });
  await c.eval(`applyConfig(true); void 0;`);
  await sleep(3000);
  const a9 = await c.eval(OBSERVE);
  record('BLOCKED -> the panel shows "Blocks Apply" (err box), both actions disabled, no success claim',
    a9.panel && /\berr\b/.test(a9.preflightClass || '') && /blocks apply/i.test(a9.preflightText || '')
      && a9.footerDisabled.length === 2 && a9.footerDisabled.every((v) => v === 'true') && a9.errToast && !a9.claimsApplied,
    `panel=${a9.panel} class=${JSON.stringify(a9.preflightClass)} footerDisabled=${JSON.stringify(a9.footerDisabled)} errToast=${a9.errToast}`);

  // --- 8. 400 INVALID_CONFIG: the tool's own message, verbatim; Review, no Retry ------------------
  await c.eval(clearToasts); await c.eval(closePanels);
  await c.eval(seed);
  setFault({ kind: 'status', match: '/api/apply', code: 400, payload: { code: 'INVALID_CONFIG', error: 'sing-box rejected the generated config',
    detail: 'FATAL[0000] decode config: INJECTED outbound[2]: missing server', remedy: 'fix the connection "olc-1"' } });
  await c.eval(`applyConfig(true); void 0;`);
  await sleep(3000);
  const a10 = await c.eval(OBSERVE);
  record('INVALID_CONFIG -> card with the message + detail <pre>, Review offered, NO Retry',
    a10.errorShown && a10.errorHasPre && /INJECTED outbound/.test(a10.errorText || '') && /rejected/i.test(a10.errorText || '')
      && a10.errorButtons.some((b) => /review/i.test(b)) && !a10.errorButtons.some((b) => /retry/i.test(b)) && a10.errToast && !a10.claimsApplied,
    `errorShown=${a10.errorShown} pre=${a10.errorHasPre} buttons=${JSON.stringify(a10.errorButtons)} text=${JSON.stringify(a10.errorText)}`);

  // --- 9. 500 APPLY_FAILED: cause + stage + whether the previous state came back; Retry ------------
  await c.eval(clearToasts); await c.eval(closePanels);
  await c.eval(seed);
  setFault({ kind: 'status', match: '/api/apply', code: 500, payload: { code: 'APPLY_FAILED', error: 'the kernel plane could not be installed',
    detail: 'nft: INJECTED Error: Could not process rule', stage: 'kernel_plane', rolled_back: true } });
  await c.eval(`applyConfig(false); void 0;`);
  await sleep(3000);
  const a11 = await c.eval(OBSERVE);
  record('APPLY_FAILED -> card names the stage, says the previous configuration was restored, offers Retry',
    a11.errorShown && /kernel plane/i.test(a11.errorText || '') && /restored/i.test(a11.errorText || '') && !/NOT restored/.test(a11.errorText || '')
      && a11.errorButtons.some((b) => /retry/i.test(b)) && a11.errToast && !a11.claimsApplied && /failed/i.test(a11.bannerText || ''),
    `text=${JSON.stringify(a11.errorText)} buttons=${JSON.stringify(a11.errorButtons)} banner=${JSON.stringify(a11.bannerText)}`);

  // --- 10. 503 BUSY: another Apply holds the lock; Retry, and follow the server ------------------
  await c.eval(clearToasts); await c.eval(closePanels);
  await c.eval(seed);
  setFault([
    { kind: 'status', match: '/api/apply', code: 503, payload: { code: 'BUSY', error: 'another apply is running' } },
    { kind: 'payload', match: '/api/apply/status', code: 200, payload: { pending: false, phase: 'idle', in_progress: false } },
  ]);
  await c.eval(`applyConfig(false); void 0;`);
  await sleep(4000);
  const a12 = await c.eval(OBSERVE);
  record('BUSY -> card says the router is busy, offers Retry, never claims "Applied"',
    a12.errorShown && /busy/i.test(a12.errorText || '') && a12.errorButtons.some((b) => /retry/i.test(b)) && a12.errToast && !a12.claimsApplied && a12.btnDisabled === false,
    `text=${JSON.stringify(a12.errorText)} buttons=${JSON.stringify(a12.errorButtons)} errToast=${a12.errToast}`);
  setFault(null);
  await c.eval(closePanels);

  // --- 11. 200 ok:false: applied, but a component needs attention --------------------------------
  await c.eval(clearToasts); await c.eval(closePanels);
  await c.eval(seed);
  setFault({ kind: 'payload', match: '/api/apply', code: 200, payload: Object.assign({}, OK200, { ok: false,
    problems: [{ stage: 'plugins', message: 'INJECTED: olcRTC did not start', remedy: 'install the engine in Updater' }] }) });
  await c.eval(`applyConfig(true); void 0;`);
  await sleep(3000);
  const a13 = await c.eval(OBSERVE);
  // The config IS applied here, so the toast may say so — what it must not be is a plain success (an
  // ok toast, or a banner that is not the attention one). The banner carries the problem and its remedy.
  record('200 ok:false -> the banner lists the problem + remedy (ab-err), an err toast, no ok toast',
    /attention/i.test(a13.bannerText || '') && /INJECTED: olcRTC did not start/.test(a13.bannerText || '') && /install the engine/i.test(a13.bannerText || '')
      && /ab-err/.test(a13.bannerClass || '') && a13.errToast && !a13.okToast,
    `banner=${JSON.stringify(a13.bannerText)} class=${JSON.stringify(a13.bannerClass)} toasts=${JSON.stringify(a13.toasts)}`);
  await c.eval(`setApplyPhase(""); void 0;`);

  // --- 12. The fail-safe (Test) window ------------------------------------------------------------
  // The banner is the only place the user can Keep or Roll back from. It must be there while the
  // window is open, say what state the window is in, and stay up when an action fails.
  const ARMED = { pending: true, phase: 'armed', seconds_left: 120, last_check_ok: true, in_progress: false };
  await c.eval(clearToasts);
  setFault([{ kind: 'payload', match: '/api/apply/status', code: 200, payload: ARMED }]);
  await c.eval(`startFailsafeBanner(); void 0;`);
  await sleep(2500);
  const f0 = await c.eval(FAILSAFE_OBSERVE);
  record('the fail-safe banner appears while the window is open', f0.shown, `text=${JSON.stringify(f0.text)}`);
  record('the banner says the config is live but not saved, with the countdown',
    /config applied live/i.test(f0.text || '') && /not saved/i.test(f0.text || '') && /120s/.test(f0.text || ''),
    `text=${JSON.stringify(f0.text)}`);
  record('the banner offers Keep & Save and Roll back',
    f0.buttons.some((b) => /keep & save/i.test(b)) && f0.buttons.some((b) => /roll back/i.test(b)), `buttons=${JSON.stringify(f0.buttons)}`);

  // Phase text: unverified and degraded are stated in words, not colour.
  setFault([{ kind: 'payload', match: '/api/apply/status', code: 200, payload: Object.assign({}, ARMED, { phase: 'unverified' }) }]);
  await sleep(2200);
  const fu = await c.eval(FAILSAFE_OBSERVE);
  setFault([{ kind: 'payload', match: '/api/apply/status', code: 200, payload: Object.assign({}, ARMED, { phase: 'degraded', last_check_ok: false }) }]);
  await sleep(2200);
  const fd = await c.eval(FAILSAFE_OBSERVE);
  record('unverified / degraded phases are named in the banner text',
    fu.shown && /could not measure/i.test(fu.text || '') && fd.shown && /connectivity problem/i.test(fd.text || ''),
    `unverified=${JSON.stringify(fu.text)} degraded=${JSON.stringify(fd.text)}`);

  // Break Keep (POST /api/apply/confirm) while the window stays open.
  setFault([
    { kind: 'payload', match: '/api/apply/status', code: 200, payload: ARMED },
    { kind: 'status', match: '/api/apply/confirm', code: 500 },
  ]);
  await c.eval(clearToasts);
  await c.eval(`failsafeKeep(); void 0;`);
  await sleep(3000);
  const f1 = await c.eval(FAILSAFE_OBSERVE);
  record('a FAILED Keep & Save keeps the fail-safe banner up', f1.shown, `bannerShown=${f1.shown}`);
  record('a FAILED Keep & Save tells the user it FAILED', toldOfFailure(f1.toasts), fmtToasts(f1.toasts));

  // Same for rollback: a failed rollback must not look like a completed one.
  setFault([
    { kind: 'payload', match: '/api/apply/status', code: 200, payload: ARMED },
    { kind: 'status', match: '/api/apply/rollback', code: 500 },
  ]);
  await c.eval(clearToasts);
  await c.eval(`failsafeRollback(); void 0;`);
  await sleep(3000);
  const f2 = await c.eval(FAILSAFE_OBSERVE);
  record('a FAILED rollback keeps the fail-safe banner up', f2.shown, `bannerShown=${f2.shown}`);
  record('a FAILED rollback tells the user it FAILED', toldOfFailure(f2.toasts), fmtToasts(f2.toasts));

  // A rollback the server answers with rolled_back:false is a failure too, whatever the status code.
  setFault([
    { kind: 'payload', match: '/api/apply/status', code: 200, payload: ARMED },
    { kind: 'payload', match: '/api/apply/rollback', code: 200, payload: { rolled_back: false, error: 'INJECTED: restore failed' } },
  ]);
  await c.eval(clearToasts);
  await c.eval(`failsafeRollback(); void 0;`);
  await sleep(3000);
  const f2b = await c.eval(FAILSAFE_OBSERVE);
  record('rolled_back:false is reported as a failure and keeps the banner', f2b.shown && toldOfFailure(f2b.toasts), fmtToasts(f2b.toasts));

  // A status poll that errors must not silently drop the banner — losing it would hide the only
  // controls the user has during the window.
  setFault([{ kind: 'status', match: '/api/apply/status', code: 500 }]);
  await sleep(4000);
  const f3 = await c.eval(FAILSAFE_OBSERVE);
  record('a failing status poll does not drop the banner', f3.shown, `bannerShown=${f3.shown}`);

  // Once the window genuinely closes, the banner must go away.
  setFault([{ kind: 'payload', match: '/api/apply/status', code: 200,
              payload: { pending: false, phase: 'committed' } }]);
  await sleep(4000);
  const f4 = await c.eval(FAILSAFE_OBSERVE);
  record('the banner clears once the window closes', !f4.shown, `bannerShown=${f4.shown}`);
  await c.eval(`hideFailsafeBanner(); void 0;`);

  // Keep that WORKS: POST /api/apply/confirm → {committed:true} — the banner goes, the toast is a success.
  await c.eval(clearToasts);
  setFault([{ kind: 'payload', match: '/api/apply/status', code: 200, payload: ARMED }]);
  await c.eval(`startFailsafeBanner(); void 0;`);
  await sleep(2000);
  setFault([
    { kind: 'payload', match: '/api/apply/status', code: 200, payload: { pending: false, phase: 'committed' } },
    { kind: 'payload', match: '/api/apply/confirm', code: 200, payload: { committed: true } },
  ]);
  await c.eval(`failsafeKeep(); void 0;`);
  await sleep(2500);
  const f5 = await c.eval(FAILSAFE_OBSERVE);
  record('a successful Keep & Save clears the banner and says "Kept & committed"',
    !f5.shown && f5.toasts.some((x) => /kept & committed/i.test(x.text) && !x.err), `shown=${f5.shown} ${fmtToasts(f5.toasts)}`);

  // Roll back that WORKS: {rolled_back:true} — banner goes, toast says so.
  await c.eval(clearToasts);
  setFault([{ kind: 'payload', match: '/api/apply/status', code: 200, payload: ARMED }]);
  await c.eval(`startFailsafeBanner(); void 0;`);
  await sleep(2000);
  // (status goes idle rather than rolled_back so the poll's own "connectivity lost — rolled back" toast
  // for an AUTOMATIC rollback cannot race the manual one being measured here)
  setFault([
    { kind: 'payload', match: '/api/apply/status', code: 200, payload: { pending: false, phase: 'idle' } },
    { kind: 'payload', match: '/api/apply/rollback', code: 200, payload: { rolled_back: true } },
  ]);
  await c.eval(`failsafeRollback(); void 0;`);
  await sleep(2500);
  const f6 = await c.eval(FAILSAFE_OBSERVE);
  record('a successful Roll back clears the banner and says "Rolled back"',
    !f6.shown && f6.toasts.some((x) => /rolled back/i.test(x.text) && !x.err), `shown=${f6.shown} ${fmtToasts(f6.toasts)}`);
  await c.eval(`hideFailsafeBanner(); void 0;`);
  setFault(null);

  await releaseHeld();
  c.close();
} finally {
  await closeChrome(chrome, chrome.profileDir);
}

const failed = results.filter((r) => !r.pass);
for (const r of results) console.log(`  ${r.pass ? 'PASS' : 'FAIL'}  ${r.name}   [${r.detail}]`);
console.log(`\n${results.length - failed.length}/${results.length} apply fault checks passed`);
process.exit(failed.length ? 1 : 0);
