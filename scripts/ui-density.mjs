// ui-density.mjs — fail if a route opens far taller than one screen.
//
// The reviewed complaint was that the panel is overloaded and hard to navigate. Settings was the
// measurable form of it: 14 cards, 32 controls, 2852px — 3.5 screens at 1280x900, twice the density
// of any other page. This gate keeps that from creeping back, on every route rather than just the
// one that was worst.
//
// The budget is deliberately loose. A page a little over one screen is normal; the defect is a page
// nobody can take in, so the line sits at 2 screens.
//
// Height alone was a PROXY for that, and it was being satisfied the wrong way. Routing and Settings met
// it by scrolling their rows inside a capped box, which the operator reported as a defect: the page could
// not scroll at all while 6836px of rules sat in an 835px window with dead space beneath. Removing the cap
// makes those routes honestly tall — 65 routing lists are 10.9 screens however they are presented — so a
// pure height rule would now forbid the fix that the complaint asked for.
//
// So the rule enforces the thing the height was standing in for. Over budget is allowed only when the
// route carries an in-page filter AND that filter is shown, here, to bring it back under budget: the gate
// types into it and re-measures. A route with no filter, or one whose filter does not shorten it, fails
// exactly as before. That is strictly harder to satisfy than the old check, which never established that
// the "in-page navigator" its own error message demanded actually existed.
//
// Usage: node scripts/ui-density.mjs http://HOST:PORT/ [--report]
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

const URL_ARG = process.argv[2];
if (!URL_ARG) { console.error('usage: node scripts/ui-density.mjs <url> [--report]'); process.exit(2); }
const REPORT = process.argv.includes('--report');
const PORT = Number(process.env.CDP_PORT || 9515);
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const PAGES = 'dashboard,server,connections,failover,routing,dns,updater,diagnostics,settings'.split(',');
const VIEW_H = 900;
const CHROME_H = 80;           // topbar and page padding the viewport spends before content
const BUDGET_SCREENS = 2.0;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const httpJSON = async (u) => (await fetch(u)).json();

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wayhop-density-'));
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
  `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`, `--window-size=1280,${VIEW_H}`, 'about:blank'],
  { stdio: 'ignore' });

let over = 0;
let subjects = 0;
let unsettled = 0;
try {
  for (let i = 0; i < 60; i++) {
    try { await httpJSON(`http://127.0.0.1:${PORT}/json/version`); break; } catch { await sleep(250); }
  }
  const targets = await httpJSON(`http://127.0.0.1:${PORT}/json/list`);
  const ws = new WebSocket((targets.find((t) => t.type === 'page') || targets[0]).webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  let id = 0; const waiting = new Map();
  // Same in-flight tracking the control gate needs, and for a sharper reason here. This gate used to
  // wait a flat 1.8s and then measure. That is ample against the demo on localhost and NOT ample
  // against a real router, so it measured half-rendered pages and called them short: on the Keenetic it
  // reported Diagnostics at 1039px/19 controls on one run and 1812px/25 on the next, and the Dashboard
  // at 5 cards then 1. A budget gate that PASSES because the content had not arrived yet is the audit's
  // own defect class — a partial result presented as the complete one — and it turns every hardware
  // height in the audit into an under-measurement rather than a verdict.
  const inflight = new Map();
  const STREAMISH = new Set(['EventSource', 'WebSocket', 'Media', 'Manifest']);
  const pending = () => {
    const now = Date.now();
    for (const [k, v] of inflight) if (now - v > 5000) inflight.delete(k);
    return inflight.size;
  };
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); return; }
    if (m.method === 'Network.requestWillBeSent' && !STREAMISH.has(m.params.type)) {
      inflight.set(m.params.requestId, Date.now());
    } else if (m.method === 'Network.loadingFinished' || m.method === 'Network.loadingFailed') {
      inflight.delete(m.params.requestId);
    }
  };
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

  await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
  await send('Page.navigate', { url: URL_ARG });
  for (let i = 0; i < 160; i++) {
    if (await ev('typeof route === "function"').catch(() => false)) break;
    await sleep(250);
  }
  await authenticateCDP({ send, evaluate: ev, url: URL_ARG });

  const budgetPx = (VIEW_H - CHROME_H) * BUDGET_SCREENS;
  for (const p of PAGES) {
    await ev(`location.hash = '#${p}'`);
    const MEASURE = `(() => {
      const v = document.querySelector('#view');
      // "controls" must mean everything a user can operate, not just form elements. Counting only
      // the latter reported the Dashboard as having ZERO controls while it carries two link-buttons
      // and a role=button card header — a column whose name promised more than it measured.
      return { h: v.scrollHeight, nodes: v.querySelectorAll('*').length,
             cards: v.querySelectorAll('.card').length,
               controls: v.querySelectorAll(
                 'button, input, select, textarea, [role="button"], a[href]').length };
    })()`;
    // Settle on the measurement itself: the same numbers twice, three samples in, and nothing still
    // being fetched. Growing pages are the whole risk here, so a page that never stops growing is
    // reported rather than silently accepted at whatever it happened to be when the clock ran out.
    // A STREAK of quiet, not an instant of it. Two equal samples with nothing in flight is also exactly
    // what a page looks like in the gap between rendering its skeleton and firing its next request, and
    // that false settle is what a two-sample rule kept reporting: dashboard 1519px then 1827px, updater
    // 9 controls then 1, on consecutive runs, neither warning that anything was still moving. Six
    // consecutive identical samples with the network idle throughout is 2.4s of real quiet; anything
    // that changes, or any request opening, resets the count to zero.
    let d = null, prev = null, streak = 0, settled = false;
    for (let i = 0; i < 60; i++) {          // 60 x 400ms = 24s ceiling
      await sleep(400);
      d = await ev(MEASURE);
      const same = prev && d.h === prev.h && d.cards === prev.cards && d.controls === prev.controls;
      streak = (same && pending() === 0) ? streak + 1 : 0;
      if (streak >= 6) { settled = true; break; }
      prev = d;
    }
    if (!settled) {
      console.error(`  warning: #${p} never stopped changing within 16s — measuring the last sample`);
      unsettled++;
    }
    subjects += (d && d.nodes) || 0;
    const screens = Math.round((d.h / (VIEW_H - CHROME_H)) * 10) / 10;

    // Over budget? Then the route must carry a filter that actually brings it back under. Typing a string
    // nothing can match is the strongest form of the question: if the list is filterable at all, the page
    // must collapse. Restored afterwards so the next route is measured on an untouched panel.
    let escape = null;
    if (d.h > budgetPx) {
      const filtered = await ev(`(async () => {
        const inputs = [...document.querySelectorAll('#view input')].filter((i) => {
          const t = (i.type || 'text').toLowerCase();
          if (t !== 'text' && t !== 'search') return false;
          return /filter|search/i.test((i.placeholder || '') + ' ' + (i.getAttribute('aria-label') || ''));
        });
        if (!inputs.length) return { hasFilter: false };
        const el = inputs[0];
        const before = document.querySelector('#view').scrollHeight;
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
        setter.call(el, 'zzzzqqqqxxxx-no-such-row');
        el.dispatchEvent(new Event('input', { bubbles: true }));
        await new Promise((r) => setTimeout(r, 600));
        const after = document.querySelector('#view').scrollHeight;
        setter.call(el, '');
        el.dispatchEvent(new Event('input', { bubbles: true }));
        await new Promise((r) => setTimeout(r, 400));
        const restored = document.querySelector('#view').scrollHeight;
        return { hasFilter: true, placeholder: (el.placeholder || '').slice(0, 40), before, after, restored };
      })()`);
      escape = filtered;
    }
    const shrank = escape && escape.hasFilter && escape.after <= budgetPx;
    const bad = d.h > budgetPx && !shrank;
    if (bad) over++;
    if (REPORT || bad || escape) {
      console.log(`${bad ? 'FAIL' : '    '} ${p.padEnd(12)} ${String(d.cards).padStart(2)} cards ` +
        `${String(d.controls).padStart(3)} controls ${String(d.h).padStart(5)}px = ${screens} screens` +
        (escape
          ? (escape.hasFilter
            ? `  filter "${escape.placeholder}" -> ${escape.after}px${shrank ? ' (within budget)' : ' (STILL over)'}` +
              (escape.restored !== escape.before ? `  [restored to ${escape.restored}, not ${escape.before}]` : '')
            : '  no in-page filter')
          : ''));
    }
  }
  ws.close();
} finally {
  await closeChrome(chrome, dir);
}

// An unsettled route is not a pass. Its number is whatever the page happened to be at 16s, which
// is exactly the under-measurement this settle loop exists to stop, so it fails the gate on its own.
if (unsettled) {
  console.error(`
${unsettled} route(s) were still changing after 16s — their heights are lower bounds, not measurements. Fix the slow render or raise the ceiling; do not read these as a pass.`);
  process.exit(1);
}
if (over) {
  console.error(`\n${over} route(s) open taller than ${BUDGET_SCREENS} screens with no in-page filter that ` +
    'brings them back under it. Add a filter that works, or group the content into sections — do not cap ' +
    'the height with an inner scroll region, which hides the overflow instead of making it navigable.');
  process.exit(1);
}
console.log(`every route opens within ${BUDGET_SCREENS} screens, or has a filter measured to bring it there`);
console.log(`subjects: ${subjects} rendered nodes measured`);
