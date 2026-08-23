// ui-injection.mjs — does hostile TEXT in the profile become markup in the panel?
//
// Run after seed-hostile.mjs. Loads every route and asks three questions per page:
//
//   1. Did anything execute? Each payload sets window.__xss if it runs, so a non-zero flag is proof,
//      not inference.
//   2. Did any element appear that the payload asked for — an <img>, <svg> or <script> whose source
//      is one of the seeded strings? A payload can inject a node without executing (CSP blocks inline
//      handlers, say) and that is still an injection: the CSP is a second line, not the guarantee.
//   3. Is the payload present as TEXT? If it is nowhere at all, the page did not render the object
//      and this check proved nothing about escaping — the "a check that passes when its subject is
//      absent proves nothing" rule, which is easy to trip here because a page that throws mid-render
//      shows neither the payload nor an injection.
//
// Usage: node scripts/ui-injection.mjs <url> [cdp-port]
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { authenticateCDP } from './ui-auth.mjs';
import { PAYLOADS } from './seed-hostile.mjs';

const URL_ARG = process.argv[2];
const PORT = Number(process.argv[3] || 9610);
if (!URL_ARG) { console.error('usage: node scripts/ui-injection.mjs <url> [cdp-port]'); process.exit(2); }
const PAGES = ['dashboard', 'server', 'connections', 'failover', 'routing', 'dns', 'updater',
  'diagnostics', 'settings'];
// Routes that render no attacker-controlled text, and WHY. A route absent from this map that renders
// no payload is a FAILURE, not a pass.
//
// The verdict used to read "hostile text stayed text on all 9 routes" and the only subject-present
// guard was a run-wide sum. Measured on the seeded demo, FOUR routes printed `payload-as-text=0` —
// server, dns, updater, settings — and were certified on nothing while the other five kept the sum at
// 34. server and dns turned out to be a seeding gap, not a structural one: both render stored text,
// the daemon stores markup in both (measured), and seed-hostile now plants a DNS rule and a saved
// provisioner record. These two are what is left.
const NO_STORED_TEXT = {
  updater: 'renders engine metadata compiled into the build, not stored user text',
  settings: 'renders stored values inside form controls; an input value is not a text node, so a payload cannot appear as text on this route',
};
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const httpJSON = async (u) => (await fetch(u)).json();
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wayhop-inj-'));
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
  `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`, '--window-size=1280,900', 'about:blank'],
  { stdio: 'ignore' });

let findings = 0;
let sawPayloadText = 0;
// Per ROUTE, because the run-wide sum cannot tell nine exercised routes from five.
const covered = [], exempt = [], uncovered = [];
try {
  for (let i = 0; i < 60; i++) {
    try { await httpJSON(`http://127.0.0.1:${PORT}/json/version`); break; } catch { await sleep(250); }
  }
  const targets = await httpJSON(`http://127.0.0.1:${PORT}/json/list`);
  const ws = new WebSocket((targets.find((t) => t.type === 'page') || targets[0]).webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  let id = 0; const waiting = new Map();
  ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); } };
  const send = (m, p = {}) => new Promise((res, rej) => {
    const i = ++id; const _to = setTimeout(() => { waiting.delete(i); rej(new Error(`CDP ${m} got no reply in 30000ms`)); }, 30000);
    waiting.set(i, (_m) => { clearTimeout(_to); ((x) => (x.error ? rej(new Error(x.error.message)) : res(x.result)))(_m); });
    ws.send(JSON.stringify({ id: i, method: m, params: p }));
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

  const PJSON = JSON.stringify(PAYLOADS);
  for (const p of PAGES) {
    await ev(`location.hash = '#${p}'`);
    await sleep(3500);
    const r = await ev(`(() => {
      const payloads = ${PJSON};
      const v = document.querySelector('#view');
      const txt = v ? v.textContent || '' : '';
      // Injected nodes, scoped to the RENDERED VIEW and to shapes only a payload produces. The first
      // cut of this searched the whole document for script tags and dutifully reported the app's own
      // <script src="page-connections.js"> on every route — a detector that fires on its subject's
      // absence is worse than no detector, and it would have buried a real hit in nine false ones.
      // An injected script here is INLINE (the payload has no src); the app's are all external.
      const scope = v || document.body;
      const suspects = [...scope.querySelectorAll('img[src="x"], svg[onload], script:not([src])')]
        .map(n => n.outerHTML.slice(0, 80));
      return {
        xss: window.__xss || 0,
        nodes: suspects,
        asText: payloads.filter(s => txt.includes(s)).length,
        controls: v ? v.querySelectorAll('button, input, select, textarea, [role="button"], a[href]').length : 0,
        badHref: [...document.querySelectorAll('a[href]')]
          .filter(a => /^javascript:/i.test(a.getAttribute('href') || '')).length,
      };
    })()`);
    sawPayloadText += r.asText;
    const bad = r.xss || r.nodes.length || r.badHref;
    if (bad) {
      findings++;
      // Report payload-as-text on failures too: it says whether the page rendered the object at all,
      // which is the difference between "escaped badly" and "did not render, so this proves nothing".
      console.error(`FAIL ${p}: xss-flag=${r.xss} injected-nodes=${r.nodes.length} ` +
        `javascript-hrefs=${r.badHref} payload-as-text=${r.asText}`);
      r.nodes.slice(0, 3).forEach((n) => console.error(`       ${n}`));
    } else if (r.asText > 0) {
      covered.push(p);
      console.log(`  ${p.padEnd(12)} clean   payload-as-text=${r.asText}  controls=${r.controls}`);
    } else if (NO_STORED_TEXT[p]) {
      exempt.push(p);
      console.log(`  ${p.padEnd(12)} n/a     nothing hostile to render — ${NO_STORED_TEXT[p]}`);
    } else {
      uncovered.push(p);
      console.error(`  ${p.padEnd(12)} NOT COVERED  no payload rendered here, so this route was not checked`);
    }
  }
  ws.close();
} finally {
  chrome.kill();
  await new Promise((r) => setTimeout(r, 1200));
  try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 12, retryDelay: 250 }); } catch (_) {}
  // Not silent: a directory that survives is a browser that may still be running, and enough of
  // those starve the next gate. Say it here rather than leave it to be counted in /tmp later.
  if (fs.existsSync(dir)) console.error(`note: could not remove the Chrome profile dir ${dir}`);
}

if (findings) {
  console.error(`\n${findings} route(s) turned stored text into markup. Endpoint names can come from a` +
    ` remote subscription, so this is reachable by whoever runs that subscription.`);
  process.exit(1);
}
if (!sawPayloadText) {
  console.error('\nNo payload appeared as text on ANY route, so nothing was actually rendered and this' +
    ' check proved nothing. Seed with scripts/seed-hostile.mjs first, and confirm the daemon stored it.');
  process.exit(2);
}
if (uncovered.length) {
  console.error(`\n${uncovered.length} route(s) rendered no hostile object at all, so nothing was checked` +
    ` there: ${uncovered.join(', ')}. Seed something those pages render, or — if the route carries no` +
    ` attacker-controlled text — say so in NO_STORED_TEXT with the reason. Certifying a route that` +
    ` rendered nothing is what this check was doing for four of nine.`);
  process.exit(3);
}
console.log(`\nhostile text stayed text on the ${covered.length} route(s) that rendered it: ` +
  `${covered.join(', ')} (seen rendered ${sawPayloadText} times). ` +
  `${exempt.length} route(s) carry no attacker-controlled text: ${exempt.join(', ')}`);
