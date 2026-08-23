// ui-render-time.mjs — how long does each route take to BUILD, and how much of that is the router
// being slow to answer versus the page being expensive to construct?
//
// The perf budget (§2.1) measures bytes. Bytes are not the thing a user waits for: a page can be
// comfortably under budget and still take seconds to appear on a router CPU, and the redesign added
// a lot of DOM — the Routing page carries 401 controls against a large profile. Nothing in the suite
// has ever measured that.
//
// Two numbers per route, deliberately separated, because they have different owners:
//
//   wall  — time from the hash change until the page stops changing (the same settle rule the density
//           gate uses). Includes waiting for the daemon, so a slow router inflates it and the UI
//           cannot fix it.
//   cpu   — ScriptDuration + LayoutDuration + RecalcStyleDuration across that window, from CDP's own
//           Performance domain. This is what the front-end actually costs, and it is the number the
//           redesign is answerable for.
//
// The BUDGET is on time-to-content and time-to-control, not on wall time. Wall time is dominated by
// the slowest field on the page — the dashboard waits on a public-IP lookup per exit, which is an
// internet round trip the panel does not control — so gating it would be gating someone else's
// network. What the design IS answerable for is that the page shows its structure and becomes
// operable quickly, and then fills in. Measured on the Keenetic with a real profile, the worst
// time-to-content was 871ms; the budget is 1500ms, which is headroom without being meaningless.
//
//   node scripts/ui-render-time.mjs <url> [cdp-port]
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { authenticateCDP } from './ui-auth.mjs';

const URL_ARG = process.argv[2];
const PORT = Number(process.argv[3] || 9620);
if (!URL_ARG) { console.error('usage: node scripts/ui-render-time.mjs <url> [cdp-port]'); process.exit(2); }
const PAGES = ['dashboard', 'server', 'connections', 'failover', 'routing', 'dns', 'updater',
  'diagnostics', 'settings'];
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const httpJSON = async (u) => (await fetch(u)).json();
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wayhop-rt-'));
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
  `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`, '--window-size=1280,900', 'about:blank'],
  { stdio: 'ignore' });

let unsettled = 0;
let slow = 0;
try {
  for (let i = 0; i < 60; i++) {
    try { await httpJSON(`http://127.0.0.1:${PORT}/json/version`); break; } catch { await sleep(250); }
  }
  const targets = await httpJSON(`http://127.0.0.1:${PORT}/json/list`);
  const ws = new WebSocket((targets.find((t) => t.type === 'page') || targets[0]).webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  let id = 0; const waiting = new Map();
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
    if (m.method === 'Network.requestWillBeSent' && !STREAMISH.has(m.params.type)) inflight.set(m.params.requestId, Date.now());
    else if (m.method === 'Network.loadingFinished' || m.method === 'Network.loadingFailed') inflight.delete(m.params.requestId);
  };
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
  await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
  await send('Performance.enable');
  const CPU_KEYS = ['ScriptDuration', 'LayoutDuration', 'RecalcStyleDuration'];
  const cpuNow = async () => {
    const { metrics } = await send('Performance.getMetrics');
    const by = Object.fromEntries(metrics.map((m) => [m.name, m.value]));
    return CPU_KEYS.reduce((a, k) => a + (by[k] || 0), 0) * 1000; // seconds -> ms
  };

  await send('Page.navigate', { url: URL_ARG });
  for (let i = 0; i < 160; i++) {
    if (await ev('typeof route === "function"').catch(() => false)) break;
    await sleep(250);
  }
  await authenticateCDP({ send, evaluate: ev, url: URL_ARG });
  // Warm: the first route paid for the cold start (measured elsewhere, and it is not what this gate
  // is about). Visit each page once before measuring so every number is a steady-state render.
  for (const p of PAGES) { await ev(`location.hash = '#${p}'`); await sleep(1200); }

  const MEASURE = `(() => {
    const v = document.querySelector('#view');
    if (!v) return null;
    const skel = v.querySelector('.skeleton-page');
    return { h: v.scrollHeight, n: v.querySelectorAll('*').length,
             real: v.querySelectorAll('*').length - (skel ? skel.querySelectorAll('*').length + 1 : 0),
             c: v.querySelectorAll('button, input, select, textarea, [role="button"], a[href]').length };
  })()`;

  console.log(`  ${URL_ARG}`);
  console.log(`  route          content  control    wall     cpu    nodes`);
  const rows = [];
  for (const p of PAGES) {
    await ev(`location.hash = '#dashboard'`);
    await sleep(900);
    const cpu0 = await cpuNow();
    const t0 = Date.now();
    await ev(`location.hash = '#${p}'`);
    // "Settled" alone cannot tell a defect from good behaviour. A page that shows its structure at
    // 300ms and fills a slow field at 5s is progressive loading; a page that is BLANK for 5s is a
    // user staring at nothing. So record when the first real content appears and when the first
    // control becomes operable, not just when everything stops moving.
    let d = null, prev = null, streak = 0, settled = false;
    let tContent = -1, tControl = -1;
    for (let i = 0; i < 120; i++) {
      await sleep(100);
      d = await ev(MEASURE);
      if (d) {
        // The skeleton placeholder is deliberately not content: it exists so the pane is not blank,
        // and counting it would report the very wait this is trying to measure as instant.
        if (tContent < 0 && d.real > 4) tContent = Date.now() - t0;
        if (tControl < 0 && d.c > 0) tControl = Date.now() - t0;
      }
      const same = prev && d && d.h === prev.h && d.n === prev.n && d.c === prev.c;
      streak = (same && pending() === 0) ? streak + 1 : 0;
      if (streak >= 10) { settled = true; break; }
      prev = d;
    }
    const wall = Date.now() - t0 - 10 * 100;         // discount the confirmation samples
    const cpu = (await cpuNow()) - cpu0;
    if (!settled) { unsettled++; console.error(`  warning: #${p} never settled — its numbers are a lower bound`); }
    rows.push({ p, wall, cpu, n: d ? d.n : 0, c: d ? d.c : 0, tContent, tControl });
    const ms = (x) => (x < 0 ? '   —' : String(x)) + 'ms';
    console.log(`  ${p.padEnd(13)} ${ms(tContent).padStart(8)} ${ms(tControl).padStart(8)} ` +
      `${(String(Math.max(0, wall)) + 'ms').padStart(7)} ${(cpu.toFixed(0) + 'ms').padStart(7)} ${String(d ? d.n : 0).padStart(6)}`);
  }
  const worstCpu = rows.reduce((a, b) => (b.cpu > a.cpu ? b : a), rows[0]);
  const worstWall = rows.reduce((a, b) => (b.wall > a.wall ? b : a), rows[0]);
  console.log(`  worst cpu:  ${worstCpu.p} ${worstCpu.cpu.toFixed(0)}ms over ${worstCpu.n} nodes`);
  console.log(`  worst wall: ${worstWall.p} ${worstWall.wall}ms`);
  const BUDGET_MS = Number(process.env.WR_CONTENT_BUDGET_MS || 1500);
  const blind = rows.filter(r => r.tContent < 0 || r.tContent > BUDGET_MS ||
                                 r.tControl < 0 || r.tControl > BUDGET_MS);
  if (blind.length) {
    console.error(`
  ${blind.length} route(s) leave the user on a skeleton past ${BUDGET_MS}ms: ` +
      blind.map(r => `${r.p} content=${r.tContent < 0 ? 'never' : r.tContent + 'ms'} ` +
        `control=${r.tControl < 0 ? 'never' : r.tControl + 'ms'}`).join(', '));
    console.error('  Render the page structure before awaiting slow data, and fill the slow fields in.');
    slow = blind.length;
  } else {
    console.log(`  every route shows content and an operable control within ${BUDGET_MS}ms`);
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
if (slow) process.exit(1);
if (unsettled) {
  console.error(`\n${unsettled} route(s) never settled, so their timings are lower bounds rather than` +
    ' measurements. Do not read this run as a result.');
  process.exit(1);
}
