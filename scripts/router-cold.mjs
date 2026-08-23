// router-cold.mjs — open every page the way a person arrives at it: cold, and alone.
//
// The page sweep walks the routes in one fixed order in one browser, so every page after the first is
// judged with whatever the earlier pages loaded. That is not how anybody uses the panel — a bookmark,
// a reload, a link from a note all land on ONE route with nothing else loaded — and the difference is
// not academic: `mono` was declared in the Set-up-Server chunk and called from Diagnostics, so opening
// Diagnostics directly threw, rendered zero health rows and left "Run all checks" disabled forever.
// The sweep passed throughout, because it visits Set up Server second and Diagnostics eighth.
//
// So: one fresh browser per route, landing straight on it, and the question asked of each is the one
// the sweep cannot ask — does this page work when it is the FIRST thing loaded?
//
//   node scripts/router-cold.mjs <panel-url> [--settle ms] [--port cdp]
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const args = process.argv.slice(2);
const flag = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const URL_ARG = args.find((a) => /^https?:\/\//.test(a));
const SETTLE = Number(flag('--settle') || 6000);
const PORT0 = Number(flag('--port') || 9680);
if (!URL_ARG) {
  console.error('usage: node scripts/router-cold.mjs <panel-url> [--settle ms] [--port cdp]');
  process.exit(2);
}
const BASE = URL_ARG.replace(/\/+$/, '') + '/';
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const httpJSON = async (u) => (await fetch(u)).json();

async function closeChrome(child, dir) {
  if (child && child.exitCode === null && !child.killed) child.kill();
  if (child) await Promise.race([new Promise((r) => child.once('exit', r)), new Promise((r) => setTimeout(r, 3000))]);
  if (!dir) return;
  for (let i = 0; i < 12; i++) {
    try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 4, retryDelay: 250 }); return; }
    catch (_) { await sleep(250); }
  }
  console.error(`note: could not remove the Chrome profile dir ${dir}`);
}

// visit opens ONE browser and loads exactly one url, reporting what the page said and whether it drew
// anything. `hash` empty means the default landing route.
async function visit(url, port, label) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cold-'));
  const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
    '--hide-scrollbars', '--disable-extensions', `--remote-debugging-port=${port}`,
    `--user-data-dir=${dir}`, '--window-size=1280,900', 'about:blank'], { stdio: 'ignore' });
  const faults = [];
  try {
    let targets = null;
    for (let i = 0; i < 60; i++) {
      try { targets = await httpJSON(`http://127.0.0.1:${port}/json/list`); break; } catch { await sleep(250); }
    }
    if (!targets) throw new Error('chrome did not expose a CDP endpoint');
    const ws = new WebSocket((targets.find((t) => t.type === 'page') || targets[0]).webSocketDebuggerUrl);
    await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });

    let id = 0;
    const waiting = new Map();
    ws.onmessage = (e) => {
      const m = JSON.parse(e.data);
      if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); return; }
      if (m.method === 'Runtime.exceptionThrown') {
        const d = m.params.exceptionDetails || {};
        faults.push({ kind: 'exception', text: String(d.exception?.description || d.text || '').split('\n')[0].slice(0, 220) });
      } else if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') {
        faults.push({ kind: 'console-error', text: (m.params.args || []).map((a) => a.value ?? a.description ?? a.type).join(' ').slice(0, 220) });
      } else if (m.method === 'Network.responseReceived') {
        const r = m.params.response || {};
        // A version check that cannot reach GitHub answers 502, and that is the daemon reporting the
        // internet, not the panel failing. Pressing "Check all" is still worth doing — a JS fault on
        // that page is a real defect — but its NETWORK outcome depends on the machine running the
        // suite, and a gate that goes red when a mirror is unreachable is a gate people learn to
        // ignore. Named narrowly: only the version endpoints, only 5xx.
        const upstream = /\/api\/updater\/[^/]+\/versions$/.test(r.url) && r.status >= 500;
        if (r.status >= 400 && !upstream) {
          faults.push({ kind: `http-${r.status}`, text: r.url });
        } else if (upstream) {
          faults.push({ kind: 'upstream-unreachable', text: `${r.status} ${r.url}` });
        }
      } else if (m.method === 'Network.loadingFailed') {
        if (!/net::ERR_ABORTED/.test(m.params.errorText || '')) faults.push({ kind: 'load-failed', text: m.params.errorText });
      }
    };
    const send = (method, params = {}) => new Promise((res, rej) => {
      const i = ++id;
      const to = setTimeout(() => { waiting.delete(i); rej(new Error(`CDP ${method} got no reply in 30000ms`)); }, 30000);
      waiting.set(i, (m) => { clearTimeout(to); return m.error ? rej(new Error(m.error.message)) : res(m.result); });
      ws.send(JSON.stringify({ id: i, method, params }));
    });
    const ev = async (expr) => {
      const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
      if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || 'eval failed');
      return r.result.value;
    };

    await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
    await send('Page.navigate', { url });
    for (let i = 0; i < 200; i++) {
      if (await ev('typeof route === "function"').catch(() => false)) break;
      await sleep(250);
    }
    await sleep(SETTLE);

    // Drew something is a separate question from threw nothing: the mono defect produced a page with
    // no exception visible in the console AFTER the fact and simply no content.
    const drew = await ev(`(() => {
      const v = document.querySelector('#view');
      if (!v) return { nodes: 0, controls: 0, text: 0, skeleton: false };
      return {
        nodes: v.querySelectorAll('*').length,
        controls: v.querySelectorAll('button, input, select, textarea, [role="button"], a[href]').length,
        text: (v.textContent || '').trim().length,
        skeleton: !!v.querySelector('.skeleton-page'),
      };
    })()`);
    // Rendering is not the whole of a cold visit. The defect that motivated this file threw from a
    // row builder reached by CLICKING, not by loading — a page that draws and then dies on the first
    // thing anybody does with it is still broken for the person who opened it. So press the page's
    // primary control and look again.
    //
    // ONLY controls known to be safe are pressed, named one by one. The first version of this had a
    // deny-list — save, apply, delete, remove, reset — and pressed anything else that was primary. On
    // the DNS page the primary control is called "Secure defaults", which matches none of those words
    // and WRITES the DNS plane: the sweep persisted a configuration on the household's router. A
    // deny-list is a guess about every button that will ever exist; an allow-list is a statement about
    // the ones that have been looked at.
    //
    // "+ …" opens a form and saves nothing. The named ones read: they probe, they do not persist.
    // `\+` — not `\\+`. In a regex LITERAL the doubled backslash matches a literal backslash, so the
    // first arm never fired and every page whose primary control is "+ Add …" silently reported "no
    // safe primary control" while the sweep said ok. Coverage quietly narrowing under a green line is
    // the same failure this file was written to find.
    const SAFE = /^\+|^(run all checks|check all|check updates|check config|test|ask)$/i;
    let acted = null;
    if (!label.startsWith('(')) {
      acted = await ev(`(async () => {
        const btns = [...document.querySelectorAll('#view button')]
          .filter(b => !b.hasAttribute('disabled'))
          .filter(b => ${SAFE}.test(((b.textContent || '').trim() || b.getAttribute('aria-label') || '').trim()));
        const b = btns.find(x => x.classList.contains('btn-primary')) || btns[0] || null;
        if (!b) return { clicked: null };
        const text = ((b.textContent || '').trim() || b.getAttribute('aria-label') || '').slice(0, 40);
        b.click();
        await new Promise(r => setTimeout(r, 4000));
        return { clicked: text };
      })()`).catch((e) => ({ clicked: null, evalError: String(e.message).slice(0, 160) }));
      if (acted && acted.evalError) faults.push({ kind: 'exception', text: acted.evalError });
      await sleep(2500);
    }

    ws.close();
    return { label, faults, drew, acted };
  } catch (e) {
    return { label, faults: [...faults, { kind: 'aborted', text: e.message }], drew: null };
  } finally {
    await closeChrome(chrome, dir);
  }
}

// One browser to learn the route names, then one per route.
console.log(`  target: ${BASE}  (one fresh browser per route)`);
const first = await visit(BASE, PORT0, '(discovery)');
if (!first.drew) {
  console.error(`FAIL  the panel did not load at all: ${JSON.stringify(first.faults)}`);
  process.exit(1);
}

const dirDisc = fs.mkdtempSync(path.join(os.tmpdir(), 'colddisc-'));
let routes = [];
{
  const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
    `--remote-debugging-port=${PORT0 + 1}`, `--user-data-dir=${dirDisc}`, 'about:blank'], { stdio: 'ignore' });
  try {
    let t = null;
    for (let i = 0; i < 60; i++) { try { t = await httpJSON(`http://127.0.0.1:${PORT0 + 1}/json/list`); break; } catch { await sleep(250); } }
    const ws = new WebSocket((t.find((x) => x.type === 'page') || t[0]).webSocketDebuggerUrl);
    await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
    let id = 0; const w = new Map();
    ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.id && w.has(m.id)) { w.get(m.id)(m); w.delete(m.id); } };
    const send = (method, params = {}) => new Promise((res, rej) => {
      const i = ++id;
      const to = setTimeout(() => { w.delete(i); rej(new Error('CDP timeout')); }, 30000);
      w.set(i, (m) => { clearTimeout(to); return m.error ? rej(new Error(m.error.message)) : res(m.result); });
      ws.send(JSON.stringify({ id: i, method, params }));
    });
    await send('Page.enable'); await send('Runtime.enable');
    await send('Page.navigate', { url: BASE });
    for (let i = 0; i < 200; i++) {
      const r = await send('Runtime.evaluate', { expression: 'typeof route === "function"', returnByValue: true }).catch(() => null);
      if (r && r.result && r.result.value) break;
      await sleep(250);
    }
    const r = await send('Runtime.evaluate', {
      expression: `[...document.querySelectorAll('.nav-item[data-page]')].map(n => n.getAttribute('data-page')).filter(Boolean)`,
      returnByValue: true,
    });
    routes = r.result.value || [];
    ws.close();
  } finally {
    await closeChrome(chrome, dirDisc);
  }
}
if (routes.length < 5) {
  console.error(`FAIL  discovered only ${routes.length} route(s) from the panel's nav — this sweep would cover almost nothing`);
  process.exit(1);
}
console.log(`  routes: ${routes.join(', ')}\n`);

let bad = 0;
for (let i = 0; i < routes.length; i++) {
  const r = routes[i];
  const res = await visit(`${BASE}#${r}`, PORT0 + 2 + i, r);
  const d = res.drew || { nodes: 0, controls: 0, text: 0, skeleton: false };
  // A page that loaded but drew nothing is the failure this whole file exists for.
  const empty = d.nodes < 5 || d.text < 20;
  // 'upstream-unreachable' is reported but does not fail: see the network handler above.
  const errs = res.faults.filter((f) => /exception|console-error|load-failed|aborted/.test(f.kind) || /^http-5/.test(f.kind));
  const notes = res.faults.filter((f) => f.kind === 'upstream-unreachable');
  const ok = !errs.length && !empty && !d.skeleton;
  if (!ok) bad++;
  const did = res.acted && res.acted.clicked ? `  pressed "${res.acted.clicked}"` : '  (no safe primary control)';
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${r.padEnd(13)} nodes=${String(d.nodes).padStart(4)} controls=${String(d.controls).padStart(3)} ` +
    `text=${String(d.text).padStart(5)}${d.skeleton ? ' STILL-SKELETON' : ''}${did}${errs.length ? `  ${errs.length} fault(s)` : ''}`);
  for (const f of errs.slice(0, 3)) console.log(`         [${f.kind}] ${f.text}`);
  for (const f of notes.slice(0, 2)) console.log(`         (${f.kind}) ${f.text}`);
  if (empty) console.log('         drew nothing — a cold visit to this route leaves the page blank');
}

console.log('');
if (bad) {
  console.error(`${bad} route(s) fail when opened cold. The page sweep cannot see this: it loads every ` +
    'route in one browser in a fixed order, so each page is judged with whatever the earlier ones left behind.');
  process.exit(1);
}
console.log(`every one of the ${routes.length} routes renders when it is the first page loaded`);
