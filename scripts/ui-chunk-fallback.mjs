// Route-scoped chunks add a failure mode the single bundle never had: the page's code can fail to
// arrive. Two things must hold, and neither is covered by a gate, so they are observed here.
//
//   1. A blocked chunk shows the ordinary render error — NOT a permanent skeleton, and not a page
//      that looks finished but is missing its controls (the AUD-78 shape).
//   2. Navigating back after the block clears actually retries. loadChunk deletes the cached promise
//      on failure specifically so a transient drop is not fatal for the rest of the session; if that
//      delete is wrong, the page stays broken until a full reload.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { authenticateCDP } from './ui-auth.mjs';

const URL_ARG = process.argv[2];
const PORT = Number(process.argv[3] || 9600);
if (!URL_ARG) { console.error('usage: node scripts/ui-chunk-fallback.mjs <url> [cdp-port]'); process.exit(2); }
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const httpJSON = async (u) => (await fetch(u)).json();
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wayhop-cf-'));
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
  `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`, '--window-size=1280,900', 'about:blank'],
  { stdio: 'ignore' });
let failures = 0;
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
  await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
  await send('Page.navigate', { url: URL_ARG });
  for (let i = 0; i < 160; i++) {
    if (await ev('typeof route === "function"').catch(() => false)) break;
    await sleep(250);
  }
  await authenticateCDP({ send, evaluate: ev, url: URL_ARG });
  const state = () => ev(`(() => {
    const v = document.querySelector('#view');
    return { skeleton: !!v.querySelector('.skeleton-page'),
             controls: v.querySelectorAll('button, input, select, textarea, [role="button"], a[href]').length,
             err: /could not load|page-dns/i.test(v.textContent || ''),
             txt: (v.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 110) };
  })()`);

  // 1. block the chunk, open the page
  await send('Network.setBlockedURLs', { urls: ['*page-dns.js'] });
  await ev(`location.hash = '#dns'`);
  await sleep(6000);
  const blocked = await state();
  const ok1 = !blocked.skeleton && blocked.err;
  if (!ok1) failures++;
  console.log(`  blocked chunk:  ${ok1 ? 'ok  ' : 'FAIL'} skeleton=${blocked.skeleton} names-the-failure=${blocked.err} controls=${blocked.controls}`);
  console.log(`                  screen: ${blocked.txt}`);

  // 2. unblock, navigate away and back — it must retry, not stay broken
  await send('Network.setBlockedURLs', { urls: [] });
  await ev(`location.hash = '#dashboard'`);
  await sleep(2500);
  await ev(`location.hash = '#dns'`);
  await sleep(7000);
  const recovered = await state();
  const ok2 = !recovered.skeleton && !recovered.err && recovered.controls > 3;
  if (!ok2) failures++;
  console.log(`  after recovery: ${ok2 ? 'ok  ' : 'FAIL'} skeleton=${recovered.skeleton} still-erroring=${recovered.err} controls=${recovered.controls}`);
  if (!ok2) console.log(`                  screen: ${recovered.txt}`);
  ws.close();
} finally {
  chrome.kill();
  await new Promise((r) => setTimeout(r, 1200));
  try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 12, retryDelay: 250 }); } catch (_) {}
  // Not silent: a directory that survives is a browser that may still be running, and enough of
  // those starve the next gate. Say it here rather than leave it to be counted in /tmp later.
  if (fs.existsSync(dir)) console.error(`note: could not remove the Chrome profile dir ${dir}`);
}
console.log(failures ? `  ${failures} check(s) failed` : '  a dropped chunk degrades honestly and recovers on the next visit');
process.exit(failures ? 1 : 0);
