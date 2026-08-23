// ui-names.mjs — fail if any route renders two buttons with the same accessible name.
//
// The audit found "Delete" three times over on Connections and on DNS, "Check updates" three times
// on Updater. A destructive control whose name omits its object is indistinguishable from its
// neighbours to anyone using the accessible name rather than the surrounding layout — a screen
// reader, a voice-control user, or an automated test. This gate keeps that from coming back.
//
// The name is read the way assistive tech resolves it: aria-label wins over text content.
// Usage: node scripts/ui-names.mjs http://HOST:PORT/
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
if (!URL_ARG) { console.error('usage: node scripts/ui-names.mjs <url>'); process.exit(2); }
const PORT = Number(process.env.CDP_PORT || 9514);
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const PAGES = 'dashboard,server,connections,failover,routing,dns,updater,diagnostics,settings'.split(',');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const httpJSON = async (u) => (await fetch(u)).json();

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wayhop-names-'));
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
  `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`, '--window-size=1280,900', 'about:blank'],
  { stdio: 'ignore' });

let failures = 0;
let examined = 0;   // named controls actually seen, so the summary reports a measurement not a constant
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

  for (const p of PAGES) {
    await ev(`location.hash = '#${p}'`);
    await sleep(1800);
    const names = await ev(`(() => {
      const out = [];
      // Not just <button>. The Dashboard's only interactive elements are two link-buttons and a
      // card header carrying role=button — none of which this gate saw, so the one page where the
      // distinction matters was the one page it never checked.
      document.querySelectorAll('#view button, #view [role="button"], #view a[href]').forEach(b => {
        const n = (b.getAttribute('aria-label') || b.textContent || '').replace(/\\s+/g, ' ').trim();
        if (n) out.push(n);
      });
      return out;
    })()`);
    examined += names.length;
    const counts = {};
    names.forEach((x) => { counts[x] = (counts[x] || 0) + 1; });
    const dup = Object.entries(counts).filter(([, c]) => c > 1);
    if (dup.length) {
      failures += dup.length;
      console.error(`FAIL ${p}: ${dup.map(([x, c]) => `"${x}" x${c}`).join(', ')}`);
    }
  }
  ws.close();
} finally {
  await closeChrome(chrome, dir);
}

if (failures) {
  console.error(`\n${failures} duplicate button name(s). Give each one an aria-label naming its object.`);
  process.exit(1);
}
// PAGES.length is a constant. Reporting it as the result meant this gate announced "unique on all 9
// routes" whether it had examined nine hundred controls or none — and it was watched doing exactly
// that: with the selector pointed at a class that does not exist, it exited 0 with the same
// triumphant sentence. The count below is what it actually looked at, and verify.mjs holds it to a
// floor, so the sentence can no longer be true of an empty page.
console.log(`button names unique across ${PAGES.length} routes`);
console.log(`subjects: ${examined} named controls examined`);
