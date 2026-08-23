// ui-wrap.mjs — is anything that should be one line taking two?
//
// A value broken across lines mid-unit ("↓3.8 MB/s ↑845.5" / "KB/s") or a card title split in half
// is the kind of flaw that reads as sloppy without being nameable. It is measurable: an element whose
// CONTENT box is taller than one line-height has wrapped.
//
// The word CONTENT matters. The first cut of this divided the border-box height by line-height, so a
// pill with 4px of vertical padding and an 11px font came out at 1.5 lines, rounded to 2, and it
// reported 35 wraps that were all padding. Subtract padding and border first, and use a tolerance,
// because sub-pixel line boxes are normal.
//
//   node scripts/ui-wrap.mjs <url> [cdp-port]
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { authenticateCDP } from './ui-auth.mjs';

const URL_ARG = process.argv[2];
const PORT = Number(process.argv[3] || 9722);
if (!URL_ARG) { console.error('usage: node scripts/ui-wrap.mjs <url> [cdp-port]'); process.exit(2); }
const PAGES = ['dashboard', 'server', 'connections', 'failover', 'routing', 'dns', 'updater',
  'diagnostics', 'settings'];
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const httpJSON = async (u) => (await fetch(u)).json();
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wayhop-wrap-'));
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
  `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`, '--window-size=1280,900', 'about:blank'],
  { stdio: 'ignore' });

// Elements whose job is to be exactly one line. A stat value, a card title, a status chip: if any of
// these wraps, the page looks broken rather than merely full.
const SINGLE_LINE = '.card-title, .sys-v, .fo-band-t, .exit-name, .exit-ip, .upd-r, .pill, .badge, .rl-chip';

const COLLECT = `(() => {
  const v = document.querySelector('#view');
  if (!v) return null;
  const out = [];
  let checked = 0;
  for (const n of v.querySelectorAll(${JSON.stringify(SINGLE_LINE)})) {
    const cs = getComputedStyle(n);
    if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    const b = n.getBoundingClientRect();
    if (b.height < 1) continue;
    // Content height: strip padding and border, which is what the first version forgot.
    const pad = parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom) +
                parseFloat(cs.borderTopWidth) + parseFloat(cs.borderBottomWidth);
    const content = b.height - (isFinite(pad) ? pad : 0);
    let lh = parseFloat(cs.lineHeight);
    if (!isFinite(lh)) lh = parseFloat(cs.fontSize) * 1.4;
    checked++;
    // 1.35 rather than 1.5: a second line always adds a full line-height, and glyphs with tall
    // ascenders can push a single line a little past 1.0 without wrapping.
    if (content > lh * 1.35) {
      out.push({
        cls: (n.className || n.tagName).toString().trim().slice(0, 26),
        lines: Math.round((content / lh) * 10) / 10,
        w: Math.round(b.width),
        txt: (n.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 46),
      });
    }
  }
  return { out, checked };
})()`;

let bad = 0, checked = 0;
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
  await send('Page.navigate', { url: URL_ARG });
  for (let i = 0; i < 160; i++) {
    if (await ev('typeof route === "function"').catch(() => false)) break;
    await sleep(250);
  }
  await authenticateCDP({ send, evaluate: ev, url: URL_ARG });
  console.log(`  ${URL_ARG}`);
  for (const p of PAGES) {
    await ev(`location.hash = '#${p}'`);
    for (let i = 0, prev = null, streak = 0; i < 50; i++) {
      await sleep(300);
      const d = await ev(`(() => { const v = document.querySelector('#view');
        return v ? { h: v.scrollHeight, n: v.querySelectorAll('*').length } : null; })()`);
      const same = prev && d && d.h === prev.h && d.n === prev.n;
      streak = (same && pending() === 0) ? streak + 1 : 0;
      if (streak >= 5) break;
      prev = d;
    }
    const r = await ev(COLLECT);
    if (!r) { console.error(`FAIL  ${p}: no #view`); bad++; continue; }
    checked += r.checked;
    if (!r.out.length) { console.log(`  ${p.padEnd(12)} ok   ${r.checked} single-line elements`); continue; }
    bad += r.out.length;
    console.error(`FAIL  ${p.padEnd(12)} ${r.out.length} of ${r.checked} wrapped`);
    for (const x of r.out.slice(0, 5)) {
      console.error(`        ${x.lines}L  w=${String(x.w).padStart(4)}  .${x.cls.padEnd(22)} "${x.txt}"`);
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

if (bad) {
  console.error(`\n${bad} element(s) that should be one line are wrapping. A value broken mid-unit or a` +
    ' title split in half reads as broken rather than as full.');
  process.exit(1);
}
console.log(`\nnothing that should be one line is wrapping`);
console.log(`subjects: ${checked} single-line elements measured`);
