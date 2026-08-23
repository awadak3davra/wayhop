// router-edit-dialogs.mjs — open every Edit dialog and check it came up FILLED.
//
// The live sweep already opens dialogs and listens for faults. A dialog that opens empty raises no
// fault at all: the page renders, the modal appears, every field is blank, and a check that only
// watches for exceptions calls that a pass. The panel's own code names this hazard twice — "a
// non-rerendering save reassigns the state, orphaning the rule instances the rendered rows captured" —
// and an orphaned row edits nothing while looking exactly like a row that edits something.
//
// So this asserts content: for each Edit control it can reach, the dialog must open and carry values.
// It reads and cancels; it never saves. Cancel is pressed by name, and if no cancel is found the run
// says so rather than leaving a dialog open over the next one.
//
//   node scripts/router-edit-dialogs.mjs <panel-url> [--max 4] [--port cdp]
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const args = process.argv.slice(2);
const flag = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const URL_ARG = args.find((a) => /^https?:\/\//.test(a));
const MAX = Number(flag('--max') || 4);
const PORT = Number(flag('--port') || 9690);
if (!URL_ARG) {
  console.error('usage: node scripts/router-edit-dialogs.mjs <panel-url> [--max N]');
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

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'edit-'));
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
  '--hide-scrollbars', `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`,
  '--window-size=1400,1100', 'about:blank'], { stdio: 'ignore' });

let bad = 0;
const faults = [];
try {
  let targets = null;
  for (let i = 0; i < 60; i++) {
    try { targets = await httpJSON(`http://127.0.0.1:${PORT}/json/list`); break; } catch { await sleep(250); }
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
      faults.push(String(d.exception?.description || d.text || '').split('\n')[0].slice(0, 200));
    }
  };
  const send = (method, params = {}) => new Promise((res, rej) => {
    const i = ++id;
    // 120s, not 45s. A page's walk takes about 11 seconds alone; run beside the suite's other browser
    // gates it went past 45 and the call timed out, failing a page that was fine. The margin is now
    // ten times the measured cost. Splitting the walk into one call per dialog would remove the
    // fragility rather than pad it, and is NOT done here — the deadline is the whole fix.
    const to = setTimeout(() => { waiting.delete(i); rej(new Error(`CDP ${method} got no reply in 120000ms`)); }, 120000);
    waiting.set(i, (m) => { clearTimeout(to); return m.error ? rej(new Error(m.error.message)) : res(m.result); });
    ws.send(JSON.stringify({ id: i, method, params }));
  });
  const ev = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || 'eval failed');
    return r.result.value;
  };

  await send('Page.enable'); await send('Runtime.enable');
  console.log(`  target: ${BASE}`);
  await send('Page.navigate', { url: BASE });
  for (let i = 0; i < 200; i++) { if (await ev('typeof route === "function"').catch(() => false)) break; await sleep(250); }

  const routes = await ev(`[...document.querySelectorAll('.nav-item[data-page]')].map(n => n.getAttribute('data-page')).filter(Boolean)`);
  if (!routes || routes.length < 5) {
    console.error(`FAIL  discovered ${(routes || []).length} route(s) — nothing to walk`);
    process.exit(1);
  }

  let opened = 0;
  for (const r of routes) {
    await ev(`location.hash = '#${r}'`);
    await sleep(3500);
    // This walks a whole page inside ONE Runtime.evaluate. It is the fragile shape — a single call
    // whose duration grows with the number of rows — and it is what timed out when the suite ran this
    // gate beside its other browser work. The deadline above now carries ten times the measured cost,
    // which holds; splitting the walk into a call per dialog is the structural answer if it recurs.
    const res = await ev(`(async () => {
      const out = [];
      // Pages with a master-detail inspector render the actions of the SELECTED row only, so a single
      // pass finds one Edit control and reports full coverage of a page holding five objects of four
      // different protocols — each with its own form. Select each row first.
      const rows = [...document.querySelectorAll('#view .insp-row')].slice(0, ${MAX});
      const editsFor = () => [...document.querySelectorAll('#view button')]
        .filter(b => /^edit$/i.test((b.textContent || '').trim()) || /^edit /i.test(b.getAttribute('aria-label') || ''));

      const targets = [];
      if (rows.length > 1) {
        for (const row of rows) {
          row.click();
          await new Promise(x => setTimeout(x, 900));
          const e = editsFor()[0];
          if (e) targets.push(e);
        }
      } else {
        targets.push(...editsFor().slice(0, ${MAX}));
      }

      for (const b of targets) {
        const what = (b.getAttribute('aria-label') || 'Edit').slice(0, 48);
        b.click();
        await new Promise(x => setTimeout(x, 1100));
        const m = document.querySelector('.modal, dialog[open], .drawer');
        if (!m) { out.push({ what, opened: false }); continue; }
        const fields = [...m.querySelectorAll('input, select, textarea')]
          .filter(f => f.type !== 'hidden' && f.type !== 'file');
        const filled = fields.filter(f => {
          if (f.type === 'checkbox' || f.type === 'radio') return true; // a false checkbox is a value
          return String(f.value || '').trim() !== '';
        }).length;
        const closer = [...m.querySelectorAll('button')].find(x => /^(cancel|close|×|отмена)$/i.test((x.textContent||'').trim()))
          || m.querySelector('[data-close], .modal-close');
        if (closer) closer.click();
        else document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
        await new Promise(x => setTimeout(x, 700));
        const stillOpen = !!document.querySelector('.modal, dialog[open], .drawer');
        out.push({ what, opened: true, fields: fields.length, filled, closed: !stillOpen });
        if (stillOpen) break; // do not stack dialogs; report and stop on this page
      }
      return out;
    })()`);

    if (!res.length) { console.log(`  ${r.padEnd(13)} no Edit controls`); continue; }
    for (const d of res) {
      opened++;
      const ok = d.opened && d.fields > 0 && d.filled > 0 && d.closed;
      if (!ok) bad++;
      console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${r.padEnd(13)} ${String(d.what).padEnd(40)} ` +
        (d.opened ? `fields=${d.fields} filled=${d.filled}${d.closed ? '' : ' STILL-OPEN'}` : 'did not open'));
      if (d.opened && d.fields > 0 && d.filled === 0) {
        console.log('         the dialog opened with every field blank — editing this object would write emptiness');
      }
    }
  }

  console.log(`\n  ${opened} edit dialog(s) opened and closed`);
  if (!opened) {
    console.error('  FAIL  no Edit control was found anywhere, so this run proved nothing');
    bad++;
  }
  ws.close();
} catch (e) {
  console.error(`\nrun aborted: ${e.message}`);
  bad++;
} finally {
  await closeChrome(chrome, dir);
}

if (faults.length) {
  console.error(`\n  ${faults.length} page exception(s):`);
  for (const f of faults.slice(0, 6)) console.error(`    ${f}`);
  bad += faults.length;
}
process.exit(bad ? 1 : 0);
