// ui-kernel-carried.mjs — a component the kernel already carries must not be offered for install.
//
// The Updater row said three things at once on a live router: "in the kernel", "the userspace
// build is not needed here", and an active "Install with apk". Every word true, and together they
// read as an instruction to fix a router that was working — the kernel module was carrying their
// tunnel at that moment.
//
// The state cannot be produced by the demo: carried_by_kernel comes from platform.DetectCapabilities,
// which finds nothing on a dev box. So the engine list is STUBBED at the network layer, before the
// app loads, and the assertions are made against the DOM the real app.js builds from it. That keeps
// the subject the shipped code rather than a re-implementation of it.
//
// Usage: node scripts/ui-kernel-carried.mjs <url>
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { authenticateCDP } from './ui-auth.mjs';

const URL_ARG = process.argv[2];
if (!URL_ARG) {
  console.error('usage: node scripts/ui-kernel-carried.mjs <url>');
  process.exit(2);
}
const base = URL_ARG.replace(/\/+$/, '');
const PORT = Number(process.env.CDP_PORT || 9533);
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let fails = 0;
const check = (name, ok, detail) => {
  if (!ok) fails++;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '   [' + detail + ']' : ''}`);
};

// One engine the kernel carries, one it does not, so every assertion has a control: if the selectors
// simply stopped matching, the "still offered" case would fail too and the run could not be read as
// a pass.
const engines = (pm) => ({
  arch: 'amd64',
  mirrors: [''],
  package_manager: pm,
  engines: [
    {
      id: 'amneziawg-go', name: 'AmneziaWG (userspace)', role: 'kernel-plugin', provides: 'amneziawg',
      installed: { present: false, version: '', path: '' },
      carried_by_kernel: true, ownership_unknown: false, native_managed: false,
    },
    {
      id: 'sing-box', name: 'sing-box', role: 'core', provides: 'singbox',
      installed: { present: false, version: '', path: '' },
      carried_by_kernel: false, ownership_unknown: false, native_managed: false,
    },
    // Owned by the package manager. The row's own buttons were already withheld for this state, but
    // the version picker is built by the per-row check that "Check all" runs for every row — so this
    // one still grew a self-managed "Install selected" over a binary opkg or apk owns.
    {
      id: 'olcrtc', name: 'olcRTC', role: 'socks-plugin', provides: 'olcrtc',
      installed: { present: true, version: '1.0.0', path: '/usr/sbin/olcrtc' },
      carried_by_kernel: false, ownership_unknown: false,
      native_managed: true, native_owner: 'olcrtc',
    },
  ],
});

// The per-engine version list, so the picker actually renders. Without it `pickable` is null and the
// control this gate is looking for never exists — a check that would pass by measuring nothing.
const versionsFor = (id) => ({
  installed: id === 'olcrtc' ? '1.0.0' : '',
  latest: '1.2.0',
  versions: ['1.2.0', '1.1.0', '1.0.0'],
});

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kc-'));
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
  '--hide-scrollbars', `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`,
  '--window-size=1280,900', 'about:blank'], { stdio: 'ignore' });

const cleanup = () => {
  if (chrome && chrome.exitCode === null && !chrome.killed) chrome.kill();
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* the browser may still hold it */ }
};

let ws;
try {
  let ver = null;
  for (let i = 0; i < 60 && !ver; i++) {
    try { ver = await (await fetch(`http://127.0.0.1:${PORT}/json/version`)).json(); } catch { await sleep(250); }
  }
  if (!ver) throw new Error('the browser never opened its debugging port');
  const targets = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
  const page = targets.find((t) => t.type === 'page') || targets[0];
  ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });

  let id = 0;
  const waiting = new Map();
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); }
  };
  // Every command gets a deadline. A CDP call that never answers used to hang a gate forever, which
  // prints nothing at all — no gate name, no location.
  const send = (method, params) => new Promise((res, rej) => {
    const myId = ++id;
    const timer = setTimeout(() => { waiting.delete(myId); rej(new Error(`${method}: no reply in 20s`)); }, 20000);
    waiting.set(myId, (m) => { clearTimeout(timer); res(m); });
    ws.send(JSON.stringify({ id: myId, method, params }));
  });
  const evaluate = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.result && r.result.exceptionDetails) throw new Error(r.result.exceptionDetails.text);
    return r.result && r.result.result ? r.result.result.value : undefined;
  };

  await send('Page.enable', {});
  await send('Runtime.enable', {});
  await send('Page.navigate', { url: URL_ARG });
  for (let i = 0; i < 160; i++) {
    if (await evaluate('typeof route === "function"').catch(() => false)) break;
    await sleep(250);
  }
  await authenticateCDP({ send, evaluate, url: URL_ARG });

  let stubId = null;
  for (const pm of ['apk', 'opkg']) {
    for (const [label, w, h] of [['desktop', 1280, 900], ['mobile', 375, 812]]) {
      // The stub is installed BEFORE any document script runs, so app.js sees it on its first fetch.
      const stub = `window.fetch = (orig => function (u, o) {
        const s = String(u && u.url ? u.url : u);
        if (s.includes('/api/updater/engines')) {
          return Promise.resolve(new Response(${JSON.stringify(JSON.stringify(engines(pm)))},
            { status: 200, headers: { 'Content-Type': 'application/json' } }));
        }
        var m = s.match(/\\/api\\/updater\\/([^/]+)\\/versions/);
        if (m) {
          var vs = ${JSON.stringify(JSON.stringify({ ac: versionsFor('amneziawg-go'), sb: versionsFor('sing-box'), ol: versionsFor('olcrtc') }))};
          var by = JSON.parse(vs);
          var pick = m[1] === 'olcrtc' ? by.ol : (m[1] === 'sing-box' ? by.sb : by.ac);
          return Promise.resolve(new Response(JSON.stringify(pick),
            { status: 200, headers: { 'Content-Type': 'application/json' } }));
        }
        return orig(u, o);
      })(window.fetch);`;
      // Removed before the next one is added. These accumulate per page load, and a stacked set
      // wraps fetch in an order that made every opkg run answer with the apk payload — the gate
      // printed four opkg PASS lines while measuring apk twice, which is the exact thing it exists
      // to catch one level up.
      if (stubId) await send('Page.removeScriptToEvaluateOnNewDocument', { identifier: stubId });
      const added = await send('Page.addScriptToEvaluateOnNewDocument', { source: stub });
      stubId = added.result && added.result.identifier;
      if (!stubId) throw new Error('the fetch stub was not registered; the page would answer from the real daemon');
      await send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: w < 768 });
      // about:blank first, then the page. Navigating straight from `…/#updater` to the same URL is a
      // hash change, not a document load, so the new-document script never re-runs and every later
      // iteration keeps the FIRST payload — the gate printed opkg PASS lines for a page that had only
      // ever been handed the apk one.
      await send('Page.navigate', { url: 'about:blank' });
      await sleep(200);
      await send('Page.navigate', { url: `${base}/#updater` });
      await sleep(2500);
      const servedPM = await evaluate(`fetch('/api/updater/engines').then(r => r.json()).then(j => j.package_manager)`);
      if (servedPM !== pm) {
        throw new Error(`the page is being served "${servedPM}" while this iteration is for "${pm}" — ` +
          'the stub did not take, so the assertions below would describe the wrong configuration');
      }

      // The operational sweep builds the compatibility core's version picker. The old label was
      // "Check all", which became false once native/deferred catalog rows left this page.
      const swept = await evaluate(`(async () => {
        const b = [...document.querySelectorAll('button')]
          .find(x => (x.textContent || '').trim() === 'Check updates');
        if (!b) return false;
        b.click(); await new Promise(r => setTimeout(r, 2500)); return true;
      })()`);

      const seen = await evaluate(`(() => {
        const rows = [...document.querySelectorAll('.upd-item')];
        const rowFor = (txt) => rows.find(r => r.textContent.includes(txt));
        const kernelRow = rowFor('AmneziaWG');
        const plainRow  = rowFor('sing-box');
        const deferredRow = rowFor('olcRTC');
        return {
          rowCount: rows.length,
          kernelRowFound: !!kernelRow,
          deferredRowFound: !!deferredRow,
          plainRowFound: !!plainRow,
          plainRole: plainRow ? (plainRow.querySelector('.upd-r') || {}).textContent : '',
          plainHasPicker: !!(plainRow && plainRow.querySelector('.upd-pick select')),
          plainHasInstallSelected: (() => {
            const row = rowFor('sing-box');
            return row ? [...row.querySelectorAll('button')]
              .some(b => /install selected/i.test(b.textContent || '')) : false;
          })(),
          mentionsKernelInstall: [...document.querySelectorAll('button')]
            .some(b => /amnezia|userspace build/i.test((b.textContent || '') + ' ' + (b.getAttribute('aria-label') || ''))),
        };
      })()`);

      const tag = `${pm}/${label}`;
      check(`${tag}: the operational sweep control rendered and ran`, swept);
      check(`${tag}: only WayHop and the optional core are operational rows`, seen.rowCount === 2,
        `rows=${seen.rowCount}`);
      check(`${tag}: the kernel-carried userspace alternative stays out of Updater`, !seen.kernelRowFound);
      check(`${tag}: the deferred olcRTC plugin stays out of Updater`, !seen.deferredRowFound);
      check(`${tag}: the optional compatibility core remains visible`, seen.plainRowFound);
      check(`${tag}: sing-box is labelled as optional compatibility`, /optional compatibility/i.test(seen.plainRole),
        JSON.stringify(seen.plainRole));
      check(`${tag}: the sweep loaded versions for the optional core`, seen.plainHasPicker);
      check(`${tag}: an unowned optional core remains installable`, seen.plainHasInstallSelected);
      check(`${tag}: no kernel-component install control leaks into Updater`, !seen.mentionsKernelInstall);
    }
  }
} catch (e) {
  console.error('FAIL  ' + (e && e.message ? e.message : String(e)));
  fails++;
} finally {
  if (ws) { try { ws.close(); } catch { /* already gone */ } }
  cleanup();
}

if (fails) {
  console.error(`\n${fails} kernel-carried problem(s).`);
  process.exit(1);
}
console.log('kernel-carried components: 36 checks across apk/opkg and desktop/mobile, no install offered');
