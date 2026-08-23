// ui-rtl.mjs — the panel ships Arabic and Persian. Has anyone ever looked at it in RTL?
//
// app.js sets dir="rtl" on <html> for the languages in RTL_LANGS, and web/dist/i18n/{ar,fa}.js are
// both shipped, so this is a live code path for real users. It has never been rendered by anything in
// this suite: every measurement, screenshot and gate has run left-to-right.
//
// The prior is bad. styles.css uses 73 physical direction properties (margin-left, padding-right,
// left:, text-align:left) and ZERO logical ones (margin-inline-start, inset-inline, text-align:start).
// Physical properties do not flip when the document direction does, so a layout built from them is
// mirrored in some places and not in others.
//
// What this asserts, at desktop width so it is not confounded with the narrow-viewport gate:
//   1. The direction actually flipped — otherwise the whole run measures LTR and proves nothing.
//   2. Nothing overflows the viewport. In RTL the overflow goes LEFT, past x=0, which is the case an
//      LTR-shaped check (right edge only) would miss entirely.
//   3. Each route still renders its content and controls, so a layout that collapsed is not read as
//      a layout that fits.
//
//   node scripts/ui-rtl.mjs <url> [cdp-port]
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { authenticateCDP } from './ui-auth.mjs';

const URL_ARG = process.argv[2];
const PORT = Number(process.argv[3] || 9680);
if (!URL_ARG) { console.error('usage: node scripts/ui-rtl.mjs <url> [cdp-port]'); process.exit(2); }
// Persian, because it is the RTL language this panel actually ships. Arabic was the subject until the
// language list was cut to the markets WayHop serves, and a gate pointed at a dictionary that no
// longer exists measures an LTR page wearing an RTL label — which is exactly what it reported.
// web/i18n/langs.json names the RTL set; keep this in step with it.
const LANG = process.env.WR_RTL_LANG || 'fa';
const PAGES = ['dashboard', 'server', 'connections', 'failover', 'routing', 'dns', 'updater',
  'diagnostics', 'settings'];
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const httpJSON = async (u) => (await fetch(u)).json();
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wayhop-rtl-'));
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
  `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`, '--window-size=1280,900', 'about:blank'],
  { stdio: 'ignore' });

let bad = 0, subjects = 0;
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

  // Settle on the measurement rather than on a timer, for the reason AUD-80 records: a page still
  // filling in has fewer elements and therefore cannot overflow, so a flat wait turns this gate
  // into one that passes hardest exactly when the page is least finished.
  // Returns { d, settled }. The budget running out is NOT the same event as the page going quiet,
  // and collapsing the two is what let this gate report a defect it had not established.
  const settle = async (measure) => {
    let d = null, prev = null, streak = 0;
    for (let i = 0; i < 60; i++) {
      await sleep(300);
      d = await ev(measure);
      const same = prev && d && prev && d.nodes === prev.nodes && d.controls === prev.controls;
      streak = (same && pending() === 0) ? streak + 1 : 0;
      if (streak >= 5) return { d, settled: true };
      prev = d;
    }
    return { d, settled: false };
  };

  // LTR baseline FIRST. "Nothing overflows" is not the same claim as "the same page rendered":
  // a route that quietly drops content in RTL passes an overflow check perfectly.
  const COUNT = `(() => {
    const v = document.querySelector('#view');
    if (!v) return null;
    return { nodes: v.querySelectorAll('*').length,
             controls: v.querySelectorAll('button, input, select, textarea, [role="button"], a[href]').length };
  })()`;
  // The both-edges overflow scan, extracted so the 1280px pass and the narrow passes cannot drift
  // into measuring different things under the same name.
  const NARROW_SCAN = `(() => {
    const vw = window.innerWidth;
    const v = document.querySelector('#view');
    if (!v) return null;
    const inScroller = (n) => {
      for (let q = n.parentElement; q; q = q.parentElement) {
        const ox = getComputedStyle(q).overflowX;
        if ((ox === 'auto' || ox === 'scroll') && q.scrollWidth > q.clientWidth) return true;
        if (q === document.body) break;
      }
      return false;
    };
    const out = [];
    let scanned = 0;
    for (const n of v.querySelectorAll('*')) {
      const b = n.getBoundingClientRect();
      if (b.width < 1 && b.height < 1) continue;
      scanned++;
      const overLeft = -b.left, overRight = b.right - vw;
      if ((overLeft > 1 || overRight > 1) && !inScroller(n)) {
        out.push({ cls: (n.className || n.tagName).toString().trim().slice(0, 34),
                   left: Math.round(b.left), right: Math.round(b.right),
                   side: overLeft > overRight ? 'left' : 'right' });
      }
    }
    return { vw, scanned, out: out.slice(0, 4), n: out.length,
             nodes: v.querySelectorAll('*').length };
  })()`;

  const ltr = {}, unsettled = new Set();
  for (const p of PAGES) {
    await ev(`location.hash = '#${p}'`);
    const r = await settle(COUNT);
    if (!r.settled) unsettled.add(p);
    ltr[p] = r.d;
  }

  // Switch through the app's own language machinery, then reload so it boots in that language the way
  // a real user's browser would.
  await ev(`(() => { try { localStorage.setItem('wr-lang', ${JSON.stringify(LANG)}); } catch (e) {} })()`);
  await send('Page.navigate', { url: URL_ARG });
  for (let i = 0; i < 160; i++) {
    if (await ev('typeof route === "function"').catch(() => false)) break;
    await sleep(250);
  }
  await sleep(1200);

  // Confirm the direction flipped BEFORE measuring anything. Without this the whole run could be an
  // LTR run wearing an RTL label — the "check that passes when its subject is absent" trap, and the
  // easiest one to fall into here because every page would simply look fine.
  const state = await ev(`(() => ({
    dir: document.documentElement.getAttribute('dir'),
    lang: (function () { try { return localStorage.getItem('wr-lang'); } catch (e) { return null; } })(),
    computed: getComputedStyle(document.documentElement).direction,
  }))()`);
  console.log(`  ${URL_ARG}  lang=${state.lang} dir=${state.dir} computed-direction=${state.computed}`);
  if (state.computed !== 'rtl') {
    console.error(`FAIL  the document did not switch to RTL (computed direction=${state.computed}).`);
    console.error('      Every measurement below would be an LTR run wearing an RTL label.');
    bad++;
  } else {
    for (const p of PAGES) {
      await ev(`location.hash = '#${p}'`);
      const rtlSettle = await settle(COUNT);
      if (!rtlSettle.settled) unsettled.add(p);
      const r = await ev(`(() => {
        const vw = window.innerWidth;
        const v = document.querySelector('#view');
        if (!v) return null;
        // In RTL the overflow runs LEFT, past x=0. A check that only looks at the right edge — the
        // shape every LTR check here has — would report a mirrored-broken page as perfect.
        const inScroller = (n) => {
          for (let q = n.parentElement; q; q = q.parentElement) {
            const ox = getComputedStyle(q).overflowX;
            if ((ox === 'auto' || ox === 'scroll') && q.scrollWidth > q.clientWidth) return true;
            if (q === document.body) break;
          }
          return false;
        };
        const out = [];
        let scanned = 0;
        for (const n of v.querySelectorAll('*')) {
          const b = n.getBoundingClientRect();
          if (b.width < 1 && b.height < 1) continue;
          scanned++;
          const overLeft = -b.left;
          const overRight = b.right - vw;
          if ((overLeft > 1 || overRight > 1) && !inScroller(n)) {
            out.push({ cls: (n.className || n.tagName).toString().trim().slice(0, 34),
                       left: Math.round(b.left), right: Math.round(b.right),
                       side: overLeft > overRight ? 'left' : 'right',
                       txt: (n.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 30) });
          }
        }
        out.sort((a, b) => (Math.max(-a.left, a.right - vw)) - (Math.max(-b.left, b.right - vw))).reverse();
        return { vw, scanned, out: out.slice(0, 4), n: out.length,
                 controls: v.querySelectorAll('button, input, select, textarea, [role="button"], a[href]').length,
                 nodes: v.querySelectorAll('*').length };
      })()`);
      if (!r) { bad++; console.error(`FAIL  ${p}: no #view`); continue; }
      subjects += r.scanned;
      if (r.n) {
        bad++;
        console.error(`FAIL  ${p.padEnd(12)} ${r.n} element(s) outside the ${r.vw}px viewport in RTL`);
        for (const x of r.out) {
          console.error(`        past the ${x.side} edge: left=${x.left} right=${x.right}  ${x.cls}` +
            `  ${x.txt ? '"' + x.txt + '"' : ''}`);
        }
      } else if (!r.nodes) {
        bad++;
        console.error(`FAIL  ${p.padEnd(12)} rendered nothing in RTL`);
      } else if (unsettled.has(p)) {
        // The budget ran out on one side or the other, so the two samples are not of comparable
        // moments. Reporting this as "renders less in RTL" is how the suite once accused the product
        // of dropping content on two routes that standalone measured identical to LTR — the counts
        // were a route behind, which is what an unsettled sample looks like.
        bad++;
        console.error(`FAIL  ${p.padEnd(12)} NOT MEASURED — the route never settled within 18s, so the` +
          ` LTR and RTL samples are not of comparable moments (RTL ${r.nodes} nodes vs LTR` +
          ` ${ltr[p] ? ltr[p].nodes : '?'})`);
      } else if (ltr[p] && r.nodes < ltr[p].nodes * 0.8) {
        // Rendered, inside the viewport, and materially smaller than the same route in LTR. That is
        // content lost to the direction switch, and an overflow-only check would call it a pass.
        bad++;
        console.error(`FAIL  ${p.padEnd(12)} renders less in RTL: ${r.nodes} nodes vs ${ltr[p].nodes} in LTR` +
          ` (controls ${r.controls} vs ${ltr[p].controls})`);
      } else {
        console.log(`  ${p.padEnd(12)} ok   controls=${String(r.controls).padStart(3)} nodes=${r.nodes}` +
          ` (LTR ${ltr[p] ? ltr[p].nodes : '?'})`);
      }
    }

    // ---- RTL at narrow widths ----------------------------------------------------------------
    // Two gates covered two axes and never crossed them: this one rendered both directions at 1280px,
    // ui-narrow rendered twelve widths in LTR. styles.css has FOUR [dir=rtl] rules inside
    // @media (max-width:760px) — the drawer slides in from the right via translateX(100%), the burger
    // margin flips, the Apply button repositions — and not one of them had ever been rendered by
    // anything. An entire arrangement of the panel existed only on paper.
    //
    // Two widths rather than twelve: every direction-specific mobile rule lives inside the 760px
    // block, so a phone width and one just below that boundary exercise the whole of it. Sweeping all
    // twelve here would double the gate's cost to re-render regimes with no direction-specific rules
    // in them at all.
    for (const W of [375, 759]) {
      await send('Emulation.setDeviceMetricsOverride',
        { width: W, height: 800, deviceScaleFactor: 1, mobile: true });
      await sleep(700);
      // The drawer first: at these widths it is the only way to reach the other eight routes, and in
      // RTL it is a different rule from the LTR one that ui-narrow proves.
      const at = await ev(`(() => { const b = document.querySelector('.nav-burger');
        if (!b) return null; const r = b.getBoundingClientRect();
        if (r.width < 1) return null;
        return { x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2) }; })()`);
      if (!at) {
        bad++;
        console.error(`FAIL  @${W}px RTL: no visible burger — NOT MEASURED, which is not a pass`);
        continue;
      }
      for (const type of ['mousePressed', 'mouseReleased']) {
        await send('Input.dispatchMouseEvent', { type, x: at.x, y: at.y, button: 'left', clickCount: 1 });
      }
      await sleep(700);
      const drawer = await ev(`(() => {
        const sb = document.querySelector('.sidebar');
        const item = document.querySelector('.nav-item');
        const vw = window.innerWidth;
        const sr = sb ? sb.getBoundingClientRect() : null;
        const ir = item ? item.getBoundingClientRect() : null;
        const on = (r) => !!r && r.width > 0 && r.right > 0 && r.left < vw;
        return { sidebarOn: on(sr), itemOn: on(ir),
                 // In RTL the drawer comes from the RIGHT. Asserting it merely "moved" would pass a
                 // drawer that slid in from the wrong side, which is the defect this whole block is
                 // about — so check which edge it is anchored to.
                 fromRight: !!sr && Math.round(sr.right) >= vw - 2,
                 left: sr ? Math.round(sr.left) : null, right: sr ? Math.round(sr.right) : null, vw };
      })()`);
      if (!drawer.sidebarOn || !drawer.itemOn) {
        bad++;
        console.error(`FAIL  @${W}px RTL: the burger does not open the navigation — sidebar` +
          ` ${drawer.sidebarOn ? 'on' : 'off'}-screen, nav item ${drawer.itemOn ? 'reachable' : 'UNREACHABLE'}.` +
          ' Every other route is a dead end for Arabic and Persian users on a phone.');
      } else if (!drawer.fromRight) {
        bad++;
        console.error(`FAIL  @${W}px RTL: the drawer opened against the LEFT edge` +
          ` (left=${drawer.left} right=${drawer.right} of ${drawer.vw}px). In RTL it belongs on the` +
          ' right; the [dir=rtl] .sidebar rule is not taking effect.');
      } else {
        console.log(`  @${W}px RTL   drawer opens from the right (left=${drawer.left} right=${drawer.right})`);
      }
      // Dismiss via the scrim — the same affordance the LTR check uses — but on the correct side:
      // with the drawer against the right edge, "outside" is to its left.
      const outside = await ev(`(() => { const sb = document.querySelector('.sidebar');
        const r = sb ? sb.getBoundingClientRect() : null;
        return { x: Math.round(r ? Math.max(12, r.left - 40) : 12), y: Math.round(window.innerHeight / 2) }; })()`);
      for (const type of ['mousePressed', 'mouseReleased']) {
        await send('Input.dispatchMouseEvent', { type, x: outside.x, y: outside.y, button: 'left', clickCount: 1 });
      }
      await sleep(500);
      if (await ev(`(() => { const cb = document.getElementById('navtoggle'); return cb ? cb.checked : false; })()`)) {
        bad++;
        console.error(`FAIL  @${W}px RTL: tapping outside does not dismiss the drawer, so every route` +
          ' below was measured with the sidebar over the content');
      }
      // Then the layout itself at this width, in RTL, reusing the both-edges scan above.
      for (const p of PAGES) {
        await ev(`location.hash = '#${p}'`);
        const s = await settle(COUNT);
        const r = await ev(NARROW_SCAN);
        if (!r) { bad++; console.error(`FAIL  @${W}px RTL ${p}: no #view`); continue; }
        subjects += r.scanned;
        if (r.n) {
          bad++;
          console.error(`FAIL  @${W}px RTL ${p.padEnd(12)} ${r.n} element(s) outside the viewport`);
          for (const x of r.out) {
            console.error(`        past the ${x.side} edge: left=${x.left} right=${x.right}  ${x.cls}`);
          }
        } else if (!r.nodes) {
          bad++;
          console.error(`FAIL  @${W}px RTL ${p.padEnd(12)} rendered nothing`);
        } else if (!s.settled) {
          bad++;
          console.error(`FAIL  @${W}px RTL ${p.padEnd(12)} never settled — NOT MEASURED`);
        }
      }
      console.log(`  @${W}px RTL   ${PAGES.length} route(s) scanned`);
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
  console.error(`\n${bad} RTL problem(s). styles.css is built from physical direction properties` +
    ' (margin-left, padding-right, left:) which do not flip with dir="rtl", so a layout can be' +
    ' mirrored in some places and not others.');
  process.exit(1);
}
console.log(`\nevery route lays out inside the viewport in RTL (${LANG})`);
console.log(`subjects: ${subjects} element boxes measured in RTL at 1280, 375 and 759px`);
