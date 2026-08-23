// ui-wide.mjs — does the panel hold together on the screen the operator actually uses?
//
// The suite's coverage was measured, not assumed: every browser gate here renders at 1280x900, and
// `ui-narrow` sweeps 375-1040. Nothing looks above 1280. The operator's viewport is 1883px and
// `.app` runs to 1720px, so the entire regime they work in is unmeasured — and that is exactly where
// a track rebalance regressed the Routing table (the download-via minimum fell from 150px to 120px,
// which is invisible at 1920 where fr governs, and truncated "Direct (no tunnel)" on every row at
// 1440 where the minimums bind). Thirty-five gates were green over it; it was found by hand.
//
// Three assertions, each chosen because it is binary rather than a matter of taste. "This page looks
// sparse" is a judgement and is deliberately NOT tested here.
//
//   1. No row may spill past the content column. Same rule `ui-narrow` uses at the other end: if a
//      row is wider than the column that holds it, part of every row is off-screen or overlapping.
//   2. A <select> displaying a string the APP owns must not be truncated. The app writes
//      "Direct (no tunnel)" and "Block (reject)" itself, so it can be held to giving them room; it
//      cannot promise the same for a tunnel name, which is the operator's own text and has no
//      bounded width. This is the exact distinction the regression fell through.
//   3. A column heading must sit over the column it names. Two independent grids resolve their fr
//      tracks separately, so a heading can drift off its data at one width while lining up at
//      another — `ui-columns` checks this at 1280 only.
//
// Widths: the desktop regime above what the rest of the suite sees. 2200 is included so a layout that
// only works up to some fixed width is not mistaken for one that works generally.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { authenticateUI } from './ui-auth.mjs';

const URL_ARG = process.argv[2] || 'http://127.0.0.1:8088/';
const PORT = Number(process.env.CDP_PORT || 9461);
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const WIDTHS = String(process.env.WR_WIDE_W || '1366,1440,1600,1720,1920,2200')
  .split(',').map((s) => Number(s.trim())).filter(Boolean);
// NINE routes, not eight. The app's PAGES map declares `server` between dashboard and connections,
// and the first version of this list simply omitted it — a gate written to close a coverage hole,
// carrying one of its own. `ui-narrow` and the contrast gate both walk all nine.
const ROUTES = ['dashboard', 'server', 'connections', 'failover', 'routing', 'dns', 'updater', 'diagnostics', 'settings'];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const LANG = process.env.WR_UI_LANG || 'en';
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wayhop-wide-'));
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
  `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`, '--window-size=1920,900', 'about:blank'],
  { stdio: 'ignore' });

// Options the APP owns. Their `value` is a fixed token, not an id the operator chose.
const APP_OWNED = "['direct','block']";

const PROBE = `(() => {
  const view = document.querySelector('#view');
  if (!view) return { error: 'no #view' };
  const vb = view.getBoundingClientRect();
  const out = { spill: [], cut: [], drift: [], rows: 0, selects: 0, heads: 0 };

  // 1. rows wider than the column that holds them
  for (const r of view.querySelectorAll('.rlrow, .dns-row, .qp-br, .sx-row, .fr-row, .upd-row, .conn-row, .card > .conn')) {
    const b = r.getBoundingClientRect();
    if (b.width < 1 || b.height < 1) continue;
    out.rows++;
    const over = Math.round(b.right - vb.right);
    if (over > 1) out.spill.push({ cls: String(r.className).split(/\\s+/)[0], over });
  }

  // 2. a select showing a string the app wrote, in a box too small for it.
  //    Measured by cloning the control down to its selected option and letting Chrome size it —
  //    reconstructing the text width from the computed font ran ~23px low and called truncated
  //    controls fine.
  const owned = new Set(${APP_OWNED});
  const host = document.createElement('div');
  host.style.cssText = 'position:absolute;left:-99999px;top:0;visibility:hidden;width:6000px';
  document.body.appendChild(host);
  for (const s of view.querySelectorAll('select')) {
    const b = s.getBoundingClientRect();
    if (b.width < 1 || b.height < 1) continue;
    const opt = s.options[s.selectedIndex];
    if (!opt) continue;
    out.selects++;
    if (!owned.has(opt.value)) continue;
    const c = s.cloneNode(true);
    const keep = c.options[s.selectedIndex];
    [...c.options].forEach((o) => { if (o !== keep) o.remove(); });
    c.style.width = 'auto'; c.style.maxWidth = 'none'; c.style.minWidth = '0';
    host.appendChild(c);
    const want = c.getBoundingClientRect().width;
    c.remove();
    if (want > b.width + 1) {
      out.cut.push({ text: opt.textContent, want: Math.round(want), has: Math.round(b.width),
                     over: Math.round(want - b.width) });
    }
  }
  host.remove();

  // 3. a heading that is not over its column.
  //
  // The pair list is DECLARED, and the run below refuses if a declared header never turns up: the
  // first version named '.dns-head', which does not exist anywhere in this app — the DNS rule table's
  // header is '.qp-brhead' — so the check silently covered Routing alone while its name promised both.
  out.headSeen = {};
  for (const [headSel, rowSel] of [['.rlhead', '.rlrow'], ['.qp-brhead', '.qp-br']]) {
    out.headSeen[headSel] = 0;
    const head = view.querySelector(headSel), row = view.querySelector(rowSel);
    if (!head || !row) continue;
    if (getComputedStyle(head).display === 'none') continue;   // compact layout drops the header
    out.heads++; out.headSeen[headSel] = 1;
    const hk = [...head.children], rk = [...row.children];
    for (let i = 0; i < Math.min(hk.length, rk.length); i++) {
      const d = Math.round(Math.abs(hk[i].getBoundingClientRect().left - rk[i].getBoundingClientRect().left));
      if (d > 2) out.drift.push({ head: headSel, col: i, off: d });
    }
  }
  return out;
})()`;

let ws, chromeGone = false, fatal = '';
function fail(msg) { console.error('FAIL  ' + msg); }

try {
  for (let i = 0; i < 80; i++) {
    try {
      const l = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
      const p = l.find((t) => t.type === 'page');
      if (p) { ws = new WebSocket(p.webSocketDebuggerUrl); break; }
    } catch {}
    await sleep(250);
  }
  if (!ws) { console.error('FAIL  could not attach to headless Chrome'); process.exit(2); }
  await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
  let id = 0; const waiting = new Map();
  ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); } };
  const send = (method, params = {}) => new Promise((res, rej) => {
    const myId = ++id;
    const t = setTimeout(() => { waiting.delete(myId); rej(new Error(`${method} never answered`)); }, 30000);
    waiting.set(myId, (m) => { clearTimeout(t); m.error ? rej(new Error(m.error.message)) : res(m.result); });
    ws.send(JSON.stringify({ id: myId, method, params }));
  });
  const ev = async (expr) => (await send('Runtime.evaluate', {
    expression: expr, awaitPromise: true, returnByValue: true,
  })).result.value;

  await send('Page.enable');

  // Pin the language rather than inherit it from the host browser.
  //
  // app.js reads navigator.language, so this gate measured whichever translation the machine
  // running it preferred — and the strings it judges are the app's own option labels, whose
  // width is exactly what changes between languages. The column minimum it polices was sized
  // against the English "Direct (no tunnel)"; nothing had ever asked what the German one needs.
  await send('Page.navigate', { url: URL_ARG });
  for (let i = 0; i < 60; i++) {
    if (await ev(`document.readyState !== 'loading'`).catch(() => false)) break;
    await sleep(200);
  }
  await authenticateUI({
    evaluate: ev,
    navigate: async url => {
      await send('Page.navigate', { url });
      for (let i = 0; i < 60; i++) {
        if (await ev(`document.readyState !== 'loading'`).catch(() => false)) return;
        await sleep(200);
      }
      throw new Error('WayHop did not reload after login');
    },
    url: URL_ARG,
  });
  await ev(`(() => { try { localStorage.setItem('wr-lang', ${JSON.stringify(LANG)}); } catch (e) {} })()`);
  await send('Page.navigate', { url: URL_ARG });
  for (let i = 0; i < 60; i++) {
    if (await ev(`!!document.querySelector('#view > div')`).catch(() => false)) break;
    await sleep(200);
  }
  // What the panel RESOLVED, not what was asked: app.js falls back to auto-detection for a code
  // it has no dictionary for, so reading the key back would only prove the write landed.
  const shownLang = await ev('document.documentElement.getAttribute("lang")');
  if (shownLang !== LANG) {
    console.error(`the panel is showing ${JSON.stringify(shownLang)} after being asked for `
      + `${JSON.stringify(LANG)} — every width below would be measured in a language this run did not choose`);
    process.exit(2);
  }
  console.log(`  language: ${LANG} (pinned; set WR_UI_LANG to measure another)`);
  let problems = 0, measuredRows = 0, measuredSelects = 0, measuredHeads = 0, judged = 0, skipped = 0;
  let expandedSections = 0, expandedJudged = 0, detailsSeen = 0;
  const headSeen = {};
  for (const w of WIDTHS) {
    await send('Emulation.setDeviceMetricsOverride', { width: w, height: 900, deviceScaleFactor: 1, mobile: false });
    for (const route of ROUTES) {
      await send('Page.navigate', { url: `${URL_ARG}#${route}` });
      let ready = false;
      for (let i = 0; i < 60; i++) {
        if (await ev(`!!document.querySelector('#view > div')`).catch(() => false)) { ready = true; break; }
        await sleep(200);
      }
      if (!ready) { skipped++; console.error(`  ${route} @ ${w}px never rendered`); continue; }
      await sleep(900);
      // The hash router does not act on a location.hash assignment made from CDP, so confirm the
      // page really is where it was sent before believing anything measured on it.
      const on = await ev(`(location.hash || '').replace('#','')`);
      if (on !== route) { skipped++; console.error(`  ${route} @ ${w}px: page is on #${on}`); continue; }

      // Measured twice: as the route first renders, and again with every folded section open.
      //
      // Content inside a shut <details> is in a display:none subtree, so it has no box, cannot spill
      // and cannot truncate — a collapsed pass says nothing whatever about the expanded state, and
      // the failover switch log, the DNS full rule order, the diagnostics feed and five Settings
      // sections only exist once opened. Measuring only what the page shows first is how a check ends
      // up narrower than its name.
      for (const phase of ['as rendered', 'expanded']) {
        if (phase === 'expanded') {
          const x = await ev(`(() => {
            let opened = 0, total = 0;
            for (const d of document.querySelectorAll('#view details')) {
              total++;
              if (!d.open) { d.open = true; opened++; }
            }
            return { opened, total };
          })()`);
          expandedSections += x.opened;
          detailsSeen += x.total;
          if (!x.total) continue;             // this route has nothing to fold; not a failure
          await sleep(500);
        }

        const r = await ev(PROBE);
        if (!r || r.error) { skipped++; console.error(`  ${route} @ ${w}px (${phase}): ${r ? r.error : 'no result'}`); continue; }
        if (phase === 'as rendered') {
          judged++;
          measuredRows += r.rows; measuredSelects += r.selects; measuredHeads += r.heads;
          for (const [sel, n] of Object.entries(r.headSeen || {})) headSeen[sel] = (headSeen[sel] || 0) + n;
        } else {
          expandedJudged++;
          measuredRows += r.rows; measuredSelects += r.selects;
        }
        const where = `${route} @ ${w}px${phase === 'expanded' ? ' (folded sections open)' : ''}`;
        for (const s of r.spill.slice(0, 3)) {
          problems++; fail(`${where}: a .${s.cls} row runs ${s.over}px past the content column`);
        }
        for (const c of r.cut.slice(0, 3)) {
          problems++;
          fail(`${where}: the panel's own text ${JSON.stringify(c.text)} is truncated — ` +
               `needs ${c.want}px, has ${c.has} (short by ${c.over}). A string the app writes itself must fit.`);
        }
        for (const d of r.drift.slice(0, 3)) {
          problems++; fail(`${where}: ${d.head} column ${d.col} heading sits ${d.off}px off its data`);
        }
      }
    }
  }

  // Positive evidence. A run that examined nothing must not read as a pass, and this gate walks a lot
  // of pages — if a selector goes stale it would quietly measure zero and stay green forever.
  console.log(`subjects: ${judged} page renders, ${measuredRows} rows, ${measuredSelects} selects, ` +
              `${measuredHeads} table headers, across ${WIDTHS.length} widths (${WIDTHS.join(', ')})`);
  console.log(`  plus ${expandedJudged} re-measure(s) with ${expandedSections} folded section(s) opened ` +
              `(${detailsSeen} <details> encountered)`);
  // The expanded pass is only worth its runtime if it actually opens things. This app has folded
  // sections on six of the eight routes, so a run that opened none means the selector or the markup
  // moved and half this gate has quietly stopped measuring.
  if (expandedSections < 10) {
    console.error(`FAIL  only ${expandedSections} folded section(s) were opened across the whole run — ` +
                  `the expanded half of this gate measured almost nothing`);
    problems++;
  }
  if (judged < WIDTHS.length * ROUTES.length - 2) {
    console.error(`FAIL  only ${judged} of ${WIDTHS.length * ROUTES.length} page renders were judged ` +
                  `(${skipped} skipped) — too much went unmeasured to call this a pass`);
    problems++;
  }
  if (measuredRows < 100 || measuredSelects < 50 || measuredHeads < 1) {
    console.error(`FAIL  the subject collapsed: ${measuredRows} rows, ${measuredSelects} selects, ` +
                  `${measuredHeads} headers. Seed the demo (scripts/seed-demo.mjs + seed-stress.mjs) ` +
                  `or fix the selectors — a sparse page passes this gate by having nothing to check.`);
    problems++;
  }
  // A declared header that never appeared is a hole, not a pass. '.dns-head' was in this list for one
  // draft and matches nothing in this app, so the heading check covered Routing only while claiming
  // both tables — the failure this whole gate exists to stop, committed by the gate itself.
  const missing = Object.entries(headSeen).filter(([, n]) => n === 0).map(([s]) => s);
  console.log(`  headers found: ${Object.entries(headSeen).map(([s, n]) => `${s} x${n}`).join(', ') || '(none declared)'}`);
  if (missing.length) {
    console.error(`FAIL  declared header(s) ${missing.join(', ')} never appeared on any page at any width — ` +
                  `the alignment check silently covered less than its name claims`);
    problems++;
  }
  ws.close();
  if (problems) { console.error(`\n${problems} wide-viewport problem(s).`); process.exitCode = 1; }
  else console.log('wide viewports: no spill, no truncated panel text, no drifted heading');
} catch (error) {
  fatal = error?.message || String(error);
} finally {
  if (chrome && chrome.exitCode === null && !chrome.killed) chrome.kill();
  await new Promise((r) => { chrome.once('exit', r); setTimeout(r, 3000); });
  chromeGone = true;
  for (let i = 0; i < 12; i++) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
    if (!fs.existsSync(dir)) break;
    await sleep(300);
  }
  if (!chromeGone) console.error('note: headless Chrome may still be running');
}
if (fatal) {
  console.error(`FAIL  ${fatal}`);
  process.exit(1);
}
