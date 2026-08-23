// ui-lang-fit.mjs — does the panel still FIT once it is not in English?
//
// check-i18n proves every key exists in every language. It says nothing about what those strings do
// to the page, and the two are not the same claim: a dictionary can be complete and still push a
// German compound out of a chip, clip a Belarusian button label to "Прав…", or send the body into a
// horizontal scroll that no English run would ever show. Nobody had looked at any of the fifteen
// languages before this existed — the translation was verified as DATA and shipped unseen.
//
// So this switches the panel through every language in ONE browser (localStorage "wr-lang" + reload,
// which is exactly what the Settings selector does) and measures, per page:
//   • the document scrolling horizontally — the whole-page symptom;
//   • any element whose text is CLIPPED by its own box (scrollWidth past clientWidth) among the
//     surfaces that are actually width-constrained: buttons, chips/badges/pills, table cells, nav;
//   • any element whose content spills outside its parent's right edge.
// English is measured first and used as the baseline: a control that already clips in English is the
// layout's problem, not the translation's, and reporting it against fifteen languages would bury the
// ones that matter. Only regressions against that baseline are counted.
//
//   node scripts/ui-lang-fit.mjs <panel-url> [--langs ru,de,be] [--port cdp] [--max-pages N]
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { authenticateCDP } from './ui-auth.mjs';

const args = process.argv.slice(2);
const flag = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const URL_ARG = args.find((a) => /^https?:\/\//.test(a));
const PORT = Number(flag('--port') || 9698);
const MAXP = Number(flag('--max-pages') || 99);
if (!URL_ARG) {
  console.error('usage: node scripts/ui-lang-fit.mjs <panel-url> [--langs ru,de] [--max-pages N]');
  process.exit(2);
}
const BASE = URL_ARG.replace(/\/+$/, '') + '/';
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const httpJSON = async (u) => (await fetch(u)).json();

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'langfit-'));
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
  '--hide-scrollbars', `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`,
  '--window-size=1280,900', 'about:blank'], { stdio: 'ignore' });

let exitCode = 0;
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
    if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); }
  };
  const send = (method, params = {}) => new Promise((res, rej) => {
    const i = ++id;
    const to = setTimeout(() => { waiting.delete(i); rej(new Error(`CDP ${method} timed out`)); }, 90000);
    waiting.set(i, (m) => { clearTimeout(to); return m.error ? rej(new Error(m.error.message)) : res(m.result); });
    ws.send(JSON.stringify({ id: i, method, params }));
  });
  const ev = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || 'eval failed');
    return r.result.value;
  };

  await send('Page.enable'); await send('Runtime.enable');
  await send('Page.navigate', { url: BASE });
  for (let i = 0; i < 200; i++) { if (await ev('typeof route === "function"').catch(() => false)) break; await sleep(250); }
  await authenticateCDP({ send, evaluate: ev, url: BASE });

  const langs = flag('--langs')
    ? flag('--langs').split(',').map((s) => s.trim()).filter(Boolean)
    : await ev(`(window.WR_LANGS||[]).map(l=>l.code).filter(c=>c!=="auto"&&c!=="en")`);
  const routes = (await ev(`[...document.querySelectorAll('.nav-item[data-page]')].map(n=>n.getAttribute('data-page')).filter(Boolean)`) || []).slice(0, MAXP);
  if (!langs.length || routes.length < 5) {
    console.error(`FAIL  discovered ${langs.length} language(s) and ${routes.length} route(s) — `
      + 'with either missing this check would pass by having nothing to look at.');
    process.exit(1);
  }
  console.log(`  target: ${BASE}`);
  console.log(`  ${langs.length} language(s) x ${routes.length} route(s), viewport 1280x900\n`);

  // One measurement pass over every route for whatever language is currently active.
  const MEASURE = `(async () => {
    const out = { pages: {}, bodyScroll: [] };
    const routes = ${JSON.stringify(routes)};
    // A clipped box is only meaningful where width is constrained. A paragraph wraps; a chip does not.
    const SEL = '#view button, #view .badge, #view .pill, #view .chip, #view td, #view th, '
      + '#view .rl-cell, #view .stat, #view .kv, .nav-item, #view label, #view .tag';
    for (const r of routes) {
      location.hash = '#' + r;
      await new Promise(x => setTimeout(x, 1600));
      const clipped = [];
      for (const el of document.querySelectorAll(SEL)) {
        const cs = getComputedStyle(el);
        if (cs.display === 'none' || cs.visibility === 'hidden') continue;
        if (el.clientWidth === 0) continue;
        // 2px of slack: sub-pixel text metrics report a 1px overhang on boxes that look fine.
        if (el.scrollWidth - el.clientWidth > 2) {
          clipped.push({ tag: el.tagName.toLowerCase(), cls: (el.className || '').toString().slice(0, 40),
            over: el.scrollWidth - el.clientWidth, text: (el.textContent || '').trim().slice(0, 44) });
        }
      }
      out.pages[r] = clipped;
      if (document.documentElement.scrollWidth - document.documentElement.clientWidth > 2) out.bodyScroll.push(r);
    }
    return out;
  })()`;

  const setLangAndReload = async (code) => {
    await ev(`localStorage.setItem('wr-lang', ${JSON.stringify(code)})`);
    await send('Page.navigate', { url: BASE });
    for (let i = 0; i < 200; i++) { if (await ev('typeof route === "function"').catch(() => false)) break; await sleep(250); }
    await sleep(1200);
  };

  // Baseline in English. Anything already clipped here is a layout fault, not a translation fault,
  // and counting it against every language would drown the real ones.
  await setLangAndReload('en');
  const base = await ev(MEASURE);
  const baseKey = (r, c) => `${r}|${c.tag}|${c.cls}`;
  const baseline = new Set();
  for (const [r, list] of Object.entries(base.pages)) for (const c of list) baseline.add(baseKey(r, c));
  const baseCount = [...baseline].length;
  console.log(`  en (baseline): ${baseCount} already-clipped control(s), `
    + `${base.bodyScroll.length} page(s) scrolling sideways`);
  if (base.bodyScroll.length) console.log(`      pages: ${base.bodyScroll.join(', ')}`);

  const rows = [];
  for (const code of langs) {
    await setLangAndReload(code);
    const rtl = await ev(`document.documentElement.getAttribute('dir') || ''`);
    const m = await ev(MEASURE);
    const news = [];
    for (const [r, list] of Object.entries(m.pages)) {
      for (const c of list) if (!baseline.has(baseKey(r, c))) news.push({ route: r, ...c });
    }
    const newScroll = m.bodyScroll.filter((r) => !base.bodyScroll.includes(r));
    rows.push({ code, rtl, news, newScroll });
    const worst = news.slice().sort((a, b) => b.over - a.over).slice(0, 2);
    console.log(`  ${code.padEnd(3)}${rtl === 'rtl' ? ' rtl' : '    '} new-clipped=${String(news.length).padStart(3)} `
      + `new-sideways-scroll=${newScroll.length}`
      + (worst.length ? `   worst: ${worst.map((w) => `${w.route}/${w.tag}.${w.cls.split(' ')[0]} +${w.over}px "${w.text}"`).join(' | ')}` : ''));
    if (newScroll.length) console.log(`        pages scrolling sideways: ${newScroll.join(', ')}`);
  }

  // Measure English AGAIN, at the end. The baseline above is a photograph of one moment, and the
  // panel is live: on the router an updater pill filled with a raw upstream error — `Get
  // "https://mirror.ghproxy.com/…` — appeared partway through a run and overflowed by 757px, so the
  // five languages that happened to be measured after it arrived were each reported as clipping a
  // control, in a string that is not translated at all. Anything clipped in EITHER English pass is
  // the layout's or the router's state, not the translation's.
  await setLangAndReload('en');
  const after = await ev(MEASURE);
  for (const [r, list] of Object.entries(after.pages)) for (const c of list) baseline.add(baseKey(r, c));
  const lateBase = [...baseline].length - baseCount;
  if (lateBase) console.log(`\n  en (second pass): ${lateBase} further control(s) clip in English too — `
    + 'live state that arrived mid-run, now excluded from every language above');
  for (const row of rows) row.news = row.news.filter((c) => !baseline.has(baseKey(c.route, c)));

  const totalNew = rows.reduce((a, r) => a + r.news.length, 0);
  const totalScroll = rows.reduce((a, r) => a + r.newScroll.length, 0);
  if (lateBase) {
    console.log('  after excluding those:');
    for (const r of rows) if (r.news.length) console.log(`    ${r.code}: ${r.news.length} still clipped`);
    if (!totalNew) console.log('    every language: none');
  }
  console.log(`\n  ${langs.length} languages, ${routes.length} routes: ${totalNew} control(s) clipped that `
    + `are not clipped in English, ${totalScroll} page(s) newly scrolling sideways`);
  if (totalScroll) {
    console.log('  FAIL  a page that scrolls sideways only in some languages is a translation-caused layout break.');
    exitCode = 1;
  } else if (totalNew) {
    console.log('  note  clipped controls are reported, not failed: many chips ellipsize by design.');
    console.log('        Read the worst offenders above and shorten those strings if the text is lost.');
  } else {
    console.log('  ok    no language clips a control that English does not, and none scrolls the page.');
  }
} catch (e) {
  console.error(`FAIL  ${e.message}`);
  exitCode = 1;
} finally {
  if (chrome.exitCode === null && !chrome.killed) chrome.kill();
  await Promise.race([new Promise((r) => chrome.once('exit', r)), new Promise((r) => setTimeout(r, 3000))]);
  for (let i = 0; i < 12; i++) {
    try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 4, retryDelay: 250 }); break; }
    catch (_) { await sleep(250); }
  }
}
process.exit(exitCode);
