// ui-contrast.mjs — is the text actually readable, in BOTH themes?
//
// The a11y gate checks structure: aria-current, label wiring, live regions, roles. Structure is not
// legibility. `[data-theme=light]` has existed for the whole redesign and has never once been
// rendered by anything in this suite — every screenshot, every density run, every narrow run has been
// dark. A token that is correct in dark and wrong in light is invisible to all of it.
//
// Contrast is the right assertion because it is arithmetic, not taste: WCAG 2.1 AA wants 4.5:1 for
// normal text and 3:1 for large text (>=24px, or >=18.66px bold). This walks every element carrying
// its own text, resolves the effective background by climbing until something is opaque, and reports
// the ratio.
//
// Deliberately exempted, with reasons, because a checker that cries wolf gets ignored:
//   • disabled controls — WCAG explicitly exempts them
//   • elements with no rendered box, or fully transparent text
//   • text over a gradient or image background — the "effective background" is not one colour, and
//     guessing produces noise. These are LISTED, not silently dropped, so the exemption stays visible.
//
//   node scripts/ui-contrast.mjs <url> [cdp-port]
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { authenticateCDP } from './ui-auth.mjs';

const URL_ARG = process.argv[2];
const PORT = Number(process.argv[3] || 9640);
if (!URL_ARG) { console.error('usage: node scripts/ui-contrast.mjs <url> [cdp-port]'); process.exit(2); }
const PAGES = ['dashboard', 'server', 'connections', 'failover', 'routing', 'dns', 'updater',
  'diagnostics', 'settings'];
const THEMES = ['dark', 'light'];
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const httpJSON = async (u) => (await fetch(u)).json();
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wayhop-ct-'));
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
  `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`, '--window-size=1280,900', 'about:blank'],
  { stdio: 'ignore' });

const COLLECT = `(() => {
  const parse = (c) => {
    const m = String(c).match(/rgba?\\(([^)]+)\\)/);
    if (!m) return null;
    const p = m[1].split(',').map((x) => parseFloat(x));
    return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
  };
  const lin = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
  const lum = (c) => 0.2126 * lin(c.r) + 0.7152 * lin(c.g) + 0.0722 * lin(c.b);
  const ratio = (a, b) => {
    const la = lum(a), lb = lum(b);
    return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
  };
  const over = (fg, bg) => ({           // composite a translucent colour onto its background
    r: fg.r * fg.a + bg.r * (1 - fg.a),
    g: fg.g * fg.a + bg.g * (1 - fg.a),
    b: fg.b * fg.a + bg.b * (1 - fg.a), a: 1,
  });

  const out = [], skipped = [];
  let examined = 0;
  const v = document.querySelector('#view');
  if (!v) return { out, skipped, none: true };
  for (const n of v.querySelectorAll('*')) {
    // Only elements carrying their OWN text: otherwise a wrapper is judged on a child's colour.
    const own = [...n.childNodes].filter((k) => k.nodeType === 3 && k.nodeValue.trim()).length;
    if (!own) continue;
    if (n.closest('[disabled]') || n.matches(':disabled')) continue;
    const cs = getComputedStyle(n);
    if (cs.visibility === 'hidden' || cs.display === 'none' || parseFloat(cs.opacity) === 0) continue;
    const box = n.getBoundingClientRect();
    if (box.width < 1 || box.height < 1) continue;
    const fg = parse(cs.color);
    if (!fg || fg.a === 0) continue;

    // Effective background: climb until something is opaque enough to matter.
    let bg = null, imaged = false;
    for (let p = n; p; p = p.parentElement) {
      const pcs = getComputedStyle(p);
      if (pcs.backgroundImage && pcs.backgroundImage !== 'none') { imaged = true; break; }
      const c = parse(pcs.backgroundColor);
      if (c && c.a > 0) { bg = bg ? over(bg, c) : c; if (c.a >= 1) break; }
    }
    const label = (n.className || n.tagName).toString().trim().slice(0, 34);
    if (imaged || !bg) { skipped.push({ label, why: imaged ? 'background image/gradient' : 'no opaque background' }); continue; }

    const size = parseFloat(cs.fontSize);
    const weight = Number(cs.fontWeight) || 400;
    const large = size >= 24 || (size >= 18.66 && weight >= 700);
    const need = large ? 3.0 : 4.5;
    examined++;
    const got = ratio(fg.a < 1 ? over(fg, bg) : fg, bg);
    if (got < need) {
      out.push({ label, got: Math.round(got * 100) / 100, need,
                 size: Math.round(size), weight,
                 fg: cs.color, bg: 'rgb(' + [bg.r, bg.g, bg.b].map(Math.round).join(',') + ')',
                 txt: (n.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 34) });
    }
  }
  return { out, skipped, examined };
})()`;

let bad = 0, skippedTotal = 0, subjects = 0;
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
  await send('Page.enable'); await send('Runtime.enable');
  await send('Page.navigate', { url: URL_ARG });
  for (let i = 0; i < 160; i++) {
    if (await ev('typeof route === "function"').catch(() => false)) break;
    await sleep(250);
  }
  await authenticateCDP({ send, evaluate: ev, url: URL_ARG });

  console.log(`  ${URL_ARG}`);
  for (const theme of THEMES) {
    // Set it the way the app does, then confirm it TOOK — a theme check that silently ran twice in
    // dark would report the light theme as flawless without ever rendering it.
    const applied = await ev(`(() => {
      document.documentElement.setAttribute('data-theme', ${JSON.stringify(theme)});
      try { localStorage.setItem('wr-theme', ${JSON.stringify(theme)}); } catch (e) {}
      // Sample a THEMED surface, not <body>: body keeps a dark background in both themes, so
      // printing it made the light run's banner read "body rgb(17,24,33)" and look as though the
      // switch had not taken. It had — the card colours in the findings were plainly light — but a
      // confirmation line that shows an unchanging value confirms nothing.
      const probe = document.querySelector('#view .card') || document.querySelector('#view') || document.body;
      return { attr: document.documentElement.getAttribute('data-theme'),
               ink: getComputedStyle(document.documentElement).getPropertyValue('--ink').trim(),
               surface: getComputedStyle(probe).backgroundColor };
    })()`);
    await sleep(600);
    console.log(`  --- theme=${applied.attr}  --ink ${applied.ink}  card ${applied.surface} ---`);
    if (applied.attr !== theme) {
      bad++;
      console.error(`FAIL  could not switch to ${theme} — the run below would be measuring the wrong theme`);
      continue;
    }
    for (const p of PAGES) {
      await ev(`location.hash = '#${p}'`);
      await sleep(2500);
      const r = await ev(COLLECT);
      skippedTotal += r.skipped.length;
      subjects += r.examined || 0;
      if (r.none) { bad++; console.error(`FAIL  ${p}: no #view`); continue; }
      if (r.out.length) {
        bad += r.out.length;
        console.error(`FAIL  ${p.padEnd(12)} ${r.out.length} element(s) below AA`);
        for (const x of r.out.slice(0, 4)) {
          console.error(`        ${x.got}:1 (needs ${x.need}) ${x.size}px/${x.weight}  ${x.label}` +
            `  ${x.fg} on ${x.bg}  ${x.txt ? '"' + x.txt + '"' : ''}`);
        }
      } else {
        console.log(`  ${p.padEnd(12)} ok`);
      }
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

console.log(`  (${skippedTotal} element(s) exempted: gradient/image backgrounds or no opaque ancestor)`);
if (bad) {
  console.error(`\n${bad} contrast problem(s). WCAG AA is 4.5:1 for normal text, 3:1 for large.`);
  process.exit(1);
}
console.log(`\nall text meets WCAG AA in both themes across ${PAGES.length} routes`);
console.log(`subjects: ${subjects} text elements measured`);
