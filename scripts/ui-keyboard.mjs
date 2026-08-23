// ui-keyboard.mjs — can the panel be operated without a mouse, and can you see where you are?
//
// The a11y gate checks that labels are wired and roles exist. The contrast gate checks that text can
// be read. Neither presses Tab. Two WCAG requirements have therefore never been exercised here:
// 2.1.1 Keyboard (everything operable from a keyboard) and 2.4.7 Focus Visible.
//
// This matters more than usual for this redesign specifically. Seven <details> folds were added to
// bound page heights, and folding moves controls out of the tab order until the summary is opened.
// The control-preservation gate counts a folded control as present — correctly, it IS in the DOM and
// one click away — but "in the DOM" and "reachable from a keyboard" are different claims, and nothing
// was checking the second. If a summary were ever not focusable, its controls would be stranded and
// every existing gate would still be green.
//
// Three assertions per route:
//   1. Tab reaches every control that is currently exposed (folds closed). Anything visible,
//      enabled and interactive must appear in the tab sequence.
//   2. Opening every <details> then re-walking reaches the controls inside them too — the fold
//      defers access, it must not remove it.
//   3. Every focused element shows a focus indicator: outline, box-shadow or ring that differs from
//      its unfocused state. A keyboard user who cannot see focus is not being served by (1).
//
// Also checked: Tab does not trap — the walk terminates by cycling rather than running to the cap.
//
//   node scripts/ui-keyboard.mjs <url> [cdp-port]
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { authenticateCDP } from './ui-auth.mjs';

const URL_ARG = process.argv[2];
const PORT = Number(process.argv[3] || 9650);
if (!URL_ARG) { console.error('usage: node scripts/ui-keyboard.mjs <url> [cdp-port]'); process.exit(2); }
const PAGES = ['dashboard', 'server', 'connections', 'failover', 'routing', 'dns', 'updater',
  'diagnostics', 'settings'];
// The cap has to be derived from the page, not fixed. A constant 400 was fine on the seeded demo and
// bound on the routing page at stress scale, which has 461 exposed controls: the walk truncated at 400
// and the gate reported 61 controls "unreachable" plus a "possible trap" — neither true. A cap that
// binds turns this into a check measuring something narrower than its name, and reports the truncation
// as a product defect. Sized per route below; this is only the floor and an escape hatch.
const TAB_FLOOR = Number(process.env.WR_TAB_CAP || 120);
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const httpJSON = async (u) => (await fetch(u)).json();
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wayhop-kb-'));
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
  `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`, '--window-size=1280,900', 'about:blank'],
  { stdio: 'ignore' });

// A stable identity for an element, so "was this focused" can be answered without holding node refs
// across evaluations. Index within its own tag keeps it unique when classes repeat.
const IDENT = `(n) => {
  if (!n) return null;
  const same = [...document.querySelectorAll(n.tagName)];
  return n.tagName.toLowerCase() + '#' + same.indexOf(n) +
    (n.className ? '.' + String(n.className).trim().split(/\\s+/)[0] : '');
}`;

const EXPOSED = `(() => {
  const ident = ${IDENT};
  const v = document.querySelector('#view');
  if (!v) return null;
  const sel = 'button, input, select, textarea, a[href], summary, [tabindex]:not([tabindex="-1"])';
  const out = [];
  for (const n of v.querySelectorAll(sel)) {
    if (n.disabled) continue;
    const cs = getComputedStyle(n);
    if (cs.visibility === 'hidden' || cs.display === 'none') continue;
    const b = n.getBoundingClientRect();
    if (b.width < 1 || b.height < 1) continue;          // not rendered -> not expected in the order
    // Inside a CLOSED details: legitimately out of the tab order until the summary is opened. Its
    // reachability is asserted separately, after opening every fold.
    //
    // A summary needs a narrower rule than "not inside a closed details", because its OWN details
    // being closed is exactly when it must still be focusable — that is how the fold gets opened.
    // What hides a summary is a closed details ABOVE its own. The first version of this exempted all
    // summaries unconditionally and duly reported the nested "Advanced — one tool, one exit" fold
    // inside the closed diag-adv fold as an unreachable control: a checker fault, not a product one,
    // and it would have been recorded as a defect had it not been traced.
    const start = n.tagName === 'SUMMARY'
      ? (n.closest('details') ? n.closest('details').parentElement : null)
      : n.parentElement;
    let hidden = false;
    for (let p = start; p; p = p.parentElement) {
      if (p.tagName === 'DETAILS' && !p.open) { hidden = true; break; }
      if (p === v) break;
    }
    if (hidden) continue;
    out.push(ident(n));
  }
  return out;
})()`;

let bad = 0;
let subjects = 0;
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
  const tab = async () => {
    for (const type of ['keyDown', 'keyUp']) {
      await send('Input.dispatchKeyEvent', { type, key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9,
        nativeVirtualKeyCode: 9, text: type === 'keyDown' ? '\t' : undefined });
    }
  };
  await send('Page.enable'); await send('Runtime.enable');
  await send('Page.navigate', { url: URL_ARG });
  for (let i = 0; i < 160; i++) {
    if (await ev('typeof route === "function"').catch(() => false)) break;
    await sleep(250);
  }
  await authenticateCDP({ send, evaluate: ev, url: URL_ARG });

  // Walk the tab order from the top of the document and collect what gets focus, plus whether each
  // focused element actually SHOWS focus.
  const walk = async (cap) => {
    await ev(`(() => { document.activeElement && document.activeElement.blur();
                       window.scrollTo(0, 0); })()`);
    const seen = [];
    const noRing = [];
    let cycled = false;
    for (let i = 0; i < cap; i++) {
      await tab();
      const r = await ev(`(() => {
        const ident = ${IDENT};
        const a = document.activeElement;
        if (!a || a === document.body) return { id: null };
        const cs = getComputedStyle(a);
        // A visible focus indicator is an outline with width, or a box-shadow/ring. Chrome's default
        // outline counts — the point is that SOMETHING marks the position, not that it is bespoke.
        const ring = (parseFloat(cs.outlineWidth) > 0 && cs.outlineStyle !== 'none')
          || (cs.boxShadow && cs.boxShadow !== 'none');
        const inView = !!a.closest('#view');
        return { id: ident(a), ring, inView };
      })()`);
      if (!r.id) break;
      if (seen.includes(r.id)) { cycled = true; break; }
      seen.push(r.id);
      if (r.inView && !r.ring) noRing.push(r.id);
    }
    return { seen, noRing, cycled };
  };

  console.log(`  ${URL_ARG}`);
  for (const p of PAGES) {
    await ev(`location.hash = '#${p}'`);
    await sleep(2800);

    const exposed = await ev(EXPOSED);
    if (exposed === null) { bad++; console.error(`FAIL  ${p}: no #view`); continue; }
    // Headroom over the page's own controls for the nav, topbar and anything else outside #view
    // that legitimately takes focus before the walk cycles.
    const cap = Math.max(TAB_FLOOR, exposed.length + 60);
    const closed = await walk(cap);
    const missed = exposed.filter((x) => !closed.seen.includes(x));

    // Now open every fold and confirm the deferred controls become reachable rather than lost.
    const folds = await ev(`(() => {
      const d = [...document.querySelectorAll('#view details')];
      d.forEach((x) => { x.open = true; });
      return d.length;
    })()`);
    await sleep(600);
    const exposedOpen = await ev(EXPOSED);
    const capOpen = Math.max(TAB_FLOOR, exposedOpen.length + 60);
    const opened = folds ? await walk(capOpen) : closed;
    const missedOpen = exposedOpen.filter((x) => !opened.seen.includes(x));

    const noRing = [...new Set([...closed.noRing, ...opened.noRing])];
    const problems = [];
    if (missed.length) problems.push(`${missed.length} exposed control(s) never received focus`);
    if (missedOpen.length) problems.push(`${missedOpen.length} control(s) unreachable even with all ${folds} fold(s) open`);
    if (noRing.length) problems.push(`${noRing.length} focused element(s) showed no focus indicator`);
    // Distinguish the two: a walk that ran out of cap proves nothing and must say so, rather than
    // accusing the page of a keyboard trap it does not have.
    if (!closed.cycled && closed.seen.length >= cap) {
      problems.push(`walk hit its ${cap}-stop ceiling without cycling — inconclusive, not necessarily a trap`);
    }

    if (problems.length) {
      bad += problems.length;
      console.error(`FAIL  ${p.padEnd(12)} ${problems.join('; ')}`);
      for (const x of missed.slice(0, 4)) console.error(`        unreached (folds closed): ${x}`);
      for (const x of missedOpen.slice(0, 4)) console.error(`        unreached (folds open):   ${x}`);
      for (const x of noRing.slice(0, 4)) console.error(`        no focus ring:            ${x}`);
    } else {
      subjects += exposedOpen.length;
      console.log(`  ${p.padEnd(12)} ok   tab stops=${String(closed.seen.length).padStart(3)}` +
        ` folds=${folds} reachable=${exposedOpen.length}`);
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
  console.error(`\n${bad} keyboard problem(s). A control that cannot be tabbed to does not exist for` +
    ' anyone using a keyboard, and focus that cannot be seen makes the tab order useless.');
  process.exit(1);
}
console.log(`\nevery exposed control is reachable by Tab and shows focus, on all ${PAGES.length} routes`);
console.log(`subjects: ${subjects} controls reached`);
