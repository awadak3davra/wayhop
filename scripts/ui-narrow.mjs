// ui-narrow.mjs — does the panel survive a phone?
//
// Every measurement in this suite has been taken at 1280x900. A router panel is opened from a phone
// at least as often as from a desktop — usually when something is broken and the person is standing
// next to the router — and nothing here has ever looked at a narrow viewport. Several rounds of grid
// and fold CSS have gone in since, none of it checked below 900px.
//
// The assertion is horizontal overflow, because it is unambiguous and it is what actually ruins a
// phone layout: if the document is wider than the viewport, the user is dragging the page sideways to
// read it and the right-hand column of every row is off-screen. Everything else at this width is a
// judgement call; this is not.
//
// Overflow usually comes from one of three things, so the report names the widest offenders rather
// than just failing: a grid with a min track wider than the screen, an unbroken string (an endpoint
// name from a subscription, a base64 key, a long URL), or a fixed pixel width left over from desktop.
//
// Also checked, because they are the difference between "cramped" and "unusable":
//   • the burger control exists and is operable at this width (the nav is off-canvas here)
//   • every route still renders content and controls
//
//   node scripts/ui-narrow.mjs <url> [cdp-port]
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { authenticateUI } from './ui-auth.mjs';

const URL_ARG = process.argv[2];
const PORT = Number(process.argv[3] || 9630);
if (!URL_ARG) { console.error('usage: node scripts/ui-narrow.mjs <url> [cdp-port]'); process.exit(2); }
// The widths to render at. This gate used to take exactly one — 375 — while styles.css declares ten
// breakpoints that restructure the layout (480, 560, 640, 680, 720, 760, 820, 860, 900, 980). That is
// eleven distinct layout regimes, of which the gate had ever rendered one, under a name that promises
// "narrow viewport" rather than "375px". The updater overflow it did catch lived in an 860px rule and
// only happened to show at 375; the same rule shape at a tablet width would have gone unseen.
//
// One sample just below each structural breakpoint, where that breakpoint's rules have just taken
// effect, plus 375 (a real phone, and the only regime where the 420px rules apply) and one width
// above the largest so the uncollapsed layout is covered too. The list is checked against the
// stylesheet by the assertion below, so adding a breakpoint without extending this is caught rather
// than silently reducing coverage.
const WIDTHS = String(process.env.WR_NARROW_W || '375,479,559,639,679,719,759,819,859,899,979,1040')
  .split(',').map((x) => Number(x.trim())).filter((x) => x > 0);
const WIDTH = WIDTHS[0];   // the burger check is about the phone case specifically
const HEIGHT = Number(process.env.WR_NARROW_H || 812);
// Coverage assertion. A hardcoded width list silently stops covering the page the first time someone
// adds a breakpoint, and the gate would keep passing while testing fewer regimes than it claims — the
// same "measures a narrower thing than its name promises" failure this list exists to fix, one level
// up. So read the stylesheet and require a sample inside every regime a STRUCTURAL breakpoint creates.
// Only structural ones count: a media block that changes a gap or a font size cannot produce the
// horizontal overflow this gate looks for, and demanding a render for each would trade minutes for
// nothing.
function assertWidthsCoverBreakpoints() {
  const cssPath = path.join(process.cwd(), 'web', 'dist', 'styles.css');
  if (!fs.existsSync(cssPath)) return;   // running against a target whose source is elsewhere
  const css = fs.readFileSync(cssPath, 'utf8');
  const STRUCTURAL = /(grid-template-columns|grid-template-areas|display\s*:|flex-direction|position\s*:|min-width\s*:|width\s*:)/;
  const found = new Set();
  for (let i = 0; i < css.length; i++) {
    if (!css.startsWith('@media', i)) continue;
    const headEnd = css.indexOf('{', i);
    if (headEnd < 0) break;
    const head = css.slice(i, headEnd);
    let depth = 0, j = headEnd;
    for (; j < css.length; j++) {
      if (css[j] === '{') depth++;
      else if (css[j] === '}') { depth--; if (depth === 0) break; }
    }
    const m = head.match(/max-width\s*:\s*(\d+)px/);
    if (m && STRUCTURAL.test(css.slice(headEnd + 1, j))) found.add(Number(m[1]));
    i = j;
  }
  const bps = [...found].sort((a, b) => a - b);
  const uncovered = bps.filter((bp) => {
    // A regime is covered if some tested width falls in (previous breakpoint, this one].
    const prev = bps.filter((x) => x < bp).pop() || 0;
    return !WIDTHS.some((w) => w > prev && w <= bp);
  });
  if (uncovered.length) {
    console.error(`FAIL  styles.css has structural breakpoint(s) no tested width exercises: ` +
      `${uncovered.join(', ')}px. Add a width just below each to WR_NARROW_W's default, or this gate ` +
      'reports on fewer layouts than the page has.');
    process.exit(1);
  }
  console.log(`  ${bps.length} structural breakpoint(s) in styles.css, all covered by ${WIDTHS.length} widths`);
}

const PAGES = ['dashboard', 'server', 'connections', 'failover', 'routing', 'dns', 'updater',
  'diagnostics', 'settings'];
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const LANG = process.env.WR_UI_LANG || 'en';
const httpJSON = async (u) => (await fetch(u)).json();
// Before spending a browser on it: does the width list still cover the stylesheet? Cheap, and a
// coverage check that is defined but never called would be its own first violation.
assertWidthsCoverBreakpoints();
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wayhop-nw-'));
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
  `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`, `--window-size=${WIDTH},${HEIGHT}`,
  'about:blank'], { stdio: 'ignore' });

let bad = 0;
let subjects = 0;
let fatal = '';
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
  // A window-size flag is not the same as a viewport: headless still reports the outer window. Force
  // the metrics so the page really believes it is on a 375px screen and the media queries fire.
  await send('Emulation.setDeviceMetricsOverride',
    { width: WIDTH, height: HEIGHT, deviceScaleFactor: 1, mobile: true });
  await send('Page.navigate', { url: URL_ARG });
  for (let i = 0; i < 160; i++) {
    if (await ev(`document.readyState !== 'loading'`).catch(() => false)) break;
    await sleep(250);
  }
  await authenticateUI({
    evaluate: ev,
    navigate: async url => {
      await send('Page.navigate', { url });
      for (let i = 0; i < 160; i++) {
        if (await ev(`document.readyState !== 'loading'`).catch(() => false)) return;
        await sleep(250);
      }
      throw new Error('WayHop did not reload after login');
    },
    url: URL_ARG,
  });

  // Pin the language instead of inheriting it from whoever is running this.
  //
  // app.js picks the language from navigator.language, so this gate rendered whatever the host
  // browser preferred: English on the runner, something else on a developer box. Two machines
  // then measured different text under the same gate name, and a 9px overflow reported by CI on
  // routing at 375px could not be reproduced here through five controlled attempts — because the
  // one variable nobody had controlled was which translation was on screen.
  //
  // English by default so the number is the same everywhere; WR_UI_LANG sweeps the rest, which is
  // how a translation that outgrows its column gets found before it ships.
  await ev(`(() => { try { localStorage.setItem('wr-lang', ${JSON.stringify(LANG)}); } catch (e) {} })()`);
  await send('Page.navigate', { url: URL_ARG });
  for (let i = 0; i < 160; i++) {
    if (await ev('typeof route === "function"').catch(() => false)) break;
    await sleep(250);
  }
  // What the panel RESOLVED, not what was asked of it. app.js falls back to auto-detection when the
  // stored code has no dictionary, so reading the key back only proves the write landed: asking for
  // a language that does not exist passed this check while the page rendered English underneath.
  const shownLang = await ev('document.documentElement.getAttribute("lang")');
  if (shownLang !== LANG) {
    console.error(`the panel is showing ${JSON.stringify(shownLang)} after being asked for `
      + `${JSON.stringify(LANG)} — every width below would be measured in a language this run did not choose`);
    process.exit(2);
  }
  console.log(`  language: ${LANG} (pinned; set WR_UI_LANG to measure another)`);

  const burger = await ev(`(() => {
    const b = document.querySelector('.burger, [aria-controls*="nav"], button[aria-expanded]');
    if (!b) return { found: false };
    const r = b.getBoundingClientRect();
    return { found: true, visible: r.width > 0 && r.height > 0, label: (b.getAttribute('aria-label') || b.textContent || '').trim().slice(0, 40) };
  })()`);
  console.log(`  ${URL_ARG} @ ${WIDTH}x${HEIGHT}`);
  if (!burger.found || !burger.visible) {
    bad++;
    console.error(`FAIL  no operable burger control at ${WIDTH}px — the nav is off-canvas here, so the` +
      ' other pages are unreachable');
  } else {
    // "Present" is not "works", and this check said "operable" while testing only that the element had
    // a box. Below the collapse breakpoint the sidebar is off-canvas at left:-300 and the ONLY way to
    // reach the other eight routes is this control; the drawer itself is a CSS-only checkbox and the
    // burger is a plain <button>, so the connection between them is one addEventListener in nav.js.
    // Delete that line and every gate here stays green while the panel becomes a single-page app on
    // any phone. So click it and look at what happens.
    const drawer = await ev(`(() => {
      const cb = document.getElementById('navtoggle');
      const sb = document.querySelector('.sidebar');
      const item = document.querySelector('.nav-item');
      const onScreen = (n) => { if (!n) return false; const r = n.getBoundingClientRect();
        return r.width > 0 && r.right > 0 && r.left < window.innerWidth; };
      return { checked: cb ? cb.checked : null, sidebarOn: onScreen(sb), itemOn: onScreen(item) };
    })()`);
    // A real input event at the control's centre, not element.click(): a pointer-events or z-index
    // problem that puts something over the burger is exactly the failure a synthetic click hides.
    const at = await ev(`(() => { const b = document.querySelector('.nav-burger, .burger, [aria-controls*="nav"]');
      if (!b) return null; const r = b.getBoundingClientRect();
      return { x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2) }; })()`);
    if (!at) {
      bad++;
      console.error('FAIL  the burger has no hit box to click — NOT MEASURED, which is not a pass');
    } else {
      for (const type of ['mousePressed', 'mouseReleased']) {
        await send('Input.dispatchMouseEvent', { type, x: at.x, y: at.y, button: 'left', clickCount: 1 });
      }
      await sleep(700);
      const after = await ev(`(() => {
        const cb = document.getElementById('navtoggle');
        const sb = document.querySelector('.sidebar');
        const item = document.querySelector('.nav-item');
        const b = document.querySelector('.nav-burger, .burger, [aria-controls*="nav"]');
        const onScreen = (n) => { if (!n) return false; const r = n.getBoundingClientRect();
          return r.width > 0 && r.right > 0 && r.left < window.innerWidth; };
        return { checked: cb ? cb.checked : null, sidebarOn: onScreen(sb), itemOn: onScreen(item),
                 expanded: b ? b.getAttribute('aria-expanded') : null };
      })()`);
      if (!after.itemOn || !after.sidebarOn) {
        bad++;
        console.error(`FAIL  the burger does not open the navigation at ${WIDTH}px — after a real click` +
          ` the sidebar is ${after.sidebarOn ? 'on' : 'off'}-screen and a nav item is` +
          ` ${after.itemOn ? 'reachable' : 'UNREACHABLE'}. Every other route is a dead end here.`);
      } else if (after.expanded !== 'true') {
        // Separate failure, separate sentence: the drawer working and screen readers being told so
        // are two claims, and folding them together would let one hide the other.
        bad++;
        console.error(`FAIL  the drawer opens but aria-expanded stayed "${after.expanded}" — a screen` +
          ' reader is told the menu is still collapsed.');
      } else {
        console.log(`  burger       opens the drawer (checkbox ${drawer.checked} -> ${after.checked},` +
          ` sidebar on-screen, aria-expanded=${after.expanded})`);
      }
      // Dismiss it the way the app is actually built to be dismissed: tap outside, on the scrim.
      //
      // Clicking the burger a second time was tried first and reported "the drawer would not close".
      // That was the test being wrong about the app, not the app being broken: once open, the sidebar
      // slides over the burger, and elementFromPoint at its coordinates returns the sidebar's logo.
      // The scrim is a full-viewport <label for="navtoggle"> that goes pointer-events:auto only while
      // the drawer is open, which is the ordinary drawer pattern. A gate has to model the affordances
      // the interface has, not the ones the person writing it assumed.
      //
      // Closing matters for the measurement as much as for the check: leaving it open would put a
      // 300px sidebar over the content at every width below and invent overflow no user would see.
      const outside = await ev(`(() => { const sb = document.querySelector('.sidebar');
        const r = sb ? sb.getBoundingClientRect() : null;
        // Whichever side the drawer is NOT on. This assumed a left-hand drawer and clamped to the
        // right edge, so in RTL — where it opens from the right and reaches x=375 on a 375px screen
        // — the click landed ON the drawer, the scrim never saw it, and ar and fa were reported as
        // a product that will not dismiss. The comment above already says a gate must model the
        // affordances the interface has; this made the same mistake one direction over.
        const roomOnLeft = r ? (r.left >= window.innerWidth - r.right) : false;
        return { x: Math.round(roomOnLeft ? Math.max(12, r.left - 40)
                                      : Math.min(window.innerWidth - 12, (r ? r.right : 0) + 40)),
                 y: Math.round(window.innerHeight / 2) }; })()`);
      for (const type of ['mousePressed', 'mouseReleased']) {
        await send('Input.dispatchMouseEvent', { type, x: outside.x, y: outside.y, button: 'left', clickCount: 1 });
      }
      await sleep(500);
      const closed = await ev(`(() => { const cb = document.getElementById('navtoggle');
        return cb ? cb.checked : null; })()`);
      if (closed) {
        bad++;
        console.error('FAIL  tapping outside the open drawer does not dismiss it — the scrim is the' +
          ' only close affordance here, since the sidebar covers the burger once open. Every width' +
          ' below was also measured with the sidebar over the content.');
      }
    }
  }

  for (const p of PAGES) {
    await ev(`location.hash = '#${p}'`);
    await sleep(3000);
    // The Updater's package-manager preview is only on screen after a click, so this sweep has never
    // measured it: the buttons were rendered, the command line, the dry-run output and the checks
    // list were not. A <pre> holding a package manager's multi-line answer is exactly the shape that
    // ruins a narrow layout, and it went eleven widths unexamined because its subject was absent.
    // Open it — the click, then every disclosure, since a shut <details> is not laid out and would
    // report zero for content that overflows the moment the operator opens it.
    if (p === 'updater') {
      await ev(`(() => { const b = document.querySelector('.pm-deleg button'); if (b) b.click(); return !!b; })()`);
      await sleep(2500);
      await ev(`(() => { document.querySelectorAll('.pm-deleg details').forEach(d => d.open = true); return true; })()`);
      await sleep(400);
      const opened = await ev(`!!document.querySelector('.pm-argv')`);
      if (!opened) {
        console.error('  the Updater package-manager preview did not open — this page is being measured' +
          ' without the widest thing on it, which is the case this step exists for');
        bad++;
      }
    }
    const fitted = [];
    for (const W of WIDTHS) {
    // Resize rather than re-navigate. Eleven full sweeps would cost about five minutes; changing the
    // metrics and letting the page reflow costs a settle. mobile:true is only right below the nav
    // collapse — asserting a touch viewport at 1040px would be describing a device nobody has.
    await send('Emulation.setDeviceMetricsOverride',
      { width: W, height: HEIGHT, deviceScaleFactor: 1, mobile: W <= 900 });
    // Settle on the reflow: two identical readings of the page's own geometry. A flat sleep here read
    // a mid-reflow layout on the widest routes, which is how a resize-based check invents overflow
    // that is not there.
    for (let i = 0, prev = null, streak = 0; i < 24; i++) {
      await sleep(120);
      const d = await ev(`(() => { const v = document.querySelector('#view');
        return v ? v.scrollHeight + ':' + Math.round(v.getBoundingClientRect().width) : null; })()`);
      streak = (d && d === prev) ? streak + 1 : 0;
      prev = d;
      if (streak >= 2) break;
    }
    const r = await ev(`(() => {
      const de = document.documentElement;
      const vw = window.innerWidth;
      // documentElement.scrollWidth ALONE IS THE WRONG MEASUREMENT HERE. The app sets
      // body { overflow-x: hidden }, which clips overflow instead of scrolling it: with a card
      // forced to 520px in a 375px viewport, body.scrollWidth read 534 while documentElement stayed
      // at 375 and this check cheerfully reported "fits" on every route. The clipping makes the
      // failure WORSE, not better — the content is cut off with no scrollbar and no way to reach it —
      // and it is exactly the case a document-level check cannot see. So take the widest of the two,
      // and scan element boxes unconditionally rather than only when the document already told us.
      // 1px of slack: sub-pixel rounding shows up as +0.5 at some zoom factors, and failing on that
      // would be reporting arithmetic as a defect.
      const over = Math.max(de.scrollWidth, document.body.scrollWidth) - vw;
      const widest = [];
      {
        // Content inside a container that scrolls horizontally is NOT a defect: that is the
        // documented remedy for wide content (a timeline, a table), and the user can reach it. What
        // is a defect is content the user cannot reach — clipped by an overflow:hidden ancestor, or
        // pushing the page itself sideways. So walk up and forgive anything sitting in a real
        // horizontal scroller.
        const inScroller = (n) => {
          for (let p = n.parentElement; p; p = p.parentElement) {
            const ox = getComputedStyle(p).overflowX;
            if ((ox === 'auto' || ox === 'scroll') && p.scrollWidth > p.clientWidth) return true;
            if (p === document.body) break;
          }
          return false;
        };
        for (const n of document.querySelectorAll('#view *')) {
          const b = n.getBoundingClientRect();
          if (b.right > vw + 1 && !inScroller(n)) {
            widest.push({
              cls: (n.className || n.tagName).toString().trim().slice(0, 40),
              right: Math.round(b.right), w: Math.round(b.width),
              txt: (n.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 40),
            });
          }
        }
        widest.sort((a, b) => b.right - a.right);
      }
      const v = document.querySelector('#view');
      return {
        over, vw,
        widest: widest.slice(0, 4),
        controls: v ? v.querySelectorAll('button, input, select, textarea, [role="button"], a[href]').length : 0,
        nodes: v ? v.querySelectorAll('*').length : 0,
        scanned: document.querySelectorAll('#view *').length,
      };
    })()`);
    if (r.over > 1 || r.widest.length) {
      bad++;
      console.error(`FAIL  ${p.padEnd(12)} @${String(r.vw).padStart(4)}px  content overflows by ${Math.max(r.over, 0)}px` +
        (r.over <= 1 ? ' (clipped by overflow-x:hidden, so there is no scrollbar to reveal it)' : '') +
        ` — ${r.widest.length} element(s) past the right edge`);
      for (const w of r.widest) {
        console.error(`        right=${w.right} width=${w.w}  ${w.cls}  ${w.txt ? '"' + w.txt + '"' : ''}`);
      }
    } else if (!r.nodes) {
      bad++;
      console.error(`FAIL  ${p.padEnd(12)} @${String(r.vw).padStart(4)}px  rendered nothing at this width`);
    } else {
      subjects += r.scanned;
      fitted.push(`${W}:${r.scanned}`);
    }
    }
    // One line per route rather than one per measurement: eleven widths x nine routes is a wall of
    // text that stops being read. The per-width box counts stay in it, because "fits" on a route that
    // rendered nothing at one width would otherwise look identical to "fits" on a full one.
    if (fitted.length) console.log(`  ${p.padEnd(12)} fits ${fitted.length}/${WIDTHS.length} widths   ${fitted.join('  ')}`);
  }
  ws.close();
} catch (error) {
  fatal = error?.message || String(error);
} finally {
  chrome.kill();
  await new Promise((r) => setTimeout(r, 1200));
  try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 12, retryDelay: 250 }); } catch (_) {}
  // Not silent: a directory that survives is a browser that may still be running, and enough of
  // those starve the next gate. Say it here rather than leave it to be counted in /tmp later.
  if (fs.existsSync(dir)) console.error(`note: could not remove the Chrome profile dir ${dir}`);
}

if (fatal) {
  console.error(`FAIL  ${fatal}`);
  process.exit(1);
}

if (bad) {
  console.error(`\n${bad} problem(s) across ${WIDTHS.length} widths. Horizontal overflow means the user` +
    ' drags the page sideways to read it — usually a grid whose min track exceeds the screen, an' +
    ' unbroken string, or a leftover fixed width.');
  process.exit(1);
}
console.log(`\nevery route fits every tested width with no horizontal overflow`);
console.log(`subjects: ${subjects} element boxes measured across ${WIDTHS.length} widths (${WIDTHS.join(', ')})`);
