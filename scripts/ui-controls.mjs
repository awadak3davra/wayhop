// ui-controls.mjs — nothing the user could operate may vanish in a redesign.
//
// The redesign brief is explicit: reorganise the pages, lose no function, drop no button. That is
// only checkable if the set of operable things is recorded BEFORE and compared AFTER, so this
// captures a per-route inventory and fails when an entry disappears without being accounted for.
//
// Identity is the accessible name. A redesign legitimately renames things, so a rename is not a
// failure: it must be DECLARED in scripts/controls-baseline.json under "renamed", which turns an
// invisible loss into a reviewable line. Anything that disappears undeclared fails.
//
//   node scripts/ui-controls.mjs <url> --capture         # record this instance
//   node scripts/ui-controls.mjs <url>                   # compare this instance against its record
//
// Two things this got wrong on the first attempt, both of which made it fail 19 controls on a box
// nobody had touched — a gate that cries wolf is worse than no gate, because it trains you to
// declare bogus renames and the one real loss hides among them:
//
//   1. The name was read from the whole subtree, so a card header came out as "Live connections361
//      active · 1% of 65536 · direct 1.1 TB · " and a settings section as "Panel4". Those strings
//      change every second and every profile edit; they are not identities. The name now comes from
//      the element's OWN text nodes, which is the label, and ignores what descendants render into
//      it — the live counter, the badge count, the "checking…" placeholder.
//   2. Captures from several instances were merged into one union, and then a single instance was
//      compared against it. No single router can satisfy the union: the Keenetic has native tunnels
//      the OpenWrt box does not, the demo has neither. Every capture is now kept under its own
//      source URL and compared only against itself, which is the property that actually matters —
//      this box kept everything this box had.
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
  // Falling out of that loop used to be silent, so a profile dir that could not be removed — and the
  // browser that may still be holding it — went unnoticed until somebody counted /tmp. Enough of them
  // starve a later gate run.
  console.error(`note: could not remove the Chrome profile dir ${dir}`);
}

const URL_ARG = process.argv[2];
const CAPTURE = process.argv.includes('--capture');
if (!URL_ARG) {
  console.error('usage: node scripts/ui-controls.mjs <url> [--capture]');
  process.exit(2);
}
const BASELINE = path.join(process.cwd(), 'scripts', 'controls-baseline.json');
const PORT = Number(process.env.CDP_PORT || 9540);
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const PAGES = 'dashboard,server,connections,failover,routing,dns,updater,diagnostics,settings'.split(',');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const httpJSON = async (u) => (await fetch(u)).json();

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wayhop-controls-'));
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
  `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`, '--window-size=1280,900', 'about:blank'],
  { stdio: 'ignore' });

// Names that name an OBJECT rather than a capability — a connection, a tunnel, a resolver. They
// differ per router and per profile, so they are folded to a shape before comparison: losing
// "Delete vless_a" from one box tells you nothing, but losing "Delete <object>" entirely does.
const OBJECTISH = [
  // "Copy report" is a NAME, not verb+object: one button, on one card, copying the whole battery.
  // Adding Copy to the verb list below collapsed it into "Copy <object>" alongside the per-row Copy
  // buttons, and the baseline then reported the control as GONE — correctly, since nothing under its
  // recorded name was left. shape() returns on the first match, so this exact rule has to precede
  // the verb rule.
  [/^Copy report$/i, () => 'Copy report'],
  [/^(Delete|Edit|Test|Check config|Move up|Move down|Show|Hide|Remove|Inspect|Copy command|Copy)\s+.+$/i, (m) => `${m[1]} <object>`],
  [/^Check updates for\s+.+$/i, () => 'Check updates for <component>'],
  [/^Set as default route for\s+.+$/i, () => 'Set as default route for <object>'],
  // The native-tunnel adopt controls name their interface; the box has awg0 and awg1.
  [/^Adopted\s+.+$/i, () => 'Adopted <object>'],
  [/^Adopt as exit\s+.+$/i, () => 'Adopt as exit <object>'],
  [/^Test all members of\s+.+$/i, () => 'Test all members of <object>'],
  [/^added as\s+.+$/i, () => 'added as <connection>'],
  // "Frankfurt VLESS enabled" — the toggle names its exit, so the set changes whenever a profile
  // does. What must survive the redesign is that an exit CAN be switched on, not what it is called.
  //
  // The trailing status is part of that name and appears only once the status is KNOWN: a routing
  // list reads "Work tools enabled" while its source is still being checked and "Work tools enabled —
  // OK" a moment later. Anchoring on the bare word therefore made this entry flicker in and out of
  // the baseline with nothing but timing behind it — observed as "1 control recorded and gone now" on
  // both Connections and Routing in one run, while every switch was present on screen. The capability
  // is identical either way, so the shape swallows the suffix.
  // Both words, one shape. The name has to agree with aria-checked, so a switch that is OFF now
  // reads "<object> disabled" - see switchWord in app.js. The capability being recorded is the
  // same either way ("this exit can be switched"), and collapsing them keeps the baseline from
  // flipping every time the walk lands on a profile whose exits are off.
  [/^.+\s+(enabled|disabled)(\s*[—–-]\s*.+)?$/i, () => '<object> enabled'],
];

function shape(name) {
  for (const [re, to] of OBJECTISH) {
    const m = name.match(re);
    if (m) return to(m);
  }
  return name;
}

// A control's name carries live status, so the same switch reads "X enabled" while its source is
// still being checked and "X enabled — OK" a moment later. Both are the same capability, but the
// browser walk below samples whichever moment it lands on. Anchoring the shape on the bare trailing
// word therefore reported a control as LOST purely because the status had arrived - seen on
// Connections and Routing in one run while every switch was present on screen, and green on a rerun
// that changed nothing. Asserting the property here makes it deterministic: a future edit to the
// rule fails immediately and by name, instead of surfacing as a false loss in one run out of five.
for (const [word, suffix] of [['enabled', ''], ['enabled', ' — OK'], ['disabled', ''],
  ['enabled', ' — source unreachable'], ['disabled', ' - checking']]) {
  const name = 'Work tools ' + word + suffix;
  const got = shape(name);
  if (got !== '<object> enabled') {
    console.error('normaliser regression: ' + JSON.stringify(name) + ' must shape as ' +
      '"<object> enabled", got ' + JSON.stringify(got));
    process.exit(1);
  }
}


let inventory = {};
try {
  for (let i = 0; i < 60; i++) {
    try { await httpJSON(`http://127.0.0.1:${PORT}/json/version`); break; } catch { await sleep(250); }
  }
  const targets = await httpJSON(`http://127.0.0.1:${PORT}/json/list`);
  const ws = new WebSocket((targets.find((t) => t.type === 'page') || targets[0]).webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  let id = 0; const waiting = new Map();
  // In-flight request tracking. DOM quiet alone is not "settled": while the Updater waits on a
  // GitHub mirror nothing moves for seconds, so a quiet-DOM heuristic declares the page finished
  // and records it as having no "Check updates" button. Streams are excluded — the traffic feed
  // never completes, and counting it would mean the page is never settled — and so is anything
  // still open after 5s, which is a long-poll rather than a render the page is waiting on.
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
    if (m.method === 'Network.requestWillBeSent' && !STREAMISH.has(m.params.type)) {
      inflight.set(m.params.requestId, Date.now());
    } else if (m.method === 'Network.loadingFinished' || m.method === 'Network.loadingFailed') {
      inflight.delete(m.params.requestId);
    }
  };
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

  await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
  await send('Page.navigate', { url: URL_ARG });
  let ready = false;
  for (let i = 0; i < 160; i++) {
    if (await ev('typeof route === "function"').catch(() => false)) { ready = true; break; }
    await sleep(250);
  }
  if (!ready) throw new Error(`app.js never initialised at ${URL_ARG}`);
  await authenticateCDP({ send, evaluate: ev, url: URL_ARG });

  const COLLECT = `(() => {
    const v = document.querySelector('.route-view') || document.querySelector('#view');
    if (!v) return null;
    // The element's own text, not its subtree's. A card header holds its label as a direct text node
    // and its live summary inside a child, so this keeps "Live connections" and drops the counter.
    const ownText = (e) => Array.from(e.childNodes)
      .filter(n => n.nodeType === 3).map(n => n.textContent).join(' ').replace(/\\s+/g, ' ').trim();
    const out = [];
    // role=switch belongs here as much as button does. Leaving it out meant the single most
    // consequential control on Connections — the toggle that enables an exit — was invisible to a
    // gate whose whole claim is that no control disappears. Same for the other composite roles the
    // panel builds by hand rather than with a native element.
    v.querySelectorAll('button, input, select, textarea, a[href],' +
      '[role="button"], [role="switch"], [role="checkbox"], [role="tab"], [role="menuitem"], [role="link"]'
    ).forEach(e => {
      const tag = e.tagName.toLowerCase();
      let n = (e.getAttribute('aria-label') || '').trim();
      if (!n && (tag === 'input' || tag === 'select' || tag === 'textarea')) {
        const f = e.closest('.field');
        const lab = (e.id && document.querySelector('label[for="' + CSS.escape(e.id) + '"]'))
          || (f && f.querySelector('label')) || e.closest('label');
        // A label element has the same problem: its text may carry a live hint beside the caption.
        n = (lab ? (ownText(lab) || (lab.textContent || '')) : (e.getAttribute('placeholder') || '')).trim();
      }
      // A composed header — chevron, caption and live summary each in their own child — has no text
      // of its own, so ownText is empty and the whole subtree would come back instead. Such an
      // element still has two stable names available: the authored title, and the .card-title child
      // that carries the caption. Both beat a string with a packet counter in it.
      if (!n) n = ownText(e);
      if (!n) {
        const cap = e.querySelector('.card-title');
        if (cap) n = (ownText(cap) || cap.textContent || '').trim();
      }
      if (!n) n = (e.getAttribute('title') || '').trim();
      if (!n) n = (e.textContent || '').trim();
      n = n.replace(/\\s+/g, ' ').slice(0, 60);
      if (n) out.push(n);
    });
    return out;
  })()`;

  // Wait for the route to settle instead of guessing a delay. A fixed 2.1s was enough for the demo
  // and not for a real router: the Keenetic came back with 74 controls one run and 81 the next,
  // because "Add as exit", "Already added" and the failover group buttons only exist once their
  // fetch lands. A gate that reports a slow box as a box that lost five buttons is measuring
  // latency and calling it function, so this reads until two consecutive samples agree.
  const settle = async (p) => {
    let prev = null;
    for (let i = 0; i < 40; i++) {          // 40 x 400ms = 16s ceiling
      await sleep(400);
      const names = await ev(COLLECT);
      if (names === null) throw new Error(`route #${p} rendered no view container`);
      const cur = [...new Set(names.map(shape))].sort();
      // Three samples' worth of quiet, nothing still being fetched, and never settle on an empty
      // page unless it really is empty.
      if (prev && i >= 3 && pending() === 0 &&
          cur.length === prev.length && cur.every((x, k) => x === prev[k])) return cur;
      prev = cur;
    }
    console.error(`  warning: #${p} never stopped changing within 16s — recording the last sample`);
    return prev || [];
  };

  for (const p of PAGES) {
    await ev(`location.hash = '#${p}'`);
    inventory[p] = await settle(p);
  }
  ws.close();
} finally {
  await closeChrome(chrome, dir);
}

const total = Object.values(inventory).reduce((a, x) => a + x.length, 0);

// One instance, one key. The raw argument WAS the key, so a trailing slash decided whether the
// baseline was found: captured as http://host:8097/ and re-run as http://host:8097, this gate
// announced "no baseline recorded" while printing that same instance in its recorded list, and
// exited 2. A guard that stops guarding over a slash, and says so in a message that reads like the
// operator's mistake. Normalise both sides - on write, on read, and for records already written.
const instanceKey = (u) => {
  try { return new URL(u).origin; } catch { return String(u).replace(/[/]+$/, ''); }
};
const load = () => {
  const raw = fs.existsSync(BASELINE)
    ? JSON.parse(fs.readFileSync(BASELINE, 'utf8'))
    : { renamed: {}, sources: {} };
  const sources = {};
  for (const [k, v] of Object.entries(raw.sources || {})) sources[instanceKey(k)] = v;
  return { ...raw, sources };
};

if (CAPTURE) {
  const base = load();
  base.renamed = base.renamed || {};
  base.sources = base.sources || {};
  // Replace rather than merge. Merging made a stale name from an earlier build immortal: it could
  // never be satisfied again and could never be explained, only declared away.
  base.sources[instanceKey(URL_ARG)] = { routes: inventory };
  fs.writeFileSync(BASELINE, JSON.stringify(base, null, 1));
  console.log(`captured ${total} controls from ${URL_ARG} across ${Object.keys(inventory).length} routes`);
  console.log(`baseline now records ${Object.keys(base.sources).length} instance(s): ${Object.keys(base.sources).join(', ')}`);
  process.exit(0);
}

if (!fs.existsSync(BASELINE)) {
  console.error(`no baseline at ${BASELINE} — run with --capture against the pre-redesign build first`);
  process.exit(2);
}
const base = load();
const rec = (base.sources || {})[instanceKey(URL_ARG)];
if (!rec) {
  console.error(`no baseline recorded for ${URL_ARG}. Comparing one instance against another's record`);
  console.error(`is not a control check — the boxes legitimately differ. Capture this one first:`);
  console.error(`  node scripts/ui-controls.mjs ${URL_ARG} --capture`);
  console.error(`recorded instances: ${Object.keys(base.sources || {}).join(', ') || '(none)'}`);
  process.exit(2);
}

// Declarations resolve global-first, then this instance's own. Some losses are only legitimate on
// ONE box: the Keenetic's sing-box is owned by opkg, so the panel refuses to remove it and correctly
// draws no Remove button, while on the OpenWrt box and the demo that same button must still exist.
// Declaring it globally would switch the gate off everywhere and make its pass mean nothing on the
// two instances where the control genuinely has to be there.
const renamed = { ...(base.renamed || {}), ...((rec && rec.renamed) || {}) };

let lost = 0;
// A control may legitimately move to another route in a redesign, so a name found anywhere on this
// instance counts as present — the gate is about losing FUNCTION, not about pinning layout.
const anywhere = new Set(Object.values(inventory).flat());
for (const [p, wanted] of Object.entries(rec.routes || {})) {
  const missing = wanted.filter((n) => {
    if (anywhere.has(n)) return false;
    const to = renamed[n];
    // Two declaration tokens, because there are two different truths and only one of them was
    // sayable. `<removed: declared>` means the control is gone from the app. But a control can also
    // still exist and simply not be REACHABLE in the state the demo is seeded into: "+ Add your first
    // server" lives in the Set-up-Server empty state, and the stress seed now creates four servers, so
    // that state no longer renders. Declaring that as removed would put a false statement in a file
    // whose whole purpose is that every loss is a reviewed line. `<state-gated: declared>` says what
    // actually happened, and is exactly as reviewable.
    if (to && (anywhere.has(to) || to === '<removed: declared>' || to === '<state-gated: declared>')) return false;
    return true;
  });
  if (missing.length) {
    lost += missing.length;
    console.error(`FAIL ${p}: ${missing.length} control(s) recorded for this instance and gone now:`);
    missing.forEach((n) => console.error(`       "${n}"`));
  }
}

const want = Object.values(rec.routes || {}).reduce((a, x) => a + x.length, 0);
console.log(`checked ${total} controls on ${URL_ARG} against its recorded ${want}`);
if (lost) {
  console.error(`\n${lost} control(s) disappeared. If a removal or rename is intended, declare it in`);
  console.error(`scripts/controls-baseline.json under "renamed" ("old name": "new name", or`);
  console.error(`"old name": "<removed: declared>") so the loss is a reviewed decision, not an accident.`);
  process.exit(1);
}
console.log('no control lost against the baseline');
