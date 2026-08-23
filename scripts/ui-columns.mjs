// ui-columns.mjs — do sibling grid rows resolve to the same columns?
//
// Routing's table headings sat over the wrong columns: .rlhead and .rlrow are two INDEPENDENT grids,
// and a content-sized track resolved differently in each, so the headings drifted right of the data
// they name by up to 192px — "Matched" over the move arrows, the match text with no heading at all.
// DNS's query path had the identical bug at 188px, and the routing fix left an 8px remainder because
// the two grids were inset by different paddings, so fr divided a different content box in each.
//
// Three instances of one thing: rows that declare a shared column structure must RESOLVE to the same
// one. That is what this measures, and the only thing it measures.
//
// Scope, stated so the name does not promise more than it delivers: this checks the TRACKS, not what
// sits in them. A control that sizes itself inside a track all rows agree on — a 34px toggle in a
// 46px column, a badge as wide as its word — is not a subject here. That is deliberate. An earlier
// cut compared cell right-edges with a tolerance, which meant carrying a fudge factor big enough to
// swallow those two (12px and 10px) and therefore too big to be sure it would catch a small real one.
// Settings' ragged form column, where a <select> sized to its longest option, is a different defect
// with a different measurement (a max-width on .sx-ctl controls); it is NOT covered here.
//
// Comparability is the rest of the design. Rows are only compared when they are structurally alike —
// same parent, same cell count — so a row that legitimately holds something else is not judged
// against one that does not.
//
//   node scripts/ui-columns.mjs <url> [cdp-port]
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { authenticateCDP } from './ui-auth.mjs';

const URL_ARG = process.argv[2];
const PORT = Number(process.argv[3] || 9750);
if (!URL_ARG) { console.error('usage: node scripts/ui-columns.mjs <url> [cdp-port]'); process.exit(2); }
const PAGES = ['dashboard', 'server', 'connections', 'failover', 'routing', 'dns', 'updater',
  'diagnostics', 'settings'];
// Two rows' tracks are "the same" within this. It is a sub-pixel allowance and nothing else — a
// fractional track resolves to 726.938px and can land a hair apart between siblings. It is NOT a
// judgement dial: every real defect was 8px or more, and nothing legitimate lands between 1px and 8px,
// because a track either resolves from the same inputs or it does not.
const TOL = Number(process.env.WR_COL_TOL || 1);
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const httpJSON = async (u) => (await fetch(u)).json();
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wayhop-cols-'));
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run',
  `--remote-debugging-port=${PORT}`, `--user-data-dir=${dir}`, '--window-size=1280,900', 'about:blank'],
  { stdio: 'ignore' });

const COLLECT = `(() => {
  const v = document.querySelector('#view');
  if (!v) return null;
  const R = (n) => n.getBoundingClientRect();
  const label = (n) => (n.className || n.tagName).toString().trim().split(/\\s+/).slice(0, 2).join('.').slice(0, 28);
  const out = [];
  let groups = 0;

  for (const parent of v.querySelectorAll('*')) {
    const kids = [...parent.children].filter((k) => {
      const b = R(k), cs = getComputedStyle(k);
      return b.width > 2 && b.height > 2 && cs.position !== 'absolute' && cs.position !== 'fixed';
    });
    if (kids.length < 3) continue;

    // The subject is rows that DECLARE a shared column structure: siblings whose computed
    // grid-template-columns is identical. Those have promised to line up, so they can be held to it
    // without judgement.
    //
    // The first cut of this took any stack of flex-or-grid children with matching cell counts. It
    // found no group at all on seven of nine routes — a check measuring nothing — while flagging the
    // flight recorder, whose rows are flex and whose "columns" are incidental rather than declared.
    // Two failures at once: blind where it mattered, noisy where it did not.
    // Group by STRUCTURE, not by resolved template. Grouping on getComputedStyle().gridTemplateColumns
    // is self-defeating here: that property reports resolved pixels, so under the very defect being
    // hunted the header and its rows resolve differently, land in different buckets, and never get
    // compared. The symptom hid the subject, and the gate passed on the reverted bug.
    //
    // Grid only, not flex: a flex row's "columns" are incidental rather than declared, and including
    // them made this flag the flight recorder, whose name cell is content-sized by design.
    const boxes = kids.map(R);
    const stacked = boxes.every((b, i) => i === 0 || b.top >= boxes[i - 1].bottom - 2);
    if (!stacked) continue;
    const grids = kids.filter((k) => getComputedStyle(k).display === 'grid' && k.children.length >= 2);
    if (grids.length < 3) continue;
    const counts = new Map();
    for (const g of grids) counts.set(g.children.length, (counts.get(g.children.length) || 0) + 1);
    const n = [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
    const rows = grids.filter((g) => g.children.length === n);
    if (rows.length < 3) continue;
    groups++;

    // The resolved template, in pixels — NOT the declared string. getComputedStyle returns used
    // values here, which is the point: two rows can declare the identical rule and still resolve
    // differently, and that gap is the entire defect.
    const tracks = rows.map((r) => getComputedStyle(r).gridTemplateColumns.split(/\\s+/).map(parseFloat));
    const width = tracks[0].length;
    if (!tracks.every((t) => t.length === width && t.every((x) => x === x))) continue;
    for (let c = 0; c < width; c++) {
      const col = tracks.map((t) => t[c]);
      const spread = Math.max(...col) - Math.min(...col);
      if (spread > ${TOL}) {
        // The track spread is the criterion; the drift is the consequence, and it is measured from
        // real boxes rather than derived. Deriving it from the tracks before this column reported 0px
        // for a defect that shifts every column AFTER it — a number that read as "no visual effect"
        // while the header sat 8px off its data.
        let drift = 0;
        for (let k = 0; k < width; k++) {
          const ls = rows.map((r) => R(r.children[k]).left);
          drift = Math.max(drift, Math.max(...ls) - Math.min(...ls));
        }
        out.push({ where: label(parent), col: c, rows: rows.length,
                   spread: Math.round(spread), drift: Math.round(drift),
                   sizes: [...new Set(col.map((x) => Math.round(x)))].slice(0, 4).join(' vs '),
                   sample: label(rows[0].children[c]) });
      }
    }
  }
  return { out, groups };
})()`;

let bad = 0, groups = 0;
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
  console.log(`  ${URL_ARG}  (tolerance ${TOL}px)`);
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
    groups += r.groups;
    if (!r.out.length) { console.log(`  ${p.padEnd(12)} ok   ${r.groups} row group(s)`); continue; }
    bad += r.out.length;
    console.error(`FAIL  ${p.padEnd(12)} ${r.out.length} disagreeing track(s) in ${r.groups} group(s)`);
    for (const x of r.out.slice(0, 5)) {
      console.error(`        track ${x.col} of .${x.where}  across ${x.rows} rows: ${x.sizes}` +
        `  (spread ${x.spread}px, cells here sit up to ${x.drift}px apart)  (.${x.sample})`);
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
  console.error(`\n${bad} track(s) that sibling rows resolve differently despite declaring the same` +
    ' grid. A heading that sits over the wrong column is read as naming it.');
  process.exit(1);
}
console.log(`\nsibling rows resolve to identical column tracks`);
console.log(`subjects: ${groups} row groups measured`);
