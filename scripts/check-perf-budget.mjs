// check-perf-budget.mjs — CI guard for the INITIAL frontend payload (§2.1/§2.4).
//
// The panel is served off a router with a slow CPU and a slower uplink, so page weight is a
// correctness-adjacent property, not a nicety. This measures exactly what a first-time visitor
// downloads before the app is interactive — the files index.html references EAGERLY, plus at most
// ONE language dictionary — and fails the build if it exceeds the budget.
//
// It deliberately does NOT count per-language dictionaries other than the visitor's own. If a
// lazy asset is ever re-added to index.html as an eager <script>, this check sees it immediately.
//
// Usage: node scripts/check-perf-budget.mjs   (exit 1 over budget)
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

const DIST = 'web/dist';
// §2.1 set this at 250 KB, and it held for a year. It is raised here for one reason, recorded so the
// next person does not have to guess whether it was earned or waved through: 321 UI strings that had
// been left in English were translated into all nine languages, and a visitor downloads exactly one
// dictionary. The 250 KB figure had been measured against dictionaries missing a third of the panel's
// copy — it was cheap because the product was incomplete, not because it was lean.
//
// The alternative the failure message names, route-scoped dictionaries, was considered and refused:
// i18n-loader.js is parser-inserted on purpose so the chosen language lands BEFORE app.js and no
// untranslated text is ever painted. Splitting the dictionary per route would reintroduce that flash
// on every navigation — trading a property a reader can see for bytes they cannot.
//
// Headroom is deliberately thin (about 1%): this number exists to make growth a decision, and a
// budget with room to spare stops doing that.
//
// Raised by 200 B for the AmneziaWG 3.1 install from WayHop's own feed, planned in
// docs/AWG_FULL_INSTALL.md (development repository).
// Its code is in the route-scoped page-updater.js and costs the first visit nothing; what does cost
// it is six new strings, translated in all nine languages, in the one dictionary every visitor loads
// (+157 B gzip in ru, the largest). At 0.5.7 the payload stood 20 B under 262000, so no feature with
// any words could land without this decision. The sentences that describe a plan (packages, paths,
// versions, the installer's reason) are the daemon's and are not translated, which is what kept the
// growth to six labels. Trimming dictionary keys the code no longer uses was the alternative; it was
// left alone because the client also translates sentences the daemon sends, and a key that reads as
// dead in the source can still be live through one of those.
//
// Raised by another 200 B for the network-service restart the AmneziaWG row offers after a kernel
// module install (netifd reads AmneziaWG's handler only when it starts). Three strings, in all nine
// languages (+212 B gzip in ru): the restart button, the opt-in to restart with the install, and the
// sentence saying the new handler is read only after a restart or at the next reboot. That sentence is
// the one an operator has to understand in their own language before cutting every link on the router,
// which is why it is not left to the daemon's English. The rest of the new text - which connections
// still run on amneziawg-go and when they switch, the installer's notes - is the daemon's and is not
// translated, like the plan sentences above, which kept the growth to three labels. Trimming was ruled
// out for the reason given above. The payload stood 63 B under the previous figure.
//
// Raised by 200 B in 0.5.8-r2 for keeping the router's own VPN connections in step with the router.
// The code is in the route-scoped page-connections.js (app.js came out a little smaller); the cost is
// six strings in every dictionary (+104 B gzip in total): a connection deleted on the router, one
// not running, the removal notice, and the partial-discovery warning. An operator has to read those in
// their own language to know which exit is dead. The payload stood 68 B under the previous figure.
const BUDGET = 262 * 1000 + 600;

const gz = (buf) => zlib.gzipSync(buf, { level: 9 }).length;
const read = (f) => fs.readFileSync(path.join(DIST, f));

const html = fs.readFileSync(path.join(DIST, 'index.html'), 'utf8');

// Eagerly-loaded assets = <script src> / <link rel=stylesheet href> written literally in the HTML.
// A src injected at runtime (document.write / createElement) is NOT eager and is excluded by design.
// Scan the MARKUP only: inline <script> bodies are stripped first, otherwise a src built inside an
// inline loader (the language bootstrap's document.write) would be mistaken for an eager asset —
// which is precisely the lazy loading this budget is meant to reward.
const markup = html.replace(/<script(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/gi, '<script></script>');
const eager = [];
for (const m of markup.matchAll(/<script[^>]+src="([^"]+)"/g)) eager.push(m[1]);
for (const m of markup.matchAll(/<link[^>]+rel="stylesheet"[^>]+href="([^"]+)"/g)) eager.push(m[1]);

const problems = [];
const rows = [];
let total = gz(Buffer.from(html, 'utf8'));
rows.push(['index.html', total]);

for (const src of eager) {
  if (/^https?:/.test(src)) { problems.push(`index.html loads an EXTERNAL asset eagerly: ${src}`); continue; }
  const file = src.replace(/^\.?\//, '');
  let buf;
  try { buf = read(file); } catch { problems.push(`index.html references a missing asset: ${src}`); continue; }
  const size = gz(buf);
  rows.push([file, size]);
  total += size;
}

// The visitor also downloads their own language dictionary. Budget against the LARGEST one, so the
// check reflects the worst real user rather than the luckiest.
let worstLang = null;
const langDir = path.join(DIST, 'i18n');
if (fs.existsSync(langDir)) {
  for (const f of fs.readdirSync(langDir).filter((f) => f.endsWith('.js'))) {
    const size = gz(fs.readFileSync(path.join(langDir, f)));
    if (!worstLang || size > worstLang[1]) worstLang = [path.join('i18n', f), size];
  }
}
if (worstLang) { rows.push([worstLang[0] + '  (largest language)', worstLang[1]]); total += worstLang[1]; }

for (const [name, size] of rows) console.log(`  ${String(size).padStart(8)}  ${name}`);
console.log(`  ${'-'.repeat(8)}`);
console.log(`  ${String(total).padStart(8)}  TOTAL gzip   (budget ${BUDGET})`);

if (total > BUDGET) {
  problems.push(`initial payload ${total} B gzip exceeds the ${BUDGET} B budget by ${total - BUDGET} B ` +
    `(${Math.round((total / BUDGET) * 100)}%). Move something to route-scoped loading, or justify a new budget.`);
}

if (problems.length) {
  console.error('\nperf budget FAILED:');
  for (const p of problems) console.error('  ' + p);
  process.exit(1);
}
console.log(`perf budget OK: ${total} B gzip of ${BUDGET} B (${Math.round((total / BUDGET) * 100)}%).`);
