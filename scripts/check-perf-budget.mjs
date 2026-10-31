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
// Raised by 300 B for Simplified Chinese (zh-CN). The dictionary itself costs this budget nothing:
// a visitor loads one language and the check counts the largest, which is still ru (65.7 KB gzip
// against zh-CN's 58.6 KB). What it does cost is eager code, measured at +320 B gzip: the picker entry
// in i18n-meta.js (+25 B), and the resolver that maps a browser tag to a shipped code (i18n-loader.js
// +~150 B as WR_PICK, app.js +~140 B for detectLang through it, its memo and the zh plural case). The
// old rule took the first two letters, which cannot name a region-tagged code: zh-CN would have
// loaded nothing. The alternative, shipping the dictionary as plain "zh", fit without a raise but sets
// <html lang="zh">, which leaves the browser to guess between Simplified, Traditional and Japanese
// glyph forms; "zh-CN" settles it. The payload stood 51 B under the previous figure.
//
// Raised by 1000 B for the routing switch in the header (WayHop's routing off / back on). It cannot
// be route-scoped: the switch and the banner that says routing is off are on every page, which is the
// point of them, so their code is in app.js (+696 B gzip) and their markup in index.html and
// styles.css (+95 B). Five strings, in all nine languages (+222 B gzip in ru): the banner, Switch on,
// Switch off, and the two confirmations, which say what the click does to every device on the network
// and so are the ones an operator has to read in their own language. The daemon's failure reasons
// are shown as sent, not translated, like the plan sentences above. The payload stood 51 B under the
// previous figure, so not even this feature's markup would have fit.
//
// The two raises above were measured on separate branches against the same base, and landed together.
// Merged with the Telegram bot's one new panel string (the "not in force" note on the bot's path to
// Telegram, +48 B gzip in ru, which fit under the old figure on its own), the payload measures
// 263713 B: 262332 at the base, +320 B for zh-CN, +1013 B for the routing switch, +48 B for the bot.
// That is 13 B over the plain sum of the two raises (263700), so the budget is set from the
// measurement instead, with 87 B of headroom, about what each raise above left.
//
// Raised by 200 B in 0.5.8-r2 for keeping the router's own VPN connections in step with the router.
// The code is in the route-scoped page-connections.js (app.js came out a little smaller); the cost is
// six strings in every dictionary (+104 B gzip in total): a connection deleted on the router, one
// not running, the removal notice, and the partial-discovery warning. An operator has to read those in
// their own language to know which exit is dead. The payload stood 68 B under the previous figure.
// Merged onto the 263800 figure above, the two raises add up.
//
// Raised by 400 B for the protocols sing-box 1.14 brought. The forms are in the route-scoped
// page-connections.js; what the initial payload pays for is their strings in the largest dictionary
// (ru), because an operator reads a sign-in field in their own language. Measured: olcRTC's removal
// freed 196 B (264000 budget, 263600 payload), the OpenVPN form took +303 B (five strings and the
// supported-formats line) and the Snell form +108 B (four labels), 264011 B in all - 11 B over. The
// raise leaves room for the OpenConnect form, the last of the three.
//
// Raised by 200 B for splitting the TLS handshake of a list routed direct (sing-box route options,
// the first gap in the competitor survey: HomeProxy has it). The control is in the route-scoped
// page-routing.js; the cost is four strings in every dictionary (+183 B gzip in ru): the label, the two
// modes, and the sentence saying it works only in tun or hybrid mode - the condition an operator has to
// understand to know why it did nothing. The payload stood 8 B under the previous figure.
//
// Raised by 100 B for the subscription User-Agent (competitor gap 2: OpenClash and Passwall2 let the
// user set it). The field is in the route-scoped page-connections.js; the cost is its label and the
// sentence saying why it exists (+93 B gzip in ru) - without that sentence "User-Agent" is a word an
// operator has no reason to touch. The payload stood 25 B under the previous figure.
//
// Raised by 400 B for the per-exit service check (competitor gap 3: OpenClash's streaming check). The
// check is in the route-scoped page-diagnostics.js and carries its own row label, so app.js did not
// grow; the cost is ten strings in every dictionary (+402 B gzip in ru): the row, the four reasons an
// exit could not be checked, the legend for its four marks, the three verdicts and the fix. Each says
// why a service fails through an exit - the one thing an operator opens this row to learn. The payload
// stood 32 B under the previous figure.
//
// Raised by 300 B for the ByeDPI connection (competitor gap 4: ByeDPI-OpenWrt and Podkop-Manager run
// it). The form is in the route-scoped page-connections.js; app.js grew by the card line that shows a
// ByeDPI connection's strategy instead of an empty "server:0" (+69 B gzip), and the dictionaries by two
// strings (+201 B gzip in ru): what ByeDPI does and that a list must be sent to it, and the strategy
// field's label - the field takes raw ciadpi flags, so an operator has to read what goes there. The
// payload stood 30 B under the previous figure.
//
// Raised by 400 B for the scheduled core restart (competitor gap 12: Passwall2 and nikki have it).
// Settings is eager, so the field lives in app.js (+241 B gzip: the input, its row in the settings
// index, the collected value and the client-side format check mirroring config.ParseCoreRestart);
// two strings (+118 B gzip in ru): the label, and the hint that says the format and that a restart
// drops every live connection - the cost an operator has to weigh before setting it. The error
// reuses the label with a language-neutral "HH:MM / 1h-24h". The payload stood 60 B under the
// previous figure.
//
// Raised by 300 B for importing routing lists (competitor gap 14: HydraRoute's HRweb imports the
// Keenetic's FQDN object-groups and its own domain.conf). The dialog is in the route-scoped
// page-routing.js; app.js grew by the toolbar button (+21 B gzip), and the dictionaries by eleven
// strings (+213 B gzip in ru): the dialog's title, its two sources, the per-group counts, what the
// router routed a group by, how many entries were skipped, and the add/nothing-to-import results -
// an operator decides which of their own lists to bring over by reading exactly these. The payload
// stood 18 B under the previous figure.
//
// Raised by 200 B for Hysteria2 through a Realm (competitor gap 15; sing-box 1.14 carries it). The
// form is in the route-scoped page-connections.js; the dictionaries grew by its two field labels
// (+69 B gzip in ru) - the realm address and its STUN servers, which an operator types - and app.js by
// the card line that shows a realm connection's rendezvous host instead of ":0" (+120 B gzip, the
// measured delta of one line and its comment). The payload stood 84 B under the previous figure.
//
// Raised by 600 B for the core override (competitor gap 11: nikki's profile mixin). Settings is in
// app.js, which grew by the textarea, its save field and its settings-index entry (+300 B gzip), and
// the dictionaries by two strings (+225 B gzip in ru): the label, and the hint that says how the
// patch is applied - merge, null deletes, arrays replace, "prepend" goes first - which an operator
// needs before typing JSON the daemon will refuse otherwise. The payload stood 21 B under the
// previous figure.
//
// Raised by 300 B for an SSH server as an exit (competitor gap 16: HomeProxy's ssh node, mihomo's ssh
// outbound). The form is in the route-scoped page-connections.js; app.js grew by the protocol's entry
// and the card line that reads user@host (+86 B gzip), and the dictionaries by four strings and the
// supported-formats line naming SSH (+189 B gzip in ru): the key passphrase, the host keys and the
// client version an operator types, and the hint that an exit with no host key accepts any server -
// the one thing about this connection they must read before trusting it. The payload stood 15 B under
// the previous figure, and stood 40 B under this one.
//
// Raised by 100 B more in the same change: the review found nothing told an operator that the SSH exit
// carries TCP only (sing-box's ssh outbound registers no UDP), so calls, games and DNS over UDP routed
// to it just fail. The form hint now opens with "TCP only, no UDP (calls, games)" in all ten
// dictionaries: +41 B gzip in ru, measured, after cutting the wording to that from a longer one (+51 B).
// The payload stands 99 B under this figure.
//
// Raised by 400 B for the Telegram bridge's panel (competitor gap 13, slice b). Its card body and its
// dialog are in the route-scoped page-telegram.js, and the Components row in page-updater.js; app.js
// grew by the card's frame only (+122 B gzip: the title and the one-line hint, which Settings search
// has to see when the page renders). The dictionaries grew by eight strings (+348 B gzip in ru): the
// title and that hint, the pointer to the Components page where the binary is installed, the two
// Cloudflare field labels and the sentence saying they are only for when Telegram's web domains are
// blocked too, "New secret", and its confirmation - that every device using the bridge then needs
// the new link, which an operator has to understand before breaking every phone's Telegram. The
// daemon's reasons (the demo, why it exited) are shown as sent, and a crash loop reuses the Dashboard's
// "Crash-loop". Measured 267675 B, 25 B under this figure; the strings were cut from a longer first
// wording (+386 B) to fit. The Components row's role hint "router service" then added 14 B gzip in
// ru, measured: 267689 B, 11 B under, so the figure stands.
//
// Raised by 250 B for the DNS page's leak verdict (QA-107). page-dns.js is route-scoped, so app.js
// did not grow; the dictionaries did by two strings and one rewording (+234 B gzip in ru, measured):
// the :53 stage saying the redirect is IPv4 only, the warning that a LAN with IPv6 bypasses every row
// because the redirect and refusals are IPv4 only, and the "✓" line, which claimed clients could not
// route around the router and now says DoH to a resolver outside the refused list still gets through.
// Measured 267923 B, 27 B under this figure. The warning then named the routes IPv6 leaves open (the
// names are port and protocol labels, left untranslated) in a shorter sentence, and renderDNS passes
// the TUN reading to the query path: +1 B, measured 267924 B, 26 B under, so the figure stands.
//
// Raised by 53 B for the Routing page's Matched column (QA-113). The kernel's counters were served as
// the core's connection count, so 52,341 packets read "52341 conns" and fell to "1 conn" once the
// core saw one. They now have their own field, which the cell shows only where the core counted
// nothing, under a unit of their own with the note Diagnostics already had ("packets since the rules
// were installed"). Measured: app.js +45 B gzip (the cell's choice and that note; its comment was cut
// to fit) and one string, "pkts", +8 B in ru. 267742 B, 11 B under this figure, as before the change.
//
// Raised by 135 B in that change's review. A feed line refused as too broad (QA-111) was counted in
// the Refresh-sources toast as "1 failed"; the refresh now answers it apart and the toast names the
// list and the line: app.js +30 B, its helper going to the route chunk page-routing.js, and one new
// string. The Matched column's header still said "Connections" over the kernel's packets; its
// tooltip now says what the column shows instead: app.js +18 B. Both strings, +87 B in ru, the
// first cut from a longer wording (-9 B) to fit. 267877 B, 11 B under this figure, as before.
//
// Both raises land together on this branch (the DNS one first): measured 268109 B with both, so the
// figure is the DNS one plus the two Routing raises (+185), keeping that change's 26 B of headroom.
//
// Raised by 175 B for Encrypted Client Hello on TLS connections (competitor gap 17: Xray/v2rayN's
// ech=, mihomo's ech-opts). The form is in the route-scoped page-connections.js and app.js did not
// change; what the first visit pays is five new strings in the one dictionary it loads (+175 B gzip in
// ru, the largest, measured: 68549 -> 68724 B): the two ECH modes an operator picks between, the
// config and query-name fields they paste into, and the hint that a config looked up in DNS fails the
// connection when the router's DNS has no answer. An empty pasted config reuses "required". The raise
// is exactly that growth, so the headroom stays the 95 B it was.
//
// Raised by 153 B more in the same change, after its review (measured in ru: 68724 -> 68877 B). The DNS
// hint said "at each connection" and nothing of privacy; it now says the record is kept for its TTL
// and that over plain DNS the name ECH hides goes out in the clear (+89 B). And a Reality link's ECH
// config, kept switched off, was said on every Apply with nothing to do about it; the connection form
// now says it once under Reality instead (+64 B). The ECH change as a whole adds 328 B to the payload
// (68549 -> 68877 B in ru); the headroom stays 95 B.
//
// ECH lands on this branch after the feeds and DNS raises: measured 268428 B with all of them (the
// ECH strings add 319 B gzip here), so the figure carries the 26 B of headroom the previous one had.
//
// Raised by 160 B for the subscription HWID (competitor gap 25: Remnawave's device limit answers 404
// to a fetch without x-hwid; tachyon sends one). The field is in the route-scoped page-connections.js
// and app.js did not change; the dictionaries grew by three strings (+160 B gzip in ru, measured:
// 69551 -> 69711 B): the Generated and Custom modes ("Off" is reused), and the hint saying why the
// field exists (the 404) and why a generated ID must not change (a new one takes another device
// slot). Measured 268588 B, so the figure keeps the 26 B of headroom.
//
// Raised by 354 B for multiplex (competitor gap 21: sing-mux on VLESS, VMess, Trojan and Shadowsocks).
// The section is in the route-scoped page-connections.js and app.js did not change; the dictionaries
// grew by ten strings (+354 B gzip in ru, measured: 69711 -> 70065 B): the section title, the four
// pool and padding labels, the two TCP Brutal rates, and the three hints an operator needs before
// switching it on (a sing-box server needs multiplex on in its inbound, and Xray drops every
// connection; Vision does not reach the multiplexed streams; Brutal needs the server's kernel
// module). The accessible names "Multiplex Protocol" and "Multiplex Enabled" are built from strings
// already there. Measured 268942 B, so the figure keeps the 26 B of headroom.
//
// Raised by 60 B for AmneziaWG before KeeneticOS 4.2 (QA-133): the connection form now offers it on
// WayHop's engine where the router's own cannot create it. The decision and the note are in the
// route-scoped page-connections.js and app.js did not change; the dictionaries grew by two strings
// (+60 B gzip in ru, measured: 69711 -> 69771 B, after cutting the first from a longer wording):
// that the connection runs on WayHop's engine and not the router's, and that amneziawg-go is still
// to be installed on the Components page - without them an operator would save a connection that
// cannot come up and not know why. The daemon's reason is shown as sent. Measured 268648 B, so the
// figure keeps the 26 B of headroom.
//
// Raised by 154 B for the AmneziaWG hint where the router's own creates the connection (QA-133
// review): "Supported natively ... can roll this connection back" was also shown for a connection
// whose AmneziaWG 2 settings (KeeneticOS 4.2 to 5.0) or amneziawg-go choice put it on WayHop's engine.
// One string replaces it for AmneziaWG, saying when the engine runs it and where to see which; the
// form cannot know before the planner has the settings. Measured in ru: 69771 -> 69925 B, total
// 268802 B, so the figure keeps the 26 B of headroom.
//
// QA-133 lands after multiplex: measured 269154 B with both (QA-133's two strings add 212 B gzip
// here), so the figure keeps the 26 B of headroom.
//
// Raised by 204 B for QUIC tuning on Hysteria2 and TUIC (competitor gap 20; sing-box 1.14's
// initial_packet_size and disable_path_mtu_discovery). The fields are in the route-scoped
// page-connections.js and app.js did not change; the dictionaries grew by four strings (+204 B gzip,
// measured: 269154 -> 269358 B, all of it ru): the two labels, the hint saying when to use them
// (PPPoE, LTE or a VPN inside a VPN, where large QUIC packets vanish) and that they need sing-box
// 1.14, and the Hysteria2 note that Chrome's handshake replaces the size unless its fingerprint is
// off - without it an operator would set a size that does nothing. A size out of range is refused
// with a language-neutral "1200–1452". The figure keeps the 26 B of headroom.
//
// Raised by 273 B for DNS servers that ask the resolvers an OpenVPN or OpenConnect connection pushes
// (competitor gap 22; sing-box 1.14's openvpn and openconnect DNS server types). The form is in the
// route-scoped page-dns.js and app.js did not change; the dictionaries grew by three strings (+273 B
// gzip, measured: 269358 -> 269631 B, all of it ru): the two switches (answer names outside the VPN's
// domains; complete short names with its search domains) and the hint saying the resolvers answer
// only through the tunnel while it is up, that a VPN pushing servers but no domains needs the first
// switch - without it every lookup there gets NXDOMAIN - and that it needs sing-box 1.14. The type
// names are untranslated technical labels like the other DNS types, and "Connection" was already
// translated. The figure keeps the 26 B of headroom.
const BUDGET = 266 * 1000 + 3657;

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
