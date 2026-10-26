// page-diagnostics.js — route-scoped chunk for the diagnostics page.
//
// Loaded by loadChunk() the first time that route is opened, NOT from index.html, so its bytes
// stay out of the initial payload the perf budget measures. A classic script, like app.js: these
// declarations become globals and app.js has already defined el/t/api/state by the time this runs.
//
// Everything here is reachable ONLY from this page's renderer — attributed by walking the call
// graph from every render* entry point, counting an identifier anywhere in a body (strings
// included) as a reference, so the shared set is over-estimated and this set is not.
//
// The battery itself lives here: the client-side checks, the report builder and renderDiagnostics
// moved out of app.js when the initial payload ran out of room. PAGES.diagnostics therefore binds
// its renderer lazily — the name resolves when the route is opened, not when app.js is parsed.

// CHECKS maps an id to its client-side thunk. time/ipv6/dns/offload/pbr_kernel are NOT
// here — they fold in from the backend /api/healthcheck call (see HC_BACKEND). This
// single map drives BOTH the full battery run and a single-row re-check.
const CHECKS = { core: chkCore, internet: chkInternet, tunnels: chkTunnels, censored: chkCensored, exit: chkExit, system: chkSystem, log: chkLog };
const HC_BACKEND = ["time", "ipv6", "dns", "offload", "pbr_kernel", "endpoint_reach"];

// nativeSupportCard — read-only "what can this router carry natively?" card for
// the Diagnostics page. Fetches GET /api/native/capabilities and renders one pill
// per protocol: NATIVE (kernel/firmware, ok), "install: <pkg>" (native possible,
// warn) for installable entries, or muted "via sing-box" for the sing-box-only set.
// Purely informational — no routing change. The card self-loads after mount so a
// slow/absent endpoint never blocks the rest of the page.
function nativeSupportCard() {
  const card = el("div", { class: "card", id: "natcap" });
  card.appendChild(el("div", { id: "natcap-body" },
    el("div", { class: "card-title", style: "margin-bottom:var(--sp-2)" }, t("Native support")),
    el("div", { class: "hint" }, t("Loading…"))));
  loadNativeCaps(); // fire-and-forget; paints into #natcap-body when it settles
  return card;
}







// recheckOne re-runs a single check after the user fixes something — no need to
// re-run the whole battery on a CPU-light router. Reuses the exact same thunk /
// backend path and writes back through the same results+paint cycle, guarded by
// the run's abort token so a concurrent full re-run can't be clobbered.
async function recheckOne(id) {
  const h = state.hbat; if (!h || h.running) return;
  const abort = h.abort;
  (h.busy = h.busy || {})[id] = true; paintBattery();
  const settle = (r) => { if (state.hbat && state.hbat.abort === abort) { state.hbat.results[id] = r; if (state.hbat.busy) delete state.hbat.busy[id]; paintBattery(); } };
  try {
    if (CHECKS[id]) { settle(await withHealthCheckDeadline(CHECKS[id])); }
    else { const d = await withHealthCheckDeadline(() => api.get("/api/healthcheck")); const c = (d.checks || []).find(x => x.id === id); settle(c ? { status: c.status, summary: c.summary, detail: c.detail, fix: c.fix } : { status: "na", summary: t("this router does not report that check") }); }
  } catch (e) { settle({ status: "warn", summary: t("check failed"), detail: e.message }); }
}

// A remote target can accept TCP and then never finish the probe. Without a deadline one such
// target leaves Run all disabled forever and makes a completed page look dead. The server-side
// probes have their own shorter bounds; this is the UI's last-resort terminal state. Promise.race
// cannot cancel the older API helpers, but it does attach their rejection handler and lets the
// operator retry instead of stranding the battery.
const HEALTH_CHECK_TIMEOUT_MS = 60000;
function withHealthCheckDeadline(fn, timeoutMs) {
  const ms = timeoutMs || HEALTH_CHECK_TIMEOUT_MS;
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error("health check timed out after " + Math.round(ms / 1000) + "s")), ms);
  });
  return Promise.race([Promise.resolve().then(fn), timeout]).finally(() => clearTimeout(timer));
}

// runPool runs thunks with bounded concurrency so the router CPU isn't hammered.
async function runPool(thunks, n) {
  const q = thunks.slice();
  await Promise.all(Array.from({ length: Math.min(n, q.length) }, async () => { while (q.length) await q.shift()(); }));
}





async function chkCore() {
  const w = await api.get("/api/watchdog");
  const h = state.health || {}, sb = h.singbox || {};
  // sing-box is the supplementary PROXY engine (VLESS/Trojan/Hy2/… family), not the main VPN — the
  // native kernel tunnels carry the rest. sb.running already includes a Clash-API probe, so an
  // init-managed core WayHop didn't spawn (its process handle nil ⇒ w.alive false) still reads UP
  // instead of a false "down". A native-only profile needs no proxy engine at all.
  const running = w.alive || sb.running;
  const d = "restarts " + (w.restarts || 0) + (w.last_restart ? " · last " + new Date(w.last_restart).toLocaleString("en-GB") : "") + (w.last_error ? "\nlast error: " + w.last_error : "");
  if (isNativeOnly(h)) return { status: "pass", summary: t("not required"), detail: t("Native-only mode — sing-box not required") };
  if (running) return { status: w.restarts ? "warn" : "pass", summary: w.restarts ? t("running (crashed {0}× since boot)", w.restarts) : t("sing-box running"), detail: d, fix: w.restarts ? t("The core has crash-restarted — check Log analysis below for the cause.") : "" };
  if (!sb.available) return { status: "warn", summary: t("sing-box absent"), detail: d };
  if (!w.supervised) return { status: "warn", summary: t("not started (WAN-only)"), detail: d };
  return { status: "fail", summary: t("down — auto-restarting"), detail: d, fix: t("The VPN core stopped and is restarting itself. If it keeps crashing, check Log analysis below for the error.") };
}
async function chkInternet() {
  const r = await api.post("/api/netdiag/all", { target: "cloudflare.com" });
  const rows = r.results || [], wan = rows.find(x => x.egress === "direct"), tun = rows.filter(x => x.egress !== "direct");
  const up = tun.filter(x => x.reachable).length;
  const d = rows.map(x => (x.reachable ? "✓ " : "✗ ") + (x.name || x.egress) + (x.reachable ? " · " + x.latency_ms + " ms" : " · " + (x.err || "unreachable"))).join("\n");
  if (!wan) return { status: "na", summary: t("no probe came back, so nothing was tested"), detail: d };
  if (!wan.reachable) return { status: "fail", summary: t("no internet on the router"), detail: d, fix: t("The router itself can't reach the internet. Check the cable/modem and your ISP — this isn't a VPN problem.") };
  return { status: "pass", summary: t("online · WAN {0} ms · {1}/{2} tunnels reach out", wan.latency_ms, up, tun.length), detail: d };
}
async function chkTunnels() {
  const eps = await api.get("/api/health/endpoints");
  const tun = (eps || []).filter(e => e.kind !== "group");
  if (!tun.length) return { status: "na", summary: t("no tunnels configured — nothing to check") };
  const up = tun.filter(e => e.state === "alive"), down = tun.filter(e => e.state === "down");
  const d = tun.map(e => (e.state === "alive" ? "✓ " : e.state === "down" ? "✗ " : "… ") + (e.name || e.id) + (e.latency_ms ? " · " + e.latency_ms + " ms" : "") + (e.success_rate ? " · " + e.success_rate + "%" : "") + (e.cause ? " · " + e.cause : "")).join("\n");
  if (up.length === tun.length) return { status: "pass", summary: t("all {0} tunnels up", tun.length), detail: d };
  const fix = down.map(e => (e.name || e.id) + ": " + (e.cause_fix || e.cause || t("down"))).join("\n");
  if (up.length === 0) return { status: "fail", summary: t("all tunnels down"), detail: d, fix: fix || t("All tunnels are down — open Connections to toggle/restart them or check the servers."), deep: "connections" };
  return { status: "warn", summary: t("{0} of {1} tunnels up", up.length, tun.length), detail: d, fix, deep: "connections" };
}
async function chkExit() {
  const x = await api.get("/api/exit-ip");
  if (!x.available || !x.ip) return { status: "na", summary: t("no exit IP to report"), detail: t("No exit IP — sing-box may be off, or general traffic uses the WAN by design (split-tunnel).") };
  const flag = x.cc ? ccFlag(x.cc) + " " + (x.country || x.cc) : "";
  const asn = x.asn || x.isp || "";
  const summary = t("exit IP {0}", x.ip) + (flag ? " · " + flag : "") + (asn ? " · " + asn : "");
  let detail = t("Traffic exits from {0}", x.ip) + (x.cached ? " " + t("(cached)") : "");
  if (x.country || x.cc) detail += "\n" + t("Country: {0}", (x.country || "") + (x.cc ? " (" + x.cc + ")" : ""));
  if (x.asn) detail += "\n" + t("AS: {0}", x.asn);
  if (x.isp && x.isp !== x.asn) detail += "\n" + t("ISP: {0}", x.isp);
  if ("hosting" in x) detail += "\n" + t("Type: {0}", x.hosting ? t("Datacenter / hosting (expected for a VPN exit)") : t("Residential"));
  return { status: "pass", summary, detail, geo: { ip: x.ip, cc: x.cc, country: x.country, asn: x.asn, isp: x.isp } };
}
async function chkSystem() {
  const s = await api.get("/api/system");
  const meta = { version: s.version, arch: s.arch };
  if (!s.available) return { status: "na", summary: t("this host reports no resource figures"), meta };
  const sum = t("{0}% RAM · load {1} · up {2}", Math.round(s.mem_used_pct), (s.load1 != null ? s.load1.toFixed(2) : "–"), humanDur(s.uptime_s));
  const st = s.mem_used_pct >= 92 ? "warn" : "pass";
  return { status: st, summary: sum, detail: sum + "\n" + t("free RAM {0} of {1} MB", Math.round((s.mem_avail_kb || 0) / 1024), Math.round((s.mem_total_kb || 0) / 1024)), fix: st === "warn" ? t("RAM is nearly full — heavy connection load can drop packets. Reboot or reduce load.") : "", meta };
}
// chkCensored promotes the "is anything blocked" question into the one-click battery:
// it probes a couple of representative censored hosts through EVERY exit (the same
// non-disruptive Clash-delay path chkInternet uses — no live selector change) and
// reports whether a tunnel still carries them.
async function chkCensored() {
  const hosts = [["YouTube", "youtube.com"], ["Instagram", "instagram.com"]];
  const lines = [], bad = [];
  let anyData = false;
  for (const [label, host] of hosts) {
    let r;
    try { r = await api.post("/api/netdiag/all", { target: host }); } catch (e) { lines.push("✗ " + label + " · " + t("test failed: {0}", e.message)); continue; }
    anyData = true;
    const rows = r.results || [];
    const viaTun = rows.filter(x => x.egress !== "direct" && x.reachable);
    const wan = rows.find(x => x.egress === "direct");
    if (viaTun.length) lines.push("✓ " + label + " · " + tn("via {0} tunnel ({1})|via {0} tunnels ({1})", viaTun.length, viaTun.map(x => x.name || x.egress).join(", ")));
    else if (wan && wan.reachable) { lines.push("● " + label + " · " + t("only on WAN — no tunnel reached it")); bad.push(label + ": " + t("no tunnel reached it")); }
    else { lines.push("✗ " + label + " · " + t("unreachable everywhere")); bad.push(label + ": " + t("unreachable (DPI/dead?)")); }
  }
  const detail = lines.join("\n");
  if (!anyData) return { status: "na", summary: t("no exit answered, so nothing was tested"), detail };
  if (bad.length) return { status: "warn", summary: t("{0} of {1} not reachable via a tunnel", bad.length, hosts.length), detail, fix: bad.join("\n") + "\n" + t("Open Connections to check the tunnels, or Routing to confirm the carve-outs."), deep: "connections" };
  return { status: "pass", summary: t("blocked sites reachable through tunnels"), detail };
}
async function chkLog() {
  const d = await api.get("/api/diagnostics");
  const n = (d.found || []).length;
  if (!n && !d.count) return {
    // No log to read is not a finding. It said "not verified" and coloured itself amber anyway,
    // which put "there is nothing to look at" on the list of things to look at.
    status: "na",
    label: t("Engine log check"),
    summary: t("no engine log to read — nothing was analysed"),
  };
  if (!n) return { status: "pass", summary: t("no known errors in {0} log lines", d.count) };
  // Signatures and events are different numbers. The row used to print the signature count as
  // "known issues", so one url-test timeout that matched two patterns read as two incidents. The
  // daemon now reports both; say how many log lines were explained, and by how many distinct causes.
  const ev = typeof d.events === "number" ? d.events : n;
  return {
    status: "warn",
    summary: ev === n
      ? tn("sing-box logged {0} known issue|sing-box logged {0} known issues", n)
      : t("Log lines scanned: {0} · known issues: {1}", ev, n),
    kb: d.found,
  };
}

function humanDur(sec) { sec = +sec || 0; const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60); return d ? d + "d " + h + "h" : h ? h + "h " + m + "m" : m + "m"; }
// ccFlag turns a 2-letter ISO country code into its regional-indicator emoji flag.
function ccFlag(cc) { if (!cc || !/^[A-Za-z]{2}$/.test(cc)) return ""; cc = cc.toUpperCase(); return String.fromCodePoint(...[...cc].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)); }

// buildReport renders the battery into a self-contained Markdown report for pasting
// into a support chat or an issue: a header (build, exit, timestamp), the verdict, every
// row's status, then the non-pass details. With mask=true (default) public IPs, WG
// keys and tokens are scrubbed first — the report carries the exit IP + ASN now.
function buildReport(h, mask) {
  // Same set the page renders, for the same reason: a report that omits the failing check is a
  // support ticket that sends the reader after the wrong thing. Seven of thirteen rows were
  // missing from this on the operator's own router, including a live dns-bypass warning.
  const res = h.results, done = hcIds(res).filter(id => res[id]);
  // The verdict is over checks that RAN. A report headed "PASS" whose rows are mostly "did not
  // run" sends the reader past the gap instead of at it, so the header states it as a number.
  const ranIDs = done.filter(id => res[id].status !== "na");
  const worst = ranIDs.map(id => res[id]).reduce((a, r) => r.status === "fail" ? "fail" : (r.status === "warn" && a !== "fail") ? "warn" : a, "pass");
  const sys = (res.system && res.system.meta) || {}, exit = (res.exit && res.exit.geo) || {};
  let out = "## WayHop diagnostics\n";
  out += "- time: " + new Date(h.ranAt).toISOString() + "\n";
  if (sys.version) out += "- build: " + sys.version + (sys.arch ? " (" + sys.arch + ")" : "") + "\n";
  if (exit.ip) out += "- exit: " + exit.ip + (exit.cc ? " " + exit.cc : "") + (exit.asn ? " · " + exit.asn : "") + "\n";
  out += "\n### Verdict: " + (ranIDs.length ? worst.toUpperCase() : "NOT CHECKED")
    + " (" + ranIDs.length + " checked"
    + (done.length - ranIDs.length ? ", " + (done.length - ranIDs.length) + " not checked here" : "")
    + ")\n";
  done.forEach(id => out += "- [" + res[id].status.toUpperCase() + "] " + hcLabel(id, res[id]) + " — " + (res[id].summary || "") + "\n");
  const det = done.filter(id => res[id].status !== "pass" && res[id].status !== "na" && (res[id].detail || res[id].fix));
  if (det.length) { out += "\n### Details\n"; det.forEach(id => { const r = res[id]; out += "\n**" + hcLabel(id, r) + "** (" + r.status + ")\n"; if (r.fix) out += "Fix: " + r.fix + "\n"; if (r.detail) out += "```\n" + r.detail + "\n```\n"; }); }
  return mask ? scrubText(out) : out;
}
// scrubText masks secrets + public IPs so a copied report is safe to share. Private /
// LAN addresses (10/8, 192.168/16, 172.16-31, 127/8, 0.x) are kept — they aren't
// sensitive and help debugging. Mirrors the publish/ scrub discipline.
function scrubText(s) {
  return String(s)
    .replace(/\b[A-Za-z0-9+/]{43}=/g, "[key]")
    .replace(/\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g, "[uuid]")
    // A MAC is six hex pairs joined by colons, which the full-form IPv6 pattern below also matches:
    // aa:bb:cc:dd:ee:ff came out of here as "[ipv6]". The value was hidden either way, so this was
    // never a leak - it is a report that tells its reader the wrong thing about what was removed, on
    // the one page whose whole job is handing someone else an accurate picture. Named before the
    // IPv6 rules so the more specific shape wins.
    .replace(/\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b/g, "[mac]")
    .replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, (m, a, b, c, d) => isPrivIP(+a, +b) ? m : a + ".x.x." + d)
    // Compressed (::) IPv6 FIRST — else a public exit like 2606:4700::1111 slips through the
    // full-form pattern below (which needs 4+ explicit hextet groups) and leaks despite masking.
    .replace(/(?:[0-9a-fA-F]{1,4}:)+:[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{1,4})*/g, "[ipv6]")
    .replace(/\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{0,4}\b/g, "[ipv6]");
}

// egressSelect lists the exits a reachability test can use: WAN (direct) + every
// enabled tunnel + group. The value is the sing-box outbound tag (endpoint/group
// ID, or "direct").
function egressSelect(selected) {
  const sel = el("select", { class: "rl-sel" });
  const add = (v, t) => sel.appendChild(el("option", { value: v }, t));
  add("direct", "WAN (direct)");
  const prof = state.profile || {};
  (prof.endpoints || []).filter(e => e.enabled).forEach(e => add(e.id, e.name || e.id));
  (prof.groups || []).forEach(g => add(g.id, "▣ " + g.name));
  if (selected) sel.value = selected;
  return sel;
}

// Preset reachability targets (bare hosts: pingable on WAN, GET https://host through a tunnel).
const NETDIAG_PRESETS = [
  { cat: "Connectivity", items: [["Cloudflare", "cloudflare.com"], ["Google", "google.com"], ["Apple", "apple.com"]] },
  { cat: "Commonly blocked", items: [["Instagram", "instagram.com"], ["X", "x.com"], ["YouTube", "youtube.com"], ["Facebook", "facebook.com"], ["Telegram", "web.telegram.org"]] },
  { cat: "DNS / IP", items: [["1.1.1.1", "1.1.1.1"], ["8.8.8.8", "8.8.8.8"], ["9.9.9.9", "9.9.9.9"]] },
  { cat: "Streaming / geo", items: [["Netflix", "netflix.com"], ["ChatGPT", "chat.openai.com"], ["Spotify", "spotify.com"]] },
];

// The currently-mounted diagnostic output container (diagWrap) and its live lines
// node (diagOut). Module-level so a stream started before navigating away can
// re-attach to a freshly-rendered Diagnostics page — it writes through these
// refs, which renderDiagOutput updates on every (re-)render. null when unmounted.
let diagWrap = null, diagOut = null;

/* groupPageCards splits a page's cards into labelled groups, in a stated order.
 *
 * Unlike the Settings navigator this hides nothing. Diagnostics is a toolbox: putting half the
 * tools behind a tab would add a click to the page's primary job. What it was missing was the
 * distinction between "this runs something" and "this reports what the device already knows",
 * which a heading gives without costing navigation.
 *
 * Cards carry data-group; anything unclassified is appended afterwards rather than dropped.
 */
function groupPageCards(view, groups) {
  const cards = [...view.querySelectorAll(':scope > [data-group]')];
  if (!cards.length) return;
  const by = new Map();
  cards.forEach(c => {
    const k = c.getAttribute('data-group');
    if (!by.has(k)) by.set(k, []);
    by.get(k).push(c);
    c.remove();
  });
  const emit = (list) => list.forEach(c => view.appendChild(c));
  groups.forEach(g => {
    const list = by.get(g.key);
    if (!list || !list.length) return;
    view.appendChild(el('div', { class: 'page-group' },
      el('div', { class: 'page-group-title' }, g.title),
      g.hint ? el('div', { class: 'page-group-hint' }, g.hint) : null));
    emit(list);
    by.delete(g.key);
  });
  by.forEach(emit);
}


// diagFilterBox narrows the page to what you are actually chasing.
//
// Diagnostics opens at ten cards — the battery, the recorder, native support, per-device reach, and
// the tools behind their disclosure — which is two screens before a single check has run. Someone
// arrives here with a question ("is DNS leaking?", "which exit is down?") and pays for the other
// nine cards to find the one that answers it. Measured at 1670px / 2 screens with no way to shorten
// it, which is what the density gate refuses.
//
// It filters at two levels because the page has two kinds of content. The health battery is a LIST,
// so a query narrows it row by row: typing "dns" leaves the DNS checks and drops the rest, which is
// the reason to type at all. Every other card is a unit, so it either matches or goes. Headings and
// the tools disclosure follow their contents rather than deciding for themselves — a heading with
// nothing under it is a lie about what is on screen.
function diagFilterBox(view) {
  const label = t("Filter diagnostics — check, tool or report");
  const inp = el("input", { type: "search", placeholder: label, "aria-label": label });
  const apply = () => {
    const q = inp.value.trim().toLowerCase();
    view.querySelectorAll(".card").forEach(card => {
      const rows = [...card.querySelectorAll(".health-row")];
      if (!q) {
        card.hidden = false;
        rows.forEach(r => { r.hidden = false; });
        return;
      }
      if (rows.length) {
        // Match the card's own name too, so a query for the battery itself ("working", from "Is
        // everything working?") keeps it whole instead of emptying it row by row.
        const title = ((card.querySelector(".card-title") || {}).textContent || "").toLowerCase();
        let shown = 0;
        rows.forEach(r => {
          const hit = title.includes(q) || (r.textContent || "").toLowerCase().includes(q);
          r.hidden = !hit;
          if (hit) shown++;
        });
        card.hidden = shown === 0;
        return;
      }
      card.hidden = !(card.textContent || "").toLowerCase().includes(q);
    });
    // A group heading stands for the cards after it, up to the next heading: it survives exactly as
    // long as one of them does.
    view.querySelectorAll(".page-group").forEach(head => {
      let alive = false;
      for (let n = head.nextElementSibling; n && !n.classList.contains("page-group"); n = n.nextElementSibling) {
        if (n.classList.contains("card") && !n.hidden) { alive = true; break; }
      }
      head.hidden = !!q && !alive;
    });
    const adv = view.querySelector(".diag-adv");
    if (adv) adv.hidden = !!q && ![...adv.querySelectorAll(".card")].some(c => !c.hidden);
  };
  inp.addEventListener("input", apply);
  return el("div", { class: "field diag-filter" }, inp);
}

async function renderDiagnostics(view) {
  view.appendChild(el("div", { class: "block-head" },
    el("div", {},
      el("div", { class: "desc" }, "Confirm everything is working, test reachability through each exit, and analyze engine logs for known errors."))));
  view.appendChild(diagFilterBox(view));
  try { await loadProfile(); } catch (_) {} // ensure the egress dropdown lists current tunnels

  // One input in front, the specific tools behind a disclosure. The tools are unchanged and none of
  // them moved out of reach — they are simply no longer the first thing you have to choose between.
  // What the router is doing comes BEFORE the tools that ask it questions: most visits end here.
  view.appendChild(diagNowCard());
  view.appendChild(askCard());
  view.appendChild(flightRecorderCard());

  const battery = healthBatteryCard(); // one-click "Run all checks" battery + verdict + copy report
  battery.setAttribute("data-group", "tools");
  view.appendChild(battery);
  if (state.hbat) paintBattery();        // restore a prior run across tab nav

  // Everything below is built into this container and disclosed together at the end.
  const tools = el("div", { class: "diag-tools" });
  const nativeCard = nativeSupportCard(); // read-only: what this router can carry natively
  nativeCard.setAttribute("data-group", "reports");
  view.appendChild(nativeCard);

  // Throughput: on-demand speedtest through the active proxy (moved off the dashboard). Globals
  // (speedResults / pinSpeed / runSpeedtest) are module-level, so the persisted result restores here.
  {
    const stResult = el("span", { class: "hint", style: "margin-left:12px" });
    pinSpeed(stResult, "__global");
    const stBtn = el("button", { class: "btn btn-sm" }, "Speedtest");
    stBtn.addEventListener("click", () => runSpeedtest(stBtn, stResult));
    tools.appendChild(el("div", { class: "card" },
      el("div", { class: "row-between", style: "align-items:center" },
        // The path is stated by the RESULT, which prints the server's own `via` — "direct" or
        // "proxy" — and the server derives it from what actually happened (singbox.Running()), not
        // from the request. The title used to promise "through active proxy" unconditionally, so on
        // a router with no core running it claimed one path while its own numbers, on the same line,
        // were annotated "(direct)". Measured on the demo: "Throughput (through active proxy)
        // ↓ 772.26 Mbps ↑ 319.43 Mbps · 227 ms (direct)".
        el("div", { class: "hint" }, t("Throughput")),
        el("div", { style: "display:flex;align-items:center" }, stResult, stBtn))));
  }

  // Network tools — egress-aware ping/traceroute/DNS (streamed live) + reachability.
  // Results live in state.diag so they survive tab navigation; a running stream
  // keeps filling in even while you're on another page and re-attaches on return.
  const egress = egressSelect((state.diag && state.diag.egress) || "direct");
  const target = el("input", { type: "text", value: (state.diag && state.diag.target) || "", placeholder: "host, IP or URL — e.g. youtube.com, 1.1.1.1, https://chat.openai.com" });
  const ndOut = el("div", { style: "margin-top:14px" });
  // Hero action: test the target across every exit at once — the universal answer.
  const testAll = el("button", { class: "btn btn-primary", onclick: () => runDiagAll(target.value, ndOut) }, "Test all exits");
  const btnRow = el("div", { style: "margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;align-items:center" });
  // An interface-backed egress (an external endpoint bound to a kernel iface like
  // awg0/awg1) can run real ICMP through that link, so it gets ping/traceroute too —
  // only a proxy outbound (vless/etc.) or group is restricted to HTTP reachability.
  // A group is not a proxy. Measured on a live Keenetic: selecting "Primary group" swapped
  // Ping / Traceroute / Resolve for a single "Reachability" under the words "ICMP can't traverse a
  // proxy" - false about that group, whose five members are all native tunnels, and it withheld two
  // tools that work through the member the group has actually elected (nwg3 at the time). The
  // election is READ from foElected, the same helper the Failover page draws "#1 current" with, so
  // this can never disagree with what the operator is shown one page over.
  const ifaceOfEndpoint = (id) => {
    const ep = findEndpoint(id);
    return (ep && ep.engine === "external" && ep.params && ep.params.interface) || "";
  };
  const diagIface = () => {
    const direct = ifaceOfEndpoint(egress.value);
    if (direct) return direct;
    const g = (state.profile.groups || []).find(x => x.id === egress.value);
    return g ? ifaceOfEndpoint(foElected(g)) : "";
  };
  function diagButtons() {
    btnRow.innerHTML = "";
    const iface = diagIface();
    const proxy = egress.value && egress.value !== "direct" && !iface;
    if (proxy) {
      btnRow.appendChild(el("button", { class: "btn btn-primary btn-sm", onclick: () => runDiagReach(target.value, egress.value, ndOut) }, "Reachability"));
      btnRow.appendChild(el("span", { class: "hint" }, "ICMP can't traverse a proxy — this GETs the target through it."));
    } else {
      [["Ping", "ping"], ["Traceroute", "traceroute"], ["Resolve (DNS)", "dns"], ["Full", "all"]].forEach(([lbl, tool]) =>
        btnRow.appendChild(el("button", { class: "btn btn-sm" + (tool === "all" ? " btn-primary" : ""), onclick: () => runDiagStream(tool, target.value, egress.value, ndOut) }, lbl)));
      if (iface) btnRow.appendChild(el("span", { class: "hint" }, t("↳ bound to {0}", iface)));
    }
  }
  egress.onchange = diagButtons;
  diagButtons();
  target.addEventListener("keydown", e => { if (e.key === "Enter") runDiagAll(target.value, ndOut); });
  const advanced = el("details", { class: "nd-advanced", style: "margin-top:14px" },
    // "one exit" is true of three of the four. The DNS lookup resolves through the router's own
    // resolver whatever is selected here — see the note the stream emits — and listing it beside
    // the tools that DO take the exit is what made the operator read its answer as coming from a
    // tunnel it never touched.
    el("summary", { style: "cursor:pointer;color:var(--ink-2);font-size:13px;user-select:none" }, "Advanced — one tool, one exit (ping · traceroute · reachability; DNS answers from the router's own resolver)"),
    el("div", { class: "field", style: "margin:12px 0 0;max-width:260px" }, el("label", {}, "Egress"), egress),
    btnRow);
  tools.appendChild(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, "Network tools"),
    el("div", { class: "hint", style: "margin-bottom:12px" }, "Type a host, IP or URL and test whether it's reachable through every exit at once — WAN, each tunnel, and your routing groups."),
    el("div", { style: "display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap" },
      el("div", { class: "field", style: "margin:0;flex:1;min-width:240px" }, el("label", {}, "Target"), target),
      testAll),
    advanced, ndOut));
  if (state.diag) renderDiagOutput(ndOut); // restore a prior / in-flight result

  // "Where does a domain go?" — surfaces the /api/diagnostics/trace explainer (already in the
  // daemon, previously UI-less): resolve the domain, then show the LIVE connections to its IPs and
  // the exit each actually took (ground truth from the connection table — it can't lie about the
  // real exit), plus the configured rules/lists/kernel-zones that reference it. Read-only.
  const traceIn = el("input", { type: "text", placeholder: t("domain — e.g. youtube.com, chatgpt.com") });
  const traceOut = el("div", { style: "margin-top:12px" });
  async function runTrace() {
    const d = (traceIn.value || "").trim();
    if (!d) return;
    traceOut.innerHTML = ""; traceOut.appendChild(el("div", { class: "hint" }, t("tracing…")));
    try {
      const r = await api.get("/api/diagnostics/trace?domain=" + encodeURIComponent(d));
      traceOut.innerHTML = ""; renderTraceResult(traceOut, r);
    } catch (e) { traceOut.innerHTML = ""; traceOut.appendChild(el("div", { class: "hint", style: "color:var(--err)" }, e.message)); }
  }
  traceIn.addEventListener("keydown", e => { if (e.key === "Enter") runTrace(); });
  tools.appendChild(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, t("Where does a domain go?")),
    el("div", { class: "hint", style: "margin-bottom:12px" }, t("Resolve a domain and see the live connections to it and which exit each actually took, plus the configured rules and lists that match it.")),
    el("div", { style: "display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap" },
      el("div", { class: "field", style: "margin:0;flex:1;min-width:240px" }, el("label", {}, t("Domain")), traceIn),
      el("button", { class: "btn btn-primary", onclick: runTrace }, t("Trace"))),
    traceOut));

  // "What each device is reaching" — surfaces GET /api/clients/destinations (already in the daemon,
  // previously UI-less): per LAN client, the external services it recently contacted + the exit each
  // took. Read-only visibility (the foundation for "add this as a routing rule"). Load-on-demand (a
  // full conntrack scan), like Log analysis's Load button.
  const destOut = el("div", { style: "margin-top:12px" });
  async function scanDests() {
    destOut.innerHTML = ""; destOut.appendChild(el("div", { class: "hint" }, t("scanning…")));
    try {
      const r = await api.get("/api/clients/destinations");
      destOut.innerHTML = ""; renderClientDests(destOut, r);
    } catch (e) { destOut.innerHTML = ""; destOut.appendChild(el("div", { class: "hint", style: "color:var(--err)" }, e.message)); }
  }
  view.appendChild(el("div", { class: "card", "data-group": "reports" },
    el("div", { class: "row-between", style: "margin-bottom:8px" },
      el("div", { class: "card-title" }, t("What each device is reaching")),
      el("button", { class: "btn btn-sm", onclick: scanDests }, t("Scan"))),
    el("div", { class: "hint", style: "margin-bottom:4px" },
      t("Per device on your network: the external services it recently contacted and which exit each took (WAN or a tunnel).")),
    destOut));

  // Log analysis — paste a log (or load sing-box's) -> known-error cards.
  const ta = el("textarea", { placeholder: "Paste engine log lines (sing-box / Xray / WireGuard…) to find known errors.", style: "min-height:110px;font-family:ui-monospace,Consolas,monospace;font-size:12px" });
  const logOut = el("div", { style: "margin-top:12px" });
  async function analyze(live) {
    logOut.innerHTML = ""; logOut.appendChild(el("div", { class: "hint" }, "analyzing…"));
    try {
      const r = live ? await api.get("/api/diagnostics") : await api.post("/api/diagnostics", { text: ta.value });
      logOut.innerHTML = ""; renderDiagResult(logOut, r);
    } catch (e) { logOut.innerHTML = ""; logOut.appendChild(el("div", { class: "hint", style: "color:var(--err)" }, e.message)); }
  }
  tools.appendChild(el("div", { class: "card" },
    el("div", { class: "row-between", style: "margin-bottom:10px" },
      el("div", { class: "card-title" }, "Log analysis"),
      el("button", { class: "btn btn-sm", onclick: () => analyze(true) }, "Load sing-box log")),
    el("div", { class: "field" }, el("label", {}, "Analyze log text"), ta),
    el("button", { class: "btn btn-sm", onclick: () => analyze(false) }, "Analyze"),
    logOut));

  // The specific tools, disclosed as one group. Closed by default but present in the DOM, so
  // nothing here is unreachable — and a keyboard or screen-reader user still finds every control.
  // groupPageCards lifts every [data-group] card out and re-appends it under its heading, so this
  // disclosure has to be added AFTER that pass — appended before, it kept its original position and
  // ended up above the groups, which put the fallback tools in front of the front door.
  groupPageCards(view, [
    { key: 'tools', title: 'Checks and tools',
      hint: 'You start these and wait for a result.' },
    { key: 'reports', title: 'What this router reports',
      hint: 'What the device already knows, without running a test.' },
  ]);

  view.appendChild(el("details", { class: "diag-adv" },
    el("summary", { class: "hint" }, t("One tool at a time — speedtest, ping, traceroute, DNS, domain trace, log analysis")),
    el("div", { class: "hint diag-adv-note" },
      t("Ask the router above covers these. Reach for one directly when you already know which question you are asking.")),
    tools));
}


// Pin the last speed-test result for `key` (an endpoint id, or "__global" for the
// throughput test) into `out`, with the time it was measured — so the Speed/Speedtest
// button reads as a living measurement that survives a re-render, not a fire-and-forget
// action. Cleared on page reload (results are session-ephemeral).
function pinSpeed(out, key) {
  const r = speedResults[key];
  if (!out || !r) return;
  out.textContent = r.text + " · " + fmtTime(r.ts);
  out.style.color = r.ok ? "var(--ok)" : "var(--err)";
}

async function runSpeedtest(btn, out) {
  const label = btn.textContent;
  btn.setAttribute("disabled", "true"); btn.textContent = t("Testing…");
  if (out) { out.textContent = t("running…"); out.style.color = "var(--ink-2)"; }
  try {
    const r = await api.post("/api/speedtest", { bytes: 10000000 });
    const txt = "↓ " + r.down_mbps + " Mbps" + (r.up_mbps ? "   ↑ " + r.up_mbps + " Mbps" : "") + "   ·   " + (r.latency_ms >= 0 ? r.latency_ms : "?") + " ms (" + (r.via ?? "?") + ")";
    speedResults["__global"] = { text: txt, ts: Date.now(), ok: true };
    if (out) { out.textContent = txt; out.style.color = "var(--ok)"; }
  } catch (e) { speedResults["__global"] = { text: t("failed: {0}", e.message), ts: Date.now(), ok: false }; if (out) { out.textContent = t("failed: {0}", e.message); out.style.color = "var(--err)"; } toast(t("Speedtest: {0}", e.message), "err"); }
  finally { btn.removeAttribute("disabled"); btn.textContent = label; }
}

// Two overlapping runs of this rendered the card twice. It clears #natcap-body up front, but two of
// its appends happen AFTER an await, so a second run's clear removes only what the first had painted
// so far — the first then resumes and appends its tunnel list and sing-box row underneath the
// second's. The router showed one protocol list and two "Detected native tunnels" blocks. The token
// makes the newest run the only one allowed to paint; every await is followed by a check.
let natcapRun = 0;
async function loadNativeCaps() {
  const run = ++natcapRun;
  const stale = () => run !== natcapRun;
  const body = () => document.getElementById("natcap-body");
  let d;
  try { d = await api.get("/api/native/capabilities"); }
  catch (e) {
    if (stale()) return;
    const b = body(); if (!b) return;
    b.innerHTML = "";
    b.appendChild(el("div", { class: "card-title", style: "margin-bottom:var(--sp-2)" }, "Native support"));
    b.appendChild(el("div", { class: "hint", style: "color:var(--ink-2)" }, t("Unavailable") + " — " + e.message));
    return;
  }
  if (stale()) return;
  const b = body(); if (!b) return;
  b.innerHTML = "";
  const native = d.native || {}, installable = d.installable || {};
  const sbReq = d.singbox_required || [];
  const sbSet = new Set(sbReq);
  // Title carries the detected platform so support reports show what we measured on.
  const title = el("div", { class: "row-between", style: "align-items:flex-start;margin-bottom:var(--sp-3)" },
    el("div", { class: "card-title" }, "Native support"),
    d.platform ? el("span", { class: "badge proto" }, d.platform) : null);
  b.appendChild(title);

  // One union of all protocols we know about, kept in a stable order.
  const all = [];
  const seen = new Set();
  const push = k => { if (k && !seen.has(k)) { seen.add(k); all.push(k); } };
  Object.keys(native).forEach(push);
  Object.keys(installable).forEach(push);
  sbReq.forEach(push);

  if (!all.length) {
    b.appendChild(el("div", { class: "hint" }, t("No capability data reported.")));
  } else {
    const rows = el("div", { style: "display:flex;flex-direction:column;gap:var(--sp-2)" });
    all.forEach(proto => {
      let pill;
      if (native[proto]) {
        // kernel/firmware-native — carried without sing-box.
        pill = el("span", { class: "pill ok", title: t("Carried by the kernel / firmware — no sing-box needed") },
          el("span", { class: "dot" }), t("NATIVE"));
      } else if (installable[proto]) {
        // native possible once the package is installed — actionable below in
        // "Recommended installs"; the pill flags it so the per-protocol row is consistent.
        pill = el("span", { class: "pill warn", title: t("Native once this package is installed") },
          el("span", { class: "dot" }), t("install") + ": " + installable[proto]);
      } else if (sbSet.has(proto)) {
        // only reachable via the sing-box core.
        pill = el("span", { class: "pill muted", title: t("Carried by the sing-box core") }, t("via sing-box"));
      } else {
        pill = el("span", { class: "pill muted" }, "—");
      }
      rows.appendChild(el("div", { class: "row-between", style: "gap:var(--sp-3);align-items:center" },
        el("span", { style: "font-size:var(--fs-control);font-weight:500" }, proto), pill));
    });
    // Same shape as the native-DNS card in AUD-77, found the same way: on the Keenetic this card
    // measured 816px — 45% of a 1793px Diagnostics page — because a real platform reports a row per
    // protocol plus its recommended installs, where the demo reports a handful. Lead with the count
    // the reader came for (how much this router carries WITHOUT sing-box) and disclose the matrix.
    // The recommended installs below stay open: they are the actionable part.
    const nNative = all.filter(p => native[p]).length;
    const nInst = all.filter(p => !native[p] && installable[p]).length;
    const nVia = all.filter(p => !native[p] && !installable[p] && sbSet.has(p)).length;
    const bits = [t("{0} of {1} carried natively", nNative, all.length)];
    if (nInst) bits.push(t("{0} native once installed", nInst));
    if (nVia) bits.push(t("{0} via sing-box", nVia));
    b.appendChild(el("div", { class: "ns-sum" }, bits.join(" · ")));
    const det = el("details", { class: "ns-det" }, el("summary", { class: "hint" }, t("Show each protocol")));
    det.appendChild(rows);
    b.appendChild(det);
  }

  // Recommended installs — turn the "install: <pkg>" pills into copyable opkg
  // commands so the user can act without leaving the page. Detect + recommend only;
  // nothing is executed here. Skipped entirely when nothing is installable.
  const recos = Object.keys(installable)
    .filter(p => !native[p] && installable[p]) // a kernel-native proto never needs a package
    .map(p => ({ proto: p, pkg: installable[p] }));
  if (recos.length) {
    const platform = d.platform || "";
    const sec = el("div", { style: "margin-top:var(--sp-3);border-top:1px solid var(--divider);padding-top:var(--sp-3)" },
      el("div", { class: "hint", style: "font-weight:600;margin-bottom:var(--sp-2)" }, t("Recommended installs")));
    recos.forEach(({ proto, pkg }) => {
      if (platform === "keenetic") {
        // Keenetic native protos are FIRMWARE COMPONENTS managed by the device's own UI —
        // NOT opkg-installable, so an "opkg install" command would be wrong. Recommend
        // enabling them in the Keenetic app instead (detect+recommend scope; WR never writes
        // ndmc). Show an instruction, not a copyable shell command.
        sec.appendChild(el("div", { style: "display:flex;flex-direction:column;gap:4px;margin-bottom:var(--sp-2)" },
          el("div", { class: "hint" }, proto + " — " + t("not enabled (firmware component)")),
          el("div", { class: "hint", style: "color:var(--muted)" },
            t("Enable it in the Keenetic app (System → Component options) and reboot — it then routes natively."))));
        return;
      }
      // OpenWrt (and default): a copyable install command for THIS host's package manager.
      //
      // This used to hardcode `opkg update && opkg install`. OpenWrt moved to apk in 24.10, and on a
      // 25.12 box there is no opkg binary at all — the command could not run. The daemon already
      // detects the manager and ships the exact command per protocol (`install_cmds`, alongside
      // `package_manager`); this page was throwing that away and printing its own guess. Prefer what
      // the router reported; fall back to composing from the reported manager; keep opkg only as the
      // last resort for a daemon too old to report either.
      //
      // Not a hypothetical: the AX3000T reports `package_manager: "apk"`, and `/etc/opkg` exists on it
      // even though opkg does not — so neither the version nor a directory can stand in for asking.
      const mgr = d.package_manager || "";
      const cmd = (d.install_cmds && d.install_cmds[proto])
        || (mgr === "apk" ? "apk update && apk add " + pkg
          : mgr === "opkg" ? "opkg update && opkg install " + pkg
            : "opkg update && opkg install " + pkg);
      const code = el("code", { class: "mono", style: "font-family:ui-monospace,Menlo,Consolas,monospace;font-size:var(--fs-small);background:var(--card-2);border-radius:5px;padding:2px 6px;word-break:break-all" }, cmd);
      const copy = el("button", { class: "btn btn-sm", title: t("Copy command"), "aria-label": t("Copy command") + " " + proto, onclick: () => copyText(cmd) }, t("Copy"));
      sec.appendChild(el("div", { style: "display:flex;flex-direction:column;gap:4px;margin-bottom:var(--sp-2)" },
        el("div", { class: "hint" }, proto + " — " + t("not built in")),
        el("div", { style: "display:flex;gap:var(--sp-2);align-items:center;flex-wrap:wrap" }, code, copy)));
    });
    b.appendChild(sec);
  }

  // Detected native tunnels — what /api/vpn/discover already found on the router
  // (iface · type · name). Each row gets an "Adopt as exit" button that POSTs to
  // /api/vpn/adopt: the OS keeps owning the tunnel; WayHop only adds a DISABLED
  // external endpoint that ROUTES THROUGH it. Best-effort: a 404 / empty list shows
  // nothing extra, mirroring loadNativeCaps' own graceful try/catch.
  try {
    const dv = await api.get("/api/vpn/discover");
    if (stale()) return;   // a newer run has already cleared and repainted the card
    const vpns = (dv && dv.vpns) || [];
    if (vpns.length) {
      // Tunnels already represented by an external endpoint shouldn't offer Adopt again. The server
      // decides (v.adopted), matching by public key first: an interface-name match alone would hide
      // a new Keenetic tunnel that reused a deleted one's WireguardN slot.
      const sec = el("div", { style: "margin-top:var(--sp-3);border-top:1px solid var(--divider);padding-top:var(--sp-3)" },
        el("div", { class: "hint", style: "font-weight:600;margin-bottom:var(--sp-2)" }, t("Detected native tunnels")),
        // One-time explainer: adopting is non-destructive and never auto-enables.
        el("div", { class: "hint", style: "color:var(--ink-2);margin-bottom:var(--sp-2);line-height:1.5" },
          t("WayHop will ROUTE THROUGH the tunnel but does not manage it (the OS owns it). It is added disabled — enable it in Connections to start routing.")));
      vpns.forEach(v => {
        // The name is what the ROUTER calls this tunnel — on KeeneticOS the description the
        // operator typed in its own UI, which is also the name WayHop gives the endpoint it creates
        // on adopt. It used to be dropped in favour of the public key, and on the KeeneticOS
        // discovery path the key is empty (`show interface` does not expose it), so the row
        // collapsed to "nwg2 · amneziawg": measured on a live Keenetic, six tunnels named
        // WgProvider_SiteB … LanAccessTunnel in NDM and told apart by nothing on this page, with
        // the one adoptable row asking him to guess which tunnel he was about to add. The key stays
        // as the fallback identity for a host that reports one and no name.
        const parts = [v.iface, v.type, v.name || v.public_key].filter(Boolean);
        const statusPill = v.active
          ? el("span", { class: "pill ok", title: t("Tunnel has a recent handshake") }, el("span", { class: "dot" }), t("active"))
          : el("span", { class: "pill muted", title: t("Configured but no recent handshake") }, t("idle"));
        // Adopt button: disabled-looking "Adopted" once an external endpoint exists
        // for this iface; otherwise a btn-sm that adopts + refreshes the card.
        // Both states name their interface. The live AX3000T has awg0 AND awg1 adopted, which put
        // two controls called "Adopted" on the page with nothing to tell them apart — the same
        // object-less naming the Failover actions had, and invisible on a demo with no native
        // tunnels at all.
        const represented = !!v.adopted;
        const adoptBtn = v.needs_repair
          ? el("button", { class: "btn btn-sm", "aria-label": t("Repair adoption") + " " + v.iface, title: t("Capture this KeeneticOS tunnel's exact ownership and NDM identity without changing whether it is enabled"),
              onclick: async () => {
                try {
                  await api.post("/api/vpn/adopt", { iface: v.iface });
                  try { await loadProfile(); } catch (_) {}
                  toast(t("Repaired adoption metadata for {0}", v.iface), "ok");
                  loadNativeCaps();
                } catch (err) { toast(err.message, "err"); }
              } }, t("Repair adoption"))
          : represented
          ? el("button", { class: "btn btn-sm", disabled: "true", "aria-label": t("Adopted") + " " + v.iface, title: t("Already added as a routing exit") }, t("Adopted"))
          : el("button", { class: "btn btn-sm", "aria-label": t("Adopt as exit") + " " + v.iface, title: t("Add this OS-owned tunnel as a routing exit (added disabled — WayHop will not manage it)"),
              onclick: async () => {
                try {
                  await api.post("/api/vpn/adopt", { iface: v.iface });
                  // Keep the profile fresh so the Connections page + the re-rendered
                  // card both see the new external endpoint, then refresh the card.
                  try { await loadProfile(); } catch (_) {}
                  toast(t("Adopted {0} — enable it in Connections to route through it", v.iface), "ok");
                  loadNativeCaps();
                } catch (err) { toast(err.message, "err"); }
              } }, t("Adopt as exit"));
        // .nt-row rather than row-between: as flex rows the right-hand cluster was as wide as that
        // row's own button label, so the one interface still offering "Adopt as exit" put its status
        // pill 62px left of every "Adopted" row above it.
        sec.appendChild(el("div", { class: "nt-row" },
          el("span", { class: "nt-name", title: parts.join(" · ") }, parts.join(" · ")),
          el("span", { class: "nt-acts" }, statusPill, adoptBtn)));
      });
      b.appendChild(sec);
    }
  } catch (_) { /* endpoint absent (404) or unreachable — show nothing extra */ }

  // sing-box presence — the core that carries everything not natively supported.
  // When the live profile is native-only (kernel plane carries everything in fast mode),
  // an absent core is BY DESIGN: show a positive "not required" badge instead of a red
  // "absent" warning. The native-only signal is read defensively from the capabilities
  // payload (d.native_only) or, failing that, the daemon health verdict — so when neither
  // field is present this falls back to the existing present/absent pill, unchanged.
  const sbNativeOnly = !!d.native_only || isNativeOnly(state.health);
  const sbPill = d.singbox_present
    ? el("span", { class: "pill ok" }, el("span", { class: "dot" }), t("present"))
    : sbNativeOnly
      ? el("span", { class: "pill ok", title: t("Every endpoint is kernel-native and traffic is routed by the kernel plane in fast mode, so the sing-box core is intentionally not running.") }, el("span", { class: "dot" }), t("not required"))
      : el("span", { class: "pill warn" }, el("span", { class: "dot" }), t("absent"));
  b.appendChild(el("div", { class: "row-between", style: "gap:var(--sp-3);align-items:center;margin-top:var(--sp-3);border-top:1px solid var(--divider);padding-top:var(--sp-3)" },
    el("span", { class: "hint" }, "sing-box"), sbPill));
  if (sbNativeOnly && !d.singbox_present)
    b.appendChild(el("div", { class: "hint", style: "color:var(--ok);margin-top:var(--sp-2)" }, t("Native-only mode — sing-box not required")));
}

function healthBatteryCard() {
  const card = el("div", { class: "card", id: "hbat" });
  const runBtn = el("button", { class: "btn btn-primary", id: "hbat-run", style: "padding:9px 20px", onclick: () => runHealthBattery() }, "Run all checks");
  const copyBtn = el("button", { class: "btn btn-sm", id: "hbat-copy", onclick: () => copyReport() }, "Copy report");
  copyBtn.disabled = true;
  // Mask toggle (default ON): the report carries exit IP + ISP/ASN once geo is in,
  // so scrub public IPs / keys / tokens before it lands on a clipboard or support chat.
  const maskCb = el("input", { type: "checkbox", id: "hbat-mask", style: "margin:0" });
  maskCb.checked = localStorage.getItem("wr_mask_report") !== "0";
  maskCb.onchange = () => localStorage.setItem("wr_mask_report", maskCb.checked ? "1" : "0");
  const maskLbl = el("label", { class: "hint", style: "display:flex;gap:5px;align-items:center;cursor:pointer;user-select:none", title: "Hide public IPs, keys and tokens in the copied report" }, maskCb, t("Mask IPs"));
  card.appendChild(el("div", { class: "row-between", style: "align-items:flex-start" },
    el("div", {},
      el("div", { class: "card-title", style: "font-size:17px" }, "Is everything working?"),
      el("div", { class: "hint", style: "margin-top:3px" }, "One click runs every check.")),
    el("div", { style: "display:flex;gap:10px;align-items:center;flex-wrap:wrap;justify-content:flex-end" }, maskLbl, copyBtn, runBtn)));
  card.appendChild(el("div", { id: "hbat-verdict", style: "margin-top:14px" }));
  card.appendChild(el("div", { id: "hbat-rows", class: "health-rows", style: "margin-top:12px" }));
  return card;
}

async function runHealthBattery() {
  const abort = {};
  state.hbat = { ranAt: Date.now(), results: {}, busy: {}, open: {}, abort, running: true };
  paintBattery();
  const mine = () => state.hbat && state.hbat.abort === abort;
  const set = (id, r) => { if (mine()) { state.hbat.results[id] = r; paintBattery(); } };
  try {
    const safe = (id, fn) => async () => { try { set(id, await withHealthCheckDeadline(fn)); } catch (e) { set(id, { status: "warn", summary: t("check failed"), detail: e.message }); } };
    const tasks = Object.keys(CHECKS).map(id => safe(id, CHECKS[id]));
    tasks.push(async () => { // backend-only probes folded in: clock skew + IPv6 leak + DoH
      // The server's LABEL is kept. Dropping it was half of why rows the daemon computes never
      // reached the screen: an id absent from HC_LABEL had nothing to be called, so the fixed list
      // below looked like the only safe thing to render.
      try { const d = await withHealthCheckDeadline(() => api.get("/api/healthcheck")); (d.checks || []).forEach(c => set(c.id, { status: c.status, summary: c.summary, detail: c.detail, fix: c.fix, label: c.label })); }
      catch (e) { HC_BACKEND.forEach(id => set(id, { status: "warn", summary: t("unavailable"), detail: e.message })); }
    });
    await runPool(tasks, 3);
  } catch (e) {
    // A programming error must be terminal too. Fill only missing standard rows so completed
    // evidence is preserved and the operator can see that the remaining checks were not verified.
    HC_ORDER.forEach(id => {
      if (mine() && !state.hbat.results[id]) set(id, { status: "warn", summary: t("check failed"), detail: e.message });
    });
  } finally {
    if (mine()) { state.hbat.running = false; paintBattery(); }
  }
}

function paintBattery() {
  const card = document.getElementById("hbat");
  if (!card || !state.hbat) return;
  const h = state.hbat, res = h.results;
  const done = hcIds(res).map(id => res[id]).filter(Boolean);
  // An `na` row never colours the page: it reports that a check did not run, which is not a verdict
  // about the router. Folding it into either side is what this whole status was added to stop.
  const ran = done.filter(r => r.status !== "na");
  const skipped = done.length - ran.length;
  const worst = ran.reduce((a, r) => r.status === "fail" ? "fail" : (r.status === "warn" && a !== "fail") ? "warn" : a, "pass");
  const vb = document.getElementById("hbat-verdict");
  if (vb) {
    vb.innerHTML = "";
    if (h.running) vb.appendChild(el("div", { class: "hero-pill hero-warn" }, el("span", { class: "spin" }), t("Checking… {0}/{1}", HC_ORDER.filter(id => res[id]).length, HC_ORDER.length)));
    else if (done.length) {
      const fails = ran.filter(r => r.status === "fail").length, warns = ran.filter(r => r.status === "warn").length;
      const cls = worst === "fail" ? "hero-err" : worst === "warn" ? "hero-warn" : "hero-ok";
      // "Everything's working" over a run where six checks never ran is the claim this counts away
      // from. With nothing left to run it stays exactly as short as it was.
      const txt = !ran.length ? t("Nothing could be checked here")
        : worst === "fail" ? t("Something is broken") + (fails > 1 ? " (" + fails + ")" : "")
          : worst === "warn" ? warns + " " + (warns > 1 ? t("things to look at") : t("thing to look at"))
            : t("Everything's working");
      vb.appendChild(el("div", { class: "hero-pill " + cls }, txt));
      const tally = ran.length ? t("{0} checked", ran.length) : "";
      const line = [tally, skipped ? t("{0} not checked here", skipped) : "", t("Checked") + " " + timeAgo(h.ranAt)]
        .filter(Boolean).join(" · ");
      vb.appendChild(el("div", { class: "hint", style: "margin-top:8px" }, line));
    }
  }
  const cb = document.getElementById("hbat-copy"); if (cb) cb.disabled = h.running || !done.length;
  const rb = document.getElementById("hbat-run"); if (rb) rb.disabled = h.running;
  const wrap = document.getElementById("hbat-rows");
  if (wrap) {
    wrap.innerHTML = "";
    h.open = h.open || {};
    hcIds(res).forEach(id => wrap.appendChild(healthRowEl(id, res[id], h.running, (h.busy || {})[id], h.open)));
  }
}

function healthRowEl(id, r, running, busy, open) {
  const chipCls = busy || (!r && running) ? "muted" : !r ? "muted"
    : r.status === "na" ? "muted" : r.status === "pass" ? "ok" : r.status === "warn" ? "warn" : "err";
  const chipInner = busy || (!r && running) ? el("span", { class: "spin" }) : !r ? el("span", { class: "dot", style: "opacity:.3" }) : el("span", { class: "dot" });
  const chipLabel = busy || (!r && running) ? t("checking…") : !r ? t("pending")
    : r.status === "na" ? t("not checked") : r.status === "pass" ? t("pass") : r.status === "warn" ? t("warning") : t("fail");
  const chip = el("span", { class: "pill " + chipCls, role: "img", "aria-label": chipLabel }, chipInner);
  // r.summary/detail/fix may be server-provided (backend checks) — translate them here too.
  // Client-side chk* strings are already localized, so t() is a no-op pass-through for those.
  const res = el("span", { class: "res" }, busy ? t("checking…") : !r && running ? t("checking…") : !r ? "—" : (r.summary ? t(r.summary) : ""));
  // per-row re-check: re-run just this check after a fix, without the whole battery
  const recheck = el("button", { class: "btn-icon", title: t("Re-check"), "aria-label": t("Re-check"), onclick: (e) => { e.stopPropagation(); recheckOne(id); } }, "↻");
  recheck.disabled = !!(running || busy);
  // The daemon names its own checks; HC_LABEL only overrides the ones the page words differently.
  // Falling straight through to the raw id put `dns-bypass` on screen as "dns-bypass".
  const head = el("div", { class: "health-row" }, chip, el("span", { class: "lbl" }, t(hcLabel(id, r))), res, recheck);
  const expandable = r && !busy && ((r.status !== "pass" && r.status !== "na") || r.detail || r.kb || r.fix);
  if (!expandable) return head;
  const isOpen = open && id in open ? open[id] : r.status === "fail";
  const chev = el("span", { class: "hint", style: "margin:0 2px" }, isOpen ? "▴" : "▾");
  head.insertBefore(chev, recheck);
  head.style.cursor = "pointer";
  const body = el("div", { class: "health-body", style: "padding:4px 0 10px 30px;display:" + (isOpen ? "" : "none") });
  if (r.fix) body.appendChild(el("div", { style: "background:var(--card-2);border-radius:8px;padding:10px 12px;line-height:1.55;white-space:pre-wrap" }, el("b", {}, t("Fix") + ": "), t(r.fix)));
  if (r.deep && HC_DEEP[r.deep]) body.appendChild(el("button", { class: "btn btn-sm", style: "margin-top:8px", onclick: () => { location.hash = HC_DEEP[r.deep][0]; } }, HC_DEEP[r.deep][1]));
  if (r.kb) r.kb.forEach(e => body.appendChild(kbCard(e)));
  if (r.detail) body.appendChild(el("details", { style: "margin-top:8px" }, el("summary", { class: "hint", style: "cursor:pointer" }, t("Show details")), mono(t(r.detail))));
  body.appendChild(el("button", { class: "btn btn-sm", style: "margin-top:8px", "aria-label": t("Copy") + " " + t(hcLabel(id, r)), onclick: () => copyText("[" + r.status.toUpperCase() + "] " + t(hcLabel(id, r)) + " — " + (r.summary || "") + (r.detail ? "\n" + r.detail : "")) }, t("Copy")));
  if (open) open[id] = isOpen;
  const toggle = () => {
    const showing = body.style.display !== "none";
    body.style.display = showing ? "none" : "";
    chev.textContent = showing ? "▾" : "▴";
    chev.setAttribute("aria-expanded", showing ? "false" : "true");
    if (open) open[id] = !showing;
  };
  head.onclick = toggle; // mouse: click anywhere on the row
  // Keyboard access: the row contains a nested Re-check button so the row div can't be role=button
  // (nested interactives). Expose the toggle on the chevron instead — role=button + tabindex +
  // Enter/Space (like the IPTV expander). stopPropagation so a chevron click doesn't also fire head.onclick.
  chev.setAttribute("aria-expanded", isOpen ? "true" : "false");
  a11yClick(chev, (ev) => { if (ev && ev.stopPropagation) ev.stopPropagation(); toggle(); }, t(hcLabel(id, r)));
  return el("div", {}, head, body);
}

function timeAgo(ms) { const s = Math.round((Date.now() - ms) / 1000); return s < 60 ? t("just now") : s < 3600 ? t("{0} min ago", Math.floor(s / 60)) : t("{0}h ago", Math.floor(s / 3600)); }

function copyReport() {
  const h = state.hbat; if (!h) return;
  const mask = !((document.getElementById("hbat-mask") || {}).checked === false); // default ON
  copyText(buildReport(h, mask));
}

function isPrivIP(a, b) { return a === 10 || a === 127 || a === 0 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31); }

// looksLikeLogLine recognises ONE log line by its shape. The paste test in askClassify only catches
// multi-line or very long input, which is not how people ask about a log: they copy the single line
// that looks wrong. Measured on a live Keenetic — pasting
// "2026-08-20 07:11:02 FATAL start service: configure tun interface: invalid argument" (84 chars,
// one line) fell through every branch and answered "could not tell what this is", then advised
// "…or paste a log", which is exactly what had just been done. The knowledge base knows that line.
//
// Deliberately narrow: a leading timestamp, the router's own "+0000 <date>" prefix, or an uppercase
// severity token — and never a single word, which is a name.
function looksLikeLogLine(q) {
  if (!/\s/.test(q)) return false;
  if (/^\d{4}[-/]\d{2}[-/]\d{2}[ T]/.test(q)) return true;
  if (/^\+\d{4}\s+\d{4}[-/]\d{2}/.test(q)) return true;
  return /(^|\s)(FATAL|PANIC|ERROR|WARN|WARNING|INFO|DEBUG|TRACE)(\s|:)/.test(q);
}

function askClassify(raw) {
  const q = (raw || "").trim();
  if (!q) return null;
  // Multi-line or very long input is a paste, not a name. Checked first: a log line can contain a
  // domain, and running a reachability test on the first hostname in someone's stack trace would be
  // a confidently wrong answer.
  if (/\r|\n/.test(q) || q.length > 160) return { kind: "log", value: q };
  const lc = q.toLowerCase();
  const ep = (state.profile.endpoints || []).find(e => e.id === q || (e.name || "").toLowerCase() === lc);
  if (ep) return { kind: "exit", value: q, ep: ep };
  const gr = (state.profile.groups || []).find(g => g.id === q || (g.name || "").toLowerCase() === lc);
  if (gr) return { kind: "exit", value: q, group: gr };
  if (/^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(q)) return { kind: "device", value: q };
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(q)) {
    return isPrivateIPv4(q) ? { kind: "device", value: q } : { kind: "ip", value: q };
  }
  if (/^https?:\/\//i.test(q)) return { kind: "url", value: q };
  if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.?$/i.test(q)) {
    return { kind: "domain", value: q };
  }
  // Checked LAST so a plain domain or an exit name still wins; only text nothing else claims is
  // read as a log.
  if (looksLikeLogLine(q)) return { kind: "log", value: q };
  return { kind: "unknown", value: q };
}

// ── Flight recorder ───────────────────────────────────────────────────────────────────────────
// What the router has been doing, on one time axis: a band per exit showing its recent probes, and
// the event feed beneath it.
//
// The band is probe COUNT, not wall-clock. The monitor keeps outcomes and not timestamps, so the
// honest label is "the last N probes at a nominal cadence" — stretching them across a real clock
// would invent precision the data does not have, and would hide a gap where the daemon was stopped.
function flightRecorderCard() {
  const card = el("div", { class: "card fr", "data-group": "reports" });
  card.appendChild(el("div", { class: "card-title" }, t("Flight recorder")));
  const body = el("div", {}, el("div", { class: "hint" }, t("Reading…")));
  card.appendChild(body);
  const paint = async () => {
    let hist = null, evs = null;
    try { hist = await api.get("/api/health/history"); } catch (_) { hist = null; }
    try { evs = await api.get("/api/failover/events?limit=25"); } catch (_) { evs = null; }
    body.innerHTML = "";
    const windows = (hist && hist.known && hist.windows) || [];
    if (!hist || !hist.known) {
      body.appendChild(el("div", { class: "hint" },
        t("WayHop could not read the probe history, so nothing is shown rather than an empty band.")));
    } else if (!windows.length) {
      body.appendChild(el("div", { class: "hint" }, t("Nothing has been probed yet.")));
    } else {
      const span = windows[0];
      body.appendChild(el("div", { class: "hint fr-scale" },
        t("Each cell is one probe, oldest on the left. Up to {0} probes at about {1}s apart.",
          span.samples.length, span.interval_s)));
      // 32 exits made this card 1033px of a 1824px page. The scale line above already says what the
      // card is FOR; the per-exit bands are the detail. Worst-first so the folded ones are the
      // healthy ones, and the fold names how many it holds.
      // 5, not 8. A fold threshold set at or above the scale real routers actually run at never fires
      // where it is needed: this was 8, the Keenetic has exactly 8 exits, and the card stayed at full
      // height (666px of a 1699px page) on the one box the fold existed for. Thresholds belong below
      // typical REAL scale, not below the synthetic stress scale they were tuned against.
      const FR_VISIBLE = 5;
      const pct = (w) => w.samples.filter(Boolean).length / (w.samples.length || 1);
      const ordered = [...windows].sort((a, b) => pct(a) - pct(b));
      const frMore = ordered.length > FR_VISIBLE
        ? el("details", { class: "fr-more" },
            el("summary", { class: "hint" }, t("Show all {0} exits", ordered.length)))
        : null;
      ordered.forEach((w, wi) => {
        const ok = w.samples.filter(Boolean).length;
        const row = el("div", { class: "fr-row" },
          el("span", { class: "fr-name" }, w.name || w.id),
          el("span", { class: "fr-band" }, ...w.samples.map((s, i) =>
            el("span", { class: "fr-cell " + (s ? "ok" : "bad"),
              title: (s ? t("probe {0}: answered") : t("probe {0}: no answer")).replace("{0}", String(i + 1)) }))),
          el("span", { class: "fr-pct" }, Math.round(ok / w.samples.length * 100) + "%"),
          w.full ? null : el("span", { class: "fr-partial", title: t("The window is not full yet") }, t("partial")));
        if (frMore && wi >= FR_VISIBLE) frMore.appendChild(row); else body.appendChild(row);
      });
      if (frMore) body.appendChild(frMore);
    }
    const feed = el("div", { class: "fr-events" });
    body.appendChild(feed);
    if (!evs || !evs.known) {
      feed.appendChild(el("div", { class: "hint" }, t("The event log could not be read.")));
    } else if (!(evs.events || []).length) {
      feed.appendChild(el("div", { class: "hint" }, evs.since_ms
        ? t("No outage or switch since the daemon started ({0}).", fmtWhen(evs.since_ms))
        : t("No outage or switch recorded yet.")));
      // The two statements on this card measure different things, and only one arrangement of the
      // data makes that matter: a red cell in a band above, and "no outage" here. Measured on the
      // operator's Keenetic — one exit at 29/30 with a single failed probe, and this line reading
      // "No outage or switch since the daemon started (25m ago)". Both are true: a cell is one probe
      // (the legend says so) while an outage is a committed state change, which the monitor's
      // fast-out hysteresis only promotes after consecutive failures. Said ONLY in that arrangement,
      // because on a clean ribbon it explains something the reader is not looking at.
      if (windows.some(w => (w.samples || []).some(ok => !ok))) {
        feed.appendChild(el("div", { class: "hint" },
          t("A missed probe above is not an outage on its own — a run of them is what counts as one.")));
      }
    } else {
      // The per-exit bands above cap at 5, and this feed did not cap at all — so the card grew with
      // how often the router had actually failed over. On the Keenetic, whose All_VPN group switches
      // regularly, it reached 370px and pushed Diagnostics to 1712px = 2.1 screens. The ring holds
      // 256 events, so the worst case is about 7400px. Newest first is already the order, and the
      // recent ones are the ones being looked for, so show a handful and disclose the rest.
      const EV_VISIBLE = 6;
      const evMore = evs.events.length > EV_VISIBLE
        ? el("details", { class: "fr-ev-more" },
            el("summary", { class: "hint" }, t("Show all {0} events", evs.events.length)))
        : null;
      evs.events.forEach((ev, ei) => {
        const ico = ev.kind === "down" ? "▼" : ev.kind === "up" ? "▲" : "⇄";
        const text = ev.kind === "switch" ? t("{0} switched to {1}", ev.name || ev.id, ev.to || "?")
          : ev.kind === "up" ? t("{0} came back", ev.name || ev.id)
            : t("{0} went down", ev.name || ev.id);
        const row = el("div", { class: "fo-log-row " + ev.kind },
          el("span", { class: "fo-log-i", "aria-hidden": "true" }, ico),
          el("span", { class: "fo-log-x" }, text),
          el("span", { class: "fo-log-w" }, fmtWhen(ev.at)));
        if (evMore && ei >= EV_VISIBLE) evMore.appendChild(row); else feed.appendChild(row);
      });
      if (evMore) feed.appendChild(evMore);
    }
    if (openBands) { const d = body.querySelector(".fr-more"); if (d) d.open = true; }
    if (openEvents) { const d = body.querySelector(".fr-ev-more"); if (d) d.open = true; }
  };

  // The recorder is a LIVE view and rendered exactly once, so it froze at whatever was true when the
  // page was opened. Measured on a live router twenty minutes after a restart: the card still
  // showed a nine-probe window with "partial" beside every exit while the daemon held thirty full
  // samples, and an outage during that time would not have appeared on the one card whose whole
  // purpose is to show outages. Repaint on the probe cadence the API itself reports.
  //
  // isConnected is the stop condition, the same test diagRefresh uses: leaving the page detaches the
  // card, so the timer retires itself instead of polling the router forever behind a page nobody is
  // looking at.
  let openBands = false, openEvents = false;
  const rememberDisclosures = () => {
    const b = body.querySelector(".fr-more"), e2 = body.querySelector(".fr-ev-more");
    openBands = !!(b && b.open);
    openEvents = !!(e2 && e2.open);
  };
  paint();
  const iv = setInterval(() => {
    if (!card.isConnected) { clearInterval(iv); return; }
    // A repaint rebuilds the disclosures, so carry their state across it: collapsing "Show all 12
    // exits" under someone reading it would make the refresh worse than the staleness it fixes.
    rememberDisclosures();
    paint();
  }, FR_REFRESH_MS);
  return card;
}

// The probes are about 10s apart, so anything faster only costs the router requests. It is a floor
// rather than a read of interval_s because the first paint has not happened yet when the timer is
// armed, and a hostile or zero interval must never turn this into a spin.
const FR_REFRESH_MS = 15000;

function renderDiagResult(out, r) {
  if (r.found && r.found.length) {
    out.appendChild(el("div", { class: "card-title", style: "margin:6px 0 10px" }, tn("{0} known issue detected|{0} known issues detected", r.found.length)));
    r.found.forEach(e => out.appendChild(kbCard(e)));
  } else {
    out.appendChild(el("div", { class: "card" }, el("div", { class: "empty" },
      r.count ? tn("No known errors matched in {0} log line.|No known errors matched in {0} log lines.", r.count) : t("No log yet. Paste logs above, or start sing-box on the device and reload."))));
  }
  if (r.lines && r.lines.length) {
    const pre = el("div", { style: "font-family:ui-monospace,Consolas,monospace;font-size:12px;max-height:340px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.55" });
    r.lines.forEach(lm => {
      const color = lm.entries ? "var(--warn)" : lm.error ? "var(--err)" : "var(--ink-2)";
      pre.appendChild(el("div", { style: "color:" + color }, (lm.entries ? "● " : "  ") + lm.line));
    });
    out.appendChild(el("div", { class: "card" }, el("div", { class: "card-title", style: "margin-bottom:10px" }, tn("Log ({0} line)|Log ({0} lines)", r.lines.length)), pre));
  }
}

function kbCard(e) {
  return el("div", { class: "card" },
    el("div", { class: "name", style: "font-size:15px" }, e.title, el("span", { class: "badge", style: "margin-left:8px" }, e.engine),
      (e.count > 1 ? el("span", { class: "badge", style: "margin-left:6px", title: t("matched {0} log lines", e.count) }, "×" + e.count) : null)),
    el("div", { class: "sub", style: "margin-top:8px;line-height:1.55" }, e.explanation),
    el("div", { style: "margin-top:10px;line-height:1.55" }, el("b", {}, "Fix: "), e.fix),
    (e.sources && e.sources.length) ? el("div", { class: "hint", style: "margin-top:10px" }, "Sources: ",
      ...e.sources.map(s => el("a", { href: s, target: "_blank", rel: "noopener", style: "margin-right:12px" }, srcLabel(s)))) : null);
}

function srcLabel(url) {
  try {
    const u = new URL(url);
    if (u.hostname.includes("github")) { const m = u.pathname.match(/issues\/(\d+)|discussions\/(\d+)/); return m ? "GitHub #" + (m[1] || m[2]) : "GitHub"; }
    return u.hostname.replace("www.", "");
  } catch (_) { return "link"; }
}

// ── What is happening right now ───────────────────────────────────────────────────────────────
// The page opened with tools: things you START and then wait for. But the first question in front of
// a router is not "run me a test", it is "what is this box doing at this moment" — and every fact
// needed to answer it was already being served, scattered across five endpoints and three other
// pages. Reading them here costs one round of requests and replaces a guess.
//
// Each line is a measurement with its source named, never a reassurance: where the default goes,
// which plane carries it, what the lists have actually matched, and who answers the clients' DNS.
function diagNowCard() {
  const card = el("div", { class: "card", "data-group": "reports" });
  card.appendChild(el("div", { class: "card-head" },
    el("div", { class: "card-title" }, t("Right now")),
    el("div", { class: "hint" }, t("Measured from the router, not inferred from the configuration."))));
  const body = el("div", { class: "diag-now" });
  body.appendChild(el("div", { class: "hint" }, t("reading…")));
  card.appendChild(body);

  const row = (label, value, note) => el("div", { class: "diag-now-row" },
    el("span", { class: "diag-now-k" }, label),
    el("span", { class: "diag-now-v" }, value),
    note ? el("span", { class: "diag-now-n" }, note) : null);

  const load = async () => {
    const get = async p => { try { const r = await fetch(p); return r.ok ? await r.json() : null; } catch (_) { return null; } };
    const [health, pbrSt, st, traffic] = await Promise.all([
      get("/api/health"), get("/api/pbr/status"), get("/api/state"), get("/api/routing/traffic"),
    ]);
    const rows = el("div", {});

    // 1. Which plane carries traffic. The one fact every other line depends on.
    const sb = (health && health.singbox) || {};
    rows.appendChild(row(t("Datapath"),
      sb.native_only ? t("kernel plane only") : (sb.running ? t("kernel plane + sing-box") : t("sing-box expected but not running")),
      sb.native_only ? t("sing-box is not installed and is not needed here") : ""));

    // 2. Where unmatched traffic goes — the question behind "why is this site slow/blocked".
    const def = (state.profile.rules || []).find(r => r.default && !r.disabled);
    const defTarget = def ? (def.outbound || "direct") : "direct";
    rows.appendChild(row(t("Everything not matched"),
      defTarget === "direct" ? t("goes out through the provider") : t("goes through {0}", nameOf(defTarget) || defTarget),
      def ? "" : t("no default rule — the provider carries it")));

    // 3. The kernel policy plane, and what it has actually matched since it was installed. Counters,
    // not presence: a zone that has matched nothing is a rule nobody is using.
    if (pbrSt) {
      rows.appendChild(row(t("Kernel policy plane"),
        pbrSt.installed && !pbrSt.stale ? t("active · {0} zones", pbrSt.zones) : (pbrSt.installed ? t("stale") : t("not applied")),
        pbrSt.verified ? t("verified against the live kernel") : t("not verified since the last apply")));
    }
    const lists = (traffic && traffic.lists) || {};
    const hit = Object.keys(lists).map(id => ({ id: id, n: lists[id].conns || 0 }))
      .filter(x => x.n > 0).sort((a, b) => b.n - a.n).slice(0, 3);
    if (Object.keys(lists).length) {
      rows.appendChild(row(t("Lists matching traffic"),
        hit.length ? hit.map(x => (nameOf(x.id) || x.id) + " (" + x.n + ")").join(", ") : t("none yet"),
        t("packets since the rules were installed")));
    }

    // 4. Who answers the clients. The bypass this router could not see until interception existed.
    const dns = state.profile.dns || {};
    const final = (dns.servers || []).find(s => s.tag === dns.final);
    rows.appendChild(row(t("Clients' DNS"),
      dns.intercept ? t("answered by this router") : t("clients may use their own resolver"),
      final ? t("default resolver {0} · {1}", final.tag, final.detour ? (nameOf(final.detour) || final.detour) : t("direct")) : ""));

    if (st && st.pending) {
      rows.appendChild(row(t("Configuration"), t("changes are staged but not applied"),
        t("what you see above is the running state, not the saved one")));
    }
    body.replaceChildren(rows);
  };
  load();
  return card;
}
