// page-dns.js — route-scoped chunk for the dns page.
//
// Loaded by loadChunk() the first time that route is opened, NOT from index.html, so its bytes
// stay out of the initial payload the perf budget measures. A classic script, like app.js: these
// declarations become globals and app.js has already defined el/t/api/state by the time this runs.
//
// Everything here is reachable ONLY from this page's renderer — attributed by walking the call
// graph from every render* entry point, counting an identifier anywhere in a body (strings
// included) as a reference, so the shared set is over-estimated and this set is not.
// Writes the DNS plane with the version it was read at, and keeps that version in step with the
// daemon on success. A refusal here is not a failure to retry: the settings on the daemon differ
// from the ones on screen, so the page has to be reloaded before the edit can mean anything.
// Reports a failed DNS write. A staleness refusal is not a retryable error: the plane on screen is
// out of date, so retrying the same submission just gets refused again. Re-rendering re-reads the
// plane and its version, which is the only thing that makes a retry meaningful.
function dnsWriteFailed(e) {
  const stale = /STALE_CONFIG/.test(e.message || "");
  toast((e.message || "").replace(/^STALE_CONFIG:\s*/, ""), "err");
  if (stale) route();
  return stale;
}

// ── DNS check ─────────────────────────────────────────────────────────────────────────────────
// The report supplies every verdict. This block only translates its stable codes and presents the
// measurements; in particular, silence is never promoted to forgery and no_data is never an error.
const DNS_CHECK_STATUS_TEXT = {
  pass: { label: L("Passed"), text: L("Answer received and checked.") },
  warn: { label: L("Warning"), text: L("The answer revealed a possible problem.") },
  fail: { label: L("Failed"), text: L("This check found a definite mismatch.") },
  no_data: { label: L("No data"), text: L("No usable answer; this is not a failure.") },
  skipped: { label: L("Skipped"), text: L("Not run, so it says nothing about the resolver.") },
};
const DNS_CHECK_PATH_TEXT = {
  wan: L("Provider"),
  tunnel: L("VPN tunnel"),
  router: L("Router"),
};
const DNS_CHECK_VERDICT_TEXT = {
  genuine: { label: L("Genuine"), text: L("This is really that resolver.") },
  partial: { label: L("Partial"), text: L("Nothing definitely wrong was found, but some checks warned or got no answer.") },
  forged: { label: L("Forged"), text: L("Something else answers in its name.") },
  unreachable: { label: L("Unreachable"), text: L("No answer on this path.") },
  unknown_operator: { label: L("Unknown operator"), text: L("No known fingerprint; nothing wrong was found.") },
};
const DNS_CHECK_PROBE_TEXT = {
  base: L("An ordinary A lookup asked whether this path can resolve names."),
  identity: L("The operator fingerprint asked who actually answered."),
  dnssec_bogus: L("A deliberately broken DNSSEC name must be rejected."),
  dnssec_signed: L("A correctly signed name must validate."),
  nxdomain: L("A random nonexistent name must return NXDOMAIN."),
  second_reply: L("A second different answer to one query would indicate injection."),
  source: L("The answer must come from the address that was asked."),
  canary: L("A popular name's HTTPS certificate can confirm its answer through a tunnel."),
  decoy: L("An unused documentation address must not answer DNS."),
};
const DNS_CHECK_CODE_TEXT = {
  ok: L("This check passed."),
  no_reply: L("No answer came back, so this check proves nothing."),
  decoy_answered: L("An address with no DNS service answered, so this path intercepts DNS."),
  path_intercepted: L("Something on this path answers DNS for addresses with no DNS service."),
  bogus_accepted: L("A name with broken DNSSEC was accepted."),
  ad_missing: L("The signed answer lacked the AD validation flag."),
  identity_mismatch: L("The answering identity does not match the named operator."),
  identity_silent: L("The operator identity query got no answer."),
  nx_rewritten: L("A nonexistent name was rewritten to an answer."),
  nx_unclear: L("The test name got neither an address nor NXDOMAIN, so this proves nothing."),
  second_reply: L("More than one different answer arrived for the same query."),
  foreign_source: L("The answer came from a different address than the one asked."),
  canary_bogon: L("The popular name resolved to an invalid or documentation address."),
  canary_bad_cert: L("The certificate did not verify the popular name's answer."),
  canary_unverified: L("The certificate proof could not be completed."),
  canary_wan_off: L("Popular blocked names on the provider's line were not tested."),
  not_validating: L("This resolver answered but did not prove DNSSEC validation."),
};
const DNS_CHECK_EXPOSURE_TEXT = {
  provider: L("Lookup names are readable on the provider's line."),
  exit: L("The VPN exit and the resolver can read lookup names inside the tunnel."),
  resolver: L("Encryption hides lookup names from the provider and VPN exit; only the resolver can read them."),
  unknown: L("Who can read lookup names has not been measured."),
};
const DNS_CHECK_LEVEL_TEXT = {
  provider_plain: {
    label: L("Provider reads lookups"),
    text: L("The provider can read every name."),
  },
  tunnel_plain: {
    label: L("Plaintext inside a VPN"),
    text: L("Hidden from the provider; the VPN exit and the resolver can read them."),
  },
  provider_encrypted: {
    label: L("Encrypted on the provider's line"),
    text: L("Encrypted; the provider sees only which resolver you use."),
  },
  tunnel_encrypted: {
    label: L("Encrypted inside the VPN"),
    text: L("Encrypted inside the VPN; only the resolver can read them."),
  },
  unknown: {
    label: L("Privacy unknown"),
    text: L("The check could not establish who can read lookups."),
  },
};
const DNS_CHECK_SEVERITY_TEXT = {
  critical: L("Critical"),
  warn: L("Warning"),
  info: L("Note"),
};
// Review prints the server's words; the page-wide translator finds them here.
const DNS_REVIEW_WORDS = [L("Answer clients"), L("On"), L("Default resolver"), L("DNS plane"), L("changes how names are resolved for routed traffic")];
const DNS_CHECK_WARN_TEXT = {
  plain_on_provider: (f) => f[1]
    ? t("The provider can read lookups to {0}; {1} flows were measured.", dnsCheckFact(f, 0), f[1])
    : t("The provider can read lookups to {0}.", dnsCheckFact(f, 0)),
  plain_last_resort: (f) => f[1]
    ? t("Plaintext last resort: {0}. Failed tunnel lookups can fall back to it ({1} flows measured).", dnsCheckFact(f, 0), f[1])
    : t("Plaintext last resort: {0}. Failed tunnel lookups can fall back to it.", dnsCheckFact(f, 0)),
  resolver_forged: (f) => t("{0} on {1} failed authentication; something else may be answering in its name.", dnsCheckFact(f, 0), dnsCheckFact(f, 1)),
  path_intercepted: (f) => t("Something on {0} answers DNS for addresses that have no DNS service.", dnsCheckFact(f, 0)),
  clients_bypass: (f) => dnsCheckList(f).length
    ? t("Devices on {0} can bypass the router and use another resolver.", dnsCheckList(f).join(", "))
    : t("Devices can bypass the router and use another resolver."),
  encrypted_escape: () => t("Devices can use their own DoH or DoT resolvers and bypass the router."),
  ipv6_gap: (f) => t("IPv6 offers a route around the DNS rules: {0}.", dnsCheckList(f).join(", ")),
  single_path: (f) => dnsCheckList(f)[0]
    ? t("DNS has only one tunnel path through {0}; if it goes down, lookups stop.", f[0])
    : t("DNS has only one upstream; if it stops answering, lookups stop."),
  profile_not_served: () => t("The encrypted resolvers in this profile do not answer the household's devices."),
  encrypted_direct: () => t("The encrypted resolver leaves on the provider's line, so the provider can see which resolver you use."),
  not_measured: () => t("This router's DNS path could not be measured, so its privacy is unknown."),
  own_lookups_plain: (f) => t("The router's own lookups use {0} in plaintext on purpose so tunnels can be found after a reboot.", dnsCheckFact(f, 0)),
};
const DNS_CHECK_OPTION_TEXT = {
  chain_into_tunnels: {
    title: L("Send lookups through VPN tunnels"),
    gives: L("Hides lookup names from the provider."),
    cost: L("DNS through a tunnel stops while that tunnel is down unless another working row follows it."),
  },
  remove_last_resort: {
    title: L("Remove the plaintext last resort"),
    gives: L("Stops failed tunnel queries from falling back to plain provider DNS."),
    cost: L("If every tunnel dies, the household loses DNS until one returns."),
  },
  replace_resolver: {
    title: L("Replace the resolver that is not genuine"),
    gives: L("Stops another server answering in the named resolver's place."),
    cost: L("The replacement must be reachable and genuine on the chosen path; changing resolvers can briefly interrupt lookups."),
  },
  intercept_on: {
    title: L("Answer all plain DNS from this router"),
    gives: L("Devices with a hardcoded plain resolver follow the router's DNS path."),
    cost: L("The router answers devices that expected another resolver, so its DNS policies apply to them too."),
  },
  block_encrypted_escape: {
    title: L("Block devices' own encrypted resolvers"),
    gives: L("Well-known DoH and DoT resolvers fall back to plain DNS, which the router can intercept."),
    cost: L("Devices using other DoH hosts can still bypass the router; some devices may lose DNS until they fall back."),
  },
  fix_ipv6: {
    title: L("Close the IPv6 bypass"),
    gives: L("Brings IPv6 under the same DNS path and blocking rules as IPv4."),
    cost: L("Devices without a working IPv6 DNS route may lose name resolution until IPv6 is configured."),
  },
  add_second_tunnel: {
    title: L("Add a backup tunnel resolver"),
    gives: L("Another tunnel can answer if the first one goes down."),
    cost: L("Lookup privacy then depends on both VPN exits and their resolvers."),
  },
  encrypted_upstream: {
    title: L("Encrypt lookups to the resolver"),
    gives: L("The provider or VPN exit sees only the resolver address, not lookup names."),
    cost: L("Requires DoT or DoH to work on the chosen path; an unreachable encrypted resolver can interrupt DNS."),
  },
  encrypted_in_tunnel: {
    title: L("Encrypt lookups inside the VPN"),
    gives: L("Only the resolver can read names, not the provider or VPN exit."),
    cost: L("Both the tunnel and encrypted resolver must work; either failing can interrupt DNS."),
  },
};
const DNS_CHECK_PROGRESS_TEXT = {
  path: L("Measuring the DNS path"),
  decoys: L("Checking for DNS interception"),
  resolvers: L("Checking resolver identities"),
  encrypted: L("Testing encrypted transports"),
};

let dnsCheckSession = null;
let dnsCheckSerial = 0;

function dnsCheckList(value) { return Array.isArray(value) ? value : []; }
function dnsCheckFact(facts, index) {
  const value = dnsCheckList(facts)[index];
  return value == null || value === "" ? t("not reported") : String(value);
}
function dnsCheckText(table, code, ...args) {
  const key = String(code || "unknown");
  const entry = (table || {})[key];
  if (typeof entry === "function") return entry(...args);
  return entry ? t(entry, ...args) : key;
}
let dnsCheckRerun = false; // the chain changed, so the last report no longer describes this router
function dnsCheckStop() {
  if (!dnsCheckSession) return;
  if (dnsCheckSession.timer != null) clearTimeout(dnsCheckSession.timer);
  dnsCheckSession = null;
}
// route() replaces the view on navigation. Stopping on the hash event clears the timer immediately;
// the isConnected check in dnsCheckActive also covers renders superseded without a hash change.
if (typeof window !== "undefined") window.addEventListener("hashchange", dnsCheckStop);
function dnsCheckActive(session) {
  if (dnsCheckSession !== session) return false;
  // route() attaches the view only when the render finishes, so "not connected" means gone only once
  // the card has been connected. Without this the first read returned at once and the card never left
  // "Reading DNS check…".
  if (session.card.isConnected) session.mounted = true;
  return !session.mounted || session.card.isConnected;
}
function dnsCheckSchedule(session) {
  if (!dnsCheckActive(session) || session.timer != null) return;
  session.timer = setTimeout(() => {
    session.timer = null;
    dnsCheckRead(session);
  }, 1000);
}
function dnsCheckError(e) { return (e && e.message) || String(e || t("unknown error")); }

function dnsCheckCard(view) {
  dnsCheckStop();
  const body = el("div", { class: "dns-check-body" },
    el("div", { class: "hint", role: "status" }, t("Reading DNS check…")));
  const card = el("section", { class: "card dns-check", id: "dns-check" },
    el("div", { class: "card-head" },
      el("div", { class: "card-title" }, t("DNS privacy check"))),
    body);
  const session = {
    id: ++dnsCheckSerial, view, card, body, timer: null, loading: false, starting: false,
    autoStarted: false, canaries: false, extraNames: "", scenario: "", state: null, error: "", errorKind: "",
    expanded: new Set(),
  };
  dnsCheckSession = session;
  dnsCheckRead(session);
  return card;
}

async function dnsCheckRead(session) {
  if (!dnsCheckActive(session) || session.loading) return;
  if (session.timer != null) { clearTimeout(session.timer); session.timer = null; }
  session.loading = true;
  let next;
  try {
    const suffix = session.scenario ? "?scenario=" + encodeURIComponent(session.scenario) : "";
    next = await api.get("/api/dns/check" + suffix);
  } catch (e) {
    session.loading = false;
    if (!dnsCheckActive(session)) return;
    session.error = t("DNS check unavailable: {0}", dnsCheckError(e));
    session.errorKind = "read";
    dnsCheckDraw(session);
    if (session.state && session.state.running) dnsCheckSchedule(session);
    return;
  }
  session.loading = false;
  if (!dnsCheckActive(session)) return;
  session.state = next || {};
  session.error = "";
  session.errorKind = "";
  dnsCheckDraw(session);
  if (!session.state.running && (dnsCheckRerun || (!session.state.report && !session.autoStarted))) {
    session.autoStarted = true;
    dnsCheckRerun = false;
    await dnsCheckStart(session, false);
    return;
  }
  if (session.state.running) dnsCheckSchedule(session);
}

async function dnsCheckStart(session, full) {
  if (!dnsCheckActive(session) || session.starting) return;
  if (session.timer != null) { clearTimeout(session.timer); session.timer = null; }
  const names = full ? session.extraNames.split(/[\s,]+/).map(x => x.trim()).filter(Boolean) : [];
  if (names.length > 10) {
    session.error = t("Enter no more than 10 extra names.");
    session.errorKind = "start";
    dnsCheckDraw(session);
    return;
  }
  session.starting = true;
  session.error = "";
  session.errorKind = "";
  dnsCheckDraw(session);
  const request = { full: !!full };
  if (full) {
    request.canaries_on_wan = session.canaries;
    request.extra_names = names;
  }
  let conflict = false;
  try { await api.post("/api/dns/check", request); }
  catch (e) {
    conflict = !!(e && e.status === 409);
    if (!conflict) {
      session.error = t("Could not start the DNS check: {0}", dnsCheckError(e));
      session.errorKind = "start";
    }
  }
  session.starting = false;
  if (!dnsCheckActive(session)) return;
  dnsCheckDraw(session);
  // A 409 means somebody else's check is already running; following it is more useful than an error.
  if (!session.error || conflict) dnsCheckSchedule(session);
}

function dnsCheckExpandedKey(address, path) {
  path = path || {};
  return (address || "") + "\x00" + (path.kind || "") + "\x00" + (path.iface || "");
}

function dnsCheckDraw(session) {
  let focusedKey = null;
  if (typeof document !== "undefined" && document.activeElement && document.activeElement.dataset && document.activeElement.dataset.expandKey) {
    focusedKey = document.activeElement.dataset.expandKey;
  }
  session._focusedKey = focusedKey;
  session.body.textContent = "";
  if (session.error) session.body.appendChild(el("div", { class: "hint qp-warn", role: "alert" }, session.error));
  const st = session.state || {};
  if (session.starting || st.running) session.body.appendChild(dnsCheckProgress(session, st));
  if (st.report) {
    session.body.appendChild(dnsCheckReport(session, st, st.report));
  } else if (!session.starting && !st.running) {
    session.body.appendChild(el("div", { class: "hint" }, t("No DNS report yet. Start with the router's own path, then check resolver identities when you are ready.")));
    const retry = el("button", {
      class: "btn btn-sm",
      onclick: () => session.errorKind === "read" && !session.autoStarted ? dnsCheckRead(session) : dnsCheckStart(session, false),
    }, session.errorKind === "read" && !session.autoStarted ? t("Retry") : t("Check the DNS path"));
    session.body.appendChild(el("div", { class: "acts" }, retry));
  }
  if (focusedKey && typeof session.body.querySelectorAll === "function") {
    const back = [...session.body.querySelectorAll("[data-expand-key]")].find(node => node.dataset.expandKey === focusedKey);
    if (back) back.focus({ preventScroll: true });
  }
}

function dnsCheckProgress(session, st) {
  const p = st.progress || {};
  const stage = dnsCheckText(DNS_CHECK_PROGRESS_TEXT, p.stage || "path");
  const detail = p.total > 1 ? stage + " · " + t("{0} of {1} checks", p.done || 0, p.total) : stage;
  return el("div", { class: "hint dns-check-progress", role: "status" },
    el("span", { class: "spin", "aria-hidden": "true" }),
    el("span", {}, session.starting ? t("Starting the DNS check…") : t("Checking DNS: {0}", detail)));
}

function dnsCheckSection(title, hint) {
  return el("section", { class: "dns-check-section" },
    el("h3", { class: "dns-check-heading" }, title),
    hint ? el("div", { class: "hint" }, hint) : null);
}

// A section folded to one line that already carries its answer. The report redraws while it polls, so
// what was opened is kept on the session. side is a control that must stay reachable while folded.
function dnsCheckFold(session, key, title, summary, openByDefault, side) {
  if (!session.folds) session.folds = new Map();
  const open = session.folds.has(key) ? session.folds.get(key) : !!openByDefault;
  const id = "dns-fold-" + session.id + "-" + key;
  const body = el("div", { class: "dns-fold-body", id, hidden: open ? null : true });
  const toggle = el("button", {
    class: "dns-fold-toggle", type: "button", "aria-expanded": open ? "true" : "false", "aria-controls": id,
    onclick: () => {
      const next = toggle.getAttribute("aria-expanded") !== "true";
      session.folds.set(key, next);
      toggle.setAttribute("aria-expanded", next ? "true" : "false");
      body.hidden = !next;
    },
  },
    el("span", { class: "dns-fold-chev", "aria-hidden": "true" }, "▸"),
    el("span", { class: "dns-fold-text" },
      el("span", { class: "dns-fold-title" }, title),
      summary ? el("span", { class: "dns-fold-sum" }, summary) : null));
  toggle.dataset.expandKey = "fold-" + key;
  const root = el("section", { class: "dns-check-section dns-fold" },
    el("div", { class: "dns-fold-head" }, toggle, side || null),
    body);
  return { root, body };
}

// The time of a check, in the page's language. A clock time cannot go stale on an open page, as "2 min ago" would.
function dnsCheckWhen(value) {
  const date = new Date(value || "");
  if (!value || isNaN(date.getTime())) return value || "";
  const lang = (document.documentElement && document.documentElement.lang) || undefined;
  if (date.toDateString() === new Date().toDateString()) return date.toLocaleTimeString(lang, { hour: "2-digit", minute: "2-digit" });
  return date.toLocaleString(lang, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
}
function dnsCheckTable(labels, className) {
  const body = el("tbody");
  const table = el("table", { class: "dns-check-table" + (className ? " " + className : "") },
    el("thead", {}, el("tr", {}, ...labels.map(label => el("th", { scope: "col" }, label)))), body);
  return { table, body, labels };
}
function dnsCheckRow(spec, cells, className) {
  const row = el("tr", { class: className || "" });
  cells.forEach((cell, i) => row.appendChild(el("td", { "data-label": spec.labels[i] || "" }, cell)));
  spec.body.appendChild(row);
  return row;
}
function dnsCheckPath(path) {
  const p = path || {};
  const kind = dnsCheckText(DNS_CHECK_PATH_TEXT, p.kind || "unknown");
  const generic = p.kind === "wan" || p.kind === "router";
  const primary = (!generic && p.label) || p.iface || kind;
  const parts = [primary];
  if (p.iface && p.iface !== primary) parts.push(p.iface);
  if (kind !== primary && p.kind) parts.push(kind);
  return parts.join(" · ");
}
function dnsCheckAddress(address, port) {
  const a = String(address || "");
  if (!port) return a || t("not reported");
  return (a.includes(":") && !a.startsWith("[") ? "[" + a + "]" : a) + ":" + port;
}
function dnsCheckStatusClass(status) {
  return status === "pass" ? "ok" : status === "warn" ? "warn" : status === "fail" ? "err" : "muted";
}
function dnsCheckStatusPill(status) {
  const key = String(status || "unknown");
  const entry = DNS_CHECK_STATUS_TEXT[key] || { label: key, text: key };
  return el("span", { class: "pill " + dnsCheckStatusClass(key), title: t(entry.text) }, t(entry.label));
}
function dnsCheckLevel(level) {
  const key = String(level || "unknown");
  const entry = DNS_CHECK_LEVEL_TEXT[key] || { label: key, text: key };
  return { label: t(entry.label), text: t(entry.text) };
}
function dnsCheckVerdict(verdict) {
  const key = String(verdict || "unknown");
  const entry = DNS_CHECK_VERDICT_TEXT[key] || { label: key, text: key };
  const cls = key === "genuine" ? "ok" : key === "forged" ? "err" : key === "partial" ? "warn" : "muted";
  return { pill: el("span", { class: "pill " + cls, title: t(entry.text) }, t(entry.label)), text: t(entry.text), cls };
}

function dnsCheckReport(session, st, report) {
  const out = el("div", { class: "dns-check-report" });
  out.appendChild(dnsCheckLadder(session, st, report));
  out.appendChild(dnsCheckWarnings(report));
  out.appendChild(dnsCheckOptions(session, report));
  out.appendChild(dnsCheckWhere(session, report));
  out.appendChild(dnsCheckResolvers(session, report));
  out.appendChild(dnsCheckEncrypted(session, report));
  const demo = dnsCheckDemo(session, st, report);
  if (demo) out.appendChild(demo);
  return out;
}

function dnsCheckLadder(session, st, report) {
  const section = el("section", { class: "dns-check-section dns-verdict" },
    el("div", { class: "dns-verdict-head" },
      el("h3", { class: "dns-check-heading" }, t("Who can read your lookups")),
      dnsCheckStamp(session, st, report)));
  const rungs = ["provider_plain", "tunnel_plain", "provider_encrypted", "tunnel_encrypted"];
  const reached = rungs.indexOf(report.level);
  // On a phone only the current rung is drawn; this says how far up the ladder it is.
  section.appendChild(el("div", {
    class: "dns-level-bar " + (report.level === "tunnel_encrypted" ? "ok" : report.level === "provider_plain" ? "err" : "warn"), "aria-hidden": "true",
  }, ...rungs.map((_, i) => el("i", { class: i <= reached ? "on" : null }))));
  const ladder = el("div", { class: "dns-check-ladder" });
  ["provider_plain", "tunnel_plain", "provider_encrypted", "tunnel_encrypted"].forEach(level => {
    const text = dnsCheckLevel(level);
    const current = report.level === level;
    const cls = level === "tunnel_encrypted" ? "ok" : level === "provider_plain" ? "err" : "warn";
    ladder.appendChild(el("div", {
      class: "dns-check-rung " + cls + (current ? " current" : ""),
      "aria-current": current ? "step" : null,
    },
      el("div", { class: "dns-check-rung-title" }, text.label),
      el("div", { class: "hint" }, text.text),
      current ? el("span", { class: "pill " + cls }, t("Current")) : null));
  });
  if (!DNS_CHECK_LEVEL_TEXT[report.level] || report.level === "unknown") {
    const unknown = dnsCheckLevel(report.level || "unknown");
    ladder.appendChild(el("div", { class: "dns-check-rung unknown current", "aria-current": "step" },
      el("div", { class: "dns-check-rung-title" }, unknown.label),
      el("div", { class: "hint" }, unknown.text),
      el("span", { class: "pill muted" }, t("Current"))));
  }
  section.appendChild(ladder);
  const exposure = dnsCheckText(DNS_CHECK_EXPOSURE_TEXT, (report.path || {}).exposure || "unknown");
  section.appendChild(el("div", { class: "dns-check-exposure" }, exposure));
  return section;
}

function dnsCheckWhere(session, report) {
  const path = report.path || {};
  const rows = dnsCheckList(path.upstreams);
  const first = rows[0] ? (rows[0].address || "") : "";
  const summary = [path.answering || "", first].filter(Boolean).join(" → ") + (rows.length > 1 ? " +" + (rows.length - 1) : "");
  const fold = dnsCheckFold(session, "where", t("Where lookups go"), summary);
  const section = fold.body;
  if (path.answering) section.appendChild(el("div", { class: "hint" }, t("{0} answers devices on this router.", path.answering)));
  const upstreams = dnsCheckTable([t("Resolver"), t("Interface or tunnel"), t("Kind"), t("Notes")], "dns-check-upstreams");
  dnsCheckList(path.upstreams).forEach(up => {
    const notes = [];
    if (up.last_resort) notes.push(el("span", { class: "pill warn" }, t("Last resort")));
    if (up.via_tunnel) notes.push(el("span", { class: "pill muted" }, t("Through a tunnel")));
    if ((up.kind === "doh" || up.kind === "dot") && up.port) notes.push(el("span", { class: "pill muted" }, t("Local proxy :{0}", up.port)));
    dnsCheckRow(upstreams, [
      up.kind === "doh" || up.kind === "dot" ? (up.address || t("not reported")) : dnsCheckAddress(up.address, up.port),
      up.label || up.iface || (up.via_tunnel ? up.leaves_by : "") || (up.kind === "local" ? t("on this router") : t("Provider's line")),
      up.kind === "plain" ? t("Plain DNS") : up.kind === "local" ? t("Local") : up.kind === "doh" ? "DoH" : up.kind === "dot" ? "DoT" : (up.kind || t("not reported")),
      notes.length ? notes : "—",
    ]);
  });
  if (!dnsCheckList(path.upstreams).length) section.appendChild(el("div", { class: "hint" }, t("No upstreams were reported.")));
  else section.appendChild(upstreams.table);
  if (!path.measured) {
    section.appendChild(el("div", { class: "hint dns-check-unmeasured" }, t("Read from settings, not measured.")));
  } else {
    if (path.sample_sec) section.appendChild(el("div", { class: "hint" }, t("Flows measured over {0} seconds.", path.sample_sec)));
    const flows = dnsCheckTable([t("Resolver"), t("Path"), t("Protocol"), t("Lookups"), t("Replies"), t("Test")], "dns-check-flows");
    dnsCheckList(path.flows).forEach(flow => {
      dnsCheckRow(flows, [
        dnsCheckAddress(flow.server, flow.port),
        dnsCheckPath({ iface: flow.iface, kind: flow.kind }),
        String(flow.proto || "").toUpperCase() || t("not reported"),
        String(flow.flows || 0),
        String(flow.replied || 0),
        flow.from_canary ? el("span", { class: "pill ok" }, t("Test lookup")) : "—",
      ]);
    });
    if (!dnsCheckList(path.flows).length) section.appendChild(el("div", { class: "hint" }, t("No DNS flows were measured.")));
    else section.appendChild(flows.table);
  }
  const own = dnsCheckList(path.own_resolv_conf);
  if (own.length) section.appendChild(el("div", { class: "hint dns-check-own" },
    t("The router's own lookups use {0} and stay plain on purpose so it can find its tunnels after a reboot.", own.join(", "))));
  return fold.root;
}

function dnsCheckWarnings(report) {
  const rank = { critical: 0, warn: 1, info: 2 };
  const warnings = dnsCheckList(report.warnings).slice().sort((a, b) => {
    const ar = rank[a.severity] == null ? 3 : rank[a.severity];
    const br = rank[b.severity] == null ? 3 : rank[b.severity];
    return ar - br;
  });
  if (!warnings.length) return el("div", { class: "hint dns-check-none" }, t("No warnings were reported."));
  const section = dnsCheckSection(t("Warnings"));
  warnings.forEach(warning => {
    const severity = String(warning.severity || "unknown");
    const cls = severity === "critical" ? "err" : severity === "warn" ? "warn" : "muted";
    const facts = dnsCheckList(warning.facts);
    const sentence = dnsCheckText(DNS_CHECK_WARN_TEXT, warning.id, facts);
    section.appendChild(el("div", { class: "dns-check-warning " + cls },
      el("div", {},
        el("span", { class: "pill " + cls }, dnsCheckText(DNS_CHECK_SEVERITY_TEXT, severity)), " ",
        el("span", {}, sentence)),
      !DNS_CHECK_WARN_TEXT[warning.id] && facts.length ? el("div", { class: "hint" }, facts.join(" · ")) : null));
  });
  return section;
}

function dnsCheckOptions(session, report) {
  const options = dnsCheckList(report.options).slice().sort((a, b) => Number(!!b.recommended) - Number(!!a.recommended));
  if (!options.length) return el("div", { class: "hint dns-check-none" }, t("No changes are suggested by this report."));
  const section = dnsCheckSection(t("What you can do"));
  options.forEach(option => {
    const copy = DNS_CHECK_OPTION_TEXT[option.id] || { title: String(option.id || "unknown"), gives: "", cost: "" };
    const note = el("div", { class: "hint dns-check-action-note", role: "status" });
    const action = option.action || {};
    let button;
    if (action.kind === "chain") {
      button = el("button", { class: option.recommended ? "btn btn-primary btn-sm" : "btn btn-sm", "aria-label": t("Review resolver chain") + ": " + t(copy.title),
        onclick: () => dnsCheckOpenChain(action, note, button) }, t("Review resolver chain"));
    } else if (action.kind === "section") {
      button = el("button", { class: option.recommended ? "btn btn-primary btn-sm" : "btn btn-sm", "aria-label": t("Open setting") + ": " + t(copy.title),
        onclick: () => dnsCheckOpenSection(action.target, note) }, t("Open setting"));
    } else {
      button = el("button", { class: "btn btn-sm", disabled: true }, action.kind && action.kind !== "none" ? String(action.kind) : t("No control available"));
    }
    const row = el("div", { class: "dns-check-option" + (option.recommended ? " recommended" : "") },
      el("div", { class: "dns-check-option-main" },
        el("div", { class: "dns-check-option-title" }, t(copy.title),
          option.recommended ? el("span", { class: "pill ok" }, t("Recommended")) : null),
        copy.gives ? el("div", {}, t(copy.gives)) : null,
        option.gives ? el("div", { class: "hint" }, t("Reaches: {0}", dnsCheckLevel(option.gives).label)) : null,
        copy.cost ? el("div", { class: "hint" }, t("Cost: {0}", t(copy.cost))) : null,
        dnsCheckList(option.facts).length ? el("div", { class: "hint" }, dnsCheckList(option.facts).join(" · ")) : null,
        note),
      el("div", { class: "acts" }, button));
    section.appendChild(row);
  });
  return section;
}

function dnsCheckOpenSection(targetId, note) {
  const target = document.getElementById(targetId || "");
  if (!target) {
    note.textContent = t("This control is not available on this page yet.");
    return;
  }
  const reduced = typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
  target.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "start" });
  target.classList.add("dns-check-target");
  const hadTabindex = target.hasAttribute("tabindex");
  if (!hadTabindex) target.setAttribute("tabindex", "-1");
  target.focus({ preventScroll: true });
  setTimeout(() => {
    target.classList.remove("dns-check-target");
    if (!hadTabindex) target.removeAttribute("tabindex");
  }, 1800);
}

async function dnsCheckOpenChain(action, note, button) {
  button.disabled = true;
  try {
    const nat = await api.get("/api/dns/native");
    if (button && button.isConnected === false) return;
    const base = nat && nat.chain;
    const chain = Object.assign({ editable: false, managed: false, vias: [], reason: "" }, base || {}, {
      rows: dnsCheckList(action.rows).map(row => ({ address: row.address || "", port: row.port || 0, via: row.via || "", iface: row.iface || "" })),
      vias: dnsCheckChainVias(action, base),
    });
    const editor = el("div", {});
    if (!chain.editable) editor.appendChild(el("div", { class: "hint qp-warn" },
      t("The resolver chain cannot be edited here: {0}", chain.reason || t("this router has no editable native DNS chain"))));
    dnsChainEditor(editor, chain, (nat && nat.serve_clients) || {});
    const back = modal({
      title: t("Review the resolver chain"), body: editor,
      footer: el("button", { class: "btn", onclick: () => back.close() }, t("Close")),
    });
  } catch (e) {
    note.textContent = t("Could not open the resolver chain: {0}", dnsCheckError(e));
  } finally {
    button.disabled = false;
  }
}

// Off a router the demo still opens the proposed rows. Supplying the profile's exits keeps their
// tunnel selections visible; the existing Review control stays disabled when the chain is not editable.
function dnsCheckChainVias(action, base) {
  const out = dnsCheckList(base && base.vias).slice();
  const seen = new Set(out.map(v => v.id));
  const add = (id, kind) => {
    if (!id || seen.has(id)) return;
    seen.add(id);
    out.push({ id, name: nameOf(id) || id, kind, ifaces: [] });
  };
  const profile = (typeof state !== "undefined" && state.profile) || {};
  dnsCheckList(profile.endpoints).forEach(endpoint => add(endpoint.id, "endpoint"));
  dnsCheckList(profile.groups).forEach(group => add(group.id, "group"));
  dnsCheckList(action.rows).forEach(row => add(row.via, "endpoint"));
  return out;
}

// What the identity check found, as the line the fold shows when closed.
function dnsCheckResolverSummary(report) {
  if (!report.full) return el("span", { class: "pill muted" }, t("Not checked yet"));
  const rows = dnsCheckList(report.resolvers);
  const count = (verdict) => rows.filter(row => row.verdict === verdict).length;
  const failed = count("forged");
  const other = rows.length - failed - count("genuine");
  return [
    failed ? el("span", { class: "pill err" }, t("Failed: {0}", failed)) : null,
    dnsCheckList(report.interception).some(result => result.intercepted) ? el("span", { class: "pill err" }, t("Intercepted")) : null,
    count("genuine") ? el("span", { class: "pill ok" }, t("Genuine: {0}", count("genuine"))) : null,
    other ? el("span", { class: "pill muted" }, t("Other: {0}", other)) : null,
  ];
}

function dnsCheckResolvers(session, report) {
  const busy = session.starting || !!((session.state || {}).running);
  const bad = dnsCheckList(report.resolvers).some(row => row.verdict === "forged") || dnsCheckList(report.interception).some(result => result.intercepted);
  const run = el("button", {
    class: report.full ? "btn btn-sm" : "btn btn-primary btn-sm", disabled: busy ? true : null,
    onclick: () => { if (session.folds) session.folds.set("resolvers", true); dnsCheckStart(session, true); },
  }, busy ? t("Checking…") : t("Check resolvers"));
  // A failed check does not wait to be opened.
  const fold = dnsCheckFold(session, "resolvers", t("Are these resolvers real?"), dnsCheckResolverSummary(report), bad, run);
  const section = fold.body;
  section.appendChild(el("div", { class: "hint" }, t("Identity checks ask who answered; they do not compare addresses between paths.")));
  const canary = el("input", { type: "checkbox", id: "dns-check-canaries" });
  canary.checked = !!session.canaries;
  canary.onchange = () => { session.canaries = canary.checked; };
  const extra = el("textarea", {
    id: "dns-check-extra", rows: "3", placeholder: t("one name per line"),
    "aria-label": t("Extra names to test (up to 10)"),
  });
  extra.value = session.extraNames;
  extra.oninput = () => { session.extraNames = extra.value; };
  canary.disabled = busy;
  extra.disabled = busy;
  section.appendChild(el("div", { class: "dns-check-controls" },
    el("label", { class: "check", for: "dns-check-canaries" }, canary,
      el("span", {}, t("Also test popular blocked names on the provider's line (your provider will see these lookups)"))),
    el("div", { class: "field dns-check-extra" }, el("label", { for: "dns-check-extra" }, t("Extra names to test (up to 10)")), extra)));
  if (!report.full) {
    section.appendChild(el("div", { class: "hint" }, t("Resolver identity has not been checked yet. Choose any extra tests above, then press Check resolvers.")));
    return fold.root;
  }
  if (report.full_at) section.appendChild(el("div", { class: "hint" }, t("Resolvers checked {0}", dnsCheckWhen(report.full_at))));
  const interception = dnsCheckList(report.interception);
  section.appendChild(el("h4", { class: "dns-check-subheading" }, t("Interception by path")));
  if (!interception.length) {
    section.appendChild(el("div", { class: "hint" }, t("No interception results were returned.")));
  } else {
    interception.forEach(result => {
      const code = result.status === "pass" ? t("Nothing answered at addresses with no DNS service: no interception seen.") : dnsCheckText(DNS_CHECK_CODE_TEXT, result.code);
      section.appendChild(el("div", { class: "dns-check-interception" },
        el("div", { class: "dns-check-interception-head" },
          el("strong", {}, dnsCheckPath(result.path)), dnsCheckStatusPill(result.status),
          result.intercepted ? el("span", { class: "pill err" }, t("Intercepted")) : null),
        el("div", {}, code),
        result.detail ? el("code", { class: "dns-check-detail" }, result.detail) : null));
    });
  }
  const resolvers = dnsCheckList(report.resolvers);
  if (!resolvers.length) {
    section.appendChild(el("div", { class: "hint" }, t("No resolver results were returned.")));
    return fold.root;
  }
  const table = dnsCheckTable([t("Resolver"), t("Path"), t("Verdict"), t("RTT"), t("Site"), t("Probes")], "dns-check-resolvers-table");
  resolvers.forEach((result, index) => {
    const verdict = dnsCheckVerdict(result.verdict);
    if (result.path && result.path.kind === "router") {
      if (result.verdict === "forged") verdict.text = t("Answers this router hands to devices failed a check.");
      if (result.verdict === "unknown_operator") verdict.text = t("This is what devices get from the router; nothing wrong was found.");
    }
    const address = result.address || t("not reported");
    const path = dnsCheckPath(result.path);
    const probeId = "dns-check-probes-" + session.id + "-" + index;
    const key = dnsCheckExpandedKey(result.address, result.path);
    const expand = el("button", {
      class: "btn btn-sm", "aria-expanded": "false", "aria-controls": probeId,
      "aria-label": t("Show probes for {0} on {1}", address, path),
    }, t("Show probes"));
    expand.dataset.expandKey = key;
    const main = dnsCheckRow(table, [
      el("span", {}, el("span", { class: "dns-check-address" }, address),
        result.operator ? el("span", { class: "hint" }, " " + result.operator) : null),
      path,
      el("span", { title: verdict.text }, verdict.pill),
      result.rtt_ms ? t("{0} ms", result.rtt_ms) : "—",
      result.site || "—",
      expand,
    ], "dns-check-result " + verdict.cls);
    const probes = dnsCheckList(result.probes);
    const details = el("div", { class: "dns-check-probes", id: probeId },
      el("div", { class: "hint" }, verdict.text));
    if (!probes.length) details.appendChild(el("div", { class: "hint" }, t("No individual probe results were returned.")));
    probes.forEach(probe => {
      const status = DNS_CHECK_STATUS_TEXT[probe.status] || { label: String(probe.status || "unknown"), text: String(probe.status || "unknown") };
      // A passed probe needs only its name: "this check passed" under a green pill says nothing.
      const passed = probe.status === "pass";
      const ms = probe.ms ? t("{0} ms", probe.ms) : "";
      const names = probe.id === "canary" && /^\d+\/\d+$/.test(probe.detail || "");
      details.appendChild(el("div", { class: "dns-check-probe" },
        el("div", { class: "dns-check-probe-head" }, dnsCheckStatusPill(probe.status),
          el("strong", {}, dnsCheckText(DNS_CHECK_PROBE_TEXT, probe.id))),
        passed ? null : el("div", {}, dnsCheckText(DNS_CHECK_CODE_TEXT, probe.code)),
        passed ? (ms ? el("div", { class: "hint" }, ms) : null) : el("div", { class: "hint" }, t(status.text), ms ? " · " + ms : ""),
        names ? el("div", { class: "hint" }, t("Names verified: {0}", probe.detail))
          : probe.detail ? el("div", { class: "dns-check-raw" }, el("span", { class: "hint" }, t("Raw detail: ")), el("code", {}, probe.detail)) : null));
    });
    const probeRow = el("tr", { class: "dns-check-probes-row", hidden: true },
      el("td", { colspan: "6", "data-label": t("Probes") }, details));
    if (!session.expanded) session.expanded = new Set();
    const isOpen = session.expanded.has(key);
    probeRow.hidden = !isOpen;
    if (isOpen) {
      expand.setAttribute("aria-expanded", "true");
      expand.setAttribute("aria-label", t("Hide probes for {0} on {1}", address, path));
      expand.textContent = t("Hide probes");
    }
    table.body.appendChild(probeRow);
    expand.onclick = () => {
      const open = probeRow.hidden;
      probeRow.hidden = !open;
      if (!session.expanded) session.expanded = new Set();
      if (open) {
        session.expanded.add(key);
      } else {
        session.expanded.delete(key);
      }
      expand.setAttribute("aria-expanded", String(open));
      expand.setAttribute("aria-label", t(open ? "Hide probes for {0} on {1}" : "Show probes for {0} on {1}", address, path));
      expand.textContent = t(open ? "Hide probes" : "Show probes");
    };
    if (session._focusedKey === key && typeof expand.focus === "function") {
      expand.focus();
    }
    // Keep the expander tied to its own row even when a newer daemon reorders results.
    main.dataset.dnsResolver = address;
  });
  section.appendChild(table.table);
  return fold.root;
}

function dnsCheckEncrypted(session, report) {
  const results = dnsCheckList(report.encrypted);
  const working = results.filter(result => result.status === "pass").length;
  const summary = !report.full ? el("span", { class: "pill muted" }, t("Not checked yet"))
    : results.length ? el("span", { class: working ? "pill ok" : "pill warn" }, t("Working: {0} of {1}", working, results.length)) : null;
  const fold = dnsCheckFold(session, "encrypted", t("Encrypted transports"), summary);
  const section = fold.body;
  section.appendChild(el("div", { class: "hint" }, t("These results decide which encrypted upgrades are possible.")));
  if (!report.full) {
    section.appendChild(el("div", { class: "hint" }, t("Encrypted transports are tested by Check resolvers.")));
    return fold.root;
  }
  if (!results.length) {
    section.appendChild(el("div", { class: "hint" }, t("No encrypted transport results were returned.")));
    return fold.root;
  }
  const groups = [];
  results.forEach(result => {
    const path = result.path || {};
    let group = groups.find(g => g.path.kind === path.kind && g.path.iface === path.iface && g.path.label === path.label);
    if (!group) { group = { path, results: [] }; groups.push(group); }
    group.results.push(result);
  });
  groups.forEach(group => {
    section.appendChild(el("h4", { class: "dns-check-subheading" }, dnsCheckPath(group.path)));
    const table = dnsCheckTable([t("Resolver"), t("Transport"), t("Result"), t("RTT"), t("Certificate name")], "dns-check-encrypted-table");
    group.results.forEach(result => {
      const status = result.status === "pass" ? t("Works") : result.status === "no_data" ? t("No answer")
        : (DNS_CHECK_STATUS_TEXT[result.status] ? t(DNS_CHECK_STATUS_TEXT[result.status].label) : String(result.status || "unknown"));
      dnsCheckRow(table, [
        result.address || t("not reported"),
        String(result.proto || "").toUpperCase() || t("not reported"),
        el("span", { class: "dns-check-transport-status", title: result.detail || "" }, dnsCheckStatusPill(result.status), " ", status),
        result.rtt_ms ? t("{0} ms", result.rtt_ms) : "—",
        result.cert_name || "—",
      ]);
    });
    section.appendChild(table.table);
  });
  return fold.root;
}

// When this report was taken, and the way to take another: after changing the chain, this is how it catches up.
function dnsCheckStamp(session, st, report) {
  const when = dnsCheckWhen(report.finished_at);
  return el("div", { class: "dns-check-stamp" },
    el("span", {}, when ? t("Checked {0}", when) : t("Check time not reported.")),
    el("button", { class: "btn btn-sm", disabled: (session.starting || st.running) ? true : null, onclick: () => dnsCheckStart(session, false) }, t("Check the DNS path")));
}

function dnsCheckDemo(session, st, report) {
  const footer = el("footer", { class: "dns-check-footer hint" });
  const scenarios = dnsCheckList(st.scenarios);
  if (report.demo && scenarios.length) {
    const select = el("select", { "aria-label": t("Demo scenario") },
      ...scenarios.map(name => el("option", { value: name }, name)));
    select.value = report.scenario || session.scenario || scenarios[0];
    select.onchange = () => {
      session.scenario = select.value;
      session.autoStarted = true;
      dnsCheckRead(session);
    };
    footer.appendChild(el("label", { class: "field dns-check-scenario" }, el("span", {}, t("Demo scenario")), select));
    return footer;
  }
  return null;
}

// ── Encrypted resolver quick list ──────────────────────────────────────────────────────────────
const DNS_FAST_STATUS_TEXT = {
  ok: L("Answered"),
  bad_cert: L("The certificate did not match this resolver."),
  timeout: L("No answer: the connection timed out."),
  refused: L("No answer: the connection was refused or reset."),
  bad_answer: L("The resolver returned an invalid or empty DNS answer."),
  other: L("The transport check failed."),
};
const DNS_FAST_FILTER_TEXT = {
  none: L("No filtering"),
  ads: L("Blocks ads"),
  malware: L("Blocks malware"),
  family: L("Family"),
};

let dnsFastSession = null;
let dnsFastSerial = 0;

let dnsFastLastVia = ""; // the way out chosen, kept across the page's re-renders
function dnsFastStop() {
  if (!dnsFastSession) return;
  if (dnsFastSession.timer != null) clearTimeout(dnsFastSession.timer);
  dnsFastSession = null;
}
if (typeof window !== "undefined") window.addEventListener("hashchange", dnsFastStop);
function dnsFastActive(session) {
  if (dnsFastSession !== session) return false;
  // The view is attached only after renderDNS returns; an initially detached card is not a left page.
  if (session.card.isConnected) session.mounted = true;
  return !session.mounted || session.card.isConnected;
}
function dnsFastSchedule(session) {
  if (!dnsFastActive(session) || session.timer != null) return;
  session.timer = setTimeout(() => {
    session.timer = null;
    dnsFastRead(session);
  }, 1000);
}
function dnsFastList(value) { return Array.isArray(value) ? value : []; }
function dnsFastBadCert(result) {
  return !!result && dnsFastList(result.transports).some(transport => transport && transport.status === "bad_cert");
}
function dnsFastViaLabel(session) {
  const vias = dnsFastList(session.state && session.state.vias);
  const via = vias.find(item => item && item.id === session.via) || {};
  const reportPath = session.state && session.state.report && session.state.report.path;
  return via.label || (reportPath && reportPath.label) || session.via || t("not reported");
}

function dnsFastCard(view, nat) {
  dnsFastStop();
  const viaSelect = el("select", { id: "dns-fast-via", "aria-label": t("Measure through") });
  const measure = el("button", { class: "btn btn-sm", type: "button" }, t("Measure again"));
  const progressFill = el("span", { class: "dns-fast-progress-fill" });
  const progress = el("div", { class: "dns-fast-progress", role: "status", "aria-label": t("Measuring encrypted resolvers") }, progressFill);
  const summary = el("div", { class: "hint dns-fast-summary", title: t("Ping is one lookup over an open encrypted connection.") });
  const providerNote = el("div", { class: "hint dns-fast-provider" });
  const body = el("div", { class: "dns-fast-body" });
  const card = el("section", { class: "card dns-fast", id: "dns-fast" },
    el("div", { class: "card-head dns-fast-head" },
      el("div", { class: "card-title" }, t("Encrypted DNS")),
      el("div", { class: "acts dns-fast-controls" },
        el("label", { class: "dns-fast-via", for: "dns-fast-via" }, el("span", {}, t("Measure through")), viaSelect),
        measure)),
    progress, summary, providerNote, body);
  const session = {
    id: ++dnsFastSerial, view, nat, card, body, viaSelect, measure, progress, progressFill, summary, providerNote,
    via: dnsFastLastVia, state: null, timer: null, loading: false, starting: false, autoChecked: false, measureRequested: false,
    filter: "all", expanded: new Set(), noAnswerOpen: false, error: "", optionSignature: "",
  };
  dnsFastSession = session;
  viaSelect.onchange = () => {
    session.via = viaSelect.value;
    dnsFastLastVia = session.via;
    session.measureRequested = true;
    session.autoChecked = true;
    session.error = "";
    session.state = Object.assign({}, session.state, { report: null, running: false });
    dnsFastDraw(session);
    dnsFastRead(session);
  };
  measure.onclick = () => dnsFastStart(session);
  dnsFastDraw(session);
  dnsFastRead(session);
  return card;
}

async function dnsFastRead(session) {
  if (!dnsFastActive(session) || session.loading) return;
  if (session.timer != null) { clearTimeout(session.timer); session.timer = null; }
  session.loading = true;
  dnsFastSyncHead(session);
  const asked = session.via;
  let next;
  try {
    next = await api.get("/api/dns/fast?via=" + encodeURIComponent(session.via || ""));
  } catch (e) {
    session.loading = false;
    if (!dnsFastActive(session)) return;
    session.error = t("Could not measure encrypted resolvers: {0}", dnsCheckError(e));
    dnsFastDraw(session);
    return;
  }
  session.loading = false;
  if (!dnsFastActive(session)) return;
  if (asked !== session.via) { dnsFastRead(session); return; }
  session.state = next || {};
  const vias = dnsFastList(session.state.vias);
  if (session.via && !vias.some(item => item && item.id === session.via)) session.via = "";
  if (!session.via) session.via = session.state.default || (vias[0] && vias[0].id) || "direct";
  session.error = "";
  dnsFastDraw(session);
  if (!vias.length) return;
  if (session.state.running) {
    session.autoChecked = true;
    session.measureRequested = false;
    dnsFastSchedule(session);
    return;
  }
  const report = session.state.report;
  const finished = report && Date.parse(report.finished_at || "");
  const stale = !!(report && finished && Date.now() - finished > 3600000);
  const owed = !!session.owedMeasure && !session.state.running;
  if (owed) session.owedMeasure = false;
  const chosenNeedsReport = owed || (session.measureRequested && !report);
  const openingNeedsReport = !session.autoChecked && session.via !== "direct" && (!report || stale);
  session.autoChecked = true;
  session.measureRequested = false;
  if (chosenNeedsReport || openingNeedsReport) await dnsFastStart(session);
}

async function dnsFastStart(session) {
  if (!dnsFastActive(session) || session.starting || session.loading) return;
  if (!dnsFastList(session.state && session.state.vias).length) return;
  if (session.timer != null) { clearTimeout(session.timer); session.timer = null; }
  session.starting = true;
  session.error = "";
  dnsFastDraw(session);
  let conflict = false;
  try { await api.post("/api/dns/fast", { via: session.via }); }
  catch (e) {
    conflict = !!(e && e.status === 409);
    if (conflict) session.owedMeasure = true;
    if (!conflict) session.error = t("Could not start the resolver measurement: {0}", dnsCheckError(e));
  }
  session.starting = false;
  if (!dnsFastActive(session)) return;
  if (!session.error || conflict) {
    session.state = Object.assign({}, session.state, { running: true });
    dnsFastDraw(session);
    dnsFastSchedule(session);
  } else dnsFastDraw(session);
}

function dnsFastSyncHead(session) {
  const st = session.state || {};
  const vias = dnsFastList(st.vias);
  const signature = JSON.stringify(vias.map(via => [via && via.id, via && via.label, via && via.iface]));
  if (signature !== session.optionSignature) {
    session.optionSignature = signature;
    session.viaSelect.textContent = "";
    vias.forEach(via => {
      if (!via) return;
      const suffix = via.iface ? " (" + via.iface + ")" : "";
      const name = via.id === "direct" ? t("Provider") : (via.label || via.id || "");
      session.viaSelect.appendChild(el("option", { value: via.id || "" }, name + (via.iface && name.includes(via.iface) ? "" : suffix)));
    });
  }
  session.viaSelect.value = session.via;
  const busy = session.starting || session.loading || !!st.running;
  session.viaSelect.disabled = busy || !vias.length;
  session.measure.disabled = busy || !vias.length;
  session.progress.hidden = !busy;
  const progress = st.progress || {};
  const percent = progress.total > 0 ? Math.max(2, Math.min(100, 100 * (progress.done || 0) / progress.total)) : 100;
  session.progressFill.setAttribute("style", "width:" + percent + "%");
  session.progressFill.classList.toggle("indeterminate", !(progress.total > 0));
  const label = dnsFastViaLabel(session);
  if (busy) {
    session.summary.textContent = t("Measuring through {0}…", label);
  } else {
    const report = st.report || {};
    const finished = Date.parse(report.finished_at || "");
    const ago = finished ? fmtWhen(finished) : t("time not reported");
    session.summary.textContent = st.report
      ? t("Measured through {0}, {1}.", label, ago)
      : t("No measurement through {0} yet.", label);
  }
  session.providerNote.textContent = session.via === "direct"
    ? t("Your provider sees which resolvers are tried, not what is asked.") : "";
  session.providerNote.hidden = session.via !== "direct";
}

const DNS_FAST_TOP = 8;

function dnsFastDraw(session) {
  if (!dnsFastActive(session)) return;
  dnsFastSyncHead(session);
  let focusKey = "";
  if (typeof document !== "undefined" && document.activeElement && typeof session.body.contains === "function"
    && session.body.contains(document.activeElement)) {
    focusKey = document.activeElement.getAttribute("data-fast-focus") || "";
  }
  session.body.textContent = "";
  if (session.error) session.body.appendChild(el("div", { class: "hint qp-warn", role: "alert" }, session.error));
  if (!session.state) {
    if (!session.error) session.body.appendChild(el("div", { class: "hint", role: "status" }, t("Reading encrypted resolvers…")));
    return;
  }
  const steps = dnsFastSteps(session);
  if (steps) session.body.appendChild(steps);
  const report = session.state.report;
  if (report && report.certs_unreliable) {
    session.body.appendChild(el("div", { class: "dns-fast-clock", role: "alert" },
      el("div", { class: "dns-fast-group-title" }, t("Every certificate failed")),
      el("div", { class: "hint" }, t("This points at this router's clock or missing CA certificates, not at the resolvers. Fix the time, then Measure again."))));
    return;
  }
  const rows = dnsFastRows(session);
  session.body.appendChild(dnsFastFilters(session, rows));
  const unmeasuredHost = !dnsFastList(session.state.vias).length;
  if (unmeasuredHost) session.body.appendChild(el("div", { class: "hint dns-fast-host-note" }, t("This host cannot measure")));
  const filtered = rows.filter(row => session.filter === "all" || (row.entry.filter || "") === session.filter);
  if (!filtered.length) {
    session.body.appendChild(el("div", { class: "hint dns-fast-empty" }, t("No resolvers match this filter.")));
    return;
  }
  const list = el("div", { class: "dns-fast-list" + (unmeasuredHost ? " unmeasured" : "") });
  const maxMs = Math.max(0, ...filtered.map(row => row.result && row.result.alive ? Number(row.result.ms) || 0 : 0));
  let fastestLeft = true;
  const alive = [], bad = [], silent = [], unmeasured = [];
  filtered.forEach(row => {
    row.fastest = !!(row.result && row.result.alive && fastestLeft);
    if (row.fastest) fastestLeft = false;
    row.maxMs = maxMs;
    if (unmeasuredHost || !row.result) unmeasured.push(row);
    else if (row.result.alive) alive.push(row);
    else if (dnsFastBadCert(row.result)) bad.push(row);
    else silent.push(row);
  });
  const shown = alive.concat(unmeasured);
  const limit = session.filter === "all" && !session.showAll && !unmeasured.length && shown.length > DNS_FAST_TOP;
  shown.filter((row, i) => !limit || i < DNS_FAST_TOP || dnsFastInUse(row.entry))
    .forEach(row => list.appendChild(dnsFastRow(session, row)));
  if (limit) {
    list.appendChild(el("button", {
      class: "btn btn-sm dns-fast-more", type: "button", "data-fast-focus": "more",
      onclick: () => { session.showAll = true; dnsFastDraw(session); },
    }, t("Show all {0}", shown.length)));
  }
  if (bad.length || silent.length) list.appendChild(el("div", { class: "dns-fast-separator" }));
  if (bad.length) {
    const group = el("section", { class: "dns-fast-bad-group" },
      el("div", { class: "dns-fast-group-title" }, t("Certificate did not check out")),
      el("div", { class: "hint" }, t("Something answered at this address without the certificate it should hold. Do not use it.")));
    bad.forEach(row => group.appendChild(dnsFastRow(session, row)));
    list.appendChild(group);
  }
  if (silent.length) {
    const group = el("details", { class: "dns-fast-silent-group", open: session.noAnswerOpen ? "open" : null },
      el("summary", {},
        el("span", { class: "dns-fast-group-title" }, t("No answer on this path")),
        el("span", { class: "badge" }, String(silent.length))),
      el("div", { class: "hint" }, t("This path may block these resolvers. Try another way out in Measure through.")));
    silent.forEach(row => group.appendChild(dnsFastRow(session, row)));
    group.addEventListener("toggle", () => { session.noAnswerOpen = group.open; });
    list.appendChild(group);
  }
  session.body.appendChild(list);
  if (focusKey && typeof session.body.querySelectorAll === "function") {
    const target = [...session.body.querySelectorAll("[data-fast-focus]")]
      .find(node => node.getAttribute("data-fast-focus") === focusKey);
    if (target) target.focus({ preventScroll: true });
  }
}

function dnsFastRows(session) {
  const catalog = dnsFastList(session.state.catalog).filter(Boolean);
  const byID = new Map(catalog.map(entry => [entry.id, entry]));
  const report = session.state.report;
  if (!report) return catalog.map(entry => ({ entry, result: null }));
  const used = new Set();
  const rows = dnsFastList(report.results).filter(Boolean).map(result => {
    used.add(result.id);
    const entry = byID.get(result.id) || { id: result.id || "", name: result.id || "", filter: "", ip: "", host: "" };
    return { entry, result };
  });
  catalog.forEach(entry => { if (!used.has(entry.id)) rows.push({ entry, result: null }); });
  return rows;
}

function dnsFastFilters(session, rows) {
  const bar = el("div", { class: "dns-fast-filters", role: "group", "aria-label": t("Filter resolvers") });
  const choices = [["all", L("All")], ["none", DNS_FAST_FILTER_TEXT.none], ["ads", DNS_FAST_FILTER_TEXT.ads],
    ["malware", DNS_FAST_FILTER_TEXT.malware], ["family", DNS_FAST_FILTER_TEXT.family]];
  choices.forEach(([id, label]) => {
    const count = id === "all" ? rows.length : rows.filter(row => (row.entry.filter || "") === id).length;
    const button = el("button", {
      class: "btn btn-sm dns-fast-filter" + (session.filter === id ? " on" : ""), type: "button",
      "aria-pressed": session.filter === id ? "true" : "false", "data-fast-focus": "filter-" + id,
      onclick: () => { session.filter = id; dnsFastDraw(session); },
    }, el("span", {}, t(label)), el("span", { class: "dns-fast-count" }, String(count)));
    bar.appendChild(button);
  });
  return bar;
}

function dnsFastToggle(session, id) {
  if (session.expanded.has(id)) session.expanded.delete(id);
  else session.expanded.add(id);
  dnsFastDraw(session);
}

function dnsFastRow(session, row) {
  const entry = row.entry || {}, result = row.result;
  const unmeasuredHost = !dnsFastList(session.state.vias).length;
  const bad = dnsFastBadCert(result);
  const status = result && result.alive ? "ok" : bad ? "err" : "muted";
  const statusText = result && result.alive ? t("Alive") : bad ? t("Bad certificate") : t("No answer");
  const expanded = session.expanded.has(entry.id);
  const detailID = "dns-fast-detail-" + session.id + "-" + String(entry.id || "row").replace(/[^A-Za-z0-9_-]/g, "_");
  const toggle = () => dnsFastToggle(session, entry.id);
  const country = entry.country || "";
  const filterText = dnsCheckText(DNS_FAST_FILTER_TEXT, entry.filter || "unknown");
  const main = el("div", { class: "dns-fast-main" },
    el("div", { class: "dns-fast-name-line" },
      el("button", {
        class: "dns-fast-name", type: "button", "aria-expanded": expanded ? "true" : "false", "aria-controls": detailID,
        "data-fast-focus": "name-" + entry.id, onclick: toggle,
      }, entry.name || entry.id || ""),
      row.fastest ? el("span", { class: "badge badge-ok" }, t("Fastest")) : null,
      dnsFastInUse(entry) ? el("span", { class: "badge" }, t("In use")) : null),
    el("div", { class: "dns-fast-sub" },
      country ? el("span", {}, country) : null,
      el("span", {}, filterText)));
  const chevron = el("button", {
    class: "dns-fast-chevron", type: "button", "aria-expanded": expanded ? "true" : "false", "aria-controls": detailID,
    "aria-label": expanded ? t("Hide details for {0}", entry.name || entry.id || "") : t("Show details for {0}", entry.name || entry.id || ""),
    "data-fast-focus": "chevron-" + entry.id, onclick: toggle,
  }, expanded ? "▴" : "▾");
  const children = [
    el("span", { class: "dns-fast-dot " + status, role: "img", "aria-label": statusText, title: statusText }),
    el("div", { class: "dns-fast-name-cell" }, main, chevron),
  ];
  if (!unmeasuredHost) {
    const ms = result && result.alive ? Number(result.ms) || 0 : 0;
    const ping = el("div", { class: "dns-fast-ping" },
      el("span", { class: "dns-fast-ms" }, ms ? String(ms) : "—"), ms ? el("span", { class: "dns-fast-ms-unit" }, t("ms")) : null,
      ms ? el("span", { class: "dns-fast-ping-track", "aria-hidden": "true" },
        el("span", { class: "dns-fast-ping-bar", style: "width:" + Math.max(2, Math.min(100, 100 * ms / Math.max(1, row.maxMs))) + "%" })) : null);
    children.push(ping, dnsFastTransports(entry, result, false));
    const best = result && (dnsFastList(result.transports).find(transport => transport && transport.proto === result.best && transport.status === "ok")
      || dnsFastList(result.transports).find(transport => transport && transport.status === "ok"));
    const trustTitle = best ? t("Issuer: {0}; {1} days left", best.issuer || t("not reported"), best.cert_days == null ? t("not reported") : best.cert_days) : "";
    children.push(el("div", { class: "dns-fast-trust" },
      result && result.alive ? el("span", { class: "dns-fast-cert", title: trustTitle }, t("Certificate OK")) : null,
      result && result.validates === true ? el("span", { class: "dns-fast-dnssec" }, t("DNSSEC")) : null));
    const inUse = dnsFastInUse(entry);
    children.push(el("div", { class: "dns-fast-action" }, result && result.alive ? el("button", {
      class: "btn btn-sm " + (row.fastest && !inUse ? "btn-primary" : "") + " dns-fast-use", type: "button",
      "aria-label": t("Use {0}", entry.name || entry.id || ""), "data-fast-focus": "use-" + entry.id,
      onclick: () => dnsFastUse(session, entry, result),
    }, inUse ? t("Change") : t("Use")) : null));
  }
  const wrap = el("div", {
    class: "dns-fast-row " + status + (expanded ? " expanded" : "") + (unmeasuredHost ? " unmeasured" : ""),
    "data-fast-id": entry.id || "",
    // The whole row opens its details: the name and a small arrow are a narrow target, above all on a phone.
    onclick: event => { if (!event.target.closest("button, a, input, select, .dns-fast-details")) toggle(); },
  }, ...children);
  wrap.appendChild(dnsFastDetails(session, entry, result, detailID, expanded));
  return wrap;
}

function dnsFastTransports(entry, result, details) {
  const transports = dnsFastList(result && result.transports);
  const wrap = el("div", { class: details ? "dns-fast-transports dns-fast-detail-transports" : "dns-fast-transports" });
  [["dot", "DoT"], ["doh", "DoH"]].forEach(([proto, label]) => {
    const measured = transports.find(transport => transport && transport.proto === proto);
    const supported = measured || (proto === "dot" ? entry.dot : !!entry.doh_path);
    if (!supported) return;
    const ok = measured && measured.status === "ok";
    const failed = !!result && (!measured || !ok);
    const best = ok && result.best === proto;
    const value = ok && measured.ms ? label + " " + measured.ms : label + (result ? " —" : "");
    const title = measured ? dnsCheckText(DNS_FAST_STATUS_TEXT, measured.status || "unknown") : t("Not measured");
    wrap.appendChild(el("span", {
      class: "dns-fast-transport" + (best ? " best" : "") + (failed ? " failed" : ""),
      title: title + (best ? " · " + t("Best transport") : ""),
    }, value, best ? el("span", { "aria-hidden": "true" }, " ✓") : null));
  });
  return wrap;
}

function dnsFastDetails(session, entry, result, detailID, expanded) {
  const transports = dnsFastList(result && result.transports);
  const best = transports.find(transport => transport && transport.proto === (result && result.best)) || transports[0] || {};
  const details = el("div", { class: "dns-fast-details", id: detailID, hidden: expanded ? null : "hidden" },
    el("div", { class: "dns-fast-detail-grid" },
      el("span", { class: "dns-fast-detail-label" }, t("Address")),
      el("span", { class: "dns-fast-address" }, entry.ip || "—"),
      el("span", { class: "dns-fast-detail-label" }, t("Certificate name")),
      el("span", {}, best.cert_name || entry.host || "—"),
      el("span", { class: "dns-fast-detail-label" }, t("Issuer")),
      el("span", {}, best.issuer || "—"),
      el("span", { class: "dns-fast-detail-label" }, t("Days left")),
      el("span", {}, best.cert_days == null ? "—" : String(best.cert_days)),
      el("span", { class: "dns-fast-detail-label" }, t("DNSSEC")),
      el("span", {}, result && result.validates === true ? t("Validates") : result && result.validates === false ? t("Does not validate") : "—")),
    dnsFastTransports(entry, result, true));
  const lines = el("div", { class: "dns-fast-transport-details" });
  transports.forEach(transport => {
    if (!transport) return;
    const label = transport.proto === "dot" ? "DoT" : transport.proto === "doh" ? "DoH" : String(transport.proto || "unknown");
    const status = dnsCheckText(DNS_FAST_STATUS_TEXT, transport.status || "unknown");
    lines.appendChild(el("div", { class: "dns-fast-transport-detail" },
      el("span", { class: "dns-fast-detail-proto" }, label),
      el("span", {}, status),
      el("span", {}, t("Lookup: {0}", transport.ms ? t("{0} ms", transport.ms) : "—")),
      el("span", {}, t("Connection: {0}", transport.connect_ms ? t("{0} ms", transport.connect_ms) : "—"))));
  });
  if (!transports.length) lines.appendChild(el("div", { class: "hint" }, t("Not measured")));
  details.appendChild(lines);
  return details;
}

function dnsFastDefaultServer() {
  const servers = dnsFastList(dnsState && dnsState.servers);
  if (dnsState && dnsState.final) return servers.find(server => server && server.tag === dnsState.final) || null;
  return servers[0] || null;
}
function dnsFastInUse(entry) {
  const current = dnsFastDefaultServer();
  return !!(current && entry.ip && current.server === entry.ip && /^(https|tls|quic|h3)$/.test(current.type || ""));
}

function dnsFastSteps(session) {
  const current = dnsFastDefaultServer();
  if (!current || !String(current.tag || "").startsWith("fast_")) return null;
  const nat = session.nat || {}, serve = nat.serve_clients || {}, chain = nat.chain;
  const id = String(current.tag).slice(5).replace(/_/g, "-");
  const entry = dnsFastList(session.state.catalog).find(item => item && (item.id === id || item.ip === current.server));
  const strip = el("div", { class: "dns-fast-steps", "aria-label": t("What is left to do") });
  strip.appendChild(el("div", { class: "dns-fast-step done" },
    el("span", { class: "dns-fast-step-number" }, "1"),
    el("div", {}, el("span", { class: "dns-fast-step-title" }, t("Resolver chosen")),
      el("span", { class: "hint" }, (entry && entry.name) || current.server || current.tag)),
    el("span", { class: "pill ok" }, t("Done"))));
  const applied = !profileDirty && (!serve.configured || serve.listening);
  strip.appendChild(el("div", { class: "dns-fast-step" + (applied ? " done" : "") },
    el("span", { class: "dns-fast-step-number" }, "2"),
    el("div", {}, el("span", { class: "dns-fast-step-title" }, t("Applied"))),
    applied ? el("span", { class: "pill ok" }, t("Done"))
      : profileDirty ? el("button", { class: "btn btn-sm", type: "button", onclick: () => openReviewChanges() }, t("Review & Apply"))
        : el("span", { class: "pill warn" }, t("Not listening"))));
  if (serve.configured && chain && chain.editable && (!nat.answering || nat.answering.plane !== "core")) {
    const first = dnsFastList(chain.rows)[0] || {};
    const devicesUse = first.address === "127.0.0.1" && Number(first.port) === Number(serve.port);
    const note = el("span", { class: "hint dns-fast-step-note" });
    strip.appendChild(el("div", { class: "dns-fast-step" + (devicesUse ? " done" : "") },
      el("span", { class: "dns-fast-step-number" }, "3"),
      el("div", {}, el("span", { class: "dns-fast-step-title" }, t("Devices use it")), note),
      devicesUse ? el("span", { class: "pill ok" }, t("Done")) : el("button", {
        class: "btn btn-sm", type: "button", onclick: event => dnsFastOpenChain(session, note, event.currentTarget),
      }, t("Add to resolver chain"))));
  } else if (!serve.configured || !nat.answering || nat.answering.plane !== "core") {
    strip.appendChild(el("div", { class: "dns-fast-step" },
      el("span", { class: "dns-fast-step-number" }, "3"),
      el("div", {}, el("span", { class: "dns-fast-step-title" }, t("Devices use it")),
        el("span", { class: "hint" }, !serve.configured
          ? t("Turn on answering this home's devices to use this resolver.")
          : t("This router's DNS program cannot be pointed here from the panel yet."))),
      el("span", { class: "pill warn" }, t("Not yet"))));
  }
  return strip;
}

function dnsFastOpenChain(session, note, button) {
  button.disabled = true;
  try {
    const nat = session.nat || {}, base = nat.chain || {}, serve = nat.serve_clients || {};
    const proposed = { address: "127.0.0.1", port: serve.port || 0, via: "", iface: "" };
    const chain = Object.assign({ editable: false, managed: false, vias: [], reason: "" }, base, {
      rows: [proposed].concat(dnsFastList(base.rows)
        .filter(row => !(row && row.address === proposed.address && Number(row.port) === Number(proposed.port)))
        .map(row => Object.assign({}, row))),
      vias: dnsFastList(base.vias).map(via => Object.assign({}, via, { ifaces: dnsFastList(via && via.ifaces) })),
    });
    const editor = el("div", {});
    dnsChainEditor(editor, chain, serve);
    const back = modal({
      title: t("Review the resolver chain"), body: editor,
      footer: el("button", { class: "btn", onclick: () => back.close() }, t("Close")),
    });
  } catch (e) {
    note.textContent = t("Could not open the resolver chain: {0}", dnsCheckError(e));
  } finally { button.disabled = false; }
}

function dnsFastUse(session, entry, result) {
  const measured = dnsFastList(result.transports).filter(transport => transport && transport.status === "ok");
  if (!measured.length && result.best) measured.push({ proto: result.best, status: "ok", ms: result.ms });
  if (!measured.length) return;
  const transport = el("select", { id: "dns-fast-use-transport" },
    ...measured.map(item => el("option", { value: item.proto },
      (item.proto === "dot" ? "DoT" : "DoH") + (item.ms ? " · " + t("{0} ms", item.ms) : ""))));
  transport.value = measured.some(item => item.proto === result.best) ? result.best : measured[0].proto;
  const measured0 = session.state && session.state.report;
  const detour = routingOutboundSelect(measured0 && measured0.demo ? primaryDetourGuess() : (session.via || "direct"), false);
  detour.id = "dns-fast-use-detour";
  const directWarn = el("div", { class: "hint qp-warn" }, t("The provider sees that you use this resolver, though not what you ask."));
  const syncDetour = () => { directWarn.hidden = detour.value !== "direct"; };
  detour.onchange = syncDetour;
  const serve = el("input", { type: "checkbox", id: "dns-fast-use-serve" });
  serve.checked = true;
  const error = el("div", { class: "hint qp-warn dns-fast-use-error", role: "alert" });
  const body = el("div", {},
    el("div", { class: "dns-fast-use-summary" }, entry.name || entry.id || "",
      result.ms ? el("span", { class: "badge" }, t("{0} ms", result.ms)) : null),
    el("div", { class: "field" }, el("label", { for: transport.id }, t("Transport")), transport),
    el("div", { class: "field" }, el("label", { for: detour.id }, t("Lookups leave through")), detour, directWarn),
    el("label", { class: "check", for: serve.id }, serve,
      el("span", {}, t("Answer this home's devices through it"))),
    el("div", { class: "hint" }, t("The router answers local DNS requests and forwards them here. Apply the change before devices use it.")),
    error);
  const save = el("button", { class: "btn btn-primary", type: "button" }, t("Use resolver"));
  const back = modal({
    title: t("Use {0}", entry.name || entry.id || ""), body,
    footer: [el("button", { class: "btn", type: "button", onclick: () => back.close() }, t("Cancel")), save],
  });
  // saveDNS refreshes after a rejected write. Keep this form through that same-page refresh, but not real navigation.
  if (typeof window !== "undefined") window.addEventListener("hashchange", () => back.close(), { once: true });
  syncDetour();
  save.onclick = async () => {
    if (save.disabled) return;
    save.disabled = true;
    error.textContent = "";
    // Wait for earlier edits before changing the shared plane; saveDNS remains the only writer below.
    await dnsSaveChain;
    if (back.isConnected === false) return;
    const previous = dnsState;
    const next = Object.assign({}, dnsState, { servers: dnsFastList(dnsState && dnsState.servers).slice() });
    const tag = "fast_" + String(entry.id || "resolver").replace(/[^A-Za-z0-9_]/g, "_");
    const proto = transport.value === "dot" ? "tls" : "https";
    const server = {
      tag, type: proto, server: entry.ip, sni: entry.host, detour: detour.value || "direct", enabled: true,
    };
    if (proto === "https") server.path = entry.doh_path || "/dns-query";
    const rules = dnsFastList(next.rules);
    next.servers = next.servers.filter(item => !item || !String(item.tag || "").startsWith("fast_") || item.tag === tag
      || rules.some(rule => rule && rule.server === item.tag));
    const at = next.servers.findIndex(item => item && item.tag === tag);
    if (at >= 0) next.servers[at] = server; else next.servers.push(server);
    next.enabled = true;
    next.final = tag;
    next.serve_clients = serve.checked;
    dnsState = next;
    const oldToasts = typeof document !== "undefined" && typeof document.querySelectorAll === "function"
      ? new Set([...document.querySelectorAll("#toasts .toast.err")]) : new Set();
    back.classList.add("auth-gate");
    const ok = await saveDNS(t("Resolver saved"), true);
    back.classList.remove("auth-gate");
    if (!ok) {
      if (dnsState === next) dnsState = previous;
      let message = t("Could not save the resolver.");
      if (typeof document !== "undefined" && typeof document.querySelectorAll === "function") {
        const fresh = [...document.querySelectorAll("#toasts .toast.err")].find(node => !oldToasts.has(node));
        if (fresh) message = fresh.textContent || message;
      }
      error.textContent = message;
      save.disabled = false;
      return;
    }
    back.close();
    if (typeof setTimeout === "function") setTimeout(() => {
      const card = document.getElementById("dns-fast");
      if (card) card.scrollIntoView({ block: "start" });
    }, 150);
    // Whoever chose a resolver came to start using it: its review is the next step, not a button to find.
    if (typeof openReviewChanges === "function") openReviewChanges();
  };
}

// ── Query path ────────────────────────────────────────────────────────────────────────────────
// One picture of where a lookup actually goes: a device on the LAN, the router's :53, the split that
// picks a resolver, the transport that carries it, the exit it leaves through.
//
// The page had all of this before, spread over four cards, and none of it in order. You could read
// the resolver list, the rule list and the leak widget and still not be able to answer "if my laptop
// asks for netflix.com right now, who sees the question?" — which is the only question DNS settings
// are ever changed to affect.
//
// The path has two halves and they are known in different ways, so they are drawn differently:
//
//   CONFIGURED (the fork, the transport, the detour, the exit) is read from the profile. It is always
//   known, because it is what WayHop will emit.
//   RUNTIME (who holds :53, whether LAN clients are forced through it, whether DoT is blocked) has to
//   be measured on the device. Off a router, or when the firewall could not be read, it is UNKNOWN —
//   and an unknown runtime must never be drawn as a clean path, which is the whole point of
//   RulesUnknown existing in the detector.
//
// tun is GET /api/dns's reading of the core this plane is generated into: only with TUN does it keep
// FakeIP servers.
function dnsQueryPath(nat, tun) {
  const eff = (nat && nat.effective) || null;
  const measured = !!(nat && nat.available && eff);
  const wrap = el("div", { class: "card qp", id: "dns-query-path" });
  wrap.appendChild(el("div", { class: "card-head" },
    el("div", { class: "card-title" }, t("Query path")),
    el("div", { class: "acts" },
      el("button", { class: "btn btn-sm", onclick: () => openDNSRule(null) }, t("+ Add rule")))));

  // Stage 1-2: the client and the router's :53.
  const head = el("div", { class: "qp-head" });
  head.appendChild(el("div", { class: "qp-stage" },
    el("div", { class: "qp-stage-l" }, t("LAN client")),
    el("div", { class: "qp-stage-v" }, t("any device")),
    el("div", { class: "qp-stage-s" }, t("asks for a name"))));

  const port = el("div", { class: "qp-stage" },
    el("div", { class: "qp-stage-l" }, t("Port 53 on the router")));
  if (!measured) {
    port.classList.add("unknown");
    port.appendChild(el("div", { class: "qp-stage-v" }, t("not measured")));
    port.appendChild(el("div", { class: "qp-stage-s" },
      nat && nat.available === false
        ? t("This host has no router DNS stack to inspect.")
        : t("WayHop could not read the device, so who holds :53 is unknown.")));
  } else if (eff.rules_unknown) {
    // The distinction AUD-43 exists for: an unreadable firewall is not a firewall with no rules.
    port.classList.add("unknown");
    const who = (eff.listeners || []).map(l => l.process).filter(Boolean);
    port.appendChild(el("div", { class: "qp-stage-v" }, who.length ? who[0] : t("unknown")));
    port.appendChild(el("div", { class: "qp-stage-s" },
      t("The firewall could not be read, so whether LAN DNS is forced here is unknown.")));
  } else {
    const who = (eff.listeners || []).map(l => l.process).filter(Boolean);
    port.appendChild(el("div", { class: "qp-stage-v" }, who.length ? who[0] : t("no listener seen")));
    // QA-107: on a LAN with IPv6 an IPv4-only redirect is not the whole door.
    if (eff.hijack53 && (eff.ipv6_gaps || []).includes("53")) {
      port.classList.add("warn");
      port.appendChild(el("div", { class: "qp-stage-s" }, t("LAN :53 is redirected here over IPv4 only; IPv6 is not")));
    } else if (eff.hijack53) {
      port.classList.add("ok");
      port.appendChild(el("div", { class: "qp-stage-s" }, eff.hijack53_to
        ? t("LAN :53 is redirected here ({0})", eff.hijack53_to)
        : t("LAN :53 is redirected here")));
    } else {
      port.classList.add("warn");
      port.appendChild(el("div", { class: "qp-stage-s" }, t("Clients may use their own resolver instead")));
    }
  }
  head.appendChild(port);
  wrap.appendChild(head);

  // Stage 3-6: one row per branch, in the order sing-box evaluates them.
  const rules = (dnsState.rules || []);
  const servers = (dnsState.servers || []);
  const byTag = new Map(servers.map(s => [s.tag, s]));
  const branches = el("div", { class: "qp-branches" });
  // One branch per rule, and 20 rules made this 917px of a 2260px page. Rules are ORDERED and
  // reorderable in place, so this folds rather than filters: every row keeps its position and its
  // move buttons, and a folded row is one click away rather than renumbered or hidden from the
  // ordering. The first few are the ones that decide most queries, being evaluated first.
  const QP_VISIBLE = 4;
  const qpMore = rules.length > QP_VISIBLE
    ? el("details", { class: "qp-more" },
        el("summary", { class: "hint" }, t("Show all {0} rules in order", rules.length)))
    : null;
  branches.appendChild(el("div", { class: "qp-brhead" },
    el("span", {}, "#"),
    el("span", {}, t("When the name matches")),
    el("span", {}, t("Resolver")),
    el("span", {}, t("Transport")),
    el("span", {}, t("Leaves through")),
    el("span", {}, "")));

  // Rows edit in place. The page used to carry a second card listing the same rules with the same
  // targets, so every rule was stated twice and the two could be read in different orders. The path
  // is the truth, so the path is where a rule is reordered, edited and deleted.
  //
  // Real rule rows keep the .dns-rule / .m / order-control classes the reorder gate asserts on; the
  // final catch-all deliberately does NOT, because it is not a rule and must not be counted as a
  // position that can move.
  const branchRow = (n, match, tag, isFinal) => {
    const s = byTag.get(tag);
    const row = el("div", { class: "qp-br" + (isFinal ? " final" : " dns-rule") });
    row.appendChild(el("span", { class: "qp-br-n" }, n));
    row.appendChild(el("span", { class: "qp-br-m m" }, match));
    if (tag === "reject") {
      row.appendChild(el("span", { class: "qp-br-r" }, el("span", { class: "pill err" }, t("blocked"))));
      row.appendChild(el("span", { class: "qp-br-t" }, t("answered locally, never sent")));
      row.appendChild(el("span", { class: "qp-br-e" }, "—"));
    } else if (!s) {
      // A rule pointing at a resolver that no longer exists routes nowhere; saying so beats an
      // empty cell that reads as "direct".
      row.appendChild(el("span", { class: "qp-br-r" }, el("span", { class: "pill err" }, tag || "—")));
      row.appendChild(el("span", { class: "qp-br-t" }, t("no such resolver")));
      row.appendChild(el("span", { class: "qp-br-e" }, "—"));
    } else {
      const enc = DNS_ENC_TYPES.includes(s.type);
      row.appendChild(el("span", { class: "qp-br-r" }, s.tag,
        s.enabled === false ? el("span", { class: "pill muted" }, t("off")) : null));
      row.appendChild(el("span", { class: "qp-br-t" },
        el("span", { class: "badge proto" + (enc ? " enc" : "") }, s.type),
        // A VPN's pushed resolvers are asked inside its tunnel: the WAN sees only the tunnel.
        enc ? null : DNS_VPN_TYPES[s.type] ? el("span", {}, t("via tunnel"))
          : el("span", { class: "qp-plain", title: t("Unencrypted — whoever carries it can read it") }, t("plaintext"))));
      // The detour IS the exit: an empty one means the query leaves over the raw WAN. A VPN's pushed
      // resolvers have no detour; they are asked through that connection's tunnel.
      const exit = DNS_VPN_TYPES[s.type] ? s.endpoint : s.detour;
      row.appendChild(el("span", { class: "qp-br-e" }, exit
        ? (nameOf(exit) || exit)
        : el("span", { class: "qp-wan" }, t("WAN (no tunnel)"))));
    }
    return row;
  };

  rules.forEach((r, i) => {
    const parts = (r.rule_sets || []).map(x => nameOf(x) || x)
      .concat(r.domain_suffix || [], r.domain || [], r.geosite || []);
    const match = parts.length ? parts.join(", ") : t("(no match)");
    const row = branchRow(String(i + 1), match, r.server, false);
    if (r.disabled) row.classList.add("off");
    // Exactly the controls the removed card carried, on the row they belong to.
    row.appendChild(el("span", { class: "qp-br-a" },
      // Serialize through dnsSaveChain for the reason the rule editor states: a bare PUT here
      // races a concurrent save. Rule ORDER is meaning - sing-box takes the first match - and
      // two quick arrow clicks sent two writes stamped with the same rev, so the second was
      // refused as stale and rolled back to a snapshot the first had already superseded: the
      // panel showed one order while the router enforced another. Mutating INSIDE the chain
      // operates on the latest state, and adopting r.dns keeps this path identical to every
      // other DNS write.
      orderControls(i, rules.length, "DNS rule " + match, (from, to) => {
        dnsSaveChain = dnsSaveChain.then(async () => {
          const prev = dnsState.rules.slice();
          dnsState.rules = moveInArray(dnsState.rules, from, to);
          try { const r = await dnsPut(); if (r && r.dns) dnsState = r.dns; route(); }
          catch (e) { dnsState.rules = prev; dnsWriteFailed(e); }
        });
        return dnsSaveChain;
      }),
      el("button", { class: "btn btn-sm", "aria-label": t("Edit") + " rule " + match, onclick: () => openDNSRule(i) }, t("Edit")),
      // Identity first, then by unique id — a non-rerendering saveDNS reassigns dnsState and
      // orphans the rule instance this row captured.
      el("button", { class: "btn btn-danger btn-sm", "aria-label": t("Delete") + " rule " + match,
        onclick: async () => {
          if (!await modalConfirm(t("Delete this DNS rule?"))) return;
          let idx = dnsState.rules.indexOf(r);
          if (idx < 0 && r.id) idx = dnsState.rules.findIndex(x => x && x.id === r.id);
          if (idx < 0) return;
          dnsState.rules.splice(idx, 1);
          saveDNS(t("rule ✕"), true);
        } }, t("Delete"))));
    if (qpMore && i >= QP_VISIBLE) qpMore.appendChild(row); else branches.appendChild(row);
  });
  // The fold sits between the last visible rule and the catch-all, so the catch-all stays where it
  // belongs: visually last, because it is what runs when nothing above matched.
  if (qpMore) branches.appendChild(qpMore);
  const finalRow = branchRow("★", t("everything else"), dnsAnswersAll(dnsState, tun), true);
  // The catch-all is not editable here: it is the "Default resolver" picker below, and giving it
  // move arrows would imply an order it does not have.
  finalRow.appendChild(el("span", { class: "qp-br-a" }));
  branches.appendChild(finalRow);
  if (!rules.length) {
    branches.appendChild(el("div", { class: "hint qp-norules" },
      t("No rules yet — every query takes the row above. Add one to send chosen names to a different resolver, or to block them at DNS level.")));
  }
  // With another program on :53 these rows are not the path a client's lookup takes (dnsPlaneNotice).
  if (((nat || {}).answering || {}).plane === "native") {
    wrap.appendChild(el("div", { class: "hint qp-warn" },
      t("These rows are sing-box's own lookups, not your devices'. {0} answers devices, through the upstreams in the card below.", nat.answering.process)));
  }
  wrap.appendChild(branches);

  // The escape hatch. A perfect chain above means nothing if a client can ignore all of it, and that
  // verdict is only as good as the firewall read that produced it.
  const foot = el("div", { class: "qp-foot" });
  if (!measured) {
    foot.appendChild(el("div", { class: "hint" },
      t("Whether a device can bypass all of this with its own DoH is a runtime question — run WayHop on the router to answer it.")));
  } else if (eff.rules_unknown) {
    foot.appendChild(el("div", { class: "hint qp-unknown" },
      t("⚠ The firewall could not be read, so nothing above about enforcement is confirmed.")));
  // Both, not either. This branch used to fire on the :853 signal alone under a field named for DoH,
  // and told the user nobody could route around the rows above while any browser with its own DoH
  // resolver walked straight past them. The warning below is the honest answer whenever either hatch
  // is open; the daemon's own note says which one and why.
  // IPv4 shut is not the LAN shut when the LAN has IPv6, and the DoH refusal names addresses: it
  // never meant "clients cannot route around this" (QA-107).
  } else if (eff.doh_bypass_blocked && eff.dot_bypass_blocked && (eff.ipv6_gaps || []).length) {
    foot.appendChild(el("div", { class: "hint qp-warn" },
      t("⚠ This LAN also has IPv6, but these routes are shut for IPv4 only: {0}. Over IPv6 they bypass every row above.",
        dnsIPv6Routes(eff.ipv6_gaps))));
  } else if (eff.doh_bypass_blocked && eff.dot_bypass_blocked) {
    foot.appendChild(el("div", { class: "hint qp-ok" },
      t("✓ DoT (:853) and the well-known DoH resolvers are refused, so most devices fall back to the router. DoH to any other resolver still gets through.")));
  } else {
    foot.appendChild(el("div", { class: "hint qp-warn" },
      t("⚠ A device with its own DoH or DoT resolver bypasses every row above. Nothing here blocks it.")));
  }
  wrap.appendChild(foot);
  return wrap;
}

// dnsAnswersAll names the resolver that answers what no rule matches, as the core will run it
// (model.DNSSettings.DefaultServer): the chosen default while the core keeps it, else the first server
// it keeps. A disabled server is never kept, and without TUN (fast or mixed mode) neither is a FakeIP
// one: the page showed an enabled FakeIP server at the top as the catch-all there.
function dnsAnswersAll(d, tun) {
  const runs = s => s.enabled && (tun || s.type !== "fakeip");
  const named = (d.servers || []).find(s => s.tag === d.final);
  if (d.final && (!named || runs(named))) return d.final;
  return ((d.servers || []).find(runs) || {}).tag || "";
}

// dnsIPv6Routes names the routes IPv6 leaves open (EffectivePath.IPv6Gaps). The warning said "the DNS
// redirect and refusals" for any of them, DoT alone included. Port and protocol names read the same in
// every language, so they are not translated.
function dnsIPv6Routes(gaps) {
  const name = { "53": ":53", dot: "DoT (:853)", doh: "DoH" };
  return (gaps || []).map(g => name[g] || g).join(", ");
}

// dnsPathNote says what a resolver's detour MEANS: which exit its queries leave through, and — the
// question the page could not answer — whether they may fall back to the provider when that exit is
// gone. The row showed "via X" and stopped, which reads as a setting rather than as the behaviour it
// buys: a tunnel detour hides the query but takes DNS down with the tunnel, while a failover group
// ending in `direct` keeps resolving over the raw WAN (still encrypted, but the provider sees whom
// you asked). Those are opposite trade-offs and they looked identical.
function dnsPathNote(detour) {
  detour = (detour || "").trim();
  if (detour === "" || detour === "direct") {
    return { cls: "hint", text: t("leaves through the provider — never hidden") };
  }
  const g = (state.profile.groups || []).find(x => x.id === detour);
  if (!g) {
    return { cls: "hint dns-path-strict", text: t("tied to one tunnel — DNS stops if it goes down") };
  }
  const members = g.members || [];
  const last = members[members.length - 1];
  if (last === "direct") {
    return { cls: "hint", text: t("falls back to the provider when every tunnel is down") };
  }
  return { cls: "hint dns-path-strict", text: t("no provider fallback — DNS stops if every member is down") };
}

// dnsFilterBox makes a long DNS page navigable the way Routing and Settings already are.
//
// This page opens taller than two screens on a router with real resolvers and rules on it, and the
// thing an operator arrives looking for is one row: a resolver, a domain, a switch by name. Scrolling
// past everything else to reach it is the cost a filter removes. The rule the whole page obeys is the
// one the density gate states: make the overflow navigable, never hide it behind an inner scrollbar.
//
// Typing hides non-matching ROWS, and a card left with no matching row hides with them. A card that
// carries no filterable rows at all — the query path, the leak widget — is scenery for the whole page
// rather than an answer to a search, so it steps aside while a search is active and returns intact
// when the box is cleared.
function dnsFilterBox(view) {
  const inp = el("input", {
    type: "search", placeholder: t("Filter DNS — resolver, domain or setting"),
    "aria-label": t("Filter DNS — resolver, domain or setting"),
  });
  const apply = () => {
    const q = inp.value.trim().toLowerCase();
    view.querySelectorAll(".card").forEach(card => {
      const rows = [...card.querySelectorAll(".dns-row, .dns-rule, .dns-tog, .dns-fast-row")];
      if (!q) {
        card.hidden = false;
        rows.forEach(r => { r.hidden = false; });
        return;
      }
      let shown = 0;
      rows.forEach(r => {
        const hit = (r.textContent || "").toLowerCase().includes(q);
        r.hidden = !hit;
        if (hit) shown++;
      });
      card.hidden = shown === 0;
    });
  };
  inp.addEventListener("input", apply);
  return el("div", { class: "field dns-filter" }, inp);
}

// dnsToggleRow — a labelled accessible switch bound to a boolean key on dnsState. Optimistic: flips
// the switch, mutates state, PUTs; saveDNS's error path re-renders from the persisted state (reverting
// a rejected flip). fakeip forces independent_cache (sing-box requires the pairing; validateDNS 400s).
// gate: { key, reason } when this switch does nothing until another one is on. "Break hardcoded
// encrypted resolvers" is the case it exists for: keeneticPBROptionsFor only passes
// DNSRejectEncrypted through inside "if p.DNS.Intercept", so with interception off the switch stores
// true and installs no rule at all - while its own hint promises those clients "fall back to plain
// DNS and are intercepted", which cannot happen. Measured on the demo: flipping it alone toasted a
// plain confirmation and saved intercept_reject_encrypted:true against intercept:false.
//
// The dependency is NOT resolved by turning interception on for the operator. That redirects every
// client's DNS to this router, which is a decision with its own consequences and its own switch one
// row above; making it a side effect of a different click is how a router starts answering queries
// nobody asked it to answer.
function dnsToggleRow(label, key, hint, gate) {
  const blocked = gate && !dnsState[gate.key] ? gate.reason : "";
  const sw = switchEl(!!dnsState[key], (s) => {
    if (applyInFlight) { toast(t("Apply in progress — finish it first"), "err"); return; } // don't mutate staged DNS mid-Apply (checked before flipSwitch, so no visual desync)
    // Only the ON direction is refused. Switching an already-stored no-op back OFF is cleanup and
    // must always be possible: a gate that locks a setting into the state it should not be in is a
    // worse trap than the silent no-op it was meant to prevent.
    if (blocked && !dnsState[key]) { toast(blocked, "err"); return; }
    const want = !dnsState[key];
    flipSwitch(s, want);
    dnsState[key] = want;
    if (key === "fakeip" && want) dnsState.independent_cache = true;
    // Switching a gated row OFF closes the only door it had: it can no longer be turned back on while
    // its gate is shut, so it must READ unavailable from this click, not from the next render that
    // happens to come along.
    if (blocked) { setGateLook(s, !want, blocked); }
    // A switch other rows depend on must redraw the page: leaving a dependent row enabled after its
    // gate closed (or greyed after it opened) is the same stale-state lie in the other direction.
    saveDNS(label + (want ? " ✓" : " ✕"), DNS_GATE_KEYS.has(key));
  }, label);
  // Greyed only while it cannot be turned ON. Already on and inert stays clickable, and the hint
  // below says why it is doing nothing.
  setGateLook(sw, blocked && !dnsState[key], blocked);
  return el("div", { class: "dns-tog" },
    el("div", { class: "top" }, el("label", { onclick: () => sw.click() }, label), sw),
    hint ? el("div", { class: "hint" }, blocked ? blocked + " " + hint : hint) : null);
}

// setGateLook marks a switch as unavailable-rather-than-off, in one place so the render and the
// click agree on what unavailable looks like.
function setGateLook(sw, unavailable, reason) {
  if (unavailable) { sw.setAttribute("aria-disabled", "true"); sw.title = reason; }
  else { sw.removeAttribute("aria-disabled"); sw.title = ""; }
}

// The keys another row is gated on. Flipping one changes whether a different switch can act at all.
const DNS_GATE_KEYS = new Set(["intercept"]);



// openNativePlan previews the native write-back on OpenWrt: POSTs the adopted NativeDNS to
// /api/dns/native/plan and shows the exact uci the router WOULD get, plus the separate user-gated
// commit commands. Nothing is applied. KeeneticOS writes its chain from dnsNativeCard instead.
async function openNativePlan(nat) {
  try {
    const r = await api.post("/api/dns/native/plan", { native: nat.native });
    const body = el("div", {},
      el("div", { class: "hint", style: "margin-bottom:8px" }, t("What writing the current native DNS back to your router would change. Nothing is applied automatically — the apply step is manual/gated.")),
      el("div", { class: "name", style: "margin:6px 0 4px" }, r.platform === "openwrt" ? t("uci commands") : t("dnsmasq.d content")),
      el("pre", { class: "code", style: "max-height:38vh;overflow:auto;white-space:pre-wrap;margin:0" }, r.content || ""),
      el("div", { class: "name", style: "margin:12px 0 4px" }, t("Then, to apply (user-gated):")),
      el("pre", { class: "code", style: "max-height:20vh;overflow:auto;white-space:pre-wrap;margin:0" }, (r.apply || []).join("\n")));
    const back = modal({ title: t("Native DNS write-back plan"), body, footer: el("button", { class: "btn", onclick: () => back.close() }, t("Close")) });
  } catch (e) { toast(e.message, "err"); }
}

// The DNS server types that ask the resolvers a VPN connection pushes (sing-box 1.14+), each named
// after the protocol of the connection it needs. They have no address and no detour: the connection
// is both, so a row names it where the address goes and reads its tunnel as the path.
const DNS_VPN_TYPES = { openvpn: "OpenVPN (pushed resolvers)", openconnect: "OpenConnect (pushed resolvers)" };

function dnsServerRow(s, i) {
  const net = DNS_NET_TYPES.includes(s.type);
  const enc = DNS_ENC_TYPES.includes(s.type);
  const vpn = !!DNS_VPN_TYPES[s.type];
  const addr = net ? (s.server + (s.server_port ? ":" + s.server_port : "") + (s.path || "")) : vpn ? (nameOf(s.endpoint) || s.endpoint || "—") : (s.type === "fakeip" ? (s.inet4_range || "198.18.0.0/15") : t("device resolver"));
  const leakWarn = (net && !enc) ? el("span", { class: "pill err", title: t("plaintext DNS — the ISP can read your queries") }, t("⚠ plaintext")) : null;
  const via = net ? t("via {0}", nameOf(s.detour) || (s.detour ? s.detour : t("direct"))) : null;
  const path = net ? dnsPathNote(s.detour) : vpn ? dnsPathNote(s.endpoint) : null;
  return el("div", { class: "dns-row" },
    el("span", { class: "badge" }, DNS_TYPE_BADGE[s.type] || s.type),
    el("div", { class: "main" },
      el("div", { class: "name" }, el("span", { class: "tag" }, s.tag), leakWarn),
      el("div", { class: "sub" }, el("span", { class: "addr" }, addr), via ? el("span", {}, "· " + via) : null),
      path ? el("div", { class: "dns-row-path " + path.cls }, path.text) : null),
    el("div", { class: "acts" },
      el("button", { class: "btn btn-sm", "aria-label": t("Edit") + " resolver " + s.tag, onclick: () => openDNSServer(i) }, t("Edit")),
      // Identity first (robust to in-flight index shifts), then by unique tag: a non-rerendering
      // saveDNS (toggle/strategy/default-resolver) reassigns dnsState to fresh round-tripped
      // instances while the rendered rows still close over the OLD objects, so indexOf(s) alone
      // returns -1 and the confirmed delete silently no-ops until a re-render.
      el("button", { class: "btn btn-danger btn-sm", onclick: async () => { if (!await modalConfirm(t("Delete DNS resolver {0}?", s.tag))) return; let idx = dnsState.servers.indexOf(s); if (idx < 0) idx = dnsState.servers.findIndex(x => x && x.tag === s.tag); if (idx < 0) return; dnsState.servers.splice(idx, 1); if (dnsState.final === s.tag) dnsState.final = ""; saveDNS(s.tag + " ✕", true); } , "aria-label": t("Delete") + " resolver " + s.tag }, t("Delete"))));
}

// dnsPlaneNotice says which plane answers clients, as measured. The profile's resolvers and rules are
// sing-box's: on a router where dnsmasq holds :53 they serve sing-box's own lookups and no device ever
// reaches them, so a page that opens on "encrypted, split DNS" misleads about the one thing it is for.
// The verdict names the first upstream too, because that is where a lookup actually goes.
function dnsPlaneNotice(nat) {
  const ans = nat && nat.available && nat.answering;
  if (!ans) return null;
  const first = ((nat.native || {}).resolvers || [])[0];
  const lines = [];
  let cls = "hint qp-ok";
  if (ans.plane === "unknown") {
    cls = "hint qp-warn";
    lines.push(t("WayHop could not read which program holds port 53, so it cannot say who answers your devices."));
  } else if (ans.plane === "core") {
    lines.push(t("sing-box holds port 53, so the resolvers and rules on this page answer your devices."));
  } else {
    lines.push(t("{0} on this router answers your devices. The resolvers and rules further down belong to sing-box and serve only its own lookups, including Secure defaults.", ans.process));
    if (!first) {
      cls = "hint qp-warn";
      lines.push(t("No upstream was read from its configuration."));
    } else if (first.via_tunnel) {
      lines.push(t("Their lookups go first to {0}, through a tunnel.", first.address));
    } else if (first.kind === "doh" || first.kind === "dot") {
      lines.push(t("Their lookups go first to {0}, encrypted.", first.address));
    } else {
      cls = "hint qp-warn";
      lines.push(t("⚠ Their lookups go first to {0} in plaintext, and your provider can read them.", first.address));
    }
  }
  return el("div", { class: "card", "data-dnsplane": ans.plane },
    el("div", { class: "card-head" }, el("div", { class: "card-title" }, t("Who answers your devices"))),
    ...lines.map(x => el("div", { class: cls }, x)));
}

// dnsNativeCard renders the router's ADOPTED native DNS stack, the resolvers the device actually
// serves, in order. On KeeneticOS the rows are the editor of that chain; elsewhere they are read-only
// with a preview of the write-back. A router that cannot take a chain says why.
const DNS_TIER_LABEL = { 1: "via VPN", 2: "WAN-encrypted", 3: "geo-fallback" };
// The page is long, and most visits want one part of it. Stays in reach while scrolling and marks where you are.
function dnsPageNav(view) {
  const items = [
    ["dns-check", t("Privacy check")], ["dns-fast", t("Encrypted DNS")], ["dns-query-path", t("Query path")],
    ["dns-native", t("Router's native DNS")], ["dns-toggles", t("Settings")], ["dns-resolvers", t("Resolvers")],
  ].filter(([id]) => view.querySelector("#" + id));
  const buttons = new Map();
  const nav = el("nav", { class: "dns-nav", "aria-label": t("DNS page sections") }, ...items.map(([id, label]) => {
    const button = el("button", { class: "dns-nav-item", type: "button", onclick: () => dnsCheckOpenSection(id, {}) }, label);
    buttons.set(id, button);
    return button;
  }));
  if (typeof IntersectionObserver === "function") {
    const seen = new Set();
    const observer = new IntersectionObserver(entries => {
      if (!document.contains(nav)) { observer.disconnect(); return; }
      entries.forEach(entry => { if (entry.isIntersecting) seen.add(entry.target.id); else seen.delete(entry.target.id); });
      const current = items.find(([id]) => seen.has(id));
      buttons.forEach((button, id) => {
        if (current && current[0] === id) button.setAttribute("aria-current", "true");
        else button.removeAttribute("aria-current");
      });
    }, { rootMargin: "-130px 0px -55% 0px" });
    items.forEach(([id]) => observer.observe(view.querySelector("#" + id)));
  }
  return nav;
}

function dnsNativeCard(nat) {
  const nd = nat.native || {};
  const rows = nd.resolvers || [];
  const chain = nat.chain;
  const card = el("div", { class: "card", id: "dns-native" });
  card.appendChild(el("div", { class: "card-head" },
    el("div", { class: "card-title" }, t("Router's native DNS")),
    el("div", { class: "acts" },
      rows.length && !chain ? el("button", { class: "btn btn-sm", title: t("Show the uci/dnsmasq commands that would write this back to the router (not run automatically)"), onclick: () => openNativePlan(nat) }, t("Preview write-back")) : null,
      nd.strict_order ? el("span", { class: "pill muted" }, t("strict-order")) : null,
      el("span", { class: "pill ok" }, t("adopted") + " · " + (nat.platform || "")))));
  if (chain && chain.editable) {
    card.appendChild(el("div", { class: "hint", style: "margin-bottom:8px" },
      t("The upstreams dnsmasq asks for your devices, strictly in this order. Bind one to a connection and its lookups stay inside that tunnel. Changes are reviewed first, tried, and put back if dnsmasq stops answering.")));
    dnsChainEditor(card, chain, nat.serve_clients || {});
    return card;
  }
  card.appendChild(el("div", { class: "hint", style: "margin-bottom:8px" },
    chain ? t("The DNS your router actually serves. It cannot be changed from here: {0}.", chain.reason || "")
      : t("The DNS your router actually serves (dnsmasq + DoH). Preview the write-back to see the exact router commands; applying them is a manual, gated step.")));
  if (!rows.length) {
    card.appendChild(el("div", { class: "hint" }, t("No upstreams detected.")));
    return card;
  }
  // A read-only view of somebody else's stack, so it leads with what it establishes and discloses
  // the row-by-row detail. On the test test router this card was 679px — the tallest thing on the page
  // and the reason DNS opened past two screens with a real router's configuration, while the demo,
  // which adopts nothing, never showed it at all.
  const enc = rows.filter(rz => /doh|dot/i.test(rz.kind || "")).length;
  const tunnelled = rows.filter(rz => rz.via_tunnel).length;
  const bits = [
    rows.length === 1 ? t("1 upstream") : t("{0} upstreams", rows.length),
    enc ? t("{0} encrypted", enc) : t("none encrypted"),
  ];
  if (tunnelled) bits.push(t("{0} via a tunnel", tunnelled));
  card.appendChild(el("div", { class: "dns-native-sum" }, bits.join(" · ")));
  const det = el("details", { class: "dns-native-det" },
    el("summary", { class: "hint" }, t("Show each upstream")));
  rows.forEach(rz => det.appendChild(dnsNativeRow(rz)));
  card.appendChild(det);
  return card;
}

// dnsChainEditor is the chain as rows: an address and what carries it. A row names a connection, never
// an interface, because interface names differ on every router; the daemon turns the choice into
// server=IP@iface when it writes. A binding the profile does not know (written by hand) stays offered
// as itself, so editing another row cannot quietly drop it.
function dnsChainEditor(card, chain, serve) {
  serve = serve || {};
  const rows = (chain.rows || []).map(r => Object.assign({}, r));
  const list = el("div", { class: "dns-chain" });
  const viaSelect = (r, n) => {
    const groups = (chain.vias || []).filter(v => v.kind === "group");
    const eps = (chain.vias || []).filter(v => v.kind !== "group");
    const opt = v => el("option", { value: v.id }, v.name + (v.ifaces.length ? " (" + v.ifaces.join(", ") + ")" : ""));
    const sel = el("select", { "aria-label": t("Upstream {0} leaves through", n) },
      el("option", { value: "" }, t("Provider, no tunnel")),
      r.iface && !r.via ? el("option", { value: "@" + r.iface }, t("{0} (not in the profile)", r.iface)) : null,
      eps.length ? el("optgroup", { label: t("Connections") }, ...eps.map(opt)) : null,
      groups.length ? el("optgroup", { label: t("Failover groups: one row per member, in order") }, ...groups.map(opt)) : null);
    sel.value = r.via || (r.iface ? "@" + r.iface : "");
    sel.onchange = () => {
      const v = sel.value;
      r.iface = v.startsWith("@") ? v.slice(1) : "";
      r.via = v.startsWith("@") ? "" : v;
    };
    return sel;
  };
  const draw = () => {
    list.replaceChildren();
    rows.forEach((r, i) => {
      const addr = (r.address || "") + (r.port ? "#" + r.port : "");
      const inp = el("input", { type: "text", value: addr, placeholder: "1.1.1.1", "aria-label": t("Upstream {0} address", i + 1) });
      inp.oninput = () => {
        const [a, p] = inp.value.trim().split("#");
        r.address = a;
        r.port = p ? parseInt(p, 10) || 0 : 0;
      };
      list.appendChild(el("div", { class: "dns-row dns-chain-row" },
        el("span", { class: "badge" }, String(i + 1)),
        el("div", { class: "main" }, inp,
          r.label ? el("div", { class: "sub" }, r.label) : null,
          r.link_absent ? el("div", { class: "sub" }, el("span", { class: "pill err" }, t("this interface is missing right now"))) : null),
        el("div", { class: "dns-chain-via" }, viaSelect(r, i + 1)),
        el("div", { class: "acts" },
          orderControls(i, rows.length, t("upstream {0}", i + 1), (from, to) => {
            const moved = moveInArray(rows, from, to);
            rows.length = 0;
            rows.push(...moved);
            draw();
          }),
          el("button", { class: "btn btn-danger btn-sm", "aria-label": t("Delete upstream {0}", i + 1),
            onclick: () => { rows.splice(i, 1); draw(); } }, t("Delete")))));
    });
    if (!rows.length) list.appendChild(el("div", { class: "hint" }, t("No upstreams detected.")));
  };
  draw();
  card.appendChild(list);
  const addWayHop = el("button", { class: "btn btn-sm", disabled: serve.listening ? null : "disabled", onclick: () => {
    if (!serve.listening) return;
    rows.unshift({ address: "127.0.0.1", port: serve.port, via: "", iface: "" });
    draw();
  } }, t("Add WayHop's encrypted resolver"));
  card.appendChild(el("div", { class: "acts dns-chain-acts" }, addWayHop,
    el("button", { class: "btn btn-sm", onclick: () => { rows.push({ address: "", via: (chain.vias || [])[0] ? chain.vias[0].id : "" }); draw(); } }, t("+ Add upstream")),
    chain.managed ? el("button", { class: "btn btn-sm", title: t("Put back the upstreams this router had before WayHop set them"), onclick: () => dnsChainRestore(chain) }, t("Restore original")) : null,
    el("button", { class: "btn btn-primary btn-sm", disabled: chain.editable === false ? true : null,
      title: chain.editable === false ? (chain.reason || t("this router has no editable native DNS chain")) : null,
      onclick: () => dnsChainReview(rows, chain) }, t("Review and apply"))));
  if (serve.configured && !serve.listening) {
    if (serve.held_by) {
      card.appendChild(el("div", { class: "hint" }, t("Port {0} is held by {1}, so WayHop's resolver cannot listen there.", serve.port, serve.held_by)));
    } else {
      card.appendChild(el("div", { class: "hint" }, t("Apply first, so the resolver is running")));
    }
  }
}

// dnsChainReview shows what the write will do, in the daemon's words, before anything happens.
async function dnsChainReview(rows, chain) {
  if (applyInFlight) { toast(t("Apply in progress — finish it first"), "err"); return; }
  const body = { rows: rows.map(r => ({ address: r.address, port: r.port || 0, via: r.via || "", iface: r.iface || "" })), rev: chain.rev };
  let res;
  try { res = await api.post("/api/dns/native/chain/plan", body); }
  catch (e) { toast(e.message, "err"); return; }
  const plan = res.plan || {};
  const content = el("div", {},
    el("div", { class: "name", style: "margin:0 0 4px" }, t("dnsmasq will ask, in this order")),
    el("pre", { class: "code", style: "max-height:26vh;overflow:auto;white-space:pre-wrap;margin:0" }, (plan.lines || []).join("\n")),
    (plan.moved || []).length ? el("div", { class: "name", style: "margin:12px 0 4px" }, t("Moved aside in the main dnsmasq config, as comments")) : null,
    (plan.moved || []).length ? el("pre", { class: "code", style: "max-height:18vh;overflow:auto;white-space:pre-wrap;margin:0" }, plan.moved.join("\n")) : null,
    plan.added_conf_dir ? el("div", { class: "hint", style: "margin-top:8px" }, t("The main config did not read the conf-dir, so that line is added too.")) : null,
    ...(res.warnings || []).map(w => el("div", { class: "hint qp-warn", style: "margin-top:8px" }, "⚠ " + w)),
    el("div", { class: "hint", style: "margin-top:12px" }, t("Each tunnel row is tried first through a throwaway dnsmasq. If none answers, nothing changes. Then dnsmasq restarts, so lookups pause for a second or two, and if it stops answering the old files go back.")));
  const go = el("button", { class: "btn btn-primary" }, t("Apply this chain"));
  const back = modal({ title: t("Review the upstream chain"), body: content, footer: el("span", {},
    el("button", { class: "btn", onclick: () => back.close() }, t("Cancel")), " ", go) });
  go.onclick = async () => {
    go.disabled = true;
    go.textContent = t("Applying…");
    try { dnsChainResult(back, await api.post("/api/dns/native/chain", body), t("The upstream chain is set.")); }
    catch (e) { back.close(); dnsWriteFailed(e); }
  };
}

// dnsChainResult replaces the review with what happened. A failure says whether the router was put back.
function dnsChainResult(back, rep, okText) {
  back.close();
  if (rep.ok) dnsCheckRerun = true;
  const steps = (rep.steps || []).map(s => el("div", { class: "hint " + (s.ok ? "qp-ok" : "qp-warn") },
    (s.ok ? "✓ " : "⚠ ") + s.step + (s.detail ? ": " + s.detail : "")));
  const body = el("div", {},
    el("div", { class: "name", style: "margin-bottom:8px" }, rep.ok ? okText : rep.error || t("error")),
    !rep.ok ? el("div", { class: "hint", style: "margin-bottom:8px" }, rep.rolled_back ? t("The router is back on the files it had.") : t("Nothing on the router changed.")) : null,
    ...steps);
  const done = modal({ title: rep.ok ? t("Done") : t("The chain was not changed"), body,
    footer: el("button", { class: "btn", onclick: () => { done.close(); route(); } }, t("Close")) });
}

async function dnsChainRestore(chain) {
  if (applyInFlight) { toast(t("Apply in progress — finish it first"), "err"); return; }
  if (!await modalConfirm(t("Put back the upstreams this router had before WayHop set them? dnsmasq restarts, so lookups pause for a second or two."))) return;
  try {
    const rep = await api.post("/api/dns/native/chain/restore", { rev: chain.rev });
    dnsChainResult({ close() {} }, rep, t("The original upstreams are back."));
  } catch (e) { dnsWriteFailed(e); }
}

function dnsNativeRow(rz) {
  const kind = (rz.kind || "").toUpperCase();
  const badge = kind === "PLAIN" ? "Do53" : (kind === "DOH" ? "DoH" : (kind === "DOT" ? "DoT" : (kind === "LOCAL" ? "Local" : kind)));
  const tier = el("span", {}, t(DNS_TIER_LABEL[rz.tier] || ("tier " + rz.tier)));
  return el("div", { class: "dns-row" },
    el("span", { class: "badge" }, badge),
    el("div", { class: "main" },
      el("div", { class: "name" }, el("span", { class: "tag" }, rz.address || "")),
      el("div", { class: "sub" }, tier, rz.via_tunnel ? el("span", {}, "· " + t("via tunnel")) : null)),
    // The source is a config identifier of unbounded length and its column is now sized from the
    // container, so a long one truncates. title keeps the full value recoverable.
    el("div", { class: "acts" }, el("span", { class: "pill muted", title: rz.source || "" }, rz.source || "")));
}

function dnsSuggestTag(p) {
  const base = (p.name || p.type || "dns").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 24) || "dns";
  const taken = new Set(dnsState.servers.map(s => s.tag));
  let tag = base, n = 1;
  while (taken.has(tag)) tag = base + "_" + (++n);
  return tag;
}

async function openDNSServer(idx) {
  const editing = idx != null;
  const cur = editing ? dnsState.servers[idx] : { type: "https", enabled: true, path: "/dns-query", detour: primaryDetourGuess() };
  let presets = [];
  try { presets = (await api.get("/api/dns/catalog")).presets || []; } catch (_) {}

  const presetSel = el("select", { id: "dnsm-preset" }, el("option", { value: "" }, t("— choose a provider —")),
    ...presets.map((p, i) => el("option", { value: String(i), title: p.note || "" }, p.name)));
  const tagIn = el("input", { id: "dnsm-tag", type: "text", value: cur.tag || "", placeholder: "dns_secure" });
  const typeSel = el("select", { id: "dnsm-type" }, ...Object.entries(Object.assign({}, DNS_TYPE_LABEL, DNS_VPN_TYPES)).map(([x, l]) => el("option", { value: x }, l)));
  typeSel.value = cur.type || "https";
  const serverIn = el("input", { id: "dnsm-server", type: "text", value: cur.server || "", placeholder: "1.1.1.1" });
  const portIn = el("input", { id: "dnsm-port", type: "number", value: cur.server_port || "", placeholder: "443" });
  const pathIn = el("input", { id: "dnsm-path", type: "text", value: cur.path || "", placeholder: "/dns-query" });
  const detourSel = routingOutboundSelect(cur.detour || "direct", false); detourSel.id = "dnsm-detour";
  const bootSel = el("select", { id: "dnsm-boot" }, el("option", { value: "" }, t("(none — server is an IP)")),
    // A VPN's pushed resolvers answer only its own names, only while it is up: never a bootstrap.
    ...dnsState.servers.filter((x, j) => j !== idx && !DNS_VPN_TYPES[x.type]).map(x => el("option", { value: x.tag }, x.tag)));
  bootSel.value = cur.domain_resolver || "";
  const i4In = el("input", { id: "dnsm-i4", type: "text", value: cur.inet4_range || "198.18.0.0/15", placeholder: "198.18.0.0/15" });
  const i6In = el("input", { id: "dnsm-i6", type: "text", value: cur.inet6_range || "", placeholder: "fc00::/18" });
  const enChk = el("input", { id: "dnsm-en", type: "checkbox" }); if (cur.enabled !== false) enChk.setAttribute("checked", "true");

  const rowServer = el("div", { class: "field" }, el("label", {}, t("Server (IP or hostname)")), serverIn);
  const rowPort = el("div", { class: "field" }, el("label", {}, t("Port (blank = default)")), portIn);
  const rowPath = el("div", { class: "field" }, el("label", {}, t("DoH path")), pathIn);
  const rowDetour = el("div", { class: "field" }, el("label", {}, t("Ride via (detour)")), detourSel);
  const rowBoot = el("div", { class: "field" }, el("label", {}, t("Bootstrap resolver (hostname only)")), bootSel);
  const rowI4 = el("div", { class: "field" }, el("label", {}, t("FakeIP IPv4 range")), i4In);
  const rowI6 = el("div", { class: "field" }, el("label", {}, t("FakeIP IPv6 range (optional)")), i6In);
  // A VPN type names the connection whose pushed resolvers it asks; only connections of that protocol
  // are offered. The two switches are sing-box's accept_default_resolvers and accept_search_domain.
  const vpnSel = el("select", { id: "dnsm-vpn" });
  const defChk = el("input", { id: "dnsm-vdef", type: "checkbox" }); if (cur.accept_default_resolvers) defChk.setAttribute("checked", "true");
  const sdChk = el("input", { id: "dnsm-vsd", type: "checkbox" }); if (cur.accept_search_domain) sdChk.setAttribute("checked", "true");
  const rowVPN = el("div", {},
    el("div", { class: "field" }, el("label", {}, t("Connection")), vpnSel),
    el("label", { class: "check" }, defChk, el("span", {}, t("Also answer names outside the VPN's own domains"))),
    el("label", { class: "check" }, sdChk, el("span", {}, t("Complete short names with the VPN's search domains"))),
    el("div", { class: "hint" }, t("Asks the DNS servers this connection's VPN pushes, through its tunnel, only while it is up. Names outside the VPN's domains get no answer unless the first box is on; a VPN that pushes servers but no domains needs it. Needs sing-box 1.14+.")));

  const sync = () => {
    const ty = typeSel.value;
    const net = DNS_NET_TYPES.includes(ty), enc = DNS_ENC_TYPES.includes(ty), fake = ty === "fakeip", vpn = !!DNS_VPN_TYPES[ty];
    rowServer.style.display = net ? "" : "none";
    rowPort.style.display = net ? "" : "none";
    rowPath.style.display = (ty === "https" || ty === "h3") ? "" : "none";
    rowDetour.style.display = net ? "" : "none";
    rowBoot.style.display = enc ? "" : "none";
    rowI4.style.display = fake ? "" : "none";
    rowI6.style.display = fake ? "" : "none";
    rowVPN.style.display = vpn ? "" : "none";
    if (vpn) {
      const eps = (state.profile.endpoints || []).filter(e => e.protocol === ty);
      const want = [vpnSel.value, ty === cur.type ? cur.endpoint : ""].find(id => id && eps.some(e => e.id === id));
      // The saved connection is gone (its resolver was parked when it was deleted): left visibly unset,
      // so switching the resolver back on cannot point it at a different VPN without a word. A new
      // resolver, or a type switch, starts on the first connection of that protocol.
      const lost = !want && ty === cur.type && !!cur.endpoint;
      vpnSel.textContent = "";
      if (lost) vpnSel.appendChild(el("option", { value: "" }, "—"));
      eps.forEach(e => vpnSel.appendChild(el("option", { value: e.id }, e.name || e.id)));
      vpnSel.value = want || (lost || !eps.length ? "" : eps[0].id);
    }
  };
  typeSel.onchange = sync;
  presetSel.onchange = () => {
    if (!presetSel.value) return; // placeholder ("— choose a provider —") selected — guard the RAW string: +"" coerces to 0 and would silently load presets[0]
    const p = presets[+presetSel.value];
    if (!p) return;
    typeSel.value = p.type;
    if (p.server != null) serverIn.value = p.server;
    portIn.value = p.server_port || "";
    pathIn.value = p.path || "";
    if (!tagIn.value.trim()) tagIn.value = dnsSuggestTag(p);
    sync();
  };

  const body = el("div", {},
    el("div", { class: "field" }, el("label", {}, t("Provider preset")), presetSel),
    el("div", { class: "field" }, el("label", {}, t("Tag")), tagIn),
    el("div", { class: "field" }, el("label", {}, t("Type")), typeSel),
    rowServer, rowPort, rowPath, rowDetour, rowBoot, rowI4, rowI6, rowVPN,
    el("label", { class: "check" }, enChk, el("span", {}, t("Enabled"))));

  const saveBtn = el("button", { class: "btn btn-primary" }, t("Save"));
  const back = modal({
    title: editing ? t("Edit resolver") : t("Add resolver"),
    body,
    footer: [el("button", { class: "btn", onclick: () => back.close() }, t("Cancel")), saveBtn],
  });
  sync();
  saveBtn.onclick = async () => {
    const ty = typeSel.value;
    const o = { tag: tagIn.value.trim(), type: ty, enabled: enChk.checked };
    if (!o.tag) { toast(t("Tag is required"), "err"); return; }
    if (DNS_NET_TYPES.includes(ty)) {
      o.server = serverIn.value.trim();
      const port = parseInt(portIn.value, 10); if (port) o.server_port = port;
      const det = detourSel.value; if (det && det !== "direct") o.detour = det;
      const boot = bootSel.value; if (boot) o.domain_resolver = boot;
      if (ty === "https" || ty === "h3") { const pth = pathIn.value.trim(); if (pth) o.path = pth; }
    }
    if (ty === "fakeip") {
      o.inet4_range = i4In.value.trim() || "198.18.0.0/15";
      const i6 = i6In.value.trim(); if (i6) o.inet6_range = i6;
    }
    if (DNS_VPN_TYPES[ty]) {
      // Left unset, a parked resolver keeps naming its old connection, which the daemon then names
      // back if it is switched on.
      o.endpoint = vpnSel.value || (ty === cur.type ? cur.endpoint || "" : "");
      if (defChk.checked) o.accept_default_resolvers = true;
      if (sdChk.checked) o.accept_search_domain = true;
    }
    saveBtn.disabled = true;
    // Serialize through dnsSaveChain like saveDNS() — a direct PUT + dnsState reassignment here
    // can race a concurrent background saveDNS() (toggle/strategy/default) and clobber dnsState.
    // Mutating inside the chained step also means it operates on the latest dnsState, not a stale one.
    dnsSaveChain = dnsSaveChain.then(async () => {
      const prev = dnsState.servers.slice();
      if (editing) dnsState.servers[idx] = o; else dnsState.servers.push(o);
      if (dnsState.fakeip && ty === "fakeip") dnsState.independent_cache = true;
      try {
        const r = await dnsPut();
        if (r && r.dns) dnsState = r.dns;
        state.profile.dns = dnsState; updateDirty();
        toast(editing ? t("Resolver updated") : t("Resolver added"), "ok");
        back.close(); route();
      } catch (e) {
        dnsState.servers = prev; saveBtn.disabled = false;
        if (dnsWriteFailed(e)) back.close();
      }
    });
    await dnsSaveChain;
  };
}

function openDNSRule(idx) {
  const editing = idx != null;
  const cur = editing ? dnsState.rules[idx] : { rule_sets: [], domain_suffix: [], query_type: [], server: dnsState.servers[0] ? dnsState.servers[0].tag : "reject" };
  const lists = state.profile.routing_lists || [];
  const listBox = el("div", { style: "max-height:160px;overflow:auto;border:1px solid var(--border);border-radius:6px;padding:8px" });
  if (!lists.length) listBox.appendChild(el("div", { class: "hint" }, t("No routing lists — add one under Routing to match by list.")));
  const listChecks = {};
  lists.forEach(rl => {
    const c = el("input", { type: "checkbox" }); if ((cur.rule_sets || []).includes(rl.id)) c.setAttribute("checked", "true");
    listChecks[rl.id] = c;
    listBox.appendChild(el("label", { class: "check" }, c, el("span", {}, rl.name || rl.id)));
  });
  // asList, not `|| []`: these come from the stored rule and a scalar there throws while the form is
  // being built, so the dialog never opens at all — see app.js and the endpoint whose local_address
  // was a string.
  const sufIn = el("textarea", { id: "dnsr-suf", rows: "3", placeholder: "example.com\ninternal.lan" }, asList(cur.domain_suffix).join("\n"));
  const qtIn = el("input", { id: "dnsr-qt", type: "text", value: asList(cur.query_type).join(","), placeholder: "A,AAAA" });
  const srvSel = el("select", { id: "dnsr-srv" }, ...dnsState.servers.map(s => el("option", { value: s.tag }, s.tag)), el("option", { value: "reject" }, t("Block (reject)")));
  srvSel.value = cur.server || "reject";

  const body = el("div", {},
    el("div", { class: "field" }, el("label", {}, t("Match routing lists")), listBox),
    el("div", { class: "field" }, el("label", {}, t("Domain suffixes (one per line)")), sufIn),
    el("div", { class: "field" }, el("label", {}, t("Query types (comma-separated, e.g. A,AAAA)")), qtIn),
    el("div", { class: "field" }, el("label", {}, t("Resolve via")), srvSel));

  const saveBtn = el("button", { class: "btn btn-primary" }, t("Save"));
  const back = modal({
    title: editing ? t("Edit DNS rule") : t("Add DNS rule"),
    body,
    footer: [el("button", { class: "btn", onclick: () => back.close() }, t("Cancel")), saveBtn],
  });
  saveBtn.onclick = async () => {
    // Spread `cur` first so fields this modal does NOT expose (geosite, domain, disabled — settable
    // via the API / an imported config and rendered in the rule row) are preserved on edit instead
    // of being silently dropped by a from-scratch rebuild; the edited fields below then override.
    const o = Object.assign({}, cur, {
      id: (editing && cur.id) ? cur.id : ("r" + Date.now().toString(36)),
      rule_sets: Object.keys(listChecks).filter(id => listChecks[id].checked),
      domain_suffix: sufIn.value.split("\n").map(x => x.trim()).filter(Boolean),
      query_type: qtIn.value.split(",").map(x => x.trim()).filter(Boolean),
      server: srvSel.value,
    });
    // Every condition the daemon counts (model.dnsRuleHasNoMatcher), the ones this form does not show
    // included: a rule matching by domain or geosite was refused here and accepted there (QA-155).
    const matches = ["rule_sets", "domain_suffix", "domain", "geosite", "query_type"].some(k => asList(o[k]).some(v => String(v).trim()));
    if (!matches) { toast(t("A rule needs at least one match condition"), "err"); return; }
    saveBtn.disabled = true;
    // Serialize through dnsSaveChain like saveDNS() so this PUT + dnsState reassignment can't race
    // a concurrent background saveDNS() and clobber dnsState (mutate inside → operates on latest state).
    dnsSaveChain = dnsSaveChain.then(async () => {
      const prev = dnsState.rules.slice();
      if (editing) dnsState.rules[idx] = o; else dnsState.rules.push(o);
      try {
        const r = await dnsPut();
        if (r && r.dns) dnsState = r.dns;
        state.profile.dns = dnsState; updateDirty();
        toast(t("Rule saved"), "ok"); back.close(); route();
      } catch (e) {
        dnsState.rules = prev; saveBtn.disabled = false;
        if (dnsWriteFailed(e)) back.close();
      }
    });
    await dnsSaveChain;
  };
}

async function previewDNS() {
  try {
    const gen = await api.post("/api/generate", {});
    const dns = gen && gen.config && gen.config.dns;
    const pre = el("pre", { class: "code", style: "max-height:60vh;overflow:auto;white-space:pre-wrap;margin:0" },
      dns ? JSON.stringify(dns, null, 2) : t("No dns block — enable DNS management first."));
    const back = modal({ title: t("Generated dns block"), body: pre, footer: el("button", { class: "btn", onclick: () => back.close() }, t("Close")) });
  } catch (e) { toast(e.message, "err"); }
}

async function applyDNSSecureDefaults() {
  if (dnsState && dnsState.servers && dnsState.servers.length &&
    !await modalConfirm(t("Replace the current DNS setup with the secure defaults (encrypted DoH via the tunnel + local, leak-proof)?"))) return;
  try {
    const resp = await api.get("/api/dns?template=1");
    // Assign dnsState INSIDE the save chain (like openDNSServer/openDNSRule) so a background saveDNS()
    // still in flight can't clobber this template — nor this reassignment clobber that chained save.
    dnsSaveChain = dnsSaveChain.then(() => { dnsState = resp.dns; return saveDNSNow(t("Applied secure DNS defaults"), true); });
    await dnsSaveChain;
  } catch (e) { toast(e.message, "err"); }
}

function dnsLeakWidget() {
  const card = el("div", { class: "card" });
  const body = el("div", {}, el("div", { class: "hint" }, t("Checks that lookups are private (DoH) and that no IPv6 path leaks around the tunnel. Runs the same server-side probes as Diagnostics.")));
  card.appendChild(el("div", { class: "card-head" },
    el("div", { class: "card-title" }, t("DNS leak test")),
    el("div", { class: "acts" }, el("button", { class: "btn btn-sm", onclick: () => runDNSLeak(body) }, t("Run test")))));
  card.appendChild(body);
  return card;
}

async function runDNSLeak(body) {
  body.textContent = ""; body.appendChild(el("div", { class: "hint" }, t("Testing…")));
  try {
    const d = await api.get("/api/healthcheck");
    const rows = (d.checks || []).filter(c => c.id === "dns" || c.id === "ipv6");
    body.textContent = "";
    if (!rows.length) { body.appendChild(el("div", { class: "hint" }, t("No DNS probe available on this device."))); return; }
    rows.forEach(c => {
      // Backend healthcheck status enum is pass | warn | fail | na (never "ok"). Every value is named
      // here, because the fall-through is the RED pill: mapping "pass" alone once turned a leak-free
      // check into a false alarm, and leaving "na" unnamed would do it again to a check that simply
      // did not run — the dns/ipv6 rows report exactly that on a host with nothing to read.
      const cls = c.status === "pass" ? "ok" : c.status === "warn" ? "warn" : c.status === "na" ? "muted" : "err";
      body.appendChild(el("div", { style: "display:flex;align-items:center;justify-content:space-between;gap:10px;padding:5px 0" },
        el("span", {}, c.label || c.id),
        el("span", { class: "pill " + cls, title: c.detail || "" }, c.summary || c.status)));
      // A check that did not run carries no advice worth acting on.
      if (c.status !== "pass" && c.status !== "na" && c.fix) body.appendChild(el("div", { class: "hint" }, "→ " + c.fix));
    });
  } catch (e) { body.textContent = ""; body.appendChild(el("div", { class: "hint" }, t("Leak test unavailable: ") + e.message)); }
}
