// page-connections.js — route-scoped chunk for the connections page.
//
// Loaded by loadChunk() the first time that route is opened, NOT from index.html, so its bytes
// stay out of the initial payload the perf budget measures. A classic script, like app.js: these
// declarations become globals and app.js has already defined el/t/api/state by the time this runs.
//
// Everything here is reachable ONLY from this page's renderer — attributed by walking the call
// graph from every render* entry point, counting an identifier anywhere in a body (strings
// included) as a reference, so the shared set is over-estimated and this set is not.
// Attention order: broken first, then unprobed, then working (slowest first, since a slow exit is
// the next thing to look at), then switched-off, then tunnels that are not exits yet. A list sorted
// best-first buries the one row the user opened the page for.
function exitRank(item) {
  if (item.kind === "native") return 5;
  const e = item.ep;
  if (!e.enabled) return 4;
  const h = healthMap[e.id];
  if (h && h.state === "down") return 0;
  if (!h || h.state === "unknown" || !h.probes) return 1;
  return 2;
}

// A rule is a bundle of matchers, not a kind/value pair — it may carry domains, suffixes, a geosite,
// a geoip, CIDRs and ports at once. Name it after what it actually matches, leading with the first
// non-empty matcher and counting the rest, so two rules aimed at the same exit stay distinguishable.
function ruleSummary(r) {
  const fields = [
    ["domain", r.domain], ["suffix", r.domain_suffix], ["geosite", r.geosite],
    ["geoip", r.geoip], ["ip", r.ip_cidr], ["port", r.port],
  ].filter(([, v]) => v && v.length);
  if (!fields.length) return r.id || t("rule");
  const [label, vals] = fields[0];
  const extra = fields.reduce((n, [, v]) => n + v.length, 0) - 1;
  return label + " " + vals[0] + (extra ? " +" + extra : "");
}

function exitPanelFor(item) {
  const panel = el("div", { class: "insp-panel" });
  if (!item) {
    panel.appendChild(el("div", { class: "insp-empty" }, t("Select an exit to inspect it.")));
    return panel;
  }

  if (item.kind === "native") {
    const tn = item.tn;
    panel.appendChild(el("div", { class: "insp-head" },
      el("div", { class: "insp-title" }, tn.name || tn.iface),
      el("div", { class: "insp-pills" },
        el("span", { class: "badge" }, tn.type),
        tn.active
          ? el("span", { class: "pill ok", title: "Recent handshake — the tunnel is carrying traffic" }, el("span", { class: "dot" }), "up")
          : el("span", { class: "pill muted", title: "No recent handshake" }, el("span", { class: "dot" }), "idle"),
        tn.full_tunnel ? el("span", { class: "pill", title: "Routes all traffic (0.0.0.0/0)" }, "full tunnel") : null)));
    panel.appendChild(el("div", { class: "insp-sub" },
      el("span", { class: "badge proto external" }, t("OS tunnel")),
      el("span", { class: "addr" }, "⇄ " + tn.iface)));
    panel.appendChild(el("div", { class: "insp-note" },
      t("Managed by the router's own VPN client. Add it as an exit to route through it without re-entering credentials.")));
    panel.appendChild(el("div", { class: "insp-acts" },
      el("button", { class: "btn btn-primary", onclick: async () => {
        try {
          await api.post("/api/vpn/adopt", { iface: tn.iface });
          // Adopting moves one row from "not an exit yet" to a real exit — a change to this list and
          // nothing else. route() would empty the page to a skeleton and re-fetch for it, which reads
          // as the whole panel reloading; rebuild just the list instead.
          if (!await refreshConnectionsInPlace()) { await loadProfile(); route(); }
          toast("Added! Enable it in Connections, then add routing lists.", "ok");
        } catch (err) { toast(err.message, "err"); }
      } }, "Add as exit")));
    return panel;
  }

  const e = item.ep;
  const isExternal = e.engine === "external";
  panel.appendChild(el("div", { class: "insp-head" },
    el("div", { class: "insp-title" }, e.name || e.id, pillFor(e)),
    el("div", { class: "insp-pills" },
      switchEl(e.enabled, (s) => toggleEndpoint(e, s), (e.name || e.id) + switchWord(e.enabled)))));
  panel.appendChild(subMeta(e));
  // An adopted tunnel keeps the fact of its adoption visible — it used to live on a second list
  // that no longer exists, and "why does this exit have no server address" is answered by it.
  if (isExternal && e.params && e.params.interface) {
    panel.appendChild(el("div", { class: "insp-note" },
      t("Adopted from the OS tunnel {0}.", e.params.interface)));
  }
  if (isExternal && !e.enabled) {
    panel.appendChild(el("div", { class: "hint", style: "margin-top:6px" },
      "OS-managed tunnel — switch it on to route through it"));
  } else {
    panel.appendChild(statsLine(e));
  }
  if (!isExternal) panel.appendChild(causeLine(e));

  const deps = dependentsOf(e.id);
  const depBox = el("div", { class: "insp-deps" },
    el("div", { class: "insp-deps-t" }, t("Depended on by")));
  if (!deps.length) {
    depBox.appendChild(el("div", { class: "insp-deps-none" },
      t("Nothing routes through this exit yet — switching it off changes nothing.")));
  } else {
    deps.forEach(d => depBox.appendChild(el("div", { class: "insp-dep" + (d.weak ? " weak" : "") },
      el("span", { class: "insp-dep-i", "aria-hidden": "true" }, d.icon),
      el("span", { class: "insp-dep-l" }, d.label),
      el("span", { class: "insp-dep-n" }, d.note))));
    // A dependency that can fail over elsewhere is a different risk from one that cannot, and the
    // difference is the whole reason to look before switching an exit off.
    const hard = deps.filter(d => !d.weak).length;
    depBox.appendChild(el("div", { class: "insp-deps-sum" },
      hard === 0 ? t("All of these can fall back to another exit.")
        : hard === 1 ? t("One of these has no alternative exit.")
          : t("{0} of these have no alternative exit.", hard)));
  }
  panel.appendChild(depBox);

  panel.appendChild(el("div", { class: "insp-acts" },
    el("button", { class: "btn", "aria-label": "Check config " + (e.name || e.id), onclick: ev => checkEndpointConfig(e, ev.currentTarget) }, "Check config"),
    el("button", { class: "btn", "aria-label": t("Test") + " " + (e.name || e.id), onclick: ev => testEndpoint(e, ev.currentTarget) }, "Test"),
    el("button", { class: "btn", "aria-label": t("Edit") + " " + (e.name || e.id), onclick: () => openEditEndpoint(e) }, "Edit"),
    el("button", { class: "btn btn-danger", "aria-label": t("Delete") + " " + (e.name || e.id), onclick: () => delEndpoint(e) }, "Delete")));
  return panel;
}

// A row says two live things — the dot and the trailing note — and both change without the list
// being rebuilt: the health tick moves latency every 5 s, and switching an exit off stages
// `enabled` on the profile object in place. Written once at construction they kept the answer the
// row was born with, so an exit switched on and applied still read "off" until the page was
// reloaded. They are written here instead, from the same source, and repainted by paintExitsList.
function paintExitRow(row, item) {
  let dotCls = "muted", note = "";
  if (item.kind === "native") { dotCls = item.tn.active ? "native" : "native idle"; note = t("not an exit yet"); }
  else {
    const e = item.ep, h = healthMap[e.id];
    if (!e.enabled) { dotCls = "muted"; note = t("off"); }
    // The cause belongs in the panel, where there is room for it and for its suggested fix. In a
    // 260px column it only ever showed a truncated fragment — "No response (timed out or bl".
    else if (h && h.state === "down") { dotCls = "err"; note = t("down"); }
    else if (h && h.state === "alive") { dotCls = h.latency_ms >= 600 ? "warn" : "ok"; note = (h.latency_ms || "?") + " ms"; }
    else note = t("checking…");
  }
  const dot = row.querySelector(".insp-dot");
  if (dot) dot.className = "insp-dot " + dotCls;
  const meta = row.querySelector(".insp-row-m");
  if (meta && meta.textContent !== note) meta.textContent = note;
}

// paintExitsList repaints every row of the exits list plus the header verdict derived from the same
// ranks. It touches one class and one text node per row, so the nodes — and whatever has keyboard
// focus — stay alive; rebuilding the list to say the same thing is what the render deliberately
// avoids (see selectExit). A no-op anywhere but the connections page.
//
// The rows are looked up on every call rather than through the pillNodes() cache: this render
// awaits the profile and native-VPN discovery before it inserts anything, so a health tick landing
// in that window caches an EMPTY list for the generation and the cache only rebuilds on the next
// navigation — measured here as rows that never repainted at all. One querySelectorAll over a
// handful of rows is not worth that failure mode.
function paintExitsList() {
  const rows = document.querySelectorAll("[data-exit-row]");
  if (!rows.length) return;
  let needing = 0;
  rows.forEach(row => {
    const item = row._exitItem;
    if (!item) return;
    paintExitRow(row, item);
    if (exitRank(item) <= 1) needing++;
  });
  const head = document.querySelector(".insp-list-h");
  if (head && head.lastChild) {
    head.replaceChild(needing
      ? el("span", { class: "insp-list-warn" }, t("{0} needing attention", needing))
      : el("span", { class: "insp-list-ok" }, t("all healthy")), head.lastChild);
  }
}

function exitRow(item, onPick) {
  const sel = item.id === selectedExitId;
  const row = el("div", { class: "insp-row" + (sel ? " sel" : "") + (item.kind === "native" ? " native" : ""), role: "button", tabindex: "0",
    "data-exit-row": item.id,
    "aria-label": t("Inspect {0}", item.label), "aria-current": sel ? "true" : null });
  const pick = () => {
    if (item.id === selectedExitId) return;
    onPick(item);
  };
  row.addEventListener("click", pick);
  row.addEventListener("keydown", ev => {
    if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); pick(); }
  });

  // item.ep is the live endpoint inside state.profile, so a staged on/off flip is visible from the
  // row without threading the change through the render that built it.
  row._exitItem = item;
  row.append(
    el("span", { class: "insp-dot muted", "aria-hidden": "true" }),
    el("span", { class: "insp-row-n" }, item.label),
    el("span", { class: "insp-row-m" }));
  paintExitRow(row, item);
  return row;
}

// dependentLabel turns one server-reported dependent into something an operator recognises. The
// kinds come from the API and are stable; an unknown one still shows its name rather than nothing.
function dependentLabel(d) {
  const kinds = {
    routing_list: t("routing list"),
    download_via: t("routing list (list download)"),
    rule: t("rule"),
    dns_detour: t("DNS server"),
    group_member: t("failover group"),
  };
  return (kinds[d.kind] || d.kind) + " " + (d.name || d.id);
}

// askDependentsChoice offers the two ways forward when something still routes through a connection:
// move those references to another exit, or go ahead and leave them parked with no exit.
//
// The old flow simply refused and told the operator to "repoint it first" — without saying what to
// repoint to, and revealing one blocker at a time. Both choices are done server-side in a single
// revision so no half-repointed profile is ever published.
//
// Deleting an exit and switching one off ask this question of the same dependent set for the same
// reason (a disabled endpoint is not emitted as an outbound either), and the server answers both the
// same way — so they share this dialog and differ only in the words on its two buttons.
function askDependentsChoice(name, dependents, replacements, words) {
  return new Promise(resolve => {
    let answered = false;
    const done = v => { if (answered) return; answered = true; back.close(); resolve(v); };
    const list = el("ul", { style: "margin:8px 0 16px 18px;padding:0" });
    dependents.forEach(d => list.appendChild(el("li", {}, dependentLabel(d))));
    const select = el("select", { class: "inp" });
    (replacements || []).forEach(r => select.appendChild(el("option", { value: r }, nameOf(r) || r)));
    const moveRow = el("div", { style: "display:flex;gap:8px;align-items:center;margin-bottom:14px" },
      el("span", {}, t("Move them to:")), select,
      el("button", { class: "btn btn-primary btn-sm", onclick: () => done({ replace: select.value }) }, words.move));
    const body = el("div", {},
      el("p", { style: "margin:0 0 6px" },
        t("{0} still routes traffic for:", name)),
      list,
      replacements && replacements.length ? moveRow : el("div"),
      el("p", { class: "hint", style: "margin:0" }, words.hint));
    const back = modal({
      title: words.title,
      body,
      footer: el("div", { style: "display:flex;gap:10px;justify-content:flex-end" },
        el("button", { class: "btn", onclick: () => done(null) }, t("Cancel")),
        el("button", { class: "btn btn-danger", onclick: () => done({ detach: true }) }, words.anyway)),
    });
    back.addEventListener("click", ev => { if (ev.target === back) done(null); });
  });
}

function askDeleteDependents(name, dependents, replacements) {
  return askDependentsChoice(name, dependents, replacements, {
    title: t("Delete {0}", name),
    move: t("Move and delete"),
    hint: t("Or delete it anyway: these keep their addresses but are switched off until you give them an exit."),
    anyway: t("Delete and leave without an exit"),
  });
}

// The switch-off wording. Nothing is destroyed on this path — the exit stays, off — but whatever it
// carried does stop routing, which is what the operator asked for when they clicked the switch.
function askDisableDependents(name, dependents, replacements) {
  return askDependentsChoice(name, dependents, replacements, {
    title: t("Switch {0} off", name),
    move: t("Move and switch off"),
    hint: t("Or switch it off anyway: these keep their addresses but stop routing until you give them an exit."),
    anyway: t("Switch off and leave without an exit"),
  });
}

async function delEndpoint(e) {
  const name = e.name || e.id;
  // The consequence sentence is stated only when it IS one. It used to be unconditional, so deleting
  // a connection that belongs to no group promised "it will also be removed from every failover group
  // that uses it" — measured on the demo with a freshly added trojan whose membership count was zero.
  // A warning that fires on nothing teaches the reader to skim the one that fires on something.
  //
  // When there ARE groups they are named, to the same standard as the switch-off dialog one click
  // away, which lists each dependent by name rather than counting them.
  const inGroups = (state.profile.groups || [])
    .filter(g => (g.members || []).includes(e.id))
    .map(g => g.name || g.id);
  const msg = inGroups.length
    ? t("Delete connection {0}?", name) + " "
      + tn("It will also be removed from this failover group: {1}.|It will also be removed from these failover groups: {1}.",
           inGroups.length, inGroups.join(", "))
    : t("Delete connection {0}?", name);
  if (!await modalConfirm(msg)) return;
  const base = "/api/endpoints/" + encodeURIComponent(e.id);
  const finish = async () => { await loadProfile(); route(); toast("Deleted", "ok"); };
  try { await api.del(base); await finish(); return; }
  catch (err) {
    const data = err && err.data;
    if (!data || data.code !== "ENDPOINT_IN_USE") { toast(err.message, "err"); return; }
    const choice = await askDeleteDependents(name, data.dependents || [], data.replacements || []);
    if (!choice) return;
    const q = choice.detach ? "?detach=1" : "?replace_with=" + encodeURIComponent(choice.replace);
    try { await api.del(base + q); await finish(); }
    catch (err2) { toast(err2.message, "err"); }
  }
}

function fInput(id, label, value, opts) {
  opts = opts || {};
  return el("div", { class: "field" }, el("label", {}, label),
    el("input", { type: opts.type || "text", id, value: value != null ? String(value) : "", placeholder: opts.ph || "" }));
}

function fSelect(id, label, options, value) {
  const opts = options.map(o => el("option", { value: o }, o));
  // If the stored value is not one of the known options (e.g. an SS-2022 cipher this
  // build's dropdown doesn't list, or a v2ray transport type like "quic"), inject an
  // option for it so it round-trips on save. Otherwise the browser sets selectedIndex
  // to -1 and .value to "" on an unknown value, and collect() would then silently
  // rewrite the field to "" — blanking the cipher / dropping the transport block and
  // breaking a working endpoint on any edit (even a rename).
  if (value != null && value !== "" && !options.includes(value)) {
    opts.push(el("option", { value }, value));
  }
  const sel = el("select", { id }, ...opts);
  if (value != null) sel.value = value;
  return el("div", { class: "field" }, el("label", {}, label), sel);
}

function fCheck(id, label, checked) {
  const c = el("input", { type: "checkbox", id });
  if (checked) c.setAttribute("checked", "true");
  return el("label", { class: "check" }, c, el("span", {}, label));
}

async function loadRealityDests() {
  if (REALITY_DESTS_CACHE) return REALITY_DESTS_CACHE;
  try {
    const r = await api.get("/api/reality/dests");
    if (Array.isArray(r) && r.length) REALITY_DESTS_CACHE = r;
  } catch (e) { /* offline / old daemon → keep the REALITY_FRONTS fallback */ }
  return REALITY_DESTS_CACHE;
}

// Reality crypto-field format checks (mirror the generator's validRealityPubKey/validShortID),
// surfaced inline so a truncated/typo'd paste is caught at input — otherwise the generator
// silently degrades the endpoint to plain TLS, which fails against a Reality server with no
// hint why. Return "" when ok, else a short reason.
function b64Bytes(s) {
  try {
    let t = String(s).replace(/-/g, "+").replace(/_/g, "/");
    while (t.length % 4) t += "=";
    return atob(t).length;
  } catch (e) { return -1; }
}

// invalidFieldError names the first field whose own validator is currently unhappy, or "" when the
// form is clean. Save paths call it BEFORE writing: a form that draws a red ✗ and saves anyway has
// told the operator the value is wrong and then kept it, which is worse than not checking at all.
function invalidFieldError(form) {
  const root = form && form.el ? form.el : form;
  if (!root || !root.querySelectorAll) return "";
  const bad = [...root.querySelectorAll('[data-invalid="1"]')][0];
  if (!bad) return "";
  const label = bad.dataset.invalidLabel || "";
  const why = bad.dataset.invalidWhy || t("is not valid");
  bad.focus();
  return label ? t("{0}: {1}", label, why) : why;
}

function realityPubkeyError(v) { return b64Bytes(v) === 32 ? "" : t("not a valid x25519 key (base64 of 32 bytes)"); }

function shortIdError(v) { return (/^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0 && v.length <= 16) ? "" : t("must be hex, even length, ≤16 chars"); }

function openEditEndpoint(ep) {
  const external = ep && ep.engine === "external";
  const form = external ? externalForm(ep) : manualForm(ep);
  async function save() {
    if (!external) {
      const unavailable = form.supportError(); if (unavailable) return toast(unavailable, "err");
      const invalid = invalidFieldError(form); if (invalid) return toast(invalid, "err");
    }
    const e = form.collect();
    if (external) { if (!e.params.interface) return toast("Bound interface required", "err"); }
    else if (!e.server || !e.port) return toast("Server and port required", "err");
    try { await api.post("/api/endpoints", e); back.remove(); await loadProfile(); route(); toast(t("Updated {0}", e.name || e.id), "ok"); }
    catch (err) { toast(redactSecrets(err.message), "err"); } // a validation error can echo a credential (e.g. a malformed TUIC uuid); redact like the paste/subscription paths
  }
  const back = modal({ title: external ? "Edit external connection" : "Edit connection", body: form.el,
    footer: [el("button", { class: "btn btn-ghost", onclick: () => back.remove() }, "Cancel"), el("button", { class: "btn btn-primary", onclick: save }, "Save")] });
}

function friendlyImportError(raw, onRetry) {
  raw = String(raw == null ? "" : raw);
  const low = raw.toLowerCase();
  let msg;
  if (low.includes("unsupported scheme") || low.includes("unknown scheme") || (low.includes("unsupported") && low.includes("type"))) msg = t("This connection format is not supported.");
  else if (low.includes("decode") || low.includes("base64")) msg = t("The link could not be decoded.");
  else if (low.includes("missing") || low.includes("required")) msg = t("Required connection information is missing.");
  else if (low.includes("incomplete") || low.includes("no host") || low.includes("no port") || low.includes("invalid port")) msg = t("The link appears incomplete.");
  else if (!raw.trim()) msg = t("The link is empty — paste a share link or a config.");
  else msg = t("The imported configuration is invalid.");
  const box = el("div", { class: "import-error", role: "alert" });
  box.appendChild(el("div", { class: "ie-msg" }, msg));
  const acts = el("div", { class: "ie-actions" });
  if (onRetry) acts.appendChild(el("button", { class: "btn btn-sm", type: "button", onclick: onRetry }, t("Paste another link")));
  acts.appendChild(el("button", { class: "btn btn-sm", type: "button", onclick: () => toast(t("Supported: VLESS · VMess · Trojan · AnyTLS · Shadowsocks · Hysteria2 · TUIC · WireGuard · AmneziaWG"), "info") }, t("View supported formats")));
  box.appendChild(acts);
  const det = el("details", { class: "ie-tech" });
  const safe = redactSecrets(raw); // both the display AND the clipboard get the redacted form
  det.appendChild(el("summary", {}, t("Technical details")));
  det.appendChild(el("pre", { class: "ie-raw" }, safe));
  // Use the shared three-rung copier. The panel normally runs over plain HTTP on a LAN address,
  // where navigator.clipboard is absent; copyText then tries execCommand and finally shows a
  // pre-selected manual-copy field. It also says "Copied" only after a browser API confirms it,
  // instead of claiming success while an un-awaited clipboard promise may still reject.
  det.appendChild(el("button", { class: "btn btn-sm", type: "button", onclick: () => copyText(safe) }, t("Copy technical details")));
  box.appendChild(det);
  return box;
}

function openAddConnection() {
  const content = el("div", { id: "addconn-panel", role: "tabpanel", tabindex: "0" }); // the tabs' panel (aria-controls target)
  const tabEls = {};
  let back;
  const done = msg => { back.remove(); loadProfile().then(route).catch(e => toast(e.message, "err")); toast(msg, "ok"); };

  // A connection id is derived from protocol+server+port and POST /api/endpoints is an UPSERT, so a
  // second account on a host that already has one lands on the SAME id and replaces it. Measured on a
  // live router: importing a new VLESS link for a server that already had a connection overwrote its
  // uuid and its name, the connection count did not change, and the toast said "Added". The paste tab
  // grew a check for that; the manual tab kept posting blind and saying "Added" for a silent
  // overwrite. One helper now guards both, so the two tabs cannot drift apart again.
  async function confirmEndpointReplace(e) {
    let replacing = null;
    try {
      // ?lite=1 — this reads endpoints only, and the full form drags every routing list's feed
      // cache along (275 KB on a live router) at the exact moment the user pressed Save.
      const cur = await api.get("/api/profile?lite=1");
      replacing = (((cur && cur.profile) || cur || {}).endpoints || []).find(x => x.id === e.id) || null;
    } catch (_) { /* the check is a courtesy; a failed read must not block the save */ }
    if (!replacing) return { go: true, replacing: null };
    const go = await modalConfirm(t(
      "A connection to {0}:{1} already exists — {2}. Saving REPLACES it: its keys and settings are overwritten and cannot be recovered from here. Replace it?",
      e.server, e.port, replacing.name || replacing.id));
    return { go, replacing };
  }

  function pasteTab() {
    const ta = el("textarea", { placeholder: "Paste a vless:// / hysteria2:// / tuic:// link — or a [Interface] WireGuard / AmneziaWG config",
      onpaste: () => setTimeout(parse, 0) });
    const confirm = el("div", {});
    // Generation guard, same shape as the router's routeGen: every paste starts a parse, and
    // /api/import can answer out of order. Paste link A, replace it with B, paste again - if A
    // lands last it overwrites B's confirmation form, and Save then writes the endpoint from A
    // while the textarea above it still reads B. Only the newest parse may touch the DOM.
    let parseGen = 0;
    async function parse() {
      const gen = ++parseGen;
      const link = ta.value.trim();
      if (!link) { confirm.innerHTML = ""; confirm.appendChild(friendlyImportError("", null)); ta.focus(); return; }
      confirm.innerHTML = ""; confirm.appendChild(el("div", { class: "hint" }, t("parsing…")));
      try {
        const parsed = await api.post("/api/import", { link });
        if (gen !== parseGen) return; // a newer paste superseded us — discard this parse
        confirm.innerHTML = "";
        const form = manualForm(parsed); // editable confirmation — protocol dropdown overrides the type
        const saveBtn = el("button", { class: "btn btn-primary", onclick: async (ev) => {
          const unavailable = form.supportError(); if (unavailable) return toast(unavailable, "err");
          const invalid = invalidFieldError(form); if (invalid) return toast(invalid, "err");
          const e = form.collect(); if (!e.server || !e.port) return toast("Server and port required", "err");
          const b = ev.currentTarget; if (b.disabled) return; b.disabled = true; // guard against double-submit firing two POSTs before done() removes the modal
          // The id is derived from protocol+server+port at import time, and POST /api/endpoints is an
          // UPSERT — so a second account on a host that already has one lands on the same id and
          // REPLACES it. Measured on a live router: importing a new VLESS link for a server
          // that already had a connection overwrote its uuid and its name, the connection count did
          // not change, and the toast said "Added". Ask first, and then say what actually happened.
          const { go, replacing } = await confirmEndpointReplace(e);
          if (!go) { b.disabled = false; return; }
          try {
            await api.post("/api/endpoints", e);
            done(replacing ? t("Replaced {0}", replacing.name || replacing.id) : t("Added {0}", e.name || e.id));
          } catch (err) { b.disabled = false; toast(redactSecrets(err.message), "err"); }
        } }, "Save connection");
        const detProto = String(parsed.protocol || "?").toUpperCase();
        const detEng = parsed.engine && parsed.engine !== "singbox" ? parsed.engine : "";
        confirm.appendChild(el("div", { class: "toast info", style: "margin:0 0 12px" },
          detEng
            ? t("Detected {0} · {1} engine — review below and fix the type if it's wrong, then save.", detProto, detEng)
            : t("Detected {0} — review below and fix the type if it's wrong, then save.", detProto)));
        confirm.appendChild(form.el);
        confirm.appendChild(el("div", { style: "margin-top:10px" }, saveBtn));
      } catch (e) {
        if (gen !== parseGen) return; // ...and a superseded parse must not replace a good form with ITS error
        confirm.innerHTML = "";
        confirm.appendChild(friendlyImportError(e.message, () => { ta.value = ""; ta.focus(); confirm.innerHTML = ""; }));
      }
    }
    const parseBtn = el("button", { class: "btn btn-primary", onclick: parse }, "Parse");
    const file = el("input", { type: "file", accept: ".conf,.json,.txt,.yaml,.yml", style: "display:none",
      onchange: async ev => { const f = ev.target.files && ev.target.files[0]; if (!f) return; ta.value = await f.text(); ev.target.value = ""; parse(); } });
    const fileBtn = el("button", { class: "btn", onclick: () => file.click() }, "Import file…");
    return el("div", {}, el("div", { class: "field" }, el("label", {}, "Paste a share link or config — or import a file"), ta),
      el("div", { style: "display:flex;gap:10px;flex-wrap:wrap" }, parseBtn, fileBtn), file,
      el("div", { style: "margin-top:14px" }, confirm));
  }
  function manualTab() {
    const form = manualForm(null);
    const addBtn = el("button", { class: "btn btn-primary", onclick: async (ev) => {
      const unavailable = form.supportError(); if (unavailable) return toast(unavailable, "err");
      const e = form.collect(); if (!e.server || !e.port) return toast("Server and port required", "err");
      const b = ev.currentTarget; if (b.disabled) return; b.disabled = true; // guard against double-submit firing two POSTs before done() removes the modal
      const { go, replacing } = await confirmEndpointReplace(e);
      if (!go) { b.disabled = false; return; }
      try { await api.post("/api/endpoints", e); done(replacing ? t("Replaced {0}", replacing.name || replacing.id) : t("Added {0}", e.name || e.id)); } catch (err) { b.disabled = false; toast(redactSecrets(err.message), "err"); } // redact: a validation error can echo a credential, like the paste/subscription paths
    } }, "Add");
    return el("div", {}, form.el, el("div", { style: "margin-top:8px" }, addBtn));
  }
  function subTab() {
    let found = [];
    const url = el("input", { type: "text", placeholder: t("{0} (optional)", "https://provider/subscription") });
    const ta = el("textarea", { placeholder: "…or paste the subscription text / base64 blob here" });
    const list = el("div", { class: "checks", style: "margin-top:14px" });
    const importBtn = el("button", { class: "btn btn-primary", disabled: "true", onclick: async (ev) => {
      const chosen = $$("input[type=checkbox]:checked", list).map(c => found[+c.value]);
      if (!chosen.length) return toast("Nothing selected", "err");
      const b = ev.currentTarget; if (b.disabled) return; b.disabled = true; // guard against double-submit firing two bulk POSTs before done() removes the modal
      try { const r = await api.post("/api/endpoints/bulk", { endpoints: chosen }); done(tn("Imported {0} connection|Imported {0} connections", r.saved) + (r.duplicates ? tn(", {0} duplicate skipped|, {0} duplicates skipped", r.duplicates) : "") + (r.errors && r.errors.length ? t(", {0} failed", r.errors.length) : "")); } catch (e) { b.disabled = false; toast(redactSecrets(e.message), "err"); }
    } }, "Import selected");
    const fetchBtn = el("button", { class: "btn", onclick: async (ev) => {
      const b = ev.currentTarget; if (b.disabled) return; b.disabled = true; // guard against a double-click firing two overlapping fetches that each clear `list` and reassign `found`, desyncing the checkbox indices
      list.innerHTML = ""; importBtn.setAttribute("disabled", "true");
      // Nothing submitted is not the same answer as nothing found. With both fields empty this said
      // "No connections found." — a report on a search that never ran, in the same dialog whose Paste
      // link tab already distinguishes "the link is empty" from "unsupported format".
      if (!url.value.trim() && !ta.value.trim()) {
        list.appendChild(el("div", { class: "hint" },
          t("Nothing to fetch — paste a subscription URL, or the subscription text itself.")));
        b.disabled = false;
        return;
      }
      try {
        const r = await api.post("/api/subscription", { url: url.value.trim(), text: ta.value });
        found = r.endpoints || [];
        if (!found.length) { list.appendChild(el("div", { class: "hint" }, r.errors && r.errors.length ? t("No connections found ({0} line errors).", r.errors.length) : t("No connections found."))); return; }
        if (r.name) list.appendChild(el("div", { class: "hint", style: "color:var(--ink-2);margin-bottom:8px" }, t("From: {0}", r.name)));
        found.forEach((e, i) => list.appendChild(el("label", { class: "check" }, el("input", { type: "checkbox", value: String(i), checked: "true" }), el("span", {}, (e.name || e.id) + "  "), el("span", { class: "badge" }, e.protocol))));
        if (r.errors && r.errors.length) list.appendChild(el("div", { class: "hint" }, r.errors.length + " line(s) skipped"));
        importBtn.removeAttribute("disabled");
      } catch (e) { list.appendChild(el("div", { class: "hint", style: "color:var(--err)" }, redactSecrets(e.message))); }
      finally { b.disabled = false; }
    } }, "Fetch / Parse");
    return el("div", {}, el("div", { class: "field" }, el("label", {}, "Subscription URL"), url),
      el("div", { class: "field" }, el("label", {}, "or paste text / base64"), ta),
      el("div", { style: "display:flex;gap:10px" }, fetchBtn, importBtn), list);
  }

  const tabKeys = [["paste", "Paste link"], ["manual", "Manual"], ["sub", "Subscription"]];
  const order = tabKeys.map(([k]) => k);
  function show(key) {
    Object.entries(tabEls).forEach(([k, t]) => {
      const sel = k === key;
      t.classList.toggle("active", sel);
      t.setAttribute("aria-selected", sel ? "true" : "false");
      t.tabIndex = sel ? 0 : -1; // roving tabindex: only the active tab is in the tab order
    });
    content.setAttribute("aria-labelledby", "addconn-tab-" + key); // name the panel by its owning tab (ARIA tabs pattern)
    content.innerHTML = "";
    content.appendChild(key === "paste" ? pasteTab() : key === "manual" ? manualTab() : subTab());
    associateLabels(content); // the tab's fields are injected AFTER modal()'s one-shot associateLabels ran — re-wire them
  }
  const tabBar = el("div", { class: "tabs", role: "tablist" }, ...tabKeys.map(([k, label]) => {
    const t = el("div", { class: "tab", id: "addconn-tab-" + k, role: "tab", tabindex: "-1", "aria-controls": "addconn-panel", onclick: () => { show(k); t.focus(); } }, label);
    t.addEventListener("keydown", ev => {
      if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); show(k); }
      else if (ev.key === "ArrowRight" || ev.key === "ArrowLeft") {
        ev.preventDefault();
        const nk = order[(order.indexOf(k) + (ev.key === "ArrowRight" ? 1 : order.length - 1)) % order.length];
        show(nk); tabEls[nk].focus();
      }
    });
    tabEls[k] = t; return t;
  }));
  back = modal({ title: "Add connection", body: el("div", {}, tabBar, content) });
  show("paste");
}

// execCopy and copyManualModal used to live here. They are copyText's fallback rungs, copyText lives
// in app.js, and app.js loads on every page while this chunk loads only when Connections is opened —
// so on Diagnostics, whose four Copy buttons need nothing else from Connections, pressing Copy raised
// `ReferenceError: execCopy is not defined` and the button did nothing at all: no text, no toast, no
// visible error. Measured on the AX3000T. They now live beside copyText in web/dist/app.js.

// ── Connection forms ──────────────────────────────────────────────────────────────────────────
// manualForm, externalForm and the health-target picker live HERE, not in app.js, and the reason is
// the initial payload: app.js is fetched before the panel is interactive on a router with a slow
// uplink, and these three are reachable only from this page — every caller is in this file. Together
// they were ~9 KB gzip of a budget that had reached 99%.
//
// The opposite case is documented in app.js for execCopy: a Copy control exists on pages reached
// without ever opening Connections, so putting its helper in this chunk threw ReferenceError. The
// test is not "is it about connections" but "can a caller run before this chunk loads". These cannot.

// healthTargetPicker turns the health field into a measured choice.
//
// An anycast probe answers from the edge NEAREST THE EXIT, so it mostly measures how far the exit is
// from you and says little about the path to the services the tunnel carries. Measured on the
// operator's router: through Armenia, Cloudflare answered in 180 ms while Telegram took 444 ms;
// through the Netherlands the same pair was 144 and 210 ms. Same tunnels, different verdict depending
// on what you probe — so the choice deserves numbers rather than a default nobody revisits.
//
// The measurement runs THROUGH THIS CONNECTION (netdiag takes an egress), which is the only way the
// numbers mean anything: a target measured over the WAN says nothing about the tunnel.
function healthTargetPicker(input, endpointID) {
  // Declared INSIDE the function on purpose. A top-level `const` in a chunk collides with the
  // same name in an app.js the browser is still running: with the panel open across an upgrade,
  // the first visit to Connections fetches the new chunk beside the old app.js, and
  // "Identifier 'HEALTH_TARGETS' has already been declared" aborts the chunk — the page renders
  // nothing, with the error only in the console. Reproduced exactly that way while moving these
  // functions here. Function declarations survive the same collision (they may be redeclared);
  // a const cannot, so it lives where no second declaration can reach it.
  // HEALTH_TARGETS is the shortlist offered for a connection's health probe.
  //
  // Every entry was measured from a live router THROUGH two different tunnels before it was
  // put here, because a probe target that is slow or unreachable turns a working tunnel into a dead
  // one on the Failover page. www.kaspi.kz was tried and rejected on that evidence: 718–1961 ms through
  // the tunnels and flatly unreachable through one of them, because it is a full TLS website rather
  // than a probe endpoint. The six below answered through every tunnel tested, in 138–444 ms.
  //
  // The list is a SHORTLIST, not a whitelist: the field stays a free-text input with a datalist, so any
  // target the operator already relies on keeps working and can still be typed.
  const HEALTH_TARGETS = [
    { url: "http://cp.cloudflare.com/generate_204", note: "Cloudflare · anycast, nearest edge to the exit" },
    { url: "http://detectportal.firefox.com/success.txt", note: "Mozilla · anycast" },
    { url: "http://nmcheck.gnome.org/check_network_status.txt", note: "GNOME" },
    { url: "http://www.gstatic.com/generate_204", note: "Google · anycast" },
    { url: "http://connectivitycheck.gstatic.com/generate_204", note: "Google · Android's own check" },
    { url: "https://web.telegram.org", note: "Telegram · what the tunnel actually carries" },
  ];
  const list = el("datalist", { id: "f-health-list" });
  const fill = (rows) => {
    list.innerHTML = "";
    rows.forEach(r => list.appendChild(el("option", { value: r.url, label: r.label || r.note })));
  };
  fill(HEALTH_TARGETS);
  input.setAttribute("list", "f-health-list");

  const out = el("span", { class: "hint", style: "margin-left:8px" });
  const btn = el("button", { class: "btn btn-sm", type: "button" }, t("Measure & sort"));
  if (!endpointID) {
    // A connection with no id yet cannot be an egress, so there is nothing to measure through. Say
    // that instead of offering a button that would silently measure the WAN and label it this tunnel.
    btn.disabled = true;
    btn.title = t("Save the connection first — the probe has to run through it.");
  }
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    const original = btn.textContent;
    btn.textContent = t("Measuring…");
    out.textContent = "";
    const scored = [];
    for (const target of HEALTH_TARGETS) {
      try {
        const r = await api.post("/api/netdiag", { target: target.url, egress: endpointID });
        // The daemon answers {reachable, latency_ms}. Reading `ok` instead — the name this code was
        // first written with — made every target report "unreachable" on a router where all six
        // answered in 173–444 ms, because an absent field is falsy and a wrong label is worse than no
        // label: it would have moved the operator off a target that was working.
        const ms = r && (r.latency_ms != null ? r.latency_ms : r.ms);
        const up = !!(r && (r.reachable != null ? r.reachable : r.ok));
        scored.push({ ...target, ms: (up && Number.isFinite(ms)) ? ms : null, failed: false });
      } catch (_) {
        // A request that never completed is not evidence about the target: say so separately.
        scored.push({ ...target, ms: null, failed: true });
      }
    }
    // Unreachable sinks to the bottom rather than sorting as zero, and says so: an empty cell next to
    // a target the operator is about to pick is exactly the trap this button exists to remove.
    scored.sort((a, b) => (a.ms == null) - (b.ms == null) || (a.ms || 0) - (b.ms || 0));
    fill(scored.map(s => ({ url: s.url,
      label: (s.ms != null ? s.ms + " ms" : s.failed ? t("not measured") : t("unreachable")) + " · " + s.note })));
    const best = scored.find(s => s.ms != null);
    out.textContent = best
      ? t("Fastest through this connection: {0} ({1} ms)", best.url, best.ms)
      : t("None of the shortlist answered through this connection.");
    btn.textContent = original;
    btn.disabled = false;
  });
  return el("div", { style: "display:flex;align-items:center;margin-top:6px" }, btn, out, list);
}

// manualForm builds the protocol form. Returns {el, collect}. Pass an endpoint to edit.
function manualForm(ep) {
  ep = ep || {};
  const P = ep.params || {}, T = ep.tls || {}, R = ep.transport || {};
  const proto0 = ep.protocol || "vless";
  const dyn = el("div", { id: "f-dyn" });

  function renderDyn(proto) {
    dyn.innerHTML = "";
    const add = (...e) => e.forEach(x => x && dyn.appendChild(x));
    if (proto === "vless") add(fInput("f-uuid", "UUID", P.uuid), fInput("f-flow", "Flow (e.g. xtls-rprx-vision, optional)", P.flow));
    else if (proto === "vmess") add(fInput("f-uuid", "UUID", P.uuid), fInput("f-aid", "Alter ID", P.alter_id || 0, { type: "number" }), fInput("f-scy", "Security (auto/aes-128-gcm/none)", P.security || "auto"));
    else if (proto === "trojan") add(fInput("f-password", "Password", P.password));
    else if (proto === "anytls") add(fInput("f-password", "Password", P.password),
      fSniCheck("f-sni", "SNI", T.sni), fInput("f-fp", "uTLS fingerprint (chrome…, optional)", T.fingerprint),
      fCheck("f-insecure", "Allow insecure TLS", T.insecure));
    else if (proto === "shadowsocks") add(fSelect("f-method", "Method", SS_METHODS, P.method || SS_METHODS[0]), fInput("f-password", "Password", P.password));
    else if (proto === "hysteria2") add(fInput("f-password", "Password", P.password), fSniCheck("f-sni", "SNI", T.sni), fInput("f-obfs", "Obfs (salamander, optional)", P.obfs), fInput("f-obfspw", "Obfs password", P.obfs_password), fCheck("f-insecure", "Allow insecure TLS", T.insecure));
    else if (proto === "tuic") add(fInput("f-uuid", "UUID", P.uuid), fInput("f-password", "Password", P.password), fSniCheck("f-sni", "SNI", T.sni), fInput("f-cc", "Congestion control (bbr/cubic)", P.congestion_control), fCheck("f-insecure", "Allow insecure TLS", T.insecure));
    else if (proto === "wireguard" || proto === "amneziawg") {
      add(fInput("f-pk", "Private key", P.private_key), fInput("f-ppk", "Peer public key", P.peer_public_key), fInput("f-psk", "Pre-shared key (optional)", P.pre_shared_key), fInput("f-addr", "Local address(es), comma-separated", asList(P.local_address).join(",")));
      // Per-tunnel link tuning (optional; blank = unset = current behavior). Read the
      // top-level Endpoint fields first, falling back to the legacy params.{mtu,
      // persistent_keepalive} so configs imported before these were promoted still show.
      const mtu0 = ep.mtu != null && ep.mtu !== 0 ? ep.mtu : (P.mtu != null ? P.mtu : "");
      const pka0 = ep.persistent_keepalive != null && ep.persistent_keepalive !== 0 ? ep.persistent_keepalive
        : (P.persistent_keepalive != null ? P.persistent_keepalive : "");
      add(el("div", { style: "display:flex;gap:12px" },
        el("div", { style: "flex:1;min-width:0" }, fInput("f-mtu", t("MTU"), mtu0, { type: "number", ph: t("e.g. 1420 — blank = auto") })),
        el("div", { style: "flex:1;min-width:0" }, fInput("f-keepalive", t("Persistent keepalive (s)"), pka0, { type: "number", ph: t("e.g. 25 — blank = off") }))));
      if (proto === "amneziawg") {
        // These parameters are what MAKES it AmneziaWG. Without them the tunnel is plain WireGuard, and a
        // peer that expects obfuscation simply will not answer — so "paste a .conf instead", which is what
        // stood here, left anyone entering a config by hand unable to produce a working connection.
        // H1-H4 are text, not numbers: they are 32-bit magic values that routinely exceed 2^31 and may be
        // a "min-max" range, and the .conf importer keeps them as strings for exactly that reason.
        const val = (k) => (P[k] === undefined || P[k] === null ? "" : P[k]);
        const cell = (k, label, opts) => el("div", { style: "min-width:0" },
          fInput("f-awg-" + k, label, val(k), opts || {}));
        // The track minimum is per group so each one lands on a SINGLE row: 3 and 4 fit at 96px, but the
        // five signature boxes needed 5 x 96 + 4 gaps = 520 in a 503px body, so I5 dropped to a row of its
        // own with three empty columns beside it. 84px gives exactly five across and still narrows on a
        // phone, where auto-fit reduces the count on its own.
        const grid = (min, ...kids) => el("div",
          { style: `display:grid;grid-template-columns:repeat(auto-fit,minmax(${min}px,1fr));gap:10px` }, ...kids);
        const group = (title, min, ...kids) => [el("div", { class: "card-title", style: "margin:12px 0 6px" }, title), grid(min, ...kids)];
        const det = el("details", { class: "awg-obf" },
          el("summary", {}, t("Obfuscation (AmneziaWG)")),
          el("div", { class: "hint", style: "margin:6px 0 2px" },
            t("Copy these from the provider's .conf. Leave every box blank for plain WireGuard behaviour.")),
          ...group(t("Junk packets"), 96, cell("jc", "Jc", { type: "number" }),
            cell("jmin", "Jmin", { type: "number" }), cell("jmax", "Jmax", { type: "number" })),
          ...group(t("Junk headers"), 96, cell("s1", "S1", { type: "number" }), cell("s2", "S2", { type: "number" }),
            cell("s3", "S3", { type: "number" }), cell("s4", "S4", { type: "number" })),
          ...group(t("Magic headers"), 96, cell("h1", "H1"), cell("h2", "H2"), cell("h3", "H3"), cell("h4", "H4")),
          ...group(t("Signatures (AmneziaWG 3.x)"), 84, cell("i1", "I1"), cell("i2", "I2"), cell("i3", "I3"),
            cell("i4", "I4"), cell("i5", "I5")));
        // Opened when the endpoint already carries any of them, so editing never hides a value in force.
        if (Object.keys(P).some((k) => /^(jc|jmin|jmax|s[1-4]|h[1-4]|i[1-5])$/.test(k))) det.open = true;
        add(det);
        // Which AmneziaWG runs it (Endpoint.awg_userspace). Automatic is the router's own - its kernel
        // module, or KeeneticOS's and OpenWrt's native tunnels - whenever it can carry these settings,
        // and amneziawg-go when they need a newer generation. The router's own may be generation 1 or
        // 2, so the newest one is offered here rather than decided for the operator.
        const eng = el("select", { id: "f-awg-engine" },
          el("option", { value: "auto" }, t("Automatic: the router's own AmneziaWG when it can carry these settings")),
          el("option", { value: "userspace" }, t("amneziawg-go: the newest AmneziaWG, in userspace")));
        eng.value = ep.awg_userspace ? "userspace" : "auto";
        add(el("div", { class: "field" }, el("label", {}, t("AmneziaWG engine")), eng,
          el("div", { class: "hint" }, t("amneziawg-go must be installed on the Components page. It is slower than the router's own AmneziaWG and holds 60-120 MB of RAM under load; the Apply review says which one each connection runs on."))));
      }
    } else if (proto === "olcrtc") {
      add(fSelect("f-provider", "Meet provider", ["jitsi", "telemost", "wbstream"], P.provider || "jitsi"),
        fInput("f-room", "Room URL / id", P.room),
        fInput("f-key", "Shared key (64 hex)", P.key),
        fSelect("f-transport", "Transport", ["datachannel", "vp8channel", "seichannel", "videochannel"], P.transport || "datachannel"),
        fInput("f-dns", "DNS resolver", P.dns || "8.8.8.8:53"),
        el("div", { class: "hint" }, "olcRTC tunnels through a WebRTC meet service to beat IP whitelists. Runs as a chained engine; needs the olcrtc binary on the router (Updater)."));
    } else if (proto === "socks" || proto === "http") add(fInput("f-user", "Username (optional)", P.username), fInput("f-password", "Password (optional)", P.password));

    if (["vless", "vmess", "trojan"].includes(proto)) {
      add(el("div", { class: "card-title", style: "margin:16px 0 8px" }, "Security"));
      // Reality borrows a real TLS-1.3 site's SNI as camouflage; a bad/unreachable front
      // silently breaks the connection. Suggest known-good fronts + remind to Check — shown
      // only for Reality (a plain-TLS SNI must be the server's OWN domain, not a front).
      const frontHint = el("div", { class: "hint", id: "f-sni-fronthint", style: "margin:-2px 0 8px;display:none" },
        t("Reality mimics a real site — pick a major TLS-1.3 host (suggestions in the field), then Check it's reachable + TLS 1.3."));
      add(fSelect("f-sec", "TLS", ["none", "tls", "reality"], T.type || (T.enabled ? "tls" : "none")),
        fSniCheck("f-sni", "SNI", T.sni), frontHint, fInput("f-fp", "uTLS fingerprint (chrome…, optional)", T.fingerprint),
        fInputValidated("f-pbk", "Reality public key", T.public_key, "base64 x25519 (43–44 chars)", realityPubkeyError),
        fInputValidated("f-sid", "Reality short id", T.short_id, "hex, even length, ≤16 (optional)", shortIdError));
      add(el("div", { class: "card-title", style: "margin:16px 0 8px" }, "Transport"));
      add(fSelect("f-tt", "Type", ["tcp", "ws", "grpc", "http", "httpupgrade"], R.type || "tcp"),
        fInput("f-path", "Path (ws/http)", R.path), fInput("f-host", "Host header (ws/http)", R.host),
        fInput("f-sname", "gRPC service name", R.service_name));
      // Offer the Reality fronts (datalist) + the hint ONLY when security=reality.
      const frontsDL = el("datalist", { id: "f-sni-fronts" }, ...realityFrontOptions());
      dyn.appendChild(frontsDL);
      // Upgrade the datalist to the server-curated catalog (more + labeled entries) once it loads;
      // harmless if the fetch never resolves (the REALITY_FRONTS fallback is already rendered).
      if (!REALITY_DESTS_CACHE) loadRealityDests().then(() => {
        if (REALITY_DESTS_CACHE && frontsDL.isConnected) {
          while (frontsDL.firstChild) frontsDL.removeChild(frontsDL.firstChild);
          realityFrontOptions().forEach(o => frontsDL.appendChild(o));
        }
      });
      const secSel = dyn.querySelector("#f-sec"), sniInp = dyn.querySelector("#f-sni");
      const syncFronts = () => {
        const on = secSel && secSel.value === "reality";
        if (sniInp) { if (on) sniInp.setAttribute("list", "f-sni-fronts"); else sniInp.removeAttribute("list"); }
        frontHint.style.display = on ? "" : "none";
      };
      if (secSel) secSel.addEventListener("change", syncFronts);
      syncFronts();
    }
    associateLabels(dyn); // re-wire labels for the freshly-rebuilt protocol fields (a protocol switch bypasses modal()'s one-shot associateLabels)
  }
  renderDyn(proto0);

  const protocolChoices = PROTOCOLS.slice();
  if (proto0 && !protocolChoices.includes(proto0)) protocolChoices.push(proto0);
  const protoSel = el("select", { id: "f-proto", "aria-describedby": "f-proto-support",
    onchange: e => { renderDyn(e.target.value); paintProtocolCapabilities(lastProtocolSet, null); } },
    ...protocolChoices.map(p => el("option", { value: p, "data-base-label": p }, p)));
  protoSel.value = proto0;
  const protoSupportText = el("span", {});
  const protoRetry = el("button", { class: "btn btn-sm", type: "button", style: "display:none;margin-left:8px" }, t("Retry"));
  const protoSupport = el("div", { id: "f-proto-support", class: "hint", "aria-live": "polite", style: "margin-top:6px" },
    protoSupportText, protoRetry);
  const serverInp = el("input", { type: "text", id: "f-server", value: ep.server || "" });
  const portInp = el("input", { type: "number", id: "f-port", min: "1", max: "65535", value: ep.port || "" });
  const serverErr = el("span", { class: "hint", style: "color:var(--err);display:block;font-size:.82em" });
  const portErr = el("span", { class: "hint", style: "color:var(--err);display:block;font-size:.82em" });
  serverInp.addEventListener("input", () => { serverErr.textContent = serverInp.value.trim() ? "" : t("required"); });
  portInp.addEventListener("input", () => { const v = parseInt(portInp.value, 10); portErr.textContent = (v >= 1 && v <= 65535) ? "" : t("1–65535"); });
  const wrap = el("div", {},
    el("div", { class: "field" }, el("label", {}, "Name"), el("input", { type: "text", id: "f-name", value: ep.name || "" })),
    el("div", { style: "display:flex;gap:12px" },
      el("div", { class: "field", style: "flex:2;min-width:0" }, el("label", {}, "Server"), serverInp, serverErr),
      el("div", { class: "field", style: "flex:1;min-width:0" }, el("label", {}, "Port"), portInp, portErr)),
    el("div", { class: "field" }, el("label", {}, "Protocol"), protoSel, protoSupport),
    dyn,
    (() => {
      const healthInp = el("input", { type: "text", id: "f-health", value: (ep.health && ep.health.url) || "", placeholder: "http://cp.cloudflare.com/generate_204  ·  or 1.1.1.1 / gateway IP" });
      return el("div", { class: "field", style: "margin-top:12px" },
        el("label", {}, "Health-check target (optional — what this tunnel pings to prove it's alive)"),
        healthInp, healthTargetPicker(healthInp, ep.id || ""));
    })());

  let lastProtocolSet = null;
  let protocolCapabilitiesVerified = false;
  function capabilityReason(item) {
    if (!item) return t("Support was not reported by this router.");
    return [item.detail, item.remedy].filter(Boolean).join(" ");
  }
  function paintProtocolCapabilities(response, error) {
    const set = response && response.capability_set ? response.capability_set : response;
    const items = set && set.items;
    const demo = !!(response && response.demo);
    const verified = !!items && !set.probe_error && !error;
    lastProtocolSet = verified ? response : null;
    protocolCapabilitiesVerified = verified;
    let enabledCount = 0;
    [...protoSel.options].forEach(option => {
      const requirements = connectionProtocolRequirementIDs(option.value);
      const supported = verified && ((demo && option.value !== "olcrtc") ||
        requirements.every(id => items[id] && items[id].state === "supported"));
      option.disabled = !supported;
      if (supported) enabledCount++;
      const base = option.dataset.baseLabel || option.value;
      option.textContent = base + (supported ? "" : verified ? t(" — unavailable on this router") : t(" — support not verified"));
    });
    if (!ep.protocol && verified && protoSel.selectedOptions[0] && protoSel.selectedOptions[0].disabled) {
      const first = [...protoSel.options].find(option => !option.disabled);
      if (first) { protoSel.value = first.value; renderDyn(first.value); }
    }
    protoSel.disabled = !verified || enabledCount === 0;
    protoSel.dataset.capabilityReady = verified ? "true" : "false";
    const selected = protoSel.selectedOptions[0];
    const requirements = connectionProtocolRequirementIDs(protoSel.value);
    const failed = verified ? requirements.map(id => items[id]).find(item => !item || item.state !== "supported") : null;
    if (!verified) {
      protoSupportText.textContent = t("WayHop could not verify this router. No new connection type can be selected until the check succeeds.");
      protoRetry.style.display = "inline-flex";
    } else if (demo && selected && !selected.disabled) {
      protoSupportText.textContent = t("Demo mode: this connection is saved for interface preview; no router connection is activated.");
      protoRetry.style.display = "none";
    } else if (selected && selected.disabled) {
      protoSupportText.textContent = t("This saved or imported type is retained but cannot be activated on this router. ") + capabilityReason(failed);
      protoRetry.style.display = "none";
    } else if (protoSel.value === "wireguard" || protoSel.value === "amneziawg") {
      protoSupportText.textContent = t("Supported natively: WayHop will use the router backend and can roll this connection back.");
      protoRetry.style.display = "none";
    } else {
      protoSupportText.textContent = t("Supported through the optional sing-box compatibility add-on.");
      protoRetry.style.display = "none";
    }
  }
  let protocolCheckBusy = false;
  async function loadProtocolCapabilities() {
    if (protocolCheckBusy) return;
    protocolCheckBusy = true;
    protoRetry.disabled = true;
    protoSupportText.textContent = t("Checking router support…");
    try { paintProtocolCapabilities(await api.get("/api/native/capabilities"), null); }
    catch (e) { paintProtocolCapabilities(null, e); }
    finally { protocolCheckBusy = false; protoRetry.disabled = false; }
  }
  protoRetry.addEventListener("click", loadProtocolCapabilities);
  function supportError() {
    const option = protoSel.selectedOptions[0];
    if (!protocolCapabilitiesVerified) return t("Router support is not verified yet. Retry the capability check.");
    if (!option || option.disabled) return protoSupportText.textContent || t("This connection type is unavailable on this router.");
    return "";
  }
  paintProtocolCapabilities(null, null);
  loadProtocolCapabilities();

  function collect() {
    const g = id => { const e = document.getElementById(id); return e ? e.value.trim() : ""; };
    const gc = id => { const e = document.getElementById(id); return e ? e.checked : false; };
    const proto = g("f-proto");
    const out = { id: ep.id || "", name: g("f-name"), protocol: proto, engine: proto === "amneziawg" ? "amneziawg" : proto === "olcrtc" ? "olcrtc" : "singbox", server: g("f-server"), port: parseInt(g("f-port"), 10) || 0, enabled: ep.enabled !== false, params: {} };
    if (!out.id) out.id = (proto + "-" + out.server + "-" + out.port).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    const p = out.params;
    if (["vless", "vmess", "tuic"].includes(proto)) p.uuid = g("f-uuid");
    if (proto === "vless" && g("f-flow")) p.flow = g("f-flow");
    if (proto === "vmess") { p.alter_id = parseInt(g("f-aid"), 10) || 0; p.security = g("f-scy") || "auto"; }
    if (["trojan", "anytls", "hysteria2", "tuic", "shadowsocks", "socks", "http"].includes(proto) && g("f-password")) p.password = g("f-password");
    if (proto === "shadowsocks") p.method = g("f-method");
    if (proto === "hysteria2" && g("f-obfs")) { p.obfs = g("f-obfs"); if (g("f-obfspw")) p.obfs_password = g("f-obfspw"); }
    if (proto === "tuic" && g("f-cc")) p.congestion_control = g("f-cc");
    if (["wireguard", "amneziawg"].includes(proto)) {
      p.private_key = g("f-pk"); p.peer_public_key = g("f-ppk"); if (g("f-psk")) p.pre_shared_key = g("f-psk"); if (g("f-addr")) p.local_address = g("f-addr").split(",").map(s => s.trim()).filter(Boolean);
      // Per-tunnel link tuning → top-level Endpoint fields (mtu / persistent_keepalive).
      // Blank/0 omits the field entirely (zero-value = "unset" = current behavior). When
      // the user sets an explicit value, drop any legacy params.{mtu,persistent_keepalive}
      // carried by the keep-map below so there's a single source of truth (the generator
      // reads the top-level field).
      const mtu = parseInt(g("f-mtu"), 10);
      if (mtu > 0) { out.mtu = mtu; delete p.mtu; } else { out.mtu = 0; }
      const pka = parseInt(g("f-keepalive"), 10);
      if (pka > 0) { out.persistent_keepalive = pka; delete p.persistent_keepalive; } else { out.persistent_keepalive = 0; }
    }
    if (proto === "amneziawg") {
      // Same typing rule as internal/importer/conf.go, deliberately: Jc/Jmin/Jmax and S1-S4 are small and
      // become ints, while H1-H4 and I1-I5 stay STRINGS — strconv.Atoi overflows on a 32-bit router build
      // and would zero the header, breaking the handshake. A cleared box removes the key rather than
      // leaving the previous value in place, so blanking a field in the editor actually blanks it.
      for (const k of ["jc", "jmin", "jmax", "s1", "s2", "s3", "s4"]) {
        const v = g("f-awg-" + k);
        if (v === "") delete p[k]; else p[k] = parseInt(v, 10) || 0;
      }
      for (const k of ["h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"]) {
        const v = g("f-awg-" + k);
        if (v === "") delete p[k]; else p[k] = v;
      }
      // collect() builds the endpoint from the form alone, so a field with no control here is lost on
      // save; the engine choice has one, and only an AmneziaWG connection may carry it.
      if (g("f-awg-engine") === "userspace") out.awg_userspace = true;
    }
    if (["socks", "http"].includes(proto) && g("f-user")) p.username = g("f-user");
    if (proto === "anytls") {
      out.tls = { enabled: true, type: "tls", sni: g("f-sni") || out.server, insecure: gc("f-insecure") };
      if (g("f-fp")) out.tls.fingerprint = g("f-fp");
      if (T.alpn) out.tls.alpn = T.alpn;
    }
    if (proto === "olcrtc") {
      p.provider = g("f-provider"); p.room = g("f-room"); p.key = g("f-key");
      if (g("f-transport")) p.transport = g("f-transport");
      if (g("f-dns")) p.dns = g("f-dns");
      if (!out.server && g("f-room")) { try { out.server = new URL(g("f-room")).hostname || out.server; } catch (_) {} }
      if (!out.port) out.port = 443;
    }
    if (document.getElementById("f-sec")) {
      const sec = g("f-sec");
      if (sec === "reality") out.tls = { enabled: true, type: "reality", sni: g("f-sni"), fingerprint: g("f-fp"), public_key: g("f-pbk"), short_id: g("f-sid") };
      else if (sec === "tls") out.tls = { enabled: true, type: "tls", sni: g("f-sni"), fingerprint: g("f-fp") };
      // The form has no ALPN / allow-insecure inputs, so carry them over from the
      // imported config — otherwise an unrelated edit (rename, port change) silently
      // drops them and breaks a tunnel that needed a specific ALPN or self-signed TLS.
      if (out.tls && T.alpn) out.tls.alpn = T.alpn;
      if (out.tls && sec === "tls" && T.insecure) out.tls.insecure = true;
    }
    if (["hysteria2", "tuic"].includes(proto)) { out.tls = { enabled: true, type: "tls", sni: g("f-sni") || out.server, insecure: gc("f-insecure") }; if (T.alpn) out.tls.alpn = T.alpn; }
    if (document.getElementById("f-tt")) {
      const tt = g("f-tt");
      if (tt && tt !== "tcp") { out.transport = { type: tt }; if (g("f-path")) out.transport.path = g("f-path"); if (g("f-host")) out.transport.host = g("f-host"); if (tt === "grpc" && g("f-sname")) out.transport.service_name = g("f-sname"); }
    }
    const healthEl = document.getElementById("f-health");
    const hv = healthEl ? healthEl.value.trim() : null; // null = field not rendered (preserve prior); "" = present-but-cleared (user wants the probe removed)
    if (hv) out.health = { url: hv, interval: (ep.health && ep.health.interval) || 60, tolerance: (ep.health && ep.health.tolerance) || 50 };
    else if (hv === null && ep.health) out.health = ep.health;
    // Carry over EVERY param the form has no input for, so editing (or re-saving an
    // import of) an endpoint never silently drops it. The form only surfaces the common
    // identity/transport fields; protocol params parsed from a link/.conf that have no
    // input must be preserved here or an unrelated edit (rename, port change) — and even
    // the first save after a paste-import — breaks the tunnel. AmneziaWG junk/header
    // params (jc…h4/i1-i5) MUST match the server; WG/AWG mtu + persistent_keepalive,
    // vless packet_encoding, ss udp_over_tcp/plugin(_opts), hy2 hop_ports, and tuic
    // udp_relay_mode/zero_rtt_handshake/udp_over_stream/heartbeat are all round-tripped
    // by the generator and otherwise lost. (New endpoints have empty P → no-op.)
    const keep = {
      vless: ["packet_encoding"],
      shadowsocks: ["udp_over_tcp", "plugin", "plugin_opts"],
      hysteria2: ["hop_ports"],
      tuic: ["udp_relay_mode", "zero_rtt_handshake", "udp_over_stream", "heartbeat"],
      // mtu / persistent_keepalive are NOT kept in params here — they are now surfaced as
      // explicit top-level Endpoint fields (out.mtu / out.persistent_keepalive) by the
      // WG/AWG branch above, which is their single source of truth (the generator reads the
      // top-level field). The collect() above migrates any legacy params.mtu into it.
      wireguard: ["reserved"],
      // ONLY reserved: the sixteen obfuscation fields are all rendered by the AWG form above,
      // whose collect() deletes a cleared key ON PURPOSE ("blanking a field actually blanks it").
      // Listing them here resurrected every cleared value from P - clear h1, Save, and the old
      // h1 came silently back - because a user-deleted key and a never-rendered key both read as
      // undefined. A keep entry is for fields the form does NOT render, and for AWG that is
      // reserved alone.
      amneziawg: ["reserved"],
    };
    (keep[proto] || []).forEach(k => { if (P[k] !== undefined && p[k] === undefined) p[k] = P[k]; });
    return out;
  }
  return { el: wrap, collect, supportError };
}

// externalForm edits an external-interface endpoint (engine="external"). These have
// no protocol/server — they route through an existing kernel interface — so the
// protocol form (which defaults to vless and demands server/port) does not apply.
function externalForm(ep) {
  ep = ep || {};
  const P = ep.params || {};
  const name = el("input", { type: "text", id: "f-name", value: ep.name || "" });
  const iface = el("input", { type: "text", id: "f-iface", value: P.interface || "", placeholder: "awg1" });
  const epip = el("input", { type: "text", id: "f-epip", value: P.endpoint_ip || "", placeholder: "optional — e.g. 198.51.100.20" });
  // A native tunnel gets the same health field a proxy connection has, because the monitor already
  // treats it the same: targetsFrom reads e.Health.URL for EVERY enabled endpoint and probes an
  // external one through its kernel interface. Only this dialog omitted the field, so the one shape
  // of connection live routers are actually built from could not be given a probe target —
  // it fell back to the group's, which is what made a tunnel that was fast to the probe and slow to
  // the traffic look like the best exit.
  const health = el("input", { type: "text", id: "f-health", value: (ep.health && ep.health.url) || "",
    placeholder: "http://cp.cloudflare.com/generate_204  ·  or 1.1.1.1 / gateway IP" });
  const wrap = el("div", {},
    el("div", { class: "hint", style: "margin-bottom:12px" },
      t("Routes through an existing kernel interface (an AmneziaWG / WireGuard tunnel configured outside WayHop). It has no protocol of its own.")),
    el("div", { class: "field" }, el("label", {}, t("Name")), name),
    el("div", { class: "field" }, el("label", {}, t("Bound interface")), iface),
    el("div", { class: "field" }, el("label", {}, t("Endpoint IP (anti-recursion bypass, optional)")), epip),
    el("div", { class: "field" },
      el("label", {}, t("Health-check target (optional — what this tunnel pings to prove it's alive)")),
      health, healthTargetPicker(health, ep.id || "")));
  function collect() {
    const g = id => { const e = document.getElementById(id); return e ? e.value.trim() : ""; };
    const out = { ...ep, name: g("f-name"), engine: "external", protocol: "", server: "", port: 0,
      enabled: ep.enabled !== false, params: { ...P } };
    out.params.interface = g("f-iface");
    if (g("f-epip")) out.params.endpoint_ip = g("f-epip"); else delete out.params.endpoint_ip;
    const hv = g("f-health");
    // Same shape manualForm writes, so an endpoint keeps its cadence when only the URL is edited.
    if (hv) out.health = { url: hv, interval: (ep.health && ep.health.interval) || 60, tolerance: (ep.health && ep.health.tolerance) || 50 };
    else delete out.health;
    return out;
  }
  return { el: wrap, collect };
}
