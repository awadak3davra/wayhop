// page-routing.js — route-scoped chunk for the routing page.
//
// Loaded by loadChunk() the first time that route is opened, NOT from index.html, so its bytes
// stay out of the initial payload the perf budget measures. A classic script, like app.js: these
// declarations become globals and app.js has already defined el/t/api/state by the time this runs.
//
// Everything here is reachable ONLY from this page's renderer — attributed by walking the call
// graph from every render* entry point, counting an identifier anywhere in a body (strings
// included) as a reference, so the shared set is over-estimated and this set is not.
// rlCached — how many entries a list's feed has fetched, from whichever form the profile arrived in.
//
// The panel loads the profile with ?lite=1, which sends `cidr_cache_count` instead of the array
// itself: the caches are the only large thing in the profile (15 866 CIDRs in one list on the
// operator's router) and this count is the only thing the UI ever wanted from them. The array is
// still read when present, so a profile object obtained the full way — a restore preview, a test
// fixture, a future caller — reports the same number rather than silently showing "not fetched yet"
// over a list holding thousands of entries.
function rlCached(rl, kind) {
  const arr = rl[kind + "_cache"];
  if (Array.isArray(arr)) return arr.length;
  return rl[kind + "_cache_count"] || 0;
}

// RL_MEM_COLOURS gives each list a stable slot colour so the bar and the per-row figures below it
// name the same thing. Position-based rather than hashed: the row order IS the match order, so the
// bar reads left to right the way the list does top to bottom.
const RL_MEM_COLOURS = ["var(--accent)", "var(--ok)", "var(--warn)", "#a78bfa", "#22d3ee", "#f472b6", "#facc15", "#94a3b8"];

// listMemoryCard shows what the routing lists cost in kernel memory: one bar segmented per list, and
// a figure per list beneath it.
//
// The numbers come from the kernel's own accounting (`ipset list -t`, one call), not from an estimate
// derived from entry counts — a hash set's footprint depends on its sizing, not only on how much is
// in it. A list the kernel holds no set for is ABSENT rather than zero: on a router where the plane
// is not installed nothing is measured, and "costs nothing" would be a different claim.
function listMemoryCard(lists) {
  const card = el("div", { class: "card rl-mem" });
  card.appendChild(el("div", { class: "card-title", style: "margin-bottom:8px" }, t("Kernel memory used by these lists")));
  const body = el("div", {}, el("div", { class: "hint" }, t("measuring…")));
  card.appendChild(body);
  api.get("/api/pbr/lists/memory").then(r => {
    body.innerHTML = "";
    if (!r || !r.measured) {
      body.appendChild(el("div", { class: "hint" },
        t("Not measured: the kernel routing plane is not installed on this router, so these lists hold no kernel sets.")));
      return;
    }
    const byID = new Map((r.lists || []).map(e => [e.id, e]));
    const shown = lists.map((rl, i) => ({ rl, i, bytes: (byID.get(rl.id) || {}).bytes || 0 }))
      .filter(x => x.bytes > 0);
    if (!shown.length) {
      body.appendChild(el("div", { class: "hint" },
        t("No kernel sets yet — apply the routing plane and these lists will appear here with what they cost.")));
      return;
    }
    const total = shown.reduce((n, x) => n + x.bytes, 0);
    const bar = el("div", { class: "rl-mem-bar", role: "img",
      "aria-label": tn("{0} list holding {1} of kernel memory|{0} lists holding {1} of kernel memory", shown.length, fmtBytes(total)) });
    shown.forEach(x => {
      // Percent of the total, floored at a visible sliver: a list costing 800 bytes next to one
      // costing half a megabyte would otherwise be an invisible segment with a legend entry.
      const pct = Math.max(1.5, (x.bytes * 100) / total);
      bar.appendChild(el("span", { class: "rl-mem-seg",
        style: "width:" + pct.toFixed(2) + "%;background:" + RL_MEM_COLOURS[x.i % RL_MEM_COLOURS.length],
        title: (x.rl.name || x.rl.id) + " — " + fmtBytes(x.bytes) }));
    });
    body.appendChild(bar);
    const legend = el("div", { class: "rl-mem-legend" });
    shown.sort((a, b) => b.bytes - a.bytes).forEach(x => {
      legend.appendChild(el("div", { class: "rl-mem-item" },
        el("span", { class: "rl-mem-dot", style: "background:" + RL_MEM_COLOURS[x.i % RL_MEM_COLOURS.length] }),
        el("span", { class: "rl-mem-name" }, x.rl.name || x.rl.id),
        el("span", { class: "rl-mem-size" }, fmtBytes(x.bytes))));
    });
    body.appendChild(legend);
    body.appendChild(el("div", { class: "hint" },
      t("{0} in total. This is kernel memory, held for as long as the lists are applied.", fmtBytes(total))));
  }).catch(e => {
    body.innerHTML = "";
    body.appendChild(el("div", { class: "hint" }, t("Could not read kernel memory: {0}", e.message)));
  });
  return card;
}

function rlFirstTunnel() {
  const e = state.profile.endpoints.find(x => x.enabled);
  if (e) return e.id;
  if (state.profile.groups.length) return state.profile.groups[0].id;
  return "direct";
}

function rlOutboundFor(suggest) { return suggest === "block" ? "block" : suggest === "direct" ? "direct" : rlFirstTunnel(); }

function rlSlug(s) {
  // A name in a non-Latin script (Cyrillic, CJK, etc.) strips to an empty body —
  // fall back to "list" so it isn't just "rl-". Uniqueness is then enforced by
  // rlUniqueId so two such lists don't collide to one id.
  const body = (s || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  return "rl-" + (body || "list");
}

function routingRow(rl, idx, total) {
  // The switch IS the status light. It is already the one control every row has in the same place,
  // so colouring it says "on and working" (green) or "on and its source is failing" (red) without
  // adding a second thing to look at; switched off it stays the neutral grey of a control that is
  // simply off. paintRoutingStatus writes the class; the accessible name carries the words.
  const tog = switchEl(rl.enabled, (s) => toggleRoutingList(rl, s), (rl.name || rl.id) + switchWord(rl.enabled));
  tog.setAttribute("data-rlswitch", rl.id);
  const mcount = (rl.manual || []).length;
  // What this list actually CONTAINS right now. A feed that has never been fetched holds nothing, and
  // saying "0 manual entries" hid that behind a true-but-irrelevant fact until Apply refused it.
  const feed = rl.cidr_source || rl.domain_source;
  const fetched = rlCached(rl, "cidr") + rlCached(rl, "domain");
  const src = rl.source
    ? el("span", { class: "addr", title: rl.source }, "⛓ " + rlShortURL(rl.source))
    : feed
      ? el("span", { class: "addr" + (fetched ? "" : " rl-unfetched"), title: feed },
        fetched ? t("{0} entries from the feed", fetched) : t("not fetched yet — click ↻ Refresh sources"))
      : el("span", { class: "addr" }, mcount === 1 ? t("{0} manual entry", mcount) : t("{0} manual entries", mcount));
  // Mutate rl in place (it IS the state.profile.routing_lists element) so the two
  // dropdowns compose: without this, the 2nd save spreads the stale closure and
  // reverts the 1st change, because saveRoutingList intentionally doesn't reload.
  const routeSel = routingOutboundSelect(rl.outbound, true);
  routeSel.setAttribute("aria-label", t("Route matching traffic via")); // programmatic name — the row has no per-select <label>
  routeSel.onchange = () => { const prev = rl.outbound, next = routeSel.value; rl.outbound = next; saveRoutingList(rl, t("route → {0}", nameOf(next) || next), () => { if (rl.outbound === next) { rl.outbound = prev; routeSel.value = prev; } }); }; // revert only if a newer edit hasn't superseded this one
  const dlSel = routingOutboundSelect(rl.download_via || "direct", false);
  dlSel.setAttribute("aria-label", t("Download the list via"));
  dlSel.onchange = () => { const prev = rl.download_via || "", next = dlSel.value === "direct" ? "" : dlSel.value; rl.download_via = next; saveRoutingList(rl, t("download via {0}", nameOf(dlSel.value) || dlSel.value), () => { if (rl.download_via === next) { rl.download_via = prev; dlSel.value = prev || "direct"; } }); };
  // Per-list source status is carried by the ROW's border (see .rlrow.framed) rather than by a dot
  // that had to float after a name of unpredictable length. This node is what paintRoutingStatus
  // still writes the accessible name to — colour alone is not a state anyone can read.
  const dot = el("span", { class: "rl-state", "data-rlstatus": rl.id, title: t("checking…"), role: "img", "aria-label": t("checking…") });
  const err = el("div", { class: "hint", "data-rlerr": rl.id, style: "color:var(--err);display:none;margin-top:3px;word-break:break-word" });
  // Scope badge: shown when the list is limited to specific device groups (not all clients). "except"
  // uses a ≠ prefix + its own tooltip so "only Kids" and "everyone except Kids" read differently.
  const scopeNames = (rl.scope_groups || []).map(deviceGroupName).join(", ") || t("groups");
  const scopeTag = (rl.scope_mode === "only" || rl.scope_mode === "except")
    ? el("span", { class: "badge", style: "margin-left:6px", title: rl.scope_mode === "except" ? t("All devices except these groups") : t("Only these device groups") },
      (rl.scope_mode === "except" ? "👥≠ " : "👥 ") + scopeNames)
    : null;
  // Cells map 1:1 to the .rlhead columns:
  // [#] [toggle] [list+source] [route via] [download via] [matched] [actions].
  //
  // The position is rendered rather than implied. Order decides which list wins an overlap, and a
  // page that only offered up/down arrows made the reader count rows to work out what "first" meant.
  // A disabled list keeps its number — it is still in the sequence, just skipped.
  return el("div", { class: "rlrow framed" + (rl.enabled ? "" : " off"), "data-rlframe": rl.id },
    el("div", { class: "rl-num" + (rl.enabled ? "" : " off"),
      title: rl.enabled ? t("Position {0} in match order", idx + 1) : t("Position {0}, currently skipped", idx + 1) },
      String(idx + 1)),
    tog,
    el("div", { class: "rl-list" },
      el("div", { class: "name" }, rl.name || rl.id, dot, scopeTag),
      el("div", { class: "sub" }, src),
      err),
    el("div", { class: "rl-cell", "data-col": t("route via") }, routeSel),
    el("div", { class: "rl-cell", "data-col": t("download via") }, dlSel),
    el("div", { class: "rl-cell rl-traffic", "data-col": t("matched"), "data-rltraffic": rl.id },
      el("span", { class: "rl-tr-none" }, t("checking…"))),
    el("div", { class: "acts" },
      // Order decides which list wins a match, so it is editable here rather than implied by
      // whatever order the lists happen to have been created in.
      (typeof idx === "number" && total > 1)
        ? orderControls(idx, total, rl.name || rl.id, (from, to) => moveRoutingList(from, to))
        : null,
      el("button", { class: "btn btn-sm", "aria-label": t("Edit") + " " + (rl.name || rl.id), onclick: () => openRoutingList(rl) }, "Edit"),
      el("button", { class: "btn btn-danger btn-sm", "aria-label": t("Delete") + " " + (rl.name || rl.id), onclick: () => delRoutingList(rl) }, "Delete")));
}

async function saveRoutingList(rl, msg, revert) {
  if (applyInFlight) { toast(t("Apply in progress — finish it first"), "err"); if (revert) revert(); return; } // don't mutate the staged config mid-Apply (mirrors toggleRoutingList); revert the optimistic dropdown change
  try {
    await api.post("/api/routing", rl);
    updateDirty(); // the route-via / download-via change is STAGED — light Apply/Save (mirrors toggleRoutingList)
    toast(msg || t("Saved"), "ok");
  } catch (e) {
    // The caller mutated rl (the live state.profile element) + the <select> optimistically before
    // this POST. On rejection, roll both back so the UI, client state, and server agree — otherwise
    // the dropdown keeps a value the server refused and a later Apply could persist it.
    if (revert) revert();
    toast(e.message, "err");
  }
}

async function delRoutingList(rl) {
  if (!await modalConfirm(t("Delete routing list {0}?", rl.name || rl.id))) return;
  try { await api.del("/api/routing/" + encodeURIComponent(rl.id)); await loadProfile(); route(); toast("Deleted", "ok"); }
  catch (e) { toast(e.message, "err"); }
}

// ---------- Device groups (per-device routing scope) ----------
function deviceGroups() { return (state.profile && state.profile.device_groups) || []; }

function deviceGroupName(id) { const g = deviceGroups().find(x => x.id === id); return g ? (g.name || g.id) : id; }

// Deleting a device group does not stop at the group. The daemon prunes its id from every routing
// list that scoped to it, and a list left holding no groups falls back to scope_mode "" — which
// means ALL clients. So a list that applied to one laptop can come out of this dialog applying to
// the whole LAN, silently: measured on the demo, a list stored as
// {"scope_mode":"only","scope_groups":["kids"]} reads back as {} after the group is deleted.
//
// The old wording named only the object being deleted, which is the narrower statement. The panel
// already refuses to SAVE a scoped list with zero groups ("Pick at least one device group, or
// choose All devices"), so it should not create that state on the operator's behalf without saying
// so. Pruning stays the daemon's job — a dangling scope would be worse — but the dialog now says
// which lists lose their scope and what that means for who they apply to.
async function delDeviceGroup(g, rerender) {
  const scoped = (state.profile.routing_lists || []).filter(rl => (rl.scope_groups || []).includes(g.id));
  const losing = scoped.filter(rl => (rl.scope_groups || []).length === 1);
  const keeping = scoped.filter(rl => (rl.scope_groups || []).length > 1);
  const nameOfList = rl => rl.name || rl.id;
  let msg = t("Delete device group {0}?", g.name || g.id);
  if (losing.length) {
    // One sentence has to hold for both modes: "only" widens from these devices to all, "except"
    // widens from all-but-these to all. Losing the scope lands both on "every device", so that is
    // what it says — claiming "applies to everyone now" only of an only-list would be backwards.
    msg += "\n\n" + tn("{0} routing list is scoped to this group and no other: {1}. Deleting it removes its device scope, so it will apply to EVERY device on the network.|{0} routing lists are scoped to this group and no other: {1}. Deleting it removes their device scope, so they will apply to EVERY device on the network.",
      losing.length, losing.map(nameOfList).join(", "));
  }
  if (keeping.length) {
    msg += "\n\n" + tn("{0} more list references it alongside other groups and will keep those: {1}.|{0} more lists reference it alongside other groups and will keep those: {1}.",
      keeping.length, keeping.map(nameOfList).join(", "));
  }
  if (!await modalConfirm(msg)) return;
  try { await api.del("/api/device-groups/" + encodeURIComponent(g.id)); await loadProfile(); if (rerender) rerender(); toast(t("Deleted"), "ok"); }
  catch (e) { toast(e.message, "err"); }
}

function openRoutingList(rl) {
  const editing = !!rl;
  rl = rl || { id: "", name: "", source: "", manual: [], outbound: rlFirstTunnel(), download_via: "", enabled: true, refresh_hours: 0 };
  const name = el("input", { type: "text", value: rl.name || "", placeholder: "My list" });
  const mode = el("select", {},
    el("option", { value: "url" }, "From URL (sing-box rule-set .srs / .json)"),
    el("option", { value: "manual" }, "Manual domains / IPs"));
  const source = el("input", { type: "text", value: rl.source || "", placeholder: "https://…/list.srs" });
  const manual = el("textarea", { rows: "6", class: "rl-ta", placeholder: t("one per line:\n{0}", "example.com\nopenai.com\n104.18.0.0/16") }, asList(rl.manual).join("\n"));
  const routeSel = routingOutboundSelect(rl.outbound, true);
  const dlSel = routingOutboundSelect(rl.download_via || "direct", false);
  const srcField = el("div", { class: "field" }, el("label", {}, "Rule-set URL"), source);
  const manField = el("div", { class: "field" }, el("label", {}, "Domains / IP-CIDRs (one per line)"), manual);
  // Optional auto-refresh CIDR feed (kernel modes hybrid/fast) — independent of the
  // url/manual mode above; its result is cached and unioned with any Manual entries.
  const cidrSrc = el("input", { type: "text", value: rl.cidr_source || "", placeholder: "asn:64512,64513  or  https://…/cidrs.txt" });
  const cidrHours = el("select", {},
    el("option", { value: "6" }, "Every 6 hours"),
    el("option", { value: "12" }, "Every 12 hours"),
    el("option", { value: "0" }, "Daily (default)"),
    el("option", { value: "48" }, "Every 2 days"),
    el("option", { value: "72" }, "Every 3 days"),
    el("option", { value: "168" }, "Weekly"));
  cidrHours.value = String(rl.refresh_hours || 0);
  if (cidrHours.value !== String(rl.refresh_hours || 0)) {
    // An API-set value outside the preset options (e.g. 24, 96) — inject it so the select doesn't
    // render blank and a Save doesn't silently reset the stored interval to 0.
    cidrHours.appendChild(el("option", { value: String(rl.refresh_hours) }, t("Every {0} hours", rl.refresh_hours)));
    cidrHours.value = String(rl.refresh_hours);
  }
  // The cached-count note is its OWN text node (not concatenated into the hint) so i18nApply can
  // match the static hint sentence as a dictionary key regardless of cache state.
  const cachedCIDRs = rlCached(rl, "cidr");
  const cachedNote = cachedCIDRs ? el("span", {}, " " + t("Cached: {0} CIDRs.", cachedCIDRs)) : null;
  // This .field packs two controls, so associateLabels can't wire the two <label>s 1:1 — give each an explicit name.
  cidrSrc.setAttribute("aria-label", t("Auto-refresh CIDR source (optional, kernel modes)"));
  cidrHours.setAttribute("aria-label", t("Auto-update interval"));
  const cidrField = el("div", { class: "field" },
    el("label", {}, "Auto-refresh CIDR source (optional, kernel modes)"),
    cidrSrc,
    el("label", { style: "margin-top:8px" }, "Auto-update interval"),
    cidrHours,
    el("div", { class: "hint" }, "Keep this list's IP-CIDRs current from a feed: asn:N,N (RIPEstat announced prefixes) or an https text list. Cached + unioned with Manual entries; active in hybrid/fast. Auto-updates on the interval above (min 6h, and only rewrites flash when the list actually changes); or click «↻ Refresh sources» then Apply.", cachedNote));
  function applyMode() {
    srcField.style.display = mode.value === "url" ? "" : "none";
    manField.style.display = mode.value === "manual" ? "" : "none";
  }
  mode.value = rl.source ? "url" : (rl.manual && rl.manual.length ? "manual" : "url");
  mode.onchange = applyMode; applyMode();

  // Device scope — which devices this list applies to (everyone, or only chosen device groups).
  const scopeSel = el("select", {}, el("option", { value: "all" }, t("All devices")), el("option", { value: "only" }, t("Only selected groups")), el("option", { value: "except" }, t("All except selected groups")));
  scopeSel.value = (rl.scope_mode === "only" || rl.scope_mode === "except") ? rl.scope_mode : "all";
  const scopeGroupsWrap = el("div", { style: "margin-top:8px" });
  const renderScopeGroups = () => {
    scopeGroupsWrap.innerHTML = "";
    if (scopeSel.value === "all") { scopeGroupsWrap.style.display = "none"; return; }
    scopeGroupsWrap.style.display = "";
    const groups = deviceGroups();
    if (!groups.length) {
      scopeGroupsWrap.appendChild(el("div", { class: "hint" }, t("No device groups yet.")));
      scopeGroupsWrap.appendChild(el("button", { class: "btn btn-sm", type: "button", style: "margin-top:6px", onclick: () => openDeviceGroup(null, renderScopeGroups) }, t("+ New group")));
      return;
    }
    const sel = new Set(rl.scope_groups || []);
    groups.forEach(g => {
      const cb = el("input", { type: "checkbox", value: g.id });
      if (sel.has(g.id)) cb.checked = true;
      scopeGroupsWrap.appendChild(el("label", { class: "check" }, cb, el("span", {}, g.name || g.id)));
    });
  };
  scopeSel.onchange = renderScopeGroups; renderScopeGroups();
  const scopeField = el("div", { class: "field" }, el("label", {}, t("Applies to")), scopeSel, scopeGroupsWrap,
    el("div", { class: "hint" }, t("Limit this list to certain devices — e.g. route or block it only for the kids' devices. All devices = everyone (default).")));

  async function save(btn) {
    if (!name.value.trim()) return toast("Name required", "err");
    const body = { id: rl.id || rlUniqueId(rlSlug(name.value)), name: name.value.trim(), outbound: routeSel.value,
      download_via: dlSel.value === "direct" ? "" : dlSel.value, enabled: rl.enabled };
    if (mode.value === "url") { body.source = source.value.trim(); body.manual = []; }
    else { body.manual = manual.value.split("\n").map(s => s.trim()).filter(Boolean); body.source = ""; }
    // Independent kernel-CIDR auto-refresh feed (the store preserves the system cache on a
    // same-source edit and drops it when this changes). Omit cidr_cache — server-managed.
    body.cidr_source = cidrSrc.value.trim();
    // Carry the per-list auto-update cadence through UNCONDITIONALLY (0 = daily default). It drives
    // BOTH the CIDR auto-refresh cadence and a URL list's sing-box rule_set update_interval, so
    // zeroing it when cidr_source is empty would destroy a Source-only list's custom interval on
    // any edit — and omitting it entirely lets the whole-struct Upsert zero it (the original bug).
    body.refresh_hours = parseInt(cidrHours.value, 10) || 0;
    // Preserve the explicit rule-set format on edit — the form has no input for it, so
    // dropping it makes a list whose URL extension doesn't reveal the format (a .json
    // source, or a query-string URL) silently re-infer wrong and fail to load. Catalog
    // presets all set format:"binary". (Empty = generator infers from the URL.)
    if (rl.format && body.source) body.format = rl.format;
    // Device scope: "" (all clients) or "only" + the checked device-group ids.
    body.scope_mode = (scopeSel.value === "only" || scopeSel.value === "except") ? scopeSel.value : "";
    if (body.scope_mode) {
      body.scope_groups = $$("input[type=checkbox]:checked", scopeGroupsWrap).map(c => c.value);
      if (!body.scope_groups.length) return toast(t("Pick at least one device group, or choose All devices"), "err");
    } else { body.scope_groups = []; }
    if (btn) { if (btn.disabled) return; btn.disabled = true; } // in-flight guard — no duplicate POST from a double-click (mirrors the group editors)
    try { await api.post("/api/routing", body); back.remove(); await loadProfile(); route(); toast(editing ? t("Saved {0}", body.name) : t("Added {0}", body.name), "ok"); }
    catch (e) { if (btn) btn.disabled = false; toast(e.message, "err"); }
  }
  const body = el("div", {},
    el("div", { class: "field" }, el("label", {}, "Name"), name),
    el("div", { class: "field" }, el("label", {}, "Source"), mode),
    srcField, manField, cidrField,
    el("div", { class: "field" }, el("label", {}, "Route matching traffic via"), routeSel),
    scopeField,
    el("div", { class: "field" }, el("label", {}, "Download the list via"), dlSel),
    el("div", { class: "hint" }, "Download-via lets a blocked list source (GitHub) be fetched through a working tunnel."));
  const back = modal({ title: editing ? "Edit routing list" : "New routing list", body,
    footer: [el("button", { class: "btn btn-ghost", onclick: () => back.remove() }, "Cancel"),
    el("button", { class: "btn btn-primary", onclick: (e) => save(e.currentTarget) }, editing ? "Save" : "Add")] });
}

async function openRoutingCatalog() {
  let presets;
  try { presets = await api.get("/api/routing/catalog"); }
  catch (e) { return toast(e.message, "err"); }
  const have = new Set((state.profile.routing_lists || []).map(rl => rl.id));
  // The engine's presence decides which half of the catalog is usable at all.
  const coreAvailable = !!(state.health && state.health.singbox && state.health.singbox.available);
  const groups = {};
  presets.forEach(p => { (groups[p.category] = groups[p.category] || []).push(p); });
  const body = el("div", {});
  Object.keys(groups).forEach(cat => {
    body.appendChild(el("div", { class: "card-title", style: "margin:10px 0 6px" }, cat));
    groups[cat].forEach(p => {
      // A rule-set preset matches domains, which only the proxy core can do. Adding one without an
      // engine installed produces a saved list that blocks every Apply with "the proxy core is
      // unavailable" — the product looks broken when the truth is a missing package. Offer it
      // greyed out with the reason instead.
      const blocked = p.requires_core && !coreAvailable;
      const badge = p.requires_core
        ? el("span", { class: "badge" }, t("needs sing-box"))
        : el("span", { class: "badge ok" }, t("kernel"));
      // What a preset MATCHES (domain/ip/mixed) and which plane RUNS it (kernel / sing-box) are two
      // facts the reader compares across rows, so they live in their own column at the right edge
      // rather than trailing each name at whatever x the name happens to end. Same reason the exits
      // list pins its protocol pill: a column can be scanned, a suffix has to be hunted.
      body.appendChild(el("div", { class: "conn" },
        el("div", { class: "body" },
          el("div", { class: "name" }, p.name),
          el("div", { class: "sub" }, el("span", { class: "addr", title: p.cidr_source || p.source },
            // Why it is unavailable is the DELIVERY FORMAT, not always the matching: three of these
            // carry nothing but IP prefixes and were still described as "domain rules". A .srs is a
            // compiled sing-box artifact — the kernel plane cannot read one whatever is inside it.
            !blocked ? p.description
              : p.kind === "ip"
                ? t("Ships as a sing-box rule-set, which only the core can read — install the core in Components, or pick the IP-list version above.")
                : t("Needs the sing-box core for its domain rules — install the core in Components, or pick an IP list.")))),
        el("div", { class: "preset-tags" }, el("span", { class: "badge proto" }, p.kind), badge),
        el("div", { class: "acts" },
          have.has(p.id) ? el("span", { class: "pill ok", style: "margin:0" }, el("span", { class: "dot" }), "Added")
            : el("button", {
              class: "btn btn-sm btn-primary", disabled: blocked || undefined,
              title: blocked ? t("Install sing-box to use domain rule-sets") : "",
              "aria-label": t("Add") + " " + p.name,
              onclick: () => { if (!blocked) addPreset(p, back); },
            }, "+ Add"))));
    });
  });
  const back = modal({ title: "Preset routing lists", body });
}

async function addPreset(p, back) {
  // The catalog knows how fast each feed moves, so a preset arrives already set to re-fetch at that
  // cadence instead of inheriting one default for all of them. It is an ordinary list field
  // afterwards — editable in the list's own dialog, and clamped by the refresh loop either way.
  const body = { id: p.id, name: p.name, source: p.source || "", cidr_source: p.cidr_source || "",
    domain_source: p.domain_source || "",
    format: p.format || "", manual: [], outbound: rlOutboundFor(p.suggest), download_via: "",
    refresh_hours: p.refresh_hours || 0, enabled: true };
  try {
    await api.post("/api/routing", body);
    if (back) back.remove();
    toast(t("Added {0} → {1}", p.name, nameOf(body.outbound) || body.outbound), "ok");
    // A preset is a FEED, and a feed that has never been fetched is an empty list: Apply refuses it
    // ("CIDR source has no reviewed CIDR cache"), which is a dead end reached one screen after the
    // one that caused it. Fetch it now, as part of adding it, so the list arrives with its contents.
    if (body.cidr_source || body.domain_source) {
      toast(t("Fetching {0}…", p.name), "info");
      try { await api.post("/api/routing/refresh", {}); }
      catch (e) { toast(t("{0} was added but its source could not be fetched: {1}", p.name, e.message), "err"); }
    }
    await loadProfile();
    route();
  } catch (e) { toast(e.message, "err"); }
}
