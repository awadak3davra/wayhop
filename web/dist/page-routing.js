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
      body.appendChild(el("div", { class: "hint" }, r && r.reason === "nft"
        ? t("Not measured: nftables does not report how much memory its sets use.")
        : t("Not measured: the kernel routing plane is not installed on this router, so these lists hold no kernel sets.")));
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

// rlKeepsFormat is the daemon's rule for a rule-set format carried to a new URL
// (model.CarriedRuleSetFormat, QA-150): kept when the new URL's file name has no extension (a mirror,
// a query-string feed: dropped, the generator would skip the list) or names the same format; dropped,
// to be inferred from the URL again, when it names the other format or is a plain-text list (.lst),
// which would otherwise be loaded as what it is not and stop the core.
function rlKeepsFormat(format, url) {
  const name = String(url || "").split(/[?#]/)[0].replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]*/i, "").split("/").pop();
  const dot = name.lastIndexOf("."), ext = dot < 0 ? "" : name.slice(dot).toLowerCase();
  const kind = dot < 0 ? "" : ext === ".srs" ? "binary" : ext === ".json" ? "source" : "text";
  return kind === "" || kind === format;
}

function rlSlug(s) {
  // A name in a non-Latin script (Cyrillic, CJK, etc.) strips to an empty body —
  // fall back to "list" so it isn't just "rl-". Uniqueness is then enforced by
  // rlUniqueId so two such lists don't collide to one id.
  const body = (s || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  return "rl-" + (body || "list");
}

// The lists ticked for a group change. Kept by id outside the rows so a re-render does not lose them.
const rlSelected = new Set();

// routingBulkBar is the strip above the lists: tick lists, pick one exit, and move them all there,
// either where their traffic goes or where their source is downloaded through.
function routingBulkBar(lists) {
  const ids = lists.map(l => l.id);
  for (const id of Array.from(rlSelected)) if (!ids.includes(id)) rlSelected.delete(id);
  const all = el("input", { type: "checkbox", "aria-label": t("Select all lists") });
  const count = el("span", { class: "hint" });
  const routeSel = addKeeneticPolicies(routingOutboundSelect("direct", true));
  routeSel.setAttribute("aria-label", t("Route the selected lists via"));
  const dlSel = routingOutboundSelect("direct", false);
  routeSel.style.cssText = dlSel.style.cssText = "width:auto;min-width:170px;max-width:240px";
  dlSel.setAttribute("aria-label", t("Download the selected lists via"));
  const goRoute = el("button", { class: "btn btn-sm", onclick: () => bulkSetExit("outbound", routeSel.value) }, t("Set route"));
  const goDl = el("button", { class: "btn btn-sm", onclick: () => bulkSetExit("download_via", dlSel.value === "direct" ? "" : dlSel.value) }, t("Set download"));
  const sync = () => {
    const n = rlSelected.size;
    const vis = shown().length;
    all.checked = n > 0 && n >= vis;
    all.indeterminate = n > 0 && n < vis;
    count.textContent = n ? tn("{0} list selected|{0} lists selected", n) : t("Tick lists to change their exit together");
    [routeSel, dlSel, goRoute, goDl].forEach(c => { c.disabled = n === 0; });
    document.querySelectorAll("[data-rlsel]").forEach(cb => { cb.checked = rlSelected.has(cb.getAttribute("data-rlsel")); });
  };
  // "All" means every list the filter leaves showing: a change must never reach a row the operator
  // cannot see.
  const shown = () => ids.filter(id => {
    const row = document.querySelector('[data-rlframe="' + id + '"]');
    return !row || row.style.display !== "none";
  });
  all.onchange = () => { rlSelected.clear(); if (all.checked) shown().forEach(id => rlSelected.add(id)); sync(); };
  window.rlBulkSync = sync;
  setTimeout(sync, 0);
  return el("div", { class: "rl-bulk", style: "display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:10px" },
    all, count,
    el("span", {}, t("Route via")), routeSel, goRoute,
    el("span", {}, t("Download via")), dlSel, goDl);
}

// bulkSetExit writes one field of every ticked list, one save each (the same checked save a single
// dropdown makes), and says how many went through. A list the server refuses keeps its old value.
async function bulkSetExit(field, value) {
  if (applyInFlight) { toast(t("Apply in progress — finish it first"), "err"); return; }
  const picked = (state.profile.routing_lists || []).filter(l => rlSelected.has(l.id));
  let done = 0; const failed = [];
  for (const rl of picked) {
    if (field === "download_via" && !(rl.source || rl.cidr_source || rl.domain_source)) continue; // nothing to download
    const prev = rl[field];
    rl[field] = value;
    try { keepRev(rl, await api.post("/api/routing", rl, ifMatch(rl))); done++; }
    catch (e) { rl[field] = prev; failed.push((rl.name || rl.id) + ": " + e.message); }
  }
  updateDirty();
  route();
  if (failed.length) toast(tn("{0} list changed, others refused: {1}|{0} lists changed, others refused: {1}", done, failed.join("; ")), "err");
  else toast(tn("{0} list changed|{0} lists changed", done), "ok");
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
  const routeSel = addKeeneticPolicies(routingOutboundSelect(rl.outbound, true));
  routeSel.setAttribute("aria-label", t("Route matching traffic via")); // programmatic name — the row has no per-select <label>
  // With several tunnels the row's select is the FIRST of them (the server keeps outbound = candidates[0]);
  // picking another one here makes it first and keeps the rest.
  routeSel.onchange = () => {
    const prev = rl.outbound, prevC = rl.candidates, next = routeSel.value;
    rl.outbound = next;
    if (Array.isArray(rl.candidates) && rl.candidates.length) {
      rl.candidates = rlTunnelLike(next) ? [next].concat(rl.candidates.filter(c => c !== next)) : [];
    }
    saveRoutingList(rl, t("route → {0}", nameOf(next) || next), () => { if (rl.outbound === next) { rl.outbound = prev; rl.candidates = prevC; routeSel.value = prev; } });
  }; // revert only if a newer edit hasn't superseded this one
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
      el("div", { class: "name" },
        el("input", { type: "checkbox", "data-rlsel": rl.id, checked: rlSelected.has(rl.id) ? "" : null, style: "margin-right:8px",
          "aria-label": t("Select {0}", rl.name || rl.id),
          onchange: (ev) => { if (ev.target.checked) rlSelected.add(rl.id); else rlSelected.delete(rl.id); if (window.rlBulkSync) window.rlBulkSync(); } }),
        rl.name || rl.id, dot, scopeTag),
      el("div", { class: "sub" }, src),
      err),
    // The active tunnel of a list in fastest mode rides under its route select (paintFastestRows): the
    // row grid's column tracks are measured by the layout gates, so it is a second line, not a column.
    el("div", { class: "rl-cell", "data-col": t("route via") }, routeSel,
      el("div", { class: "rl-fast", "data-rlfast": rl.id })),
    // A list of hand-typed entries downloads nothing, and a second select with the same options as
    // "route via" beside it read as a second routing choice.
    el("div", { class: "rl-cell", "data-col": t("download via") }, (rl.source || feed) ? dlSel
      : el("span", { class: "hint", title: t("Nothing to download: this list holds only what you typed in") }, "—")),
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
    // The whole list goes back, so it must still be the list as saved (QA-152).
    keepRev(rl, await api.post("/api/routing", rl, ifMatch(rl)));
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
  const base = "/api/routing/" + encodeURIComponent(rl.id);
  const finish = async () => { await loadProfile(); route(); toast("Deleted", "ok"); };
  try { await api.del(base); await finish(); }
  catch (e) {
    const data = e && e.data;
    if (!data || data.code !== "ROUTING_LIST_IN_USE") { toast(e.message, "err"); return; }
    // A DNS rule still matches on this list. Offer the way out instead of naming the rule and
    // leaving the operator to find it: take the list out of those rules (a rule that matched on
    // nothing else goes with it) and delete.
    const names = (data.dependents || []).map(d => d.name || d.id).join(", ");
    if (!await modalConfirm(t("DNS rules still use {0}: {1}. Remove the list from those rules (a rule that matches nothing else is deleted) and delete the list?",
      rl.name || rl.id, names), { okLabel: t("Remove from rules and delete") })) return;
    try { await api.del(base + "?detach=1"); await finish(); }
    catch (e2) { toast(e2.message, "err"); }
  }
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
  const routeSel = addKeeneticPolicies(routingOutboundSelect(rl.outbound, true));
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
  // A list can have both a URL and manual entries (the model takes both, and lists from the API or a
  // backup do). Such a list opens in URL mode, and its manual entries were hidden and saved as []
  // on any edit (QA-154). They stay shown and saved beside the URL.
  const both = !!(rl.source && asList(rl.manual).length);
  function applyMode() {
    srcField.style.display = mode.value === "url" ? "" : "none";
    manField.style.display = mode.value === "manual" || both ? "" : "none";
  }
  // A new list opens on hand-typed entries: "send this site through the VPN" is the common reason to
  // make one, and it used to open on a rule-set URL field most people have nothing to put in.
  mode.value = rl.source ? "url" : "manual";
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
  // TLS fragmentation (sing-box route options): only a list routed direct uses it, so the field shows
  // only then, and leaving direct clears it rather than keeping a hidden setting.
  const fragSel = el("select", {}, el("option", { value: "" }, t("Off")),
    el("option", { value: "record" }, t("TLS records")), el("option", { value: "handshake" }, t("TCP segments")));
  fragSel.value = rl.tls_fragment || "";
  const fragField = el("div", { class: "field" }, el("label", {}, t("Split the TLS handshake")), fragSel,
    el("div", { class: "hint" }, t("Against DPI that reads the site name in the TLS handshake. Try TLS records first; works only in tun or hybrid mode.")));
  const syncFrag = () => { fragField.style.display = routeSel.value === "direct" ? "" : "none"; };
  routeSel.addEventListener("change", syncFrag); syncFrag();
  const fast = fastestEditor(rl, routeSel);

  async function save(btn) {
    if (!name.value.trim()) return toast("Name required", "err");
    const body = { id: rl.id || rlUniqueId(rlSlug(name.value)), name: name.value.trim(), outbound: routeSel.value,
      download_via: dlSel.value === "direct" ? "" : dlSel.value, enabled: rl.enabled };
    const lines = manual.value.split("\n").map(s => s.trim()).filter(Boolean);
    if (mode.value === "url") { body.source = source.value.trim(); body.manual = both ? lines : []; }
    else { body.manual = lines; body.source = ""; }
    // Independent kernel-CIDR auto-refresh feed (the store preserves the system cache on a
    // same-source edit and drops it when this changes). Omit cidr_cache — server-managed.
    body.cidr_source = cidrSrc.value.trim();
    // Carry the per-list auto-update cadence through UNCONDITIONALLY (0 = daily default). It drives
    // BOTH the CIDR auto-refresh cadence and a URL list's sing-box rule_set update_interval, so
    // zeroing it when cidr_source is empty would destroy a Source-only list's custom interval on
    // any edit — and omitting it entirely lets the whole-struct Upsert zero it (the original bug).
    body.refresh_hours = parseInt(cidrHours.value, 10) || 0;
    // Preserve the domain feed on edit for the same reason, with a sharper consequence. The form
    // has no input for domain_source, and the store reads a MISSING one as a CHANGED one: it then
    // drops domain_cache and domain_refreshed along with it. So renaming a list, or changing its
    // outbound, used to delete both the feed URL and every domain it had fetched — the list stayed
    // in the panel and quietly stopped matching anything, with nothing left to refill it.
    if (rl.domain_source) body.domain_source = rl.domain_source;
    // Preserve the explicit rule-set format on edit — the form has no input for it, so
    // dropping it makes a list whose URL extension doesn't reveal the format (a .json
    // source, or a query-string URL) silently re-infer wrong and fail to load. Catalog
    // presets all set format:"binary". (Empty = generator infers from the URL.)
    // On a new URL the format stays only while rlKeepsFormat says so: kept, a preset moved to a .json
    // list was read as binary, and a rule set that fails to load stops the whole core (QA-150).
    if (rl.format && body.source && (body.source === (rl.source || "").trim() || rlKeepsFormat(rl.format, body.source))) body.format = rl.format;
    body.tls_fragment = routeSel.value === "direct" ? fragSel.value : "";
    // Device scope: "" (all clients) or "only" + the checked device-group ids.
    body.scope_mode = (scopeSel.value === "only" || scopeSel.value === "except") ? scopeSel.value : "";
    if (body.scope_mode) {
      body.scope_groups = $$("input[type=checkbox]:checked", scopeGroupsWrap).map(c => c.value);
      if (!body.scope_groups.length) { adv.open = true; return toast(t("Pick at least one device group, or choose All devices"), "err"); }
    } else { body.scope_groups = []; }
    const fastErr = fast.collect(body);
    if (fastErr) return toast(fastErr, "err");
    if (btn) { if (btn.disabled) return; btn.disabled = true; } // in-flight guard — no duplicate POST from a double-click (mirrors the group editors)
    // An edit is refused, nothing saved, if the list was saved by anything else since it was loaded (QA-152).
    try { await api.post("/api/routing", body, ifMatch(rl)); back.remove(); await loadProfile(); route(); toast(editing ? t("Saved {0}", body.name) : t("Added {0}", body.name), "ok"); }
    catch (e) { if (btn) btn.disabled = false; toast(e.message, "err"); }
  }
  // Name, entries and where they go are the whole of the common case. The rest (a CIDR feed, a device
  // scope, the download path) is folded away, and opens by itself for a list that already uses any of
  // it, so nothing that is set is ever hidden.
  const adv = el("details", { class: "form-adv" }, el("summary", {}, t("Advanced")),
    cidrField,
    scopeField,
    el("div", { class: "field" }, el("label", {}, "Download the list via"), dlSel,
      el("div", { class: "hint" }, t("Feeds and rule sets leave through this connection. If it is down the list keeps what it has and tries again, and never falls to your provider, unless this is a failover group ending in direct. A proxy connection has no network link to bind to, so its feeds leave over your provider."))),
    el("div", { class: "hint" }, "Download-via lets a blocked list source (GitHub) be fetched through a working tunnel."));
  adv.open = !!(rl.cidr_source || rl.download_via || rl.scope_mode === "only" || rl.scope_mode === "except");
  const body = el("div", {},
    el("div", { class: "field" }, el("label", {}, "Name"), name),
    el("div", { class: "field" }, el("label", {}, "Source"), mode),
    srcField, manField,
    el("div", { class: "field" }, el("label", {}, "Route matching traffic via"), routeSel),
    fast.node,
    fragField,
    adv);
  const back = modal({ title: editing ? "Edit routing list" : "New routing list", body,
    footer: [el("button", { class: "btn btn-ghost", onclick: () => back.remove() }, "Cancel"),
    el("button", { class: "btn btn-primary", onclick: (e) => save(e.currentTarget) }, editing ? "Save" : "Add")] });
}

// The router's own KeeneticOS access policies as list exits (competitor gap 6): NDM then routes the
// list by the policy's ladder, fail-back and drop. Asked once per load, shared by every select on the
// page; a router that is not KeeneticOS answers 422 and the selects stay as they are.
function addKeeneticPolicies(sel) {
  state.ndmPoliciesP = state.ndmPoliciesP || api.get("/api/keenetic/policies")
    .then(ps => (state.ndmPolicies = ps || []))
    .catch(e => { if (e.status !== 422) toast(e.message, "err"); return (state.ndmPolicies = []); });
  state.ndmPoliciesP.then(ps => ps.forEach(pol => {
    const v = "ndm-policy:" + pol.name, label = "⌂ " + (pol.description || pol.name) + " · " + t("Keenetic access policy");
    const have = [...sel.options].find(o => o.value === v); // routingOutboundSelect's "⚠ unavailable" until now
    if (have) have.textContent = label; else sel.appendChild(el("option", { value: v }, label));
  }));
  return sel;
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

// refusedLines names, by list, the lines a refreshed feed loaded without as too broad for any list
// (QA-111): not failures, and the refresh answers them apart. name(id), if given, names the list.
// Also called by app.js's refreshCidrSources, whose button only this page renders.
function refusedLines(r, name) {
  const of = id => name ? name(id) : ((state.profile.routing_lists || []).find(l => l.id === id) || {}).name || id;
  return Object.entries((r && r.refused) || {}).map(([id, x]) =>
    t("{0}: refused as too broad: {1}", of(id), x.slice(0, 3).join(", ") + (x.length > 3 ? " +" + (x.length - 3) : "")));
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
      // This list only (QA-032): refetching every feed kept Apply blocked for tens of seconds, and its
      // per-feed failures arrive in a 200 that was never read, so a failed fetch went unsaid.
      try {
        const r = await api.post("/api/routing/refresh", { id: body.id });
        if (r && r.errors && r.errors.length) toast(t("{0} was added but its source could not be fetched: {1}", p.name, redactSecrets(r.errors.join("; "))), "err");
        refusedLines(r, () => p.name).forEach(m => toast(m, "info")); // loaded, without lines no list may carry
      } catch (e) { toast(t("{0} was added but its source could not be fetched: {1}", p.name, e.message), "err"); }
    }
    await loadProfile();
    route();
  } catch (e) { toast(e.message, "err"); }
}

// Routing lists from what the operator already runs (competitor gap 14): the Keenetic's own FQDN
// object-groups, or a HydraRoute Neo domain.conf / ip.list pasted in. The server only parses, and
// changes nothing; each chosen group becomes an ordinary list through POST /api/routing, as a preset
// does. The Keenetic half asks once on open and stays hidden where the router is not a Keenetic
// (the server answers 422), so no platform guess is needed here.
async function openRoutingImport() {
  const rows = el("div", {});
  const picked = new Map(); // checkbox -> the server's suggested list
  const routeSel = addKeeneticPolicies(routingOutboundSelect(rlOutboundFor("proxy"), true));
  const show = (res) => {
    rows.textContent = "";
    picked.clear();
    // The heading names the router's own lists; a paste's results replace them and must not sit under it.
    keen.hidden = res.source !== "keenetic";
    (res.groups || []).forEach(g => {
      const s = g.suggested;
      const ok = !!(s && (s.manual || []).length);
      const box = el("input", { type: "checkbox", checked: ok || undefined, disabled: !ok || undefined });
      if (ok) picked.set(box, s);
      const bits = [t("{0} names, {1} networks", (g.domains || []).length, (g.cidrs || []).length)];
      if (g.route) bits.push(t("was routed via {0}", g.route));
      const skipped = g.skipped_total || (g.skipped || []).length;
      if (skipped) bits.push(t("{0} skipped", skipped));
      if (g.refused) bits.push(g.refused);
      rows.appendChild(el("label", { class: "conn" }, box,
        el("div", { class: "body" }, el("div", { class: "name" }, ok ? s.name : (g.description || g.name)),
          el("div", { class: "sub" }, bits.join(" · ")))));
    });
    if (!picked.size) rows.appendChild(el("div", { class: "hint" }, t("Nothing to import")));
  };
  const keen = el("div", { hidden: true }, el("div", { class: "card-title" }, t("This Keenetic's own lists")));
  const text = el("textarea", { rows: 5, placeholder: t("Paste a HydraRoute domain.conf or ip.list") });
  const read = el("button", { class: "btn btn-sm", onclick: async () => {
    try { show(await api.post("/api/routing/import/hydraroute", { text: text.value })); }
    catch (e) { toast(e.message, "err"); }
  } }, t("Read"));
  async function add(btn) {
    const lists = [...picked].filter(([box]) => box.checked).map(([, s]) => s);
    if (!lists.length) return toast(t("Nothing to import"), "err");
    if (btn.disabled) return;
    btn.disabled = true;
    let n = 0;
    for (const s of lists) {
      const body = { id: rlUniqueId(rlSlug(s.name)), name: s.name, manual: s.manual, outbound: routeSel.value, enabled: true };
      // One at a time, each against the profile the previous one changed, so ids stay unique.
      try { await api.post("/api/routing", body); n++; await loadProfile(); }
      catch (e) { toast(s.name + ": " + e.message, "err"); }
    }
    back.remove();
    if (n) toast(t("Added {0} lists", n), "ok");
    route();
  }
  const body = el("div", {}, keen, rows,
    el("div", { class: "field" }, text, read),
    el("div", { class: "field" }, el("label", {}, t("Route matching traffic via")), routeSel));
  const back = modal({ title: t("Import routing lists"), body,
    footer: [el("button", { class: "btn btn-ghost", onclick: () => back.remove() }, t("Cancel")),
      el("button", { class: "btn btn-primary", onclick: (e) => add(e.currentTarget) }, t("Add selected"))] });
  try { show(await api.get("/api/routing/import/keenetic")); }
  catch (e) { if (e.status !== 422) toast(e.message, "err"); }
}

// ---------- Fastest tunnel per list ----------
// A list with two or more tunnels may leave by the fastest WORKING one, measured to its own
// destinations (KeeneticOS kernel plane; listfastest.go). The editor collects the tunnels and the
// policy, the row shows the active tunnel, and the panel shows the measurements and the journal.

// rlTunnelLike: an outbound that can be one of several tunnels (not direct/block or an NDM policy).
function rlTunnelLike(id) { return !!id && id !== "direct" && id !== "block" && !String(id).startsWith("ndm-policy:"); }

// rlExpandCandidates mirrors model.ListCandidates: groups expanded in order, duplicates dropped.
function rlExpandCandidates(ids) {
  const p = state.profile || {}, out = [], seen = new Set();
  const walk = (id, visiting) => {
    if (!rlTunnelLike(id) || visiting.has(id)) return;
    if ((p.endpoints || []).some(e => e.id === id)) { if (!seen.has(id)) { seen.add(id); out.push(id); } return; }
    const g = (p.groups || []).find(x => x.id === id);
    if (g) { visiting.add(id); (g.members || []).forEach(m => walk(m, visiting)); visiting.delete(id); }
  };
  (ids || []).forEach(id => walk(id, new Set()));
  return out;
}

const FASTEST_MODE_WORDS = { auto: "auto", pinned: "pinned", fallback: "fallback", all_down: "all down", targets_down: "targets unreachable" };
function fastestModeBadge(mode) {
  const cls = mode === "all_down" ? "badge rl-fast-err" : mode === "pinned" || mode === "fallback" || mode === "targets_down" ? "badge rl-fast-warn" : "badge";
  return el("span", { class: cls }, t(FASTEST_MODE_WORDS[mode] || "auto"));
}

// fastestEditor is the editor's "tunnels + fastest" block under the route select.
function fastestEditor(rl, routeSel) {
  const pol = Object.assign({ enabled: false, targets: [], interval_sec: 0, switch_delta_ms: 0, switch_delta_pct: 0,
    min_dwell_sec: 0, on_all_down: "", reset_on_switch: false, notify: false }, rl.fastest || {});
  const extra = new Set((rl.candidates || []).slice(1));
  const tunnels = el("div", { class: "rl-fast-tunnels" });
  const fastCb = el("input", { type: "checkbox" });
  fastCb.checked = !!pol.enabled;
  const fastHint = el("div", { class: "hint" });
  const num = (v, min, max, ph) => el("input", { type: "number", min: String(min), max: String(max), placeholder: ph, value: v ? String(v) : "", style: "max-width:110px" });
  const interval = num(pol.interval_sec, 30, 600, "60");
  const dms = num(pol.switch_delta_ms, 0, 5000, "30");
  const dpct = num(pol.switch_delta_pct, 0, 500, "20");
  const dwell = num(pol.min_dwell_sec, 0, 86400, "120");
  interval.setAttribute("aria-label", t("Measure every (seconds)"));
  dms.setAttribute("aria-label", t("Switch threshold, ms"));
  dpct.setAttribute("aria-label", t("Switch threshold, %"));
  dwell.setAttribute("aria-label", t("Minimum time on a tunnel (seconds)"));
  const tgtMode = el("select", {}, el("option", { value: "auto" }, t("Automatic")), el("option", { value: "custom" }, t("My own")));
  tgtMode.value = (pol.targets || []).length ? "custom" : "auto";
  const tgts = el("textarea", { rows: "3", class: "rl-ta", placeholder: "149.154.167.51:443\nwww.example.com:443" }, (pol.targets || []).join("\n"));
  tgts.setAttribute("aria-label", t("Probe targets (host:port, up to 3)"));
  const autoNote = el("div", { class: "hint" });
  const pickAuto = el("button", { class: "btn btn-sm", type: "button" }, t("Pick automatically"));
  pickAuto.onclick = async () => {
    tgtMode.value = "auto"; syncTargets();
    if (!rl.id) { autoNote.textContent = t("Targets are picked from the list's own addresses after it is saved."); return; }
    try {
      const d = await api.get("/api/lists/" + encodeURIComponent(rl.id) + "/fastest");
      autoNote.textContent = t("Automatic targets: {0}", (d.auto_targets ? d.targets : []).join(", ") || "—");
    } catch (e) { autoNote.textContent = e.message; }
  };
  const syncTargets = () => { tgts.style.display = tgtMode.value === "custom" ? "" : "none"; };
  tgtMode.onchange = syncTargets; syncTargets();
  const allDown = el("select", {}, el("option", { value: "wan" }, t("Through the provider")),
    el("option", { value: "block" }, t("Block")), el("option", { value: "keep" }, t("Keep the last tunnel")));
  allDown.value = pol.on_all_down || "wan";
  // What "fastest" means for this list. Left on Automatic, a media list (Telegram, Instagram,
  // YouTube) chooses by both, any other list by delay.
  const modeSel = el("select", {}, el("option", { value: "" }, tpMediaList(rl && rl.id, rl && rl.name) ? t("Automatic (both)") : t("Automatic (delay)")), el("option", { value: "latency" }, t("Delay (latency)")),
    el("option", { value: "throughput" }, t("Download speed")), el("option", { value: "mixed" }, t("Both: drop the slow to answer, then the highest speed")));
  modeSel.value = pol.mode || "";
  const resetCb = el("input", { type: "checkbox" }); resetCb.checked = !!pol.reset_on_switch;
  const notifyCb = el("input", { type: "checkbox" }); notifyCb.checked = !!pol.notify;
  const adv = el("details", { class: "form-adv" }, el("summary", {}, t("Fine tuning")),
    el("div", { class: "field" }, el("label", {}, t("Choose by")), modeSel,
      el("div", { class: "hint" }, t("Automatic: both for Telegram, Instagram and YouTube lists, delay for the rest. Speed is what Measure speed last found; older than 24 hours it is not used."))),
    el("div", { class: "field" }, el("label", {}, t("Probe targets")), tgtMode, pickAuto, tgts, autoNote,
      el("div", { class: "hint" }, t("Up to three host:port destinations that stand for this list. Automatic: built-in ones for well-known lists, else addresses or names from the list."))),
    el("div", { class: "field" }, el("label", {}, t("Measure every (seconds)")), interval),
    el("div", { class: "field" }, el("label", {}, t("Switch when faster by")),
      el("div", { style: "display:flex;gap:8px;align-items:center;flex-wrap:wrap" }, dms, el("span", {}, t("ms and")), dpct, el("span", {}, "%"))),
    el("div", { class: "field" }, el("label", {}, t("Minimum time on a tunnel (seconds)")), dwell),
    el("div", { class: "field" }, el("label", {}, t("When every tunnel is down")), allDown),
    el("label", { class: "check" }, resetCb, el("span", {}, t("Reset connections on switch"))),
    el("label", { class: "check" }, notifyCb, el("span", {}, t("Notify in Telegram"))));
  const fastRow = el("label", { class: "check" }, fastCb, el("span", {}, t("Fastest tunnel for this list")));
  const node = el("div", { class: "field rl-fast-edit" },
    el("label", {}, t("More tunnels for this list")), tunnels,
    el("div", { class: "hint" }, t("The list may leave by any of these. Without the option below the first one is used.")),
    fastRow, fastHint, adv);
  // linked: the tunnels with an interface of their own, which a list's table can be pointed at (null
  // until the router said). note: what the choice covers on a router whose kernel plane routes
  // addresses only (OpenWrt), in the router's own words.
  let supported = true, why = "", linked = null, note = "";
  const sync = () => {
    const first = routeSel.value;
    tunnels.innerHTML = "";
    if (!rlTunnelLike(first)) {
      tunnels.appendChild(el("div", { class: "hint" }, t("Direct, block and access policies have no alternatives.")));
    } else {
      const p = state.profile;
      const opts = (p.endpoints || []).filter(e => e.enabled).map(e => [e.id, e.name || e.id])
        .concat((p.groups || []).map(g => [g.id, "▣ " + (g.name || g.id)]));
      opts.filter(([id]) => id !== first).forEach(([id, label]) => {
        const cb = el("input", { type: "checkbox", value: id });
        cb.checked = extra.has(id);
        cb.onchange = () => { if (cb.checked) extra.add(id); else extra.delete(id); sync(); };
        tunnels.appendChild(el("label", { class: "check" }, cb, el("span", {}, label)));
      });
    }
    const cands = rlTunnelLike(first) ? rlExpandCandidates([first].concat([...extra])) : [];
    const n = cands.length;
    const nLinked = linked ? cands.filter(id => linked.has(id)).length : n;
    const can = n >= 2 && nLinked >= 2 && supported;
    fastCb.disabled = !can;
    fastRow.classList.toggle("off", !can);
    if (!supported) fastHint.textContent = why || t("Not available on this router.");
    else if (n < 2) fastHint.textContent = t("Needs at least two tunnels.");
    else if (nLinked < 2) fastHint.textContent = t("Needs at least two tunnels with an interface of their own on the router (WireGuard, AmneziaWG). Tunnels that run inside the proxy core cannot be switched between.");
    else fastHint.textContent = t("Measures each tunnel to this list's own destinations and uses the fastest working one.") + (note ? " " + note : "");
    if (!can) fastCb.checked = false;
    adv.style.display = fastCb.checked ? "" : "none";
  };
  fastCb.onchange = sync;
  routeSel.addEventListener("change", sync);
  sync();
  const info = state.fastestInfo ? Promise.resolve(state.fastestInfo) : (typeof loadFastestInfo === "function" ? loadFastestInfo() : Promise.resolve(null));
  info.then(d => {
    if (!d) return;
    if (d.supported === false) { supported = false; why = d.reason || ""; }
    if (Array.isArray(d.linked)) linked = new Set(d.linked);
    note = d.note || "";
    sync();
  });
  adv.open = !!(pol.mode || (pol.targets || []).length || pol.interval_sec || pol.switch_delta_ms || pol.switch_delta_pct || pol.min_dwell_sec || pol.on_all_down || pol.reset_on_switch || pol.notify);

  // collect writes candidates/fastest into the request body; a string return is a refusal.
  function collect(body) {
    const first = routeSel.value;
    const more = rlTunnelLike(first) ? [...extra].filter(x => x !== first) : [];
    body.candidates = more.length ? [first].concat(more) : [];
    if (!fastCb.checked && !rl.fastest) return "";
    const targets = tgtMode.value === "custom" ? tgts.value.split("\n").map(s => s.trim()).filter(Boolean) : [];
    if (targets.length > 3) return t("At most three probe targets.");
    if (targets.some(x => !/^[^\s:]+:\d{1,5}$|^\[[0-9a-fA-F:]+\]:\d{1,5}$/.test(x))) return t("A probe target is host:port, e.g. www.example.com:443.");
    const iv = parseInt(interval.value, 10) || 0;
    if (iv && (iv < 30 || iv > 600)) return t("Measure every 30 to 600 seconds.");
    body.fastest = Object.assign({}, rl.fastest || {}, {
      enabled: fastCb.checked, targets, mode: modeSel.value || undefined,
      interval_sec: iv, switch_delta_ms: parseInt(dms.value, 10) || 0, switch_delta_pct: parseInt(dpct.value, 10) || 0,
      min_dwell_sec: parseInt(dwell.value, 10) || 0, on_all_down: allDown.value === "wan" ? "" : allDown.value,
      reset_on_switch: resetCb.checked, notify: notifyCb.checked,
    });
    return "";
  }
  return { node, collect };
}

// paintFastestRows writes the active tunnel under each fastest list's route select.
function paintFastestRows(info) {
  const by = {};
  ((info && info.lists) || []).forEach(s => { by[s.id] = s; });
  document.querySelectorAll("[data-rlfast]").forEach(box => {
    const s = by[box.getAttribute("data-rlfast")];
    box.innerHTML = "";
    if (!s || !s.active) return;
    const parts = [el("span", { class: "rl-fast-ico", "aria-hidden": "true" }, "⚡")];
    if (!s.applied) parts.push(el("span", { class: "hint" }, t("fastest: after Apply")));
    else if (s.mode === "all_down") parts.push(fastestModeBadge("all_down"));
    else {
      parts.push(el("span", { class: "rl-fast-now" }, s.current_name || "—"));
      if (s.rtt_ms) parts.push(el("span", { class: "hint" }, t("{0} ms", s.rtt_ms)));
      parts.push(fastestModeBadge(s.mode || "auto"));
      if (s.since) parts.push(el("span", { class: "hint" }, t("since {0}", fmtClock(s.since))));
    }
    box.appendChild(el("button", { class: "rl-fast-link", type: "button", title: t("Open the list's measurements"),
      onclick: () => openFastestPanel(s.id) }, ...parts));
  });
}

// openFastestPanel shows one list's measurements, its controls and its journal.
async function openFastestPanel(id) {
  let d;
  try { d = await api.get("/api/lists/" + encodeURIComponent(id) + "/fastest"); await loadThroughput(); }
  catch (e) { toast(e.message, "err"); return; }
  const body = el("div", { class: "rl-fast-panel" });
  const back = modal({ title: t("Fastest tunnel: {0}", d.name || d.id), body,
    footer: [el("button", { class: "btn btn-ghost", onclick: () => back.remove() }, t("Close"))] });
  const reload = async () => { back.remove(); await loadFastestInfo(); paintFastestRows(state.fastestInfo); openFastestPanel(id); };
  const staged = async (path, payload, msg) => {
    try {
      await api.post("/api/lists/" + encodeURIComponent(id) + "/fastest/" + path, payload || {});
      await loadProfile(); updateDirty();
      toast(msg + " — " + t("staged: Review and Apply to run it"), "ok");
      reload();
    } catch (e) { toast(e.message, "err"); }
  };
  // Head: where it goes now and why.
  const head = el("div", { class: "row-between", style: "gap:var(--sp-3);flex-wrap:wrap;align-items:center" });
  if (!d.applied) head.appendChild(el("div", { class: "hint" }, t("The router does not run this yet: Review and Apply.")));
  else head.appendChild(el("div", {},
    el("strong", {}, d.current_name || "—"), " ",
    d.rtt_ms ? el("span", { class: "hint" }, t("{0} ms", d.rtt_ms) + " ") : null,
    fastestModeBadge(d.mode || "auto"), " ",
    d.since ? el("span", { class: "hint" }, t("since {0}", fmtClock(d.since))) : null));
  const probeBtn = el("button", { class: "btn btn-sm", type: "button" }, t("Probe now"));
  // Nothing measures a list the router does not run (the line beside it says so): no "Measuring within 20 s".
  probeBtn.disabled = !d.applied;
  probeBtn.onclick = async () => {
    probeBtn.disabled = true;
    try { const r = await api.post("/api/lists/" + encodeURIComponent(id) + "/fastest/probe", {}); toast(t("Measuring within {0} s", r.within_s || 20), "ok"); setTimeout(() => { if (document.body.contains(body)) reload(); }, ((r.within_s || 20) + 4) * 1000); }
    catch (e) { probeBtn.disabled = false; toast(e.message, "err"); }
  };
  head.appendChild(probeBtn);
  // Every tunnel of the list, one after another; the list's own media sources first for a media list.
  head.appendChild(tpButton("list", id, "btn btn-sm", d.name || d.id));
  body.setAttribute("data-tp-live", "1");
  body._tpLive = done => { if (done && document.body.contains(body)) reload(); };
  body.appendChild(head);
  body.appendChild(el("div", { class: "hint" }, d.election === "mixed" ? t("Chooses by both: tunnels much slower to answer are dropped, then the highest measured speed wins.")
    : d.election === "throughput" ? t("Chooses by the highest measured download speed.") : t("Chooses by the lowest delay.")));
  if (d.election_now === "delay") body.appendChild(el("div", { class: "hint" }, t("By delay for now: {0} of {1} live tunnels have a fresh speed measurement, and speed is compared only between measured ones.", d.sampled || 0, d.sampled_of || 0)));
  else if (d.election_now === "throughput") body.appendChild(el("div", { class: "hint" }, d.sample_class === "media"
    ? t("Speeds compared are those of the Telegram media file.") : t("Speeds compared are those of the test servers.")));
  if (d.pin_dead) body.appendChild(el("div", { class: "hint", style: "color:var(--warn)" }, t("The pinned tunnel is unavailable: automatic choice meanwhile.")));
  if (d.calm) body.appendChild(el("div", { class: "hint", style: "color:var(--warn)" }, t("Frequent switches: the list waits four times longer before the next one.")));
  if ((d.dead_targets || []).length) body.appendChild(el("div", { class: "hint", style: "color:var(--warn)" },
    t("A target answers through no tunnel, so measuring it says nothing: {0}", d.dead_targets.join(", "))));
  if (d.pinned) body.appendChild(el("div", { class: "row-between", style: "gap:8px;align-items:center;margin-top:8px" },
    el("span", {}, t("Pinned to {0}", (d.candidates.find(c => c.id === d.pinned) || {}).name || d.pinned) + " " +
      (d.pinned_until ? t("until {0}", new Date(d.pinned_until * 1000).toLocaleString()) : t("until cancelled"))),
    el("button", { class: "btn btn-sm", type: "button", onclick: () => staged("unpin", {}, t("Unpinned")) }, t("Unpin"))));

  // Matrix: tunnel x target.
  const targets = d.targets || [];
  let best = "", bestScore = Infinity;
  Object.entries(d.measurements || {}).forEach(([c, m]) => { if (m.alive && m.score_ms < bestScore) { best = c; bestScore = m.score_ms; } });
  const tbl = el("table", { class: "tbl rl-fast-matrix" });
  tbl.appendChild(el("thead", {}, el("tr", {}, el("th", {}, t("Tunnel")), ...targets.map(x => el("th", { class: "mono" }, x)),
    el("th", {}, t("Score")), el("th", {}, t("Speed")), el("th", {}, ""))));
  const tb = el("tbody", {});
  // The Speed column shows the figures the list compares: the Telegram media file's while those elect it.
  const tpClass = d.election_now === "throughput" && d.sample_class === "media" ? "media" : "";
  (d.candidates || []).forEach(c => {
    const row = (d.matrix || {})[c.id] || {};
    const m = (d.measurements || {})[c.id];
    const cells = targets.map(x => {
      const cell = row[x];
      if (!cell) return el("td", { class: "hint" }, "—");
      return el("td", { class: cell.ok ? "" : "rl-fast-bad", title: t("measured at {0}", fmtClock(cell.at)) },
        cell.ok ? t("{0} ms", cell.median_ms) : t("no answer"), cell.loss_pct && cell.ok ? el("span", { class: "hint" }, " · " + t("{0}% lost", cell.loss_pct)) : null);
    });
    const pinSel = el("select", { class: "rl-sel", style: "max-width:140px" },
      el("option", { value: "" }, t("Pin…")), el("option", { value: "15" }, t("for 15 min")), el("option", { value: "60" }, t("for 1 hour")), el("option", { value: "0" }, t("until cancelled")));
    pinSel.setAttribute("aria-label", t("Pin {0}", c.name));
    pinSel.onchange = () => { if (pinSel.value === "") return; staged("pin", { candidate: c.id, minutes: parseInt(pinSel.value, 10) }, t("Pinned to {0}", c.name)); };
    const exBtn = el("button", { class: "btn btn-sm", type: "button" }, c.excluded ? t("Include") : t("Exclude"));
    exBtn.onclick = () => staged("exclude", { candidate: c.id, excluded: !c.excluded }, c.excluded ? t("Included {0}", c.name) : t("Excluded {0}", c.name));
    tb.appendChild(el("tr", { class: (c.id === best ? "rl-fast-best" : "") + (c.excluded ? " off" : "") },
      el("td", {}, c.name, c.id === d.current ? el("span", { class: "badge", style: "margin-left:6px" }, t("now")) : null,
        c.excluded ? el("span", { class: "hint" }, " " + t("excluded")) : null),
      ...cells,
      el("td", {}, m ? (m.alive ? t("{0} ms", m.score_ms) : t("down")) : "—"),
      el("td", { style: "white-space:nowrap" }, tpSpan(c.id, tpClass) || el("span", { class: "hint" }, "—")),
      // A tunnel inside the proxy core has no interface to point the list's table at: no pin control.
      el("td", { style: "white-space:nowrap" }, c.no_link ? null : pinSel, c.no_link ? null : " ", exBtn)));
  });
  tbl.appendChild(tb);
  body.appendChild(el("div", { class: "tbl-wrap", style: "margin-top:var(--sp-3);overflow-x:auto" }, tbl));
  body.appendChild(el("div", { class: "hint" }, d.last_cycle ? t("Last measured at {0}.", fmtClock(d.last_cycle)) : t("Not measured yet.")));

  // Journal: last 50 events, newest first, filter by reason, copy.
  const evs = (d.events || []).slice().reverse();
  const reasons = [...new Set(evs.map(e => e.reason))];
  const filt = el("select", { class: "rl-sel", style: "max-width:180px" }, el("option", { value: "" }, t("All reasons")),
    ...reasons.map(r => el("option", { value: r }, t(fastestReasonWord(r)))));
  filt.setAttribute("aria-label", t("Filter by reason"));
  const feed = el("div", { class: "rl-fast-log" });
  const name = cid => ((d.candidates || []).find(c => c.id === cid) || {}).name || cid || "—";
  const line = e => fmtClock(e.at) + "  " + name(e.from) + " → " + name(e.to) + "  " + t(fastestReasonWord(e.reason)) +
    (e.rtt_from || e.rtt_to ? "  (" + (e.rtt_from || "—") + " → " + (e.rtt_to || "—") + " ms)" : "");
  const paint = () => {
    feed.innerHTML = "";
    const shown = evs.filter(e => !filt.value || e.reason === filt.value);
    if (!shown.length) { feed.appendChild(el("div", { class: "hint" }, t("No events yet."))); return; }
    shown.forEach(e => feed.appendChild(el("div", { class: "mono" }, line(e))));
  };
  filt.onchange = paint; paint();
  const copy = el("button", { class: "btn btn-sm", type: "button", onclick: () => copyText(evs.filter(e => !filt.value || e.reason === filt.value).map(line).join("\n")) }, t("Copy log"));
  body.appendChild(el("div", { class: "row-between", style: "gap:8px;align-items:center;margin-top:var(--sp-3)" },
    el("div", { class: "card-title" }, t("Journal")), el("div", { style: "display:flex;gap:8px" }, filt, copy)));
  body.appendChild(feed);
}

function fastestReasonWord(r) {
  return ({ elected: "elected", faster: "faster", dead: "tunnel down", recovered: "recovered", pinned: "pinned",
    unpinned: "unpinned", all_down: "all down", manual: "excluded by you", flapping: "frequent switches",
    targets_down: "targets unreachable" })[r] || r;
}
