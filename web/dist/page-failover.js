// page-failover.js — route-scoped chunk for the failover page.
//
// Loaded by loadChunk() the first time that route is opened, NOT from index.html, so its bytes
// stay out of the initial payload the perf budget measures. A classic script, like app.js: these
// declarations become globals and app.js has already defined el/t/api/state by the time this runs.
//
// The failover-group dialogs and the member list they share. renderFailover stays in app.js; the
// only ways into these are its "+ New group" button and each group card's Edit, both drawn by that
// page after this chunk has loaded. They moved here with the QA-149 and QA-152 fixes, whose own
// bytes did not fit the initial payload.

// memberPicker builds the failover-group member list: a checkbox row per endpoint with ▲/▼ arrows
// that reorder the rows. DOM order IS the saved preference order (both group modals collect checked
// members via $$("input:checked").map(value) in DOM order), so moving a row changes its priority.
// The arrows preventDefault+stopPropagation so a click never toggles that row's checkbox.
// rows: [{ e, checked }] already in the desired initial order.
function memberPicker(rows) {
  const box = el("div", { class: "checks checks-members" });
  rows.forEach(({ e, checked }) => {
    const cb = el("input", { type: "checkbox", value: e.id });
    if (checked) cb.setAttribute("checked", "true");
    const up = el("button", { class: "btn btn-sm", type: "button", title: "Move up (higher priority)", "aria-label": "Move up", style: "padding:1px 8px;line-height:1.2" }, "▲");
    const dn = el("button", { class: "btn btn-sm", type: "button", title: "Move down (lower priority)", "aria-label": "Move down", style: "padding:1px 8px;line-height:1.2" }, "▼");
    // A member is picked on what it IS and how it is DOING, and the row said only the first. The
    // live state comes from the same healthMap the exits list reads, so "which of these is actually
    // up right now" is answered where the choice is made rather than one page away. The word beside
    // the dot carries the state for anyone who cannot use its colour.
    const h = healthMap[e.id];
    let dotCls = "muted", note = "";
    if (e.member) { note = t(e.member); } // a member that is not a connection (QA-149): what it is
    else if (!e.enabled) { note = t("off"); }
    else if (h && h.state === "down") { dotCls = "err"; note = t("down"); }
    else if (h && h.state === "alive") { dotCls = h.latency_ms >= 600 ? "warn" : "ok"; note = (h.latency_ms || "?") + " ms"; }
    else { note = t("checking…"); }
    const row = el("label", { class: "check member-row" }, cb,
      el("span", { class: "insp-dot " + dotCls, "aria-hidden": "true" }),
      el("span", { class: "member-n" }, e.name || e.id),
      el("span", { class: "member-m" }, note),
      e.protocol ? el("span", { class: "badge proto member-p" }, e.protocol) : el("span", { class: "member-p" }),
      el("span", { class: "member-ord" }, up, dn));
    row._up = up; row._dn = dn;
    const move = (dir) => (ev) => {
      ev.preventDefault(); ev.stopPropagation();
      if (dir < 0 && row.previousElementSibling) box.insertBefore(row, row.previousElementSibling);
      else if (dir > 0 && row.nextElementSibling) box.insertBefore(row.nextElementSibling, row);
      syncEnds();
    };
    up.onclick = move(-1);
    dn.onclick = move(1);
    box.appendChild(row);
  });
  // The top row cannot move up and the bottom row cannot move down. move() already guards on the
  // sibling, so both clicks were harmless - and silent, which is the defect: a control that looks
  // live and answers nothing teaches the operator that these arrows are unreliable, on the one screen
  // where order IS the configuration. Measured on the demo: clicking the top ▲ and the bottom ▼ left
  // the row order byte-identical with nothing said. Re-run after every move, because which row sits
  // at an end changes with each one.
  const syncEnds = () => {
    const rows = [...box.children];
    rows.forEach((r, i) => {
      if (r._up) r._up.disabled = i === 0;
      if (r._dn) r._dn.disabled = i === rows.length - 1;
    });
  };
  syncEnds();
  return box;
}

// memberOrderHint explains what the ▲/▼ order actually does.
//
// It used to say "urltest/fallback auto-pick the fastest working member and use your order as a
// tiebreak" — flatly, in a dialog whose own type dropdown offers "fallback — strict order", and whose
// group card afterwards says fallback follows the order top to bottom. Three statements, two of them
// wrong depending on the carrier, all on screen within one workflow. What decides it is who carries
// the group, which is not known while the form is still being filled in, so the hint now says which
// answers exist and leaves the group's own card to state the one in force.
const MEMBER_ORDER_HINT = "Use ▲/▼ to set priority. A selector group uses the top member. Order is followed strictly on router tunnels; on the proxy core the fastest working member wins and your order is the tiebreak — the group's card says which applies to it.";

// dialogNotes moves a form's explanatory prose out from between its controls and into the footer,
// where it becomes one line that follows what the operator is touching: any section carrying
// data-note shows its note on focus or hover, and the default note holds the rest of the time.
//
// In the failover dialog those three paragraphs took more vertical room than the member list they
// were explaining, which is the part of it you actually work in. Notes passed in are already
// translated — they are read from the attribute, not re-localized later.
function dialogNotes(defaultNote) {
  const line = el("div", { class: "hint foot-note", role: "status" }, defaultNote);
  const show = ev => {
    const sec = ev.target && ev.target.closest ? ev.target.closest("[data-note]") : null;
    const next = sec ? sec.getAttribute("data-note") : defaultNote;
    if (line.textContent !== next) line.textContent = next;
  };
  return {
    wire(body) {
      body.addEventListener("focusin", show);
      body.addEventListener("mouseover", show);
      body.addEventListener("mouseleave", () => { line.textContent = defaultNote; });
      return body;
    },
    footer(...actions) {
      return el("div", { class: "foot-notes" }, line, el("div", { class: "foot-actions" }, ...actions));
    },
  };
}

// testTuningFields builds the shared "health & flap tuning" block for a group's Test config —
// probe URL, interval (s), and TOLERANCE (ms). tolerance is the anti-flap deadband sing-box gives
// for free: a higher value keeps the active exit stickier on a jittery/DPI link (stops exit
// ping-pong), a lower interval detects a dead exit faster (the daemon floors it to 5s). Returns the
// DOM node + read() yielding a complete model.Health (defaults filled, so no field is dropped).
function testTuningFields(test) {
  test = test || {};
  const url = el("input", { type: "text", value: test.url || "", placeholder: "http://cp.cloudflare.com/generate_204" });
  const interval = el("input", { type: "number", min: "5", step: "5", value: String(test.interval || 60) });
  const tolerance = el("input", { type: "number", min: "0", step: "10", value: String(test.tolerance != null ? test.tolerance : 50) });
  // The tuning note rides along as data-note instead of a paragraph under the fields: the dialog's
  // footer shows it while these three inputs are in use (see dialogNotes).
  const node = el("div", { "data-note": t("Higher tolerance = stickier exit on a jittery/DPI link (try 100–150 ms); lower interval = faster failover (floored to 5 s). Tunes urltest/fallback auto-failover; a selector group only uses the URL for its health badge.") },
    el("div", { class: "field" }, el("label", {}, t("Health check URL")), url),
    el("div", { style: "display:flex;gap:12px" },
      el("div", { class: "field", style: "flex:1" }, el("label", {}, t("Probe interval (s)")), interval),
      el("div", { class: "field", style: "flex:1" }, el("label", {}, t("Flap tolerance (ms)")), tolerance)));
  const read = () => {
    const iv = parseInt(interval.value, 10);
    const tol = parseInt(tolerance.value, 10);
    return {
      url: url.value.trim() || "http://cp.cloudflare.com/generate_204",
      interval: Number.isFinite(iv) && iv > 0 ? iv : 60,
      tolerance: Number.isFinite(tol) && tol >= 0 ? tol : 50,
    };
  };
  return { node, read };
}

function openNewGroup() {
  if (!state.profile.endpoints.length) { toast("Add some connections first", "err"); return; }
  const name = el("input", { type: "text", placeholder: "Main failover" });
  const type = el("select", {}, el("option", { value: "urltest" }, "urltest — auto, fastest working"),
    el("option", { value: "fallback" }, "fallback — strict order"),
    el("option", { value: "selector" }, "selector — manual"));
  const checks = memberPicker(state.profile.endpoints.map(e => ({ e, checked: false })));
  const tuning = testTuningFields();
  const asDefault = el("input", { type: "checkbox" });
  const killSwitch = el("input", { type: "checkbox" });

  async function create(btn) {
    const members = $$("input[type=checkbox]:checked", checks).map(c => c.value);
    if (!name.value.trim()) return toast("Name required", "err");
    if (!members.length) return toast("Pick at least one member", "err");
    if (btn) { if (btn.disabled) return; btn.disabled = true; } // in-flight guard — no duplicate group from a double-click
    // rlUniqueId walks endpoint/group/rule/list ids so a new group whose name slugs to an existing
    // group's id gets a fresh id instead of silently OVERWRITING that group (UpsertGroup is by-id).
    const id = rlUniqueId("grp-" + name.value.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""));
    // kill_switch is omitted from the payload when unchecked (omitempty / false =
    // current behavior: WAN fallback when all members are down).
    const g = { id, name: name.value.trim(), type: type.value, members, test: tuning.read() };
    if (killSwitch.checked) g.kill_switch = true;
    try { await api.post("/api/groups", g); }
    catch (e) { if (btn) btn.disabled = false; return toast(e.message, "err"); } // group not created — re-enable, modal stays open for retry
    // The group now exists. Setting it as the default route is a best-effort follow-up:
    // if it fails, keep the created group (don't discard the success) and surface the error
    // separately, so a retry can't collide on the already-created group id.
    let ruleErr = null;
    if (asDefault.checked) {
      try { await api.post("/api/rules", { id: "default", default: true, outbound: id }); }
      catch (e) { ruleErr = e; }
    }
    back.remove(); await loadProfile(); route();
    toast(t("Created {0}", name.value.trim()), "ok");
    if (ruleErr) toast(ruleErr.message, "err");
  }

  const notes = dialogNotes(t(MEMBER_ORDER_HINT));
  const body = notes.wire(el("div", {},
    el("div", { class: "field" }, el("label", {}, "Group name"), name),
    el("div", { class: "field" }, el("label", {}, "Type"), type),
    el("div", { class: "field", "data-note": t(MEMBER_ORDER_HINT) }, el("label", {}, t("Members (priority order)")), checks),
    tuning.node,
    el("label", { class: "check" }, asDefault, el("span", {}, "Set as default route (all traffic)")),
    el("label", { class: "check", "data-note": t("When on, traffic is dropped instead of falling back to the open WAN if every member is down — no leak to the unprotected internet.") },
      killSwitch, el("span", {}, t("Kill switch (drop when all members down)")))));
  const back = modal({ title: "New failover group", body, fixed: true,
    footer: notes.footer(el("button", { class: "btn btn-ghost", onclick: () => back.remove() }, "Cancel"),
      el("button", { class: "btn btn-primary", onclick: (e) => create(e.currentTarget) }, "Create")) });
}

// openEditGroup edits an existing failover group's settings. The create modal builds new
// groups; this re-posts the SAME group (POST /api/groups upserts by id) with the editable
// fields — name, type, members, and the kill_switch toggle — preserving every other field
// (test config, etc.) verbatim so an edit never silently drops it.
function openEditGroup(g) {
  const name = el("input", { type: "text", value: g.name || "" });
  const type = el("select", {},
    el("option", { value: "urltest" }, "urltest — auto, fastest working"),
    el("option", { value: "fallback" }, "fallback — strict order"),
    el("option", { value: "selector" }, "selector — manual"));
  type.value = g.type || "urltest";
  const have = new Set(g.members || []);
  // List current members first (in saved preference order), then the remaining endpoints.
  //
  // A member is not always a connection: a group can hold another group or `direct` (the model takes
  // both). Those were left out of the list, and Save wrote back only what the list showed checked, so
  // saving without a change turned [vless-de, auto, direct] into [vless-de] (QA-149). They are listed
  // in their place, checked, and say what they are; unchecking one is how to drop it.
  const ordered = (g.members || []).map(m => findEndpoint(m) ||
    { id: m, name: nameOf(m), enabled: true, member: findGroup(m) ? "nested group" : m === "direct" ? "direct" : "" })
    .concat(state.profile.endpoints.filter(e => !have.has(e.id)));
  const checks = memberPicker(ordered.map(e => ({ e, checked: have.has(e.id) })));
  const tuning = testTuningFields(g.test);
  const killSwitch = el("input", { type: "checkbox" });
  if (g.kill_switch) killSwitch.setAttribute("checked", "true");

  async function save(btn) {
    const members = $$("input[type=checkbox]:checked", checks).map(c => c.value);
    if (!name.value.trim()) return toast("Name required", "err");
    if (!members.length) return toast("Pick at least one member", "err");
    if (btn) { if (btn.disabled) return; btn.disabled = true; } // in-flight guard — no duplicate POST from a double-click
    try {
      // Spread g first so unedited fields round-trip unchanged; test is rebuilt from the tuning
      // block (seeded from g.test, so untouched values round-trip and no Health field is dropped).
      const out = { ...g, name: name.value.trim(), type: type.value, members, kill_switch: killSwitch.checked, test: tuning.read() };
      await api.post("/api/groups", out, ifMatch(g)); // refused if g changed since it was loaded (QA-152)
      back.remove(); await loadProfile(); route(); toast(t("Saved {0}", name.value.trim()), "ok");
    } catch (e) { if (btn) btn.disabled = false; toast(e.message, "err"); }
  }

  const notes = dialogNotes(t(MEMBER_ORDER_HINT));
  const body = notes.wire(el("div", {},
    el("div", { class: "field" }, el("label", {}, "Group name"), name),
    el("div", { class: "field" }, el("label", {}, "Type"), type),
    el("div", { class: "field", "data-note": t(MEMBER_ORDER_HINT) }, el("label", {}, t("Members (priority order)")), checks),
    tuning.node,
    el("label", { class: "check", "data-note": t("When on, traffic is dropped instead of falling back to the open WAN if every member is down — no leak to the unprotected internet.") },
      killSwitch, el("span", {}, t("Kill switch (drop when all members down)")))));
  const back = modal({ title: t("Edit failover group"), body, fixed: true,
    footer: notes.footer(el("button", { class: "btn btn-ghost", onclick: () => back.remove() }, "Cancel"),
      el("button", { class: "btn btn-primary", onclick: (e) => save(e.currentTarget) }, "Save")) });
}
