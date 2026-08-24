"use strict";

/* ---------- tiny DOM helpers ---------- */
const $ = (s, r = document) => r.querySelector(s);
function el(tag, props, ...kids) {
  const n = document.createElement(tag);
  if (props) for (const [k, v] of Object.entries(props)) {
    if (v == null) continue;
    if (k === "class") n.className = v;
    else if (k === "html") n.innerHTML = v;
    else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    n.appendChild(typeof kid === "string" ? document.createTextNode(kid) : kid);
  }
  return n;
}

// switchEl: an accessible on/off switch. The old bare <div class="toggle"> had no role/tabindex/
// keydown, so keyboard + screen-reader users literally could not flip a tunnel on/off (and the
// .toggle:focus-visible CSS was dead). onToggle(el) fires on click AND Enter/Space; aria-checked
// reflects `on`. Callers that re-render on change get the new state for free; those that flip the
// class in place (selfAutoToggle) update aria-checked themselves.
function switchEl(on, onToggle, label) {
  const s = el("div", { class: "toggle" + (on ? " on" : ""), role: "switch", tabindex: "0", "aria-checked": on ? "true" : "false" });
  if (label) s.setAttribute("aria-label", label);
  const fire = () => onToggle(s);
  s.addEventListener("click", fire);
  s.addEventListener("keydown", ev => { if (ev.key === "Enter" || ev.key === " " || ev.key === "Spacebar") { ev.preventDefault(); fire(); } });
  return s;
}

// switchWord is the state half of a switch's accessible name.
//
// A switch carries its state in aria-checked, and these two also carry it in the NAME because the
// visible state is a colour — the routing row says so outright: "the switch IS the status light …
// the accessible name carries the words". The name was the fixed string " enabled" in both states,
// so turning an exit off left a control announcing "Frankfurt VLESS enabled, switch, off": the two
// channels contradicted each other, and the one a screen reader reads first was the stale one.
// Measured on the demo by flipping a freshly-added exit — aria-checked went true→false, aria-label
// did not move.
function switchWord(on) { return on ? " enabled" : " disabled"; }

// a11yClick makes a non-button clickable element (an icon/span such as a drill-down expander or
// a pin) keyboard-operable and screen-reader-announced — role=button + tabindex + Enter/Space —
// matching switchEl so icon controls aren't mouse-only.
function a11yClick(elm, handler, label) {
  elm.setAttribute("role", "button");
  elm.setAttribute("tabindex", "0");
  if (label) elm.setAttribute("aria-label", label);
  elm.addEventListener("click", handler);
  elm.addEventListener("keydown", ev => { if (ev.key === "Enter" || ev.key === " " || ev.key === "Spacebar") { ev.preventDefault(); handler(ev); } });
  return elm;
}
// wireNavItem makes a static .nav-item <div> a keyboard-operable button
// (role + tabindex + Enter/Space → its page).
function wireNavItem(n) {
  n.setAttribute("role", "button");
  n.setAttribute("tabindex", "0");
  const go = () => { location.hash = "#" + n.dataset.page; };
  n.addEventListener("click", go);
  n.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
}

// emptyState builds a richer empty placeholder — a bold title + an optional muted
// how-to hint (and optional leading glyph) — replacing bare run-on sentences. A plain
// string child still renders via .empty, so existing call sites stay unaffected.
function emptyState(title, hint, glyph) {
  return el("div", { class: "empty" },
    glyph ? el("div", { class: "empty-ico" }, glyph) : null,
    el("div", { class: "empty-title" }, title),
    hint ? el("div", { class: "empty-hint" }, hint) : null);
}

/* ---------- a11y ---------- */
// associateLabels wires each .field's sibling <label> to its single control via
// for/id so screen readers announce form fields by name. The UI renders labels as
// visual siblings (not wrapping, not for-linked); this is additive (for/id only —
// no visual change) and idempotent. Call after each page/modal render.
let _wfLabelId = 0;
function associateLabels(root) {
  if (!root) return;
  root.querySelectorAll(".field").forEach(f => {
    const label = f.querySelector(":scope > label");
    if (!label || label.htmlFor) return;
    const ctrls = f.querySelectorAll("input, select, textarea");
    if (ctrls.length !== 1) return;     // skip empty / ambiguous fields
    const c = ctrls[0];
    if (label.contains(c)) return;      // a wrapping label already associates
    if (!c.id) c.id = "wf" + (++_wfLabelId);
    label.htmlFor = c.id;
  });
}

/* ---------- API ---------- */
// A 4xx body is not always just a sentence. The package-manager path answers "the core is running"
// with `{error, needs_stop:true}`, and a caller that can only see `.message` cannot tell that refusal
// apart from a permanent one — so it would show the operator a dead end where a second confirmation
// was all that was needed. Status and body ride along; every existing caller reads .message and is
// unaffected.
async function apiErr(r) {
  try {
    const j = await r.json();
    const e = new Error(j.error || r.statusText);
    e.status = r.status; e.data = j;
    return e;
  } catch { const e = new Error(r.statusText); e.status = r.status; return e; }
}
let authCSRFToken = "";
let authGatePromise = null;
let authCheckPromise = null;

function authRequestHeaders(headers, mutating) {
  const result = { ...(headers || {}) };
  if (mutating && authCSRFToken) result["X-WayHop-CSRF"] = authCSRFToken;
  return result;
}

function handleAuthAPIError(error) {
  const code = error && error.data && error.data.code;
  if (code === "AUTH_REQUIRED" || code === "AUTH_SETUP_REQUIRED") {
    authCSRFToken = "";
    ensureAuthenticated().catch(() => {});
  }
  return error;
}

async function authStatus() {
  const response = await fetch("/api/auth/status", { cache: "no-store" });
  if (!response.ok) throw await apiErr(response);
  return response.json();
}

function showAuthGate(status) {
  if (authGatePromise) return authGatePromise;
  authGatePromise = new Promise(resolve => {
    const setup = !status.configured;
    const title = setup ? "Secure this WayHop panel" : "Sign in to WayHop";
    const description = setup
      ? "Create the first operator account. There is no default password, and router changes stay blocked until this is complete."
      : "Enter the operator credentials for this router.";
    const username = el("input", { type: "text", autocomplete: "username", maxlength: "64", required: "required" });
    username.value = setup ? "admin" : "";
    const password = el("input", { type: "password", autocomplete: setup ? "new-password" : "current-password", maxlength: "256", required: "required" });
    const confirmPassword = setup
      ? el("input", { type: "password", autocomplete: "new-password", maxlength: "256", required: "required" })
      : null;
    const errorBox = el("div", { class: "settings-errors", role: "alert", "aria-live": "assertive" });
    const submit = el("button", { class: "btn btn-primary", type: "submit" }, setup ? "Create operator account" : "Sign in");
    // Running without a password is allowed and is a decision, so it takes two deliberate clicks and
    // states what it costs. One click would put it a stray tap away from the primary button; a
    // checkbox would put it there permanently. The consequence is named in full because it is not
    // obvious from "skip": this panel changes routing and DNS for the whole house and holds every
    // tunnel's private key.
    const skipBox = setup ? el("div", { class: "auth-skip" }) : null;
    if (setup) {
      const ask = el("button", { class: "btn btn-sm", type: "button" }, "Continue without a password");
      const warn = el("div", { class: "auth-skip-warn", role: "note", hidden: "hidden" },
        el("strong", {}, "Anyone who can open this page will control the router."),
        el("span", {}, "It changes routing and DNS for every device here and holds each tunnel's private key. Other websites still cannot drive it — the panel refuses cross-site requests — but everyone on this network can. You can set a password later in Settings → Account."));
      const confirm = el("button", { class: "btn btn-danger btn-sm", type: "button", hidden: "hidden" }, "Yes, run without a password");
      ask.addEventListener("click", () => {
        ask.hidden = true; warn.hidden = false; confirm.hidden = false; confirm.focus();
      });
      confirm.addEventListener("click", async () => {
        confirm.disabled = true;
        errorBox.textContent = "";
        try {
          const response = await fetch("/api/auth/setup", {
            method: "POST", headers: { "content-type": "application/json" },
            body: JSON.stringify({ skip: true }),
          });
          if (!response.ok) throw await apiErr(response);
          await response.json();
          authCSRFToken = ""; // no session in this state, and the router asks for no token
          closeAuthGate();
          authGatePromise = null;
          resolve(true);
        } catch (error) {
          errorBox.textContent = error.message || "The choice could not be saved.";
          confirm.disabled = false;
        }
      });
      skipBox.appendChild(ask);
      skipBox.appendChild(warn);
      skipBox.appendChild(confirm);
    }
    const form = el("form", { class: "auth-form" },
      el("div", { class: "field" }, el("label", null, "Username"), username),
      el("div", { class: "field" }, el("label", null, "Password"), password),
      setup ? el("div", { class: "field" }, el("label", null, "Confirm password"), confirmPassword) : null,
      setup ? el("div", { class: "hint" }, "Use at least 12 characters. The password is stored only as a memory-hard Argon2id hash.") : null,
      el("div", { class: "auth-http-warning", role: "note" },
        location.protocol === "https:"
          ? "This connection uses HTTPS."
          : "This panel uses plain HTTP. Use it only on a trusted management LAN or through a trusted VPN; anyone carrying the traffic can read the password."),
      errorBox,
      submit,
      skipBox);
    const dialog = el("section", { class: "modal auth-card", role: "dialog", "aria-modal": "true", "aria-labelledby": "auth-title" },
      el("div", { class: "modal-head" }, el("h2", { id: "auth-title" }, title)),
      el("div", { class: "modal-body" }, el("p", { class: "hint auth-intro" }, description), form));
    const backdrop = el("div", { class: "modal-backdrop auth-gate" }, dialog);
    document.body.appendChild(backdrop);
    // aria-modal is a promise, not decoration: keyboard and assistive-technology users must not
    // reach the router UI behind the authentication gate. Preserve any pre-existing state so the
    // page returns exactly to its former accessibility tree after a successful login.
    const backgroundState = [...document.body.children]
      .filter(node => node !== backdrop)
      .map(node => ({
        node,
        inert: node.hasAttribute("inert"),
        ariaHidden: node.getAttribute("aria-hidden"),
      }));
    backgroundState.forEach(({ node }) => {
      node.setAttribute("inert", "");
      node.setAttribute("aria-hidden", "true");
    });
    const onAuthKey = event => {
      if (event.key !== "Tab") return;
      const items = focusables(dialog);
      if (!items.length) { event.preventDefault(); dialog.focus(); return; }
      const first = items[0], last = items[items.length - 1], active = document.activeElement;
      if (event.shiftKey && (active === first || !dialog.contains(active))) {
        event.preventDefault(); last.focus();
      } else if (!event.shiftKey && (active === last || !dialog.contains(active))) {
        event.preventDefault(); first.focus();
      }
    };
    document.addEventListener("keydown", onAuthKey);
    const closeAuthGate = () => {
      document.removeEventListener("keydown", onAuthKey);
      backgroundState.forEach(({ node, inert, ariaHidden }) => {
        if (!inert) node.removeAttribute("inert");
        if (ariaHidden == null) node.removeAttribute("aria-hidden");
        else node.setAttribute("aria-hidden", ariaHidden);
      });
      backdrop.remove();
    };
    associateLabels(dialog);
    form.addEventListener("submit", async event => {
      event.preventDefault();
      errorBox.textContent = "";
      if (setup && password.value !== confirmPassword.value) {
        errorBox.textContent = "The passwords do not match.";
        confirmPassword.focus();
        return;
      }
      submit.disabled = true;
      try {
        const response = await fetch(setup ? "/api/auth/setup" : "/api/auth/login", {
          method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify({ username: username.value, password: password.value }),
        });
        if (!response.ok) throw await apiErr(response);
        const authenticated = await response.json();
        authCSRFToken = authenticated.csrf_token || "";
        if (!authCSRFToken) throw new Error("The router did not issue a session CSRF token.");
        closeAuthGate();
        authGatePromise = null;
        resolve(true);
      } catch (error) {
        errorBox.textContent = error.message || "Authentication failed.";
        submit.disabled = false;
      }
    });
    setTimeout(() => username.focus(), 0);
  });
  return authGatePromise;
}

async function ensureAuthenticated() {
  if (authGatePromise) return authGatePromise;
  if (authCheckPromise) return authCheckPromise;
  // Publish the whole status-check + dialog lifetime before the first await. When a live
  // session expires, several dashboard requests can fail together; every later poll must see
  // one shared gate immediately instead of continuing to hammer protected routes with 401s.
  authCheckPromise = (async () => {
    const status = await authStatus();
    // No password was set, by the operator's own choice. There is no session and therefore no CSRF
    // token — the router does not ask for one in this state — so the token check below must not be
    // what decides whether the panel opens, or the gate would reappear on every load.
    if (status.passwordless) {
      authCSRFToken = "";
      return true;
    }
    if (status.authenticated && status.csrf_token) {
      authCSRFToken = status.csrf_token;
      return true;
    }
    return showAuthGate(status);
  })();
  try { return await authCheckPromise; }
  finally { authCheckPromise = null; }
}

async function waitForAuthentication() {
  if (authCheckPromise) await authCheckPromise;
  else if (authGatePromise) await authGatePromise;
}
// _inflightGets deduplicates CONCURRENT GETs to the same path: several widgets refreshing at once
// (or a fast double navigation) previously fired the same request repeatedly at a router CPU that can
// barely spare it. The shared promise resolves to the response TEXT, and every caller parses its OWN
// object — sharing a parsed object would alias mutable state between unrelated callers. Cleared as
// soon as the request settles, so this is request coalescing, never a response cache.
const _inflightGets = new Map();

const api = {
  async get(p) {
    await waitForAuthentication();
    let pending = _inflightGets.get(p);
    if (!pending) {
      pending = (async () => {
        const r = await fetch(p);
        if (!r.ok) throw handleAuthAPIError(await apiErr(r));
        return r.text();
      })();
      _inflightGets.set(p, pending);
      // Detach the cleanup from the returned promise so a rejection here is never an unhandled one.
      pending.then(() => _inflightGets.delete(p), () => _inflightGets.delete(p));
    }
    return JSON.parse(await pending);
  },
  async post(p, body) {
    await waitForAuthentication();
    const r = await fetch(p, { method: "POST", headers: authRequestHeaders({ "content-type": "application/json" }, true), body: JSON.stringify(body || {}) });
    if (!r.ok) throw handleAuthAPIError(await apiErr(r)); return r.json();
  },
  async put(p, body, headers) {
    await waitForAuthentication();
    const r = await fetch(p, { method: "PUT", headers: authRequestHeaders({ "content-type": "application/json", ...(headers || {}) }, true), body: JSON.stringify(body || {}) });
    if (!r.ok) throw handleAuthAPIError(await apiErr(r)); return r.json();
  },
  // The optional body is how a DELETE the daemon REFUSED once gets answered: the engine-remove route
  // reads {stop:true} to mean "yes, stop the running core first". Callers that pass nothing send no
  // body and no content-type, exactly as before.
  async del(p, body) {
    await waitForAuthentication();
    const r = await fetch(p, {
      method: "DELETE",
      headers: authRequestHeaders(body === undefined ? {} : { "content-type": "application/json" }, true),
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!r.ok) throw handleAuthAPIError(await apiErr(r)); return r.json();
  },
};

/* ---------- state ---------- */
const state = { health: null, profile: { endpoints: [], groups: [], rules: [] } };

// --- pending-Apply (profile-dirty) tracking ------------------------------
// Every connection/group/routing edit only STAGES into the store; it activates on Apply. Without a
// signal the Apply button looks identical whether or not changes are pending, silently dead-ending
// the primary "paste link → it works" flow. We snapshot the profile at Apply time and compare on
// each reload, so the topbar can flag unsaved changes — no per-mutation-site bookkeeping needed.
let _appliedSnapshot = null;
let profileDirty = false;
// _backendPending is the AUTHORITATIVE saved-vs-applied verdict from GET /api/state (survives a
// reload). Kept SEPARATE from the local snapshot baseline: overloading _appliedSnapshot=null as a
// "force dirty" sentinel used to be silently reset by the next updateDirty() (which reads null as
// "first load, re-baseline to current"), clearing a real backend-pending indicator on a staging toggle.
let _backendPending = false;
let applyInFlight = false; // true while POST /api/apply is in flight — blocks staging toggles so a mid-Apply edit can't race the applied config + dirty baseline
function profileSnapshot() {
  const p = state.profile || {};
  // device_groups is an editable top-level section (a routing list's scope references it), and the
  // backend canonical hash includes it — so it MUST be in the local snapshot too, or a device-group
  // edit produces no instant local dirty signal and the "unapplied changes" banner depends solely on
  // a single fire-and-forget /api/state call that swallows transient failures.
  return JSON.stringify([p.endpoints, p.groups, p.rules, p.routing_lists, p.dns, p.device_groups]);
}
function reflectDirty() {
  const ab = document.getElementById("applybtn");
  // Mid-Apply the button carries the busy label + spinner (applyConfig). This runs from every
  // /api/state refresh — including the 10 s poll — and used to overwrite that label with "Review &
  // Apply" and could even hide the button while the POST was still out. Leave it alone until the
  // apply settles; applyConfig's finally re-runs this.
  if (ab && !applyInFlight) {
    ab.hidden = !profileDirty;
    ab.classList.remove("dirty");
    ab.textContent = t("Review & Apply");
    ab.title = t("Review pending changes before applying them");
  }
  renderApplyBanner();
}
// recomputeDirty derives the single display flag from BOTH signals: a LOCAL unsaved edit (the live
// profile differs from the applied baseline) OR the backend's authoritative pending verdict. Either
// lights the Apply banner; keeping them separate stops a staging toggle from clearing a real
// backend-pending indicator (the null-baseline sentinel bug).
function recomputeDirty() {
  const localEdit = _appliedSnapshot !== null && profileSnapshot() !== _appliedSnapshot;
  profileDirty = localEdit || _backendPending;
}
function updateDirty() {
  if (_appliedSnapshot === null) _appliedSnapshot = profileSnapshot(); // first load = the current live baseline
  recomputeDirty();
  reflectDirty();
}

// --- backend-sourced applied-state (the SOURCE OF TRUTH; survives a reload) + the Apply banner ---
// profileDirty above is an INSTANT optimistic hint. /api/state is authoritative: it compares the
// SAVED profile hash against the last-APPLIED one (persisted on the backend), so a hard reload can
// never falsely show "all applied" when saved edits were never pushed to the engine. It is polled
// every 10 s while the tab is visible (init) so an edit made from another device shows up here too.
state.applyState = { pending: false, applied_at: 0 };
state.applyPhase = "";    // "" | "applying" | "applied" | "failed" | "failed-attention"
state.applyStage = "";    // server-reported stage of a running Apply (GET /api/apply/status), shown in the banner
state.applyProblems = []; // soft problems from a 200 ok:false Apply, listed by the failed-attention banner
let _applyPhaseTimer = null;
async function refreshApplyState() {
  try {
    const r = await api.get("/api/state");
    state.applyState = (r && typeof r.pending === "boolean") ? r : { pending: false };
    _backendPending = !!state.applyState.pending; // authoritative saved-vs-applied; survives a reload
    if (!_backendPending) _appliedSnapshot = profileSnapshot(); // backend confirms applied → re-baseline local edit tracking to clean
    recomputeDirty();
  } catch (e) { /* transient error — keep the last known state, don't flip to a wrong value */ }
  reflectDirty();
  updateStatusPill();
}
function setApplyPhase(p, autoClearMs) {
  if (_applyPhaseTimer) { clearTimeout(_applyPhaseTimer); _applyPhaseTimer = null; }
  state.applyPhase = p;
  if (p !== "applying") state.applyStage = "";
  renderApplyBanner();
  if (autoClearMs) _applyPhaseTimer = setTimeout(() => { if (state.applyPhase === p) { state.applyPhase = ""; renderApplyBanner(); } }, autoClearMs);
}
// applyStageText makes the server's stage token readable ("kernel_plane" → "kernel plane"). The
// server names the plane it is working on; this never invents a phase it was not told about.
function applyStageText(stage) { return String(stage || "").replace(/[_-]+/g, " ").trim(); }
function renderApplyBanner() {
  const host = document.getElementById("apply-banner");
  if (!host) return;
  const phase = state.applyPhase, pending = profileDirty;
  let cls = "", role = "status", msg = "", acts = [];
  if (phase === "applying")            { cls = "ab-info"; msg = t("Applying changes…"); }
  else if (phase === "applied")        { cls = "ab-ok";   msg = t("Changes applied successfully."); }
  else if (phase === "failed")         { cls = "ab-err"; role = "alert"; msg = t("Apply failed — the previous configuration is still active."); acts = ["review"]; }
  else if (phase === "failed-attention"){ cls = "ab-err"; role = "alert"; msg = t("Applied, but a component needs attention:"); acts = ["diag", "review"]; }
  else if (pending)                    {
    cls = "ab-warn";
    msg = t("You have unapplied changes. Review them before applying.");
  }
  else { host.hidden = true; host.textContent = ""; host.removeAttribute("role"); host.removeAttribute("aria-live"); return; }
  host.hidden = false;
  host.className = "apply-banner " + cls;
  host.setAttribute("role", role);
  host.setAttribute("aria-live", role === "alert" ? "assertive" : "polite");
  host.textContent = "";
  const row = el("div", { class: "ab-row" });
  if (phase === "applying") row.appendChild(el("span", { class: "ab-spin", "aria-hidden": "true" }));
  const msgEl = el("span", { class: "ab-msg" }, msg);
  // The stage is polled from GET /api/apply/status every 1.5 s while the POST is out (applyConfig)
  // — the only honest progress there is on a multi-second Apply.
  if (phase === "applying" && state.applyStage) msgEl.appendChild(el("span", { class: "ab-stage" }, " — " + applyStageText(state.applyStage)));
  row.appendChild(msgEl);
  if (phase === "failed-attention" && state.applyProblems.length) {
    row.appendChild(el("ul", { class: "ab-problems" }, ...state.applyProblems.map(p => el("li", {},
      el("span", { class: "ab-problem-msg" }, (p.stage ? applyStageText(p.stage) + ": " : "") + (p.message || "")),
      p.remedy ? el("span", { class: "hint ab-problem-remedy" }, " " + p.remedy) : null))));
  }
  if (acts.length) {
    const bx = el("div", { class: "ab-actions" });
    acts.forEach(a => {
      if (a === "review")      bx.appendChild(el("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: () => openReviewChanges() }, t("Review changes")));
      else if (a === "diag")   bx.appendChild(el("button", { class: "btn btn-primary btn-sm", type: "button", onclick: () => { location.hash = "#diagnostics"; } }, t("Open Diagnostics")));
    });
    row.appendChild(bx);
  }
  host.appendChild(row);
}
const findEndpoint = id => state.profile.endpoints.find(e => e.id === id);
const findGroup = id => state.profile.groups.find(g => g.id === id);
const nameOf = id => (findEndpoint(id) || findGroup(id) || {}).name || id;

/* ---------- formatting ---------- */
function fmtRate(bps) {
  const bits = (bps || 0) * 8;
  if (bits >= 1e9) return (bits / 1e9).toFixed(2) + " Gbit/s";
  if (bits >= 1e6) return (bits / 1e6).toFixed(2) + " Mbit/s";
  if (bits >= 1e3) return (bits / 1e3).toFixed(2) + " kbit/s";
  return Math.round(bits) + " bit/s";
}
const fmtTime = ms => new Date(ms).toLocaleTimeString("en-GB");

/* ---------- toast ---------- */
// asList takes what the profile ACTUALLY holds and returns something a form can join.
//
// A params field the panel writes as a list does not always come back as one. It can arrive as a
// scalar from an import, from an older profile, or from a file somebody edited by hand — and
// `(x || []).join(",")` throws on a string, which is not a cosmetic failure: the throw happens while
// the Edit form is being built, so no dialog appears at all. Measured on the demo, whose "Home
// WireGuard" endpoint stores `local_address: "10.7.0.2/32"` — the row is listed, its Edit button is
// enabled, pressing it throws `TypeError: (P.local_address || []).join is not a function` and nothing
// opens. An object you can see and cannot edit.
//
// A scalar becomes a one-element list, so a value like "10.7.0.2/32" displays unchanged; the save
// path already splits the field back into an array, so editing one of these normalises it.
function asList(v) {
  if (Array.isArray(v)) return v;
  if (v === undefined || v === null || v === "") return [];
  return [v];
}

// mono renders a block of machine output — a script, a command's stdout, a check's detail.
//
// It lives here, in the always-loaded file, because TWO chunks call it: page-server.js (which used to
// define it) and page-diagnostics.js. Route chunks load only when their route is first opened, so on
// any visit that reached Diagnostics without passing through Set up Server — a bookmark, a reload on
// that page, the ordinary way somebody checks their router — this threw
// `ReferenceError: mono is not defined` from the row renderer and took the ENTIRE battery with it:
// zero rows, the button stuck disabled forever, while the daemon had answered in 1.3 seconds with
// thirteen results. Measured on a live router and reproduced on the demo.
//
// The suite did not catch it because its page sweep visits `server` second and `diagnostics` eighth,
// so the chunk that defined this was already loaded by the time it mattered — a pass that depended on
// the order of the walk rather than on the code being right.
function mono(text) {
  return el("div", { style: "font-family:ui-monospace,Consolas,monospace;font-size:12px;white-space:pre-wrap;overflow-wrap:anywhere;background:var(--card-2);border-radius:7px;padding:10px 12px;max-height:280px;overflow:auto;line-height:1.5" }, text || "(no output)");
}

function toast(msg, kind = "info") {
  // Localize whole-string toasts via the dictionary; concatenated/interpolated
  // messages that aren't an exact key pass through unchanged.
  const node = el("div", { class: "toast " + kind, role: kind === "err" ? "alert" : "status" },
    (typeof t === "function" ? t(msg) : msg));
  $("#toasts").appendChild(node);
  setTimeout(() => node.remove(), 4200);
}

/* ---------- theme (dark/light) ---------- */
// Pref is "system" | "dark" | "light", persisted client-side (not server config).
const THEME_KEY = "wr-theme";
const themePref = () => localStorage.getItem(THEME_KEY) || "system";
function resolveTheme(pref) {
  if (pref === "light" || pref === "dark") return pref;
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}
// Setting data-theme="light" triggers the [data-theme=light] palette override;
// "dark" just falls back to the :root defaults. Applied at load so there's no flash.
const applyTheme = pref => document.documentElement.setAttribute("data-theme", resolveTheme(pref));
function setThemePref(pref) {
  if (pref === "system") localStorage.removeItem(THEME_KEY); else localStorage.setItem(THEME_KEY, pref);
  applyTheme(pref);
}
applyTheme(themePref());
if (window.matchMedia) {
  window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => {
    if (themePref() === "system") applyTheme("system");
  });
}

/* ---------- i18n (English-keyed; dictionaries live in i18n.js) ---------- */
// English literals ARE the keys: t() returns the active-language string when a
// translation exists, otherwise the original English — so dynamic data (names, IPs,
// numbers) and not-yet-translated text pass through unchanged. Use {0},{1}… for
// interpolation: t("Added {0}", name). Dictionaries + language metadata come from
// i18n.js (window.WR_DICTS / WR_LANGS / WR_RTL), loaded before this file.
const LANG_KEY = "wr-lang";
const DICTS = window.WR_DICTS || {};
// The inline RU supplement that used to sit here is gone. It filled dictionary keys the generated
// i18n.js was missing, additively, "until the dict is regenerated" — and the dict has been
// regenerated: all 195 of its keys are present in web/dist/i18n/ru.js with translations, so the
// merge could never fire. Inert or not, it was 20 KB raw / 9.5 KB gzip of Russian in the EAGER
// bundle, downloaded by every user in every language, while the real dictionaries are already
// split per language and loaded one at a time. New strings belong in .claude/i18n/dicts/*.json
// and reach the browser through i18n.js; there is no second home for them.

const I18N_LANGS = window.WR_LANGS || [{ code: "en", name: "English" }];
const RTL_LANGS = new Set(window.WR_RTL || ["fa"]);
const hasDict = c => c === "en" || DICTS[c] != null;
function detectLang() {
  const nav = (navigator.language || "en").toLowerCase();
  for (const l of I18N_LANGS) {
    if (l.code === "auto" || l.code === "en") continue;
    if (nav === l.code || nav.startsWith(l.code + "-")) return l.code;
  }
  return "en";
}
const lang = () => { const v = localStorage.getItem(LANG_KEY); return v && hasDict(v) ? v : detectLang(); };
function setLang(v) {
  // Reloading in the requested language would silently discard unsaved form edits — the same hazard
  // the SPA nav guard covers for hash navigation. Consult the shared registry first; on cancel,
  // return false so the caller can revert the language <select>.
  const requested = v || "auto";
  if (!I18N_LANGS.some(l => l.code === requested)) {
    toast(t("Error: ") + t("Language"), "err");
    return false;
  }
  const h = location.hash || "#dashboard";
  if (typeof hasUnsavedPageEdits === "function" && hasUnsavedPageEdits(h)) {
    if (!confirm(t("You have unsaved changes on this page. Leave without saving?"))) return false;
    discardPageEdits(h);
  }
  if (requested === "auto") localStorage.removeItem(LANG_KEY); else localStorage.setItem(LANG_KEY, requested);
  // Only the boot-selected dictionary is present: index.html deliberately downloads one language,
  // not the 2 MB all-language bundle. A route-only render cannot switch to an absent dictionary and
  // used to interpret that absence as Auto, making every non-English choice snap straight back.
  // Reload after persisting the requested code so i18n-loader.js fetches that dictionary before
  // app.js renders. The dirty-page confirmation/discard above prevents this safe reload from losing
  // edits silently (and prevents beforeunload from asking the same question a second time).
  location.reload();
  return true;
}
function t(s, ...args) {
  const d = DICTS[lang()];
  let out = d && d[s] != null ? d[s] : s;
  args.forEach((a, i) => { out = out.split("{" + i + "}").join(a); });
  return out;
}

// tn is t() for a phrase whose wording depends on a COUNT.
//
// Measured on a live router: the review header read "1 pending changes". One key, one form,
// and the number in front of it makes the sentence wrong exactly when there is a single thing to
// look at. German, Spanish, French and Portuguese carried the same fault in their own words
// ("1 offene Änderungen", "1 cambios pendientes"); the Slavic dictionaries had already dodged it by
// rewriting the phrase so no form is needed ("Ожидают применения: {0}") — a workaround per string,
// which is why it never generalised.
//
// The forms live in the translation, separated by "|", rather than in extra keys: one key per phrase
// keeps the dictionary shape and the coverage gate exactly as they are, and a translator who needs
// three forms writes three without anyone adding two more keys in nine files. A translation with
// fewer forms than the language asks for falls back to its last one, so a single-form entry is a
// valid entry and not a crash.
function pluralIndex(code, n) {
  const x = Math.abs(Number(n) || 0);
  switch (String(code || "en").slice(0, 2).toLowerCase()) {
    // Russian, Ukrainian, Belarusian: one / few / many, by the last digit with the teens excepted.
    case "ru": case "uk": case "be": {
      const m10 = x % 10, m100 = x % 100;
      if (m10 === 1 && m100 !== 11) return 0;
      if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return 1;
      return 2;
    }
    case "tr": return 0;              // Turkish does not pluralise a noun that already carries a number
    case "fr": return x < 2 ? 0 : 1;  // French treats 0 as singular
    case "fa": return x <= 1 ? 0 : 1;
    default: return x === 1 ? 0 : 1;  // en, de, es, pt
  }
}

function tn(key, n, ...args) {
  const forms = String(t(key)).split("|");
  const form = forms[Math.min(pluralIndex(lang(), n), forms.length - 1)];
  let out = form;
  [n, ...args].forEach((a, i) => { out = out.split("{" + i + "}").join(a); });
  return out;
}
// i18nApply localizes a freshly-rendered (English) subtree in place: every text node
// and title/placeholder/aria-label whose English text is a dictionary key is swapped.
// This translates pages/modals built from hardcoded English without wrapping each
// string in t(); dynamic data isn't a key, so it passes through. No-op for English.
function i18nApply(root) {
  if (!root) return;
  const d = DICTS[lang()];
  if (!d) return;
  const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
  const nodes = [];
  for (let n = w.nextNode(); n; n = w.nextNode()) nodes.push(n);
  for (const node of nodes) {
    const tx = node.nodeValue;
    if (d[tx] != null) { node.nodeValue = d[tx]; continue; }
    const tr = tx.trim();
    if (!tr || d[tr] == null) continue;
    const lead = tx.slice(0, tx.length - tx.trimStart().length);
    const trail = tx.slice(tx.trimEnd().length);
    node.nodeValue = lead + d[tr] + trail;
  }
  ["title", "placeholder", "aria-label"].forEach(attr => {
    root.querySelectorAll("[" + attr + "]").forEach(e => {
      const v = e.getAttribute(attr);
      if (v && d[v] != null) e.setAttribute(attr, d[v]);
    });
  });
}
// i18nObserve catches content inserted AFTER a render hook ran — modal tabs, lazily
// shown panels, async-loaded API data, toasts — by localizing each inserted subtree
// on the next frame. i18nApply only rewrites text matching an English key and mutates
// characterData (which this childList observer ignores), so it never loops and is a
// no-op in English.
const i18nQueue = new Set();
let i18nScheduled = false;
function i18nFlush() {
  i18nScheduled = false;
  const nodes = [...i18nQueue];
  i18nQueue.clear();
  for (const n of nodes) if (n.isConnected) i18nApply(n);
}
function i18nObserve() {
  if (!window.MutationObserver) return;
  new MutationObserver(muts => {
    for (const m of muts) for (const n of m.addedNodes) if (n.nodeType === 1) i18nQueue.add(n);
    // setTimeout, not requestAnimationFrame: rAF is throttled/suspended in background
    // or headless tabs, which would leave late-inserted content untranslated.
    if (i18nQueue.size && !i18nScheduled) { i18nScheduled = true; setTimeout(i18nFlush, 0); }
  }).observe(document.body, { childList: true, subtree: true });
}
// Static chrome (nav labels + topbar) lives in index.html, outside any render();
// translate it directly. data-page -> English label.
// The route key stays "updater" — it is in bookmarks, in the gates' page sweeps and in the daemon's
// own API paths — but the LABEL is "Components", because the section is not about updating WayHop.
// This build has no self-update channel at all (private repository), and what the page really does is
// install the optional protocol engines a router needs only when its kernel cannot carry a protocol
// itself. Naming it "Updater" made an absent sing-box read as an update the operator had missed.
const NAV_LABELS = { dashboard: "Dashboard", server: "Set up Server", connections: "Connections", failover: "Failover", routing: "Routing", dns: "DNS", updater: "Components", diagnostics: "Diagnostics", settings: "Settings" };
// Short hover explanations for each nav item (data-page -> English tooltip). Applied as the
// element's title in translateChrome so they localize alongside the labels.
const NAV_TOOLTIPS = {
  dashboard: "Overview — status, live connections, traffic, and routing-list health",
  server: "Provision a fresh server into a proxy over SSH, and manage existing ones",
  connections: "Your proxy/VPN connections — add, import, edit and test them",
  failover: "Group connections so traffic auto-switches to a healthy one",
  routing: "Send chosen domain/IP lists through a tunnel; everything else stays direct",
  dns: "Encrypted, split, failover-aware DNS — hides lookups from the ISP, degrades gracefully",
  updater: "Optional protocol engines — what is installed, what it would unlock, and where it lands",
  diagnostics: "Health checks — connectivity, DNS, IPv6, exit IP, ping/traceroute",
  settings: "Ports, routing mode, web panel, fail-safe and other options",
};
function translateChrome() {
  document.documentElement.setAttribute("lang", lang());
  document.documentElement.setAttribute("dir", RTL_LANGS.has(lang()) ? "rtl" : "ltr");
  document.querySelectorAll(".nav-item").forEach(it => {
    const en = NAV_LABELS[it.dataset.page];
    if (!en) return;
    const ico = it.querySelector(".ico");
    it.textContent = "";
    if (ico) it.appendChild(ico);
    it.appendChild(document.createTextNode(" " + t(en)));
    const tip = NAV_TOOLTIPS[it.dataset.page];
    if (tip) it.title = t(tip); // hover explanation, localized
  });
  const ab = document.getElementById("applybtn");
  // Static chrome that is NOT rebuilt per render must be re-rendered from its English
  // source on every language switch (like the nav above) — translating it in place
  // would stick it in the first language chosen, since the swapped text is no longer
  // an English key.
  if (ab) {
    ab.textContent = t("Review & Apply");
    ab.title = t("Review pending changes before applying them");
  }
  try { reflectDirty(); } catch (e) {} // re-assert the dirty title/marker after a language switch
  const bs = document.querySelector(".brand .bs");
  if (bs) bs.textContent = t("proxy control");
  const burger = document.querySelector(".nav-burger");
  if (burger) burger.setAttribute("aria-label", t("Menu")); // mobile drawer toggle — localize its screen-reader name
  try { updateStatusPill(); } catch (e) {} // re-localize the live status pill
}

/* ---------- restart the WayHop service ---------- */
async function restartService() {
  if (!await modalConfirm(t("Restart the WayHop service now?\nThe web panel will be unavailable for a few seconds while the init system brings it back."))) return;
  try { await api.post("/api/service/restart"); }
  catch (e) { return toast(e.message, "err"); }
  toast("Restarting… the panel will reconnect when it's back.", "info");
  // The daemon exits ~1s after responding. Wait past that, then poll a light
  // endpoint until it answers again, then reload onto the fresh instance.
  setTimeout(() => {
    let tries = 0;
    const iv = setInterval(async () => {
      tries++;
      try {
        const r = await fetch("/api/health", { cache: "no-store" });
        if (r.ok) { clearInterval(iv); toast("Back online — reloading.", "ok"); setTimeout(() => location.reload(), 500); return; }
      } catch (_) { /* still down */ }
      if (tries > 40) { clearInterval(iv); toast("Still reconnecting — reload the page manually if it doesn't return.", "err"); }
    }, 1500);
  }, 2500);
}

/* ---------- live traffic graph ---------- */
const MAXG = 90;
const GRAPH_WINDOW_SEC = 300; // fixed 5-min X window: the plot SCROLLS (stable width), never compresses as samples accumulate
let graphCanvas = null;
// Per-interface throughput series for the multi-line graph: iface name -> [{t, r}] where r is the
// TOTAL rate (down+up, bytes/s) computed from successive /api/system counters. ifaceOrder keeps a
// stable insertion order so each iface keeps its colour + legend slot across ticks.
let ifaceSeries = {};
let ifaceOrder = [];
let graphHover = null; // pointer X (CSS px within the canvas) while hovering the graph, else null
// A distinct-hue palette for the per-interface lines (assigned by ifaceOrder index, wraps if needed).
const IFACE_COLORS = ["#4f8cff", "#22c55e", "#f59e0b", "#ef4444", "#06b6d4", "#84cc16", "#eab308", "#14b8a6"];
// isTunnelIface: only the TUNNEL interfaces get a graph line — each maps to an exit tile below, so the
// line and the tile share a colour. The WAN's own throughput lives in the "WAN now" system tile, so
// it's left out to avoid an unlabelled line with no tile. Shared by the live push + the load-time seed.
const isTunnelIface = (name) => /^(awg|wg|nwg|tun|wr-|proton|nordlynx)/.test(name);
// endpointBoundIfaces returns the kernel interfaces enabled endpoints egress through (e.g. an
// "external" endpoint bound to eth1 or the WAN). These aren't tunnel-named but DO back an exit tile, so
// they must be graphed too — otherwise that tile's rate would be stuck on "—" forever.
function endpointBoundIfaces() {
  const set = new Set();
  ((state.profile && state.profile.endpoints) || []).forEach(e => { if (e.enabled && e.params && e.params.interface) set.add(e.params.interface); });
  return set;
}
// graphIface: an interface gets a line iff it's a tunnel OR it backs an enabled endpoint's exit tile.
const graphIface = (name, bound) => isTunnelIface(name) || bound.has(name);
// pushIfaceRates appends one sample per interface to the rolling per-iface series (called on each
// /api/system tick). rates is { name: {up, down} } (bytes/s). Only interfaces that carry traffic —
// the tunnels + any endpoint-bound iface — are graphed; the LAN bridge / loopback are skipped as noise.
function pushIfaceRates(rates, wanName) {
  const now = Date.now() / 1000, bound = endpointBoundIfaces();
  for (const name of Object.keys(rates)) {
    if (!graphIface(name, bound)) continue;
    const r = rates[name];
    if (!ifaceSeries[name]) { ifaceSeries[name] = []; ifaceOrder.push(name); }
    const s = ifaceSeries[name];
    s.push({ t: now, r: (r.up || 0) + (r.down || 0) });
    if (s.length > MAXG) s.splice(0, s.length - MAXG);
  }
  drawGraph();
  updateExitRates(); // refresh the live rate + colour dot on each exit tile in place
}
// updateExitRates refreshes each exit tile's live throughput (the [data-iface] span) + colour dot
// from ifaceSeries, in place, so the tiles track the graph without a full re-fetch/re-render.
function updateExitRates() {
  const grid = document.getElementById("exit-grid");
  if (!grid) return;
  grid.querySelectorAll(".exit-rate-v[data-iface]").forEach(sp => {
    const iface = sp.getAttribute("data-iface"), ser = ifaceSeries[iface];
    if (ser && ser.length) sp.textContent = fmtRate(ser[ser.length - 1].r);
    const dot = sp.parentNode && sp.parentNode.querySelector(".dot");
    if (dot) dot.style.background = ifaceColor(iface);
  });
}
// seedIfaceSeries pre-fills the per-interface graph from the server's RAM-only counter history
// (/api/system/recent) so a freshly-loaded dashboard shows the last few minutes immediately instead
// of an empty plot. It replays the SAME Δbytes/Δt math paintThroughput uses on live polls. Server
// snapshot times are rebased onto the client clock (anchoring the newest sample to now) so the seeded
// history is contiguous with the live points that follow — no server/client clock-skew gap.
async function seedIfaceSeries() {
  let snaps;
  try { snaps = await api.get("/api/system/recent"); } catch (_) { return; }
  if (!Array.isArray(snaps) || snaps.length < 2) return;
  const clientNow = Date.now() / 1000, bound = endpointBoundIfaces();
  const lastT = snaps[snaps.length - 1].t;                 // server ms of the newest snapshot
  const toClient = (serverMs) => clientNow + (serverMs - lastT) / 1000; // rebase server time onto the client clock
  for (let i = 1; i < snaps.length; i++) {
    const p = snaps[i - 1], c = snaps[i];
    const dt = (c.t - p.t) / 1000;
    if (!(dt > 0 && dt <= 30)) continue;                   // non-consecutive snapshots → skip (same guard as live)
    const pm = {}; (p.ifaces || []).forEach(f => { pm[f.name] = f; });
    (c.ifaces || []).forEach(f => {
      if (!graphIface(f.name, bound)) return;
      const pf = pm[f.name]; if (!pf) return;
      const down = Math.max(0, (f.rx_bytes - pf.rx_bytes) / dt), up = Math.max(0, (f.tx_bytes - pf.tx_bytes) / dt);
      if (!ifaceSeries[f.name]) { ifaceSeries[f.name] = []; ifaceOrder.push(f.name); }
      const s = ifaceSeries[f.name];
      s.push({ t: toClient(c.t), r: up + down });
      if (s.length > MAXG) s.splice(0, s.length - MAXG);
    });
  }
  // NB: deliberately do NOT prime prevIfaces from the newest snapshot here. Its counters were captured
  // up to one sample interval before load, but the live delta would divide by wall-time since load,
  // over-reporting the first live sample by that phase gap. Leaving prevIfaces unset lets the first two
  // live /api/system polls establish the baseline with a correct dt (one extra tick before the first
  // live point — the seeded history is already on screen meanwhile).
}
// pushOutboundRates feeds the PROXY exits (VLESS/SOCKS/etc. — sing-box outbounds with no kernel
// interface, so /proc/net/dev can't see them) into the same per-series machinery as the kernel
// interfaces: it reads the server's Clash-derived per-outbound rate map (/api/traffic/outbounds) and
// pushes one sample per enabled proxy endpoint (keyed by its id = its sing-box outbound tag), so each
// gets a graph line AND a live tile rate, coloured consistently with the kernel-iface exits. Kernel
// exits are skipped here (they're already graphed from the interface counters). Idle proxy exits get 0.
async function pushOutboundRates() {
  let rates;
  try { rates = await api.get("/api/traffic/outbounds"); } catch (_) { return; }
  if (!rates || typeof rates !== "object") return;
  const now = Date.now() / 1000;
  const eps = (state.profile && state.profile.endpoints) || [];
  let changed = false;
  eps.forEach(e => {
    if (!e.enabled || ifaceOfEndpoint(e.id)) return; // enabled proxy exits only (kernel exits already graphed)
    const r = Math.max(0, +rates[e.id] || 0);
    if (!ifaceSeries[e.id]) { ifaceSeries[e.id] = []; ifaceOrder.push(e.id); }
    const s = ifaceSeries[e.id];
    s.push({ t: now, r });
    if (s.length > MAXG) s.splice(0, s.length - MAXG);
    changed = true;
  });
  if (changed) { drawGraph(); updateExitRates(); }
}
// ifaceOfEndpoint returns the kernel interface an endpoint egresses through (for correlating an exit
// tile with its graph line), from the live profile — "" for a sing-box outbound with no kernel iface.
function ifaceOfEndpoint(id) {
  const ep = (state.profile && state.profile.endpoints || []).find(e => e.id === id);
  return ep && ep.params && ep.params.interface ? ep.params.interface : "";
}
// ifaceColor returns the stable colour for an interface (by ifaceOrder position).
function ifaceColor(name) { const i = ifaceOrder.indexOf(name); return IFACE_COLORS[(i < 0 ? 0 : i) % IFACE_COLORS.length]; }
let connInFlight = false; // in-flight guard for paintConnections' /api/conntrack fetch — don't stack requests on a slow link
// hex color (#rgb / #rrggbb) → "rgba(r,g,b,a)" for translucent graph fills.
function rgba(hex, a) {
  let h = (hex || "").replace("#", "");
  if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
  const n = parseInt(h, 16);
  return "rgba(" + ((n >> 16) & 255) + "," + ((n >> 8) & 255) + "," + (n & 255) + "," + a + ")";
}
// niceCeil rounds v UP to a clean 1/2/5 × 10ⁿ so the graph's Y-axis changes only in stable steps
// rather than rescaling on every tick as throughput wiggles — the plot stops "jumping" on update.
function niceCeil(v) {
  if (!(v > 0)) return 1;
  const exp = Math.floor(Math.log10(v)), base = Math.pow(10, exp), f = v / base;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * base;
}
// curveThrough emits gently-smoothed quadratic segments through pts[1..] (each control point is a
// sample, anchored at segment midpoints) — a light, overshoot-free smoothing of the line. The caller
// has already positioned the path at pts[0].
function curveThrough(ctx, pts) {
  const n = pts.length;
  if (n < 3) { for (let i = 1; i < n; i++) ctx.lineTo(pts[i][0], pts[i][1]); return; }
  for (let i = 1; i < n - 2; i++) {
    const xc = (pts[i][0] + pts[i + 1][0]) / 2, yc = (pts[i][1] + pts[i + 1][1]) / 2;
    ctx.quadraticCurveTo(pts[i][0], pts[i][1], xc, yc);
  }
  ctx.quadraticCurveTo(pts[n - 2][0], pts[n - 2][1], pts[n - 1][0], pts[n - 1][1]);
}
// drawGraph renders ONE throughput line per interface (each tunnel in its own colour) from
// ifaceSeries. All lines share one Y scale (the peak across every iface) so their magnitudes are
// comparable. The per-interface colour + current rate live on the exit tiles (updateExitRates), not a
// separate legend. On hover it overlays a time crosshair + a #g-tip readout of every iface's rate at
// the hovered sample.
const GRAPH_STALE_MS = 15000; // ~3 sample intervals; one dropped tick must not raise anything

// markGraphStale states that the plot is no longer being fed. The window drawGraph uses is anchored
// on the NEWEST sample, so when samples stop arriving the window stops moving and every point stays
// in view — the plot holds the last five minutes forever, and (being redrawn only when data lands)
// never repaints itself away. Measured: two series still plotted 27 s after both feeds were cut,
// reading exactly like live throughput. The line is kept, it just stops claiming to be current.
function markGraphStale(stale) {
  const c = graphCanvas;
  if (!c) return;
  const card = c.closest(".card") || c.parentNode;
  if (!card) return;
  card.toggleAttribute("data-graph-stale", !!stale);
  let note = document.getElementById("graph-stale");
  if (!stale) { if (note) note.remove(); return; }
  if (note) return;
  note = el("div", { class: "graph-stale", id: "graph-stale", role: "status" },
    "No new traffic samples — this is the last five minutes received, not current throughput.");
  c.parentNode.insertBefore(note, c.nextSibling);
}

// checkGraphStale is driven by the 5 s tick, because a plot that stopped being fed is never
// redrawn and so cannot notice on its own.
function checkGraphStale() {
  if (!graphCanvas) return;
  let newest = 0;
  for (const nm of ifaceOrder) {
    const s = ifaceSeries[nm];
    if (s && s.length) newest = Math.max(newest, s[s.length - 1].t);
  }
  if (!newest) return; // nothing was ever plotted; an empty graph claims nothing
  markGraphStale(Date.now() / 1000 - newest > GRAPH_STALE_MS / 1000);
}

function drawGraph() {
  const c = graphCanvas;
  if (!c) return;
  markGraphStale(false); // fresh data just landed
  const ctx = c.getContext("2d"), pad = 6;
  // Hi-DPI: size the backing store to the device pixel ratio, draw in CSS px.
  const dpr = window.devicePixelRatio || 1;
  const W = c.clientWidth || c.width, H = c.clientHeight || c.height;
  c.width = W * dpr; c.height = H * dpr;
  ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, W, H);
  const ymaxEl = $("#g-ymax"), tip = document.getElementById("g-tip");
  // Newest sample across every series anchors the fixed window (tMin = tMax - span).
  const span = GRAPH_WINDOW_SEC;
  let tMax = 0;
  for (const nm of ifaceOrder) { const s = ifaceSeries[nm]; if (s && s.length) tMax = Math.max(tMax, s[s.length - 1].t); }
  const tMin = tMax - span;
  // Only series with an IN-WINDOW sample are drawn: a tunnel/endpoint that stopped reporting scrolls
  // off and is dropped — no frozen line, no stale hover row, no phantom peak from an old off-screen burst.
  const inWin = p => p.t >= tMin;
  const names = ifaceOrder.filter(n => { const s = ifaceSeries[n]; return s && s.length && s[s.length - 1].t >= tMin; });
  if (!names.length) { if (ymaxEl) ymaxEl.textContent = "—"; if (tip) tip.style.display = "none"; return; }
  // Peak over IN-WINDOW samples only — the fixed-window rework's whole point is that only visible
  // traffic sets the scale. Nice-stepped (1/2/5×10ⁿ) so it changes in clean steps, not every tick.
  let peakRaw = 0;
  for (const nm of names) for (const p of ifaceSeries[nm]) if (inWin(p)) peakRaw = Math.max(peakRaw, p.r);
  const peak = niceCeil(Math.max(peakRaw * 1.1, 1024));
  if (ymaxEl) ymaxEl.textContent = fmtRate(peak);
  const X = t => pad + (W - 2 * pad) * ((t - tMin) / span);
  const Y = v => H - pad - (H - 2 * pad) * (v / peak);
  for (const nm of names) {
    const col = ifaceColor(nm);
    const pts = ifaceSeries[nm].filter(inWin).map(p => [X(p.t), Y(p.r)]);
    if (!pts.length) continue;
    // Translucent fill under the (smoothed) line, then the line itself.
    ctx.beginPath(); ctx.moveTo(pts[0][0], H - pad); ctx.lineTo(pts[0][0], pts[0][1]);
    curveThrough(ctx, pts);
    ctx.lineTo(pts[pts.length - 1][0], H - pad); ctx.closePath();
    ctx.fillStyle = rgba(col, .12); ctx.fill();
    ctx.beginPath(); ctx.moveTo(pts[0][0], pts[0][1]);
    curveThrough(ctx, pts);
    ctx.lineWidth = 2; ctx.strokeStyle = col; ctx.lineJoin = "round"; ctx.stroke();
  }
  // Hover overlay: crosshair at the pointer's time + a dot on each line at its nearest sample, and a
  // #g-tip readout listing every interface's rate at that instant.
  if (graphHover != null && tip) {
    let tHov = tMin + span * ((graphHover - pad) / Math.max(1, W - 2 * pad));
    tHov = Math.max(tMin, Math.min(tMax, tHov));
    const hx = X(tHov);
    ctx.beginPath(); ctx.moveTo(hx, pad); ctx.lineTo(hx, H - pad);
    ctx.lineWidth = 1; ctx.strokeStyle = "rgba(127,127,127,.55)"; ctx.stroke();
    const cardBg = getComputedStyle(document.documentElement).getPropertyValue("--card").trim() || "#1B2433";
    const rows = [];
    for (const nm of names) {
      let best = null, bd = Infinity;
      for (const p of ifaceSeries[nm]) { if (!inWin(p)) continue; const d = Math.abs(p.t - tHov); if (d < bd) { bd = d; best = p; } }
      if (!best) continue;
      ctx.beginPath(); ctx.arc(X(best.t), Y(best.r), 3.5, 0, 2 * Math.PI);
      ctx.fillStyle = ifaceColor(nm); ctx.fill();
      ctx.lineWidth = 1.5; ctx.strokeStyle = cardBg; ctx.stroke();
      rows.push({ nm, r: best.r, t: best.t });
    }
    tip.innerHTML = "";
    tip.appendChild(el("div", { class: "g-tip-t" }, fmtTime((rows[0] ? rows[0].t : tHov) * 1000)));
    rows.forEach(r => tip.appendChild(el("div", { class: "g-tip-r" },
      el("span", { class: "dot", style: "background:" + ifaceColor(r.nm) }),
      el("span", { class: "g-tip-n" }, r.nm),
      el("b", {}, fmtRate(r.r)))));
    tip.style.left = Math.max(64, Math.min(W - 64, hx)) + "px";
    tip.style.display = "";
  } else if (tip) {
    tip.style.display = "none";
  }
  const set = (id, v) => { const e = $(id); if (e) e.textContent = v; };
  set("#g-tstart", fmtTime(tMin * 1000)); set("#g-tend", fmtTime(tMax * 1000));
}
// (the graph is redrawn by the 5s health tick, which updates ifaceSeries via paintThroughput)

/* ---------- status pill ---------- */
// isNativeOnly — true when the backend signals that sing-box is intentionally absent
// because the live profile is native-only (DatapathNativeOnly: "fast" mode + every
// endpoint kernel-native + nothing surviving into sing-box, so the kernel plane carries
// everything). In that regime an absent core is BY DESIGN, not a fault, so the UI must
// read it as a positive state, never a red "core down".
//
// The signal is read from /api/health's singbox.native_only (the natural place a backend
// agent surfaces the verdict on the same payload the header pill already consumes). The
// read is defensive: if the field is absent (older daemon / not yet wired) this returns
// false and every existing "core not running" treatment stays byte-identical. The
// Diagnostics battery additionally has an authoritative native_only row from
// /api/healthcheck (nativeOnlyCheck) for the same verdict.
function isNativeOnly(h) {
  return !!(h && h.singbox && h.singbox.native_only);
}
function updateStatusPill() {
  const h = state.health, pill = $("#statuspill"), text = $("#statustext");
  if (!pill || !text) return;
  if (!h) { pill.className = "pill err"; text.textContent = t("OFFLINE"); return; }
  $("#foot").textContent = "wayhop " + (h.version || "");
  if (h.demo) { pill.className = "pill"; pill.style.color = "var(--accent)"; pill.style.background = "var(--accent-tint)"; text.textContent = t("DEMO MODE"); return; }
  pill.style.color = ""; pill.style.background = "";
  const as = state.applyState || {};
  const life = as.lifecycle;
  if (life && life.state) {
    const meta = {
      committed: ["ok", L("ACTIVE")],
      saved_not_applied: ["warn", L("CHANGES PENDING")],
      live_not_committed: ["warn", L("TESTING")],
      external_drift: ["err", L("NEEDS ATTENTION")],
      unverified: ["warn", L("NOT VERIFIED")],
      nothing_configured: ["muted", L("NO CHANGES")],
    }[life.state];
    if (meta) {
      pill.className = "pill " + meta[0];
      text.textContent = t(meta[1]);
      pill.title = t(life.detail || life.label || "");
      return;
    }
  }
  // No lifecycle block (older daemon) but the state says nothing is configured: say so instead of
  // "IDLE", which reads as "the core is off" rather than "there is nothing to run yet".
  if (!life && as.nothing_configured) {
    pill.className = "pill muted"; text.textContent = t("NO CHANGES"); pill.removeAttribute("title"); return;
  }
  pill.removeAttribute("title");
  if (h.singbox && h.singbox.running) { pill.className = "pill ok"; text.textContent = t("ONLINE"); }
  else if (isNativeOnly(h)) { pill.className = "pill ok"; text.textContent = t("NATIVE"); }
  else { pill.className = "pill muted"; text.textContent = t("IDLE"); }
}

/* ---------- routing ---------- */
const PAGES = {
  dashboard: { title: "Dashboard", render: renderDashboard },
  server: { title: "Set up Server", chunk: "page-server", render: renderServer },
  connections: { title: "Connections", chunk: "page-connections", render: renderConnections },
  failover: { title: "Failover", render: renderFailover },
  routing: { title: "Routing", chunk: "page-routing", render: renderRouting },
  dns: { title: "DNS", chunk: "page-dns", render: renderDNS },
  updater: { title: "Components", chunk: "page-updater", render: renderUpdater },
  // The renderer now lives in the chunk, so the reference has to resolve at CALL time — the page
  // is loaded before render() runs. Binding it here would capture `undefined` at startup.
  diagnostics: { title: "Diagnostics", chunk: "page-diagnostics", render: (v) => renderDiagnostics(v) },
  settings: { title: "Settings", render: renderSettings },
};
// isNetworkError distinguishes a daemon-UNREACHABLE failure (fetch rejected — the
// panel can't reach the daemon, e.g. mid-restart/deploy/crash) from an application
// error (a 4xx/5xx that came back WITH a message). The former should auto-recover,
// not show a dead error page.
function isNetworkError(e) {
  const msg = String((e && e.message) || "");
  // A fetch that can't reach the daemon rejects with a TypeError whose MESSAGE is usually one of
  // these (Chrome "Failed to fetch", Firefox "NetworkError…", modern Safari "Load failed").
  if (/failed to fetch|networkerror|network request failed|load failed|connection refused|fetch/i.test(msg)) return true;
  // Older WebKit (pre-~Safari 14.1) and V8 reject a network failure with a BARE TypeError whose
  // message is empty or the generic "Type error". Catch those too — but ONLY a TypeError with no
  // descriptive message, so an application-bug TypeError ("Cannot read properties of undefined",
  // "x is not a function") is NOT read as "daemon down". Otherwise renderError would raise the
  // auto-reconnect overlay and — the daemon being up — reload straight back into the same bug, a loop.
  return e instanceof TypeError && (msg === "" || /^type\s*error$/i.test(msg));
}

// showReconnect puts up a non-blocking banner and polls /api/health until the daemon
// answers again, then reloads onto the fresh instance. Idempotent (one banner). This
// generalises the Settings restart-flow poll to ANY daemon-down moment — so the family
// no longer just sees a broken "Error:" page on every restart/deploy.
let wrReconnecting = false;
function showReconnect() {
  if (wrReconnecting) return;
  wrReconnecting = true;
  const sub = el("div", { class: "hint", style: "margin-top:4px" }, t("The panel will return as soon as the service is back."));
  const ov = el("div", { class: "wr-reconnect", role: "alert", "aria-live": "assertive" }, el("div", { class: "wr-reconnect-box" },
    el("span", { class: "spin" }),
    el("div", {}, el("div", { style: "font-weight:600" }, t("Reconnecting to WayHop…")), sub)));
  document.body.appendChild(ov);
  let tries = 0, iv = null;
  const poll = async () => {
    tries++;
    try {
      const r = await fetch("/api/health", { cache: "no-store" });
      if (r.ok) { clearInterval(iv); setTimeout(() => location.reload(), 400); return; }
    } catch (_) { /* still down */ }
    // After ~90s, back OFF to a slow keepalive instead of giving up: the single overlay stays
    // (wrReconnecting true → a later network error can't stack a second one), but recovery is
    // still automatic when the router returns — so the user is never stranded on a dead page.
    if (tries === 60) { sub.textContent = t("Still unreachable — reload the page when the router is back."); clearInterval(iv); iv = setInterval(poll, 10000); }
  };
  iv = setInterval(poll, 1500);
}

// renderError shows a page-render failure: a daemon-down error becomes the
// auto-recovering reconnect banner; any other (application) error stays an inline note.
function renderError(view, e) {
  if (isNetworkError(e)) { showReconnect(); return; }
  view.appendChild(el("div", { class: "empty" }, "Error: " + e.message));
}

// --- SPA navigation guard: warn before leaving a page with UNSAVED FORM edits. This is DISTINCT
// from "saved but unapplied" config (the Apply banner) — saved config is safe to navigate away from,
// so it does NOT warn. Covers sidebar + mobile nav, browser Back/Forward, and internal links (all
// change the hash), plus browser reload/close via the shared beforeunload hook below. Native
// confirm() is synchronous, so it can block before the new page renders (an async dialog cannot). ---
let _navGuardHash = location.hash || "#dashboard";
let _navGuardSkip = false;
// Registry: ANY page with unsaved-form state registers { check, discard } from its render —
//   registerDirtyCheck("settings", () => _settingsDirty, () => { _settingsDirty = false; })
// The guard consults the checker of the page being LEFT; a re-render simply overwrites its
// own entry, so registration is idempotent per page.
const _dirtyChecks = {};
function registerDirtyCheck(page, check, discard) { _dirtyChecks[page] = { check, discard }; }
function hasUnsavedPageEdits(hash) {
  const d = _dirtyChecks[(hash || "").slice(1)];
  try { return !!(d && d.check()); } catch (_) { return false; }
}
function discardPageEdits(hash) {
  const d = _dirtyChecks[(hash || "").slice(1)];
  try { if (d && d.discard) d.discard(); } catch (_) {}
}
function onHashChange() {
  const to = location.hash || "#dashboard";
  // Authentication owns the whole application while its status check or modal is active. A user can
  // still edit the hash in the address bar even though the inert backdrop blocks sidebar clicks. Do
  // not let that navigation call route(): route rendering waits for authentication and used to remove
  // the auth backdrop, leaving a permanent "loading settings..." page with no way to sign in.
  if (authCheckPromise || authGatePromise) {
    if (to !== _navGuardHash) history.replaceState(null, "", _navGuardHash);
    return;
  }
  if (_navGuardSkip) { _navGuardSkip = false; _navGuardHash = to; route(); return; }
  if (to !== _navGuardHash && hasUnsavedPageEdits(_navGuardHash)) {
    if (!confirm(t("You have unsaved changes on this page. Leave without saving?"))) {
      _navGuardSkip = true;
      location.hash = _navGuardHash; // revert; the resulting hashchange is skipped above
      return;
    }
    discardPageEdits(_navGuardHash); // user chose to leave without saving → clear so re-entry is clean
  }
  _navGuardHash = to;
  route();
}
// Browser reload/close protection for ANY page with unsaved form edits — one hook, same registry.
window.addEventListener("beforeunload", e => {
  if (hasUnsavedPageEdits(location.hash || "#dashboard")) { e.preventDefault(); e.returnValue = ""; }
});

// Route-scoped chunks. A page whose code is only needed when that page is opened declares
// `chunk: "page-<name>"` and route() loads it before rendering. index.html deliberately does NOT
// reference these files — that is the whole point, and it is what keeps them out of the initial
// payload the perf budget measures.
//
// Classic scripts, not modules, matching app.js: their declarations become globals, and app.js has
// already defined el/t/api/state before any route can run. Each chunk is fetched once; a failed
// fetch is not cached, so navigating back to the page retries rather than showing a dead route
// forever. `async = false` preserves execution order if two chunks are ever requested at once.
const chunkPromises = {};
function loadChunk(name) {
  if (chunkPromises[name]) return chunkPromises[name];
  chunkPromises[name] = new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = name + ".js";
    s.async = false;
    s.onload = () => resolve(true);
    s.onerror = () => {
      delete chunkPromises[name]; // let the next navigation try again
      reject(new Error("could not load " + name + ".js — check the connection to the router"));
    };
    document.head.appendChild(s);
  });
  return chunkPromises[name];
}

async function route() {
  // Close any open modal when navigating: modals are appended to <body>, so
  // clearing #view alone would leave the dialog floating over the new page. The authentication gate
  // is different: it is the active security boundary and is closed only by successful authentication.
  $$(".modal-backdrop:not(.auth-gate)").forEach(m => m.remove());
  // Proactively abort any live netdiag stream we're leaving. runDiagStream's own in-loop guard only
  // fires after the next reader.read() resolves, so a stalled traceroute (silent between hops) would
  // otherwise keep the fetch + AbortController alive; killing it here frees it the instant we navigate.
  if (state.diag && state.diag.abort) { try { state.diag.abort.abort(); } catch (e) {} state.diag = null; }
  const requested = (location.hash || "#dashboard").slice(1);
  const key = Object.prototype.hasOwnProperty.call(PAGES, requested) ? requested : "dashboard";
  if (requested !== key) history.replaceState(null, "", "#dashboard");
  const page = PAGES[key];
  $$(".nav-item").forEach(n => { const on = n.dataset.page === key; n.classList.toggle("active", on); if (on) n.setAttribute("aria-current", "page"); else n.removeAttribute("aria-current"); }); // aria-current so AT users know the current page, not just via color
  $("#pagetitle").textContent = t(page.title);
  graphCanvas = null;
  pageRepaint = null; // the page being replaced stops being repainted (see onPageRepaint)
  const gen = ++routeGen; // this navigation's token
  const view = $("#view");
  view.innerHTML = "";
  pillGen++; // invalidate refreshPills' cached node lists — the page DOM is being rebuilt
  // Skeleton placeholder so the four core pages (which await loadProfile/loadHealth before appending
  // any DOM) don't flash a blank pane — the 'is it broken?' moment on a slow router link. Removed
  // once render resolves; render's appends and this removal happen in the same tick, so the browser
  // never paints skeleton+content together.
  const skel = el("div", { class: "skeleton-page", "aria-hidden": "true" },
    el("div", { class: "skel skel-title" }),
    el("div", { class: "skel skel-line" }), el("div", { class: "skel skel-line short" }),
    el("div", { class: "skel skel-card" }), el("div", { class: "skel skel-card" }));
  // Render into a fresh container OWNED by #view (not #view itself). Renders await the API before
  // appending; if a second navigation lands meanwhile it replaces #view's child, detaching this
  // container — so the slow render's late appends go off-DOM instead of mixing into the new page.
  // The gen check then discards the superseded render's skeleton removal + localization.
  const container = el("div", { class: "route-view" });
  container.appendChild(skel);
  view.appendChild(container);
  // The chunk load sits INSIDE the same try as the render, so a chunk that cannot be fetched shows
  // the ordinary render error on the page rather than rejecting into an unhandled promise and
  // leaving the skeleton up forever. The gen check below still discards a superseded navigation.
  try {
    if (page.chunk) await loadChunk(page.chunk);
    await page.render(container);
    associateLabels(container);
  } catch (e) { renderError(container, e); }
  if (gen !== routeGen) return; // a newer navigation superseded us — discard this render
  skel.remove();
  i18nApply(container); // localize the freshly-rendered (English) page in place
}
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

/* ---------- pages ---------- */
function dashboardHero(eps, groups) {
  const enabled = eps.filter(e => e.enabled).length;
  return el("section", { class: "hero dashboard-hero", "aria-live": "polite" },
    el("div", { class: "hero-pill hero-muted", id: "hero-pill" },
      el("span", { class: "hero-ico", id: "hero-ico", "aria-hidden": "true" }, "…"),
      el("span", { id: "hero-word" }, t("CHECKING"))),
    el("div", { class: "hero-text" },
      el("div", { class: "hero-verdict", id: "hero-verdict" }, t("Checking…")),
      el("div", { class: "hero-sub hint", id: "hero-sub" }),
      el("div", { class: "dashboard-facts" },
        el("span", {}, t("{0} of {1} connections enabled", enabled, eps.length)),
        // "(s)" like the "route(s)" one line above, and for the same reason the Go side spells out at
        // countWordLists: a router that writes "1 failover groups" invites the reader to doubt the
        // number next to it. Measured on a live Keenetic, which has exactly one group.
        el("span", {}, tn("{0} failover group|{0} failover groups", groups.length)))),
    el("div", { class: "dashboard-hero-actions" },
      el("a", { class: "btn btn-sm", href: "#connections" }, t("Connections")),
      el("a", { class: "btn btn-sm", href: "#failover" }, t("Failover"))));
}

async function renderDashboard(view) {
  // The failover state comes with the profile and health: the hero's first line answers which exit
  // is carrying traffic, and without this it answered from the latency guess alone.
  await Promise.all([loadProfile(), loadHealth(), loadFailoverState()]);
  let wd = null; try { wd = await api.get("/api/watchdog"); } catch (_) {}
  const eps = state.profile.endpoints;
  const groups = state.profile.groups;
  watchdog = wd;

  // The dashboard starts with the one answer the user came for: whether traffic is
  // protected and which configured path is carrying it.
  view.appendChild(dashboardHero(eps, groups));

  // (The old standalone "Interfaces" card was removed — per-tunnel ↓/↑ throughput is now shown
  // inline on each connection/failover row, and the WAN rate stays in the system strip's "WAN now"
  // tile. See connRow + paintIfaceList.)

  // Graceful degradation: when the proxy core isn't running (and we're not in demo),
  // say so plainly at the top instead of leaving the dashboard silently empty — the
  // live graph + per-tunnel stats only populate once sing-box is up.
  const hh = state.health || {};
  if (!hh.demo && !(hh.singbox && hh.singbox.running) && !isNativeOnly(hh)) {
    const inner = el("div", {});
    if (eps.length) {
      // A core was configured and is expected to be up. This IS a fault, so it keeps the alarming
      // headline.
      inner.appendChild(el("b", {}, t("Proxy core not running")));
      inner.appendChild(el("div", { class: "hint", style: "margin-top:3px" },
        t("Review and apply the pending configuration to start the tunnel.")));
    } else {
      // Nothing is configured, so no core is expected and "not running" describes a fault that does
      // not exist. Name the actual state, then offer the two routes out of it that this router can
      // actually take: adopt the native tunnels /api/vpn/discover already sees (the dashboard used
      // to ignore that endpoint entirely and send the operator off to create a connection it had
      // already found), and install an engine when none is present.
      inner.appendChild(el("b", {}, t("No VPN connections added")));
      let tunnels = [];
      try {
        const dv = await api.get("/api/vpn/discover");
        tunnels = (dv && dv.vpns) || [];
      } catch (_) { /* CLI tools absent or endpoint unreachable — offer the manual route below */ }
      if (tunnels.length) {
        inner.appendChild(el("div", { class: "hint", style: "margin-top:3px" },
          tn("This router already carries {0} connection WayHop can import: {1}.|This router already carries {0} connections WayHop can import: {1}.",
            tunnels.length, tunnels.map(tn => tn.name || tn.iface).join(", "))));
      } else {
        inner.appendChild(el("div", { class: "hint", style: "margin-top:3px" },
          t("Add a connection, then review and apply the configuration.")));
      }
      // singbox.available is the binary's presence, which is a different fact from whether it runs.
      // Reporting only "not running" for a router that has no engine at all sends the operator to
      // look for a crash that never happened.
      if (hh.singbox && !hh.singbox.available) {
        inner.appendChild(el("div", { class: "hint", style: "margin-top:3px" },
          t("No proxy engine is installed. sing-box is required for VLESS, VMess, Trojan and SOCKS exits; AmneziaWG and olcRTC run as plugins.")));
      }
      const actions = el("div", { style: "margin-top:8px;display:flex;gap:8px;flex-wrap:wrap" });
      actions.appendChild(el("button", {
        class: "btn btn-primary btn-sm",
        onclick: () => { location.hash = "#connections"; },
      }, tunnels.length ? t("Import from the router →") : t("Add a connection →")));
      if (hh.singbox && !hh.singbox.available) {
        actions.appendChild(el("button", {
          class: "btn btn-sm",
          onclick: () => { location.hash = "#updater"; },
        }, t("Install an engine →")));
      }
      inner.appendChild(actions);
    }
    view.appendChild(el("div", { class: "card notice-core" },
      el("span", { class: "notice-core-ico", "aria-hidden": "true" }, "○"), inner));
  }

  // The time axis: what this router has been doing, and when. It sits directly under the verdict
  // because "is it working now" and "has it been working" are the same question asked twice.
  view.appendChild(activityRibbonCard());

  // System-health strip (RAM gauge / CPU / uptime) — removes itself when procfs is absent.
  view.appendChild(systemStrip());

  // PBR status row — best-effort; silently absent if server is old or mode != hybrid.
  try {
    const pbrSt = await api.get("/api/pbr/status");
    if (pbrSt && pbrSt.mode === "hybrid") {
      const pbrPill = pbrSt.installed && !pbrSt.stale
        ? el("span", { class: "pill ok pill--dot" }, t("active · {0} zones", pbrSt.zones))
        : pbrSt.installed
          ? el("span", { class: "pill warn" }, t("stale — Apply to activate"))
          : el("span", { class: "pill muted" }, t("not applied"));
      view.appendChild(el("div", { class: "card" },
        el("div", { class: "row-between", style: "align-items:center;gap:var(--sp-3)" },
          el("span", {}, t("Kernel routing")),
          pbrPill)));
    }
  } catch (_) {}

  // Traffic card: live graph and one tile per enabled exit. Connection management
  // remains on its explicitly labelled page rather than being repeated for every group here.
  const card = el("div", { class: "card" });
  card.appendChild(el("div", { class: "card-head" },
    el("div", {},
      el("div", { class: "card-title" }, t("Traffic")),
      el("div", { class: "hint" }, t("Live throughput and public exit addresses")))));

  const graphWrap = el("div", { class: "graphwrap" },
    el("div", { class: "ymax", id: "g-ymax" }, "—"),
    el("canvas", {
      class: "graph", id: "g-canvas", width: "1600", height: "400",
      role: "img", "aria-label": t("Live throughput over the last five minutes"),
    }),
    // Hover readout: drawGraph fills + positions this with the time + each interface's rate at the
    // hovered sample. Hidden until the pointer is over the canvas.
    el("div", { class: "g-tip", id: "g-tip", style: "display:none" }));
  card.appendChild(graphWrap);
  // No separate legend strip: the per-interface colour + live rate now live on the exit tiles below
  // (one block). Only the time axis stays under the graph.
  card.appendChild(el("div", { class: "axis" }, el("span", { id: "g-tstart" }, "—"), el("span", { id: "g-tend" }, "—")));
  // (The on-demand Speedtest button lives on the Diagnostics page now, not here — the dashboard graph
  //  already shows continuous live throughput, so an action button was redundant on it.)

  // Exit grid — one tile per enabled tunnel (name, WAN exit IP + flag, provider), directly below the
  // speed graph. Health-outlined green/red by paintExitGrid; hidden until populated.
  card.appendChild(el("div", { class: "exit-grid", id: "exit-grid", style: "display:none;margin-top:14px" }));

  view.appendChild(card);

  // Routing-list reachability strip (routing is the device's core job).
  const rstrip = routingStripCard();
  if (rstrip) view.appendChild(rstrip);

  view.appendChild(el("div", { class: "dashboard-activity" },
    talkersCard(),
    connectionsCard()));

  graphCanvas = $("#g-canvas");
  graphHover = null; // clear any stale hover from a prior view (keyboard-nav away can skip mouseleave)
  if (graphCanvas) {
    // Hover crosshair + readout. The canvas is recreated each dashboard render, so (re)bind here.
    graphCanvas.addEventListener("mousemove", e => {
      const r = graphCanvas.getBoundingClientRect();
      graphHover = e.clientX - r.left; // CSS px within the canvas; drawGraph maps it to a time
      drawGraph();
    });
    graphCanvas.addEventListener("mouseleave", () => { graphHover = null; drawGraph(); });
  }
  paintHero();
  drawGraph();
  paintDashRouting(); // fire-and-forget: colour the routing-list strip once per render
  paintSystem();      // fill the system strip (or remove it when procfs is unavailable)
  paintConnections(); // fill the live-connections table (empty state when Clash is down)
  paintExitGrid();    // fill the per-egress exit grid (name + WAN IP + flag + provider per tunnel)
}

function tile(k, v, sub) {
  return el("div", { class: "tile" },
    el("div", { class: "k" }, k),
    el("div", { class: "v" }, v, sub ? el("small", {}, "  " + sub) : null));
}
// refreshEnabledTile updates just the dashboard Endpoints tile's "N enabled" sub after an optimistic
// toggle — no route() re-render (which would kill the switch animation + jump scroll). No-op off-dashboard.
function refreshEnabledTile() {
  if (!state.profile) return;
  const small = document.querySelector('.tile[data-tile="endpoints"] .v small');
  if (small) small.textContent = "  " + t("{0} enabled", (state.profile.endpoints || []).filter(e => e.enabled).length);
}

// Status hero — the dashboard's first answer to "am I protected, and which exit am I
// on right now?". Derives a single verdict from the default route + per-endpoint health
// (color + icon SHAPE + word, WCAG). Re-painted live by refreshPills. Lightweight first
// pass: no public-exit-IP lookup yet (that needs a cached backend probe — Tier 2).
function bestAliveMember(members) {
  let best = null;
  members.forEach(m => {
    const h = healthMap[m.id];
    if (h && h.state === "alive") { const lat = h.latency_ms || 9999; if (!best || lat < best.lat) best = { ep: m, lat: lat }; }
  });
  return best;
}
function computeVerdict() {
  const h = state.health || {};
  if (!h.demo && !(h.singbox && h.singbox.running)) {
    // Native-only: an absent core is by design (kernel plane carries everything), so the
    // hero shows a benign "native" verdict instead of the red OFFLINE / core-down state.
    if (isNativeOnly(h)) return { level: "protected", ico: "✓", word: "NATIVE", verdict: t("Native-only mode — sing-box not required"), sub: t("Routed by the kernel plane (fast mode)") };
    return { level: "offline", ico: "○", word: "OFFLINE", verdict: t("Proxy core not running"), sub: "" };
  }
  const def = (state.profile.rules || []).find(r => r.default);

  // What the DEFAULT does and what happens to ALL traffic are different statements, and both of the
  // branches below used to make the second while measuring the first. On the operator's own router
  // the default is direct and FIFTEEN enabled routing lists send named destinations through tunnels —
  // the whole point of the Routing page — and the hero called it UNPROTECTED.
  //
  // So count what else routes, ONCE, above both branches: a list or a rule that is enabled and points
  // at something other than direct/block is a tunnel the panel itself set up. Computing it inside the
  // direct branch is what left the block branch still claiming "blocks all traffic" on a router whose
  // allowlist plainly gets out — the same defect, one branch over, which is the shape this audit
  // keeps finding when a fix is written for the case that was reported rather than for the class.
  const tunnelledOut = (o) => o && o !== "direct" && o !== "block";
  const tunnelledCount =
    (state.profile.routing_lists || []).filter(l => l.enabled !== false && tunnelledOut(l.outbound)).length +
    (state.profile.rules || []).filter(r => !r.default && !r.disabled && tunnelledOut(r.outbound)).length;
  const selective = (fallback) => ({
    level: "selective", ico: "◐", word: "SELECTIVE",
    verdict: fallback,
    sub: tn("{0} route via a tunnel|{0} routes via a tunnel", tunnelledCount),
  });

  if (!def || !def.outbound || def.outbound === "direct") {
    if (tunnelledCount > 0) return selective(t("Selective routing — everything else goes direct"));
    return { level: "unprotected", ico: "✕", word: "UNPROTECTED", verdict: t("Traffic goes direct (no tunnel)"), sub: def ? "" : t("No default route set") };
  }
  if (def.outbound === "block") {
    // Deny-by-default with an allowlist through tunnels is a deliberate posture, not a degraded one.
    // Reporting it as "blocks all traffic" is both wrong and alarming: the routed lists get out.
    if (tunnelledCount > 0) return selective(t("Selective routing — everything else is blocked"));
    return { level: "degraded", ico: "⚠", word: "BLOCKED", verdict: t("Default route blocks all traffic"), sub: "" };
  }
  const g = findGroup(def.outbound), ep = findEndpoint(def.outbound);
  if (g) {
    const members = (g.members || []).map(findEndpoint).filter(Boolean);
    const best = bestAliveMember(members);
    // Which member is actually carrying traffic is a fact the daemon reports (Clash `now`), and the
    // Failover page already renders it as "● LIVE" while calling the latency pick a "✓ BEST" GUESS.
    // The hero asked the same question and answered with the guess: for a `selector` group — which is
    // what the generator emits for every group — traffic goes through the SELECTED member, so the
    // two are different names whenever the selection is not the quickest one. The hero's own line is
    // "which exit am I on right now", so it names the elected member, and when that is not known it
    // says so instead of promoting the guess.
    const electedEp = findEndpoint((failoverState.elected || {})[g.id] || "");
    if (electedEp) {
      const he = healthMap[electedEp.id] || {};
      return { level: "protected", ico: "✓", word: "PROTECTED", verdict: t("via ") + g.name,
        sub: g.type + " · " + (electedEp.name || electedEp.id) + (he.latency_ms ? " · " + he.latency_ms + " ms" : "") };
    }
    if (best) {
      const hb = healthMap[best.ep.id] || {};
      return { level: "protected", ico: "✓", word: "PROTECTED", verdict: t("via ") + g.name,
        sub: g.type + " · " + t("active member unknown") + " · " + t("fastest: {0}", (best.ep.name || best.ep.id) + (hb.latency_ms ? " " + hb.latency_ms + " ms" : "")) };
    }
    if (members.some(m => healthMap[m.id])) return { level: "degraded", ico: "⚠", word: "DEGRADED", verdict: t("via ") + g.name + t(" — no live member"), sub: g.type };
    return { level: "checking", ico: "…", word: "CHECKING", verdict: t("Checking") + " " + g.name + "…", sub: g.type };
  }
  if (ep) {
    const he = healthMap[ep.id];
    if (he && he.state === "alive") return { level: "protected", ico: "✓", word: "PROTECTED", verdict: t("via ") + (ep.name || ep.id), sub: (ep.protocol || ep.engine || "") + (he.latency_ms ? " · " + he.latency_ms + " ms" : "") };
    if (he && he.state === "down") return { level: "degraded", ico: "⚠", word: "DEGRADED", verdict: t("via ") + (ep.name || ep.id) + t(" — down"), sub: he.cause || "" };
    return { level: "checking", ico: "…", word: "CHECKING", verdict: t("Checking") + " " + (ep.name || ep.id) + "…", sub: ep.protocol || "" };
  }
  return { level: "unprotected", ico: "✕", word: "UNPROTECTED", verdict: t("Default route unavailable"), sub: nameOf(def.outbound) || def.outbound };
}
function paintHero() {
  const pill = document.getElementById("hero-pill");
  if (!pill) return;
  const v = computeVerdict();
  // "selective" is not a warning — it is the configuration working as designed — so it takes the ok
  // colour rather than warn. The word and the sub-line carry the distinction from full-tunnel.
  const cls = { protected: "ok", selective: "ok", degraded: "warn", unprotected: "err", checking: "muted", offline: "muted" }[v.level] || "muted";
  pill.className = "hero-pill hero-" + cls;
  const ico = document.getElementById("hero-ico");
  const word = document.getElementById("hero-word");
  const verdict = document.getElementById("hero-verdict");
  const sub = document.getElementById("hero-sub");
  if (ico) ico.textContent = v.ico;
  if (word) word.textContent = t(v.word);
  if (verdict) verdict.textContent = v.verdict;
  if (sub) { sub.textContent = v.sub || ""; sub.style.display = v.sub ? "" : "none"; }
}
// Public exit IP — the address the active proxy presents upstream (what a VPN user
// most wants to confirm). Async (a cached through-proxy lookup); fills the hero when
// available, stays hidden otherwise (demo / core down / unreachable).
// flagOf maps an ISO-3166-1 alpha-2 country code to its flag emoji (two regional-indicator
// symbols). Returns "" for anything that isn't a 2-letter code, so a missing/unknown geo shows
// no flag rather than tofu.
function flagOf(cc) {
  cc = String(cc || "").trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return "";
  return String.fromCodePoint(...[...cc].map(c => 0x1f1e6 + c.charCodeAt(0) - 65));
}

// paintExitGrid fills the dashboard's per-egress exit grid from /api/exit-ips: one tile per enabled
// tunnel with its name (top), the public WAN exit IP (center) beside its country flag, and the
// provider (bottom). Hidden when no exits are available (demo / core down / no endpoints). Async +
// cached server-side, so it's cheap to call on each dashboard render.
function paintExitGrid() {
  const grid = document.getElementById("exit-grid");
  if (!grid) return;
  const show = vis => { grid.style.display = vis ? "" : "none"; };
  // Fetch the exit list and the live per-endpoint health together so each tile is outlined green
  // (up) / red (down) by its endpoint's current state; an unknown/unprobed state stays neutral.
  Promise.all([
    api.get("/api/exit-ips"),
    api.get("/api/health/endpoints").catch(() => []),
  ]).then(([d, health]) => {
    const exits = (d && d.available && Array.isArray(d.exits)) ? d.exits : [];
    if (!exits.length) { grid.innerHTML = ""; show(false); return; }
    const stateById = {};
    (health || []).forEach(h => { if (h && h.id) stateById[h.id] = h.state; });
    grid.innerHTML = "";
    // Every address is primary dashboard information. Keep all cards in one responsive surface:
    // CSS distributes them across the available width and centres any partially-filled final row.
    // The old four-card <details> fold created a second, narrow grid when opened, which is precisely
    // the awkward left-aligned stack this layout is meant to avoid.
    exits.forEach(x => {
      const flag = flagOf(x.cc);
      const provider = x.isp || x.asn || (x.country || "");
      const st = stateById[x.id]; // alive | down | unknown | undefined
      const cls = "exit-tile" + (st === "alive" ? " ok" : st === "down" ? " down" : "");
      // Fold the graph legend into the tile: every exit gets a colour-dot matching its graph line + its
      // live throughput (data-iface, refreshed by updateExitRates each tick). Kernel-interface exits key
      // on their iface (rate from /proc counters); proxy exits (VLESS/SOCKS — no kernel iface) key on the
      // endpoint id, whose rate comes from the Clash-derived per-outbound map (pushOutboundRates).
      const key = ifaceOfEndpoint(x.id) || x.id;
      // Register the key up front so its dot colour is a stable palette slot from the very first paint
      // (ifaceColor falls back to palette-0 for an unregistered key). The empty series draws no line —
      // drawGraph needs an in-window sample — and the push fns dedup on ifaceSeries, so no double-add.
      if (!ifaceSeries[key]) { ifaceSeries[key] = []; ifaceOrder.push(key); }
      const ser = ifaceSeries[key];
      const rateRow = el("div", { class: "exit-rate" },
        el("span", { class: "dot", style: "background:" + ifaceColor(key) }),
        el("span", { class: "exit-rate-v", "data-iface": key }, ser && ser.length ? fmtRate(ser[ser.length - 1].r) : "—"));
      // Always render the provider line (nbsp placeholder when unknown, e.g. KEENETIC DNR) so every
      // tile has the same row structure and therefore the same height — no "floating" on content.
      const tile = el("div", { class: cls, title: st || "" },
        el("div", { class: "exit-name" }, x.name || x.id || ""),
        el("div", { class: "exit-mid" },
          flag ? el("span", { class: "exit-flag", title: x.country || x.cc || "" }, flag) : null,
          el("span", { class: "exit-ip" }, x.ip || "")),
        el("div", { class: "exit-prov" }, provider || " "),
        rateRow);
      grid.appendChild(tile);
    });
    show(true);
  }).catch(() => { grid.innerHTML = ""; show(false); });
}

// System-health strip: host RAM / CPU-load / uptime from /api/system. RAM is the #1
// bottleneck on the router, so it leads as a gauge (green<70 / amber<88 / red). Fetched
// once per render (kept out of the 1 Hz tick); the strip removes itself when procfs is
// unavailable (e.g. the demo on a non-Linux dev box) rather than showing dead tiles.
function sysTile(label, key) {
  return el("div", { class: "tile sys-tile", "data-sys": key },
    el("div", { class: "k" }, label), el("div", { class: "sys-v" }, "…"));
}
function systemStrip() {
  const strip = el("div", { class: "sys-strip", id: "sys-strip" },
    el("div", { class: "tile sys-tile", "data-sys": "ram" },
      el("div", { class: "k" }, "RAM"),
      el("div", { class: "sys-v" }, "…"),
      el("div", { class: "sys-bar" }, el("span", { class: "sys-bar-fill" }))),
    sysTile("CPU load", "load"),
    sysTile("Uptime", "uptime"),
    sysTile("CPU temp", "temp"),
    sysTile("WAN now", "thru"));
  return strip; // painted by paintSystem() after it's in the DOM (see renderDashboard)
}
let prevIfaces = null; // {name:{rx,tx,t}} — previous /api/system iface counters, for rate calc
// paintSystem repaints the system strip. When the 5 s health tick already fetched
// /api/system as part of its parallel batch it passes the sample in (si !== undefined),
// so the strip refreshes without a second, serial round-trip on the router link. Called
// with no argument (initial render, manual refresh) it fetches its own copy.
// When the last successful /api/system sample arrived. The feed is best-effort inside the 5 s poll
// (.catch(() => null)), and the endpoints feed keeps answering, so a dead /api/system raises no
// reconnect banner. Without this the strip kept displaying its last RAM/CPU/uptime/throughput
// indefinitely, presented as current — measured: unchanged 13 s after the feed died, with nothing
// on screen to say so. Keeping the last figures is fine; passing them off as live is not.
let lastSysOK = 0;
const SYS_STALE_MS = 12000; // two poll cycles plus slack, so one dropped sample is not an alarm

// markSystemStale flags the strip when its figures have stopped refreshing, and clears the flag the
// moment a sample lands. The values stay put — they are the last thing that was true.
function markSystemStale(strip, stale) {
  if (stale) strip.setAttribute("data-stale", "1");
  else strip.removeAttribute("data-stale");
  let note = strip.querySelector(".sys-stale");
  if (!stale) { if (note) note.remove(); return; }
  if (!note) {
    note = el("div", { class: "sys-stale", role: "status" }, "Not updating — these are the last figures received.");
    strip.appendChild(note);
  }
}

function paintSystem(si) {
  const strip = document.getElementById("sys-strip");
  if (!strip) return;
  if (si === null) {
    // The batched poll dropped this tick. Leave the figures, but stop implying they are current.
    if (lastSysOK && Date.now() - lastSysOK > SYS_STALE_MS) markSystemStale(strip, true);
    return;
  }
  const apply = si => {
    if (!si || !si.available) { strip.remove(); return; } // no procfs (non-Linux) → drop the strip
    lastSysOK = Date.now();
    markSystemStale(strip, false);
    const tot = si.mem_total_kb / 1024, used = (si.mem_total_kb - si.mem_avail_kb) / 1024, pct = Math.round(si.mem_used_pct);
    const ram = strip.querySelector('[data-sys="ram"]');
    if (ram) {
      const rv = ram.querySelector(".sys-v");
      if (rv) { rv.innerHTML = ""; rv.append(pct + "%", el("small", {}, "  " + Math.round(used) + " / " + Math.round(tot) + " MB")); }
      const fill = ram.querySelector(".sys-bar-fill");
      if (fill) { fill.style.width = Math.min(100, pct) + "%"; fill.style.background = pct >= 88 ? "var(--err)" : pct >= 70 ? "var(--warn)" : "var(--ok)"; }
      ram.title = t("{0} MB free of {1} MB", Math.round(tot - used), Math.round(tot));
    }
    const lv = strip.querySelector('[data-sys="load"] .sys-v');
    if (lv) { lv.innerHTML = ""; lv.append((si.load1 || 0).toFixed(2), el("small", {}, "  " + t("1-min"))); }
    const uv = strip.querySelector('[data-sys="uptime"] .sys-v');
    if (uv) uv.textContent = fmtUptime(si.uptime_s);
    const tt = strip.querySelector('[data-sys="temp"]'), tv = tt && tt.querySelector(".sys-v");
    if (tv) {
      tv.textContent = si.temp_c ? Math.round(si.temp_c) + "°C" : "—";
      if (si.temp_c) tt.title = si.temp_c.toFixed(1) + " °C (CPU)";
    }
    const thru = strip.querySelector('[data-sys="thru"] .sys-v');
    if (thru) paintThroughput(thru, si.interfaces || []);
  };
  if (si !== undefined) { apply(si); return; } // real object supplied by the batched poll — no extra round-trip (available:false still removes = genuine non-Linux)
  api.get("/api/system").then(apply).catch(() => strip.remove());
}
// paintThroughput shows REAL WAN throughput (rate = Δbytes/Δt across successive /api/system
// polls) and, on the tile's hover title, the per-interface breakdown (WAN + each tunnel +
// LAN). Captures all traffic incl. the kernel fast-path — unlike the proxy-only graph.
function paintThroughput(node, ifaces) {
  const now = Date.now() / 1000;
  const cur = {};
  ifaces.forEach(f => { cur[f.name] = { rx: f.rx_bytes, tx: f.tx_bytes, t: now }; });
  const rate = (name) => {
    const p = prevIfaces && prevIfaces[name], c = cur[name];
    if (!p || !c) return null;
    // Guard against a stale prevIfaces from before the user navigated away: a gap far larger than the
    // poll interval (~5 s) means the two samples aren't consecutive, so the Δbytes/Δt rate would be wrong.
    // Treat it as a fresh first sample (null → "…") and let the next tick produce a correct rate.
    const dt = c.t - p.t; if (dt <= 0 || dt > 30) return null;
    return { down: Math.max(0, (c.rx - p.rx) / dt), up: Math.max(0, (c.tx - p.tx) / dt) };
  };
  // WAN iface: prefer one literally named "wan", else the busiest non-bridge/non-tunnel.
  const wan = ifaces.find(f => f.name === "wan") ||
    ifaces.filter(f => !/^(br-|lo$|awg|wg|tun)/.test(f.name)).sort((a, b) => (b.rx_bytes + b.tx_bytes) - (a.rx_bytes + a.tx_bytes))[0];
  const w = wan && rate(wan.name);
  // The WAN tile and the per-tunnel rate list are independent: a momentarily-null WAN rate
  // (counter reset, WAN not yet identified) must not blank tunnel rates that ARE computable.
  if (!w) {
    node.textContent = "…";
  } else {
    // ONE unit for both readings instead of one each. As "↓3.8 MB/s ↑845.5 KB/s" this needed two
    // lines in a 148px tile — first breaking between a number and its unit, and after that was
    // prevented, still breaking between the two readings — either way leaving this tile taller than
    // the four beside it. Scaled to a shared unit the pair reads as a pair and always fits; the exact
    // per-interface figures stay in the tile's title.
    const U = [[1 << 30, "GB"], [1 << 20, "MB"], [1 << 10, "KB"]];
    const top = Math.max(w.down, w.up);
    const [div, unit] = U.find(([d]) => top >= d) || [1, "B"];
    const n = (v) => (v / div >= 100 ? Math.round(v / div) : Math.round((v / div) * 10) / 10);
    node.innerHTML = "";
    node.append(el("span", { class: "sv-r" }, "↓" + n(w.down)), " ",
      el("span", { class: "sv-r" }, "↑" + n(w.up)), " ",
      el("small", { class: "sv-r" }, unit + "/s"));
    const tile = node.closest(".sys-tile");
    if (tile) {
      const lines = ifaces.map(f => { const r = rate(f.name); return r ? f.name + ": ↓" + fmtBytes(r.down) + "/s ↑" + fmtBytes(r.up) + "/s" : null; }).filter(Boolean);
      tile.title = lines.join("\n");
    }
  }
  paintIfaceList(ifaces, rate, wan && wan.name); // per-tunnel rates paint regardless of the WAN tile state
  // Feed the per-interface throughput graph: one rate sample per interface this tick (skips ifaces
  // with no computable rate yet, e.g. the first sample after a navigation).
  const rmap = {};
  ifaces.forEach(f => { const r = rate(f.name); if (r) rmap[f.name] = r; });
  pushIfaceRates(rmap, wan && wan.name);
  pushOutboundRates(); // proxy exits (no kernel iface) get their rate from the Clash-derived map
  prevIfaces = cur;
}

// paintIfaceList paints each tunnel's live ↓download / ↑upload rate INLINE on its connection row
// (the .conn-rate slot keyed by the bound kernel iface), from the same /api/system byte counters
// as the WAN throughput tile. Replaces the old standalone "Interfaces" card; the WAN's own rate
// stays in the system strip's "WAN now" tile. A slot with no rate yet is left blank (it fills on
// the next /api/system poll). Off-Linux dev boxes report no interfaces, so nothing paints there.
function paintIfaceList(ifaces, rate, wanName) {
  const slots = document.querySelectorAll(".conn-rate[data-iface]");
  if (!slots.length) return;
  slots.forEach(slot => {
    const r = rate(slot.getAttribute("data-iface"));
    slot.innerHTML = "";
    if (!r) return;
    slot.append(
      el("span", { class: "rx" }, "↓ " + fmtBytes(r.down) + "/s"),
      el("span", { class: "hint", style: "margin:0 7px" }, "·"),
      el("span", { class: "tx" }, "↑ " + fmtBytes(r.up) + "/s"));
  });
}
// ifaceFriendly maps a kernel iface (nwg1) to the name of the endpoint bound to it.
function ifaceFriendly(name) {
  const ep = ((state.profile && state.profile.endpoints) || []).find(e => e.params && e.params.interface === name);
  return ep ? (ep.name || ep.id) : name;
}

// Live connections (the #1 Clash-dashboard feature): make routing observable — see
// which host went through which chain + matched which rule, live. Data from the Clash
// /connections list (server-capped to the top ~60 by bytes). Refreshed on the health
// tick; empty / core-down shows a clean empty state.
function fmtAge(startISO) {
  const t = Date.parse(startISO || "");
  if (isNaN(t)) return "";
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m";
  return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
}
// exitLabel maps a conntrack connection's resolved egress tag to a friendly name: "direct"
// (general WAN) stays as-is; an endpoint OR GROUP id resolves to the name the operator gave it.
//
// Groups were not looked up, so every connection a failover group carried printed its raw tag.
// Measured on a live Keenetic: the Dashboard's Live connections summary read
// "grp-primary 94.0 MB" while the Routing lists card ON THE SAME PAGE called that group
// "Primary group" — one page, one object, two names, and the one shown against the traffic figure
// was the internal id.
function exitLabel(tag) {
  if (!tag || tag === "direct") return "direct";
  const e = findEndpoint(tag) || findGroup(tag);
  return (e && e.name) ? e.name : tag;
}
// connItem renders one REAL kernel connection (from /api/conntrack) — remote dst:port, the
// L4 proto, which exit it took, and per-direction bytes. The right-hand slot shows the TCP
// state. Sees the kernel fast-path that the Clash view cannot.
function connItem(c) {
  const dst = (c.dst || "—") + (c.dport ? ":" + c.dport : "");
  return el("div", { class: "conn-item" },
    el("div", { class: "conn-main" },
      el("div", { class: "conn-host", title: (c.src || "") + " → " + dst }, dst),
      el("div", { class: "conn-sub" }, (c.proto || "") + " · via " + exitLabel(c.exit) +
        "  ·  ↓" + fmtBytes(c.down_bytes || 0) + " ↑" + fmtBytes(c.up_bytes || 0))),
    el("div", { class: "conn-age" }, c.state || ""));
}
// connItemClash renders a sing-box (Clash) connection — used only as the demo / off-router
// fallback when /api/conntrack is unavailable (it shows the proxy chain + matched rule).
function connItemClash(c) {
  const m = c.metadata || {};
  const host = (m.host || m.destinationIP || "—") + (m.destinationPort ? ":" + m.destinationPort : "");
  const chain = (c.chains && c.chains.length) ? c.chains.join(" → ") : "direct";
  const rule = c.rule ? c.rule + (c.rulePayload ? " · " + c.rulePayload : "") : "";
  return el("div", { class: "conn-item" },
    el("div", { class: "conn-main" },
      el("div", { class: "conn-host", title: host }, host),
      el("div", { class: "conn-sub" }, "⇢ " + chain + (rule ? "  ·  " + rule : "") +
        "  ·  ↓" + fmtBytes(c.download || 0) + " ↑" + fmtBytes(c.upload || 0))),
    el("div", { class: "conn-age" }, fmtAge(c.start)));
}
// groupConnsByIP aggregates a normalized connection list ({ip,port,proto,up,down,exit})
// into per-destination-IP groups — each carrying its used ports (with per-port conn
// count + bytes), total bytes, exits and connection count. Backs the "summarize live
// connections by IP" view: one row per remote IP, the ports it used listed beneath.
function groupConnsByIP(rows) {
  const byIP = new Map();
  rows.forEach(r => {
    const ip = r.ip || "—";
    let g = byIP.get(ip);
    if (!g) { g = { ip, up: 0, down: 0, conns: 0, exits: new Set(), ports: new Map() }; byIP.set(ip, g); }
    g.up += r.up || 0; g.down += r.down || 0; g.conns++;
    if (r.exit) g.exits.add(r.exit);
    if (r.port) {
      const key = r.port + (r.proto ? "/" + r.proto : "");
      const p = g.ports.get(key) || { n: 0, up: 0, down: 0 };
      p.n++; p.up += r.up || 0; p.down += r.down || 0;
      g.ports.set(key, p);
    }
  });
  return [...byIP.values()].sort((a, b) => (b.up + b.down) - (a.up + a.down));
}
// connGroupItem renders one destination-IP group: the IP + aggregate (exits, bytes,
// conn count) on top, and the set of used ports beneath (proto-tagged, ×N when reused;
// per-port conns + bytes on hover) — the by-IP summary form of connItem.
function connGroupItem(g) {
  const exits = [...g.exits].map(exitLabel).join(", ");
  const sub = (exits ? t("via {0}", exits) + "  ·  " : "") +
    "↓" + fmtBytes(g.down) + " ↑" + fmtBytes(g.up) + "  ·  " + (g.conns > 1 ? t("{0} conns", g.conns) : t("{0} conn", g.conns));
  const chips = [...g.ports.entries()]
    .sort((a, b) => (parseInt(a[0]) || 0) - (parseInt(b[0]) || 0))
    .map(([key, p]) => el("span", {
      class: "conn-port",
      title: key + "  ·  " + (p.n > 1 ? t("{0} conns", p.n) : t("{0} conn", p.n)) + "  ·  ↓" + fmtBytes(p.down) + " ↑" + fmtBytes(p.up),
    }, p.n > 1 ? key + " ×" + p.n : key));
  return el("div", { class: "conn-group" },
    el("div", { class: "conn-item" },
      el("div", { class: "conn-main" },
        el("div", { class: "conn-host", title: g.ip }, g.ip),
        el("div", { class: "conn-sub" }, sub)),
      el("div", { class: "conn-age" }, tn("{0} port|{0} ports", g.ports.size))),
    g.ports.size ? el("div", { class: "conn-ports" }, chips) : null);
}
function connectionsCard() {
  // Collapsed by default — the connection table is long and secondary on the dashboard, so it
  // shouldn't take up space until asked for. The header stays a live summary (count + per-exit
  // split via #conns-sum, kept updated even while collapsed); a click on the header toggles the
  // list open/closed and the choice persists per-browser (localStorage).
  const card = el("div", { class: "card conns-card" });
  const chev = el("span", { class: "chev" }, "▸");
  const head = el("div", { class: "card-head conns-head", role: "button", tabindex: "0", title: t("Show / hide live connections") },
    el("div", { class: "conns-head-l" }, chev, el("div", { class: "card-title" }, "Live connections")),
    el("div", { class: "hint", id: "conns-sum" }, "checking…"));
  const list = el("div", { class: "conns-list", id: "conns-list" });
  const setOpen = (on) => {
    card.classList.toggle("open", on);
    chev.textContent = on ? "▾" : "▸";
    head.setAttribute("aria-expanded", on ? "true" : "false");
    try { localStorage.setItem("wr.conns.open", on ? "1" : "0"); } catch (_) {}
  };
  const toggle = () => setOpen(!card.classList.contains("open"));
  head.addEventListener("click", toggle);
  head.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(); } });
  card.append(head, list);
  let open = false; try { open = localStorage.getItem("wr.conns.open") === "1"; } catch (_) {}
  setOpen(open); // default: collapsed
  return card;
}
function talkersCard() {
  const card = el("div", { class: "card" });
  card.appendChild(el("div", { class: "card-title", style: "margin-bottom:12px" }, "Top talkers"));
  card.appendChild(el("div", { class: "talkers-list", id: "talkers-list" }));
  return card;
}
// exitsSummary turns the per-exit byte totals into a short "direct 1.2G · NL 300M" line.
function exitsSummary(exits) {
  if (!exits) return "";
  return Object.entries(exits).sort((a, b) => b[1] - a[1]).slice(0, 3)
    .map(([tag, bytes]) => exitLabel(tag) + " " + fmtBytes(bytes)).join("  ·  ");
}
// renderConnList paints the REAL connection table from the /api/conntrack payload, with the
// live count vs the conntrack limit and a per-exit traffic split in the header.
function renderConnList(list, data) {
  const sum = document.getElementById("conns-sum");
  const conns = (data && data.conns) || [];
  list.innerHTML = "";
  if (!conns.length) { list.appendChild(el("div", { class: "empty" }, t("No active connections"))); if (sum) sum.textContent = ""; return; }
  if (sum) {
    let s = (data.total || conns.length) + " " + t("active");
    if (data.max && data.total != null) s += "  ·  " + t("{0}% of {1}", Math.round((data.total / data.max) * 100), data.max);
    const ex = exitsSummary(data.exits);
    if (ex) s += "  ·  " + ex;
    sum.textContent = s;
  }
  const groups = groupConnsByIP(conns.map(c => ({ ip: c.dst, port: c.dport, proto: c.proto, up: c.up_bytes, down: c.down_bytes, exit: c.exit })));
  groups.slice(0, 40).forEach(g => list.appendChild(connGroupItem(g)));
}
// renderConnListClash — demo / off-router fallback (sing-box connections array).
function renderConnListClash(list, conns) {
  const sum = document.getElementById("conns-sum");
  list.innerHTML = "";
  if (!conns.length) { list.appendChild(el("div", { class: "empty" }, t("No active connections"))); if (sum) sum.textContent = ""; return; }
  if (sum) sum.textContent = conns.length + " " + t("active");
  const groups = groupConnsByIP(conns.map(c => {
    const m = c.metadata || {};
    return { ip: m.destinationIP || m.host, port: m.destinationPort, proto: "", up: c.upload, down: c.download, exit: (c.chains && c.chains.length) ? c.chains[c.chains.length - 1] : "" };
  }));
  groups.slice(0, 40).forEach(g => list.appendChild(connGroupItem(g)));
}
// Top talkers ("which device is using my bandwidth"): the /api/conntrack payload already
// aggregates per LAN client (name from DHCP leases + total up/down + conn count). Ranked
// with a proportional bar. Real — includes the kernel fast-path, unlike the Clash view.
function paintTopTalkers(list, data) {
  const clients = (data && data.clients) || [];
  list.innerHTML = "";
  if (!clients.length) { list.appendChild(el("div", { class: "empty" }, t("No traffic"))); return; }
  // Ranked, and SAY it is ranked. Showing 8 of a real LAN's clients under a bare "Top talkers"
  // heading is the same partial-as-complete defect this audit keeps finding: the reader cannot tell
  // whether 8 is everyone or the first page of thirty.
  const top = clients.slice(0, 8);
  const hidden = clients.length - top.length;
  const max = ((top[0].up_bytes || 0) + (top[0].down_bytes || 0)) || 1;
  top.forEach(c => {
    const total = (c.up_bytes || 0) + (c.down_bytes || 0);
    list.appendChild(el("div", { class: "talker" },
      el("div", { class: "talker-row" },
        el("span", { class: "talker-host", title: c.ip + "  ·  " + t("{0} conns", c.conns || 0) }, c.name || c.ip),
        el("span", { class: "talker-bytes" }, fmtBytes(total))),
      el("div", { class: "talker-bar" }, el("span", { class: "talker-bar-fill", style: "width:" + Math.max(2, Math.round(total / max * 100)) + "%" }))));
  });
  if (hidden > 0) list.appendChild(el("div", { class: "hint talker-more" },
    t("top {0} of {1} devices by traffic", top.length, clients.length)));
}
// paintTopTalkersClash — demo / off-router fallback (aggregate sing-box conns by host).
function paintTopTalkersClash(list, conns) {
  list.innerHTML = "";
  if (!conns.length) { list.appendChild(el("div", { class: "empty" }, t("No traffic"))); return; }
  const byHost = {};
  conns.forEach(c => {
    const h = (c.metadata && (c.metadata.host || c.metadata.destinationIP)) || "—";
    const e = byHost[h] || (byHost[h] = { host: h, total: 0, chain: "" });
    e.total += (c.upload || 0) + (c.download || 0);
    if (!e.chain && c.chains && c.chains.length) e.chain = c.chains.join(" → ");
  });
  const ranked = Object.values(byHost).sort((a, b) => b.total - a.total);
  const talkers = ranked.slice(0, 8);
  const hidden = ranked.length - talkers.length;
  const max = talkers[0].total || 1;
  talkers.forEach(t => list.appendChild(el("div", { class: "talker" },
    el("div", { class: "talker-row" },
      el("span", { class: "talker-host", title: t.host + (t.chain ? "  ⇢ " + t.chain : "") }, t.host),
      el("span", { class: "talker-bytes" }, fmtBytes(t.total))),
    el("div", { class: "talker-bar" }, el("span", { class: "talker-bar-fill", style: "width:" + Math.max(2, Math.round(t.total / max * 100)) + "%" })))));
  if (hidden > 0) list.appendChild(el("div", { class: "hint talker-more" },
    t("top {0} of {1} hosts by traffic", talkers.length, ranked.length)));
}
function paintConnections() {
  const list = document.getElementById("conns-list"), tlist = document.getElementById("talkers-list");
  if (!list && !tlist) return;
  if (connInFlight) return; // a prior conntrack fetch is still outstanding (slow link) — skip this tick rather than stacking overlapping requests
  connInFlight = true;
  // Prefer the REAL kernel connection table (/api/conntrack) — it sees every flow incl. the
  // fast-path. Off-router / demo (available:false) falls back to the sing-box Clash view.
  api.get("/api/conntrack").then(data => {
    if (!data || !data.available) {
      return api.get("/api/connections").then(cd => {
        const conns = (cd && cd.connections) || [];
        if (list) renderConnListClash(list, conns);
        if (tlist) paintTopTalkersClash(tlist, conns);
      });
    }
    if (list) renderConnList(list, data);
    if (tlist) paintTopTalkers(tlist, data);
  }).catch(() => {
    if (list) { list.innerHTML = ""; list.appendChild(el("div", { class: "empty" }, "—")); }
    if (tlist) { tlist.innerHTML = ""; tlist.appendChild(el("div", { class: "empty" }, "—")); }
  }).finally(() => { connInFlight = false; });
}

// Dashboard routing-list reachability strip: routing is the device's core job, yet
// per-list source health lived only on the Routing page. Render one compact chip per
// list (status icon SHAPE + colour + the list name + its egress), painted by
// paintDashRouting() from /api/routing/status. Returns null when there are no lists
// (don't clutter the dashboard). Manual no-source lists report OK.
function routingStripCard() {
  const lists = state.profile.routing_lists || [];
  if (!lists.length) return null;
  const card = el("div", { class: "card" });
  card.appendChild(el("div", { class: "card-head" },
    el("div", { class: "card-title" }, "Routing lists"),
    el("div", { class: "hint", id: "dashrl-sum" }, "checking…")));
  const strip = el("div", { class: "rl-strip" });
  lists.forEach(rl => {
    const off = !rl.enabled;
    strip.appendChild(el("div", { class: "rl-chip" + (off ? " rl-chip-off" : ""), "data-dashrl": rl.id },
      el("span", { class: "rl-ico", style: "color:var(--ink-2)" }, off ? "○" : "…"),
      el("span", { class: "rl-chip-name" }, rl.name || rl.id),
      el("span", { class: "rl-chip-via" }, "→ " + (nameOf(rl.outbound) || rl.outbound)),
      el("span", { class: "rl-note" })));
  });
  // The head already carries the verdict this card exists to give ("29 OK"), so at real scale the
  // chips below it are enumeration, not summary: on the Keenetic's 29 lists they wrap to 225px and
  // push the dashboard past two screens, where the demo's four sit on one line. Fold the enumeration
  // and keep the verdict. The chips stay in the DOM either way, so paintDashRouting still finds every
  // [data-dashrl] and a closed card is as current as an open one.
  if (lists.length > 8) {
    const det = el("details", { class: "dashrl-det" },
      el("summary", { class: "hint" }, t("Show all {0} lists", lists.length)));
    det.appendChild(strip);
    card.appendChild(det);
  } else {
    card.appendChild(strip);
  }
  return card;
}
async function paintDashRouting() {
  const chips = document.querySelectorAll("[data-dashrl]");
  if (!chips.length) return;
  let st; try { st = await api.get("/api/routing/status"); } catch (_) { return; }
  const byId = {}; (st || []).forEach(s => { byId[s.id] = s; });
  let ok = 0, down = 0, off = 0;
  chips.forEach(d => {
    const ico = d.querySelector(".rl-ico"), note = d.querySelector(".rl-note");
    if (!ico || !note) return;
    if (d.classList.contains("rl-chip-off")) { off++; ico.textContent = "○"; ico.style.color = "var(--ink-2)"; return; }
    const s = byId[d.getAttribute("data-dashrl")];
    if (!s) return; // leave the muted "…" until first probe lands
    if (s.ok) { ok++; ico.textContent = "✓"; ico.style.color = "var(--ok)"; d.title = s.status ? t("reachable (HTTP {0})", s.status) : t("OK"); note.textContent = ""; }
    else { down++; ico.textContent = "✕"; ico.style.color = "var(--err)"; d.title = s.error || t("error"); note.textContent = s.status ? "HTTP " + s.status : t("unreachable"); }
  });
  const sum = document.getElementById("dashrl-sum");
  if (sum) {
    const parts = [];
    if (ok) parts.push(ok + " " + t("OK"));
    if (down) parts.push(down + " " + t("down"));
    if (off) parts.push(off + " " + t("off"));
    sum.textContent = parts.join(" · ") || "—";
    sum.style.color = down ? "var(--err)" : "";
  }
}

function connRow(e) {
  const tog = switchEl(e.enabled, (s) => toggleEndpoint(e, s), (e.name || e.id) + switchWord(e.enabled));
  const name = el("div", { class: "name" }, e.name || e.id, pillFor(e));
  // Live ↓/↑ throughput shown INLINE on each tunnel row (external endpoints bind a kernel iface),
  // painted by paintIfaceList from the same /api/system byte counters. This replaces the old
  // standalone "Interfaces" card — the speed now lives on the Failover / connection it belongs to.
  if (e.engine === "external" && e.params && e.params.interface) {
    name.appendChild(el("span", { class: "conn-rate", "data-iface": e.params.interface, title: t("Live throughput on this interface") }));
  }
  return el("div", { class: "conn" }, tog,
    el("div", { class: "body" },
      name,
      subMeta(e),
      statsLine(e),
      causeLine(e)));
}

// Order a connection stack worst-first so problems surface at the top: down → slow →
// unknown → healthy → disabled, tie-broken by latency. Uses health known at render time
// (re-evaluated on the next full render); falls back to config order when health is absent.
function severityRank(e) {
  if (!e.enabled) return 4;                 // disabled sinks to the bottom
  const h = healthMap[e.id];
  if (h && h.state === "down") return 0;    // broken first
  if (h && h.state === "alive") return h.latency_ms >= 600 ? 1 : 3; // slow before healthy
  return 2;                                 // unknown / not yet probed
}
function bySeverity(a, b) {
  const ra = severityRank(a), rb = severityRank(b);
  if (ra !== rb) return ra - rb;
  const la = (healthMap[a.id] || {}).latency_ms || 9999;
  const lb = (healthMap[b.id] || {}).latency_ms || 9999;
  return la - lb;
}

// Optimistic in-place toggle: flip the switch (smooth CSS) + local state IMMEDIATELY, persist in the
// background, and revert only if the POST fails. No route() — a full re-render killed the animation,
// jumped the row (disabled sinks to the bottom) and lost scroll position. The dashboard "N enabled"
// count / row re-sort refresh naturally on the next navigation.
function flipSwitch(sw, on) {
  if (!sw) return;
  sw.classList.toggle("on", on);
  sw.setAttribute("aria-checked", on ? "true" : "false");
  // The NAME carries the state too, for the switches whose visible state is a colour (see
  // switchWord). This flips in place without re-rendering the row, so without the line below the
  // name kept the value it was born with: measured on the demo, clicking a switched-off exit moved
  // aria-checked false→true while the label still read "Reality Probe disabled". Fixing only the
  // render path left the same contradiction, pointing the other way.
  const label = sw.getAttribute("aria-label");
  if (label) {
    const swapped = label.replace(/\s(enabled|disabled)(?=$|\s*[—–-])/, switchWord(on));
    if (swapped !== label) sw.setAttribute("aria-label", swapped);
  }
}
// The exits list is rendered by the connections chunk, which is only loaded once that page has been
// opened — call into it the way paintConnections is called for the dashboard table: a no-op when the
// chunk is absent or the page is not on screen.
function repaintExits() { if (typeof paintExitsList === "function") paintExitsList(); }

// Every page renders once. What is LIVE on it — a plane's state, a probe's answer, a counter — has to
// be repainted after that, and until now only the dashboard did: the routing page read the kernel
// plane's state at render time and then kept saying "not applied" through the Apply that installed
// it, and a failover card kept the latencies it was born with.
//
// So a page registers what to repaint when it renders, and the health tick calls it. The generation
// stamp is what makes it safe: route() bumps routeGen for every navigation, so a registration from
// the page the operator just left can never paint into a detached DOM.
let pageRepaint = null;
let pageRepaintGen = -1;
function onPageRepaint(fn) {
  pageRepaint = fn;
  pageRepaintGen = routeGen;
}
function repaintPage() {
  if (typeof pageRepaint !== "function" || pageRepaintGen !== routeGen) return;
  // A repaint is best-effort decoration over a page that already rendered: one that throws (a feed
  // that answered 500, a node an edit removed) must not take the health tick down with it.
  try { pageRepaint(); } catch (e) {}
}
// tryDisableWithDependents runs the dialog behind a refused switch-off and, if the operator chooses,
// repeats the write with the choice attached (?replace_with= / ?detach=1 — see handleUpsertEndpoint).
// Returns true when the exit ended up off, false when the operator cancelled or the retry failed, so
// the caller knows whether to put the switch back.
//
// The dialog lives in the connections chunk, which the dashboard has not loaded — fetch it rather
// than degrade to the bare refusal on the one page where a switch is just as reachable.
async function tryDisableWithDependents(e, data) {
  try { await loadChunk("page-connections"); } catch (_) { return false; }
  if (typeof askDisableDependents !== "function") return false;
  const choice = await askDisableDependents(e.name || e.id, data.dependents || [], data.replacements || []);
  if (!choice) return false;
  const q = choice.detach ? "?detach=1" : "?replace_with=" + encodeURIComponent(choice.replace);
  try {
    await api.post("/api/endpoints" + q, { ...e, enabled: false });
  } catch (err) { toast(err.message, "err"); return false; }
  // The server moved or parked OTHER objects in the same revision — lists, rules, resolvers, group
  // membership — so the profile in hand is stale and the list must be rebuilt, in place where the
  // connections page is what's on screen and via route() from anywhere else.
  await loadProfile();
  if (!await refreshConnectionsInPlace()) route();
  toast(t("{0} switched off", e.name || e.id), "ok");
  return true;
}

async function toggleEndpoint(e, sw) {
  if (applyInFlight) { toast(t("Apply in progress — finish it first"), "err"); return; } // don't mutate staged config mid-Apply (checked before flipSwitch, so no visual desync)
  if (sw && sw._busy) return; // ignore rapid re-clicks while a write is in flight — no racing double-write
  if (sw) sw._busy = true;
  const want = !e.enabled;
  flipSwitch(sw, want);
  e.enabled = want; // live ref inside state.profile; the change is STAGED until Apply
  updateDirty();    // light the Apply/Save buttons (the removed loadProfile() used to do this)
  refreshEnabledTile(); // keep the dashboard "N enabled" tile in sync (no full re-render)
  try {
    await api.post("/api/endpoints", { ...e, enabled: want });
    repaintExits(); // the switch and the row it belongs to are two nodes; without this the row keeps saying "off"
  } catch (err) {
    // Switching an exit off while a list, rule, resolver or group still points at it is refused —
    // and the refusal used to end there, in ids the operator never typed. It is the same question a
    // delete asks, so it now gets the same dialog: move those dependents to another exit, or switch
    // it off anyway and leave them parked. Only then is the switch put back.
    const data = (err && err.data) || {};
    if (!want && data.code === "ENDPOINT_IN_USE" && await tryDisableWithDependents(e, data)) return;
    flipSwitch(sw, !want);
    e.enabled = !want;
    updateDirty();
    refreshEnabledTile();
    repaintExits();
    toast(err.message, "err");
  } finally { if (sw) sw._busy = false; }
}

// firstRunConnections is the empty-state / first-run experience for the Connections
// page. Instead of a bare "nothing here" line, it names the primary action and gives
// a 3-step orientation (add → route → apply) so a first-time, non-technical user knows
// exactly what to do next. All copy is localized via t().
function firstRunConnections() {
  const step = (n, title, detail) =>
    el("li", { class: "fr-step" },
      el("span", { class: "fr-num", "aria-hidden": "true" }, String(n)),
      el("div", { class: "fr-step-body" },
        el("div", { class: "fr-step-t" }, title),
        el("div", { class: "fr-step-d" }, detail)));
  return el("div", { class: "firstrun" },
    el("div", { class: "fr-ico", "aria-hidden": "true" }, "⇄"),
    el("div", { class: "fr-title" }, t("Add your first connection")),
    el("div", { class: "fr-hint" }, t("A connection is a VPN or proxy tunnel your router sends traffic through. Add one to get started.")),
    el("button", { class: "btn btn-primary fr-cta", onclick: openAddConnection }, "+ " + t("Add your first connection")),
    el("ol", { class: "fr-steps" },
      step(1, t("Paste a link or import a config"), t("Works with vless://, vmess://, trojan://, hysteria2://, tuic:// links and WireGuard / AmneziaWG configs.")),
      step(2, t("Choose what routes through it"), t("Send specific sites or devices through the tunnel — or route everything.")),
      step(3, t("Apply to activate"), t("Changes go live on the router only when you press Apply."))));
}

// ── Exit inspector ────────────────────────────────────────────────────────────────────────────
// The page used to be two stacked lists — configured connections, then native OS tunnels — with
// four buttons on every row. With seven exits that is twenty-eight buttons competing for the eye,
// none of which is the question the page is actually asked: which exit is in trouble, and what
// breaks if I switch it off. So: one list of every exit ordered by how much attention it needs,
// and one panel that answers those two questions for whichever exit is selected.
//
// Nothing was dropped in the move. Check config, Test, Edit, Delete and the enable toggle all live
// in the panel; Add as exit still adopts a native tunnel; adoption state, the OS-tunnel badge, the
// failure cause and the stats line all still render. What is new is "Depended on by", which the old
// layout had no room for even though it is what makes disabling an exit safe or dangerous.

// Which exit the panel is showing. Survives the health repaints and the route rebuilds so the panel
// does not jump back to the first row every five seconds.
let selectedExitId = null;


// 19 function(s) for the connections page now live in web/dist/page-connections.js,
// loaded on demand by loadChunk(). See PAGES.connections.chunk.


// dependentsOf answers "what stops working if this exit does". A group counts twice over: the group
// itself, and everything pointing at that group, because a routing list aimed at a failover group
// is aimed at this exit too whenever the group elects it.
function dependentsOf(id) {
  const out = [];
  const groups = (state.profile.groups || []).filter(g => (g.members || []).includes(id));
  const groupIds = groups.map(g => g.id);
  const viaIds = [id, ...groupIds];
  groups.forEach(g => out.push({
    icon: "⇄", label: g.name || g.id,
    note: t("failover group") + " · " + tn("{0} member|{0} members", (g.members || []).length),
    weak: (g.members || []).length > 1,
  }));
  (state.profile.routing_lists || []).forEach(rl => {
    if (viaIds.includes(rl.outbound)) {
      out.push({
        icon: "≡", label: rl.name || rl.id,
        note: t("routing list") + (rl.enabled ? "" : " · " + t("disabled")) +
          (rl.outbound === id ? "" : " · " + t("via {0}", nameOf(rl.outbound) || rl.outbound)),
        weak: rl.outbound !== id,
      });
    }
    // A list is also FETCHED through an exit. Missing this meant a list that downloads over a
    // tunnel — the whole point of RuleSetDetour on a censored network — counted as no dependency
    // at all, and the panel would have said switching that exit off changes nothing.
    if (rl.download_via && viaIds.includes(rl.download_via)) {
      out.push({
        icon: "↓", label: rl.name || rl.id,
        note: t("downloads its list through this") + (rl.enabled ? "" : " · " + t("disabled")),
        weak: rl.download_via !== id,
      });
    }
  });
  // DNS resolvers route through exits too, and a resolver is the least visible dependency of all:
  // nothing on the Connections page hints at it, so "nothing routes through this exit" was a
  // confident verdict built from a search that never looked at the DNS plane.
  const dns = state.profile.dns || {};
  (dns.servers || []).forEach(sv => {
    if (!sv.detour || !viaIds.includes(sv.detour)) return;
    const isFinal = (dns.final || ((dns.servers || [])[0] || {}).tag) === sv.tag;
    out.push({
      icon: "◎", label: sv.tag,
      note: t("DNS resolver") + (isFinal ? " · " + t("the default one") : "")
        + (sv.enabled === false ? " · " + t("disabled") : ""),
      weak: sv.detour !== id,
    });
  });
  (state.profile.rules || []).forEach(r => {
    if (!viaIds.includes(r.outbound)) return;
    out.push({
      icon: r.default ? "★" : "→",
      label: r.default ? t("Default route") : ruleSummary(r),
      note: r.default ? t("everything not matched by a list") : t("rule"),
      weak: r.outbound !== id,
    });
  });
  return out;
}







// refreshConnectionsInPlace rebuilds only the body of the connections page — the exits list and the
// detail panel — and swaps it for the one on screen.
//
// The alternative is route(), and route() is a navigation: it empties #view, paints the skeleton and
// re-fetches through the chunk loader, so adopting a tunnel or switching an exit off looked like the
// page reloading under the operator's hands. Here the old subtree stays up until the new one is
// built, so the only thing that changes is what actually changed. Returns false when the page is not
// on screen, which is the caller's cue that a plain route() is the honest refresh.
async function refreshConnectionsInPlace() {
  const cur = document.querySelector("#view .conn-body");
  if (!cur) return false;
  const next = await connectionsBody();
  cur.replaceWith(next);
  pillGen++;            // the panel's [data-*] nodes were just replaced — drop refreshPills' cache
  associateLabels(next);
  i18nApply(next);      // route() localizes what IT renders; a later swap must localize its own
  return true;
}

async function renderConnections(view) {
  const head = el("div", { class: "block-head" },
    el("div", {},
      el("div", { class: "desc" }, "VPN and proxy tunnels. Paste a vless:// / hysteria2:// link or import a WireGuard config to add one.")),
    el("div", { class: "side" },
      el("button", { class: "btn btn-primary", title: "Add one connection — paste a vless://, hysteria2://… link, fill a form, or import a config", onclick: openAddConnection }, "+ Add connection")));
  view.appendChild(head);
  view.appendChild(await connectionsBody());
}

// connectionsBody is everything under that head: the first-run card, or the exits list beside the
// detail panel. It reads the profile and the native tunnels itself and returns a detached node, so
// the same builder serves the first render and every in-place refresh.
async function connectionsBody() {
  const view = el("div", { class: "conn-body" });
  await loadProfile();

  // Native tunnels are fetched before anything renders so both kinds can share one ordering.
  // Best-effort: absent CLI tools or an unreachable endpoint simply means there are none.
  let tunnels = [];
  try {
    const dv = await api.get("/api/vpn/discover");
    tunnels = (dv && dv.vpns) || [];
  } catch (_) { /* CLI tools absent or endpoint unreachable */ }

  if (!state.profile.endpoints.length && !tunnels.length) {
    const card = el("div", { class: "card" });
    card.appendChild(firstRunConnections());
    view.appendChild(card);
    return view;
  }

  const adoptedIfaces = new Set(state.profile.endpoints
    .filter(e => e.engine === "external" && e.params && e.params.interface)
    .map(e => e.params.interface));
  const items = [
    ...state.profile.endpoints.map(e => ({ kind: "exit", id: e.id, ep: e, label: e.name || e.id })),
    ...tunnels.filter(tn => !adoptedIfaces.has(tn.iface))
      .map(tn => ({ kind: "native", id: "native:" + tn.iface, tn: tn, label: tn.name || tn.iface })),
  ];
  const order = new Map(items.map((it, i) => [it.id, i]));
  items.sort((a, b) => {
    const ra = exitRank(a), rb = exitRank(b);
    if (ra !== rb) return ra - rb;
    // Within the working band, slowest first — same reasoning as the bands themselves.
    const la = (healthMap[a.id] || {}).latency_ms || 0;
    const lb = (healthMap[b.id] || {}).latency_ms || 0;
    if (ra === 2 && la !== lb) return lb - la;
    return order.get(a.id) - order.get(b.id);
  });

  if (!items.some(it => it.id === selectedExitId)) selectedExitId = items[0].id;
  const current = items.find(it => it.id === selectedExitId);

  const list = el("div", { class: "insp-list" });
  const rows = new Map();
  let panel = exitPanelFor(current);
  // Selecting an exit is a local inspector action, not a route reload. Rebuilding the whole view
  // here used to re-fetch both the profile and native VPN discovery, flash every row on slower
  // Keenetic hardware, and discard keyboard focus. Keep the list nodes alive and replace only the
  // detail pane whose contents actually changed.
  const selectExit = (item) => {
    if (!item || item.id === selectedExitId) return;
    const nextPanel = exitPanelFor(item);
    selectedExitId = item.id;
    for (const [id, row] of rows) {
      const selected = id === selectedExitId;
      row.classList.toggle("sel", selected);
      if (selected) row.setAttribute("aria-current", "true");
      else row.removeAttribute("aria-current");
    }
    panel.replaceWith(nextPanel);
    panel = nextPanel;
  };
  const needing = items.filter(it => exitRank(it) <= 1).length;
  list.appendChild(el("div", { class: "insp-list-h" },
    el("span", {}, t("{0} exits", items.length)),
    needing
      ? el("span", { class: "insp-list-warn" }, t("{0} needing attention", needing))
      : el("span", { class: "insp-list-ok" }, t("all healthy"))));
  items.forEach(it => {
    const row = exitRow(it, selectExit);
    rows.set(it.id, row);
    list.appendChild(row);
  });

  view.appendChild(el("div", { class: "inspector" }, list, panel));
  return view;
}



// failoverMembers renders a group's members in the order urltest would prefer them:
// alive first (lowest measured latency first), then unknown/not-yet-probed, then down
// last (dimmed). The single member urltest would actually pick — alive + lowest latency —
// gets a "BEST" pill so the user sees which exit currently carries traffic. Read-only:
// it reuses the live per-endpoint healthMap the dashboard already polls (no extra fetch);
// when health is absent it falls back to the configured member order.
// failoverState holds the daemon's REAL failover view, polled from GET /api/failover/state:
// elected[groupID] = the member sing-box is actually routing through right now (Clash `now`),
// and local_fault = every exit is unreachable at once (likely the local uplink). This is the
// authoritative truth the "● LIVE" pill and the local-fault banner render — distinct from the
// client-side lowest-latency "✓ BEST" guess.
// `known` records whether the daemon's failover truth was actually READ. Without it an unreadable
// /api/failover/state was indistinguishable from a group with no healthy member: elected came back
// empty either way, and the card asserted "No live exit — no healthy member". That is a strong,
// wrong claim built from missing data, made precisely when the user is looking because something
// is broken.
let failoverState = { elected: {}, local_fault: false, known: false, self_switching: [], kernel_members: {} };

// loadFailoverState pulls the daemon's real view. Best-effort: on any error it resets to "not known"
// rather than leaving a stale answer, because a stale elected member is worse than none.
//
// It is a function because TWO pages need it. It used to be inline in renderFailover, so the
// Dashboard — whose hero answers "which exit am I on right now?" — ran with the module default and
// named the client-side lowest-latency guess instead. For a `selector` group, which is what the
// generator emits, traffic goes through the SELECTED member, not the fastest one: the guess and the
// truth are different members whenever the selection is not the quickest.
async function loadFailoverState() {
  try {
    const fs = await api.get("/api/failover/state");
    failoverState = { elected: (fs && fs.elected) || {}, local_fault: !!(fs && fs.local_fault), known: true,
      self_switching: (fs && fs.self_switching_groups) || [], kernel_members: (fs && fs.kernel_members) || {} };
  } catch (e) { failoverState = { elected: {}, local_fault: false, known: false, self_switching: [], kernel_members: {} }; }
}

function failoverMemberRank(id) {
  const h = healthMap[id];
  if (h && h.state === "alive") return 0; // live exits sort to the top
  if (h && h.state === "down") return 2;  // dead exits sink to the bottom
  return 1;                               // unknown / not yet probed sits between
}
function failoverMembers(g) {
  const ids = (g.members || []).slice();
  const best = bestAliveMember(ids.map(findEndpoint).filter(Boolean));
  const bestId = best ? best.ep.id : null;
  const electedId = (failoverState.elected || {})[g.id] || null;
  // Stable sort: rank first, then latency (alive members ascending), preserving the
  // configured order for ties (e.g. two unknown members) via the original index.
  const order = new Map(ids.map((id, i) => [id, i]));
  ids.sort((a, b) => {
    const ra = failoverMemberRank(a), rb = failoverMemberRank(b);
    if (ra !== rb) return ra - rb;
    const la = (healthMap[a] || {}).latency_ms || 9999;
    const lb = (healthMap[b] || {}).latency_ms || 9999;
    if (la !== lb) return la - lb;
    return order.get(a) - order.get(b);
  });
  const wrap = el("div", { class: "fo-members", style: "display:flex;flex-wrap:wrap;gap:8px;margin-top:8px" });
  ids.forEach(id => {
    const h = healthMap[id] || {};
    const alive = h.state === "alive", down = h.state === "down";
    const chip = el("div", {
      class: "fo-member",
      style: "display:inline-flex;align-items:center;gap:8px;min-width:0;word-break:break-word"
        + (down ? ";opacity:.5" : "")
    });
    const dotCls = alive ? "ok" : down ? "err" : "muted";
    chip.appendChild(el("span", { class: "pill " + dotCls, role: "img", "aria-label": alive ? t("alive") : down ? t("down") : t("not yet checked"), title: alive ? "alive" : down ? "down" : "not yet checked" },
      el("span", { class: "dot" }),
      nameOf(id),
      alive && h.latency_ms ? el("small", { style: "margin-left:6px;color:inherit;opacity:.75" }, h.latency_ms + " ms") : null));
    // "● LIVE" = the member sing-box is ACTUALLY routing through now (authoritative, from the
    // daemon). "✓ BEST" = the client-side lowest-latency guess — shown only when there is no live
    // truth, or when it DIFFERS from LIVE (so the user sees "you'd expect X by latency, but sing-box
    // is on Y" instead of a misleading single guess).
    if (electedId && id === electedId) {
      chip.appendChild(el("span", { class: "pill ok", title: t("sing-box is routing through this member right now"), style: "font-weight:600" }, "● LIVE"));
    } else if (id === bestId && (!electedId || bestId !== electedId)) {
      chip.appendChild(el("span", { class: "pill", title: electedId ? t("Lowest latency — but not the member currently routed") : t("urltest would route through this member (alive, lowest latency)"), style: "font-weight:600" }, "✓ BEST"));
    }
    wrap.appendChild(chip);
  });
  return wrap;
}

async function renderFailover(view) {
  await loadProfile();
  // Pull the daemon's REAL failover truth (elected member per group + local-fault flag). Best-effort:
  // on any error fall back to an empty state so the page still renders with the latency guess.
  await loadFailoverState();

  const head = el("div", { class: "block-head" },
    el("div", {},
      el("div", { class: "desc" }, "Group your connections so traffic automatically switches to a healthy one when the active tunnel goes down.")),
    el("div", { class: "side" },
      el("button", { class: "btn btn-primary", title: "Create a failover group — pick members and traffic auto-switches to a healthy one", onclick: openNewGroup }, "+ New group")));
  view.appendChild(head);

  if (failoverState.local_fault) {
    view.appendChild(el("div", { class: "card", style: "border:1px solid var(--err,#d9534f)" },
      el("div", { style: "display:flex;gap:10px;align-items:center;flex-wrap:wrap" },
        el("span", { class: "pill err" }, el("span", { class: "dot" }), t("Local network problem")),
        el("div", { class: "desc", style: "min-width:0" }, t("Every exit is unreachable at once — this looks like your internet/uplink, not the VPNs. Failover is paused until connectivity returns.")))));
  }

  if (!state.profile.groups.length) {
    view.appendChild(el("div", { class: "card" }, emptyState("No failover groups",
      "Create one to auto-select the fastest working connection (urltest), like a router's backup-WAN stack.")));
    return;
  }
  const defRule = state.profile.rules.find(r => r.default);
  // Each group reads as its failure chain — what carries traffic now, where it falls next, and what
  // is left after that — because that sequence is the only thing a failover group is for. The old
  // card answered "which exit is live" and left the rest of the order to a numbered roster below it.
  const strip = el("div", { class: "fo-strip" });
  // The dominant term on this page is the NUMBER OF GROUPS, not the hops inside them: nine groups
  // put the strip at 1700px of a 2925px page while each chain was a perfectly ordinary four hops.
  // Real profiles have two or three groups and nothing folds; a profile large enough to run the page
  // to three and a half screens shows the first few and says how many more there are.
  // 3, so the strip is at most ONE row of cards at the 3-column desktop width. Four allowed a second
  // row, which is ~450px of swing on a page that also swings with health state.
  const GROUPS_VISIBLE = 3;
  const groups = state.profile.groups || [];
  const groupMore = groups.length > GROUPS_VISIBLE
    ? el("details", { class: "fo-g-more" },
        el("summary", { class: "hint" }, t("Show all {0} groups", groups.length)))
    : null;
  const cards = [];
  groups.forEach((g, gi) => {
    const card = foChainCard(g, defRule);
    cards.push({ g, card });
    if (groupMore && gi >= GROUPS_VISIBLE) groupMore.appendChild(card); else strip.appendChild(card);
  });
  // A chain is drawn from the health snapshot it was built with, so without this the page froze at the
  // latencies it opened on and a member that died stayed green until the operator navigated away.
  // Each card is rebuilt in place — cheap (a handful of rows) and it keeps the strip's own layout.
  onPageRepaint(async () => {
    await loadFailoverState(); // the daemon's own election, not this page's guess
    cards.forEach(entry => {
      const fresh = foChainCard(entry.g, defRule);
      entry.card.replaceWith(fresh);
      entry.card = fresh;
    });
  });

  // A filter, once there are enough groups that the fold above stops being the answer.
  //
  // The fold shows three and hides the rest, which keeps the page short for someone SCROLLING. It does
  // nothing for someone LOOKING for one group among ten: they open "Show all", and the page is then
  // 2.1 screens of chains with no way to narrow it — measured on a live router, and the
  // density gate reads it exactly that way, with the fold open, because that is the state a person
  // puts the page in. Routing and Settings already answer this; Failover did not.
  //
  // Filtering opens the fold. A match the user cannot see because it is inside a collapsed section is
  // not a match, and a count that includes it is a claim about something off screen.
  // The same threshold the FOLD uses, not a second number beside it. They disagreed by one, and the
  // page that fell in the gap is the ordinary one: at exactly four groups the fold appears ("Show all
  // 4 groups") with nothing to narrow it, and opening it puts the page at 2.24 screens. Measured on
  // the seeded demo, 1616px against a 720px viewport, and the density gate reported it as a route
  // "taller than 2 screens with no in-page filter" — intermittently, because the page also swings
  // with health text, so the same tree passed and failed on consecutive runs.
  if (groups.length > GROUPS_VISIBLE) {
    const find = el("input", { type: "text", class: "fo-find",
      placeholder: t("Filter {0} groups — name or member", groups.length) });
    find.setAttribute("aria-label", t("Filter failover groups"));
    const count = el("div", { class: "hint fo-find-n" });
    const apply = () => {
      const q = find.value.trim().toLowerCase();
      let shown = 0;
      for (const { g, card } of cards) {
        const hay = ((g.name || "") + " " + (g.id || "") + " "
          + (g.members || []).map(m => nameOf(m) || m).join(" ")).toLowerCase();
        const on = !q || hay.includes(q);
        card.style.display = on ? "" : "none";
        if (on) shown++;
      }
      if (groupMore) groupMore.open = !!q;
      count.textContent = q ? t("{0} of {1} groups", shown, groups.length) : t("{0} groups", groups.length);
    };
    find.addEventListener("input", apply);
    view.appendChild(el("div", { class: "fo-findbar" }, find, count));
    apply();
  }

  view.appendChild(strip);
  if (groupMore) view.appendChild(groupMore);

  const warn = foIdenticalNote(state.profile.groups);
  if (warn) view.appendChild(warn);

  view.appendChild(el("div", { class: "block-head fo-pool-head" },
    el("div", {},
      el("div", { class: "ttl" }, t("Exit capacity")),
      el("div", { class: "desc" }, t("Every exit once, in readiness bands. Chips show which groups can fall back to it.")))));
  view.appendChild(foBands(state.profile.groups));

  // The log is appended asynchronously so a slow or missing endpoint cannot delay the page.
  const logBox = el("div", { class: "card fo-log-box" },
    el("div", { class: "fo-log-t" }, t("Switch log")),
    el("div", { class: "hint" }, t("Reading…")));
  view.appendChild(logBox);
  foRenderLog(logBox);
}

// foRenderLog fills the switch log in place. An unreadable endpoint and an empty log are different
// answers and are shown differently: the log lives in RAM, so "nothing since the daemon started" is
// the strongest claim an empty list supports, and the panel says so rather than implying that
// nothing has ever gone wrong.
async function foRenderLog(box) {
  let data = null;
  try { data = await api.get("/api/failover/events?limit=40"); } catch (_) { data = null; }
  box.innerHTML = "";
  box.appendChild(el("div", { class: "fo-log-t" }, t("Switch log")));
  if (!data || !data.known) {
    box.appendChild(el("div", { class: "hint" },
      t("WayHop could not read the failover log, so nothing here is claimed either way.")));
    return;
  }
  const events = data.events || [];
  if (!events.length) {
    box.appendChild(el("div", { class: "hint" }, data.since_ms
      ? t("No outage or switch since the daemon started ({0}).", fmtWhen(data.since_ms))
      : t("No outage or switch recorded yet.")));
    return;
  }
  const list = el("div", { class: "fo-log" });
  // The log is fetched with ?limit=40 and used to render all forty. On a daemon that has been
  // running a while that alone pushes this route past the two-screen budget — the density gate
  // caught it only after the demo had accumulated enough events, which is why it looked like a
  // flake: the subject grows with uptime, so a short run and a long run measure different pages.
  // Same treatment as the diagnostics feed and the group strip: show the recent ones, fold the rest.
  const LOG_VISIBLE = 6;
  const logMore = events.length > LOG_VISIBLE
    ? el("details", { class: "fo-log-more" },
        el("summary", { class: "hint" },
          t("Show {0} older entries", events.length - LOG_VISIBLE)))
    : null;
  events.forEach((ev, li) => {
    const ico = ev.kind === "down" ? "▼" : ev.kind === "up" ? "▲" : "⇄";
    const cls = ev.kind === "down" ? "down" : ev.kind === "up" ? "up" : "switch";
    let text;
    if (ev.kind === "switch") text = t("{0} switched to {1}", ev.name || ev.id, ev.to || "?");
    else if (ev.kind === "up") text = t("{0} came back", ev.name || ev.id);
    else text = t("{0} went down", ev.name || ev.id);
    (logMore && li >= LOG_VISIBLE ? logMore : list).appendChild(el("div", { class: "fo-log-row " + cls },
      el("span", { class: "fo-log-i", "aria-hidden": "true" }, ico),
      el("span", { class: "fo-log-x" }, text),
      ev.latency_ms ? el("span", { class: "fo-log-l" }, ev.latency_ms + " ms") : null,
      el("span", { class: "fo-log-w" }, fmtWhen(ev.at))));
  });
  box.appendChild(list);
  if (logMore) box.appendChild(logMore);
  if (data.since_ms) {
    box.appendChild(el("div", { class: "hint fo-log-since" },
      t("Covers everything since the daemon started ({0}). The log is not kept across restarts.",
        fmtWhen(data.since_ms))));
  }
}

// fmtWhen renders an absolute unix-ms timestamp as an age, which is what a log of recent events is
// read for. Beyond a day it falls back to a date, because "37h ago" stops being meaningful.
function fmtWhen(ms) {
  if (!ms) return "";
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (s < 60) return t("{0}s ago", s);
  if (s < 3600) return t("{0}m ago", Math.floor(s / 60));
  if (s < 86400) return t("{0}h ago", Math.floor(s / 3600));
  return new Date(ms).toLocaleString();
}

async function setDefault(g) {
  // Pointing EVERYTHING at a group whose members are all down is worth one question.
  //
  // The control took effect silently, and the card afterwards said only the general rule ("if it
  // fails, traffic through this group stops") — never that the thing just chosen is dead right now.
  // Measured while testing: a group with both members reading "unusable / down" became the default
  // route with no warning at any point. This asks only when the answer is known and bad: a member
  // whose health has not been measured yet is not evidence of anything, so it does not trigger it.
  const members = (g.members || []).map(id => healthMap[id]).filter(Boolean);
  const measured = members.length > 0;
  const anyAlive = members.some(h => h.state === "alive");
  if (measured && !anyAlive) {
    const ok = await modalConfirm(t(
      "Every member of {0} is down right now. Making it the default route sends ALL unmatched traffic through it, so that traffic stops until a member recovers. Continue?", g.name));
    if (!ok) return;
  }
  try { await api.post("/api/rules", { id: "default", default: true, outbound: g.id }); await loadProfile(); route(); toast(t("Default route → {0}", g.name), "ok"); }
  catch (err) { toast(err.message, "err"); }
}
// blockingGroupRefs answers, from the profile already in the browser, whether the store will refuse
// to delete this group — and names what has to move first.
//
// Store.DeleteGroup refuses on exactly two conditions: a rule whose outbound IS this group, and
// another group for which this one is the only member. Both are in state.profile, so the panel can
// say so before the destructive click instead of after it. Measured on the demo: pointing the
// default route at a group and pressing Delete gave "Delete group Order probe?" — no mention of the
// route — and the refusal arrived only once OK had been pressed, as an error toast.
//
// The conditions mirror the store's two checks deliberately, and the wording names the object to
// repoint rather than restating the rule, because "repoint it first" is only actionable if the
// operator is told what "it" is.
function blockingGroupRefs(g) {
  const p = state.profile || {};
  // All FOUR conditions Store.DeleteGroup refuses on. The first cut knew two — a rule and a
  // sole-member parent — so deleting a group a routing list or a DNS server pointed at still asked
  // first and refused afterwards. Measured on the demo: DELETE /api/groups/auto answered `group
  // "auto" is used by DNS server "dns_secure_bk" (detour)` after the confirm had already been taken.
  //
  // Returned as one flat list of {kind, name}: the dialog reads them all the same way, and a shape
  // per condition was three shapes for one sentence.
  const out = [];
  for (const r of (p.rules || [])) {
    if (r.outbound === g.id) out.push({ kind: "rule", name: r.default ? t("the default route") : (r.id || "") });
  }
  for (const other of (p.groups || [])) {
    if (other.id !== g.id && (other.members || []).length === 1 && (other.members || [])[0] === g.id) {
      out.push({ kind: "sole_member_of", name: other.name || other.id });
    }
  }
  for (const rl of (p.routing_lists || [])) {
    if (rl.outbound === g.id || rl.download_via === g.id) out.push({ kind: "routing_list", name: rl.name || rl.id });
  }
  for (const ds of ((p.dns && p.dns.servers) || [])) {
    if (ds.detour === g.id) out.push({ kind: "dns_detour", name: ds.tag || "" });
  }
  return out;
}

async function delGroup(g) {
  // Ask BEFORE offering the destructive confirm: a dialog that takes OK and then refuses has spent
  // the operator's decision on nothing.
  const blocked = blockingGroupRefs(g);
  if (blocked.length) {
    // The same sentence the refusal path uses, so a blocker the pre-check knows and one it does not
    // read identically to the operator.
    await modalConfirm(t("{0} cannot be deleted yet. {1} Point it somewhere else first, then delete this group.",
      g.name || g.id,
      tn("{0} object still points at it: {1}.|{0} objects still point at it: {1}.",
        blocked.length, blocked.map(b => b.name).filter(Boolean).join(", "))),
      { acknowledgeOnly: true, okLabel: t("Close") });
    return;
  }
  if (!await modalConfirm(t("Delete group {0}?", g.name))) return;
  try { await api.del("/api/groups/" + encodeURIComponent(g.id)); await loadProfile(); route(); toast("Deleted", "ok"); }
  catch (err) {
    // The check above asks before offering, so reaching here means it did not know about a condition
    // the store does. The daemon now answers structurally (GROUP_IN_USE + dependents) for exactly
    // that case, so the fallback names what blocks instead of printing a sentence the operator
    // cannot act on — which is what this path used to do.
    const data = err && err.data;
    const deps = (data && data.code === "GROUP_IN_USE" && Array.isArray(data.dependents)) ? data.dependents : null;
    if (!deps || !deps.length) { toast(err.message, "err"); return; }
    const named = deps.map(d => d.name || d.id).join(", ");
    await modalConfirm(t("{0} cannot be deleted yet. {1} Point it somewhere else first, then delete this group.",
      g.name || g.id, tn("{0} object still points at it: {1}.|{0} objects still point at it: {1}.", deps.length, named)),
      { acknowledgeOnly: true, okLabel: t("Close") });
  }
}

// testFailoverGroup actively re-measures every member's latency on demand (reusing the
// same per-endpoint Clash-delay probe testEndpoint() uses — /api/health/test/{id}),
// folds the fresh results into the shared healthMap, then re-renders the Failover page
// so failoverMembers() re-sorts members best-first (alive + lowest latency → ✓ BEST).
// Falls back to /api/health/endpoints if a per-endpoint test fails for a member, so the
// sort still reflects the latest known health rather than aborting outright.
async function testFailoverGroup(g, btn) {
  const ids = (g.members || []).slice();
  if (!ids.length) { toast(t("This group has no members to test"), "info"); return; }
  const label = btn ? btn.textContent : "";
  if (btn) { btn.setAttribute("disabled", "true"); btn.textContent = t("Testing…"); }
  let failed = 0;
  // Which members actually returned a fresh probe this run. Counting "alive" across ALL members
  // instead folded each unprobed member's PREVIOUS state into a number presented as the result of
  // this test — a member that answered an hour ago and whose probe just failed counted as alive.
  const probed = new Set();
  let usedFallback = false;
  try {
    // Probe members concurrently — each reuses the existing per-endpoint delay test.
    await Promise.all(ids.map(async id => {
      try {
        const h = await api.post("/api/health/test/" + encodeURIComponent(id), {});
        if (h && h.id) { healthMap[h.id] = h; probed.add(id); }
        else failed++;
      } catch (_) { failed++; }
    }));
    if (failed === ids.length) {
      // Every per-endpoint probe failed (old daemon / endpoint gone) — fall back to a
      // single bulk health read so the re-sort still uses the freshest available data.
      try {
        const r = await api.get("/api/health/endpoints");
        (r || []).forEach(h => { healthMap[h.id] = h; });
        usedFallback = true;
      } catch (_) {}
    }
    refreshPills();
    route(); // re-render Failover → failoverMembers() re-sorts by the fresh latency
    // Alive is counted ONLY over members this run actually reached.
    const alive = [...probed].filter(id => (healthMap[id] || {}).state === "alive").length;
    if (probed.size === ids.length) {
      toast(t("Tested {0} members — {1} alive", ids.length, alive), alive ? "ok" : "info");
    } else if (probed.size > 0) {
      // A partial run must not read as a completed one; same rule as a partly-failed provisioning.
      // Three counts in one sentence, so no single form serves it: written count-last, which needs
      // no agreement in any language this panel ships. It was also not translated at all — built by
      // concatenation, it went out in English in nine languages while the COMPLETE-run toast beside
      // it was translated, so a partial run silently changed language.
      toast(t("Tested {0} of {1} members · alive: {2} · did not answer: {3} (these still show their previous state)",
        probed.size, ids.length, alive, failed), "err");
    } else if (usedFallback) {
      toast("Could not probe any member. Showing the router's last health report instead of fresh results.", "err");
    } else {
      toast("Could not probe any member, and the router's health report is unavailable too.", "err");
    }
  } catch (err) {
    toast(err.message, "err");
    if (btn) { btn.removeAttribute("disabled"); btn.textContent = label; }
  }
}

/* ---------- routing (list-based selective routing) ---------- */
function routingOutboundSelect(selected, includeBlock) {
  const sel = el("select", { class: "rl-sel" });
  const add = (v, t) => sel.appendChild(el("option", { value: v }, t));
  state.profile.endpoints.filter(e => e.enabled).forEach(e => add(e.id, e.name || e.id));
  state.profile.groups.forEach(g => add(g.id, "▣ " + g.name));
  add("direct", "Direct (no tunnel)");
  if (includeBlock) add("block", "Block (reject)");
  // If the saved target is no longer a selectable option (a disabled or deleted
  // endpoint/group), surface it instead of silently snapping to option 0 — which
  // would misrepresent where the list routes. Keep the real value visible + selected.
  if (selected && ![...sel.options].some(o => o.value === selected)) add(selected, "⚠ " + (nameOf(selected) || selected) + " (unavailable)");
  if (selected) sel.value = selected;
  // The column is now wide enough for every exit name the demo can produce, but a name is user data
  // and there is no width that fits all of them. A <select> ellipsises silently and offers no way to
  // read what it hid, so the full text goes on the element itself. Not a new UI string — it is the
  // option's own label — and it has to be re-set on change or it would describe the previous choice.
  const syncTitle = () => {
    const o = sel.options[sel.selectedIndex];
    sel.title = o ? o.textContent : "";
  };
  syncTitle();
  sel.addEventListener("change", syncTitle);
  return sel;
}

// 12 function(s) for the routing page now live in web/dist/page-routing.js,
// loaded on demand by loadChunk(). See PAGES.routing.chunk.


function rlShortURL(u) { return u.replace(/^https?:\/\//, "").replace(/\/releases\/latest\/download\//, "/…/").slice(0, 50); }

// rlUniqueId suffixes base (-2, -3, …) until it is unique across the whole profile,
// so a new list never overwrites an existing endpoint/group/rule/list by id collision.
//
// device_groups belong in that set and were missing from it, while the device-group dialog mints its
// id with this very function. Measured on the demo: creating a second device group named "Kids
// devices" produced ONE group at rl-kids-devices holding only the second device — the first group's
// member was gone, with no warning. A routing list scoped to that group then applies to a different
// set of devices than the operator configured, which is the quiet kind of wrong.
function rlUniqueId(base) {
  const p = state.profile || {};
  const have = new Set([].concat(
    (p.endpoints || []).map(e => e.id),
    (p.groups || []).map(g => g.id),
    (p.rules || []).map(r => r.id),
    (p.routing_lists || []).map(rl => rl.id),
    (p.device_groups || []).map(d => d.id)
  ));
  if (!have.has(base)) return base;
  for (let i = 2; ; i++) {
    const cand = base + "-" + i;
    if (!have.has(cand)) return cand;
  }
}

async function renderRouting(view) {
  await loadProfile();
  view.appendChild(el("div", { class: "block-head" },
    el("div", {},
      el("div", { class: "desc" }, "Route domain/IP lists through any tunnel. Add a ready-made preset or your own list; choose which connection each list uses — and which connection downloads it.")),
    el("div", { class: "side" },
      el("button", { class: "btn", title: "Re-fetch CIDRs for any list with an auto-refresh source, then Apply to activate", onclick: (e) => refreshCidrSources(e.currentTarget) }, "↻ Refresh sources"),
      el("button", { class: "btn", title: "Add a ready-made routing list from the catalog", onclick: openRoutingCatalog }, "Preset lists"),
      el("button", { class: "btn", title: t("Manage device groups, then scope a list to certain devices"), onclick: openDeviceGroups }, t("Device groups")),
      el("button", { class: "btn btn-primary", title: "Create your own routing list (domains/IPs or a feed)", onclick: () => openRoutingList(null) }, "+ Custom list"))));

  // Routing status is backend truth: nft on OpenWrt, native NDM on Keenetic. It is also the fact this
  // page was most wrong about: read once at render, it kept reporting the state from before the Apply
  // that changed it. The pill is rebuilt from the same reading by repaintRoutingStatus below.
  try {
    const pbrSt = await api.get("/api/pbr/status");
    if (pbrSt && (pbrSt.mode === "hybrid" || pbrSt.mode === "fast")) {
      const active = pbrSt.installed && !pbrSt.stale;
      const pbrPill = pbrStatusPill(pbrSt);
      const row = el("div", { class: "hint row-between", "data-pbr-row": "1", style: "margin-top:var(--sp-2);align-items:center" },
        el("span", {}, t("Routing") + ": ", pbrPill));
      if (!active) {
        const applyBtn = el("button", { class: "btn", style: "font-size:var(--fs-small)" }, t("Review changes"));
        // Kernel repair is an Apply, not a side door: the review shows what will change and any
        // finding about this router before any router mutation.
        applyBtn.onclick = () => openReviewChanges();
        row.appendChild(applyBtn);
      }
      view.appendChild(row);
    }
  } catch (_) {}

  if (!state.profile.endpoints.filter(e => e.enabled).length) {
    view.appendChild(el("div", { class: "card" }, el("div", { class: "hint" },
      "Add an enabled connection first (Connections) — routing lists send matching traffic through your tunnels.")));
  }
  const disabledExternal = (state.profile.endpoints || []).filter(e => e.engine === "external" && !e.enabled);
  if (disabledExternal.length) {
    view.appendChild(el("div", { class: "card" }, el("div", { class: "hint" },
      t("Adopted native tunnels are disabled by default. Enable them in Connections before adding routing rules."))));
  }
  const lists = state.profile.routing_lists || [];
  const card = el("div", { class: "card" });
  if (!lists.length) {
    card.appendChild(emptyState("No routing lists yet", "Add a ready-made preset (or your own list) and point it at a tunnel — matching sites then go through the VPN, everything else stays direct."));
  } else {
    // Fixed-column grid so the per-row "Route via" / "Download via" dropdowns line up
    // in their own columns instead of flowing inline after variable-width source text
    // (which made them drift left/right by ~200px between rows).
    const table = el("div", { class: "rltable" });
    table.appendChild(el("div", { class: "rlhead framed" },
      el("span", { title: t("Match order — the first list that matches decides where the traffic goes") }, "#"),
      el("span", {}, ""),
      el("span", {}, t("List")),
      el("span", {}, t("Route via")),
      el("span", {}, t("Download via")),
      el("span", { title: t("Connections and bytes the proxy core attributed to this list") }, t("Matched")),
      el("span", {}, "")));
    lists.forEach((rl, i) => table.appendChild(routingRow(rl, i, lists.length)));
    card.appendChild(table);
    // At real scale the ordered ruleset outgrows the screen: 29 lists on the Keenetic is 2425px,
    // three screens, where the demo's four fit easily. Order is the semantics here, so tabs or
    // grouping are out — the list keeps its sequence and gains a filter above it plus its own
    // scroll region, exactly as the Settings index did.
    //
    // Filtering an ORDERED list would be dangerous if a move could then act on the visible subset,
    // which is why moveRoutingList already refuses when the rendered order is shorter than the
    // stored one. That guard was written before this filter existed; this is the case it was for.
    // Measured, not guessed: the demo's ordinary six-list profile renders #view at 1948px in a
    // 1280x900 window, against a two-screen budget of 1640px, with no way to narrow it. The old
    // threshold was eight, chosen when "the demo's four fit easily" — but the page carries a second
    // card and a header above the list, so the list is over budget well before it is long. Five is
    // where a router stops being scannable at a glance, and the cost of being wrong is one input.
    if (lists.length > 4) {
      const find = el("input", { type: "text", class: "rl-find",
        placeholder: t("Filter {0} lists — name, source or exit", lists.length) });
      find.setAttribute("aria-label", t("Filter routing lists"));
      const count = el("div", { class: "hint rl-find-n" });
      const apply = () => {
        const q = find.value.trim().toLowerCase();
        let shown = 0;
        [...table.querySelectorAll(".rlrow")].forEach((row, i) => {
          const rl = lists[i];
          const hay = ((rl.name || "") + " " + (rl.id || "") + " " + (rl.source || "") + " "
            + (nameOf(rl.outbound) || rl.outbound || "")).toLowerCase();
          const on = !q || hay.includes(q);
          row.style.display = on ? "" : "none";
          if (on) shown++;
        });
        count.textContent = q
          ? t("{0} of {1} lists — reordering is disabled while filtered", shown, lists.length)
          : t("{0} lists, evaluated in this order", lists.length);
      };
      find.addEventListener("input", apply);
      card.insertBefore(el("div", { class: "rl-findbar" }, find, count), table);
      table.classList.add("rl-scroll");
      apply();
    }
    // The order is the rule, so say what the order means once rather than making every reader
    // work it out from the arrows.
    card.appendChild(el("div", { class: "hint rl-order-note" },
      t("Evaluated top to bottom: the first list that matches wins, and a disabled list is skipped entirely.")));
    // …on the plane that reads a rule list. The KERNEL plane does neither: pbr.go sorts zones (blocks
    // last, then by zone name) and emits one non-terminating mark per zone, so an address in two
    // zones takes the LAST one emitted — "for OVERLAPPING destination CIDRs the LAST-emitted zone
    // wins", in the compiler's own words. Verified on a live Keenetic: the panel lists
    // Telegram, Antifilter, Meta, Twitter, Re:filter, TeamViewer, GitHub in that order while
    // iptables -t mangle -S WR_PREROUTING emits antifilter, meta, refilter, telegram, twitter,
    // github, teamviewer — alphabetical. It changes nothing there because all seven carry the same
    // mark, and that is exactly why it would go unnoticed until two overlapping lists take
    // different exits.
    card.appendChild(el("div", { class: "hint rl-order-note" },
      t("Where the kernel carries a list this order does not decide an overlap: a block always wins, and between two ordinary lists the later zone name does. It only matters if overlapping lists take different exits.")));
  }
  view.appendChild(card);
  // What these lists cost the router, in kernel memory, per list. A routing list is not free: each one
  // is an ipset the kernel holds resident, and on a 256 MB router that is a budget being spent without
  // a bill. Measured on a live box, two open feeds account for about a megabyte between them
  // while the other three cost under 5 KB — a difference the page showed nowhere.
  if (lists.length) view.appendChild(listMemoryCard(lists));
  if (lists.length) { paintRoutingStatus(); paintRoutingTraffic(); }
  // The live half of this page: the kernel plane's state, each list's source check, and the matched
  // counters. Registered rather than ticked here so it stops when the operator navigates away.
  onPageRepaint(() => {
    repaintRoutingStatus();
    if ((state.profile.routing_lists || []).length) { paintRoutingStatus(); paintRoutingTraffic(); }
  });
}

// pbrStatusPill states what the kernel routing plane is doing, from the backend's own reading.
function pbrStatusPill(st) {
  if (st && st.installed && !st.stale) {
    return el("span", { class: "pill ok pill--dot" }, st.strict ? t("active") : t("active · {0} zones", st.zones));
  }
  return st && st.installed
    ? el("span", { class: "pill warn" }, t("stale"))
    : el("span", { class: "pill muted" }, t("not applied"));
}

// repaintRoutingStatus re-reads the plane and swaps the pill in place. Without it the page kept the
// answer it got at render — the reason an Apply that installed the plane left "not applied" on screen
// until the operator navigated away and back.
let pbrStatusInFlight = false;
let pbrStatusLast = 0;
const PBR_STATUS_MIN_MS = 15000;
async function repaintRoutingStatus() {
  const row = document.querySelector("#view [data-pbr-row]");
  if (!row) return;
  // This endpoint recompiles the kernel plane to answer, so it is the one poll on the page that can
  // cost real router CPU on a big feed. Never overlap two of them, and never ask more often than
  // this: a plane's state does not change between health ticks, and a 5 s poll of a call that takes
  // longer than 5 s is how a panel saturates the router it is reporting on.
  const now = Date.now();
  if (pbrStatusInFlight || now - pbrStatusLast < PBR_STATUS_MIN_MS) return;
  pbrStatusInFlight = true;
  let st;
  try { st = await api.get("/api/pbr/status"); }
  catch (_) { return; } // a status blip is not news
  finally { pbrStatusInFlight = false; pbrStatusLast = Date.now(); }
  const span = row.firstChild;
  if (!span || !span.lastChild) return;
  span.replaceChild(pbrStatusPill(st), span.lastChild);
  // The "Review changes" button belongs to the not-active state; drop it once the plane is in place.
  const btn = row.querySelector("button");
  const active = st && st.installed && !st.stale;
  if (btn && active) btn.remove();
}

// paintRoutingTraffic fills the "Matched" column from GET /api/routing/traffic.
//
// The number is only as strong as what the proxy core can see, and the difference matters most on
// exactly the routers this project targets: in hybrid/fast mode a pure-IP list pointed at a kernel
// egress never reaches sing-box, so it can carry the bulk of the traffic and still report zero.
// Printing a bare "0" there would be the page's most confident lie, so a list the running core has
// no rule-set for says so instead of showing a count.
async function paintRoutingTraffic() {
  let d;
  try { d = await api.get("/api/routing/traffic"); } catch (_) { d = null; }
  document.querySelectorAll("[data-rltraffic]").forEach(cell => {
    const id = cell.getAttribute("data-rltraffic");
    cell.innerHTML = "";
    if (!d) {
      cell.appendChild(el("span", { class: "rl-tr-none", title: t("The router did not answer, so nothing is claimed either way") }, t("not read")));
      return;
    }
    if (d.visible_known && d.core_visible && d.core_visible[id] === false) {
      // "The core has no rule-set for this list" has two causes and they are not the same news.
      // A switched-off list was never emitted, so saying "kernel-routed" would invent a routing
      // plane for a rule that is not routing anything at all.
      const rl = (state.profile.routing_lists || []).find(x => x.id === id);
      cell.appendChild(rl && !rl.enabled
        ? el("span", { class: "rl-tr-none", title: t("Switched off, so the core carries no rule for it") }, t("switched off"))
        : el("span", { class: "rl-tr-none",
            title: t("The running proxy core has no rule-set for this list — its traffic is routed by the kernel and is not counted here.") },
            t("kernel-routed")));
      return;
    }
    if (!d.sampled) {
      cell.appendChild(el("span", { class: "rl-tr-none", title: t("No proxy core is running to attribute traffic") }, t("not sampled")));
      return;
    }
    const s = (d.lists || {})[id] || { live: 0, conns: 0, bytes: 0 };
    if (!s.conns && !s.bytes) {
      cell.appendChild(el("span", { class: "rl-tr-zero",
        title: t("Nothing has matched this list since the daemon started ({0})", fmtWhen(d.since_ms)) }, t("nothing yet")));
      return;
    }
    cell.appendChild(el("span", { class: "rl-tr-n" }, String(s.conns)));
    cell.appendChild(el("span", { class: "rl-tr-u" }, s.conns === 1 ? t("conn") : t("conns")));
    cell.appendChild(el("span", { class: "rl-tr-b" }, fmtBytes(s.bytes)));
    if (s.live) cell.appendChild(el("span", { class: "rl-tr-live", title: t("open right now") }, s.live + " " + t("open")));
  });
}

// paintRoutingStatus probes each list's rule-set source (GET /api/routing/status)
// and colours its dot green/red, surfacing the HTTP/error code under the list.
async function paintRoutingStatus() {
  let st;
  try { st = await api.get("/api/routing/status"); } catch (_) { return; }
  const byId = {};
  (st || []).forEach(s => { byId[s.id] = s; });
  document.querySelectorAll("[data-rlstatus]").forEach(d => {
    const s = byId[d.getAttribute("data-rlstatus")];
    if (!s) return;
    const label = s.ok ? (s.status ? t("source reachable (HTTP {0})", s.status) : t("OK")) : (s.error || t("error"));
    d.title = label;
    d.setAttribute("role", "img");
    d.setAttribute("aria-label", label); // expose the pass/fail state to assistive tech, not color alone
    // The state itself lives on the row's switch — the one control every row has in the same place.
    // A disabled list keeps the neutral grey it was rendered with: whether its source answers is not
    // the fact worth colouring while it routes nothing.
    const id = d.getAttribute("data-rlstatus");
    const sw = document.querySelector('[data-rlswitch="' + CSS.escape(id) + '"]');
    if (sw) {
      sw.classList.toggle("src-ok", !!s.ok);
      sw.classList.toggle("src-err", !s.ok);
      sw.setAttribute("aria-label", (sw.getAttribute("aria-label") || "").split(" — ")[0] + " — " + label);
    }
  });
  document.querySelectorAll("[data-rlerr]").forEach(e => {
    const s = byId[e.getAttribute("data-rlerr")];
    if (s && !s.ok && s.error) { e.textContent = "⚠ " + s.error; e.style.display = ""; }
    else { e.style.display = "none"; }
  });
}



// moveRoutingList persists a new order through the endpoint that validates it. The visible order
// is the ENABLED-list order the page renders, so the ids sent back are rebuilt from the full stored
// list — sending only what is on screen would look like a request to drop the rest.
async function moveRoutingList(from, to) {
  const all = (state.profile.routing_lists || []).map(x => x.id);
  const shown = renderedRoutingOrder();
  if (shown.length !== all.length) {
    // Defensive: the page currently renders every list. If that ever changes, refuse rather than
    // submit an order that the store would read as "these are all the lists there are".
    toast("Cannot reorder while the list is filtered — clear the filter and try again.", "err");
    return;
  }
  const next = moveInArray(shown, from, to);
  try {
    await api.post("/api/routing/reorder", { ids: next });
    await loadProfile();
    route();
  } catch (e) { toast(e.message, "err"); }
}

// renderedRoutingOrder is the order the user is actually looking at.
function renderedRoutingOrder() {
  return [...document.querySelectorAll("[data-rlstatus]")].map(n => n.getAttribute("data-rlstatus"));
}

async function toggleRoutingList(rl, sw) {
  if (applyInFlight) { toast(t("Apply in progress — finish it first"), "err"); return; } // don't mutate staged config mid-Apply (checked before flipSwitch, so no visual desync)
  if (sw && sw._busy) return; // ignore rapid re-clicks while a write is in flight — no racing double-write
  if (sw) sw._busy = true;
  const want = !rl.enabled;
  flipSwitch(sw, want);
  rl.enabled = want;
  updateDirty(); // light the Apply/Save buttons (the removed loadProfile() used to do this)
  try {
    await api.post("/api/routing", { ...rl, enabled: want });
  } catch (e) {
    flipSwitch(sw, !want);
    rl.enabled = !want;
    updateDirty();
    toast(e.message, "err");
  } finally { if (sw) sw._busy = false; }
}






// openDeviceGroups: manage the named device groups a routing list can scope to (apply/block a list
// only for those devices).
function openDeviceGroups() {
  const listWrap = el("div", {});
  const render = () => {
    listWrap.innerHTML = "";
    const groups = deviceGroups();
    if (!groups.length) listWrap.appendChild(el("div", { class: "hint", style: "margin:8px 0" }, t("No device groups yet. Create one, then scope a routing list to it.")));
    groups.forEach(g => listWrap.appendChild(el("div", { class: "conn" },
      el("div", { class: "body" },
        el("div", { class: "name" }, g.name || g.id),
        el("div", { class: "sub" }, el("span", { class: "addr" }, tn("{0} device|{0} devices", (g.members || []).length)))),
      el("div", { class: "acts" },
        el("button", { class: "btn btn-sm", onclick: () => openDeviceGroup(g, render) }, t("Edit")),
        el("button", { class: "btn btn-danger btn-sm", "aria-label": t("Delete") + " " + (g.name || g.id), onclick: () => delDeviceGroup(g, render) }, t("Delete"))))));
  };
  render();
  modal({
    title: t("Device groups"), body: el("div", {},
      el("div", { class: "hint", style: "margin-bottom:10px" }, t("Named sets of devices (by MAC or IP) that a routing list can apply to — or be blocked for.")),
      listWrap,
      el("div", { style: "margin-top:12px" }, el("button", { class: "btn btn-primary", onclick: () => openDeviceGroup(null, render) }, t("+ New group")))),
  });
}



// openDeviceGroup: create/edit one group — a name + members picked from the live device list or typed
// as a MAC/IP. onSaved re-renders whatever opened it (the manager, or a routing-list scope picker).
function openDeviceGroup(g, onSaved) {
  const editing = !!g;
  g = g || { id: "", name: "", members: [] };
  let members = (g.members || []).map(m => ({ mac: m.mac || "", ip: m.ip || "" }));
  const name = el("input", { type: "text", value: g.name || "", placeholder: t("e.g. {0}", "Kids") });
  const has = (mac, ip) => members.some(m => (mac && m.mac.toLowerCase() === mac.toLowerCase()) || (ip && m.ip === ip));
  const memWrap = el("div", { style: "max-height:30vh;overflow:auto;margin:6px 0" });
  const renderMembers = () => {
    memWrap.innerHTML = "";
    if (!members.length) { memWrap.appendChild(el("div", { class: "hint" }, t("No devices yet — pick one below or add a MAC/IP."))); return; }
    members.forEach((m, i) => memWrap.appendChild(el("div", { class: "conn" },
      el("div", { class: "body" }, el("div", { class: "name" }, m.mac || m.ip),
        el("div", { class: "sub" }, el("span", { class: "addr" }, [m.mac, m.ip].filter(Boolean).join(" · ")))),
      el("div", { class: "acts" }, el("button", { class: "btn btn-sm btn-ghost", title: t("Remove"), "aria-label": t("Remove"), onclick: () => { members.splice(i, 1); renderMembers(); } }, "✕")))));
  };
  renderMembers();
  const pickWrap = el("div", { style: "max-height:24vh;overflow:auto" }, el("div", { class: "hint" }, t("loading devices…")));
  api.get("/api/devices").then(r => {
    pickWrap.innerHTML = "";
    const devs = (r && r.devices) || [];
    if (!devs.length) { pickWrap.appendChild(el("div", { class: "hint" }, t("No devices seen on the LAN right now."))); return; }
    devs.forEach(d => {
      // Use the same visible primary label as the accessible name. A hostname is preferred;
      // IP/MAC are fallbacks only when the device has no human name, avoiding gratuitous raw IDs.
      const deviceLabel = d.hostname || d.ip || d.mac || "Device";
      pickWrap.appendChild(el("div", { class: "conn" },
        el("div", { class: "body" }, el("div", { class: "name" }, deviceLabel),
          el("div", { class: "sub" }, el("span", { class: "addr" }, [d.mac, d.ip].filter(Boolean).join(" · ")))),
        el("div", { class: "acts" }, el("button", { class: "btn btn-sm", "aria-label": t("Add") + " " + deviceLabel, onclick: () => { if (has(d.mac, d.ip)) return toast(t("Already added"), "err"); members.push({ mac: (d.mac || "").toLowerCase(), ip: d.ip || "" }); renderMembers(); } }, "+"))));
    });
  }).catch(() => { pickWrap.innerHTML = ""; pickWrap.appendChild(el("div", { class: "hint" }, t("Couldn't load the device list."))); });
  const manIn = el("input", { type: "text", placeholder: t("MAC (aa:bb:…) or IP") });
  // Anything that is not a 6-byte MAC used to be filed as an IP, whatever it was: typing
  // "not-a-device" added a chip and the field said nothing, and only Save came back with the server's
  // "invalid IP/CIDR". The rule is checkable where it is typed, so it is checked there - the
  // connection dialog marks a bad Reality key the same way rather than waiting for the save.
  //
  // Deliberately permissive about IPv6: any hex-and-colon form passes here. Rejecting a valid address
  // the router would have accepted is the worse failure, and the server stays the authority either way.
  const looksLikeAddress = (v) => {
    const slash = v.indexOf("/");
    const addr = slash < 0 ? v : v.slice(0, slash);
    const len = slash < 0 ? "" : v.slice(slash + 1);
    if (slash >= 0 && !/^[0-9]{1,3}$/.test(len)) return false;
    if (/^[0-9]{1,3}(.[0-9]{1,3}){3}$/.test(addr)) {
      return addr.split(".").every(o => Number(o) <= 255) && (len === "" || Number(len) <= 32);
    }
    if (addr.includes(":") && /^[0-9a-fA-F:]+$/.test(addr)) return len === "" || Number(len) <= 128;
    return false;
  };
  const addManual = () => {
    const v = manIn.value.trim(); if (!v) return;
    const isMAC = /^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$/.test(v);
    if (!isMAC && !looksLikeAddress(v)) {
      return toast(t("{0} is neither a MAC (aa:bb:cc:dd:ee:ff) nor an IP address", JSON.stringify(v)), "err");
    }
    const m = isMAC ? { mac: v.toLowerCase(), ip: "" } : { mac: "", ip: v };
    if (has(m.mac, m.ip)) return toast(t("Already added"), "err");
    members.push(m); manIn.value = ""; renderMembers();
  };
  async function save(btn) {
    if (!name.value.trim()) return toast(t("Name required"), "err");
    if (!members.length) return toast(t("Add at least one device"), "err");
    if (btn) { if (btn.disabled) return; btn.disabled = true; } // in-flight guard — no duplicate POST from a double-click (mirrors the group editors)
    const dbody = { id: g.id || rlUniqueId(rlSlug(name.value)), name: name.value.trim(), members: members.map(m => { const o = {}; if (m.mac) o.mac = m.mac; if (m.ip) o.ip = m.ip; return o; }) };
    try { await api.post("/api/device-groups", dbody); await loadProfile(); back.remove(); if (onSaved) onSaved(); toast(editing ? t("Saved {0}", dbody.name) : t("Added {0}", dbody.name), "ok"); }
    catch (e) { if (btn) btn.disabled = false; toast(e.message, "err"); }
  }
  const body = el("div", {},
    el("div", { class: "field" }, el("label", {}, t("Name")), name),
    el("div", { class: "field" }, el("label", {}, t("Devices in this group")), memWrap),
    el("div", { class: "field" }, el("label", {}, t("Add by MAC or IP")), el("div", { style: "display:flex;gap:8px" }, manIn, el("button", { class: "btn", type: "button", onclick: addManual }, t("Add"))),
      el("div", { class: "hint", style: "margin-top:6px" }, t("MAC matches most reliably — but turn off the device's Private/Random Wi-Fi address for this network, or its MAC will change and drop out of the group."))),
    el("div", { class: "field" }, el("label", {}, t("Pick from devices on the network")), pickWrap));
  const back = modal({
    title: editing ? t("Edit device group") : t("New device group"), body,
    footer: [el("button", { class: "btn btn-ghost", onclick: () => back.remove() }, t("Cancel")), el("button", { class: "btn btn-primary", onclick: (e) => save(e.currentTarget) }, editing ? t("Save") : t("Add"))],
  });
}



// refreshCidrSources re-fetches every routing list that has an auto-refresh CIDR source
// (POST /api/routing/refresh) and reports the result. It updates each list's cached CIDRs
// but does NOT apply — the user clicks Apply to activate (matching the stage-then-Apply
// model). A no-op (friendly toast) when no list has a CIDR source configured.
async function refreshCidrSources(btn) {
  if (btn) { if (btn.disabled) return; btn.disabled = true; } // guard: the refresh is multi-second — no double-submit
  try {
    const r = await api.post("/api/routing/refresh", {});
    await loadProfile(); route();
    const srcN = (r.lists || []).length;
    const errN = (r.errors || []).length;
    if (!srcN) { toast(t("No auto-refresh CIDR sources — set one on a list first."), "ok"); return; }
    const msg = (r.changed ? t("Refreshed") : t("No changes")) + " · " + tn("{0} source|{0} sources", srcN) +
      (errN ? " · " + t("{0} failed", errN) : "") + (r.changed ? t(" — click Apply to activate.") : "");
    toast(msg, errN ? "err" : "ok");
  } catch (e) { toast(e.message, "err"); }
  finally { if (btn) btn.disabled = false; } // harmless if route() already replaced the button
}




/* ---------- modal ---------- */
let modalSeq = 0;
// modalConfirm is a themed, async replacement for the browser's native confirm().
// Returns a Promise<boolean>: true = OK, false = Cancel / Escape / backdrop click.
// Reuses the .modal-backdrop / .modal / .modal-body / .modal-foot CSS classes so it
// inherits the same look, dark-mode, and responsive sizing as all other modals.
// opts is optional and defaults to the OK/Cancel pair every existing caller expects. It exists for
// the case where the dialog is a STATEMENT rather than a choice: "this group cannot be deleted yet"
// offered OK and Cancel, and on a destructive flow "OK" reads as "delete it anyway" — the opposite
// of what pressing it does.
function modalConfirm(msg, opts) {
  const o = opts || {};
  return new Promise(resolve => {
    const prevFocus = document.activeElement;
    let settled = false;
    let mo = null;
    const nativeRemove = node => Element.prototype.remove.call(node);
    const settle = v => {
      if (settled) return; settled = true;
      if (mo) mo.disconnect();
      document.removeEventListener("keydown", onKey);
      nativeRemove(back);
      if (prevFocus && typeof prevFocus.focus === "function" && document.contains(prevFocus)) prevFocus.focus();
      resolve(v);
    };
    const ok = el("button", { class: "btn btn-primary" }, o.okLabel || t("OK"));
    const cancel = el("button", { class: "btn" }, t("Cancel"));
    if (o.acknowledgeOnly) cancel.hidden = true;
    ok.addEventListener("click", () => settle(true));
    cancel.addEventListener("click", () => settle(false));
    const onKey = e => {
      if (e.key === "Escape") { e.preventDefault(); settle(false); return; }
      if (e.key !== "Tab") return;
      // Tab focus-trap: keep focus inside the dialog (matches modal()); without it Tab escapes to the page behind.
      const items = focusables(dlg);
      if (!items.length) { e.preventDefault(); dlg.focus(); return; }
      const first = items[0], last = items[items.length - 1], active = document.activeElement;
      if (e.shiftKey && (active === first || !dlg.contains(active))) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && (active === last || !dlg.contains(active))) { e.preventDefault(); first.focus(); }
    };
    const back = el("div", { class: "modal-backdrop", onclick: e => { if (e.target === back) settle(false); } });
    // aria-label gives the dialog an accessible name (the confirmation question) so screen readers don't
    // announce an unnamed dialog.
    const dlg = el("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": msg },
      el("div", { class: "modal-body" }, el("p", { style: "margin:0 0 16px;white-space:pre-wrap" }, msg)),
      el("div", { class: "modal-foot" },
        el("div", { style: "display:flex;gap:10px;justify-content:flex-end" }, cancel, ok)));
    back.appendChild(dlg);
    document.body.appendChild(back);
    document.addEventListener("keydown", onKey);
    // External-teardown safety: route() clears open dialogs on navigation by removing .modal-backdrop
    // directly (not via settle). Watch for that so we still detach the keydown listener and resolve the
    // awaiting caller (otherwise the listener leaks and `await modalConfirm(...)` hangs forever).
    mo = new MutationObserver(() => { if (!document.contains(back)) settle(false); });
    mo.observe(document.body, { childList: true });
    ok.focus();
  });
}
// focusables returns the modal's tabbable controls, in DOM order, skipping hidden
// ones — used both for initial focus and for the Tab focus-trap.
function focusables(root) {
  return [...root.querySelectorAll(
    'input:not([type=hidden]):not([disabled]), select:not([disabled]), textarea:not([disabled]), button:not([disabled]), [href], [tabindex]:not([tabindex="-1"])')]
    .filter(n => n.offsetParent !== null || n === document.activeElement);
}
// fixed: give the dialog a constant frame — see .modal-fixed. Worth asking for when what is inside
// changes size while the dialog is open (a list that grows, a footer note that swaps length); a form
// that is simply long is better left to size itself.
function modal({ title, body, footer, fixed }) {
  // Remember what was focused so we can restore it when the modal closes (a11y).
  const prevFocus = document.activeElement;
  // close() centralizes teardown so every close path (Escape, backdrop click, ×,
  // and any caller's back.remove()) detaches the keydown listener and restores
  // focus — no leaked listener firing for a removed modal.
  let closed = false;
  // domRemove keeps a handle on the native Element.remove so close() can detach
  // the node without recursing through our overridden back.remove (set below).
  const domRemove = Element.prototype.remove;
  const close = () => {
    if (closed) return;
    closed = true;
    document.removeEventListener("keydown", onKey);
    domRemove.call(back);
    if (prevFocus && typeof prevFocus.focus === "function" && document.contains(prevFocus)) {
      prevFocus.focus();
    }
  };
  // Escape closes; Tab is trapped inside the dialog so keyboard focus can't wander
  // onto the (aria-hidden, visually-behind) page — required for a real aria-modal.
  const onKey = e => {
    if (e.key === "Escape") { e.preventDefault(); close(); return; }
    if (e.key !== "Tab") return;
    const items = focusables(m);
    if (!items.length) { e.preventDefault(); m.focus(); return; }
    const first = items[0], last = items[items.length - 1], active = document.activeElement;
    if (e.shiftKey && (active === first || !m.contains(active))) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && (active === last || !m.contains(active))) { e.preventDefault(); first.focus(); }
  };
  const back = el("div", { class: "modal-backdrop", onclick: e => { if (e.target === back) close(); } });
  const titleId = "modal-title-" + (++modalSeq);
  const m = el("div", { class: "modal" + (fixed ? " modal-fixed" : ""), tabindex: "-1", role: "dialog", "aria-modal": "true", "aria-labelledby": titleId },
    el("div", { class: "modal-head" }, el("div", { class: "card-title", id: titleId }, title),
      a11yClick(el("div", { class: "x" }, "×"), () => close(), t("Close"))),
    el("div", { class: "modal-body" }, body));
  if (footer) m.appendChild(el("div", { class: "modal-foot" }, footer));
  back.appendChild(m);
  i18nApply(m); // localize the modal's English content (titles, labels, hints, buttons)
  associateLabels(m); // wire form labels to their controls for screen readers
  document.body.appendChild(back);
  document.addEventListener("keydown", onKey);
  // Move focus into the modal: first focusable control, else the dialog container. preventScroll,
  // because in a fixed-height dialog the body is a scroller and focusing its first input made the
  // browser scroll that input into view — which pushed the field's own label off the top edge the
  // moment the dialog opened.
  (focusables(m)[0] || m).focus({ preventScroll: true });
  // Route every existing back.remove() call site through close() so they also
  // detach the keydown listener and restore focus (close() de-dupes; the native
  // removal happens via domRemove inside close). back.close is an explicit alias.
  back.remove = close;
  back.close = close;
  return back;
}

/* ---------- share / QR / subscription ---------- */

// checkEndpointConfig validates ONE connection's config server-side (the generator + `sing-box check`,
// scoped to that endpoint) without touching the live setup — the per-connection replacement for the
// old Share/QR export. Mirrors testEndpoint's button UX; the server error text carries the reason.
async function checkEndpointConfig(e, btn) {
  if (btn && btn.hasAttribute("disabled")) return; // guard against repeated concurrent checks
  const label = btn ? btn.textContent : "";
  // "Checking", not "Testing": this validates the configuration, it sends no traffic. The two row
  // actions ask different questions and used to announce themselves identically.
  if (btn) { btn.setAttribute("disabled", "true"); btn.textContent = "Checking…"; }
  try {
    const r = await api.post("/api/endpoints/" + encodeURIComponent(e.id) + "/check", {});
    if (r && r.ok) {
      // A pass from the generator alone is a much weaker statement than one from the engine, and
      // both used to render as a bare "OK" — on a router with no sing-box every connection passed.
      const weak = r.checked_by === "generator";
      // A native connection is not checked by the engine at all (pbr routes it), so saying
      // "configuration is valid" here claimed a verdict sing-box never gave — and could not give:
      // it exits 0 on a bind_interface that does not exist. Name what was actually verified.
      const msg = weak
        ? "settings accepted, but sing-box is not installed here so the configuration itself was not checked"
        : r.checked_by === "interface"
          ? "interface " + (r.iface || "?") + " exists — that is all a native connection has to check"
          : "configuration is valid";
      toast((e.name || e.id) + ": " + msg, weak ? "info" : "ok");
    } else toast((e.name || e.id) + ": " + ((r && r.error) || "config invalid"), "err");
  } catch (err) { toast(err.message, "err"); }
  finally { if (btn) { btn.removeAttribute("disabled"); btn.textContent = label; } }
}


// olcRTC is deliberately absent: the strict executor cannot yet identify and roll back its binary.
// Existing/imported olcRTC entries are still shown by manualForm, but cannot be selected for a new
// connection. AnyTLS is supported end-to-end by the importer, model and sing-box generator.
const PROTOCOLS = ["vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic", "anytls", "wireguard", "amneziawg", "socks", "http"];
const SS_METHODS = ["aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-256-gcm", "2022-blake3-aes-128-gcm", "2022-blake3-chacha20-poly1305"];

function connectionProtocolRequirementIDs(proto) {
  if (proto === "wireguard" || proto === "amneziawg") {
    return ["native.operation." + proto + ".create", "native.operation." + proto + ".remove"];
  }
  if (proto === "olcrtc") return ["engine.olcrtc"];
  return ["engine.singbox", "protocol." + proto];
}





// REALITY_FRONTS — known-good, globally-reachable TLS-1.3 sites that make sensible Reality
// camouflage destinations. Offered as SNI suggestions ONLY when security=reality (a plain-TLS
// SNI must be the server's own domain). Starting points — the Check button verifies each is
// reachable + TLS 1.3 from the router's vantage before saving.
const REALITY_FRONTS = ["www.microsoft.com", "www.cloudflare.com", "www.apple.com", "dl.google.com", "www.amazon.com", "aws.amazon.com", "www.bing.com"];

// The daemon ships a richer, single-source curated catalog (model.RealityDests via GET
// /api/reality/dests) — more entries, each with a human label — so the picker stays maintained in
// ONE place (Go) instead of drifting from this list. Fetched once + cached; until it loads (or
// forever, on an old/offline daemon) the datalist falls back to the built-in REALITY_FRONTS above,
// so the picker always works. label = the vendor name (a proper noun — no i18n needed).
let REALITY_DESTS_CACHE = null;

// realityFrontOptions builds the datalist <option>s: the server catalog (value=host, label=name)
// when loaded, else the built-in REALITY_FRONTS hostnames.
function realityFrontOptions() {
  if (REALITY_DESTS_CACHE && REALITY_DESTS_CACHE.length) {
    return REALITY_DESTS_CACHE.map(d => el("option", { value: d.host, label: d.name || d.host }));
  }
  return REALITY_FRONTS.map(d => el("option", { value: d }));
}





// fInputValidated — an input with an inline format indicator. validate(trimmedValue) returns ""
// (ok) or a short error; an EMPTY field never errors (the Reality fields are unused for plain
// TLS). Keeps the input id so collect()'s g(id) is unchanged.
// The field validates as you type AND records the verdict where a save path can find it.
//
// Recording it is the point. Every one of these fields drew a red "✗ not a valid x25519 key" and then
// let Save write the value anyway: the form knew, said so, and did not act on what it knew. Measured
// on a freshly imported Reality link whose public key was 3 characters — saved, stored, and the Apply
// preflight has no opinion about key material, so the next thing to notice would be the tunnel not
// coming up. `data-invalid` carries the reason so the refusal can name the field instead of making
// the operator hunt for the red mark.
function fInputValidated(id, label, value, ph, validate) {
  const input = el("input", { type: "text", id, value: value != null ? String(value) : "", placeholder: ph || "" });
  const result = el("span", { class: "hint", style: "margin-left:8px" });
  const run = () => {
    const v = (input.value || "").trim();
    const err = v ? validate(v) : "";
    result.textContent = err ? "✗ " + err : "";
    result.style.color = err ? "var(--err)" : "";
    input.dataset.invalid = err ? "1" : "";
    input.dataset.invalidLabel = err ? label : "";
    input.dataset.invalidWhy = err || "";
  };
  input.addEventListener("input", run);
  run();
  return el("div", { class: "field" }, el("label", {}, label),
    el("div", { class: "row", style: "display:flex;align-items:center;gap:8px;flex-wrap:wrap" }, input, result));
}

// fSniCheck is the SNI field (used by the vless tls/reality branch AND hysteria2/tuic)
// with a "Check" button that probes the entered SNI from the router's vantage:
// TCP-reachable + speaks TLS + negotiates TLS 1.3. Reality borrows a real public
// TLS 1.3 site's SNI as camouflage, so an unreachable/non-TLS/TLS-1.2 dest silently
// breaks the connection — this surfaces it before saving. Additive; the input keeps id
// so collect()'s g("f-sni") is unchanged.
function fSniCheck(id, label, value) {
  const input = el("input", { type: "text", id, value: value != null ? String(value) : "" });
  const result = el("span", { class: "hint", style: "margin-left:8px" });
  const btn = el("button", { class: "btn btn-sm", type: "button" }, t("Check"));
  btn.addEventListener("click", async () => {
    const host = (input.value || "").trim();
    if (!host) { toast(t("Enter an SNI to check"), "err"); return; }
    const prev = btn.textContent;
    btn.disabled = true; btn.textContent = t("Checking…");
    result.textContent = "";
    result.style.color = "";
    try {
      const r = await api.post("/api/probe/tls", { host });
      if (!r.reachable) {
        result.style.color = "var(--err)";
        result.textContent = t("✗ unreachable: {0}", r.error || t("no response"));
      } else if (r.tls13) {
        result.style.color = "var(--ok)";
        result.textContent = t("✓ reachable · TLS 1.3");
      } else {
        result.style.color = "var(--warn)";
        result.textContent = t("reachable, but TLS {0} (Reality needs 1.3)", r.version || "1.2");
      }
    } catch (e) {
      result.style.color = "var(--err)";
      result.textContent = t("✗ check failed: {0}", e.message || String(e));
    } finally {
      btn.disabled = false; btn.textContent = prev;
    }
  });
  return el("div", { class: "field" },
    el("label", {}, label),
    el("div", { class: "row", style: "display:flex;align-items:center;gap:8px;flex-wrap:wrap" }, input, btn, result));
}

// Map a raw importer/parser error (e.g. `unsupported scheme ""`) to a friendly category, with an
// expandable Technical details section + recovery actions. The pasted link (which may hold secrets)
// is never shown — only the parser's own message goes into the details.
// redactSecrets masks credential-like material in a raw error string before it is shown in
// "Technical details" or copied to the clipboard: URL userinfo (the uuid/password before @),
// full UUIDs, and long base64/key-ish runs. The user pasted their own link, but the details
// end up in screenshots and support logs — never echo whole secrets back. Over-redaction is
// safe here (it is a diagnostics box, not the data path).
function redactSecrets(raw) {
  let s = String(raw == null ? "" : raw);
  // URL userinfo (user:pass@host, trojan://pass@host, ss://method:pass@host): keep a short
  // recognizable prefix, redact the rest. NO length floor now, so SHORT passwords are covered too
  // (the old {5,} let a short trojan/ss password through verbatim).
  s = s.replace(/(\w[\w+.-]*:\/\/)([^/@\s]+)@/g, (m, p, u) => p + u.slice(0, 3) + "…@");
  // Secret-bearing QUERY params in a share link (?password=…&token=…&psk=…&secret=…&auth=…),
  // redacted regardless of value length — the backend can echo a parsed link back inside an error,
  // and these short values slipped past the >=20-char long-token rule below.
  s = s.replace(/([?&](?:pass(?:word)?|pwd|psk|secret|token|auth|servicename|obfs(?:-?password)?)=)([^&\s#]+)/gi,
    (m, k, v) => k + v.slice(0, 2) + "…");
  // UUIDs (VLESS / VMess / TUIC ids).
  s = s.replace(/\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g, u => u.slice(0, 4) + "…");
  // Long opaque tokens / base64 blobs.
  s = s.replace(/\b[A-Za-z0-9+/=_-]{20,}\b/g, r => r.slice(0, 4) + "…" + r.slice(-2));
  return s;
}





function parsedView(e) {
  const wrap = el("div", {});
  if (e.engine && e.engine !== "singbox")
    wrap.appendChild(el("div", { class: "toast info", style: "margin:0 0 12px" }, t("Uses the {0} engine (chained into sing-box).", e.engine)));
  const kv = el("div", { class: "kv" });
  const add = (k, v) => { kv.appendChild(el("div", { class: "k" }, k)); kv.appendChild(el("div", { class: "v" }, String(v))); };
  add("Name", e.name || e.id);
  add("Protocol", e.protocol);
  add("Server", e.server + ":" + e.port);
  if (e.tls && e.tls.type) add("Security", e.tls.type + (e.tls.sni ? " (" + e.tls.sni + ")" : ""));
  if (e.transport && e.transport.type) add("Transport", e.transport.type);
  wrap.appendChild(kv);
  return wrap;
}

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
    if (!e.enabled) { note = t("off"); }
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
  const ordered = (g.members || []).map(findEndpoint).filter(Boolean)
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
      await api.post("/api/groups", out);
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

/* ---------- apply ----------
 * POST /api/apply {save, rev, ack}. The ONLY thing pinned is `rev`, the desired-configuration
 * revision the review panel showed (docs/APPLY_REDESIGN.md in the development repository). Every refusal names its cause and its
 * consequence, and each one gets its own treatment here:
 *   409 REV_STALE     → the panel re-renders from the plan the server sent, with a notice; click again
 *   409 ACK_REQUIRED  → the panel re-opens with the checkboxes, first unchecked one focused
 *   422 BLOCKED       → the panel re-opens with the blocking findings highlighted; retrying cannot help
 *   400 INVALID_CONFIG→ #apply-error with the tool's actual message; Review, no Retry
 *   500 APPLY_FAILED  → #apply-error with cause/stage + whether the previous state was restored; Retry
 *   503 BUSY / no answer / timeout → #apply-error + Retry, and the browser follows GET /api/apply/status
 *                       until in_progress is false, then refreshes the state
 * A success is never claimed unless the server said applied:true.
 */
// Phased progress for the multi-second Apply. The POST only returns at the very end, so on a slow
// A53 the button text would otherwise freeze for 3-30 s at the moment of peak user anxiety. The
// server's own stage (state.applyStage, polled by applyConfig) is shown when it says one; until
// then honest timer hints that mirror the real sequence, plus a live elapsed counter — never
// claiming "done" until the promise resolves. Returns a stop() fn.
function applyProgress(btn) {
  const phases = [
    [0,    t("Checking…")],
    [1200, t("Reloading…")],
    [3800, t("Applying routing…")],
    [7000, t("Finishing…")],
  ];
  const started = Date.now();
  const paint = () => {
    const dt = Date.now() - started;
    let label = phases[0][1];
    for (const [ms, txt] of phases) { if (dt >= ms) label = txt; }
    if (state.applyStage) label = applyStageText(state.applyStage) + "…";
    const secs = dt >= 2000 ? " " + Math.round(dt / 1000) + "s" : "";
    btn.textContent = "";
    btn.appendChild(el("span", { class: "spin", "aria-hidden": "true" }));
    btn.appendChild(document.createTextNode(" " + label + secs));
  };
  paint();
  const iv = setInterval(paint, 500);
  return () => clearInterval(iv);
}

function hideApplyError() {
  const b = $("#apply-error");
  if (b) { b.style.display = "none"; b.innerHTML = ""; }
}
// showApplyError renders the persistent failure card under the topbar. `spec`:
//   title, message      — what happened (the server's own words where it has them)
//   detail              — tool output tail / cause, shown verbatim in a <pre> (never a toast)
//   note                — the consequence ("the previous configuration was restored")
//   retry (bool), save  — offer Retry only where retrying can help; it re-runs applyConfig(save)
//   review (bool)       — offer "Review changes"
//   diag (bool)         — offer "Open Diagnostics"
function showApplyError(spec) {
  const b = $("#apply-error");
  spec = spec || {};
  const msg = spec.message || "";
  if (!b) { toast(t("Apply failed: {0}", msg), "err"); return; }
  b.style.display = "block"; b.innerHTML = "";
  const acts = el("div", { class: "acts ae-acts" });
  if (spec.retry) acts.appendChild(el("button", { class: "btn btn-primary btn-sm", type: "button", onclick: () => { hideApplyError(); applyConfig(!!spec.save); } }, t("Retry")));
  if (spec.review !== false) acts.appendChild(el("button", { class: "btn btn-sm", type: "button", onclick: () => { hideApplyError(); openReviewChanges(); } }, t("Review changes")));
  if (spec.diag) acts.appendChild(el("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: () => { location.hash = "#diagnostics"; } }, t("Open Diagnostics")));
  b.appendChild(el("div", { class: "card ae-card" },
    el("div", { class: "row-between ae-head" },
      el("b", {}, spec.title || t("Apply failed")),
      a11yClick(el("div", { class: "x ae-x" }, "×"), () => hideApplyError(), t("Close"))),
    msg ? el("div", { class: "ae-msg" }, msg) : null,
    spec.detail ? el("pre", { class: "code ae-detail" }, String(spec.detail)) : null,
    spec.note ? el("div", { class: "hint ae-note" }, spec.note) : null,
    acts.childNodes.length ? acts : null));
}

// applyPostTimeoutMs bounds how long the browser waits for POST /api/apply before treating the
// router as not answering. An Apply legitimately runs `sing-box check`, reads the NDM running
// config and settles the core, so this is generous; the browser then follows the server's own
// status instead of guessing.
let applyPostTimeoutMs = 90000;
let _applyWatch = null; // interval while the browser follows a server-side Apply it did not start, or lost the answer of
// watchServerApply follows GET /api/apply/status until the server says no Apply is in progress —
// used after a timeout/BUSY/network failure ("the apply may still be running") and by checkFailsafe
// when a reloaded page finds an Apply already running. Ends by refreshing the authoritative state.
function watchServerApply(onDone) {
  if (_applyWatch) return;
  let ticks = 0;
  const tick = async () => {
    let st;
    try { st = await api.get("/api/apply/status"); }
    catch (_) { if (++ticks > 200) { clearInterval(_applyWatch); _applyWatch = null; } return; } // keep watching through a blip, not forever
    if (st && st.in_progress) {
      state.applyStage = st.stage || "";
      if (state.applyPhase !== "applying") setApplyPhase("applying"); else renderApplyBanner();
      return;
    }
    clearInterval(_applyWatch); _applyWatch = null;
    if (state.applyPhase === "applying") { state.applyPhase = ""; state.applyStage = ""; renderApplyBanner(); }
    await refreshApplyState();
    checkFailsafe();
    if (onDone) onDone();
  };
  _applyWatch = setInterval(tick, 1500);
  tick();
}

async function applyConfig(save) {
  const btn = $("#applybtn");
  if (applyInFlight) { toast(t("Apply in progress — finish it first"), "err"); return; } // block re-entry so two /api/apply POSTs can't race + one's finally can't clear applyInFlight while the other runs
  save = !!save;
  const plan = reviewedPlan;
  // The panel's checked boxes; pre-checked (persisted) ones ride along too, which the server merges
  // harmlessly. Sent every time, so a required finding acknowledged here is not asked about again.
  const payload = { save, rev: plan && plan.rev ? String(plan.rev) : "", ack: [...ackedFindings] };
  const pendingBefore = _backendPending; // only an Apply clears "pending" — the one signal that a lost answer still succeeded
  const label = btn ? btn.textContent : "";
  if (btn) {
    btn.hidden = false;
    btn.setAttribute("disabled", "true");
    btn.setAttribute("aria-busy", "true");
    btn.classList.remove("dirty"); // spinner replaces the dirty dot while working
    btn.classList.add("working");
  }
  const stop = btn ? applyProgress(btn) : () => {};
  applyInFlight = true; // freeze staging toggles until this Apply settles (see the guards in toggleEndpoint/toggleRoutingList/dnsToggleRow)
  state.applyStage = "";
  setApplyPhase("applying");
  hideApplyError();
  // While the POST is out, the server reports which plane it is on; that is the banner's progress.
  const stagePoll = setInterval(async () => {
    try {
      const st = await api.get("/api/apply/status");
      if (st && applyInFlight && state.applyPhase === "applying") { state.applyStage = st.stage || ""; renderApplyBanner(); }
    } catch (_) { /* a status blip says nothing about the apply */ }
  }, 1500);
  let timedOut = false;
  try {
    const post = api.post("/api/apply", payload);
    post.catch(() => {}); // a late rejection after the timeout below must not surface as unhandled
    const r = await Promise.race([
      post,
      new Promise((_, rej) => setTimeout(() => {
        timedOut = true;
        const e = new Error(t("The router did not answer; the apply may still be running.")); e.data = { code: "TIMEOUT" }; rej(e);
      }, applyPostTimeoutMs)),
    ]);
    if (!r || r.applied !== true) {
      const e = new Error(t("Apply result could not be verified.")); e.data = { code: "UNVERIFIED", body: r }; throw e;
    }
    ackedFindings.clear(); // acknowledged findings are persisted server-side now
    if (r.ok === false) {
      // Applied, but a soft problem remains (a plugin did not start). Not a refusal and not a
      // success either: the banner lists what and how to fix it, and stays until the next Apply.
      state.applyProblems = Array.isArray(r.problems) ? r.problems : [];
      setApplyPhase("failed-attention");
      toast(t("Applied, but a component needs attention — see the banner."), "err");
    } else {
      toast(save ? t("Applied & saved") : t("Applied live (reverts on reboot unless saved)."), "ok");
      setApplyPhase("applied", 3500);
    }
    (r.warnings || []).forEach(w => { if (w) toast(String(w), "info"); });
    if (save) hideFailsafeBanner();
    else if (r.failsafe && r.failsafe.pending) startFailsafeBanner();
    else checkFailsafe();
    await refreshApplyState(); // backend truth — clears "pending" only if the backend confirms the apply
    repaintExits(); // an apply is exactly when the user looks at the list to see the change landed
  } catch (e) {
    const code = (e && e.data && e.data.code) || "";
    const data = (e && e.data) || {};
    const msg = (e && e.message) || "";
    if (code === "REV_STALE") {
      // Information, not an error: the desired configuration moved since the panel was opened. The
      // server sent the current plan; show it with a notice and let the user click again.
      setApplyPhase("");
      toast(t("The configuration changed while you were reviewing — check the updated list and apply again."), "info");
      openReviewChanges({ plan: data.plan, notice: "stale" });
    } else if (code === "ACK_REQUIRED") {
      setApplyPhase("");
      toast(t("Confirm the warnings in the review before applying."), "err");
      openReviewChanges({ findings: data.findings, notice: "ack", focusAck: true });
    } else if (code === "BLOCKED") {
      setApplyPhase("");
      toast(t("This router cannot execute part of this configuration — nothing was applied."), "err");
      openReviewChanges({ findings: data.findings, notice: "blocked" });
    } else if (code === "INVALID_CONFIG") {
      setApplyPhase("failed");
      toast(t("The configuration was rejected — nothing was applied."), "err");
      showApplyError({ title: t("The configuration was rejected"), message: msg, detail: data.detail,
        note: data.remedy || t("Fix the configuration and apply again — retrying as-is cannot help."), review: true });
    } else if (code === "APPLY_FAILED") {
      setApplyPhase("failed");
      toast(t("Apply failed: {0}", msg), "err");
      const restored = data.rolled_back === true;
      showApplyError({ title: t("Apply failed"), message: (data.stage ? t("Stage: {0}", applyStageText(data.stage)) + " — " : "") + msg,
        detail: data.detail,
        note: restored ? t("The previous configuration was restored.") : t("The previous configuration was NOT restored — check Diagnostics."),
        retry: true, save, review: true, diag: !restored });
    } else if (code === "BUSY") {
      setApplyPhase("applying");
      toast(t("The router is busy — another apply is still running."), "err");
      showApplyError({ title: t("The router is busy"), message: t("Another apply is still running on the router. Wait for it to finish, then retry."), retry: true, save, review: false });
      watchServerApply();
    } else if (code === "TIMEOUT" || isNetworkError(e)) {
      // The router did not answer. The apply may be running, finished, or never have arrived — the
      // status endpoint is the only honest source, so follow it rather than guess.
      setApplyPhase("applying");
      toast(t("The router did not answer; the apply may still be running."), "err");
      showApplyError({ title: t("No answer from the router"), message: t("The router did not answer; the apply may still be running."), retry: true, save, review: false });
      // When the server is done and the pending flag it owns has flipped, the apply went through
      // after all; otherwise the card (with Retry) stays — a lost answer is never turned into a claim.
      watchServerApply(() => { if (pendingBefore && !_backendPending) { hideApplyError(); setApplyPhase("applied", 3500); } });
    } else {
      // Anything else (a bare 500, an auth refusal, an unverifiable 200): the previous configuration
      // is still active as far as we know; say what the server said and offer to try again.
      setApplyPhase("failed");
      toast(t("Apply failed: {0}", msg), "err");
      showApplyError({ title: t("Apply failed"), message: msg, detail: data.detail, retry: true, save, review: true });
    }
    if (!timedOut && code !== "BUSY") { try { await refreshApplyState(); } catch (_) {} }
  } finally {
    clearInterval(stagePoll);
    applyInFlight = false;
    stop();
    if (btn) {
      btn.classList.remove("working");
      btn.removeAttribute("aria-busy");
      btn.removeAttribute("disabled");
      btn.textContent = label;
    }
    try { reflectDirty(); } catch (e) {} // restore the pending state of the button/banner
  }
}

/* ---------- fail-safe (Test) window ----------
 * "Test safely" applies without saving and arms the connectivity fail-safe: the router pings its
 * target every 15 s; healthy through the keep window → the config stays live (unsaved) until reboot;
 * unreachable for 45 s → automatic rollback (→ reboot as a last resort). The banner polls
 * GET /api/apply/status every 1.5 s and offers Keep & Save (POST /api/apply/confirm) and Roll back
 * (POST /api/apply/rollback). Terminal phases are announced as toasts once the window closes.
 */
let failsafeTimer = null;
function startFailsafeBanner() {
  if (failsafeTimer) clearInterval(failsafeTimer);
  const poll = async () => {
    let st;
    try { st = await api.get("/api/apply/status"); } catch (_) { return; } // a failing poll must not drop the banner — it holds the only controls the user has
    if (!st || typeof st !== "object") return;
    if (!st.pending) {
      hideFailsafeBanner();
      if (st.phase === "rolled_back") toast(t("Connectivity lost — config rolled back."), "err");
      else if (st.phase === "rollback_failed") toast(t("Connectivity lost AND the rollback failed — {0}", st.last_error || t("restore the config manually")), "err");
      else if (st.phase === "reboot") toast(t("Fail-safe couldn't restore connectivity (escalated to reboot)."), "err");
      else if (st.phase === "live_unsaved") toast(t("Config is live but not saved. Use Apply & Save to keep it after a reboot."), "info");
      refreshApplyState();
      return;
    }
    renderFailsafeBanner(st);
  };
  poll();
  failsafeTimer = setInterval(poll, 1500);
}
function hideFailsafeBanner() {
  const b = $("#failsafe-banner");
  if (!b) { if (failsafeTimer) { clearInterval(failsafeTimer); failsafeTimer = null; } return; }
  b.style.display = "none"; b.innerHTML = "";
  if (failsafeTimer) { clearInterval(failsafeTimer); failsafeTimer = null; }
}

/* ---------- DNS ---------- */
// The DNS plane is edited as a whole object and PUT to /api/dns on every change (staged in the store;
// the global Apply then regenerates + activates it). It is FAILOVER-AWARE: a resolver's detour is a
// failover group, so DNS rides the tunnel while a VPN tier is up (the ISP sees nothing) and falls to
// encrypted DoH over the raw WAN when every tier is down (the query stays encrypted — DNS never goes
// dark). See docs/DNS_SECTION.md in the development repository for the "hide while we can, degrade
// gracefully" model.
let dnsState = null;
let dnsRev = null;
const DNS_NET_TYPES = ["https", "tls", "quic", "h3", "udp", "tcp"];
const DNS_ENC_TYPES = ["https", "tls", "quic", "h3"];
const DNS_TYPE_LABEL = { https: "DoH (HTTPS)", tls: "DoT (TLS)", quic: "DoQ (QUIC)", h3: "DoH3", udp: "Plain (UDP)", tcp: "Plain (TCP)", local: "Local (device resolver)", fakeip: "FakeIP" };
const DNS_TYPE_BADGE = { https: "DoH", tls: "DoT", quic: "DoQ", h3: "DoH3", udp: "Do53", tcp: "Do53", local: "Local", fakeip: "FakeIP" };


// 11 function(s) for the dns page now live in web/dist/page-dns.js,
// loaded on demand by loadChunk(). See PAGES.dns.chunk.


async function dnsPut() {
  const r = await api.put("/api/dns", dnsState, dnsRev == null ? undefined : { "If-Match": String(dnsRev) });
  if (r && r.rev != null) dnsRev = r.rev;
  return r;
}

// orderControls renders the position number plus move-up/move-down for a list whose ORDER decides
// behaviour. sing-box takes the first matching rule and the generator emits them in array order, so
// position is not presentation — it is the rule's meaning. The lists used to show neither.
//
// `label` names the object in each button's accessible name, because "Move up" repeated down a list
// is the same defect the row actions had.
function orderControls(i, total, label, onMove) {
  const btn = (dir, glyph, word) => {
    const at = dir < 0 ? i === 0 : i === total - 1;
    const b = el("button", {
      class: "btn btn-sm ord-btn", type: "button",
      "aria-label": word + " " + label + " (position " + (i + 1) + " of " + total + ")",
      onclick: () => onMove(i, i + dir),
    }, glyph);
    if (at) b.setAttribute("disabled", "true"); // already at the end it would move to
    return b;
  };
  return el("div", { class: "ord" },
    el("span", { class: "ord-n", title: "Evaluation order — the first rule that matches wins" }, String(i + 1)),
    btn(-1, "↑", "Move up"),
    btn(+1, "↓", "Move down"));
}

// moveInArray returns a copy with the item at `from` placed at `to`. Out-of-range moves are a no-op
// rather than an error: the buttons at the ends are disabled, and a stray call must not corrupt order.
function moveInArray(arr, from, to) {
  if (to < 0 || to >= arr.length || from === to) return arr.slice();
  const out = arr.slice();
  const [item] = out.splice(from, 1);
  out.splice(to, 0, item);
  return out;
}

async function renderDNS(view) {
  await loadProfile();
  let resp;
  try { resp = await api.get("/api/dns"); }
  catch (e) { view.appendChild(el("div", { class: "card" }, el("div", { class: "hint" }, t("DNS API unavailable: ") + e.message))); return; }
  // When DNS is not yet managed the endpoint still returns a secure-default TEMPLATE (for the "Apply
  // secure defaults" prefill), but the page starts EMPTY so "not managed yet" isn't contradicted by a
  // list of resolvers that don't actually exist — the template is loaded on demand via ?template=1.
  const configured = !!(resp && resp.configured);
  // Unconfigured seed uses enabled:false so the "Enable DNS management" toggle reads OFF, matching the
  // "DNS is not managed yet" empty state (off = sing-box's default resolver). Enabling the toggle or
  // clicking "Secure defaults" (which replaces dnsState from the server template) turns management on.
  dnsState = (configured && resp && resp.dns) ? resp.dns : { enabled: false, servers: [], rules: [] };
  // The version this plane was read at. Every write echoes it back so the daemon can refuse a write
  // that was based on settings somebody else has since changed - the DNS plane is submitted whole,
  // so a blind write would erase the other change rather than conflict with it.
  dnsRev = (resp && resp.rev != null) ? resp.rev : null;
  dnsState.servers = dnsState.servers || [];
  dnsState.rules = dnsState.rules || [];

  view.appendChild(el("div", { class: "block-head" },
    el("div", {},
      el("div", { class: "desc" }, t("Encrypted, split, failover-aware DNS: hides your lookups from the ISP while a tunnel is up, and gracefully falls back to encrypted DoH over the raw WAN when every VPN is down — so DNS never goes dark."))),
    el("div", { class: "side" },
      dnsFilterBox(view),
      el("button", { class: "btn", title: t("Preview the generated sing-box dns block"), onclick: previewDNS }, t("Preview {0}", "dns{}")),
      el("button", { class: "btn btn-primary", title: t("One-click encrypted DoH via the tunnel + local for in-country, leak-proof"), onclick: applyDNSSecureDefaults }, t("Secure defaults")))));

  if (!configured) {
    view.appendChild(el("div", { class: "card" }, el("div", { class: "hint" },
      t("DNS is not managed by WayHop yet — sing-box uses its default resolver. Click “Secure defaults” for one-click encrypted, failover-aware DNS, or add resolvers manually."))));
  }

  // One read serves both the query path and the adopted-stack card. It is also what decides whether
  // the runtime half of the path can be stated at all: a null here is "not measured", never "clean".
  let nat = null;
  try { nat = await api.get("/api/dns/native"); } catch (_) { nat = null; }

  // The path leads the page. Everything below it is the controls that shape it, which is only worth
  // reading once you can see what you are shaping.
  if (configured || dnsState.servers.length) view.appendChild(dnsQueryPath(nat));

  // The router's OWN native DNS stack (dnsmasq + DoH), if WayHop is running on a router that has one —
  // a read-only "adopted" view so there's no hidden second config. Editing lands with native write-back.
  if (nat && nat.available && nat.native) view.appendChild(dnsNativeCard(nat));

  // Global toggles + strategy.
  const g = el("div", { class: "card" });
  g.appendChild(el("div", { class: "card-head" }, el("div", { class: "card-title" }, t("Settings"))));
  g.appendChild(dnsToggleRow(t("Enable DNS management"), "enabled", t("Emit a dns block. Off keeps sing-box's default resolver (today's behaviour).")));
  g.appendChild(dnsToggleRow(t("Leak protection (encrypted-only)"), "leak_proof", t("Reject plaintext resolvers and require an encrypted default — the ISP can never read your queries, even on the WAN fallback.")));
  // The page states, at the top of the query path, that a device with its own resolver walks past
  // every row below it — and until now could do nothing about it. These two are that answer, and they
  // are two clicks: the first catches plain DNS, the second makes a hardcoded ENCRYPTED resolver fall
  // back to plain DNS so the first one catches it too.
  g.appendChild(dnsToggleRow(t("Intercept clients' DNS"), "intercept",
    t("Answer every client's plain DNS from this router, whatever server they were configured with — so a device with a hardcoded 8.8.8.8 obeys the rules above instead of bypassing them.")));
  g.appendChild(dnsToggleRow(t("Break hardcoded encrypted resolvers"), "intercept_reject_encrypted",
    t("Refuse DoT and the well-known public DoH addresses (Cloudflare, Google, Quad9, OpenDNS, AdGuard, Yandex) so those clients fall back to plain DNS and are intercepted. DoH to any other host is ordinary HTTPS and cannot be caught."),
    { key: "intercept", reason: t("Turn on the row above first: on its own this refuses those resolvers and nothing catches the plain queries they fall back to.") }));
  g.appendChild(dnsToggleRow(t("FakeIP domain routing"), "fakeip", t("Synthetic IPs so domain rules match reliably. Requires gateway/TUN mode; ignored in fast/mixed mode.")));
  const strat = el("select", {}, ...["prefer_ipv4", "ipv4_only", "prefer_ipv6", "ipv6_only"].map(s => el("option", { value: s }, s)));
  strat.value = dnsState.strategy || "prefer_ipv4";
  strat.onchange = () => { dnsState.strategy = strat.value; saveDNS(t("strategy → {0}", strat.value)); };
  g.appendChild(el("div", { class: "field", style: "margin-top:14px;margin-bottom:0" }, el("label", {}, t("IP strategy")), strat,
    el("div", { class: "hint" }, t("ipv4_only suppresses AAAA — pick it when your tunnels are IPv4-only to stop v6 DNS leaks."))));
  view.appendChild(g);

  // Resolvers (with the default-resolver picker as a footer, so it's one coherent card).
  const sc = el("div", { class: "card" });
  sc.appendChild(el("div", { class: "card-head" },
    el("div", { class: "card-title" }, t("Resolvers")),
    el("div", { class: "acts" }, el("button", { class: "btn btn-sm", onclick: () => openDNSServer(null) }, t("+ Add resolver")))));
  if (!dnsState.servers.length) sc.appendChild(emptyState(t("No resolvers"), t("Add an encrypted resolver (DoH/DoT), or apply the secure defaults.")));
  else {
    dnsState.servers.forEach((s, i) => sc.appendChild(dnsServerRow(s, i)));
    const fin = el("select", {}, el("option", { value: "" }, t("(first resolver)")), ...dnsState.servers.map(s => el("option", { value: s.tag }, s.tag)));
    fin.value = dnsState.final || "";
    fin.onchange = () => { dnsState.final = fin.value; saveDNS(t("default → {0}", fin.value || t("first"))); };
    sc.appendChild(el("div", { class: "field", style: "margin-top:16px;margin-bottom:0" },
      el("label", {}, t("Default resolver (unmatched queries)")), fin,
      el("div", { class: "hint" }, t("Keep it encrypted for leak protection — a plaintext/local default would let a foreign lookup reach the ISP."))));
  }
  view.appendChild(sc);

  // The split-DNS rules used to have a card of their own here, listing the same rules with the same
  // targets the query path already draws. Two renderings of one thing is two places to read a
  // different answer, so the rules now live in the path and are edited there.

  view.appendChild(dnsLeakWidget());
}



function dnsRuleRow(r, i) {
  const via = r.server === "reject" ? el("span", { class: "pill err" }, t("block")) : el("span", { class: "pill" }, r.server);
  const parts = (r.rule_sets || []).map(x => nameOf(x) || x)
    .concat(r.domain_suffix || [], r.geosite || [], (r.query_type || []).map(q => "type:" + q));
  const match = parts.length ? parts.join(", ") : t("(no match)");
  return el("div", { class: "dns-rule" },
    // Serialize through dnsSaveChain for the reason the rule editor states: a bare PUT here
    // races a concurrent save. Rule ORDER is meaning - sing-box takes the first match - and
    // two quick arrow clicks sent two writes stamped with the same rev, so the second was
    // refused as stale and rolled back to a snapshot the first had already superseded: the
    // panel showed one order while the router enforced another. Mutating INSIDE the chain
    // operates on the latest state, and adopting r.dns keeps this path identical to every
    // other DNS write.
    orderControls(i, dnsState.rules.length, "DNS rule " + match, (from, to) => {
      dnsSaveChain = dnsSaveChain.then(async () => {
        const prev = dnsState.rules.slice();
        dnsState.rules = moveInArray(dnsState.rules, from, to);
        try { const r = await dnsPut(); if (r && r.dns) dnsState = r.dns; route(); }
        catch (e) { dnsState.rules = prev; dnsWriteFailed(e); }
      });
      return dnsSaveChain;
    }),
    // Match and destination are siblings, not nested, so the row is one grid line instead of two.
    // The old two-column grid held three children, which pushed the order controls onto a row of
    // their own and made every rule 113px tall — four rules were a quarter of the page.
    el("div", { class: "match" }, el("div", { class: "m" }, match)),
    el("div", { class: "via" }, "→", via),
    el("div", { class: "acts" },
      el("button", { class: "btn btn-sm", "aria-label": t("Edit") + " rule " + match, onclick: () => openDNSRule(i) }, t("Edit")),
      // Identity first, then by unique id (validateDNS rejects empty rule ids) — same stale-
      // closure hazard as dnsServerRow: a non-rerendering saveDNS reassigns dnsState, orphaning
      // the rule instances the rendered rows captured.
      el("button", { class: "btn btn-danger btn-sm", onclick: async () => { if (!await modalConfirm(t("Delete this DNS rule?"))) return; let idx = dnsState.rules.indexOf(r); if (idx < 0 && r.id) idx = dnsState.rules.findIndex(x => x && x.id === r.id); if (idx < 0) return; dnsState.rules.splice(idx, 1); saveDNS(t("rule ✕"), true); } , "aria-label": t("Delete") + " rule " + match }, t("Delete"))));
}

// dnsNativeCard renders the router's ADOPTED native DNS stack (read-only) — the resolvers the device
// actually serves, in tier order — so WayHop reflects the router's reality, not a hidden second config.
const DNS_TIER_LABEL = { 1: "via VPN", 2: "WAN-encrypted", 3: "geo-fallback" };
function dnsNativeCard(nat) {
  const nd = nat.native || {};
  const rows = nd.resolvers || [];
  const card = el("div", { class: "card" });
  card.appendChild(el("div", { class: "card-head" },
    el("div", { class: "card-title" }, t("Router's native DNS")),
    el("div", { class: "acts" },
      rows.length ? el("button", { class: "btn btn-sm", title: t("Show the uci/dnsmasq commands that would write this back to the router (not run automatically)"), onclick: () => openNativePlan(nat) }, t("Preview write-back")) : null,
      nd.strict_order ? el("span", { class: "pill muted" }, t("strict-order")) : null,
      el("span", { class: "pill ok" }, t("adopted") + " · " + (nat.platform || "")))));
  card.appendChild(el("div", { class: "hint", style: "margin-bottom:8px" },
    t("The DNS your router actually serves (dnsmasq + DoH). Preview the write-back to see the exact router commands; applying them is a manual, gated step.")));
  if (!rows.length) {
    card.appendChild(el("div", { class: "hint" }, t("No upstreams detected.")));
    return card;
  }
  // A read-only view of somebody else's stack, so it leads with what it establishes and discloses
  // the row-by-row detail. On the test AX3000T this card was 679px — the tallest thing on the page
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



// saveDNS PUTs the whole plane. On reject (a bad detour/rule/leak-proof violation) it toasts the
// precise 400 and re-renders from the persisted state, so a rejected local edit never lingers in the UI.
let dnsSaveChain = Promise.resolve();
// Serialize DNS saves: callers fire saveDNS without await, so two quick edits could otherwise PUT and
// reassign dnsState concurrently and clobber it. Chain saves so each PUT + reassign runs after the last.
function saveDNS(msg, rerender) {
  dnsSaveChain = dnsSaveChain.then(() => saveDNSNow(msg, rerender));
  return dnsSaveChain;
}
async function saveDNSNow(msg, rerender) {
  try {
    const r = await dnsPut();
    if (r && r.dns) dnsState = r.dns;
    state.profile.dns = dnsState;
    updateDirty();
    if (msg) toast(msg, "ok");
    if (rerender) route();
    return true;
  } catch (e) {
    toast((e.message || "").replace(/^STALE_CONFIG:\s*/, ""), "err");
    route();
    return false;
  }
}

// primaryDetourGuess mirrors the server's primaryDetour for the "Add resolver" default: the default
// route's outbound (usually the main failover group ⇒ failover-aware), else the first group, else Direct.
function primaryDetourGuess() {
  const def = (state.profile.rules || []).find(r => r.default && r.outbound && r.outbound !== "block");
  if (def) return def.outbound;
  if ((state.profile.groups || []).length) return state.profile.groups[0].id;
  return "direct";
}















// renderFailsafeBanner paints the window's current phase. Phase text is always carried by words
// (never colour alone) and every phase the fail-safe can report has copy here:
//   armed       — live, connectivity checked, countdown to "stays live (unsaved)"
//   unverified  — the check could not measure yet; the window is on hold, nothing is decided
//   degraded    — the check is failing; the router will roll back on its own unless it recovers
//   (rolled_back / rollback_failed / reboot / live_unsaved close the window → toasts in startFailsafeBanner)
let _failsafeBusy = false; // Keep/Roll back in flight — the poll must not repaint over a disabled control
function renderFailsafeBanner(st) {
  const b = $("#failsafe-banner");
  if (!b) return;
  const phase = st.phase || "armed";
  const degraded = phase === "degraded";
  const unverified = phase === "unverified";
  const left = Number(st.seconds_left) > 0 ? Number(st.seconds_left) : 0;
  let title, detail;
  if (degraded) {
    title = t("⚠ Connectivity problem — config will roll back");
    detail = t("The router lost connectivity on the test configuration; it rolls back automatically unless the connection recovers.");
  } else if (unverified) {
    title = t("Config applied live (not saved)");
    detail = t("Checking connectivity — could not measure yet. The window is on hold until a check succeeds.");
  } else {
    title = t("Config applied live (not saved)");
    detail = left
      ? t("watching connectivity {0}s · auto-rollback if internet drops", left)
      : t("Apply live — not saved, reverts on reboot or if connectivity drops");
  }
  if (st.last_error) detail += " · " + t("last error: {0}", st.last_error);
  const keep = el("button", { class: "btn btn-primary btn-sm", type: "button", onclick: failsafeKeep }, t("Keep & Save"));
  const roll = el("button", { class: "btn btn-danger btn-sm", type: "button", onclick: failsafeRollback }, t("Roll back"));
  if (_failsafeBusy) { keep.disabled = true; roll.disabled = true; }
  b.style.display = "block"; b.innerHTML = "";
  b.appendChild(el("div", { class: "card fs-card" + (degraded ? " fs-degraded" : unverified ? " fs-unverified" : " fs-armed") },
    el("div", { class: "row-between" },
      el("div", { class: "fs-text" },
        el("b", { class: "fs-title" }, title),
        el("span", { class: "hint fs-detail" }, detail)),
      el("div", { class: "acts" }, keep, roll))));
}
async function failsafeKeep() {
  if (_failsafeBusy) return;
  _failsafeBusy = true;
  try {
    const r = await api.post("/api/apply/confirm", {});
    if (!r || r.committed !== true) throw new Error(t("Apply result could not be verified."));
    toast(t("Kept & committed"), "ok");
    hideFailsafeBanner();
    setApplyPhase("applied", 3500);
  } catch (e) {
    // The window stays open and the banner stays up: a failed Keep must not read as a kept one.
    toast(t("Could not keep the configuration: {0}", (e && e.message) || ""), "err");
  } finally { _failsafeBusy = false; refreshApplyState(); }
}
async function failsafeRollback() {
  if (_failsafeBusy) return;
  _failsafeBusy = true;
  try {
    const r = await api.post("/api/apply/rollback", {});
    if (!r || r.rolled_back !== true) throw new Error((r && r.error) || t("The router did not confirm the rollback."));
    toast(t("Rolled back to previous config"), "info");
    hideFailsafeBanner();
  } catch (e) { toast(t("Rollback failed: {0}", (e && e.message) || ""), "err"); }
  // A rollback reverts the applied revision on the backend, so the saved changes are NO LONGER active —
  // resync so the persistent Apply banner correctly flips back to "pending" instead of staying stale.
  finally { _failsafeBusy = false; refreshApplyState(); }
}
// Re-surface the window controls if a Test window is still open — otherwise a page reload (or
// opening the panel from another device) mid-window hides the only controls the user has (Keep &
// Save / Roll back). Also picks up an Apply that is running on the server (in_progress) so a
// reloaded page shows its progress. No-op once the banner is already shown (it self-polls), so
// this is cheap to call often.
async function checkFailsafe() {
  if (failsafeTimer) return;
  try {
    const as = await api.get("/api/apply/status");
    if (!as) return;
    if (as.pending) startFailsafeBanner();
    else if (as.in_progress && !applyInFlight) watchServerApply();
  } catch (_) {}
}

/* ---------- per-endpoint health (live latency from the Clash API) ---------- */
let healthMap = {};
let pluginMap = {};
let watchdog = null; // last /api/watchdog snapshot, shared with the dashboard Engine tile
let speedResults = {}; // last speed-test per key (endpoint id, or "__global"); session-only
let healthInFlight = false;
// Run-state badge for engine-plugin endpoints (amneziawg / olcrtc). The protocol
// type itself is shown by the .proto chip; this conveys running / needs-binary only.
function pluginBadge(e) {
  if (!e.engine || e.engine === "singbox") return null;
  const span = el("span", { class: "badge", "data-plugin": e.id });
  paintPluginBadge(span, e);
  return span;
}
function paintPluginBadge(span, e) {
  const st = pluginMap[e.id];
  if (!st) { span.style.display = "none"; return; } // no run-state yet (not applied)
  span.style.display = "";
  if (st.running) { span.textContent = t("running ✓"); span.style.color = "var(--ok)"; span.style.background = "var(--ok-tint)"; }
  else if (st.needs_binary) { span.textContent = t("needs binary"); span.style.color = "var(--warn)"; span.style.background = "var(--warn-tint)"; }
  else { span.textContent = e.engine; span.style.color = "var(--ink-2)"; span.style.background = "var(--card-2)"; }
}
// Dashboard "Engine" tile: surface the sing-box supervisor's HEALTH, not just a restart
// count — a crash-loop (backoff window active) or a down-but-supervised core now reads
// loud (color + icon shape + word, WCAG 1.4.1) instead of looking healthy.
function shortErr(s) { s = String(s || ""); return s.length > 42 ? s.slice(0, 41) + "…" : s; }
function paintEngineTile(node) {
  const v = node.querySelector(".v"); if (!v) return;
  const h = state.health || {}, wd = watchdog || {}, sb = h.singbox || {};
  // sing-box is the SUPPLEMENTARY proxy engine (VLESS/Trojan/Hy2/… family), NOT the main VPN — the
  // native kernel tunnels carry the rest. Two health truths override the watchdog's raw process-handle
  // flag so the tile never cries a scary red "Down" while the service actually works:
  //  • running: sb.running already includes a Clash-API probe, so an init-managed core WayHop didn't
  //    spawn (handle nil ⇒ wd.alive false) still reads UP — no false "Down" while it demonstrably serves.
  //  • nativeOnly: the live profile needs no proxy engine at all (fast mode / kernel plane) — an absent
  //    core is BY DESIGN. Red "Down" is reserved for the genuine case: needed + installed + not running.
  const running = wd.alive || sb.running;
  const nativeOnly = isNativeOnly(h);
  let word, ico, color, sub;
  if (h.demo) { word = "Demo"; ico = "●"; color = "var(--accent)"; sub = "v" + (h.version || ""); }
  else if (running) { word = "Running"; ico = "✓"; color = "var(--ok)"; sub = wd.restarts ? (tn("↻ {0} restart|↻ {0} restarts", wd.restarts) + (wd.last_error ? t(" · last: {0}", shortErr(wd.last_error)) : "")) : (wd.supervised ? t("supervised") : "v" + (h.version || "")); }
  else if (nativeOnly) { word = "Native"; ico = "○"; color = "var(--ink-2)"; sub = t("not required"); }
  else if (!sb.available) { word = "Idle"; ico = "○"; color = "var(--ink-2)"; sub = t("sing-box absent"); }
  else if (wd.supervised) { word = "Down"; ico = "⚠"; color = "var(--err)"; sub = t("auto-restarting") + (wd.backoff_ms ? " · backoff " + Math.round(wd.backoff_ms / 1000) + "s" : ""); }
  else if (wd.backoff_ms) { word = "Crash-loop"; ico = "↻"; color = "var(--warn)"; sub = (wd.failed_restarts
      ? (wd.failed_restarts >= (wd.restarts || 0)
          ? "none of " + (wd.restarts || 0) + " restart attempts succeeded"
          : (wd.restarts || 0) + " restart attempts, " + wd.failed_restarts + " failed")
      : t("{0} restarts · backoff {1}s", wd.restarts || 0, Math.round(wd.backoff_ms / 1000))); }
  else { word = "Idle"; ico = "○"; color = "var(--ink-2)"; sub = t("sing-box available"); }
  v.innerHTML = "";
  v.appendChild(el("span", { style: "color:" + color }, ico + " " + t(word)));
  if (sub) v.appendChild(el("small", {}, "  " + sub));
  node.title = wd.last_error ? "Last error: " + wd.last_error : "";
}
// Sub-line under a connection name: protocol type chip + plugin run-state + address.
function subMeta(e) {
  const sub = el("div", { class: "sub" });
  // External endpoints bind an existing kernel interface (e.g. an AmneziaWG/WireGuard
  // tunnel set up outside WayHop) — they have no protocol/server of their own, so
  // showing an empty proto badge + ":0" reads as a broken/mislabeled (vless) entry.
  // Render the bound interface instead, which is what actually carries the traffic.
  if (e.engine === "external") {
    const iface = (e.params && e.params.interface) || "?";
    const epip = e.params && e.params.endpoint_ip;
    sub.appendChild(el("span", { class: "badge proto external" }, t("OS tunnel")));
    sub.appendChild(el("span", { class: "addr" }, "⇄ " + iface + (epip ? " → " + epip : "")));
    return sub;
  }
  sub.appendChild(el("span", { class: "badge proto" }, e.protocol));
  const pb = pluginBadge(e);
  if (pb) sub.appendChild(pb);
  sub.appendChild(el("span", { class: "addr" }, e.server + ":" + e.port));
  return sub;
}
function pillFor(e) {
  const span = el("span", { class: "pill", "data-health": e.id, style: "margin-left:8px" });
  paintPill(span, e);
  return span;
}
function paintPill(span, e) {
  span.innerHTML = "";
  span.title = "";
  span.removeAttribute("role"); span.removeAttribute("aria-label"); // reset — the span is reused across repaints
  if (!e.enabled) { span.className = "pill muted pill--dot"; span.title = t("Disabled"); span.setAttribute("role", "img"); span.setAttribute("aria-label", t("Disabled")); span.append(el("span", { class: "dot" })); return; }
  const h = healthMap[e.id];
  // Healthy/idle states show only a status light; the latency value lives in the
  // stats line under the name. "Down" keeps its loud label (pairs with the cause line).
  if (h && h.state === "down") {
    span.className = "pill err";
    span.append(el("span", { class: "dot" }), t("Down")); // visible text — already announced to AT
    return;
  }
  // The remaining states (alive-fast / alive-slow / idle) are otherwise a bare colored dot —
  // convey them to assistive tech via role=img + aria-label, not colour alone (WCAG 1.4.1/1.1.1).
  let cls = "muted", label = t("not yet checked");
  if (h && h.state === "alive") { cls = h.latency_ms >= 600 ? "warn" : "ok"; span.title = h.latency_ms + " ms"; label = t("alive") + " · " + h.latency_ms + " ms"; }
  span.className = "pill " + cls + " pill--dot";
  span.setAttribute("role", "img");
  span.setAttribute("aria-label", label);
  span.append(el("span", { class: "dot" }));
}
function fmtUptime(s) {
  if (!s) return "0s";
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d) return d + "d " + h + "h";
  if (h) return h + "h " + m + "m";
  if (m) return m + "m";
  return s + "s";
}
function statsLine(e) {
  const div = el("div", { class: "stats", "data-stats": e.id });
  paintStats(div, e);
  return div;
}
function fmtBytes(b) {
  if (!b) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0, n = b;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + " " + u[i];
}
function paintStats(div, e) {
  const h = healthMap[e.id];
  div.innerHTML = "";
  if (!h || !h.probes) {
    // No probe yet: show a "Gathering data" hint for enabled tunnels (not a blank line),
    // nothing for disabled ones. Fills in on the next health poll.
    if (e.enabled) div.appendChild(el("span", { class: "stat", style: "color:var(--ink-2)" }, t("checking…")));
    return;
  }
  // Each stat is a nowrap "chip" (muted label + emphasized value) so a value never
  // splits across a line — the old inline flow broke "322.3 MB / transferred" and
  // "12 / restarts" mid-phrase once a row had restarts. Chips flex-wrap as whole units.
  const part = (label, val) => {
    const s = el("span", { class: "stat" });
    if (label) s.append(label + " ");
    s.appendChild(el("b", {}, val));
    return s;
  };
  const parts = [];
  const ping = h.avg_latency_ms || h.latency_ms;
  if (h.state === "alive" && ping) parts.push(part("ping", ping + " ms"));
  if (h.state !== "unknown") parts.push(part("uptime", h.success_rate + "%"));
  // External (kernel-iface) endpoints show their REAL iface throughput inline via .conn-rate
  // (paintIfaceList from /api/system), so skip the Clash-attributed rate here — for an external it
  // is ~0 anyway (Clash can't attribute kernel-iface traffic) and showing both reads as a duplicate.
  if ((h.rate_down_bps || h.rate_up_bps) && e.engine !== "external") parts.push(part("", "↓ " + fmtRate(h.rate_down_bps) + "  ↑ " + fmtRate(h.rate_up_bps)));
  if (h.bytes_down || h.bytes_up) parts.push(part("", t("{0} transferred", fmtBytes((h.bytes_down || 0) + (h.bytes_up || 0)))));
  if (h.reconnects) parts.push(part("", tn("{0} restart|{0} restarts", h.reconnects)));
  if (h.uptime_s) parts.push(part("up", fmtUptime(h.uptime_s)));
  // Separator trails INSIDE each chip (except the last) so it stays glued to its
  // value and a wrapped line never begins with a dangling "·".
  parts.forEach((p, i) => {
    if (i < parts.length - 1) p.appendChild(el("span", { class: "sep" }, "·"));
    div.appendChild(p);
  });
}
// R6: inline failure cause under a tunnel's name when it's down.
function causeLine(e) {
  const d = el("div", { class: "hint", "data-cause": e.id, style: "margin-top:4px" });
  paintCause(d, e);
  return d;
}
function paintCause(d, e) {
  const h = healthMap[e.id];
  d.innerHTML = "";
  if (!h || h.state !== "down") return;
  const head = h.handshake === "failed" ? t("Handshake not received — ") : t("Down — ");
  d.appendChild(el("div", { style: "color:var(--err)" }, "⚠ " + head + (h.cause || "no response")));
  // Show the suggested fix inline (it used to hide behind a "details" toast link) so a
  // down tunnel reads as a one-glance diagnostic with actionable guidance right there.
  if (h.cause_fix) d.appendChild(el("div", { class: "cause-fix" }, "↳ " + h.cause_fix));
}
// refreshPills repaints on every ~5 s health tick. The set of [data-*] elements only
// changes when the page DOM is rebuilt (route() bumps pillGen), so the six full-tree
// querySelectorAll scans are cached here and reused across ticks — rebuilt lazily only
// when the generation changes. Behavior is identical; just no repeated DOM scanning.
let pillGen = 0;
let routeGen = 0; // bumped per navigation; a stale render whose gen != routeGen is discarded (anti render-race)
let pillCacheGen = -1;
let pillCache = null;
function pillNodes() {
  if (pillCacheGen === pillGen && pillCache) return pillCache;
  const c = {
    health: document.querySelectorAll("[data-health]"),
    stats: document.querySelectorAll("[data-stats]"),
    cause: document.querySelectorAll("[data-cause]"),
    plugin: document.querySelectorAll("[data-plugin]"),
    engine: document.querySelectorAll("[data-engine]"),
  };
  // Memoize only a NON-EMPTY reading. route() bumps pillGen and empties #view BEFORE it awaits the
  // render, so every health tick that lands in that window — the window is a network round trip
  // wide, and the tick is every 5 s — used to pin five empty NodeLists to this generation. Nothing
  // cleared them until the next navigation, so the pills, per-tunnel rates and cause lines simply
  // stopped updating on a page the operator was looking at. Measured on the router: the cache held
  // 0 exits while the DOM had 6. The same window reopens for anything that appends its first pill
  // after the render resolves (a card that fills from its own fetch).
  //
  // The cost of not caching is five querySelectorAll every 5 s on a page that genuinely has no
  // pills — which is the case where the scans are cheapest.
  if (c.health.length || c.stats.length || c.cause.length || c.plugin.length || c.engine.length) {
    pillCache = c;
    pillCacheGen = pillGen;
  }
  return c;
}
function refreshPills(sys) {
  const c = pillNodes();
  c.health.forEach(span => {
    const e = findEndpoint(span.getAttribute("data-health"));
    if (e) paintPill(span, e);
  });
  c.stats.forEach(div => {
    const e = findEndpoint(div.getAttribute("data-stats"));
    if (e) paintStats(div, e);
  });
  c.cause.forEach(div => {
    const e = findEndpoint(div.getAttribute("data-cause"));
    if (e) paintCause(div, e);
  });
  c.plugin.forEach(span => {
    const e = findEndpoint(span.getAttribute("data-plugin"));
    if (e) paintPluginBadge(span, e);
  });
  c.engine.forEach(t => paintEngineTile(t));
  paintHero();
  paintConnections(); // live-refresh the connections table (no-op off the dashboard)
  repaintExits();     // …and the exits list, whose rows carry the same health (no-op off Connections)
  repaintPage();      // …and whatever the page on screen registered as its own live part
  paintSystem(sys);   // live-refresh RAM/temp + throughput; reuses the batched sample when given
}

// 15 function(s) for the diagnostics page now live in web/dist/page-diagnostics.js,
// loaded on demand by loadChunk(). See PAGES.diagnostics.chunk.

async function runEndpointSpeedtest(e, btn, out) {
  const label = btn.textContent;
  btn.setAttribute("disabled", "true"); btn.textContent = "…";
  if (out) { out.textContent = "testing…"; out.style.color = "var(--ink-2)"; }
  try {
    const r = await api.post("/api/speedtest", { id: e.id, bytes: 10000000 });
    const txt = "↓ " + r.down_mbps + (r.up_mbps ? "  ↑ " + r.up_mbps : "") + " Mbps" + (r.pinned ? "" : " " + t("(active route)"));
    speedResults[e.id] = { text: txt, ts: Date.now(), ok: true };
    if (out) { out.textContent = txt; out.style.color = "var(--ok)"; } else toast((e.name || e.id) + ": " + txt, "ok");
  } catch (err) { speedResults[e.id] = { text: t("failed"), ts: Date.now(), ok: false }; if (out) { out.textContent = t("failed"); out.style.color = "var(--err)"; } toast(t("Speedtest: {0}", err.message), "err"); }
  finally { btn.removeAttribute("disabled"); btn.textContent = label; }
}
// When the last successful /api/health/endpoints read landed. Separate from the reconnect banner
// on purpose: the banner answers "is the daemon reachable", this answers "is what you are looking
// at still being confirmed". A daemon replying 500 is reachable and useless, and only this catches it.
let lastHealthOK = 0;
const HEALTH_STALE_MS = 12000; // ~2.5 poll cycles, so a single failed read is not an alarm

// markHealthStale states that the live states on screen have stopped being refreshed. It does not
// hide or reset them — they were true when they arrived — it stops them reading as current.
function markHealthStale(stale) {
  document.body.toggleAttribute("data-health-stale", !!stale);
  let note = document.getElementById("health-stale");
  if (!stale) { if (note) note.remove(); return; }
  if (note) return;
  note = el("div", { class: "health-stale", id: "health-stale", role: "status" },
    "The router stopped answering health checks. The states shown are the last ones confirmed.");
  const bar = document.querySelector(".topbar");
  if (bar && bar.parentNode) bar.parentNode.insertBefore(note, bar.nextSibling);
  else document.body.insertBefore(note, document.body.firstChild);
}

async function pollHealth() {
  if (healthInFlight) return;
  healthInFlight = true;
  try {
    // Fetch the independent dashboard feeds concurrently — serial awaits stacked round-trips
    // of latency on every 5s poll, which is felt on a high-latency router link. plugins/watchdog/
    // system are best-effort (null on failure); only the endpoints feed drives the reconnect
    // banner. /api/system is batched here so the system strip refreshes in the SAME round-trip
    // instead of a 4th one stacked after this poll inside paintSystem().
    const [r, pl, wd, sys] = await Promise.all([
      api.get("/api/health/endpoints"),
      api.get("/api/plugins").catch(() => null),
      api.get("/api/watchdog").catch(() => null),
      api.get("/api/system").catch(() => null),
    ]);
    healthMap = {};
    (r || []).forEach(h => { healthMap[h.id] = h; });
    if (pl) { pluginMap = {}; pl.forEach(p => pluginMap[p.id] = p); }
    if (wd) watchdog = wd;
    lastHealthOK = Date.now();
    markHealthStale(false);
    refreshPills(sys);
  } catch (e) {
    // A daemon that ANSWERS but answers 500 is not a network error, so the reconnect banner
    // below never fires — and every "alive"/"down" pill, exit tile and Failover card kept
    // asserting its last state as current. Measured: pills unchanged after 22 s of 500s with
    // nothing on screen to say the state had stopped being confirmed.
    if (lastHealthOK && Date.now() - lastHealthOK > HEALTH_STALE_MS) markHealthStale(true);
    // The dashboard polls every 5s. If the daemon went down while the user is just
    // SITTING on the dashboard (not navigating, so route()'s catch never fires), the
    // stats would silently freeze — surface the same auto-reconnect banner instead.
    if (isNetworkError(e)) showReconnect();
  } finally { healthInFlight = false; }
}
async function testEndpoint(e, btn) {
  if (btn && btn.hasAttribute("disabled")) return; // guard against repeated concurrent probes
  const label = btn ? btn.textContent : "";
  if (btn) { btn.setAttribute("disabled", "true"); btn.textContent = t("Testing…"); }
  try {
    const h = await api.post("/api/health/test/" + encodeURIComponent(e.id), {});
    if (h && h.id) { healthMap[h.id] = h; refreshPills(); toast((e.name || e.id) + ": " + (h.state === "alive" ? h.latency_ms + " ms" : h.state), h.state === "alive" ? "ok" : h.state === "down" ? "err" : "info"); }
  } catch (err) { toast(err.message, "err"); }
  finally { if (btn) { btn.removeAttribute("disabled"); btn.textContent = label; } }
}


/* ---------- Updater (engine version manager) ---------- */
// 22 function(s) and the page's module state for the updater page now live in
// web/dist/page-updater.js, loaded on demand by loadChunk(). See PAGES.updater.chunk.
//
// renderUpdater stays here because PAGES stores the function VALUE when app.js runs, which is before
// any chunk exists. It runs only after route() has awaited loadChunk("page-updater"), so updRows,
// updAdvRows and paintUpdVerdict below are defined by the time this touches them.

async function renderUpdater(view) {
  updRows = new Map();
  updAdvRows = new Map();
  const sweepBtn = el("button", { class: "btn btn-primary", title: t("Check every component this router actually uses"), onclick: ev => updSweep(ev.currentTarget) }, t("Check updates"));
  const side = el("div", { class: "side" }, sweepBtn);
  view.appendChild(el("div", { class: "block-head" },
    el("div", {},
      el("div", { class: "desc" }, t("Optional engines. WayHop routes with the kernel and this router's own tunnels; a component here is needed only for a protocol the router cannot carry itself. Nothing installed is the normal state."))),
    side));

  // Where an install would land, and whether there is room — BEFORE any Install button is pressed.
  // On a live Keenetic that is a 7.3 GB USB stick; on OpenWrt the same button writes to the
  // internal overlay, which is routinely under 10 MB free and can leave the router unbootable when
  // filled. A page that offers to install without naming the target is asking them to gamble.
  view.appendChild(installTargetCard());

  const verdict = el("div", { class: "upd-verdict muted", id: "upd-verdict" },
    el("div", { class: "upd-verdict-w" }, t("checking…")));
  view.appendChild(verdict);

  const table = el("div", { class: "card upd-table" });
  table.appendChild(el("div", { class: "upd-head" },
    el("span", {}, t("Component")),
    el("span", {}, t("Installed")),
    el("span", {}, t("Latest")),
    el("span", {}, t("State")),
    el("span", {}, "")));
  view.appendChild(table);

  // WayHop's own row leads, and fills asynchronously so a slow GitHub check never blocks the page.
  table.appendChild(selfUpdateRow());

  let data;
  try { data = await api.get("/api/updater/engines"); }
  catch (e) { renderError(view, e); return; }
  const mirrorCount = (data.mirrors || []).filter(Boolean).length;
  const engines = data.engines || [];
  const pmKind = data.package_manager || "";
  if (pmKind) {
    side.insertBefore(el("button", { class: "btn", onclick: ev => updRefreshPackageLists(ev.currentTarget, pmKind) },
      t("Refresh package lists")), sweepBtn);
  }
  // Which rows belong here is componentsToShow's decision (page-updater.js): rows carry buttons, so
  // only what this page may actually install gets one. What the kernel or the package manager already
  // carries is stated below the table instead, as prose with nothing to click.
  componentsToShow(engines).forEach(e => table.appendChild(engineRow(e, pmKind)));
  const carried = kernelCarriedNote(engines);
  if (carried) view.appendChild(carried);

  view.appendChild(el("div", { class: "hint upd-foot" },
    t("router arch: {0}", data.arch || "?") + " · " + (mirrorCount ? tn("{0} mirror|{0} mirrors", mirrorCount) : t("direct"))));

  paintUpdVerdict();
}


/* ---------- Diagnostics (log error knowledgebase) ---------- */
// Crash-restart supervisor state (M10 watchdog).
/* ---------- Health battery: one-click "Run all checks" ----------
   The headline of Diagnostics: one button runs a verdict-first battery composed from
   existing endpoints (watchdog/health/netdiag/exit-ip/system/diagnostics) + the
   server-side /api/healthcheck (clock skew + IPv6 leak the browser can't probe).
   Results live in state.hbat so they survive tab navigation; nothing runs until the
   family clicks Run (router-light). Worst row drives the banner; FAIL rows auto-expand. */
const HC_ORDER = ["core", "internet", "tunnels", "censored", "exit", "endpoint_reach", "time", "ipv6", "dns", "offload", "pbr_kernel", "system", "log"];
// L marks a translatable literal that is NOT translated where it is written.
//
// check-i18n decides which strings the UI uses by matching translator calls with a literal argument
// (the call shape is deliberately not spelled out here: the scanner cannot tell code from comment, so
// writing one in prose registers a phantom string — this comment did exactly that once, and the gate
// dutifully demanded fifteen translations of an ellipsis). A table of labels cannot call the
// translator where it is declared: the map is built at module load, before the language is
// known, so translating there would freeze whichever language happened to be current. These labels
// go through t() at RENDER instead — see healthRowEl — and the literal never appears inside a t(…)
// call syntactically, so the gate could not see a single one of the thirteen. Adding the renamed
// "Encrypted DNS (DoH)" to the pending list therefore FAILED the gate, reporting a string that is
// plainly on screen as one the UI no longer uses (AUD-199).
//
// L is the identity function. It changes nothing at runtime and makes the literal scannable, so a
// label can be recorded as awaiting translation like every other string in the panel.
function L(s) { return s; }

const HC_LABEL = {
  core: L("Proxy core"), internet: L("Internet works"), tunnels: L("VPN tunnels healthy"),
  censored: L("Blocked sites reachable"), exit: L("Exit IP"), endpoint_reach: L("VPN servers reachable"),
  // "DNS is private" until the daemon was asked what it measured: three outbound HTTPS calls to
  // public DoH providers, and nothing about the router's own resolvers. Reachability, labelled as
  // privacy. The row now states the reachability and separately reports a plaintext upstream when
  // there is one — and this label has to match, because it OVERRIDES the server's.
  time: L("Router clock is correct"), ipv6: L("No IPv6 leak"), dns: L("Encrypted DNS (DoH)"),
  offload: L("Flow offload"), pbr_kernel: L("Kernel routing (PBR)"), system: L("Router resources"), log: L("No engine errors"),
};
// Most diagnostic labels are UI copy, but IPv6 is measurement-dependent: the server deliberately
// returns a neutral title for warn/fail and the reassuring title only after a proven pass. A static
// override here previously rendered "No IPv6 leak" over an UNKNOWN result.
function hcLabel(id, row) {
  if ((id === "ipv6" || id === "log") && row && row.status !== "pass" && row.label) return row.label;
  return HC_LABEL[id] || (row && row.label) || id;
}
// hcIds is every check that has a result: HC_ORDER first, for the reading order the page was designed
// around, then anything else the daemon returned.
//
// The Diagnostics page iterated HC_ORDER alone — for the rows, for the verdict and for the copied
// report — while the fetch stored EVERY id the daemon sent. Measured on a live own AX3000T:
// thirteen rows returned and SEVEN dropped, among them `dns-bypass: warn — 1 client(s) may be
// bypassing the router's DNS`. The daemon computed that warning and nobody ever saw it. Also dropped:
// disk-space, whose fail reads "config applies and updates will fail", and singbox-build, whose fail
// names endpoints that cannot apply — with "Everything's working" over the top.
//
// A fixed list is the wrong shape for a set the SERVER decides. A backend check added later now
// appears by itself, which is what stops this recurring.
//
// It stays here, beside HC_ORDER and HC_LABEL, because the id list is shared vocabulary: the
// Diagnostics chunk and anything else that reads a battery result both name checks through it.
// The checks themselves, the report builder and the renderer moved into page-diagnostics.js —
// they are reachable only from that page, and the initial payload had run out of room.
function hcIds(res) {
  const seen = new Set();
  const out = [];
  for (const id of HC_ORDER) { if (!seen.has(id)) { seen.add(id); out.push(id); } }
  for (const id of Object.keys(res || {})) { if (!seen.has(id)) { seen.add(id); out.push(id); } }
  return out;
}
const HC_DEEP = { connections: ["#connections", "Open Connections"], routing: ["#routing", "Open Routing"] };

// copyText copies to the clipboard with graceful degradation for the panel's real
// deployment: it is served over plain HTTP on a LAN IP (e.g. http://192.168.50.1:8088),
// which is NOT a secure context, so navigator.clipboard is undefined. Chain:
// async Clipboard API → execCommand("copy") → a manual-copy modal (pre-selected
// textarea) so the user can always get the text out (Ctrl/Cmd+C) instead of a dead end.
function copyText(str) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    // Start in a promise so a browser/extension that throws synchronously is treated exactly like a
    // rejected write: no optimistic success toast, and the plain-HTTP-safe fallbacks still run.
    return Promise.resolve().then(() => navigator.clipboard.writeText(str)).then(
      () => { toast(t("Copied"), "ok"); return true; },
      () => execCopy(str));
  }
  return Promise.resolve(execCopy(str));
}

// execCopy and copyManualModal are the rest of that chain, and they live HERE rather than in a route
// chunk for the reason the comment above gives: on the router the panel is not a secure context, so
// navigator.clipboard is undefined and this fallback is not the rare path — it is the only path.
// They were declared in page-connections.js, which loads only when Connections is first opened, so
// every Copy control on a page reached without going there first threw `ReferenceError: execCopy is
// not defined` and did nothing visible. Diagnostics has four of them, including "Copy report".
function execCopy(str) {
  let ta = null;
  try {
    ta = el("textarea", { style: "position:fixed;top:-1000px;opacity:0" });
    ta.value = str;
    document.body.appendChild(ta);
    ta.focus(); ta.select();
    const ok = document.execCommand("copy");
    if (ok) { toast(t("Copied"), "ok"); return true; }
  } catch (_) { /* fall through to the manual modal */ }
  finally {
    // Extensions and old embedded browsers can throw from focus/select/execCommand. Never leave the
    // hidden textarea attached when that happens.
    if (ta && ta.parentNode) ta.parentNode.removeChild(ta);
  }
  copyManualModal(str);
  return false;
}

function copyManualModal(str) {
  const ta = el("textarea", { readonly: "readonly", "aria-label": t("Text to copy"), style: "width:100%;min-height:160px;font-family:ui-monospace,Consolas,monospace;font-size:12px;line-height:1.5" });
  ta.value = str;
  modal({
    title: t("Copy manually"),
    body: el("div", {},
      el("div", { class: "hint", style: "margin-bottom:8px" }, copyBlockedReason()),
      ta),
  });
  setTimeout(() => { ta.focus(); ta.select(); }, 60);
}

// copyBlockedReason names why the copy did not happen, rather than asserting the commonest cause.
//
// This dialog blamed plain HTTP unconditionally. Over the SSH tunnel both the operator and this
// project use, the panel is served from 127.0.0.1, which the browser DOES treat as a secure context:
// measured with the dialog open, isSecureContext true and navigator.clipboard present, while the real
// refusal came from the page not being focused. Telling that user to fix the scheme sends them to
// re-terminate TLS over a problem a click would solve, and it is the wrong sentence for a denied
// clipboard permission too. Only one of these three is about HTTP, so only that one says HTTP.
function copyBlockedReason() {
  if (!window.isSecureContext || !(navigator.clipboard && navigator.clipboard.writeText)) {
    return t("Automatic copy is blocked (the panel runs over plain HTTP, not a secure context). Select all and press Ctrl/Cmd+C.");
  }
  if (!document.hasFocus()) {
    return t("Automatic copy needs this window focused. Click the text below, then press Ctrl/Cmd+C.");
  }
  return t("The browser refused the copy (clipboard permission). Select all and press Ctrl/Cmd+C.");
}



// ── Activity ribbon ───────────────────────────────────────────────────────────────────────────
// One row of minutes, newest on the right, with the router's own events marked on the same axis.
//
// The dashboard could show throughput right now and throughput for the last seven minutes, and
// nothing else. "The VPN dropped last night" was unanswerable, and so was "was anything even using
// this router while I was out". The ribbon answers both, and the event marks put the two together:
// a gap in activity beside a switch mark is a different story from a gap on its own.
//
// Two honesty constraints shape it, both inherited from the data rather than chosen:
//
//   It is ACTIVITY, not WAN throughput. The counters sum every interface, and a packet crossing the
//   router is counted on the LAN port and again on the WAN port. Labelling that "throughput" would
//   overstate the link by roughly double, so it is labelled what it is.
//   It covers since the daemon started, up to a day — the buckets live in RAM so the router's flash
//   is never written. An empty ribbon on a box that has been up for a week means a restart, not a
//   quiet week, and the caption says so rather than letting the emptiness speak.
function activityRibbonCard() {
  const card = el("div", { class: "card ribbon" });
  card.appendChild(el("div", { class: "card-head" },
    el("div", { class: "card-title" }, t("Recent activity")),
    el("div", { class: "hint ribbon-scale" }, t("reading…"))));
  const body = el("div", { class: "ribbon-body" });
  card.appendChild(body);
  (async () => {
    let day = null, evs = null;
    try { day = await api.get("/api/system/day"); } catch (_) { day = null; }
    try { evs = await api.get("/api/failover/events?limit=40"); } catch (_) { evs = null; }
    const scale = card.querySelector(".ribbon-scale");
    body.innerHTML = "";
    if (!day || !day.known) {
      scale.textContent = "";
      body.appendChild(el("div", { class: "hint" },
        t("WayHop could not read the activity history, so nothing is drawn rather than an empty hour.")));
      return;
    }
    const buckets = day.buckets || [];
    if (!buckets.length) {
      scale.textContent = "";
      body.appendChild(el("div", { class: "hint" },
        t("No minutes recorded yet. The ribbon fills as the daemon runs and is not kept across restarts.")));
      return;
    }
    const from = buckets[0].t, to = buckets[buckets.length - 1].t + 60000;
    const span = Math.max(1, to - from);
    scale.textContent = t("{0} → now · one bar per minute · not kept across restarts", fmtWhen(from));

    const peak = buckets.reduce((m, b) => Math.max(m, b.bytes), 0);
    // Every bucket at zero draws every bar at zero height, which looks exactly like a ribbon with no
    // data in it. "Nothing moved" and "nothing was recorded" are different facts and the ribbon is
    // the one place they are easiest to confuse, so the quiet case says so in words.
    if (peak === 0) {
      body.appendChild(el("div", { class: "hint" },
        tn("Recorded {0} minute, and no traffic moved in it.|Recorded {0} minutes, and no traffic moved in any of them.", buckets.length)));
    }
    const bars = el("div", { class: "ribbon-bars", role: "img",
      "aria-label": t("Router activity over the last {0} minutes", buckets.length) });
    buckets.forEach(b => {
      // A minute with no sample at all is a hole in the record, not a quiet minute. It is drawn
      // differently so the two are never confused.
      const missing = !b.samples;
      const h = peak > 0 ? Math.max(2, Math.round(b.bytes / peak * 100)) : 0;
      bars.appendChild(el("span", { class: "ribbon-bar" + (missing ? " gap" : ""),
        style: missing ? "" : "height:" + h + "%",
        title: missing ? t("{0} — no sample", fmtClock(b.t))
          : t("{0} — {1}", fmtClock(b.t), fmtBytes(b.bytes)) }));
    });
    const track = el("div", { class: "ribbon-track" }, bars);

    // Events are positioned by time on the same axis. One that predates the ribbon is dropped
    // rather than clamped to the left edge, which would date it wrongly.
    const marks = el("div", { class: "ribbon-marks" });
    let dropped = 0;
    ((evs && evs.known && evs.events) || []).forEach(ev => {
      if (ev.at < from || ev.at > to) { dropped++; return; }
      const pct = (ev.at - from) / span * 100;
      const text = ev.kind === "switch" ? t("{0} switched to {1}", ev.name || ev.id, ev.to || "?")
        : ev.kind === "up" ? t("{0} came back", ev.name || ev.id)
          : t("{0} went down", ev.name || ev.id);
      marks.appendChild(el("span", { class: "ribbon-mark " + ev.kind, style: "left:" + pct.toFixed(3) + "%",
        title: fmtClock(ev.at) + " — " + text }));
    });
    track.appendChild(marks);
    body.appendChild(track);

    const legend = el("div", { class: "ribbon-legend" });
    legend.appendChild(el("span", { class: "hint" }, t("Bars are bytes across every interface, so LAN and WAN both count — this is how busy the router was, not link speed.")));
    if (dropped) {
      legend.appendChild(el("span", { class: "hint" }, tn("{0} event is older than the ribbon and is not marked.|{0} events are older than the ribbon and are not marked.", dropped)));
    }
    // The log was fetched with a limit. If more events exist than were returned, some of them fall
    // inside this window and are simply not on it — and a ribbon with marks on it reads as a ribbon
    // with ALL the marks on it. Saying how many are missing is the difference between a partial
    // picture and a partial picture that admits it.
    if (evs && evs.known && evs.truncated) {
      const missing = Math.max(0, (evs.total || 0) - (evs.events || []).length);
      legend.appendChild(el("span", { class: "hint ribbon-partial" }, missing
        ? tn("{0} older event exists and is not marked; showing the {1} most recent.|{0} older events exist and are not marked; showing the {1} most recent.",
            missing, (evs.events || []).length)
        : t("Only the most recent events are marked; the log holds more.")));
    }
    if (evs && !evs.known) {
      legend.appendChild(el("span", { class: "hint" }, t("The event log could not be read, so no events are marked.")));
    }
    body.appendChild(legend);
  })();
  return card;
}

// fmtClock renders a wall-clock time for a point on the axis. The ribbon is read against "when was
// I out", which is a clock question, unlike the event feed's "how long ago".
function fmtClock(ms) {
  if (!ms) return "";
  const d = new Date(ms);
  return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
}

// ── Ask the router ────────────────────────────────────────────────────────────────────────────
// Diagnostics had three text inputs — a target, a domain, and a log paste — each in its own card
// with its own buttons. They ask the same kind of question ("what happens to this thing?") and
// differ only in what you happen to be holding, so the page made you classify your own problem
// before it would help. One input classifies it instead.
//
// The classification is stated, never silent. A guess that quietly runs the wrong tool is worse
// than no guess, so every answer says how the input was read and offers the other readings.

const ASK_KINDS = {
  domain: "a domain",
  url: "a URL",
  ip: "a public IP",
  device: "a device on your network",
  exit: "one of your exits",
  log: "a pasted log",
};

// isPrivateIPv4 decides "device on my LAN" vs "host out on the internet". The distinction changes
// which question is even answerable: a LAN address has no route to test, it has a client history.
function isPrivateIPv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (m.slice(1).some(x => Number(x) > 255)) return false;
  return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31)
    || (a === 169 && b === 254);
}



// askRun answers one question into a feed entry. Every branch reuses the renderer the old dedicated
// card used, so the answers are the same answers — only the way you ask changed.
async function askRun(kind, value, body) {
  body.innerHTML = "";
  const busy = el("div", { class: "hint" }, t("working…"));
  body.appendChild(busy);
  const fail = (e) => { body.innerHTML = ""; body.appendChild(el("div", { class: "hint ask-err" }, e.message || String(e))); };
  try {
    if (kind === "log") {
      const r = await api.post("/api/diagnostics", { text: value });
      body.innerHTML = ""; renderDiagResult(body, r);
      return;
    }
    if (kind === "device") {
      const r = await api.get("/api/clients/destinations");
      body.innerHTML = "";
      // "The scan found nothing for this device" and "the scan could not run" are different answers,
      // and only the first is about the device. Off a router the connection table does not exist at
      // all, so reporting "no recent traffic" there would be a measurement claim built on a probe
      // that never happened — and it would read as a verdict about the device.
      if (!r || !r.available) {
        renderClientDests(body, r || {});
        return;
      }
      // The scan returns every client; narrowing to the one asked about is the whole point of
      // having typed an address. If it is not there, say so rather than showing everyone else.
      const all = r.clients || [];
      const want = value.toLowerCase();
      const hit = all.filter(c => [c.ip, c.mac, c.name].some(x => (x || "").toLowerCase() === want));
      if (!hit.length) {
        body.appendChild(el("div", { class: "hint" },
          t("No recent traffic recorded for {0}. It may be idle, or its traffic may not pass through this router.", value)));
        if (all.length) {
          body.appendChild(el("div", { class: "hint" }, tn("{0} other device does have recent traffic.|{0} other devices do have recent traffic.", all.length)));
        }
        return;
      }
      // The renderer refuses to draw a payload that does not say it is available; passing only the
      // filtered clients dropped that flag and the answer silently became "this needs the router".
      renderClientDests(body, Object.assign({}, r, { clients: hit }));
      return;
    }
    if (kind === "exit") {
      // A named exit is asked "are you working", which is the probe the Connections page runs.
      const ep = (state.profile.endpoints || []).find(e => e.id === value || (e.name || "").toLowerCase() === value.toLowerCase());
      const id = ep ? ep.id : value;
      const h = await api.post("/api/health/test/" + encodeURIComponent(id), {});
      if (h && h.id) healthMap[h.id] = h;
      body.innerHTML = "";
      const alive = h && h.state === "alive";
      body.appendChild(el("div", { class: "ask-verdict " + (alive ? "ok" : "err") },
        alive ? t("{0} answered in {1} ms", nameOf(id) || id, h.latency_ms || "?")
              : t("{0} did not answer", nameOf(id) || id)));
      if (h && h.cause) body.appendChild(el("div", { class: "hint" }, h.cause));
      if (h && h.cause_fix) body.appendChild(el("div", { class: "hint" }, "↳ " + h.cause_fix));
      if (h && h.success_rate != null) {
        body.appendChild(el("div", { class: "hint" },
          t("{0}% of the last probes answered", h.success_rate)));
      }
      return;
    }
    // domain / url / ip — where does it go, and can every exit reach it.
    body.innerHTML = "";
    if (kind === "domain") {
      const traceBox = el("div", { class: "ask-part" });
      body.appendChild(traceBox);
      try {
        const r = await api.get("/api/diagnostics/trace?domain=" + encodeURIComponent(value));
        renderTraceResult(traceBox, r);
      } catch (e) {
        traceBox.appendChild(el("div", { class: "hint ask-err" }, t("Could not trace it: {0}", e.message)));
      }
    }
    const reachBox = el("div", { class: "ask-part" });
    body.appendChild(reachBox);
    await runDiagAll(value, reachBox);
  } catch (e) { fail(e); }
}

// askCard is the input, and the feed the answers land in.
function askCard() {
  const card = el("div", { class: "card ask", "data-group": "tools" });
  card.appendChild(el("div", { class: "card-title" }, t("Ask the router")));
  card.appendChild(el("div", { class: "hint ask-hint" },
    t("A domain, an IP, one of your exits, a device on your network, or a pasted log. It works out which and answers below.")));
  const input = el("input", { type: "text", class: "ask-in",
    placeholder: t("youtube.com · 1.1.1.1 · 192.168.1.42 · Frankfurt VLESS · paste a log") });
  input.setAttribute("aria-label", t("Ask the router"));
  const feed = el("div", { class: "ask-feed" });

  const ask = (forceKind, rawValue) => {
    // A reclassification chip belongs to the historical answer that contains it. Capture that
    // answer's value in the callback; otherwise changing the input and then clicking an old chip
    // silently runs the NEW text under the OLD answer's controls.
    const c = askClassify(rawValue == null ? input.value : rawValue);
    if (!c) return;
    const kind = forceKind || c.kind;
    if (kind === "unknown") {
      feed.prepend(askEntry(c.value, "unknown", null));
      return;
    }
    const entry = askEntry(c.value, kind, (other) => ask(other, c.value));
    feed.prepend(entry);
    askRun(kind, c.value, entry.querySelector(".ask-body"));
  };
  input.addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); ask(null); } });
  card.appendChild(el("div", { class: "ask-row" }, input,
    el("button", { class: "btn btn-primary", onclick: () => ask(null) }, t("Ask"))));
  card.appendChild(feed);
  return card;
}

// askEntry is one answer in the feed: what was asked, how it was read, and room for the answer.
// The "read as" line is not decoration — it is the only way a wrong guess becomes visible, and the
// chips beside it are how you overrule it without retyping.
function askEntry(value, kind, reask) {
  const entry = el("div", { class: "ask-entry" });
  const head = el("div", { class: "ask-head" },
    el("span", { class: "ask-q" }, value.length > 60 ? value.slice(0, 60) + "…" : value.replace(/\s+/g, " ")),
    el("span", { class: "ask-read" }, kind === "unknown"
      ? t("could not tell what this is")
      : t("read as {0}", t(ASK_KINDS[kind] || kind))));
  entry.appendChild(head);
  if (kind === "unknown") {
    entry.appendChild(el("div", { class: "ask-body" },
      el("div", { class: "hint" },
        t("Try a domain (youtube.com), an IP, the name of one of your exits, a device address, or paste a log."))));
    return entry;
  }
  if (reask) {
    const chips = el("div", { class: "ask-chips" });
    Object.keys(ASK_KINDS).filter(k => k !== kind).forEach(k => {
      chips.appendChild(el("button", { class: "btn btn-ghost btn-sm",
        "aria-label": t("Ask again reading it as {0}", t(ASK_KINDS[k])),
        onclick: () => reask(k) }, t(ASK_KINDS[k])));
    });
    head.appendChild(chips);
  }
  entry.appendChild(el("div", { class: "ask-body" }));
  return entry;
}




// 13 function(s) for the server page now live in web/dist/page-server.js,
// loaded on demand by loadChunk(). See PAGES.server.chunk.


// renderTraceResult draws a /api/diagnostics/trace explain into wrap: resolved IPs, the LIVE
// connections + the exit each actually took (ground truth), the configured rules/lists/kernel-zones
// that reference the domain, and the count of geo/remote matchers that can't be checked statically.
function renderTraceResult(wrap, r) {
  const rowStyle = "display:flex;justify-content:space-between;gap:12px;padding:5px 0;border-bottom:1px solid var(--divider);font-size:13px";
  if (r.resolve_error) {
    wrap.appendChild(el("div", { class: "hint", style: "color:var(--err)" }, t("Could not resolve this domain: ") + r.resolve_error));
  } else if (r.ips && r.ips.length) {
    wrap.appendChild(el("div", { class: "hint", style: "margin-bottom:10px" }, t("Resolved IPs: ") + r.ips.join(", ")));
  }
  const conns = r.connections || [];
  if (conns.length) {
    wrap.appendChild(el("div", { class: "card-title", style: "margin:6px 0;font-size:13px" }, t("Live connections (ground truth)")));
    conns.forEach(c => wrap.appendChild(el("div", { style: rowStyle },
      el("span", { style: "font-family:ui-monospace,Consolas,monospace;overflow-wrap:anywhere" },
        c.dst + (c.dport ? ":" + c.dport : "") + (c.domain && c.domain !== r.domain ? " (" + c.domain + ")" : "")),
      el("span", { class: "badge" }, t("via {0}", c.exit || "direct")))));
  }
  const cfg = r.configured || [];
  if (cfg.length) {
    wrap.appendChild(el("div", { class: "card-title", style: "margin:14px 0 6px;font-size:13px" }, t("Configured rules & lists that match")));
    cfg.forEach(c => wrap.appendChild(el("div", { style: "padding:5px 0;border-bottom:1px solid var(--divider);font-size:13px" },
      el("span", { class: "badge", style: "margin-right:8px" }, c.kind),
      el("span", {}, "“" + c.id + "” → " + (c.outbound || "direct")),
      c.why ? el("span", { class: "hint", style: "margin-left:8px" }, c.why) : null)));
  }
  const uneval = r.unevaluated || [];
  if (uneval.length) {
    wrap.appendChild(el("div", { class: "card-title", style: "margin:14px 0 6px;font-size:13px" }, t("May also match (can't check statically)")));
    uneval.forEach(c => wrap.appendChild(el("div", { style: "padding:5px 0;border-bottom:1px solid var(--divider);font-size:13px" },
      el("span", { class: "badge", style: "margin-right:8px" }, c.kind),
      el("span", {}, "“" + c.id + "” → " + (c.outbound || "direct")),
      c.why ? el("span", { class: "hint", style: "margin-left:8px" }, c.why) : null)));
    wrap.appendChild(el("div", { class: "hint", style: "margin-top:6px" },
      t("These use geo/remote rule-sets whose contents aren't loaded here — test live to confirm.")));
  }
  if (r.note) wrap.appendChild(el("div", { class: "hint", style: "margin-top:10px" }, r.note));
  if (!conns.length && !cfg.length && !r.resolve_error && !r.note)
    wrap.appendChild(el("div", { class: "hint" }, t("No live connections and no configured rule matches this domain right now.")));
}

// renderClientDests draws GET /api/clients/destinations: each LAN client (name + IP) followed by the
// PUBLIC destinations it reached — the sniffed domain (or bare IP), the exit it took, and its bytes.
function renderClientDests(wrap, r) {
  if (!r || !r.available) {
    wrap.appendChild(el("div", { class: "hint" }, t("The connection table isn't available here (this needs the router).")));
    return;
  }
  const clients = r.clients || [];
  if (!clients.length) {
    wrap.appendChild(el("div", { class: "hint" }, t("No active external connections right now.")));
    return;
  }
  clients.forEach(c => {
    wrap.appendChild(el("div", { class: "card-title", style: "margin:12px 0 4px;font-size:13px" },
      // A device with no DHCP lease name rendered as "(192.168.50.11)" — parentheses around the only
      // thing there, which reads as a name that failed to load. Measured on a live Keenetic:
      // every one of the three devices Scan found is nameless, so the whole report was bracketed.
      c.name ? c.name + " (" + c.ip + ")" : c.ip));
    (c.dests || []).forEach(d => wrap.appendChild(el("div", { style: "display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:4px 0;border-bottom:1px solid var(--divider);font-size:12.5px" },
      el("span", { style: "font-family:ui-monospace,Consolas,monospace;overflow-wrap:anywhere" }, d.domain || d.dst),
      el("span", { style: "white-space:nowrap;display:inline-flex;align-items:center;gap:8px" },
        el("span", { class: "hint" }, fmtBytes((d.up_bytes || 0) + (d.down_bytes || 0))),
        // The exit by the name the operator gave it. The daemon sends the outbound TAG, and the badge
        // printed it raw: measured on a live Keenetic, every tunnelled row read "via
        // grp-primary" while his Failover page calls that same group "Primary group". nameOf
        // resolves an endpoint or a group and falls back to the id, so an outbound the profile no
        // longer holds still shows something rather than nothing.
        el("span", { class: "badge" }, t("via {0}", d.exit ? nameOf(d.exit) : "direct")),
        routeDestAction(d)))));
  });
}

// routeDestAction: a per-destination "Route" button that adds the observed destination (its sniffed
// domain, or the bare IP as an explicit /32-/128 CIDR) to a chosen routing list's manual entries —
// the "discover what a device reaches → route it" flow (COMMUNITY_BACKLOG Tier-B). It STAGES the
// change (updateDirty), exactly like the Routing page: nothing is applied until the user hits Apply,
// so mutating from this diagnostic view stays inside the review-before-apply model.
function routeDestAction(d) {
  const lists = (state.profile && state.profile.routing_lists) || [];
  const btn = el("button", { class: "btn btn-sm", title: t("Add this destination to a routing list (staged; apply on the toolbar)") }, t("Route"));
  const picker = el("span", { style: "display:none;align-items:center;gap:6px;margin-left:6px" });
  btn.onclick = () => {
    if (!lists.length) { toast(t("No routing lists yet — create one on the Routing page first."), "err"); return; }
    if (picker.style.display !== "none") { picker.style.display = "none"; return; }
    picker.innerHTML = "";
    const sel = el("select", { style: "font-size:12px;padding:2px 4px" }, ...lists.map(rl => el("option", { value: rl.id }, rl.name || rl.id)));
    const add = el("button", { class: "btn btn-sm btn-primary" }, t("Add"));
    add.onclick = async () => {
      const rl = lists.find(x => x.id === sel.value);
      if (!rl) return;
      const entry = d.domain || (String(d.dst).includes(":") ? d.dst + "/128" : d.dst + "/32");
      rl.manual = rl.manual || [];
      if (!rl.manual.includes(entry)) rl.manual.push(entry);
      try {
        await api.post("/api/routing", rl);
        updateDirty();
        toast(t("Added {0} → {1}", entry, rl.name || rl.id), "ok");
        picker.style.display = "none";
        btn.textContent = t("Routed ✓"); btn.disabled = true;
      } catch (e) {
        const i = rl.manual.indexOf(entry); if (i >= 0) rl.manual.splice(i, 1); // roll back the optimistic add
        toast(e.message, "err");
      }
    };
    picker.append(sel, add);
    picker.style.display = "inline-flex";
  };
  return el("span", { style: "display:inline-flex;align-items:center" }, btn, picker);
}

function diagToolLabel(tool) {
  return ({ ping: "Ping", traceroute: "Traceroute", dns: "DNS lookup", all: "Full diagnostic", reach: "Reachability", matrix: "All exits" })[tool] || "Test";
}

// renderDiagOutput (re)draws state.diag into wrap and (re)binds the live refs, so
// a still-running stream's diagAppend lands in the freshly-mounted node.
function renderDiagOutput(wrap) {
  diagWrap = wrap; diagOut = null;
  wrap.innerHTML = "";
  const d = state.diag;
  if (!d) return;
  if (d.kind === "reach") { renderReach(wrap, d.result); return; }
  if (d.kind === "matrix") { renderReachMatrix(wrap, d.result); return; }
  if (d.kind === "pending") { wrap.appendChild(el("div", { class: "hint" }, d.note || "running…")); return; }
  if (d.kind === "error") { wrap.appendChild(el("div", { class: "hint", style: "color:var(--err)" }, d.message || "error")); return; }
  // streamed tool (ping / traceroute / dns / all)
  const st = d.status || "done";
  const right = el("div", { style: "display:flex;gap:8px;align-items:center" },
    el("span", { class: "pill " + (st === "running" ? "warn" : st === "error" ? "err" : "ok") },
      st === "running" ? "running…" : st === "stopped" ? "stopped" : st === "error" ? "error" : "done"));
  if (st === "running") right.appendChild(el("button", { class: "btn btn-sm", onclick: () => { if (state.diag && state.diag.abort) state.diag.abort.abort(); } }, "Stop"));
  wrap.appendChild(el("div", { class: "row-between", style: "margin-bottom:8px" },
    el("div", { class: "card-title" }, diagToolLabel(d.tool) + " · " + d.target), right));
  const lines = el("div", { class: "diag-out" });
  (d.lines || []).forEach(l => lines.appendChild(el("div", { class: "diag-line" }, l || " ")));
  wrap.appendChild(lines);
  diagOut = lines;
  lines.scrollTop = lines.scrollHeight;
}

// diagAppend pushes one streamed line into state (always) and the live DOM (only
// when the Diagnostics page is currently mounted) — that split is what lets a
// stream keep accumulating across navigation without losing data.
function diagAppend(line) {
  if (!state.diag) return;
  (state.diag.lines = state.diag.lines || []).push(line);
  if (diagOut && diagOut.isConnected) {
    diagOut.appendChild(el("div", { class: "diag-line" }, line || " "));
    diagOut.scrollTop = diagOut.scrollHeight;
  }
}
function diagRefresh() { if (diagWrap && diagWrap.isConnected) renderDiagOutput(diagWrap); }

// runDiagStream streams a WAN tool (ping/traceroute/dns/all) over SSE, appending
// each line live. myDiag-vs-state.diag guards keep a superseded stream from
// writing into a newer one's output.
async function runDiagStream(tool, target, egress, wrap) {
  target = (target || "").trim();
  if (!target) { toast("Enter a host, IP or URL", "err"); return; }
  if (state.diag && state.diag.abort) state.diag.abort.abort();
  const abort = new AbortController();
  const myDiag = { kind: "stream", tool, target, egress, lines: [], status: "running", abort };
  state.diag = myDiag;
  renderDiagOutput(wrap);
  try {
    const r = await fetch("/api/netdiag/stream?tool=" + encodeURIComponent(tool) + "&target=" + encodeURIComponent(target) + "&egress=" + encodeURIComponent(egress || ""), { signal: abort.signal });
    if (!r.ok) { let m = "stream failed (" + r.status + ")"; try { m = (await r.json()).error || m; } catch (_) {} throw new Error(m); }
    if (!r.body) throw new Error("no stream body");
    const reader = r.body.getReader(), dec = new TextDecoder();
    let buf = "";
    for (;;) {
      if (state.diag !== myDiag || !wrap.isConnected) { reader.cancel(); abort.abort(); return; } // superseded, OR the user navigated away (wrap detached) — free the stream
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const frame = buf.slice(0, i); buf = buf.slice(i + 2);
        if (frame.indexOf("event: done") === 0) continue;
        const m = frame.match(/^data: ?([\s\S]*)$/);
        if (m && state.diag === myDiag) diagAppend(m[1]);
      }
    }
    if (state.diag === myDiag) { myDiag.status = "done"; diagRefresh(); }
  } catch (e) {
    if (state.diag !== myDiag) return;
    myDiag.status = e.name === "AbortError" ? "stopped" : "error";
    if (e.name !== "AbortError") diagAppend("error: " + e.message);
    diagRefresh();
  }
}

// runDiagReach / runDiagAll: tunnel reachability + the all-exits matrix. Both park
// their result in state.diag so they persist across navigation like the streams.
// myDiag is an ownership token (like runDiagStream's): a slow earlier probe that
// resolves after a newer action started must NOT clobber it. And we re-render via
// diagRefresh() (current diagWrap), not the captured wrap — otherwise a result
// that lands after you navigate away+back paints into the now-detached node and
// the visible page stays stuck on "testing…".
async function runDiagReach(target, egress, wrap) {
  target = (target || "").trim();
  if (!target) { toast("Enter a host, IP or URL", "err"); return; }
  if (state.diag && state.diag.abort) state.diag.abort.abort();
  const myDiag = { kind: "pending", tool: "reach", target, egress, note: "testing reachability through the tunnel…" };
  state.diag = myDiag;
  renderDiagOutput(wrap);
  try {
    const r = await api.post("/api/netdiag", { target, egress });
    if (state.diag !== myDiag) return;
    state.diag = { kind: "reach", tool: "reach", target, egress, result: r };
  } catch (e) {
    if (state.diag !== myDiag) return;
    state.diag = { kind: "error", tool: "reach", target, egress, message: e.message };
  }
  diagRefresh();
}
async function runDiagAll(target, wrap) {
  target = (target || "").trim();
  if (!target) { toast("Enter a host, IP or URL", "err"); return; }
  if (state.diag && state.diag.abort) state.diag.abort.abort();
  const myDiag = { kind: "pending", tool: "matrix", target, note: "testing reachability through every exit…" };
  state.diag = myDiag;
  renderDiagOutput(wrap);
  try {
    const r = await api.post("/api/netdiag/all", { target });
    if (state.diag !== myDiag) return;
    state.diag = { kind: "matrix", tool: "matrix", target, result: r };
  } catch (e) {
    if (state.diag !== myDiag) return;
    state.diag = { kind: "error", tool: "matrix", target, message: e.message };
  }
  diagRefresh();
}

function renderReach(out, r) {
  const ok = r.reachable;
  out.appendChild(el("div", { class: "row-between", style: "margin-bottom:8px" },
    el("div", { class: "card-title" }, t("Reachability via {0}", r.name || r.egress)),
    el("span", { class: "pill " + (ok ? "ok" : "err") }, el("span", { class: "dot" }),
      ok ? (r.latency_ms + " ms") : "unreachable")));
  out.appendChild(el("div", { class: "hint", style: "word-break:break-all" }, t("GET {0}", r.url) + (r.err ? "  —  " + r.err : "")));
}

function renderReachMatrix(out, r) {
  const rows = (r.results || []).slice();
  const reached = rows.filter(x => x.reachable).length;
  out.appendChild(el("div", { class: "card-title", style: "margin-bottom:4px" }, t("Reachability of {0} by exit", r.target)));
  out.appendChild(el("div", { class: "hint", style: "margin-bottom:10px" }, t("{0} of {1} exits reached it", reached, rows.length)));
  // Sort state persists on state.diag so it survives re-render / tab nav. Unreachable
  // exits sink (latency = Infinity) regardless of direction's effect on the rest.
  if (state.diag && !state.diag.sort) state.diag.sort = { col: "latency", dir: 1 };
  const sort = (state.diag && state.diag.sort) || { col: "latency", dir: 1 };
  const lat = x => x.reachable ? (x.latency_ms || 0) : Infinity;
  const cmp = ({
    name: (a, b) => (a.name || a.egress || "").localeCompare(b.name || b.egress || ""),
    status: (a, b) => (a.reachable ? 0 : 1) - (b.reachable ? 0 : 1),
    latency: (a, b) => lat(a) - lat(b),
  })[sort.col] || (() => 0);
  rows.sort((a, b) => cmp(a, b) * sort.dir);
  const setSort = (col) => { const s = state.diag.sort = state.diag.sort || { col: "latency", dir: 1 }; if (s.col === col) s.dir = -s.dir; else { s.col = col; s.dir = 1; } diagRefresh(); };
  const th = (label, col, alignR) => {
    const active = sort.col === col;
    return el("th", { class: alignR ? "rm-r" : "", "aria-sort": active ? (sort.dir > 0 ? "ascending" : "descending") : "none" },
      el("button", { class: "rm-th" + (active ? " active" : ""), onclick: () => setSort(col) }, label, active ? el("span", { class: "rm-arr" }, sort.dir > 0 ? "▴" : "▾") : null));
  };
  const table = el("table", { class: "rm-table" },
    el("thead", {}, el("tr", {}, th(t("Exit"), "name"), th(t("Status"), "status"), th(t("Latency"), "latency", true))),
    el("tbody", {}, ...rows.map(x => {
      const ok = x.reachable, ms = ok ? x.latency_ms : null;
      const band = ms == null ? null : ms < 150 ? "fast" : ms < 600 ? "moderate" : "slow";
      const latCls = ms == null ? "" : ms < 150 ? "lat-ok" : ms < 600 ? "lat-warn" : "lat-err";
      // Color alone conveys latency quality, which is invisible to colorblind users. Add a
      // tiny fixed-width leading glyph (monochrome-distinguishable: blank/"~"/"!") that differs
      // by band plus an aria-label, without disturbing the tabular-nums right-alignment or sort.
      const glyph = band === "moderate" ? "~" : band === "slow" ? "!" : ""; // fast = no glyph (baseline); fixed cue width keeps numbers aligned
      const latCue = ms == null ? null : el("span", { class: "lat-cue", "aria-hidden": "true", style: "display:inline-block;width:1.1em;text-align:center" }, glyph);
      const latText = ok ? (ms + " ms") : "—";
      const latAria = ms == null ? latText : (ms + " ms, " + band);
      return el("tr", {},
        el("td", { "data-label": t("Exit") }, x.name || x.egress),
        el("td", { "data-label": t("Status") }, el("span", { class: "pill " + (ok ? "ok" : "err") }, el("span", { class: "dot" }), ok ? t("reachable") : t("unreachable"))),
        el("td", { "data-label": t("Latency"), class: "rm-r " + latCls, title: x.err || "", "aria-label": latAria }, latCue, latText));
    })));
  out.appendChild(table);
  const wan = rows.find(x => x.egress === "direct");
  // "too" was the whole sentence: it was written for the run where the tunnels failed AND the WAN
  // failed as well, but the condition only ever asked about the WAN. So a target that is simply
  // blocked on the provider — the ordinary reason these tunnels exist — was reported as a fault of
  // the router. Measured on a live Keenetic asking about youtube.com: WAN (direct)
  // unreachable, all five tunnels and the group reachable at 291-641 ms, and the page told him to
  // check the uplink his own six successful probes had just exercised.
  const tunnelsReach = rows.some(x => x.egress !== "direct" && x.reachable);
  if (wan && !wan.reachable) out.appendChild(el("div", { class: "hint", style: "margin-top:10px" + (tunnelsReach ? "" : ";color:var(--warn)") },
    tunnelsReach
      ? t("The direct path to this target is blocked or filtered — your exits reach it, which is what they are for.")
      : t("WAN (direct) failed too — the router itself can't reach this target; check the uplink/DNS.")));
}







/* ---------- Init Server (R8) ---------- */
let serverOptionsCache = null;
const SERVER_OPT_NAME = { "amneziawg": "AmneziaWG", "vless-reality": "VLESS-Reality" };

async function renderServer(view) {
  view.appendChild(el("div", { class: "block-head" },
    el("div", {},
      el("div", { class: "desc" }, "Provision and manage proxy servers over SSH. WayHop installs what you pick, auto-adds the client to Connections and tests it — keep several servers for redundancy, and harden fresh ones with key-only login.")),
    el("div", { class: "side" },
      el("button", { class: "btn btn-primary", title: "Provision a new remote server over SSH and add its client to Connections", onclick: openAddServer }, "+ Add server"))));

  const loadingSrv = el("div", { class: "hint", style: "margin:18px 0" }, t("loading servers…"));
  view.appendChild(loadingSrv);
  let servers;
  try { servers = (await api.get("/api/servers")) || []; }
  catch (e) { loadingSrv.remove(); renderError(view, e); return; }
  loadingSrv.remove();

  if (!servers.length) {
    view.appendChild(el("div", { class: "card" }, el("div", { class: "empty" },
      el("div", { style: "font-size:15px;color:var(--ink)" }, "No servers yet"),
      el("div", { class: "hint", style: "margin-top:8px;max-width:46ch;margin-left:auto;margin-right:auto" }, "Add a VPS to provision it into a VPN endpoint. Keep more than one for redundancy. Credentials are used per-action and never stored."),
      el("button", { class: "btn btn-primary btn-sm", style: "margin-top:16px", onclick: openAddServer }, "+ Add your first server"))));
    return;
  }
  // Lay the servers out across the width instead of one full-width card per server.
  //
  // Each card holds a name, two short status lines and four buttons — measured at 1920px, the ink
  // covered 47% of a 1444px card and the empty middle was 746px. Worse, the hole grew one-for-one
  // with the screen: from 1280 to 1920 the card gained 455px and the gap gained 455px, so not one of
  // those pixels reached the content. Failover already solves exactly this for its group cards with
  // an auto-fit strip; this is the same shape, so it gets the same treatment.
  const strip = el("div", { class: "srv-strip" });
  servers.forEach(sv => strip.appendChild(serverCard(sv)));
  view.appendChild(strip);
}







// usesSelfSignedTLS detects, from the option's own copy, whether the protocol
// provisions with a self-signed certificate (and therefore needs a "bring your own
// domain+cert" caveat). Data-driven — looks for the phrase the catalog Details use
// ("self-signed") or the insecure=1 marker — so adding/removing such a protocol
// server-side needs no UI change, and never hard-codes protocol ids.
function usesSelfSignedTLS(o) {
  const hay = [o.summary || ""].concat(o.details || []).join(" ").toLowerCase();
  return hay.includes("self-signed") || hay.includes("insecure=1") || hay.includes("skip-cert-verify");
}

// protoCard builds one selectable protocol card (a <label> so the whole card toggles
// its checkbox). Read-only, fully escaped via el(); reuses the existing install-grid
// / proto-card / opt-details classes.
function protoCard(o, checked) {
  const cb = el("input", { type: "checkbox" });
  cb.checked = !!checked;
  const selfSigned = usesSelfSignedTLS(o);
  const card = el("label", { class: "proto-card" }, cb,
    el("div", {},
      el("div", { class: "pt" }, o.name,
        o.recommended ? el("span", { class: "tag-ok" }, "recommended") : null,
        selfSigned ? el("span", { class: "tag-ok", style: "color:var(--warn);background:var(--warn-tint)", title: "Provisions with a self-signed TLS certificate" }, "self-signed TLS") : null,
        o.port ? el("span", { class: "hint", style: "margin-left:8px;font-weight:400" }, (o.transport || "tcp") + " :" + o.port) : null),
      el("div", { class: "pd" }, o.summary),
      el("ul", { class: "opt-details" }, ...(o.details || []).map(d => el("li", {}, d)))));
  return { cb, card };
}















// openVersions — per-server binary version check + update (over SSH, creds not stored).
// Reads sing-box (Reality core) + AmneziaWG versions, compares sing-box to its latest
// GitHub release, and offers a gated per-binary update.
async function openVersions(sv) {
  const c = credsBlock(sv);
  const con = smartConsole();
  const results = el("div", { style: "margin-top:14px" });
  const checkBtn = el("button", { class: "btn btn-primary" }, t("Check versions"));
  modal({
    title: t("Binary versions") + " — " + ((sv && (sv.name || sv.host)) || t("server")),
    body: el("div", {}, c.node,
      el("div", { class: "hint", style: "margin-top:6px" }, "Reads sing-box + AmneziaWG versions on the server over SSH and compares sing-box to its latest release. Updating restarts that service briefly and keeps a backup of the old binary on the server."),
      con.node, results),
    footer: checkBtn,
  });
  checkBtn.addEventListener("click", async () => {
    const cr = c.get();
    if (!cr.host || !cr.user) return toast("Host and SSH user are required", "err");
    checkBtn.disabled = true; checkBtn.textContent = t("Checking…"); results.innerHTML = "";
    try {
      const r = await api.post("/api/server/check-versions", { server_id: sv && sv.id, ...cr });
      con.run(r.job_id, v => {
        checkBtn.disabled = false; checkBtn.textContent = t("Re-check");
        if (v.ok && v.result) renderVersionTable(results, v.result, sv, c, con);
        else toast("Version check failed — see console", "err");
      });
    } catch (e) { checkBtn.disabled = false; checkBtn.textContent = t("Check versions"); toast(e.message, "err"); }
  });
}





/* ---------- Settings (M10) ---------- */
function restartTag() { return el("span", { class: "tag-restart", title: t("Takes effect after the daemon restarts") }, t("↻ restart")); }

// secretInput is a password-type field with a Show/Hide reveal toggle, for values
// that shouldn't sit in plain sight on an unauthenticated LAN panel (the clash
// secret, the watchdog webhook URL which commonly embeds a token). Returns the
// input (read .value) plus the row to place in a .field.
// `label` names WHICH secret this reveals: the page carries more than one, and a bare "Show"
// is indistinguishable between them to anyone not reading the surrounding layout.
function secretInput(v, ph, label) {
  const input = el("input", { type: "password", value: v == null ? "" : String(v), placeholder: ph || "", autocomplete: "off", spellcheck: "false" });
  const toggle = el("button", { class: "btn btn-sm reveal", type: "button", "aria-label": t("Show") + (label ? " " + label : "") }, t("Show"));
  toggle.addEventListener("click", () => {
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    toggle.textContent = show ? t("Hide") : t("Show");
    toggle.setAttribute("aria-label", (show ? t("Hide") : t("Show")) + (label ? " " + label : ""));
  });
  return { input, row: el("div", { class: "secret-row" }, input, toggle) };
}

// Settings client-side validation mirrors config.Validate on the server (which is
// still the authority); it just catches the common foot-guns before a round-trip
// (a blank port that becomes 0 → 400, a malformed listen, a non-URL webhook).
function isHostPort(s) { const m = /^(.*):(\d{1,5})$/.exec(s || ""); return !!m && +m[2] >= 1 && +m[2] <= 65535; }
function isHTTPUrl(s) { return /^https?:\/\//i.test(s || ""); }
function normalizeHostJS(h) {
  // Mirror the server's normalizeHost: strip :port and IPv6 brackets, lower-case.
  // A bare IPv6 (multiple colons, no brackets) must NOT have its last group treated
  // as a port, so only strip :port when there's exactly one colon.
  h = String(h || "").trim().toLowerCase();
  const m = h.match(/^\[(.+?)\](?::\d+)?$/); // [ipv6] or [ipv6]:port
  if (m) return m[1];
  if ((h.match(/:/g) || []).length === 1) h = h.replace(/:\d+$/, "");
  return h;
}
function validateSettingsClient(next) {
  const errs = [];
  if (!isHostPort(next.listen)) errs.push(t("Listen must be host:port (for example :8088)."));
  const pv = [next.ports.ui, next.ports.clash, next.ports.dns, next.ports.mixed];
  if (pv.some(p => !(p >= 1 && p <= 65535))) errs.push(t("Every port must be between 1 and 65535."));
  else if (new Set(pv).size !== pv.length) errs.push(t("The four ports must all be different."));
  if (next.clash.controller && !isHostPort(next.clash.controller)) errs.push(t("Clash controller must be host:port."));
  if (next.watchdog.notify_url && !isHTTPUrl(next.watchdog.notify_url)) errs.push(t("Webhook URL must start with http:// or https://."));
  (next.updater.mirrors || []).filter(Boolean).forEach(m => { if (!isHTTPUrl(m)) errs.push(t("Component download mirror is not a URL: ") + m); });
  return errs;
}

// Module-scoped so the nav-guard registry's checker (registered per render) always
// reads the live dirty state.
let _settingsDirty = false;

/* ---------- Settings section navigator ----------
 * Settings carried thirteen sibling cards with no grouping: 32 controls over 3.5 screens, twice the
 * density of any other page, and the reason the panel reads as cluttered. The cards are grouped into
 * four sections and one is shown at a time, so the page opens at about one screen.
 *
 * Nothing is removed and nothing is collapsed away permanently — this is navigation, not a reduction
 * of the product. Every card is still BUILT on render; the hidden ones are simply detached. That
 * matters for correctness: Save reads the input elements through the closures renderSettings holds,
 * so a field the user never navigated to still submits the value it loaded with. Detaching cannot
 * silently blank a setting.
 */

// ── Settings index ────────────────────────────────────────────────────────────────────────────
// One searchable table instead of fourteen cards behind four tabs.
//
// Tabs made every question a hunt. "Which port does the panel listen on" meant guessing whether that
// lived under Panel or Routing & core, and "what have I changed" was unanswerable at any price. The
// index is one list of every setting with the facets that actually get asked about.
//
// It is built by MOVING the live controls out of the cards the page already constructed, not by
// re-creating them. Re-creating would mean a second definition of every field, free to drift from
// the one that saves — and the save button reads these exact elements.
//
// SETTING_META maps a field's label to what a reader needs to filter by. `cfg` is the dotted path in
// the daemon config, used to compare against GET /api/config/defaults; a field with no path cannot
// be judged against a default and says so rather than silently sitting out the filter.
// hostOfListen takes the host half of a "host:port" listen string — "" for ":8088", which means
// "all interfaces". The Listen host field edits only this half; the port lives under Ports → Web UI.
function hostOfListen(v) {
  const s = String(v || "");
  const i = s.lastIndexOf(":");
  return i < 0 ? s : s.slice(0, i);
}

const SETTING_META = {
  "Theme": { browser: true },
  "Language": { browser: true },
  // `project` maps the raw config value to what this field actually edits. Without it the badge
  // compared a HALF against a WHOLE: the field holds the host ("" = all interfaces) while cfg.listen
  // is "host:port". Measured on a live Keenetic — default listen ":8088", current listen
  // ":8088", the setting untouched — and the row still carried "not default", with a tooltip
  // reading "Default is :8088" over a field where that string would not be a valid entry.
  "Listen host": { cfg: "listen", project: hostOfListen, lockout: true, restart: true },
  "Web UI": { cfg: "ports.ui", lockout: true, restart: true },
  "Clash API": { cfg: "ports.clash", restart: true },
  "DNS": { cfg: "ports.dns", restart: true },
  "Mixed (socks+http)": { cfg: "ports.mixed", restart: true },
  "Mode": { cfg: "routing_mode" },
  "Demo mode": { cfg: "demo", restart: true },
  // The paths are the daemon's own json names — `offload` / `offload_devices`, which is what the page
  // reads on load and sends on save. They were written here as `flow_offload…`, matching nothing, so
  // both rows silently sat out the "not default" filter for want of a field that does not exist.
  "Flow offload": { cfg: "offload" },
  "Offload devices": { cfg: "offload_devices" },
  "sing-box binary": { cfg: "singbox.bin", restart: true },
  "sing-box config": { cfg: "singbox.config", restart: true },
  "Clash controller": { cfg: "clash.controller" },
  "Clash secret": { cfg: "clash.secret", secret: true },
  "Notify webhook URL": { cfg: "watchdog.notify_url", secret: true },
  "Connectivity-check target": { cfg: "failsafe.target" },
};

// Facets, in the order they are offered. Each is a question someone actually arrives with.
const SETTING_FACETS = [
  ["changed", "changed by you", "Edited on this page and not saved yet"],
  ["nondefault", "not default", "Differs from a fresh install"],
  ["restart", "needs a restart", "Saving is not enough — the daemon has to come back"],
  ["lockout", "can lock you out", "Get this wrong and the panel stops answering"],
  ["browser", "browser only", "Stored in this browser, never sent to the router"],
];

// tuckProse moves a row's explanatory paragraphs behind a disclosure, leaving the controls visible.
//
// The old cards carried their reasoning as body text, which is right when you are reading one card
// and wrong when you are scanning twenty-four rows: the prose alone made the index three screens
// tall, and the thing being explained scrolled off with it. The warnings that must survive a scan
// are already chips on the row — this is the long-form "why", available on demand.
//
// Short hints stay put: a one-line note costs nothing and hiding it would just add a click.
function tuckProse(wrap) {
  const hints = [...wrap.querySelectorAll(":scope > .hint")];
  const long = hints.filter(h => (h.textContent || "").trim().length > 90);
  if (long.length < 1) return;
  const total = long.reduce((n, h) => n + h.textContent.length, 0);
  if (total < 120) return;
  const det = el("details", { class: "sx-why" }, el("summary", {}, t("why this matters")));
  // Insert the disclosure where the first paragraph was, so the reading order does not jump.
  long[0].parentNode.insertBefore(det, long[0]);
  long.forEach(h => det.appendChild(h));
}

// settingValueOf fingerprints everything a row can hold, not just its first control.
//
// Reading only the first one made "changed by you" quietly incomplete on exactly the rows that hold
// several: ticking "Allow auto-reboot" or editing the mirror list left the row looking untouched,
// because the fingerprint was taken from a sibling nobody had typed in. A filter that reports fewer
// changes than were made is worse than no filter — it is a reassurance.
function settingValueOf(node) {
  if (!node) return "";
  const parts = [];
  node.querySelectorAll("input, select, textarea").forEach(c => {
    if (c.type === "file") return; // a file picker holds no persisted setting
    parts.push(c.type === "checkbox" ? (c.checked ? "1" : "0") : String(c.value == null ? "" : c.value));
  });
  return parts.join("\u0000");
}

// settingPrimaryValue is the single value compared against the daemon's default. Only a row mapped
// to one config path has a default to compare with, and those rows hold exactly one control.
function settingPrimaryValue(node) {
  if (!node) return "";
  const c = node.querySelector("input, select, textarea");
  if (!c) return "";
  if (c.type === "checkbox") return c.checked ? "1" : "0";
  return String(c.value == null ? "" : c.value);
}

// dig walks a dotted path into the defaults object. Returns undefined for a path the defaults do
// not carry, which the caller treats as "cannot judge" rather than as "empty".
function dig(obj, path) {
  return String(path).split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);
}

function settingsIndex(view, defaults) {
  const cards = [...view.querySelectorAll(":scope > .card[data-section]")];
  if (!cards.length) return;

  const rows = [];
  cards.forEach(card => {
    const section = card.getAttribute("data-section");
    const titleEl = card.querySelector(".card-title");
    const cardTitle = titleEl ? (Array.from(titleEl.childNodes).filter(n => n.nodeType === 3)
      .map(n => n.textContent).join(" ").trim() || titleEl.textContent.trim()) : section;
    // A card-level restart tag applies to every field inside it — that is how the old page said it.
    const cardRestart = !!card.querySelector(".card-title .tag-restart");
    const fields = [...card.querySelectorAll(".field")];
    if (fields.length) {
      fields.forEach(f => {
        const lab = f.querySelector("label");
        const name = lab ? (Array.from(lab.childNodes).filter(n => n.nodeType === 3)
          .map(n => n.textContent).join(" ").trim() || lab.textContent.trim()) : cardTitle;
        rows.push({ name, section, card: cardTitle, node: f,
          restart: cardRestart || !!f.querySelector(".tag-restart") });
      });
      // Anything in the card that is not a .field — checkboxes, textareas, buttons, hints — moves as
      // one "rest of this card" row so no control is left behind in a card about to be removed.
      const leftovers = [...card.children].filter(ch =>
        ch !== titleEl && !ch.classList.contains("card-title") && !fields.some(f => ch.contains(f) || ch === f));
      if (leftovers.some(l => l.querySelector("input, select, textarea, button") || l.tagName === "BUTTON")) {
        const wrap = el("div", { class: "sx-rest" });
        leftovers.forEach(l => wrap.appendChild(l));
        tuckProse(wrap);
      rows.push({ name: cardTitle, section, card: cardTitle, node: wrap, restart: cardRestart, group: true });
      }
    } else {
      const wrap = el("div", { class: "sx-rest" });
      [...card.children].forEach(ch => { if (ch !== titleEl) wrap.appendChild(ch); });
      tuckProse(wrap);
      rows.push({ name: cardTitle, section, card: cardTitle, node: wrap, restart: cardRestart, group: true });
    }
  });
  cards.forEach(c => c.remove());

  rows.forEach(r => {
    const meta = SETTING_META[r.name] || {};
    r.meta = meta;
    r.restart = r.restart || !!meta.restart;
    r.lockout = !!meta.lockout;
    r.browser = !!meta.browser;
    r.initial = settingValueOf(r.node);
    // What the row can be FOUND by. Built once, here, after tuckProse has moved the prose into the
    // row: the index's whole promise is "one list you can search", and until now the haystack was
    // name + card + section + config path, so any word that appears only in the explanation was
    // invisible. Measured on a live router: searching "dev-no-auth" reported "0 of 26
    // settings" while that exact word was on screen in one of them.
    //
    // textContent deliberately: it includes the collapsed "why this matters" disclosure, and it does
    // NOT include input VALUES — so a typed password or token can never be matched, or revealed by
    // the fact that it matched.
    r.hay = (r.name + " " + r.card + " " + r.section + " " + (r.meta.cfg || "") + " "
      + (r.node.textContent || "")).toLowerCase().replace(/\s+/g, " ");
    // The row shows the name once, in its key column, so the field's own <label> is hidden. A hidden
    // label is not announced, which would leave the control with no accessible name at all — the
    // exact defect the button-name gate exists to prevent, arriving through the back door. Name the
    // control directly instead, unless it already carries a name of its own.
    if (!r.group) {
      const ctl = r.node.querySelector("input, select, textarea");
      if (ctl && !ctl.getAttribute("aria-label") && !ctl.getAttribute("aria-labelledby")) {
        ctl.setAttribute("aria-label", r.name);
      }
    }
    // "not default" is only claimable for a field whose config path is known AND whose default the
    // daemon actually reports. A secret is never compared: the current value is redacted, so any
    // comparison would be against a mask and would call every secret "customised".
    r.tracked = !!(meta.cfg && !meta.browser && !meta.secret && defaults && dig(defaults, meta.cfg) !== undefined);
    if (r.tracked) {
      const d = dig(defaults, meta.cfg);
      const projected = meta.project ? meta.project(d) : d;
      const dv = typeof projected === "boolean" ? (projected ? "1" : "0") : String(projected == null ? "" : projected);
      r.nondefault = settingPrimaryValue(r.node) !== dv;
      r.defaultText = dv === "" ? t("(blank)") : dv;
    }
  });

  // Order. The list arrives in the order the CARDS were built, which is an implementation detail:
  // measured on a live router, Panel appeared at rows 2, 9, 14–17 and 23, Maintenance at 4,
  // 18, 24 and 25 — the same subject scattered down the page with nothing to say why. Tabs are not
  // the answer here (they were deliberately dropped; see the navigator note above), so the flat list
  // is SORTED instead: rows of one section sit together, and cards keep their internal order.
  //
  // Stable and derived from the page itself — the first appearance of a section or card defines its
  // position — so adding a card cannot silently reshuffle everything, and no second list of section
  // names has to be kept in step with the page.
  const seenOrder = (key, seen) => {
    if (!seen.has(key)) seen.set(key, seen.size);
    return seen.get(key);
  };
  const sectionOrder = new Map(), cardOrder = new Map();
  rows.forEach(r => {
    r.sortSection = seenOrder(r.section, sectionOrder);
    r.sortCard = seenOrder(r.section + " :: " + r.card, cardOrder);
  });
  rows.sort((a, b) => (a.sortSection - b.sortSection) || (a.sortCard - b.sortCard));

  const box = el("div", { class: "sx" });
  const search = el("input", { type: "text", class: "sx-search", placeholder: t("Search settings — port, offload, webhook, theme…") });
  search.setAttribute("aria-label", t("Search settings"));
  const count = el("div", { class: "hint sx-count" });
  const facetBar = el("div", { class: "sx-facets" });
  const active = new Set();
  const list = el("div", { class: "sx-list" });

  const apply = () => {
    const q = search.value.trim().toLowerCase();
    let shown = 0;
    rows.forEach(r => {
      let ok = !q || r.hay.includes(q);
      if (ok && active.has("changed")) ok = settingValueOf(r.node) !== r.initial;
      if (ok && active.has("nondefault")) ok = !!r.nondefault;
      if (ok && active.has("restart")) ok = r.restart;
      if (ok && active.has("lockout")) ok = r.lockout;
      if (ok && active.has("browser")) ok = r.browser;
      r.el.style.display = ok ? "" : "none";
      if (ok) shown++;
    });
    const untracked = rows.filter(r => !r.tracked && !r.browser && !r.group).length;
    count.textContent = t("{0} of {1} settings", shown, rows.length)
      + (active.has("nondefault") && untracked
        ? " · " + t("{0} cannot be compared with a default", untracked) : "");
  };

  SETTING_FACETS.forEach(([key, label, hint]) => {
    const b = el("button", { class: "btn btn-sm sx-facet", title: hint,
      "aria-pressed": "false", "aria-label": t("Filter: {0}", label) }, label);
    b.addEventListener("click", () => {
      if (active.has(key)) { active.delete(key); b.classList.remove("on"); b.setAttribute("aria-pressed", "false"); }
      else { active.add(key); b.classList.add("on"); b.setAttribute("aria-pressed", "true"); }
      apply();
    });
    facetBar.appendChild(b);
  });

  rows.forEach(r => {
    const chips = el("span", { class: "sx-chips" });
    if (r.restart) chips.appendChild(el("span", { class: "tag-restart", title: t("Takes effect after the daemon restarts") }, t("↻ restart")));
    if (r.lockout) chips.appendChild(el("span", { class: "sx-chip warn", title: t("Get this wrong and the panel stops answering") }, t("lock-out risk")));
    if (r.browser) chips.appendChild(el("span", { class: "sx-chip", title: t("Stored in this browser, never sent to the router") }, t("browser only")));
    if (r.nondefault) chips.appendChild(el("span", { class: "sx-chip", title: t("Default is {0}", r.defaultText) }, t("not default")));
    // Name, where it used to live, and the chips all on one line. Stacking them made a plain row
    // three lines tall, and twenty-four of those is three screens — the density the index exists to
    // undo. The section is kept because search matches on it and because "which card was this in"
    // is how anyone who knew the old page will look for it.
    r.el = el("div", { class: "sx-row" + (r.group ? " group" : "") },
      el("div", { class: "sx-key" },
        el("span", { class: "sx-name" }, r.name),
        el("span", { class: "sx-where" }, r.section + (r.card && r.card !== r.name ? " · " + r.card : "")),
        chips),
      el("div", { class: "sx-ctl" }, r.node));
    list.appendChild(r.el);
  });

  search.addEventListener("input", apply);
  // The "changed by you" facet is only truthful if it re-evaluates after an edit.
  list.addEventListener("input", () => { if (active.has("changed") || active.has("nondefault")) apply(); });
  list.addEventListener("change", () => { if (active.has("changed") || active.has("nondefault")) apply(); });

  box.appendChild(el("div", { class: "sx-top" }, search, facetBar));
  box.appendChild(count);
  box.appendChild(list);
  view.appendChild(box);
  apply();
}

// accountCard — the operator's own account: who is signed in, changing the password, signing out.
//
// It fills from /api/auth/status after mount, so a slow answer never holds up the rest of Settings,
// and it renders one of three states because the panel genuinely has three: a password is set, the
// operator declined one, or authentication is off for this process (--dev-no-auth / demo), which is
// not a thing anybody can change from here and must not be presented as if it were.
function accountCard(status) {
  const card = el("div", { class: "card", "data-section": "Account" });
  card.appendChild(el("div", { class: "card-title", style: "margin-bottom:12px" }, t("Account")));
  // Flat on purpose: settingsIndex indexes each direct-child .field as its own searchable row and
  // sweeps the remaining direct children into one "rest of this card" row. Nesting them under a
  // wrapper hid the warning and the button from the page's own search — the fields were indexed and
  // everything explaining them was not.
  const body = card;
  // Built SYNCHRONOUSLY from a status the caller already awaited. settingsIndex dismantles every card
  // into searchable rows at the end of the render, so a card that fills itself from a later promise is
  // empty when that runs — and an empty card indexes to nothing, which is how this section disappeared
  // from the page entirely on its first outing.
  (() => {
    if (!status) {
      body.appendChild(el("div", { class: "hint" }, t("The account state could not be read.")));
      return;
    }
    if (status.passwordless) {
      body.appendChild(el("div", { class: "upd-target-warn" },
        el("strong", {}, t("This panel has no password.")),
        el("span", {}, t("Everyone who can reach it on this network can change routing, DNS and read every tunnel's keys. Other websites cannot drive it — cross-site requests are refused — but nobody here is asked who they are."))));
      body.appendChild(setPasswordForm());
      return;
    }
    // --dev-no-auth or the loopback demo. The status reports configured/authenticated so the panel
    // opens; `bypass` is what distinguishes it from a real account, and without it this card would
    // offer a password form that the daemon refuses (there is no stored credential to change).
    if (status.bypass || !status.configured) {
      body.appendChild(el("div", { class: "hint" },
        t("Authentication is disabled for this process, not by a setting — the daemon was started with --dev-no-auth, or this is the local demo. Restart it without that flag to use accounts.")));
      return;
    }
    body.appendChild(el("div", { class: "row-between" },
      el("div", {}, el("div", {}, t("Signed in as {0}", status.principal || "?")),
        el("div", { class: "hint" }, t("The password is stored only as a memory-hard Argon2id hash."))),
      el("button", { class: "btn btn-sm", onclick: ev => signOut(ev.currentTarget) }, t("Sign out"))));
    body.appendChild(changePasswordForm(status.principal || ""));
  })();
  return card;
}

// setPasswordForm turns a passwordless panel into a protected one. It posts to the same setup route
// the first run uses — which is reachable precisely because no password exists yet.
function setPasswordForm() {
  const frag = document.createDocumentFragment();
  const user = el("input", { type: "text", autocomplete: "username", maxlength: "64", value: "admin" });
  const pass = el("input", { type: "password", autocomplete: "new-password", maxlength: "256" });
  const again = el("input", { type: "password", autocomplete: "new-password", maxlength: "256" });
  const errors = el("div", { class: "settings-errors", role: "alert" });
  const save = el("button", { class: "btn btn-primary btn-sm" }, t("Set a password"));
  save.addEventListener("click", async () => {
    errors.textContent = "";
    if (pass.value !== again.value) { errors.textContent = t("The passwords do not match."); again.focus(); return; }
    save.disabled = true;
    try {
      await api.post("/api/auth/setup", { username: user.value, password: pass.value });
      // The panel now has a session — reload so every later request carries its CSRF token.
      location.reload();
    } catch (e) { errors.textContent = e.message; save.disabled = false; }
  });
  [el("div", { class: "field" }, el("label", {}, t("Username")), user),
    el("div", { class: "field" }, el("label", {}, t("Password")), pass),
    el("div", { class: "field" }, el("label", {}, t("Confirm password")), again),
    el("div", { class: "hint" }, t("Use at least 12 characters.")),
    errors, el("div", { class: "acts" }, save)].forEach(n => frag.appendChild(n));
  return frag;
}

// changePasswordForm asks for the current password even though the caller is already signed in: a
// session is a bearer token, and one that leaked must not be a lever for taking the account over.
// The daemon enforces that too — this form is not the check, it is the way to answer it.
function changePasswordForm(principal) {
  const frag = document.createDocumentFragment();
  const current = el("input", { type: "password", autocomplete: "current-password", maxlength: "256" });
  const next = el("input", { type: "password", autocomplete: "new-password", maxlength: "256" });
  const again = el("input", { type: "password", autocomplete: "new-password", maxlength: "256" });
  const user = el("input", { type: "text", autocomplete: "username", maxlength: "64", value: principal });
  const errors = el("div", { class: "settings-errors", role: "alert" });
  const save = el("button", { class: "btn btn-primary btn-sm" }, t("Change password"));
  save.addEventListener("click", async () => {
    errors.textContent = "";
    if (next.value !== again.value) { errors.textContent = t("The passwords do not match."); again.focus(); return; }
    save.disabled = true;
    try {
      const r = await api.post("/api/auth/password", {
        username: user.value !== principal ? user.value : "",
        current_password: current.value, new_password: next.value,
      });
      // Every other session died with the old password; this one was reissued under a new token, so
      // the panel has to carry the new CSRF token from here on.
      authCSRFToken = r.csrf_token || "";
      current.value = next.value = again.value = "";
      toast(t("Password changed. Any other signed-in device was signed out."), "ok");
      route();
    } catch (e) { errors.textContent = e.message; save.disabled = false; }
  });
  [el("div", { class: "field" }, el("label", {}, t("Current password")), current),
    el("div", { class: "field" }, el("label", {}, t("New password")), next),
    el("div", { class: "field" }, el("label", {}, t("Confirm new password")), again),
    el("div", { class: "field" }, el("label", {}, t("Username")), user),
    el("div", { class: "hint" }, t("At least 12 characters. Changing it signs out every other device.")),
    errors, el("div", { class: "acts" }, save)].forEach(n => frag.appendChild(n));
  return frag;
}

async function signOut(btn) {
  if (!await modalConfirm(t("Sign out of this panel?"))) return;
  if (btn) btn.disabled = true;
  try { await api.post("/api/auth/logout", {}); } catch (e) { /* the cookie is cleared either way */ }
  location.reload();
}

async function renderSettings(view) {
  const loadingCfg = el("div", { class: "hint", style: "margin:18px 0" }, t("loading settings…"));
  view.appendChild(loadingCfg);
  // The config and the account state are independent reads, so they go out together. Awaiting them one
  // after the other cost a whole extra round trip on every Settings open — on a router where each one
  // takes a second or two, that is the difference between a page that appears and a page that arrives.
  let cfg, authState = null;
  try {
    const [c, a] = await Promise.all([
      api.get("/api/config"),
      // Not fatal to Settings: the card says so itself when it cannot be read.
      api.get("/api/auth/status").catch(() => null),
    ]);
    cfg = c;
    authState = a;
  } catch (e) { loadingCfg.remove(); view.appendChild(el("div", { class: "empty" }, t("Could not load config: {0}", e.message))); return; }
  loadingCfg.remove();

  view.appendChild(el("div", { class: "block-head" },
    el("div", {},
      el("div", { class: "desc" }, t("Daemon configuration. Saving here stores these settings; the Apply button in the top bar regenerates routing — they are separate actions. Fields tagged ↻ take effect only after WayHop restarts."))),
    el("div", { class: "side" })));

  // Account leads the page: who is signed in, how to change the password, how to leave. Until now the
  // panel could be logged INTO and never out of — the logout endpoint existed with nothing calling it
  // — the password could not be changed at all without editing config.json over SSH, and a panel
  // running with no password said so nowhere.
  // Read next to the config above, before anything is appended: the card must be complete by the time
  // settingsIndex walks the page.
  view.appendChild(accountCard(authState));

  // Appearance — client-side prefs (theme + language persist in localStorage, not server config).
  const themeSel = el("select", {},
    el("option", { value: "system" }, t("System (match OS)")),
    el("option", { value: "dark" }, t("Dark")),
    el("option", { value: "light" }, t("Light")));
  themeSel.value = themePref();
  themeSel.addEventListener("change", () => setThemePref(themeSel.value));
  const langSel = el("select", {},
    ...I18N_LANGS.map(l => el("option", { value: l.code }, l.code === "auto" ? t("Auto (browser)") : l.name)));
  langSel.value = localStorage.getItem(LANG_KEY) || "auto";
  langSel.addEventListener("change", () => { if (setLang(langSel.value) === false) langSel.value = localStorage.getItem(LANG_KEY) || "auto"; });
  view.appendChild(el("div", { class: "card", "data-section": "Panel" },
    el("div", { class: "card-title", style: "margin-bottom:12px" }, t("Appearance")),
    el("div", { style: "display:flex;gap:16px;flex-wrap:wrap" },
      el("div", { class: "field", style: "margin-bottom:0" }, el("label", {}, t("Theme")), themeSel),
      el("div", { class: "field", style: "margin-bottom:0" }, el("label", {}, t("Language")), langSel))));

  // Subscription auto-refresh — opt-in periodic re-fetch of an imported subscription URL
  // (additive: it only ADDS the provider's newly-rotated servers, never deletes). Self-
  // contained: fetches /api/subscription/info + drives the dedicated control endpoints.
  (function subRefreshCard() {
    // Built imperatively rather than in one el() call, which is why it was missed when the other
    // Settings cards were assigned sections — it rendered orphaned below the navigator.
    const card = el("div", { class: "card", "data-section": "Maintenance" });
    card.appendChild(el("div", { class: "card-title", style: "margin-bottom:12px" }, t("Subscription auto-refresh")));
    const bodyDiv = el("div", {}, el("div", { class: "hint" }, t("loading…")));
    card.appendChild(bodyDiv);
    view.appendChild(card);
    api.get("/api/subscription/info").then(info => {
      bodyDiv.innerHTML = "";
      if (!info || !info.configured) {
        bodyDiv.appendChild(el("div", { class: "hint" }, t("No imported subscription. Import a subscription URL under Connections to enable periodic auto-refresh.")));
        return;
      }
      // `source` is a display-only scheme+host identity from the server. The raw provider URL
      // can carry account credentials in userinfo, query parameters, or its path and is never
      // part of this public DTO (nor accepted as a fallback here).
      bodyDiv.appendChild(el("div", { class: "hint", style: "margin-bottom:10px;word-break:break-all" },
        t("Source: ") + (info.source || "—")));
      const enable = el("input", { type: "checkbox" }); enable.checked = (info.refresh_hours || 0) > 0;
      const hours = el("input", { type: "number", min: "1", max: "168", value: String(info.refresh_hours > 0 ? info.refresh_hours : 24), style: "width:80px" });
      const save = el("button", { class: "btn btn-sm" }, t("Save"));
      const now = el("button", { class: "btn btn-sm" }, t("Refresh now"));
      // Status of the last real refresh attempt (auto loop or manual) — so the user
      // can see auto-refresh is actually working, not just that it's enabled.
      const statusLine = el("div", { class: "hint", style: "margin-top:10px" });
      const relAgo = (unixSec) => {
        const s = Math.max(0, Math.floor(Date.now() / 1000) - unixSec);
        if (s < 60) return t("just now");
        if (s < 3600) return t("{0}m ago", Math.floor(s / 60));
        if (s < 86400) return t("{0}h ago", Math.floor(s / 3600));
        return t("{0}d ago", Math.floor(s / 86400));
      };
      const renderStatus = (lastUnix, added, errStr) => {
        statusLine.innerHTML = "";
        if (errStr) statusLine.appendChild(el("span", { style: "color:var(--bad,#e0666e)" }, t("Last refresh failed: ") + errStr));
        else if (lastUnix > 0) statusLine.appendChild(el("span", {}, t("Last refreshed {0} (+{1} new)", relAgo(lastUnix), added || 0)));
        else statusLine.appendChild(el("span", {}, t("Never refreshed yet")));
      };
      renderStatus(info.last_refresh_unix || 0, info.last_added || 0, info.last_error || "");
      save.addEventListener("click", async () => {
        const h = enable.checked ? Math.max(1, Math.min(168, parseInt(hours.value, 10) || 24)) : 0;
        save.disabled = true;
        try { await api.post("/api/subscription/autorefresh", { hours: h }); toast(h > 0 ? t("Auto-refresh every {0} h", h) : t("Auto-refresh disabled"), "ok"); }
        catch (e) { toast(e.message, "err"); }
        finally { save.disabled = false; }
      });
      now.addEventListener("click", async () => {
        const prev = now.textContent; now.disabled = true; now.textContent = t("Refreshing…");
        try { const r = await api.post("/api/subscription/refresh", {}); const n = (r && r.added) || 0; toast(tn("Refreshed — {0} new connection|Refreshed — {0} new connections", n), "ok"); renderStatus(Math.floor(Date.now() / 1000), n, ""); }
        catch (e) { toast(e.message, "err"); }
        finally { now.disabled = false; now.textContent = prev; }
      });
      bodyDiv.appendChild(el("div", { style: "display:flex;gap:14px;align-items:center;flex-wrap:wrap" },
        el("label", { class: "check" }, enable, el("span", {}, t("Auto-refresh"))),
        el("div", { class: "field", style: "margin-bottom:0" }, el("label", {}, t("Every (hours)")), hours),
        save, now));
      bodyDiv.appendChild(statusLine);
      associateLabels(bodyDiv); // this card's fields are built in an async .then, AFTER route()'s one-shot associateLabels ran
    }).catch(() => { bodyDiv.innerHTML = ""; bodyDiv.appendChild(el("div", { class: "hint" }, t("Could not load subscription info."))); });
  })();

  const txt = (v, ph) => el("input", { type: "text", value: v == null ? "" : String(v), placeholder: ph || "" });
  const num = (v) => el("input", { type: "number", value: v == null ? "" : String(v) });
  const field = (label, input, restart) =>
    el("div", { class: "field" },
      el("label", {}, label, restart ? restartTag() : null), input);

  // Web panel
  // Host only. The panel port lives under Ports -> Web UI, which is what the daemon actually
  // binds (reconcileListen rewrites Listen's port from Ports.UI on every save); accepting a port
  // here too meant one of the two was always thrown away without saying so.
  // The host half of a "host:port" listen string. Shared with SETTING_META below on purpose: the
  // field shows this projection, so the "not default" badge has to compare against the same one.
  const listenHost = hostOfListen(cfg.listen);
  const listen = txt(listenHost, "(all interfaces)");
  // Proxy core
  const sbBin = txt(cfg.singbox && cfg.singbox.bin, "/opt/sbin/sing-box");
  const sbCfg = txt(cfg.singbox && cfg.singbox.config, "/opt/etc/wayhop/singbox.json");
  const clashCtl = txt(cfg.clash && cfg.clash.controller, "127.0.0.1:9090");
  const clashSecF = secretInput(cfg.clash && cfg.clash.secret, t("optional"), "Clash API secret");
  const clashSec = clashSecF.input;
  // Ports
  const pUI = num(cfg.ports && cfg.ports.ui), pClash = num(cfg.ports && cfg.ports.clash),
    pDNS = num(cfg.ports && cfg.ports.dns), pMixed = num(cfg.ports && cfg.ports.mixed);
  // The panel is answering on whatever the daemon BOUND, which is not always what this field says.
  // A daemon started with --listen host:PORT keeps serving that port, while Ports -> Web UI still
  // holds the config's value, and reconcileListen rewrites Listen's port from this field on the next
  // save. Measured while testing: an AX3000T panel launched on 8089 read "Web UI 8088" here, and
  // saving an unrelated setting moved the panel to 8088 and took LAN access with it.
  //
  // The number is not wrong - it is what the next save will bind. The page just reads as a
  // description of the running daemon, so the difference is stated at the one moment it can still be
  // acted on, rather than discovered by a panel that stops answering.
  const boundPort = (() => {
    const v = String(cfg.listen || ""), i = v.lastIndexOf(":");
    const raw = i < 0 ? "" : v.slice(i + 1);
    return /^[0-9]+$/.test(raw) ? Number(raw) : 0;
  })();
  const uiPort = Number((cfg.ports && cfg.ports.ui) || 0);
  const portDrift = boundPort && uiPort && boundPort !== uiPort ? boundPort : 0;
  // Mirrors used when DOWNLOADING a component release. Named for what they do rather than for the
  // section they belong to: that section is Components now, and a label naming a page that no longer
  // exists sends the reader looking for it.
  const mirrors0 = (cfg.updater && cfg.updater.mirrors) || [];
  const directFirst = el("input", { type: "checkbox" }); directFirst.checked = mirrors0.includes("");
  const mirrorsTA = el("textarea", { placeholder: "https://ghproxy.net/\nhttps://mirror.ghproxy.com/", "aria-label": t("Component download mirrors") });
  mirrorsTA.value = mirrors0.filter(m => m !== "").join("\n");
  // Watchdog (webhook may embed a token → masked)
  const wdURLF = secretInput(cfg.watchdog && cfg.watchdog.notify_url, "https://… (optional, blank = off)", "notification URL");
  const wdURL = wdURLF.input;
  // Fail-safe (Apply rollback)
  const fsTarget = txt(cfg.failsafe && cfg.failsafe.target, "1.1.1.1");
  const fsReboot = el("input", { type: "checkbox" }); fsReboot.checked = !!(cfg.failsafe && cfg.failsafe.auto_reboot);
  // Mode
  const demo = el("input", { type: "checkbox" }); demo.checked = !!cfg.demo;
  // Security — Host allow-list (DNS-rebinding guard; one host per line, empty = allow any)
  const allowedHosts = el("textarea", { placeholder: "192.168.50.1\nrouter.lan", "aria-label": t("Host allow-list") });
  allowedHosts.value = (cfg.allowed_hosts || []).join("\n");
  // Routing mode (applies on the next Apply, not a restart)
  const autoRouteCapability = cfg.gateway ? "routing.mode.tun" : "routing.mode.mixed";
  const ROUTE_MODES = [
    ["hybrid", t("Everything via WayHop (domain carve-outs work; general traffic slower / CPU-bound)"), "routing.mode.hybrid"],
    ["fast", t("Fast: general traffic bypasses WayHop (kernel fast-path) — IP carve-outs (calls/VoWiFi) still work; domain carve-outs OFF"), "routing.mode.fast"],
    ["tun", t("All traffic through sing-box (TUN)"), "routing.mode.tun"],
    ["mixed", t("Local proxy only, no gateway (mixed)"), "routing.mode.mixed"],
    ["", t("Auto (derive from Gateway)"), autoRouteCapability],
  ];
  const routeMode = el("select", { id: "settings-routing-mode", "aria-describedby": "settings-routing-support" },
    ...ROUTE_MODES.map(m => el("option", { value: m[0], "data-capability": m[2], "data-base-label": m[1] }, m[1])));
  routeMode.value = cfg.routing_mode || "";
  const routeModeSupportText = el("span", {});
  const capabilityRetry = el("button", { class: "btn btn-sm", type: "button", style: "display:none;margin-left:8px" }, t("Retry"));
  const routeModeSupport = el("div", { id: "settings-routing-support", class: "hint", "aria-live": "polite", style: "margin-top:6px" },
    routeModeSupportText, capabilityRetry);
  // Flow offload (Phase 1b): accelerates GENERAL traffic in Fast mode. Carve-outs are
  // mark-routed and auto-excluded from the flowtable, so they keep working. Devices blank
  // => the daemon auto-probes the WAN uplink + LAN bridge.
  const OFFLOAD_MODES = [
    // "auto" resolves server-side against this router's accelerator (platform.ResolveOffload) and is
    // listed first: it is the right answer for anyone who does not already know whether their SoC has
    // a flowtable. When it resolves to Off, preflight says so and why.
    ["auto", t("Automatic — pick the safest option this router supports"), ""],
    ["", t("Off (default)"), ""],
    ["sw", t("Software flow-offload (recommended)"), "offload.software"],
    ["hw", t("Hardware offload (PPE/WED) — can stall VPN tunnels; not faster on most routers"), "offload.hardware"],
  ];
  const offloadSel = el("select", { "aria-describedby": "settings-offload-support" },
    ...OFFLOAD_MODES.map(m => el("option", { value: m[0], "data-capability": m[2], "data-base-label": m[1] }, m[1])));
  offloadSel.value = cfg.offload || "";
  const offloadDevs = el("input", { type: "text", placeholder: t("auto-detect (leave blank)") });
  offloadDevs.value = (cfg.offload_devices || []).join(" ");
  const offloadSupport = el("div", { id: "settings-offload-support", class: "hint", "aria-live": "polite", style: "margin-top:6px" });

  // Gate capabilities at the point of choice. Auto is bound to the capability of the mode it
  // actually derives (Gateway => TUN, otherwise Mixed), so it cannot bypass a failed probe. A
  // currently saved unsupported value stays selected and survives an unrelated
  // Save, but its option is disabled so it cannot be selected again. The old Keenetic gate assigned
  // offloadSel.value="" asynchronously and could silently erase the saved setting.
  let lastCapabilitySet = null;
  function capabilityExplanation(item) {
    if (!item) return t("Support was not reported by this router.");
    return [item.detail, item.remedy].filter(Boolean).join(" ");
  }
  function setCapabilityOption(option, item, verified, platformName) {
    const supported = verified && item && item.state === "supported";
    option.disabled = !supported;
    let platformSuffix = "";
    if (platformName === "keenetic") {
      if (option.value === "mixed") platformSuffix = t(" — Keenetic native mode");
      if (option.value === "tun") platformSuffix = t(" — sing-box compatibility");
    }
    const stateSuffix = supported ? "" : (verified && item && item.state !== "unknown"
      ? t(" — unavailable on this router") : t(" — support not verified"));
    option.textContent = option.dataset.baseLabel + platformSuffix + stateSuffix;
    return supported;
  }
  function paintCapabilityControls(response, error) {
    const set = response && response.capability_set;
    const items = set && set.items;
    const verified = !!items && !set.probe_error;
    lastCapabilitySet = verified ? set : null;

    let routeSupported = 0;
    [...routeMode.options].forEach(option => {
      const id = option.dataset.capability;
      if (!id) { option.disabled = false; option.textContent = option.dataset.baseLabel; return; }
      if (setCapabilityOption(option, items && items[id], verified, set && set.platform)) routeSupported++;
    });
    let offloadSupported = 0;
    [...offloadSel.options].forEach(option => {
      const id = option.dataset.capability;
      if (!id) { option.disabled = false; option.textContent = option.dataset.baseLabel; return; }
      if (setCapabilityOption(option, items && items[id], verified, set && set.platform)) offloadSupported++;
    });
    offloadDevs.disabled = offloadSupported === 0;

    const selectedOption = [...routeMode.options].find(o => o.value === routeMode.value);
    const selectedID = selectedOption && selectedOption.dataset.capability;
    const selected = selectedID && items ? items[selectedID] : null;
    if (error || !verified) {
      routeModeSupportText.textContent = t("WayHop could not verify router support. Saved values are retained; no routing mode can be selected until the check succeeds. ") +
        (error ? error.message : capabilityExplanation(selected));
      capabilityRetry.style.display = "inline-flex";
      offloadSupport.textContent = t("Flow-offload support is not verified. The saved value will not be changed.");
    } else {
      capabilityRetry.style.display = "none";
      if (routeMode.value === "" && selected && selected.state === "supported") {
        routeModeSupportText.textContent = t("Automatic derives the safe Mixed or TUN mode from the Gateway setting.") + " " +
          t("Supported by this router. Only modes proven usable are selectable.");
      } else if (selected && selected.state === "supported") {
        routeModeSupportText.textContent = t("Supported by this router. Only modes proven usable are selectable.");
      } else {
        routeModeSupportText.textContent = t("This saved mode is retained but cannot be activated on this router. Choose an available mode. ") + capabilityExplanation(selected);
      }
      offloadSupport.textContent = offloadSupported
        ? t("Only flow-offload modes proven usable by this router are selectable.")
        : t("WayHop does not control this router's acceleration. The saved value is retained; use Off or Automatic.");
    }
    routeMode.dataset.supportedCount = String(routeSupported);
  }
  paintCapabilityControls(null, null);
  routeMode.addEventListener("change", () => paintCapabilityControls(lastCapabilitySet ? { capability_set: lastCapabilitySet } : null, null));
  let capabilityCheckBusy = false;
  async function loadCapabilityControls() {
    if (capabilityCheckBusy) return;
    capabilityCheckBusy = true;
    capabilityRetry.disabled = true;
    routeModeSupportText.textContent = t("Checking router support…");
    try { paintCapabilityControls(await api.get("/api/native/capabilities"), null); }
    catch (e) { paintCapabilityControls(null, e); }
    finally { capabilityCheckBusy = false; capabilityRetry.disabled = false; }
  }
  capabilityRetry.addEventListener("click", loadCapabilityControls);
  loadCapabilityControls();

  const save = el("button", { class: "btn btn-primary" }, t("Save settings"));
  const status = el("span", { class: "hint", style: "margin-right:12px" });
  const dirtyBadge = el("span", { class: "dirty-badge", style: "display:none" }, t("Unsaved changes"));
  const errBox = el("div", { class: "settings-errors" });
  let lastSavedRouteMode = cfg.routing_mode || "";
  let lastSavedOffload = (cfg.offload || "") + "|" + ((cfg.offload_devices || []).join(" "));

  // collectSettings builds the saved config object from the live controls. Field
  // handling matches the server's expectations: the mirrors direct-first ""
  // sentinel, clash.secret kept verbatim (untrimmed), ports coerced to numbers,
  // allowed_hosts split + trimmed + de-blanked.
  function collectSettings() {
    const mirrors = [];
    if (directFirst.checked) mirrors.push("");
    mirrorsTA.value.split("\n").map(s => s.trim()).filter(Boolean).forEach(m => mirrors.push(m));
    return {
      ...cfg,
      // Recomposed from the two fields that own the two halves, so what is submitted is what
      // the daemon will bind.
      listen: listen.value.trim() + ":" + (+pUI.value || 0),
      demo: demo.checked,
      routing_mode: routeMode.value,
      offload: offloadSel.value,
      offload_devices: offloadDevs.value.split(/[\s,]+/).map(s => s.trim()).filter(Boolean),
      ports: { ui: +pUI.value || 0, clash: +pClash.value || 0, dns: +pDNS.value || 0, mixed: +pMixed.value || 0 },
      clash: { controller: clashCtl.value.trim(), secret: clashSec.value },
      singbox: { bin: sbBin.value.trim(), config: sbCfg.value.trim() },
      updater: { ...(cfg.updater || {}), mirrors },
      watchdog: { ...(cfg.watchdog || {}), notify_url: wdURL.value.trim() },
      failsafe: { ...(cfg.failsafe || {}), target: fsTarget.value.trim(), auto_reboot: fsReboot.checked },
      allowed_hosts: allowedHosts.value.split("\n").map(s => s.trim()).filter(Boolean),
    };
  }

  // Dirty tracking: baseline the controls now, flag any divergence so the user
  // gets an "Unsaved changes" cue and a guard against losing edits on reload/close.
  let baseline = JSON.stringify(collectSettings());
  const markDirty = () => {
    _settingsDirty = JSON.stringify(collectSettings()) !== baseline;
    dirtyBadge.style.display = _settingsDirty ? "" : "none";
  };
  // #view persists across renders (innerHTML is cleared, not the element), so drop
  // any prior render's delegated handler before re-adding to avoid accumulation.
  if (view._wrDirty) { view.removeEventListener("input", view._wrDirty); view.removeEventListener("change", view._wrDirty); }
  view._wrDirty = markDirty;
  view.addEventListener("input", markDirty);
  view.addEventListener("change", markDirty);
  // Nav-guard registration: the SPA hash guard + the global beforeunload hook both
  // consult this (see registerDirtyCheck) — no page-local beforeunload needed.
  registerDirtyCheck("settings", () => _settingsDirty, () => { _settingsDirty = false; });

  save.addEventListener("click", async () => {
    const next = collectSettings();
    const errs = validateSettingsClient(next);
    // Lock-out guard: a non-empty allow-list that omits the host you're using now
    // would 403 you on the next request — block and offer to add it.
    const here = normalizeHostJS(location.hostname);
    const lockedOut = next.allowed_hosts.length && here && !next.allowed_hosts.map(normalizeHostJS).includes(here);
    errBox.innerHTML = "";
    errs.forEach(m => errBox.appendChild(el("div", { class: "err-row" }, m)));
    if (lockedOut) {
      const addBtn = el("button", { class: "btn btn-sm", type: "button" }, t("Add current host") + " (" + location.hostname + ")");
      addBtn.addEventListener("click", () => {
        allowedHosts.value = (allowedHosts.value.trim() ? allowedHosts.value.trim() + "\n" : "") + location.hostname;
        markDirty(); errBox.innerHTML = "";
      });
      errBox.appendChild(el("div", { class: "err-row" }, t("The host you are using is not in the allow-list — you would lock yourself out.")));
      errBox.appendChild(addBtn);
    }
    if (errs.length || lockedOut) { errBox.scrollIntoView({ block: "nearest" }); return; }

    save.disabled = true; status.textContent = t("saving…");
    try {
      const r = await api.put("/api/config", next);
      status.textContent = "";
      const routeModeChanged = (next.routing_mode || "") !== lastSavedRouteMode;
      const offloadNow = (next.offload || "") + "|" + ((next.offload_devices || []).join(" "));
      const offloadChanged = offloadNow !== lastSavedOffload;
      cfg = next;
      lastSavedRouteMode = next.routing_mode || "";
      lastSavedOffload = offloadNow;
      baseline = JSON.stringify(collectSettings()); _settingsDirty = false; dirtyBadge.style.display = "none";
      // Config now feeds the canonical applied-state (routing mode / TUN / offload…), so a
      // config-only save can flip the backend to "pending" — refresh the Apply banner NOW.
      refreshApplyState();
      toast(r.restart_needed ? t("Saved — restart WayHop for all changes to take effect.") : t("Saved."), "ok");
      if (routeModeChanged) toast(t("Routing mode changed — press Apply (top bar) to activate it."), "info");
      else if (offloadChanged) toast(t("Flow offload changed — press Apply (top bar) to activate it."), "info");
    } catch (e) { status.textContent = ""; toast(e.message, "err"); }
    finally { save.disabled = false; }
  });

  view.appendChild(el("div", { class: "card", "data-section": "Routing & core" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, t("Routing mode")),
    el("div", { class: "hint", style: "margin-bottom:10px" }, t("How LAN traffic is routed. «Fast» keeps your tunnels/carve-outs for IPs (calls, VoWiFi) but lets general traffic (downloads, games) take the kernel fast-path instead of the userspace proxy — much higher throughput. Takes effect on the next Apply.")),
    field(t("Mode"), routeMode), routeModeSupport,
    el("div", { class: "hint", style: "margin:14px 0 10px" }, t("Flow offload accelerates general (non-tunnel) traffic via the kernel fast path in «Fast» mode. Your tunnel carve-outs (calls, VoWiFi, blocked sites) are mark-routed and automatically excluded, so they keep working. «Software» is recommended — it routes near line-rate on most routers without touching your tunnels. «Hardware» (PPE/WED) can be faster on some NICs, but on many routers it has a bug that stalls VPN tunnels (long-lived UDP) and is no faster than software — avoid it if you route any traffic through a tunnel. Leave devices blank to auto-detect the WAN + LAN interfaces. Takes effect on the next Apply.")),
    el("div", { style: "display:flex;gap:12px;flex-wrap:wrap" },
      el("div", { style: "flex:1;min-width:220px" }, field(t("Flow offload"), offloadSel)),
      el("div", { style: "flex:1;min-width:220px" }, field(t("Offload devices"), offloadDevs))),
    offloadSupport));

  view.appendChild(el("div", { class: "card", "data-section": "Panel" },
    el("div", { class: "card-title", style: "margin-bottom:12px" }, t("Web panel")),
    field("Listen host", listen, true),
    el("div", { class: "hint" },
      "Which interface the panel answers on. Blank means all of them. The port is set under "
      + "Ports → Web UI.")));

  view.appendChild(el("div", { class: "card", "data-section": "Routing & core" },
    el("div", { class: "card-title", style: "margin-bottom:12px" }, t("Proxy core")),
    el("div", { style: "display:flex;gap:12px;flex-wrap:wrap" },
      el("div", { style: "flex:1;min-width:220px" }, field(t("sing-box binary"), sbBin, true)),
      el("div", { style: "flex:1;min-width:220px" }, field(t("sing-box config"), sbCfg, true))),
    el("div", { style: "display:flex;gap:12px;flex-wrap:wrap" },
      el("div", { style: "flex:1;min-width:220px" }, field(t("Clash controller"), clashCtl)),
      el("div", { style: "flex:1;min-width:220px" }, field(t("Clash secret"), clashSecF.row)))));

  view.appendChild(el("div", { class: "card", "data-section": "Panel" },
    el("div", { class: "card-title", style: "margin-bottom:12px" }, t("Ports"), restartTag()),
    el("div", { class: "kv-grid" },
      field(t("Web UI"), portDrift
        // Inside the field on purpose: the settings index re-renders each .field as one row and drops
        // any leftover card content that carries no control, so a sibling hint would never be seen.
        ? el("div", {}, pUI, el("div", { class: "hint upd-err", style: "margin-top:6px" },
          t("The panel is answering on port {0} right now. Saving binds it to {1} — reopen the panel there.",
            portDrift, uiPort)))
        : pUI),
      field(t("Clash API"), pClash), field(t("DNS"), pDNS), field(t("Mixed (socks+http)"), pMixed))));

  view.appendChild(el("div", { class: "card", "data-section": "Maintenance" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, t("Component download mirrors")),
    el("div", { class: "hint", style: "margin-bottom:10px" }, t("GitHub URL prefixes tried in order when downloading engine binaries — fix these if a mirror is blocked in your region.")),
    el("label", { class: "check", style: "display:inline-flex;margin-bottom:10px" }, directFirst, el("span", {}, t("Try a direct connection first"))),
    mirrorsTA));

  view.appendChild(el("div", { class: "card", "data-section": "Reliability" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, t("Watchdog alerts")),
    el("div", { class: "hint", style: "margin-bottom:10px" }, t("Optional webhook POSTed {\"text\":\"…\"} on each sing-box crash-restart (e.g. a Telegram bot endpoint). Leave blank to disable.")),
    field(t("Notify webhook URL"), wdURLF.row)));

  view.appendChild(el("div", { class: "card", "data-section": "Reliability" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, t("Fail-safe")),
    el("div", { class: "hint", style: "margin-bottom:10px" }, t("After an Apply (not yet saved), WayHop pings this target to confirm the new config kept you online; if it can't be reached, the previous config is rolled back.")),
    field(t("Connectivity-check target"), fsTarget),
    el("label", { class: "check", style: "display:inline-flex;margin-top:10px" }, fsReboot, el("span", {}, t("Allow auto-reboot as a last resort"))),
    el("div", { class: "hint", style: "margin-top:6px" }, t("Off by default. Only triggers if a rollback still can't restore connectivity — leave off unless you trust unattended reboots."))));

  // Titled for what it holds. It was "Mode", which collided with the routing-mode field also called
  // "Mode": the settings index keys a row's metadata BY NAME, so this card inherited the routing
  // mode's config path and was compared against it — a checkbox against a routing-mode string, which
  // can never match, so it reported "not default" forever whatever the operator had set.
  view.appendChild(el("div", { class: "card", "data-section": "Reliability" },
    el("div", { class: "card-title", style: "margin-bottom:10px" }, t("Demo mode")),
    el("label", { class: "check", style: "display:inline-flex" }, demo, el("span", {}, t("Demo mode (synthesize traffic when sing-box is absent)"))),
    el("div", { class: "hint", style: "margin-top:6px" }, restartTag(), t(" applies after restart"))));

  view.appendChild(el("div", { class: "card", "data-section": "Panel" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, t("Security"), restartTag()),
    el("div", { class: "hint", style: "margin-bottom:10px" }, t("Host allow-list — one hostname or IP per line. When set, the panel only answers requests whose Host header matches one of these (a DNS-rebinding defense). Leave EMPTY to allow any host (the default). List every name/IP you use to reach the panel, or you will lock yourself out (recover by clearing it in config.json and restarting).")),
    allowedHosts));

  // Backup & restore — download/upload the whole config + reset to defaults.
  const includeSecrets = el("input", { type: "checkbox" });
  const downloadBtn = el("button", { class: "btn", type: "button" }, t("Download backup"));
  downloadBtn.addEventListener("click", () => {
    const a = el("a", { href: "/api/config/export" + (includeSecrets.checked ? "?secrets=1" : ""), download: "wayhop-config.json" });
    document.body.appendChild(a); a.click(); a.remove();
  });
  const fileInput = el("input", { type: "file", accept: "application/json,.json", style: "display:none" });
  const restoreBtn = el("button", { class: "btn", type: "button" }, t("Restore from file…"));
  restoreBtn.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", async () => {
    const f = fileInput.files && fileInput.files[0];
    if (!f) return;
    let parsed;
    try { parsed = JSON.parse(await f.text()); }
    catch { fileInput.value = ""; return toast(t("That file is not valid JSON."), "err"); }
    if (!await modalConfirm(t("Restore settings from this backup? It replaces your current settings (they are validated first)."))) { fileInput.value = ""; return; }
    try {
      const r = await api.post("/api/config/import", parsed);
      toast(r.restart_needed ? t("Restored — restart WayHop to apply.") : t("Restored."), "ok");
      route();
    } catch (e) { toast(e.message, "err"); }
    finally { fileInput.value = ""; }
  });
  const resetBtn = el("button", { class: "btn btn-danger", type: "button" }, t("Reset to defaults"));
  resetBtn.addEventListener("click", async () => {
    if (!await modalConfirm(t("Reset to defaults") + "?")) return;
    try {
      const r = await api.post("/api/config/reset", {});
      toast(r.restart_needed ? t("Reset to defaults — restart WayHop to apply.") : t("Reset to defaults."), "ok");
      route();
    } catch (e) { toast(e.message, "err"); }
  });
  view.appendChild(el("div", { class: "card", "data-section": "Maintenance" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, t("Backup & restore")),
    el("div", { class: "hint", style: "margin-bottom:12px" }, t("Download all settings as a file, restore from a backup, or reset to defaults. Secrets are left out of a backup unless you tick “Include secrets”.")),
    el("div", { style: "display:flex;gap:10px;flex-wrap:wrap;align-items:center" },
      downloadBtn,
      el("label", { class: "check", style: "display:inline-flex" }, includeSecrets, el("span", {}, t("Include secrets"))),
      restoreBtn, fileInput, resetBtn)));

  // Full backup (everything) — the whole setup (connections, failover groups,
  // routing lists, saved servers, routing mode) in one file, for saving before a
  // firmware reflash or migrating to another WayHop instance.
  const fullDownloadBtn = el("a", { class: "btn", href: "/api/backup", download: "wayhop-backup.json" }, t("Download full backup"));
  const fullFileInput = el("input", { type: "file", accept: "application/json,.json", style: "display:none" });
  const fullRestoreBtn = el("button", { class: "btn", type: "button" }, t("Restore full backup…"));
  fullRestoreBtn.addEventListener("click", () => fullFileInput.click());
  fullFileInput.addEventListener("change", async () => {
    const f = fullFileInput.files && fullFileInput.files[0];
    if (!f) return;
    let parsed;
    try { parsed = JSON.parse(await f.text()); }
    catch { fullFileInput.value = ""; return toast(t("That file is not valid JSON."), "err"); }
    if (!parsed || typeof parsed !== "object" || parsed.wayhop_backup !== 1) { fullFileInput.value = ""; return toast(t("That is not a WayHop full backup."), "err"); }
    if (!await modalConfirm(t("Restore your whole setup from this backup? It replaces all connections, groups and routing lists (validated first). Nothing is applied automatically — review it, then press Apply. Your panel address and access settings are NOT changed."))) { fullFileInput.value = ""; return; }
    try {
      const r = await api.post("/api/backup/restore", parsed);
      toast(t("Restored {0} connections, {1} groups, {2} servers — review and press Apply to activate.", r.endpoints, r.groups, r.servers), "ok");
      await loadProfile();
      route();
    } catch (e) { toast(e.message, "err"); }
    finally { fullFileInput.value = ""; }
  });
  view.appendChild(el("div", { class: "card", "data-section": "Maintenance" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, t("Full backup (everything)")),
    el("div", { class: "hint", style: "margin-bottom:6px" }, t("Save your whole setup — connections, failover groups, routing lists, saved servers and routing mode — to one file. Ideal before a firmware reflash or when moving to another WayHop. Restoring validates everything first and never applies on its own; you review it and press Apply.")),
    el("div", { class: "hint", style: "margin-bottom:12px" }, t("The backup file contains your connection secrets (keys, passwords) — keep it private. Daemon access settings (panel port and host allow-list) are NOT changed by a restore.")),
    el("div", { style: "display:flex;gap:10px;flex-wrap:wrap;align-items:center" },
      fullDownloadBtn, fullRestoreBtn, fullFileInput)));

  const restartBtn = el("button", { class: "btn btn-danger" }, t("Restart service"));
  restartBtn.addEventListener("click", restartService);
  if (cfg.demo) restartBtn.disabled = true; // the demo daemon rejects /api/service/restart — don't let the button dead-end after a confirm; the card copy already says it's unavailable
  view.appendChild(el("div", { class: "card", "data-section": "Reliability" },
    el("div", { class: "card-title", style: "margin-bottom:10px" }, t("Service")),
    el("div", { class: "hint", style: "margin-bottom:12px" }, t("Restart the whole WayHop daemon (panel + proxy core). The web panel drops for a few seconds while the init system brings it back; this page reconnects automatically. (Not available in the demo.)")),
    restartBtn));

  // The defaults are what makes "not default" a fact rather than a guess. Best-effort: an older
  // daemon without the route simply means that one facet cannot judge anything, and the index says
  // so per row instead of quietly reporting every setting as untouched.
  let cfgDefaults = null;
  try { cfgDefaults = await api.get("/api/config/defaults"); } catch (_) { cfgDefaults = null; }
  settingsIndex(view, cfgDefaults);
  view.appendChild(errBox);
  view.appendChild(el("div", { class: "row-between", style: "margin-top:4px" }, el("div"),
    el("div", { style: "display:flex;align-items:center" }, dirtyBadge, status, save)));
  _settingsDirty = false; dirtyBadge.style.display = "none";
}

/* ---------- data ---------- */
async function loadProfile() {
  // ?lite=1 — the profile WITHOUT the routing lists' feed caches, which are the only large thing in
  // it and which nothing here reads. This runs on every page render and after every mutation, so on
  // a live router it was fetching 275 KB (one list holds 15 866 CIDRs) about thirty times a
  // session to use a few kilobytes of names and toggles. The two places that need a cache SIZE read
  // cidr_cache_count / domain_cache_count, which lite carries. The full form stays on the bare URL:
  // it is the backup format, and a backup without caches restores a router that cannot apply.
  const p = await api.get("/api/profile?lite=1");
  // Go marshals nil slices as JSON null; the UI assumes arrays everywhere.
  p.endpoints = p.endpoints || [];
  p.groups = p.groups || [];
  p.rules = p.rules || [];
  p.routing_lists = p.routing_lists || [];
  // Nested: a group's members can be null too (dashboard/Failover call .map on it).
  p.groups.forEach(g => { g.members = g.members || []; });
  state.profile = p;
  updateDirty();
  refreshApplyState(); // authoritative pending from the backend — runs on load + after every mutation
}
async function loadHealth() { state.health = await api.get("/api/health"); updateStatusPill(); }

/* ---------- init ---------- */
async function init() {
  $$(".nav-item").forEach(wireNavItem); // keyboard-operable nav (role/tabindex/Enter-Space); see wireNavItem
  // Mobile nav drawer: the burger is a real <button> (index.html) and nav.js owns its
  // click→checkbox toggle + aria-expanded sync (single owner — a second keydown handler
  // here would double-toggle with the button's native Enter/Space activation). Here we
  // only drop the hidden CSS-toggle checkbox out of the tab order so keyboard users land
  // on the button, not on an aria-hidden checkbox.
  const navToggle = $("#navtoggle");
  if (navToggle) navToggle.tabIndex = -1;
  const ab = $("#applybtn");
  if (ab) ab.addEventListener("click", () => openReviewChanges());
  window.addEventListener("hashchange", onHashChange);
  await ensureAuthenticated();
  // Cold-load: fetch the authoritative pending state NOW, whatever the first page is.
  // Without this the Apply banner only appeared after some page happened to call
  // loadProfile() — a reload landing on Diagnostics/Settings showed no banner while
  // changes were in fact pending. refreshApplyState() swallows transient errors itself.
  await refreshApplyState();
  try { await loadHealth(); } catch (_) {}
  checkFailsafe(); // re-arm the rollback countdown if a reload landed mid-Apply-window
  try { await seedIfaceSeries(); drawGraph(); } catch (_) {} // pre-fill the per-iface graph with recent RAM history
  pollHealth();
  // Polling is gated to keep the router idle: nothing fires while the tab is hidden, and per-tunnel
  // health polls only where pills/stats are shown. The graph is redrawn by the 5s health tick (which
  // updates ifaceSeries) — there is no separate 1 Hz traffic poll.
  const page = () => (location.hash || "#dashboard").slice(1);
  // Failover belongs here too: its cards read the SAME healthMap this poll fills — ping, uptime %,
  // bytes transferred, "up <age>" and each member's alive/down state — and the page's own repaint
  // only refreshes the daemon's election, so it faithfully re-rendered a snapshot taken when the
  // page loaded. Measured on a live Keenetic, sixteen minutes after opening the page:
  // healthMap uptime_s = 13 against the API's 972, so the Exit capacity card read "up 13s" and
  // "12.2 MB transferred" while the tunnel had carried 943 MB. This is the page someone opens to
  // ask which exit is carrying traffic RIGHT NOW.
  const onHealth = () => page() === "dashboard" || page() === "connections" || page() === "failover";
  setInterval(() => { if (!document.hidden) { loadHealth().catch(e => { if (isNetworkError(e)) showReconnect(); }); checkFailsafe(); checkGraphStale(); } }, 5000);
  setInterval(() => { if (!document.hidden && onHealth()) pollHealth(); }, 5000);
  // /api/state every 10 s while the tab is visible: an edit made from another device (or another
  // tab) flips "pending" here without a reload. Skipped mid-Apply — applyConfig owns the state then.
  setInterval(() => { if (!document.hidden && !applyInFlight) refreshApplyState(); }, 10000);
  // Refresh immediately on tab refocus so data isn't a full interval stale.
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) return;
    loadHealth().catch(e => { if (isNetworkError(e)) showReconnect(); });
    checkFailsafe();
    if (!applyInFlight) refreshApplyState();
    if (onHealth()) pollHealth();
  });
  i18nObserve();
  translateChrome();
  route();
}
init();

/* ---------- Review & Apply panel ----------
 * What an Apply would do, before it does it: the plan from GET /api/apply/plan — findings (blocked /
 * needs acknowledgement / notes) above the change set grouped by subsystem with per-change /
 * per-group / all undo — and the two actions, Test safely (auto-rollback window) and Apply & Save.
 * Every row is server-derived — never a diff of rendered HTML — and secrets are already redacted
 * server-side ("Not set → Set" / "Changed"), so nothing here can leak a key. Undo calls
 * POST /api/changeset/undo, which reverts the REAL stored data, then re-fetches the plan so the count
 * can never drift from the truth. The plan's `rev` is the ONE thing Apply is pinned to; a stale one
 * comes back as 409 REV_STALE with the current plan and re-renders here (docs/APPLY_REDESIGN.md in the development repository).
 */
const CS_SUBSYSTEM_LABEL = {
  connections: L("Connections"), native_vpn: L("Native VPN"), routing: L("Routing"),
  device_rules: L("Device rules"), groups: L("Groups"), dns: L("DNS"),
  firewall_pbr: L("Firewall & routing"), offload: L("Offload"), general: L("Settings"), external: L("External changes"),
};
// Action → { icon, label }. Colour is NEVER the only signal (§1.3): every row carries an icon AND
// a text label, so the diff stays readable in high-contrast mode and for colour-blind users.
const CS_ACTION_META = {
  added: { icon: "+", label: L("Added") },
  removed: { icon: "−", label: L("Removed") },
  modified: { icon: "±", label: L("Modified") },
  reordered: { icon: "↕", label: L("Reordered") },
  externally_changed: { icon: "!", label: L("Changed externally") },
};

// csRow renders one change: what/where + before→after + why it matters + its own undo.
function csRow(ch, onUndo) {
  const meta = CS_ACTION_META[ch.action] || { icon: "•", label: ch.action || "" };
  const head = el("div", { class: "cs-head" },
    el("span", { class: "cs-badge cs-" + (ch.action || "modified"), title: t(meta.label) },
      el("span", { "aria-hidden": "true" }, meta.icon), " ", t(meta.label)),
    el("span", { class: "cs-obj" }, ch.object_name || ch.id),
    ch.field ? el("span", { class: "cs-field" }, ch.field) : null);

  // before → after, stacked (never side-by-side) so it never needs horizontal scrolling on mobile.
  let diff = null;
  if (ch.before || ch.after) {
    diff = el("div", { class: "cs-diff" },
      el("span", { class: "cs-before" }, ch.before || "—"),
      el("span", { class: "cs-arrow", "aria-hidden": "true" }, " → "),
      el("span", { class: "cs-after" }, ch.after || "—"));
    if (ch.secret) diff.appendChild(el("span", { class: "pill muted cs-secret" }, t("secret hidden")));
  }

  const flags = el("div", { class: "cs-flags" });
  if (ch.may_interrupt) flags.appendChild(el("span", { class: "pill warn" }, t("May interrupt connectivity")));
  if (ch.requires_service_restart) flags.appendChild(el("span", { class: "pill muted" }, t("Restarts the service")));
  if (ch.requires_reboot) flags.appendChild(el("span", { class: "pill warn" }, t("Needs a router reboot")));
  (ch.warnings || []).forEach(wn => flags.appendChild(el("span", { class: "pill err" }, wn)));

  return el("div", { class: "cs-row" },
    el("div", { class: "cs-main" }, head, diff,
      ch.impact ? el("div", { class: "hint cs-impact" }, ch.impact) : null,
      flags.childNodes.length ? flags : null),
    el("button", {
      class: "btn btn-ghost btn-sm", type: "button", title: t("Undo this change"),
      onclick: () => onUndo(ch.field ? { scope: "field", id: ch.id, field: ch.field } : { scope: "object", id: ch.id }),
    }, t("Undo")));
}

// Finding taxonomy (docs/APPLY_REDESIGN.md in the development repository, "Decisions"): blocks=apply is a hard blocker the router
// cannot execute — never acknowledgeable; ack_required (blocks=feature, or a privacy finding) needs
// an explicit tick, remembered server-side by finding id; blocks=nothing/optimisation is
// informational and folds away under "N notes".
function findingBlocks(f) { return !!f && f.blocks === "apply"; }
// findingNeedsAck asks the SERVER's answer rather than re-deriving one. The client used to add its
// own conditions — anything blocking a feature, anything about privacy — so a finding the server had
// already decided was informational still demanded a checkbox here, and the two halves of the same
// decision could not be changed in one place.
function findingNeedsAck(f) { return !!f && !findingBlocks(f) && f.ack_required === true; }
// findingStatus is the row's status pill: [pill class, text]. Text, not colour, carries the meaning.
function findingStatus(f) {
  if (findingBlocks(f)) return ["err", t("Blocks Apply")];
  if (f.severity === "privacy") return ["warn", t("Privacy")];
  if (findingNeedsAck(f)) return ["warn", t("Needs confirmation")];
  return ["muted", t("Note")];
}
function fmtAppliedAt(v) {
  if (!v) return "";
  let d;
  if (typeof v === "number") d = new Date(v < 1e12 ? v * 1000 : v);
  else { const p = Date.parse(String(v)); if (!isFinite(p)) return String(v); d = new Date(p); }
  return isFinite(d.getTime()) ? d.toLocaleString() : "";
}

// reviewedPlan is the plan the user actually saw; Apply sends its `rev` back so the server can say
// "that moved" (409 REV_STALE, carrying the current plan). ackedFindings are the ids whose box is
// ticked in the open panel; Apply sends them as `ack` and the server remembers them.
let reviewedPlan = null;
const ackedFindings = new Set();
let _reviewPanelEl = null;
let _reviewPanelOpening = false;
let _reviewRerender = null; // re-renders the OPEN panel in place from a server answer; null when closed
let _ackSeq = 0;
const REVIEW_PLAN_TIMEOUT_MS = 20000;

function reviewLoadingBody() {
  return el("div", { class: "cs-review-loading", role: "status", "aria-live": "polite" },
    el("span", { class: "cs-review-spinner", "aria-hidden": "true" }),
    el("div", {},
      el("div", { class: "cs-review-loading-title" }, t("Checking pending changes…")),
      el("div", { class: "hint" }, t("Nothing is changed until you apply."))));
}
function reviewErrorBody(msg, onRetry) {
  return el("div", { class: "cs-review-error", role: "alert" },
    el("div", { class: "cs-review-error-msg" }, t("Could not load the review: {0}", msg)),
    el("div", { class: "hint" }, t("Nothing was changed. The router may be busy or unreachable.")),
    el("button", { class: "btn btn-primary", type: "button", onclick: onRetry }, t("Retry")));
}
function reviewNotice(kind) {
  if (kind === "stale") return el("div", { class: "cs-notice warn", role: "status" }, t("The configuration changed while you were reviewing — check the updated list and apply again."));
  if (kind === "ack") return el("div", { class: "cs-notice warn", role: "alert" }, t("Confirm the warnings below before applying."));
  if (kind === "blocked") return el("div", { class: "cs-notice err", role: "alert" }, t("The router refused to apply this configuration — resolve the blocking issues below."));
  return null;
}

// openReviewChanges opens the panel (or, when it is already on screen and `opts` carries a server
// answer, re-renders it in place). It opens synchronously with a loading state, before the first
// network await — a blank interval looks like a dead button — fetches the plan with a 20 s timeout,
// and on failure shows an inline Retry (plus a toast) rather than leaving the loading state up.
//
//   opts.plan      — render this plan instead of fetching (409 REV_STALE carries the current plan)
//   opts.findings  — replace the findings of the plan on screen (409 ACK_REQUIRED / 422 BLOCKED)
//   opts.notice    — "stale" | "ack" | "blocked": the banner line at the top of the panel
//   opts.focusAck  — move focus to the first unchecked acknowledgement box
//
// Singleton guard: _reviewPanelOpening is claimed SYNCHRONOUSLY, before the first await, so two
// concurrent calls cannot both open; _reviewPanelEl is checked against the DOM rather than trusted
// as a boolean, so a teardown that bypasses close() (route() removing dialogs on navigation) can
// never latch the panel permanently unopenable.
async function openReviewChanges(opts) {
  opts = opts || {};
  if (_reviewPanelEl && document.contains(_reviewPanelEl)) {
    if (_reviewRerender && (opts.plan || opts.findings)) _reviewRerender(opts);
    return;
  }
  if (_reviewPanelOpening) return;
  _reviewPanelOpening = true;
  _reviewPanelEl = null;
  let needsRoute = false; // an undo changed the stored data: re-render the page behind once the panel closes
  const closeOnlyFooter = () => el("div", { class: "cs-footer" },
    el("button", { class: "btn", type: "button", onclick: () => back.close() }, t("Close")));
  const back = modal({ title: t("Review & Apply"), body: reviewLoadingBody(), footer: closeOnlyFooter() });
  _reviewPanelEl = back;
  const dlg = back.querySelector(".modal");
  const bodyHost = back.querySelector(".modal-body");
  const footHost = back.querySelector(".modal-foot");
  const onClosed = () => {
    if (_reviewPanelEl === back) { _reviewPanelEl = null; _reviewRerender = null; }
    // Deferred: route() itself removes dialogs on navigation, and re-entering it synchronously from
    // inside that removal would render the same page twice.
    if (needsRoute) { needsRoute = false; setTimeout(() => route(), 0); }
  };
  const origClose = back.close;
  back.close = () => { origClose(); onClosed(); };
  back.remove = back.close;
  // Escape, the backdrop and route() bypass the wrapper above; watching the DOM catches every path.
  const mo = new MutationObserver(() => { if (!document.contains(back)) { mo.disconnect(); onClosed(); } });
  mo.observe(document.body, { childList: true });

  const paint = (bodyEl, footerEl) => {
    if (!document.contains(back)) return false;
    bodyHost.textContent = ""; bodyHost.appendChild(bodyEl);
    footHost.textContent = ""; footHost.appendChild(footerEl);
    i18nApply(dlg); associateLabels(dlg);
    // A repaint that removed the focused control (an Undo button) must not drop focus onto the page
    // behind the dialog; the dialog itself (tabindex -1) is the neutral place, Tab then goes to the
    // first control.
    if (!dlg.contains(document.activeElement)) dlg.focus();
    return true;
  };
  const refreshBehindReview = async () => { needsRoute = true; try { await loadProfile(); } catch (_) {} };

  const load = async (refresh) => {
    let plan;
    try {
      // A request that never answers (a router that went away mid-click, a dropped uplink that
      // never resets the socket) leaves fetch's promise pending forever; the race turns that into
      // an inline error with a Retry. Scoped to this fetch on purpose: a blanket timeout on api.get
      // would break the legitimately long-running calls (apply, updater).
      plan = await Promise.race([
        api.get("/api/apply/plan" + (refresh ? "?refresh=1" : "")),
        new Promise((_, rej) => setTimeout(() => rej(new Error(t("The router is not responding."))), REVIEW_PLAN_TIMEOUT_MS)),
      ]);
    } catch (e) {
      if (!document.contains(back)) return; // dismissed while loading — a late failure of a closed dialog is not actionable
      const msg = (e && e.message) || String(e);
      paint(reviewErrorBody(msg, () => { paint(reviewLoadingBody(), closeOnlyFooter()); load(true); }), closeOnlyFooter());
      toast(t("Could not load the review: {0}", msg), "err");
      return;
    }
    if (!document.contains(back)) return; // closing the dialog cancels this presentation
    if (!plan || typeof plan !== "object") {
      const msg = t("The router returned an invalid plan.");
      paint(reviewErrorBody(msg, () => { paint(reviewLoadingBody(), closeOnlyFooter()); load(true); }), closeOnlyFooter());
      toast(msg, "err");
      return;
    }
    renderPlan(plan, { notice: opts.notice, focusAck: opts.focusAck });
  };

  const renderPlan = (plan, o) => {
    o = o || {};
    reviewedPlan = plan;
    const findings = Array.isArray(plan.findings) ? plan.findings.filter(f => f && typeof f === "object") : [];
    const chg = (plan.changes && typeof plan.changes === "object") ? plan.changes : {};
    const baselineOK = chg.baseline_available !== false;
    const groups = (chg.by_subsystem && typeof chg.by_subsystem === "object") ? chg.by_subsystem : {};
    const rows = Array.isArray(chg.changes) ? chg.changes : [];
    const count = Number(chg.count) || rows.length || Object.values(groups).reduce((n, a) => n + (Array.isArray(a) ? a.length : 0), 0);
    const pending = !!(plan.pending || chg.pending);
    const windowOpen = !!(plan.window && plan.window.open);
    const probe = plan.probe || {};
    const hard = findings.filter(findingBlocks);
    const acks = findings.filter(findingNeedsAck);
    const notes = findings.filter(f => !findingBlocks(f) && !findingNeedsAck(f));
    // Persisted acknowledgements arrive pre-checked; a re-render from a server answer (REV_STALE,
    // ACK_REQUIRED) keeps the boxes the user ticked a moment ago, a fresh open starts from the record.
    const kept = o.keepAcks ? new Set(ackedFindings) : new Set();
    ackedFindings.clear();
    acks.forEach(f => { if (f.id && (f.acked || kept.has(f.id))) ackedFindings.add(f.id); });

    const body = el("div", { class: "cs-panel" });
    const notice = reviewNotice(o.notice);
    if (notice) body.appendChild(notice);

    // Summary line: how much, and the verdict, in words.
    const summary = el("div", { class: "cs-summary" });
    let headline;
    if (count) headline = tn("{0} pending change|{0} pending changes", count);
    else if (plan.nothing_configured && !pending) headline = t("Nothing is configured yet — add a connection or a routing list first.");
    else if (pending) headline = t("Changes are pending, but there is no applied baseline to compare against yet.");
    else headline = t("No pending changes — the router matches your saved configuration.");
    summary.appendChild(el("strong", {}, headline));
    // The server's verdict when it gave one (blocked / warning / ready); derived from the findings
    // otherwise. A hard blocker always reads as Blocked whatever the field says.
    const verdict = (plan.verdict === "blocked" || hard.length) ? ["err", t("blocked")]
      : (plan.verdict === "warning" || (!plan.verdict && findings.length)) ? ["warn", t("warning")] : ["ok", t("ready")];
    summary.appendChild(el("span", { class: "pill cs-verdict " + verdict[0] }, verdict[1]));
    if (chg.may_interrupt) summary.appendChild(el("span", { class: "pill warn" }, t("May interrupt connectivity")));
    if (windowOpen) summary.appendChild(el("span", { class: "pill warn" }, t("Test window open")));
    body.appendChild(summary);
    const appliedAt = fmtAppliedAt(plan.applied_at);
    if (appliedAt) body.appendChild(el("div", { class: "hint cs-applied-at" }, t("Last applied: {0}", appliedAt)));

    // Findings go ABOVE the change list on purpose. The changes answer "what am I about to send?";
    // this answers "will this router actually do it?" — a setting the box silently discards at apply
    // is worth more to see than any individual field edit.
    let updateActions = () => {};
    const findingRow = (f, kind) => {
      const [pillCls, status] = findingStatus(f);
      const items = Array.isArray(f.items) ? f.items.filter(x => x != null && x !== "").map(String) : [];
      const n = Math.max(Number(f.count) || 0, items.length);
      const row = el("div", { class: "cs-preflight-row" + (kind === "blocked" ? " cs-blocked" : kind === "ack" ? " cs-ack" : " cs-note"), "data-finding": f.id || "" });
      row.appendChild(el("div", { class: "cs-preflight-hd" },
        el("span", { class: "pill " + pillCls }, status),
        el("span", { class: "cs-preflight-title" }, f.title || f.code || f.id || t("Review required")),
        n > 1 ? el("span", { class: "pill muted" }, t("{0} items", n)) : null));
      if (f.detail) row.appendChild(el("div", { class: "cs-preflight-reason" }, f.detail));
      // A NOTE states something true about a configuration that works. Its fix belongs one click
      // away, not open: five notes with an always-open remedy box each filled half the review, and a
      // wall of advice about things that are not broken is what made the blockers hard to find.
      // Anything that blocks Apply or asks for a decision keeps its fix in plain sight.
      if (f.remedy) {
        if (kind === "note") {
          row.appendChild(el("details", { class: "cs-preflight-fix" },
            el("summary", {}, t("How to fix")), el("div", {}, f.remedy)));
        } else {
          row.appendChild(el("div", { class: "cs-preflight-fix" }, el("strong", {}, t("How to fix: ")), f.remedy));
        }
      }
      // One finding class names an object with NO page: a rule. profile.rules is read in five places
      // and rendered as an editable row in none, so the remedy could only hand over a REST route —
      // honest, and still leaving the operator to run curl by hand to unblock their own router. The
      // daemon names the action in a closed vocabulary (finding.fix); this renders it as the button
      // it should have been. Nothing else gets one: every other object has a page, and a button here
      // would pull the operator away from the screen where that object actually lives.
      if (f.fix && f.fix.action === "delete_rule" && f.fix.id) {
        const what = f.fix.label || f.fix.id;
        const btn = el("button", { class: "btn btn-sm", type: "button" }, t("Remove") + " " + what);
        btn.addEventListener("click", async () => {
          // Deleting is not reversible and the object is invisible everywhere else, so the operator
          // gets the same confirm every other delete in this panel asks for.
          if (!(await modalConfirm(t("Remove") + " " + what + "?"))) return;
          btn.disabled = true;
          try {
            await api.del("/api/rules/" + encodeURIComponent(f.fix.id));
            toast(t("Removed"), "ok");
            await refreshBehindReview();
            await load(false);
          } catch (e) {
            toast(t("Remove failed:") + " " + ((e && e.message) || ""), "err");
            btn.disabled = false;
          }
        });
        row.appendChild(el("div", { class: "cs-preflight-fix" }, btn));
      }
      if (items.length) {
        const more = n > items.length ? t("and {0} more", n - items.length) : "";
        if (items.length <= 3) row.appendChild(el("div", { class: "cs-preflight-items" }, t("Items: ") + items.join(", ") + (more ? " " + more : "")));
        else row.appendChild(el("details", { class: "cs-preflight-items" },
          el("summary", {}, t("Items ({0})", n)),
          el("ul", {}, ...items.map(x => el("li", {}, x))),
          more ? el("div", { class: "hint" }, more) : null));
      }
      if (kind === "ack") {
        const cb = el("input", { type: "checkbox", "data-ack": f.id || "" });
        cb.checked = !!f.id && ackedFindings.has(f.id);
        cb.addEventListener("change", async () => {
          if (cb.checked) { if (f.id) ackedFindings.add(f.id); }
          else {
            ackedFindings.delete(f.id);
            if (f.acked && f.id) { // persisted server-side: forget it there too, so it is asked about again
              try { await api.post("/api/apply/ack", { ids: [f.id], acked: false }); f.acked = false; }
              catch (e) { toast(t("Could not update the acknowledgement: {0}", (e && e.message) || ""), "err"); }
            }
          }
          updateActions();
        });
        // The checkbox lives INSIDE the label (wrapping association) with no `for` — a label that both
        // contains its control and points at it with `for` re-dispatches the click and toggles twice.
        row.appendChild(el("label", { class: "cs-preflight-ack" },
          cb, el("span", {}, t("I understand — apply anyway")),
          f.acked ? el("span", { class: "pill muted" }, t("acknowledged earlier")) : null));
      }
      if (f.id || f.code) row.appendChild(el("details", { class: "cs-preflight-tech" },
        el("summary", {}, t("Technical details")),
        el("code", {}, [f.id, f.code].filter(Boolean).join(" · "))));
      return row;
    };
    if (hard.length || acks.length || notes.length || probe.error) {
      const box = el("section", { class: "cs-preflight " + (hard.length ? "err" : "warn"), "aria-label": t("Apply review decisions") });
      const head = hard.length ? t("Resolve the blocked issues before applying")
        : acks.length ? t("Confirm the warnings to continue") : t("Notes about this configuration");
      box.appendChild(el("div", { class: "cs-decision" }, el("div", { class: "cs-preflight-head" }, head)));
      // A failed capability probe produces fewer findings, and rendering nothing would read as "all
      // clear" — say so, and offer a fresh probe.
      if (probe.error || probe.stale) {
        const recheck = el("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: () => { paint(reviewLoadingBody(), closeOnlyFooter()); load(true); } }, t("Re-check"));
        box.appendChild(el("div", { class: "cs-preflight-probe" },
          el("span", {}, probe.error
            ? t("The router capability check failed ({0}) — findings may be incomplete; they are re-checked when you apply.", String(probe.error))
            : t("Capability readings are stale; they are re-checked when you apply.")),
          " ", recheck));
      }
      hard.forEach(f => box.appendChild(findingRow(f, "blocked")));
      acks.forEach(f => box.appendChild(findingRow(f, "ack")));
      if (notes.length) box.appendChild(el("details", { class: "cs-notes" },
        el("summary", {}, notes.length === 1 ? t("1 note") : t("{0} notes", notes.length)),
        ...notes.map(f => findingRow(f, "note"))));
      body.appendChild(box);
    }

    // The change set. Undo reverts the REAL stored data and re-fetches the plan.
    const onUndo = async (req) => {
      try {
        await api.post("/api/changeset/undo", Object.assign({ baseline_rev: chg.baseline_rev || "" }, req));
        await refreshBehindReview();
        paint(reviewLoadingBody(), closeOnlyFooter());
        await load(false);
      } catch (e) { toast((e && e.message) || t("Undo failed"), "err"); }
    };
    if (!baselineOK) {
      body.appendChild(el("div", { class: "hint cs-nobase" },
        t("No baseline to compare against yet.") + " " + t("Nothing has been applied by WayHop yet, so there is no diff to show — Apply activates the whole saved configuration.")));
    } else if (count) {
      const subs = Object.keys(groups).filter(sub => Array.isArray(groups[sub]) && groups[sub].length);
      const grouped = subs.length ? subs.map(sub => [sub, groups[sub]]) : [["general", rows]];
      grouped.forEach(([sub, list]) => {
        if (!list.length) return;
        body.appendChild(el("div", { class: "cs-group" },
          el("div", { class: "cs-group-head" },
            el("div", { class: "name" }, t(CS_SUBSYSTEM_LABEL[sub] || sub)),
            el("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: () => onUndo({ scope: "subsystem", subsystem: sub }) }, t("Undo group"))),
          ...list.map(ch => csRow(ch, onUndo))));
      });
    }

    const note = el("div", { class: "cs-apply-note", role: "status", "aria-live": "polite" });
    body.appendChild(note);

    // Footer: Close never discards — discarding is its own explicitly-confirmed action. Both apply
    // actions are always present; an unavailable one stays visibly disabled with a reason instead
    // of disappearing and leaving a Close-only dead end.
    const closeBtn = el("button", { class: "btn", type: "button", onclick: () => back.close() }, t("Close"));
    const discardBtn = count ? el("button", {
      class: "btn btn-ghost", type: "button",
      onclick: async () => {
        if (!(await modalConfirm(t("Discard all pending changes and restore the last applied configuration?")))) return;
        await onUndo({ scope: "all" });
      },
    }, t("Discard all changes")) : null;
    const testBtn = el("button", { class: "btn", type: "button", onclick: () => { back.close(); applyConfig(false); } }, t("Test safely"));
    const saveBtn = el("button", { class: "btn btn-primary", type: "button", onclick: () => { back.close(); applyConfig(true); } }, t("Apply & Save"));
    const footer = el("div", { class: "cs-footer" }, closeBtn, discardBtn, testBtn, saveBtn);

    updateActions = () => {
      const missing = acks.filter(f => !f.id || !ackedFindings.has(f.id)).length;
      const nothing = !pending && !count && !windowOpen;
      let disabled = false, title = "", noteTxt, noteCls = "";
      if (hard.length) { disabled = true; title = t("Resolve the blocking issues above first."); noteCls = " err";
        noteTxt = t("The router cannot execute this configuration — resolve the blocking issues above; retrying will not help."); }
      else if (missing) { disabled = true; title = t("Confirm the warnings above to enable this action."); noteTxt = t("Confirm the warnings above to enable Apply."); }
      else if (nothing) { disabled = true; title = t("Nothing to apply."); noteTxt = t("Nothing to apply — the router already runs the saved configuration."); }
      else noteTxt = windowOpen
        ? t("A test configuration is live. Apply & Save keeps it; Test safely re-arms the window.")
        : t("Ready to apply. Test safely can be rolled back; Apply & Save makes it permanent.");
      [testBtn, saveBtn].forEach(b => {
        b.disabled = disabled;
        b.setAttribute("aria-disabled", String(disabled));
        if (title) b.title = title; else b.removeAttribute("title");
      });
      note.textContent = noteTxt;
      note.className = "cs-apply-note" + noteCls;
    };
    updateActions();
    if (!paint(body, footer)) return;
    if (o.focusAck) { const cb = body.querySelector(".cs-preflight-ack input:not(:checked)"); if (cb) cb.focus(); }
  };
  _reviewRerender = (o) => {
    if (o.plan && typeof o.plan === "object") renderPlan(o.plan, Object.assign({ keepAcks: true }, o));
    else if (Array.isArray(o.findings) && reviewedPlan) renderPlan(Object.assign({}, reviewedPlan, { findings: o.findings }), Object.assign({ keepAcks: true }, o));
  };

  try {
    if (opts.plan && typeof opts.plan === "object") renderPlan(opts.plan, Object.assign({ keepAcks: true }, opts));
    else if (Array.isArray(opts.findings) && reviewedPlan) renderPlan(Object.assign({}, reviewedPlan, { findings: opts.findings }), Object.assign({ keepAcks: true }, opts));
    else await load(false);
  } finally {
    // Always release the in-flight claim, including when the fetch failed — otherwise one failed
    // open would block every later attempt.
    _reviewPanelOpening = false;
  }
}

/* ---------- Failover: shared endpoint pool ----------
   Groups no longer each print their own copy of the member list. Four identical groups used to
   render the same three members four times over, which made the page ~80% repeated content and hid
   the one fact that matters: which member is actually carrying traffic right now.

   Instead: each group renders as a compact card answering only "which exit is live?", and every
   endpoint is drawn ONCE in a traffic-ranked pool with its group membership inverted into chips.
   The group->member tree survives on each endpoint as "Used by" chips carrying role + position. */

// foElected returns the member sing-box is ACTUALLY routing through (authoritative, from the
// daemon), falling back to the client-side lowest-latency guess when the daemon has not reported.
// foElection answers two questions that must not be merged: WHICH member carries traffic, and
// whether that is the daemon's answer or this page's guess.
//
// The pre-redesign member chips kept them apart ("● LIVE" from the daemon vs "✓ BEST" by latency,
// with tooltips saying which was which). The compact card lost the distinction: it called
// foElected() and printed "Live exit", so a latency guess was rendered exactly like the
// authoritative election — including when /api/failover/state had simply failed.
function foElection(g) {
  const live = (failoverState.elected || {})[g.id];
  if (live) return { id: live, authoritative: true };
  // The guess has to guess what THIS group does, not what urltest does. A fallback group walks the
  // operator's list top to bottom and takes the first member that is up; a selector sits on the one
  // they picked, which is the head of the same list. Answering "lowest latency" for those named a
  // member the router would never choose — the exact mismatch behind "why is my #1 not current?".
  // …unless nothing on this router walks that list. A fallback group the CORE elects has no strict
  // order — foOrderNote says so in the same card, in as many words: "This group runs on the core,
  // which has no strict-order mode: it keeps the fastest working member and uses your order only as
  // a tiebreak." The guess kept walking the order anyway, so the two halves of one card contradicted
  // each other. Measured on the demo with a fallback of three core-carried exits ordered against
  // their latency: the note said the fastest wins while the chain named "#1 current Helsinki Trojan
  // 87 ms" with Frankfurt VLESS alive at 40 ms — the same "why is my #1 not current?" mismatch this
  // function exists to prevent, pointing the other way.
  //
  // The split case keeps the order guess: there the kernel really does walk the list for the routing
  // lists it carries, which is a live AX3000T.
  const coreElectsAlone = g.type === "fallback" && !g.managed && foGroupNeedsCore(g)
    && !((failoverState.kernel_members || {})[g.id] || []).length;
  if ((g.type === "fallback" || g.type === "selector") && !coreElectsAlone) {
    const first = (g.members || []).find(id => (healthMap[id] || {}).state !== "down"
      && (findEndpoint(id) || {}).enabled !== false);
    return { id: first || null, authoritative: false };
  }
  const best = bestAliveMember((g.members || []).map(findEndpoint).filter(Boolean));
  return { id: best ? best.ep.id : null, authoritative: false };
}

// foElected keeps the id-only shape for callers that only need "which member", not "how we know".
function foElected(g) {
  return foElection(g).id;
}

// foOrderedMembers sorts exactly as the old member list did (rank, then latency, configured order
// breaking ties) so the position numbers shown match the failover order the user configured.
function foOrderedMembers(g) {
  const ids = (g.members || []).slice();
  // Only urltest reorders by speed. A fallback group takes the list exactly as written and a selector
  // routes through the member the operator picked, so re-sorting THEIR list by latency showed a
  // sequence the router will never walk — and made the saved order look like it had been ignored.
  if (g.type === "fallback" || g.type === "selector") return ids;
  const order = new Map(ids.map((id, i) => [id, i]));
  ids.sort((a, b) => {
    const ra = failoverMemberRank(a), rb = failoverMemberRank(b);
    if (ra !== rb) return ra - rb;
    const la = (healthMap[a] || {}).latency_ms || 9999;
    const lb = (healthMap[b] || {}).latency_ms || 9999;
    if (la !== lb) return la - lb;
    return order.get(a) - order.get(b);
  });
  return ids;
}

function foTraffic(id) {
  const h = healthMap[id] || {};
  return (h.bytes_down || 0) + (h.bytes_up || 0);
}

// foChainCard renders one group as its failure chain. It keeps every action the old card had:
// dropping them to save space would trade a cosmetic win for lost functionality.
// foSwitchesItself reports whether this group moves to another member WITHOUT a person doing it.
//
// THREE things can do the moving, and the group has to be one of them:
//
//   • sing-box's own prober, for a group emitted as `urltest` (generator: types urltest and fallback);
//   • the WayHop daemon control loop, for a group marked MANAGED — it acts through clash.Select, so it
//     needs the core too;
//   • the ROUTER, for a group of native tunnels: Apply writes the members onto the `ip global` ladder
//     in order, and KeeneticOS's own connection failover walks it. Measured on a live box
//     with no core installed at all — Wireguard3 was taken down and the default moved to Wireguard5,
//     then moved back when it returned.
//
// The last one is why a native group is not simply "core absent ⇒ nothing switches" — but it is
// narrower than it looks, and the narrowing is the honest part. The ladder is written by
// defaultRouteLadder, which runs for the group carrying the DEFAULT route and for nothing else. A
// native group used as a routing list's target compiles to a plain static route at its elected
// member (keenetic/backend.go, "1c) Failover groups → the interface of their elected member"); if
// that member dies, the route stays where it is and traffic stops. So `isDefault` is not decoration
// here: it is the difference between a chain that describes the router's behaviour and one that
// describes a wish.
function foSwitchesItself(g, isDefault) {
  if (foGroupNeedsCore(g)) return !!g.managed || g.type === "urltest" || g.type === "fallback";
  // A native group has two ways to move without anyone touching it, and the page knew only one.
  // As the DEFAULT ROUTE, KeeneticOS fails the `ip global` ladder over itself. Backing ROUTING LISTS,
  // the daemon's own owner re-points the list's table at a healthy member (listfailover.go) — which
  // the card flatly denied, telling the operator to go and switch something the daemon had already
  // switched. The daemon names those groups, so this is read rather than guessed: it reports the
  // truth for THIS platform, and is empty where that owner does not run.
  if ((failoverState.self_switching || []).includes(g.id)) return true;
  return !!isDefault && (g.type === "urltest" || g.type === "fallback");
}

// foGroupNeedsCore mirrors the backend's groupIsNativelyRoutable: an adopted tunnel (engine
// "external") or a kernel-native one needs no proxy core, because the route IS the datapath. A
// member that is anything else — a VLESS/plugin endpoint, or a nested group that is not an endpoint
// here — is what pulls the core in.
function foGroupNeedsCore(g) {
  return (g.members || []).some(id => {
    const e = findEndpoint(id);
    if (!e) return true;
    return e.engine !== "external" && e.engine !== "amneziawg";
  });
}

// foRunNote answers, before the chain says anything else, whether ANY of it is happening.
//
// This used to open by stating that a group is a proxy-core object on every platform, because a
// single group moved the whole Keenetic policy into the compatibility core. That is no longer true:
// needsCompatibilityRouting was relaxed so a group whose members are all native tunnels compiles to
// the `ip global` ladder and needs no core at all (keenetic/backend.go, groupIsNativelyRoutable).
// The body below was corrected then; this rationale was not, and a stale reason above live text is
// how the text drifts back. What survives from it is the shape of the bug it was written for: the
// chain was drawn identically whether or not anything was running, so a group that could not even be
// applied still showed a confident "EXPECTED … FALLS TO … THEN".
function foRunNote(g) {
  const sb = (state.health && state.health.singbox) || {};
  // Only a group that actually depends on the core is affected by its absence. A group of adopted or
  // kernel-native tunnels is routed by the router itself — WayHop compiles it to the elected member's
  // interface and moves that route — so reporting a missing core there was reporting someone else's
  // problem as this group's.
  if (foGroupNeedsCore(g)) {
    if (sb.available === false) {
      return { cls: "err", text: t("Not running: a member of this group is a proxy connection, and the proxy core (sing-box) is not installed.") };
    }
    if (sb.running === false) {
      return { cls: "warn", text: t("The proxy core is not running, so the proxy members of this group cannot carry traffic.") };
    }
  }
  if (_backendPending) {
    return { cls: "warn", text: t("There are unapplied changes. The chain below is the saved configuration, not necessarily what the router is running.") };
  }
  return null;
}

// foOrderNote states, in the group's own terms, what the member ORDER buys — the question the chain
// raises the moment its head is not the member the operator put on top.
function foOrderNote(g) {
  // fallback means two different things too, and the card claimed the flattering one for both.
  //
  // A group the KERNEL carries is elected in the operator's order — first healthy member wins — and a
  // MANAGED group gets that same policy from the daemon's control loop. But an unmanaged group the
  // core carries is compiled to a sing-box `urltest` outbound (generator/singbox.go: URLTest and
  // Fallback share that branch, because sing-box has no strict-order outbound), and urltest keeps the
  // FASTEST member. Telling that operator their order is followed top to bottom is telling them the
  // opposite of what their router does.
  if (g.type === "fallback") {
    if (!foGroupNeedsCore(g) || g.managed) return t("fallback follows your order strictly, top to bottom.");
    // Both can be true of one group, and on a live AX3000T they are: group-failover is a
    // fallback whose PREFIX lists the kernel routes - elected in his order, first healthy member wins
    // - while everything else it carries goes through the core, which has no strict-order outbound.
    // Answering only with the core's half is the same mistake this function was written to fix, taken
    // in the other direction: one of two truths, stated as the whole one.
    if (((failoverState.kernel_members || {})[g.id] || []).length) {
      return t("Split: the routing lists the kernel carries follow your order strictly, top to bottom; everything the core carries keeps the fastest working member and uses your order only as a tiebreak.");
    }
    return t("This group runs on the core, which has no strict-order mode: it keeps the fastest working member and uses your order only as a tiebreak.");
  }
  if (g.type === "selector" && !g.managed) return t("selector routes through the member you pick; it does not switch by itself.");
  // urltest means two different things, and only one of them measures anything. With the core,
  // sing-box probes the members and keeps picking the fastest. A native group has no prober at all:
  // Compile pins the group to one member, the daemon is supposed to supply that choice through
  // CompileOptions.GroupElection — and nothing in the daemon sets it today, so the documented
  // fallback applies: "the first routable member in the operator's own order". The ladder is then
  // written in that order and the router walks it top-down. That is fallback behaviour under a
  // urltest label, and the card said "picks the fastest working member" over it.
  if (g.type === "urltest" && !foGroupNeedsCore(g)) {
    return t("These are router tunnels, so nothing measures their latency: your order is followed, top to bottom, exactly as fallback does.");
  }
  return t("urltest picks the fastest working member. Your order (#) is only the tiebreak.");
}

function foChainCard(g, defRule) {
  const isDefault = defRule && defRule.outbound === g.id;
  const election = foElection(g);
  const electedId = election.id;
  const members = foOrderedMembers(g);
  const switchesItself = foSwitchesItself(g, isDefault);
  // Where each member sits in the SAVED order, which the chain no longer shows by position: it is
  // sorted by latency, so the operator's #1 can appear fourth with nothing to explain it.
  const savedPos = new Map((g.members || []).map((id, i) => [id, i + 1]));

  const head = el("div", { class: "fo-g-head" },
    el("div", { class: "fo-g-name" }, g.name,
      el("span", { class: "badge" }, g.type),
      isDefault ? el("span", { class: "pill ok" }, el("span", { class: "dot" }), t("Default route")) : null));

  // Every action names its group. With one group on the page the bare labels were unambiguous; with
  // two, "Test all", "Set as default route" and "Edit" each appeared twice with nothing to tell them
  // apart for anyone reading the accessible name rather than the surrounding card.
  const gname = g.name || g.id;
  const acts = el("div", { class: "fo-g-acts" },
      el("button", { class: "btn btn-sm", "aria-label": t("Test all members of {0}", gname), title: t("Actively re-test every member's latency, then sort best-first"), onclick: e => testFailoverGroup(g, e.currentTarget) }, t("Test all")),
      !isDefault ? el("button", { class: "btn btn-sm", "aria-label": t("Set as default route for {0}", gname), onclick: () => setDefault(g) }, t("Set as default route")) : null,
      el("button", { class: "btn btn-sm", "aria-label": t("Edit") + " " + gname, title: t("Edit group settings"), onclick: () => openEditGroup(g) }, t("Edit")),
      el("button", { class: "btn btn-danger btn-sm", "aria-label": t("Delete") + " " + gname, onclick: () => delGroup(g) }, t("Delete")));

  // The chain's first hop already names the exit and says whether that is confirmed or guessed, so
  // this is only the caveat — the sentence that stops a latency guess from reading as the router's
  // own report. When the election IS authoritative there is nothing to qualify and no note renders.
  let exit = null;
  const run = foRunNote(g);
  if (run) {
    // Nothing is carrying traffic through this group, and that outranks any question about WHICH
    // member would. Said first, and said as the reason, not as "could not read".
    exit = el("div", { class: "fo-g-exit fo-g-stopped " + run.cls, "data-failover-unknown": "1" },
      el("div", { class: "fo-g-exit-note" }, run.text));
  } else if (electedId && !election.authoritative) {
    exit = el("div", { class: "fo-g-exit", "data-failover-unknown": "1" },
      el("div", { class: "fo-g-exit-note" }, failoverState.known
        ? "Ordered by latency. The router has not reported which member it is actually using."
        : "Ordered by latency. WayHop could not read which member the router is actually using."));
  } else if (!electedId && !failoverState.known) {
    // Not "no live exit" — WayHop does not know which member is routed. Saying the group has no
    // healthy member here would be asserting a fact nothing established.
    exit = el("div", { class: "fo-g-exit", "data-failover-unknown": "1" },
      el("div", { class: "fo-g-exit-note" },
        "WayHop could not read which member is carrying traffic right now."));
  } else if (!electedId) {
    exit = el("div", { class: "fo-g-exit" },
      el("div", { class: "fo-g-exit-note" }, t("No live exit — no healthy member.")));
  }

  // The chain: what carries traffic now, then each exit it would fall to in turn, then what is left
  // when there is nothing to fall to. Reading it left to right answers the question the page exists
  // for without the reader having to reconstruct it from a roster and a separate "live exit" panel.
  const track = el("ol", { class: "fo-chain rows" });
  // This block grows TWICE over: one card per group, and one hop per member inside each card. At
  // stress scale (9 groups, 4+ members each) the strip reached 1700px of a 2925px page. The hops
  // that answer "what is carrying my traffic and what does it fall to" are the first few; the rest
  // is depth, and the terminus below already states that depth as a number. So keep the head of the
  // chain and fold its tail, which bounds the card and therefore the page.
  // As rows the chain no longer wraps, so the fold is only about card height on a long roster —
  // eight rows is already more than the question needs, and folding at four hid the middle of a
  // five-member group behind a summary that then floated over the strip.
  const HOPS_VISIBLE = 8;
  const hopMore = members.length > HOPS_VISIBLE + 1
    ? el("details", { class: "fo-hop-more" },
        el("summary", { class: "hint" }, t("Show all {0} hops", members.length)))
    : null;
  let seenUsable = 0;
  members.forEach((id, mi) => {
    const h = healthMap[id] || {};
    const down = h.state === "down";
    const current = id === electedId;
    let role, cls;
    if (current) {
      // One word for the head of the chain: CURRENT. Whether that is the daemon's own answer or this
      // page's reading of the group's rule is a separate fact, and it is already stated above the
      // chain (foRunNote) and carried by the row's colour — it does not need a second vocabulary.
      role = t("current");
      cls = election.authoritative ? "now" : "now guess";
    } else if (down) {
      role = t("unusable"); cls = "dead";
    } else {
      seenUsable++;
      // "falls to" and "then" describe a switch that happens BY ITSELF, and one group shape does no
      // such thing: an unmanaged `selector`. Nothing moves it — sing-box emits a plain selector with
      // no prober, and the daemon's control loop only drives groups marked managed — so if the
      // selected member dies, traffic stops rather than moving to the next name in this list. The
      // demo carries three of them, so the chain has been drawing that promise all along.
      role = switchesItself ? (seenUsable === 1 ? t("falls to") : t("then")) : t("alternative");
      cls = "standby";
    }
    // Alive or dead, per member, on the row itself — the same dot the rest of the panel uses for the
    // same fact. Until now a dead member was only distinguishable by a struck-through name and the
    // word "unusable", which is a lot of reading for the question "is this one up?".
    const dotCls = down ? "err" : h.state === "alive" ? (h.latency_ms >= 600 ? "warn" : "ok") : "muted";
    const hop = el("li", { class: "fo-hop " + cls },
      el("span", { class: "fo-hop-p", title: t("Your position in the member list") }, "#" + (savedPos.get(id) || "?")),
      el("span", { class: "insp-dot " + dotCls, "aria-hidden": "true" }),
      el("span", { class: "fo-hop-r" }, role),
      el("span", { class: "fo-hop-n" }, nameOf(id)),
      el("span", { class: "fo-hop-l" }, down ? t("down") : h.latency_ms ? h.latency_ms + " ms" : t("checking…")));
    if (hopMore && mi >= HOPS_VISIBLE) hopMore.appendChild(hop); else track.appendChild(hop);
  });
  if (hopMore) track.appendChild(hopMore);
  if (!members.length) {
    track.appendChild(el("li", { class: "fo-hop dead" },
      el("span", { class: "fo-hop-n muted" }, t("No members"))));
  } else {
    // The terminus. A group with one healthy member and four dead ones is not redundant, and the
    // only place that is visible is at the end of the chain.
    //
    // "N exits deep" is a DEPTH GUARANTEE, and a group nothing switches by itself does not have one:
    // the alternatives are there to be chosen, not to be fallen to. Saying "if all fail" of a group
    // that will not move off the FIRST failure is the same promise the hop roles were making.
    const usable = members.filter(id => (healthMap[id] || {}).state !== "down").length;
    if (!switchesItself) {
      track.appendChild(el("li", { class: "fo-hop end thin" },
        el("span", { class: "fo-hop-p" }, ""),
        el("span", { class: "fo-hop-dot-gap" }),
        el("span", { class: "fo-hop-r" }, t("if it fails")),
        el("span", { class: "fo-hop-n" }, usable > 1
          ? t("traffic stops until a member is chosen — this group does not switch by itself")
          : t("traffic through this group stops"))));
    } else {
      track.appendChild(el("li", { class: "fo-hop end" + (usable > 1 ? "" : " thin") },
        el("span", { class: "fo-hop-p" }, ""),
        el("span", { class: "fo-hop-dot-gap" }),
        el("span", { class: "fo-hop-r" }, t("if all fail")),
        el("span", { class: "fo-hop-n" }, usable > 1
          ? t("{0} exits deep", usable)
          : usable === 1 ? t("nothing left to fall to") : t("traffic through this group stops"))));
    }
  }
  // The depth above counts every member. For a group whose ROUTING LISTS the kernel carries, that is
  // not the depth those lists have: the kernel can only fall to a member with a real link, so a group
  // mixing a native tunnel with an engine-carried one has fewer exits than names. Measured on the
  // operator's AX3000T: group-failover reads "2 exits deep" while exactly one of its two members
  // (tunnel-a → awg1) is something the kernel plane can elect; the other is a sing-box socks outbound.
  //
  // Silent when there is nothing to correct — every member routable, or the kernel routes none of
  // this group's lists — so the ordinary card is unchanged.
  const kernelIDs = (failoverState.kernel_members || {})[g.id];
  if (kernelIDs && kernelIDs.length < members.length) {
    const kernelUp = members.filter(id => kernelIDs.includes(id) && (healthMap[id] || {}).state !== "down").length;
    // What happens once those are gone is the part worth knowing: without a kill switch the table
    // keeps a route through a dead link, the fwmark lookup finds nothing usable and falls through to
    // the main table — the provider. With one, the same traffic is dropped instead.
    const exhausted = g.kill_switch
      ? t("once none is up, their traffic is dropped")
      : t("once none is up, their traffic leaves through the provider");
    track.appendChild(el("li", { class: "fo-hop end thin" },
      el("span", { class: "fo-hop-p" }, ""),
      el("span", { class: "fo-hop-dot-gap" }),
      el("span", { class: "fo-hop-r" }, t("in the kernel")),
      el("span", { class: "fo-hop-n" },
        // Out of the members the KERNEL can elect, not out of every name in the group. The
        // denominator was members.length — the number this whole block exists to correct. Measured
        // on the demo: "Mixed depth" holds a native tunnel (down) and a Hysteria2 exit, and the card
        // read "0 of 2 usable for routing lists", which says both members are merely down right now.
        // One of them can never carry a kernel-routed list at all, whatever its health, so the honest
        // reading is 0 of 1 — and on a live AX3000T the same line reads "1 of 2" while
        // group-failover has exactly one kernel-electable member and is at full strength.
        t("{0} of {1} usable for routing lists — {2}", kernelUp, kernelIDs.length, exhausted))));
  }

  return el("div", { class: "card fo-g" }, head, exit,
    el("div", { class: "hint fo-g-order" }, foOrderNote(g)), foProbeNote(g, switchesItself), track, acts);
}

// foProbeNote says WHAT the milliseconds on this card were measured against.
//
// The card prints a latency per member and marks one CURRENT, and a reader takes that as "this is the
// best exit". It is the best exit TO THE PROBE TARGET, which is not what the group carries. Measured
// on a live router while diagnosing a slow Telegram: the elected member answered the probe in
// 83 ms and reached Telegram in 437 ms, while two other members reached Telegram in 216 and 219 ms.
// Nothing on the page connected those numbers to a target, so the honest question — "best at what?" —
// had no answer on screen.
//
// A selector is worded differently on purpose: nothing elects it, so its URL only colours the health
// badge, which is what the edit dialog already tells whoever opens it.
function foProbeNote(g, switchesItself) {
  const url = ((g.test && g.test.url) || "").trim();
  if (!url) return null; // the daemon's default is not ours to name; say nothing rather than guess
  const every = (g.test && g.test.interval) || 60;
  return el("div", { class: "hint fo-g-probe" }, switchesItself
    ? t("Elected by {0} every {1}s — the times below are to that target, not to the sites this group carries.", url, every)
    : t("Health measured by {0} every {1}s — the times below are to that target, not to the sites this group carries.", url, every));
}

// foIdenticalNote: several groups holding the same members AND electing the same exit is redundancy
// that only looks like redundancy, because one endpoint failing moves all of them at once. It was
// invisible while every group printed its own identical copy of the member list.
function foIdenticalNote(groups) {
  if (groups.length < 2) return null;
  // Cluster by (member set + elected exit) and report the LARGEST cluster. Requiring every group to
  // match meant one differently-shaped group - a nested group with its own smaller roster - silenced
  // the warning even while four others were identical, which is exactly the case it exists to catch.
  const clusters = new Map();
  groups.forEach(g => {
    const members = (g.members || []).slice().sort().join(" ");
    if (!members) return;
    const elected = foElected(g);
    if (!elected) return;
    const k = members + "\u0000" + elected;
    if (!clusters.has(k)) clusters.set(k, { elected: elected, names: [] });
    clusters.get(k).names.push(g.name);
  });
  let biggest = null;
  clusters.forEach(c => { if (!biggest || c.names.length > biggest.names.length) biggest = c; });
  if (!biggest || biggest.names.length < 2) return null;
  return el("div", { class: "card fo-warn", role: "note" },
    el("div", { class: "fo-warn-t" }, "⚠ " + t("{0} groups are currently identical", biggest.names.length)),
    el("div", { class: "hint" },
      t("They hold the same members and all elect {0}. Failing that one exit moves every group at once, so the redundancy is nominal.",
        nameOf(biggest.elected))),
    el("div", { class: "hint fo-warn-names" }, biggest.names.join(" · ")));
}

// foBands draws every exit ONCE, in three readiness bands, with group membership as chips.
//
// Ranking the pool by traffic carried answered "what is busy", which is a dashboard question. On a
// failover page the question is "what could take over right now", and that is a different ordering:
// an idle exit that is up and in two groups is worth more here than a busy one that is down. The
// bands are the answer, and the chips say which groups each band membership actually helps.
//
// A member may itself be a nested GROUP, so this covers both kinds.
function foBandOf(r) {
  if (r.isGroup) {
    // A nested group is ready only if something inside it is. Returning "ready" unconditionally put
    // a group whose every member was down into the band that means "can take traffic right now" —
    // the single claim the bands exist to make, made without looking at the members.
    const members = r.g.members || [];
    if (!members.length) return "out";
    const states = members.map(id => (healthMap[id] || {}).state);
    if (states.some(s => s === "alive")) return "ready";
    if (states.every(s => s === "down")) return "out";
    return "standby"; // nothing alive, but not everything confirmed dead either
  }
  if (!r.ep.enabled) return "out";
  const h = healthMap[r.id];
  if (h && h.state === "down") return "out";
  if (h && h.state === "alive") return "ready";
  return "standby";                                     // not probed yet — cannot claim either way
}

function foBands(groups) {
  const memberships = new Map(); // id -> [{g, pos, live}]
  groups.forEach(g => {
    const ordered = foOrderedMembers(g);
    const electedId = foElected(g);
    ordered.forEach((id, i) => {
      if (!memberships.has(id)) memberships.set(id, []);
      memberships.get(id).push({ g: g, pos: i + 1, live: id === electedId });
    });
  });

  const rows = [];
  (state.profile.endpoints || []).forEach(e => rows.push({ id: e.id, ep: e, isGroup: false }));
  memberships.forEach((_, id) => {
    if (rows.some(r => r.id === id)) return;
    const g = (state.profile.groups || []).find(x => x.id === id);
    if (g) rows.push({ id: id, ep: null, isGroup: true, g: g });
  });
  rows.forEach(r => { r.traffic = foTraffic(r.id); r.band = foBandOf(r); });
  const total = rows.reduce((s, r) => s + r.traffic, 0);

  const BANDS = [
    ["ready", t("Ready now"), t("up and able to take traffic")],
    ["standby", t("Not yet confirmed"), t("no probe result yet — readiness unknown")],
    ["out", t("Unavailable"), t("down or switched off")],
  ];
  const wrap = el("div", { class: "fo-bands" });
  BANDS.forEach(([key, title, hint]) => {
    const inBand = rows.filter(r => r.band === key);
    if (!inBand.length) return;
    // Busiest first within a band, so the band is ordered by what it would cost to lose.
    inBand.sort((a, b) => b.traffic - a.traffic);
    const band = el("div", { class: "fo-band " + key });
    band.appendChild(el("div", { class: "fo-band-h" },
      el("span", { class: "fo-band-t" }, title),
      el("span", { class: "fo-band-n" }, String(inBand.length)),
      el("span", { class: "fo-band-d" }, hint)));
    // The band header already IS the verdict — "Ready now, 6, up and able to take traffic" — so the
    // rows under it are enumeration, and enumeration grows with the profile. On the seeded demo the
    // two bands came to 836px of a 1738px page, about 100px per exit, and pushed Failover past two
    // screens. Show the busiest few (they are sorted by traffic, so these are the ones whose loss
    // costs most) and disclose the rest, stating the count rather than implying completeness.
    const BAND_VISIBLE = 4;
    const overflow = inBand.length > BAND_VISIBLE
      ? el("details", { class: "fo-band-more" },
          el("summary", { class: "hint" }, t("Show all {0} in this band", inBand.length)))
      : null;
    inBand.forEach((r, bi) => {
      const mem = memberships.get(r.id) || [];
      const row = el("div", { class: "fo-band-row" });
      const nameCell = el("div", { class: "fo-band-name" },
        r.isGroup ? r.g.name : (r.ep.name || r.ep.id),
        r.isGroup ? el("span", { class: "badge" }, t("nested group")) : pillFor(r.ep));
      row.appendChild(nameCell);
      const meta = el("div", { class: "fo-band-meta" });
      if (!r.isGroup) {
        meta.appendChild(subMeta(r.ep));
        meta.appendChild(statsLine(r.ep));   // [data-stats] keeps the ~5s live repaint working
        meta.appendChild(causeLine(r.ep));
      } else {
        meta.appendChild(el("div", { class: "hint" }, t("A group used as a member; it elects its own exit internally.")));
      }
      row.appendChild(meta);
      const right = el("div", { class: "fo-band-right" });
      if (total > 0 && r.traffic > 0) {
        right.appendChild(el("span", { class: "fo-e-share" }, Math.round(r.traffic / total * 100) + "% " + t("of traffic")));
      }
      const used = el("div", { class: "fo-e-used" });
      if (!mem.length) {
        used.appendChild(el("span", { class: "chip none", title: t("reached by routing rules only, so no group can fail over to it") }, t("No group")));
      } else {
        mem.forEach(m => used.appendChild(el("span", { class: "chip" + (m.live ? " live" : "") },
          m.g.name, el("span", { class: "sub" }, (m.live ? t("LIVE") : t("STANDBY")) + " · #" + m.pos))));
      }
      right.appendChild(used);
      row.appendChild(right);
      if (overflow && bi >= BAND_VISIBLE) overflow.appendChild(row); else band.appendChild(row);
    });
    if (overflow) band.appendChild(overflow);
    wrap.appendChild(band);
  });
  // Each band already folds its own rows, so this section is BOUNDED — but bounded is not the same
  // as small: three band headers plus four rows each still came to 870px with 32 exits, and the page
  // has two other sections to fit. This section answers "how much capacity do I have", and that
  // answer is the three counts, not the roster. Past a dozen exits the counts move into the summary
  // and the roster folds behind it. A real profile (the Keenetic has eight) never reaches this.
  // 6, not 12. Both real routers and the demo carry ~8 exits, so a threshold of 12 never fired where
  // it was needed — the fourth time a fold has been calibrated above the scale things actually run at.
  // It matters more here than height alone suggests: this block grows with how exits DISTRIBUTE across
  // bands, not just how many there are, because each populated band adds a header. Measured swing on
  // the same demo profile minutes apart: 1314px when the exits were uniformly healthy, 1685px when
  // they spread across three bands — passing and failing the same budget on transient health state.
  // Folding past 4 makes the section a fixed summary line, so the page is bounded regardless. Six
  // was tried first and did nothing: the demo has exactly six exits in bands, so 6 <= 6 left it open —
  // the same off-by-one as AUD-97, made again in the very change that cited it. A threshold equal to
  // the observed value is not below it.
  const BAND_FOLD_AT = 4;
  if (rows.length <= BAND_FOLD_AT) return wrap;
  const counts = BANDS
    .map(([key, title]) => [title, rows.filter(r => r.band === key).length])
    .filter(([, n]) => n > 0)
    .map(([title, n]) => n + " " + title.toLowerCase());
  const det = el("details", { class: "fo-bands-more" },
    el("summary", { class: "hint" },
      t("{0} exits — {1}", rows.length, counts.join(" · "))));
  det.appendChild(wrap);
  return det;
}

