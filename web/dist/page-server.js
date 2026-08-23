// page-server.js — route-scoped chunk for the server page.
//
// Loaded by loadChunk() the first time that route is opened, NOT from index.html, so its bytes
// stay out of the initial payload the perf budget measures. A classic script, like app.js: these
// declarations become globals and app.js has already defined el/t/api/state by the time this runs.
//
// Everything here is reachable ONLY from this page's renderer — attributed by walking the call
// graph from every render* entry point, counting an identifier anywhere in a body (strings
// included) as a reference, so the shared set is over-estimated and this set is not.
// mono moved to app.js: page-diagnostics.js calls it too, and a chunk is loaded only when its route
// is opened — so opening Diagnostics without having visited this page first threw
// `ReferenceError: mono is not defined` and killed the whole battery render. See app.js.

function serverCard(sv) {
  const inst = (sv.installed || []);
  const meta = inst.length
    ? inst.map(p => el("span", { class: "badge proto" }, SERVER_OPT_NAME[p] || p))
    : [el("span", { class: "hint" }, "nothing set up yet")];
  return el("div", { class: "card" },
    el("div", { class: "conn" },
      el("div", { class: "body" },
        el("div", { class: "name" }, sv.name || sv.host,
          sv.hardened ? el("span", { class: "pill ok pill--dot", title: "Key-only login", role: "img", "aria-label": "Key-only login" }, el("span", { class: "dot" })) : null),
        el("div", { class: "sub" }, ...meta, el("span", { class: "addr" }, (sv.user || "root") + "@" + sv.host + ":" + (sv.port || 22))),
        el("div", { class: "stats" }, sv.hardened ? el("b", {}, "🔒 hardened — password login disabled") : el("span", {}, "password login still enabled"))),
      // Every row action names its object, the way Delete below already did.
      //
      // With one server there is one "Set up" and nothing to confuse it with; with four there are four
      // identical "Set up", "Secure" and "Versions" and no way to tell which box each acts on. The page
      // had never been seen with more than zero servers — no seed created one — so the duplication only
      // appeared once the stress seed started making records, and the button-names gate found it
      // immediately. Same shape as AUD-01: visible label unchanged, accessible name carries the object.
      el("div", { class: "acts" },
        el("button", { class: "btn btn-primary btn-sm", "aria-label": t("Set up") + " " + (sv.name || sv.host || sv.id), onclick: () => openProvision(sv) }, "Set up"),
        el("button", { class: "btn btn-sm", "aria-label": (sv.hardened ? t("Re-key") : t("Secure")) + " " + (sv.name || sv.host || sv.id), onclick: () => openHarden(sv) }, sv.hardened ? "Re-key" : "Secure"),
        el("button", { class: "btn btn-sm", "aria-label": t("Versions") + " " + (sv.name || sv.host || sv.id), onclick: () => openVersions(sv) }, "Versions"),
        el("button", { class: "btn btn-danger btn-sm", "aria-label": t("Delete") + " " + (sv.name || sv.host || sv.id), onclick: () => delServer(sv) }, "Delete"))));
}

async function delServer(sv) {
  if (!await modalConfirm(t("Remove “{0}” from your servers list? The server itself is not touched.", sv.name || sv.host))) return;
  try { await api.del("/api/servers/" + encodeURIComponent(sv.id)); toast("Removed", "ok"); route(); }
  catch (e) { toast(e.message, "err"); }
}

// Reusable SSH-credentials block (host/port/user + password|key tabs). Never stored.
function credsBlock(sv) {
  const host = el("input", { type: "text", value: (sv && sv.host) || "", placeholder: "203.0.113.10 or vps.example.com" });
  const port = el("input", { type: "number", value: String((sv && sv.port) || 22) });
  const user = el("input", { type: "text", value: (sv && sv.user) || "root" });
  const pw = el("input", { type: "password", placeholder: "SSH password" });
  const key = el("textarea", { placeholder: "-----BEGIN OPENSSH PRIVATE KEY-----", style: "min-height:80px" });
  const pwWrap = el("div", { class: "field", id: "creds-panel-pw", role: "tabpanel", "aria-labelledby": "creds-tab-pw" }, el("label", {}, "Password"), pw);
  const keyWrap = el("div", { class: "field", id: "creds-panel-key", role: "tabpanel", "aria-labelledby": "creds-tab-key", style: "display:none" }, el("label", {}, "SSH private key (paste)"), key);
  let mode = "password";
  // Proper ARIA tab pattern (role=tab/tablist + aria-selected + aria-controls + roving tabindex + arrow-key nav),
  // mirroring the Add-connection tabs — so a screen-reader user hears which credential method is selected and that
  // the panel changed, instead of two generic role=button controls.
  const pwTab = el("div", { class: "tab active", id: "creds-tab-pw", role: "tab", "aria-selected": "true", "aria-controls": "creds-panel-pw", tabindex: "0" }, "Password");
  const keyTab = el("div", { class: "tab", id: "creds-tab-key", role: "tab", "aria-selected": "false", "aria-controls": "creds-panel-key", tabindex: "-1" }, "SSH key");
  const showMode = (m) => {
    mode = m; const isPw = m === "password";
    pwTab.classList.toggle("active", isPw); keyTab.classList.toggle("active", !isPw);
    pwTab.setAttribute("aria-selected", isPw ? "true" : "false"); keyTab.setAttribute("aria-selected", isPw ? "false" : "true");
    pwTab.tabIndex = isPw ? 0 : -1; keyTab.tabIndex = isPw ? -1 : 0;
    pwWrap.style.display = isPw ? "" : "none"; keyWrap.style.display = isPw ? "none" : "";
  };
  const wireCredTab = (tab, m, other) => {
    tab.addEventListener("click", () => { showMode(m); tab.focus(); });
    tab.addEventListener("keydown", ev => {
      if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); showMode(m); }
      else if (ev.key === "ArrowRight" || ev.key === "ArrowLeft") { ev.preventDefault(); showMode(m === "password" ? "key" : "password"); other.focus(); }
    });
  };
  wireCredTab(pwTab, "password", keyTab);
  wireCredTab(keyTab, "key", pwTab);
  const node = el("div", {},
    el("div", { style: "display:flex;gap:12px;flex-wrap:wrap" },
      el("div", { class: "field", style: "flex:2;min-width:0" }, el("label", {}, "Host / IP"), host),
      el("div", { class: "field", style: "flex:1;min-width:0" }, el("label", {}, "SSH port"), port)),
    el("div", { class: "field" }, el("label", {}, "SSH user"), user),
    el("div", { class: "tabs", role: "tablist" }, pwTab, keyTab), pwWrap, keyWrap,
    el("div", { class: "hint lock" }, "🔒 Credentials are used once for this request and never stored."));
  return { node, get: () => ({ host: host.value.trim(), port: parseInt(port.value, 10) || 22, user: user.value.trim(), password: mode === "password" ? pw.value : "", key: mode === "key" ? key.value : "" }) };
}

// Setup-options picker — the list of what WayHop can install, with details.
// Recommended protocols (the suggested defaults) are surfaced first; the rest are
// grouped under "Also available". A single self-signed-TLS caveat is shown once for
// the group of protocols whose option data says they use a self-signed certificate.
async function optionPicker(preselect) {
  if (!serverOptionsCache) { try { serverOptionsCache = await api.get("/api/server/options"); } catch (_) { serverOptionsCache = []; } }
  const opts = serverOptionsCache || [];
  const inputs = {};
  const wrap = el("div", {});

  const isOn = o => (preselect && preselect.length) ? preselect.includes(o.id) : o.recommended;
  const addGroup = (label, list, sub) => {
    if (!list.length) return;
    wrap.appendChild(el("div", { class: "hint", style: "margin:2px 0 8px;font-weight:600;color:var(--ink-2)" },
      label, sub ? el("span", { style: "font-weight:400;margin-left:6px" }, sub) : null));
    const grid = el("div", { class: "install-grid", style: "margin-bottom:14px" });
    list.forEach(o => {
      const { cb, card } = protoCard(o, isOn(o));
      inputs[o.id] = cb;
      grid.appendChild(card);
    });
    wrap.appendChild(grid);
  };

  const recommended = opts.filter(o => o.recommended);
  const others = opts.filter(o => !o.recommended);

  addGroup("Recommended", recommended, "— suggested defaults, hardest to detect");

  // One shared caveat for the self-signed-TLS protocols (driven by option data, not
  // by hard-coded names), placed just above the group that contains them. When there
  // are no recommended protocols, the self-signed ones may sit in "Available", so key
  // the caveat off whichever list will actually be rendered as "others".
  if (others.some(usesSelfSignedTLS)) {
    wrap.appendChild(el("div", { class: "card", style: "margin:0 0 12px;padding:10px 12px;border-left:3px solid var(--warn)" },
      el("div", { class: "hint", style: "color:var(--ink-2);line-height:1.5" },
        el("b", { style: "color:var(--warn)" }, "Self-signed TLS"),
        " — the protocols tagged below provision with a self-signed certificate. That's fine for personal use; for active-probing resistance, bring your own domain + a real cert.")));
  }

  // Group the rest under "Also available" — or just "Available" when there were no
  // recommended ones to contrast against, so the label never reads oddly.
  addGroup(recommended.length ? "Also available" : "Available", others);

  return { node: wrap, get: () => Object.keys(inputs).filter(id => inputs[id].checked) };
}

// Smart console: polls a job and renders steps (✓/✗/…/∅) + a verbose log.
function smartConsole() {
  const steps = el("div", { class: "wr-steps" });
  const log = el("pre", { class: "wr-console" });
  const logBox = el("details", { class: "wr-logbox" }, el("summary", { class: "hint" }, "verbose log"), log);
  const node = el("div", { style: "margin-top:14px;display:none" }, steps, logBox);
  let timer = null, stopped = false;
  const ICON = { ok: "✓", error: "✗", skipped: "∅", running: "…" };
  const CLS = { ok: "ok", error: "err", skipped: "muted", running: "run" };
  function paint(v) {
    steps.innerHTML = "";
    (v.steps || []).forEach(st => {
      steps.appendChild(el("div", { class: "wr-step " + (CLS[st.state] || "run") },
        el("span", { class: "ic" }, ICON[st.state] || "…"),
        el("div", {},
          el("div", { class: "nm" }, st.name + (st.detail ? " — " + st.detail : "")),
          st.hint ? el("div", { class: "err-hint" }, st.hint) : null)));
    });
    log.textContent = (v.console || []).join("\n");
    log.scrollTop = log.scrollHeight;
  }
  async function run(jobId, onDone) {
    if (timer !== null) { clearInterval(timer); timer = null; } // clear any leftover timer from a prior job
    stopped = false; // reset so a SECOND job (re-run / next step) resumes polling — else it froze on the first snapshot and onDone never fired
    node.style.display = "";
    let fails = 0;
    const poll = async () => {
      if (!document.body.contains(node)) { stop(); return; } // modal closed
      try {
        const v = await api.get("/api/server/job/" + jobId);
        fails = 0;
        paint(v);
        if (v.done) { stop(); if (onDone) onDone(v); }
      } catch (_) {
        // Tolerate transient fetch failures (flaky router link): only give up after several in a row —
        // otherwise a single blip permanently freezes the console and onDone never fires.
        if (++fails >= 5) {
          stop();
          // Surface the give-up so the caller's onDone re-enables its action button (every caller
          // keys off v.ok and re-enables in onDone) and toasts the failure — otherwise the button
          // stays disabled forever and the console freezes on its last snapshot. A synthetic terminal
          // value keeps the onDone contract (done + ok=false).
          if (onDone) onDone({ ok: false, done: true });
        }
      }
    };
    await poll();
    // stopped may be true if the job finished (or errored) during the first poll;
    // only start the repeating timer when the job is still in progress.
    if (!stopped) timer = setInterval(poll, 600);
  }
  function stop() { if (timer !== null) { clearInterval(timer); timer = null; } stopped = true; }
  return { node, run, stop };
}

function downloadText(filename, text) {
  const blob = new Blob([text], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = el("a", { href: url, download: filename });
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

function openAddServer() {
  const name = el("input", { type: "text", placeholder: t("e.g. {0}", "NL VPS") });
  const c = credsBlock(null);
  const save = el("button", { class: "btn btn-primary" }, "Save server");
  const back = modal({
    title: "Add a server",
    body: el("div", {}, el("div", { class: "field" }, el("label", {}, "Name (optional)"), name), c.node),
    footer: save,
  });
  save.addEventListener("click", async () => {
    const cr = c.get();
    if (!cr.host) return toast("Host is required", "err");
    try {
      const sv = await api.post("/api/servers", { name: name.value.trim(), host: cr.host, port: cr.port, user: cr.user });
      back.remove(); toast("Server saved", "ok"); route();
      offerNextStep(sv); // #2 — ask whether to secure the fresh server
    } catch (e) { toast(e.message, "err"); }
  });
}

// After adding a server, ask the user what to do next (secure / set up / later).
function offerNextStep(sv) {
  const secure = el("button", { class: "btn btn-primary" }, "🔒 Secure it");
  const setup = el("button", { class: "btn" }, "Set up VPN");
  const later = el("button", { class: "btn btn-ghost" }, "Later");
  const back = modal({
    title: "Server added",
    body: el("div", {}, el("div", {}, t("“{0}” is saved.", sv.name || sv.host)),
      el("div", { class: "hint", style: "margin-top:8px" }, "If it's a fresh server, securing it first is recommended — WayHop installs an SSH key, lets you download it, then can disable password login so only the key works.")),
    footer: el("div", { style: "display:flex;gap:10px;flex-wrap:wrap" }, later, setup, secure),
  });
  later.onclick = () => back.remove();
  setup.onclick = () => { back.remove(); openProvision(sv); };
  secure.onclick = () => { back.remove(); openHarden(sv); };
}

async function openProvision(sv) {
  const c = credsBlock(sv);
  const picker = await optionPicker(sv && sv.installed);
  const con = smartConsole();
  const runBtn = el("button", { class: "btn btn-primary" }, "Set up");
  const previewBtn = el("button", { class: "btn btn-sm" }, "Preview script");
  const checkBtn = el("button", { class: "btn btn-sm" }, "Check reachability");
  // The answer has to survive being looked away from. This probe takes about 12 seconds against a
  // dead host (see below), and it reported ONLY through a toast — which expires. Measured on the
  // demo against 203.0.113.10: press, wait, and by the time the verdict arrives and fades there is
  // nothing on the dialog saying whether the host answered. The toast stays (it is the page-level
  // half and survives a re-render); this is the half that stays put.
  const checkOut = el("span", { class: "hint", style: "align-self:center" });
  const back = modal({
    title: t("Set up {0}", (sv && (sv.name || sv.host)) || t("server")),
    body: el("div", {}, c.node,
      el("div", { class: "card-title", style: "margin:18px 0 10px" }, "What to set up"),
      picker.node, con.node),
    footer: el("div", { style: "display:flex;gap:10px;flex-wrap:wrap" }, checkBtn, previewBtn, runBtn, checkOut),
  });
  checkBtn.addEventListener("click", async () => {
    const cr = c.get();
    if (!cr.host) return toast("Enter a host first", "err");
    // A dead host answers this in about 12 seconds (ping timeout plus the TCP connect), and for all
    // that time the only sign of life was a greyed button. runBtn one handler below already says
    // "Working…" for the same reason; the slower of the two was the silent one. Measured against the
    // fixture's 198.51.100.21: 11.6s to "unreachable".
    const checkLabel = checkBtn.textContent;
    checkBtn.disabled = true;
    checkBtn.textContent = t("Checking…");
    checkOut.textContent = "";
    checkOut.className = "hint";
    try {
      const r = await api.post("/api/server/check", { host: cr.host, port: cr.port });
      const verdict = t("{0} — ping {1}, SSH port {2} {3}", r.reachable ? t("✓ reachable") : t("✗ unreachable"), r.ping_ok ? ((r.ping_ms != null ? Math.round(r.ping_ms) : "?") + " ms") : t("no reply"), r.port, r.port_open ? t("open") : t("closed"));
      checkOut.textContent = verdict;
      checkOut.className = "hint" + (r.reachable ? "" : " upd-err");
      toast(verdict, r.reachable ? "ok" : "err");
    } catch (e) { checkOut.textContent = e.message; checkOut.className = "hint upd-err"; toast(e.message, "err"); } finally { checkBtn.disabled = false; checkBtn.textContent = checkLabel; }
  });
  previewBtn.addEventListener("click", async () => {
    const opts = picker.get(); if (!opts.length) return toast("Pick at least one option", "err");
    try { const r = await api.post("/api/server/script", { protocols: opts, host: c.get().host }); modal({ title: "Install script (review)", body: mono(r.script) }); }
    catch (e) { toast(e.message, "err"); }
  });
  runBtn.addEventListener("click", async () => {
    const cr = c.get(), opts = picker.get();
    if (!cr.host || !cr.user) return toast("Host and SSH user are required", "err");
    if (!opts.length) return toast("Pick at least one option", "err");
    runBtn.disabled = true; runBtn.textContent = t("Working…");
    try {
      const r = await api.post("/api/server/provision", { server_id: sv && sv.id, name: sv && sv.name, ...cr, protocols: opts });
      con.run(r.job_id, v => {
        runBtn.disabled = false; runBtn.textContent = t("Set up again");
        // A run that delivered SOME of what was asked for used to render as plain success: ok is
        // true as soon as one protocol comes up, so "ask for three, get one" read as Done.
        const res = v.result || {};
        const req = (res.requested_protocols || []).length;
        const got = (res.provisioned_protocols || []).length;
        if (v.ok && res.partial) {
          toast("Partly set up — " + got + " of " + req + " ready, the rest failed. See the console.", "err");
        } else if (v.ok) toast("Done — client added to Connections", "ok");
        else toast("Finished with errors — see console", "err");
      });
    } catch (e) { runBtn.disabled = false; runBtn.textContent = t("Set up"); toast(e.message, "err"); }
  });
}

async function openHarden(sv) {
  const c = credsBlock(sv);
  const con = smartConsole();
  let installedKey = null, keyFile = "wr-key";
  const genBtn = el("button", { class: "btn btn-primary" }, "Generate & install key");
  const dlBtn = el("button", { class: "btn btn-sm", style: "display:none" }, "⤓ Download key");
  const savedCb = el("input", { type: "checkbox" });
  const savedWrap = el("label", { class: "check", style: "display:none" }, savedCb, el("span", {}, "I've downloaded the key and can log in with it"));
  const lockBtn = el("button", { class: "btn btn-danger", style: "display:none;margin-top:10px" }, "Disable password login");
  const back = modal({
    title: "Secure " + ((sv && (sv.name || sv.host)) || "server"),
    body: el("div", {}, c.node,
      el("div", { class: "hint", style: "margin-top:6px" }, "Step 1 installs a fresh SSH key and lets you download it. Step 2 (optional) disables password login so only the key works — do this only after you've saved and tested the key; it's your only way back in."),
      con.node,
      el("div", { style: "margin-top:12px;display:flex;gap:12px;align-items:center;flex-wrap:wrap" }, dlBtn, savedWrap),
      lockBtn),
    footer: genBtn,
  });
  genBtn.addEventListener("click", async () => {
    const cr = c.get();
    if (!cr.host || !cr.user) return toast("Host and SSH user are required", "err");
    genBtn.disabled = true; genBtn.textContent = t("Working…");
    try {
      const r = await api.post("/api/server/harden/keys", { server_id: sv && sv.id, ...cr });
      con.run(r.job_id, v => {
        genBtn.disabled = false; genBtn.textContent = t("Re-generate key");
        if (v.ok && v.result && v.result.private_key) {
          installedKey = v.result.private_key; keyFile = v.result.filename || "wr-key";
          dlBtn.style.display = ""; savedWrap.style.display = "inline-flex";
          dlBtn.onclick = () => downloadText(keyFile, installedKey);
          toast("Key installed — download it now", "ok");
        } else toast("Key install failed — see console", "err");
      });
    } catch (e) { genBtn.disabled = false; genBtn.textContent = t("Generate & install key"); toast(e.message, "err"); }
  });
  savedCb.addEventListener("change", () => { lockBtn.style.display = savedCb.checked ? "" : "none"; });
  lockBtn.addEventListener("click", async () => {
    if (!installedKey) return toast("Generate a key first", "err");
    if (!await modalConfirm(t("Disable password login on {0}?\n\nMake sure you downloaded the key and it works — afterwards only the key can log in.", sv ? sv.host : t("this server")))) return;
    lockBtn.disabled = true; lockBtn.textContent = t("Working…");
    try {
      const cr = c.get();
      const r = await api.post("/api/server/harden/lockdown", { server_id: sv && sv.id, host: cr.host, port: cr.port, user: cr.user, key: installedKey });
      con.run(r.job_id, v => {
        lockBtn.disabled = false; lockBtn.textContent = t("Disable password login");
        if (v.ok) { toast("Server hardened — key-only login", "ok"); back.remove(); route(); }
        else toast("Lockdown failed — password login unchanged", "err");
      });
    } catch (e) { lockBtn.disabled = false; lockBtn.textContent = t("Disable password login"); toast(e.message, "err"); }
  });
}

function renderVersionTable(box, result, sv, c, con) {
  box.innerHTML = "";
  const binaries = result && result.binaries;
  // Rendered on the job-done callback — AFTER route()/modal() i18nApply — so these
  // strings must go through t() explicitly to localize (i18nApply won't revisit them).
  if (result && result.arch) box.appendChild(el("div", { class: "hint", style: "margin-bottom:var(--sp-2)" }, "arch: " + result.arch));
  if (result && result.curl === false) box.appendChild(el("div", { class: "hint", style: "color:var(--warn);margin-bottom:var(--sp-2)" }, t("⚠ curl not found on the server — sing-box binary updates require curl (apt install curl)")));
  if (!binaries || !binaries.length) { box.appendChild(el("div", { class: "hint" }, t("No managed binaries found on this server."))); return; }
  const th = lbl => el("th", { style: "padding:8px 10px;text-align:left;border-bottom:1px solid var(--divider)" }, t(lbl));
  const table = el("table", { class: "rm-table" },
    el("thead", {}, el("tr", {}, th("Binary"), th("Installed"), th("Latest"), th(""))),
    el("tbody", {}, ...binaries.map(b => {
      const avail = !!b.update_available;
      const latest = b.managed === "apt" ? t("apt-managed") : (b.latest || (b.latest_error ? t("unknown") : "—"));
      const status = avail
        ? el("span", { class: "badge badge-ok" }, t("update → {0}", b.latest))
        : (b.managed === "apt" ? el("span", { class: "hint" }, t("via apt"))
          : el("span", { class: "pill muted" }, el("span", { class: "dot" }), b.latest_error ? t("check failed") : t("up to date")));
      const curlOk = result && result.curl !== false;
      let act = null;
      if (b.managed === "github" && avail) act = curlOk
        ? el("button", { class: "btn btn-primary btn-sm", onclick: (e) => updateBinary(sv, c, con, b, b.latest_tag || b.latest, e.currentTarget) }, t("Update"))
        : el("button", { class: "btn btn-primary btn-sm", disabled: true, title: t("curl not found on the server — install curl first (apt install curl)") }, t("Update"));
      else if (b.managed === "apt") act = el("button", { class: "btn btn-sm", onclick: (e) => updateBinary(sv, c, con, b, "", e.currentTarget) }, t("apt upgrade"));
      return el("tr", {},
        el("td", { "data-label": "Binary" }, b.name),
        el("td", { "data-label": "Installed" }, b.installed || "?"),
        el("td", { "data-label": "Latest" }, latest),
        el("td", { "data-label": "", class: "rm-r" }, el("div", { style: "display:flex;gap:8px;align-items:center;justify-content:flex-end;flex-wrap:wrap" }, status, act)));
    })));
  box.appendChild(table);
}

async function updateBinary(sv, c, con, b, version, btn) {
  if (btn && btn.disabled) return; // in-flight guard — this restarts the remote service; no double-submit
  const what = b.managed === "apt" ? t("{0} via apt upgrade", b.name) : t("{0} → {1}", b.name, version);
  if (!await modalConfirm(t("Update {0} on {1}?\n\nThe service will briefly restart. The old binary is backed up on the server as <path>.wayhop.bak.", what, sv ? sv.host : t("the server")))) return;
  const cr = c.get();
  if (!cr.host || !cr.user) return toast("Host and SSH user are required", "err");
  if (btn) btn.disabled = true;
  try {
    const r = await api.post("/api/server/update-binary", { server_id: sv && sv.id, ...cr, binary: b.key, version: version || "", confirm: true });
    con.run(r.job_id, v => {
      if (btn) btn.disabled = false;
      if (v.ok) toast(v.result && v.result.new_version ? t("{0} updated → {1}", b.name, v.result.new_version) : t("{0} updated", b.name), "ok");
      else toast("Update failed — see console", "err");
    });
  } catch (e) { if (btn) btn.disabled = false; toast(e.message, "err"); }
}
