// page-telegram.js — the Telegram bot card's content in Settings and the manager it opens.
//
// Loaded by loadChunk() when Settings renders the card, NOT from index.html, so its bytes stay out of
// the initial payload. A classic script, like app.js: these declarations
// become globals and app.js has already defined el/t/api/state/modal/toast by the time this runs.
//
// Everything the bot stores has its own routes (/api/telegram/*), so nothing here touches the
// Settings page's Save: the token, the chats and the alert switches are written the moment their
// own button is pressed, and the page's "unsaved changes" badge never counts them.

// The manager's styles travel with it, so they stay out of the initial payload. The dialog waits for
// them: opening unstyled for a frame and then jumping is worse than opening a few ms later.
const tgStylesReady = new Promise(resolve => {
  const link = el("link", { rel: "stylesheet", href: "page-telegram.css" });
  link.addEventListener("load", () => resolve());
  link.addEventListener("error", () => resolve()); // an unstyled dialog still works
  document.head.appendChild(link);
});

const TG_KINDS = [
  ["exits", L("Exits go down and come back"), L("With the cause and where the traffic went; the recovery replies to the outage.")],
  ["switches", L("Failover groups switch exits"), L("Which group moved, from which exit to which.")],
  ["uplink", L("The internet is lost on the uplink"), L("Every exit failing at once is one alert about the provider, not one per tunnel.")],
  ["core", L("The routing core crashes or stays down"), L("sing-box crash-restarts, and a core that stays down for a minute.")],
  ["apply", L("Test Apply: keep or roll back"), L("Owners get Keep and Roll back buttons with the countdown.")],
  ["boot", L("The router or WayHop restarts"), L("After a power cut: when it came back and roughly how long it was gone.")],
  ["system", L("RAM is almost full"), L("Above 92% for a while, and when it is back to normal.")],
  ["updates", L("A new WayHop release"), L("Once per release, with an Install button for owners.")],
];

const TG_ROLES = [
  ["owner", L("Owner"), L("Status, alerts, and the buttons that change things (Keep, Roll back). Private chats only.")],
  ["viewer", L("Viewer"), L("Status and alerts, no buttons that change anything. For family, or a second phone.")],
  ["alerts", L("Alerts only"), L("Only receives alerts. For a group or a channel.")],
];

// The bot's connection states, as a pill with the reason in its title.
const TELEGRAM_STATES = {
  off: ["muted", L("Off")],
  connecting: ["warn", L("Connecting…")],
  online: ["ok", L("Online")],
  error: ["err", L("Cannot reach Telegram")],
  unauthorized: ["err", L("Token rejected")],
  conflict: ["warn", L("Token used elsewhere")],
};
function telegramPill(bot) {
  const st = (bot && bot.state) || "off";
  const [cls, label] = TELEGRAM_STATES[st] || ["muted", st];
  const p = el("span", { class: "pill " + cls }, el("span", { class: "dot" }), t(label));
  if (bot && bot.error) p.title = bot.error;
  return p;
}

// telegramSummary is the one line under the pill: who the bot is and whom it serves, or why not.
function telegramSummary(m) {
  const bot = (m && m.bot) || {};
  if (bot.state === "online") return t("@{0} · {1} chat(s) paired", bot.username, ((m && m.chats) || []).length);
  if (bot.state === "off") return m && m.has_token ? t("Switched off.") : t("Not set up yet.");
  return bot.error || "";
}

// telegramCardFill fills the Settings card (app.js telegramCard) with the state and the button that
// opens the manager. The card refreshes after anything the manager saves.
function telegramCardFill(slot) {
  const line = el("div", { class: "tg-card-line" });
  const manage = el("button", { class: "btn", type: "button" }, t("Set up…"));
  const fill = m => {
    line.innerHTML = "";
    line.appendChild(telegramPill(m && m.bot));
    const text = telegramSummary(m);
    if (text) line.appendChild(el("span", { class: "hint tg-card-text" }, text));
    manage.textContent = m && m.has_token ? t("Manage…") : t("Set up…");
  };
  manage.addEventListener("click", async () => {
    manage.disabled = true;
    try { await telegramManage(fill); } catch (e) { toast(e.message, "err"); }
    finally { manage.disabled = false; }
  });
  slot.innerHTML = "";
  slot.appendChild(line);
  slot.appendChild(manage);
  api.get("/api/telegram").then(fill).catch(() => {
    line.innerHTML = "";
    line.appendChild(el("span", { class: "hint" }, t("The bot's state could not be read.")));
  });
}

// tgAgo is a relative time for a panel list ("5 min ago").
function tgAgo(iso) {
  const ms = Date.now() - Date.parse(iso || "");
  if (!isFinite(ms) || ms < 0) return "";
  const m = Math.round(ms / 60000);
  if (m < 1) return t("just now");
  if (m < 60) return t("{0} min ago", m);
  const h = Math.round(m / 60);
  if (h < 48) return t("{0} h ago", h);
  return t("{0} d ago", Math.round(h / 24));
}

// telegramManage opens the manager. onChange runs after anything is saved, so the Settings card
// can refresh its one-line summary.
async function telegramManage(onChange) {
  let model = await api.get("/api/telegram");
  await tgStylesReady;
  let pairTimer = null;
  let pollTimer = null;
  let pairing = null; // {code, exp, link, role, chatsBefore}
  const changed = () => { if (typeof onChange === "function") onChange(model); };

  const body = el("div", { class: "tg-mgr" });
  const statusRow = el("div", { class: "tg-status" });
  const chatsBox = el("div", { class: "tg-chats" });
  const pairBox = el("div", { class: "tg-pair" });
  const strangersBox = el("div", { class: "tg-strangers" });

  // ── Connection ──────────────────────────────────────────────────────────────────────────────
  const tokenInput = el("input", { type: "password", autocomplete: "off", spellcheck: "false",
    placeholder: "123456789:AA…", "aria-label": t("Bot token") });
  const tokenSaved = el("div", { class: "tg-token-saved" });
  const replaceBtn = el("button", { class: "btn btn-sm", type: "button" }, t("Replace token"));
  const checkBtn = el("button", { class: "btn btn-sm", type: "button" }, t("Check"));
  const checkOut = el("span", { class: "hint tg-check" });
  const enabled = el("input", { type: "checkbox" });
  const via = el("select", { "aria-label": t("Reach Telegram through") });
  const apiBase = el("input", { type: "text", spellcheck: "false", placeholder: "https://api.telegram.org",
    "aria-label": t("Bot API server") });
  const saveConn = el("button", { class: "btn btn-primary", type: "button" }, t("Save connection"));

  const fillVia = () => {
    via.innerHTML = "";
    via.appendChild(el("option", { value: "" }, t("The router's own connection")));
    via.appendChild(el("option", { value: "@proxy" }, t("WayHop's local proxy (follows your routing)")));
    const eps = (state.profile && state.profile.endpoints) || [];
    const groups = (state.profile && state.profile.groups) || [];
    if (groups.length) {
      const og = el("optgroup", { label: t("Failover groups") });
      groups.forEach(g => og.appendChild(el("option", { value: g.id }, g.name || g.id)));
      via.appendChild(og);
    }
    if (eps.length) {
      const og = el("optgroup", { label: t("Connections") });
      eps.forEach(e => og.appendChild(el("option", { value: e.id }, (e.name || e.id) + (e.enabled ? "" : " — " + t("disabled")))));
      via.appendChild(og);
    }
    // A saved choice that no longer matches the profile stays visible rather than silently
    // turning into "the router's own connection".
    if (model.via && ![...via.options].some(o => o.value === model.via)) {
      via.appendChild(el("option", { value: model.via }, t("{0} (no longer in the profile)", model.via)));
    }
    via.value = model.via || "";
  };

  const renderToken = () => {
    tokenSaved.innerHTML = "";
    if (model.has_token && !tokenInput.dataset.replacing) {
      tokenInput.hidden = true;
      tokenSaved.hidden = false;
      tokenSaved.appendChild(el("span", { class: "tg-mask" }, "••••••••••"));
      tokenSaved.appendChild(el("span", { class: "hint" }, t("saved on the router, never shown again")));
      tokenSaved.appendChild(replaceBtn);
    } else {
      tokenInput.hidden = false;
      tokenSaved.hidden = true;
    }
    enabled.checked = !!model.enabled;
  };
  replaceBtn.addEventListener("click", () => {
    tokenInput.dataset.replacing = "1";
    renderToken();
    tokenInput.focus();
  });

  const connBody = () => ({
    token: tokenInput.hidden ? "" : tokenInput.value.trim(),
    api_base: apiBase.value.trim(),
    via: via.value,
  });

  checkBtn.addEventListener("click", async () => {
    checkBtn.disabled = true;
    checkOut.className = "hint tg-check";
    checkOut.textContent = t("Asking Telegram…");
    try {
      const r = await api.post("/api/telegram/check", connBody());
      if (r.ok) {
        checkOut.className = "hint tg-check ok";
        checkOut.textContent = t("Works: @{0} ({1})", r.username, r.name);
      } else {
        checkOut.className = "hint tg-check err";
        checkOut.textContent = r.error;
      }
    } catch (e) {
      checkOut.className = "hint tg-check err";
      checkOut.textContent = e.message;
    } finally { checkBtn.disabled = false; }
  });

  // The whole settings object goes back on every save: the route replaces the settings it is given,
  // so the connection form and the alerts form must not erase each other.
  const settingsBody = () => ({
    enabled: enabled.checked,
    ...connBody(),
    alerts_off: TG_KINDS.map(k => k[0]).filter(k => !kindBoxes[k].checked),
    quiet_from: quietOn.checked ? quietFrom.value : "",
    quiet_to: quietOn.checked ? quietTo.value : "",
    digest: digestOn.checked ? digestAt.value : "",
  });

  const save = async (btn, okMsg) => {
    btn.disabled = true;
    try {
      model = await api.put("/api/telegram", settingsBody());
      delete tokenInput.dataset.replacing;
      tokenInput.value = "";
      renderToken();
      renderLive();
      toast(okMsg, "ok");
      changed();
    } catch (e) { toast(e.message, "err"); }
    finally { btn.disabled = false; }
  };
  saveConn.addEventListener("click", () => save(saveConn, t("Telegram connection saved.")));

  // ── Alerts ──────────────────────────────────────────────────────────────────────────────────
  const kindBoxes = {};
  const kindsGrid = el("div", { class: "tg-kinds" });
  TG_KINDS.forEach(([key, label, hint]) => {
    const cb = el("input", { type: "checkbox" });
    cb.checked = !(model.alerts_off || []).includes(key);
    kindBoxes[key] = cb;
    kindsGrid.appendChild(el("label", { class: "check tg-kind" }, cb,
      el("span", {}, el("span", { class: "tg-kind-name" }, t(label)), el("span", { class: "hint" }, t(hint)))));
  });
  const quietOn = el("input", { type: "checkbox" });
  const quietFrom = el("input", { type: "time", value: model.quiet_from || "23:00", "aria-label": t("Quiet from") });
  const quietTo = el("input", { type: "time", value: model.quiet_to || "07:30", "aria-label": t("Quiet until") });
  quietOn.checked = !!(model.quiet_from && model.quiet_to);
  const syncQuiet = () => { quietFrom.disabled = quietTo.disabled = !quietOn.checked; };
  quietOn.addEventListener("change", syncQuiet);
  syncQuiet();
  const digestOn = el("input", { type: "checkbox" });
  const digestAt = el("input", { type: "time", value: model.digest || "09:00", "aria-label": t("Daily summary at") });
  digestOn.checked = !!model.digest;
  const syncDigest = () => { digestAt.disabled = !digestOn.checked; };
  digestOn.addEventListener("change", syncDigest);
  syncDigest();
  // Both times are the router's, which need not be the browser's: say what its clock reads. Isolated
  // (LRI…PDI) like the bot's name below, or Persian draws "14:32 (+03)" as "(03+) 14:32".
  const clockNote = el("div", { class: "hint" });
  const renderClock = () => {
    clockNote.textContent = model.clock ? t("Router clock: {0}; quiet hours and the summary follow it.",
      "⁦" + model.clock + (model.zone ? " (" + model.zone + ")" : "") + "⁩") : "";
  };
  const saveAlerts = el("button", { class: "btn btn-primary", type: "button" }, t("Save alerts"));
  saveAlerts.addEventListener("click", () => save(saveAlerts, t("Alert settings saved.")));

  // ── Chats ───────────────────────────────────────────────────────────────────────────────────
  // The option names are short so they fit a row; what a role may do is the select's title and,
  // where there is room, a line under it.
  const roleHint = key => t((TG_ROLES.find(r => r[0] === key) || TG_ROLES[0])[2]);
  const roleSelect = (value, isGroup) => {
    const s = el("select", {});
    TG_ROLES.forEach(([key, label]) => {
      const o = el("option", { value: key }, t(label));
      if (key === "owner" && isGroup) o.disabled = true;
      s.appendChild(o);
    });
    s.value = value;
    s.title = roleHint(value);
    s.addEventListener("change", () => { s.title = roleHint(s.value); });
    return s;
  };

  const renderChats = () => {
    chatsBox.innerHTML = "";
    const chats = model.chats || [];
    if (!chats.length) {
      chatsBox.appendChild(el("div", { class: "hint" }, t("No chat is paired yet. Get a pairing code below and send it to the bot.")));
      return;
    }
    chats.forEach(c => {
      const isGroup = c.id < 0;
      const role = roleSelect(c.role, isGroup);
      role.setAttribute("aria-label", t("Role of {0}", c.name || c.id));
      role.addEventListener("change", async () => {
        try { model = await api.put("/api/telegram/chats/" + c.id, { role: role.value }); renderLive(); changed(); }
        catch (e) { toast(e.message, "err"); role.value = c.role; }
      });
      const langSel = el("select", { "aria-label": t("Language of {0}", c.name || c.id) },
        el("option", { value: "en" }, "English"), el("option", { value: "ru" }, "Русский"),
        el("option", { value: "uk" }, "Українська"));
      langSel.value = c.lang || "en";
      langSel.addEventListener("change", async () => {
        try { model = await api.put("/api/telegram/chats/" + c.id, { lang: langSel.value }); changed(); }
        catch (e) { toast(e.message, "err"); }
      });
      const drop = el("button", { class: "btn btn-sm btn-danger", type: "button" }, t("Disconnect"));
      drop.addEventListener("click", async () => {
        if (!await modalConfirm(t("Disconnect {0} from the bot? It stops getting alerts and can no longer ask the router anything.", c.name || c.id))) return;
        try { model = await api.del("/api/telegram/chats/" + c.id); renderLive(); changed(); }
        catch (e) { toast(e.message, "err"); }
      });
      chatsBox.appendChild(el("div", { class: "tg-chat" },
        el("div", { class: "tg-chat-who" },
          el("span", { class: "tg-chat-name" }, (isGroup ? "👥 " : "👤 ") + (c.name || String(c.id))),
          el("span", { class: "hint" }, c.paired_at ? t("paired {0}", tgAgo(new Date(c.paired_at * 1000).toISOString())) : "")),
        role, langSel, drop));
    });
  };

  const renderStrangers = () => {
    strangersBox.innerHTML = "";
    const list = model.strangers || [];
    if (!list.length) return;
    strangersBox.appendChild(el("div", { class: "tg-sub" }, t("Asked to connect")));
    strangersBox.appendChild(el("div", { class: "hint" }, t("These chats wrote to the bot without a code. Let one in only if you know who it is.")));
    list.forEach(s => {
      const isGroup = s.type !== "private";
      // Viewer by default: letting in a chat that nobody vouched for with a code should not hand it the
      // Keep and Roll back buttons unless the operator picks that on purpose.
      const role = roleSelect("viewer", isGroup);
      role.setAttribute("aria-label", t("Role for {0}", s.name));
      const allow = el("button", { class: "btn btn-sm", type: "button" }, t("Let in"));
      allow.addEventListener("click", async () => {
        try { model = await api.post("/api/telegram/strangers/" + s.chat_id + "/allow", { role: role.value }); renderLive(); changed(); toast(t("{0} is connected.", s.name), "ok"); }
        catch (e) { toast(e.message, "err"); }
      });
      const dismiss = el("button", { class: "btn btn-sm", type: "button" }, t("Dismiss"));
      dismiss.addEventListener("click", async () => {
        try { model = await api.del("/api/telegram/strangers/" + s.chat_id); renderLive(); }
        catch (e) { toast(e.message, "err"); }
      });
      strangersBox.appendChild(el("div", { class: "tg-chat" },
        el("div", { class: "tg-chat-who" },
          el("span", { class: "tg-chat-name" }, (isGroup ? "👥 " : "👤 ") + s.name + (s.username ? " @" + s.username : "")),
          el("span", { class: "hint" }, t("wrote {0} · {1} message(s)", tgAgo(s.last_seen), s.attempts))),
        role, allow, dismiss));
    });
  };

  // Pairing: a one-time code, a deep link, and a countdown. The poll notices the new chat and turns
  // the box into a confirmation, so nobody has to guess whether it worked.
  const pairRole = roleSelect("owner", false);
  pairRole.setAttribute("aria-label", t("Role of the new chat"));
  const pairHint = el("div", { class: "hint" }, roleHint(pairRole.value));
  pairRole.addEventListener("change", () => { pairHint.textContent = roleHint(pairRole.value); });
  const pairBtn = el("button", { class: "btn", type: "button" }, t("Get a pairing code"));
  const renderPair = () => {
    pairBox.innerHTML = "";
    if (!pairing) {
      pairBox.appendChild(el("div", { class: "tg-pair-start" }, el("span", { class: "hint" }, t("Connect a new chat as")), pairRole, pairBtn));
      pairBox.appendChild(pairHint);
      return;
    }
    const left = Math.max(0, Math.round((pairing.exp - Date.now()) / 1000));
    if (pairing.done) {
      pairBox.appendChild(el("div", { class: "tg-pair-done" }, "✅ " + t("{0} is connected.", pairing.done)));
      pairBox.appendChild(el("div", { class: "tg-pair-start" }, el("span", { class: "hint" }, t("Connect a new chat as")), pairRole, pairBtn));
      pairBox.appendChild(pairHint);
      return;
    }
    if (!left) {
      pairBox.appendChild(el("div", { class: "hint" }, t("The code expired. Get a new one.")));
      pairBox.appendChild(el("div", { class: "tg-pair-start" }, el("span", { class: "hint" }, t("Connect a new chat as")), pairRole, pairBtn));
      pairBox.appendChild(pairHint);
      return;
    }
    const code = el("div", { class: "tg-code", "aria-label": t("Pairing code") }, pairing.code.slice(0, 4) + " " + pairing.code.slice(4));
    const copy = el("button", { class: "btn btn-sm", type: "button" }, t("Copy"));
    copy.addEventListener("click", () => { copyText("/start " + pairing.code); toast(t("Copied."), "ok"); });
    // Two whole sentences rather than a name spliced into one: the link exists exactly when the bot's
    // name is known, and a spliced "your bot" read as "to the bot your bot" in languages that decline.
    const steps = el("div", { class: "hint" }, pairing.link
      // The name is isolated (LRI…PDI) because it lands inside a translated sentence: in Persian, a
      // right-to-left page, a bare "@name" was drawn as "name@".
      ? t("Open the link on the phone that has Telegram and press Start, or send /start {0} to {1}.", pairing.code,
        pairing.link.replace(/^https:\/\/t\.me\/([^?]+).*$/, "⁦@$1⁩"))
      : t("Send /start {0} to your bot in Telegram.", pairing.code));
    const row = el("div", { class: "tg-code-row" }, code, copy);
    if (pairing.link) row.appendChild(el("a", { class: "btn btn-sm btn-primary", href: pairing.link, target: "_blank", rel: "noopener" }, t("Open in Telegram")));
    pairBox.appendChild(row);
    if (pairing.qr) {
      // Drawn by the daemon from the deep link; an <img> of it, so nothing from the response is ever
      // parsed as markup in this page.
      pairBox.appendChild(el("div", { class: "tg-qr" },
        el("img", { src: "data:image/svg+xml;charset=utf-8," + encodeURIComponent(pairing.qr), alt: t("QR code of the link"), width: "164", height: "164" }),
        el("div", { class: "hint" }, t("Or point the phone's camera at this code."))));
    }
    pairBox.appendChild(steps);
    pairing.validity = el("div", { class: "hint" });
    pairBox.appendChild(pairing.validity);
    tickPair();
  };
  // tickPair moves the countdown without rebuilding the box, so Copy and the link stay put under the
  // pointer; only the moment the code runs out redraws it.
  const tickPair = () => {
    if (!pairing || pairing.done || !pairing.validity) return;
    const left = Math.max(0, Math.round((pairing.exp - Date.now()) / 1000));
    if (!left) { renderPair(); return; }
    pairing.validity.textContent = t("Valid for {0} · single use · as {1}", Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0"),
      t((TG_ROLES.find(r => r[0] === pairing.role) || TG_ROLES[0])[1]));
  };
  pairBtn.addEventListener("click", async () => {
    pairBtn.disabled = true;
    try {
      const r = await api.post("/api/telegram/pair", { role: pairRole.value });
      pairing = { code: r.code, link: r.link, qr: r.qr_svg || "", role: pairRole.value, exp: Date.now() + r.ttl_s * 1000,
        chatsBefore: new Set((model.chats || []).map(c => c.id)) };
      renderPair();
    } catch (e) { toast(e.message, "err"); }
    finally { pairBtn.disabled = false; }
  });

  const testBtn = el("button", { class: "btn btn-sm", type: "button" }, t("Send a test message"));
  testBtn.addEventListener("click", async () => {
    testBtn.disabled = true;
    try {
      const r = await api.post("/api/telegram/test", {});
      const bad = (r.results || []).filter(x => !x.ok);
      if (!bad.length) toast(t("Sent to {0} chat(s).", (r.results || []).length), "ok");
      else toast(bad.map(x => (x.name || x.id) + ": " + x.error).join("; "), "err");
    } catch (e) { toast(e.message, "err"); }
    finally { testBtn.disabled = false; }
  });

  // renderLive redraws what the router can change under the open dialog: the connection state, the
  // chats, the strangers. The forms are left alone, so a poll never eats what is being typed.
  const renderLive = () => {
    renderClock();
    statusRow.innerHTML = "";
    const b = model.bot || {};
    statusRow.appendChild(telegramPill(b));
    statusRow.appendChild(el("span", { class: "tg-status-line" }, telegramSummary(model)));
    testBtn.disabled = b.state !== "online" || !(model.chats || []).length;
    statusRow.appendChild(testBtn);
    if (pairing && !pairing.done) {
      const fresh = (model.chats || []).find(c => !pairing.chatsBefore.has(c.id));
      if (fresh) { pairing.done = fresh.name || String(fresh.id); changed(); renderPair(); }
    }
    // The lists are redrawn only when what they show changed: a poll that rebuilt them every three
    // seconds reset a role somebody had just picked and pulled "Let in" out from under the pointer.
    const sig = JSON.stringify([model.chats || [], (model.strangers || []).map(x => [x.chat_id, x.name, x.username, x.type, x.attempts])]);
    if (sig !== listSig) {
      listSig = sig;
      renderChats();
      renderStrangers();
    }
  };
  let listSig = "";

  const section = (title, ...kids) => el("div", { class: "tg-section" }, el("div", { class: "tg-sub" }, t(title)), ...kids);

  body.appendChild(statusRow);
  body.appendChild(section(L("Connection"),
    el("div", { class: "hint" }, t("In Telegram, open @BotFather, send /newbot, and paste the token it gives you here. The router talks to Telegram itself, so no port has to be opened.")),
    el("div", { class: "field" }, el("label", {}, t("Bot token")),
      el("div", { class: "tg-token" }, tokenInput, tokenSaved, checkBtn), checkOut),
    el("div", { class: "field" }, el("label", {}, t("Reach Telegram through")), via,
      el("div", { class: "hint" }, t("Where Telegram is blocked, send the bot through a tunnel or through WayHop's own routing."))),
    el("details", { class: "tg-adv" }, el("summary", {}, t("Advanced")),
      el("div", { class: "field" }, el("label", {}, t("Bot API server")), apiBase,
        el("div", { class: "hint" }, t("Only for a self-hosted Bot API server or a relay. Leave blank for Telegram's own.")))),
    el("div", { class: "tg-actions" },
      el("label", { class: "check" }, enabled, el("span", {}, t("Bot enabled"))), saveConn)));
  body.appendChild(section(L("Chats"), chatsBox, pairBox, strangersBox));
  body.appendChild(section(L("Alerts"), kindsGrid,
    el("div", { class: "tg-quiet" },
      el("label", { class: "check" }, quietOn, el("span", {}, t("Quiet hours"))), quietFrom, el("span", {}, "–"), quietTo),
    el("div", { class: "hint" }, t("During quiet hours alerts wait and arrive as one summary afterwards; critical ones and Keep/Roll back requests arrive at once.")),
    el("div", { class: "tg-quiet" },
      el("label", { class: "check" }, digestOn, el("span", {}, t("Daily summary at"))), digestAt),
    el("div", { class: "hint" }, t("Outages, switches, traffic by exit. Silent, even in quiet hours.")),
    clockNote,
    el("div", { class: "tg-actions" }, saveAlerts)));

  apiBase.value = model.api_base || "";
  fillVia();
  renderToken();
  renderLive();
  renderPair();

  const dlg = modal({ title: t("Telegram bot"), body, fixed: false });
  const alive = () => document.contains(dlg);
  pairTimer = setInterval(() => { if (!alive()) return clearInterval(pairTimer); tickPair(); }, 1000);
  pollTimer = setInterval(async () => {
    if (!alive()) return clearInterval(pollTimer);
    try {
      const fresh = await api.get("/api/telegram");
      if (!alive()) return;
      model = { ...fresh };
      renderLive();
    } catch (_) { /* the next tick tries again; the dialog keeps what it has */ }
  }, 3000);
  return dlg;
}
