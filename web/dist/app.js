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
async function apiErr(r) {
  try { const j = await r.json(); return new Error(j.error || r.statusText); }
  catch { return new Error(r.statusText); }
}
const api = {
  async get(p) { const r = await fetch(p); if (!r.ok) throw await apiErr(r); return r.json(); },
  async post(p, body) {
    const r = await fetch(p, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body || {}) });
    if (!r.ok) throw await apiErr(r); return r.json();
  },
  async put(p, body) {
    const r = await fetch(p, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(body || {}) });
    if (!r.ok) throw await apiErr(r); return r.json();
  },
  async del(p) { const r = await fetch(p, { method: "DELETE" }); if (!r.ok) throw await apiErr(r); return r.json(); },
};

/* ---------- state ---------- */
const state = { health: null, profile: { endpoints: [], groups: [], rules: [] } };
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
function toast(msg, kind = "info") {
  // Localize whole-string toasts via the dictionary; concatenated/interpolated
  // messages that aren't an exact key pass through unchanged.
  const node = el("div", { class: "toast " + kind }, (typeof t === "function" ? t(msg) : msg));
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
// RU supplements for recently-added UI strings not yet in the generated i18n.js dict
// (Native-support card, Set-up-Server picker, native-tunnel adoption). Additive only:
// we fill missing keys, never override an existing translation. The canonical home for
// these is .claude/i18n/dicts/ru.json → i18n.js; this merge keeps RU complete until the
// dict is regenerated. English keys must match the rendered text EXACTLY.
(function supplementRuDict() {
  const add = {
    // Native support card
    "Native support": "Нативная поддержка",
    "No capability data reported.": "Данные о возможностях отсутствуют.",
    "Carried by the kernel / firmware — no sing-box needed": "Обрабатывается ядром / прошивкой — sing-box не нужен",
    "NATIVE": "НАТИВНО",
    "Native once this package is installed": "Станет нативным после установки этого пакета",
    "Carried by the sing-box core": "Обрабатывается ядром sing-box",
    "via sing-box": "через sing-box",
    "Recommended installs": "Рекомендуемые установки",
    "not built in": "не встроено",
    "not enabled (firmware component)": "не включено (компонент прошивки)",
    "Enable it in the Keenetic app (System → Component options) and reboot — it then routes natively.": "Включите его в приложении Keenetic (Система → Параметры компонентов) и перезагрузитесь — после этого трафик идёт нативно.",
    "Copy command": "Скопировать команду",
    // Subscription auto-refresh card
    "Subscription auto-refresh": "Автообновление подписки",
    "No imported subscription. Import a subscription URL under Connections to enable periodic auto-refresh.": "Подписка не импортирована. Импортируйте URL подписки в разделе «Соединения», чтобы включить периодическое автообновление.",
    "Source: ": "Источник: ",
    "Refresh now": "Обновить сейчас",
    "Auto-refresh": "Автообновление",
    "Every (hours)": "Каждые (часов)",
    "Auto-refresh every {0} h": "Автообновление каждые {0} ч",
    "Auto-refresh disabled": "Автообновление выключено",
    "Refreshing…": "Обновление…",
    "Refreshed — {0} new connection(s)": "Обновлено — {0} новых соединений",
    "Last refreshed {0} (+{1} new)": "Обновлено {0} (+{1} новых)",
    "Last refresh failed: ": "Последнее обновление не удалось: ",
    "Never refreshed yet": "Ещё не обновлялось",
    "just now": "только что",
    "{0}m ago": "{0} мин назад",
    "{0}h ago": "{0} ч назад",
    "{0}d ago": "{0} дн назад",
    "matched {0} log lines": "совпало строк лога: {0}",
    "Reality mimics a real site — pick a major TLS-1.3 host (suggestions in the field), then Check it's reachable + TLS 1.3.": "Reality маскируется под реальный сайт — выберите крупный хост с TLS 1.3 (подсказки в поле), затем нажмите «Проверить» (доступен + TLS 1.3).",
    "not a valid x25519 key (base64 of 32 bytes)": "недействительный ключ x25519 (base64 из 32 байт)",
    "must be hex, even length, ≤16 chars": "только hex, чётная длина, ≤16 символов",
    "Could not load subscription info.": "Не удалось загрузить данные подписки.",
    "present": "присутствует",
    "not required": "не требуется",
    // Native-only mode (sing-box intentionally absent — kernel plane carries everything)
    "Native": "Нативный",
    "Native-only mode — sing-box not required": "Только нативный режим — sing-box не требуется",
    "Routed by the kernel plane (fast mode)": "Маршрутизация ядром (быстрый режим)",
    "Every endpoint is kernel-native and traffic is routed by the kernel plane in fast mode, so the sing-box core is intentionally not running.":
      "Все подключения нативны для ядра, и трафик маршрутизируется ядром в быстром режиме, поэтому ядро sing-box намеренно не запущено.",
    // Detected native tunnels + adoption
    "Detected native tunnels": "Обнаруженные нативные туннели",
    "Tunnel has a recent handshake": "У туннеля недавнее рукопожатие",
    "Configured but no recent handshake": "Настроен, но без недавнего рукопожатия",
    "idle": "простаивает",
    "Adopt as exit": "Принять как выход",
    "Adopted": "Принят",
    "Already added as a routing exit": "Уже добавлен как маршрутный выход",
    "Add this OS-owned tunnel as a routing exit (added disabled — WakeRoute will not manage it)":
      "Добавить этот туннель ОС как маршрутный выход (добавляется отключённым — WakeRoute не управляет им)",
    "WakeRoute will ROUTE THROUGH the tunnel but does not manage it (the OS owns it). It is added disabled — enable it in Connections to start routing.":
      "WakeRoute будет МАРШРУТИЗИРОВАТЬ ЧЕРЕЗ туннель, но не управляет им (туннель принадлежит ОС). Он добавляется отключённым — включите его в разделе «Подключения», чтобы начать маршрутизацию.",
    "Adopted {0} — enable it in Connections to route through it":
      "Принят {0} — включите его в разделе «Подключения», чтобы маршрутизировать через него",
    // Set-up-Server option picker
    "Recommended": "Рекомендуемые",
    "Also available": "Также доступно",
    "Available": "Доступно",
    "— suggested defaults, hardest to detect": "— предлагаемые по умолчанию, труднее всего обнаружить",
    "self-signed TLS": "самоподписанный TLS",
    "Provisions with a self-signed TLS certificate": "Развёртывается с самоподписанным сертификатом TLS",
    "Self-signed TLS": "Самоподписанный TLS",
    " — the protocols tagged below provision with a self-signed certificate. That's fine for personal use; for active-probing resistance, bring your own domain + a real cert.":
      " — отмеченные ниже протоколы развёртываются с самоподписанным сертификатом. Для личного использования это нормально; для устойчивости к активному зондированию используйте свой домен и настоящий сертификат.",
    // Native VPNs section on the Connections page
    "OS-managed tunnel — enable to use for routing": "Туннель под управлением ОС — включите для использования в маршрутизации",
    "Native VPNs on this router": "Нативные VPN на этом роутере",
    "Tunnels already managed by the OS — add them as routing exits without re-entering credentials.":
      "Туннели, уже управляемые ОС — добавьте их как маршрутные выходы без повторного ввода учётных данных.",
    "Already added": "Уже добавлен",
    "Add as exit": "Добавить как выход",
    "full tunnel": "полный туннель",
    "Routes all traffic (0.0.0.0/0)": "Маршрутизирует весь трафик (0.0.0.0/0)",
    "Active — recent handshake": "Активен — недавнее рукопожатие",
    "No recent handshake": "Нет недавнего рукопожатия",
    "Added! Enable it in Connections, then add routing lists.": "Добавлено! Включите в разделе «Подключения», затем добавьте списки маршрутизации.",
    // Failover: active "Test all" + member re-sort by fresh latency
    "Test all": "Проверить все",
    "Actively re-test every member's latency, then sort best-first": "Активно перепроверить задержку каждого участника и отсортировать лучшие первыми",
    "Testing…": "Проверка…",
    "This group has no members to test": "В этой группе нет участников для проверки",
    "Tested {0} members — {1} alive": "Проверено участников: {0} — активны: {1}",
    // Failover: edit group + kill switch
    "Edit": "Изменить",
    "Edit group settings": "Изменить настройки группы",
    "Edit failover group": "Изменить группу отказоустойчивости",
    "Kill switch (drop when all members down)": "Аварийная блокировка (сбрасывать трафик, если все участники недоступны)",
    "When on, traffic is dropped instead of falling back to the open WAN if every member is down — no leak to the unprotected internet.":
      "Когда включено, трафик сбрасывается вместо возврата на открытый WAN, если все участники недоступны — без утечки в незащищённый интернет.",
    "Saved {0}": "Сохранено: {0}",
    // Per-tunnel link tuning (WireGuard / AmneziaWG)
    "MTU": "MTU",
    "e.g. 1420 — blank = auto": "напр. 1420 — пусто = авто",
    "Persistent keepalive (s)": "Постоянный keepalive (с)",
    "e.g. 25 — blank = off": "напр. 25 — пусто = выкл",
    // Full backup (whole-setup export/restore — Settings)
    "Full backup (everything)": "Полный бэкап (всё)",
    "Download full backup": "Скачать полный бэкап",
    "Restore full backup…": "Восстановить из полного бэкапа…",
    "Save your whole setup — connections, failover groups, routing lists, saved servers and routing mode — to one file. Ideal before a firmware reflash or when moving to another WakeRoute. Restoring validates everything first and never applies on its own; you review it and press Apply.":
      "Сохраните всю конфигурацию — подключения, группы отказоустойчивости, списки маршрутизации, сохранённые серверы и режим маршрутизации — в один файл. Удобно перед перепрошивкой или при переносе на другой WakeRoute. При восстановлении всё сначала проверяется и ничего не применяется автоматически; вы просматриваете и нажимаете «Применить».",
    "The backup file contains your connection secrets (keys, passwords) — keep it private. Daemon access settings (panel port and host allow-list) are NOT changed by a restore.":
      "Файл бэкапа содержит секреты подключений (ключи, пароли) — храните его в тайне. Настройки доступа к демону (порт панели и список разрешённых хостов) при восстановлении НЕ меняются.",
    "That is not a WakeRoute full backup.": "Это не файл полного бэкапа WakeRoute.",
    "Restore your whole setup from this backup? It replaces all connections, groups and routing lists (validated first). Nothing is applied automatically — review it, then press Apply. Your panel address and access settings are NOT changed.":
      "Восстановить всю конфигурацию из этого бэкапа? Это заменит все подключения, группы и списки маршрутизации (сначала с проверкой). Ничего не применяется автоматически — просмотрите и нажмите «Применить». Адрес панели и настройки доступа НЕ меняются.",
    "Restored {0} connections, {1} groups, {2} servers — review and press Apply to activate.":
      "Восстановлено: подключений {0}, групп {1}, серверов {2} — просмотрите и нажмите «Применить» для активации.",
    // Reality dest/SNI reachability probe (Check button next to the SNI field)
    "Check": "Проверить",
    "Checking…": "Проверка…",
    "Enter an SNI to check": "Введите SNI для проверки",
    "✓ reachable · TLS 1.3": "✓ доступен · TLS 1.3",
    "reachable, but TLS {0} (Reality needs 1.3)": "доступен, но TLS {0} (Reality требует 1.3)",
    "✗ unreachable: {0}": "✗ недоступен: {0}",
    "✗ check failed: {0}": "✗ проверка не удалась: {0}",
    "no response": "нет ответа",
  };
  try {
    const ru = DICTS.ru || (DICTS.ru = {});
    for (const k in add) if (ru[k] == null) ru[k] = add[k];
  } catch (_) { /* WR_DICTS frozen or absent — fall back to English, never throw */ }
})();
const I18N_LANGS = window.WR_LANGS || [{ code: "en", name: "English" }];
const RTL_LANGS = new Set(window.WR_RTL || ["ar", "fa"]);
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
  if (v === "auto" || !hasDict(v)) localStorage.removeItem(LANG_KEY); else localStorage.setItem(LANG_KEY, v);
  translateChrome();
  if (typeof route === "function") route();
}
function t(s, ...args) {
  const d = DICTS[lang()];
  let out = d && d[s] != null ? d[s] : s;
  args.forEach((a, i) => { out = out.split("{" + i + "}").join(a); });
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
const NAV_LABELS = { dashboard: "Dashboard", server: "Set up Server", connections: "Connections", failover: "Failover", routing: "Routing", updater: "Updater", diagnostics: "Diagnostics", settings: "Settings" };
// Short hover explanations for each nav item (data-page -> English tooltip). Applied as the
// element's title in translateChrome so they localize alongside the labels.
const NAV_TOOLTIPS = {
  dashboard: "Overview — status, live connections, traffic, and routing-list health",
  server: "Provision a fresh server into a proxy over SSH, and manage existing ones",
  connections: "Your proxy/VPN connections — add, import, edit and test them",
  failover: "Group connections so traffic auto-switches to a healthy one",
  routing: "Send chosen domain/IP lists through a tunnel; everything else stays direct",
  updater: "Update the proxy cores and the panel itself",
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
  const ab = document.getElementById("applybtn"), asb = document.getElementById("applysavebtn");
  // Static chrome that is NOT rebuilt per render must be re-rendered from its English
  // source on every language switch (like the nav above) — translating it in place
  // would stick it in the first language chosen, since the swapped text is no longer
  // an English key.
  if (ab) { ab.textContent = t("Apply"); ab.title = t("Apply live — not saved, reverts on reboot or if connectivity drops"); }
  if (asb) { asb.textContent = t("Apply & Save"); asb.title = t("Apply and persist as the saved baseline"); }
  const bs = document.querySelector(".brand .bs");
  if (bs) bs.textContent = t("proxy control");
  try { updateStatusPill(); } catch (e) {} // re-localize the live status pill
}

/* ---------- restart the WakeRoute service ---------- */
async function restartService() {
  if (!confirm(t("Restart the WakeRoute service now?\nThe web panel will be unavailable for a few seconds while the init system brings it back."))) return;
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
let gdata = [];
let graphCanvas = null;
// Poll the server's rolling buffer (1 Hz). Polling rather than a persistent SSE
// keeps the connection idle between ticks, which embedded WebViews + headless
// screenshot tools require (a long-lived SSE never reaches "network idle").
async function pollTraffic() {
  // Ask for only the last MAXG samples the graph renders, not the full 300 buffer.
  try { gdata = (await api.get("/api/traffic/recent?n=" + MAXG)).slice(-MAXG); drawGraph(); } catch (_) {}
}
// hex color (#rgb / #rrggbb) → "rgba(r,g,b,a)" for translucent graph fills.
function rgba(hex, a) {
  let h = (hex || "").replace("#", "");
  if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
  const n = parseInt(h, 16);
  return "rgba(" + ((n >> 16) & 255) + "," + ((n >> 8) & 255) + "," + (n & 255) + "," + a + ")";
}
function drawGraph() {
  const c = graphCanvas;
  if (!c) return;
  const ctx = c.getContext("2d"), pad = 6;
  // Hi-DPI: size the backing store to the device pixel ratio, draw in CSS px.
  const dpr = window.devicePixelRatio || 1;
  const W = c.clientWidth || c.width, H = c.clientHeight || c.height;
  c.width = W * dpr; c.height = H * dpr;
  ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.scale(dpr, dpr);
  // Theme-aware download/upload colors (read from CSS vars, correct in light mode).
  const cs = getComputedStyle(document.documentElement);
  const rx = cs.getPropertyValue("--rx").trim(), tx = cs.getPropertyValue("--tx").trim();
  ctx.clearRect(0, 0, W, H);
  const ymaxEl = $("#g-ymax");
  if (!gdata.length) { if (ymaxEl) ymaxEl.textContent = "—"; return; }
  let peak = 1;
  for (const s of gdata) peak = Math.max(peak, s.up, s.down);
  peak *= 1.15;
  if (ymaxEl) ymaxEl.textContent = fmtRate(peak);
  const n = gdata.length;
  const X = i => pad + (W - 2 * pad) * (n === 1 ? 1 : i / (n - 1));
  const Y = v => H - pad - (H - 2 * pad) * (v / peak);
  const area = (key, line, fill) => {
    ctx.beginPath(); ctx.moveTo(X(0), H - pad);
    for (let i = 0; i < n; i++) ctx.lineTo(X(i), Y(gdata[i][key]));
    ctx.lineTo(X(n - 1), H - pad); ctx.closePath();
    ctx.fillStyle = fill; ctx.fill();
    ctx.beginPath();
    for (let i = 0; i < n; i++) { const px = X(i), py = Y(gdata[i][key]); i ? ctx.lineTo(px, py) : ctx.moveTo(px, py); }
    ctx.lineWidth = 2.5; ctx.strokeStyle = line; ctx.stroke();
  };
  area("down", rx, rgba(rx, .22));
  area("up", tx, rgba(tx, .22));
  const last = gdata[n - 1];
  const set = (id, v) => { const e = $(id); if (e) e.textContent = v; };
  set("#g-up", fmtRate(last.up)); set("#g-down", fmtRate(last.down));
  set("#g-tstart", fmtTime(gdata[0].t)); set("#g-tend", fmtTime(last.t));
}
// Per-row sparkline: a tiny area graph of one tunnel's recent up/down rate (same
// download-blue / upload-green as the main graph), so "is THIS path moving traffic"
// is answered on its own row (Keenetic-style). Cheap: ≤40 samples, no library.
function drawSpark(c, buf) {
  if (!c) return;
  const ctx = c.getContext("2d"), pad = 2;
  // Hi-DPI: size the backing store to the device pixel ratio, draw in CSS px.
  const dpr = window.devicePixelRatio || 1;
  const W = c.clientWidth || c.width, H = c.clientHeight || c.height;
  c.width = W * dpr; c.height = H * dpr;
  ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.scale(dpr, dpr);
  // Theme-aware download/upload colors.
  const cs = getComputedStyle(document.documentElement);
  const rx = cs.getPropertyValue("--rx").trim(), tx = cs.getPropertyValue("--tx").trim();
  ctx.clearRect(0, 0, W, H);
  if (!buf || !buf.length) return;
  let peak = 1;
  for (const s of buf) peak = Math.max(peak, s.up, s.down);
  const n = buf.length, X = i => pad + (W - 2 * pad) * (n === 1 ? 1 : i / (n - 1)), Y = v => H - pad - (H - 2 * pad) * (v / peak);
  const area = (key, line, fill) => {
    ctx.beginPath(); ctx.moveTo(X(0), H - pad);
    for (let i = 0; i < n; i++) ctx.lineTo(X(i), Y(buf[i][key]));
    ctx.lineTo(X(n - 1), H - pad); ctx.closePath(); ctx.fillStyle = fill; ctx.fill();
    ctx.beginPath();
    for (let i = 0; i < n; i++) { const px = X(i), py = Y(buf[i][key]); i ? ctx.lineTo(px, py) : ctx.moveTo(px, py); }
    ctx.lineWidth = 1.5; ctx.strokeStyle = line; ctx.stroke();
  };
  area("down", rx, rgba(rx, .18));
  area("up", tx, rgba(tx, .18));
}
// (traffic graph is driven by pollTraffic above, scheduled from init)

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
  if (!h) { pill.className = "pill err"; text.textContent = t("OFFLINE"); return; }
  if (h.demo) { pill.className = "pill"; pill.style.color = "var(--accent)"; pill.style.background = "var(--accent-tint)"; text.textContent = t("DEMO MODE"); return; }
  pill.style.color = ""; pill.style.background = "";
  if (h.singbox && h.singbox.running) { pill.className = "pill ok"; text.textContent = t("ONLINE"); }
  else if (isNativeOnly(h)) { pill.className = "pill ok"; text.textContent = t("NATIVE"); }
  else { pill.className = "pill muted"; text.textContent = t("IDLE"); }
  $("#foot").textContent = "wakeroute " + (h.version || "");
}

/* ---------- routing ---------- */
const PAGES = {
  dashboard: { title: "Dashboard", render: renderDashboard },
  server: { title: "Set up Server", render: renderServer },
  connections: { title: "Connections", render: renderConnections },
  failover: { title: "Failover", render: renderFailover },
  routing: { title: "Routing", render: renderRouting },
  updater: { title: "Updater", render: renderUpdater },
  diagnostics: { title: "Diagnostics", render: renderDiagnostics },
  settings: { title: "Settings", render: renderSettings },
};
// isNetworkError distinguishes a daemon-UNREACHABLE failure (fetch rejected — the
// panel can't reach the daemon, e.g. mid-restart/deploy/crash) from an application
// error (a 4xx/5xx that came back WITH a message). The former should auto-recover,
// not show a dead error page.
function isNetworkError(e) {
  return e instanceof TypeError || /failed to fetch|networkerror|load failed|connection refused|fetch/i.test(String(e && e.message));
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
  const ov = el("div", { class: "wr-reconnect" }, el("div", { class: "wr-reconnect-box" },
    el("span", { class: "spin" }),
    el("div", {}, el("div", { style: "font-weight:600" }, t("Reconnecting to WakeRoute…")), sub)));
  document.body.appendChild(ov);
  let tries = 0;
  const iv = setInterval(async () => {
    tries++;
    try {
      const r = await fetch("/api/health", { cache: "no-store" });
      if (r.ok) { clearInterval(iv); setTimeout(() => location.reload(), 400); return; }
    } catch (_) { /* still down */ }
    if (tries > 60) { clearInterval(iv); wrReconnecting = false; sub.textContent = t("Still unreachable — reload the page when the router is back."); }
  }, 1500);
}

// renderError shows a page-render failure: a daemon-down error becomes the
// auto-recovering reconnect banner; any other (application) error stays an inline note.
function renderError(view, e) {
  if (isNetworkError(e)) { showReconnect(); return; }
  view.appendChild(el("div", { class: "empty" }, "Error: " + e.message));
}

async function route() {
  // Close any open modal when navigating: modals are appended to <body>, so
  // clearing #view alone would leave the dialog floating over the new page.
  $$(".modal-backdrop").forEach(m => m.remove());
  const key = (location.hash || "#dashboard").slice(1);
  const page = PAGES[key] || PAGES.dashboard;
  $$(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.page === key));
  $("#pagetitle").textContent = t(page.title);
  graphCanvas = null;
  const view = $("#view");
  view.innerHTML = "";
  pillGen++; // invalidate refreshPills' cached node lists — the page DOM is being rebuilt
  try { await page.render(view); associateLabels(view); } catch (e) { renderError(view, e); }
  i18nApply(view); // localize the freshly-rendered (English) page in place
}
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

/* ---------- pages ---------- */
async function renderDashboard(view) {
  await Promise.all([loadProfile(), loadHealth()]);
  let wd = null; try { wd = await api.get("/api/watchdog"); } catch (_) {}
  const eps = state.profile.endpoints;
  const groups = state.profile.groups;

  // Exit-IP hero: shows the current public exit IP only. (Routing here is selective /
  // split-tunnel — general traffic is direct by design — so no protected/unprotected
  // verdict is shown; it would just be a misleading alarm.) Hidden until the exit IP
  // is known (paintExitIP toggles it) so there's never an empty box.
  view.appendChild(el("div", { class: "hero", id: "hero", style: "display:none" },
    el("div", { class: "hero-text" },
      el("div", { class: "hero-ip", id: "hero-ip" }))));

  // System-health strip (RAM gauge / CPU / uptime) — removes itself when procfs is absent.
  view.appendChild(systemStrip());

  // (The old standalone "Interfaces" card was removed — per-tunnel ↓/↑ throughput is now shown
  // inline on each connection/failover row, and the WAN rate stays in the system strip's "WAN now"
  // tile. See connRow + paintIfaceList.)

  // Graceful degradation: when the proxy core isn't running (and we're not in demo),
  // say so plainly at the top instead of leaving the dashboard silently empty — the
  // live graph + per-tunnel stats only populate once sing-box is up.
  const hh = state.health || {};
  if (!hh.demo && !(hh.singbox && hh.singbox.running)) {
    if (isNativeOnly(hh)) {
      // Native-only mode: sing-box is intentionally absent (the kernel plane carries
      // everything in fast mode). Read it as a positive state, not a "core down" alarm.
      view.appendChild(el("div", { class: "card notice-core notice-core--ok" },
        el("span", { class: "notice-core-ico", style: "color:var(--ok)" }, "✓"),
        el("div", {},
          el("b", {}, t("Native-only mode — sing-box not required")),
          el("div", { class: "hint", style: "margin-top:3px" },
            t("Every endpoint is kernel-native and traffic is routed by the kernel plane in fast mode, so the sing-box core is intentionally not running.")))));
    } else {
      view.appendChild(el("div", { class: "card notice-core" },
        el("span", { class: "notice-core-ico" }, "○"),
        el("div", {},
          el("b", {}, "Proxy core not running"),
          el("div", { class: "hint", style: "margin-top:3px" },
            eps.length
              ? "sing-box isn't started — Apply a config to bring a tunnel up. Live stats appear once it's running."
              : "Add a connection under Connections, then Apply — live stats appear once sing-box is running."))));
    }
  }

  // PBR status row — best-effort; silently absent if server is old or mode != hybrid.
  try {
    const pbrSt = await api.get("/api/pbr/status");
    if (pbrSt && pbrSt.mode === "hybrid") {
      const pbrPill = pbrSt.installed && !pbrSt.stale
        ? el("span", { class: "pill ok pill--dot" }, "active · " + pbrSt.zones + " zones")
        : pbrSt.installed
          ? el("span", { class: "pill warn" }, "stale — Apply to activate")
          : el("span", { class: "pill muted" }, "not applied");
      view.appendChild(el("div", { class: "card" },
        el("div", { class: "row-between", style: "align-items:center;gap:var(--sp-3)" },
          el("span", {}, "Kernel routing"),
          pbrPill)));
    }
  } catch (_) {}

  // INTERNET card: live graph + connection stack (members of first group, else all endpoints).
  const card = el("div", { class: "card" });
  card.appendChild(el("div", { class: "card-head" },
    el("div", { class: "card-title" }, "Internet"),
    el("div", { class: "dots" }, "⠿")));

  const graphWrap = el("div", { class: "graphwrap" },
    el("div", { class: "ymax", id: "g-ymax" }, "—"),
    el("canvas", { class: "graph", id: "g-canvas", width: "1600", height: "400" }));
  card.appendChild(graphWrap);
  card.appendChild(el("div", { class: "legend" },
    el("span", {}, el("span", { class: "dot", style: "background:var(--tx)" }), "Upload: ", el("b", { id: "g-up" }, "0 bit/s")),
    el("span", {}, el("span", { class: "dot", style: "background:var(--rx)" }), "Download: ", el("b", { id: "g-down" }, "0 bit/s"))));
  card.appendChild(el("div", { class: "axis" }, el("span", { id: "g-tstart" }, "—"), el("span", { id: "g-tend" }, "—")));

  const stResult = el("span", { class: "hint", style: "margin-left:12px" });
  pinSpeed(stResult, "__global"); // restore the last throughput result across re-renders
  const stBtn = el("button", { class: "btn btn-sm" }, "Speedtest");
  stBtn.addEventListener("click", () => runSpeedtest(stBtn, stResult));
  card.appendChild(el("div", { class: "row-between", style: "margin-top:10px" },
    el("div", { class: "hint" }, "Throughput (through active proxy)"),
    el("div", { style: "display:flex;align-items:center" }, stResult, stBtn)));

  // Failover stack: one labelled sub-stack per group, then an "Other connections"
  // sub-stack for endpoints in no group — so nothing is hidden. (The old code rendered
  // only groups[0], silently dropping every other group + every ungrouped endpoint,
  // a real data loss on the live multi-zone setup.)
  const inGroup = new Set();
  groups.forEach(g => (g.members || []).forEach(m => inGroup.add(m)));
  const subStacks = [];
  groups.forEach(g => {
    const members = (g.members || []).map(findEndpoint).filter(Boolean);
    if (members.length) subStacks.push({ label: g.name + " · " + g.type, rows: members, spark: true });
  });
  const ungrouped = eps.filter(e => !inGroup.has(e.id));
  if (ungrouped.length) subStacks.push({ label: groups.length ? t("Other connections") : t("All connections"), rows: ungrouped, spark: false });

  if (!subStacks.length) {
    card.appendChild(el("div", { class: "card-title", style: "margin:18px 0 4px" }, "Connections"));
    card.appendChild(emptyState("No connections yet", "Add one under Connections."));
  } else {
    subStacks.forEach(s => {
      card.appendChild(el("div", { class: "card-title", style: "margin:18px 0 4px" }, s.label));
      // Severity-first: broken rows rise to the top (with their cause line), then slow,
      // then unknown, then healthy — so the thing that needs attention is seen first.
      s.rows.slice().sort(bySeverity).forEach(e => card.appendChild(connRow(e, s.spark)));
    });
  }
  view.appendChild(card);

  // Routing-list reachability strip (routing is the device's core job).
  const rstrip = routingStripCard();
  if (rstrip) view.appendChild(rstrip);

  // tiles
  watchdog = wd; // share the freshly-fetched supervisor state with the live repaint path
  const engTile = el("div", { class: "tile", "data-engine": "1" },
    el("div", { class: "k" }, "Engine"), el("div", { class: "v" }));
  paintEngineTile(engTile);
  view.appendChild(el("div", { class: "tiles" },
    tile("Endpoints", String(eps.length), eps.filter(e => e.enabled).length + " enabled"),
    tile("Failover groups", String(groups.length), groups.length ? "configured" : "none"),
    engTile,
    tile("Mode", hh.demo ? "Demo" : (hh.singbox && hh.singbox.running ? "Live" : (isNativeOnly(hh) ? t("Native") : "Idle")), "v" + (hh.version || ""))));

  view.appendChild(talkersCard());
  view.appendChild(connectionsCard());

  graphCanvas = $("#g-canvas");
  drawGraph();
  paintDashRouting(); // fire-and-forget: colour the routing-list strip once per render
  paintSystem();      // fill the system strip (or remove it when procfs is unavailable)
  paintConnections(); // fill the live-connections table (empty state when Clash is down)
  paintExitIP();      // fill the hero's public exit IP (cached through-proxy lookup)
}

function tile(k, v, sub) {
  return el("div", { class: "tile" },
    el("div", { class: "k" }, k),
    el("div", { class: "v" }, v, sub ? el("small", {}, "  " + sub) : null));
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
  if (!def || !def.outbound || def.outbound === "direct") return { level: "unprotected", ico: "✕", word: "UNPROTECTED", verdict: t("Traffic goes direct (no tunnel)"), sub: def ? "" : t("No default route set") };
  if (def.outbound === "block") return { level: "degraded", ico: "⚠", word: "BLOCKED", verdict: t("Default route blocks all traffic"), sub: "" };
  const g = findGroup(def.outbound), ep = findEndpoint(def.outbound);
  if (g) {
    const members = (g.members || []).map(findEndpoint).filter(Boolean);
    const best = bestAliveMember(members);
    if (best) { const hb = healthMap[best.ep.id] || {}; return { level: "protected", ico: "✓", word: "PROTECTED", verdict: t("via ") + g.name, sub: g.type + " · " + (best.ep.name || best.ep.id) + (hb.latency_ms ? " · " + hb.latency_ms + " ms" : "") }; }
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
  const cls = { protected: "ok", degraded: "warn", unprotected: "err", checking: "muted", offline: "muted" }[v.level] || "muted";
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
function paintExitIP() {
  const e = document.getElementById("hero-ip");
  if (!e) return;
  const hero = document.getElementById("hero");
  const show = vis => { if (hero) hero.style.display = vis ? "" : "none"; };
  api.get("/api/exit-ip").then(d => {
    if (d && d.available && d.ip) { e.innerHTML = ""; e.append(t("Exit IP") + " ", el("b", {}, d.ip)); show(true); }
    else { e.textContent = ""; show(false); }
  }).catch(() => { e.textContent = ""; show(false); });
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
function paintSystem() {
  const strip = document.getElementById("sys-strip");
  if (!strip) return;
  api.get("/api/system").then(si => {
    if (!si || !si.available) { strip.remove(); return; } // no procfs (non-Linux) → drop the strip
    const tot = si.mem_total_kb / 1024, used = (si.mem_total_kb - si.mem_avail_kb) / 1024, pct = Math.round(si.mem_used_pct);
    const ram = strip.querySelector('[data-sys="ram"]');
    if (ram) {
      const rv = ram.querySelector(".sys-v");
      if (rv) { rv.innerHTML = ""; rv.append(pct + "%", el("small", {}, "  " + Math.round(used) + " / " + Math.round(tot) + " MB")); }
      const fill = ram.querySelector(".sys-bar-fill");
      if (fill) { fill.style.width = Math.min(100, pct) + "%"; fill.style.background = pct >= 88 ? "var(--err)" : pct >= 70 ? "var(--warn)" : "var(--ok)"; }
      ram.title = Math.round(tot - used) + " MB free of " + Math.round(tot) + " MB";
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
  }).catch(() => strip.remove());
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
    const dt = c.t - p.t; if (dt <= 0) return null;
    return { down: Math.max(0, (c.rx - p.rx) / dt), up: Math.max(0, (c.tx - p.tx) / dt) };
  };
  // WAN iface: prefer one literally named "wan", else the busiest non-bridge/non-tunnel.
  const wan = ifaces.find(f => f.name === "wan") ||
    ifaces.filter(f => !/^(br-|lo$|awg|wg|tun)/.test(f.name)).sort((a, b) => (b.rx_bytes + b.tx_bytes) - (a.rx_bytes + a.tx_bytes))[0];
  const w = wan && rate(wan.name);
  if (!w) { node.textContent = "…"; prevIfaces = cur; return; }
  node.innerHTML = ""; node.append("↓" + fmtBytes(w.down) + "/s ", el("small", {}, "↑" + fmtBytes(w.up) + "/s"));
  const tile = node.closest(".sys-tile");
  if (tile) {
    const lines = ifaces.map(f => { const r = rate(f.name); return r ? f.name + ": ↓" + fmtBytes(r.down) + "/s ↑" + fmtBytes(r.up) + "/s" : null; }).filter(Boolean);
    tile.title = lines.join("\n");
  }
  paintIfaceList(ifaces, rate, wan && wan.name); // visible per-interface DL/UL
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
// (general WAN) stays as-is; an endpoint id resolves to that connection's name.
function exitLabel(tag) {
  if (!tag || tag === "direct") return "direct";
  const e = findEndpoint(tag);
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
  const sub = (exits ? "via " + exits + "  ·  " : "") +
    "↓" + fmtBytes(g.down) + " ↑" + fmtBytes(g.up) + "  ·  " + g.conns + (g.conns > 1 ? " conns" : " conn");
  const chips = [...g.ports.entries()]
    .sort((a, b) => (parseInt(a[0]) || 0) - (parseInt(b[0]) || 0))
    .map(([key, p]) => el("span", {
      class: "conn-port",
      title: key + "  ·  " + p.n + (p.n > 1 ? " conns" : " conn") + "  ·  ↓" + fmtBytes(p.down) + " ↑" + fmtBytes(p.up),
    }, p.n > 1 ? key + " ×" + p.n : key));
  return el("div", { class: "conn-group" },
    el("div", { class: "conn-item" },
      el("div", { class: "conn-main" },
        el("div", { class: "conn-host", title: g.ip }, g.ip),
        el("div", { class: "conn-sub" }, sub)),
      el("div", { class: "conn-age" }, g.ports.size + (g.ports.size === 1 ? " port" : " ports"))),
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
    if (data.max && data.total != null) s += "  ·  " + Math.round((data.total / data.max) * 100) + "% of " + data.max;
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
  const top = clients.slice(0, 8);
  const max = ((top[0].up_bytes || 0) + (top[0].down_bytes || 0)) || 1;
  top.forEach(c => {
    const total = (c.up_bytes || 0) + (c.down_bytes || 0);
    list.appendChild(el("div", { class: "talker" },
      el("div", { class: "talker-row" },
        el("span", { class: "talker-host", title: c.ip + "  ·  " + (c.conns || 0) + " conns" }, c.name || c.ip),
        el("span", { class: "talker-bytes" }, fmtBytes(total))),
      el("div", { class: "talker-bar" }, el("span", { class: "talker-bar-fill", style: "width:" + Math.max(2, Math.round(total / max * 100)) + "%" }))));
  });
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
  const talkers = Object.values(byHost).sort((a, b) => b.total - a.total).slice(0, 8);
  const max = talkers[0].total || 1;
  talkers.forEach(t => list.appendChild(el("div", { class: "talker" },
    el("div", { class: "talker-row" },
      el("span", { class: "talker-host", title: t.host + (t.chain ? "  ⇢ " + t.chain : "") }, t.host),
      el("span", { class: "talker-bytes" }, fmtBytes(t.total))),
    el("div", { class: "talker-bar" }, el("span", { class: "talker-bar-fill", style: "width:" + Math.max(2, Math.round(t.total / max * 100)) + "%" })))));
}
function paintConnections() {
  const list = document.getElementById("conns-list"), tlist = document.getElementById("talkers-list");
  if (!list && !tlist) return;
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
  });
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
  card.appendChild(strip);
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
    if (s.ok) { ok++; ico.textContent = "✓"; ico.style.color = "var(--ok)"; d.title = s.status ? "reachable (HTTP " + s.status + ")" : "OK"; note.textContent = ""; }
    else { down++; ico.textContent = "✕"; ico.style.color = "var(--err)"; d.title = s.error || "error"; note.textContent = s.status ? "HTTP " + s.status : t("unreachable"); }
  });
  const sum = document.getElementById("dashrl-sum");
  if (sum) {
    const parts = [];
    if (ok) parts.push(ok + " OK");
    if (down) parts.push(down + " " + t("down"));
    if (off) parts.push(off + " " + t("off"));
    sum.textContent = parts.join(" · ") || "—";
    sum.style.color = down ? "var(--err)" : "";
  }
}

function connRow(e, showSpark) {
  const tog = el("div", { class: "toggle" + (e.enabled ? " on" : ""), onclick: () => toggleEndpoint(e) });
  // Per-row sparkline only on failover-group members (the paths that carry/back up
  // traffic) — not every ungrouped endpoint — to keep the stack focused + compact.
  let spark = null;
  if (showSpark && e.enabled) {
    spark = el("canvas", { class: "spark", "data-spark": e.id, width: "300", height: "40" });
    drawSpark(spark, sparkBuf[e.id]);
  }
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
      spark,
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

async function toggleEndpoint(e) {
  try { await api.post("/api/endpoints", { ...e, enabled: !e.enabled }); await loadProfile(); route(); }
  catch (err) { toast(err.message, "err"); }
}

async function renderConnections(view) {
  await loadProfile();
  const head = el("div", { class: "block-head" },
    el("div", {},
      el("div", { class: "ttl" }, "Connections"),
      el("div", { class: "desc" }, "VPN and proxy tunnels. Paste a vless:// / hysteria2:// link or import a WireGuard config to add one.")),
    el("div", { class: "side" },
      el("button", { class: "btn", title: "Import many connections at once from a subscription URL or pasted list", onclick: openSubscription }, "⛓ Subscription"),
      el("button", { class: "btn btn-primary", title: "Add one connection — paste a vless://, hysteria2://… link, fill a form, or import a config", onclick: openAddConnection }, "+ Add connection")));
  view.appendChild(head);

  const card = el("div", { class: "card" });
  if (!state.profile.endpoints.length) {
    card.appendChild(emptyState("No connections yet", "Paste a vless:// / hysteria2:// link or a WireGuard config to add one."));
  } else {
    state.profile.endpoints.forEach(e => {
      const tog = el("div", { class: "toggle" + (e.enabled ? " on" : ""), onclick: () => toggleEndpoint(e) });
      const isExternal = e.engine === "external";
      card.appendChild(el("div", { class: "conn" }, tog,
        el("div", { class: "body" },
          el("div", { class: "name" }, e.name || e.id, pillFor(e)),
          subMeta(e),
          isExternal
            ? el("div", { class: "hint", style: "margin-top:3px" }, "OS-managed tunnel — enable to use for routing")
            : statsLine(e),
          isExternal ? null : causeLine(e)),
        el("div", { class: "acts" },
          el("button", { class: "btn btn-sm", onclick: () => shareEndpoint(e) }, "Share"),
          el("button", { class: "btn btn-sm", onclick: () => testEndpoint(e) }, "Test"),
          el("button", { class: "btn btn-sm", onclick: () => openEditEndpoint(e) }, "Edit"),
          el("button", { class: "btn btn-danger btn-sm", onclick: () => delEndpoint(e) }, "Delete"))));
    });
  }
  view.appendChild(card);

  // Native VPN adoption — tunnels already managed by the OS (AmneziaWG / WireGuard).
  // Best-effort: absent CLI tools → empty list → show nothing.
  try {
    const dv = await api.get("/api/vpn/discover");
    const tunnels = (dv && dv.vpns) || [];
    if (tunnels.length) {
      const nativeHead = el("div", { class: "block-head" },
        el("div", {},
          el("div", { class: "ttl" }, "Native VPNs on this router"),
          el("div", { class: "desc" }, "Tunnels already managed by the OS — add them as routing exits without re-entering credentials.")));
      view.appendChild(nativeHead);
      const nativeCard = el("div", { class: "card" });
      tunnels.forEach(tunnel => {
        const alreadyAdded = state.profile.endpoints.some(
          e => e.engine === "external" && e.params && e.params.interface === tunnel.iface);
        const typeBadge = el("span", { class: "badge" }, tunnel.type);
        const activeDot = tunnel.active
          ? el("span", { class: "pill ok", title: "Active — recent handshake" }, el("span", { class: "dot" }), "active")
          : el("span", { class: "pill muted", title: "No recent handshake" }, "idle");
        const fullTunnelPill = tunnel.full_tunnel
          ? el("span", { class: "pill", title: "Routes all traffic (0.0.0.0/0)" }, "full tunnel")
          : null;
        const addBtn = alreadyAdded
          ? el("button", { class: "btn btn-sm", disabled: "true" }, "Already added")
          : el("button", { class: "btn btn-sm btn-primary", onclick: async () => {
              try {
                await api.post("/api/vpn/adopt", { iface: tunnel.iface });
                await loadProfile();
                route();
                toast("Added! Enable it in Connections, then add routing lists.", "ok");
              } catch (err) { toast(err.message, "err"); }
            } }, "Add as exit");
        nativeCard.appendChild(el("div", { class: "conn" },
          el("div", { class: "body" },
            el("div", { class: "name" }, tunnel.iface, typeBadge, activeDot, fullTunnelPill),
            tunnel.name ? el("div", { class: "hint" }, tunnel.name) : null),
          el("div", { class: "acts" }, addBtn)));
      });
      view.appendChild(nativeCard);
    }
  } catch (_) { /* CLI tools absent or endpoint unreachable — show nothing */ }
}

async function delEndpoint(e) {
  if (!confirm("Delete connection " + (e.name || e.id) + "?")) return;
  try { await api.del("/api/endpoints/" + encodeURIComponent(e.id)); await loadProfile(); route(); toast("Deleted", "ok"); }
  catch (err) { toast(err.message, "err"); }
}

// failoverMembers renders a group's members in the order urltest would prefer them:
// alive first (lowest measured latency first), then unknown/not-yet-probed, then down
// last (dimmed). The single member urltest would actually pick — alive + lowest latency —
// gets a "BEST" pill so the user sees which exit currently carries traffic. Read-only:
// it reuses the live per-endpoint healthMap the dashboard already polls (no extra fetch);
// when health is absent it falls back to the configured member order.
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
    chip.appendChild(el("span", { class: "pill " + dotCls, title: alive ? "alive" : down ? "down" : "not yet checked" },
      el("span", { class: "dot" }),
      nameOf(id),
      alive && h.latency_ms ? el("small", { style: "margin-left:6px;color:inherit;opacity:.75" }, h.latency_ms + " ms") : null));
    if (id === bestId) chip.appendChild(el("span", { class: "pill ok", title: "urltest would route through this member (alive, lowest latency)", style: "font-weight:600" }, "✓ BEST"));
    wrap.appendChild(chip);
  });
  return wrap;
}

async function renderFailover(view) {
  await loadProfile();
  const head = el("div", { class: "block-head" },
    el("div", {},
      el("div", { class: "ttl" }, "Failover"),
      el("div", { class: "desc" }, "Group your connections so traffic automatically switches to a healthy one when the active tunnel goes down.")),
    el("div", { class: "side" },
      el("button", { class: "btn btn-primary", title: "Create a failover group — pick members and traffic auto-switches to a healthy one", onclick: openNewGroup }, "+ New group")));
  view.appendChild(head);

  if (!state.profile.groups.length) {
    view.appendChild(el("div", { class: "card" }, emptyState("No failover groups",
      "Create one to auto-select the fastest working connection (urltest), like a router's backup-WAN stack.")));
    return;
  }
  const defRule = state.profile.rules.find(r => r.default);
  state.profile.groups.forEach(g => {
    const isDefault = defRule && defRule.outbound === g.id;
    const card = el("div", { class: "card" });
    card.appendChild(el("div", { class: "card-head" },
      el("div", { style: "min-width:0" }, el("div", { class: "name", style: "font-size:16px;min-width:0;word-break:break-word" }, g.name,
        el("span", { class: "badge" }, g.type),
        isDefault ? el("span", { class: "pill ok", style: "margin-left:6px" }, el("span", { class: "dot" }), "Default route") : null),
        failoverMembers(g)),
      el("div", { class: "acts" },
        el("button", { class: "btn btn-sm", title: t("Actively re-test every member's latency, then sort best-first"), onclick: e => testFailoverGroup(g, e.currentTarget) }, t("Test all")),
        !isDefault ? el("button", { class: "btn btn-sm", onclick: () => setDefault(g) }, "Set as default route") : null,
        el("button", { class: "btn btn-sm", title: t("Edit group settings"), onclick: () => openEditGroup(g) }, t("Edit")),
        el("button", { class: "btn btn-danger btn-sm", onclick: () => delGroup(g) }, "Delete"))));
    view.appendChild(card);
  });
}

async function setDefault(g) {
  try { await api.post("/api/rules", { id: "default", default: true, outbound: g.id }); await loadProfile(); route(); toast("Default route → " + g.name, "ok"); }
  catch (err) { toast(err.message, "err"); }
}
async function delGroup(g) {
  if (!confirm("Delete group " + g.name + "?")) return;
  try { await api.del("/api/groups/" + encodeURIComponent(g.id)); await loadProfile(); route(); toast("Deleted", "ok"); }
  catch (err) { toast(err.message, "err"); }
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
  try {
    // Probe members concurrently — each reuses the existing per-endpoint delay test.
    await Promise.all(ids.map(async id => {
      try {
        const h = await api.post("/api/health/test/" + encodeURIComponent(id), {});
        if (h && h.id) healthMap[h.id] = h;
      } catch (_) { failed++; }
    }));
    if (failed === ids.length) {
      // Every per-endpoint probe failed (old daemon / endpoint gone) — fall back to a
      // single bulk health read so the re-sort still uses the freshest available data.
      try {
        const r = await api.get("/api/health/endpoints");
        (r || []).forEach(h => { healthMap[h.id] = h; });
      } catch (_) {}
    }
    refreshPills();
    route(); // re-render Failover → failoverMembers() re-sorts by the fresh latency
    const alive = ids.filter(id => (healthMap[id] || {}).state === "alive").length;
    toast(t("Tested {0} members — {1} alive", ids.length, alive), alive ? "ok" : "info");
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
  return sel;
}
function rlFirstTunnel() {
  const e = state.profile.endpoints.find(x => x.enabled);
  if (e) return e.id;
  if (state.profile.groups.length) return state.profile.groups[0].id;
  return "direct";
}
function rlOutboundFor(suggest) { return suggest === "block" ? "block" : suggest === "direct" ? "direct" : rlFirstTunnel(); }
function rlShortURL(u) { return u.replace(/^https?:\/\//, "").replace(/\/releases\/latest\/download\//, "/…/").slice(0, 50); }
function rlSlug(s) {
  // A name in a non-Latin script (Cyrillic, CJK, etc.) strips to an empty body —
  // fall back to "list" so it isn't just "rl-". Uniqueness is then enforced by
  // rlUniqueId so two such lists don't collide to one id.
  const body = (s || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  return "rl-" + (body || "list");
}
// rlUniqueId suffixes base (-2, -3, …) until it is unique across the whole profile,
// so a new list never overwrites an existing endpoint/group/rule/list by id collision.
function rlUniqueId(base) {
  const p = state.profile || {};
  const have = new Set([].concat(
    (p.endpoints || []).map(e => e.id),
    (p.groups || []).map(g => g.id),
    (p.rules || []).map(r => r.id),
    (p.routing_lists || []).map(rl => rl.id)
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
      el("div", { class: "ttl" }, "Routing"),
      el("div", { class: "desc" }, "Route domain/IP lists through any tunnel. Add a ready-made preset or your own list; choose which connection each list uses — and which connection downloads it.")),
    el("div", { class: "side" },
      el("button", { class: "btn", title: "Re-fetch CIDRs for any list with an auto-refresh source, then Apply to activate", onclick: refreshCidrSources }, "↻ Refresh sources"),
      el("button", { class: "btn", title: "Add a ready-made routing list from the catalog", onclick: openRoutingCatalog }, "Preset lists"),
      el("button", { class: "btn btn-primary", title: "Create your own routing list (domains/IPs or a feed)", onclick: () => openRoutingList(null) }, "+ Custom list"))));

  // PBR status badge — best-effort; silently absent if server is old or mode != hybrid.
  try {
    const pbrSt = await api.get("/api/pbr/status");
    if (pbrSt && pbrSt.mode === "hybrid") {
      const active = pbrSt.installed && !pbrSt.stale;
      const pbrPill = active
        ? el("span", { class: "pill ok pill--dot" }, "active · " + pbrSt.zones + " zones")
        : pbrSt.installed
          ? el("span", { class: "pill warn" }, "stale")
          : el("span", { class: "pill muted" }, "not applied");
      const row = el("div", { class: "hint row-between", style: "margin-top:var(--sp-2);align-items:center" },
        el("span", {}, "Kernel routing: ", pbrPill));
      if (!active) {
        const applyBtn = el("button", { class: "btn", style: "font-size:var(--fs-small)" }, "Re-apply kernel routing");
        applyBtn.onclick = async () => {
          applyBtn.disabled = true;
          try {
            await api.post("/api/pbr/apply", {});
            toast("Kernel routing re-applied");
            renderRouting();
          } catch (e) { toast("Re-apply failed: " + e.message, "err"); applyBtn.disabled = false; }
        };
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
      "Adopted native tunnels are disabled by default. Enable them in Connections before adding routing rules.")));
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
    table.appendChild(el("div", { class: "rlhead" },
      el("span", {}, ""),
      el("span", {}, t("List")),
      el("span", {}, t("Route via")),
      el("span", {}, t("Download via")),
      el("span", {}, "")));
    lists.forEach(rl => table.appendChild(routingRow(rl)));
    card.appendChild(table);
  }
  view.appendChild(card);
  if (lists.length) paintRoutingStatus(); // colour each list's download-status dot
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
    d.className = "pill " + (s.ok ? "ok" : "err") + " pill--dot";
    d.title = s.ok ? (s.status ? "source reachable (HTTP " + s.status + ")" : "OK") : (s.error || "error");
  });
  document.querySelectorAll("[data-rlerr]").forEach(e => {
    const s = byId[e.getAttribute("data-rlerr")];
    if (s && !s.ok && s.error) { e.textContent = "⚠ " + s.error; e.style.display = ""; }
    else { e.style.display = "none"; }
  });
}

function routingRow(rl) {
  const tog = el("div", { class: "toggle" + (rl.enabled ? " on" : ""), onclick: () => toggleRoutingList(rl) });
  const mcount = (rl.manual || []).length;
  const src = rl.source
    ? el("span", { class: "addr", title: rl.source }, "⛓ " + rlShortURL(rl.source))
    : el("span", { class: "addr" }, mcount + " manual " + (mcount === 1 ? "entry" : "entries"));
  // Mutate rl in place (it IS the state.profile.routing_lists element) so the two
  // dropdowns compose: without this, the 2nd save spreads the stale closure and
  // reverts the 1st change, because saveRoutingList intentionally doesn't reload.
  const routeSel = routingOutboundSelect(rl.outbound, true);
  routeSel.onchange = () => { rl.outbound = routeSel.value; saveRoutingList(rl, "route → " + (nameOf(routeSel.value) || routeSel.value)); };
  const dlSel = routingOutboundSelect(rl.download_via || "direct", false);
  dlSel.onchange = () => { rl.download_via = dlSel.value === "direct" ? "" : dlSel.value; saveRoutingList(rl, "download via " + (nameOf(dlSel.value) || dlSel.value)); };
  // Per-list download status: a green/red dot next to the name + the error code
  // below. Starts muted ("checking…") and is painted by paintRoutingStatus().
  const dot = el("span", { class: "pill muted pill--dot", "data-rlstatus": rl.id, style: "margin-left:8px", title: "checking…" }, el("span", { class: "dot" }));
  const err = el("div", { class: "hint", "data-rlerr": rl.id, style: "color:var(--err);display:none;margin-top:3px;word-break:break-word" });
  // Cells map 1:1 to the .rlhead columns: [toggle] [list+source] [route via] [download via] [actions].
  return el("div", { class: "rlrow" }, tog,
    el("div", { class: "rl-list" },
      el("div", { class: "name" }, rl.name || rl.id, dot),
      el("div", { class: "sub" }, src),
      err),
    el("div", { class: "rl-cell", "data-col": "route via" }, routeSel),
    el("div", { class: "rl-cell", "data-col": "download via" }, dlSel),
    el("div", { class: "acts" },
      el("button", { class: "btn btn-sm", onclick: () => openRoutingList(rl) }, "Edit"),
      el("button", { class: "btn btn-danger btn-sm", onclick: () => delRoutingList(rl) }, "Delete")));
}

async function toggleRoutingList(rl) {
  try { await api.post("/api/routing", { ...rl, enabled: !rl.enabled }); await loadProfile(); route(); }
  catch (e) { toast(e.message, "err"); }
}
async function saveRoutingList(rl, msg) {
  try { await api.post("/api/routing", rl); toast(msg || "Saved", "ok"); }
  catch (e) { toast(e.message, "err"); }
}
async function delRoutingList(rl) {
  if (!confirm("Delete routing list " + (rl.name || rl.id) + "?")) return;
  try { await api.del("/api/routing/" + encodeURIComponent(rl.id)); await loadProfile(); route(); toast("Deleted", "ok"); }
  catch (e) { toast(e.message, "err"); }
}

function openRoutingList(rl) {
  const editing = !!rl;
  rl = rl || { id: "", name: "", source: "", manual: [], outbound: rlFirstTunnel(), download_via: "", enabled: true };
  const name = el("input", { type: "text", value: rl.name || "", placeholder: "My list" });
  const mode = el("select", {},
    el("option", { value: "url" }, "From URL (sing-box rule-set .srs / .json)"),
    el("option", { value: "manual" }, "Manual domains / IPs"));
  const source = el("input", { type: "text", value: rl.source || "", placeholder: "https://…/list.srs" });
  const manual = el("textarea", { rows: "6", class: "rl-ta", placeholder: "one per line:\nexample.com\nopenai.com\n104.18.0.0/16" }, (rl.manual || []).join("\n"));
  const routeSel = routingOutboundSelect(rl.outbound, true);
  const dlSel = routingOutboundSelect(rl.download_via || "direct", false);
  const srcField = el("div", { class: "field" }, el("label", {}, "Rule-set URL"), source);
  const manField = el("div", { class: "field" }, el("label", {}, "Domains / IP-CIDRs (one per line)"), manual);
  // Optional auto-refresh CIDR feed (kernel modes hybrid/fast) — independent of the
  // url/manual mode above; its result is cached and unioned with any Manual entries.
  const cidrSrc = el("input", { type: "text", value: rl.cidr_source || "", placeholder: "asn:64512,64513  or  https://…/cidrs.txt" });
  const cachedNote = (rl.cidr_cache && rl.cidr_cache.length) ? "  Cached: " + rl.cidr_cache.length + " CIDRs." : "";
  const cidrField = el("div", { class: "field" },
    el("label", {}, "Auto-refresh CIDR source (optional, kernel modes)"),
    cidrSrc,
    el("div", { class: "hint" }, "Keep this list's IP-CIDRs current from a feed: asn:N,N (RIPEstat announced prefixes) or an https text list. Cached + unioned with Manual entries; active in hybrid/fast. After saving, use «↻ Refresh sources», then Apply." + cachedNote));
  function applyMode() {
    srcField.style.display = mode.value === "url" ? "" : "none";
    manField.style.display = mode.value === "manual" ? "" : "none";
  }
  mode.value = rl.source ? "url" : (rl.manual && rl.manual.length ? "manual" : "url");
  mode.onchange = applyMode; applyMode();

  async function save() {
    if (!name.value.trim()) return toast("Name required", "err");
    const body = { id: rl.id || rlUniqueId(rlSlug(name.value)), name: name.value.trim(), outbound: routeSel.value,
      download_via: dlSel.value === "direct" ? "" : dlSel.value, enabled: rl.enabled };
    if (mode.value === "url") { body.source = source.value.trim(); body.manual = []; }
    else { body.manual = manual.value.split("\n").map(s => s.trim()).filter(Boolean); body.source = ""; }
    // Independent kernel-CIDR auto-refresh feed (the store preserves the system cache on a
    // same-source edit and drops it when this changes). Omit cidr_cache — server-managed.
    body.cidr_source = cidrSrc.value.trim();
    // Preserve the explicit rule-set format on edit — the form has no input for it, so
    // dropping it makes a list whose URL extension doesn't reveal the format (a .json
    // source, or a query-string URL) silently re-infer wrong and fail to load. Catalog
    // presets all set format:"binary". (Empty = generator infers from the URL.)
    if (rl.format && body.source) body.format = rl.format;
    try { await api.post("/api/routing", body); back.remove(); await loadProfile(); route(); toast((editing ? "Saved " : "Added ") + body.name, "ok"); }
    catch (e) { toast(e.message, "err"); }
  }
  const body = el("div", {},
    el("div", { class: "field" }, el("label", {}, "Name"), name),
    el("div", { class: "field" }, el("label", {}, "Source"), mode),
    srcField, manField, cidrField,
    el("div", { class: "field" }, el("label", {}, "Route matching traffic via"), routeSel),
    el("div", { class: "field" }, el("label", {}, "Download the list via"), dlSel),
    el("div", { class: "hint" }, "Download-via lets a blocked list source (GitHub) be fetched through a working tunnel."));
  const back = modal({ title: editing ? "Edit routing list" : "New routing list", body,
    footer: [el("button", { class: "btn btn-ghost", onclick: () => back.remove() }, "Cancel"),
    el("button", { class: "btn btn-primary", onclick: save }, editing ? "Save" : "Add")] });
}

// refreshCidrSources re-fetches every routing list that has an auto-refresh CIDR source
// (POST /api/routing/refresh) and reports the result. It updates each list's cached CIDRs
// but does NOT apply — the user clicks Apply to activate (matching the stage-then-Apply
// model). A no-op (friendly toast) when no list has a CIDR source configured.
async function refreshCidrSources() {
  try {
    const r = await api.post("/api/routing/refresh", {});
    await loadProfile(); route();
    const srcN = (r.lists || []).length;
    const errN = (r.errors || []).length;
    if (!srcN) { toast("No auto-refresh CIDR sources — set one on a list first.", "ok"); return; }
    const msg = (r.changed ? "Refreshed" : "No changes") + " · " + srcN + " source" + (srcN === 1 ? "" : "s") +
      (errN ? " · " + errN + " failed" : "") + (r.changed ? " — click Apply to activate." : "");
    toast(msg, errN ? "err" : "ok");
  } catch (e) { toast(e.message, "err"); }
}

async function openRoutingCatalog() {
  let presets;
  try { presets = await api.get("/api/routing/catalog"); }
  catch (e) { return toast(e.message, "err"); }
  const have = new Set((state.profile.routing_lists || []).map(rl => rl.id));
  const groups = {};
  presets.forEach(p => { (groups[p.category] = groups[p.category] || []).push(p); });
  const body = el("div", {});
  Object.keys(groups).forEach(cat => {
    body.appendChild(el("div", { class: "card-title", style: "margin:10px 0 6px" }, cat));
    groups[cat].forEach(p => {
      body.appendChild(el("div", { class: "conn" },
        el("div", { class: "body" },
          el("div", { class: "name" }, p.name, el("span", { class: "badge proto" }, p.kind)),
          el("div", { class: "sub" }, el("span", { class: "addr", title: p.source }, p.description))),
        el("div", { class: "acts" },
          have.has(p.id) ? el("span", { class: "pill ok", style: "margin:0" }, el("span", { class: "dot" }), "Added")
            : el("button", { class: "btn btn-sm btn-primary", onclick: () => addPreset(p, back) }, "+ Add"))));
    });
  });
  const back = modal({ title: "Preset routing lists", body });
}
async function addPreset(p, back) {
  const body = { id: p.id, name: p.name, source: p.source, format: p.format, manual: [],
    outbound: rlOutboundFor(p.suggest), download_via: "", enabled: true };
  try { await api.post("/api/routing", body); if (back) back.remove(); await loadProfile(); route(); toast("Added " + p.name + " → " + (nameOf(body.outbound) || body.outbound), "ok"); }
  catch (e) { toast(e.message, "err"); }
}

/* ---------- modal ---------- */
function modal({ title, body, footer }) {
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
  const onKey = e => { if (e.key === "Escape") { e.preventDefault(); close(); } };
  const back = el("div", { class: "modal-backdrop", onclick: e => { if (e.target === back) close(); } });
  const m = el("div", { class: "modal", tabindex: "-1", role: "dialog", "aria-modal": "true" },
    el("div", { class: "modal-head" }, el("div", { class: "card-title" }, title),
      el("div", { class: "x", onclick: () => close(), "aria-label": t("Close") }, "×")),
    el("div", { class: "modal-body" }, body));
  if (footer) m.appendChild(el("div", { class: "modal-foot" }, footer));
  back.appendChild(m);
  i18nApply(m); // localize the modal's English content (titles, labels, hints, buttons)
  associateLabels(m); // wire form labels to their controls for screen readers
  document.body.appendChild(back);
  document.addEventListener("keydown", onKey);
  // Move focus into the modal: first focusable control, else the dialog container.
  const focusable = m.querySelector(
    'input:not([type=hidden]):not([disabled]), select:not([disabled]), textarea:not([disabled]), button:not([disabled]), [href], [tabindex]:not([tabindex="-1"])');
  (focusable || m).focus();
  // Route every existing back.remove() call site through close() so they also
  // detach the keydown listener and restore focus (close() de-dupes; the native
  // removal happens via domRemove inside close). back.close is an explicit alias.
  back.remove = close;
  back.close = close;
  return back;
}

/* ---------- share / QR / subscription ---------- */
// QR is rendered server-side (no external service — the config never leaves the
// router) and POSTed so secrets never hit a URL. Returns an <img> filled async.
async function qrImg(text, size) {
  size = size || 300;
  const img = el("img", { class: "qr-img", alt: "QR", width: size, height: size });
  try {
    const r = await fetch("/api/qr", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ text, size }) });
    if (!r.ok) throw new Error("qr");
    img.src = URL.createObjectURL(await r.blob());
  } catch (_) { return el("div", { class: "hint" }, "QR unavailable"); }
  return img;
}
async function shareEndpoint(e) {
  let res;
  try { res = await api.get("/api/endpoints/" + encodeURIComponent(e.id) + "/export"); }
  catch (err) { return toast(err.message, "err"); }
  const qrWrap = el("div", { class: "qr-wrap" }, el("div", { class: "hint" }, "rendering…"));
  modal({
    title: "Share " + (e.name || e.id),
    body: el("div", {}, qrWrap,
      el("div", { class: "hint", style: "margin:12px 0 4px" }, res.kind === "conf" ? "Scan in the AmneziaVPN / WireGuard app, or download the .conf" : "Scan in your VPN client, or copy the link"),
      el("pre", { class: "wr-console", style: "max-height:130px" }, res.text),
      el("div", { style: "display:flex;gap:10px;margin-top:10px" },
        el("button", { class: "btn btn-sm", onclick: () => copyText(res.text) }, "Copy"),
        res.kind === "conf" ? el("button", { class: "btn btn-sm", onclick: () => downloadText(res.filename || "client.conf", res.text) }, "⤓ Download .conf") : null)),
  });
  try {
    const img = await qrImg(res.text, 280);
    qrWrap.innerHTML = ""; qrWrap.appendChild(img);
  } catch (_) { qrWrap.innerHTML = ""; qrWrap.appendChild(el("div", { class: "hint", style: "color:var(--err)" }, "QR rendering failed")); }
}
async function openSubscription() {
  let info;
  try { info = await api.get("/api/subscription/info"); }
  catch (e) { return toast(e.message, "err"); }
  let url = window.location.origin + info.path;
  const qrWrap = el("div", { class: "qr-wrap" }, el("div", { class: "hint" }, "rendering…"));
  const urlBox = el("pre", { class: "wr-console", style: "max-height:80px;margin-top:10px" }, url);
  async function renderQR() {
    qrWrap.innerHTML = ""; qrWrap.appendChild(el("div", { class: "hint" }, "rendering…"));
    try {
      const img = await qrImg(url, 280);
      qrWrap.innerHTML = ""; qrWrap.appendChild(img);
    } catch (_) { qrWrap.innerHTML = ""; qrWrap.appendChild(el("div", { class: "hint", style: "color:var(--err)" }, "QR rendering failed")); }
  }
  // Rotate: issues a fresh token and invalidates the current URL — for when the URL leaked
  // (it grants access to every connection's secrets). Re-renders the URL + QR in place.
  const rotateBtn = el("button", { class: "btn btn-sm", title: "Issue a new URL and invalidate the current one" }, "Rotate token");
  rotateBtn.addEventListener("click", async () => {
    if (!confirm("Rotate the subscription token? The current URL stops working immediately — you'll need to re-share the new one with every device.")) return;
    const prev = rotateBtn.textContent;
    rotateBtn.disabled = true; rotateBtn.textContent = "Rotating…";
    try {
      const r = await api.post("/api/subscription/rotate", {});
      url = window.location.origin + r.path;
      urlBox.textContent = url;
      await renderQR();
      toast("Subscription token rotated — re-share the new URL", "ok");
    } catch (e) { toast(e.message, "err"); }
    finally { rotateBtn.disabled = false; rotateBtn.textContent = prev; }
  });
  modal({
    title: "Subscription",
    body: el("div", {},
      el("div", { class: "hint", style: "margin-bottom:12px" }, "Add this URL as a subscription in v2rayN/NG, Nekobox, Hiddify or Shadowrocket. Apps auto-update when your connections change — e.g. after a failover or re-provision — with no re-import. Covers link-based protocols (VLESS/Hysteria2/Trojan/…); WireGuard/AmneziaWG use per-connection Share."),
      qrWrap,
      urlBox,
      el("div", { style: "display:flex;gap:10px;margin-top:10px" },
        el("button", { class: "btn btn-sm", onclick: () => copyText(url) }, "Copy URL"),
        rotateBtn)),
  });
  renderQR();
}

const PROTOCOLS = ["vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic", "wireguard", "amneziawg", "olcrtc", "socks", "http"];
const SS_METHODS = ["aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"];

function fInput(id, label, value, opts) {
  opts = opts || {};
  return el("div", { class: "field" }, el("label", {}, label),
    el("input", { type: opts.type || "text", id, value: value != null ? String(value) : "", placeholder: opts.ph || "" }));
}
function fSelect(id, label, options, value) {
  const sel = el("select", { id }, ...options.map(o => el("option", { value: o }, o)));
  if (value != null) sel.value = value;
  return el("div", { class: "field" }, el("label", {}, label), sel);
}
function fCheck(id, label, checked) {
  const c = el("input", { type: "checkbox", id });
  if (checked) c.setAttribute("checked", "true");
  return el("label", { class: "check" }, c, el("span", {}, label));
}

// REALITY_FRONTS — known-good, globally-reachable TLS-1.3 sites that make sensible Reality
// camouflage destinations. Offered as SNI suggestions ONLY when security=reality (a plain-TLS
// SNI must be the server's own domain). Starting points — the Check button verifies each is
// reachable + TLS 1.3 from the router's vantage before saving.
const REALITY_FRONTS = ["www.microsoft.com", "www.cloudflare.com", "www.apple.com", "dl.google.com", "www.amazon.com", "aws.amazon.com", "www.bing.com"];

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
function realityPubkeyError(v) { return b64Bytes(v) === 32 ? "" : t("not a valid x25519 key (base64 of 32 bytes)"); }
function shortIdError(v) { return (/^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0 && v.length <= 16) ? "" : t("must be hex, even length, ≤16 chars"); }

// fInputValidated — an input with an inline format indicator. validate(trimmedValue) returns ""
// (ok) or a short error; an EMPTY field never errors (the Reality fields are unused for plain
// TLS). Keeps the input id so collect()'s g(id) is unchanged.
function fInputValidated(id, label, value, ph, validate) {
  const input = el("input", { type: "text", id, value: value != null ? String(value) : "", placeholder: ph || "" });
  const result = el("span", { class: "hint", style: "margin-left:8px" });
  const run = () => {
    const v = (input.value || "").trim();
    const err = v ? validate(v) : "";
    result.textContent = err ? "✗ " + err : "";
    result.style.color = err ? "var(--err)" : "";
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
    if (!host) { toast(t("Enter an SNI to check"), "warn"); return; }
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
    else if (proto === "shadowsocks") add(fSelect("f-method", "Method", SS_METHODS, P.method || SS_METHODS[0]), fInput("f-password", "Password", P.password));
    else if (proto === "hysteria2") add(fInput("f-password", "Password", P.password), fSniCheck("f-sni", "SNI", T.sni), fInput("f-obfs", "Obfs (salamander, optional)", P.obfs), fInput("f-obfspw", "Obfs password", P.obfs_password), fCheck("f-insecure", "Allow insecure TLS", T.insecure));
    else if (proto === "tuic") add(fInput("f-uuid", "UUID", P.uuid), fInput("f-password", "Password", P.password), fSniCheck("f-sni", "SNI", T.sni), fInput("f-cc", "Congestion control (bbr/cubic)", P.congestion_control), fCheck("f-insecure", "Allow insecure TLS", T.insecure));
    else if (proto === "wireguard" || proto === "amneziawg") {
      add(fInput("f-pk", "Private key", P.private_key), fInput("f-ppk", "Peer public key", P.peer_public_key), fInput("f-psk", "Pre-shared key (optional)", P.pre_shared_key), fInput("f-addr", "Local address(es), comma-separated", (P.local_address || []).join(",")));
      // Per-tunnel link tuning (optional; blank = unset = current behavior). Read the
      // top-level Endpoint fields first, falling back to the legacy params.{mtu,
      // persistent_keepalive} so configs imported before these were promoted still show.
      const mtu0 = ep.mtu != null && ep.mtu !== 0 ? ep.mtu : (P.mtu != null ? P.mtu : "");
      const pka0 = ep.persistent_keepalive != null && ep.persistent_keepalive !== 0 ? ep.persistent_keepalive
        : (P.persistent_keepalive != null ? P.persistent_keepalive : "");
      add(el("div", { style: "display:flex;gap:12px" },
        el("div", { style: "flex:1;min-width:0" }, fInput("f-mtu", t("MTU"), mtu0, { type: "number", ph: t("e.g. 1420 — blank = auto") })),
        el("div", { style: "flex:1;min-width:0" }, fInput("f-keepalive", t("Persistent keepalive (s)"), pka0, { type: "number", ph: t("e.g. 25 — blank = off") }))));
      if (proto === "amneziawg") add(el("div", { class: "hint" }, "AmneziaWG junk params (Jc/Jmin/…) are best captured by pasting a full .conf in the Paste tab."));
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
      dyn.appendChild(el("datalist", { id: "f-sni-fronts" }, ...REALITY_FRONTS.map(d => el("option", { value: d }))));
      const secSel = dyn.querySelector("#f-sec"), sniInp = dyn.querySelector("#f-sni");
      const syncFronts = () => {
        const on = secSel && secSel.value === "reality";
        if (sniInp) { if (on) sniInp.setAttribute("list", "f-sni-fronts"); else sniInp.removeAttribute("list"); }
        frontHint.style.display = on ? "" : "none";
      };
      if (secSel) secSel.addEventListener("change", syncFronts);
      syncFronts();
    }
  }
  renderDyn(proto0);

  const protoSel = el("select", { id: "f-proto", onchange: e => renderDyn(e.target.value) }, ...PROTOCOLS.map(p => el("option", { value: p }, p)));
  protoSel.value = proto0;
  const wrap = el("div", {},
    el("div", { class: "field" }, el("label", {}, "Name"), el("input", { type: "text", id: "f-name", value: ep.name || "" })),
    el("div", { style: "display:flex;gap:12px" },
      el("div", { class: "field", style: "flex:2;min-width:0" }, el("label", {}, "Server"), el("input", { type: "text", id: "f-server", value: ep.server || "" })),
      el("div", { class: "field", style: "flex:1;min-width:0" }, el("label", {}, "Port"), el("input", { type: "number", id: "f-port", value: ep.port || "" }))),
    el("div", { class: "field" }, el("label", {}, "Protocol"), protoSel),
    dyn,
    el("div", { class: "field", style: "margin-top:12px" },
      el("label", {}, "Health-check target (optional — what this tunnel pings to prove it's alive)"),
      el("input", { type: "text", id: "f-health", value: (ep.health && ep.health.url) || "", placeholder: "http://cp.cloudflare.com/generate_204  ·  or 1.1.1.1 / gateway IP" })));

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
    if (["trojan", "hysteria2", "tuic", "shadowsocks", "socks", "http"].includes(proto) && g("f-password")) p.password = g("f-password");
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
    if (["socks", "http"].includes(proto) && g("f-user")) p.username = g("f-user");
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
    const hv = g("f-health");
    if (hv) out.health = { url: hv, interval: (ep.health && ep.health.interval) || 60, tolerance: (ep.health && ep.health.tolerance) || 50 };
    else if (ep.health) out.health = ep.health;
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
      amneziawg: ["jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5", "reserved"],
    };
    (keep[proto] || []).forEach(k => { if (P[k] !== undefined && p[k] === undefined) p[k] = P[k]; });
    return out;
  }
  return { el: wrap, collect };
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
  const wrap = el("div", {},
    el("div", { class: "hint", style: "margin-bottom:12px" },
      t("Routes through an existing kernel interface (an AmneziaWG / WireGuard tunnel configured outside WakeRoute). It has no protocol of its own.")),
    el("div", { class: "field" }, el("label", {}, t("Name")), name),
    el("div", { class: "field" }, el("label", {}, t("Bound interface")), iface),
    el("div", { class: "field" }, el("label", {}, t("Endpoint IP (anti-recursion bypass, optional)")), epip));
  function collect() {
    const g = id => { const e = document.getElementById(id); return e ? e.value.trim() : ""; };
    const out = { ...ep, name: g("f-name"), engine: "external", protocol: "", server: "", port: 0,
      enabled: ep.enabled !== false, params: { ...P } };
    out.params.interface = g("f-iface");
    if (g("f-epip")) out.params.endpoint_ip = g("f-epip"); else delete out.params.endpoint_ip;
    return out;
  }
  return { el: wrap, collect };
}

function openEditEndpoint(ep) {
  const external = ep && ep.engine === "external";
  const form = external ? externalForm(ep) : manualForm(ep);
  async function save() {
    const e = form.collect();
    if (external) { if (!e.params.interface) return toast("Bound interface required", "err"); }
    else if (!e.server || !e.port) return toast("Server and port required", "err");
    try { await api.post("/api/endpoints", e); back.remove(); await loadProfile(); route(); toast("Updated " + (e.name || e.id), "ok"); }
    catch (err) { toast(err.message, "err"); }
  }
  const back = modal({ title: external ? "Edit external connection" : "Edit connection", body: form.el,
    footer: [el("button", { class: "btn btn-ghost", onclick: () => back.remove() }, "Cancel"), el("button", { class: "btn btn-primary", onclick: save }, "Save")] });
}

function openAddConnection() {
  const content = el("div", {});
  const tabEls = {};
  let back;
  const done = msg => { back.remove(); loadProfile().then(route); toast(msg, "ok"); };

  function pasteTab() {
    const ta = el("textarea", { placeholder: "Paste a vless:// / hysteria2:// / tuic:// link — or a [Interface] WireGuard / AmneziaWG config" });
    const confirm = el("div", {});
    async function parse() {
      const link = ta.value.trim();
      if (!link) return;
      confirm.innerHTML = ""; confirm.appendChild(el("div", { class: "hint" }, "parsing…"));
      try {
        const parsed = await api.post("/api/import", { link });
        confirm.innerHTML = "";
        const form = manualForm(parsed); // editable confirmation — protocol dropdown overrides the type
        const saveBtn = el("button", { class: "btn btn-primary", onclick: async () => {
          const e = form.collect(); if (!e.server || !e.port) return toast("Server and port required", "err");
          try { await api.post("/api/endpoints", e); done("Added " + (e.name || e.id)); } catch (err) { toast(err.message, "err"); }
        } }, "Save connection");
        confirm.appendChild(el("div", { class: "toast info", style: "margin:0 0 12px" },
          "Detected " + String(parsed.protocol || "?").toUpperCase() + (parsed.engine && parsed.engine !== "singbox" ? " · " + parsed.engine + " engine" : "") + " — review below and fix the type if it's wrong, then save."));
        confirm.appendChild(form.el);
        confirm.appendChild(el("div", { style: "margin-top:10px" }, saveBtn));
      } catch (e) { confirm.innerHTML = ""; confirm.appendChild(el("div", { class: "hint", style: "color:var(--err)" }, e.message)); }
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
    const addBtn = el("button", { class: "btn btn-primary", onclick: async () => {
      const e = form.collect(); if (!e.server || !e.port) return toast("Server and port required", "err");
      try { await api.post("/api/endpoints", e); done("Added " + (e.name || e.id)); } catch (err) { toast(err.message, "err"); }
    } }, "Add");
    return el("div", {}, form.el, el("div", { style: "margin-top:8px" }, addBtn));
  }
  function subTab() {
    let found = [];
    const url = el("input", { type: "text", placeholder: "https://provider/subscription  (optional)" });
    const ta = el("textarea", { placeholder: "…or paste the subscription text / base64 blob here" });
    const list = el("div", { class: "checks", style: "margin-top:14px" });
    const importBtn = el("button", { class: "btn btn-primary", disabled: "true", onclick: async () => {
      const chosen = $$("input[type=checkbox]:checked", list).map(c => found[+c.value]);
      if (!chosen.length) return toast("Nothing selected", "err");
      try { const r = await api.post("/api/endpoints/bulk", { endpoints: chosen }); done("Imported " + r.saved + " connection(s)" + (r.duplicates ? ", " + r.duplicates + " duplicate(s) skipped" : "") + (r.errors && r.errors.length ? ", " + r.errors.length + " failed" : "")); } catch (e) { toast(e.message, "err"); }
    } }, "Import selected");
    const fetchBtn = el("button", { class: "btn", onclick: async () => {
      list.innerHTML = ""; importBtn.setAttribute("disabled", "true");
      try {
        const r = await api.post("/api/subscription", { url: url.value.trim(), text: ta.value });
        found = r.endpoints || [];
        if (!found.length) { list.appendChild(el("div", { class: "hint" }, "No connections found" + (r.errors && r.errors.length ? " (" + r.errors.length + " line errors)" : "") + ".")); return; }
        if (r.name) list.appendChild(el("div", { class: "hint", style: "color:var(--ink-2);margin-bottom:8px" }, "From: " + r.name));
        found.forEach((e, i) => list.appendChild(el("label", { class: "check" }, el("input", { type: "checkbox", value: String(i), checked: "true" }), el("span", {}, (e.name || e.id) + "  "), el("span", { class: "badge" }, e.protocol))));
        if (r.errors && r.errors.length) list.appendChild(el("div", { class: "hint" }, r.errors.length + " line(s) skipped"));
        importBtn.removeAttribute("disabled");
      } catch (e) { list.appendChild(el("div", { class: "hint", style: "color:var(--err)" }, e.message)); }
    } }, "Fetch / Parse");
    return el("div", {}, el("div", { class: "field" }, el("label", {}, "Subscription URL"), url),
      el("div", { class: "field" }, el("label", {}, "or paste text / base64"), ta),
      el("div", { style: "display:flex;gap:10px" }, fetchBtn, importBtn), list);
  }

  function show(key) {
    Object.entries(tabEls).forEach(([k, t]) => t.classList.toggle("active", k === key));
    content.innerHTML = "";
    content.appendChild(key === "paste" ? pasteTab() : key === "manual" ? manualTab() : subTab());
  }
  const tabBar = el("div", { class: "tabs" }, ...[["paste", "Paste link"], ["manual", "Manual"], ["sub", "Subscription"]].map(([k, label]) => {
    const t = el("div", { class: "tab", onclick: () => show(k) }, label); tabEls[k] = t; return t;
  }));
  back = modal({ title: "Add connection", body: el("div", {}, tabBar, content) });
  show("paste");
}

function parsedView(e) {
  const wrap = el("div", {});
  if (e.engine && e.engine !== "singbox")
    wrap.appendChild(el("div", { class: "toast info", style: "margin:0 0 12px" }, "Uses the " + e.engine + " engine (chained into sing-box)."));
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

function openNewGroup() {
  if (!state.profile.endpoints.length) { toast("Add some connections first", "err"); return; }
  const name = el("input", { type: "text", placeholder: "Main failover" });
  const type = el("select", {}, el("option", { value: "urltest" }, "urltest — auto, fastest working"),
    el("option", { value: "fallback" }, "fallback — strict order"),
    el("option", { value: "selector" }, "selector — manual"));
  const checks = el("div", { class: "checks" });
  state.profile.endpoints.forEach(e => {
    checks.appendChild(el("label", { class: "check" },
      el("input", { type: "checkbox", value: e.id }),
      el("span", {}, (e.name || e.id) + "  "), el("span", { class: "badge" }, e.protocol)));
  });
  const asDefault = el("input", { type: "checkbox" });
  const killSwitch = el("input", { type: "checkbox" });

  async function create() {
    const members = $$("input[type=checkbox]:checked", checks).map(c => c.value);
    if (!name.value.trim()) return toast("Name required", "err");
    if (!members.length) return toast("Pick at least one member", "err");
    const id = "grp-" + name.value.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    try {
      // kill_switch is omitted from the payload when unchecked (omitempty / false =
      // current behavior: WAN fallback when all members are down).
      const g = { id, name: name.value.trim(), type: type.value, members,
        test: { url: "http://cp.cloudflare.com/generate_204", interval: 60, tolerance: 50 } };
      if (killSwitch.checked) g.kill_switch = true;
      await api.post("/api/groups", g);
      if (asDefault.checked) await api.post("/api/rules", { id: "default", default: true, outbound: id });
      back.remove(); await loadProfile(); route(); toast("Created " + name.value.trim(), "ok");
    } catch (e) { toast(e.message, "err"); }
  }

  const body = el("div", {},
    el("div", { class: "field" }, el("label", {}, "Group name"), name),
    el("div", { class: "field" }, el("label", {}, "Type"), type),
    el("div", { class: "field" }, el("label", {}, "Members (preference order)"), checks),
    el("label", { class: "check" }, asDefault, el("span", {}, "Set as default route (all traffic)")),
    el("label", { class: "check" }, killSwitch, el("span", {}, t("Kill switch (drop when all members down)"))),
    el("div", { class: "hint" }, t("When on, traffic is dropped instead of falling back to the open WAN if every member is down — no leak to the unprotected internet.")));
  const back = modal({ title: "New failover group", body,
    footer: [el("button", { class: "btn btn-ghost", onclick: () => back.remove() }, "Cancel"),
    el("button", { class: "btn btn-primary", onclick: create }, "Create")] });
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
  const checks = el("div", { class: "checks" });
  // List current members first (in saved preference order), then the remaining endpoints.
  const ordered = (g.members || []).map(findEndpoint).filter(Boolean)
    .concat(state.profile.endpoints.filter(e => !have.has(e.id)));
  ordered.forEach(e => {
    const cb = el("input", { type: "checkbox", value: e.id });
    if (have.has(e.id)) cb.setAttribute("checked", "true");
    checks.appendChild(el("label", { class: "check" }, cb,
      el("span", {}, (e.name || e.id) + "  "), el("span", { class: "badge" }, e.protocol)));
  });
  const killSwitch = el("input", { type: "checkbox" });
  if (g.kill_switch) killSwitch.setAttribute("checked", "true");

  async function save() {
    const members = $$("input[type=checkbox]:checked", checks).map(c => c.value);
    if (!name.value.trim()) return toast("Name required", "err");
    if (!members.length) return toast("Pick at least one member", "err");
    try {
      // Spread g first so unedited fields (test config, etc.) round-trip unchanged.
      const out = { ...g, name: name.value.trim(), type: type.value, members, kill_switch: killSwitch.checked };
      await api.post("/api/groups", out);
      back.remove(); await loadProfile(); route(); toast(t("Saved {0}", name.value.trim()), "ok");
    } catch (e) { toast(e.message, "err"); }
  }

  const body = el("div", {},
    el("div", { class: "field" }, el("label", {}, "Group name"), name),
    el("div", { class: "field" }, el("label", {}, "Type"), type),
    el("div", { class: "field" }, el("label", {}, "Members (preference order)"), checks),
    el("label", { class: "check" }, killSwitch, el("span", {}, t("Kill switch (drop when all members down)"))),
    el("div", { class: "hint" }, t("When on, traffic is dropped instead of falling back to the open WAN if every member is down — no leak to the unprotected internet.")));
  const back = modal({ title: t("Edit failover group"), body,
    footer: [el("button", { class: "btn btn-ghost", onclick: () => back.remove() }, "Cancel"),
    el("button", { class: "btn btn-primary", onclick: save }, "Save")] });
}

/* ---------- apply ---------- */
async function applyConfig(save) {
  const btn = save ? $("#applysavebtn") : $("#applybtn");
  if (!btn) return;
  const label = btn.textContent;
  btn.setAttribute("disabled", "true"); btn.textContent = "Applying…";
  try {
    const r = await api.post("/api/apply", { save: !!save });
    let msg = save ? "Applied & saved" : "Applied (live, not saved)";
    if (r.checked) msg += " · check OK";
    if (r.reloaded) msg += " · reloaded";
    toast(msg, "ok");
    if (!save && r.failsafe && r.failsafe.pending) startFailsafeBanner();
    else hideFailsafeBanner();
  } catch (e) { toast("Apply failed: " + e.message, "err"); }
  finally { btn.removeAttribute("disabled"); btn.textContent = label; }
}

/* ---------- fail-safe countdown banner (R1) ---------- */
let failsafeTimer = null;
function startFailsafeBanner() {
  if (failsafeTimer) clearInterval(failsafeTimer);
  const poll = async () => {
    let st;
    try { st = await api.get("/api/apply/status"); } catch (_) { return; }
    if (!st.pending) {
      hideFailsafeBanner();
      if (st.phase === "rolled_back") toast("Connectivity lost — config rolled back", "err");
      else if (st.phase === "rollback_failed") toast("Connectivity lost AND the rollback failed — " + (st.last_error || "restore the config manually"), "err");
      else if (st.phase === "reboot") toast("Fail-safe couldn't restore connectivity (escalated to reboot)", "err");
      else if (st.phase === "live_unsaved") toast("Config is live (not saved). Use Apply & Save to keep it.", "info");
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
function renderFailsafeBanner(st) {
  const b = $("#failsafe-banner");
  if (!b) return;
  b.style.display = "block"; b.innerHTML = "";
  const degraded = st.phase === "degraded";
  b.appendChild(el("div", { class: "card", style: "margin:0;border-left:3px solid " + (degraded ? "var(--err)" : "var(--warn)") },
    el("div", { class: "row-between" },
      el("div", {},
        el("b", {}, degraded ? "⚠ Connectivity problem — config will roll back" : "Config applied live (not saved)"),
        el("span", { class: "hint", style: "margin-left:10px" },
          degraded ? "phase: " + st.phase : "watching connectivity " + st.seconds_left + "s · auto-rollback if internet drops")),
      el("div", { class: "acts" },
        el("button", { class: "btn btn-primary btn-sm", onclick: failsafeKeep }, "Keep & Save"),
        el("button", { class: "btn btn-danger btn-sm", onclick: failsafeRollback }, "Roll back")))));
  i18nApply(b); // localize the fail-safe banner
}
async function failsafeKeep() {
  try { await api.post("/api/apply/confirm", {}); toast("Kept & committed", "ok"); hideFailsafeBanner(); }
  catch (e) { toast(e.message, "err"); }
}
async function failsafeRollback() {
  try { await api.post("/api/apply/rollback", {}); toast("Rolled back to previous config", "info"); hideFailsafeBanner(); }
  catch (e) { toast(e.message, "err"); }
}
// Re-surface the fail-safe countdown if an Apply window is still armed — otherwise a
// page reload (or opening the panel from another device) mid-window hides the live
// rollback controls (Keep & Save / Roll back) until it silently auto-reverts. No-op
// once the banner is already shown (it self-polls), so this is cheap to call often.
async function checkFailsafe() {
  if (failsafeTimer) return;
  try { const as = await api.get("/api/apply/status"); if (as && as.pending) startFailsafeBanner(); } catch (_) {}
}

/* ---------- per-endpoint health (live latency from the Clash API) ---------- */
let healthMap = {};
let pluginMap = {};
let watchdog = null; // last /api/watchdog snapshot, shared with the dashboard Engine tile
let speedResults = {}; // last speed-test per key (endpoint id, or "__global"); session-only
let sparkBuf = {}; // per-endpoint rolling rate samples for the row sparklines
const SPARK_MAX = 40; // ~40 samples × 5 s health poll ≈ a 3-minute trend window (Keenetic-style)
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
  if (st.running) { span.textContent = "running ✓"; span.style.color = "var(--ok)"; span.style.background = "var(--ok-tint)"; }
  else if (st.needs_binary) { span.textContent = "needs binary"; span.style.color = "var(--warn)"; span.style.background = "var(--warn-tint)"; }
  else { span.textContent = e.engine; span.style.color = "var(--ink-2)"; span.style.background = "var(--card-2)"; }
}
// Dashboard "Engine" tile: surface the sing-box supervisor's HEALTH, not just a restart
// count — a crash-loop (backoff window active) or a down-but-supervised core now reads
// loud (color + icon shape + word, WCAG 1.4.1) instead of looking healthy.
function shortErr(s) { s = String(s || ""); return s.length > 42 ? s.slice(0, 41) + "…" : s; }
function paintEngineTile(node) {
  const v = node.querySelector(".v"); if (!v) return;
  const h = state.health || {}, wd = watchdog || {};
  let word, ico, color, sub;
  if (h.demo) { word = "Demo"; ico = "●"; color = "var(--accent)"; sub = "v" + (h.version || ""); }
  else if (wd.supervised && !wd.alive) { word = "Down"; ico = "⚠"; color = "var(--err)"; sub = t("auto-restarting") + (wd.backoff_ms ? " · backoff " + Math.round(wd.backoff_ms / 1000) + "s" : ""); }
  else if (wd.backoff_ms) { word = "Crash-loop"; ico = "↻"; color = "var(--warn)"; sub = (wd.restarts || 0) + " restarts · backoff " + Math.round(wd.backoff_ms / 1000) + "s"; }
  else if (wd.supervised && wd.alive) { word = "Running"; ico = "✓"; color = "var(--ok)"; sub = wd.restarts ? "↻ " + wd.restarts + " restart" + (wd.restarts > 1 ? "s" : "") + (wd.last_error ? " · last: " + shortErr(wd.last_error) : "") : t("supervised"); }
  else if (h.singbox && h.singbox.running) { word = "Running"; ico = "✓"; color = "var(--ok)"; sub = "v" + (h.version || ""); }
  else { word = "Idle"; ico = "○"; color = "var(--ink-2)"; sub = (h.singbox && h.singbox.available) ? t("sing-box available") : t("sing-box absent"); }
  v.innerHTML = "";
  v.appendChild(el("span", { style: "color:" + color }, ico + " " + t(word)));
  if (sub) v.appendChild(el("small", {}, "  " + sub));
  node.title = wd.last_error ? "Last error: " + wd.last_error : "";
}
// Sub-line under a connection name: protocol type chip + plugin run-state + address.
function subMeta(e) {
  const sub = el("div", { class: "sub" });
  // External endpoints bind an existing kernel interface (e.g. an AmneziaWG/WireGuard
  // tunnel set up outside WakeRoute) — they have no protocol/server of their own, so
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
  if (!e.enabled) { span.className = "pill muted pill--dot"; span.title = "Disabled"; span.append(el("span", { class: "dot" })); return; }
  const h = healthMap[e.id];
  // Healthy/idle states show only a status light; the latency value lives in the
  // stats line under the name. "Down" keeps its loud label (pairs with the cause line).
  if (h && h.state === "down") {
    span.className = "pill err";
    span.append(el("span", { class: "dot" }), "Down");
    return;
  }
  let cls = "muted";
  if (h && h.state === "alive") { cls = h.latency_ms >= 600 ? "warn" : "ok"; span.title = h.latency_ms + " ms"; }
  span.className = "pill " + cls + " pill--dot";
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
  if (h.bytes_down || h.bytes_up) parts.push(part("", fmtBytes((h.bytes_down || 0) + (h.bytes_up || 0)) + " transferred"));
  if (h.reconnects) parts.push(part("", h.reconnects + " restart" + (h.reconnects > 1 ? "s" : "")));
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
let pillCacheGen = -1;
let pillCache = null;
function pillNodes() {
  if (pillCacheGen !== pillGen || !pillCache) {
    pillCache = {
      health: document.querySelectorAll("[data-health]"),
      stats: document.querySelectorAll("[data-stats]"),
      cause: document.querySelectorAll("[data-cause]"),
      plugin: document.querySelectorAll("[data-plugin]"),
      engine: document.querySelectorAll("[data-engine]"),
      spark: document.querySelectorAll("[data-spark]"),
    };
    pillCacheGen = pillGen;
  }
  return pillCache;
}
function refreshPills() {
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
  c.spark.forEach(cv => drawSpark(cv, sparkBuf[cv.getAttribute("data-spark")]));
  paintHero();
  paintConnections(); // live-refresh the connections table (no-op off the dashboard)
  paintSystem();      // live-refresh RAM/temp + compute real interface throughput rates
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
async function runEndpointSpeedtest(e, btn, out) {
  const label = btn.textContent;
  btn.setAttribute("disabled", "true"); btn.textContent = "…";
  if (out) { out.textContent = "testing…"; out.style.color = "var(--ink-2)"; }
  try {
    const r = await api.post("/api/speedtest", { id: e.id, bytes: 10000000 });
    const txt = "↓ " + r.down_mbps + (r.up_mbps ? "  ↑ " + r.up_mbps : "") + " Mbps" + (r.pinned ? "" : " (active route)");
    speedResults[e.id] = { text: txt, ts: Date.now(), ok: true };
    if (out) { out.textContent = txt; out.style.color = "var(--ok)"; } else toast((e.name || e.id) + ": " + txt, "ok");
  } catch (err) { speedResults[e.id] = { text: "failed", ts: Date.now(), ok: false }; if (out) { out.textContent = "failed"; out.style.color = "var(--err)"; } toast("Speedtest: " + err.message, "err"); }
  finally { btn.removeAttribute("disabled"); btn.textContent = label; }
}
async function pollHealth() {
  if (healthInFlight) return;
  healthInFlight = true;
  try {
    const r = await api.get("/api/health/endpoints"); healthMap = {};
    (r || []).forEach(h => {
      healthMap[h.id] = h;
      const b = sparkBuf[h.id] || (sparkBuf[h.id] = []);
      b.push({ up: h.rate_up_bps || 0, down: h.rate_down_bps || 0 });
      if (b.length > SPARK_MAX) b.shift();
    });
    try { const pl = await api.get("/api/plugins"); pluginMap = {}; (pl || []).forEach(p => pluginMap[p.id] = p); } catch (_) {}
    try { watchdog = await api.get("/api/watchdog"); } catch (_) {}
    refreshPills();
  } catch (e) {
    // The dashboard polls every 5s. If the daemon went down while the user is just
    // SITTING on the dashboard (not navigating, so route()'s catch never fires), the
    // stats would silently freeze — surface the same auto-reconnect banner instead.
    if (isNetworkError(e)) showReconnect();
  } finally { healthInFlight = false; }
}
async function testEndpoint(e) {
  try {
    const h = await api.post("/api/health/test/" + encodeURIComponent(e.id), {});
    if (h && h.id) { healthMap[h.id] = h; refreshPills(); toast((e.name || e.id) + ": " + (h.state === "alive" ? h.latency_ms + " ms" : h.state), h.state === "alive" ? "ok" : h.state === "down" ? "err" : "info"); }
  } catch (err) { toast(err.message, "err"); }
}
async function runSpeedtest(btn, out) {
  const label = btn.textContent;
  btn.setAttribute("disabled", "true"); btn.textContent = "Testing…";
  if (out) { out.textContent = "running…"; out.style.color = "var(--ink-2)"; }
  try {
    const r = await api.post("/api/speedtest", { bytes: 10000000 });
    const txt = "↓ " + r.down_mbps + " Mbps" + (r.up_mbps ? "   ↑ " + r.up_mbps + " Mbps" : "") + "   ·   " + (r.latency_ms ?? "?") + " ms (" + (r.via ?? "?") + ")";
    speedResults["__global"] = { text: txt, ts: Date.now(), ok: true };
    if (out) { out.textContent = txt; out.style.color = "var(--ok)"; }
  } catch (e) { speedResults["__global"] = { text: "failed: " + e.message, ts: Date.now(), ok: false }; if (out) { out.textContent = "failed: " + e.message; out.style.color = "var(--err)"; } toast("Speedtest: " + e.message, "err"); }
  finally { btn.removeAttribute("disabled"); btn.textContent = label; }
}

/* ---------- Updater (engine version manager) ---------- */
async function renderUpdater(view) {
  view.appendChild(el("div", { class: "block-head" },
    el("div", {},
      el("div", { class: "ttl" }, "Updater"),
      el("div", { class: "desc" }, "Keep WakeRoute and its proxy engines up to date."))));
  view.appendChild(selfUpdateCard()); // WakeRoute self-update — at the top (fills async, non-blocking)
  const loadingEngines = el("div", { class: "hint", style: "margin:18px 0" }, "checking engine versions…");
  view.appendChild(loadingEngines);
  let data;
  try { data = await api.get("/api/updater/engines"); }
  catch (e) { loadingEngines.remove(); renderError(view, e); return; }
  loadingEngines.remove();
  const mirrorCount = (data.mirrors || []).filter(Boolean).length;
  view.appendChild(el("div", { class: "row-between", style: "margin:18px 0 16px" },
    el("div", { class: "card-title" }, "Engine versions"),
    el("div", { class: "hint" }, "router arch: " + (data.arch || "?") + " · " + (mirrorCount ? mirrorCount + " mirror(s)" : "direct"))));
  // Foreground the engines the router actually runs (core + plugins); tuck the
  // catalog-only standalone cores (sing-box covers their protocols natively) into a
  // collapsed "Advanced" group. Falls back to a flat list if the backend predates roles.
  const engines = data.engines || [];
  const router = engines.filter(e => e.role && e.role !== "standalone");
  const advanced = engines.filter(e => !e.role || e.role === "standalone");
  (router.length ? router : engines).forEach(e => view.appendChild(engineCard(e)));
  if (router.length && advanced.length) {
    const det = el("details", { style: "margin-top:6px" });
    det.appendChild(el("summary", { class: "hint", style: "cursor:pointer;font-weight:600;padding:8px 0" },
      "Advanced — " + advanced.length + " engine" + (advanced.length > 1 ? "s" : "") + " not used on this router"));
    det.appendChild(el("div", { class: "hint", style: "margin:2px 0 12px;max-width:60ch" },
      "sing-box handles these protocols natively, so the router never runs these binaries. Install one only if you run the standalone core yourself."));
    advanced.forEach(e => det.appendChild(engineCard(e)));
    view.appendChild(det);
  }
}
const ENGINE_ROLE_HINT = { "core": "core", "kernel-plugin": "kernel plugin", "socks-plugin": "SOCKS plugin", "standalone": "standalone core" };

// WakeRoute self-update card: current version, available release, "Update now",
// and an auto-update toggle. Backed by /api/updater/self*. Returns synchronously with a
// placeholder and fills in async so the slow GitHub check never blocks the page render.
function selfUpdateCard() {
  const card = el("div", { class: "card" });
  card.appendChild(el("div", { class: "card-title", style: "margin-bottom:10px" }, "WakeRoute"));
  const body = el("div", {}, el("div", { class: "hint" }, t("checking for updates…")));
  card.appendChild(body);
  (async () => {
  try {
    const s = await api.get("/api/updater/self");
    body.innerHTML = "";
    const avail = !!s.update_available;
    const badge = avail
      ? el("span", { class: "badge badge-ok", style: "margin-left:8px" }, "update → " + (s.latest || "?"))
      : el("span", { class: "pill muted", style: "margin-left:8px" }, el("span", { class: "dot" }), s.error ? "check failed" : "up to date");
    body.appendChild(el("div", { class: "row-between" },
      el("div", {},
        el("div", { class: "name", style: "font-size:16px" }, "v" + (s.current || "?"), badge),
        el("div", { class: "sub", style: "margin-top:3px" }, s.repo + (s.error ? " · " + s.error : (s.latest ? " · latest " + s.latest : "")))),
      el("div", { class: "acts" },
        avail ? el("button", { class: "btn btn-primary btn-sm", onclick: ev => selfUpdate(ev.target) }, "Update now") : null)));
    const tog = el("div", { class: "toggle" + (s.auto_update ? " on" : ""), onclick: () => selfAutoToggle(tog) });
    body.appendChild(el("div", { class: "row-between", style: "margin-top:14px" },
      el("div", { class: "hint", style: "max-width:70%" }, "Auto-update: install new WakeRoute releases automatically (daily check) and restart"),
      tog));
  } catch (e) {
    body.innerHTML = "";
    body.appendChild(el("div", { class: "hint", style: "color:var(--err)" }, e.message));
  }
  })();
  return card;
}

async function selfUpdate(btn) {
  if (!confirm("Download the latest WakeRoute release, replace the running binary, and restart the service? The panel will briefly drop, then return.")) return;
  btn.setAttribute("disabled", "true"); btn.textContent = "Updating…";
  try {
    const r = await api.post("/api/updater/self/install", {});
    toast("WakeRoute → " + r.installed + (r.restarting ? " · restarting…" : (r.note ? " · " + r.note : "")), "ok");
  } catch (e) { toast("Update failed: " + e.message, "err"); btn.removeAttribute("disabled"); btn.textContent = "Update now"; }
}

async function selfAutoToggle(tog) {
  const on = !tog.classList.contains("on");
  try { await api.put("/api/updater/self/auto", { enabled: on }); tog.classList.toggle("on", on); toast("Auto-update " + (on ? "enabled" : "disabled"), "ok"); }
  catch (e) { toast(e.message, "err"); }
}

function engineCard(e) {
  const card = el("div", { class: "card" });
  const inst = e.installed || {};
  card.appendChild(el("div", { class: "row-between" },
    el("div", {},
      el("div", { class: "name", style: "font-size:16px" }, e.name,
        inst.present
          ? el("span", { class: "badge", style: "margin-left:8px" }, inst.version || "installed")
          : el("span", { class: "pill muted", style: "margin-left:8px" }, el("span", { class: "dot" }), "not installed")),
      el("div", { class: "sub", style: "margin-top:3px" }, e.repo + (e.role ? " · runs as " + (ENGINE_ROLE_HINT[e.role] || e.role) : ""))),
    el("div", { class: "acts" }, el("button", { class: "btn btn-sm", onclick: () => loadVersions(e, card) }, "Check updates"))));
  const box = el("div", { class: "vbox", style: "margin-top:12px" });
  if (e.source_only) box.appendChild(el("div", { class: "hint" }, e.note || "No prebuilt releases."));
  card.appendChild(box);
  return card;
}

async function loadVersions(e, card) {
  const box = card.querySelector(".vbox");
  if (!box) return;
  box.innerHTML = ""; box.appendChild(el("div", { class: "hint" }, "checking releases…"));
  try {
    const v = await api.get("/api/updater/" + encodeURIComponent(e.id) + "/versions");
    box.innerHTML = "";
    if (v.source_only) {
      if (v.versions && v.versions.length) {
        const sel = el("select", {}, ...v.versions.map(t => el("option", { value: t }, t + (t === v.latest ? "  (latest)" : ""))));
        box.appendChild(el("div", { style: "max-width:280px" }, sel));
      }
      box.appendChild(el("div", { class: "hint", style: "margin-top:8px" }, "installed: " + (v.installed || "none") + (v.latest ? " · latest: " + v.latest : "")));
      box.appendChild(el("div", { class: "hint", style: "margin-top:6px" }, v.note || "Build from source on the device."));
      return;
    }
    const sel = el("select", {}, ...(v.versions || []).map(t => el("option", { value: t }, t + (t === v.latest ? "  (latest)" : ""))));
    const btn = el("button", { class: "btn btn-primary btn-sm", onclick: () => installVersion(e, sel.value, btn) }, "Install selected");
    box.appendChild(el("div", { style: "display:flex;gap:10px;align-items:center" }, sel, btn));
    box.appendChild(el("div", { class: "hint", style: "margin-top:6px" }, "installed: " + (v.installed || "none") + " · latest: " + (v.latest || "?")));
  } catch (err) { box.innerHTML = ""; box.appendChild(el("div", { class: "hint", style: "color:var(--err)" }, err.message)); }
}

async function installVersion(e, version, btn) {
  if (!version) return;
  if (!confirm("Download and install " + e.name + " " + version + " for this router?")) return;
  btn.setAttribute("disabled", "true"); btn.textContent = "Installing…";
  try {
    const r = await api.post("/api/updater/" + encodeURIComponent(e.id) + "/install", { version });
    toast(e.name + " → " + r.installed + (r.reloaded ? " (reloaded)" : ""), "ok");
    route();
  } catch (err) { toast("Install failed: " + err.message, "err"); btn.removeAttribute("disabled"); btn.textContent = "Install selected"; }
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
const HC_LABEL = {
  core: "VPN core running", internet: "Internet works", tunnels: "VPN tunnels healthy",
  censored: "Blocked sites reachable", exit: "Exit IP", endpoint_reach: "VPN servers reachable",
  time: "Router clock is correct", ipv6: "No IPv6 leak", dns: "DNS is private",
  offload: "Flow offload", pbr_kernel: "Kernel routing (PBR)", system: "Router resources", log: "No engine errors",
};
const HC_DEEP = { connections: ["#connections", "Open Connections"], routing: ["#routing", "Open Routing"] };
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
    el("div", { class: "card-title", style: "margin-bottom:var(--sp-2)" }, "Native support"),
    el("div", { class: "hint" }, "Loading…")));
  loadNativeCaps(); // fire-and-forget; paints into #natcap-body when it settles
  return card;
}

async function loadNativeCaps() {
  const body = () => document.getElementById("natcap-body");
  let d;
  try { d = await api.get("/api/native/capabilities"); }
  catch (e) {
    const b = body(); if (!b) return;
    b.innerHTML = "";
    b.appendChild(el("div", { class: "card-title", style: "margin-bottom:var(--sp-2)" }, "Native support"));
    b.appendChild(el("div", { class: "hint", style: "color:var(--ink-2)" }, t("Unavailable") + " — " + e.message));
    return;
  }
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
    b.appendChild(rows);
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
      // OpenWrt (and default): a copyable opkg command. `opkg update` first so a fresh feed
      // index is present (kmods especially need a matching, current index).
      const cmd = "opkg update && opkg install " + pkg;
      const code = el("code", { class: "mono", style: "font-family:ui-monospace,Menlo,Consolas,monospace;font-size:var(--fs-small);background:var(--card-2);border-radius:5px;padding:2px 6px;word-break:break-all" }, cmd);
      const copy = el("button", { class: "btn btn-sm", title: t("Copy command"), onclick: () => copyText(cmd) }, t("Copy"));
      sec.appendChild(el("div", { style: "display:flex;flex-direction:column;gap:4px;margin-bottom:var(--sp-2)" },
        el("div", { class: "hint" }, proto + " — " + t("not built in")),
        el("div", { style: "display:flex;gap:var(--sp-2);align-items:center;flex-wrap:wrap" }, code, copy)));
    });
    b.appendChild(sec);
  }

  // Detected native tunnels — what /api/vpn/discover already found on the router
  // (iface · type · name). Each row gets an "Adopt as exit" button that POSTs to
  // /api/vpn/adopt: the OS keeps owning the tunnel; WakeRoute only adds a DISABLED
  // external endpoint that ROUTES THROUGH it. Best-effort: a 404 / empty list shows
  // nothing extra, mirroring loadNativeCaps' own graceful try/catch.
  try {
    const dv = await api.get("/api/vpn/discover");
    const vpns = (dv && dv.vpns) || [];
    if (vpns.length) {
      // Tunnels already represented by an external endpoint shouldn't offer Adopt
      // again — mirror the matcher the Connections page uses (engine external +
      // params.interface). state.profile is loaded on the Diagnostics route.
      const adopted = iface => ((state.profile && state.profile.endpoints) || []).some(
        e => e.engine === "external" && e.params && e.params.interface === iface);
      const sec = el("div", { style: "margin-top:var(--sp-3);border-top:1px solid var(--divider);padding-top:var(--sp-3)" },
        el("div", { class: "hint", style: "font-weight:600;margin-bottom:var(--sp-2)" }, t("Detected native tunnels")),
        // One-time explainer: adopting is non-destructive and never auto-enables.
        el("div", { class: "hint", style: "color:var(--ink-2);margin-bottom:var(--sp-2);line-height:1.5" },
          t("WakeRoute will ROUTE THROUGH the tunnel but does not manage it (the OS owns it). It is added disabled — enable it in Connections to start routing.")));
      vpns.forEach(v => {
        const parts = [v.iface, v.type, v.public_key].filter(Boolean);
        const statusPill = v.active
          ? el("span", { class: "pill ok", title: t("Tunnel has a recent handshake") }, el("span", { class: "dot" }), t("active"))
          : el("span", { class: "pill muted", title: t("Configured but no recent handshake") }, t("idle"));
        // Adopt button: disabled-looking "Adopted" once an external endpoint exists
        // for this iface; otherwise a btn-sm that adopts + refreshes the card.
        const adoptBtn = adopted(v.iface)
          ? el("button", { class: "btn btn-sm", disabled: "true", title: t("Already added as a routing exit") }, t("Adopted"))
          : el("button", { class: "btn btn-sm", title: t("Add this OS-owned tunnel as a routing exit (added disabled — WakeRoute will not manage it)"),
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
        sec.appendChild(el("div", { class: "row-between", style: "gap:var(--sp-3);align-items:center;margin-bottom:var(--sp-2)" },
          el("span", { class: "mono", style: "font-family:ui-monospace,Menlo,Consolas,monospace;font-size:var(--fs-small);word-break:break-all" }, parts.join(" · ")),
          el("span", { style: "display:inline-flex;gap:var(--sp-2);align-items:center;flex-shrink:0" }, statusPill, adoptBtn)));
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
  const safe = (id, fn) => async () => { try { set(id, await fn()); } catch (e) { set(id, { status: "warn", summary: "check failed", detail: e.message }); } };
  const tasks = Object.keys(CHECKS).map(id => safe(id, CHECKS[id]));
  tasks.push(async () => { // backend-only probes folded in: clock skew + IPv6 leak + DoH
    try { const d = await api.get("/api/healthcheck"); (d.checks || []).forEach(c => set(c.id, { status: c.status, summary: c.summary, detail: c.detail, fix: c.fix })); }
    catch (e) { HC_BACKEND.forEach(id => set(id, { status: "warn", summary: "unavailable", detail: e.message })); }
  });
  await runPool(tasks, 3);
  if (mine()) { state.hbat.running = false; paintBattery(); }
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
    if (CHECKS[id]) { settle(await CHECKS[id]()); }
    else { const d = await api.get("/api/healthcheck"); const c = (d.checks || []).find(x => x.id === id); settle(c ? { status: c.status, summary: c.summary, detail: c.detail, fix: c.fix } : { status: "warn", summary: "unavailable" }); }
  } catch (e) { settle({ status: "warn", summary: "check failed", detail: e.message }); }
}

// runPool runs thunks with bounded concurrency so the router CPU isn't hammered.
async function runPool(thunks, n) {
  const q = thunks.slice();
  await Promise.all(Array.from({ length: Math.min(n, q.length) }, async () => { while (q.length) await q.shift()(); }));
}

function paintBattery() {
  const card = document.getElementById("hbat");
  if (!card || !state.hbat) return;
  const h = state.hbat, res = h.results;
  const done = HC_ORDER.map(id => res[id]).filter(Boolean);
  const worst = done.reduce((a, r) => r.status === "fail" ? "fail" : (r.status === "warn" && a !== "fail") ? "warn" : a, "pass");
  const vb = document.getElementById("hbat-verdict");
  if (vb) {
    vb.innerHTML = "";
    if (h.running) vb.appendChild(el("div", { class: "hero-pill hero-warn" }, el("span", { class: "spin" }), t("Checking…")));
    else if (done.length) {
      const fails = done.filter(r => r.status === "fail").length, warns = done.filter(r => r.status === "warn").length;
      const cls = worst === "fail" ? "hero-err" : worst === "warn" ? "hero-warn" : "hero-ok";
      const txt = worst === "fail" ? t("Something is broken") + (fails > 1 ? " (" + fails + ")" : "")
        : worst === "warn" ? warns + " " + (warns > 1 ? t("things to look at") : t("thing to look at"))
          : t("Everything's working");
      vb.appendChild(el("div", { class: "hero-pill " + cls }, txt));
      vb.appendChild(el("div", { class: "hint", style: "margin-top:8px" }, t("Checked") + " " + timeAgo(h.ranAt)));
    }
  }
  const cb = document.getElementById("hbat-copy"); if (cb) cb.disabled = h.running || !done.length;
  const rb = document.getElementById("hbat-run"); if (rb) rb.disabled = h.running;
  const wrap = document.getElementById("hbat-rows");
  if (wrap) {
    wrap.innerHTML = "";
    h.open = h.open || {};
    HC_ORDER.forEach(id => wrap.appendChild(healthRowEl(id, res[id], h.running, (h.busy || {})[id], h.open)));
  }
}

function healthRowEl(id, r, running, busy, open) {
  const chipCls = busy || (!r && running) ? "muted" : !r ? "muted" : r.status === "pass" ? "ok" : r.status === "warn" ? "warn" : "err";
  const chipInner = busy || (!r && running) ? el("span", { class: "spin" }) : !r ? el("span", { class: "dot", style: "opacity:.3" }) : el("span", { class: "dot" });
  const chip = el("span", { class: "pill " + chipCls }, chipInner);
  const res = el("span", { class: "res" }, busy ? t("checking…") : !r && running ? t("checking…") : !r ? "—" : (r.summary || ""));
  // per-row re-check: re-run just this check after a fix, without the whole battery
  const recheck = el("button", { class: "btn-icon", title: t("Re-check"), onclick: (e) => { e.stopPropagation(); recheckOne(id); } }, "↻");
  recheck.disabled = !!(running || busy);
  const head = el("div", { class: "health-row" }, chip, el("span", { class: "lbl" }, t(HC_LABEL[id] || id)), res, recheck);
  const expandable = r && !busy && (r.status !== "pass" || r.detail || r.kb || r.fix);
  if (!expandable) return head;
  const isOpen = open && id in open ? open[id] : r.status === "fail";
  const chev = el("span", { class: "hint", style: "margin:0 2px" }, isOpen ? "▴" : "▾");
  head.insertBefore(chev, recheck);
  head.style.cursor = "pointer";
  const body = el("div", { class: "health-body", style: "padding:4px 0 10px 30px;display:" + (isOpen ? "" : "none") });
  if (r.fix) body.appendChild(el("div", { style: "background:var(--card-2);border-radius:8px;padding:10px 12px;line-height:1.55;white-space:pre-wrap" }, el("b", {}, t("Fix") + ": "), r.fix));
  if (r.deep && HC_DEEP[r.deep]) body.appendChild(el("button", { class: "btn btn-sm", style: "margin-top:8px", onclick: () => { location.hash = HC_DEEP[r.deep][0]; } }, HC_DEEP[r.deep][1]));
  if (r.kb) r.kb.forEach(e => body.appendChild(kbCard(e)));
  if (r.detail) body.appendChild(el("details", { style: "margin-top:8px" }, el("summary", { class: "hint", style: "cursor:pointer" }, t("Show details")), mono(r.detail)));
  body.appendChild(el("button", { class: "btn btn-sm", style: "margin-top:8px", onclick: () => copyText("[" + r.status.toUpperCase() + "] " + t(HC_LABEL[id] || id) + " — " + (r.summary || "") + (r.detail ? "\n" + r.detail : "")) }, t("Copy")));
  if (open) open[id] = isOpen;
  head.onclick = () => { const showing = body.style.display !== "none"; body.style.display = showing ? "none" : ""; chev.textContent = showing ? "▾" : "▴"; if (open) open[id] = !showing; };
  return el("div", {}, head, body);
}

async function chkCore() {
  const w = await api.get("/api/watchdog");
  const d = "restarts " + (w.restarts || 0) + (w.last_restart ? " · last " + new Date(w.last_restart).toLocaleString("en-GB") : "") + (w.last_error ? "\nlast error: " + w.last_error : "");
  if (w.supervised && w.alive) return { status: w.restarts ? "warn" : "pass", summary: w.restarts ? "running (crashed " + w.restarts + "× since boot)" : "sing-box running", detail: d, fix: w.restarts ? "The core has crash-restarted — check Log analysis below for the cause." : "" };
  if (!w.supervised) return { status: "warn", summary: "not started (WAN-only)", detail: d };
  return { status: "fail", summary: "down — auto-restarting", detail: d, fix: "The VPN core stopped and is restarting itself. If it keeps crashing, check Log analysis below for the error." };
}
async function chkInternet() {
  const r = await api.post("/api/netdiag/all", { target: "cloudflare.com" });
  const rows = r.results || [], wan = rows.find(x => x.egress === "direct"), tun = rows.filter(x => x.egress !== "direct");
  const up = tun.filter(x => x.reachable).length;
  const d = rows.map(x => (x.reachable ? "✓ " : "✗ ") + (x.name || x.egress) + (x.reachable ? " · " + x.latency_ms + " ms" : " · " + (x.err || "unreachable"))).join("\n");
  if (!wan) return { status: "warn", summary: "couldn't test (core not running?)", detail: d };
  if (!wan.reachable) return { status: "fail", summary: "no internet on the router", detail: d, fix: "The router itself can't reach the internet. Check the cable/modem and your ISP — this isn't a VPN problem." };
  return { status: "pass", summary: "online · WAN " + wan.latency_ms + " ms · " + up + "/" + tun.length + " tunnels reach out", detail: d };
}
async function chkTunnels() {
  const eps = await api.get("/api/health/endpoints");
  const tun = (eps || []).filter(e => e.kind !== "group");
  if (!tun.length) return { status: "warn", summary: "no tunnels configured" };
  const up = tun.filter(e => e.state === "alive"), down = tun.filter(e => e.state === "down");
  const d = tun.map(e => (e.state === "alive" ? "✓ " : e.state === "down" ? "✗ " : "… ") + (e.name || e.id) + (e.latency_ms ? " · " + e.latency_ms + " ms" : "") + (e.success_rate ? " · " + e.success_rate + "%" : "") + (e.cause ? " · " + e.cause : "")).join("\n");
  if (up.length === tun.length) return { status: "pass", summary: "all " + tun.length + " tunnels up", detail: d };
  const fix = down.map(e => (e.name || e.id) + ": " + (e.cause_fix || e.cause || "down")).join("\n");
  if (up.length === 0) return { status: "fail", summary: "all tunnels down", detail: d, fix: fix || "All tunnels are down — open Connections to toggle/restart them or check the servers.", deep: "connections" };
  return { status: "warn", summary: up.length + " of " + tun.length + " tunnels up", detail: d, fix, deep: "connections" };
}
async function chkExit() {
  const x = await api.get("/api/exit-ip");
  if (!x.available || !x.ip) return { status: "warn", summary: "unknown", detail: "No exit IP — sing-box may be off, or general traffic uses the WAN by design (split-tunnel)." };
  const flag = x.cc ? ccFlag(x.cc) + " " + (x.country || x.cc) : "";
  const asn = x.asn || x.isp || "";
  const summary = "exit IP " + x.ip + (flag ? " · " + flag : "") + (asn ? " · " + asn : "");
  let detail = "Traffic exits from " + x.ip + (x.cached ? " (cached)" : "");
  if (x.country || x.cc) detail += "\nCountry: " + (x.country || "") + (x.cc ? " (" + x.cc + ")" : "");
  if (x.asn) detail += "\nAS: " + x.asn;
  if (x.isp && x.isp !== x.asn) detail += "\nISP: " + x.isp;
  if ("hosting" in x) detail += "\nType: " + (x.hosting ? "Datacenter / hosting (expected for a VPN exit)" : "Residential");
  return { status: "pass", summary, detail, geo: { ip: x.ip, cc: x.cc, country: x.country, asn: x.asn, isp: x.isp } };
}
async function chkSystem() {
  const s = await api.get("/api/system");
  const meta = { version: s.version, arch: s.arch };
  if (!s.available) return { status: "warn", summary: "unavailable", meta };
  const sum = Math.round(s.mem_used_pct) + "% RAM · load " + (s.load1 != null ? s.load1.toFixed(2) : "–") + " · up " + humanDur(s.uptime_s);
  const st = s.mem_used_pct >= 92 ? "warn" : "pass";
  return { status: st, summary: sum, detail: sum + "\nfree RAM " + Math.round((s.mem_avail_kb || 0) / 1024) + " of " + Math.round((s.mem_total_kb || 0) / 1024) + " MB", fix: st === "warn" ? "RAM is nearly full — heavy connection load can drop packets. Reboot or reduce load." : "", meta };
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
    try { r = await api.post("/api/netdiag/all", { target: host }); } catch (e) { lines.push("✗ " + label + " · test failed: " + e.message); continue; }
    anyData = true;
    const rows = r.results || [];
    const viaTun = rows.filter(x => x.egress !== "direct" && x.reachable);
    const wan = rows.find(x => x.egress === "direct");
    if (viaTun.length) lines.push("✓ " + label + " · via " + viaTun.length + " tunnel" + (viaTun.length > 1 ? "s" : "") + " (" + viaTun.map(x => x.name || x.egress).join(", ") + ")");
    else if (wan && wan.reachable) { lines.push("● " + label + " · only on WAN — no tunnel reached it"); bad.push(label + ": no tunnel reached it"); }
    else { lines.push("✗ " + label + " · unreachable everywhere"); bad.push(label + ": unreachable (DPI/dead?)"); }
  }
  const detail = lines.join("\n");
  if (!anyData) return { status: "warn", summary: "couldn't test (core not running?)", detail };
  if (bad.length) return { status: "warn", summary: bad.length + " of " + hosts.length + " not reachable via a tunnel", detail, fix: bad.join("\n") + "\nOpen Connections to check the tunnels, or Routing to confirm the carve-outs.", deep: "connections" };
  return { status: "pass", summary: "blocked sites reachable through tunnels", detail };
}
async function chkLog() {
  const d = await api.get("/api/diagnostics");
  const n = (d.found || []).length;
  if (!n) return { status: "pass", summary: d.count ? "no known errors in " + d.count + " log lines" : "no log yet" };
  return { status: "warn", summary: "sing-box logged " + n + " known issue" + (n > 1 ? "s" : ""), kb: d.found };
}

function humanDur(sec) { sec = +sec || 0; const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60); return d ? d + "d " + h + "h" : h ? h + "h " + m + "m" : m + "m"; }
// ccFlag turns a 2-letter ISO country code into its regional-indicator emoji flag.
function ccFlag(cc) { if (!cc || !/^[A-Za-z]{2}$/.test(cc)) return ""; cc = cc.toUpperCase(); return String.fromCodePoint(...[...cc].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)); }
function timeAgo(ms) { const s = Math.round((Date.now() - ms) / 1000); return s < 60 ? "just now" : s < 3600 ? Math.floor(s / 60) + " min ago" : Math.floor(s / 3600) + "h ago"; }
// copyText copies to the clipboard with graceful degradation for the panel's real
// deployment: it is served over plain HTTP on a LAN IP (e.g. http://192.168.1.1:8088),
// which is NOT a secure context, so navigator.clipboard is undefined. Chain:
// async Clipboard API → execCommand("copy") → a manual-copy modal (pre-selected
// textarea) so the user can always get the text out (Ctrl/Cmd+C) instead of a dead end.
function copyText(str) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(str).then(() => toast("Copied", "ok"), () => execCopy(str));
    return;
  }
  execCopy(str);
}
function execCopy(str) {
  try {
    const ta = el("textarea", { style: "position:fixed;top:-1000px;opacity:0" });
    ta.value = str;
    document.body.appendChild(ta);
    ta.focus(); ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    if (ok) { toast("Copied", "ok"); return; }
  } catch (_) { /* fall through to the manual modal */ }
  copyManualModal(str);
}
function copyManualModal(str) {
  const ta = el("textarea", { readonly: "readonly", style: "width:100%;min-height:160px;font-family:ui-monospace,Consolas,monospace;font-size:12px;line-height:1.5" });
  ta.value = str;
  modal({
    title: "Copy manually",
    body: el("div", {},
      el("div", { class: "hint", style: "margin-bottom:8px" }, "Automatic copy is blocked (the panel runs over plain HTTP, not a secure context). Select all and press Ctrl/Cmd+C."),
      ta),
  });
  setTimeout(() => { ta.focus(); ta.select(); }, 60);
}
function copyReport() {
  const h = state.hbat; if (!h) return;
  const mask = !((document.getElementById("hbat-mask") || {}).checked === false); // default ON
  copyText(buildReport(h, mask));
}
// buildReport renders the battery into a self-contained Markdown report for pasting
// into a support chat / wgbot: a header (build, exit, timestamp), the verdict, every
// row's status, then the non-pass details. With mask=true (default) public IPs, WG
// keys and tokens are scrubbed first — the report carries the exit IP + ASN now.
function buildReport(h, mask) {
  const res = h.results, done = HC_ORDER.filter(id => res[id]);
  const worst = done.map(id => res[id]).reduce((a, r) => r.status === "fail" ? "fail" : (r.status === "warn" && a !== "fail") ? "warn" : a, "pass");
  const sys = (res.system && res.system.meta) || {}, exit = (res.exit && res.exit.geo) || {};
  let out = "## WakeRoute diagnostics\n";
  out += "- time: " + new Date(h.ranAt).toISOString() + "\n";
  if (sys.version) out += "- build: " + sys.version + (sys.arch ? " (" + sys.arch + ")" : "") + "\n";
  if (exit.ip) out += "- exit: " + exit.ip + (exit.cc ? " " + exit.cc : "") + (exit.asn ? " · " + exit.asn : "") + "\n";
  out += "\n### Verdict: " + worst.toUpperCase() + "\n";
  done.forEach(id => out += "- [" + res[id].status.toUpperCase() + "] " + (HC_LABEL[id] || id) + " — " + (res[id].summary || "") + "\n");
  const det = done.filter(id => res[id].status !== "pass" && (res[id].detail || res[id].fix));
  if (det.length) { out += "\n### Details\n"; det.forEach(id => { const r = res[id]; out += "\n**" + (HC_LABEL[id] || id) + "** (" + r.status + ")\n"; if (r.fix) out += "Fix: " + r.fix + "\n"; if (r.detail) out += "```\n" + r.detail + "\n```\n"; }); }
  return mask ? scrubText(out) : out;
}
// scrubText masks secrets + public IPs so a copied report is safe to share. Private /
// LAN addresses (10/8, 192.168/16, 172.16-31, 127/8, 0.x) are kept — they aren't
// sensitive and help debugging. Mirrors the publish/ scrub discipline.
function scrubText(s) {
  return String(s)
    .replace(/\b[A-Za-z0-9+/]{43}=/g, "[key]")
    .replace(/\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g, "[uuid]")
    .replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, (m, a, b, c, d) => isPrivIP(+a, +b) ? m : a + ".x.x." + d)
    .replace(/\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{0,4}\b/g, "[ipv6]");
}
function isPrivIP(a, b) { return a === 10 || a === 127 || a === 0 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31); }
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

async function renderDiagnostics(view) {
  view.appendChild(el("div", { class: "block-head" },
    el("div", {},
      el("div", { class: "ttl" }, "Diagnostics"),
      el("div", { class: "desc" }, "Confirm everything is working, test reachability through each exit, and analyze engine logs for known errors."))));
  try { await loadProfile(); } catch (_) {} // ensure the egress dropdown lists current tunnels
  view.appendChild(healthBatteryCard()); // hero: one-click "Run all checks" battery + verdict + copy report
  if (state.hbat) paintBattery();        // restore a prior run across tab nav
  view.appendChild(nativeSupportCard()); // read-only: what this router can carry natively (next to the battery)

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
  const diagIface = () => { const ep = findEndpoint(egress.value); return ep && ep.engine === "external" && ep.params && ep.params.interface; };
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
      if (iface) btnRow.appendChild(el("span", { class: "hint" }, "↳ bound to " + iface));
    }
  }
  egress.onchange = diagButtons;
  diagButtons();
  target.addEventListener("keydown", e => { if (e.key === "Enter") runDiagAll(target.value, ndOut); });
  const advanced = el("details", { class: "nd-advanced", style: "margin-top:14px" },
    el("summary", { style: "cursor:pointer;color:var(--ink-2);font-size:13px;user-select:none" }, "Advanced — one tool, one exit (ping · traceroute · DNS · reachability)"),
    el("div", { class: "field", style: "margin:12px 0 0;max-width:260px" }, el("label", {}, "Egress"), egress),
    btnRow);
  view.appendChild(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, "Network tools"),
    el("div", { class: "hint", style: "margin-bottom:12px" }, "Type a host, IP or URL and test whether it's reachable through every exit at once — WAN, each tunnel, and your routing groups."),
    el("div", { style: "display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap" },
      el("div", { class: "field", style: "margin:0;flex:1;min-width:240px" }, el("label", {}, "Target"), target),
      testAll),
    advanced, ndOut));
  if (state.diag) renderDiagOutput(ndOut); // restore a prior / in-flight result

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
  view.appendChild(el("div", { class: "card" },
    el("div", { class: "row-between", style: "margin-bottom:10px" },
      el("div", { class: "card-title" }, "Log analysis"),
      el("button", { class: "btn btn-sm", onclick: () => analyze(true) }, "Load sing-box log")),
    el("div", { class: "field" }, el("label", {}, "Analyze log text"), ta),
    el("button", { class: "btn btn-sm", onclick: () => analyze(false) }, "Analyze"),
    logOut));
}

function mono(text) {
  return el("div", { style: "font-family:ui-monospace,Consolas,monospace;font-size:12px;white-space:pre-wrap;background:var(--card-2);border-radius:7px;padding:10px 12px;max-height:280px;overflow:auto;line-height:1.5" }, text || "(no output)");
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
      if (state.diag !== myDiag) { reader.cancel(); return; } // superseded
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
    el("div", { class: "card-title" }, "Reachability via " + (r.name || r.egress)),
    el("span", { class: "pill " + (ok ? "ok" : "err") }, el("span", { class: "dot" }),
      ok ? (r.latency_ms + " ms") : "unreachable")));
  out.appendChild(el("div", { class: "hint", style: "word-break:break-all" }, "GET " + r.url + (r.err ? "  —  " + r.err : "")));
}

function renderReachMatrix(out, r) {
  const rows = (r.results || []).slice();
  const reached = rows.filter(x => x.reachable).length;
  out.appendChild(el("div", { class: "card-title", style: "margin-bottom:4px" }, "Reachability of " + r.target + " by exit"));
  out.appendChild(el("div", { class: "hint", style: "margin-bottom:10px" }, reached + " of " + rows.length + " exits reached it"));
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
    el("thead", {}, el("tr", {}, th("Exit", "name"), th("Status", "status"), th("Latency", "latency", true))),
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
        el("td", { "data-label": "Exit" }, x.name || x.egress),
        el("td", { "data-label": "Status" }, el("span", { class: "pill " + (ok ? "ok" : "err") }, el("span", { class: "dot" }), ok ? "reachable" : "unreachable")),
        el("td", { "data-label": "Latency", class: "rm-r " + latCls, title: x.err || "", "aria-label": latAria }, latCue, latText));
    })));
  out.appendChild(table);
  const wan = rows.find(x => x.egress === "direct");
  if (wan && !wan.reachable) out.appendChild(el("div", { class: "hint", style: "margin-top:10px;color:var(--warn)" },
    "WAN (direct) failed too — the router itself can't reach this target; check the uplink/DNS."));
}

function renderDiagResult(out, r) {
  if (r.found && r.found.length) {
    out.appendChild(el("div", { class: "card-title", style: "margin:6px 0 10px" }, r.found.length + " known issue" + (r.found.length > 1 ? "s" : "") + " detected"));
    r.found.forEach(e => out.appendChild(kbCard(e)));
  } else {
    out.appendChild(el("div", { class: "card" }, el("div", { class: "empty" },
      r.count ? "No known errors matched in " + r.count + " log lines." : "No log yet. Paste logs above, or start sing-box on the device and reload.")));
  }
  if (r.lines && r.lines.length) {
    const pre = el("div", { style: "font-family:ui-monospace,Consolas,monospace;font-size:12px;max-height:340px;overflow:auto;white-space:pre-wrap;line-height:1.55" });
    r.lines.forEach(lm => {
      const color = lm.entries ? "var(--warn)" : lm.error ? "var(--err)" : "var(--ink-2)";
      pre.appendChild(el("div", { style: "color:" + color }, (lm.entries ? "● " : "  ") + lm.line));
    });
    out.appendChild(el("div", { class: "card" }, el("div", { class: "card-title", style: "margin-bottom:10px" }, "Log (" + r.lines.length + " lines)"), pre));
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

/* ---------- Init Server (R8) ---------- */
let serverOptionsCache = null;
const SERVER_OPT_NAME = { "amneziawg": "AmneziaWG", "vless-reality": "VLESS-Reality" };

async function renderServer(view) {
  view.appendChild(el("div", { class: "block-head" },
    el("div", {},
      el("div", { class: "ttl" }, "Set up Server"),
      el("div", { class: "desc" }, "Provision and manage proxy servers over SSH. WakeRoute installs what you pick, auto-adds the client to Connections and tests it — keep several servers for redundancy, and harden fresh ones with key-only login.")),
    el("div", { class: "side" },
      el("button", { class: "btn btn-primary", title: "Provision a new remote server over SSH and add its client to Connections", onclick: openAddServer }, "+ Add server"))));

  const loadingSrv = el("div", { class: "hint", style: "margin:18px 0" }, "loading servers…");
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
  servers.forEach(sv => view.appendChild(serverCard(sv)));
}

function serverCard(sv) {
  const inst = (sv.installed || []);
  const meta = inst.length
    ? inst.map(p => el("span", { class: "badge proto" }, SERVER_OPT_NAME[p] || p))
    : [el("span", { class: "hint" }, "nothing set up yet")];
  return el("div", { class: "card" },
    el("div", { class: "conn" },
      el("div", { class: "body" },
        el("div", { class: "name" }, sv.name || sv.host,
          sv.hardened ? el("span", { class: "pill ok pill--dot", title: "Key-only login" }, el("span", { class: "dot" })) : null),
        el("div", { class: "sub" }, ...meta, el("span", { class: "addr" }, (sv.user || "root") + "@" + sv.host + ":" + (sv.port || 22))),
        el("div", { class: "stats" }, sv.hardened ? el("b", {}, "🔒 hardened — password login disabled") : el("span", {}, "password login still enabled"))),
      el("div", { class: "acts" },
        el("button", { class: "btn btn-primary btn-sm", onclick: () => openProvision(sv) }, "Set up"),
        el("button", { class: "btn btn-sm", onclick: () => openHarden(sv) }, sv.hardened ? "Re-key" : "Secure"),
        el("button", { class: "btn btn-sm", onclick: () => openVersions(sv) }, "Versions"),
        el("button", { class: "btn btn-danger btn-sm", onclick: () => delServer(sv) }, "Delete"))));
}

async function delServer(sv) {
  if (!confirm("Remove “" + (sv.name || sv.host) + "” from your servers list? The server itself is not touched.")) return;
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
  const pwWrap = el("div", { class: "field" }, el("label", {}, "Password"), pw);
  const keyWrap = el("div", { class: "field", style: "display:none" }, el("label", {}, "SSH private key (paste)"), key);
  let mode = "password";
  const pwTab = el("div", { class: "tab active" }, "Password");
  const keyTab = el("div", { class: "tab" }, "SSH key");
  pwTab.addEventListener("click", () => { mode = "password"; pwTab.classList.add("active"); keyTab.classList.remove("active"); pwWrap.style.display = ""; keyWrap.style.display = "none"; });
  keyTab.addEventListener("click", () => { mode = "key"; keyTab.classList.add("active"); pwTab.classList.remove("active"); pwWrap.style.display = "none"; keyWrap.style.display = ""; });
  const node = el("div", {},
    el("div", { style: "display:flex;gap:12px" },
      el("div", { class: "field", style: "flex:2" }, el("label", {}, "Host / IP"), host),
      el("div", { class: "field", style: "flex:1" }, el("label", {}, "SSH port"), port)),
    el("div", { class: "field" }, el("label", {}, "SSH user"), user),
    el("div", { class: "tabs" }, pwTab, keyTab), pwWrap, keyWrap,
    el("div", { class: "hint lock" }, "🔒 Credentials are used once for this request and never stored."));
  return { node, get: () => ({ host: host.value.trim(), port: parseInt(port.value, 10) || 22, user: user.value.trim(), password: mode === "password" ? pw.value : "", key: mode === "key" ? key.value : "" }) };
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

// Setup-options picker — the list of what WakeRoute can install, with details.
// Recommended protocols (the suggested defaults) are surfaced first; the rest are
// grouped under "Also available". A single self-signed-TLS caveat is shown once for
// the group of protocols whose option data says they use a self-signed certificate.
async function optionPicker(preselect) {
  if (!serverOptionsCache) { try { serverOptionsCache = await api.get("/api/server/options"); } catch (_) { serverOptionsCache = []; } }
  const opts = serverOptionsCache || [];
  const inputs = {};
  const wrap = el("div", {});

  const isOn = o => (preselect && preselect.includes(o.id)) || (!preselect && o.recommended);
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
    node.style.display = "";
    const poll = async () => {
      if (!document.body.contains(node)) { stop(); return; } // modal closed
      try {
        const v = await api.get("/api/server/job/" + jobId);
        paint(v);
        if (v.done) { stop(); if (onDone) onDone(v); }
      } catch (_) { stop(); }
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
  const name = el("input", { type: "text", placeholder: "e.g. NL VPS" });
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
    body: el("div", {}, el("div", {}, "“" + (sv.name || sv.host) + "” is saved."),
      el("div", { class: "hint", style: "margin-top:8px" }, "If it's a fresh server, securing it first is recommended — WakeRoute installs an SSH key, lets you download it, then can disable password login so only the key works.")),
    footer: el("div", { style: "display:flex;gap:10px" }, later, setup, secure),
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
  const back = modal({
    title: "Set up " + ((sv && (sv.name || sv.host)) || "server"),
    body: el("div", {}, c.node,
      el("div", { class: "card-title", style: "margin:18px 0 10px" }, "What to set up"),
      picker.node, con.node),
    footer: el("div", { style: "display:flex;gap:10px" }, checkBtn, previewBtn, runBtn),
  });
  checkBtn.addEventListener("click", async () => {
    const cr = c.get();
    if (!cr.host) return toast("Enter a host first", "err");
    checkBtn.disabled = true;
    try {
      const r = await api.post("/api/server/check", { host: cr.host, port: cr.port });
      toast((r.reachable ? "✓ reachable" : "✗ unreachable") + " — ping " + (r.ping_ok ? (r.ping_ms != null ? Math.round(r.ping_ms) : "?") + " ms" : "no reply") + ", SSH port " + r.port + " " + (r.port_open ? "open" : "closed"), r.reachable ? "ok" : "err");
    } catch (e) { toast(e.message, "err"); } finally { checkBtn.disabled = false; }
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
    runBtn.disabled = true; runBtn.textContent = "Working…";
    try {
      const r = await api.post("/api/server/provision", { server_id: sv && sv.id, name: sv && sv.name, ...cr, protocols: opts });
      con.run(r.job_id, v => {
        runBtn.disabled = false; runBtn.textContent = "Set up again";
        if (v.ok) toast("Done — client added to Connections", "ok");
        else toast("Finished with errors — see console", "err");
      });
    } catch (e) { runBtn.disabled = false; runBtn.textContent = "Set up"; toast(e.message, "err"); }
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
    genBtn.disabled = true; genBtn.textContent = "Working…";
    try {
      const r = await api.post("/api/server/harden/keys", { server_id: sv && sv.id, ...cr });
      con.run(r.job_id, v => {
        genBtn.disabled = false; genBtn.textContent = "Re-generate key";
        if (v.ok && v.result && v.result.private_key) {
          installedKey = v.result.private_key; keyFile = v.result.filename || "wr-key";
          dlBtn.style.display = ""; savedWrap.style.display = "inline-flex";
          dlBtn.onclick = () => downloadText(keyFile, installedKey);
          toast("Key installed — download it now", "ok");
        } else toast("Key install failed — see console", "err");
      });
    } catch (e) { genBtn.disabled = false; genBtn.textContent = "Generate & install key"; toast(e.message, "err"); }
  });
  savedCb.addEventListener("change", () => { lockBtn.style.display = savedCb.checked ? "" : "none"; });
  lockBtn.addEventListener("click", async () => {
    if (!installedKey) return toast("Generate a key first", "err");
    if (!confirm("Disable password login on " + (sv ? sv.host : "this server") + "?\n\nMake sure you downloaded the key and it works — afterwards only the key can log in.")) return;
    lockBtn.disabled = true; lockBtn.textContent = "Working…";
    try {
      const cr = c.get();
      const r = await api.post("/api/server/harden/lockdown", { server_id: sv && sv.id, host: cr.host, port: cr.port, user: cr.user, key: installedKey });
      con.run(r.job_id, v => {
        lockBtn.disabled = false; lockBtn.textContent = "Disable password login";
        if (v.ok) { toast("Server hardened — key-only login", "ok"); back.remove(); route(); }
        else toast("Lockdown failed — password login unchanged", "err");
      });
    } catch (e) { lockBtn.disabled = false; lockBtn.textContent = "Disable password login"; toast(e.message, "err"); }
  });
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

function renderVersionTable(box, result, sv, c, con) {
  box.innerHTML = "";
  const binaries = result && result.binaries;
  // Rendered on the job-done callback — AFTER route()/modal() i18nApply — so these
  // strings must go through t() explicitly to localize (i18nApply won't revisit them).
  if (result && result.arch) box.appendChild(el("div", { class: "hint", style: "margin-bottom:var(--sp-2)" }, "arch: " + result.arch));
  if (result && result.curl === false) box.appendChild(el("div", { class: "hint", style: "color:var(--warn);margin-bottom:var(--sp-2)" }, "⚠ curl not found on the server — sing-box binary updates require curl (apt install curl)"));
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
        ? el("button", { class: "btn btn-primary btn-sm", onclick: () => updateBinary(sv, c, con, b, b.latest_tag || b.latest) }, t("Update"))
        : el("button", { class: "btn btn-primary btn-sm", disabled: true, title: t("curl not found on the server — install curl first (apt install curl)") }, t("Update"));
      else if (b.managed === "apt") act = el("button", { class: "btn btn-sm", onclick: () => updateBinary(sv, c, con, b, "") }, t("apt upgrade"));
      return el("tr", {},
        el("td", { "data-label": "Binary" }, b.name),
        el("td", { "data-label": "Installed" }, b.installed || "?"),
        el("td", { "data-label": "Latest" }, latest),
        el("td", { "data-label": "", class: "rm-r" }, el("div", { style: "display:flex;gap:8px;align-items:center;justify-content:flex-end;flex-wrap:wrap" }, status, act)));
    })));
  box.appendChild(table);
}

async function updateBinary(sv, c, con, b, version) {
  const what = b.managed === "apt" ? (b.name + " via apt upgrade") : (b.name + " → " + version);
  if (!confirm("Update " + what + " on " + (sv ? sv.host : "the server") + "?\n\nThe service will briefly restart. The old binary is backed up on the server as <path>.wakeroute.bak.")) return;
  const cr = c.get();
  if (!cr.host || !cr.user) return toast("Host and SSH user are required", "err");
  try {
    const r = await api.post("/api/server/update-binary", { server_id: sv && sv.id, ...cr, binary: b.key, version: version || "", confirm: true });
    con.run(r.job_id, v => {
      if (v.ok) toast(b.name + " updated" + (v.result && v.result.new_version ? " → " + v.result.new_version : ""), "ok");
      else toast("Update failed — see console", "err");
    });
  } catch (e) { toast(e.message, "err"); }
}

/* ---------- Settings (M10) ---------- */
function restartTag() { return el("span", { class: "tag-restart", title: t("Takes effect after the daemon restarts") }, t("↻ restart")); }

// secretInput is a password-type field with a Show/Hide reveal toggle, for values
// that shouldn't sit in plain sight on an unauthenticated LAN panel (the clash
// secret, the watchdog webhook URL which commonly embeds a token). Returns the
// input (read .value) plus the row to place in a .field.
function secretInput(v, ph) {
  const input = el("input", { type: "password", value: v == null ? "" : String(v), placeholder: ph || "", autocomplete: "off", spellcheck: "false" });
  const toggle = el("button", { class: "btn btn-sm reveal", type: "button" }, t("Show"));
  toggle.addEventListener("click", () => {
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    toggle.textContent = show ? t("Hide") : t("Show");
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
  (next.updater.mirrors || []).filter(Boolean).forEach(m => { if (!isHTTPUrl(m)) errs.push(t("Updater mirror is not a URL: ") + m); });
  return errs;
}

// Module-scoped so the single beforeunload guard (added once) can see the live
// dirty state without re-binding on every Settings render.
let _settingsDirty = false;
let _settingsUnloadHooked = false;

async function renderSettings(view) {
  const loadingCfg = el("div", { class: "hint", style: "margin:18px 0" }, t("loading settings…"));
  view.appendChild(loadingCfg);
  let cfg;
  try { cfg = await api.get("/api/config"); }
  catch (e) { loadingCfg.remove(); view.appendChild(el("div", { class: "empty" }, t("Could not load config: {0}", e.message))); return; }
  loadingCfg.remove();

  view.appendChild(el("div", { class: "block-head" },
    el("div", {},
      el("div", { class: "ttl" }, t("Settings")),
      el("div", { class: "desc" }, t("Daemon configuration. Saving here stores these settings; the Apply button in the top bar regenerates routing — they are separate actions. Fields tagged ↻ take effect only after WakeRoute restarts."))),
    el("div", { class: "side" })));

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
  langSel.addEventListener("change", () => setLang(langSel.value));
  view.appendChild(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:12px" }, t("Appearance")),
    el("div", { style: "display:flex;gap:16px;flex-wrap:wrap" },
      el("div", { class: "field", style: "max-width:260px;margin-bottom:0" }, el("label", {}, t("Theme")), themeSel),
      el("div", { class: "field", style: "max-width:260px;margin-bottom:0" }, el("label", {}, t("Language")), langSel))));

  // Subscription auto-refresh — opt-in periodic re-fetch of an imported subscription URL
  // (additive: it only ADDS the provider's newly-rotated servers, never deletes). Self-
  // contained: fetches /api/subscription/info + drives the dedicated control endpoints.
  (function subRefreshCard() {
    const card = el("div", { class: "card" });
    card.appendChild(el("div", { class: "card-title", style: "margin-bottom:12px" }, t("Subscription auto-refresh")));
    const bodyDiv = el("div", {}, el("div", { class: "hint" }, t("loading…")));
    card.appendChild(bodyDiv);
    view.appendChild(card);
    api.get("/api/subscription/info").then(info => {
      bodyDiv.innerHTML = "";
      if (!info || !info.url) {
        bodyDiv.appendChild(el("div", { class: "hint" }, t("No imported subscription. Import a subscription URL under Connections to enable periodic auto-refresh.")));
        return;
      }
      bodyDiv.appendChild(el("div", { class: "hint", style: "margin-bottom:10px;word-break:break-all" }, t("Source: ") + info.url));
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
        try { const r = await api.post("/api/subscription/refresh", {}); const n = (r && r.added) || 0; toast(t("Refreshed — {0} new connection(s)", n), "ok"); renderStatus(Math.floor(Date.now() / 1000), n, ""); }
        catch (e) { toast(e.message, "err"); }
        finally { now.disabled = false; now.textContent = prev; }
      });
      bodyDiv.appendChild(el("div", { style: "display:flex;gap:14px;align-items:center;flex-wrap:wrap" },
        el("label", { class: "check" }, enable, el("span", {}, t("Auto-refresh"))),
        el("div", { class: "field", style: "margin-bottom:0" }, el("label", {}, t("Every (hours)")), hours),
        save, now));
      bodyDiv.appendChild(statusLine);
    }).catch(() => { bodyDiv.innerHTML = ""; bodyDiv.appendChild(el("div", { class: "hint" }, t("Could not load subscription info."))); });
  })();

  const txt = (v, ph) => el("input", { type: "text", value: v == null ? "" : String(v), placeholder: ph || "" });
  const num = (v) => el("input", { type: "number", value: v == null ? "" : String(v) });
  const field = (label, input, restart) =>
    el("div", { class: "field" },
      el("label", {}, label, restart ? restartTag() : null), input);

  // Web panel
  const listen = txt(cfg.listen, ":8088");
  // Proxy core
  const sbBin = txt(cfg.singbox && cfg.singbox.bin, "/opt/sbin/sing-box");
  const sbCfg = txt(cfg.singbox && cfg.singbox.config, "/opt/etc/wakeroute/singbox.json");
  const clashCtl = txt(cfg.clash && cfg.clash.controller, "127.0.0.1:9090");
  const clashSecF = secretInput(cfg.clash && cfg.clash.secret, t("optional"));
  const clashSec = clashSecF.input;
  // Ports
  const pUI = num(cfg.ports && cfg.ports.ui), pClash = num(cfg.ports && cfg.ports.clash),
    pDNS = num(cfg.ports && cfg.ports.dns), pMixed = num(cfg.ports && cfg.ports.mixed);
  // Updater mirrors
  const mirrors0 = (cfg.updater && cfg.updater.mirrors) || [];
  const directFirst = el("input", { type: "checkbox" }); directFirst.checked = mirrors0.includes("");
  const mirrorsTA = el("textarea", { placeholder: "https://ghproxy.net/\nhttps://mirror.ghproxy.com/" });
  mirrorsTA.value = mirrors0.filter(m => m !== "").join("\n");
  // Watchdog (webhook may embed a token → masked)
  const wdURLF = secretInput(cfg.watchdog && cfg.watchdog.notify_url, "https://… (optional, blank = off)");
  const wdURL = wdURLF.input;
  // Fail-safe (Apply rollback)
  const fsTarget = txt(cfg.failsafe && cfg.failsafe.target, "1.1.1.1");
  const fsReboot = el("input", { type: "checkbox" }); fsReboot.checked = !!(cfg.failsafe && cfg.failsafe.auto_reboot);
  // Mode
  const demo = el("input", { type: "checkbox" }); demo.checked = !!cfg.demo;
  // Security — Host allow-list (DNS-rebinding guard; one host per line, empty = allow any)
  const allowedHosts = el("textarea", { placeholder: "192.168.1.1\nrouter.lan" });
  allowedHosts.value = (cfg.allowed_hosts || []).join("\n");
  // Routing mode (applies on the next Apply, not a restart)
  const ROUTE_MODES = [
    ["hybrid", t("Everything via WakeRoute (domain carve-outs work; general traffic slower / CPU-bound)")],
    ["fast", t("Fast: general traffic bypasses WakeRoute (kernel fast-path) — IP carve-outs (calls/VoWiFi) still work; domain carve-outs OFF")],
    ["tun", t("All traffic through sing-box (TUN)")],
    ["mixed", t("Local proxy only, no gateway (mixed)")],
    ["", t("Auto (derive from Gateway)")],
  ];
  const routeMode = el("select", {}, ...ROUTE_MODES.map(m => el("option", { value: m[0] }, m[1])));
  routeMode.value = cfg.routing_mode || "";
  // Flow offload (Phase 1b): accelerates GENERAL traffic in Fast mode. Carve-outs are
  // mark-routed and auto-excluded from the flowtable, so they keep working. Devices blank
  // => the daemon auto-probes the WAN uplink + LAN bridge.
  const OFFLOAD_MODES = [
    ["", t("Off (default)")],
    ["sw", t("Software flow-offload")],
    ["hw", t("Hardware offload (NIC/PPE) — fastest where supported")],
  ];
  const offloadSel = el("select", {}, ...OFFLOAD_MODES.map(m => el("option", { value: m[0] }, m[1])));
  offloadSel.value = cfg.offload || "";
  const offloadDevs = el("input", { type: "text", placeholder: t("auto-detect (leave blank)") });
  offloadDevs.value = (cfg.offload_devices || []).join(" ");

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
      listen: listen.value.trim(),
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
  if (!_settingsUnloadHooked) {
    _settingsUnloadHooked = true;
    // Fires only while ON Settings with unsaved edits (in-app nav re-fetches config,
    // so leaving simply discards — the badge is the warning there).
    window.addEventListener("beforeunload", e => {
      if (_settingsDirty && (location.hash || "#dashboard").slice(1) === "settings") { e.preventDefault(); e.returnValue = ""; }
    });
  }

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
      toast(r.restart_needed ? t("Saved — restart WakeRoute for all changes to take effect.") : t("Saved."), "ok");
      if (routeModeChanged) toast(t("Routing mode changed — press Apply (top bar) to activate it."), "info");
      else if (offloadChanged) toast(t("Flow offload changed — press Apply (top bar) to activate it."), "info");
    } catch (e) { status.textContent = ""; toast(e.message, "err"); }
    finally { save.disabled = false; }
  });

  view.appendChild(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, t("Routing mode")),
    el("div", { class: "hint", style: "margin-bottom:10px" }, t("How LAN traffic is routed. «Fast» keeps your tunnels/carve-outs for IPs (calls, VoWiFi) but lets general traffic (downloads, games) take the kernel fast-path instead of the userspace proxy — much higher throughput. Takes effect on the next Apply.")),
    field(t("Mode"), routeMode),
    el("div", { class: "hint", style: "margin:14px 0 10px" }, t("Flow offload accelerates general (non-tunnel) traffic via the kernel/hardware fast path in «Fast» mode. Your tunnel carve-outs (calls, VoWiFi, blocked sites) are mark-routed and automatically excluded from the flowtable, so they keep working. Enable «Hardware» only on routers whose NIC supports it. Leave devices blank to auto-detect the WAN + LAN interfaces. Takes effect on the next Apply.")),
    el("div", { style: "display:flex;gap:12px;flex-wrap:wrap" },
      el("div", { style: "flex:1;min-width:220px" }, field(t("Flow offload"), offloadSel)),
      el("div", { style: "flex:1;min-width:220px" }, field(t("Offload devices"), offloadDevs)))));

  view.appendChild(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:12px" }, t("Web panel")),
    field(t("Listen address"), listen, true)));

  view.appendChild(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:12px" }, t("Proxy core")),
    el("div", { style: "display:flex;gap:12px;flex-wrap:wrap" },
      el("div", { style: "flex:1;min-width:220px" }, field(t("sing-box binary"), sbBin, true)),
      el("div", { style: "flex:1;min-width:220px" }, field(t("sing-box config"), sbCfg, true))),
    el("div", { style: "display:flex;gap:12px;flex-wrap:wrap" },
      el("div", { style: "flex:1;min-width:220px" }, field(t("Clash controller"), clashCtl)),
      el("div", { style: "flex:1;min-width:220px" }, field(t("Clash secret"), clashSecF.row)))));

  view.appendChild(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:12px" }, t("Ports"), restartTag()),
    el("div", { class: "kv-grid" },
      field(t("Web UI"), pUI), field(t("Clash API"), pClash), field(t("DNS"), pDNS), field(t("Mixed (socks+http)"), pMixed))));

  view.appendChild(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, t("Updater mirrors")),
    el("div", { class: "hint", style: "margin-bottom:10px" }, t("GitHub URL prefixes tried in order when downloading engine binaries — fix these if a mirror is blocked in your region.")),
    el("label", { class: "check", style: "display:inline-flex;margin-bottom:10px" }, directFirst, el("span", {}, t("Try a direct connection first"))),
    mirrorsTA));

  view.appendChild(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, t("Watchdog alerts")),
    el("div", { class: "hint", style: "margin-bottom:10px" }, t("Optional webhook POSTed {\"text\":\"…\"} on each sing-box crash-restart (e.g. a WGBot endpoint). Leave blank to disable.")),
    field(t("Notify webhook URL"), wdURLF.row)));

  view.appendChild(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, t("Fail-safe")),
    el("div", { class: "hint", style: "margin-bottom:10px" }, t("After an Apply (not yet saved), WakeRoute pings this target to confirm the new config kept you online; if it can't be reached, the previous config is rolled back.")),
    field(t("Connectivity-check target"), fsTarget),
    el("label", { class: "check", style: "display:inline-flex;margin-top:10px" }, fsReboot, el("span", {}, t("Allow auto-reboot as a last resort"))),
    el("div", { class: "hint", style: "margin-top:6px" }, t("Off by default. Only triggers if a rollback still can't restore connectivity — leave off unless you trust unattended reboots."))));

  view.appendChild(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:10px" }, t("Mode")),
    el("label", { class: "check", style: "display:inline-flex" }, demo, el("span", {}, t("Demo mode (synthesize traffic when sing-box is absent)"))),
    el("div", { class: "hint", style: "margin-top:6px" }, restartTag(), t(" applies after restart"))));

  view.appendChild(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, t("Security"), restartTag()),
    el("div", { class: "hint", style: "margin-bottom:10px" }, t("Host allow-list — one hostname or IP per line. When set, the panel only answers requests whose Host header matches one of these (a DNS-rebinding defense). Leave EMPTY to allow any host (the default). List every name/IP you use to reach the panel, or you will lock yourself out (recover by clearing it in config.json and restarting).")),
    allowedHosts));

  // Backup & restore — download/upload the whole config + reset to defaults.
  const includeSecrets = el("input", { type: "checkbox" });
  const downloadBtn = el("button", { class: "btn", type: "button" }, t("Download backup"));
  downloadBtn.addEventListener("click", () => {
    const a = el("a", { href: "/api/config/export" + (includeSecrets.checked ? "?secrets=1" : ""), download: "wakeroute-config.json" });
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
    if (!confirm(t("Restore settings from this backup? It replaces your current settings (they are validated first)."))) { fileInput.value = ""; return; }
    try {
      const r = await api.post("/api/config/import", parsed);
      toast(r.restart_needed ? t("Restored — restart WakeRoute to apply.") : t("Restored."), "ok");
      route();
    } catch (e) { toast(e.message, "err"); }
    finally { fileInput.value = ""; }
  });
  const resetBtn = el("button", { class: "btn btn-danger", type: "button" }, t("Reset to defaults"));
  resetBtn.addEventListener("click", async () => {
    if (!confirm(t("Reset settings to defaults? Your panel address, UI port, host allow-list and subscription token are kept; everything else returns to defaults."))) return;
    try {
      const r = await api.post("/api/config/reset", {});
      toast(r.restart_needed ? t("Reset to defaults — restart WakeRoute to apply.") : t("Reset to defaults."), "ok");
      route();
    } catch (e) { toast(e.message, "err"); }
  });
  view.appendChild(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, t("Backup & restore")),
    el("div", { class: "hint", style: "margin-bottom:12px" }, t("Download all settings as a file, restore from a backup, or reset to defaults. Secrets are left out of a backup unless you tick “Include secrets”.")),
    el("div", { style: "display:flex;gap:10px;flex-wrap:wrap;align-items:center" },
      downloadBtn,
      el("label", { class: "check", style: "display:inline-flex" }, includeSecrets, el("span", {}, t("Include secrets"))),
      restoreBtn, fileInput, resetBtn)));

  // Full backup (everything) — the whole setup (connections, failover groups,
  // routing lists, saved servers, routing mode) in one file, for saving before a
  // firmware reflash or migrating to another WakeRoute instance.
  const fullDownloadBtn = el("a", { class: "btn", href: "/api/backup", download: "wakeroute-backup.json" }, t("Download full backup"));
  const fullFileInput = el("input", { type: "file", accept: "application/json,.json", style: "display:none" });
  const fullRestoreBtn = el("button", { class: "btn", type: "button" }, t("Restore full backup…"));
  fullRestoreBtn.addEventListener("click", () => fullFileInput.click());
  fullFileInput.addEventListener("change", async () => {
    const f = fullFileInput.files && fullFileInput.files[0];
    if (!f) return;
    let parsed;
    try { parsed = JSON.parse(await f.text()); }
    catch { fullFileInput.value = ""; return toast(t("That file is not valid JSON."), "err"); }
    if (parsed.wakeroute_backup !== 1) { fullFileInput.value = ""; return toast(t("That is not a WakeRoute full backup."), "err"); }
    if (!confirm(t("Restore your whole setup from this backup? It replaces all connections, groups and routing lists (validated first). Nothing is applied automatically — review it, then press Apply. Your panel address and access settings are NOT changed."))) { fullFileInput.value = ""; return; }
    try {
      const r = await api.post("/api/backup/restore", parsed);
      toast(t("Restored {0} connections, {1} groups, {2} servers — review and press Apply to activate.", r.endpoints, r.groups, r.servers), "ok");
      await loadProfile();
      route();
    } catch (e) { toast(e.message, "err"); }
    finally { fullFileInput.value = ""; }
  });
  view.appendChild(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, t("Full backup (everything)")),
    el("div", { class: "hint", style: "margin-bottom:6px" }, t("Save your whole setup — connections, failover groups, routing lists, saved servers and routing mode — to one file. Ideal before a firmware reflash or when moving to another WakeRoute. Restoring validates everything first and never applies on its own; you review it and press Apply.")),
    el("div", { class: "hint", style: "margin-bottom:12px" }, t("The backup file contains your connection secrets (keys, passwords) — keep it private. Daemon access settings (panel port and host allow-list) are NOT changed by a restore.")),
    el("div", { style: "display:flex;gap:10px;flex-wrap:wrap;align-items:center" },
      fullDownloadBtn, fullRestoreBtn, fullFileInput)));

  const restartBtn = el("button", { class: "btn btn-danger" }, t("Restart service"));
  restartBtn.addEventListener("click", restartService);
  view.appendChild(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:10px" }, t("Service")),
    el("div", { class: "hint", style: "margin-bottom:12px" }, t("Restart the whole WakeRoute daemon (panel + proxy core). The web panel drops for a few seconds while the init system brings it back; this page reconnects automatically. (Not available in the demo.)")),
    restartBtn));

  view.appendChild(errBox);
  view.appendChild(el("div", { class: "row-between", style: "margin-top:4px" }, el("div"),
    el("div", { style: "display:flex;align-items:center" }, dirtyBadge, status, save)));
  _settingsDirty = false; dirtyBadge.style.display = "none";
}

/* ---------- data ---------- */
async function loadProfile() {
  const p = await api.get("/api/profile");
  // Go marshals nil slices as JSON null; the UI assumes arrays everywhere.
  p.endpoints = p.endpoints || [];
  p.groups = p.groups || [];
  p.rules = p.rules || [];
  p.routing_lists = p.routing_lists || [];
  // Nested: a group's members can be null too (dashboard/Failover call .map on it).
  p.groups.forEach(g => { g.members = g.members || []; });
  state.profile = p;
}
async function loadHealth() { state.health = await api.get("/api/health"); updateStatusPill(); }

/* ---------- init ---------- */
async function init() {
  $$(".nav-item").forEach(n => n.addEventListener("click", () => { location.hash = "#" + n.dataset.page; }));
  const ab = $("#applybtn"), asb = $("#applysavebtn");
  if (ab) ab.addEventListener("click", () => applyConfig(false));
  if (asb) asb.addEventListener("click", () => applyConfig(true));
  window.addEventListener("hashchange", route);
  try { await loadHealth(); } catch (_) {}
  checkFailsafe(); // re-arm the rollback countdown if a reload landed mid-Apply-window
  await pollTraffic();
  pollHealth();
  // Polling is gated to keep the router idle: nothing fires while the tab is
  // hidden, the 1 Hz traffic poll runs only on the dashboard (the only page with
  // a graph), and per-tunnel health polls only where pills/stats are shown.
  const page = () => (location.hash || "#dashboard").slice(1);
  const onGraph = () => page() === "dashboard";
  const onHealth = () => page() === "dashboard" || page() === "connections";
  setInterval(() => { if (!document.hidden) { loadHealth().catch(() => {}); checkFailsafe(); } }, 5000);
  setInterval(() => { if (!document.hidden && onGraph()) pollTraffic(); }, 1000);
  setInterval(() => { if (!document.hidden && onHealth()) pollHealth(); }, 5000);
  // Refresh immediately on tab refocus so data isn't a full interval stale.
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) return;
    loadHealth().catch(() => {});
    checkFailsafe();
    if (onGraph()) pollTraffic();
    if (onHealth()) pollHealth();
  });
  i18nObserve();
  translateChrome();
  route();
}
init();
