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

// a11yClick makes a non-button clickable element (an icon/span like the IPTV drill-down ▸ expander or
// the 📌 pin) keyboard-operable and screen-reader-announced — role=button + tabindex + Enter/Space —
// matching switchEl so icon controls aren't mouse-only.
function a11yClick(elm, handler, label) {
  elm.setAttribute("role", "button");
  elm.setAttribute("tabindex", "0");
  if (label) elm.setAttribute("aria-label", label);
  elm.addEventListener("click", handler);
  elm.addEventListener("keydown", ev => { if (ev.key === "Enter" || ev.key === " " || ev.key === "Spacebar") { ev.preventDefault(); handler(ev); } });
  return elm;
}
// wireNavItem makes a .nav-item <div> a keyboard-operable button (role + tabindex + Enter/Space → its
// page). Shared by the static nav (init) AND the dynamically-injected plugin nav (injectPluginNav) so the
// two can't drift — a mouse-only plugin item would leave its page (e.g. IPTV) unreachable by keyboard.
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

// --- pending-Apply (profile-dirty) tracking ------------------------------
// Every connection/group/routing edit only STAGES into the store; it activates on Apply. Without a
// signal the Apply button looks identical whether or not changes are pending, silently dead-ending
// the primary "paste link → it works" flow. We snapshot the profile at Apply time and compare on
// each reload, so the topbar can flag unsaved changes — no per-mutation-site bookkeeping needed.
let _appliedSnapshot = null;
let profileDirty = false;
let applyInFlight = false; // true while POST /api/apply is in flight — blocks staging toggles so a mid-Apply edit can't race the applied config + dirty baseline
function profileSnapshot() {
  const p = state.profile || {};
  return JSON.stringify([p.endpoints, p.groups, p.rules, p.routing_lists, p.dns]);
}
function reflectDirty() {
  const ab = document.getElementById("applybtn"), asb = document.getElementById("applysavebtn");
  [ab, asb].forEach(b => b && b.classList.toggle("dirty", profileDirty));
  if (ab) ab.title = profileDirty
    ? t("Unsaved changes — Apply to activate them (live, reverts on reboot)")
    : t("Apply live — not saved, reverts on reboot or if connectivity drops");
}
function updateDirty() {
  const snap = profileSnapshot();
  if (_appliedSnapshot === null) _appliedSnapshot = snap; // first load = the current live baseline
  profileDirty = snap !== _appliedSnapshot;
  reflectDirty();
}
function clearDirty() { _appliedSnapshot = profileSnapshot(); profileDirty = false; reflectDirty(); }
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
    "Add this OS-owned tunnel as a routing exit (added disabled — WayHop will not manage it)":
      "Добавить этот туннель ОС как маршрутный выход (добавляется отключённым — WayHop не управляет им)",
    "WayHop will ROUTE THROUGH the tunnel but does not manage it (the OS owns it). It is added disabled — enable it in Connections to start routing.":
      "WayHop будет МАРШРУТИЗИРОВАТЬ ЧЕРЕЗ туннель, но не управляет им (туннель принадлежит ОС). Он добавляется отключённым — включите его в разделе «Подключения», чтобы начать маршрутизацию.",
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
    "Use ▲/▼ to set priority. A selector group uses the top member; urltest/fallback auto-pick the fastest working member and use your order as a tiebreak.":
      "Стрелками ▲/▼ задайте приоритет. Группа selector использует верхний туннель; urltest/fallback сами выбирают самый быстрый рабочий, а ваш порядок — лишь при равенстве.",
    "sing-box is routing through this member right now": "sing-box прямо сейчас направляет трафик через этот туннель",
    "Lowest latency — but not the member currently routed": "Наименьшая задержка — но трафик сейчас идёт не через него",
    "Local network problem": "Проблема локальной сети",
    "Every exit is unreachable at once — this looks like your internet/uplink, not the VPNs. Failover is paused until connectivity returns.":
      "Все выходы недоступны одновременно — похоже на проблему вашего интернета/аплинка, а не VPN. Переключение приостановлено до восстановления связи.",
    "Health check URL": "URL проверки доступности",
    "Probe interval (s)": "Интервал проверки (с)",
    "Flap tolerance (ms)": "Порог антидребезга (мс)",
    "Higher tolerance = stickier exit on a jittery/DPI link (try 100–150 ms); lower interval = faster failover (floored to 5 s). Tunes urltest/fallback auto-failover; a selector group only uses the URL for its health badge.":
      "Больше порог = стабильнее выбор на дёрганом/DPI-канале (попробуйте 100–150 мс); меньше интервал = быстрее переключение (минимум 5 с). Настраивает автопереключение urltest/fallback; selector использует только URL для индикатора здоровья.",
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
    "Save your whole setup — connections, failover groups, routing lists, saved servers and routing mode — to one file. Ideal before a firmware reflash or when moving to another WayHop. Restoring validates everything first and never applies on its own; you review it and press Apply.":
      "Сохраните всю конфигурацию — подключения, группы отказоустойчивости, списки маршрутизации, сохранённые серверы и режим маршрутизации — в один файл. Удобно перед перепрошивкой или при переносе на другой WayHop. При восстановлении всё сначала проверяется и ничего не применяется автоматически; вы просматриваете и нажимаете «Применить».",
    "The backup file contains your connection secrets (keys, passwords) — keep it private. Daemon access settings (panel port and host allow-list) are NOT changed by a restore.":
      "Файл бэкапа содержит секреты подключений (ключи, пароли) — храните его в тайне. Настройки доступа к демону (порт панели и список разрешённых хостов) при восстановлении НЕ меняются.",
    "That is not a WayHop full backup.": "Это не файл полного бэкапа WayHop.",
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
    // DNS section
    "Encrypted, split, failover-aware DNS — hides lookups from the ISP, degrades gracefully":
      "Шифрованный, раздельный, отказоустойчивый DNS — прячет запросы от провайдера, деградирует плавно",
    "Encrypted, split, failover-aware DNS: hides your lookups from the ISP while a tunnel is up, and gracefully falls back to encrypted DoH over the raw WAN when every VPN is down — so DNS never goes dark.":
      "Шифрованный, раздельный, отказоустойчивый DNS: прячет ваши запросы от провайдера, пока туннель поднят, и плавно откатывается на шифрованный DoH через обычный WAN, когда все VPN упали — так DNS никогда не «гаснет».",
    "Preview the generated sing-box dns block": "Показать сгенерированный блок dns для sing-box",
    "+ Add resolver": "+ Добавить резолвер",
    "Secure defaults": "Безопасные настройки",
    "One-click encrypted DoH via the tunnel + local for in-country, leak-proof": "В один клик: шифрованный DoH через туннель + local для внутренних доменов, без утечек",
    "DNS is not managed by WayHop yet — sing-box uses its default resolver. Click “Secure defaults” for one-click encrypted, failover-aware DNS, or add resolvers manually.":
      "DNS ещё не управляется WayHop — sing-box использует резолвер по умолчанию. Нажмите «Безопасные настройки» для шифрованного отказоустойчивого DNS в один клик или добавьте резолверы вручную.",
    "Settings": "Настройки",
    "Enable DNS management": "Включить управление DNS",
    "Emit a dns block. Off keeps sing-box's default resolver (today's behaviour).": "Генерировать блок dns. Выкл — sing-box использует резолвер по умолчанию (текущее поведение).",
    "Leak protection (encrypted-only)": "Защита от утечек (только шифрование)",
    "Reject plaintext resolvers and require an encrypted default — the ISP can never read your queries, even on the WAN fallback.":
      "Запретить незашифрованные резолверы и требовать шифрованный по умолчанию — провайдер никогда не прочитает ваши запросы, даже при откате на WAN.",
    "FakeIP domain routing": "Доменная маршрутизация FakeIP",
    "Synthetic IPs so domain rules match reliably. Requires gateway/TUN mode; ignored in fast/mixed mode.":
      "Синтетические IP, чтобы доменные правила срабатывали надёжно. Требует режим шлюза/TUN; в быстром/смешанном режиме игнорируется.",
    "IP strategy": "Стратегия IP",
    "ipv4_only suppresses AAAA — pick it when your tunnels are IPv4-only to stop v6 DNS leaks.":
      "ipv4_only подавляет AAAA — выберите его, если туннели только IPv4, чтобы исключить утечки DNS по v6.",
    "Resolvers": "Резолверы",
    "No resolvers": "Нет резолверов",
    "Add an encrypted resolver (DoH/DoT), or apply the secure defaults.": "Добавьте шифрованный резолвер (DoH/DoT) или примените безопасные настройки.",
    "Default resolver (unmatched queries)": "Резолвер по умолчанию (для несовпавших запросов)",
    "(first resolver)": "(первый резолвер)",
    "Keep it encrypted for leak protection — a plaintext/local default would let a foreign lookup reach the ISP.":
      "Держите его шифрованным для защиты от утечек — незашифрованный/local по умолчанию пропустил бы внешний запрос к провайдеру.",
    "Split-DNS rules": "Правила раздельного DNS",
    "+ Add rule": "+ Добавить правило",
    "No rules — every query uses the default resolver. Add a rule to resolve chosen lists via a specific resolver (e.g. domestic sites via the local resolver, or block a list at DNS level).":
      "Правил нет — все запросы идут через резолвер по умолчанию. Добавьте правило, чтобы разрешать выбранные списки через конкретный резолвер (например, внутренние сайты через local или блокировать список на уровне DNS).",
    "DNS leak test": "Тест утечки DNS",
    "Run test": "Запустить тест",
    "Checks that lookups are private (DoH) and that no IPv6 path leaks around the tunnel. Runs the same server-side probes as Diagnostics.":
      "Проверяет, что запросы приватны (DoH) и что IPv6 не утекает мимо туннеля. Использует те же серверные проверки, что и «Диагностика».",
    "No DNS probe available on this device.": "На этом устройстве нет проверки DNS.",
    "Leak test unavailable: ": "Тест утечки недоступен: ",
    "device resolver": "резолвер устройства",
    "plaintext DNS — the ISP can read your queries": "незашифрованный DNS — провайдер может читать ваши запросы",
    "block": "блок",
    "(no match)": "(нет условия)",
    // DNS resolver modal
    "Add resolver": "Добавить резолвер",
    "Edit resolver": "Изменить резолвер",
    "Provider preset": "Готовый провайдер",
    "— choose a provider —": "— выберите провайдера —",
    "Recommended — secure, global": "Рекомендуемые — защищённые, глобальные",
    "Country-local — geo-fallback": "Локальные для страны — гео-резерв",
    "Tag": "Тег",
    "Type": "Тип",
    "Server (IP or hostname)": "Сервер (IP или имя хоста)",
    "Port (blank = default)": "Порт (пусто = по умолчанию)",
    "DoH path": "Путь DoH",
    "Ride via (detour)": "Идти через (detour)",
    "Bootstrap resolver (hostname only)": "Загрузочный резолвер (только для имени хоста)",
    "(none — server is an IP)": "(нет — сервер задан как IP)",
    "FakeIP IPv4 range": "Диапазон FakeIP IPv4",
    "FakeIP IPv6 range (optional)": "Диапазон FakeIP IPv6 (необязательно)",
    "Enabled": "Включён",
    "Tag is required": "Тег обязателен",
    "Resolver added": "Резолвер добавлен",
    "Resolver updated": "Резолвер обновлён",
    "Save": "Сохранить",
    "Cancel": "Отмена",
    // DNS rule modal
    "Add DNS rule": "Добавить правило DNS",
    "Edit DNS rule": "Изменить правило DNS",
    "Match routing lists": "Списки маршрутизации для совпадения",
    "Domain suffixes (one per line)": "Суффиксы доменов (по одному в строке)",
    "Query types (comma-separated, e.g. A,AAAA)": "Типы запросов (через запятую, напр. A,AAAA)",
    "Resolve via": "Разрешать через",
    "Block (reject)": "Блокировать (reject)",
    "Rule saved": "Правило сохранено",
    "A rule needs at least one match condition": "Правилу нужно хотя бы одно условие совпадения",
    // DNS preview + apply
    "Generated dns block": "Сгенерированный блок dns",
    "No dns block — enable DNS management first.": "Блока dns нет — сначала включите управление DNS.",
    "Close": "Закрыть",
    "Applied secure DNS defaults": "Применены безопасные настройки DNS",
    "Replace the current DNS setup with the secure defaults (encrypted DoH via the tunnel + local, leak-proof)?":
      "Заменить текущую настройку DNS безопасными значениями (шифрованный DoH через туннель + local, без утечек)?",
    "DNS API unavailable: ": "API DNS недоступен: ",
    // Native adopt (router's own DNS)
    "Router's native DNS": "Собственный DNS роутера",
    "adopted": "принято",
    "strict-order": "строгий порядок",
    "The DNS your router actually serves (dnsmasq + DoH). Preview the write-back to see the exact router commands; applying them is a manual, gated step.":
      "DNS, который реально раздаёт ваш роутер (dnsmasq + DoH). Нажмите «Показать запись», чтобы увидеть точные команды роутера; их применение — ручной, защищённый шаг.",
    "Preview write-back": "Показать запись",
    "Show the uci/dnsmasq commands that would write this back to the router (not run automatically)":
      "Показать команды uci/dnsmasq, которые запишут это обратно в роутер (не выполняются автоматически)",
    "Native DNS write-back plan": "План нативной записи DNS",
    "What writing the current native DNS back to your router would change. Nothing is applied automatically — the apply step is manual/gated.":
      "Что изменит запись текущего нативного DNS обратно в роутер. Ничего не применяется автоматически — шаг применения ручной/защищённый.",
    "uci commands": "команды uci",
    "dnsmasq.d content": "содержимое dnsmasq.d",
    "Then, to apply (user-gated):": "Затем, чтобы применить (по решению пользователя):",
    "No upstreams detected.": "Апстримы не обнаружены.",
    "via VPN": "через VPN",
    "WAN-encrypted": "шифрованный WAN",
    "geo-fallback": "гео-резерв",
    "via tunnel": "через туннель",
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
const NAV_LABELS = { dashboard: "Dashboard", server: "Set up Server", connections: "Connections", failover: "Failover", routing: "Routing", dns: "DNS", updater: "Updater", diagnostics: "Diagnostics", plugins: "Plugins", settings: "Settings" };
// Short hover explanations for each nav item (data-page -> English tooltip). Applied as the
// element's title in translateChrome so they localize alongside the labels.
const NAV_TOOLTIPS = {
  dashboard: "Overview — status, live connections, traffic, and routing-list health",
  server: "Provision a fresh server into a proxy over SSH, and manage existing ones",
  connections: "Your proxy/VPN connections — add, import, edit and test them",
  failover: "Group connections so traffic auto-switches to a healthy one",
  routing: "Send chosen domain/IP lists through a tunnel; everything else stays direct",
  dns: "Encrypted, split, failover-aware DNS — hides lookups from the ISP, degrades gracefully",
  updater: "Update the proxy cores and the panel itself",
  diagnostics: "Health checks — connectivity, DNS, IPv6, exit IP, ping/traceroute",
  plugins: "Optional features — install a plugin to add it to the menu",
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
let gdata = [];
let graphCanvas = null;
// Poll the server's rolling buffer (1 Hz). Polling rather than a persistent SSE
// keeps the connection idle between ticks, which embedded WebViews + headless
// screenshot tools require (a long-lived SSE never reaches "network idle").
let trafficInFlight = false;
let connInFlight = false; // in-flight guard for paintConnections' /api/conntrack fetch (mirrors trafficInFlight/healthInFlight) — don't stack requests on a slow link
async function pollTraffic() {
  if (trafficInFlight) return; // don't stack fetches on a stalled router — the 1 Hz interval keeps firing
  trafficInFlight = true;
  // Ask for only the last MAXG samples the graph renders, not the full 300 buffer.
  try { gdata = (await api.get("/api/traffic/recent?n=" + MAXG)).slice(-MAXG); drawGraph(); } catch (_) {}
  finally { trafficInFlight = false; }
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
  $("#foot").textContent = "wayhop " + (h.version || "");
}

/* ---------- routing ---------- */
const PAGES = {
  dashboard: { title: "Dashboard", render: renderDashboard },
  server: { title: "Set up Server", render: renderServer },
  connections: { title: "Connections", render: renderConnections },
  failover: { title: "Failover", render: renderFailover },
  routing: { title: "Routing", render: renderRouting },
  dns: { title: "DNS", render: renderDNS },
  updater: { title: "Updater", render: renderUpdater },
  diagnostics: { title: "Diagnostics", render: renderDiagnostics },
  plugins: { title: "Plugins", render: renderPlugins },
  iptv: { title: "IPTV", render: renderIptv },
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

/* ---------- Plugins (feature modules) ---------- */
// The Plugins section (P4). Lists every compiled-in feature module with an install switch. Installing
// flips config.Features[id].Enabled server-side (PUT /api/features/{id}) — a hot config flip, no
// restart — and the module's routes go live immediately. The left-menu nav item for an enabled module
// is injected by P5 (refreshPluginNav, guarded here so P4 stands alone).
async function renderPlugins(view) {
  view.appendChild(el("div", { class: "block-head" },
    el("div", {},
      el("div", { class: "ttl" }, "Plugins"),
      el("div", { class: "desc" }, "Optional features. Install one to add it to the left menu."))));
  const loading = el("div", { class: "hint", style: "margin:18px 0" }, "loading plugins…");
  view.appendChild(loading);
  let mods;
  try { mods = await api.get("/api/features"); }
  catch (e) { loading.remove(); return renderError(view, e); }
  loading.remove();
  if (!Array.isArray(mods) || !mods.length) {
    view.appendChild(el("div", { class: "card" },
      emptyState(t("No plugins available"), t("This build has no optional plugins compiled in."), "⧉")));
    return;
  }
  mods.forEach(m => view.appendChild(pluginCard(m)));
}

// pluginCard renders one module: icon, name, description, and an install switch. The switch flips the
// class in place (selfAutoToggle pattern) and refreshes the nav so the module appears/disappears.
function pluginCard(mod) {
  const card = el("div", { class: "card" });
  const sw = switchEl(mod.enabled, async node => {
    const next = !node.classList.contains("on");
    try {
      await api.put("/api/features/" + encodeURIComponent(mod.id), { enabled: next });
    } catch (e) { return toast(e.message, "err"); }
    node.classList.toggle("on", next);
    node.setAttribute("aria-checked", next ? "true" : "false");
    toast(next ? t("Installed — added to the menu") : t("Removed from the menu"), "ok");
    if (typeof refreshPluginNav === "function") refreshPluginNav(); // P5 injects/removes the nav item
  }, mod.name);
  card.appendChild(el("div", { class: "card-head" },
    el("div", { style: "display:flex;gap:13px;align-items:center;min-width:0" },
      el("span", { style: "font-size:26px;line-height:1;flex:none" }, mod.icon || "⧉"),
      el("div", { style: "min-width:0" },
        el("div", { class: "card-title" }, mod.name),
        mod.tip ? el("div", { class: "hint", style: "margin-top:2px" }, mod.tip) : null)),
    sw));
  return card;
}

// P5: dynamic left-menu injection for installed modules. Generic — the label/tooltip/icon come from
// each module's Descriptor (GET /api/features), so ANY future plugin appears with no per-module code.
// Called at boot and after every install/uninstall (pluginCard). translateChrome() skips unknown
// data-page keys, so it never clobbers these injected labels; route() picks up the .active state.
let _pluginNavMods = [];
async function refreshPluginNav() {
  try { _pluginNavMods = (await api.get("/api/features")).filter(m => m.enabled); }
  catch (_) { return; } // best-effort: a fetch failure leaves the menu unchanged
  injectPluginNav();
}
function injectPluginNav() {
  document.querySelectorAll(".nav-item.nav-plugin").forEach(n => n.remove()); // idempotent rebuild
  const anchor = document.querySelector('.nav-item[data-page="plugins"]');
  if (!anchor || !anchor.parentNode) return;
  _pluginNavMods.forEach(m => {
    const item = el("div", { class: "nav-item nav-plugin", "data-page": m.id, title: m.tip || "" },
      el("span", { class: "ico", "aria-hidden": "true" }, m.icon || "⧉"), " " + m.name);
    wireNavItem(item); // keyboard access (role/tabindex/Enter-Space) — same as static nav, so plugin pages are reachable
    anchor.parentNode.insertBefore(item, anchor); // installed modules sit just above the Plugins manager
  });
  const key = (location.hash || "#dashboard").slice(1);
  document.querySelectorAll(".nav-item").forEach(n => { const on = n.dataset.page === key; n.classList.toggle("active", on); if (on) n.setAttribute("aria-current", "page"); else n.removeAttribute("aria-current"); }); // aria-current so AT users know the current page, not just via color
}

// IPTV plugin page (U1). Manages the user's channel lists over the backend at /api/iptv/*: pick
// countries from the compiled-in catalog, and WayHop aggregates each country's open iptv-org playlist
// into one deduped, auto-refreshing M3U served at a token URL (add to a player, or open the landing +
// QR in a browser). Nav routing + this page's registration live in P5; here we fill the body.
async function renderIptv(view) {
  const loading = el("div", { class: "hint", style: "margin:18px 0" }, "loading…");
  view.appendChild(el("div", { class: "block-head" }, el("div", {},
    el("div", { class: "ttl" }, "IPTV"),
    el("div", { class: "desc" }, "Add open, auto-updating channel lists — by country, language or category — as one deduped M3U your player imports."))));
  view.appendChild(loading);
  let lists, catalog;
  try { [lists, catalog] = await Promise.all([api.get("/api/iptv/lists"), api.get("/api/iptv/catalog")]); }
  catch (e) {
    loading.remove();
    // A 404 here means the IPTV feature route isn't registered = the plugin is disabled.
    // Show a friendly pointer to Plugins instead of a raw "Error: Not Found" page.
    if (!isNetworkError(e) && /not found|404|not enabled|disabled/i.test(String(e && e.message))) {
      view.appendChild(el("div", { class: "empty" }, t("IPTV isn't enabled — turn it on under Plugins.")));
      return;
    }
    return renderError(view, e);
  }
  loading.remove();
  if (!Array.isArray(lists)) lists = []; // the API returns null (not []) when there are no lists
  const catMap = {};
  (catalog || []).forEach(c => { catMap[c.code] = c; });
  // Which exit countries do you have a WayHop tunnel for? (R1 inference; informational — routing is
  // device-gated R2/R3). Best-effort: a failure just omits the exit hints.
  let exits = [];
  try { exits = await api.get("/api/iptv/exits"); } catch (_) {}
  const exitCC = new Set((exits || []).filter(e => e.country).map(e => e.country));
  // Language/category iptv-org lists (the picker beyond countries) → a token→name map for card labels.
  let catalogKinds = [];
  try { catalogKinds = await api.get("/api/iptv/catalogs"); } catch (_) {}
  const catLabels = {};
  (catalogKinds || []).forEach(k => (k.entries || []).forEach(e => { catLabels[k.kind + ":" + e.code] = e.name; }));

  view.appendChild(el("div", { style: "display:flex;justify-content:space-between;align-items:center;gap:12px;margin:4px 0 12px;flex-wrap:wrap" },
    el("div", { style: "display:flex;gap:8px;flex-wrap:wrap" },
      el("button", { class: "btn", onclick: () => openIptvCatalog() }, "Browse public lists"),
      el("button", { class: "btn btn-sm", onclick: () => openIptvList(null, catalog) }, "+ Custom list"),
      el("button", { class: "btn btn-sm", onclick: () => importIptvList() }, "Import")),
    el("span", { class: "hint" }, t("{0} list(s)", lists.length || 0))));
  view.appendChild(el("div", { class: "hint", style: "margin:0 0 14px;max-width:72ch" },
    "Playlists link to publicly-listed free-to-air streams from the open iptv-org per-country catalogs. WayHop serves links only — it never hosts or re-streams. Availability isn't guaranteed; adult channels are excluded unless you opt in per list."));

  if (!Array.isArray(lists) || !lists.length) {
    view.appendChild(el("div", { class: "card" }, emptyState(t("No channel lists yet"),
      t("Add a list, pick one or more countries, and WayHop builds a deduped, auto-refreshing M3U you add to your player."), "📺")));
    return;
  }
  lists.forEach(l => view.appendChild(iptvListCard(l, catMap, catalog, exitCC, catLabels)));
}

// Auto-refresh cadence choices (label ↔ hours). The backend clamps to 6h..2w regardless.
const IPTV_REFRESH = [["6h", 6], ["12h", 12], ["24h", 24], ["2 days", 48], ["1 week", 168]];
function iptvRefreshLabel(h) { const o = IPTV_REFRESH.find(x => x[1] === h); return o ? o[0] : "12h"; }
function iptvLabelHours(l) { const o = IPTV_REFRESH.find(x => x[0] === l); if (o) return o[1]; const m = /^(\d+)h$/.exec(l || ""); return m ? +m[1] : 12; } // parse a synthetic "<n>h" option injected for out-of-preset stored intervals

// flagEmoji derives a flag from a 2-letter code (two regional-indicator symbols), matching the Go
// catalog — so a code missing from catMap still shows a flag.
function flagEmoji(code) {
  code = (code || "").toLowerCase();
  if (!/^[a-z]{2}$/.test(code)) return "";
  return String.fromCodePoint(0x1f1e6 + code.charCodeAt(0) - 97, 0x1f1e6 + code.charCodeAt(1) - 97);
}
function countryLabel(code, catMap) {
  const c = catMap[code];
  return (c && c.flag ? c.flag : flagEmoji(code)) + " " + (c ? c.name : code.toUpperCase());
}

function iptvListCard(l, catMap, catalog, exitCC, catLabels) {
  const card = el("div", { class: "card" });
  const url = window.location.origin + "/api/iptv/" + l.token + "/tv.m3u";
  const srcParts = (l.countries || []).map(c => countryLabel(c, catMap));
  (l.source_urls || []).forEach(u => { try { srcParts.push("🔗 " + new URL(u).host); } catch (_) { srcParts.push("🔗 custom"); } });
  (l.xtream_sources || []).forEach(x => { try { srcParts.push("🔗 " + new URL(/:\/\//.test(x.url) ? x.url : "http://" + x.url).host + " (Xtream)"); } catch (_) { srcParts.push("🔗 Xtream"); } });
  (l.catalogs || []).forEach(tok => srcParts.push("📺 " + ((catLabels && catLabels[tok]) || tok)));
  const flags = srcParts.join(" · ");
  const st = l.stats || {};
  let status;
  if (st.last_refresh > 0) {
    const parts = [t("{0} channels", st.channels || 0)];
    if (st.category_cut) parts.push(t("{0} you cut", st.category_cut));    // deliberate category curation
    const autoPruned = (st.pruned || 0) - (st.category_cut || 0);          // blocked/junk/dead (automatic)
    if (autoPruned > 0) parts.push(t("{0} pruned", autoPruned));
    if (st.adult_cut) parts.push(t("{0} adult-filtered", st.adult_cut));
    parts.push(t("refreshed {0}", timeAgo(st.last_refresh * 1000)));
    status = parts.join(" · ");
  } else if (st.last_attempt > 0) {
    // Attempted but never succeeded (e.g. every source failing behind a not-yet-up tunnel) — say so
    // honestly instead of an eternal "runs shortly"; the error detail is on its own line below.
    status = l.paused ? t("first build failed {0} — paused", timeAgo(st.last_attempt * 1000))
      : t("first build failed {0} — will retry automatically", timeAgo(st.last_attempt * 1000));
  } else {
    status = t("not refreshed yet — first build runs shortly");
  }
  const badges = el("div", { style: "display:flex;gap:6px;flex:none" },
    l.paused ? el("span", { class: "badge", style: "border-color:var(--warn,#d29922);color:var(--warn,#d29922)", title: "Auto-refresh paused" }, "paused") : null,
    l.adult ? el("span", { class: "badge", title: "Adult channels included" }, "adult") : null,
    l.probe ? el("span", { class: "badge", title: "Health-checked — dead channels dropped" }, "checked") : null);
  card.appendChild(el("div", { class: "card-head" },
    el("div", { style: "min-width:0" },
      el("div", { class: "card-title" }, l.name),
      el("div", { class: "hint", style: "margin-top:2px" }, flags)),
    badges));
  card.appendChild(el("div", { class: "hint", style: "margin:8px 0 2px" }, status));
  // Exit-match (informational): per source country, do you have a WayHop tunnel that exits there? Many
  // national streams are geo-locked, so a "none" hints why some channels may not play (routing = R2/R3).
  if (exitCC && (l.countries || []).length) {
    const parts = (l.countries || []).map(cc => (catMap[cc]?.flag || flagEmoji(cc)) + (exitCC.has(cc) ? " ✓" : " ✗"));
    const missing = (l.countries || []).some(cc => !exitCC.has(cc));
    card.appendChild(el("div", { class: "hint", style: "margin:2px 0" + (missing ? ";color:var(--warn,#d29922)" : "") },
      t("Exits: {0}", parts.join(" · ")) + (missing ? t(" — no matching exit; geo-locked channels there may not play") : t(" — all covered"))));
  }
  if (st.last_error) card.appendChild(el("div", { class: "hint", style: "color:var(--err);margin:2px 0" }, t("last error: {0}", st.last_error)));
  // Weak TV boxes / older players stall or OOM parsing a huge M3U — the router is fine, but the DEVICE
  // that imports the token URL isn't. Warn (don't truncate) so the user can cut categories if needed.
  if ((st.channels || 0) > IPTV_BIG_LIST) card.appendChild(el("div", { class: "hint", style: "color:var(--warn,#d29922);margin:2px 0" },
    t("⚠ {0} channels — some TV boxes/players load large lists slowly; cut categories to trim", st.channels)));
  card.appendChild(el("pre", { class: "wr-console", style: "max-height:56px;margin:8px 0" }, url));
  card.appendChild(el("div", { style: "display:flex;gap:8px;flex-wrap:wrap" },
    // "N new — review": categories that appeared upstream since setup, awaiting a keep/cut decision.
    (l.new_categories && l.new_categories.length)
      ? el("button", { class: "btn btn-sm", style: "border-color:var(--warn,#d29922);color:var(--warn,#d29922);font-weight:600", onclick: () => reviewIptvList(l) },
          t("⚑ {0} new — review", l.new_categories.length))
      : null,
    el("button", { class: "btn btn-sm", onclick: () => copyText(url) }, "Copy URL"),
    el("button", { class: "btn btn-sm", onclick: () => iptvQR(l) }, "QR"),
    el("button", { class: "btn btn-sm", onclick: () => exportIptvList(l) }, "⤓ Export"),
    el("button", { class: "btn btn-sm", onclick: () => dupIptvList(l) }, "⎘ Duplicate"),
    el("button", { class: "btn btn-sm", onclick: e => refreshIptvList(l, e.target) }, t("↻ Update now")),
    el("button", { class: "btn btn-sm", onclick: () => pauseIptvList(l) }, l.paused ? "▶ Resume" : "⏸ Pause"),
    el("button", { class: "btn btn-sm", onclick: () => openIptvList(l, catalog) }, "Edit"),
    el("button", { class: "btn btn-danger btn-sm", onclick: () => delIptvList(l) }, "Delete")));
  return card;
}

// countryPicker: a filterable checkbox list over the whole catalog with a live selected-count. Mutates
// the passed `selected` Set; returns the wrapper element.
// openIptvCatalog is the public-lists browser — modelled on the Routing preset catalog (openRoutingCatalog):
// a searchable catalog of ready-made iptv-org lists (per-country, per-language, per-category), grouped
// with a type badge + description and an "Added"/"+ Add" control. "+ Add" creates a first-class IPTV
// list from that single source (its own token URL, auto-refresh, edit/delete) — exactly like adding a
// routing list from a preset. Building a CUSTOM combined list stays on "+ Add list" (openIptvList).
async function openIptvCatalog() {
  let countries, kinds, lists;
  try { [countries, kinds, lists] = await Promise.all([api.get("/api/iptv/catalog"), api.get("/api/iptv/catalogs"), api.get("/api/iptv/lists")]); }
  catch (e) { return toast(e.message, "err"); }
  // Which sources are already covered by an existing list → show "Added" instead of "+ Add".
  const have = new Set();
  (lists || []).forEach(l => { (l.countries || []).forEach(c => have.add("country:" + c)); (l.catalogs || []).forEach(tok => have.add(tok)); });
  // Build the grouped entries. key = the dedup key; name = display; the POST body creates the list.
  const groups = [{
    label: t("Countries"), badge: "country", desc: t("Free-to-air channels in this country"),
    entries: (countries || []).map(c => ({ key: "country:" + c.code, name: (c.flag ? c.flag + " " : "") + c.name, plain: c.name, body: { name: c.name, countries: [c.code] } })),
  }];
  // Per-kind group label + description (regions/providers added alongside languages/categories).
  const kindGroup = {
    language: ["Languages", "Channels in this language"],
    category: ["Categories", "Channels in this category"],
    region: ["Regions", "Channels across this whole region — large lists; trim categories if your player struggles"],
    provider: ["Providers", "A curated free-to-air provider playlist"],
  };
  (kinds || []).forEach(k => {
    const g = kindGroup[k.kind] || [k.label, ""];
    groups.push({
      label: t(g[0]), badge: k.kind, desc: t(g[1]),
      entries: (k.entries || []).map(e => ({ key: k.kind + ":" + e.code, name: e.name, plain: e.name, body: { name: e.name, catalogs: [k.kind + ":" + e.code] } })),
    });
  });

  const filter = el("input", { placeholder: "Filter…", "aria-label": "Filter", style: "width:100%;margin-bottom:10px" });
  const listWrap = el("div", {});
  const render = () => {
    listWrap.innerHTML = "";
    const q = filter.value.trim().toLowerCase();
    groups.forEach(g => {
      const matches = g.entries.filter(e => !q || e.plain.toLowerCase().includes(q));
      if (!matches.length) return;
      listWrap.appendChild(el("div", { class: "card-title", style: "margin:10px 0 6px" }, g.label));
      matches.forEach(e => {
        const act = have.has(e.key)
          ? el("span", { class: "pill ok", style: "margin:0" }, el("span", { class: "dot" }), "Added")
          : el("button", { class: "btn btn-sm btn-primary", onclick: ev => addIptvCatalogEntry(e, ev.target, back, have) }, "+ Add");
        listWrap.appendChild(el("div", { class: "conn" },
          el("div", { class: "body" },
            el("div", { class: "name" }, e.name, el("span", { class: "badge proto" }, g.badge)),
            el("div", { class: "sub" }, el("span", { class: "addr" }, g.desc))),
          el("div", { class: "acts" }, act)));
      });
    });
    i18nApply(listWrap);
  };
  render();
  filter.addEventListener("input", render);
  const back = modal({ title: "Public channel lists", body: el("div", {}, filter, listWrap) });
}

// addIptvCatalogEntry creates a single-source IPTV list from a catalog entry (mirrors routing's
// addPreset): POST the list, then re-render so it shows in the user's lists. The catalog closes on add
// (like the routing preset catalog); re-open to add more.
async function addIptvCatalogEntry(e, btn, back, have) {
  if (btn) { btn.disabled = true; btn.textContent = t("Adding…"); }
  try { await api.post("/api/iptv/lists", e.body); }
  catch (err) { if (btn) { btn.disabled = false; btn.textContent = t("+ Add"); } return toast(err.message, "err"); }
  if (have) have.add(e.key);
  if (back) back.remove();
  route();
  toast(t("List added — it builds shortly; add the link to your player"), "ok");
}

function countryPicker(catalog, selected) {
  const listBox = el("div", { class: "wr-console", style: "max-height:230px;overflow:auto;padding:6px;text-align:left" });
  const rows = [];
  const count = el("div", { class: "hint", style: "margin:6px 0 4px" });
  const updateCount = () => { count.textContent = t("{0} selected", selected.size); };
  (catalog || []).forEach(c => {
    const cb = el("input", { type: "checkbox", checked: selected.has(c.code) ? "checked" : null });
    cb.addEventListener("change", () => { cb.checked ? selected.add(c.code) : selected.delete(c.code); updateCount(); });
    const row = el("label", { class: "check", style: "display:flex;gap:8px;align-items:center;padding:3px 4px", "data-q": (c.name + " " + c.code).toLowerCase() },
      cb, el("span", {}, (c.flag ? c.flag + " " : "") + c.name));
    rows.push(row);
    listBox.appendChild(row);
  });
  const filter = el("input", { type: "text", placeholder: "Filter countries…", "aria-label": "Filter countries", style: "width:100%" });
  filter.addEventListener("input", () => {
    const q = filter.value.trim().toLowerCase();
    rows.forEach(r => { r.style.display = !q || r.dataset.q.includes(q) ? "" : "none"; });
  });
  updateCount();
  return el("div", {}, filter, count, listBox);
}

// JUNK_CATEGORIES are the low-value buckets the "Cut common junk" shortcut (and the smart default for
// a brand-new list) switch off — matched case-insensitively against the source's group-titles.
const JUNK_CATEGORIES = ["undefined", "uncategorized", "religious", "legislative", "shop", "shopping"];
// Soft threshold above which the card warns that weak TV boxes/players may struggle with the M3U size.
const IPTV_BIG_LIST = 8000;

async function openIptvList(list, catalog) {
  const editing = !!list;
  const selected = new Set((list && list.countries) || []);
  const name = fInput("iptv-name", "Name (optional)", (list && list.name) || "", { ph: "defaults to the country names" });
  const picker = countryPicker(catalog, selected);
  // A list's iptv-org language/category lists ("kind:code" tokens) are added via the public-lists
  // catalog browser (openIptvCatalog); here we only PRESERVE what the list already has across an edit
  // so a plain edit never drops them.
  const catalogSet = new Set((list && list.catalogs) || []);
  const readCatalogs = () => [...catalogSet];
  // Owner-supplied provider / custom M3U URLs (one per line). Optional — a list can be countries, URLs,
  // or both. Fetched through the same SSRF-guarded client, links-only.
  const sourcesBox = el("textarea", { id: "iptv-sources", rows: "2", placeholder: t("{0} (one per line)", "https://your-provider.example/playlist.m3u"), style: "width:100%" },
    ((list && list.source_urls) || []).join("\n"));
  const readSources = () => $("#iptv-sources").value.split("\n").map(s => s.trim()).filter(Boolean);
  // Xtream Codes accounts (host + username + password): WayHop builds the get.php M3U and fetches it like
  // a custom source. Credentials stay on the router; they never appear in a user-facing error or a log.
  const xtreamRows = el("div", { id: "iptv-xtream", style: "display:flex;flex-direction:column;gap:6px" });
  const addXtreamRow = x => {
    const host = el("input", { class: "iptv-xt-host", "aria-label": "Xtream host", placeholder: "host or http://host:port", value: (x && x.url) || "", style: "flex:2;min-width:130px" });
    const user = el("input", { class: "iptv-xt-user", "aria-label": "Xtream username", placeholder: "username", value: (x && x.username) || "", style: "flex:1;min-width:90px" });
    const pass = el("input", { class: "iptv-xt-pass", type: "password", "aria-label": "Xtream password", placeholder: "password", value: (x && x.password) || "", style: "flex:1;min-width:90px" });
    const row = el("div", { class: "iptv-xt-row", style: "display:flex;gap:6px;flex-wrap:wrap;align-items:center" }, host, user, pass);
    row.appendChild(el("button", { class: "btn btn-sm btn-ghost", type: "button", title: t("Remove account"), "aria-label": t("Remove account"), onclick: () => row.remove() }, "✕"));
    xtreamRows.appendChild(row);
  };
  ((list && list.xtream_sources) || []).forEach(addXtreamRow);
  const addXtreamBtn = el("button", { class: "btn btn-sm", type: "button", onclick: () => addXtreamRow() }, "+ Add Xtream account");
  const readXtream = () => [...xtreamRows.querySelectorAll(".iptv-xt-row")].map(r => ({
    url: r.querySelector(".iptv-xt-host").value.trim(),
    username: r.querySelector(".iptv-xt-user").value.trim(),
    password: r.querySelector(".iptv-xt-pass").value.trim(),
  })).filter(x => x.url || x.username || x.password);
  const adult = fCheck("iptv-adult", "Include adult channels — off by default", list && list.adult);
  const probe = fCheck("iptv-probe", "Check availability every refresh and drop dead channels (the automatic interval checker — slower)", list && list.probe);
  const strict = fCheck("iptv-strict", "Hold new categories for review before adding them to the box", list && list.strict_new);
  const cadence = fSelect("iptv-refresh", "Auto-refresh", IPTV_REFRESH.map(x => x[0]), iptvRefreshLabel((list && list.refresh_hours) || 12));
  const storedHrs = list && list.refresh_hours;
  if (storedHrs && !IPTV_REFRESH.some(x => x[1] === storedHrs)) {
    // Preserve an out-of-preset interval (e.g. 72h/336h set via import or the API — backend accepts 6h..2w)
    // so opening + saving the modal without touching cadence doesn't silently reset it. Mirrors openRoutingList.
    const csel = cadence.querySelector("select");
    csel.appendChild(el("option", { value: storedHrs + "h" }, t("Every {0} hours", storedHrs)));
    csel.value = storedHrs + "h";
  }
  const block = el("textarea", { id: "iptv-block", rows: "3", placeholder: "one tvg-id or exact stream URL per line", style: "width:100%" },
    ((list && list.blocklist) || []).join("\n"));
  const adv = el("details", { style: "margin-top:8px" },
    el("summary", { class: "hint", style: "cursor:pointer;font-weight:600" }, "Advanced — block individual channels"),
    el("div", { class: "field", style: "margin-top:6px" }, el("label", {}, "Blocklist"), block));

  // ---- Channel curation (categories) ----
  // excludeSet holds the LOWERCASED category names to drop (exclude-list = auto-update safe: a category
  // you keep keeps filling with new channels on refresh; only what you switch off stays off).
  const excludeSet = new Set(((list && list.exclude_categories) || []).map(s => s.toLowerCase()));
  // blockSet holds per-channel exclusions (tvg-id or URL) — the drill-down un-ticks feed it; it merges
  // with the Advanced blocklist textarea on save. origBlock lets us tell drill-down edits apart from
  // manual textarea edits so neither clobbers the other.
  const origBlock = new Set((list && list.blocklist) || []);
  const blockSet = new Set(origBlock);
  // includeSet holds per-channel RESCUES (tvg-ids kept even though their category is cut). The
  // drill-down is its only editor, so [...includeSet] round-trips cleanly on save.
  const includeSet = new Set((list && list.channel_include) || []);
  // pinnedList is ORDERED (pin priority) — pinned categories lead the served M3U in this order. It's the
  // source of truth (preserves a pinned category even if it's transiently absent from a later preview).
  let pinnedList = ((list && list.pinned_categories) || []).slice();
  const isPinned = n => pinnedList.some(p => p.toLowerCase() === n.toLowerCase());
  const togglePin = n => { isPinned(n) ? (pinnedList = pinnedList.filter(p => p.toLowerCase() !== n.toLowerCase())) : pinnedList.push(n); };
  let previewCats = null; // [{name,count}] once previewed
  let previewTotal = 0;
  const totalBanner = el("div", { class: "hint", style: "font-weight:600;margin:8px 0 4px" });
  const catPanel = el("div", {});
  const previewBtn = el("button", { class: "btn btn-sm", type: "button" }, "🔎 Preview & choose channels");

  function recomputeTotal() {
    if (!previewCats) { totalBanner.textContent = ""; return; }
    let n = previewTotal;
    for (const c of previewCats) if (excludeSet.has(c.name.toLowerCase())) n -= c.count;
    n += includeSet.size; // per-channel rescues (only exist inside cut categories → add them back)
    n -= [...blockSet].filter(k => !origBlock.has(k)).length; // drill-down blocklist additions (all in kept categories)
    if (n < 0) n = 0;
    totalBanner.textContent = t("You'll get about {0} of {1} channels — the rest stay off.", n, previewTotal);
  }
  function renderCats() {
    catPanel.innerHTML = "";
    if (!previewCats) return;
    if (!previewCats.length) { catPanel.appendChild(el("div", { class: "hint" }, "No channels found for these countries.")); return; }
    catPanel.appendChild(el("div", { style: "display:flex;gap:8px;flex-wrap:wrap;margin:6px 0" },
      el("button", { class: "btn btn-sm", type: "button", onclick: () => { excludeSet.clear(); renderCats(); } }, "Keep all"),
      el("button", { class: "btn btn-sm", type: "button", onclick: () => { previewCats.forEach(c => { if (JUNK_CATEGORIES.includes(c.name.toLowerCase())) excludeSet.add(c.name.toLowerCase()); }); renderCats(); } }, "Cut common junk")));
    const box = el("div", { class: "wr-console", style: "max-height:300px;overflow:auto;padding:6px;text-align:left" });
    // Pinned categories lead the panel (in pin order), then the rest in the previewed (count-desc) order.
    const pinnedFirst = pinnedList.map(p => previewCats.find(c => c.name.toLowerCase() === p.toLowerCase())).filter(Boolean);
    const displayCats = [...pinnedFirst, ...previewCats.filter(c => !isPinned(c.name))];
    displayCats.forEach((c, ci) => {
      const key = c.name.toLowerCase();
      // id keyed by INDEX, not a slug of the name — compound names ("General;News" vs "General/News")
      // slug to the same string and a label click would then toggle the wrong category.
      const cb = el("input", { type: "checkbox", id: "iptv-cat-" + ci, checked: excludeSet.has(key) ? null : "checked" });
      const sub = el("div", { id: "iptv-sub-" + ci, style: "margin:2px 0 6px 24px;display:none" }); // lazy per-channel drill-down
      let loaded = false;
      const arrow = el("span", { style: "cursor:pointer;width:14px;display:inline-block;user-select:none;color:var(--muted)", title: "Show channels", "aria-expanded": "false", "aria-controls": "iptv-sub-" + ci }, "▸");
      const collapse = () => { sub.style.display = "none"; sub.innerHTML = ""; arrow.textContent = "▸"; arrow.setAttribute("aria-expanded", "false"); loaded = false; };
      cb.addEventListener("change", () => {
        cb.checked ? excludeSet.delete(key) : excludeSet.add(key);
        recomputeTotal();
        if (sub.style.display !== "none") collapse(); // category kept/cut flipped → drop the now-stale drill-down
      });
      a11yClick(arrow, async () => {
        if (sub.style.display !== "none") { collapse(); return; }
        sub.style.display = ""; arrow.textContent = "▾"; arrow.setAttribute("aria-expanded", "true");
        if (!loaded) { loaded = true; await loadCategoryChannels(c.name, sub); }
      }, t("Show channels in {0}", c.name));
      // 📌 pin toggle — a pinned category leads the served M3U (bright = pinned, dim = not).
      const pin = el("span", { style: "cursor:pointer;user-select:none;flex:none;font-size:12px;opacity:" + (isPinned(c.name) ? "1" : "0.3"), title: isPinned(c.name) ? t("Unpin from top") : t("Pin to top"), "aria-pressed": isPinned(c.name) ? "true" : "false" }, "📌");
      a11yClick(pin, () => { togglePin(c.name); renderCats(); }, isPinned(c.name) ? t("Unpin {0}", c.name) : t("Pin {0}", c.name));
      // Row is a div (not a label) so clicking the arrow doesn't toggle the checkbox.
      box.appendChild(el("div", { style: "display:flex;align-items:center;justify-content:space-between;gap:8px;padding:3px 4px" },
        el("span", { style: "display:flex;gap:6px;align-items:center;min-width:0" },
          arrow, cb, el("label", { for: cb.id, style: "cursor:pointer" }, c.name)),
        el("span", { style: "display:flex;gap:8px;align-items:center;flex:none" }, pin, el("span", { class: "hint" }, String(c.count)))));
      box.appendChild(sub);
    });
    catPanel.appendChild(box);
    recomputeTotal();
  }
  // setHealthStatus paints a channel's reachability marker: green ✓ alive, amber ◐ geo-blocked, red ✗ dead.
  function setHealthStatus(span, status) {
    // Expose the marker's meaning to AT (role=img + aria-label), not just a color/glyph + title — the
    // span sits inside a <label class="check">, so the bare ✓/◐/✗ glyph would otherwise be all a reader gets.
    span.removeAttribute("role"); span.removeAttribute("aria-label");
    const mark = (txt) => { span.title = txt; span.setAttribute("role", "img"); span.setAttribute("aria-label", txt); };
    if (status === "alive") { span.textContent = "✓"; span.style.color = "var(--accent,#3fb950)"; mark(t("Reachable")); }
    else if (status === "geo") { span.textContent = "◐"; span.style.color = "var(--warn,#d29922)"; mark(t("Geo-blocked — needs an in-country exit")); }
    else if (status) { span.textContent = "✗"; span.style.color = "var(--err,#d9534f)"; mark(t("Unreachable")); }
    else { span.textContent = ""; span.title = ""; }
  }
  // loadCategoryChannels lazily fetches one category's capped channel page and renders per-channel
  // checkboxes (checked = kept; un-ticking adds the tvg-id/URL to blockSet) + an on-demand "Check
  // availability" button that probes them live (POST preview/health) and paints ✓/◐/✗ per channel.
  async function loadCategoryChannels(catName, box) {
    box.appendChild(el("div", { class: "hint" }, "loading channels…"));
    const req = { countries: [...selected], catalogs: readCatalogs(), source_urls: readSources(), adult: $("#iptv-adult").checked, category: catName, limit: 100 };
    let res;
    try { res = await api.post("/api/iptv/preview/channels", req); }
    catch (e) { box.innerHTML = ""; box.appendChild(el("div", { class: "hint", style: "color:var(--err)" }, e.message)); return; }
    box.innerHTML = "";
    const items = res.items || [];
    // Dual meaning by parent-category state: in a KEPT category a checkbox = "in the list" (un-tick →
    // blocklist); in a CUT category the whole category is dropped, so checkboxes default OFF and
    // checking one RESCUES it via channel_include (tvg-id only — a channel without one can't be rescued).
    const rescueMode = excludeSet.has(catName.toLowerCase());
    const statusEls = {}; // key -> status span, for the health check to paint into
    if (rescueMode) {
      box.appendChild(el("div", { class: "hint", style: "margin:0 0 4px;color:var(--warn,#d29922)" },
        "This category is cut — check a channel to keep it anyway."));
    }
    const checkBtn = el("button", { class: "btn btn-sm", type: "button" }, "🔍 Check availability");
    checkBtn.addEventListener("click", async () => {
      const prev = checkBtn.textContent; checkBtn.disabled = true; checkBtn.textContent = "Checking…";
      try {
        const h = await api.post("/api/iptv/preview/health", { ...req, limit: 50 });
        (h.items || []).forEach(it => { const k = it.tvg_id || it.url; if (statusEls[k]) setHealthStatus(statusEls[k], it.status); });
      } catch (e) { toast(e.message, "err"); }
      finally { checkBtn.disabled = false; checkBtn.textContent = prev; }
    });
    box.appendChild(el("div", { style: "display:flex;align-items:center;gap:8px;margin:2px 0 4px" },
      checkBtn, el("span", { class: "hint" }, res.total > items.length ? t("{0} of {1} channels", items.length, res.total) : t("{0} channels", items.length))));
    items.forEach(it => {
      const k = it.tvg_id || it.url;
      let cb;
      if (rescueMode) {
        // Rescue: default OFF; checking adds the tvg-id to channel_include. No tvg-id → can't rescue.
        const canRescue = !!it.tvg_id;
        cb = el("input", { type: "checkbox", checked: (canRescue && includeSet.has(it.tvg_id)) ? "checked" : null, disabled: canRescue ? null : "disabled" });
        cb.addEventListener("change", () => { cb.checked ? includeSet.add(it.tvg_id) : includeSet.delete(it.tvg_id); recomputeTotal(); });
      } else {
        // Normal: default ON; un-ticking blocklists the channel by tvg-id/URL.
        cb = el("input", { type: "checkbox", checked: blockSet.has(k) ? null : "checked" });
        cb.addEventListener("change", () => { cb.checked ? blockSet.delete(k) : blockSet.add(k); recomputeTotal(); });
      }
      const statusSpan = el("span", { style: "width:14px;text-align:center;flex:none" });
      setHealthStatus(statusSpan, it.status); // preview/channels may already carry a status
      statusEls[k] = statusSpan;
      // Logo thumbnail. CSP allows external images (no default-src/img-src), but we lazy-load and send
      // no referrer (don't leak the panel URL to the logo host); a broken logo removes itself, and a
      // fixed-width slot keeps the rows aligned whether or not a logo exists.
      const logoSlot = el("span", { style: "width:18px;height:18px;flex:none;display:inline-block" });
      // Only accept http(s) logo URLs — it.logo comes from an untrusted remote playlist; reject
      // javascript:/data:/other schemes before they reach the <img src> DOM sink.
      if (it.logo && /^https?:\/\//i.test(it.logo)) {
        logoSlot.appendChild(el("img", {
          src: it.logo, width: 18, height: 18, loading: "lazy", referrerpolicy: "no-referrer", alt: "",
          style: "width:18px;height:18px;object-fit:contain;border-radius:3px",
          onerror: function () { this.remove(); },
        }));
      }
      box.appendChild(el("label", { class: "check", style: "display:flex;gap:7px;align-items:center;padding:2px 2px" },
        cb, statusSpan, logoSlot, el("span", { style: "overflow:hidden;text-overflow:ellipsis;white-space:nowrap" }, it.name)));
    });
    if (!items.length) box.appendChild(el("div", { class: "hint" }, "No channels."));
  }
  previewBtn.addEventListener("click", async () => {
    const countries = [...selected], sources = readSources();
    if (!countries.length && !readCatalogs().length && !sources.length) return toast(t("Pick a country or add a provider URL first"), "err");
    const prev = previewBtn.textContent;
    previewBtn.disabled = true; previewBtn.textContent = t("Loading channels…");
    try {
      const pr = await api.post("/api/iptv/preview", { countries, catalogs: readCatalogs(), source_urls: sources, adult: $("#iptv-adult").checked });
      previewCats = pr.categories || [];
      previewTotal = pr.total || 0;
      // Smart default: only for a brand-new list with no prior curation — pre-cut obvious junk so the
      // user subtracts a couple more rather than staring at 1471 channels of shopping/legislative/etc.
      if (!editing && excludeSet.size === 0) {
        previewCats.forEach(c => { if (JUNK_CATEGORIES.includes(c.name.toLowerCase())) excludeSet.add(c.name.toLowerCase()); });
      }
      renderCats();
      if (pr.errors && pr.errors.length) toast(t("{0} source(s) failed to load — showing the rest", pr.errors.length), "err");
    } catch (e) { toast(e.message, "err"); }
    finally { previewBtn.disabled = false; previewBtn.textContent = prev; }
  });
  const chooseSection = el("div", { class: "field" }, el("label", {}, "Channels"),
    el("div", { class: "hint", style: "margin-bottom:6px" },
      "Preview what's inside and switch off whole categories you don't want (shopping, religious, …). Channels in the categories you keep update automatically."),
    previewBtn, totalBanner, catPanel);

  const save = el("button", { class: "btn btn-primary" }, editing ? "Save" : "Add list");
  const back = modal({
    title: editing ? "Edit channel list" : "Add channel list",
    body: el("div", {}, name,
      el("div", { class: "field" }, el("label", {}, "Countries"),
        el("div", { class: "hint", style: "margin-bottom:6px" },
          "Channels come from the open iptv-org project — one live, auto-updating list per country."),
        picker),
      el("div", { class: "field" }, el("label", {}, "Provider / custom playlist URL"),
        el("div", { class: "hint", style: "margin-bottom:6px" },
          "Optional: paste your own provider's M3U URL (one per line). Fetched securely; WayHop serves the links, never the stream."),
        sourcesBox),
      el("div", { class: "field" }, el("label", {}, "Xtream Codes account"),
        el("div", { class: "hint", style: "margin-bottom:6px" },
          "Optional: your provider's Xtream login (host + username + password). WayHop builds the playlist for you; the credentials stay on your router."),
        xtreamRows, addXtreamBtn),
      el("div", { style: "display:flex;flex-direction:column;gap:8px;margin:10px 0" }, adult, probe, strict),
      cadence, chooseSection, adv),
    footer: [el("button", { class: "btn btn-ghost", onclick: () => back.close() }, "Cancel"), save],
  });
  save.addEventListener("click", async () => {
    const countries = [...selected], sources = readSources(), xtream = readXtream(), catalogs = readCatalogs();
    if (!countries.length && !catalogs.length && !sources.length && !xtream.length) return toast(t("Add at least one country or a provider URL"), "err");
    // exclude_categories: derived from the previewed checkboxes when the user previewed; otherwise the
    // list's existing curation is preserved untouched (so a plain edit never wipes it).
    let excludeCategories;
    if (previewCats) {
      excludeCategories = previewCats.filter(c => excludeSet.has(c.name.toLowerCase())).map(c => c.name);
      // Preserve deliberately-cut categories that are transiently ABSENT from this preview (upstream
      // outage/rename), so a category you cut never silently un-cuts and floods the box on its return.
      const inPreview = new Set(previewCats.map(c => c.name.toLowerCase()));
      ((list && list.exclude_categories) || []).forEach(n => { if (!inPreview.has(n.toLowerCase())) excludeCategories.push(n); });
    } else {
      excludeCategories = ((list && list.exclude_categories) || []);
    }
    // blocklist: the manual Advanced textarea is the base; drill-down additions (blockSet − orig) are
    // added and drill-down removals (orig − blockSet) are removed, so the two editors don't clobber.
    const blockOut = new Set($("#iptv-block").value.split("\n").map(s => s.trim()).filter(Boolean));
    blockSet.forEach(k => { if (!origBlock.has(k)) blockOut.add(k); });          // drill-down added
    origBlock.forEach(k => { if (!blockSet.has(k)) blockOut.delete(k); });       // drill-down removed
    const body = {
      name: $("#iptv-name").value.trim(),
      countries,
      catalogs,
      source_urls: sources,
      xtream_sources: xtream,
      adult: $("#iptv-adult").checked,
      probe: $("#iptv-probe").checked,
      strict_new: $("#iptv-strict").checked,
      refresh_hours: iptvLabelHours($("#iptv-refresh").value),
      blocklist: [...blockOut],
      exclude_categories: excludeCategories,
      channel_include: [...includeSet],
      pinned_categories: pinnedList,
    };
    save.disabled = true;
    try {
      if (editing) await api.put("/api/iptv/lists/" + encodeURIComponent(list.id), body);
      else await api.post("/api/iptv/lists", body);
    } catch (e) { save.disabled = false; return toast(e.message, "err"); }
    back.close();
    toast(editing ? t("Saved — your box updates itself; the same link keeps working") : t("List added — it builds shortly; add the link to your player"), "ok");
    route();
  });
}

async function iptvQR(l) {
  const url = window.location.origin + "/api/iptv/" + l.token + "/tv.m3u";
  const qrWrap = el("div", { class: "qr-wrap" }, el("div", { class: "hint" }, "rendering…"));
  modal({
    title: l.name,
    body: el("div", {},
      el("div", { class: "hint", style: "margin-bottom:12px" }, "Scan in your IPTV player (TiviMate, IPTV Smarters, VLC, Kodi), or copy the URL."),
      qrWrap,
      el("pre", { class: "wr-console", style: "max-height:56px;margin-top:10px" }, url),
      el("div", { style: "display:flex;gap:10px;margin-top:10px" },
        el("button", { class: "btn btn-sm", onclick: () => copyText(url) }, "Copy URL"),
        el("a", { class: "btn btn-sm", href: url + "?web=1", target: "_blank", rel: "noopener" }, "Open landing page"))),
  });
  try { const img = await qrImg(url, 280); qrWrap.innerHTML = ""; qrWrap.appendChild(img); }
  catch (_) { qrWrap.innerHTML = ""; qrWrap.appendChild(el("div", { class: "hint", style: "color:var(--err)" }, "QR rendering failed")); }
}

async function delIptvList(l) {
  if (!await modalConfirm(t("Delete list \"{0}\"? Its playlist URL stops working immediately.", l.name))) return;
  try { await api.del("/api/iptv/lists/" + encodeURIComponent(l.id)); }
  catch (e) { return toast(e.message, "err"); }
  toast(t("List deleted"), "ok");
  route();
}

// refreshIptvList forces an immediate rebuild (POST …/refresh → 202, build runs in the background,
// re-checking availability when the list's health-check is on). The card re-renders shortly after so
// the fresh "refreshed …" status shows.
async function refreshIptvList(l, btn) {
  if (btn) { btn.disabled = true; btn.textContent = t("Updating…"); }
  try { await api.post("/api/iptv/lists/" + encodeURIComponent(l.id) + "/refresh", {}); }
  catch (e) { if (btn) { btn.disabled = false; btn.textContent = t("↻ Update now"); } return toast(e.message, "err"); }
  toast(t("Updating in the background — your box gets the fresh list within a minute"), "ok");
  setTimeout(route, 4000); // give the background build a moment, then re-render the fresh stats
}

// pauseIptvList toggles a list's auto-refresh (POST …/pause). Paused keeps the token serving the
// last-good playlist (players unaffected) but stops the scheduled rebuild — a flaky source or
// flash-wear can be halted without deleting the list, which would change the URL and break players.
async function pauseIptvList(l) {
  try { await api.post("/api/iptv/lists/" + encodeURIComponent(l.id) + "/pause", { paused: !l.paused }); }
  catch (e) { return toast(e.message, "err"); }
  toast(l.paused ? t("Auto-refresh resumed") : t("Auto-refresh paused"), "ok");
  route();
}

// reviewIptvList opens the "new categories" review: each category that appeared upstream since setup
// gets a Keep (default — auto-update safe) / Cut choice; Apply POSTs {keep,cut} to …/review (cut →
// added to the list's exclusions) and re-renders (the badge clears).
// exportIptvList shows a list's portable curation JSON (GET …/export) to copy or download; importing
// it on any WayHop recreates the list.
async function exportIptvList(l) {
  let blob;
  try { blob = await api.get("/api/iptv/lists/" + encodeURIComponent(l.id) + "/export"); }
  catch (e) { return toast(e.message, "err"); }
  const json = JSON.stringify(blob, null, 2);
  const fname = ((l.name || "iptv-list").replace(/[^\w.-]+/g, "_")) + ".json";
  modal({
    title: t("Export — {0}", l.name),
    body: el("div", {},
      el("div", { class: "hint", style: "margin-bottom:8px" }, "Copy or download this to back up or share the list's setup. Import recreates the list on any WayHop (with a fresh URL)."),
      el("textarea", { rows: "12", readonly: "readonly", style: "width:100%;font-family:monospace;font-size:12px" }, json),
      el("div", { style: "display:flex;gap:10px;margin-top:10px" },
        el("button", { class: "btn btn-sm", onclick: () => copyText(json) }, "Copy"),
        el("button", { class: "btn btn-sm", onclick: () => downloadText(fname, json) }, "⤓ Download"))),
  });
}

// importIptvList pastes an exported curation JSON and creates a NEW list from it (POST /lists, which
// validates + mints a fresh id/token).
function importIptvList() {
  const ta = el("textarea", { rows: "10", placeholder: "Paste an exported list JSON here", style: "width:100%;font-family:monospace;font-size:12px" });
  const imp = el("button", { class: "btn btn-primary" }, "Import");
  const back = modal({
    title: "Import a list",
    body: el("div", {},
      el("div", { class: "hint", style: "margin-bottom:8px" }, "Paste a list exported from WayHop. It's added as a new list with its own URL."),
      ta),
    footer: [el("button", { class: "btn btn-ghost", onclick: () => back.close() }, "Cancel"), imp],
  });
  imp.addEventListener("click", async () => {
    let obj;
    try { obj = JSON.parse(ta.value); } catch (_) { return toast(t("That isn't valid JSON"), "err"); }
    imp.disabled = true;
    try { await api.post("/api/iptv/lists", obj); }
    catch (e) { imp.disabled = false; return toast(e.message, "err"); }
    back.close();
    toast(t("List imported"), "ok");
    route();
  });
}

// dupIptvList clones a list — GET its portable curation, then POST it back as a new list (fresh
// id/token), so making a near-identical list (different country, adult on, …) doesn't mean redoing
// every country + category pick from scratch. The export payload's json fields match listInput.
async function dupIptvList(l) {
  let blob;
  try { blob = await api.get("/api/iptv/lists/" + encodeURIComponent(l.id) + "/export"); }
  catch (e) { return toast(e.message, "err"); }
  blob.name = (l.name || "List") + " (copy)";
  try { await api.post("/api/iptv/lists", blob); }
  catch (e) { return toast(e.message, "err"); }
  toast(t("List duplicated"), "ok");
  route();
}

async function reviewIptvList(l) {
  const cats = l.new_categories || [];
  if (!cats.length) return;
  const keepSet = new Set(cats); // default: keep everything (new channels flow in)
  const setters = [];            // per-row set(keep) so the bulk buttons can drive every checkbox
  const rows = cats.map(c => {
    const cb = el("input", { type: "checkbox", checked: "checked" });
    const tag = el("span", { class: "hint", style: "margin-left:auto" }, "keep");
    const sync = () => { tag.textContent = cb.checked ? "keep" : "cut"; tag.style.color = cb.checked ? "" : "var(--err,#d9534f)"; };
    cb.addEventListener("change", () => { cb.checked ? keepSet.add(c) : keepSet.delete(c); sync(); });
    setters.push(keep => { cb.checked = keep; keep ? keepSet.add(c) : keepSet.delete(c); sync(); });
    return el("label", { class: "check", style: "display:flex;gap:8px;align-items:center;padding:4px 2px" }, cb, el("span", {}, c), tag);
  });
  const setAll = keep => setters.forEach(s => s(keep));
  // Bulk actions — adding a big country can surface dozens of new categories at once, so single-clicking
  // each is untenable; mirror the category-picker's Keep-all / Cut-common-junk shortcuts.
  const bulk = el("div", { style: "display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px" },
    el("button", { class: "btn btn-sm", type: "button", onclick: () => setAll(true) }, "Keep all"),
    el("button", { class: "btn btn-sm", type: "button", onclick: () => setAll(false) }, "Cut all"),
    el("button", { class: "btn btn-sm", type: "button", onclick: () => setters.forEach((s, i) => { if (JUNK_CATEGORIES.includes(cats[i].toLowerCase())) s(false); }) }, "Cut junk"));
  const apply = el("button", { class: "btn btn-primary" }, "Apply");
  const back = modal({
    title: "New channel categories",
    body: el("div", {},
      el("div", { class: "hint", style: "margin-bottom:10px" },
        "These categories appeared in your sources since you set up this list. Keep the ones you want; un-check to cut them (excluded from now on)."),
      bulk,
      el("div", { class: "wr-console", style: "max-height:260px;overflow:auto;padding:6px;text-align:left" }, ...rows)),
    footer: [el("button", { class: "btn btn-ghost", onclick: () => back.close() }, "Cancel"), apply],
  });
  apply.addEventListener("click", async () => {
    const keep = [...keepSet], cut = cats.filter(c => !keepSet.has(c));
    apply.disabled = true;
    try { await api.post("/api/iptv/lists/" + encodeURIComponent(l.id) + "/review", { keep, cut }); }
    catch (e) { apply.disabled = false; return toast(e.message, "err"); }
    back.close();
    toast(cut.length ? t("Kept {0}, cut {1}", keep.length, cut.length) : t("All kept"), "ok");
    route();
  });
}

async function route() {
  // Close any open modal when navigating: modals are appended to <body>, so
  // clearing #view alone would leave the dialog floating over the new page.
  $$(".modal-backdrop").forEach(m => m.remove());
  // Proactively abort any live netdiag stream we're leaving. runDiagStream's own in-loop guard only
  // fires after the next reader.read() resolves, so a stalled traceroute (silent between hops) would
  // otherwise keep the fetch + AbortController alive; killing it here frees it the instant we navigate.
  if (state.diag && state.diag.abort) { try { state.diag.abort.abort(); } catch (e) {} state.diag = null; }
  const key = (location.hash || "#dashboard").slice(1);
  const page = PAGES[key] || PAGES.dashboard;
  $$(".nav-item").forEach(n => { const on = n.dataset.page === key; n.classList.toggle("active", on); if (on) n.setAttribute("aria-current", "page"); else n.removeAttribute("aria-current"); }); // aria-current so AT users know the current page, not just via color
  $("#pagetitle").textContent = t(page.title);
  graphCanvas = null;
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
  try { await page.render(container); associateLabels(container); } catch (e) { renderError(container, e); }
  if (gen !== routeGen) return; // a newer navigation superseded us — discard this render
  skel.remove();
  i18nApply(container); // localize the freshly-rendered (English) page in place
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
      const inner = el("div", {},
        el("b", {}, t("Proxy core not running")),
        el("div", { class: "hint", style: "margin-top:3px" },
          eps.length
            ? t("sing-box isn't started — Apply a config to bring a tunnel up. Live stats appear once it's running.")
            : t("Add a connection under Connections, then Apply — live stats appear once sing-box is running.")));
      // First run (no endpoints yet): give a one-click path to the Connections page
      // instead of only telling the user where to go.
      if (!eps.length) {
        inner.appendChild(el("button", {
          class: "btn btn-primary btn-sm", style: "margin-top:8px",
          onclick: () => { location.hash = "#connections"; },
        }, t("Add a connection →")));
      }
      view.appendChild(el("div", { class: "card notice-core" },
        el("span", { class: "notice-core-ico" }, "○"), inner));
    }
  }

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
  const epTile = tile("Endpoints", String(eps.length), t("{0} enabled", eps.filter(e => e.enabled).length));
  epTile.setAttribute("data-tile", "endpoints"); // so refreshEnabledTile() can update the "N enabled" sub in place after a toggle
  view.appendChild(el("div", { class: "tiles" },
    epTile,
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
// paintSystem repaints the system strip. When the 5 s health tick already fetched
// /api/system as part of its parallel batch it passes the sample in (si !== undefined),
// so the strip refreshes without a second, serial round-trip on the router link. Called
// with no argument (initial render, manual refresh) it fetches its own copy.
function paintSystem(si) {
  const strip = document.getElementById("sys-strip");
  if (!strip) return;
  const apply = si => {
    if (!si || !si.available) { strip.remove(); return; } // no procfs (non-Linux) → drop the strip
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
  if (si === null) return; // batched poll dropped /api/system this tick (best-effort .catch(()=>null)) — leave the strip as-is; don't remove it
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
    node.innerHTML = ""; node.append("↓" + fmtBytes(w.down) + "/s ", el("small", {}, "↑" + fmtBytes(w.up) + "/s"));
    const tile = node.closest(".sys-tile");
    if (tile) {
      const lines = ifaces.map(f => { const r = rate(f.name); return r ? f.name + ": ↓" + fmtBytes(r.down) + "/s ↑" + fmtBytes(r.up) + "/s" : null; }).filter(Boolean);
      tile.title = lines.join("\n");
    }
  }
  paintIfaceList(ifaces, rate, wan && wan.name); // per-tunnel rates paint regardless of the WAN tile state
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
      el("div", { class: "conn-age" }, t("{0} port(s)", g.ports.size))),
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
  const top = clients.slice(0, 8);
  const max = ((top[0].up_bytes || 0) + (top[0].down_bytes || 0)) || 1;
  top.forEach(c => {
    const total = (c.up_bytes || 0) + (c.down_bytes || 0);
    list.appendChild(el("div", { class: "talker" },
      el("div", { class: "talker-row" },
        el("span", { class: "talker-host", title: c.ip + "  ·  " + t("{0} conns", c.conns || 0) }, c.name || c.ip),
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

function connRow(e, showSpark) {
  const tog = switchEl(e.enabled, (s) => toggleEndpoint(e, s), (e.name || e.id) + " enabled");
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

// Optimistic in-place toggle: flip the switch (smooth CSS) + local state IMMEDIATELY, persist in the
// background, and revert only if the POST fails. No route() — a full re-render killed the animation,
// jumped the row (disabled sinks to the bottom) and lost scroll position. The dashboard "N enabled"
// count / row re-sort refresh naturally on the next navigation.
function flipSwitch(sw, on) {
  if (!sw) return;
  sw.classList.toggle("on", on);
  sw.setAttribute("aria-checked", on ? "true" : "false");
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
  } catch (err) {
    flipSwitch(sw, !want);
    e.enabled = !want;
    updateDirty();
    refreshEnabledTile();
    toast(err.message, "err");
  } finally { if (sw) sw._busy = false; }
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
      const tog = switchEl(e.enabled, (s) => toggleEndpoint(e, s), (e.name || e.id) + " enabled");
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
          el("button", { class: "btn btn-sm", onclick: ev => testEndpoint(e, ev.currentTarget) }, "Test"),
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
  if (!await modalConfirm(t("Delete connection {0}?", e.name || e.id))) return;
  try { await api.del("/api/endpoints/" + encodeURIComponent(e.id)); await loadProfile(); route(); toast("Deleted", "ok"); }
  catch (err) { toast(err.message, "err"); }
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
let failoverState = { elected: {}, local_fault: false };

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
  try {
    const fs = await api.get("/api/failover/state");
    failoverState = { elected: (fs && fs.elected) || {}, local_fault: !!(fs && fs.local_fault) };
  } catch (e) { failoverState = { elected: {}, local_fault: false }; }

  const head = el("div", { class: "block-head" },
    el("div", {},
      el("div", { class: "ttl" }, "Failover"),
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
  try { await api.post("/api/rules", { id: "default", default: true, outbound: g.id }); await loadProfile(); route(); toast(t("Default route → {0}", g.name), "ok"); }
  catch (err) { toast(err.message, "err"); }
}
async function delGroup(g) {
  if (!await modalConfirm(t("Delete group {0}?", g.name))) return;
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
      el("button", { class: "btn", title: "Re-fetch CIDRs for any list with an auto-refresh source, then Apply to activate", onclick: (e) => refreshCidrSources(e.currentTarget) }, "↻ Refresh sources"),
      el("button", { class: "btn", title: "Add a ready-made routing list from the catalog", onclick: openRoutingCatalog }, "Preset lists"),
      el("button", { class: "btn", title: t("Manage device groups, then scope a list to certain devices"), onclick: openDeviceGroups }, t("Device groups")),
      el("button", { class: "btn btn-primary", title: "Create your own routing list (domains/IPs or a feed)", onclick: () => openRoutingList(null) }, "+ Custom list"))));

  // PBR status badge — best-effort; silently absent if server is old or mode != hybrid.
  try {
    const pbrSt = await api.get("/api/pbr/status");
    if (pbrSt && pbrSt.mode === "hybrid") {
      const active = pbrSt.installed && !pbrSt.stale;
      const pbrPill = active
        ? el("span", { class: "pill ok pill--dot" }, t("active · {0} zones", pbrSt.zones))
        : pbrSt.installed
          ? el("span", { class: "pill warn" }, t("stale"))
          : el("span", { class: "pill muted" }, t("not applied"));
      const row = el("div", { class: "hint row-between", style: "margin-top:var(--sp-2);align-items:center" },
        el("span", {}, t("Kernel routing:") + " ", pbrPill));
      if (!active) {
        const applyBtn = el("button", { class: "btn", style: "font-size:var(--fs-small)" }, t("Re-apply kernel routing"));
        applyBtn.onclick = async () => {
          applyBtn.disabled = true;
          try {
            await api.post("/api/pbr/apply", {});
            toast(t("Kernel routing re-applied"), "ok");
            route(); // re-render via the standard path (renderRouting() with no view arg would throw)
          } catch (e) { toast(t("Re-apply failed: {0}", e.message), "err"); applyBtn.disabled = false; }
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
    const label = s.ok ? (s.status ? t("source reachable (HTTP {0})", s.status) : t("OK")) : (s.error || t("error"));
    d.title = label;
    d.setAttribute("role", "img");
    d.setAttribute("aria-label", label); // expose the pass/fail state to assistive tech, not color alone
  });
  document.querySelectorAll("[data-rlerr]").forEach(e => {
    const s = byId[e.getAttribute("data-rlerr")];
    if (s && !s.ok && s.error) { e.textContent = "⚠ " + s.error; e.style.display = ""; }
    else { e.style.display = "none"; }
  });
}

function routingRow(rl) {
  const tog = switchEl(rl.enabled, (s) => toggleRoutingList(rl, s), (rl.name || rl.id) + " enabled");
  const mcount = (rl.manual || []).length;
  const src = rl.source
    ? el("span", { class: "addr", title: rl.source }, "⛓ " + rlShortURL(rl.source))
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
  // Per-list download status: a green/red dot next to the name + the error code
  // below. Starts muted ("checking…") and is painted by paintRoutingStatus().
  const dot = el("span", { class: "pill muted pill--dot", "data-rlstatus": rl.id, style: "margin-left:8px", title: "checking…", role: "img", "aria-label": t("checking…") }, el("span", { class: "dot" }));
  const err = el("div", { class: "hint", "data-rlerr": rl.id, style: "color:var(--err);display:none;margin-top:3px;word-break:break-word" });
  // Scope badge: shown when the list is limited to specific device groups (not all clients). "except"
  // uses a ≠ prefix + its own tooltip so "only Kids" and "everyone except Kids" read differently.
  const scopeNames = (rl.scope_groups || []).map(deviceGroupName).join(", ") || t("groups");
  const scopeTag = (rl.scope_mode === "only" || rl.scope_mode === "except")
    ? el("span", { class: "badge", style: "margin-left:6px", title: rl.scope_mode === "except" ? t("All devices except these groups") : t("Only these device groups") },
      (rl.scope_mode === "except" ? "👥≠ " : "👥 ") + scopeNames)
    : null;
  // Cells map 1:1 to the .rlhead columns: [toggle] [list+source] [route via] [download via] [actions].
  return el("div", { class: "rlrow" }, tog,
    el("div", { class: "rl-list" },
      el("div", { class: "name" }, rl.name || rl.id, dot, scopeTag),
      el("div", { class: "sub" }, src),
      err),
    el("div", { class: "rl-cell", "data-col": t("route via") }, routeSel),
    el("div", { class: "rl-cell", "data-col": t("download via") }, dlSel),
    el("div", { class: "acts" },
      el("button", { class: "btn btn-sm", onclick: () => openRoutingList(rl) }, "Edit"),
      el("button", { class: "btn btn-danger btn-sm", onclick: () => delRoutingList(rl) }, "Delete")));
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
async function saveRoutingList(rl, msg, revert) {
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
        el("div", { class: "sub" }, el("span", { class: "addr" }, t("{0} device(s)", (g.members || []).length)))),
      el("div", { class: "acts" },
        el("button", { class: "btn btn-sm", onclick: () => openDeviceGroup(g, render) }, t("Edit")),
        el("button", { class: "btn btn-danger btn-sm", onclick: () => delDeviceGroup(g, render) }, t("Delete"))))));
  };
  render();
  modal({
    title: t("Device groups"), body: el("div", {},
      el("div", { class: "hint", style: "margin-bottom:10px" }, t("Named sets of devices (by MAC or IP) that a routing list can apply to — or be blocked for.")),
      listWrap,
      el("div", { style: "margin-top:12px" }, el("button", { class: "btn btn-primary", onclick: () => openDeviceGroup(null, render) }, t("+ New group")))),
  });
}

async function delDeviceGroup(g, rerender) {
  if (!await modalConfirm(t("Delete device group {0}?", g.name || g.id))) return;
  try { await api.del("/api/device-groups/" + encodeURIComponent(g.id)); await loadProfile(); if (rerender) rerender(); toast(t("Deleted"), "ok"); }
  catch (e) { toast(e.message, "err"); }
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
    devs.forEach(d => pickWrap.appendChild(el("div", { class: "conn" },
      el("div", { class: "body" }, el("div", { class: "name" }, d.hostname || d.ip || d.mac),
        el("div", { class: "sub" }, el("span", { class: "addr" }, [d.mac, d.ip].filter(Boolean).join(" · ")))),
      el("div", { class: "acts" }, el("button", { class: "btn btn-sm", onclick: () => { if (has(d.mac, d.ip)) return toast(t("Already added"), "err"); members.push({ mac: (d.mac || "").toLowerCase(), ip: d.ip || "" }); renderMembers(); } }, "+")))));
  }).catch(() => { pickWrap.innerHTML = ""; pickWrap.appendChild(el("div", { class: "hint" }, t("Couldn't load the device list."))); });
  const manIn = el("input", { type: "text", placeholder: t("MAC (aa:bb:…) or IP") });
  const addManual = () => {
    const v = manIn.value.trim(); if (!v) return;
    const m = /^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$/.test(v) ? { mac: v.toLowerCase(), ip: "" } : { mac: "", ip: v };
    if (has(m.mac, m.ip)) return toast(t("Already added"), "err");
    members.push(m); manIn.value = ""; renderMembers();
  };
  async function save() {
    if (!name.value.trim()) return toast(t("Name required"), "err");
    if (!members.length) return toast(t("Add at least one device"), "err");
    const dbody = { id: g.id || rlUniqueId(rlSlug(name.value)), name: name.value.trim(), members: members.map(m => { const o = {}; if (m.mac) o.mac = m.mac; if (m.ip) o.ip = m.ip; return o; }) };
    try { await api.post("/api/device-groups", dbody); await loadProfile(); back.remove(); if (onSaved) onSaved(); toast(editing ? t("Saved {0}", dbody.name) : t("Added {0}", dbody.name), "ok"); }
    catch (e) { toast(e.message, "err"); }
  }
  const body = el("div", {},
    el("div", { class: "field" }, el("label", {}, t("Name")), name),
    el("div", { class: "field" }, el("label", {}, t("Devices in this group")), memWrap),
    el("div", { class: "field" }, el("label", {}, t("Add by MAC or IP")), el("div", { style: "display:flex;gap:8px" }, manIn, el("button", { class: "btn", type: "button", onclick: addManual }, t("Add"))),
      el("div", { class: "hint", style: "margin-top:6px" }, t("MAC matches most reliably — but turn off the device's Private/Random Wi-Fi address for this network, or its MAC will change and drop out of the group."))),
    el("div", { class: "field" }, el("label", {}, t("Pick from devices on the network")), pickWrap));
  const back = modal({
    title: editing ? t("Edit device group") : t("New device group"), body,
    footer: [el("button", { class: "btn btn-ghost", onclick: () => back.remove() }, t("Cancel")), el("button", { class: "btn btn-primary", onclick: save }, editing ? t("Save") : t("Add"))],
  });
}

function openRoutingList(rl) {
  const editing = !!rl;
  rl = rl || { id: "", name: "", source: "", manual: [], outbound: rlFirstTunnel(), download_via: "", enabled: true, refresh_hours: 0 };
  const name = el("input", { type: "text", value: rl.name || "", placeholder: "My list" });
  const mode = el("select", {},
    el("option", { value: "url" }, "From URL (sing-box rule-set .srs / .json)"),
    el("option", { value: "manual" }, "Manual domains / IPs"));
  const source = el("input", { type: "text", value: rl.source || "", placeholder: "https://…/list.srs" });
  const manual = el("textarea", { rows: "6", class: "rl-ta", placeholder: t("one per line:\n{0}", "example.com\nopenai.com\n104.18.0.0/16") }, (rl.manual || []).join("\n"));
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
  const cachedNote = (rl.cidr_cache && rl.cidr_cache.length) ? el("span", {}, " " + t("Cached: {0} CIDRs.", rl.cidr_cache.length)) : null;
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

  async function save() {
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
    try { await api.post("/api/routing", body); back.remove(); await loadProfile(); route(); toast(editing ? t("Saved {0}", body.name) : t("Added {0}", body.name), "ok"); }
    catch (e) { toast(e.message, "err"); }
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
    el("button", { class: "btn btn-primary", onclick: save }, editing ? "Save" : "Add")] });
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
    const msg = (r.changed ? t("Refreshed") : t("No changes")) + " · " + t("{0} source(s)", srcN) +
      (errN ? " · " + t("{0} failed", errN) : "") + (r.changed ? t(" — click Apply to activate.") : "");
    toast(msg, errN ? "err" : "ok");
  } catch (e) { toast(e.message, "err"); }
  finally { if (btn) btn.disabled = false; } // harmless if route() already replaced the button
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
  try { await api.post("/api/routing", body); if (back) back.remove(); await loadProfile(); route(); toast(t("Added {0} → {1}", p.name, nameOf(body.outbound) || body.outbound), "ok"); }
  catch (e) { toast(e.message, "err"); }
}

/* ---------- modal ---------- */
let modalSeq = 0;
// modalConfirm is a themed, async replacement for the browser's native confirm().
// Returns a Promise<boolean>: true = OK, false = Cancel / Escape / backdrop click.
// Reuses the .modal-backdrop / .modal / .modal-body / .modal-foot CSS classes so it
// inherits the same look, dark-mode, and responsive sizing as all other modals.
function modalConfirm(msg) {
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
    const ok = el("button", { class: "btn btn-primary" }, t("OK"));
    const cancel = el("button", { class: "btn" }, t("Cancel"));
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
  const m = el("div", { class: "modal", tabindex: "-1", role: "dialog", "aria-modal": "true", "aria-labelledby": titleId },
    el("div", { class: "modal-head" }, el("div", { class: "card-title", id: titleId }, title),
      a11yClick(el("div", { class: "x" }, "×"), () => close(), t("Close"))),
    el("div", { class: "modal-body" }, body));
  if (footer) m.appendChild(el("div", { class: "modal-foot" }, footer));
  back.appendChild(m);
  i18nApply(m); // localize the modal's English content (titles, labels, hints, buttons)
  associateLabels(m); // wire form labels to their controls for screen readers
  document.body.appendChild(back);
  document.addEventListener("keydown", onKey);
  // Move focus into the modal: first focusable control, else the dialog container.
  (focusables(m)[0] || m).focus();
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
    const url = URL.createObjectURL(await r.blob());
    const freeUrl = () => URL.revokeObjectURL(url); // free the blob once it's no longer needed — no per-render leak
    img.addEventListener("load", freeUrl, { once: true });
    img.addEventListener("error", freeUrl, { once: true }); // also free if the blob never decodes (bad/empty image)
    img.src = url;
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
  const rotateBtn = el("button", { class: "btn btn-sm", title: "Issue a new URL and invalidate the current one" }, t("Rotate token"));
  rotateBtn.addEventListener("click", async () => {
    if (!await modalConfirm(t("Rotate the subscription token? The current URL stops working immediately — you'll need to re-share the new one with every device."))) return;
    const prev = rotateBtn.textContent;
    rotateBtn.disabled = true; rotateBtn.textContent = t("Rotating…");
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
    associateLabels(dyn); // re-wire labels for the freshly-rebuilt protocol fields (a protocol switch bypasses modal()'s one-shot associateLabels)
  }
  renderDyn(proto0);

  const protoSel = el("select", { id: "f-proto", onchange: e => renderDyn(e.target.value) }, ...PROTOCOLS.map(p => el("option", { value: p }, p)));
  protoSel.value = proto0;
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
      t("Routes through an existing kernel interface (an AmneziaWG / WireGuard tunnel configured outside WayHop). It has no protocol of its own.")),
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
    try { await api.post("/api/endpoints", e); back.remove(); await loadProfile(); route(); toast(t("Updated {0}", e.name || e.id), "ok"); }
    catch (err) { toast(err.message, "err"); }
  }
  const back = modal({ title: external ? "Edit external connection" : "Edit connection", body: form.el,
    footer: [el("button", { class: "btn btn-ghost", onclick: () => back.remove() }, "Cancel"), el("button", { class: "btn btn-primary", onclick: save }, "Save")] });
}

function openAddConnection() {
  const content = el("div", { id: "addconn-panel", role: "tabpanel", tabindex: "0" }); // the tabs' panel (aria-controls target)
  const tabEls = {};
  let back;
  const done = msg => { back.remove(); loadProfile().then(route).catch(e => toast(e.message, "err")); toast(msg, "ok"); };

  function pasteTab() {
    const ta = el("textarea", { placeholder: "Paste a vless:// / hysteria2:// / tuic:// link — or a [Interface] WireGuard / AmneziaWG config",
      onpaste: () => setTimeout(parse, 0) });
    const confirm = el("div", {});
    async function parse() {
      const link = ta.value.trim();
      if (!link) return;
      confirm.innerHTML = ""; confirm.appendChild(el("div", { class: "hint" }, "parsing…"));
      try {
        const parsed = await api.post("/api/import", { link });
        confirm.innerHTML = "";
        const form = manualForm(parsed); // editable confirmation — protocol dropdown overrides the type
        const saveBtn = el("button", { class: "btn btn-primary", onclick: async (ev) => {
          const e = form.collect(); if (!e.server || !e.port) return toast("Server and port required", "err");
          const b = ev.currentTarget; if (b.disabled) return; b.disabled = true; // guard against double-submit firing two POSTs before done() removes the modal
          try { await api.post("/api/endpoints", e); done(t("Added {0}", e.name || e.id)); } catch (err) { b.disabled = false; toast(err.message, "err"); }
        } }, "Save connection");
        const detProto = String(parsed.protocol || "?").toUpperCase();
        const detEng = parsed.engine && parsed.engine !== "singbox" ? parsed.engine : "";
        confirm.appendChild(el("div", { class: "toast info", style: "margin:0 0 12px" },
          detEng
            ? t("Detected {0} · {1} engine — review below and fix the type if it's wrong, then save.", detProto, detEng)
            : t("Detected {0} — review below and fix the type if it's wrong, then save.", detProto)));
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
    const addBtn = el("button", { class: "btn btn-primary", onclick: async (ev) => {
      const e = form.collect(); if (!e.server || !e.port) return toast("Server and port required", "err");
      const b = ev.currentTarget; if (b.disabled) return; b.disabled = true; // guard against double-submit firing two POSTs before done() removes the modal
      try { await api.post("/api/endpoints", e); done(t("Added {0}", e.name || e.id)); } catch (err) { b.disabled = false; toast(err.message, "err"); }
    } }, "Add");
    return el("div", {}, form.el, el("div", { style: "margin-top:8px" }, addBtn));
  }
  function subTab() {
    let found = [];
    const url = el("input", { type: "text", placeholder: t("{0} (optional)", "https://provider/subscription") });
    const ta = el("textarea", { placeholder: "…or paste the subscription text / base64 blob here" });
    const list = el("div", { class: "checks", style: "margin-top:14px" });
    const importBtn = el("button", { class: "btn btn-primary", disabled: "true", onclick: async () => {
      const chosen = $$("input[type=checkbox]:checked", list).map(c => found[+c.value]);
      if (!chosen.length) return toast("Nothing selected", "err");
      try { const r = await api.post("/api/endpoints/bulk", { endpoints: chosen }); done(t("Imported {0} connection(s)", r.saved) + (r.duplicates ? t(", {0} duplicate(s) skipped", r.duplicates) : "") + (r.errors && r.errors.length ? t(", {0} failed", r.errors.length) : "")); } catch (e) { toast(e.message, "err"); }
    } }, "Import selected");
    const fetchBtn = el("button", { class: "btn", onclick: async () => {
      list.innerHTML = ""; importBtn.setAttribute("disabled", "true");
      try {
        const r = await api.post("/api/subscription", { url: url.value.trim(), text: ta.value });
        found = r.endpoints || [];
        if (!found.length) { list.appendChild(el("div", { class: "hint" }, r.errors && r.errors.length ? t("No connections found ({0} line errors).", r.errors.length) : t("No connections found."))); return; }
        if (r.name) list.appendChild(el("div", { class: "hint", style: "color:var(--ink-2);margin-bottom:8px" }, t("From: {0}", r.name)));
        found.forEach((e, i) => list.appendChild(el("label", { class: "check" }, el("input", { type: "checkbox", value: String(i), checked: "true" }), el("span", {}, (e.name || e.id) + "  "), el("span", { class: "badge" }, e.protocol))));
        if (r.errors && r.errors.length) list.appendChild(el("div", { class: "hint" }, r.errors.length + " line(s) skipped"));
        importBtn.removeAttribute("disabled");
      } catch (e) { list.appendChild(el("div", { class: "hint", style: "color:var(--err)" }, e.message)); }
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
  const box = el("div", { class: "checks" });
  rows.forEach(({ e, checked }) => {
    const cb = el("input", { type: "checkbox", value: e.id });
    if (checked) cb.setAttribute("checked", "true");
    const up = el("button", { class: "btn btn-sm", type: "button", title: "Move up (higher priority)", "aria-label": "Move up", style: "padding:1px 8px;line-height:1.2" }, "▲");
    const dn = el("button", { class: "btn btn-sm", type: "button", title: "Move down (lower priority)", "aria-label": "Move down", style: "padding:1px 8px;line-height:1.2" }, "▼");
    const row = el("label", { class: "check", style: "display:flex;align-items:center;gap:8px" }, cb,
      el("span", { style: "flex:1;min-width:0" }, (e.name || e.id) + "  ", el("span", { class: "badge" }, e.protocol)),
      el("span", { style: "display:flex;gap:4px;flex:none" }, up, dn));
    const move = (dir) => (ev) => {
      ev.preventDefault(); ev.stopPropagation();
      if (dir < 0 && row.previousElementSibling) box.insertBefore(row, row.previousElementSibling);
      else if (dir > 0 && row.nextElementSibling) box.insertBefore(row.nextElementSibling, row);
    };
    up.onclick = move(-1);
    dn.onclick = move(1);
    box.appendChild(row);
  });
  return box;
}

// memberOrderHint explains what the ▲/▼ order actually does per group type (avoids implying strict
// priority where sing-box doesn't give it): urltest/fallback auto-pick the fastest ALIVE member and
// use your order only as a tiebreak; selector routes through the FIRST member until you switch.
const MEMBER_ORDER_HINT = "Use ▲/▼ to set priority. A selector group uses the top member; urltest/fallback auto-pick the fastest working member and use your order as a tiebreak.";

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
  const node = el("div", {},
    el("div", { class: "field" }, el("label", {}, t("Health check URL")), url),
    el("div", { style: "display:flex;gap:12px" },
      el("div", { class: "field", style: "flex:1" }, el("label", {}, t("Probe interval (s)")), interval),
      el("div", { class: "field", style: "flex:1" }, el("label", {}, t("Flap tolerance (ms)")), tolerance)),
    el("div", { class: "hint" }, t("Higher tolerance = stickier exit on a jittery/DPI link (try 100–150 ms); lower interval = faster failover (floored to 5 s). Tunes urltest/fallback auto-failover; a selector group only uses the URL for its health badge.")));
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
    const id = "grp-" + name.value.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
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

  const body = el("div", {},
    el("div", { class: "field" }, el("label", {}, "Group name"), name),
    el("div", { class: "field" }, el("label", {}, "Type"), type),
    el("div", { class: "field" }, el("label", {}, t("Members (priority order)")), checks,
      el("div", { class: "hint" }, t(MEMBER_ORDER_HINT))),
    tuning.node,
    el("label", { class: "check" }, asDefault, el("span", {}, "Set as default route (all traffic)")),
    el("label", { class: "check" }, killSwitch, el("span", {}, t("Kill switch (drop when all members down)"))),
    el("div", { class: "hint" }, t("When on, traffic is dropped instead of falling back to the open WAN if every member is down — no leak to the unprotected internet.")));
  const back = modal({ title: "New failover group", body,
    footer: [el("button", { class: "btn btn-ghost", onclick: () => back.remove() }, "Cancel"),
    el("button", { class: "btn btn-primary", onclick: (e) => create(e.currentTarget) }, "Create")] });
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

  const body = el("div", {},
    el("div", { class: "field" }, el("label", {}, "Group name"), name),
    el("div", { class: "field" }, el("label", {}, "Type"), type),
    el("div", { class: "field" }, el("label", {}, t("Members (priority order)")), checks,
      el("div", { class: "hint" }, t(MEMBER_ORDER_HINT))),
    tuning.node,
    el("label", { class: "check" }, killSwitch, el("span", {}, t("Kill switch (drop when all members down)"))),
    el("div", { class: "hint" }, t("When on, traffic is dropped instead of falling back to the open WAN if every member is down — no leak to the unprotected internet.")));
  const back = modal({ title: t("Edit failover group"), body,
    footer: [el("button", { class: "btn btn-ghost", onclick: () => back.remove() }, "Cancel"),
    el("button", { class: "btn btn-primary", onclick: (e) => save(e.currentTarget) }, "Save")] });
}

/* ---------- apply ---------- */
// Phased progress for the multi-second Apply. The server runs check → reload → routing
// in that order but the POST only returns at the very end, so on a slow A53 the button
// text would otherwise freeze for 3-8s at the moment of peak user anxiety. We advance
// honest phase hints on a timer that mirrors the real sequence, plus a live elapsed
// counter — never claiming "done" until the promise resolves. Returns a stop() fn.
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
function showApplyError(msg, save) {
  const b = $("#apply-error");
  if (!b) { toast(t("Apply failed: {0}", msg), "err"); return; }
  b.style.display = "block"; b.innerHTML = "";
  b.appendChild(el("div", { class: "card", style: "margin:0;border-left:3px solid var(--err)" },
    el("div", { class: "row-between" },
      el("div", {},
        el("b", {}, "Apply failed"),
        el("span", { class: "hint", style: "margin-left:10px" }, msg)),
      el("button", { class: "btn btn-sm", onclick: () => { hideApplyError(); applyConfig(save); } }, "Retry"))));
}

async function applyConfig(save) {
  const btn = save ? $("#applysavebtn") : $("#applybtn");
  if (!btn) return;
  if (applyInFlight) { toast(t("Apply in progress — finish it first"), "err"); return; } // the OTHER apply button stays enabled — block re-entry so two /api/apply POSTs can't race + one's finally can't clear applyInFlight while the other runs
  const label = btn.textContent;
  btn.setAttribute("disabled", "true");
  btn.setAttribute("aria-busy", "true");
  btn.classList.remove("dirty"); // spinner replaces the dirty dot while working
  btn.classList.add("working");
  const stop = applyProgress(btn);
  applyInFlight = true; // freeze staging toggles until this Apply settles (see the guards in toggleEndpoint/toggleRoutingList/dnsToggleRow)
  try {
    const r = await api.post("/api/apply", { save: !!save });
    let msg = save ? "Applied & saved" : "Applied (live, not saved)";
    if (r.checked) msg += " · check OK";
    if (r.reloaded) msg += " · reloaded";
    hideApplyError();
    toast(msg, "ok");
    if (!save && r.failsafe && r.failsafe.pending) startFailsafeBanner();
    else hideFailsafeBanner();
    clearDirty(); // the staged profile is now the live baseline
  } catch (e) { showApplyError(e.message, save); }
  finally {
    applyInFlight = false;
    stop();
    btn.classList.remove("working");
    btn.removeAttribute("aria-busy");
    btn.removeAttribute("disabled");
    btn.textContent = label;
    try { reflectDirty(); } catch (e) {} // restore the dirty dot if the apply failed
  }
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
      else if (st.phase === "rollback_failed") toast(t("Connectivity lost AND the rollback failed — {0}", st.last_error || t("restore the config manually")), "err");
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

/* ---------- DNS ---------- */
// The DNS plane is edited as a whole object and PUT to /api/dns on every change (staged in the store;
// the global Apply then regenerates + activates it). It is FAILOVER-AWARE: a resolver's detour is a
// failover group, so DNS rides the tunnel while a VPN tier is up (the ISP sees nothing) and falls to
// encrypted DoH over the raw WAN when every tier is down (the query stays encrypted — DNS never goes
// dark). See docs/DNS_SECTION.md for the "hide while we can, degrade gracefully" model.
let dnsState = null;
const DNS_NET_TYPES = ["https", "tls", "quic", "h3", "udp", "tcp"];
const DNS_ENC_TYPES = ["https", "tls", "quic", "h3"];
const DNS_TYPE_LABEL = { https: "DoH (HTTPS)", tls: "DoT (TLS)", quic: "DoQ (QUIC)", h3: "DoH3", udp: "Plain (UDP)", tcp: "Plain (TCP)", local: "Local (device resolver)", fakeip: "FakeIP" };
const DNS_TYPE_BADGE = { https: "DoH", tls: "DoT", quic: "DoQ", h3: "DoH3", udp: "Do53", tcp: "Do53", local: "Local", fakeip: "FakeIP" };

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
  dnsState.servers = dnsState.servers || [];
  dnsState.rules = dnsState.rules || [];

  view.appendChild(el("div", { class: "block-head" },
    el("div", {},
      el("div", { class: "ttl" }, "DNS"),
      el("div", { class: "desc" }, t("Encrypted, split, failover-aware DNS: hides your lookups from the ISP while a tunnel is up, and gracefully falls back to encrypted DoH over the raw WAN when every VPN is down — so DNS never goes dark."))),
    el("div", { class: "side" },
      el("button", { class: "btn", title: t("Preview the generated sing-box dns block"), onclick: previewDNS }, t("Preview {0}", "dns{}")),
      el("button", { class: "btn btn-primary", title: t("One-click encrypted DoH via the tunnel + local for in-country, leak-proof"), onclick: applyDNSSecureDefaults }, t("Secure defaults")))));

  if (!configured) {
    view.appendChild(el("div", { class: "card" }, el("div", { class: "hint" },
      t("DNS is not managed by WayHop yet — sing-box uses its default resolver. Click “Secure defaults” for one-click encrypted, failover-aware DNS, or add resolvers manually."))));
  }

  // The router's OWN native DNS stack (dnsmasq + DoH), if WayHop is running on a router that has one —
  // a read-only "adopted" view so there's no hidden second config. Editing lands with native write-back.
  try {
    const nat = await api.get("/api/dns/native");
    if (nat && nat.available && nat.native) view.appendChild(dnsNativeCard(nat));
  } catch (_) { /* off a router / endpoint absent — no card */ }

  // Global toggles + strategy.
  const g = el("div", { class: "card" });
  g.appendChild(el("div", { class: "card-head" }, el("div", { class: "card-title" }, t("Settings"))));
  g.appendChild(dnsToggleRow(t("Enable DNS management"), "enabled", t("Emit a dns block. Off keeps sing-box's default resolver (today's behaviour).")));
  g.appendChild(dnsToggleRow(t("Leak protection (encrypted-only)"), "leak_proof", t("Reject plaintext resolvers and require an encrypted default — the ISP can never read your queries, even on the WAN fallback.")));
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

  // Split-DNS rules.
  const rc = el("div", { class: "card" });
  rc.appendChild(el("div", { class: "card-head" },
    el("div", { class: "card-title" }, t("Split-DNS rules")),
    el("div", { class: "acts" }, el("button", { class: "btn btn-sm", onclick: () => openDNSRule(null) }, t("+ Add rule")))));
  if (!dnsState.rules.length) rc.appendChild(el("div", { class: "hint" }, t("No rules — every query uses the default resolver. Add a rule to resolve chosen lists via a specific resolver (e.g. domestic sites via the local resolver, or block a list at DNS level).")));
  else dnsState.rules.forEach((r, i) => rc.appendChild(dnsRuleRow(r, i)));
  view.appendChild(rc);

  view.appendChild(dnsLeakWidget());
}

// dnsToggleRow — a labelled accessible switch bound to a boolean key on dnsState. Optimistic: flips
// the switch, mutates state, PUTs; saveDNS's error path re-renders from the persisted state (reverting
// a rejected flip). fakeip forces independent_cache (sing-box requires the pairing; validateDNS 400s).
function dnsToggleRow(label, key, hint) {
  const sw = switchEl(!!dnsState[key], (s) => {
    if (applyInFlight) { toast(t("Apply in progress — finish it first"), "err"); return; } // don't mutate staged DNS mid-Apply (checked before flipSwitch, so no visual desync)
    const want = !dnsState[key];
    flipSwitch(s, want);
    dnsState[key] = want;
    if (key === "fakeip" && want) dnsState.independent_cache = true;
    saveDNS(label + (want ? " ✓" : " ✕"));
  }, label);
  return el("div", { class: "dns-tog" },
    el("div", { class: "top" }, el("label", {}, label), sw),
    hint ? el("div", { class: "hint" }, hint) : null);
}

function dnsServerRow(s, i) {
  const net = DNS_NET_TYPES.includes(s.type);
  const enc = DNS_ENC_TYPES.includes(s.type);
  const addr = net ? (s.server + (s.server_port ? ":" + s.server_port : "") + (s.path || "")) : (s.type === "fakeip" ? (s.inet4_range || "198.18.0.0/15") : t("device resolver"));
  const leakWarn = (net && !enc) ? el("span", { class: "pill err", title: t("plaintext DNS — the ISP can read your queries") }, t("⚠ plaintext")) : null;
  const via = net ? "via " + (nameOf(s.detour) || (s.detour ? s.detour : t("direct"))) : null;
  return el("div", { class: "dns-row" },
    el("span", { class: "badge" }, DNS_TYPE_BADGE[s.type] || s.type),
    el("div", { class: "main" },
      el("div", { class: "name" }, el("span", { class: "tag" }, s.tag), leakWarn),
      el("div", { class: "sub" }, el("span", { class: "addr" }, addr), via ? el("span", {}, "· " + via) : null)),
    el("div", { class: "acts" },
      el("button", { class: "btn btn-sm", onclick: () => openDNSServer(i) }, t("Edit")),
      el("button", { class: "btn btn-danger btn-sm", onclick: async () => { if (!await modalConfirm(t("Delete DNS resolver {0}?", s.tag))) return; dnsState.servers.splice(i, 1); if (dnsState.final === s.tag) dnsState.final = ""; saveDNS(s.tag + " ✕", true); } }, t("Delete"))));
}

function dnsRuleRow(r, i) {
  const via = r.server === "reject" ? el("span", { class: "pill err" }, t("block")) : el("span", { class: "pill" }, r.server);
  const parts = (r.rule_sets || []).map(x => nameOf(x) || x)
    .concat(r.domain_suffix || [], r.geosite || [], (r.query_type || []).map(q => "type:" + q));
  const match = parts.length ? parts.join(", ") : t("(no match)");
  return el("div", { class: "dns-rule" },
    el("div", { class: "match" },
      el("div", { class: "m" }, match),
      el("div", { class: "via" }, "→", via)),
    el("div", { class: "acts" },
      el("button", { class: "btn btn-sm", onclick: () => openDNSRule(i) }, t("Edit")),
      el("button", { class: "btn btn-danger btn-sm", onclick: async () => { if (!await modalConfirm(t("Delete this DNS rule?"))) return; dnsState.rules.splice(i, 1); saveDNS(t("rule ✕"), true); } }, t("Delete"))));
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
  if (!rows.length) card.appendChild(el("div", { class: "hint" }, t("No upstreams detected.")));
  else rows.forEach(rz => card.appendChild(dnsNativeRow(rz)));
  return card;
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
    el("div", { class: "acts" }, el("span", { class: "pill muted" }, rz.source || "")));
}

// openNativePlan previews the native write-back: POSTs the adopted NativeDNS to /api/dns/native/plan
// and shows the exact uci (OpenWrt) / dnsmasq.d (Keenetic) the router WOULD get, plus the separate
// user-gated apply commands. Nothing is applied — this is the safe, offline-verifiable end of the wiring.
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
    const r = await api.put("/api/dns", dnsState);
    if (r && r.dns) dnsState = r.dns;
    state.profile.dns = dnsState;
    updateDirty();
    if (msg) toast(msg, "ok");
    if (rerender) route();
    return true;
  } catch (e) {
    toast(e.message, "err");
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

  // Group the picker: recommended secure/global resolvers vs country-local (geo-fallback) ones.
  // Option values stay the ORIGINAL preset index, so the onchange handler is unchanged.
  const presetSel = el("select", { id: "dnsm-preset" }, el("option", { value: "" }, t("— choose a provider —")));
  [["", t("Recommended — secure, global")], ["local", t("Country-local — geo-fallback")]].forEach(([cat, label]) => {
    const items = presets.map((p, i) => [p, i]).filter(([p]) => (p.category || "") === cat);
    if (items.length) presetSel.appendChild(el("optgroup", { label },
      ...items.map(([p, i]) => el("option", { value: String(i), title: p.note || "" }, p.name))));
  });
  const tagIn = el("input", { id: "dnsm-tag", type: "text", value: cur.tag || "", placeholder: "dns_secure" });
  const typeSel = el("select", { id: "dnsm-type" }, ...Object.keys(DNS_TYPE_LABEL).map(x => el("option", { value: x }, DNS_TYPE_LABEL[x])));
  typeSel.value = cur.type || "https";
  const serverIn = el("input", { id: "dnsm-server", type: "text", value: cur.server || "", placeholder: "1.1.1.1" });
  const portIn = el("input", { id: "dnsm-port", type: "number", value: cur.server_port || "", placeholder: "443" });
  const pathIn = el("input", { id: "dnsm-path", type: "text", value: cur.path || "", placeholder: "/dns-query" });
  const detourSel = routingOutboundSelect(cur.detour || "direct", false); detourSel.id = "dnsm-detour";
  const bootSel = el("select", { id: "dnsm-boot" }, el("option", { value: "" }, t("(none — server is an IP)")),
    ...dnsState.servers.filter((_, j) => j !== idx).map(x => el("option", { value: x.tag }, x.tag)));
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

  const sync = () => {
    const ty = typeSel.value;
    const net = DNS_NET_TYPES.includes(ty), enc = DNS_ENC_TYPES.includes(ty), fake = ty === "fakeip";
    rowServer.style.display = net ? "" : "none";
    rowPort.style.display = net ? "" : "none";
    rowPath.style.display = (ty === "https" || ty === "h3") ? "" : "none";
    rowDetour.style.display = net ? "" : "none";
    rowBoot.style.display = enc ? "" : "none";
    rowI4.style.display = fake ? "" : "none";
    rowI6.style.display = fake ? "" : "none";
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
    rowServer, rowPort, rowPath, rowDetour, rowBoot, rowI4, rowI6,
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
    saveBtn.disabled = true;
    // Serialize through dnsSaveChain like saveDNS() — a direct PUT + dnsState reassignment here
    // can race a concurrent background saveDNS() (toggle/strategy/default) and clobber dnsState.
    // Mutating inside the chained step also means it operates on the latest dnsState, not a stale one.
    dnsSaveChain = dnsSaveChain.then(async () => {
      const prev = dnsState.servers.slice();
      if (editing) dnsState.servers[idx] = o; else dnsState.servers.push(o);
      if (dnsState.fakeip && ty === "fakeip") dnsState.independent_cache = true;
      try {
        const r = await api.put("/api/dns", dnsState);
        if (r && r.dns) dnsState = r.dns;
        state.profile.dns = dnsState; updateDirty();
        toast(editing ? t("Resolver updated") : t("Resolver added"), "ok");
        back.close(); route();
      } catch (e) {
        dnsState.servers = prev; saveBtn.disabled = false;
        toast(e.message, "err");
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
  const sufIn = el("textarea", { id: "dnsr-suf", rows: "3", placeholder: "example.com\ninternal.lan" }, (cur.domain_suffix || []).join("\n"));
  const qtIn = el("input", { id: "dnsr-qt", type: "text", value: (cur.query_type || []).join(","), placeholder: "A,AAAA" });
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
    const o = {
      id: (editing && cur.id) ? cur.id : ("r" + Date.now().toString(36)),
      rule_sets: Object.keys(listChecks).filter(id => listChecks[id].checked),
      domain_suffix: sufIn.value.split("\n").map(x => x.trim()).filter(Boolean),
      query_type: qtIn.value.split(",").map(x => x.trim()).filter(Boolean),
      server: srvSel.value,
    };
    if (!o.rule_sets.length && !o.domain_suffix.length && !o.query_type.length) { toast(t("A rule needs at least one match condition"), "err"); return; }
    saveBtn.disabled = true;
    // Serialize through dnsSaveChain like saveDNS() so this PUT + dnsState reassignment can't race
    // a concurrent background saveDNS() and clobber dnsState (mutate inside → operates on latest state).
    dnsSaveChain = dnsSaveChain.then(async () => {
      const prev = dnsState.rules.slice();
      if (editing) dnsState.rules[idx] = o; else dnsState.rules.push(o);
      try {
        const r = await api.put("/api/dns", dnsState);
        if (r && r.dns) dnsState = r.dns;
        state.profile.dns = dnsState; updateDirty();
        toast(t("Rule saved"), "ok"); back.close(); route();
      } catch (e) { dnsState.rules = prev; saveBtn.disabled = false; toast(e.message, "err"); }
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
      // Backend healthcheck status enum is pass | warn | fail (never "ok") — map "pass" to the green
      // pill, else a passing (leak-free) check would fall through to the red err pill (false alarm).
      const cls = c.status === "pass" ? "ok" : (c.status === "warn" ? "warn" : "err");
      body.appendChild(el("div", { style: "display:flex;align-items:center;justify-content:space-between;gap:10px;padding:5px 0" },
        el("span", {}, c.label || c.id),
        el("span", { class: "pill " + cls, title: c.detail || "" }, c.summary || c.status)));
      if (c.status !== "pass" && c.fix) body.appendChild(el("div", { class: "hint" }, "→ " + c.fix));
    });
  } catch (e) { body.textContent = ""; body.appendChild(el("div", { class: "hint" }, t("Leak test unavailable: ") + e.message)); }
}

function renderFailsafeBanner(st) {
  const b = $("#failsafe-banner");
  if (!b) return;
  b.style.display = "block"; b.innerHTML = "";
  const degraded = st.phase === "degraded";
  b.appendChild(el("div", { class: "card", style: "margin:0;border-left:3px solid " + (degraded ? "var(--err)" : "var(--warn)") },
    el("div", { class: "row-between" },
      el("div", {},
        el("b", {}, degraded ? t("⚠ Connectivity problem — config will roll back") : t("Config applied live (not saved)")),
        el("span", { class: "hint", style: "margin-left:10px" },
          degraded ? t("phase: {0}", st.phase) : t("watching connectivity {0}s · auto-rollback if internet drops", st.seconds_left))),
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
  const h = state.health || {}, wd = watchdog || {};
  let word, ico, color, sub;
  if (h.demo) { word = "Demo"; ico = "●"; color = "var(--accent)"; sub = "v" + (h.version || ""); }
  else if (wd.supervised && !wd.alive) { word = "Down"; ico = "⚠"; color = "var(--err)"; sub = t("auto-restarting") + (wd.backoff_ms ? " · backoff " + Math.round(wd.backoff_ms / 1000) + "s" : ""); }
  else if (wd.backoff_ms) { word = "Crash-loop"; ico = "↻"; color = "var(--warn)"; sub = t("{0} restarts · backoff {1}s", wd.restarts || 0, Math.round(wd.backoff_ms / 1000)); }
  else if (wd.supervised && wd.alive) { word = "Running"; ico = "✓"; color = "var(--ok)"; sub = wd.restarts ? (t("↻ {0} restart(s)", wd.restarts) + (wd.last_error ? t(" · last: {0}", shortErr(wd.last_error)) : "")) : t("supervised"); }
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
  if (h.reconnects) parts.push(part("", t("{0} restart(s)", h.reconnects)));
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
  c.spark.forEach(cv => drawSpark(cv, sparkBuf[cv.getAttribute("data-spark")]));
  paintHero();
  paintConnections(); // live-refresh the connections table (no-op off the dashboard)
  paintSystem(sys);   // live-refresh RAM/temp + throughput; reuses the batched sample when given
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
    const txt = "↓ " + r.down_mbps + (r.up_mbps ? "  ↑ " + r.up_mbps : "") + " Mbps" + (r.pinned ? "" : " " + t("(active route)"));
    speedResults[e.id] = { text: txt, ts: Date.now(), ok: true };
    if (out) { out.textContent = txt; out.style.color = "var(--ok)"; } else toast((e.name || e.id) + ": " + txt, "ok");
  } catch (err) { speedResults[e.id] = { text: t("failed"), ts: Date.now(), ok: false }; if (out) { out.textContent = t("failed"); out.style.color = "var(--err)"; } toast(t("Speedtest: {0}", err.message), "err"); }
  finally { btn.removeAttribute("disabled"); btn.textContent = label; }
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
    (r || []).forEach(h => {
      healthMap[h.id] = h;
      const b = sparkBuf[h.id] || (sparkBuf[h.id] = []);
      b.push({ up: h.rate_up_bps || 0, down: h.rate_down_bps || 0 });
      if (b.length > SPARK_MAX) b.shift();
    });
    // Drop spark buffers for endpoints that no longer exist (deleted/renamed) so sparkBuf can't grow
    // unbounded over a long session. Only prune on a real array response, not a transient null.
    if (Array.isArray(r)) for (const id in sparkBuf) if (!(id in healthMap)) delete sparkBuf[id];
    if (pl) { pluginMap = {}; pl.forEach(p => pluginMap[p.id] = p); }
    if (wd) watchdog = wd;
    refreshPills(sys);
  } catch (e) {
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
async function runSpeedtest(btn, out) {
  const label = btn.textContent;
  btn.setAttribute("disabled", "true"); btn.textContent = t("Testing…");
  if (out) { out.textContent = t("running…"); out.style.color = "var(--ink-2)"; }
  try {
    const r = await api.post("/api/speedtest", { bytes: 10000000 });
    const txt = "↓ " + r.down_mbps + " Mbps" + (r.up_mbps ? "   ↑ " + r.up_mbps + " Mbps" : "") + "   ·   " + (r.latency_ms ?? "?") + " ms (" + (r.via ?? "?") + ")";
    speedResults["__global"] = { text: txt, ts: Date.now(), ok: true };
    if (out) { out.textContent = txt; out.style.color = "var(--ok)"; }
  } catch (e) { speedResults["__global"] = { text: t("failed: {0}", e.message), ts: Date.now(), ok: false }; if (out) { out.textContent = t("failed: {0}", e.message); out.style.color = "var(--err)"; } toast(t("Speedtest: {0}", e.message), "err"); }
  finally { btn.removeAttribute("disabled"); btn.textContent = label; }
}

/* ---------- Updater (engine version manager) ---------- */
async function renderUpdater(view) {
  view.appendChild(el("div", { class: "block-head" },
    el("div", {},
      el("div", { class: "ttl" }, "Updater"),
      el("div", { class: "desc" }, "Keep WayHop and its proxy engines up to date."))));
  view.appendChild(selfUpdateCard()); // WayHop self-update — at the top (fills async, non-blocking)
  const loadingEngines = el("div", { class: "hint", style: "margin:18px 0" }, t("checking engine versions…"));
  view.appendChild(loadingEngines);
  let data;
  try { data = await api.get("/api/updater/engines"); }
  catch (e) { loadingEngines.remove(); renderError(view, e); return; }
  loadingEngines.remove();
  const mirrorCount = (data.mirrors || []).filter(Boolean).length;
  view.appendChild(el("div", { class: "row-between", style: "margin:18px 0 16px" },
    el("div", { class: "card-title" }, t("Engine versions")),
    el("div", { class: "hint" }, t("router arch: {0}", data.arch || "?") + " · " + (mirrorCount ? t("{0} mirror(s)", mirrorCount) : t("direct")))));
  // Foreground the engines the router actually runs (core + plugins); tuck the
  // catalog-only standalone cores (sing-box covers their protocols natively) into a
  // collapsed "Advanced" group. Falls back to a flat list if the backend predates roles.
  const engines = data.engines || [];
  const pmKind = data.package_manager || "";
  const router = engines.filter(e => e.role && e.role !== "standalone");
  const advanced = engines.filter(e => !e.role || e.role === "standalone");
  (router.length ? router : engines).forEach(e => view.appendChild(engineCard(e, pmKind)));
  if (router.length && advanced.length) {
    const det = el("details", { style: "margin-top:6px" });
    det.appendChild(el("summary", { class: "hint", style: "cursor:pointer;font-weight:600;padding:8px 0" },
      t("Advanced — {0} engine(s) not used on this router", advanced.length)));
    det.appendChild(el("div", { class: "hint", style: "margin:2px 0 12px;max-width:60ch" },
      t("sing-box handles these protocols natively, so the router never runs these binaries. Install one only if you run the standalone core yourself.")));
    advanced.forEach(e => det.appendChild(engineCard(e, pmKind)));
    view.appendChild(det);
  }
}
const ENGINE_ROLE_HINT = { "core": "core", "kernel-plugin": "kernel plugin", "socks-plugin": "SOCKS plugin", "standalone": "standalone core" };

// WayHop self-update card: current version, available release, "Update now",
// and an auto-update toggle. Backed by /api/updater/self*. Returns synchronously with a
// placeholder and fills in async so the slow GitHub check never blocks the page render.
function selfUpdateCard() {
  const card = el("div", { class: "card" });
  card.appendChild(el("div", { class: "card-title", style: "margin-bottom:10px" }, "WayHop"));
  const body = el("div", {}, el("div", { class: "hint" }, t("checking for updates…")));
  card.appendChild(body);
  (async () => {
  try {
    const s = await api.get("/api/updater/self");
    body.innerHTML = "";
    const avail = !!s.update_available;
    // Feed-installed wayhop (opkg/apk owns the binary): a panel self-swap would fight the package
    // manager, so the backend refuses it (409) — hide the button and say how to upgrade instead.
    const managed = !!s.native_managed;
    const badge = avail
      ? el("span", { class: "badge badge-ok", style: "margin-left:8px" }, t("update → {0}", s.latest || "?"))
      : el("span", { class: "pill muted", style: "margin-left:8px" }, el("span", { class: "dot" }), s.error ? "check failed" : "up to date");
    body.appendChild(el("div", { class: "row-between" },
      el("div", {},
        el("div", { class: "name", style: "font-size:16px" }, "v" + (s.current || "?"), badge,
          managed ? el("span", { class: "pill muted", style: "margin-left:8px" }, el("span", { class: "dot" }), t("managed by {0}", s.package_manager || "the system")) : null),
        el("div", { class: "sub", style: "margin-top:3px" }, s.repo + (s.error ? " · " + s.error : (s.latest ? t(" · latest {0}", s.latest) : "")))),
      el("div", { class: "acts" },
        (avail && !managed) ? el("button", { class: "btn btn-primary btn-sm", onclick: ev => selfUpdate(ev.target) }, "Update now") : null)));
    if (managed) {
      body.appendChild(el("div", { class: "hint", style: "margin-top:10px" },
        t("WayHop was installed from the package feed — upgrade it with {0} over SSH; the panel's self-update (and auto-update) won't replace a package-owned binary.", s.package_manager || "opkg/apk")));
    }
    const tog = switchEl(s.auto_update, tel => selfAutoToggle(tel), "Auto-update WayHop");
    body.appendChild(el("div", { class: "row-between", style: "margin-top:14px" },
      el("div", { class: "hint", style: "max-width:70%" }, "Auto-update: install new WayHop releases automatically (daily check) and restart"),
      tog));
  } catch (e) {
    body.innerHTML = "";
    body.appendChild(el("div", { class: "hint", style: "color:var(--err)" }, e.message));
  }
  })();
  return card;
}

async function selfUpdate(btn) {
  if (!await modalConfirm("Download the latest WayHop release, replace the running binary, and restart the service? The panel will briefly drop, then return.")) return;
  btn.setAttribute("disabled", "true"); btn.textContent = t("Updating…");
  try {
    const r = await api.post("/api/updater/self/install", {});
    toast(t("WayHop → {0}", r.installed) + (r.restarting ? " · " + t("restarting…") : (r.note ? " · " + r.note : "")), "ok");
    // The daemon swaps its binary and restarts ~1s after responding, so the panel is about to
    // drop. Poll /api/health and reload when it returns (same recovery restartService uses) —
    // otherwise the user is stranded on a frozen Updater page with a disabled button.
    if (r.restarting) showReconnect();
  } catch (e) { toast(t("Update failed: {0}", e.message), "err"); btn.removeAttribute("disabled"); btn.textContent = t("Update now"); }
}

async function selfAutoToggle(tog) {
  const on = !tog.classList.contains("on");
  try {
    await api.put("/api/updater/self/auto", { enabled: on });
    tog.classList.toggle("on", on);
    tog.setAttribute("aria-checked", on ? "true" : "false"); // flipped in place, no re-render
    toast(on ? t("Auto-update enabled") : t("Auto-update disabled"), "ok");
  } catch (e) { toast(e.message, "err"); }
}

function engineCard(e, pmKind) {
  const card = el("div", { class: "card" });
  const inst = e.installed || {};
  // A PM-owned binary (apk/opkg): the backend refuses panel install/remove (409) so it can't
  // clobber the packaged file or orphan the package DB — say so up front instead of after a
  // failed click, and don't render buttons that can only error.
  const managed = !!e.native_managed;
  card.appendChild(el("div", { class: "row-between" },
    el("div", {},
      el("div", { class: "name", style: "font-size:16px" }, e.name,
        inst.present
          ? el("span", { class: "badge", style: "margin-left:8px" }, inst.version || "installed")
          : el("span", { class: "pill muted", style: "margin-left:8px" }, el("span", { class: "dot" }), "not installed"),
        managed ? el("span", { class: "pill muted", style: "margin-left:8px" }, el("span", { class: "dot" }), t("managed by {0}", pmKind || "the system")) : null),
      el("div", { class: "sub", style: "margin-top:3px" }, e.repo + (e.role ? t(" · runs as {0}", t(ENGINE_ROLE_HINT[e.role] || e.role)) : ""))),
    el("div", { class: "acts" },
      managed ? null : el("button", { class: "btn btn-sm", onclick: () => loadVersions(e, card) }, "Check updates"),
      (!managed && inst.present && !e.source_only)
        ? el("button", { class: "btn btn-sm btn-danger", onclick: ev => removeEngine(e, ev.currentTarget) }, "Remove")
        : null)));
  const box = el("div", { class: "vbox", style: "margin-top:12px" });
  if (managed) box.appendChild(el("div", { class: "hint" },
    e.native_owner
      ? t("Installed by the system package manager (package {0}). Update or remove it with {1} over SSH — the panel won't touch it.", e.native_owner, pmKind || "opkg/apk")
      : t("Installed by the system package manager. Update or remove it with {0} over SSH — the panel won't touch it.", pmKind || "opkg/apk")));
  if (e.source_only) box.appendChild(el("div", { class: "hint" }, e.note || "No prebuilt releases."));
  if (e.last_error) box.appendChild(el("div", { class: "hint", style: "color:var(--err);margin-top:4px" }, t("Last update failed:") + " " + e.last_error));
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
        sel.setAttribute("aria-label", t("Version")); // version-picker had no accessible name
        box.appendChild(el("div", { style: "max-width:280px" }, sel));
      }
      box.appendChild(el("div", { class: "hint", style: "margin-top:8px" }, "installed: " + (v.installed || "none") + (v.latest ? " · latest: " + v.latest : "")));
      box.appendChild(el("div", { class: "hint", style: "margin-top:6px" }, v.note || "Build from source on the device."));
      return;
    }
    const sel = el("select", {}, ...(v.versions || []).map(t => el("option", { value: t }, t + (t === v.latest ? "  (latest)" : ""))));
    sel.setAttribute("aria-label", t("Version"));
    const btn = el("button", { class: "btn btn-primary btn-sm", onclick: () => installVersion(e, sel.value, btn) }, "Install selected");
    box.appendChild(el("div", { style: "display:flex;gap:10px;align-items:center" }, sel, btn));
    box.appendChild(el("div", { class: "hint", style: "margin-top:6px" }, "installed: " + (v.installed || "none") + " · latest: " + (v.latest || "?")));
  } catch (err) { box.innerHTML = ""; box.appendChild(el("div", { class: "hint", style: "color:var(--err)" }, err.message)); }
}

async function installVersion(e, version, btn) {
  if (!version) return;
  if (!await modalConfirm(t("Download and install {0} {1} for this router?", e.name, version))) return;
  btn.setAttribute("disabled", "true"); btn.textContent = "Installing…";
  try {
    const r = await api.post("/api/updater/" + encodeURIComponent(e.id) + "/install", { version });
    toast(e.name + " → " + r.installed + (r.reloaded ? " (reloaded)" : ""), "ok");
    route();
  } catch (err) {
    toast(t("Install failed: {0}", err.message), "err");
    const card = btn.closest(".card");
    const box = card && card.querySelector(".vbox");
    if (box) box.appendChild(el("div", { class: "hint", style: "color:var(--err);margin-top:8px" }, t("Install failed:") + " " + err.message));
    btn.removeAttribute("disabled"); btn.textContent = "Install selected";
  }
}

async function removeEngine(e, btn) {
  if (!await modalConfirm(t("Delete the installed {0} binary from this router?", e.name))) return;
  btn.setAttribute("disabled", "true"); btn.textContent = t("Removing…");
  try {
    await api.del("/api/updater/" + encodeURIComponent(e.id));
    toast(t("{0} removed", e.name), "ok");
    route();
  } catch (err) { toast(t("Remove failed:") + " " + err.message, "err"); btn.removeAttribute("disabled"); btn.textContent = t("Remove"); }
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
    el("div", { class: "card-title", style: "margin-bottom:var(--sp-2)" }, t("Native support")),
    el("div", { class: "hint" }, t("Loading…"))));
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
  // /api/vpn/adopt: the OS keeps owning the tunnel; WayHop only adds a DISABLED
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
          t("WayHop will ROUTE THROUGH the tunnel but does not manage it (the OS owns it). It is added disabled — enable it in Connections to start routing.")));
      vpns.forEach(v => {
        const parts = [v.iface, v.type, v.public_key].filter(Boolean);
        const statusPill = v.active
          ? el("span", { class: "pill ok", title: t("Tunnel has a recent handshake") }, el("span", { class: "dot" }), t("active"))
          : el("span", { class: "pill muted", title: t("Configured but no recent handshake") }, t("idle"));
        // Adopt button: disabled-looking "Adopted" once an external endpoint exists
        // for this iface; otherwise a btn-sm that adopts + refreshes the card.
        const adoptBtn = adopted(v.iface)
          ? el("button", { class: "btn btn-sm", disabled: "true", title: t("Already added as a routing exit") }, t("Adopted"))
          : el("button", { class: "btn btn-sm", title: t("Add this OS-owned tunnel as a routing exit (added disabled — WayHop will not manage it)"),
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
  const safe = (id, fn) => async () => { try { set(id, await fn()); } catch (e) { set(id, { status: "warn", summary: t("check failed"), detail: e.message }); } };
  const tasks = Object.keys(CHECKS).map(id => safe(id, CHECKS[id]));
  tasks.push(async () => { // backend-only probes folded in: clock skew + IPv6 leak + DoH
    try { const d = await api.get("/api/healthcheck"); (d.checks || []).forEach(c => set(c.id, { status: c.status, summary: c.summary, detail: c.detail, fix: c.fix })); }
    catch (e) { HC_BACKEND.forEach(id => set(id, { status: "warn", summary: t("unavailable"), detail: e.message })); }
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
    else { const d = await api.get("/api/healthcheck"); const c = (d.checks || []).find(x => x.id === id); settle(c ? { status: c.status, summary: c.summary, detail: c.detail, fix: c.fix } : { status: "warn", summary: t("unavailable") }); }
  } catch (e) { settle({ status: "warn", summary: t("check failed"), detail: e.message }); }
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
  const chipLabel = busy || (!r && running) ? t("checking…") : !r ? t("pending") : r.status === "pass" ? t("pass") : r.status === "warn" ? t("warning") : t("fail");
  const chip = el("span", { class: "pill " + chipCls, role: "img", "aria-label": chipLabel }, chipInner);
  // r.summary/detail/fix may be server-provided (backend checks) — translate them here too.
  // Client-side chk* strings are already localized, so t() is a no-op pass-through for those.
  const res = el("span", { class: "res" }, busy ? t("checking…") : !r && running ? t("checking…") : !r ? "—" : (r.summary ? t(r.summary) : ""));
  // per-row re-check: re-run just this check after a fix, without the whole battery
  const recheck = el("button", { class: "btn-icon", title: t("Re-check"), "aria-label": t("Re-check"), onclick: (e) => { e.stopPropagation(); recheckOne(id); } }, "↻");
  recheck.disabled = !!(running || busy);
  const head = el("div", { class: "health-row" }, chip, el("span", { class: "lbl" }, t(HC_LABEL[id] || id)), res, recheck);
  const expandable = r && !busy && (r.status !== "pass" || r.detail || r.kb || r.fix);
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
  body.appendChild(el("button", { class: "btn btn-sm", style: "margin-top:8px", onclick: () => copyText("[" + r.status.toUpperCase() + "] " + t(HC_LABEL[id] || id) + " — " + (r.summary || "") + (r.detail ? "\n" + r.detail : "")) }, t("Copy")));
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
  a11yClick(chev, (ev) => { if (ev && ev.stopPropagation) ev.stopPropagation(); toggle(); }, t(HC_LABEL[id] || id));
  return el("div", {}, head, body);
}

async function chkCore() {
  const w = await api.get("/api/watchdog");
  const d = "restarts " + (w.restarts || 0) + (w.last_restart ? " · last " + new Date(w.last_restart).toLocaleString("en-GB") : "") + (w.last_error ? "\nlast error: " + w.last_error : "");
  if (w.supervised && w.alive) return { status: w.restarts ? "warn" : "pass", summary: w.restarts ? t("running (crashed {0}× since boot)", w.restarts) : t("sing-box running"), detail: d, fix: w.restarts ? t("The core has crash-restarted — check Log analysis below for the cause.") : "" };
  if (!w.supervised) return { status: "warn", summary: t("not started (WAN-only)"), detail: d };
  return { status: "fail", summary: t("down — auto-restarting"), detail: d, fix: t("The VPN core stopped and is restarting itself. If it keeps crashing, check Log analysis below for the error.") };
}
async function chkInternet() {
  const r = await api.post("/api/netdiag/all", { target: "cloudflare.com" });
  const rows = r.results || [], wan = rows.find(x => x.egress === "direct"), tun = rows.filter(x => x.egress !== "direct");
  const up = tun.filter(x => x.reachable).length;
  const d = rows.map(x => (x.reachable ? "✓ " : "✗ ") + (x.name || x.egress) + (x.reachable ? " · " + x.latency_ms + " ms" : " · " + (x.err || "unreachable"))).join("\n");
  if (!wan) return { status: "warn", summary: t("couldn't test (core not running?)"), detail: d };
  if (!wan.reachable) return { status: "fail", summary: t("no internet on the router"), detail: d, fix: t("The router itself can't reach the internet. Check the cable/modem and your ISP — this isn't a VPN problem.") };
  return { status: "pass", summary: t("online · WAN {0} ms · {1}/{2} tunnels reach out", wan.latency_ms, up, tun.length), detail: d };
}
async function chkTunnels() {
  const eps = await api.get("/api/health/endpoints");
  const tun = (eps || []).filter(e => e.kind !== "group");
  if (!tun.length) return { status: "warn", summary: t("no tunnels configured") };
  const up = tun.filter(e => e.state === "alive"), down = tun.filter(e => e.state === "down");
  const d = tun.map(e => (e.state === "alive" ? "✓ " : e.state === "down" ? "✗ " : "… ") + (e.name || e.id) + (e.latency_ms ? " · " + e.latency_ms + " ms" : "") + (e.success_rate ? " · " + e.success_rate + "%" : "") + (e.cause ? " · " + e.cause : "")).join("\n");
  if (up.length === tun.length) return { status: "pass", summary: t("all {0} tunnels up", tun.length), detail: d };
  const fix = down.map(e => (e.name || e.id) + ": " + (e.cause_fix || e.cause || t("down"))).join("\n");
  if (up.length === 0) return { status: "fail", summary: t("all tunnels down"), detail: d, fix: fix || t("All tunnels are down — open Connections to toggle/restart them or check the servers."), deep: "connections" };
  return { status: "warn", summary: t("{0} of {1} tunnels up", up.length, tun.length), detail: d, fix, deep: "connections" };
}
async function chkExit() {
  const x = await api.get("/api/exit-ip");
  if (!x.available || !x.ip) return { status: "warn", summary: t("unknown"), detail: t("No exit IP — sing-box may be off, or general traffic uses the WAN by design (split-tunnel).") };
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
  if (!s.available) return { status: "warn", summary: t("unavailable"), meta };
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
    if (viaTun.length) lines.push("✓ " + label + " · " + t("via {0} tunnel(s) ({1})", viaTun.length, viaTun.map(x => x.name || x.egress).join(", ")));
    else if (wan && wan.reachable) { lines.push("● " + label + " · " + t("only on WAN — no tunnel reached it")); bad.push(label + ": " + t("no tunnel reached it")); }
    else { lines.push("✗ " + label + " · " + t("unreachable everywhere")); bad.push(label + ": " + t("unreachable (DPI/dead?)")); }
  }
  const detail = lines.join("\n");
  if (!anyData) return { status: "warn", summary: t("couldn't test (core not running?)"), detail };
  if (bad.length) return { status: "warn", summary: t("{0} of {1} not reachable via a tunnel", bad.length, hosts.length), detail, fix: bad.join("\n") + "\n" + t("Open Connections to check the tunnels, or Routing to confirm the carve-outs."), deep: "connections" };
  return { status: "pass", summary: t("blocked sites reachable through tunnels"), detail };
}
async function chkLog() {
  const d = await api.get("/api/diagnostics");
  const n = (d.found || []).length;
  if (!n) return { status: "pass", summary: d.count ? t("no known errors in {0} log lines", d.count) : t("no log yet") };
  return { status: "warn", summary: t("sing-box logged {0} known issue(s)", n), kb: d.found };
}

function humanDur(sec) { sec = +sec || 0; const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60); return d ? d + "d " + h + "h" : h ? h + "h " + m + "m" : m + "m"; }
// ccFlag turns a 2-letter ISO country code into its regional-indicator emoji flag.
function ccFlag(cc) { if (!cc || !/^[A-Za-z]{2}$/.test(cc)) return ""; cc = cc.toUpperCase(); return String.fromCodePoint(...[...cc].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)); }
function timeAgo(ms) { const s = Math.round((Date.now() - ms) / 1000); return s < 60 ? t("just now") : s < 3600 ? t("{0} min ago", Math.floor(s / 60)) : t("{0}h ago", Math.floor(s / 3600)); }
// copyText copies to the clipboard with graceful degradation for the panel's real
// deployment: it is served over plain HTTP on a LAN IP (e.g. http://192.168.1.1:8088),
// which is NOT a secure context, so navigator.clipboard is undefined. Chain:
// async Clipboard API → execCommand("copy") → a manual-copy modal (pre-selected
// textarea) so the user can always get the text out (Ctrl/Cmd+C) instead of a dead end.
function copyText(str) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(str).then(() => toast(t("Copied"), "ok"), () => execCopy(str));
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
    if (ok) { toast(t("Copied"), "ok"); return; }
  } catch (_) { /* fall through to the manual modal */ }
  copyManualModal(str);
}
function copyManualModal(str) {
  const ta = el("textarea", { readonly: "readonly", style: "width:100%;min-height:160px;font-family:ui-monospace,Consolas,monospace;font-size:12px;line-height:1.5" });
  ta.value = str;
  modal({
    title: t("Copy manually"),
    body: el("div", {},
      el("div", { class: "hint", style: "margin-bottom:8px" }, t("Automatic copy is blocked (the panel runs over plain HTTP, not a secure context). Select all and press Ctrl/Cmd+C.")),
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
  let out = "## WayHop diagnostics\n";
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
      if (iface) btnRow.appendChild(el("span", { class: "hint" }, t("↳ bound to {0}", iface)));
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
  return el("div", { style: "font-family:ui-monospace,Consolas,monospace;font-size:12px;white-space:pre-wrap;overflow-wrap:anywhere;background:var(--card-2);border-radius:7px;padding:10px 12px;max-height:280px;overflow:auto;line-height:1.5" }, text || "(no output)");
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
  if (wan && !wan.reachable) out.appendChild(el("div", { class: "hint", style: "margin-top:10px;color:var(--warn)" },
    t("WAN (direct) failed too — the router itself can't reach this target; check the uplink/DNS.")));
}

function renderDiagResult(out, r) {
  if (r.found && r.found.length) {
    out.appendChild(el("div", { class: "card-title", style: "margin:6px 0 10px" }, t("{0} known issue(s) detected", r.found.length)));
    r.found.forEach(e => out.appendChild(kbCard(e)));
  } else {
    out.appendChild(el("div", { class: "card" }, el("div", { class: "empty" },
      r.count ? t("No known errors matched in {0} log lines.", r.count) : t("No log yet. Paste logs above, or start sing-box on the device and reload."))));
  }
  if (r.lines && r.lines.length) {
    const pre = el("div", { style: "font-family:ui-monospace,Consolas,monospace;font-size:12px;max-height:340px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.55" });
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
          sv.hardened ? el("span", { class: "pill ok pill--dot", title: "Key-only login", role: "img", "aria-label": "Key-only login" }, el("span", { class: "dot" })) : null),
        el("div", { class: "sub" }, ...meta, el("span", { class: "addr" }, (sv.user || "root") + "@" + sv.host + ":" + (sv.port || 22))),
        el("div", { class: "stats" }, sv.hardened ? el("b", {}, "🔒 hardened — password login disabled") : el("span", {}, "password login still enabled"))),
      el("div", { class: "acts" },
        el("button", { class: "btn btn-primary btn-sm", onclick: () => openProvision(sv) }, "Set up"),
        el("button", { class: "btn btn-sm", onclick: () => openHarden(sv) }, sv.hardened ? "Re-key" : "Secure"),
        el("button", { class: "btn btn-sm", onclick: () => openVersions(sv) }, "Versions"),
        el("button", { class: "btn btn-danger btn-sm", onclick: () => delServer(sv) }, "Delete"))));
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

// Setup-options picker — the list of what WayHop can install, with details.
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
        if (++fails >= 5) stop();
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
  const back = modal({
    title: t("Set up {0}", (sv && (sv.name || sv.host)) || t("server")),
    body: el("div", {}, c.node,
      el("div", { class: "card-title", style: "margin:18px 0 10px" }, "What to set up"),
      picker.node, con.node),
    footer: el("div", { style: "display:flex;gap:10px;flex-wrap:wrap" }, checkBtn, previewBtn, runBtn),
  });
  checkBtn.addEventListener("click", async () => {
    const cr = c.get();
    if (!cr.host) return toast("Enter a host first", "err");
    checkBtn.disabled = true;
    try {
      const r = await api.post("/api/server/check", { host: cr.host, port: cr.port });
      toast(t("{0} — ping {1}, SSH port {2} {3}", r.reachable ? t("✓ reachable") : t("✗ unreachable"), r.ping_ok ? ((r.ping_ms != null ? Math.round(r.ping_ms) : "?") + " ms") : t("no reply"), r.port, r.port_open ? t("open") : t("closed")), r.reachable ? "ok" : "err");
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
    runBtn.disabled = true; runBtn.textContent = t("Working…");
    try {
      const r = await api.post("/api/server/provision", { server_id: sv && sv.id, name: sv && sv.name, ...cr, protocols: opts });
      con.run(r.job_id, v => {
        runBtn.disabled = false; runBtn.textContent = t("Set up again");
        if (v.ok) toast("Done — client added to Connections", "ok");
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
      el("div", { class: "desc" }, t("Daemon configuration. Saving here stores these settings; the Apply button in the top bar regenerates routing — they are separate actions. Fields tagged ↻ take effect only after WayHop restarts."))),
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
      associateLabels(bodyDiv); // this card's fields are built in an async .then, AFTER route()'s one-shot associateLabels ran
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
  const sbCfg = txt(cfg.singbox && cfg.singbox.config, "/opt/etc/wayhop/singbox.json");
  const clashCtl = txt(cfg.clash && cfg.clash.controller, "127.0.0.1:9090");
  const clashSecF = secretInput(cfg.clash && cfg.clash.secret, t("optional"));
  const clashSec = clashSecF.input;
  // Ports
  const pUI = num(cfg.ports && cfg.ports.ui), pClash = num(cfg.ports && cfg.ports.clash),
    pDNS = num(cfg.ports && cfg.ports.dns), pMixed = num(cfg.ports && cfg.ports.mixed);
  // Updater mirrors
  const mirrors0 = (cfg.updater && cfg.updater.mirrors) || [];
  const directFirst = el("input", { type: "checkbox" }); directFirst.checked = mirrors0.includes("");
  const mirrorsTA = el("textarea", { placeholder: "https://ghproxy.net/\nhttps://mirror.ghproxy.com/", "aria-label": t("Updater mirrors") });
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
  const allowedHosts = el("textarea", { placeholder: "192.168.1.1\nrouter.lan", "aria-label": t("Host allow-list") });
  allowedHosts.value = (cfg.allowed_hosts || []).join("\n");
  // Routing mode (applies on the next Apply, not a restart)
  const ROUTE_MODES = [
    ["hybrid", t("Everything via WayHop (domain carve-outs work; general traffic slower / CPU-bound)")],
    ["fast", t("Fast: general traffic bypasses WayHop (kernel fast-path) — IP carve-outs (calls/VoWiFi) still work; domain carve-outs OFF")],
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
    ["sw", t("Software flow-offload (recommended)")],
    ["hw", t("Hardware offload (PPE/WED) — can stall VPN tunnels; not faster on most routers")],
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
      toast(r.restart_needed ? t("Saved — restart WayHop for all changes to take effect.") : t("Saved."), "ok");
      if (routeModeChanged) toast(t("Routing mode changed — press Apply (top bar) to activate it."), "info");
      else if (offloadChanged) toast(t("Flow offload changed — press Apply (top bar) to activate it."), "info");
    } catch (e) { status.textContent = ""; toast(e.message, "err"); }
    finally { save.disabled = false; }
  });

  view.appendChild(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:8px" }, t("Routing mode")),
    el("div", { class: "hint", style: "margin-bottom:10px" }, t("How LAN traffic is routed. «Fast» keeps your tunnels/carve-outs for IPs (calls, VoWiFi) but lets general traffic (downloads, games) take the kernel fast-path instead of the userspace proxy — much higher throughput. Takes effect on the next Apply.")),
    field(t("Mode"), routeMode),
    el("div", { class: "hint", style: "margin:14px 0 10px" }, t("Flow offload accelerates general (non-tunnel) traffic via the kernel fast path in «Fast» mode. Your tunnel carve-outs (calls, VoWiFi, blocked sites) are mark-routed and automatically excluded, so they keep working. «Software» is recommended — it routes near line-rate on most routers without touching your tunnels. «Hardware» (PPE/WED) can be faster on some NICs, but on many routers it has a bug that stalls VPN tunnels (long-lived UDP) and is no faster than software — avoid it if you route any traffic through a tunnel. Leave devices blank to auto-detect the WAN + LAN interfaces. Takes effect on the next Apply.")),
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
    el("div", { class: "hint", style: "margin-bottom:10px" }, t("After an Apply (not yet saved), WayHop pings this target to confirm the new config kept you online; if it can't be reached, the previous config is rolled back.")),
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
    if (!await modalConfirm(t("Reset settings to defaults? Your panel address, UI port, host allow-list and subscription token are kept; everything else returns to defaults."))) return;
    try {
      const r = await api.post("/api/config/reset", {});
      toast(r.restart_needed ? t("Reset to defaults — restart WayHop to apply.") : t("Reset to defaults."), "ok");
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
    if (parsed.wayhop_backup !== 1) { fullFileInput.value = ""; return toast(t("That is not a WayHop full backup."), "err"); }
    if (!await modalConfirm(t("Restore your whole setup from this backup? It replaces all connections, groups and routing lists (validated first). Nothing is applied automatically — review it, then press Apply. Your panel address and access settings are NOT changed."))) { fullFileInput.value = ""; return; }
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
    el("div", { class: "hint", style: "margin-bottom:6px" }, t("Save your whole setup — connections, failover groups, routing lists, saved servers and routing mode — to one file. Ideal before a firmware reflash or when moving to another WayHop. Restoring validates everything first and never applies on its own; you review it and press Apply.")),
    el("div", { class: "hint", style: "margin-bottom:12px" }, t("The backup file contains your connection secrets (keys, passwords) — keep it private. Daemon access settings (panel port and host allow-list) are NOT changed by a restore.")),
    el("div", { style: "display:flex;gap:10px;flex-wrap:wrap;align-items:center" },
      fullDownloadBtn, fullRestoreBtn, fullFileInput)));

  const restartBtn = el("button", { class: "btn btn-danger" }, t("Restart service"));
  restartBtn.addEventListener("click", restartService);
  if (cfg.demo) restartBtn.disabled = true; // the demo daemon rejects /api/service/restart — don't let the button dead-end after a confirm; the card copy already says it's unavailable
  view.appendChild(el("div", { class: "card" },
    el("div", { class: "card-title", style: "margin-bottom:10px" }, t("Service")),
    el("div", { class: "hint", style: "margin-bottom:12px" }, t("Restart the whole WayHop daemon (panel + proxy core). The web panel drops for a few seconds while the init system brings it back; this page reconnects automatically. (Not available in the demo.)")),
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
  updateDirty();
}
async function loadHealth() { state.health = await api.get("/api/health"); updateStatusPill(); }

/* ---------- init ---------- */
async function init() {
  $$(".nav-item").forEach(wireNavItem); // keyboard-operable nav (role/tabindex/Enter-Space); see wireNavItem
  // Mobile nav drawer: the burger is a <label> (not keyboard-focusable) driving an aria-hidden checkbox
  // that is itself in the tab order. Make the burger a real button (role/tabindex/Enter-Space + aria-expanded)
  // and drop the hidden checkbox out of the tab order, so keyboard/AT users can open the drawer.
  const burger = $(".nav-burger"), navToggle = $("#navtoggle");
  if (navToggle) navToggle.tabIndex = -1;
  if (burger) {
    burger.setAttribute("role", "button");
    burger.setAttribute("tabindex", "0");
    burger.setAttribute("aria-expanded", "false");
    if (navToggle) {
      const syncExpanded = () => burger.setAttribute("aria-expanded", navToggle.checked ? "true" : "false");
      navToggle.addEventListener("change", syncExpanded);
      burger.addEventListener("keydown", ev => {
        if (ev.key === "Enter" || ev.key === " " || ev.key === "Spacebar") { ev.preventDefault(); navToggle.checked = !navToggle.checked; syncExpanded(); }
      });
    }
  }
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
  setInterval(() => { if (!document.hidden) { loadHealth().catch(e => { if (isNetworkError(e)) showReconnect(); }); checkFailsafe(); } }, 5000);
  setInterval(() => { if (!document.hidden && onGraph()) pollTraffic(); }, 1000);
  setInterval(() => { if (!document.hidden && onHealth()) pollHealth(); }, 5000);
  // Refresh immediately on tab refocus so data isn't a full interval stale.
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) return;
    loadHealth().catch(e => { if (isNetworkError(e)) showReconnect(); });
    checkFailsafe();
    if (onGraph()) pollTraffic();
    if (onHealth()) pollHealth();
  });
  i18nObserve();
  translateChrome();
  refreshPluginNav(); // inject nav items for any installed plugin modules (P5)
  route();
}
init();
