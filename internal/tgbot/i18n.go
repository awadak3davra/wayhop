package tgbot

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Languages the bot speaks. The first is the fallback.
var Languages = []string{"en", "ru", "uk"}

// clientLangs maps the Telegram client languages the bot does not answer in English to the language
// it answers in. Russian is the lingua franca of the CIS locales: a Kazakh or Belarusian client reads
// it more comfortably than English. Each of these codes gets its own command menu too.
var clientLangs = map[string]string{
	"ru": "ru", "be": "ru", "kk": "ru", "ky": "ru", "uz": "ru", "tg": "ru", "hy": "ru", "az": "ru",
	"uk": "uk",
}

// LangFor maps a Telegram language_code to a language the bot speaks.
func LangFor(code string) string {
	code = strings.ToLower(code)
	if i := strings.IndexAny(code, "-_"); i > 0 {
		code = code[:i]
	}
	if lang, ok := clientLangs[code]; ok {
		return lang
	}
	return Languages[0]
}

// msgs holds every user-visible string: key -> {en, ru}; the Ukrainian column is msgsUK. Values are
// fmt formats; every language of one key must take the same verbs (TestTranslationsAgree checks).
var msgs = map[string][2]string{
	// Headline verdicts.
	"h.good":       {"All good", "Всё в порядке"},
	"h.testing":    {"Test Apply awaiting confirmation", "Тестовое применение ждёт подтверждения"},
	"h.degraded":   {"Degraded", "Частичный сбой"},
	"h.localfault": {"No internet on the uplink", "Нет интернета у провайдера"},
	"h.down":       {"Down", "Не работает"},

	// Status lines.
	"st.exitip":         {"Exit: %s", "Выход: %s"},
	"st.exitip.unknown": {"Exit: not determined yet", "Выход: пока не определён"},
	"st.core.running":   {"Core: sing-box running", "Ядро: sing-box работает"},
	"st.core.native":    {"Core: native routing only (sing-box not needed)", "Ядро: только нативная маршрутизация (sing-box не нужен)"},
	"st.core.stopped":   {"Core: sing-box is <b>not running</b>", "Ядро: sing-box <b>не запущен</b>"},
	"st.core.absent":    {"Core: sing-box is not installed", "Ядро: sing-box не установлен"},
	"st.core.restarts":  {" · restarts: %d", " · перезапусков: %d"},
	"st.exits":          {"Exits: %d up · %d down", "Выходы: в строю %d · недоступно %d"},
	"st.exits.none":     {"Exits: none configured", "Выходы: не настроены"},
	"st.group":          {"%s → %s", "%s → %s"},
	"st.traffic":        {"Traffic: ↓ %s · ↑ %s", "Трафик: ↓ %s · ↑ %s"},
	"st.system":         {"Router: RAM %d%% · load %s · up %s", "Роутер: ОЗУ %d%% · нагрузка %s · аптайм %s"},
	"st.pending.none":   {"Changes: all applied", "Изменения: всё применено"},
	"st.feed":           {"⚠️ List %s is not updating: its feed has failed %s in a row, since %s. The list keeps what it last got.", "⚠️ Список %s не обновляется: загрузка не удалась %s подряд, с %s. Список работает с тем, что получил раньше."},
	"st.feed.empty":     {"⚠️ List %s has not loaded: its feed has failed %s in a row, since %s, so the list has nothing from it yet.", "⚠️ Список %s не загрузился: загрузка не удалась %s подряд, с %s, так что из источника в нём пока ничего нет."},
	"st.feeds":          {"⚠️ %s are not updating: %s. Their feeds keep failing.", "⚠️ Не обновляются %s: %s. Их источники не загружаются."},
	"st.feeds.more":     {" and %d more", " и ещё %d"},
	"st.pending":        {"Changes: <b>%d not applied</b> (Review &amp; Apply in the panel)", "Изменения: <b>не применено: %d</b> (Проверить и применить в панели)"},
	"st.pending.some":   {"Changes: <b>saved, not applied</b> (Review &amp; Apply in the panel)", "Изменения: <b>сохранены, не применены</b> (Проверить и применить в панели)"},
	"st.failsafe":       {"⏳ Test Apply: rolls back in %s unless kept", "⏳ Тестовое применение: откат через %s, если не подтвердить"},
	"st.update":         {"⬆️ WayHop %s is available", "⬆️ Доступна WayHop %s"},
	"st.localfault":     {"Every exit failed at once: this is the uplink or the router's own connection, not the tunnels.", "Отказали все выходы разом: проблема в канале провайдера или подключении роутера, а не в туннелях."},
	"st.demo":           {"demo mode", "демо-режим"},

	// Buttons.
	"b.refresh":  {"🔄 Refresh", "🔄 Обновить"},
	"b.exits":    {"🌍 Exits", "🌍 Выходы"},
	"b.events":   {"📜 Events", "📜 События"},
	"b.help":     {"❓ Help", "❓ Помощь"},
	"b.back":     {"⬅ Back", "⬅ Назад"},
	"b.status":   {"🏠 Status", "🏠 Статус"},
	"b.test":     {"⚡ Test now", "⚡ Проверить"},
	"b.older":    {"⬅ Older", "⬅ Раньше"},
	"b.newer":    {"Newer ➡", "Позже ➡"},
	"b.prevpage": {"⬅ Previous", "⬅ Назад"},
	"b.nextpage": {"Next ➡", "Дальше ➡"},
	"b.alerts":   {"🔔 Alerts", "🔔 Оповещения"},

	// A chat's own alert switches (/alerts).
	"an.title":      {"🔔 <b>Alerts in this chat</b>", "🔔 <b>Оповещения в этом чате</b>"},
	"an.hint":       {"Tap a kind to switch it on or off for this chat only.", "Нажмите на вид, чтобы включить или выключить его только в этом чате."},
	"an.panel":      {"Off in the panel for every chat: %s.", "Выключено в панели для всех чатов: %s."},
	"an.on":         {"🔔 %s: on in this chat", "🔔 %s: включено в этом чате"},
	"an.off":        {"🔕 %s: off in this chat", "🔕 %s: выключено в этом чате"},
	"err.save":      {"The setting could not be saved; try again.", "Не удалось сохранить настройку, попробуйте ещё раз."},
	"kind.exits":    {"Exits", "Выходы"},
	"kind.switches": {"Switches", "Переключения"},
	"kind.uplink":   {"Internet", "Интернет"},
	"kind.core":     {"Core", "Ядро"},
	"kind.apply":    {"Test Apply", "Тестовое применение"},
	"kind.boot":     {"Restarts", "Перезапуски"},
	"kind.system":   {"Memory", "Память"},
	"kind.updates":  {"Updates", "Обновления"},
	"kind.digest":   {"Daily summary", "Сводка за сутки"},
	"cmd.alerts":    {"Which alerts come to this chat", "Какие оповещения приходят в этот чат"},

	// Exits.
	"ex.title":                 {"<b>Exits</b>", "<b>Выходы</b>"},
	"ex.none":                  {"No exits are configured yet. Add a connection in the panel.", "Выходы ещё не настроены. Добавьте подключение в панели."},
	"ex.groups":                {"<b>Groups</b>", "<b>Группы</b>"},
	"ex.elected":               {"now on %s", "сейчас через %s"},
	"ex.noelected":             {"elected member unknown", "активный участник неизвестен"},
	"ex.latency":               {"%d ms", "%d мс"},
	"ex.success":               {"success %d%%", "успешно %d%%"},
	"ex.state":                 {"State: %s", "Состояние: %s"},
	"ex.up_for":                {"Up for %s", "Работает %s"},
	"ex.avg":                   {"Latency %s · avg %s · %s", "Задержка %s · средняя %s · %s"},
	"ex.rate":                  {"Traffic: ↓ %s · ↑ %s", "Трафик: ↓ %s · ↑ %s"},
	"ex.cause":                 {"Cause: %s", "Причина: %s"},
	"ex.fix":                   {"Fix: %s", "Что сделать: %s"},
	"cause.engine-missing.fix": {"Install sing-box on the Components page. This protocol runs inside it, so no change of server, port or transport can bring the exit up until it is there.", "Установите sing-box на странице «Компоненты». Этот протокол работает внутри него, и пока его нет, никакая смена сервера, порта или транспорта выход не поднимет."},
	"cause.engine-missing":     {"The engine this exit needs is not installed", "Не установлено ядро, нужное этому выходу"},
	"cause.no-response.fix":    {"Run Diagnostics (ping/traceroute) to the server. If the path is filtered (DPI/TSPU), try a camouflaged transport (Reality/WS-CDN) or AmneziaWG.", "Запустите Диагностику (ping, traceroute) до сервера. Если путь фильтруется (DPI, ТСПУ), попробуйте замаскированный транспорт (Reality, WS через CDN) или AmneziaWG."},
	"cause.no-response":        {"No response (timed out or blocked)", "Нет ответа (тайм-аут или блокировка)"},
	"ex.gone":                  {"This exit no longer exists.", "Этого выхода больше нет."},
	"ex.tested":                {"Tested just now", "Проверено только что"},
	"ex.testfail":              {"Test failed: %s", "Проверка не удалась: %s"},
	"state.alive":              {"up", "в строю"},
	"state.down":               {"down", "недоступен"},
	"state.unk":                {"unknown", "неизвестно"},

	// Events.
	"ev.title":   {"<b>Events</b>", "<b>События</b>"},
	"ev.since":   {"Log kept in RAM since %s (%s ago).", "Журнал хранится в памяти с %s (%s назад)."},
	"ev.empty":   {"Nothing happened since then: no outages, no switches.", "С тех пор ничего не случилось: ни отказов, ни переключений."},
	"ev.unknown": {"The failover log is not available (the health monitor is not running).", "Журнал отказов недоступен (монитор здоровья не запущен)."},
	"ev.down":    {"🔴 %s went down", "🔴 %s недоступен"},
	"ev.up":      {"🟢 %s is back", "🟢 %s снова в строю"},
	"ev.switch":  {"🔀 %s: %s → %s", "🔀 %s: %s → %s"},
	"ev.lat":     {" (%d ms)", " (%d мс)"},
	"ev.page":    {"Page %d of %d", "Страница %d из %d"},
	"ev.dropped": {"Older entries have been dropped from memory.", "Более старые записи вытеснены из памяти."},

	// Help and onboarding.
	// The help is put together per role (see view.Help): the commands everyone has, an owner's own,
	// the chat's settings, then what arrives by itself.
	"help": {
		"<b>WayHop bot</b>\n\n" +
			"/status: the router at a glance\n" +
			"/exits: tunnels and failover groups\n" +
			"/events: outages and switches\n" +
			"/summary: the last 24 hours in one message\n" +
			"/route youtube.com: where a site goes (or just send the site)\n" +
			"/devices: devices on the LAN\n" +
			"/diag: run the diagnostics\n" +
			"/ping 1.1.1.1, /dns youtube.com: probes from the router",
		"<b>Бот WayHop</b>\n\n" +
			"/status: роутер одним взглядом\n" +
			"/exits: туннели и группы отказоустойчивости\n" +
			"/events: отказы и переключения\n" +
			"/summary: последние сутки одним сообщением\n" +
			"/route youtube.com: куда идёт сайт (или просто пришлите сайт)\n" +
			"/devices: устройства в сети\n" +
			"/diag: запустить диагностику\n" +
			"/ping 1.1.1.1, /dns youtube.com: проверки с роутера",
	},
	"help.tail": {
		"\n/alerts: which alerts come to this chat\n" +
			"/mute: silence alerts for an hour (critical ones still arrive)\n" +
			"/lang: language\n" +
			"/help: this message",
		"\n/alerts: какие оповещения приходят в этот чат\n" +
			"/mute: без звука на час (критичные всё равно придут)\n" +
			"/lang: язык\n" +
			"/help: эта справка",
	},
	"help.more": {
		"\n\nAlerts arrive here by themselves when an exit goes down or comes back, the core crashes, or the uplink is lost. " +
			"The summary can come by itself too, once a day: its time is set in the panel, Settings → Telegram bot → Manage.",
		"\n\nОповещения приходят сюда сами: когда выход падает или восстанавливается, падает ядро или пропадает интернет у провайдера. " +
			"Сводка тоже может приходить сама, раз в день: время задаётся в панели, Настройки → Telegram-бот → Управление.",
	},
	"help.viewer": {"\n\nThis chat is <b>read-only</b>.", "\n\nЭтот чат <b>только для просмотра</b>."},
	"stranger": {
		"This is a private bot of a WayHop router.\n\nTo connect this chat, open the panel: Settings → Telegram bot → Manage → Get a pairing code, and send the code here.",
		"Это личный бот роутера WayHop.\n\nЧтобы подключить этот чат, откройте в панели: Настройки → Telegram-бот → Управление → Получить код подключения, и пришлите код сюда.",
	},
	"about.short":  {"The private bot of a WayHop router: its state, alerts and a few controls.", "Личный бот роутера WayHop: его состояние, оповещения и немного управления."},
	"about":        {"This is the private bot of a WayHop router. It answers only the chats its owner paired in the router's panel: the router's state and exits, alerts when a tunnel falls or comes back, where a site goes, who is using the line, and maintenance for the owner, which asks first.\n\nTo pair this chat, open the panel: Settings → Telegram bot → Manage → Get a pairing code, and send the code here, or scan its QR code.", "Это личный бот роутера WayHop. Он отвечает только чатам, которые владелец подключил в панели роутера: состояние роутера и выходов, оповещения, когда туннель падает или возвращается, куда идёт сайт, кто занимает линию, а владельцу ещё и обслуживание, которое сначала спрашивает.\n\nЧтобы подключить этот чат, откройте в панели: Настройки → Telegram-бот → Управление → Получить код подключения, и пришлите код сюда или отсканируйте его QR-код."},
	"pair.ok":      {"✅ Paired as <b>%s</b>. Alerts will arrive in this chat.", "✅ Чат подключён, роль: <b>%s</b>. Оповещения будут приходить сюда."},
	"pair.bad":     {"That code is not valid or has expired. Make a new one in the panel.", "Код неверный или устарел. Создайте новый в панели."},
	"pair.limited": {"Too many wrong codes. Try again later.", "Слишком много неверных кодов. Попробуйте позже."},
	"pair.already": {"This chat is already paired as <b>%s</b>.", "Этот чат уже подключён, роль: <b>%s</b>."},
	"alerts.only":  {"This chat only receives alerts.", "Этот чат только получает оповещения."},
	"role.owner":   {"owner", "владелец"},
	"role.viewer":  {"viewer", "наблюдатель"},
	"role.alerts":  {"alerts only", "только оповещения"},
	"unknown.cmd":  {"Unknown command. /help lists what I can do.", "Неизвестная команда. /help покажет, что я умею."},
	"test.msg":     {"✅ Test message from your WayHop router. Alerts will arrive here.", "✅ Проверочное сообщение от роутера WayHop. Оповещения будут приходить сюда."},
	"unpaired":     {"This chat was disconnected from the WayHop router in the panel.", "Этот чат отключён от роутера WayHop в панели."},
	"lang.pick":    {"Choose the language:", "Выберите язык:"},
	"lang.set":     {"Language: English", "Язык: русский"},
	"stale":        {"That button is from an older session; here is the current picture.", "Эта кнопка из прошлой сессии; вот актуальная картина."},
	"err.backend":  {"Could not read the router state: %s", "Не удалось прочитать состояние роутера: %s"},
	"err.denied":   {"Not allowed for this chat.", "Этому чату это не разрешено."},

	// Alerts.
	"al.down":        {"🔴 <b>%s</b> is down", "🔴 <b>%s</b> недоступен"},
	"al.down.via":    {"Group %s now goes through <b>%s</b>", "Группа %s теперь идёт через <b>%s</b>"},
	"al.down.none":   {"Group %s has no working member left", "В группе %s не осталось рабочих участников"},
	"al.up":          {"🟢 <b>%s</b> is back", "🟢 <b>%s</b> снова в строю"},
	"al.down.many":   {"🔴 <b>%d exits are down</b>", "🔴 <b>Недоступно выходов: %d</b>"},
	"al.unreachable": {"⚠️ <b>%s</b> no longer accepts the bot's messages (Telegram says: %s). Alerts do not reach it until it does; to stop trying, disconnect it in the panel.", "⚠️ <b>%s</b> больше не принимает сообщения бота (Telegram: %s). Оповещения туда не доходят, пока это так; чтобы бот перестал пытаться, отключите чат в панели."},
	"al.up.many":     {"🟢 <b>%d exits are back</b>", "🟢 <b>Снова в строю выходов: %d</b>"},
	"al.up.after":    {" · was down %s", " · не работал %s"},
	"al.switch":      {"🔀 <b>%s</b> switched: %s → %s", "🔀 <b>%s</b> переключилась: %s → %s"},
	"al.uplink":      {"🟠 <b>No internet on the uplink</b>\nEvery exit failed at once: the provider or the router's own connection is down, not the tunnels.", "🟠 <b>Нет интернета у провайдера</b>\nОтказали все выходы разом: не работает канал провайдера или подключение роутера, а не туннели."},
	"al.uplink.back": {"🟢 <b>Internet is back</b> · was out %s", "🟢 <b>Интернет вернулся</b> · не было %s"},
	"al.core.restart": {"⚠️ sing-box crashed and was restarted (%d since WayHop started)",
		"⚠️ sing-box упал и был перезапущен (%d с запуска WayHop)"},
	"al.core.lasterr": {"Last error: <code>%s</code>", "Последняя ошибка: <code>%s</code>"},
	"al.core.down":    {"🔴 <b>sing-box is not running</b> for %s already", "🔴 <b>sing-box не работает</b> уже %s"},
	"al.core.up":      {"🟢 sing-box is running again · was down %s", "🟢 sing-box снова работает · не работал %s"},
	"al.apply.armed": {"⏳ <b>Test Apply is running</b>\nIt rolls back by itself in %s unless you keep it.",
		"⏳ <b>Идёт тестовое применение</b>\nОткатится само через %s, если не подтвердить."},
	"al.apply.failing":  {"⚠️ The connectivity check is failing.", "⚠️ Проверка связи не проходит."},
	"al.apply.degraded": {"⚠️ <b>The connectivity check fails</b> after Apply. It rolls back soon unless the connection recovers.", "⚠️ <b>После применения не проходит проверка связи.</b> Скоро будет откат, если связь не восстановится."},
	"al.apply.kept":     {"✅ Test Apply kept: the new configuration is saved.", "✅ Тестовое применение подтверждено: новая конфигурация сохранена."},
	"al.apply.passed":   {"✔️ The test window passed with the internet up.", "✔️ Тестовое окно прошло, интернет работал."},
	"al.apply.unsaved": {"💾 <b>The tested configuration runs unsaved</b>\nA reboot brings the previous one back. Keep it to make it permanent.",
		"💾 <b>Проверенная конфигурация работает, но не сохранена</b>\nПосле перезагрузки вернётся прежняя. Подтвердите, чтобы закрепить."},
	"al.apply.rolledback": {"↩️ <b>Rolled back.</b> Connectivity was lost after Apply, so the previous configuration was restored.",
		"↩️ <b>Откат.</b> После применения пропала связь, восстановлена прежняя конфигурация."},
	"al.apply.reverted": {"↩️ Rolled back to the previous configuration.", "↩️ Выполнен откат к предыдущей конфигурации."},
	"al.apply.reboot":   {"🔁 <b>Rebooting the router</b>: no connectivity even after the rollback.", "🔁 <b>Перезагрузка роутера</b>: связи нет даже после отката."},
	"al.apply.rbfailed": {"❌ <b>The rollback failed</b>: %s", "❌ <b>Откат не удался</b>: %s"},
	"al.apply.ended":    {"The test Apply window ended.", "Окно тестового применения закрыто."},
	"al.mem":            {"⚠️ <b>RAM is almost full</b>: %d%% used", "⚠️ <b>Память почти заполнена</b>: занято %d%%"},
	"al.mem.ok":         {"🟢 RAM is back to normal: %d%% used", "🟢 Память в норме: занято %d%%"},
	"al.boot.back": {"🔌 <b>The router is back online</b>\nIt started at %s; last heard from at %s (offline about %s).",
		"🔌 <b>Роутер снова в сети</b>\nЗапустился в %s; последний раз был на связи в %s (не было около %s)."},
	"al.boot.reboot":  {"🔌 <b>The router restarted</b> at %s and WayHop is running.", "🔌 <b>Роутер перезапустился</b> в %s, WayHop работает."},
	"al.boot.restart": {"🔄 WayHop restarted (%s).", "🔄 WayHop перезапущен (%s)."},
	"al.held":         {"🌙 <b>While alerts were held</b> (%d):", "🌙 <b>Пока оповещения были отложены</b> (%d):"},
	"al.held.more":    {"…and %d more", "…и ещё %d"},

	"b.mute":              {"🔕 1 h", "🔕 1 ч"},
	"b.unmute":            {"🔔 Unmute", "🔔 Включить звук"},
	"b.keep":              {"✅ Keep", "✅ Оставить"},
	"b.rollback":          {"↩️ Roll back", "↩️ Откатить"},
	"mute.on":             {"Alerts muted until %s. Critical ones still arrive.", "Оповещения без звука до %s. Критичные всё равно придут."},
	"mute.off":            {"Alerts are on.", "Оповещения включены."},
	"st.muted":            {"🔕 Alerts muted until %s", "🔕 Оповещения отключены до %s"},
	"apply.kept_by":       {"✅ Kept by %s · %s", "✅ Подтвердил %s · %s"},
	"apply.rolledback_by": {"↩️ Rolled back by %s · %s", "↩️ Откатил %s · %s"},
	"apply.failed":        {"Did not work: %s", "Не получилось: %s"},
	"cmd.mute":            {"Mute alerts for an hour (/mute 30 for 30 min)", "Без звука на час (/mute 30 на 30 минут)"},

	// Tools: /route, /devices, /diag, /ping, /dns.
	"tag.direct":          {"direct (the provider)", "напрямую (провайдер)"},
	"tag.block":           {"blocked", "заблокировано"},
	"rt.noresolve":        {"The router could not resolve this name.", "Роутер не смог разрешить это имя."},
	"rt.ips":              {"Resolves to %s", "Адреса: %s"},
	"rt.more":             {"…and %d more", "…и ещё %d"},
	"why.geo":             {"%s, needs the router's dataset", "%s, нужна база на роутере"},
	"why.unfetched":       {"a feed not fetched yet", "список ещё ни разу не загружался"},
	"why.remote":          {"a remote rule-set, not read here", "удалённый набор правил, здесь не читается"},
	"why.suffix":          {"%s and its subdomains", "%s и поддомены"},
	"why.domain":          {"domain %s", "домен %s"},
	"rt.live":             {"<b>Now:</b> %d connection(s), through %s", "<b>Сейчас:</b> соединений %d, через %s"},
	"rt.nolive":           {"No live connections to it right now.", "Сейчас соединений с ним нет."},
	"rt.configured":       {"<b>In the configuration</b>", "<b>В настройках</b>"},
	"rt.default":          {"Nothing in the configuration names it: it follows the default route.", "В настройках не упоминается: идёт по маршруту по умолчанию."},
	"rt.maybe":            {"May also match (geo and remote sets are not checked here):", "Может совпасть ещё (гео- и удалённые наборы здесь не проверяются):"},
	"rt.kind.rule":        {"rule", "правило"},
	"rt.kind.list":        {"list", "список"},
	"rt.kind.kernel-zone": {"kernel zone", "зона ядра"},
	"rt.prompt":           {"🔎 Which site or IP address? Send it in reply, for example <code>youtube.com</code>.", "🔎 Какой сайт или IP-адрес? Пришлите в ответ, например <code>youtube.com</code>."},
	"rt.bad":              {"That is not a domain name or an IP address.", "Это не доменное имя и не IP-адрес."},
	"dv.title":            {"📱 <b>Devices on the LAN</b> (%d)", "📱 <b>Устройства в сети</b> (%d)"},
	"dv.active":           {" · %d active now", " · сейчас активны: %d"},
	"dv.none":             {"The router knows no devices right now: no DHCP leases, and the ARP table is empty.", "Роутер сейчас не знает ни одного устройства: нет аренд DHCP, таблица ARP пуста."},
	"dv.noname":           {"no name", "без имени"},
	"dv.fast.more":        {"more on the fast path, not counted", "ещё на быстром пути, не учтено"},
	"dv.fast":             {"on the fast path, not counted", "на быстром пути, не учтено"},
	"dv.group":            {"group «%s»", "группа «%s»"},
	"dg.title":            {"Diagnostics", "Диагностика"},
	"dg.counts":           {"✅ %d passed · ⚠️ %d to look at · ❌ %d failed", "✅ в порядке: %d · ⚠️ стоит посмотреть: %d · ❌ ошибок: %d"},
	"dg.na":               {"%d check(s) did not apply here and are not counted.", "Неприменимо здесь, не учтено: %d."},
	"dg.running":          {"⏳ Running the checks…", "⏳ Идут проверки…"},
	"dg.busy":             {"The checks are already running.", "Проверки уже идут."},
	"pg.usage":            {"Send /ping and a host, for example <code>/ping 1.1.1.1</code>.", "Отправьте /ping и адрес, например <code>/ping 1.1.1.1</code>."},
	"pg.norun":            {"📶 A ping to %s could not run on the router.", "📶 Пинг до %s не удалось запустить на роутере."},
	"pg.fail":             {"📶 %s does not answer ping.", "📶 %s не отвечает на пинг."},
	"pg.ok":               {"📶 %s answers", "📶 %s отвечает"},
	"pg.avg":              {"%s ms on average", "в среднем %s мс"},
	"pg.loss":             {"%d%% lost", "потери %d%%"},
	"dn.usage":            {"Send /dns and a name, for example <code>/dns youtube.com</code>.", "Отправьте /dns и имя, например <code>/dns youtube.com</code>."},
	"dn.fail":             {"🌐 %s does not resolve through the router.", "🌐 %s не разрешается через роутер."},
	"dn.ok":               {"🌐 %s → %s", "🌐 %s → %s"},
	"dn.cname":            {"an alias of %s", "псевдоним для %s"},
	"mo.title":            {"🧰 <b>Tools</b>", "🧰 <b>Инструменты</b>"},
	"b.again":             {"🔄 Again", "🔄 Ещё раз"},
	"b.route.other":       {"🔎 Another site", "🔎 Другой сайт"},
	"b.route":             {"🔎 Where does a site go", "🔎 Куда идёт сайт"},
	"b.devices":           {"📱 Devices", "📱 Устройства"},
	"b.diag":              {"🩺 Diagnostics", "🩺 Диагностика"},
	"b.more":              {"🧰 More", "🧰 Ещё"},
	"cmd.route":           {"Where does a site go (/route youtube.com)", "Куда идёт сайт (/route youtube.com)"},
	"cmd.devices":         {"Devices on the LAN", "Устройства в сети"},
	"cmd.diag":            {"Run the diagnostics", "Запустить диагностику"},
	"cmd.maint":           {"Maintenance: apply, refresh, backup, restart, update", "Обслуживание: применить, обновить, бэкап, перезапуск"},
	"cmd.speed":           {"Is it the line or the tunnel? A speed test", "Линия или туннель: замер скорости"},

	// Maintenance (owners).
	"mt.title":             {"🛠 <b>Maintenance</b>", "🛠 <b>Обслуживание</b>"},
	"mt.pending.n":         {"Saved, not applied: %d change(s).", "Сохранено, но не применено изменений: %d."},
	"mt.pending.some":      {"There are saved changes that are not applied.", "Есть сохранённые, но не применённые изменения."},
	"mt.pending.none":      {"Everything saved is applied.", "Всё сохранённое применено."},
	"mt.hint":              {"The panel's own operations. Anything that changes the router asks first.", "Те же операции, что в панели. Всё, что меняет роутер, сначала спрашивает."},
	"mt.unavailable":       {"not available on this router (the demo has no init system)", "недоступно на этом роутере (в демо нет системы инициализации)"},
	"b.maint":              {"🛠 Maintenance", "🛠 Обслуживание"},
	"b.maint.back":         {"⬅ Maintenance", "⬅ Обслуживание"},
	"b.apply":              {"⚙️ Apply saved changes", "⚙️ Применить сохранённое"},
	"b.lists":              {"🧾 Refresh routing lists", "🧾 Обновить списки"},
	"b.sub":                {"📥 Refresh subscription", "📥 Обновить подписку"},
	"b.backup":             {"💾 Backup to this chat", "💾 Бэкап в этот чат"},
	"b.restart":            {"♻️ Restart WayHop", "♻️ Перезапустить WayHop"},
	"b.cancel":             {"✖ Cancel", "✖ Отмена"},
	"mt.lists.run":         {"⏳ Refreshing the routing lists…", "⏳ Обновляю списки маршрутизации…"},
	"mt.lists.done":        {"🧾 <b>Routing lists refreshed</b>\nChanged: %d of %d. The new content takes effect on the next Apply.", "🧾 <b>Списки обновлены</b>\nИзменилось: %d из %d. Новое содержимое заработает после применения."},
	"mt.lists.none":        {"🧾 No routing list has a source to refresh.", "🧾 Ни у одного списка нет источника для обновления."},
	"mt.lists.err":         {"%s failed, the last good content is kept: %s", "%s: не удалось, оставлено прежнее содержимое: %s"},
	"mt.lists.err.empty":   {"%s failed, and the list has nothing from it yet: %s", "%s: не удалось, из источника в списке пока ничего нет: %s"},
	"mt.lists.unreached":   {"⏳ Not reached in time: %d more. Refresh again to try them.", "⏳ Не хватило времени ещё на %d; обновите снова, чтобы попробовать их."},
	"mt.lists.fail":        {"🧾 The lists could not be refreshed: %s", "🧾 Не удалось обновить списки: %s"},
	"mt.sub.run":           {"⏳ Refreshing the subscription…", "⏳ Обновляю подписку…"},
	"mt.sub.done":          {"📥 <b>Subscription refreshed</b>: %d new connection(s). They take effect on the next Apply.", "📥 <b>Подписка обновлена</b>: новых подключений %d. Они заработают после применения."},
	"mt.sub.fail":          {"📥 The subscription could not be refreshed: %s", "📥 Не удалось обновить подписку: %s"},
	"mt.apply.nothing":     {"⚙️ Nothing to apply: the router runs what is saved.", "⚙️ Применять нечего: роутер работает на сохранённом."},
	"mt.apply.blocked":     {"⛔ <b>Apply is blocked</b> by %d issue(s):", "⛔ <b>Применение заблокировано</b>, проблем: %d:"},
	"mt.apply.blocked.fix": {"Fix them in the panel: Review &amp; Apply.", "Исправьте их в панели: «Проверить и применить»."},
	"mt.apply.ask":         {"⚙️ <b>Apply the saved changes as a test?</b>", "⚙️ <b>Применить сохранённые изменения как тест?</b>"},
	"mt.apply.count":       {"%d change(s).", "Изменений: %d."},
	"mt.apply.interrupt":   {"Connections may drop for a moment.", "Соединения могут на миг оборваться."},
	"mt.apply.window":      {"It rolls back by itself unless you keep it.", "Если не подтвердить, откатится само."},
	"mt.apply.confirms":    {"Applying also confirms:", "Применение также подтверждает:"},
	"mt.apply.ok":          {"✅ Apply as a test", "✅ Применить как тест"},
	"mt.apply.run":         {"⏳ Applying…", "⏳ Применяю…"},
	"mt.apply.done":        {"✅ <b>Test Apply started</b> by %s. Keep it or roll it back in the message that follows.", "✅ <b>Тестовое применение запустил %s.</b> Оставить или откатить можно в следующем сообщении."},
	"mt.apply.fail":        {"❌ Apply failed: %s", "❌ Применить не удалось: %s"},
	"mt.restart.ask":       {"♻️ <b>Restart WayHop?</b>\nThe panel, the routing core and this bot drop for a few seconds. The bot says when it is back.", "♻️ <b>Перезапустить WayHop?</b>\nПанель, ядро маршрутизации и этот бот пропадут на несколько секунд. Бот напишет, когда вернётся."},
	"mt.restart.ok":        {"♻️ Restart", "♻️ Перезапустить"},
	"mt.restart.run":       {"♻️ WayHop is restarting… back in a few seconds.", "♻️ WayHop перезапускается… вернётся через несколько секунд."},
	"mt.restart.fail":      {"♻️ Could not restart: %s", "♻️ Перезапустить не удалось: %s"},
	"mt.backup.ask":        {"💾 <b>Send a full backup to this chat?</b>\nIt holds every connection's keys and passwords, and Telegram keeps the file until you delete the message.", "💾 <b>Прислать полный бэкап в этот чат?</b>\nВ нём ключи и пароли всех подключений, и Telegram хранит файл, пока вы не удалите сообщение."},
	"mt.backup.ok":         {"💾 Send the backup", "💾 Прислать бэкап"},
	"mt.backup.caption":    {"💾 WayHop backup · %s\nDelete this message once the file is saved elsewhere: it holds every key.", "💾 Бэкап WayHop · %s\nУдалите это сообщение, когда сохраните файл в другом месте: в нём все ключи."},
	"mt.backup.sent":       {"💾 Backup sent.", "💾 Бэкап отправлен."},
	"mt.backup.fail":       {"💾 The backup could not be sent: %s", "💾 Не удалось отправить бэкап: %s"},
	"mt.cancelled":         {"Cancelled.", "Отменено."},
	"mt.expired":           {"That confirmation expired. Nothing was done.", "Подтверждение устарело. Ничего не сделано."},
	"mt.again":             {"Already confirmed.", "Уже подтверждено."},
	"help.owner": {"\n/speed: the provider's line against the route through WayHop\n/maint: maintenance (apply, refresh lists and subscription, updates, backup, restart)",
		"\n/speed: скорость линии провайдера и маршрута через WayHop\n/maint: обслуживание (применить, обновить списки и подписку, обновления, бэкап, перезапуск)"},

	// Speed test (owners).
	"b.speed":        {"📶 Speed", "📶 Скорость"},
	"sp.ask":         {"📶 <b>Measure the speed?</b>\nThe router downloads about 10 MB and uploads 5 MB twice: straight through the provider, then through WayHop. It usually takes under a minute, and the network may slow down meanwhile.", "📶 <b>Измерить скорость?</b>\nРоутер дважды скачает около 10 МБ и отправит 5 МБ: напрямую через провайдера, затем через WayHop. Обычно это меньше минуты, и сеть на это время может притормозить."},
	"sp.cannot":      {"This exit cannot be measured on its own: only a kernel tunnel (WireGuard, AmneziaWG) can, on the router.", "Этот выход нельзя измерить отдельно: так можно только туннель ядра (WireGuard, AmneziaWG) на роутере."},
	"sp.ask.exit":    {"📶 <b>Measure the speed of %s?</b>\nThe router downloads about 10 MB and uploads 5 MB twice: straight through the provider, then through this tunnel alone. Nobody's traffic is moved onto it. It usually takes under a minute.", "📶 <b>Измерить скорость %s?</b>\nРоутер дважды скачает около 10 МБ и отправит 5 МБ: напрямую через провайдера, затем только через этот туннель. Ничей трафик на него не переводится. Обычно это меньше минуты."},
	"sp.via":         {"Through %s: %s", "Через %s: %s"},
	"sp.run.route":   {"⏳ Measuring through %s (2 of 2)…", "⏳ Измеряю через %s (2 из 2)…"},
	"sp.ok":          {"📶 Measure", "📶 Измерить"},
	"sp.run.line":    {"⏳ Measuring the provider's line (1 of 2)…", "⏳ Измеряю линию провайдера (1 из 2)…"},
	"sp.title":       {"📶 <b>Speed</b>", "📶 <b>Скорость</b>"},
	"sp.line":        {"Provider's line: %s", "Линия провайдера: %s"},
	"sp.blocked":     {"Through WayHop: not measured, a rule here blocks the test's site.", "Через WayHop: не измерено, правило здесь блокирует сайт замера."},
	"sp.direct.rule": {"Through WayHop: a rule or list here sends the test's site straight out, so this would measure the line again. A WireGuard or AmneziaWG tunnel can be measured on its own from its card in /exits.", "Через WayHop: правило или список здесь отправляет сайт замера напрямую, так что замер повторил бы линию. Туннель WireGuard или AmneziaWG можно измерить отдельно с его карточки в /exits."},
	"sp.direct":      {"Through WayHop: sites with no rule of their own go straight out here, so they get the line's speed. A WireGuard or AmneziaWG tunnel can be measured on its own from its card in /exits.", "Через WayHop: сайты без собственного правила идут здесь напрямую, так что получают скорость линии. Туннель WireGuard или AmneziaWG можно измерить отдельно с его карточки в /exits."},
	"sp.line.tunnel": {"Provider's line: the router's own traffic leaves through %s, so this is that tunnel, not the line: %s", "Линия провайдера: собственный трафик роутера уходит через %s, поэтому это скорость туннеля, а не линии: %s"},
	"sp.nocore":      {"Through WayHop: not measured, sing-box is not running.", "Через WayHop: не измерено, sing-box не запущен."},
	"sp.native":      {"Through WayHop: not measured, the router routes natively, without sing-box.", "Через WayHop: не измерено, роутер маршрутизирует нативно, без sing-box."},
	"sp.fail":        {"not measured (%s)", "не измерено (%s)"},
	"sp.noanswer":    {"no answer", "нет ответа"},
	"sp.up.none":     {"not measured", "не измерено"},
	"sp.good":        {"✅ The route through %s keeps up with the line. If it still feels slow, see who is using it: /devices.", "✅ Маршрут через %s не отстаёт от линии. Если всё равно медленно, посмотрите, кто её занимает: /devices."},
	"sp.share":       {"The route through %s gives about %d%% of the line's speed.", "Маршрут через %s даёт около %d%% скорости линии."},
	"sp.slow":        {"⚠️ The tunnel is the bottleneck: about %d%% of the line's speed. Another exit may be faster: /exits.", "⚠️ Узкое место в туннеле: около %d%% скорости линии. Другой выход может оказаться быстрее: /exits."},
	"sp.faster":      {"✅ Through %s is faster than straight through the provider: the provider seems to slow down traffic it can see.", "✅ Через %s быстрее, чем напрямую: похоже, провайдер замедляет трафик, который видит."},
	"sp.busy":        {"📶 Another speed test is running (from the panel or another chat). Try again in a minute.", "📶 Уже идёт другое измерение (из панели или другого чата). Попробуйте через минуту."},
	"sp.hint":        {"Measured from the router itself against Cloudflare's speed test; a device on Wi-Fi may get less.", "Замер с самого роутера до сервера скорости Cloudflare; устройство по Wi-Fi может получать меньше."},

	// WayHop updates.
	"b.updates":    {"⬆️ Updates", "⬆️ Обновления"},
	"b.install":    {"⬆️ Install %s", "⬆️ Установить %s"},
	"up.run":       {"⏳ Checking for a new WayHop…", "⏳ Проверяю, нет ли новой WayHop…"},
	"up.available": {"⬆️ <b>WayHop %s is available</b> (this router runs %s).", "⬆️ <b>Доступна WayHop %s</b> (на роутере %s)."},
	"up.auto":      {"Auto-update is on: it installs by itself within a day.", "Автообновление включено: установится само в течение суток."},
	"up.latest":    {"✅ WayHop %s is the latest release.", "✅ WayHop %s: это последняя версия."},
	"up.managed":   {"📦 WayHop is installed by %s here: update it with the package manager (Components in the panel).", "📦 WayHop здесь установлен через %s: обновляйте его пакетным менеджером (раздел «Компоненты» в панели)."},
	"up.nochannel": {"This build has no update channel: its release list is not published.", "У этой сборки нет канала обновлений: список релизов не опубликован."},
	"up.fail":      {"The check failed: %s", "Проверить не удалось: %s"},
	"up.unknown":   {"This router runs WayHop %s; whether a newer release exists could not be told.", "На роутере WayHop %s; есть ли версия новее, определить не удалось."},
	"up.none":      {"There is nothing newer to install.", "Нового для установки нет."},
	"up.ask": {"⬆️ <b>Install WayHop %s?</b>\nIt downloads the release, verifies it, keeps the running binary as a backup, and restarts. The bot is back in about a minute.",
		"⬆️ <b>Установить WayHop %s?</b>\nСкачает релиз, проверит его, сохранит текущую версию как резервную и перезапустится. Бот вернётся примерно через минуту."},
	"up.ok":             {"⬆️ Install", "⬆️ Установить"},
	"up.installing":     {"⏳ Downloading and verifying WayHop %s…", "⏳ Скачиваю и проверяю WayHop %s…"},
	"up.done":           {"⬆️ <b>WayHop %s is installed.</b> Restarting now; the bot is back in about a minute.", "⬆️ <b>WayHop %s установлена.</b> Перезапуск; бот вернётся примерно через минуту."},
	"up.done.norestart": {"⬆️ WayHop %s is installed, but the restart did not start: %s", "⬆️ WayHop %s установлена, но перезапуск не начался: %s"},
	"up.installfail":    {"⬆️ The update failed: %s", "⬆️ Обновить не удалось: %s"},

	// Diagnostics check names, by check id; an id the bot does not know shows the router's label.
	"hc.time":           {"Router clock is correct", "Часы роутера верны"},
	"hc.ipv6":           {"IPv6 bypass check", "Нет обхода по IPv6"},
	"hc.ipv6-carried":   {"IPv6 works where it is routed", "IPv6 работает там, где маршрутизируется"},
	"hc.dns":            {"Encrypted DNS (DoH)", "Шифрованный DNS (DoH)"},
	"hc.offload":        {"Flow offload (fast path)", "Ускорение потоков (fast path)"},
	"hc.conntrack":      {"Connection-tracking table has room", "В таблице соединений есть место"},
	"hc.pbr_kernel":     {"Kernel routing (PBR)", "Маршрутизация в ядре (PBR)"},
	"hc.lists_in_force": {"Routing lists in force", "Списки маршрутизации действуют"},
	"hc.native_only":    {"Datapath core (sing-box)", "Ядро трафика (sing-box)"},
	"hc.endpoint_reach": {"VPN servers reachable", "VPN-серверы доступны"},
	"hc.group_depth":    {"Failover groups are as deep as they look", "Группы резервирования так глубоки, как кажутся"},
	"hc.source-iface":   {"Source-routing interfaces exist", "Интерфейсы маршрутизации по источнику существуют"},
	"hc.dns-bypass":     {"LAN clients use the router's DNS", "Клиенты сети используют DNS роутера"},
	"hc.rtt-ceiling":    {"Latency limits one connection", "Задержка ограничивает одно соединение"},
	"hc.singbox-build":  {"sing-box build supports your endpoints", "Сборка sing-box поддерживает ваши подключения"},
	"hc.disk-space":     {"Router storage has room", "На накопителе роутера есть место"},
	"hc.subscription":   {"Subscription auto-refresh is healthy", "Автообновление подписки работает"},

	// Units. Speeds are in bits per second, like the panel.
	"u.bps":  {"%s bit/s", "%s бит/с"},
	"u.kbps": {"%s kbit/s", "%s Кбит/с"},
	"u.mbps": {"%s Mbit/s", "%s Мбит/с"},
	"u.gbps": {"%s Gbit/s", "%s Гбит/с"},
	"u.d":    {"%dd", "%d д"},
	"u.h":    {"%dh", "%d ч"},
	"u.m":    {"%d min", "%d мин"},
	"u.s":    {"%d s", "%d с"},
	"u.b":    {"%s B", "%s Б"},
	"u.kb":   {"%s KB", "%s КБ"},
	"u.mb":   {"%s MB", "%s МБ"},
	"u.gb":   {"%s GB", "%s ГБ"},
	"u.tb":   {"%s TB", "%s ТБ"},

	// Nouns for Count: English one|other, Russian one|few|many.
	"n.outage": {"outage|outages", "сбой|сбоя|сбоев"},
	"n.time":   {"time|times", "раз|раза|раз"},
	"n.list":   {"list|lists", "список|списка|списков"},

	// The daily digest.
	"digest.title":         {"☀️ <b>Daily summary</b> · %s", "☀️ <b>Сводка за сутки</b> · %s"},
	"digest.line":          {"☀️ Daily summary", "☀️ Сводка за сутки"},
	"digest.title.now":     {"📋 <b>Summary</b> · %s", "📋 <b>Сводка</b> · %s"},
	"b.summary":            {"📋 Last 24 hours", "📋 За сутки"},
	"digest.exits":         {"exits up: %d of %d", "выходов в строю: %d из %d"},
	"digest.day":           {"<b>Last 24 hours</b>", "<b>За последние сутки</b>"},
	"digest.since":         {"<b>Since %s</b> (the log starts there)", "<b>С %s</b> (раньше журнал пуст)"},
	"digest.outage":        {"🔴 %s: %s, %s in total", "🔴 %s: %s, всего %s"},
	"digest.outage.group":  {"🔴 %s (group): %s, %s in total", "🔴 %s (группа): %s, всего %s"},
	"digest.open":          {" · still down", " · недоступен до сих пор"},
	"digest.switched":      {"🔁 %s switched %s · now %s", "🔁 %s переключалась %s · сейчас %s"},
	"digest.restarts":      {"♻️ sing-box restarted %s", "♻️ sing-box перезапускался %s"},
	"digest.calm":          {"✅ No outages, no switches", "✅ Ни сбоев, ни переключений"},
	"digest.traffic.day":   {"<b>Traffic by exit</b> · 24 h", "<b>Трафик по выходам</b> · сутки"},
	"digest.traffic.since": {"<b>Traffic by exit</b> · since %s", "<b>Трафик по выходам</b> · с %s"},
	"digest.traffic":       {"%s · ↓ %s ↑ %s", "%s · ↓ %s ↑ %s"},
	"digest.more":          {"…and %d more", "…и ещё %d"},
	"digest.uptime":        {"⏱ Router up %s", "⏱ Роутер работает %s"},
	"u.now":                {"just now", "только что"},

	// Command menu.
	"cmd.status":  {"The router at a glance", "Роутер одним взглядом"},
	"cmd.exits":   {"Tunnels and failover groups", "Туннели и группы отказоустойчивости"},
	"cmd.events":  {"Outages and switches", "Отказы и переключения"},
	"cmd.summary": {"The last 24 hours in one message", "Последние сутки одним сообщением"},
	"cmd.lang":    {"Language", "Язык"},
	"cmd.help":    {"What the bot can do", "Что умеет бот"},
}

// T renders key in lang with args.
func T(lang, key string, args ...any) string {
	v, ok := msgs[key]
	if !ok {
		return key
	}
	s := v[0]
	switch {
	case lang == "ru" && v[1] != "":
		s = v[1]
	case lang == "uk" && msgsUK[key] != "":
		s = msgsUK[key]
	}
	if len(args) == 0 {
		return s
	}
	return fmt.Sprintf(s, args...)
}

// decimal formats f with one decimal in the language's convention ("12.4" / "12,4").
func decimal(lang string, f float64) string {
	s := strconv.FormatFloat(f, 'f', 1, 64)
	s = strings.TrimSuffix(s, ".0")
	if commaDecimal(lang) {
		s = strings.Replace(s, ".", ",", 1)
	}
	return s
}

// Count is n with its noun in the form the number takes: "1 outage", "3 outages"; "1 сбой",
// "3 сбоя", "5 сбоев". The key holds the forms separated by "|": English one|other, Russian
// one|few|many.
func Count(lang string, n int, key string) string {
	forms := strings.Split(T(lang, key), "|")
	i := 0
	switch {
	case (lang == "ru" || lang == "uk") && len(forms) == 3: // the same one|few|many rule
		switch n10, n100 := n%10, n%100; {
		case n10 == 1 && n100 != 11:
			i = 0
		case n10 >= 2 && n10 <= 4 && (n100 < 12 || n100 > 14):
			i = 1
		default:
			i = 2
		}
	case n != 1 && len(forms) > 1:
		i = 1
	}
	return strconv.Itoa(n) + " " + forms[i]
}

// Bytes formats a volume the way the panel does: binary multiples, one decimal ("3.2 GB", "3,2 ГБ").
func Bytes(lang string, n int64) string {
	units := []string{"u.b", "u.kb", "u.mb", "u.gb", "u.tb"}
	f, i := float64(n), 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return T(lang, units[0], strconv.FormatInt(n, 10))
	}
	return T(lang, units[i], decimal(lang, f))
}

// fixed formats f with prec decimals in the language's convention ("0.46", "0,46").
func fixed(lang string, f float64, prec int) string {
	s := strconv.FormatFloat(f, 'f', prec, 64)
	if commaDecimal(lang) {
		s = strings.Replace(s, ".", ",", 1)
	}
	return s
}

// commaDecimal: the languages that write 12,4 rather than 12.4.
func commaDecimal(lang string) bool { return lang == "ru" || lang == "uk" }

// Speed formats a byte rate as bits per second.
func Speed(lang string, bytesPerSec int64) string {
	bits := float64(bytesPerSec) * 8
	switch {
	case bits >= 1e9:
		return T(lang, "u.gbps", decimal(lang, bits/1e9))
	case bits >= 1e6:
		return T(lang, "u.mbps", decimal(lang, bits/1e6))
	case bits >= 1e3:
		return T(lang, "u.kbps", decimal(lang, math.Round(bits/1e3)))
	}
	return T(lang, "u.bps", strconv.FormatInt(int64(bits), 10))
}

// Duration formats d with its two most significant units: "6d 4h", "3h 12 min", "45 s".
func Duration(lang string, d time.Duration) string {
	if d < time.Second {
		return T(lang, "u.now")
	}
	secs := int64(d / time.Second)
	days, hours, mins := secs/86400, secs%86400/3600, secs%3600/60
	switch {
	case days > 0:
		if hours == 0 {
			return T(lang, "u.d", days)
		}
		return T(lang, "u.d", days) + " " + T(lang, "u.h", hours)
	case hours > 0:
		if mins == 0 {
			return T(lang, "u.h", hours)
		}
		return T(lang, "u.h", hours) + " " + T(lang, "u.m", mins)
	case mins > 0:
		return T(lang, "u.m", mins)
	}
	return T(lang, "u.s", secs)
}

// Countdown formats a short remaining time as m:ss.
func Countdown(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := int64(d.Round(time.Second) / time.Second)
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}

// Flag turns an ISO 3166-1 alpha-2 code into its flag emoji ("" for anything else).
func Flag(code string) string {
	if len(code) != 2 {
		return ""
	}
	code = strings.ToUpper(code)
	var b strings.Builder
	for _, c := range code {
		if c < 'A' || c > 'Z' {
			return ""
		}
		b.WriteRune(0x1F1E6 + (c - 'A'))
	}
	return b.String()
}
