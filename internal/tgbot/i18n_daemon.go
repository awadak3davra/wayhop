package tgbot

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

// The router words its Diagnostics battery in English (internal/server: healthcheck.go and the check
// files beside it), and a Russian or Ukrainian chat got those sentences as they were. Translated here
// is what the bot shows in full, the summaries and fixes of the checks that warn or fail, sentence by
// sentence; what the router assembles from parts, and anything not listed, stays English rather than
// be guessed at, as whyIn does for the trace. TestDaemonSentencesAreTheRoutersOwn keeps every English
// sentence here in step with the router's source: a reworded one would otherwise silently fall back.

// daemonText is a fixed English sentence and its {ru, uk}.
var daemonText = map[string][2]string{
	// Summaries.
	"global IPv6 present; the leak test could not complete": {
		"есть глобальный IPv6; проверка утечки не завершилась",
		"є глобальний IPv6; перевірка витоку не завершилася"},
	"IPv6 reaches the internet directly": {
		"IPv6 выходит в интернет напрямую",
		"IPv6 виходить в інтернет напряму"},
	"flow offload is off": {
		"flow offload выключен",
		"flow offload вимкнено"},
	"no DoH resolver reachable": {
		"нет доступного DoH-резолвера",
		"немає доступного DoH-резолвера"},
	"kernel PBR (nftables) not available on this router": {
		"PBR ядра (nftables) недоступен на этом роутере",
		"PBR ядра (nftables) недоступний на цьому роутері"},
	"nft table missing — plan was applied but table is gone": {
		"таблица nft отсутствует — план применён, но таблица пропала",
		"таблиця nft відсутня — план застосовано, але таблиця зникла"},
	"the ipset/iptables policy plane is missing — WayHop reinstalls it on its next reconcile": {
		"правила ipset/iptables отсутствуют — WayHop восстановит их при следующей сверке",
		"правила ipset/iptables відсутні — WayHop відновить їх під час наступного звіряння"},
	"router storage critically low": {
		"на накопителе роутера критически мало места",
		"на накопичувачі роутера критично мало місця"},
	"IPv6 is routed into a tunnel that does not carry it": {
		"IPv6 направлен в туннель, который его не пропускает",
		"IPv6 спрямовано в тунель, який його не пропускає"},
	"IPv6 is routed into a tunnel, but this check could not test whether it carries traffic": {
		"IPv6 направлен в туннель, но проверить, проходит ли через него трафик, не удалось",
		"IPv6 спрямовано в тунель, але перевірити, чи проходить ним трафік, не вдалося"},

	// Fixes.
	"The router clock drifts. Enable NTP / fix the time — large skew breaks secure (TLS/Reality) connections.": {
		"Часы роутера уходят. Включите NTP / исправьте время — большое расхождение ломает защищённые (TLS/Reality) соединения.",
		"Годинник роутера збивається. Увімкніть NTP / виправте час — велике розходження ламає захищені (TLS/Reality) з'єднання."},
	"The router's clock is far off, which breaks secure (TLS/Reality) tunnels and makes working exits look broken. Fix the time / enable NTP.": {
		"Часы роутера сильно сбиты, что ломает защищённые (TLS/Reality) туннели и делает рабочие точки выхода нерабочими на вид. Исправьте время / включите NTP.",
		"Годинник роутера сильно збитий, що ламає захищені (TLS/Reality) тунелі й робить робочі точки виходу неробочими на вигляд. Виправте час / увімкніть NTP."},
	"This router has a global IPv6 address and the check could not determine whether it bypasses the tunnels. Re-run it; if it keeps failing, test from a device on the LAN (e.g. open an IPv6-only address) or disable IPv6 forwarding until you know.": {
		"У роутера есть глобальный IPv6-адрес, и проверка не смогла выяснить, идёт ли он в обход туннелей. Запустите её ещё раз; если она снова не завершится, проверьте с устройства в сети (например, откройте адрес, доступный только по IPv6) или отключите форвардинг IPv6, пока не выясните.",
		"Роутер має глобальну IPv6-адресу, і перевірка не змогла з'ясувати, чи йде він в обхід тунелів. Запустіть її ще раз; якщо вона знову не завершиться, перевірте з пристрою в мережі (наприклад, відкрийте адресу, доступну лише через IPv6) або вимкніть форвардинг IPv6, доки не з'ясуєте."},
	"Your device can use IPv6 to bypass the VPN and expose your real address. Disable IPv6 on the router, or block IPv6 forwarding.": {
		"Ваше устройство может использовать IPv6, чтобы обойти VPN и раскрыть ваш реальный адрес. Отключите IPv6 на роутере или заблокируйте форвардинг IPv6.",
		"Ваш пристрій може використовувати IPv6, щоб обійти VPN і розкрити вашу справжню адресу. Вимкніть IPv6 на роутері або заблокуйте форвардинг IPv6."},
	"Encrypted DNS (DoH) couldn't be reached from the router, so DNS may be falling back to your ISP's plaintext servers. Check https-dns-proxy / your DNS settings — or it may just be a transient network blip.": {
		"Шифрованный DNS (DoH) недоступен с роутера, так что DNS может уходить на открытые серверы провайдера. Проверьте https-dns-proxy и настройки DNS — или это просто кратковременный сбой сети.",
		"Шифрований DNS (DoH) недоступний з роутера, тож DNS може йти на відкриті сервери провайдера. Перевірте https-dns-proxy і налаштування DNS — або це просто короткочасний збій мережі."},
	"Encrypted DNS is reachable, but this router's own lookups go to a plaintext resolver, so they are visible to whoever carries them. Point the router at a DoH/DoT resolver (https-dns-proxy, or the DNS page's upstreams) if you want them private.": {
		"Шифрованный DNS доступен, но собственные запросы роутера уходят на открытый резолвер, и их видит тот, кто их передаёт. Направьте роутер на DoH/DoT-резолвер (https-dns-proxy или серверы на странице DNS), если хотите скрыть их.",
		"Шифрований DNS доступний, але власні запити роутера йдуть на відкритий резолвер, і їх бачить той, хто їх передає. Спрямуйте роутер на DoH/DoT-резолвер (https-dns-proxy або сервери на сторінці DNS), якщо хочете їх приховати."},
	"Unreachable means one of two measurements failed: the router could not open a TCP connection to a proxy server, or a native tunnel's own probe got no handshake. Check the peer is up and the port right, and that the path is not blocked (DPI/firewall); for a native tunnel also check its keys and endpoint are still valid. A server that IS reachable while its connection still fails points at the proxy/protocol config, not the network.": {
		"«Недоступен» значит, что не удалось одно из двух измерений: роутер не смог открыть TCP-соединение с прокси-сервером, или собственная проверка нативного туннеля не получила рукопожатия. Проверьте, что сервер работает и порт верный, а путь не заблокирован (DPI/файрвол); у нативного туннеля проверьте ещё ключи и адрес сервера. Если сервер доступен, а подключение всё равно не работает, дело в настройках прокси или протокола, а не в сети.",
		"«Недоступний» означає, що не вдалося одне з двох вимірювань: роутер не зміг відкрити TCP-з'єднання з проксі-сервером, або власна перевірка нативного тунелю не отримала рукостискання. Перевірте, що сервер працює і порт правильний, а шлях не заблоковано (DPI/файрвол); у нативного тунелю перевірте ще ключі й адресу сервера. Якщо сервер доступний, а підключення все одно не працює, справа в налаштуваннях проксі чи протоколу, а не в мережі."},
	"Apply a config with at least one routing list to activate the kernel policy plane.": {
		"Примените конфигурацию хотя бы с одним списком маршрутизации, чтобы включить правила маршрутизации в ядре.",
		"Застосуйте конфігурацію хоча б з одним списком маршрутизації, щоб увімкнути правила маршрутизації в ядрі."},
	"Switch routing mode to tun or mixed — those route entirely through the sing-box TUN and need no kernel plane.": {
		"Переключите режим маршрутизации на tun или mixed — они идут целиком через TUN sing-box и не требуют правил в ядре.",
		"Перемкніть режим маршрутизації на tun або mixed — вони йдуть повністю через TUN sing-box і не потребують правил у ядрі."},
	"Apply a config with at least one routing list to activate kernel PBR.": {
		"Примените конфигурацию хотя бы с одним списком маршрутизации, чтобы активировать PBR ядра.",
		"Застосуйте конфігурацію хоча б з одним списком маршрутизації, щоб активувати PBR ядра."},
	"Click Apply to re-install the nftables routing rules (fw4 reload may have flushed them).": {
		"Нажмите «Применить», чтобы заново установить правила nftables (их могла сбросить перезагрузка fw4).",
		"Натисніть «Застосувати», щоб заново встановити правила nftables (їх міг скинути перезапуск fw4)."},
	"Give the group a second member the kernel can route to (a native tunnel), or turn on its kill switch so the traffic is dropped rather than sent out the provider.": {
		"Добавьте в группу второго участника, через которого может маршрутизировать ядро (нативный туннель), или включите её аварийное отключение, чтобы трафик сбрасывался, а не уходил через провайдера.",
		"Додайте до групи другого учасника, через якого може маршрутизувати ядро (нативний тунель), або увімкніть її аварійне вимкнення, щоб трафік скидався, а не йшов через провайдера."},
	"Apply the configuration so the kernel plane picks these lists up, or check that their outbound still exists.": {
		"Примените конфигурацию, чтобы ядро подхватило эти списки, или проверьте, что их выход ещё существует.",
		"Застосуйте конфігурацію, щоб ядро підхопило ці списки, або перевірте, що їхній вихід ще існує."},
	"fix the source interface name (or create/enable that interface); a source rule whose interface doesn't exist never matches any traffic": {
		"исправьте имя интерфейса источника (или создайте и включите этот интерфейс): правило по источнику с несуществующим интерфейсом не срабатывает никогда",
		"виправте назву інтерфейсу джерела (або створіть і увімкніть цей інтерфейс): правило за джерелом з неіснуючим інтерфейсом не спрацьовує ніколи"},
	"these will fail to apply — install a sing-box built with the listed tags, or switch those endpoints to a supported protocol": {
		"их не удастся применить — установите sing-box, собранный с указанными тегами, или переведите эти подключения на поддерживаемый протокол",
		"їх не вдасться застосувати — встановіть sing-box, зібраний із зазначеними тегами, або переведіть ці підключення на підтримуваний протокол"},
	"those clients resolve names themselves over encrypted DNS, so domain-based routing rules won't apply to them — disable DoH on the device, or block public DoH resolvers in Routing": {
		"эти клиенты сами разрешают имена через шифрованный DNS, поэтому правила маршрутизации по доменам к ним не применяются — отключите DoH на устройстве или заблокируйте публичные DoH-резолверы в маршрутизации",
		"ці клієнти самі розв'язують імена через шифрований DNS, тому правила маршрутизації за доменами до них не застосовуються — вимкніть DoH на пристрої або заблокуйте публічні DoH-резолвери в маршрутизації"},
	"free space now (clear logs / remove unused packages) — config applies and updates will fail": {
		"освободите место сейчас (очистите журналы, удалите ненужные пакеты) — иначе применение настроек и обновления не пройдут",
		"звільніть місце зараз (очистьте журнали, видаліть непотрібні пакети) — інакше застосування налаштувань і оновлення не пройдуть"},
	"free space before updating: the new binary is staged beside the old one, so a swap needs about twice the binary. Installing a component needs more still — the Components page states what each one costs.": {
		"освободите место перед обновлением: новый файл кладётся рядом со старым, так что для замены нужно примерно вдвое больше его размера. Установке компонента нужно ещё больше — на странице «Компоненты» указано, сколько требует каждый.",
		"звільніть місце перед оновленням: новий файл кладеться поруч зі старим, тож для заміни потрібно приблизно вдвічі більше за його розмір. Встановленню компонента потрібно ще більше — на сторінці «Компоненти» вказано, скільки потребує кожен."},
	"WayHop couldn't re-fetch your subscription, so it may be missing servers your provider rotated in. Check the subscription URL is reachable from the router (the DNS/reachability diagnostics help) or re-import it.": {
		"WayHop не смог заново загрузить подписку, так что в ней может не быть серверов, которые провайдер добавил с тех пор. Проверьте, что адрес подписки доступен с роутера (помогут проверки DNS и доступности), или импортируйте её заново.",
		"WayHop не зміг заново завантажити підписку, тож у ній може не бути серверів, які провайдер додав відтоді. Перевірте, що адреса підписки доступна з роутера (допоможуть перевірки DNS і доступності), або імпортуйте її заново."},
}

// daemonPattern is a sentence of the router's with a number or a name in it: the router's own
// literal (src, for the drift test), how to read the parts out of a sentence, and {ru, uk} formats
// over those parts in order (each a %s).
type daemonPattern struct {
	src    string
	re     *regexp.Regexp
	ru, uk string
}

var daemonPatterns = []daemonPattern{
	{"clock is off by ", regexp.MustCompile(`^clock is off by (.+)$`),
		"часы сбиты на %s", "годинник збився на %s"},
	{"clock is wrong by ", regexp.MustCompile(`^clock is wrong by (.+)$`),
		"часы ошибаются на %s", "годинник помиляється на %s"},
	{"%d of %d endpoint(s) unreachable", regexp.MustCompile(`^(\d+) of (\d+) endpoint\(s\) unreachable$`),
		"недоступно подключений: %s из %s", "недоступно підключень: %s з %s"},
	{" mode but plan not installed — click Apply", regexp.MustCompile(`^(\S+) mode but plan not installed — click Apply$`),
		"режим %s, но план не установлен — нажмите «Применить»", "режим %s, але план не встановлено — натисніть «Застосувати»"},
	{" mode but the policy plane is not applied — click Apply", regexp.MustCompile(`^(\S+) mode but the policy plane is not applied — click Apply$`),
		"режим %s, но правила в ядре не применены — нажмите «Применить»", "режим %s, але правила в ядрі не застосовано — натисніть «Застосувати»"},
	{"%d source rule(s) reference a missing interface", regexp.MustCompile(`^(\d+) source rule\(s\) reference a missing interface$`),
		"правил по источнику с несуществующим интерфейсом: %s", "правил за джерелом з неіснуючим інтерфейсом: %s"},
	{"%d endpoint(s) use a feature this sing-box build lacks", regexp.MustCompile(`^(\d+) endpoint\(s\) use a feature this sing-box build lacks$`),
		"подключений с возможностью, которой нет в этой сборке sing-box: %s", "підключень із можливістю, якої немає в цій збірці sing-box: %s"},
	{"%d of %d configured lists match nothing on this router", regexp.MustCompile(`^(\d+) of (\d+) configured lists match nothing on this router$`),
		"списков, которые ничего не находят на этом роутере: %s из %s", "списків, які нічого не знаходять на цьому роутері: %s з %s"},
	{"last subscription refresh failed: ", regexp.MustCompile(`^last subscription refresh failed: (.+)$`),
		"последнее обновление подписки не удалось: %s", "останнє оновлення підписки не вдалося: %s"},
	{"%d MiB free — not enough to replace WayHop itself (%d MiB)", regexp.MustCompile(`^(\d+) MiB free — not enough to replace WayHop itself \((\d+) MiB\)$`),
		"свободно %s МиБ — не хватит, чтобы заменить саму WayHop (%s МиБ)", "вільно %s МіБ — не вистачить, щоб замінити саму WayHop (%s МіБ)"},
}

// daemonIn is one of the router's own sentences in lang, when the bot knows it; as written otherwise.
func daemonIn(lang, s string) string {
	col := 0
	switch lang {
	case "ru":
	case "uk":
		col = 1
	default:
		return s
	}
	if tr, ok := daemonText[s]; ok {
		return tr[col]
	}
	for _, p := range daemonPatterns {
		m := p.re.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		args := make([]any, 0, len(m)-1)
		for _, part := range m[1:] {
			args = append(args, part)
		}
		if col == 0 {
			return fmt.Sprintf(p.ru, args...)
		}
		return fmt.Sprintf(p.uk, args...)
	}
	return s
}

// errorText is an error for the chat: the ones the bot knows by kind in the chat's language, the
// rest in the words they came with.
func errorText(v view, err error) string {
	switch {
	case errors.Is(err, ErrUnavailable):
		return v.t("mt.unavailable")
	case errors.Is(err, ErrBusy):
		return v.t("err.busy")
	case errors.Is(err, context.DeadlineExceeded):
		return v.t("err.timeout")
	}
	return fmt.Sprint(err)
}
