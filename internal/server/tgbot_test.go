package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/serverstore"
	"wayhop/internal/speedtest"
	"wayhop/internal/tgbot"
	"wayhop/internal/updater"
	"wayhop/internal/util"
)

const tgTestToken = "123456789:AAtest_token-abcdefghijklmnopqrstuv"

// tgServer is a demo server whose config is file-backed, so the bot settings can be saved.
func tgServer(t *testing.T) *Server {
	t.Helper()
	s, _ := tgServerAt(t)
	return s
}

func tgServerAt(t *testing.T) (*Server, string) {
	t.Helper()
	s := opshandlers_server(t)
	path := filepath.Join(t.TempDir(), "config.json")
	data, _ := json.Marshal(s.cfg)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s.cfg = loaded
	return s, path
}

func tgDo(t *testing.T, s *Server, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://127.0.0.1"+target, strings.NewReader(body))
	w := httptest.NewRecorder()
	authenticatedTestHandler(t, s).ServeHTTP(w, req)
	return w
}

func TestTelegramTokenIsWriteOnly(t *testing.T) {
	s, path := tgServerAt(t)
	w := tgDo(t, s, http.MethodPut, "/api/telegram", `{"enabled":false,"token":"`+tgTestToken+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", w.Code, w.Body)
	}
	if s.Telegram().Token != tgTestToken {
		t.Fatal("token not saved")
	}
	for _, target := range []string{"/api/telegram", "/api/config", "/api/config/export"} {
		r := tgDo(t, s, http.MethodGet, target, "")
		if strings.Contains(r.Body.String(), "AAtest_token") {
			t.Fatalf("%s returned the bot token", target)
		}
	}
	var v telegramView
	_ = json.Unmarshal(tgDo(t, s, http.MethodGet, "/api/telegram", "").Body.Bytes(), &v)
	if !v.HasToken || v.Bot.State != tgbot.StateOff {
		t.Fatalf("view %+v", v)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), tgTestToken) {
		t.Fatal("the token must persist on disk (mode 0600) or the bot cannot start after a reboot")
	}
}

func TestTelegramMaskedTokenKeepsTheSavedOne(t *testing.T) {
	s := tgServer(t)
	tgDo(t, s, http.MethodPut, "/api/telegram", `{"token":"`+tgTestToken+`"}`)
	for _, body := range []string{`{"token":"***"}`, `{"token":""}`, `{}`, `{"api_base":"https://api.telegram.org/"}`} {
		if w := tgDo(t, s, http.MethodPut, "/api/telegram", body); w.Code != http.StatusOK {
			t.Fatalf("%s = %d %s", body, w.Code, w.Body)
		}
		if s.Telegram().Token != tgTestToken {
			t.Fatalf("%s replaced the saved token", body)
		}
	}
	tgDo(t, s, http.MethodPut, "/api/telegram", `{"clear_token":true}`)
	if s.Telegram().Token != "" {
		t.Fatal("clear_token kept the token")
	}
}

// The saved token goes only to the Bot API server it was saved for. Pointing the bot elsewhere takes
// typing the token again; otherwise anyone at the panel could send it to a host of their own with
// Check or Save, and the token is the bot.
func TestTelegramTokenFollowsItsServer(t *testing.T) {
	s := tgServer(t)
	tgDo(t, s, http.MethodPut, "/api/telegram", `{"token":"`+tgTestToken+`"}`)
	hits := make(chan string, 8)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- r.URL.Path
		_, _ = io.WriteString(w, `{"ok":true,"result":{"id":7,"is_bot":true,"first_name":"Other","username":"other_bot"}}`)
	}))
	defer other.Close()
	elsewhere := `{"api_base":"` + other.URL + `"}`
	for _, call := range []struct{ method, path string }{{http.MethodPost, "/api/telegram/check"}, {http.MethodPut, "/api/telegram"}} {
		w := tgDo(t, s, call.method, call.path, elsewhere)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "enter the bot token again") {
			t.Fatalf("%s %s = %d %s", call.method, call.path, w.Code, w.Body)
		}
	}
	select {
	case p := <-hits:
		t.Fatalf("the saved token was sent to another server: %s", p)
	default:
	}
	if s.Telegram().APIBase != "" {
		t.Fatalf("api_base saved as %q", s.Telegram().APIBase)
	}
	// Typed again, it is the owner's to send wherever they like.
	typed := `{"token":"` + tgTestToken + `","api_base":"` + other.URL + `"}`
	if w := tgDo(t, s, http.MethodPost, "/api/telegram/check", typed); !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("check with the token typed: %s", w.Body)
	}
	if w := tgDo(t, s, http.MethodPut, "/api/telegram", typed); w.Code != http.StatusOK || s.Telegram().APIBase != other.URL {
		t.Fatalf("save with the token typed: %d %s", w.Code, w.Body)
	}
}

// "Refresh routing lists" counts what refreshAll refreshes: enabled lists with an address feed, a
// name feed or both. Counting address feeds alone told a router of name feeds that nothing had a
// source, right after refreshing them all.
func TestTelegramListRefreshCountsNameFeeds(t *testing.T) {
	lists := []model.RoutingList{
		{ID: "names", Enabled: true, DomainSource: "https://feeds.example/names.txt", DomainCache: []string{"a.example"}},
		{ID: "addrs", Enabled: true, CIDRSource: "https://feeds.example/cidr.txt", CIDRCache: []string{"192.0.2.0/24"}},
		{ID: "off", Enabled: false, CIDRSource: "https://feeds.example/off.txt"},
		{ID: "hand", Enabled: true, Manual: []string{"b.example"}},
	}
	before := listCaches(lists)
	if len(before) != 2 || before["names"] == "" || before["addrs"] == "" {
		t.Fatalf("counted %v", before)
	}
	lists[0].DomainCache = append(lists[0].DomainCache, "c.example")
	if after := listCaches(lists); after["names"] == before["names"] || after["addrs"] != before["addrs"] {
		t.Fatal("a name feed's new content does not count as a change")
	}
}

func TestTelegramSettingsAreValidated(t *testing.T) {
	s := tgServer(t)
	for _, body := range []string{
		`{"token":"not a token"}`,
		`{"enabled":true}`,
		`{"token":"` + tgTestToken + `","api_base":"ftp://x"}`,
		`{"token":"` + tgTestToken + `","quiet_from":"23:00"}`,
		`{"token":"` + tgTestToken + `","digest":"25:00"}`,
		`{"token":"` + tgTestToken + `","via":"no-such-tunnel"}`,
	} {
		if w := tgDo(t, s, http.MethodPut, "/api/telegram", body); w.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", body, w.Code)
		}
	}
	if s.Telegram().Token != "" {
		t.Fatal("a refused body was partly saved")
	}
}

func TestTelegramViaAcceptsProfileObjectsAndTheLocalProxy(t *testing.T) {
	s := tgServer(t)
	if err := s.store.Replace(model.Profile{Endpoints: []model.Endpoint{opshandlers_awgEndpoint("nl")}}); err != nil {
		t.Fatal(err)
	}
	for _, via := range []string{"nl", viaLocalProxy, ""} {
		if w := tgDo(t, s, http.MethodPut, "/api/telegram", `{"via":"`+via+`"}`); w.Code != http.StatusOK {
			t.Errorf("via %q = %d %s", via, w.Code, w.Body)
		}
	}
}

// The bulk Settings save carries the masked token back. It must neither store the mask nor drop
// the chats the bot paired.
func TestSettingsSaveLeavesTheBotAlone(t *testing.T) {
	s := tgServer(t)
	if err := s.UpdateTelegram(func(tg *config.Telegram) error {
		tg.Token = tgTestToken
		tg.Chats = []config.TelegramChat{{ID: 500, Name: "Sam", Role: config.TelegramOwner}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	_ = json.Unmarshal(tgDo(t, s, http.MethodGet, "/api/config", "").Body.Bytes(), &cfg)
	cfg.Telegram.Chats = nil
	body, _ := json.Marshal(cfg)
	if w := tgDo(t, s, http.MethodPut, "/api/config", string(body)); w.Code != http.StatusOK {
		t.Fatalf("PUT /api/config = %d %s", w.Code, w.Body)
	}
	got := s.Telegram()
	if got.Token != tgTestToken || len(got.Chats) != 1 {
		t.Fatalf("the Settings save touched the bot: %+v", got)
	}
}

func TestTelegramPairIssuesAUsableCode(t *testing.T) {
	s := tgServer(t)
	w := tgDo(t, s, http.MethodPost, "/api/telegram/pair", `{"role":"viewer"}`)
	var out struct {
		Code string `json:"code"`
		TTL  int    `json:"ttl_s"`
		Link string `json:"link"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if len(out.Code) != 8 || out.TTL != 600 || out.Link != "" {
		t.Fatalf("pair %+v", out)
	}
	role, res := s.telegram().Gate().Redeem(tgbot.Chat{ID: 9, Type: "private"}, out.Code)
	if res != tgbot.RedeemOK || role != config.TelegramViewer {
		t.Fatalf("redeem %v %v", role, res)
	}
}

func TestTelegramChatRoleAndUnpair(t *testing.T) {
	s := tgServer(t)
	_ = s.UpdateTelegram(func(tg *config.Telegram) error {
		tg.Chats = []config.TelegramChat{{ID: 500, Role: config.TelegramOwner}, {ID: -100, Role: config.TelegramViewer}}
		return nil
	})
	if w := tgDo(t, s, http.MethodPut, "/api/telegram/chats/-100", `{"role":"owner"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("a group was made owner: %d", w.Code)
	}
	if w := tgDo(t, s, http.MethodPut, "/api/telegram/chats/-100", `{"role":"alerts"}`); w.Code != http.StatusOK {
		t.Fatalf("role change = %d %s", w.Code, w.Body)
	}
	if w := tgDo(t, s, http.MethodPut, "/api/telegram/chats/-100", `{"lang":"xx"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("a language the bot does not speak was stored: %d", w.Code)
	}
	if w := tgDo(t, s, http.MethodPut, "/api/telegram/chats/42", `{"role":"alerts"}`); w.Code != http.StatusNotFound {
		t.Fatalf("unknown chat = %d", w.Code)
	}
	if w := tgDo(t, s, http.MethodDelete, "/api/telegram/chats/500", ""); w.Code != http.StatusOK {
		t.Fatalf("unpair = %d %s", w.Code, w.Body)
	}
	chats := s.Telegram().Chats
	if len(chats) != 1 || chats[0].ID != -100 || chats[0].Role != config.TelegramAlerts {
		t.Fatalf("chats %+v", chats)
	}
	// Both left the owners and viewers, so both may still show the bot's menu, and the bot is to
	// take it back, now or when it next runs. An alerts-only chat never had one of its own.
	if stale := s.Telegram().StaleMenus; !slices.Equal(stale, []int64{-100, 500}) {
		t.Fatalf("stale menus %v", stale)
	}
	if w := tgDo(t, s, http.MethodDelete, "/api/telegram/chats/-100", ""); w.Code != http.StatusOK || len(s.Telegram().StaleMenus) != 2 {
		t.Fatalf("unpairing an alerts-only chat: %d, stale menus %v", w.Code, s.Telegram().StaleMenus)
	}
}

func TestTelegramStrangerCanBeAllowedFromThePanel(t *testing.T) {
	s := tgServer(t)
	g := s.telegram().Gate()
	g.Seen(tgbot.Chat{ID: 777, Type: "private"}, &tgbot.User{ID: 777, FirstName: "Mom", LanguageCode: "ru"})
	g.Seen(tgbot.Chat{ID: -300, Type: "group", Title: "Family"}, &tgbot.User{ID: 1})
	if w := tgDo(t, s, http.MethodPost, "/api/telegram/strangers/-300/allow", `{"role":"owner"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("a group was allowed as owner: %d", w.Code)
	}
	// No role asked for: a viewer, private chat or not. A chat nobody vouched for with a code gets
	// the owner's buttons only when somebody at the panel says so.
	tgDo(t, s, http.MethodPost, "/api/telegram/strangers/777/allow", `{}`)
	tgDo(t, s, http.MethodPost, "/api/telegram/strangers/-300/allow", `{}`)
	chats := s.Telegram().Chats
	if len(chats) != 2 || chats[0].Role != config.TelegramViewer || chats[0].Lang != "ru" || chats[0].Name != "Mom" ||
		chats[1].Role != config.TelegramViewer || chats[1].Name != "Family" {
		t.Fatalf("chats %+v", chats)
	}
	g.Seen(tgbot.Chat{ID: 778, Type: "private"}, &tgbot.User{ID: 778, FirstName: "Dad"})
	tgDo(t, s, http.MethodPost, "/api/telegram/strangers/778/allow", `{"role":"owner"}`)
	if c := s.Telegram().Chats; len(c) != 3 || c[2].Role != config.TelegramOwner {
		t.Fatalf("an owner asked for by name: %+v", c)
	}
	if len(g.Strangers()) != 0 {
		t.Fatal("allowed chats stay listed as strangers")
	}
	if w := tgDo(t, s, http.MethodPost, "/api/telegram/strangers/5/allow", `{}`); w.Code != http.StatusNotFound {
		t.Fatalf("unknown stranger = %d", w.Code)
	}
}

func TestTelegramFailedSaveChangesNothing(t *testing.T) {
	s := unwritableCfgServer(t)
	err := s.UpdateTelegram(func(tg *config.Telegram) error { tg.Token = tgTestToken; return nil })
	if err == nil || s.Telegram().Token != "" {
		t.Fatalf("err=%v token=%q", err, s.Telegram().Token)
	}
}

// The adapter reads a demo server without a core, a monitor or a Clash API and still answers.
func TestTelegramBackendStatusOnABareDemo(t *testing.T) {
	s := tgServer(t)
	st := tgBackend{s}.Status(context.Background())
	if !st.Demo || !st.ExitIP.Known || st.ExitIP.IP != "203.0.113.7" || !st.System.Known || !st.Changes.Known {
		t.Fatalf("status %+v", st)
	}
	if log := (tgBackend{s}).Events(10); log.Known {
		t.Fatal("no monitor must read as an unknown log, not an empty one")
	}
	if _, err := (tgBackend{s}).TestExit(context.Background(), "x"); err == nil {
		t.Fatal("testing without a monitor must fail")
	}
}

func TestTelegramPulseAndDecisionsOnABareDemo(t *testing.T) {
	s := tgServer(t)
	p := tgBackend{s}.Pulse(context.Background())
	if !p.Mem.Known || p.FailSafe.Pending || p.FailSafe.Live || p.Core.Supervised {
		t.Fatalf("pulse %+v", p)
	}
	if err := (tgBackend{s}).ConfirmApply(context.Background()); err == nil || !strings.Contains(err.Error(), "no unsaved configuration to keep") {
		t.Fatalf("keep without a window: %v", err)
	}
	if err := (tgBackend{s}).RollbackApply(context.Background()); err == nil || !strings.Contains(err.Error(), "no unsaved configuration to roll back") {
		t.Fatalf("roll back without a window: %v", err)
	}
}

// The heartbeat is what lets the bot say how long the router was gone. It is read before the first
// write replaces it, and written only while the bot is enabled and never by the demo.
func TestTelegramHeartbeat(t *testing.T) {
	s := cfgFileServer(t)
	dir := t.TempDir()
	s.cfg.DataDir = dir
	s.startedAt = time.Now()
	prev := time.Now().Add(-3 * time.Hour).Unix()
	if err := os.WriteFile(filepath.Join(dir, "telegram-heartbeat"), []byte(strconv.FormatInt(prev, 10)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.cfg.Telegram = config.Telegram{Enabled: true, Token: tgTestToken}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.heartbeatLoop(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, _ := os.ReadFile(filepath.Join(dir, "telegram-heartbeat"))
		if v, _ := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); v > prev {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no heartbeat written")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if bi := (tgBackend{s}).Boot(); bi.LastSeen.Unix() != prev || bi.DaemonStart.IsZero() {
		t.Fatalf("boot info read after the write, or not at all: %+v", bi)
	}

	demo := tgServer(t)
	demo.cfg.DataDir = t.TempDir()
	demo.cfg.Telegram = config.Telegram{Enabled: true, Token: tgTestToken}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() { demo.heartbeatLoop(ctx2); close(done2) }()
	time.Sleep(50 * time.Millisecond)
	cancel2()
	<-done2
	if _, err := os.Stat(filepath.Join(demo.cfg.DataDir, "telegram-heartbeat")); err == nil {
		t.Fatal("the demo wrote a heartbeat")
	}
}

// The digest claim outlives the process on a router, so a restart in the digest's half hour does not
// send it again; the demo keeps its claim to itself and writes nothing.
func TestTelegramDigestClaim(t *testing.T) {
	s := cfgFileServer(t)
	s.cfg.DataDir = t.TempDir()
	if b := (tgBackend{s}); !b.ClaimDigest("2026-09-24") || b.ClaimDigest("2026-09-24") {
		t.Fatal("the first claim of a day must win and the second lose")
	}
	restarted := cfgFileServer(t)
	restarted.cfg.DataDir = s.cfg.DataDir
	b := tgBackend{restarted}
	if b.ClaimDigest("2026-09-24") {
		t.Fatal("claimed again after a restart")
	}
	if !b.ClaimDigest("2026-09-25") {
		t.Fatal("the next day was refused")
	}

	demo := tgServer(t)
	demo.cfg.DataDir = t.TempDir()
	if d := (tgBackend{demo}); !d.ClaimDigest("2026-09-24") || d.ClaimDigest("2026-09-24") {
		t.Fatal("the demo's claim")
	}
	if _, err := os.Stat(filepath.Join(demo.cfg.DataDir, "telegram-digest")); err == nil {
		t.Fatal("the demo wrote the digest file")
	}
}

// Quiet hours and the digest run on the router's clock, so the panel shows it beside them.
func TestTelegramViewCarriesTheRoutersClock(t *testing.T) {
	s := tgServer(t)
	w := tgDo(t, s, http.MethodGet, "/api/telegram", "")
	var v struct{ Clock, Zone string }
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil || len(v.Clock) != 5 || v.Clock[2] != ':' || v.Zone == "" {
		t.Fatalf("clock %q zone %q (%v): %s", v.Clock, v.Zone, err, w.Body.String())
	}
	for _, c := range []struct {
		loc  *time.Location
		want string
	}{
		{time.FixedZone("CEST", 2*3600), "CEST"},
		{time.FixedZone("", 3*3600), "+03"},
		{time.FixedZone("", -(3*3600 + 30*60)), "-03:30"},
		{time.FixedZone("", 5*3600+45*60), "+05:45"},
		{time.UTC, "UTC"},
	} {
		if got := zoneLabel(time.Date(2026, 9, 24, 12, 0, 0, 0, c.loc)); got != c.want {
			t.Errorf("%v: %q, want %q", c.loc, got, c.want)
		}
	}
}

func TestTelegramDeviceGroupOf(t *testing.T) {
	groups := []model.DeviceGroup{
		{ID: "kids", Name: "Kids", Members: []model.DeviceMember{{MAC: "AA:BB:CC:DD:EE:FF"}}},
		{ID: "iot", Name: "IoT", Members: []model.DeviceMember{{IP: "192.168.1.64/26"}}},
		{ID: "tv", Name: "TV", Members: []model.DeviceMember{{IP: "192.168.1.40"}}},
	}
	for d, want := range map[deviceInfo]string{
		{IP: "192.168.1.23", MAC: "aa:bb:cc:dd:ee:ff"}: "Kids",
		{IP: "192.168.1.70", MAC: "02:00:00:00:00:01"}: "IoT",
		{IP: "192.168.1.40", MAC: "de:ad:be:ef:00:01"}: "TV",
		{IP: "192.168.1.41", MAC: "de:ad:be:ef:00:11"}: "",
		{IP: "not-an-ip", MAC: "de:ad:be:ef:00:99"}:    "",
	} {
		if got := deviceGroupOf(groups, d); got != want {
			t.Errorf("%+v: got %q want %q", d, got, want)
		}
	}
}

func TestTelegramToolsRefuseBadTargets(t *testing.T) {
	s := tgServer(t)
	b := tgBackend{s}
	if _, err := b.Trace(context.Background(), "$(reboot)"); err != tgbot.ErrBadTarget {
		t.Fatalf("trace: %v", err)
	}
	if _, err := b.Ping(context.Background(), "-f"); err != tgbot.ErrBadTarget {
		t.Fatalf("ping: %v", err)
	}
	if _, err := b.Lookup(context.Background(), "a b"); err != tgbot.ErrBadTarget {
		t.Fatalf("lookup: %v", err)
	}
}

// The demo has no leases and no router ARP table; the bot's walkthrough still shows a device list,
// and says it is the demo by the documentation-style addresses. A real router never gets these.
func TestTelegramDemoDevicesOnlyInTheDemo(t *testing.T) {
	s := tgServer(t)
	if l := (tgBackend{s}).Devices(context.Background()); len(lanDevices()) == 0 && (len(l.Devices) == 0 || !l.Measured) {
		t.Fatalf("the demo shows no devices, or no traffic: %+v", l)
	}
	s.cfg.Demo = false
	if l := (tgBackend{s}).Devices(context.Background()); len(lanDevices()) == 0 && len(l.Devices) != 0 {
		t.Fatalf("a non-demo daemon invented devices: %+v", l)
	}
}

// Who is using the line now: two reads of the connection table, a gap apart, per client.
func TestTelegramDeviceRates(t *testing.T) {
	flow := func(src string, sport, up, down int) string {
		return fmt.Sprintf("ipv4     2 tcp      6 431999 ESTABLISHED src=%s dst=198.51.100.10 sport=%d dport=443 packets=10 bytes=%d "+
			"src=198.51.100.10 dst=%s sport=443 dport=%d packets=20 bytes=%d [ASSURED] mark=0 zone=0 use=2\n", src, sport, up, src, sport, down)
	}
	reads := []string{
		flow("192.168.1.40", 51000, 1000, 1_000_000) + flow("192.168.1.23", 52000, 500, 20_000) + flow("192.168.1.55", 53000, 10, 10),
		// The TV's flow moved 3 MB, the phone's flow closed and a new one opened, the third is idle.
		flow("192.168.1.40", 51000, 101_000, 4_000_000) + flow("192.168.1.23", 52001, 300, 6_000) + flow("192.168.1.55", 53000, 10, 10),
	}
	i := 0
	read := func() (string, error) { i++; return reads[i-1], nil }
	rates, ok := deviceRates(context.Background(), read, 100*time.Millisecond)
	if !ok {
		t.Fatal("not measured")
	}
	if tv := rates.rate["192.168.1.40"]; tv != [2]int64{30_000_000, 1_000_000} {
		t.Fatalf("tv %v", tv)
	}
	// The closed flow counts nothing, the new one counts whole: 6000 down and 300 up in 0.1 s.
	if phone := rates.rate["192.168.1.23"]; phone != [2]int64{60_000, 3_000} {
		t.Fatalf("phone %v", phone)
	}
	if idle := rates.rate["192.168.1.55"]; idle != [2]int64{} {
		t.Fatalf("idle %v", idle)
	}
	// No byte counters (nf_conntrack_acct off) or no table: not measured, rather than all idle.
	zero := func() (string, error) { return flow("192.168.1.40", 51000, 0, 0), nil }
	if _, ok := deviceRates(context.Background(), zero, time.Millisecond); ok {
		t.Fatal("a table with no byte counts was taken as a measurement")
	}
	missing := func() (string, error) { return "", os.ErrNotExist }
	if _, ok := deviceRates(context.Background(), missing, time.Millisecond); ok {
		t.Fatal("no table was taken as a measurement")
	}
}

func TestTelegramMaintenanceOnADemo(t *testing.T) {
	s := tgServer(t)
	ss, err := serverstore.Open(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.servers = ss
	b := tgBackend{s}
	ctx := context.Background()
	if err := b.RestartDaemon(ctx); err != tgbot.ErrUnavailable {
		t.Fatalf("restart in the demo: %v", err)
	}
	if r, err := b.RefreshLists(ctx); err != nil || r.Lists != 0 || r.Changed != 0 {
		t.Fatalf("lists with no sources: %+v %v", r, err)
	}
	if _, err := b.RefreshSubscription(ctx); err == nil || err.Error() != "no subscription is imported" {
		t.Fatalf("subscription: %v", err)
	}
	name, data, err := b.Backup(ctx)
	if err != nil || !strings.HasPrefix(name, "wayhop-backup-") || !strings.HasSuffix(name, ".json") ||
		!strings.Contains(string(data), `"wayhop_backup"`) {
		t.Fatalf("backup %q %v", name, err)
	}
	p, err := b.ApplyPreview(ctx)
	if err != nil || p.Rev == "" {
		t.Fatalf("preview %+v %v", p, err)
	}
	if err := b.ApplyTest(ctx, "not-the-reviewed-rev"); err == nil || !strings.Contains(err.Error(), "changed since you reviewed it") {
		t.Fatalf("a stale revision was applied: %v", err)
	}
}

// The demo has no release catalogue for WayHop itself: the check says it could not tell, and
// never offers a version that does not exist.
func TestTelegramUpdateCheckOnADemo(t *testing.T) {
	s := tgServer(t)
	// Built the way New builds it for the demo: offline catalogue, the demo package manager.
	up := updater.New(t.TempDir(), "", nil)
	up.WithPM(updater.DemoPM())
	up.Offline = true
	s.updater = up
	info := (tgBackend{s}).UpdateCheck(context.Background())
	if info.Available || info.Current == "" {
		t.Fatalf("demo update check %+v", info)
	}
}

// One speed test at a time, the panel's and the bot's alike: two at once share the line and each
// reports about half of it.
func TestSpeedTestsRunOneAtATime(t *testing.T) {
	s := tgServer(t)
	s.speedMu.Lock()
	w := servererrorpaths_post(s.handleSpeedtest, "/api/speedtest", `{"via":"proxy"}`)
	if w.Code != http.StatusConflict || !strings.Contains(servererrorpaths_errMsg(t, w), "already running") {
		t.Fatalf("panel test during another: %d %s", w.Code, w.Body.String())
	}
	if _, err := (tgBackend{s}).SpeedTest(context.Background(), "", func(string) { t.Error("a leg started") }); err != tgbot.ErrBusy {
		t.Fatalf("bot test during another: %v", err)
	}
	s.speedMu.Unlock()
}

// The demo spends no line: it walks the legs and answers with numbers of its own, then frees the
// slot. The route leg follows the configured rules: with none, the test's site goes straight out
// and only the line is measured; a default route through a kernel tunnel is measured under its
// name. One exit is measured on its own only when it is a kernel tunnel, which a sing-box outbound
// or an unknown id is not.
func TestSpeedTestOnTheDemo(t *testing.T) {
	defer func(d time.Duration) { demoSpeedLeg = d }(demoSpeedLeg)
	demoSpeedLeg = time.Millisecond
	s := tgServer(t)
	for _, e := range []model.Endpoint{
		{ID: "wg-exit", Name: "WireGuard exit", Engine: model.EngineExternal, Protocol: model.ProtoWireGuard,
			Server: "198.51.100.20", Port: 51820, Enabled: true, Params: map[string]any{"interface": "wg-exit"}},
		{ID: "vless-de", Name: "Reality DE", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
			Server: "203.0.113.10", Port: 443, Enabled: true},
	} {
		if err := s.store.UpsertEndpoint(e); err != nil {
			t.Fatal(err)
		}
	}
	if k := (tgBackend{s}).exitKinds(); !k["wg-exit"].tunnel || k["vless-de"].tunnel {
		t.Fatalf("kinds %+v", k)
	}
	var legs []string
	step := func(l string) { legs = append(legs, l) }
	rep, err := tgBackend{s}.SpeedTest(context.Background(), "", step)
	if err != nil || strings.Join(legs, ",") != "line" || !rep.Direct || !rep.Route.Skipped || rep.Line.DownMbps < 90 {
		t.Fatalf("no rules: legs %v, report %+v, err %v", legs, rep, err)
	}
	if err := s.store.UpsertRule(model.Rule{ID: "all", Default: true, Outbound: "wg-exit"}); err != nil {
		t.Fatal(err)
	}
	legs = nil
	rep, err = tgBackend{s}.SpeedTest(context.Background(), "", step)
	if err != nil || strings.Join(legs, ",") != "line,route" || rep.Direct || rep.Via != "WireGuard exit" || rep.Route.DownMbps < 40 {
		t.Fatalf("default route: legs %v, report %+v, err %v", legs, rep, err)
	}
	rep, err = tgBackend{s}.SpeedTest(context.Background(), "wg-exit", func(string) {})
	if err != nil || rep.Exit != "WireGuard exit" || rep.Route.DownMbps < 70 {
		t.Fatalf("one tunnel: %+v, %v", rep, err)
	}
	for _, id := range []string{"vless-de", "nope"} {
		if _, err := (tgBackend{s}).SpeedTest(context.Background(), id, func(string) { t.Errorf("%s: a leg started", id) }); err != tgbot.ErrUnavailable {
			t.Fatalf("%s: %v", id, err)
		}
	}
	if !s.speedMu.TryLock() {
		t.Fatal("the slot was not freed")
	}
	s.speedMu.Unlock()
}

// A tunnel's link is the one the monitor probes: an imported AmneziaWG endpoint's derived device, an
// adopted interface, the applied binding when there is one (empty when the core carries the
// endpoint), a Keenetic NDM name as its kernel link. A leg left by the interface that holds its
// connections' source address: a tunnel if that is one of WayHop's or a tunnel device, nothing if it
// is the uplink, whatever else moved through the tunnels meanwhile.
func TestTunnelLinkAndTheLinkALegLeftBy(t *testing.T) {
	awg := model.Endpoint{ID: "imported", Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG}
	adopted := model.Endpoint{ID: "adopted", Engine: model.EngineExternal, Params: map[string]any{"interface": "awg0"}}
	for _, c := range []struct {
		e      model.Endpoint
		native map[string]string
		known  bool
		want   string
	}{
		{awg, nil, false, util.AWGIface("imported")},
		{adopted, nil, false, "awg0"},
		{awg, map[string]string{"imported": "Wireguard0"}, true, "nwg0"},
		{awg, map[string]string{"imported": "wr_1a2b"}, true, "wr_1a2b"},
		{awg, map[string]string{}, true, ""},
		{model.Endpoint{ID: "v", Engine: model.EngineSingBox}, nil, false, ""},
	} {
		if got := tunnelLink(c.e, c.native, c.known); got != c.want || (c.want == "" && got != "") {
			t.Errorf("%s %v %v: %q, want %q", c.e.ID, c.native, c.known, got, c.want)
		}
	}
	defer func(f func(net.IP) string, g func(string) bool) { linkOfAddr, isTunnelDevice = f, g }(linkOfAddr, isTunnelDevice)
	links := map[string]string{"203.0.113.2": "wan", "10.8.0.2": "awg0", "10.9.0.2": "tun0"}
	linkOfAddr = func(ip net.IP) string { return links[ip.String()] }
	isTunnelDevice = func(name string) bool { return name == "tun0" }
	tunnels := map[string]bool{"awg0": true}
	for _, c := range []struct {
		local []string
		want  string
	}{
		{[]string{"203.0.113.2"}, ""},
		{[]string{"203.0.113.2", "10.8.0.2"}, "awg0"},
		{[]string{"10.9.0.2"}, "tun0"},
		{[]string{"192.0.2.99"}, ""},
	} {
		var l dialLog
		for _, a := range c.local {
			l.local = append(l.local, net.ParseIP(a))
		}
		if got := l.tunnelLeft(tunnels); got != c.want {
			t.Errorf("%v: %q, want %q", c.local, got, c.want)
		}
	}
	// wrap logs what the dialer connected from.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var l dialLog
	c, err := l.wrap(nil, nil)(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if len(l.local) != 1 || !l.local[0].IsLoopback() {
		t.Fatalf("logged %v", l.local)
	}
	// A dial that failed is still known by the way it would have left, when the route can be looked
	// up: a line leg whose own route is a dead tunnel is that tunnel's failure, not the provider's.
	var failed dialLog
	refuse := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("i/o timeout") }
	route := func(context.Context, string) net.IP { return net.ParseIP("10.8.0.2") }
	if _, err := failed.wrap(refuse, route)(context.Background(), "tcp", "speed.example:443"); err == nil {
		t.Fatal("the failed dial succeeded")
	}
	if got := failed.tunnelLeft(tunnels); got != "awg0" {
		t.Fatalf("a failed dial left by %q, want awg0", got)
	}
}

// A failed run keeps its reason and claims no latency; a good one carries its numbers over.
func TestSpeedLeg(t *testing.T) {
	if l := speedLeg(speedtest.Result{LatencyMs: 12}, fmt.Errorf("download: refused")); l.Err != "download: refused" || l.LatencyMs >= 0 {
		t.Fatalf("failed %+v", l)
	}
	if l := speedLeg(speedtest.Result{DownMbps: 94.2, UpMbps: 38.1, LatencyMs: 12}, nil); l != (tgbot.SpeedLeg{DownMbps: 94.2, UpMbps: 38.1, LatencyMs: 12}) {
		t.Fatalf("good %+v", l)
	}
}

// Offloaded flows whose counters stand still leave their devices unknown rather than idle; one that
// moved shows the flowtable counts, and every number stands. A device is also credited with its
// IPv6 traffic, which the table prints unabbreviated and the neighbour table ties to its MAC.
func TestTelegramDeviceRatesOnTheFastPathAndIPv6(t *testing.T) {
	line := func(fam, src, dst string, sport, up, down int, flag string) string {
		return fmt.Sprintf("%s     2 tcp      6 431999 ESTABLISHED src=%s dst=%s sport=%d dport=443 packets=10 bytes=%d "+
			"src=%s dst=%s sport=443 dport=%d packets=20 bytes=%d %s mark=0 zone=0 use=2\n",
			fam, src, dst, sport, up, dst, src, sport, down, flag)
	}
	v4 := func(src string, sport, up, down int, flag string) string {
		return line("ipv4", src, "198.51.100.10", sport, up, down, flag)
	}
	sample := func(reads ...string) flowRates {
		t.Helper()
		i := 0
		fr, ok := deviceRates(context.Background(), func() (string, error) { i++; return reads[i-1], nil }, 100*time.Millisecond)
		if !ok {
			t.Fatal("not measured")
		}
		return fr
	}
	frozen := sample(
		v4("192.168.1.40", 51000, 1000, 1_000_000, "[OFFLOAD]")+v4("192.168.1.23", 52000, 500, 20_000, "[ASSURED]"),
		v4("192.168.1.40", 51000, 1000, 1_000_000, "[OFFLOAD]")+v4("192.168.1.23", 52000, 900, 60_000, "[ASSURED]"),
	)
	if !frozen.fast["192.168.1.40"] || frozen.fast["192.168.1.23"] || frozen.rate["192.168.1.23"] != [2]int64{400_000, 4_000} {
		t.Fatalf("frozen fast path: %+v", frozen)
	}
	live := sample(
		v4("192.168.1.40", 51000, 1000, 1_000_000, "[HW_OFFLOAD]"),
		v4("192.168.1.40", 51000, 2000, 3_000_000, "[HW_OFFLOAD]"),
	)
	if len(live.fast) != 0 || live.rate["192.168.1.40"] != [2]int64{20_000_000, 10_000} {
		t.Fatalf("counting fast path: %+v", live)
	}
	tv6 := "2001:0db8:0000:0000:0000:0000:0000:0040"
	both := sample(
		v4("192.168.1.40", 51000, 0, 100, "[ASSURED]")+line("ipv6", tv6, "2001:0db8:0000:0000:0000:0000:0000:00aa", 53000, 0, 100, "[ASSURED]"),
		v4("192.168.1.40", 51000, 0, 100_100, "[ASSURED]")+line("ipv6", tv6, "2001:0db8:0000:0000:0000:0000:0000:00aa", 53000, 0, 200_100, "[ASSURED]"),
	)
	devs := deviceTraffic(
		[]deviceInfo{{IP: "192.168.1.40", MAC: strings.ToUpper("00:00:5e:00:53:40"), Hostname: "tv"}, {IP: "192.168.1.23", MAC: "00:00:5e:00:53:23"}},
		nil, both, map[string]string{"2001:db8::40": "00:00:5e:00:53:40"},
	)
	if devs[0].Down != 3_000_000 || devs[1].Down != 0 {
		t.Fatalf("devices %+v", devs)
	}
}

// The Telegram bot translates the trace's explanations by their English wording (tgbot.whyIn): if
// one of these changes here, change it there too, or the bot shows it untranslated.
func TestTraceWordsTheBotTranslates(t *testing.T) {
	ips := parseAddrs([]string{"142.250.1.1"})
	if got := matchDomainIP("youtube.com", ips, []string{"youtube.com"}, nil, nil); got != "domain youtube.com" {
		t.Errorf("domain: %q", got)
	}
	if got := matchDomainIP("www.youtube.com", ips, nil, []string{"youtube.com"}, nil); got != "domain_suffix youtube.com" {
		t.Errorf("suffix: %q", got)
	}
	if got := geoMatcherWhy(&model.Rule{GeoSite: []string{"youtube"}}); got != "geosite: youtube — needs the on-router dataset" {
		t.Errorf("geo: %q", got)
	}
	p := &model.Profile{RoutingLists: []model.RoutingList{
		{ID: "srs", Enabled: true, Source: "https://example.org/list.srs"},
		{ID: "feed", Enabled: true, DomainSource: "https://example.org/list.txt"},
	}}
	_, uneval := traceCandidates("youtube.com", nil, p, nil)
	whys := map[string]string{}
	for _, c := range uneval {
		whys[c.ID] = c.Why
	}
	if whys["srs"] != "remote rule-set — its contents are a sing-box artifact, not read here" ||
		whys["feed"] != "feed has never been fetched — nothing to match against yet" {
		t.Errorf("fixed sentences: %q", whys)
	}
}

// A connection forwarded in from outside is credited to the LAN host behind the forward, the
// directions swapped; an ordinary or redirected flow is credited to its client only. A flow
// offloaded in the gap cannot tell whether the flowtable counts; only one offloaded in both reads
// can, so a frozen stream still reads as the fast path's.
func TestTelegramDeviceRatesForwardedAndOffloadedInTheGap(t *testing.T) {
	line := func(src, dst, rsrc, rdst string, sport, up, down int, flag string) string {
		return fmt.Sprintf("ipv4     2 tcp      6 431999 ESTABLISHED src=%s dst=%s sport=%d dport=443 packets=10 bytes=%d "+
			"src=%s dst=%s sport=443 dport=%d packets=20 bytes=%d %s mark=0 zone=0 use=2\n",
			src, dst, sport, up, rsrc, rdst, sport, down, flag)
	}
	i := 0
	reads := []string{
		// A remote peer uploading to the NAS through a port forward; the TV's stream frozen on the
		// fast path; the phone's new flow opened in the gap and offloaded by the second read.
		line("198.51.100.7", "203.0.113.2", "192.168.1.50", "198.51.100.7", 40000, 1000, 1000, "[ASSURED]") +
			line("192.168.1.40", "198.51.100.10", "198.51.100.10", "203.0.113.2", 51000, 1000, 5_000_000, "[OFFLOAD]"),
		line("198.51.100.7", "203.0.113.2", "192.168.1.50", "198.51.100.7", 40000, 301_000, 11_000, "[ASSURED]") +
			line("192.168.1.40", "198.51.100.10", "198.51.100.10", "203.0.113.2", 51000, 1000, 5_000_000, "[OFFLOAD]") +
			line("192.168.1.23", "198.51.100.10", "198.51.100.10", "203.0.113.2", 52000, 2000, 80_000, "[OFFLOAD]"),
	}
	fr, ok := deviceRates(context.Background(), func() (string, error) { i++; return reads[i-1], nil }, 100*time.Millisecond)
	if !ok {
		t.Fatal("not measured")
	}
	if nas := fr.incoming["192.168.1.50"]; nas != [2]int64{3_000_000, 100_000} {
		t.Fatalf("forwarded to the NAS: %v", nas)
	}
	if !fr.fast["192.168.1.40"] {
		t.Fatalf("a flow offloaded in the gap made the frozen stream read as counted: %+v", fr)
	}
	devs := deviceTraffic([]deviceInfo{{IP: "192.168.1.50", MAC: "00:00:5e:00:53:55", Hostname: "nas"}}, nil, fr, nil)
	if devs[0].Down != 3_000_000 || devs[0].Up != 100_000 {
		t.Fatalf("nas %+v", devs[0])
	}
}

// A peer reaching a LAN host over IPv6 needs no NAT: the reply comes from the very address the flow
// was sent to, and the host is credited all the same.
func TestTelegramDeviceRatesInboundIPv6(t *testing.T) {
	line := func(up, down int) string {
		return fmt.Sprintf("ipv6     10 tcp      6 431999 ESTABLISHED src=2001:0db8:ffff:0000:0000:0000:0000:0007 "+
			"dst=2001:0db8:0001:0000:0000:0000:0000:0050 sport=40000 dport=443 packets=10 bytes=%d "+
			"src=2001:0db8:0001:0000:0000:0000:0000:0050 dst=2001:0db8:ffff:0000:0000:0000:0000:0007 sport=443 dport=40000 "+
			"packets=20 bytes=%d [ASSURED] mark=0 zone=0 use=2\n", up, down)
	}
	i := 0
	reads := []string{line(1000, 1000), line(301_000, 11_000)}
	fr, ok := deviceRates(context.Background(), func() (string, error) { i++; return reads[i-1], nil }, 100*time.Millisecond)
	if !ok {
		t.Fatal("not measured")
	}
	if got := fr.incoming["2001:db8:1::50"]; got != [2]int64{3_000_000, 100_000} {
		t.Fatalf("the LAN host got %v: %+v", got, fr)
	}
}

// Without the core a group's member is elected by the kernel plane, which answers with a link; the
// chat names the member that owns it.
func TestMemberOnLink(t *testing.T) {
	g := model.Group{ID: "auto", Members: []string{"vless-de", "wg-a", "wg-b"}}
	ifaceOf := map[string]string{"wg-a": "awg0", "wg-b": "awg1"}
	if got := memberOnLink(g, ifaceOf, "awg1"); got != "wg-b" {
		t.Fatalf("got %q", got)
	}
	if got := memberOnLink(g, ifaceOf, "tun9"); got != "" {
		t.Fatalf("an unknown link named %q", got)
	}
}
