package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"wayhop/internal/atomicfile"
	"wayhop/internal/config"
	"wayhop/internal/health"
	"wayhop/internal/localtz"
	"wayhop/internal/model"
	"wayhop/internal/netdiag"
	"wayhop/internal/qr"
	"wayhop/internal/speedtest"
	"wayhop/internal/tgbot"
	"wayhop/internal/updater"
	"wayhop/internal/updatetx"
	"wayhop/internal/version"
)

// tgbot.go wires the Telegram bot (internal/tgbot) to the daemon: the Backend it reads the router
// through, the Store its settings live in, the HTTP client it reaches Telegram with, and the panel's
// /api/telegram/* routes. See docs/TELEGRAM_BOT.md in the development repository.

// viaLocalProxy is the Telegram.Via value that sends the bot's traffic through sing-box's local
// mixed inbound, so it follows WayHop's own routing (a "Telegram" list, a group) instead of one
// fixed interface. It is the only option for an exit that has no kernel interface (VLESS, Trojan).
const viaLocalProxy = "@proxy"

// telegram returns the bot manager, creating it on first use.
func (s *Server) telegram() *tgbot.Manager {
	s.tgOnce.Do(func() {
		s.tg = tgbot.NewManager(tgBackend{s}, s, s.telegramClient)
	})
	return s.tg
}

// StartTelegram runs the bot per the saved settings until ctx ends, and the heartbeat that lets it
// say how long the router was gone after a power cut.
func (s *Server) StartTelegram(ctx context.Context) {
	go s.heartbeatLoop(ctx)
	s.telegram().Start(ctx)
}

// Telegram implements tgbot.Store: the saved bot settings, with the chat list copied.
func (s *Server) Telegram() config.Telegram {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	return cloneTelegram(s.cfg.Telegram)
}

func cloneTelegram(t config.Telegram) config.Telegram { return t.Clone() }

// UpdateTelegram implements tgbot.Store: fn edits a copy, which is validated and saved durably. A
// failed save leaves memory and disk as they were.
func (s *Server) UpdateTelegram(fn func(*config.Telegram) error) error {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	next := cloneTelegram(s.cfg.Telegram)
	if err := fn(&next); err != nil {
		return err
	}
	if err := next.Validate(); err != nil {
		return err
	}
	prev := s.cfg.Telegram
	s.cfg.Telegram = next
	if err := s.cfg.Save(); err != nil {
		s.cfg.Telegram = prev
		return err
	}
	return nil
}

// errTelegramPathDown refuses a dial when the chosen path cannot carry the bot right now: a group with
// no healthy member, a connection deleted or disabled since. The bot then stays offline and says why,
// instead of reaching Telegram over the ordinary path, which is the one the choice was made to avoid
// (it may be blocked, or watched).
var errTelegramPathDown = errors.New("the path chosen for the bot cannot carry it now")

// telegramClient is the HTTP client the bot reaches Telegram with. The socket is bound at dial time,
// like the component downloader's, so a group follows its healthy member without a restart. Unlike
// the downloader's, a choice that resolves to nothing fails closed: no Telegram traffic leaves by
// another way when a route was chosen.
func (s *Server) telegramClient(t config.Telegram) *http.Client {
	tr := &http.Transport{
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 90 * time.Second, // a long poll holds the response for up to 50s
		IdleConnTimeout:       2 * time.Minute,
		MaxIdleConnsPerHost:   2,
	}
	via := t.Via
	if via == viaLocalProxy {
		tr.Proxy = http.ProxyURL(&url.URL{Scheme: "socks5", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(s.config().Ports.Mixed))})
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second, Control: func(network, address string, c syscall.RawConn) error {
		if via == "" || via == model.OutboundDirect || via == viaLocalProxy {
			return nil
		}
		iface := s.outboundIface(via)
		if iface == "" {
			return fmt.Errorf("%w (%q)", errTelegramPathDown, via)
		}
		return netdiag.BindToDevice(iface)(network, address, c)
	}}
	tr.DialContext = dialer.DialContext
	return &http.Client{Transport: tr}
}

// tgBackend reads the router for the bot. Every part is best-effort: a part that cannot be read is
// reported unknown, never guessed.
type tgBackend struct{ s *Server }

func (b tgBackend) Status(ctx context.Context) tgbot.Status {
	s := b.s
	cfg := s.config()
	st := tgbot.Status{At: time.Now(), Version: version.Version, Demo: cfg.Demo}

	if s.singbox != nil {
		st.Core.Available, st.Core.Running = s.singbox.Available(), s.singbox.Running()
	}
	if !st.Core.Running && s.clash != nil {
		cctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		if _, err := s.clash.Proxies(cctx); err == nil {
			st.Core.Available, st.Core.Running = true, true
		}
		cancel()
	}
	if s.store != nil {
		st.Core.NativeOnly = s.nativeOnlyCached()
	}
	st.Core.Restarts = s.supervisionStats().Restarts

	if ip, geo, _, ok := s.exitIPNow(ctx); ok {
		st.ExitIP = tgbot.ExitIP{Known: true, IP: ip, Country: geo.Country, Code: geo.CC, Org: geo.ISP}
	} else if cfg.Demo {
		st.ExitIP = demoExitIP
	}

	if s.monitor != nil {
		kinds := b.exitKinds()
		for _, v := range s.monitor.Snapshot() {
			e := exitFromView(v, kinds)
			st.Exits = append(st.Exits, e)
		}
		st.LocalFault = s.monitor.LocalFault()
	}
	st.Groups = b.groups(ctx)
	if v := s.routingSwitchView(); !v.Enabled {
		st.Routing = tgbot.Routing{Off: true, By: v.By, Err: v.Error}
		if v.Since > 0 {
			st.Routing.Since = time.Unix(v.Since, 0)
		}
		// With the core stopped on purpose every exit it carries fails at once, which is what the
		// monitor's "the uplink, not the tunnels" verdict looks for. It is neither.
		st.LocalFault = false
	}

	si := readSystemInfo()
	if cfg.Demo {
		si = demoSystemInfo(time.Now())
	}
	if si.Available {
		st.System = tgbot.System{Known: true, MemUsedPct: si.MemUsedPct, Load1: si.Load1, UptimeS: si.UptimeS, TempC: si.TempC}
	}
	if s.hub != nil {
		if r := s.hub.RecentN(1); len(r) == 1 && time.Since(time.UnixMilli(r[0].T)) < 15*time.Second {
			st.Traffic = tgbot.Rates{Known: true, Up: r[0].Up, Down: r[0].Down}
		}
	}
	st.Changes = b.changes()
	st.Feeds = b.feedIssues()
	if s.failsafe != nil {
		if fs := s.failsafe.Status(); fs.Pending {
			health := "unknown"
			if fs.LastCheckAt > 0 {
				health = "down"
				if fs.LastCheckOk {
					health = "up"
				}
			}
			st.FailSafe = tgbot.FailSafe{Armed: true, Remaining: time.Duration(fs.SecondsLeft) * time.Second, Health: health,
				Window: applyWindow(s.liveRevision())}
		}
	}
	if s.liveRollbackFailed() != nil {
		st.FailSafe.RollbackOutstanding, st.FailSafe.Window = true, applyWindow(s.liveRevision())
	}
	return st
}

// feedIssues lists, in the profile's order, the enabled routing lists with a feed whose last
// refresh failed, with how many failed in a row. The bot decides how many make it worth saying.
func (b tgBackend) feedIssues() []tgbot.FeedIssue { return b.feedIssuesSince(time.Time{}) }

// feedIssuesSince is feedIssues limited to the lists whose feed failed at t or later. A record of
// other feeds than the list has now is left out: the list was given new ones, not yet tried.
func (b tgBackend) feedIssuesSince(t time.Time) []tgbot.FeedIssue {
	s := b.s
	if s.store == nil {
		return nil
	}
	fails := s.feedFailuresNow()
	if len(fails) == 0 {
		return nil
	}
	var out []tgbot.FeedIssue
	for _, rl := range s.store.Profile().RoutingLists {
		f, ok := fails[rl.ID]
		if !ok || !rl.Enabled || (rl.CIDRSource == "" && rl.DomainSource == "") || f.feeds != feedsOf(rl) || f.seen.Before(t) {
			continue
		}
		name := rl.Name
		if name == "" {
			name = rl.ID
		}
		out = append(out, tgbot.FeedIssue{List: name, Fails: f.fails, Since: f.since, Err: f.err,
			Empty: len(rl.CIDRCache) == 0 && len(rl.DomainCache) == 0})
	}
	return out
}

// groups names each group's elected member: the core's live pick where the core has one (Clash
// `now`), otherwise the member the kernel plane routes through (first healthy in the operator's order).
func (b tgBackend) groups(ctx context.Context) []tgbot.Group {
	s := b.s
	if s.store == nil {
		return nil
	}
	profile := s.store.Profile()
	if len(profile.Groups) == 0 {
		return nil
	}
	var proxies map[string]string
	if s.clash != nil {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if ps, err := s.clash.Proxies(cctx); err == nil {
			proxies = map[string]string{}
			for id, p := range ps {
				proxies[id] = p.Now
			}
		}
		cancel()
	}
	ifaceOf := kernelIfaceByEndpoint(&profile)
	var out []tgbot.Group
	for _, g := range profile.Groups {
		tg := tgbot.Group{ID: g.ID, Name: g.Name, Members: append([]string(nil), g.Members...)}
		if tg.Name == "" {
			tg.Name = g.ID
		}
		if now := proxies[g.ID]; now != "" {
			tg.Elected = now
		} else if s.monitor != nil {
			if iface, ok := s.electHealthyMember(g, ifaceOf); ok {
				tg.Elected = memberOnLink(g, ifaceOf, iface)
			}
		}
		out = append(out, tg)
	}
	return out
}

// memberOnLink is the group member the kernel plane routes through. The plane elects by link
// (electMember answers with an interface), and a chat names the exit that owns it; "" when none does.
func memberOnLink(g model.Group, ifaceOf map[string]string, iface string) string {
	for _, id := range g.Members {
		if ifaceOf[id] == iface {
			return id
		}
	}
	return ""
}

// changes is the saved-but-not-applied state, counted when the review can count it.
func (b tgBackend) changes() tgbot.Changes {
	s := b.s
	if s.store == nil {
		return tgbot.Changes{}
	}
	desired, err := s.captureDesiredSnapshot()
	if err != nil {
		return tgbot.Changes{}
	}
	view := s.pendingView(desired)
	c := tgbot.Changes{Known: true, Pending: view.Pending}
	if view.Pending {
		if plan := s.planChanges(desired, s.appliedBaseline()); plan.BaselineAvailable {
			c.Count = plan.Count
		}
	}
	return c
}

func (b tgBackend) TestExit(ctx context.Context, id string) (tgbot.Exit, error) {
	if b.s.monitor == nil {
		return tgbot.Exit{}, errors.New("the health monitor is not running")
	}
	v := b.s.monitor.ProbeOne(ctx, id)
	if v.ID == "" {
		return tgbot.Exit{}, errors.New("no such exit")
	}
	return exitFromView(v, b.exitKinds()), nil
}

// exitKind is what the bot calls an exit's kind: its protocol for an endpoint, "group" for a group.
type exitKind struct {
	label  string
	group  bool
	tunnel bool // a kernel interface to bind a speed test to
}

// protocolLabels are the protocol names as people write them.
var protocolLabels = map[model.Protocol]string{
	model.ProtoVLESS: "VLESS", model.ProtoVMess: "VMess", model.ProtoTrojan: "Trojan",
	model.ProtoShadowsocks: "Shadowsocks", model.ProtoHysteria2: "Hysteria2", model.ProtoTUIC: "TUIC",
	model.ProtoAnyTLS: "AnyTLS", model.ProtoWireGuard: "WireGuard", model.ProtoAmneziaWG: "AmneziaWG",
	model.ProtoOlcRTC: "olcRTC", model.ProtoSOCKS: "SOCKS", model.ProtoHTTP: "HTTP",
	model.ProtoOpenVPN: "OpenVPN", model.ProtoSnell: "Snell",
	model.ProtoOpenConnect: "OpenConnect", model.ProtoSSH: "SSH",
}

// exitKinds maps every endpoint and group id to its kind, from one read of the profile.
func (b tgBackend) exitKinds() map[string]exitKind {
	out := map[string]exitKind{}
	if b.s.store == nil {
		return out
	}
	p := b.s.store.Profile()
	// The same resolution the speed test binds with, so the card offers the test exactly where the
	// test can run: an imported AmneziaWG tunnel's derived device, an applied plan's binding.
	native, known := b.s.currentNativeInterfaceBindings()
	for _, e := range p.Endpoints {
		label := protocolLabels[e.Protocol]
		if label == "" {
			label = string(e.Protocol)
		}
		out[e.ID] = exitKind{label: label, tunnel: tunnelLink(e, native, known) != ""}
	}
	for _, g := range p.Groups {
		out[g.ID] = exitKind{group: true}
	}
	return out
}

func exitFromView(v health.View, kinds map[string]exitKind) tgbot.Exit {
	k := kinds[v.ID]
	return tgbot.Exit{
		ID: v.ID, Name: v.Name, Kind: k.label, State: v.State, LatencyMs: v.LatencyMs,
		AvgLatency: v.AvgLatencyMs, SuccessRate: v.SuccessRate, UptimeS: v.UptimeS,
		RateUp: v.RateUpBps, RateDown: v.RateDownBps, BytesUp: v.BytesUp, BytesDown: v.BytesDown,
		Cause: v.Cause, Fix: v.CauseFix, CauseID: v.CauseID,
		Group: k.group, Tunnel: k.tunnel,
	}
}

func (b tgBackend) Events(limit int) tgbot.EventLog {
	s := b.s
	if s.monitor == nil {
		return tgbot.EventLog{}
	}
	since := s.startedAt.UnixMilli()
	if oldest := s.monitor.OldestEventAt(); oldest != 0 && (oldest < since || s.monitor.EventLogFull()) {
		// A full ring has dropped its oldest entries, so it covers only what it still holds. Starting
		// the window at the daemon's start would claim a day of history the digest does not have.
		since = oldest
	}
	out := tgbot.EventLog{Known: true, Since: time.UnixMilli(since), Total: s.monitor.EventCount()}
	for _, e := range s.monitor.Events(limit) {
		out.Events = append(out.Events, tgbot.Event{At: time.UnixMilli(e.At), Kind: e.Kind, ID: e.ID, Name: e.Name,
			From: e.From, To: e.To, LatencyMs: e.LatencyMS})
	}
	return out
}

// telegramView is what GET /api/telegram returns: the settings without the token, the connection
// state, and the chats that asked to be let in.
type telegramView struct {
	Enabled   bool                  `json:"enabled"`
	HasToken  bool                  `json:"has_token"`
	APIBase   string                `json:"api_base"`
	Via       string                `json:"via"`
	Chats     []config.TelegramChat `json:"chats"`
	AlertsOff []string              `json:"alerts_off"`
	QuietFrom string                `json:"quiet_from"`
	QuietTo   string                `json:"quiet_to"`
	Digest    string                `json:"digest"`
	// Clock is the router's time and zone ("14:32", "+03"). Quiet hours and the digest follow the
	// router's clock, which need not be the browser's.
	Clock     string           `json:"clock"`
	Zone      string           `json:"zone"`
	Bot       tgbot.Info       `json:"bot"`
	Strangers []tgbot.Stranger `json:"strangers"`
	// ViaPaths is every connection and group the bot can be bound to, the same list the component
	// downloader offers: an exit an engine carries has no link to bind to and goes through the local
	// proxy instead. ViaIface is the link the saved choice resolves to right now, "" for the ordinary
	// path, the local proxy, or a choice that cannot carry the bot now (which then keeps it offline).
	ViaPaths []downloadPath `json:"via_paths"`
	ViaIface string         `json:"via_iface,omitempty"`
}

func (s *Server) handleTelegramGet(w http.ResponseWriter, r *http.Request) {
	t := s.Telegram()
	v := telegramView{
		Enabled: t.Enabled, HasToken: t.Token != "", APIBase: t.APIBase, Via: t.Via,
		Chats: t.Chats, AlertsOff: t.AlertsOff, QuietFrom: t.QuietFrom, QuietTo: t.QuietTo, Digest: t.Digest,
		Bot: s.telegram().Info(), Strangers: s.telegram().Gate().Strangers(),
	}
	now := time.Now().In(localtz.Location())
	v.Clock, v.Zone = now.Format("15:04"), localtz.Label(now)
	v.ViaPaths = s.downloadPathChoices()
	if v.ViaPaths == nil {
		v.ViaPaths = []downloadPath{}
	}
	if t.Via != "" && t.Via != viaLocalProxy {
		v.ViaIface = s.outboundIface(t.Via)
	}
	if v.Chats == nil {
		v.Chats = []config.TelegramChat{}
	}
	if v.AlertsOff == nil {
		v.AlertsOff = []string{}
	}
	writeJSONNoStore(w, http.StatusOK, v)
}

// telegramSettingsIn is the PUT body. Token: omitted, "" or the redaction mark keeps the saved one;
// ClearToken removes it.
type telegramSettingsIn struct {
	Enabled    bool     `json:"enabled"`
	Token      string   `json:"token"`
	ClearToken bool     `json:"clear_token"`
	APIBase    string   `json:"api_base"`
	Via        string   `json:"via"`
	AlertsOff  []string `json:"alerts_off"`
	QuietFrom  string   `json:"quiet_from"`
	QuietTo    string   `json:"quiet_to"`
	Digest     string   `json:"digest"`
}

func (in telegramSettingsIn) apply(t *config.Telegram) {
	t.Enabled = in.Enabled
	switch tok := strings.TrimSpace(in.Token); {
	case in.ClearToken:
		t.Token = ""
	case tok != "" && tok != config.RedactedMark:
		t.Token = tok
	}
	t.APIBase = strings.TrimSpace(in.APIBase)
	t.Via = strings.TrimSpace(in.Via)
	t.AlertsOff = in.AlertsOff
	t.QuietFrom, t.QuietTo = strings.TrimSpace(in.QuietFrom), strings.TrimSpace(in.QuietTo)
	t.Digest = strings.TrimSpace(in.Digest)
}

// errTokenFollowsServer refuses to send the saved token to a Bot API server it was not saved for.
// The token is write-only: the panel never shows it again. Without this, anyone at the panel could
// point api_base at a host of their own, press Check (or Save), and receive the token in the request
// path, which is the bot itself. Typing the token again proves it is theirs to send.
var errTokenFollowsServer = errors.New("to use a different Bot API server, enter the bot token again: it is sent to that server")

// tokenFollowsServer reports whether in may be applied over saved: a request that keeps the saved
// token must keep the server it was saved for.
func (in telegramSettingsIn) tokenFollowsServer(saved config.Telegram) error {
	tok := strings.TrimSpace(in.Token)
	keepsToken := !in.ClearToken && (tok == "" || tok == config.RedactedMark) && saved.Token != ""
	if keepsToken && apiServer(in.APIBase) != apiServer(saved.APIBase) {
		return errTokenFollowsServer
	}
	return nil
}

// apiServer is where a Bot API base points, "" and the public API's own address being the same.
func apiServer(base string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return tgbot.DefaultAPIBase
	}
	return base
}

func (s *Server) handleTelegramPut(w http.ResponseWriter, r *http.Request) {
	var in telegramSettingsIn
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if msg := s.checkTelegramVia(strings.TrimSpace(in.Via), s.Telegram().Via); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.UpdateTelegram(func(t *config.Telegram) error {
		if err := in.tokenFollowsServer(*t); err != nil {
			return err
		}
		in.apply(t)
		return nil
	}); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.telegram().Reload()
	s.handleTelegramGet(w, r)
}

// checkTelegramVia refuses a new path that cannot carry the bot: one that names nothing, a disabled
// connection, one an engine carries (VLESS, Trojan: no link to bind a socket to), a group with no
// member that has a link, or one whose members are all down right now. Each of those resolved to
// the ordinary path at dial time, so the bot went straight out while the panel showed a tunnel.
// The ordinary path and the local proxy are always accepted, and so is the saved choice unchanged:
// every save sends the whole settings, and the alert switches must stay savable while the chosen
// group is down. A saved choice that stops resolving keeps the bot offline (telegramClient).
func (s *Server) checkTelegramVia(via, saved string) string {
	if via == "" || via == viaLocalProxy || via == saved || s.store == nil {
		return ""
	}
	p := s.store.Profile()
	e, g := p.EndpointByID(via), p.GroupByID(via)
	if e == nil && g == nil {
		return "via: no connection or group with id " + strconv.Quote(via)
	}
	for _, c := range s.downloadPathChoices() {
		if c.ID != via {
			continue
		}
		if c.Iface == "" {
			return "via: no member of " + strconv.Quote(c.Name) + " is up right now, so it cannot carry the bot; choose it again once one is"
		}
		return ""
	}
	if e != nil && !e.Enabled {
		return "via: " + strconv.Quote(nameOrID(e.Name, e.ID)) + " is disabled, so it cannot carry the bot"
	}
	var msg string
	if e != nil {
		msg = "via: " + strconv.Quote(nameOrID(e.Name, e.ID)) + " has no network link of its own to bind the bot to"
	} else {
		msg = "via: no member of " + strconv.Quote(nameOrID(g.Name, g.ID)) + " has a network link of its own to bind the bot to"
	}
	if s.config().Ports.Mixed > 0 {
		msg += "; choose WayHop's local proxy, which follows your routing and can send the bot through it"
	}
	return msg
}

// handleTelegramCheck tries a token (the typed one, or the saved one) with getMe, through the path
// the body describes, without saving anything.
func (s *Server) handleTelegramCheck(w http.ResponseWriter, r *http.Request) {
	var in telegramSettingsIn
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	t := s.Telegram()
	if err := in.tokenFollowsServer(t); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if msg := s.checkTelegramVia(strings.TrimSpace(in.Via), t.Via); msg != "" {
		writeJSONNoStore(w, http.StatusOK, map[string]any{"ok": false, "error": msg})
		return
	}
	in.Enabled = true
	in.apply(&t)
	if t.Token == "" {
		writeErr(w, http.StatusBadRequest, "paste the token from @BotFather first")
		return
	}
	if err := t.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	me, err := s.telegram().Check(ctx, t)
	if err != nil {
		msg := err.Error()
		if tgbot.IsUnauthorized(err) {
			msg = "Telegram rejected this token. Copy it again from @BotFather (/mybots → API Token)."
		}
		writeJSONNoStore(w, http.StatusOK, map[string]any{"ok": false, "error": msg})
		return
	}
	writeJSONNoStore(w, http.StatusOK, map[string]any{"ok": true, "username": me.Username, "name": me.FirstName})
}

func (s *Server) handleTelegramPair(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Role string `json:"role"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	// With no token there is no bot to send the code to; the panel offered one anyway and said "send
	// /start CODE to your bot" on a router that had none (QA-034).
	if s.Telegram().Token == "" {
		writeErr(w, http.StatusConflict, "set up the bot token first: there is no bot to send a pairing code to")
		return
	}
	code, exp := s.telegram().Gate().NewCode(in.Role)
	link := s.telegram().DeepLink(code)
	out := map[string]any{
		"code": code, "expires_at": exp.UTC().Format(time.RFC3339), "ttl_s": int(tgbot.CodeTTL / time.Second),
		"link": link,
	}
	// The link as a QR code, for the usual case of the panel on a computer and Telegram on a phone:
	// the camera opens the bot with the code already in it.
	if link != "" {
		if q, err := qr.Encode(link); err == nil {
			out["qr_svg"] = q.SVG()
		}
	}
	writeJSONNoStore(w, http.StatusOK, out)
}

// handleTelegramTest sends a test message to every paired chat and reports each outcome.
func (s *Server) handleTelegramTest(w http.ResponseWriter, r *http.Request) {
	chats := s.Telegram().Chats
	if len(chats) == 0 {
		writeErr(w, http.StatusBadRequest, "no chat is paired yet")
		return
	}
	type result struct {
		ID    int64  `json:"id"`
		Name  string `json:"name"`
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}
	var out []result
	for _, c := range chats {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		lang := c.Lang
		if lang == "" {
			lang = tgbot.Languages[0]
		}
		err := s.telegram().Send(ctx, c.ID, tgbot.T(lang, "test.msg"))
		cancel()
		res := result{ID: c.ID, Name: c.Name, OK: err == nil}
		if err != nil {
			res.Error = err.Error()
		}
		out = append(out, res)
	}
	writeJSONNoStore(w, http.StatusOK, map[string]any{"results": out})
}

func chatIDParam(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id != 0
}

// handleTelegramChatPut changes a paired chat's role or language.
func (s *Server) handleTelegramChatPut(w http.ResponseWriter, r *http.Request) {
	id, ok := chatIDParam(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad chat id")
		return
	}
	var in struct {
		Role string `json:"role"`
		Lang string `json:"lang"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if in.Lang != "" && !slices.Contains(tgbot.Languages, in.Lang) {
		writeErr(w, http.StatusBadRequest, "the bot speaks "+strings.Join(tgbot.Languages, ", ")+"; "+strconv.Quote(in.Lang)+" is not one of them")
		return
	}
	found := false
	err := s.UpdateTelegram(func(t *config.Telegram) error {
		for i := range t.Chats {
			if t.Chats[i].ID != id {
				continue
			}
			found = true
			if in.Role != "" {
				if in.Role == config.TelegramOwner && id < 0 {
					return errors.New("a group or channel cannot be an owner: everyone in it could press the owner's buttons")
				}
				// A channel's subscribers can press the buttons on its posts without being in it, so a
				// viewer channel let anyone who can see it mute it, switch its alerts off and post the
				// device list into it (QA-102). Pairing forces a channel to alerts; this was the way back.
				if in.Role != config.TelegramAlerts && t.Chats[i].Type == "channel" {
					return errors.New("a channel can only receive alerts: anyone who can see it could press its buttons")
				}
				if in.Role == config.TelegramAlerts {
					menuGoes(t, t.Chats[i])
				}
				t.Chats[i].Role = in.Role
			}
			if in.Lang != "" {
				t.Chats[i].Lang = in.Lang
			}
		}
		return nil
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !found {
		writeErr(w, http.StatusNotFound, "no such chat")
		return
	}
	s.handleTelegramGet(w, r)
}

// menuGoes lists a chat that stops being an owner or a viewer in StaleMenus, so the bot takes back
// the command menu it gave the chat, now or when it next runs.
func menuGoes(t *config.Telegram, c config.TelegramChat) {
	if (c.Role == config.TelegramOwner || c.Role == config.TelegramViewer) && !slices.Contains(t.StaleMenus, c.ID) {
		t.StaleMenus = append(t.StaleMenus, c.ID)
	}
}

// handleTelegramChatDelete unpairs a chat. The chat is told, best effort, and its menu is taken back.
func (s *Server) handleTelegramChatDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := chatIDParam(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad chat id")
		return
	}
	var gone config.TelegramChat
	err := s.UpdateTelegram(func(t *config.Telegram) error {
		kept := t.Chats[:0]
		for _, c := range t.Chats {
			if c.ID == id {
				gone = c
				menuGoes(t, c)
				continue
			}
			kept = append(kept, c)
		}
		t.Chats = kept
		return nil
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if gone.ID == 0 {
		writeErr(w, http.StatusNotFound, "no such chat")
		return
	}
	lang := gone.Lang
	if lang == "" {
		lang = tgbot.Languages[0]
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	_ = s.telegram().Send(ctx, id, tgbot.T(lang, "unpaired"))
	cancel()
	s.handleTelegramGet(w, r)
}

// handleTelegramStrangerAllow pairs a chat that wrote to the bot, for when the code route is not
// convenient (the code expired, or it is a group where typing it is awkward).
func (s *Server) handleTelegramStrangerAllow(w http.ResponseWriter, r *http.Request) {
	id, ok := chatIDParam(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad chat id")
		return
	}
	var in struct {
		Role string `json:"role"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	var st tgbot.Stranger
	for _, x := range s.telegram().Gate().Strangers() {
		if x.ChatID == id {
			st = x
		}
	}
	if st.ChatID == 0 {
		writeErr(w, http.StatusNotFound, "that chat is no longer in the list; ask it to write to the bot again")
		return
	}
	role := in.Role
	switch {
	case role == "":
		// A chat nobody vouched for with a code does not get the owner's buttons by default; the
		// panel already asks for viewer, and the API must not be the way around that.
		role = config.TelegramViewer
	case role == config.TelegramOwner && st.Type != "private":
		writeErr(w, http.StatusBadRequest, "a group or channel cannot be an owner: everyone in it could press the owner's buttons")
		return
	}
	if st.Type == "channel" {
		role = config.TelegramAlerts
	}
	rec := config.TelegramChat{ID: id, Name: st.Name, Type: st.Type, Role: role, Lang: tgbot.LangFor(st.Lang), PairedAt: time.Now().Unix()}
	err := s.UpdateTelegram(func(t *config.Telegram) error {
		for _, c := range t.Chats {
			if c.ID == id {
				return nil
			}
		}
		t.Chats = append(t.Chats, rec)
		return nil
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.telegram().Gate().Forget(id)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	_ = s.telegram().Welcome(ctx, rec)
	cancel()
	s.handleTelegramGet(w, r)
}

func (s *Server) handleTelegramStrangerDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := chatIDParam(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad chat id")
		return
	}
	s.telegram().Gate().Forget(id)
	s.handleTelegramGet(w, r)
}

// Pulse is the cheap part of the state the alert watcher reads every few seconds: RAM, free space,
// no network, no profile compile.
func (b tgBackend) Pulse(ctx context.Context) tgbot.Pulse {
	s := b.s
	var p tgbot.Pulse
	p.RoutingOff = s.routingIsOff()
	if s.monitor != nil && !p.RoutingOff {
		p.LocalFault = s.monitor.LocalFault()
	}
	wd := s.supervisionStats()
	p.Core = tgbot.CorePulse{Supervised: wd.Supervised, Alive: wd.Alive, Restarts: wd.Restarts, Failed: wd.Failed, LastError: wd.LastError}
	if s.failsafe != nil {
		fs := s.failsafe.Status()
		p.FailSafe = tgbot.FailSafePulse{Pending: fs.Pending, Phase: fs.Phase, SecondsLeft: fs.SecondsLeft, LastError: fs.LastError,
			Checked: fs.LastCheckAt > 0, CheckOK: fs.LastCheckOk}
	}
	live := s.liveRevision()
	p.FailSafe.Live, p.FailSafe.Window = live != nil, applyWindow(live)
	// Keep makes the live revision the committed one as it is, so a kept Test keeps its window's name
	// there: the watcher tells a Keep from a newer Test replacing it when both fall inside one pulse.
	p.FailSafe.Committed = applyWindow(s.committedRevision())
	// The failed rollback the record is waiting on. The window's phase says it only for the window's
	// own rollback: a Roll back after the window closed and boot's rollback set nothing the bot read,
	// so it stayed silent and its earlier message kept offering a Keep the daemon refuses.
	if mark := s.liveRollbackFailed(); mark != nil {
		p.FailSafe.RollbackOutstanding, p.FailSafe.RollbackError = true, mark.Error
	}
	if s.config().Demo {
		p.Mem = tgbot.MemPulse{Known: true, UsedPct: demoSystemInfo(time.Now()).MemUsedPct}
	} else if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		if total, avail := parseMeminfo(string(raw)); total > 0 {
			p.Mem = tgbot.MemPulse{Known: true, UsedPct: float64(total-avail) / float64(total) * 100}
		}
	}
	// One statfs of the filesystem the Diagnostics battery's storage check reads; never in the demo,
	// whose disk is a development machine's.
	if !s.config().Demo {
		if free, ok := updater.AvailBytes(selfDir()); ok {
			p.Disk = tgbot.DiskPulse{Known: true, FreeBytes: free}
		}
	}
	return p
}

// selfDir is the directory of the running binary, read once: the filesystem whose free space the
// storage alert watches, as diskSpaceCheck does.
var selfDir = sync.OnceValue(func() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	return "/"
})

// applyWindow names a test Apply for the bot's Keep and Roll back buttons: the revision it applied
// and when, hashed short, so a button names the one test it was offered for and fits Telegram's
// 64-byte callback data. "" when nothing runs unsaved.
func applyWindow(live *appliedRevision) string {
	if live == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(live.Rev + "@" + strconv.FormatInt(live.At, 10)))
	return hex.EncodeToString(sum[:5])
}

// Boot describes this daemon start for the "back online" alert.
func (b tgBackend) Boot() tgbot.BootInfo {
	s := b.s
	s.tgBootOnce.Do(func() { s.tgBoot = s.readBootInfo() })
	return s.tgBoot
}

// readBootInfo reads the router's uptime and the previous heartbeat once, before the first new
// heartbeat overwrites it.
func (s *Server) readBootInfo() tgbot.BootInfo {
	bi := tgbot.BootInfo{DaemonStart: s.startedAt, Version: version.Version}
	// An update the supervisor rolled back (or failed) just before this start is the reason for it.
	if etc := s.updateDir(); etc != "" {
		if r, ok := updatetx.ReadResult(etc); ok && (r.Result == "rolled_back" || r.Result == "failed") &&
			s.startedAt.Sub(time.Unix(r.At, 0)) < 15*time.Minute && s.startedAt.Sub(time.Unix(r.At, 0)) > -15*time.Minute {
			bi.UpdateNote = r.Note(s.startedAt.In(s.updateZone()))
		}
	}
	if raw, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(raw)); len(f) > 0 {
			if up, err := strconv.ParseFloat(f[0], 64); err == nil {
				// Uptime now, minus how long the daemon has been running, is the uptime at its start.
				bi.RouterUp = time.Duration(up*float64(time.Second)) - time.Since(s.startedAt)
				if bi.RouterUp < 0 {
					bi.RouterUp = 0
				}
			}
		}
	}
	if raw, err := os.ReadFile(s.heartbeatPath()); err == nil {
		if sec, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err == nil && sec > 0 {
			bi.LastSeen = time.Unix(sec, 0)
		}
	}
	return bi
}

// heartbeatEvery is how often a running bot records that the router is alive. The record is how the
// "back online" alert knows how long the router was gone; ten minutes is the resolution of that
// answer, and at most 144 small writes a day, only while the bot is enabled.
const heartbeatEvery = 10 * time.Minute

func (s *Server) heartbeatPath() string {
	return filepath.Join(s.config().DataDir, "telegram-heartbeat")
}

// heartbeatLoop writes the heartbeat while the bot is enabled. Never in demo mode: the demo runs on a
// development machine, whose data directory is not a router's.
func (s *Server) heartbeatLoop(ctx context.Context) {
	tgBackend{s}.Boot() // read the previous heartbeat before the first write replaces it
	t := time.NewTicker(heartbeatEvery)
	defer t.Stop()
	for {
		if c := s.config(); !c.Demo && c.Telegram.Enabled && c.DataDir != "" {
			if err := os.MkdirAll(c.DataDir, 0o755); err == nil {
				_ = atomicfile.Write(s.heartbeatPath(), []byte(strconv.FormatInt(time.Now().Unix(), 10)+"\n"), 0o644)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ClaimDigest records the day of the last daily digest in a file beside the heartbeat: one short
// write a day. The demo, which must not write beside a real install's files, keeps it in memory.
// A write that fails still lets the digest go: a rare duplicate beats a lost summary.
func (b tgBackend) ClaimDigest(day string) bool {
	s := b.s
	s.tgDigestMu.Lock()
	defer s.tgDigestMu.Unlock()
	c := s.config()
	if c.Demo || c.DataDir == "" {
		if s.tgDigestDay == day {
			return false
		}
		s.tgDigestDay = day
		return true
	}
	path := filepath.Join(c.DataDir, "telegram-digest")
	if raw, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(raw)) == day {
		return false
	}
	if err := os.MkdirAll(c.DataDir, 0o755); err == nil {
		_ = atomicfile.Write(path, []byte(day+"\n"), 0o644)
	}
	return true
}

// ConfirmApply keeps the test Apply named window (applyWindow), and nothing else: a newer Test that
// replaced it while the press waited for applyMu is refused as tgbot.ErrWindowChanged.
func (b tgBackend) ConfirmApply(ctx context.Context, window string) error {
	code, resp := b.s.applyConfirm(ctx, window)
	if code != http.StatusOK {
		return applyRespErr(resp)
	}
	return nil
}

// RollbackApply rolls back the test Apply named window, as ConfirmApply keeps it.
func (b tgBackend) RollbackApply(ctx context.Context, window string) error {
	code, resp := b.s.applyRollback(ctx, window)
	if code != http.StatusOK {
		return applyRespErr(resp)
	}
	if done, _ := resp["rolled_back"].(bool); !done {
		return applyRespErr(resp)
	}
	return nil
}

// applyRespErr turns the panel's error body into one sentence.
func applyRespErr(resp map[string]any) error {
	if resp["code"] == applyCodeWindowChanged {
		return tgbot.ErrWindowChanged
	}
	for _, k := range []string{"error", "message"} {
		if msg, _ := resp[k].(string); msg != "" {
			if d, _ := resp["detail"].(string); d != "" {
				msg += ": " + d
			}
			return errors.New(msg)
		}
	}
	return errors.New("the router refused the request")
}

// Trace is the Diagnostics page's per-domain trace, with list and rule ids turned into names.
func (b tgBackend) Trace(ctx context.Context, target string) (tgbot.Trace, error) {
	if !validTraceDomain(target) {
		return tgbot.Trace{}, tgbot.ErrBadTarget
	}
	res := b.s.traceDomain(ctx, target)
	names := map[string]string{}
	if b.s.store != nil {
		p := b.s.store.Profile()
		for _, rl := range p.RoutingLists {
			if rl.Name != "" {
				names["list:"+rl.ID] = rl.Name
			}
		}
	}
	conv := func(in []traceCandidate) []tgbot.TraceMatch {
		var out []tgbot.TraceMatch
		for _, c := range in {
			out = append(out, tgbot.TraceMatch{Kind: c.Kind, ID: c.ID, Name: names[c.Kind+":"+c.ID], Why: c.Why, Via: c.Outbound})
		}
		return out
	}
	return tgbot.Trace{
		Target: res.Domain, IPs: res.IPs, ResolveError: res.ResolveError, Live: res.Exits,
		Configured: conv(res.Configured), Maybe: conv(res.Unevaluated), Note: res.Note,
	}, nil
}

// Devices is the device picker's list, each device with the device group it belongs to.
func (b tgBackend) Devices(ctx context.Context) tgbot.DeviceList {
	devs := lanDevices()
	demo := len(devs) == 0 && b.s.config().Demo
	if demo {
		// The demo runs on a development machine with no leases and no router ARP table. A few
		// documented-looking LAN clients keep the view whole in the walkthrough; never on a router.
		devs = []deviceInfo{
			{IP: "192.168.1.23", MAC: "00:00:5e:00:53:23", Hostname: "Sam-phone"},
			{IP: "192.168.1.40", MAC: "00:00:5e:00:53:40", Hostname: "Living-room-TV"},
			{IP: "192.168.1.55", MAC: "00:00:5e:00:53:55"},
		}
	}
	var groups []model.DeviceGroup
	if b.s.store != nil {
		groups = b.s.store.Profile().DeviceGroups
	}
	var flows flowRates
	var measured bool
	if demo {
		// The third sample device sits on the fast path, so the walkthrough shows how that reads.
		flows, measured = flowRates{rate: demoDeviceRates(time.Now()), fast: map[string]bool{"192.168.1.55": true}}, true
	} else {
		flows, measured = deviceRates(ctx, func() (string, error) {
			raw, err := os.ReadFile("/proc/net/nf_conntrack")
			return string(raw), err
		}, deviceSample)
	}
	return tgbot.DeviceList{Measured: measured, Devices: deviceTraffic(devs, groups, flows, ipv6Neighbours())}
}

// deviceTraffic credits each device with what its addresses moved: its IPv4 one, and the IPv6 ones
// the neighbour table (address -> MAC) ties to its MAC, since the leases and the ARP table never
// see a device's IPv6 addresses.
func deviceTraffic(devs []deviceInfo, groups []model.DeviceGroup, flows flowRates, neigh map[string]string) []tgbot.Device {
	v6 := map[string][]string{}
	for ip, mac := range neigh {
		v6[strings.ToLower(mac)] = append(v6[strings.ToLower(mac)], ip)
	}
	out := make([]tgbot.Device, 0, len(devs))
	for _, d := range devs {
		dev := tgbot.Device{Name: d.Hostname, IP: d.IP, MAC: d.MAC, Group: deviceGroupOf(groups, d)}
		for _, addr := range append([]string{canonIP(d.IP)}, v6[strings.ToLower(d.MAC)]...) {
			r, in := flows.rate[addr], flows.incoming[addr]
			dev.Down += r[0] + in[0]
			dev.Up += r[1] + in[1]
			dev.FastPath = dev.FastPath || flows.fast[addr]
		}
		out = append(out, dev)
	}
	return out
}

// deviceSample is how long the connection table is watched to tell who is using the line now.
const deviceSample = 1500 * time.Millisecond

// flowRates is what two reads of the connection table say about each source address, keyed by the
// address in its canonical form (the table prints IPv6 unabbreviated).
type flowRates struct {
	rate map[string][2]int64 // bytes per second over the gap, down then up
	// incoming is the same for connections forwarded in from outside, by the LAN host they reach.
	incoming map[string][2]int64
	// fast marks sources with flows on a flowtable fast path while no fast-path flow's counters
	// moved: the flowtable does not count, so what those flows carry is unknown, not nothing.
	fast map[string]bool
}

// deviceRates reads the connection table twice, gap apart, and returns each LAN client's bytes per
// second over the gap, down then up. The counters live on the flows, so the difference is taken per
// flow: one that closed in between is gone from the second read and counts nothing, one that
// opened in between counts whole, being all inside the gap. (Summed per client first, a closed
// flow's bytes hid a new flow's, and a busy phone read as idle.) ok is false where there is no
// table, or where it counts no bytes at all (nf_conntrack_acct off): a list of idle devices would
// then be a false answer, and none is better.
//
// Offloaded flows ([OFFLOAD], [HW_OFFLOAD]) keep counting only when their flowtable was made with
// counters, which WayHop's own is not. If any of them moved, the counters are live and every number
// stands; if none did, the sources that have them are marked fast rather than called idle.
func deviceRates(ctx context.Context, read func() (string, error), gap time.Duration) (flowRates, bool) {
	type flowKey struct {
		proto, src, dst string
		sport, dport    int
	}
	sample := func() (map[flowKey]Conn, int64, bool) {
		raw, err := read()
		if err != nil {
			return nil, 0, false
		}
		out := map[flowKey]Conn{}
		total := int64(0)
		parseConntrackInto(raw, func(c Conn) {
			total += c.UpBytes + c.DownBytes
			out[flowKey{c.Proto, c.Src, c.Dst, c.Sport, c.Dport}] = c
		})
		return out, total, true
	}
	first, total, ok := sample()
	if !ok || (len(first) > 0 && total == 0) {
		return flowRates{}, false
	}
	select {
	case <-ctx.Done():
		return flowRates{}, false
	case <-time.After(gap):
	}
	second, _, ok := sample()
	if !ok {
		return flowRates{}, false
	}
	moved := map[string][2]int64{}
	offloaded := map[string]bool{}
	offloadMoved := false
	incoming := map[string][2]int64{}
	for k, now := range second {
		was, seen := first[k]
		d, u := max(now.DownBytes-was.DownBytes, 0), max(now.UpBytes-was.UpBytes, 0)
		src := canonIP(now.Src)
		v := moved[src]
		v[0] += d
		v[1] += u
		moved[src] = v
		// A connection that came in from outside (a port forward, a peer reaching a torrent client
		// over IPv6 with no NAT at all) has the far side as its source; the LAN host it reached is
		// its reply source, and receives what the original direction carries. On an ordinary
		// outgoing flow the reply source is the far side itself, and on one the engine redirected
		// it is the router's own address: no device has either, so crediting them changes nothing.
		if now.ReplySrc != "" {
			r := canonIP(now.ReplySrc)
			w := incoming[r]
			w[0] += u
			w[1] += d
			incoming[r] = w
		}
		if now.Offloaded {
			offloaded[src] = true
			if now.ReplySrc != "" {
				offloaded[canonIP(now.ReplySrc)] = true
			}
			// Only a flow on the fast path in both reads says whether the flowtable counts: one
			// offloaded in the gap moved while it still went through the slow path.
			if seen && was.Offloaded && (d > 0 || u > 0) {
				offloadMoved = true
			}
		}
	}
	perSecond := func(m map[string][2]int64) map[string][2]int64 {
		out := make(map[string][2]int64, len(m))
		for ip, v := range m {
			out[ip] = [2]int64{int64(float64(v[0]) / gap.Seconds()), int64(float64(v[1]) / gap.Seconds())}
		}
		return out
	}
	out := flowRates{rate: perSecond(moved), incoming: perSecond(incoming)}
	if !offloadMoved && len(offloaded) > 0 {
		out.fast = offloaded
	}
	return out, true
}

// canonIP is an address in the form Go prints it, so an unabbreviated IPv6 source from the table
// and the abbreviated one from the neighbour table meet.
func canonIP(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

// demoDeviceRates gives the demo's sample devices something to be doing: a TV streaming, a phone
// browsing, the third idle, all drifting with the clock like the demo's other live numbers.
func demoDeviceRates(now time.Time) map[string][2]int64 {
	s := float64(now.Unix()%60) / 60
	return map[string][2]int64{
		"192.168.1.40": {int64(1_400_000 + 300_000*s), int64(40_000 + 10_000*s)},
		"192.168.1.23": {int64(90_000 + 60_000*s), int64(15_000 + 5_000*s)},
	}
}

// deviceGroupOf names the first device group whose members match d by MAC or by IP (or CIDR).
func deviceGroupOf(groups []model.DeviceGroup, d deviceInfo) string {
	ip := net.ParseIP(d.IP)
	for _, g := range groups {
		for _, m := range g.Members {
			if m.MAC != "" && strings.EqualFold(m.MAC, d.MAC) {
				return g.Name
			}
			if m.IP == "" || ip == nil {
				continue
			}
			if _, n, err := net.ParseCIDR(m.IP); err == nil {
				if n.Contains(ip) {
					return g.Name
				}
			} else if other := net.ParseIP(m.IP); other != nil && other.Equal(ip) {
				return g.Name
			}
		}
	}
	return ""
}

// Diagnose runs the Diagnostics battery.
func (b tgBackend) Diagnose(ctx context.Context) []tgbot.Check {
	rows := b.s.healthBattery(ctx)
	out := make([]tgbot.Check, 0, len(rows))
	for _, r := range rows {
		out = append(out, tgbot.Check{ID: r.ID, Label: r.Label, Status: r.Status, Summary: r.Summary, Fix: r.Fix})
	}
	return out
}

func (b tgBackend) Ping(ctx context.Context, host string) (tgbot.PingResult, error) {
	if !netdiag.ValidTarget(host) {
		return tgbot.PingResult{}, tgbot.ErrBadTarget
	}
	p := netdiag.Ping(ctx, host, 3)
	return tgbot.PingResult{Target: host, Ran: p.Ran, OK: p.Ok, LossPct: p.LossPct, AvgMs: p.AvgMs}, nil
}

func (b tgBackend) Lookup(ctx context.Context, host string) (tgbot.LookupResult, error) {
	if !netdiag.ValidTarget(host) {
		return tgbot.LookupResult{}, tgbot.ErrBadTarget
	}
	l := netdiag.DNSLookup(ctx, host)
	return tgbot.LookupResult{Target: host, IPs: l.IPs, CNAME: l.CNAME, Err: l.Err}, nil
}

// speedBudget bounds each transfer of the bot's tests (see speedtest.Tester.Budget), so both legs
// fit the minute the question promises even on a slow line.
const speedBudget = 8 * time.Second

// SpeedTest measures the provider's line, then the default route through WayHop or one exit's own
// tunnel, holding the router's one speed-test slot for both legs so a panel test cannot land in
// between. The line leg says which interface it left by from its connections' own source address,
// which the kernel chose with the route and nobody's traffic moves: a line whose route is a tunnel
// is reported as that tunnel. A tunnel's leg is bound to it and marked past the engine's redirect,
// both required, so it cannot leave any other way.
func (b tgBackend) SpeedTest(ctx context.Context, exit string, step func(leg string)) (tgbot.SpeedReport, error) {
	s := b.s
	var rep tgbot.SpeedReport
	var p model.Profile
	if s.store != nil {
		p = s.store.Profile()
	}
	native, known := s.currentNativeInterfaceBindings()
	link := ""
	if exit != "" {
		e := p.EndpointByID(exit)
		if e == nil {
			return rep, tgbot.ErrUnavailable
		}
		if link = tunnelLink(*e, native, known); link == "" {
			return rep, tgbot.ErrUnavailable
		}
		rep.Exit = exitName(e)
		if !s.config().Demo && ifaceDial(link) == nil {
			return rep, tgbot.ErrUnavailable
		}
	}
	if !s.speedMu.TryLock() {
		return tgbot.SpeedReport{}, tgbot.ErrBusy
	}
	defer s.speedMu.Unlock()

	if exit == "" {
		// The route leg measures what the test's own site gets, which is the default route only
		// when no rule names it; a split-tunnel profile sends it straight out, and measuring that
		// would pass the line off as the tunnel.
		route, named := s.speedRoute(ctx, &p)
		rep.ByRule = named
		switch {
		case route == "" || strings.EqualFold(route, model.OutboundDirect):
			rep.Direct = true
		case strings.EqualFold(route, model.OutboundBlock):
			rep.Blocked = true
		default:
			rep.Via = b.routeLabel(ctx, &p, route)
			if e := p.EndpointByID(route); e != nil {
				// A route that is one kernel tunnel is measured bound to it, core or no core.
				link = tunnelLink(*e, native, known)
			}
		}
	}
	if s.config().Demo {
		return demoSpeed(ctx, step, time.Now(), rep)
	}

	tunnels := map[string]bool{}
	for _, e := range p.Endpoints {
		if l := tunnelLink(e, native, known); l != "" {
			tunnels[l] = true
		}
	}
	step(tgbot.LegLine)
	var local dialLog
	line := speedtest.New(0)
	line.Direct, line.Budget = local.wrap(lineDial, lineRoute), speedBudget
	// Measured or not, a line leg that left by a tunnel is that tunnel's: a failure there is the
	// tunnel's to answer for, not the provider's.
	rep.Line = speedLeg(line.Run(ctx, false, speedBytes))
	rep.Line.Through = local.tunnelLeft(tunnels)
	switch {
	case rep.Direct || rep.Blocked:
		rep.Route.Skipped = true
	case link != "" && ifaceDial(link) != nil:
		step(tgbot.LegRoute)
		bound := speedtest.New(0)
		bound.Direct, bound.Budget = ifaceDial(link), speedBudget
		rep.Route = speedLeg(bound.Run(ctx, false, speedBytes))
	case !s.coreUp():
		rep.Route.Skipped = true
		rep.Native = s.store != nil && s.nativeOnlyCached()
	default:
		step(tgbot.LegRoute)
		through := speedtest.New(s.config().Ports.Mixed)
		through.Budget = speedBudget
		rep.Route = speedLeg(through.Run(ctx, true, speedBytes))
	}
	return rep, nil
}

// speedLeg is one run of the tester as the bot reports it.
func speedLeg(r speedtest.Result, err error) tgbot.SpeedLeg {
	if err != nil {
		return tgbot.SpeedLeg{Err: err.Error(), NoAnswer: errors.Is(err, speedtest.ErrNoAnswer), LatencyMs: -1}
	}
	return tgbot.SpeedLeg{DownMbps: r.DownMbps, UpMbps: r.UpMbps, UpMissed: r.UpErr != "", LatencyMs: r.LatencyMs}
}

// routeLabel names an outbound for people: an endpoint by its name, a group by its name and, where
// the core or the monitor knows it, the member it is on now ("Auto (fastest) → nl-main").
func (b tgBackend) routeLabel(ctx context.Context, p *model.Profile, tag string) string {
	if e := p.EndpointByID(tag); e != nil {
		return exitName(e)
	}
	for _, g := range b.groups(ctx) {
		if g.ID != tag {
			continue
		}
		if e := p.EndpointByID(g.Elected); e != nil {
			return g.Name + " → " + exitName(e)
		}
		return g.Name
	}
	return tag
}

// demoExitIP is the demo's exit. The demo has no real one; a documentation address (RFC 5737)
// keeps the views whole without pretending to be anybody's.
var demoExitIP = tgbot.ExitIP{Known: true, IP: "203.0.113.7", Country: "Netherlands", Code: "NL", City: "Amsterdam"}

// demoSpeedLeg is how long each demo leg pretends to measure.
var demoSpeedLeg = 1500 * time.Millisecond

// demoSpeed stands in for a measurement on the demo, which has no line of its own to spend: each
// leg takes a moment, and the numbers drift with the clock like the demo's other live values. The
// route is the one the demo's rules give (rep carries it); a kernel tunnel measured on its own comes
// out faster than a route through the core, as one often does.
func demoSpeed(ctx context.Context, step func(string), now time.Time, rep tgbot.SpeedReport) (tgbot.SpeedReport, error) {
	legs := []string{tgbot.LegLine}
	if !rep.Direct && !rep.Blocked {
		legs = append(legs, tgbot.LegRoute)
	}
	for _, leg := range legs {
		step(leg)
		select {
		case <-ctx.Done():
			return tgbot.SpeedReport{}, ctx.Err()
		case <-time.After(demoSpeedLeg):
		}
	}
	f := float64(now.Unix()%60) / 60
	rep.Line = tgbot.SpeedLeg{DownMbps: 94 + 4*f, UpMbps: 38 + 2*f, LatencyMs: 11}
	switch {
	case len(legs) == 1:
		rep.Route.Skipped = true
	case rep.Exit != "":
		rep.Route = tgbot.SpeedLeg{DownMbps: 78 + 5*f, UpMbps: 33 + 2*f, LatencyMs: 44}
	default:
		rep.Route = tgbot.SpeedLeg{DownMbps: 41 + 6*f, UpMbps: 19 + 2*f, LatencyMs: 57}
	}
	return rep, nil
}

// RestartDaemon restarts the service the way Settings → Service does.
func (b tgBackend) RestartDaemon(ctx context.Context) error {
	cmd := restartCommand()
	if cmd == nil || b.s.config().Demo {
		return tgbot.ErrUnavailable
	}
	return cmd.Start()
}

// SetRouting is the panel's routing switch (routingswitch.go), recorded as switched from Telegram.
// The demo flips the switch and touches nothing, exactly as the panel's does.
func (b tgBackend) SetRouting(ctx context.Context, on bool) error {
	if _, err := b.s.setRouting(ctx, on, routingByTelegram); err != nil {
		return applyRespErr(err.body())
	}
	return nil
}

// RefreshLists is the Routing page's "Refresh sources", counted per list.
func (b tgBackend) RefreshLists(ctx context.Context) (tgbot.ListsRefresh, error) {
	s := b.s
	if s.store == nil {
		return tgbot.ListsRefresh{}, errors.New("no profile")
	}
	before, start := listCaches(s.store.Profile().RoutingLists), time.Now()
	_, errs := s.refreshAll(ctx)
	after := listCaches(s.store.Profile().RoutingLists)
	var out tgbot.ListsRefresh
	for id, cache := range after {
		out.Lists++
		if before[id] != cache {
			out.Changed++
		}
	}
	for _, e := range errs {
		if errors.Is(e, errFeedNotTried) {
			out.Unreached++
		}
	}
	// The record of what failed just now names each list and keeps the feed's credentials out of the
	// chat, which the raw errors did not.
	out.Failed = b.feedIssuesSince(start)
	return out, nil
}

// listCaches fingerprints the cached content of every list refreshAll refreshes: enabled, with an
// address feed, a name feed, or both. Counting address feeds alone told a router whose lists are
// all name feeds that nothing had a source, right after refreshing them all.
func listCaches(lists []model.RoutingList) map[string]string {
	out := map[string]string{}
	for _, rl := range lists {
		if (rl.CIDRSource == "" && rl.DomainSource == "") || !rl.Enabled {
			continue
		}
		out[rl.ID] = strings.Join(rl.CIDRCache, ",") + "\x00" + strings.Join(rl.DomainCache, ",")
	}
	return out
}

// RefreshSubscription is Settings' "Refresh now" for the imported subscription.
func (b tgBackend) RefreshSubscription(ctx context.Context) (int, error) {
	// With nothing stored the refresh is a silent no-op; the chat asked for a refresh, so it hears
	// that there is nothing to refresh rather than "0 new connections".
	if b.s.config().Subscription.URL == "" {
		return 0, errors.New("no subscription is imported")
	}
	added, err := b.s.refreshSubscriptionOnce(ctx)
	if err != nil {
		return 0, errors.New(redactSubscriptionError(err.Error()))
	}
	return added, nil
}

// ApplyPreview is Review & Apply's review.
func (b tgBackend) ApplyPreview(ctx context.Context) (tgbot.ApplyPreview, error) {
	plan, err := b.s.buildPlan(ctx, false)
	if err != nil {
		return tgbot.ApplyPreview{}, err
	}
	p := tgbot.ApplyPreview{Pending: plan.Pending, Rev: plan.Rev, Count: plan.Changes.Count, MayInterrupt: plan.Changes.MayInterrupt}
	for _, f := range plan.blockers() {
		p.Blockers = append(p.Blockers, f.Title)
	}
	for _, f := range plan.unacked() {
		p.Confirms = append(p.Confirms, f.Title)
	}
	return p, nil
}

// ApplyTest is "Test safely" for exactly the reviewed revision: the findings that review listed as
// needing a confirmation are acknowledged, nothing else. A revision that moved on since the review
// is refused by the Apply pipeline itself.
func (b tgBackend) ApplyTest(ctx context.Context, rev string) error {
	plan, err := b.s.buildPlan(ctx, false)
	if err != nil {
		return err
	}
	var acks []string
	for _, f := range plan.unacked() {
		acks = append(acks, f.ID)
	}
	if _, aerr := b.s.runApply(ctx, applyRequest{Save: false, Rev: rev, Ack: acks}); aerr != nil {
		msg := aerr.Message
		if aerr.Remedy != "" {
			msg += ". " + aerr.Remedy
		}
		return errors.New(msg)
	}
	return nil
}

// Backup is the full backup the panel downloads.
func (b tgBackend) Backup(ctx context.Context) (string, []byte, error) {
	data, err := json.MarshalIndent(b.s.buildBackupBundle(), "", "  ")
	if err != nil {
		return "", nil, err
	}
	return backupName(time.Now(), localtz.Location()), data, nil
}

// backupName names the bot's backup by the router's own clock, the one the caption beside it gives:
// Go alone reads UTC on KeeneticOS and on OpenWrt without zoneinfo, and a file named three hours off
// its caption reads as another backup.
func backupName(t time.Time, loc *time.Location) string {
	return "wayhop-backup-" + t.In(loc).Format("20060102-1504") + ".json"
}

// UpdateCheck is the Components page's self row, as the bot reads it.
func (b tgBackend) UpdateCheck(ctx context.Context) tgbot.UpdateInfo {
	out := b.s.selfStatus(ctx)
	str := func(k string) string { v, _ := out[k].(string); return v }
	flag := func(k string) bool { v, _ := out[k].(bool); return v }
	info := tgbot.UpdateInfo{
		// Latest is the release tag exactly as published: it is what the install asks for.
		Current: str("current"), Latest: str("latest"),
		Available: flag("update_available"), Decided: flag("version_comparable"),
		NoChannel: flag("no_channel"), Auto: flag("auto_update"), Note: str("last_update_note"),
	}
	if flag("native_managed") {
		info.Managed = str("package_manager")
		if info.Managed == "" {
			info.Managed = "the package manager"
		}
	}
	if !info.NoChannel {
		if e := str("error_summary"); e != "" {
			info.Err = e
		} else if e := str("error"); e != "" {
			info.Err = e
		}
	}
	return info
}

// UpdateInstall is the Components page's "Update WayHop".
func (b tgBackend) UpdateInstall(ctx context.Context, version string) (tgbot.UpdateResult, error) {
	code, out := b.s.selfInstall(ctx, version)
	if code != http.StatusOK {
		msg, _ := out["error"].(string)
		if msg == "" {
			msg = http.StatusText(code)
		}
		return tgbot.UpdateResult{}, errors.New(msg)
	}
	res := tgbot.UpdateResult{}
	res.Installed, _ = out["installed"].(string)
	res.Restarting, _ = out["restarting"].(bool)
	res.Note, _ = out["note"].(string)
	return res, nil
}
