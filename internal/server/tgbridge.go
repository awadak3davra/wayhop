package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/platform"
	"wayhop/internal/plugin"
	"wayhop/internal/qr"
	"wayhop/internal/tgbridge"
)

// tgbridge.go runs the Telegram bridge (competitor gap 13, internal/tgbridge) as a router service:
// started with the daemon when it is enabled and its binary is installed, restarted with backoff by
// the plugin supervisor when it exits, stopped when it is disabled.
//
// A save takes effect at once, not through Apply. Apply exists for the routing plane, where a bad
// change can cut the operator off and the fail-safe window has to be able to roll it back. The bridge
// routes nothing: it is a listener on the LAN address plus the router's own outbound connections, the
// panel stays reachable whatever it does, and there is nothing for a rollback to restore. Holding it
// behind a review would only tie fixing Telegram to whatever else is pending in the routing plan.

// tgBridgeService is the bridge's name in the plugin manager.
const tgBridgeService = "telegram-bridge"

// tgBridgeEngineID is the bridge's Components entry (updater.Engines).
const tgBridgeEngineID = "tg-ws-proxy"

// tgBridgeResync is how often the daemon re-reads the LAN address and re-checks the binary while the
// bridge is enabled. The LAN bridge may get its address after the daemon starts (netifd on OpenWrt
// brings lan up on its own schedule), the operator may renumber the LAN or install the binary over
// SSH; each converges here without a save or a restart. Unchanged, it costs one interface read.
const tgBridgeResync = 30 * time.Second

// tgBridgeCrashExits and tgBridgeCrashWindow make the review's "keeps exiting" finding: three exits,
// the last within a quarter of an hour. The supervisor's own backoff counter resets once a process
// survives a tick, so a bridge that dies after ten seconds every time would never read as looping by it.
const (
	tgBridgeCrashExits  = 3
	tgBridgeCrashWindow = 15 * time.Minute
)

// tgBridgeCrashLoop is that rule, the one place it is decided: the review's finding and the API's
// crash_loop (the panel's pill) both read it, so the two never disagree about one process. A bridge
// in the loop is alive between restarts, so "running" alone would read it as healthy.
func tgBridgeCrashLoop(exits int, lastExit, now time.Time) bool {
	return exits >= tgBridgeCrashExits && now.Sub(lastExit) < tgBridgeCrashWindow
}

// tgBridgeState is what the last sync decided, for the API and the review.
type tgBridgeState struct {
	mu sync.Mutex
	// refused says why the daemon did not start an enabled bridge ("" when it did): no LAN address,
	// a public one, a config it cannot run, the demo.
	refused string
	listen  netip.Addr
	iface   string
	public  bool // the LAN bridge holds a public address: refused, see tgbridge.Public
	uplink  bool // the LAN bridge carries a default route: started, and said in the review
}

// StartTelegramBridge runs the bridge per the saved settings until ctx ends, and returns a channel
// closed once its loop has stopped. The daemon's shutdown waits for that before it stops the bridge
// with the other plugin processes (Plugins().StopAll), so the loop's last sync lands before StopAll
// rather than racing it; a sync from anywhere after StopAll starts nothing (RunService).
//
// Before anything syncs, a bridge an earlier daemon left running is ended (plugin.ReapStrays):
// enabled or not, since a disabled bridge is the case where nothing else would end it. This runs
// before the function returns, so before the daemon serves the panel and a save can sync.
func (s *Server) StartTelegramBridge(ctx context.Context) <-chan struct{} {
	s.reapTelegramBridge()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.syncTelegramBridge()
		t := time.NewTicker(tgBridgeResync)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				// select picks among ready cases at random: a tick that lands with the shutdown
				// must not sync.
				if ctx.Err() == nil && s.config().TelegramBridge.Enabled {
					s.syncTelegramBridge()
				}
			}
		}
	}()
	return done
}

// reapTelegramBridge ends tg-ws-proxy processes running as the bridge's uid that this daemon did not
// start. The demo runs no bridge and leaves the host's processes alone.
func (s *Server) reapTelegramBridge() {
	if s.tgBridgeReapOf != nil {
		s.tgBridgeReapOf()
		return
	}
	if s.plugins == nil || s.config().Demo {
		return
	}
	s.plugins.ReapStrays(tgbridge.BinName, tgbridge.UID)
}

// tgBridgeAddrs reads an interface's addresses; tests replace it.
func (s *Server) tgBridgeAddrs(name string) ([]net.Addr, error) {
	if s.tgBridgeAddrsOf != nil {
		return s.tgBridgeAddrsOf(name)
	}
	return tgbridge.SystemIfaceAddrs(name)
}

// tgBridgeDefaultRoutes names the interfaces with a default route; tests replace it.
func (s *Server) tgBridgeDefaultRoutes() map[string]bool {
	if s.tgBridgeRoutesOf != nil {
		return s.tgBridgeRoutesOf()
	}
	return defaultRouteIfaces()
}

// syncTelegramBridge makes the process match the saved settings and the router as it is now.
func (s *Server) syncTelegramBridge() {
	if s == nil || s.plugins == nil {
		return
	}
	st := &s.tgBridge
	st.mu.Lock()
	defer st.mu.Unlock()
	stop := func(why string) {
		s.plugins.RunService(tgBridgeService, nil)
		st.refused, st.listen, st.iface, st.public, st.uplink = why, netip.Addr{}, "", false, false
	}
	cfg := s.config()
	b := cfg.TelegramBridge
	if !b.Enabled {
		stop("")
		return
	}
	if cfg.Demo {
		stop("This is the demo: the bridge runs only on a router.")
		return
	}
	if b.Secret == "" {
		// Enabled without a secret (a hand-edited config): make one and keep it before the bridge
		// starts. A secret made up at each start would change the link every phone was given.
		secret, err := config.NewTelegramBridgeSecret()
		if err == nil {
			err = s.updateTelegramBridge(func(tb *config.TelegramBridge) error {
				if tb.Secret == "" {
					tb.Secret = secret
				}
				return nil
			})
		}
		if err != nil {
			stop("no secret could be saved for it: " + err.Error())
			return
		}
		b = s.config().TelegramBridge
	}
	if !config.ValidTelegramBridgeSecret(b.Secret) {
		stop("its saved secret is not 32 hex digits; set a new one")
		return
	}
	if err := b.Validate(); err != nil {
		stop(err.Error())
		return
	}
	if err := cfg.TelegramBridgePortConflict(); err != nil {
		stop(err.Error())
		return
	}
	iface := tgbridge.LANIface(s.detectedPlatform())
	addr, err := tgbridge.LANAddress(iface, s.tgBridgeAddrs)
	if err != nil {
		stop("no LAN address to listen on: " + err.Error())
		return
	}
	if tgbridge.Public(addr) {
		stop(fmt.Sprintf("%s holds the public address %s, and the bridge does not listen where the internet can reach it.", iface, addr))
		st.public, st.listen, st.iface = true, addr, iface
		return
	}
	port := b.EffectivePort()
	args, err := tgbridge.Args(tgbridge.Settings{Listen: addr, Port: port, CFDomain: b.CFDomain, CFWorkerDomain: b.CFWorkerDomain})
	if err != nil {
		stop(err.Error())
		return
	}
	s.plugins.RunService(tgBridgeService, &plugin.ServiceSpec{
		Bin: tgbridge.BinName, Args: args, Env: tgbridge.Env(b.Secret), UID: tgbridge.UID,
		Scrub: []string{strings.ToLower(b.Secret), strings.ToUpper(b.Secret)},
	})
	st.refused, st.listen, st.iface, st.public = "", addr, iface, false
	st.uplink = s.tgBridgeDefaultRoutes()[iface]
}

// updateTelegramBridge edits the saved block under cfgMu: fn edits a copy, which is validated and
// saved durably. A failed save leaves memory and disk as they were.
func (s *Server) updateTelegramBridge(fn func(*config.TelegramBridge) error) error {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	next := s.cfg.TelegramBridge
	if err := fn(&next); err != nil {
		return err
	}
	if err := next.Validate(); err != nil {
		return err
	}
	probe := *s.cfg
	probe.TelegramBridge = next
	if err := probe.TelegramBridgePortConflict(); err != nil {
		return err
	}
	prev := s.cfg.TelegramBridge
	s.cfg.TelegramBridge = next
	if err := s.cfg.Save(); err != nil {
		s.cfg.TelegramBridge = prev
		return err
	}
	return nil
}

// tgBridgeView is GET /api/telegram-bridge.
type tgBridgeView struct {
	Enabled bool `json:"enabled"`
	Running bool `json:"running"`
	// Installed: the tg-ws-proxy binary is where the daemon looks for it (Components installs it).
	Installed bool `json:"installed"`
	Port      int  `json:"port"`
	// Listen is the LAN address and port the bridge listens on (or would, while it is not running);
	// Iface the LAN bridge that address is on.
	Listen string `json:"listen,omitempty"`
	Iface  string `json:"iface,omitempty"`
	// Link is the tg://proxy link a client on the LAN imports: the LAN address, the port, the secret.
	Link string `json:"link,omitempty"`
	// QRSVG draws Link as a QR code (internal/qr), set by the GET handler only: the panel is usually
	// on a computer and Telegram on a phone, and the review's findings have no use for it.
	QRSVG          string `json:"qr_svg,omitempty"`
	CFDomain       string `json:"cf_domain,omitempty"`
	CFWorkerDomain string `json:"cf_worker_domain,omitempty"`
	// LastError is why it is not running, or how it last ended; empty when the reason is only the
	// missing binary, which Installed says.
	LastError string `json:"last_error,omitempty"`
	// Exits counts the times it ended on its own since it was last started with these settings, and
	// LastExit (RFC 3339) is when it last did.
	Exits    int    `json:"exits,omitempty"`
	LastExit string `json:"last_exit,omitempty"`
	// CrashLoop: it keeps exiting (tgBridgeCrashLoop), the review's crash_loop finding, whether or not
	// it is up between two restarts at this moment. LastError then says how it last ended.
	CrashLoop bool `json:"crash_loop,omitempty"`
	// PublicAddress and Uplink describe the LAN bridge: a public address (the bridge refuses it) or
	// a default route on it (the bridge runs, and the review says what that exposes).
	PublicAddress bool `json:"public_address,omitempty"`
	Uplink        bool `json:"uplink,omitempty"`

	demo     bool
	lastExit time.Time
}

// tgBridgeStatus assembles the view from the saved settings, the last sync and the process.
func (s *Server) tgBridgeStatus() tgBridgeView {
	cfg := s.config()
	b := cfg.TelegramBridge
	v := tgBridgeView{Enabled: b.Enabled, Port: b.EffectivePort(), CFDomain: b.CFDomain, CFWorkerDomain: b.CFWorkerDomain, demo: cfg.Demo}
	if s.plugins != nil {
		v.Installed = s.plugins.BinaryPresent(tgbridge.BinName)
	}
	st := &s.tgBridge
	st.mu.Lock()
	refused, listen, iface, public, uplink := st.refused, st.listen, st.iface, st.public, st.uplink
	st.mu.Unlock()
	if !b.Enabled {
		return v
	}
	v.Iface, v.PublicAddress, v.Uplink = iface, public, uplink
	if listen.IsValid() {
		v.Listen = net.JoinHostPort(listen.String(), strconv.Itoa(v.Port))
		if !public {
			v.Link = tgbridge.Link(listen, v.Port, b.Secret)
		}
	}
	if refused != "" {
		v.LastError = refused
		return v
	}
	if s.plugins == nil {
		return v
	}
	ps, ok := s.plugins.ServiceStatus(tgBridgeService)
	if !ok {
		return v
	}
	v.Running, v.Exits, v.lastExit = ps.Running, ps.Exits, ps.LastExit
	// Gated on the binary as the review is: there a missing binary is the finding, not the loop.
	v.CrashLoop = v.Installed && tgBridgeCrashLoop(ps.Exits, ps.LastExit, time.Now())
	if !ps.LastExit.IsZero() {
		v.LastExit = ps.LastExit.UTC().Format(time.RFC3339)
	}
	switch {
	case ps.NeedsBinary:
		// Installed (false) already says it, and the panel puts its own pointer to the Components page
		// beside that: a sentence here was the same fact a third time on the Settings card. A reason
		// that is not the binary (a refusal above, the demo's) is still sent and still shown.
	case !ps.Running && ps.Reason != "":
		v.LastError = ps.Reason
	case ps.Exits > 0 && ps.LastOutput != "":
		v.LastError = "it last exited with: " + ps.LastOutput
	case ps.Exits > 0:
		v.LastError = "it last exited without saying why"
	}
	return v
}

func (s *Server) handleTelegramBridgeGet(w http.ResponseWriter, r *http.Request) {
	// The link carries the secret, and so does its QR code.
	v := s.tgBridgeStatus()
	if v.Link != "" {
		if q, err := qr.Encode(v.Link); err == nil {
			v.QRSVG = q.SVG()
		}
	}
	writeJSONNoStore(w, http.StatusOK, v)
}

// tgBridgeIn is the PUT body. Secret: omitted, "" or the redaction mark keeps the saved one; 32 hex
// digits replace it; RegenerateSecret makes a new one (every client then needs the new link).
type tgBridgeIn struct {
	Enabled          bool   `json:"enabled"`
	Port             int    `json:"port"`
	Secret           string `json:"secret"`
	RegenerateSecret bool   `json:"regenerate_secret"`
	CFDomain         string `json:"cf_domain"`
	CFWorkerDomain   string `json:"cf_worker_domain"`
}

func (s *Server) handleTelegramBridgePut(w http.ResponseWriter, r *http.Request) {
	var in tgBridgeIn
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErrNoStore(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	var fresh string
	if in.RegenerateSecret {
		var err error
		if fresh, err = config.NewTelegramBridgeSecret(); err != nil {
			writeErrNoStore(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	err := s.updateTelegramBridge(func(b *config.TelegramBridge) error {
		b.Enabled = in.Enabled
		b.Port = in.Port
		b.CFDomain = strings.ToLower(strings.TrimSpace(in.CFDomain))
		b.CFWorkerDomain = strings.ToLower(strings.TrimSpace(in.CFWorkerDomain))
		switch sec := strings.TrimSpace(in.Secret); {
		case in.RegenerateSecret:
			b.Secret = fresh
		case sec != "" && sec != config.RedactedMark:
			if !config.ValidTelegramBridgeSecret(sec) {
				return errors.New("telegram bridge: the secret must be 32 hex digits (without the dd or ee prefix of a tg:// link)")
			}
			b.Secret = strings.ToLower(sec)
		}
		if b.Enabled && b.Secret == "" {
			sec, err := config.NewTelegramBridgeSecret()
			if err != nil {
				return err
			}
			b.Secret = sec
		}
		return nil
	})
	if err != nil {
		writeErrNoStore(w, http.StatusBadRequest, err.Error())
		return
	}
	s.syncTelegramBridge()
	s.handleTelegramBridgeGet(w, r)
}

// tgBridgeFindings put a bridge that is enabled but cannot do its job in the review. None blocks
// anything: Apply does not touch the bridge, and it would not fix it either. They are there because
// the review is where the operator looks to see whether the router does what was asked of it.
func (s *Server) tgBridgeFindings() []PlanFinding {
	v := s.tgBridgeStatus()
	if !v.Enabled || v.demo {
		return nil
	}
	f := func(id, severity string, reason platform.ReasonCode, detail, remedy string) PlanFinding {
		return PlanFinding{ID: id, Setting: "telegram bridge", Severity: severity, Reason: reason,
			Blocks: platform.BlocksNothing, Detail: detail, Remedy: remedy}
	}
	var out []PlanFinding
	switch {
	case !v.Installed:
		out = append(out, f("telegram_bridge.binary_missing", platform.SeverityDegraded, platform.ReasonMissingBinary,
			"The Telegram bridge is on, but tg-ws-proxy is not installed, so nothing listens for Telegram on the LAN.",
			"Install the Telegram bridge (tg-ws-proxy) on the Components page; it starts by itself once installed."))
	case v.PublicAddress:
		out = append(out, f("telegram_bridge.wan_listener", platform.SeverityDegraded, platform.ReasonInterfaceMissing,
			fmt.Sprintf("The Telegram bridge would listen on %s, a public address on %s, where anybody on the internet could reach it. It was not started.", v.Listen, v.Iface),
			"Give the LAN bridge a private address, or turn the Telegram bridge off."))
	case v.CrashLoop:
		out = append(out, f("telegram_bridge.crash_loop", platform.SeverityDegraded, platform.ReasonBinaryNotRunnable,
			fmt.Sprintf("The Telegram bridge keeps exiting (%d times since it was started, the last %s ago): %s",
				v.Exits, time.Since(v.lastExit).Round(time.Second), v.LastError),
			"A port another program holds, or a Cloudflare domain the bridge refuses, stops it at start: change the port or the domains."))
	case !v.Running && v.LastError != "":
		out = append(out, f("telegram_bridge.not_running", platform.SeverityDegraded, platform.ReasonMissingService,
			"The Telegram bridge is on but not running: "+v.LastError,
			"Fix what the reason names; the daemon retries every 30 seconds and on every save."))
	}
	if v.Uplink {
		out = append(out, f("telegram_bridge.wan_listener", platform.SeverityPrivacy, platform.ReasonOperatorChoice,
			fmt.Sprintf("The Telegram bridge listens on %s, on %s, and the router's default route leaves through %s too: every host on that network, not only your own devices, can reach it with the link.", v.Listen, v.Iface, v.Iface),
			"Expected when this router sits inside another network as an access point; otherwise check which interface is the LAN."))
	}
	return out
}
