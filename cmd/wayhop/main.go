// Command wayhop is the WayHop daemon: it serves the web panel and
// supervises the proxy cores (sing-box plus engine plugins).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"wayhop/internal/clash"
	"wayhop/internal/config"
	"wayhop/internal/core"
	_ "wayhop/internal/feature/iptv" // compiled-in IPTV plugin (self-registers via init) — Go driver idiom
	"wayhop/internal/featurestore"
	"wayhop/internal/generator"
	"wayhop/internal/health"
	"wayhop/internal/platform"
	"wayhop/internal/server"
	"wayhop/internal/serverstore"
	"wayhop/internal/store"
	"wayhop/internal/traffic"
	"wayhop/internal/version"
	"wayhop/web"
)

func main() {
	var (
		configPath = flag.String("config", "/opt/etc/wayhop/config.json", "path to the wayhop config file")
		listen     = flag.String("listen", "", "override the UI listen address (e.g. :8088)")
		demo       = flag.Bool("demo", false, "synthesize traffic for UI development without sing-box")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("wayhop %s (%s, %s)\n", version.Version, version.Commit, version.Date)
		return
	}

	// Non-daemon subcommands: `wayhop import <link>`, `wayhop gen <link>`.
	if args := flag.Args(); len(args) > 0 {
		if err := runTool(args); err != nil {
			log.Fatalf("%s: %v", args[0], err)
		}
		return
	}

	// `wayhop --demo` with no explicit --config runs entirely from a throwaway temp
	// dir, so "try before you install" works for ANY user (non-root, Windows) — the
	// README's demo one-liner would otherwise MkdirAll("/opt/etc/wayhop") in
	// config.Load/store.Open and fatal for a non-root user.
	if *demo {
		configSet := false
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "config" {
				configSet = true
			}
		})
		if !configSet {
			demoDir := filepath.Join(os.TempDir(), "wayhop-demo")
			if err := os.MkdirAll(demoDir, 0o755); err == nil {
				*configPath = filepath.Join(demoDir, "config.json")
				log.Printf("demo: throwaway state in %s (delete it to reset)", demoDir)
			}
		}
	}

	// Cap the daemon's heap with a memory soft-limit so a spike (bulk import,
	// config reload) can't OOM-kill it — and take routing down — on a low-RAM
	// router. No-op when GOMEMLIMIT is set or RAM can't be read (demo/non-Linux).
	applyMemSoftLimit()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *demo {
		cfg.Demo = true
	}

	// Runtime platform detection (D-PLAT-2: one universal binary, behavior chosen at
	// runtime rather than per-platform builds). Informational today — the OpenWrt apply
	// path (pbr/nft + sing-box) is unchanged. On Keenetic the native-first backend
	// (internal/keenetic implementing platform.RoutingBackend) is what the apply path will
	// select here once it is platform-routed; the backend itself is built + validated.
	log.Printf("platform: %s", platform.Detect())

	hub := traffic.NewHub(300)
	sb := core.New(cfg.SingBox.Bin, cfg.SingBox.Config)
	cl, err := clash.New(cfg.Clash.Controller, cfg.Clash.Secret)
	if err != nil {
		log.Fatalf("clash client: %v", err)
	}

	profilePath := filepath.Join(filepath.Dir(*configPath), "profile.json")
	st, err := store.Open(profilePath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	serversPath := filepath.Join(filepath.Dir(*configPath), "servers.json")
	ss, err := serverstore.Open(serversPath)
	if err != nil {
		log.Fatalf("server store: %v", err)
	}
	features, err := featurestore.Open(filepath.Join(filepath.Dir(*configPath), "features.json"))
	if err != nil {
		log.Fatalf("feature store: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Feed the traffic hub from the demo generator or the real Clash stream.
	if cfg.Demo {
		go runDemoTraffic(ctx, hub)
	} else {
		go runClashTraffic(ctx, cl, hub)
	}

	// Background health monitor: probes endpoints/groups, accumulates stats,
	// attributes traffic, and derives failure causes from the sing-box log.
	mon := health.NewMonitor(cl, st, sb, cfg.Demo)
	go mon.Run(ctx)

	// Autostart sing-box if a config already exists (so it's supervised from
	// boot). Demo mode and a missing binary are no-ops handled by Start.
	//
	// P4 (sing-box optionality): when the live profile + resolved routing mode are
	// provably native-only (generator.DatapathNativeOnly), the kernel-PBR plane +
	// engine plugins carry everything and the sing-box core must NOT come up — even
	// if a stale singbox.json is still on disk. SyncPlugins (started just below)
	// installs the kernel plane and Stops any running core in the native-only arm,
	// but gating the boot autostart here avoids briefly starting a core we'd then
	// tear down. Fail-safe: DatapathNativeOnly returns false on ANY ambiguity
	// (nil/empty profile, non-fast mode, a surviving sing-box-only reference), so a
	// false verdict (start the core) is the conservative default. The routing mode
	// is resolved exactly as the server does (Server.routingMode): an explicit
	// value wins, "" derives from Gateway.
	// Reap any sing-box orphaned by a PREVIOUS daemon instance (OOM-kill / crash / self-update
	// restart) before we bring our own core up: an orphan keeps the cache.db flock, which would
	// make our sing-box crash-loop on "initialize cache-file: timeout" until the orphan dies.
	// No-op in demo / on non-Linux.
	if !cfg.Demo {
		sb.ReapStrays()
	}
	if !cfg.Demo && sb.Available() {
		if _, err := os.Stat(cfg.SingBox.Config); err == nil {
			prof := st.Profile()
			if generator.DatapathNativeOnly(&prof, bootRoutingMode(cfg)) {
				log.Printf("sing-box autostart skipped: profile is native-only (kernel-PBR datapath)")
			} else if err := sb.Start(); err != nil {
				log.Printf("sing-box autostart: %v", err)
			} else {
				log.Printf("sing-box started")
			}
		}
	}

	srv := server.New(cfg, hub, cl, sb, st, mon, ss, web.FS())
	srv.SetFeatures(features, filepath.Dir(*configPath)) // Plugins section: per-module state store + data dir
	go srv.SyncPlugins()                                 // bring engine plugins (AmneziaWG interfaces, olcRTC) up from boot
	go srv.AutoUpdateLoop(ctx)                           // self-update WayHop when Updater.AutoUpdate is on (default off)
	go srv.SubscriptionRefreshLoop(ctx)                  // re-fetch an imported subscription when auto-refresh is opted in (off by default)
	go srv.CIDRRefreshLoop(ctx)                          // auto-refresh each routing list's CIDR carve-out on its RefreshHours cadence (default 24h)
	go srv.PBRReconcileLoop(ctx)                         // self-heal the kernel PBR plane if its nft table is flushed out-of-band (fw4 reload / https-dns-proxy / adblock)
	go srv.StartFeatures(ctx)                            // background loops of installed plugin modules (each no-ops while disabled)
	// Crash-restart supervision for sing-box (+ best-effort engine plugins).
	wdDone := make(chan struct{})
	go func() { srv.Watchdog().Run(ctx); close(wdDone) }()
	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("wayhop %s listening on %s (demo=%v)", version.Version, cfg.Listen, cfg.Demo)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down…")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	// Wait for the watchdog to stop ticking before tearing down the engine: an
	// in-flight tick could otherwise (re)start sing-box right after we Stop it,
	// orphaning a process that keeps the listen ports bound. tick() is fast, so
	// this returns promptly.
	<-wdDone
	_ = sb.Stop()
	srv.Plugins().StopAll() // stop engine plugins (olcRTC procs, awg interfaces) so they don't orphan
}

// bootRoutingMode resolves the effective routing mode from a config snapshot for
// the boot-time native-only check, mirroring Server.routingMode (the canonical
// resolver, internal/server/profile.go): an explicit "tun"/"hybrid"/"fast"/"mixed"
// wins; "" derives from Gateway (TUN when on, else mixed). The Server's method is
// unexported and the Server is not constructed until after the autostart decision,
// so this keeps the boot path and the apply path agreeing on which mode is active.
func bootRoutingMode(cfg *config.Config) string {
	mode := cfg.RoutingMode
	if mode == "" {
		if cfg.Gateway {
			mode = "tun"
		} else {
			mode = "mixed"
		}
	}
	return mode
}

// runClashTraffic keeps the Clash /traffic stream connected, retrying on failure.
//
// The Clash API only exists while sing-box is running, so a failure here is
// normally just "no engine up yet" — the expected idle state, not a fault. We
// log the first drop, then stay quiet while retrying so we don't flood the
// router log (logread) every few seconds when nothing is applied. The next
// drop is logged again only after a stream that actually stayed connected.
func runClashTraffic(ctx context.Context, cl *clash.Client, hub *traffic.Hub) {
	const retry = 3 * time.Second
	loggedDown := false
	for ctx.Err() == nil {
		start := time.Now()
		err := cl.StreamTraffic(ctx, hub.Push)
		if ctx.Err() != nil {
			return
		}
		// A stream that lasted longer than the retry interval was a real,
		// connected session that dropped — treat the next failure as fresh
		// news worth logging. A near-instant return is the idle "engine not
		// up" state, which we announce once and then suppress.
		if time.Since(start) > retry {
			loggedDown = false
		}
		if !loggedDown {
			log.Printf("clash traffic stream unavailable (%v); retrying every %s until the engine is up", err, retry)
			loggedDown = true
		}
		select {
		case <-ctx.Done():
		case <-time.After(retry):
		}
	}
}

// runDemoTraffic synthesizes a believable up/down signal at 1 Hz so the UI and
// graph can be developed without a running sing-box.
func runDemoTraffic(ctx context.Context, hub *traffic.Hub) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var i float64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			i++
			down := 1.5e6 + 1.0e6*math.Sin(i/7) + 4.0e5*math.Sin(i/2.3)
			up := 5.0e5 + 3.0e5*math.Sin(i/5+1) + 1.5e5*math.Sin(i/1.7)
			if down < 0 {
				down = 0
			}
			if up < 0 {
				up = 0
			}
			hub.Push(traffic.Sample{T: time.Now().UnixMilli(), Up: int64(up), Down: int64(down)})
		}
	}
}
