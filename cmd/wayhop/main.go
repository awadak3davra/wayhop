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
	"path"
	"path/filepath"
	"syscall"
	"time"

	"wayhop/internal/clash"
	"wayhop/internal/config"
	"wayhop/internal/core"
	"wayhop/internal/health"
	"wayhop/internal/platform"
	"wayhop/internal/server"
	"wayhop/internal/serverstore"
	"wayhop/internal/store"
	"wayhop/internal/traffic"
	"wayhop/internal/util"
	"wayhop/internal/version"
	"wayhop/web"
)

// listenOrDefault returns listen unless it is empty, in which case it falls back to the default bind.
// An empty listen would make net/http's ListenAndServe bind the unauthenticated panel on 0.0.0.0:80.
func listenOrDefault(listen string) string {
	if listen == "" {
		return config.Default().Listen
	}
	return listen
}

// routerConfigPathAllowed collapses every production router process onto one installation-wide
// ledger/lock domain. Custom paths remain available on development hosts and in demo mode, but a
// second --config directory on OpenWrt/Keenetic must never create an independent router writer.
// routerConfigDir is the one directory routerConfigPathAllowed accepts for a platform, or "" where
// any path is allowed. One definition, so the refusal cannot name a directory the predicate would
// then reject — two lists of the same paths is how a message starts sending people to the wrong one.
func routerConfigDir(got platform.Platform) string {
	switch got {
	case platform.OpenWrt:
		return "/etc/wayhop"
	case platform.Keenetic:
		return "/opt/etc/wayhop"
	default:
		return ""
	}
}

func routerConfigPathAllowed(got platform.Platform, configPath string) bool {
	if want := routerConfigDir(got); want != "" {
		return path.Dir(configPath) == want
	}
	// A platform with no fixed installation directory (development hosts) accepts any path. The
	// comparison above uses path.Dir, not filepath.Dir, deliberately: configPath describes the TARGET
	// router even when this predicate is exercised by a cross-platform gate, so its authority boundary
	// is POSIX rather than the host running the tests.
	return true
}

func main() {
	var (
		configPath = flag.String("config", "/opt/etc/wayhop/config.json", "path to the wayhop config file")
		listen     = flag.String("listen", "", "override the UI listen address (e.g. :8088)")
		demo       = flag.Bool("demo", false, "synthesize traffic for UI development without sing-box")
		showVer    = flag.Bool("version", false, "print version and exit")
		// Development scaffold. A process flag rather than a config field on purpose: it cannot be
		// left on by a file, so a router that reboots comes back authenticated.
		devNoAuth = flag.Bool("dev-no-auth", false,
			"DEVELOPMENT ONLY: disable panel authentication for this process")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("wayhop %s\n", version.Get())
		return
	}

	// Non-daemon subcommands: `wayhop import <link>`, `wayhop gen <link>`.
	if args := flag.Args(); len(args) > 0 {
		if err := runTool(args); err != nil {
			log.Fatalf("%s: %v", args[0], err)
		}
		return
	}

	// Before anything creates a file. WayHop's own writes carry an explicit mode, but sing-box
	// creates its cache.db itself and it landed at 0644 on the router — the umask a child inherits is
	// the only control the daemon has over a file it never opens.
	util.RestrictNewFiles()

	// `wayhop --demo` with no explicit --config runs entirely from a throwaway temp
	// dir, so "try before you install" works for ANY user (non-root, Windows) — the
	// README's demo one-liner would otherwise MkdirAll("/opt/etc/wayhop") in
	// config.Load/store.Open and fatal for a non-root user.
	demoDir := "" // non-empty only for the zero-config throwaway demo (below)
	if *demo {
		configSet := false
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "config" {
				configSet = true
			}
		})
		if !configSet {
			d := filepath.Join(os.TempDir(), "wayhop-demo")
			if err := os.MkdirAll(d, 0o755); err == nil {
				demoDir = d
				*configPath = filepath.Join(d, "config.json")
				log.Printf("demo: throwaway state in %s (delete it to reset)", d)
			}
		}
	}
	startupConfigPath, err := filepath.Abs(*configPath)
	if err != nil || filepath.Clean(startupConfigPath) != startupConfigPath {
		log.Fatalf("config path: unsafe startup path %q", *configPath)
	}
	*configPath = startupConfigPath

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
	// config.Load is intentionally lenient (it LOGS a Validate failure but proceeds, so a partially
	// bad config can't brick boot) — but an EMPTY listen is special: net/http's ListenAndServe
	// substitutes ":http" for an empty Addr, binding the UNAUTHENTICATED panel on 0.0.0.0:80. Fall
	// back to the documented default bind so a blanked listen can never silently become port 80.
	if def := listenOrDefault(cfg.Listen); def != cfg.Listen {
		log.Printf("config: empty listen address — using the default %q (an empty listen would otherwise bind 0.0.0.0:80)", def)
		cfg.Listen = def
	}
	if *demo {
		cfg.Demo = true
		// Keep the throwaway demo fully self-contained: an Apply generates a
		// singbox.json, and without this it would MkdirAll the default
		// /opt/etc/wayhop (→ C:\opt on Windows) — the same non-root/Windows trap
		// the config redirect above avoids. Only for the zero-config demo; an
		// explicit --config keeps whatever SingBox.Config it declares.
		if demoDir != "" {
			cfg.SingBox.Config = filepath.Join(demoDir, "singbox.json")
			cfg.DataDir = demoDir // keep runtime state (e.g. scheduled auto-backups) off /opt too
		}
	}

	// Runtime platform detection (D-PLAT-2: one universal binary, behavior chosen at runtime rather
	// than per-platform builds). Apply dispatches native plans to the matching OpenWrt or Keenetic
	// adapter and runs the generic core/plugin path everywhere else.
	detectedPlatform := platform.Detect()
	log.Printf("platform: %s", detectedPlatform)
	if !cfg.Demo && !routerConfigPathAllowed(detectedPlatform, startupConfigPath) {
		// Name the directory that WOULD be accepted. The refusal used to state only the rejected path,
		// which tells the reader what failed and nothing about what to do — measured while trying to
		// bring a test binary up on a live OpenWrt box: "openwrt routers require the
		// installation config directory; refusing an independent apply-state record at
		// \"/tmp/wh-test\"" left the required directory to be found by reading the source.
		log.Fatalf("config path: %s routers require the installation config directory %q; refusing an independent apply-state record at %q. "+
			"Point --config at %s/config.json, or use --demo for a throwaway instance.",
			detectedPlatform, routerConfigDir(detectedPlatform), filepath.Dir(startupConfigPath), routerConfigDir(detectedPlatform))
	}

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
	// A fresh throwaway demo starts empty; seed a sample connection set (documentation IPs only) so
	// the Connections, Failover, and Routing pages render populated and the health monitor has
	// endpoints to synthesize state for. Demo + empty store only — a real profile is never touched.
	if cfg.Demo && len(st.Profile().Endpoints) == 0 {
		if err := st.Replace(server.DemoProfile()); err != nil {
			log.Printf("demo: seed profile failed: %v", err)
		}
	}

	serversPath := filepath.Join(filepath.Dir(*configPath), "servers.json")
	ss, err := serverstore.Open(serversPath)
	if err != nil {
		log.Fatalf("server store: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Background health monitor: probes endpoints/groups, accumulates stats,
	// attributes traffic, and derives failure causes from the sing-box log.
	mon := health.NewMonitor(cl, st, sb, cfg.Demo)
	// Without this the monitor can only guess from the engine log, and an endpoint whose engine was
	// never installed has no log to guess from: it was told to try another transport, which is
	// unreachable advice when every transport it names runs inside the engine that is missing.
	mon.SetCoreAvailable(sb.Available)

	srv := server.New(cfg, hub, cl, sb, st, mon, ss, web.FS())
	if *devNoAuth {
		srv.SetDevNoAuth(true)
		// Announced on every start, not once at the flag site: the panel binds all interfaces, so a
		// router left running this way is an unauthenticated control plane on the LAN and the log is
		// the only place that fact is visible afterwards.
		log.Printf("SECURITY: panel authentication is DISABLED by --dev-no-auth (development only)")
	}
	// The apply-state record lives next to the startup config. StartApply discards a stale unsaved
	// window, converges the router to the committed state in the background (never fatal), feeds the
	// health monitor the applied native interface names and runs the kernel-plane reconcile loop.
	srv.StartApply(ctx, startupConfigPath)
	if cfg.Demo {
		go runDemoTraffic(ctx, hub)
	} else {
		go runClashTraffic(ctx, cl, hub)
	}
	go mon.Run(ctx)
	go srv.SubscriptionRefreshLoop(ctx) // re-fetch an imported subscription when auto-refresh is opted in (off by default)
	go srv.BackupLoop(ctx)              // scheduled local whole-setup backup when Backup.AutoHours>0 (opt-in, off by default)
	go srv.SampleInterfacesLoop(ctx)    // RAM-only per-iface counter history so a fresh dashboard seeds recent throughput (no flash writes)
	go srv.CIDRRefreshLoop(ctx)         // updates the saved routing-list caches only; activation is Apply
	go srv.AutoUpdateLoop(ctx)          // opt-in binary update, serialized with Apply
	// Crash-restart supervision for sing-box (+ best-effort engine plugins).
	wdDone := make(chan struct{})
	go func() { srv.Watchdog().Run(ctx); close(wdDone) }()
	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second, // bounds a slow-HEADERS slowloris
		// IdleTimeout closes a kept-alive connection that sits between requests instead of holding a
		// goroutine and a file descriptor open indefinitely. Without it (and with no ReadTimeout) an
		// unauthenticated LAN client can open many connections and simply keep them, exhausting a
		// ~256 MB router's descriptors. Slow BODIES are bounded per-request in limitBody, not here, so
		// this stays clear of the SSE streams (long-lived GET responses that carry no request body and
		// set their own per-frame write deadline). No global WriteTimeout, for the same SSE reason.
		IdleTimeout: 2 * time.Minute,
	}

	go func() {
		// The full identity, not just the version: a router running a build nobody can trace back to a
		// commit is exactly what the audit found, and the log is where an operator looks first.
		log.Printf("wayhop %s listening on %s (demo=%v)", version.Get(), cfg.Listen, cfg.Demo)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down…")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	// Wait for the watchdog to stop ticking before tearing down the engine: an in-flight tick could
	// otherwise (re)start sing-box right after we Stop it, orphaning a process that keeps the listen
	// ports bound. tick() is fast, so this returns promptly.
	<-wdDone
	// Shutdown (not Stop): it also marks the core "closed" so an in-flight HTTP apply
	// handler that outlived httpSrv.Shutdown's 5s deadline can't call singbox.Start()
	// after teardown and orphan a fresh core. httpSrv.Shutdown does not cancel a
	// running handler's context, and there is no WriteTimeout, so this is the only
	// backstop for that apply-vs-shutdown race.
	_ = sb.Shutdown()
	// Retire only plugin processes tracked by WayHop so none survives the daemon and keeps an
	// interface or listener behind. Externally owned/adopted tunnels are not in this manager.
	srv.Plugins().StopAll()
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
