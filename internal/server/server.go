// Package server exposes the wayhop HTTP API and serves the embedded web UI.
package server

import (
	"context"
	"io/fs"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"wayhop/internal/awg"
	"wayhop/internal/clash"
	"wayhop/internal/config"
	"wayhop/internal/core"
	"wayhop/internal/failsafe"
	"wayhop/internal/health"
	"wayhop/internal/initserver"
	"wayhop/internal/netdiag"
	"wayhop/internal/netvpn"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
	"wayhop/internal/plugin"
	"wayhop/internal/serverstore"
	"wayhop/internal/speedtest"
	"wayhop/internal/store"
	"wayhop/internal/tgbot"
	"wayhop/internal/traffic"
	"wayhop/internal/updater"
	"wayhop/internal/watchdog"
)

// Server wires the HTTP handlers to the daemon's components.
type Server struct {
	cfg *config.Config
	hub *traffic.Hub
	// ifaceHist is a RAM-only ring of per-interface counter snapshots (last few minutes) so a fresh
	// dashboard seeds its per-interface graph from history instead of an empty plot. See ifacehistory.go.
	ifaceHist *ifaceRing
	// dayHist is the coarse 24h companion to ifaceHist: one activity bucket per minute, RAM-only.
	dayHist *dayRing
	// outbound derives an approximate per-outbound throughput from Clash /connections, so proxy exits
	// (VLESS/SOCKS — no kernel interface) show a speed on the dashboard too. See ifacehistory.go.
	outbound *obSampler
	clash    *clash.Client
	singbox  *core.SingBox
	store    *store.Store
	updater  *updater.Updater
	monitor  *health.Monitor
	// cidrChecks records when each routing list was last FETCHED, which is not when it last
	// changed — see cidrchecked.go.
	cidrChecks *cidrCheckState
	failsafe   *failsafe.Manager
	plugins    *plugin.Manager
	watchdog   *watchdog.Watchdog
	servers    *serverstore.Store
	jobs       *initserver.JobManager
	auth       *authManager
	// startedAt bounds what the failover log can possibly contain: it lives in RAM, so an empty log
	// means "nothing since this time", not "nothing ever". The Failover page says which.
	startedAt time.Time
	// feedFails records the routing lists whose feed refreshes keep failing; see feedfailures.go.
	feedFails feedFailures
	// keeneticLeft records the WayHop-created KeeneticOS tunnels last found changed outside WayHop;
	// see keeneticleft.go.
	keeneticLeft keeneticLeftAsIs
	// The optional-module (Plugins/IPTV) state used to live here as a featurestore handle plus a data
	// dir, wired by a setter that nothing ever called: its routes were never registered, its start
	// hook never ran, and the field stayed nil for the life of every process. The subsystem is
	// deferred, not deleted — it is preserved in the development repository, outside the Go build and
	// outside this published tree. deferred_features_test.go is the tripwire that keeps it out: it
	// asserts the routes 404 and the IPTV assets are not embedded.
	cfgMu   sync.Mutex // serializes all s.cfg field writes + Save() + reads
	applyMu sync.Mutex // serializes Apply, confirm, rollback, boot converge and the reconcile loop
	// speedMu lets one throughput test run at a time, the panel's and the Telegram bot's alike: two
	// at once share the line, and each would report about half of it.
	speedMu sync.Mutex
	// speedRunOf is nil in production (the real run, see speedRun); tests answer for the panel's run,
	// so which path it took (through the core, straight out, or bound to the kernel tunnel link) and
	// what the answer calls that path can be checked without a network.
	speedRunOf func(ctx context.Context, viaProxy bool, link string, bytes int) (speedtest.Result, error)

	// nativeOperations names the exact NDM operations the Keenetic adapter implements (set at
	// StartApply on that platform); the capability evaluator offers native adoption/creation only
	// when it is populated.
	nativeOperations map[string]bool

	// applyState is the apply-state record (what WayHop last applied); applyStateDir is where it
	// lives once StartApply told us the startup config path. See applystate.go.
	applyState    applyStateStore
	applyStateDir string
	// bootDroppedPlan is the kernel plan of the Test state the previous process left installed;
	// convergeOnBoot moves its flows once the committed plane is back (see ctflush.go).
	bootDroppedPlan *pbr.Plan
	// bootLive is that Test state when it is still on the router and boot must roll it back rather
	// than discard it (liveNeedsRollbackOnBoot); nil otherwise.
	bootLive *appliedRevision
	// bootIDOf is nil in production (reads /proc/sys/kernel/random/boot_id); tests answer for it.
	bootIDOf func() string
	// failSafePingOf is nil in production (netdiag.Ping); tests answer for the fail-safe window's
	// connectivity ping, which would otherwise measure the developer host's own internet.
	failSafePingOf func(ctx context.Context, host string, count int) netdiag.PingResult
	// applyStage / applyInProgress publish the running Apply's step for GET /api/apply/status.
	applyStage      atomic.Value
	applyInProgress atomic.Bool
	// kernelPlaneState is the last kernel-plane observation (postcheck / reconcile), for /api/state.
	kernelPlaneState atomic.Int32
	// execOps is nil in production (the real adapters); tests inject fakes. See applyexec.go.
	execOps *applyExecOps
	// hostProbeOf is nil in production (the real host probe); tests inject one so an Apply neither
	// shells out to the developer host nor is limited to the platform it happens to run on.
	hostProbeOf func(context.Context, DesiredSnapshot) (hostProbeV1, error)
	// binaryPresentOf is nil in production (the real engine-binary lookup); tests inject one because
	// the lookup ends in exec.LookPath, so a developer who happens to have `awg` installed would turn
	// every test about a missing-engine finding into a silent skip.
	binaryPresentOf func(string) bool

	// devNoAuth disables panel authentication for development. Set only by the --dev-no-auth process
	// flag; nothing in config.json can reach it, so it cannot outlive the process that asked for it.
	devNoAuth bool

	// pbrRunner is the kernel-PBR command runner; a non-ExecRunner (a test RecordRunner) marks a
	// test that wants the plane logic to run without touching the host (see kernelPBRAvailable).
	pbrRunner pbr.Runner
	// uciReader is nil in production (the real reader) and injected by tests; see netvpnplan.go.
	uciReader            uciReadFunc
	keeneticConfigReader keeneticConfigReadFunc
	// keeneticInterfacesReader reads `show interface` (each WireGuard interface's own public key);
	// nil means the real bounded ndmc read. Tests inject a stand-in.
	keeneticInterfacesReader keeneticConfigReadFunc
	// keeneticPolicyReader reads `show ip policy`; nil means the real bounded ndmc read. Tests inject
	// the measured shape.
	keeneticPolicyReader keeneticConfigReadFunc
	// offloadObserver is nil in production (the bounded/cancellable strict observer). Tests inject a
	// captured fixture so API truth can be checked without reading the development host's /proc.
	offloadObserver func(context.Context, string, string) (platform.OffloadState, []string)
	// dnsUpstreamsOf answers which resolvers this router's own lookups go to, and whether that could
	// be read; nil is the real reader. Injected by tests — a development host has no router
	// resolv.conf, and the cases worth asserting are exactly the ones it cannot produce.
	dnsUpstreamsOf func() ([]string, bool)
	// netifdProtosOf answers which netifd protocol handlers the router has; nil is the real probe.
	// Injected by tests: no development host has /lib/netifd/proto, so the real answer there is
	// "not probed", which refuses nothing and would make every capability assertion vacuous.
	netifdProtosOf func() netvpn.RouterProtos
	// pmCoreHook is the routing core as the package-manager delegation sees it; nil is the real one.
	// Injected by tests, which cannot make a *core.SingBox report Running() without a live process —
	// and a running core is the only state that guard is about. See updaterpm.go.
	pmCoreHook *pmCoreState
	// awgProbeOf is nil in production (awg.ProbeHost); tests give the AmneziaWG component a router.
	awgProbeOf func() awg.Probe
	// awgKernelReadsOf is nil in production (the netifd handler and /sys/module/amneziawg); tests give
	// the AmneziaWG kernel capture a router. See awgkernel.go.
	awgKernelReadsOf *awgKernelReads
	// netifdStaleOf and networkRestartOf are nil in production (/proc and the handler's ctime; the
	// detached /etc/init.d/network restart); tests inject. awgNetifdPending is what the last AmneziaWG
	// install reported about netifd, for when its state cannot be measured. See awgnetifd.go.
	netifdStaleOf    func() (stale, known bool)
	networkRestartOf func() error
	awgNetifdPending atomic.Bool
	// awgUserspaceRunningOf is nil in production (the plugin manager's amneziawg-go procs); tests say
	// which AmneziaWG connections run on amneziawg-go now.
	awgUserspaceRunningOf func() []string
	// routeTables is nil in production (iproute2, see tableIO); tests replace how the list-routing
	// loop reads and writes table defaults and asks whether a device is up.
	routeTables *routeTableIO
	// tableRestoreErr is the last refusal per family/table the route restore logged (under
	// listFailoverErrMu), so a device that keeps failing is reported once, not every tick.
	tableRestoreErr map[string]string
	// platformOf is nil in production (platform.Detect); injected so the refusal paths below can be
	// exercised on a dev box, which is never OpenWrt and would otherwise stop every test at the door.
	platformOf func() platform.Platform
	// coreVer remembers the configured sing-box's `version` answer per binary identity, for the
	// generator's schema gate (see coreversion.go). coreVersionOf is nil in production (runs the
	// binary); tests answer for it.
	coreVer       coreVersionCache
	coreVersionOf func(ctx context.Context, bin string) (string, error)
	ui            fs.FS
	etagOnce      sync.Once // computes the UI asset ETag lazily, once
	etag          string
	caps          capCache         // cached capability evaluation; see capabilitySet()
	hostVerdicts  hostVerdictCache // kernel-PBR and accelerator verdicts, as fresh as caps (see kernelPBRAvailable, accelKind)
	exitIP        exitIPState      // cached public-exit-IP lookup for the Dashboard hero
	exitTiles     exitTilesState   // cached per-egress exit grid (name + WAN IP + geo per endpoint)
	// markExitResolver cache: the connmark→exit-tag map (Dashboard live-connections table) is
	// derived from a full Profile() clone + pbr.Compile() that only changes on Apply, yet it was
	// recomputed on EVERY /api/conntrack poll. Cache the resolver and recompute at most once per
	// exitResolverTTL (a few seconds of staleness on a display label is harmless).
	exitResolverMu  sync.Mutex
	exitResolver    func(uint32) string
	exitResolverExp int64 // unix-ms; recompute the mark→exit resolver after this

	// nativeOnly datapath verdict cache: DatapathNativeOnly walks a full Profile() clone on
	// EVERY /api/health poll (~5s) even though it only changes when the profile or routing
	// mode does. Cache it keyed on (store gen, routing mode) — a hit skips both the clone and
	// the walk. Not a TTL cache: gen makes it exact, so there is no staleness window.
	nativeOnlyMu   sync.Mutex
	nativeOnlyGen  uint64
	nativeOnlyMode string
	nativeOnlyVal  bool
	nativeOnlyOK   bool

	subStatus subRefreshStatus // last subscription auto-refresh outcome (for the Settings card)

	updErrMu sync.Mutex        // guards updErrs
	updErrs  map[string]string // engine id -> last install-failure reason, so the Updater can show WHY it failed after the toast fades / a reload

	// Last write outcome per routing-list family/table, so the failover owner reports a refusal once
	// rather than every tick. See noteListFailoverWrite.
	listFailoverErrMu sync.Mutex
	listFailoverErr   map[string]string

	// tg is the Telegram bot manager, built on first use (see tgbot.go).
	tgOnce     sync.Once
	tg         *tgbot.Manager
	tgBootOnce sync.Once
	tgBoot     tgbot.BootInfo
	// tgDigestDay is the demo's record of the last daily digest; a router keeps it in a file.
	tgDigestMu  sync.Mutex
	tgDigestDay string

	// tgBridge is what the last Telegram-bridge sync decided (tgbridge.go). tgBridgeAddrsOf and
	// tgBridgeRoutesOf are nil in production (the interface's addresses, /proc/net/route); tests
	// give the bridge a LAN.
	tgBridge         tgBridgeState
	tgBridgeAddrsOf  func(name string) ([]net.Addr, error)
	tgBridgeRoutesOf func() map[string]bool
	// tgBridgeReapOf replaces the start-up reap of a leftover bridge (reapTelegramBridge) in tests.
	tgBridgeReapOf func()

	allowInternalFetch bool // test-only: skip the subscription-fetch SSRF dial guard so httptest (loopback) servers can be used
	// updInit and updSpawn are the self-update supervisor's seams (selfupdate_tx.go): nil = the real
	// init script and the real detached spawn.
	updInit  func() string
	updSpawn func(etc string, args ...string) error
	// updPIDFile is the supervisor's pid file ("" = updatetx.SupervisorPIDFile) and updZone the zone
	// update times are named in, the in-flight refusal and the rollback note (nil =
	// localtz.Location()), as seams for the same reason.
	updPIDFile string
	updZone    func() *time.Location
	// selfSwap is the release-asset swap (updater.SelfUpdateWith), as a seam for the same reason.
	selfSwap func(ctx context.Context, repo, tag, exe string, before func(string) error) (string, error)
}

// New builds a Server.
func New(cfg *config.Config, hub *traffic.Hub, cl *clash.Client, sb *core.SingBox, st *store.Store, mon *health.Monitor, ss *serverstore.Store, ui fs.FS) *Server {
	up := updater.New(filepath.Dir(cfg.SingBox.Bin), cfg.Updater.Arch, cfg.Updater.Mirrors)
	if cfg.Demo {
		// The package-manager delegation only renders for an engine opkg or apk OWNS, and the dev host
		// has neither — so without this the whole feature would appear on no page and every UI gate
		// would walk past a control that was never drawn. Reads are shaped like a real apk; the
		// mutating verbs return what they WOULD have run and change nothing, because demo mode must
		// not touch host state.
		up.WithPM(updater.DemoPM())
		// Release lookups answer from the built-in catalogue rather than api.github.com. The demo is
		// what everything risky is clicked through on, and what the verification suite drives, so it
		// must not depend on a third party being reachable — see internal/updater/offline.go.
		up.Offline = true
	}
	pdir := filepath.Join(filepath.Dir(cfg.SingBox.Config), "plugins")
	s := &Server{cfg: cfg, hub: hub, clash: cl, singbox: sb, store: st, updater: up, monitor: mon, cidrChecks: newCIDRCheckState(),
		failsafe: failsafe.New(failsafe.DefaultDurations()), plugins: plugin.New(pdir, filepath.Dir(cfg.SingBox.Bin)),
		servers: ss, jobs: initserver.NewJobManager(), ui: ui, pbrRunner: pbr.ExecRunner{}, updErrs: map[string]string{},
		startedAt: time.Now(), keeneticConfigReader: readKeeneticRunningConfig}
	s.auth = newAuthManager(s)
	// NDM owns KeeneticOS's AmneziaWG kernel module: the plugin must not add links on it behind NDM's
	// back, so every AmneziaWG endpoint it runs there runs on amneziawg-go.
	if platform.Detect() == platform.Keenetic && !cfg.Demo {
		s.plugins.FirmwareOwnsAWGKernel()
	}
	// Component downloads consult the chosen path per connection, so a saved choice applies from the
	// first fetch and a group follows its healthy member without waiting for a config write.
	up.BindVia(s.updaterDownloadIface)
	// Crash-restart supervision for sing-box (and best-effort the engine plugins).
	wd := watchdog.New("sing-box", sb)
	wd.SetPluginSupervisor(s.plugins.Supervise)
	if mon != nil {
		pm := s.plugins
		mon.SetPluginStateResolver(func(id string) (health.PluginState, bool) {
			for _, st := range pm.Status() {
				if st.ID == id {
					return health.PluginState{Running: st.Running, NeedsBinary: st.NeedsBinary, Reason: st.Reason}, true
				}
			}
			return health.PluginState{}, false
		})
	}
	// Route crash-restart alerts through s.alert so they read the CURRENT NotifyURL (a
	// Settings change is honored, not frozen at startup) and share one notifier path with
	// the fail-safe rollback/reboot alerts. No-op when no URL is configured.
	wd.SetNotify(s.alert)
	s.watchdog = wd
	// ~7.5 min of history at the 5s sample cadence (matches the client's MAXG=90 graph window).
	s.ifaceHist = newIfaceRing(90)
	s.dayHist = newDayRing()
	s.outbound = newObSampler() // per-outbound (proxy-exit) rate sampler, refreshed by SampleInterfacesLoop
	return s
}

// Watchdog exposes the crash-restart supervisor so the daemon can Run it.
func (s *Server) Watchdog() *watchdog.Watchdog { return s.watchdog }

// Plugins exposes the engine-plugin manager so the daemon can stop the engines
// (nfqws2 procs, AmneziaWG interfaces) cleanly on shutdown.
func (s *Server) Plugins() *plugin.Manager { return s.plugins }

// Handler returns the root http.Handler with all routes mounted.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Public bootstrap surface. Static assets contain no runtime state and health is liveness only.
	// Every other route is explicitly session-protected below, and route registration panics on an
	// unknown classification.
	s.route(mux, authRoutePublic, "GET /api/auth/status", s.handleAuthStatus)
	s.route(mux, authRoutePublic, "POST /api/auth/setup", s.handleAuthSetup)
	s.route(mux, authRoutePublic, "POST /api/auth/login", s.handleAuthLogin)
	s.route(mux, authRouteProtected, "POST /api/auth/logout", s.handleAuthLogout)
	s.route(mux, authRouteProtected, "POST /api/auth/password", s.handleAuthPassword)
	s.route(mux, authRoutePublic, "GET /api/health", s.handleHealth)
	s.route(mux, authRouteProtected, "GET /api/health/endpoints", s.handleHealthEndpoints)
	s.route(mux, authRouteProtected, "GET /api/failover/state", s.handleFailoverState)
	s.route(mux, authRouteProtected, "GET /api/failover/events", s.handleFailoverEvents)
	s.route(mux, authRouteProtected, "GET /api/health/history", s.handleHealthHistory)
	s.route(mux, authRouteProtected, "POST /api/health/test/{id}", s.handleHealthTest)
	s.route(mux, authRouteProtected, "/api/traffic/recent", s.handleTrafficRecent)
	s.route(mux, authRouteProtected, "/api/traffic/stream", s.handleTrafficStream)
	s.route(mux, authRouteProtected, "GET /metrics", s.handleMetrics)

	// Profile API (M2b). Go 1.22 method+wildcard routing.
	s.route(mux, authRouteProtected, "POST /api/import", s.handleImport)
	s.route(mux, authRouteProtected, "POST /api/subscription", s.handleSubscription)
	s.route(mux, authRouteProtected, "GET /api/profile", s.handleGetProfile)
	s.route(mux, authRouteProtected, "POST /api/profile", s.handleRestoreProfile)
	s.route(mux, authRouteProtected, "POST /api/endpoints", s.handleUpsertEndpoint)
	s.route(mux, authRouteProtected, "POST /api/endpoints/bulk", s.handleBulkEndpoints)
	s.route(mux, authRouteProtected, "DELETE /api/endpoints/{id}", s.handleDeleteEndpoint)
	// A connection's on/off switch: {"enabled": bool} and nothing else (QA-152).
	s.route(mux, authRouteProtected, "PATCH /api/endpoints/{id}", s.handlePatchEndpoint)
	s.route(mux, authRouteProtected, "POST /api/groups", s.handleUpsertGroup)
	s.route(mux, authRouteProtected, "DELETE /api/groups/{id}", s.handleDeleteGroup)
	s.route(mux, authRouteProtected, "POST /api/rules", s.handleUpsertRule)
	s.route(mux, authRouteProtected, "DELETE /api/rules/{id}", s.handleDeleteRule)
	// Routing lists (the "Routing" page): list CRUD + the preset catalog.
	s.route(mux, authRouteProtected, "POST /api/routing", s.handleUpsertRoutingList)
	s.route(mux, authRouteProtected, "DELETE /api/routing/{id}", s.handleDeleteRoutingList)
	s.route(mux, authRouteProtected, "PATCH /api/routing/{id}", s.handlePatchRoutingList) // the list's switch (QA-152)
	s.route(mux, authRouteProtected, "POST /api/device-groups", s.handleUpsertDeviceGroup)
	s.route(mux, authRouteProtected, "DELETE /api/device-groups/{id}", s.handleDeleteDeviceGroup)
	s.route(mux, authRouteProtected, "GET /api/routing/catalog", s.handleRoutingCatalog)
	s.route(mux, authRouteProtected, "GET /api/routing/status", s.handleRoutingStatus)
	s.route(mux, authRouteProtected, "GET /api/routing/traffic", s.handleRoutingTraffic)
	s.route(mux, authRouteProtected, "POST /api/routing/refresh", s.handleRoutingRefresh)
	s.route(mux, authRouteProtected, "POST /api/routing/reorder", s.handleRoutingReorder)
	// Read-only previews of lists kept elsewhere (routingimport.go); the panel adds one via POST /api/routing.
	s.route(mux, authRouteProtected, "GET /api/routing/import/keenetic", s.handleRoutingImportKeenetic)
	// KeeneticOS's access policies a routing list can be sent to ("ndm-policy:<name>"); read-only.
	s.route(mux, authRouteProtected, "GET /api/keenetic/policies", s.handleKeeneticPolicies)
	s.route(mux, authRouteProtected, "POST /api/routing/import/hydraroute", s.handleRoutingImportHydraRoute)
	// The routing switch (routingswitch.go): WayHop's routing off / back on, configuration untouched.
	s.route(mux, authRouteProtected, "GET /api/routing/switch", s.handleRoutingSwitchGet)
	s.route(mux, authRouteProtected, "POST /api/routing/switch", s.handleRoutingSwitchSet)
	// DNS section: DNS-plane CRUD + provider presets (dns.go). /api/dns/doh-resolvers stays below.
	s.route(mux, authRouteProtected, "GET /api/dns", s.handleGetDNS)
	s.route(mux, authRouteProtected, "PUT /api/dns", s.handleSetDNS)
	s.route(mux, authRouteProtected, "GET /api/dns/catalog", s.handleDNSCatalog)
	s.route(mux, authRouteProtected, "GET /api/dns/native", s.handleGetDNSNative)
	s.route(mux, authRouteProtected, "POST /api/dns/native/plan", s.handleDNSNativePlan)

	s.route(mux, authRouteProtected, "POST /api/generate", s.handleGenerate)
	s.route(mux, authRouteProtected, "POST /api/endpoints/{id}/check", s.handleEndpointCheck) // per-connection config validation
	s.route(mux, authRouteProtected, "POST /api/apply", s.handleApply)
	// Per-connection share / QR plus imported-subscription refresh controls.
	s.route(mux, authRouteProtected, "GET /api/endpoints/{id}/export", s.handleEndpointExport)
	s.route(mux, authRouteProtected, "GET /api/subscription/info", s.handleSubInfo)
	s.route(mux, authRouteProtected, "POST /api/subscription/autorefresh", s.handleSubAutoRefresh)
	s.route(mux, authRouteProtected, "POST /api/subscription/refresh", s.handleSubRefreshNow)
	s.route(mux, authRouteProtected, "POST /api/apply/confirm", s.handleApplyConfirm)
	s.route(mux, authRouteProtected, "POST /api/apply/rollback", s.handleApplyRollback)
	s.route(mux, authRouteProtected, "GET /api/apply/status", s.handleApplyStatus)
	s.route(mux, authRouteProtected, "GET /api/apply/plan", s.handleApplyPlan)
	s.route(mux, authRouteProtected, "POST /api/apply/ack", s.handleApplyAck)
	s.route(mux, authRouteProtected, "GET /api/state", s.handleState) // saved vs applied vs pending (survives reload)
	// Structured "what would Apply change?" review: per-field diff vs the applied baseline, grouped
	// by subsystem, secrets never included.
	s.route(mux, authRouteProtected, "GET /api/changeset", s.handleChangeSet)
	// Undo part of the pending set (field | object | subsystem | all) — reverts the REAL stored data.
	s.route(mux, authRouteProtected, "POST /api/changeset/undo", s.handleChangeSetUndo)
	s.route(mux, authRouteProtected, "POST /api/speedtest", s.handleSpeedtest)
	s.route(mux, authRouteProtected, "GET /api/plugins", s.handlePlugins)
	s.route(mux, authRouteProtected, "GET /api/watchdog", s.handleWatchdog)
	s.route(mux, authRouteProtected, "GET /api/system", s.handleSystem)
	s.route(mux, authRouteProtected, "GET /api/system/recent", s.handleSystemRecent)         // RAM-only per-iface history (seeds the graph on load)
	s.route(mux, authRouteProtected, "GET /api/traffic/outbounds", s.handleTrafficOutbounds) // per-outbound rates so proxy exits (VLESS/SOCKS) show a speed
	s.route(mux, authRouteProtected, "GET /api/connections", s.handleConnections)
	s.route(mux, authRouteProtected, "GET /api/conntrack", s.handleConntrack)
	s.route(mux, authRouteProtected, "GET /api/exit-ip", s.handleExitIP)
	s.route(mux, authRouteProtected, "GET /api/exit-ips", s.handleExitIPs)
	s.route(mux, authRouteProtected, "GET /api/pbr/preview", s.handlePBRPreview)
	s.route(mux, authRouteProtected, "GET /api/netvpn/plan", s.handleNetvpnPlan)
	// Native and kernel mutations happen only inside POST /api/apply.
	s.route(mux, authRouteProtected, "GET /api/pbr/status", s.handlePBRStatus)
	s.route(mux, authRouteProtected, "GET /api/pbr/lists/memory", s.handlePBRListMemory)
	s.route(mux, authRouteProtected, "GET /api/vpn/discover", s.handleVPNDiscover)
	s.route(mux, authRouteProtected, "POST /api/vpn/adopt", s.handleVPNAdopt)
	s.route(mux, authRouteProtected, "POST /api/drift/ignore", s.handleDriftIgnore)
	s.route(mux, authRouteProtected, "GET /api/native/capabilities", s.handleNativeCapabilities)
	s.route(mux, authRouteProtected, "GET /api/interfaces", s.handleInterfaces)
	s.route(mux, authRouteProtected, "GET /api/devices", s.handleDevices)
	s.route(mux, authRouteProtected, "GET /api/clients/destinations", s.handleClientDestinations)
	s.route(mux, authRouteProtected, "GET /api/dns/doh-resolvers", s.handleDoHResolvers)

	// Diagnostics + error knowledgebase.
	s.route(mux, authRouteProtected, "GET /api/diagnostics", s.handleDiagnostics)
	s.route(mux, authRouteProtected, "POST /api/diagnostics", s.handleDiagnosticsAnalyze)
	s.route(mux, authRouteProtected, "GET /api/diagnostics/trace", s.handleTrace)
	s.route(mux, authRouteProtected, "GET /api/healthcheck", s.handleHealthCheck)
	s.route(mux, authRouteProtected, "POST /api/netdiag", s.handleNetDiag)
	s.route(mux, authRouteProtected, "POST /api/netdiag/all", s.handleNetDiagAll)
	s.route(mux, authRouteProtected, "POST /api/netdiag/services", s.handleNetDiagServices)
	s.route(mux, authRouteProtected, "GET /api/netdiag/stream", s.handleNetDiagStream)
	s.route(mux, authRouteProtected, "POST /api/probe/tls", s.handleProbeTLS)
	s.route(mux, authRouteProtected, "GET /api/reality/dests", s.handleRealityDests)
	s.route(mux, authRouteProtected, "GET /api/kb", s.handleKB)

	// Init Server (R8) — multi-server registry, options, job-based provisioning,
	// hardening, and the smart-console job feed.
	s.route(mux, authRouteProtected, "GET /api/servers", s.handleServers)
	s.route(mux, authRouteProtected, "POST /api/servers", s.handleServers)
	s.route(mux, authRouteProtected, "DELETE /api/servers/{id}", s.handleDeleteServer)
	s.route(mux, authRouteProtected, "GET /api/server/options", s.handleServerOptions)
	s.route(mux, authRouteProtected, "GET /api/server/job/{id}", s.handleServerJob)
	s.route(mux, authRouteProtected, "POST /api/server/check", s.handleServerCheck)
	s.route(mux, authRouteProtected, "POST /api/server/script", s.handleServerScript)
	s.route(mux, authRouteProtected, "POST /api/server/provision", s.handleServerProvision)
	s.route(mux, authRouteProtected, "POST /api/server/harden/keys", s.handleServerHardenKeys)
	s.route(mux, authRouteProtected, "POST /api/server/harden/lockdown", s.handleServerLockdown)
	s.route(mux, authRouteProtected, "POST /api/server/check-versions", s.handleServerCheckVersions)
	s.route(mux, authRouteProtected, "POST /api/server/update-binary", s.handleServerUpdateBinary)

	// Config (Settings).
	s.route(mux, authRouteProtected, "GET /api/config", s.handleGetConfig)
	s.route(mux, authRouteProtected, "PUT /api/config", s.handlePutConfig)
	s.route(mux, authRouteProtected, "GET /api/system/day", s.handleSystemDay)
	s.route(mux, authRouteProtected, "GET /api/config/defaults", s.handleConfigDefaults)
	s.route(mux, authRouteProtected, "GET /api/config/export", s.handleConfigExport)
	s.route(mux, authRouteProtected, "POST /api/config/import", s.handleConfigImport)
	s.route(mux, authRouteProtected, "POST /api/config/reset", s.handleConfigReset)
	// Whole-setup backup: download/restore profile+servers+routing knobs in one
	// file (e.g. before a firmware reflash). Restore never auto-applies and never
	// touches the access-critical config (see backup.go).
	s.route(mux, authRouteProtected, "GET /api/backup", s.handleBackupExport)
	s.route(mux, authRouteProtected, "POST /api/backup/restore", s.handleBackupRestore)
	s.route(mux, authRouteProtected, "GET /api/support-bundle", s.handleSupportBundle)
	s.route(mux, authRouteProtected, "POST /api/service/restart", s.handleServiceRestart)

	// Telegram bot (tgbot.go): settings, token check, pairing, test message, chats and the chats that
	// asked to be let in. The token is write-only: no route returns it.
	s.route(mux, authRouteProtected, "GET /api/telegram", s.handleTelegramGet)
	s.route(mux, authRouteProtected, "PUT /api/telegram", s.handleTelegramPut)
	s.route(mux, authRouteProtected, "POST /api/telegram/check", s.handleTelegramCheck)
	s.route(mux, authRouteProtected, "POST /api/telegram/pair", s.handleTelegramPair)
	s.route(mux, authRouteProtected, "POST /api/telegram/test", s.handleTelegramTest)
	s.route(mux, authRouteProtected, "PUT /api/telegram/chats/{id}", s.handleTelegramChatPut)
	s.route(mux, authRouteProtected, "DELETE /api/telegram/chats/{id}", s.handleTelegramChatDelete)
	s.route(mux, authRouteProtected, "POST /api/telegram/strangers/{id}/allow", s.handleTelegramStrangerAllow)
	s.route(mux, authRouteProtected, "DELETE /api/telegram/strangers/{id}", s.handleTelegramStrangerDelete)
	s.route(mux, authRouteProtected, "GET /api/telegram-bridge", s.handleTelegramBridgeGet)
	s.route(mux, authRouteProtected, "PUT /api/telegram-bridge", s.handleTelegramBridgePut)

	// Engine version manager (Updater) + WayHop self-update.
	s.route(mux, authRouteProtected, "GET /api/updater/engines", s.handleUpdaterEngines)
	s.route(mux, authRouteProtected, "GET /api/updater/self", s.handleSelfStatus)
	s.route(mux, authRouteProtected, "GET /api/updater/storage", s.handleUpdaterStorage)
	s.route(mux, authRouteProtected, "POST /api/updater/self/install", s.handleSelfUpdate)
	s.route(mux, authRouteProtected, "PUT /api/updater/self/auto", s.handleSelfAuto)
	s.route(mux, authRouteProtected, "GET /api/updater/{id}/versions", s.handleUpdaterVersions)
	s.route(mux, authRouteProtected, "GET /api/updater/{id}/fit", s.handleUpdaterFit)
	s.route(mux, authRouteProtected, "GET /api/updater/pm/refresh/plan", s.handleUpdaterPMRefreshPlan)
	s.route(mux, authRouteProtected, "POST /api/updater/pm/refresh/apply", s.handleUpdaterPMRefreshApply)
	// Native package-manager delegation. The plan is a GET because it runs nothing; the apply is a
	// POST because it mutates the system package database, and it only ever runs the argv the plan
	// already showed. See internal/server/updaterpm.go.
	s.route(mux, authRouteProtected, "GET /api/updater/{id}/pm/plan", s.handleUpdaterPMPlan)
	s.route(mux, authRouteProtected, "GET /api/updater/{id}/pm/candidates", s.handleUpdaterPMCandidates)
	s.route(mux, authRouteProtected, "POST /api/updater/{id}/pm/apply", s.handleUpdaterPMApply)
	// netifd reads AmneziaWG's handler only when it starts: the restart the AmneziaWG row offers after
	// a kernel-module install. See awgnetifd.go.
	s.route(mux, authRouteProtected, "POST /api/updater/awg/restart-network", s.handleAWGRestartNetwork)
	s.route(mux, authRouteProtected, "POST /api/updater/{id}/install", s.handleUpdaterInstall)
	s.route(mux, authRouteProtected, "DELETE /api/updater/{id}", s.handleUpdaterUninstall)

	// No route forwards to the sing-box Clash controller. Its bearer secret exists
	// so that only this daemon may drive it; the generic /api/clash/ reverse proxy
	// that used to be mounted here re-published that authority to any client the
	// host guard admits — every method, every suffix the controller understands
	// (including ones a future sing-box adds), and encoded traversals (..%2F)
	// forwarded verbatim past the mount. The panel never needed it: every
	// Clash-derived view is served by a typed endpoint above (traffic, health,
	// connections), and the UI has no /api/clash/* call. The boundary is pinned
	// by TestClashControllerNotReachableThroughPanel.
	// Unregistered API paths are a public 404 rather than falling through to the SPA. This keeps
	// retired mutation surfaces dark without turning a nonexistent endpoint into an auth oracle.
	s.route(mux, authRoutePublic, "/api/", func(w http.ResponseWriter, r *http.Request) {
		// API routes can appear after an upgrade. A cached negative response would strand an
		// otherwise-current panel on the old route map, and API responses should never inherit
		// intermediary cache policy from the surrounding LAN. Keep retired and unknown surfaces
		// dark while making the 404 explicitly non-cacheable.
		w.Header().Set("Cache-Control", "no-store")
		http.NotFound(w, r)
	})
	s.route(mux, authRoutePublic, "/", s.staticHandler().ServeHTTP)
	// Outer-to-inner: security headers (set even on Host-guard rejections) -> Host
	// allow-list (DNS-rebinding guard) -> access log (sees only accepted hosts) ->
	// gzip -> same-origin guard on mutating methods ->
	// request-body size cap -> routes.
	chain := hostAllowGuard(newHostDecider(s.allowedHosts, s.allowAnyHost),
		logRequests(gzipMiddleware(sameOriginGuard(limitBody(mux)))))
	// Security headers are outermost so literally every response carries them, including a Host
	// rejection that intentionally never reaches the access log or route stack. Host accessors are
	// still read per request, so saved policy applies without a restart.
	return securityHeaders(chain)
}
