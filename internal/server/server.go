// Package server exposes the wayhop HTTP API and serves the embedded web UI.
package server

import (
	"io/fs"
	"net/http"
	"path/filepath"
	"sync"

	"wayhop/internal/clash"
	"wayhop/internal/config"
	"wayhop/internal/core"
	"wayhop/internal/failsafe"
	"wayhop/internal/featurestore"
	"wayhop/internal/health"
	"wayhop/internal/initserver"
	"wayhop/internal/pbr"
	"wayhop/internal/plugin"
	"wayhop/internal/serverstore"
	"wayhop/internal/store"
	"wayhop/internal/traffic"
	"wayhop/internal/updater"
	"wayhop/internal/watchdog"
)

// Server wires the HTTP handlers to the daemon's components.
type Server struct {
	cfg      *config.Config
	hub      *traffic.Hub
	clash    *clash.Client
	singbox  *core.SingBox
	store    *store.Store
	updater  *updater.Updater
	monitor  *health.Monitor
	failsafe *failsafe.Manager
	plugins  *plugin.Manager
	watchdog *watchdog.Watchdog
	servers  *serverstore.Store
	jobs     *initserver.JobManager
	// Plugin (optional-module) state: the atomic per-module store + the dir modules write files to.
	// Wired via SetFeatures after New() (nil in tests that don't use plugins). See features.go.
	features       *featurestore.Store
	featureDataDir string
	cfgMu          sync.Mutex // serializes all s.cfg field writes + Save() + reads
	applyMu        sync.Mutex // serializes Apply so concurrent applies don't race singbox.json.tmp / Backup

	// Kernel policy-based-routing plane (RoutingMode=="hybrid"). pbrMu is the SINGLE
	// authority for pbrPlan+pbrBaseline AND for the whole nft/ip command stream against
	// the shared "wayhop_pbr" table — DISTINCT from applyMu. The rollback closure and
	// boot sync take ONLY pbrMu (never applyMu, which handleApply holds end-to-end), so
	// there is no lock-ordering cycle. pbrRunner is injectable (a RecordRunner) for tests.
	pbrRunner   pbr.Runner
	pbrMu       sync.Mutex
	pbrPlan     *pbr.Plan // currently-installed kernel plan (nil = none installed)
	pbrBaseline *pbr.Plan // rollback target, snapshotted at the FIRST apply of a fail-safe window
	// Engine-plugin specs (AmneziaWG/olcRTC) matching the pre-window config, snapshotted
	// alongside pbrBaseline so a fail-safe rollback re-Syncs the plugins to the restored
	// config (else a restored outbound bound to a torn-down awg device runs dead). Guarded
	// by pbrMu (same rollback-baseline state, set under applyMu, read in the rollback path).
	pluginBaseline []plugin.Spec
	ui             fs.FS
	etagOnce       sync.Once // computes the UI asset ETag lazily, once
	etag           string
	exitIP         exitIPState // cached public-exit-IP lookup for the Dashboard hero
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

	allowInternalFetch bool // test-only: skip the subscription-fetch SSRF dial guard so httptest (loopback) servers can be used
}

// New builds a Server.
func New(cfg *config.Config, hub *traffic.Hub, cl *clash.Client, sb *core.SingBox, st *store.Store, mon *health.Monitor, ss *serverstore.Store, ui fs.FS) *Server {
	up := updater.New(filepath.Dir(cfg.SingBox.Bin), cfg.Updater.Arch, cfg.Updater.Mirrors)
	pdir := filepath.Join(filepath.Dir(cfg.SingBox.Config), "plugins")
	s := &Server{cfg: cfg, hub: hub, clash: cl, singbox: sb, store: st, updater: up, monitor: mon,
		failsafe: failsafe.New(failsafe.DefaultDurations()), plugins: plugin.New(pdir, filepath.Dir(cfg.SingBox.Bin)),
		servers: ss, jobs: initserver.NewJobManager(), ui: ui, pbrRunner: pbr.ExecRunner{}, updErrs: map[string]string{}}
	// Crash-restart supervision for sing-box (and best-effort the engine plugins).
	wd := watchdog.New("sing-box", sb)
	wd.SetPluginSupervisor(s.plugins.Supervise)
	// Route crash-restart alerts through s.alert so they read the CURRENT NotifyURL (a
	// Settings change is honored, not frozen at startup) and share one notifier path with
	// the fail-safe rollback/reboot alerts. No-op when no URL is configured.
	wd.SetNotify(s.alert)
	s.watchdog = wd
	return s
}

// Watchdog exposes the crash-restart supervisor so the daemon can Run it.
func (s *Server) Watchdog() *watchdog.Watchdog { return s.watchdog }

// Plugins exposes the engine-plugin manager so the daemon can stop the engines
// (olcRTC procs, AmneziaWG interfaces) cleanly on shutdown.
func (s *Server) Plugins() *plugin.Manager { return s.plugins }

// Handler returns the root http.Handler with all routes mounted.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("GET /api/health/endpoints", s.handleHealthEndpoints)
	mux.HandleFunc("GET /api/failover/state", s.handleFailoverState)
	mux.HandleFunc("POST /api/health/test/{id}", s.handleHealthTest)
	mux.HandleFunc("/api/traffic/recent", s.handleTrafficRecent)
	mux.HandleFunc("/api/traffic/stream", s.handleTrafficStream)
	mux.HandleFunc("GET /metrics", s.handleMetrics)

	// Profile API (M2b). Go 1.22 method+wildcard routing.
	mux.HandleFunc("POST /api/import", s.handleImport)
	mux.HandleFunc("POST /api/subscription", s.handleSubscription)
	mux.HandleFunc("GET /api/profile", s.handleGetProfile)
	mux.HandleFunc("POST /api/profile", s.handleRestoreProfile)
	mux.HandleFunc("POST /api/endpoints", s.handleUpsertEndpoint)
	mux.HandleFunc("POST /api/endpoints/bulk", s.handleBulkEndpoints)
	mux.HandleFunc("DELETE /api/endpoints/{id}", s.handleDeleteEndpoint)
	mux.HandleFunc("POST /api/groups", s.handleUpsertGroup)
	mux.HandleFunc("DELETE /api/groups/{id}", s.handleDeleteGroup)
	mux.HandleFunc("POST /api/rules", s.handleUpsertRule)
	mux.HandleFunc("DELETE /api/rules/{id}", s.handleDeleteRule)
	// Routing lists (the "Routing" page): list CRUD + the preset catalog.
	mux.HandleFunc("POST /api/routing", s.handleUpsertRoutingList)
	mux.HandleFunc("DELETE /api/routing/{id}", s.handleDeleteRoutingList)
	mux.HandleFunc("GET /api/routing/catalog", s.handleRoutingCatalog)
	mux.HandleFunc("GET /api/routing/status", s.handleRoutingStatus)
	mux.HandleFunc("POST /api/routing/refresh", s.handleRoutingRefresh)
	// DNS section: DNS-plane CRUD + provider presets (dns.go). /api/dns/doh-resolvers stays below.
	mux.HandleFunc("GET /api/dns", s.handleGetDNS)
	mux.HandleFunc("PUT /api/dns", s.handleSetDNS)
	mux.HandleFunc("GET /api/dns/catalog", s.handleDNSCatalog)
	mux.HandleFunc("GET /api/dns/native", s.handleGetDNSNative)
	mux.HandleFunc("POST /api/dns/native/plan", s.handleDNSNativePlan)

	// Plugins (optional feature modules): management routes + each compiled-in module's own routes,
	// mounted UNCONDITIONALLY (the module gates on the enabled flag inside its handlers, so a toggle
	// needs no restart).
	mux.HandleFunc("GET /api/features", s.handleFeaturesList)
	mux.HandleFunc("PUT /api/features/{id}", s.handleFeatureToggle)
	mux.HandleFunc("GET /api/features/{id}/settings", s.handleFeatureSettingsGet)
	mux.HandleFunc("PUT /api/features/{id}/settings", s.handleFeatureSettingsPut)
	s.registerFeatureRoutes(mux)
	mux.HandleFunc("POST /api/generate", s.handleGenerate)
	mux.HandleFunc("POST /api/apply", s.handleApply)
	// Share / QR / subscription (export connections to client apps).
	mux.HandleFunc("GET /api/endpoints/{id}/export", s.handleEndpointExport)
	mux.HandleFunc("POST /api/qr", s.handleQR)
	mux.HandleFunc("GET /api/subscription/info", s.handleSubInfo)
	mux.HandleFunc("POST /api/subscription/rotate", s.handleSubRotate)
	mux.HandleFunc("POST /api/subscription/autorefresh", s.handleSubAutoRefresh)
	mux.HandleFunc("POST /api/subscription/refresh", s.handleSubRefreshNow)
	mux.HandleFunc("GET /api/sub/{token}", s.handleSubServe)
	mux.HandleFunc("POST /api/apply/confirm", s.handleApplyConfirm)
	mux.HandleFunc("POST /api/apply/rollback", s.handleApplyRollback)
	mux.HandleFunc("GET /api/apply/status", s.handleApplyStatus)
	mux.HandleFunc("POST /api/speedtest", s.handleSpeedtest)
	mux.HandleFunc("GET /api/plugins", s.handlePlugins)
	mux.HandleFunc("GET /api/watchdog", s.handleWatchdog)
	mux.HandleFunc("GET /api/system", s.handleSystem)
	mux.HandleFunc("GET /api/connections", s.handleConnections)
	mux.HandleFunc("GET /api/conntrack", s.handleConntrack)
	mux.HandleFunc("GET /api/exit-ip", s.handleExitIP)
	mux.HandleFunc("GET /api/pbr/preview", s.handlePBRPreview)
	mux.HandleFunc("GET /api/pbr/status", s.handlePBRStatus)
	mux.HandleFunc("POST /api/pbr/apply", s.handlePBRApply)
	mux.HandleFunc("POST /api/pbr/teardown", s.handlePBRTeardown)
	mux.HandleFunc("GET /api/vpn/discover", s.handleVPNDiscover)
	mux.HandleFunc("POST /api/vpn/adopt", s.handleVPNAdopt)
	mux.HandleFunc("GET /api/native/capabilities", s.handleNativeCapabilities)
	mux.HandleFunc("GET /api/interfaces", s.handleInterfaces)
	mux.HandleFunc("GET /api/devices", s.handleDevices)
	mux.HandleFunc("GET /api/clients/destinations", s.handleClientDestinations)
	mux.HandleFunc("GET /api/dns/doh-resolvers", s.handleDoHResolvers)

	// Diagnostics + error knowledgebase.
	mux.HandleFunc("GET /api/diagnostics", s.handleDiagnostics)
	mux.HandleFunc("POST /api/diagnostics", s.handleDiagnosticsAnalyze)
	mux.HandleFunc("GET /api/diagnostics/trace", s.handleTrace)
	mux.HandleFunc("GET /api/healthcheck", s.handleHealthCheck)
	mux.HandleFunc("POST /api/netdiag", s.handleNetDiag)
	mux.HandleFunc("POST /api/netdiag/all", s.handleNetDiagAll)
	mux.HandleFunc("GET /api/netdiag/stream", s.handleNetDiagStream)
	mux.HandleFunc("POST /api/probe/tls", s.handleProbeTLS)
	mux.HandleFunc("GET /api/kb", s.handleKB)

	// Init Server (R8) — multi-server registry, options, job-based provisioning,
	// hardening, and the smart-console job feed.
	mux.HandleFunc("GET /api/servers", s.handleServers)
	mux.HandleFunc("POST /api/servers", s.handleServers)
	mux.HandleFunc("DELETE /api/servers/{id}", s.handleDeleteServer)
	mux.HandleFunc("GET /api/server/options", s.handleServerOptions)
	mux.HandleFunc("GET /api/server/job/{id}", s.handleServerJob)
	mux.HandleFunc("POST /api/server/check", s.handleServerCheck)
	mux.HandleFunc("POST /api/server/script", s.handleServerScript)
	mux.HandleFunc("POST /api/server/provision", s.handleServerProvision)
	mux.HandleFunc("POST /api/server/harden/keys", s.handleServerHardenKeys)
	mux.HandleFunc("POST /api/server/harden/lockdown", s.handleServerLockdown)
	mux.HandleFunc("POST /api/server/check-versions", s.handleServerCheckVersions)
	mux.HandleFunc("POST /api/server/update-binary", s.handleServerUpdateBinary)

	// Config (Settings).
	mux.HandleFunc("GET /api/config", s.handleGetConfig)
	mux.HandleFunc("PUT /api/config", s.handlePutConfig)
	mux.HandleFunc("GET /api/config/export", s.handleConfigExport)
	mux.HandleFunc("POST /api/config/import", s.handleConfigImport)
	mux.HandleFunc("POST /api/config/reset", s.handleConfigReset)
	// Whole-setup backup: download/restore profile+servers+routing knobs in one
	// file (e.g. before a firmware reflash). Restore never auto-applies and never
	// touches the access-critical config (see backup.go).
	mux.HandleFunc("GET /api/backup", s.handleBackupExport)
	mux.HandleFunc("POST /api/backup/restore", s.handleBackupRestore)
	mux.HandleFunc("POST /api/service/restart", s.handleServiceRestart)

	// Engine version manager (Updater) + WayHop self-update.
	mux.HandleFunc("GET /api/updater/engines", s.handleUpdaterEngines)
	mux.HandleFunc("GET /api/updater/self", s.handleSelfStatus)
	mux.HandleFunc("POST /api/updater/self/install", s.handleSelfUpdate)
	mux.HandleFunc("PUT /api/updater/self/auto", s.handleSelfAuto)
	mux.HandleFunc("GET /api/updater/{id}/versions", s.handleUpdaterVersions)
	mux.HandleFunc("POST /api/updater/{id}/install", s.handleUpdaterInstall)
	mux.HandleFunc("DELETE /api/updater/{id}", s.handleUpdaterUninstall)

	if s.clash != nil {
		mux.Handle("/api/clash/", s.clash.Proxy("/api/clash"))
	}
	mux.Handle("/", s.staticHandler())
	// Outer-to-inner: Host allow-list (DNS-rebinding guard; opt-in, no-op when
	// unset) -> security headers (set on every reply) -> access log (sees final
	// status) -> gzip -> same-origin (CSRF) guard on mutating methods ->
	// request-body size cap -> routes.
	chain := securityHeaders(logRequests(gzipMiddleware(sameOriginGuard(limitBody(mux)))))
	// Read AllowedHosts per request (not a boot snapshot) so a saved list applies
	// immediately and a too-narrow one stays fixable from the live UI.
	return hostAllowGuard(func() []string { return s.config().AllowedHosts }, chain)
}
