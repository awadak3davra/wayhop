package server

import (
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/store"
)

func desiredSnapshotProfile(name string) model.Profile {
	return model.Profile{Endpoints: []model.Endpoint{{
		ID:       "edge",
		Name:     name,
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoTrojan,
		Server:   "198.51.100.10",
		Port:     443,
		Params:   map[string]any{"password": "test-only"},
		Enabled:  true,
	}}}
}

func desiredSnapshotServer(t *testing.T, profile model.Profile) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.Replace(profile); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	cfg := config.Default()
	return &Server{cfg: cfg, store: st}
}

func TestDesiredSnapshotRevisionDeterministic(t *testing.T) {
	cfg := *config.Default()
	profile := desiredSnapshotProfile("A")
	one, err := newDesiredSnapshot(cfg, profile, 7)
	if err != nil {
		t.Fatalf("first snapshot: %v", err)
	}
	two, err := newDesiredSnapshot(cfg, profile, 7)
	if err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	if one.SchemaVersion != DesiredSnapshotSchemaV1 {
		t.Fatalf("schema = %d, want %d", one.SchemaVersion, DesiredSnapshotSchemaV1)
	}
	if one.DesiredRev != two.DesiredRev {
		t.Fatalf("identical inputs produced different revisions: %q != %q", one.DesiredRev, two.DesiredRev)
	}
	if len(one.DesiredRev) != sha256HexLen || strings.Trim(one.DesiredRev, "0123456789abcdef") != "" {
		t.Fatalf("revision is not a full lowercase SHA-256: %q", one.DesiredRev)
	}
}

const sha256HexLen = 64

func TestDesiredSnapshotRevisionBindsProfileContentButNotProcessGeneration(t *testing.T) {
	cfg := *config.Default()
	base, err := newDesiredSnapshot(cfg, desiredSnapshotProfile("A"), 4)
	if err != nil {
		t.Fatal(err)
	}
	content, err := newDesiredSnapshot(cfg, desiredSnapshotProfile("B"), 4)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := newDesiredSnapshot(cfg, desiredSnapshotProfile("A"), 99)
	if err != nil {
		t.Fatal(err)
	}
	if base.DesiredRev == content.DesiredRev {
		t.Error("profile content change did not move DesiredRev")
	}
	if base.DesiredRev != generation.DesiredRev {
		t.Error("process-local profile generation changed stable DesiredRev")
	}
}

func TestDesiredSnapshotRevisionIgnoresCIDRRefreshClockButBindsCache(t *testing.T) {
	cfg := *config.Default()
	profile := desiredSnapshotProfile("A")
	profile.RoutingLists = []model.RoutingList{{
		ID: "auto-cidr", CIDRSource: "asn:64500", CIDRCache: []string{"192.0.2.0/24"},
		CIDRRefreshed: 100,
	}}
	base, err := newDesiredSnapshot(cfg, profile, 1)
	if err != nil {
		t.Fatal(err)
	}

	clockOnlyProfile := profile
	clockOnlyProfile.RoutingLists = append([]model.RoutingList(nil), profile.RoutingLists...)
	clockOnlyProfile.RoutingLists[0].CIDRRefreshed = 200
	clockOnly, err := newDesiredSnapshot(cfg, clockOnlyProfile, 2)
	if err != nil {
		t.Fatal(err)
	}
	if base.DesiredRev != clockOnly.DesiredRev {
		t.Fatal("scheduler-only CIDRRefreshed moved DesiredRev")
	}
	if clockOnly.Profile.RoutingLists[0].CIDRRefreshed != 200 {
		t.Fatal("captured execution profile lost its CIDR refresh timestamp")
	}
	if clockOnly.Inputs.Profile.RoutingLists[0].CIDRRefreshed != 0 {
		t.Fatal("canonical desired inputs retained scheduler-only CIDRRefreshed")
	}
	if profile.RoutingLists[0].CIDRRefreshed != 100 {
		t.Fatal("canonicalization mutated the caller's published profile")
	}

	cacheProfile := clockOnlyProfile
	cacheProfile.RoutingLists = append([]model.RoutingList(nil), clockOnlyProfile.RoutingLists...)
	cacheProfile.RoutingLists[0].CIDRCache = []string{"198.51.100.0/24"}
	cacheChanged, err := newDesiredSnapshot(cfg, cacheProfile, 3)
	if err != nil {
		t.Fatal(err)
	}
	if base.DesiredRev == cacheChanged.DesiredRev {
		t.Fatal("materialized CIDRCache change did not move DesiredRev")
	}
}

func TestDesiredSnapshotRevisionCanonicalizesEffectiveRoutingMode(t *testing.T) {
	profile := desiredSnapshotProfile("A")
	cases := []struct {
		name     string
		legacy   config.Config
		explicit config.Config
	}{
		{
			name: "mixed",
			legacy: func() config.Config {
				c := *config.Default()
				c.RoutingMode, c.Gateway = "", false
				return c
			}(),
			explicit: func() config.Config {
				c := *config.Default()
				c.RoutingMode, c.Gateway = "mixed", true // explicit mode wins; raw Gateway is irrelevant
				return c
			}(),
		},
		{
			name: "tun",
			legacy: func() config.Config {
				c := *config.Default()
				c.RoutingMode, c.Gateway = "", true
				return c
			}(),
			explicit: func() config.Config {
				c := *config.Default()
				c.RoutingMode, c.Gateway = "tun", false
				return c
			}(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			legacy, err := newDesiredSnapshot(tc.legacy, profile, 1)
			if err != nil {
				t.Fatal(err)
			}
			explicit, err := newDesiredSnapshot(tc.explicit, profile, 99)
			if err != nil {
				t.Fatal(err)
			}
			if legacy.DesiredRev != explicit.DesiredRev {
				t.Fatalf("equivalent effective modes differ: %q != %q", legacy.DesiredRev, explicit.DesiredRev)
			}
		})
	}
}

func TestDesiredSnapshotRevisionCoversEveryApplyDecisionInput(t *testing.T) {
	baseCfg := *config.Default()
	baseCfg.RoutingMode = "hybrid"
	baseCfg.Gateway = true
	baseCfg.GatewayMTU = 1400
	baseCfg.GatewayAddr = "172.31.3.1/30"
	baseCfg.OffloadDevices = []string{"wan", "br-lan"}
	profile := desiredSnapshotProfile("A")
	base, err := newDesiredSnapshot(baseCfg, profile, 9)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		edit func(*config.Config)
	}{
		{"transaction data directory", func(c *config.Config) { c.DataDir = "/opt/var/wayhop-next" }},
		{"routing mode", func(c *config.Config) { c.RoutingMode = "fast" }},
		{"gateway mtu", func(c *config.Config) { c.GatewayMTU = 1280 }},
		{"gateway address", func(c *config.Config) { c.GatewayAddr = "172.20.0.1/30" }},
		{"mixed port", func(c *config.Config) { c.Ports.Mixed++ }},
		{"managed clash port", func(c *config.Config) { c.Ports.Clash++ }},
		{"clash secret", func(c *config.Config) { c.Clash.Secret = "changed" }},
		{"sing-box binary", func(c *config.Config) { c.SingBox.Bin = "/opt/sbin/sing-box-next" }},
		{"sing-box config target", func(c *config.Config) { c.SingBox.Config = "/opt/etc/wayhop/next.json" }},
		{"demo", func(c *config.Config) { c.Demo = !c.Demo }},
		{"offload", func(c *config.Config) { c.Offload = "hw" }},
		{"offload devices", func(c *config.Config) { c.OffloadDevices = []string{"eth0"} }},
		// Regression guard for the concrete hole in appliedInputs: this changes generator.Options
		// and therefore emitted sing-box JSON, but the old canonicalHash did not include it.
		{"rule-set detour", func(c *config.Config) { c.RuleSetDetour = "edge" }},
		{"native firewall zone", func(c *config.Config) { c.NativeFirewallZone = "vpn" }},
		{"fail-safe target", func(c *config.Config) { c.FailSafe.Target = "9.9.9.9" }},
		{"fail-safe reboot policy", func(c *config.Config) { c.FailSafe.AutoReboot = !c.FailSafe.AutoReboot }},
	}
	legacyGateway := cloneDesiredConfig(baseCfg)
	legacyGateway.RoutingMode = ""
	legacyGateway.Gateway = false
	legacy, err := newDesiredSnapshot(legacyGateway, profile, 9)
	if err != nil {
		t.Fatal(err)
	}
	legacyGateway.Gateway = true
	legacyChanged, err := newDesiredSnapshot(legacyGateway, profile, 9)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.DesiredRev == legacyChanged.DesiredRev {
		t.Error("Gateway change did not move DesiredRev when it changes the effective legacy routing mode")
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cloneDesiredConfig(baseCfg)
			tc.edit(&cfg)
			got, err := newDesiredSnapshot(cfg, profile, 9)
			if err != nil {
				t.Fatal(err)
			}
			if got.DesiredRev == base.DesiredRev {
				t.Fatalf("%s change did not move DesiredRev", tc.name)
			}
		})
	}
}

func TestDesiredSnapshotRevisionIgnoresUnrelatedDaemonSettings(t *testing.T) {
	baseCfg := *config.Default()
	profile := desiredSnapshotProfile("A")
	base, err := newDesiredSnapshot(baseCfg, profile, 3)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		edit func(*config.Config)
	}{
		{"panel listen", func(c *config.Config) { c.Listen = "127.0.0.1:18088" }},
		{"panel port", func(c *config.Config) { c.Ports.UI++ }},
		{"host allow-list", func(c *config.Config) { c.AllowedHosts = []string{"wayhop.test"} }},
		{"updater mirror", func(c *config.Config) { c.Updater.Mirrors = []string{"https://mirror.test"} }},
		{"updater policy", func(c *config.Config) { c.Updater.AutoUpdate = true }},
		{"subscription url", func(c *config.Config) { c.Subscription.URL = "https://provider.test/private" }},
		{"backup destination", func(c *config.Config) { c.Backup.Dir = "/mnt/backup" }},
		{"notification secret", func(c *config.Config) { c.Watchdog.NotifyURL = "https://hook.test/token" }},
		{"deferred feature", func(c *config.Config) {
			c.Features = map[string]config.FeatureConfig{"iptv": {Enabled: true}}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cloneDesiredConfig(baseCfg)
			tc.edit(&cfg)
			got, err := newDesiredSnapshot(cfg, profile, 3)
			if err != nil {
				t.Fatal(err)
			}
			if got.DesiredRev != base.DesiredRev {
				t.Fatalf("unrelated %s change moved DesiredRev: %q != %q", tc.name, got.DesiredRev, base.DesiredRev)
			}
		})
	}
}

func TestDesiredSnapshotCaptureRetriesAcrossProfileConfigBarrier(t *testing.T) {
	profileA := desiredSnapshotProfile("A")
	profileB := desiredSnapshotProfile("B")
	s := desiredSnapshotServer(t, profileA)

	enteredConfigRead := make(chan struct{})
	releaseConfigRead := make(chan struct{})
	var configReads atomic.Int32
	src := desiredSnapshotReader{
		profileSnapshot: s.store.Snapshot,
		profileGen:      s.store.Gen,
		configSnapshot: func() config.Config {
			if configReads.Add(1) == 1 {
				close(enteredConfigRead)
				<-releaseConfigRead
			}
			return s.config()
		},
	}

	type result struct {
		snapshot DesiredSnapshot
		err      error
	}
	done := make(chan result, 1)
	go func() {
		snapshot, err := captureDesiredSnapshotFrom(src)
		done <- result{snapshot: snapshot, err: err}
	}()

	select {
	case <-enteredConfigRead:
	case <-time.After(5 * time.Second):
		close(releaseConfigRead)
		t.Fatal("capture never reached the deterministic config-read barrier")
	}
	if err := s.store.Replace(profileB); err != nil {
		close(releaseConfigRead)
		t.Fatalf("publish profile B: %v", err)
	}
	close(releaseConfigRead)

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("capture after retry: %v", got.err)
		}
		if configReads.Load() != 2 {
			t.Fatalf("config reads = %d, want exactly two attempts", configReads.Load())
		}
		if got.snapshot.ProfileGen != s.store.Gen() {
			t.Fatalf("captured gen = %d, current gen = %d", got.snapshot.ProfileGen, s.store.Gen())
		}
		if len(got.snapshot.Profile.Endpoints) != 1 || got.snapshot.Profile.Endpoints[0].Name != "B" {
			t.Fatalf("capture returned torn/stale profile instead of retried B: %+v", got.snapshot.Profile.Endpoints)
		}
		if got.snapshot.Inputs.Profile.Endpoints[0].Name != "B" {
			t.Fatalf("canonical inputs disagree with captured profile: %+v", got.snapshot.Inputs.Profile.Endpoints)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("capture did not finish after releasing the barrier")
	}
}

func TestDesiredSnapshotCaptureRetryIsBounded(t *testing.T) {
	profile := desiredSnapshotProfile("A")
	cfg := *config.Default()
	var snapshots atomic.Uint64
	var configReads atomic.Uint64
	src := desiredSnapshotReader{
		profileSnapshot: func() (model.Profile, uint64) {
			return profile, snapshots.Add(1)
		},
		configSnapshot: func() config.Config {
			configReads.Add(1)
			return cfg
		},
		profileGen: func() uint64 {
			return snapshots.Load() + 1 // every attempt observes a writer crossing the barrier
		},
	}

	_, err := captureDesiredSnapshotFrom(src)
	if !errors.Is(err, errDesiredSnapshotUnstable) {
		t.Fatalf("error = %v, want errDesiredSnapshotUnstable", err)
	}
	if snapshots.Load() != desiredSnapshotMaxAttempts || configReads.Load() != desiredSnapshotMaxAttempts {
		t.Fatalf("attempts snapshot/config = %d/%d, want %d/%d",
			snapshots.Load(), configReads.Load(), desiredSnapshotMaxAttempts, desiredSnapshotMaxAttempts)
	}
}

func TestDesiredSnapshotSurvivesLaterConfigAndStorePublications(t *testing.T) {
	profileA := desiredSnapshotProfile("A")
	s := desiredSnapshotServer(t, profileA)
	s.cfg.OffloadDevices = []string{"wan", "br-lan"}
	s.cfg.Features = map[string]config.FeatureConfig{
		"future": {Enabled: true, Settings: []byte(`{"mode":"a"}`)},
	}

	snapshot, err := s.captureDesiredSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.Replace(desiredSnapshotProfile("B")); err != nil {
		t.Fatalf("publish profile B: %v", err)
	}
	s.cfgMu.Lock()
	s.cfg.OffloadDevices = []string{"eth0"}
	feature := s.cfg.Features["future"]
	feature.Settings[9] = 'b'
	s.cfg.Features["future"] = feature
	s.cfgMu.Unlock()

	if snapshot.Profile.Endpoints[0].Name != "A" || snapshot.Inputs.Profile.Endpoints[0].Name != "A" {
		t.Fatalf("published profile B mutated captured profile A: %+v", snapshot.Profile.Endpoints)
	}
	if got := snapshot.Config.OffloadDevices; len(got) != 2 || got[0] != "wan" {
		t.Fatalf("later config publication mutated captured devices: %v", got)
	}
	if got := string(snapshot.Config.Features["future"].Settings); got != `{"mode":"a"}` {
		t.Fatalf("later raw-message mutation reached captured config: %q", got)
	}
}
