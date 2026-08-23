package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// DesiredSnapshotSchemaV1 is the canonical serialization contract for a desired-state revision.
// Bump it whenever DesiredInputsV1 changes meaning. The schema, not the WayHop/package version, is
// part of DesiredRev: installing an immutable v0.5.5-rN package must not manufacture a configuration
// change when the saved inputs are byte-for-byte equivalent.
const DesiredSnapshotSchemaV1 = 3

// desiredSnapshotMaxAttempts bounds the optimistic profile/config capture. A profile writer that
// continuously wins the barrier must make the caller retry later rather than spin forever while an
// HTTP handler holds resources (or, later, applyMu).
const desiredSnapshotMaxAttempts = 8

var errDesiredSnapshotUnstable = errors.New("desired state changed while it was being captured")

// DesiredInputsV1 is the explicit, canonical set of saved inputs that decide what Apply would
// materialize and how its safety window behaves. It intentionally excludes unrelated daemon/UI
// settings (listen/allowed-hosts, updater, subscriptions, backups, notifications and deferred
// features), so changing one of those cannot invalidate an otherwise identical Apply review.
//
// This value contains credentials through Profile and ClashSecret. It is hash input only: never
// return it from an API or include it in diagnostics/logs.
type DesiredInputsV1 struct {
	Profile model.Profile `json:"profile"`
	DataDir string        `json:"data_dir"`

	RoutingMode string `json:"routing_mode"`
	GatewayMTU  int    `json:"gateway_mtu"`
	GatewayAddr string `json:"gateway_addr"`

	MixedPort   int    `json:"mixed_port"`
	ClashAddr   string `json:"clash_addr"`
	ClashSecret string `json:"clash_secret"`

	SingBoxBin    string `json:"singbox_bin"`
	SingBoxConfig string `json:"singbox_config"`

	Demo               bool     `json:"demo"`
	Offload            string   `json:"offload"`
	OffloadDevices     []string `json:"offload_devices"`
	RuleSetDetour      string   `json:"rule_set_detour"`
	NativeFirewallZone string   `json:"native_firewall_zone"`

	FailSafeTarget     string `json:"failsafe_target"`
	FailSafeAutoReboot bool   `json:"failsafe_auto_reboot"`
}

// DesiredSnapshot is one immutable point-in-time view of the saved Apply inputs. Config and Profile
// are the exact values later planning/execution code must consume; ProfileGen binds the profile to the
// Store publication from which it came. Inputs is the canonical projection used for DesiredRev.
//
// The sensitive values are deliberately excluded from JSON. Accidentally serializing this struct in
// a future handler may expose the schema/revision, but never endpoint or Clash credentials.
type DesiredSnapshot struct {
	SchemaVersion int    `json:"schema_version"`
	DesiredRev    string `json:"desired_rev"`

	Config     config.Config   `json:"-"`
	Profile    model.Profile   `json:"-"`
	ProfileGen uint64          `json:"-"`
	Inputs     DesiredInputsV1 `json:"-"`
}

// desiredRevisionV1 is the only byte representation DesiredRev hashes. ProfileGen is deliberately
// absent: Store generations are process-local and reset on Open/reboot. Hashing one would make an
// unchanged persisted configuration acquire a new revision after restart. A content-identical ABA is
// semantically the same desired Apply; generation exists only to prove capture coherence.
type desiredRevisionV1 struct {
	SchemaVersion int             `json:"schema_version"`
	Inputs        DesiredInputsV1 `json:"inputs"`
}

// desiredSnapshotReader isolates the three reads needed by the optimistic capture. Production wires
// these directly to Store.Snapshot, Server.config and Store.Gen; tests place deterministic channel
// barriers between them so the torn-read retry contract is measured without sleeps.
type desiredSnapshotReader struct {
	profileSnapshot func() (model.Profile, uint64)
	configSnapshot  func() config.Config
	profileGen      func() uint64
}

// captureDesiredSnapshot captures an internally-consistent config/profile pair. Store.Snapshot gives
// an atomic (Profile, Gen). Bracketing the cfgMu-protected config read with the generation re-check
// proves there was a point during that read at which both values coexisted. A later writer may make
// the returned snapshot stale, but it cannot make the snapshot internally torn; the future CAS layer
// will reject that stale revision.
func (s *Server) captureDesiredSnapshot() (DesiredSnapshot, error) {
	if s == nil || s.cfg == nil || s.store == nil {
		return DesiredSnapshot{}, errors.New("desired snapshot source is unavailable")
	}
	return captureDesiredSnapshotFrom(desiredSnapshotReader{
		profileSnapshot: s.store.Snapshot,
		configSnapshot:  s.config,
		profileGen:      s.store.Gen,
	})
}

func captureDesiredSnapshotFrom(src desiredSnapshotReader) (DesiredSnapshot, error) {
	if src.profileSnapshot == nil || src.configSnapshot == nil || src.profileGen == nil {
		return DesiredSnapshot{}, errors.New("desired snapshot reader is incomplete")
	}
	for attempt := 0; attempt < desiredSnapshotMaxAttempts; attempt++ {
		profile, gen := src.profileSnapshot()
		cfg := src.configSnapshot()
		if src.profileGen() != gen {
			continue
		}
		return newDesiredSnapshot(cfg, profile, gen)
	}
	return DesiredSnapshot{}, fmt.Errorf("%w after %d attempts", errDesiredSnapshotUnstable, desiredSnapshotMaxAttempts)
}

func newDesiredSnapshot(cfg config.Config, profile model.Profile, profileGen uint64) (DesiredSnapshot, error) {
	// Server.config already gives callers a read-only value snapshot. Clone every reference field as
	// well so DesiredSnapshot remains self-contained even if a future config writer changes from the
	// current replace-whole-slice discipline to an in-place mutation.
	cfg = cloneDesiredConfig(cfg)
	inputs := desiredInputsV1(cfg, profile)
	rev, err := desiredRevision(inputs)
	if err != nil {
		return DesiredSnapshot{}, err
	}
	return DesiredSnapshot{
		SchemaVersion: DesiredSnapshotSchemaV1,
		DesiredRev:    rev,
		Config:        cfg,
		Profile:       profile,
		ProfileGen:    profileGen,
		Inputs:        inputs,
	}, nil
}

func desiredInputsV1(cfg config.Config, profile model.Profile) DesiredInputsV1 {
	return DesiredInputsV1{
		Profile: desiredProfileInputsV1(profile),
		// Apply persists its transaction-truth snapshot below DataDir. DataDir is currently hot
		// configuration, so changing it must invalidate a review even though Backup.Dir is unrelated.
		DataDir: cfg.DataDir,

		// Canonicalize the legacy representation (RoutingMode=="" derives from Gateway) to the
		// effective mode Apply actually uses. ""+Gateway and an equivalent explicit tun/mixed value
		// therefore have one revision instead of manufacturing a datapath change.
		RoutingMode: desiredRoutingMode(cfg),
		GatewayMTU:  cfg.GatewayMTU,
		GatewayAddr: cfg.GatewayAddr,

		MixedPort:   cfg.Ports.Mixed,
		ClashAddr:   managedClashAddress(cfg),
		ClashSecret: cfg.Clash.Secret,

		SingBoxBin:    cfg.SingBox.Bin,
		SingBoxConfig: cfg.SingBox.Config,

		Demo:               cfg.Demo,
		Offload:            cfg.Offload,
		OffloadDevices:     cloneDesiredStrings(cfg.OffloadDevices),
		RuleSetDetour:      cfg.RuleSetDetour,
		NativeFirewallZone: cfg.NativeFirewallZone,

		FailSafeTarget:     cfg.FailSafe.Target,
		FailSafeAutoReboot: cfg.FailSafe.AutoReboot,
	}
}

// managedClashAddress is where the WayHop-owned compatibility core binds its private Clash API.
// Config.Clash.Controller is a monitor/client target and may intentionally point at an independent
// router service. Reusing it as a bind address makes two unrelated cores fight over one listener.
func managedClashAddress(cfg config.Config) string {
	if cfg.Ports.Clash <= 0 || cfg.Ports.Clash > 65535 {
		return ""
	}
	return "127.0.0.1:" + strconv.Itoa(cfg.Ports.Clash)
}

// desiredProfileInputsV1 removes persisted scheduler metadata that cannot change what Apply
// materializes. CIDRRefreshed and DomainRefreshed only seed the background refresh clock; the
// CIDRCache and DomainCache they stamp remain exact datapath inputs and therefore stay in the
// revision. Copy the RoutingLists slice before clearing the scalars so the captured Profile and
// Store's published immutable value remain untouched.
//
// DomainRefreshed was missed when CIDRRefreshed was excluded, and a timestamp in the revision is a
// configuration change nobody can review: a names feed that re-fetched to a BYTE-IDENTICAL result
// still moved the hash, so the panel raised "You have unapplied changes — review them" over a
// changeset with nothing in it. Measured field by field: bumping DomainRefreshed alone moved the
// revision and produced zero review rows.
//
// The top-level collections are canonicalized to empty (never nil) slices. The store publishes them
// that way, but a baseline that arrived through JSON (an imported applied snapshot, a test fixture)
// may carry nil, and encoding/json spells the two differently ("null" vs "[]") — the same
// configuration would then hash to two revisions and read as "pending" forever.
func desiredProfileInputsV1(profile model.Profile) model.Profile {
	if profile.Endpoints == nil {
		profile.Endpoints = []model.Endpoint{}
	}
	if profile.Groups == nil {
		profile.Groups = []model.Group{}
	}
	if profile.Rules == nil {
		profile.Rules = []model.Rule{}
	}
	if profile.DeviceGroups == nil {
		profile.DeviceGroups = []model.DeviceGroup{}
	}
	if profile.RoutingLists == nil {
		profile.RoutingLists = []model.RoutingList{}
	}
	if len(profile.RoutingLists) == 0 {
		return profile
	}
	profile.RoutingLists = append([]model.RoutingList(nil), profile.RoutingLists...)
	for i := range profile.RoutingLists {
		profile.RoutingLists[i].CIDRRefreshed = 0
		profile.RoutingLists[i].DomainRefreshed = 0
	}
	return profile
}

func desiredRevision(inputs DesiredInputsV1) (string, error) {
	b, err := json.Marshal(desiredRevisionV1{
		SchemaVersion: DesiredSnapshotSchemaV1,
		Inputs:        inputs,
	})
	if err != nil {
		return "", fmt.Errorf("encode desired snapshot revision: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// desiredRoutingMode mirrors Server.routingMode without reading server state. Keeping revision
// construction pure lets the deterministic reader/barrier tests exercise it directly; the ATX
// integration slice should make Server.routingMode delegate here so the two cannot drift later.
func desiredRoutingMode(cfg config.Config) string {
	if cfg.RoutingMode != "" {
		return cfg.RoutingMode
	}
	if cfg.Gateway {
		return "tun"
	}
	return "mixed"
}

func cloneDesiredConfig(cfg config.Config) config.Config {
	cfg.OffloadDevices = cloneDesiredStrings(cfg.OffloadDevices)
	cfg.IgnoredDrift = cloneDesiredStrings(cfg.IgnoredDrift)
	cfg.AllowedHosts = cloneDesiredStrings(cfg.AllowedHosts)
	cfg.Updater.Mirrors = cloneDesiredStrings(cfg.Updater.Mirrors)
	if cfg.Features != nil {
		features := make(map[string]config.FeatureConfig, len(cfg.Features))
		for id, feature := range cfg.Features {
			feature.Settings = append(json.RawMessage(nil), feature.Settings...)
			features[id] = feature
		}
		cfg.Features = features
	}
	return cfg
}

func cloneDesiredStrings(in []string) []string {
	if in == nil {
		return nil
	}
	return append([]string(nil), in...)
}
