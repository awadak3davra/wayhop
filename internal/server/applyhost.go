package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// HostSnapshotSchemaV1 is the canonical host-observation contract. Bump it only when a
// decision-bearing field changes meaning or is added/removed.
const HostSnapshotSchemaV1 = 1

const (
	coreIdentityProbeTimeout = 8 * time.Second
	coreVersionOutputLimit   = 16 << 10
	hostCommandWaitDelay     = time.Second
)

const (
	coreStateUnset         = "unset"
	coreStateMissing       = "missing"
	coreStateNotExecutable = "not_executable"
	coreStateProbeFailed   = "probe_failed"
	coreStateReady         = "ready"
)

// reviewSHA256HexLen is the length of a lowercase hex SHA-256, the shape every content revision
// (desired rev, tool identity, running-config rev) in this package has.
const reviewSHA256HexLen = 64

// isLowerHexRevision reports whether value is exactly size lowercase hex characters.
func isLowerHexRevision(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for i := 0; i < len(value); i++ {
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}

// CoreRunnableIdentityV1 names and fingerprints the exact configured executable whose ability to
// run was evaluated. A same-version replacement still changes ContentSHA256, while a symlink/path
// change is visible through ConfiguredPath and ResolvedPath.
type CoreRunnableIdentityV1 struct {
	ConfiguredPath string `json:"configured_path"`
	ResolvedPath   string `json:"resolved_path,omitempty"`
	ContentSHA256  string `json:"content_sha256,omitempty"`
	Version        string `json:"version,omitempty"`
	Present        bool   `json:"present"`
	Runnable       bool   `json:"runnable"`
	State          string `json:"state"`
	ProbeError     string `json:"probe_error,omitempty"`
}

// HostSnapshotV1 is one self-contained observation of the host against one captured desired state.
// RawCapabilities preserves what the platform probe saw; CapabilitySet is the evaluated, fail-closed
// contract. RuntimeFacts and the explicit fields are kept together so later planning/execution code
// consumes this object rather than re-probing individual facts and accidentally mixing H1 with H2.
type HostSnapshotV1 struct {
	SchemaVersion int    `json:"schema_version"`
	DesiredRev    string `json:"desired_rev"`

	Platform        string                 `json:"platform"`
	RawCapabilities platform.Capabilities  `json:"raw_capabilities"`
	RuntimeFacts    platform.RuntimeFacts  `json:"runtime_facts"`
	CapabilitySet   platform.CapabilitySet `json:"capability_set"`
	Core            CoreRunnableIdentityV1 `json:"core"`

	KernelPBRAvailable bool                  `json:"kernel_pbr_available"`
	Accel              platform.Accel        `json:"accel"`
	OffloadState       platform.OffloadState `json:"offload_state"`
	ResolvedOffload    string                `json:"resolved_offload"`
	OffloadReason      string                `json:"offload_reason,omitempty"`
	OffloadDevices     []string              `json:"resolved_offload_devices"`
	IPv6Routable       bool                  `json:"ipv6_routable"`

	ProbedAt    time.Time `json:"probed_at"`
	ProbeError  string    `json:"probe_error,omitempty"`
	ProbeErrors []string  `json:"probe_errors,omitempty"`
}

// hostProbeV1 is the single value an injectable provider publishes. The capture calls its provider
// exactly once and derives every evaluated/canonical field from this one value.
type hostProbeV1 struct {
	Platform        string
	RawCapabilities platform.Capabilities
	Core            CoreRunnableIdentityV1

	KernelPBRAvailable bool
	Accel              platform.Accel
	OffloadState       platform.OffloadState
	ResolvedOffload    string
	OffloadReason      string
	OffloadDevices     []string
	NativeDNSRead      bool
	NativeDNSWrite     bool
	NativeOperations   map[string]bool
	IPv6Routable       bool

	ProbedAt    time.Time
	ProbeErrors []string
}

type hostSnapshotProvider interface {
	ProbeHost(context.Context, DesiredSnapshot) (hostProbeV1, error)
}

type hostSnapshotProviderFunc func(context.Context, DesiredSnapshot) (hostProbeV1, error)

func (f hostSnapshotProviderFunc) ProbeHost(ctx context.Context, desired DesiredSnapshot) (hostProbeV1, error) {
	return f(ctx, desired)
}

// captureHostSnapshot is the production entry point for a previously captured DesiredSnapshot. The
// provider performs fresh probes only: it deliberately does not call capabilitySet, accelKind,
// accelHW or kernelPBRAvailable, whose sync.Once/TTL caches cannot prove one coherent observation.
func (s *Server) captureHostSnapshot(ctx context.Context, desired DesiredSnapshot) (HostSnapshotV1, error) {
	if s == nil {
		return HostSnapshotV1{}, errors.New("host snapshot source is unavailable")
	}
	probe := s.probeHostSnapshot
	if s.hostProbeOf != nil {
		// Injected by tests: the real probe shells out to nft/sing-box/conntrack and reports the
		// developer host, so an Apply test could neither be deterministic nor exercise a router
		// platform. nil is always the real probe.
		probe = s.hostProbeOf
	}
	return captureHostSnapshotFrom(ctx, desired, hostSnapshotProviderFunc(probe))
}

func captureHostSnapshotFrom(ctx context.Context, desired DesiredSnapshot, provider hostSnapshotProvider) (HostSnapshotV1, error) {
	if ctx == nil {
		return HostSnapshotV1{}, errors.New("host snapshot context is nil")
	}
	if desired.SchemaVersion != DesiredSnapshotSchemaV1 || desired.DesiredRev == "" {
		return HostSnapshotV1{}, errors.New("host snapshot requires a captured desired snapshot")
	}
	if provider == nil {
		return HostSnapshotV1{}, errors.New("host snapshot provider is nil")
	}

	// Exactly one provider call is the H1/H2 barrier. A provider error is host evidence, not a reason
	// to discard the partial observation: it is folded into RuntimeFacts.ProbeError so Evaluate
	// poisons otherwise-supported capabilities to unknown and the caller fails closed.
	probe, probeErr := provider.ProbeHost(ctx, desired)
	return newHostSnapshot(desired, probe, probeErr)
}

func newHostSnapshot(desired DesiredSnapshot, probe hostProbeV1, providerErr error) (HostSnapshotV1, error) {
	raw := cloneHostCapabilities(probe.RawCapabilities)
	platformName := strings.TrimSpace(probe.Platform)
	if platformName == "" {
		platformName = strings.TrimSpace(raw.Platform)
	}
	if platformName == "" {
		platformName = string(platform.Unknown)
	}

	errs := append([]string(nil), probe.ProbeErrors...)
	if providerErr != nil {
		errs = append(errs, providerErr.Error())
	}
	if raw.Platform == "" {
		raw.Platform = platformName
	} else if raw.Platform != platformName {
		errs = append(errs, "platform probe disagreed with raw capabilities")
	}
	if probe.Core.ConfiguredPath != strings.TrimSpace(desired.Config.SingBox.Bin) {
		errs = append(errs, "core probe did not use the captured configured binary")
	}
	if probe.OffloadState.Requested != desired.Config.Offload {
		errs = append(errs, "offload probe did not use the captured requested mode")
	}
	configuredCore := strings.TrimSpace(desired.Config.SingBox.Bin)
	coreReady := probe.Core.Present && probe.Core.Runnable && probe.Core.State == coreStateReady &&
		probe.Core.ResolvedPath != "" && isLowerHexRevision(probe.Core.ContentSHA256, 64) &&
		strings.TrimSpace(probe.Core.Version) != ""
	if (probe.Core.Runnable || probe.Core.State == coreStateReady) && !coreReady {
		errs = append(errs, "configured core was marked ready without a complete identity")
	}
	if probe.Core.State == coreStateProbeFailed {
		errs = append(errs, "configured core identity could not be verified")
	}
	if configuredCore != "" && probe.Core.State == coreStateUnset {
		errs = append(errs, "configured core probe returned no state")
	}
	errs = canonicalHostStrings(errs)
	probeError := strings.Join(errs, "; ")

	// Accel is the decision fact (including the demo override); RawCapabilities remains the unedited
	// platform observation. The evaluator consumes the decision fact so it cannot disagree with the
	// offload resolver or later materialization.
	evalCaps := cloneHostCapabilities(raw)
	evalCaps.Platform = platformName
	evalCaps.Accel = probe.Accel
	evalCaps.SingboxPresent = evalCaps.SingboxPresent || probe.Core.Present

	runtimeFacts := platform.RuntimeFacts{
		KernelPBRWired:   probe.KernelPBRAvailable,
		SingboxRunnable:  probe.Core.Runnable,
		SingboxVersion:   probe.Core.Version,
		NativeDNSRead:    probe.NativeDNSRead,
		NativeDNSWrite:   probe.NativeDNSWrite,
		NativeOperations: cloneHostBoolMap(probe.NativeOperations),
		IPv6Routable:     probe.IPv6Routable,
		ProbeError:       probeError,
		ProbedAt:         probe.ProbedAt,
	}
	capabilitySet := platform.Evaluate(evalCaps, runtimeFacts)
	devices := canonicalHostStrings(probe.OffloadDevices)
	offloadState := cloneHostOffloadState(probe.OffloadState)

	snapshot := HostSnapshotV1{
		SchemaVersion:      HostSnapshotSchemaV1,
		DesiredRev:         desired.DesiredRev,
		Platform:           platformName,
		RawCapabilities:    raw,
		RuntimeFacts:       runtimeFacts,
		CapabilitySet:      capabilitySet,
		Core:               probe.Core,
		KernelPBRAvailable: probe.KernelPBRAvailable,
		Accel:              probe.Accel,
		OffloadState:       offloadState,
		ResolvedOffload:    probe.ResolvedOffload,
		OffloadReason:      probe.OffloadReason,
		OffloadDevices:     devices,
		IPv6Routable:       probe.IPv6Routable,
		ProbedAt:           probe.ProbedAt,
		ProbeError:         probeError,
		ProbeErrors:        errs,
	}
	return snapshot, nil
}

// probeHostSnapshot performs each live observation once and only against desired.Config. It must not
// call s.config(): the caller has already captured the configuration that this host observation will
// be paired with.
func (s *Server) probeHostSnapshot(ctx context.Context, desired DesiredSnapshot) (hostProbeV1, error) {
	cfg := desired.Config
	probedAt := time.Now().UTC()
	// Synthetic facts are valid only for the off-router demo plane. A config accidentally left in
	// demo mode on real OpenWrt/Keenetic hardware must never bypass that router's capability probes.
	if cfg.Demo && platform.Detect() == platform.Unknown {
		return demoHostProbe(desired, probedAt), nil
	}
	raw, capabilityProbeErrors := platform.DetectCapabilitiesObservedContext(ctx)
	platformName := raw.Platform

	accel := raw.Accel
	evalCaps := cloneHostCapabilities(raw)
	evalCaps.Accel = accel

	coreIdentity, coreErr := probeConfiguredCore(ctx, cfg.SingBox.Bin)
	// Reaching the real-host branch means demo is not allowed to synthesize host facts. The kernel
	// probe intentionally has no demo bypass parameter, so a stale flag cannot skip this check.
	kernelPBR, kernelProbeErr := probeKernelPBRFresh(ctx, s, platformName)
	resolvedOffload, offloadReason := resolveHostOffload(desired, evalCaps)
	offloadState, observationErrors := observeEffectiveOffloadContext(ctx, cfg.Offload, pbrKernelTable)
	if offloadReason != "" {
		offloadState.Reasons = append(offloadState.Reasons, offloadReason)
	}
	// Runtime offload evidence informs review copy, including stale flowtables while transitioning
	// away from fast mode, but it does not decide whether a requested flowtable can be materialized.
	// Keep failures visible without poisoning unrelated engine/protocol capabilities globally.
	offloadState.Reasons = uniqueApplyHostErrors(append(offloadState.Reasons, observationErrors...))

	var devices []string
	var deviceProbeErrors []string
	if desiredRoutingMode(cfg) == "fast" && (resolvedOffload == "sw" || resolvedOffload == "hw") {
		devices = cloneDesiredStrings(cfg.OffloadDevices)
		if len(devices) == 0 {
			devices, deviceProbeErrors = probeAutoOffloadDevicesContext(ctx)
		}
	}

	nativeDNSRead := platformName == string(platform.OpenWrt) || platformName == string(platform.Keenetic)
	probe := hostProbeV1{
		Platform:           platformName,
		RawCapabilities:    raw,
		Core:               coreIdentity,
		KernelPBRAvailable: kernelPBR,
		Accel:              accel,
		OffloadState:       offloadState,
		ResolvedOffload:    resolvedOffload,
		OffloadReason:      offloadReason,
		OffloadDevices:     devices,
		NativeDNSRead:      nativeDNSRead,
		NativeDNSWrite:     false,
		IPv6Routable:       hasRoutableIPv6(),
		ProbedAt:           probedAt,
		ProbeErrors:        capabilityProbeErrors,
		NativeOperations:   cloneHostBoolMap(s.nativeOperations),
	}
	if coreErr != nil {
		probe.ProbeErrors = append(probe.ProbeErrors, coreErr.Error())
	}
	if kernelProbeErr != nil {
		probe.ProbeErrors = append(probe.ProbeErrors, kernelProbeErr.Error())
	}
	probe.ProbeErrors = append(probe.ProbeErrors, deviceProbeErrors...)
	return probe, nil
}

// demoHostProbe is a deterministic, explicitly synthetic observation used only after the caller has
// established that this is an unknown/off-router host. Probing the developer host would turn an
// expected missing nft/ndmc or sing-box binary into UNKNOWN and make the demo impossible to review.
// The demo URI and digest make the synthetic core unmistakable while preserving the same
// complete-identity invariant as a real executable.
func demoHostProbe(desired DesiredSnapshot, probedAt time.Time) hostProbeV1 {
	cfg := desired.Config
	raw := platform.DemoCapabilities()
	resolvedOffload, offloadReason := resolveHostOffload(desired, raw)
	devices := cloneDesiredStrings(cfg.OffloadDevices)
	if desiredRoutingMode(cfg) == "fast" && (resolvedOffload == "sw" || resolvedOffload == "hw") && len(devices) == 0 {
		devices = []string{"wan", "br-lan"}
	}
	digest := sha256.Sum256([]byte("wayhop-demo-sing-box-v1"))
	offloadState := platform.OffloadState{
		Requested:   cfg.Offload,
		Configured:  resolvedOffload,
		Effective:   resolvedOffload,
		MarkedPlane: desiredRoutingMode(cfg) == "fast" || desiredRoutingMode(cfg) == "hybrid",
	}
	if offloadReason != "" {
		offloadState.Reasons = []string{offloadReason}
	}
	return hostProbeV1{
		Platform:        raw.Platform,
		RawCapabilities: raw,
		Core: CoreRunnableIdentityV1{
			ConfiguredPath: strings.TrimSpace(cfg.SingBox.Bin),
			ResolvedPath:   "demo://sing-box",
			ContentSHA256:  hex.EncodeToString(digest[:]),
			Version:        "sing-box version 0.0.0-demo",
			Present:        true,
			Runnable:       true,
			State:          coreStateReady,
		},
		KernelPBRAvailable: true,
		Accel:              raw.Accel,
		OffloadState:       offloadState,
		ResolvedOffload:    resolvedOffload,
		OffloadReason:      offloadReason,
		OffloadDevices:     devices,
		NativeDNSRead:      true,
		NativeDNSWrite:     false,
		IPv6Routable:       true,
		ProbedAt:           probedAt,
	}
}

func resolveHostOffload(desired DesiredSnapshot, caps platform.Capabilities) (string, string) {
	if desiredRoutingMode(desired.Config) != "fast" {
		return "off", "flow offload is only materialized in fast routing mode"
	}
	return platform.ResolveOffload(desired.Config.Offload, caps)
}

// probeKernelPBRFresh checks the actual nft/kernel transaction path without changing the ruleset.
// A binary merely present on PATH is not evidence that its kernel/netlink path can compile the
// table/chain shape Apply needs.
func probeKernelPBRFresh(ctx context.Context, s *Server, platformName string) (bool, error) {
	// Non-exec runners are test/dry-run planes and deliberately remain available, matching the
	// existing apply behavior. Production New wires pbr.ExecRunner.
	if s != nil {
		if _, isExec := s.pbrRunner.(pbr.ExecRunner); !isExec {
			return true, nil
		}
	}
	if platformName == string(platform.Keenetic) {
		// KeeneticOS has no nftables, so the nft probe below can never answer for it. Its plane is
		// ipset + iptables mangle; both binaries present is the honest availability answer, and the
		// executor authenticates their exact identities before it runs anything. Probing by
		// presence only — no dry-run — because iptables has no --check for a whole ruleset and a
		// mutating probe on a live router is not acceptable to answer a capability question.
		return keeneticKernelPBRPresent(), nil
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return false, nil
		}
		return false, errors.New("kernel policy-routing executable lookup failed")
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	table := fmt.Sprintf("wayhop_probe_%d", os.Getpid())
	script := (&pbr.Plan{Table: table, Mask: 0x00ff0000}).RenderNft()
	var stdout, stderr cappedHostOutput
	cmd := exec.CommandContext(probeCtx, nft, "--check", "--file", "-")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = strings.NewReader(script), &stdout, &stderr
	cmd.WaitDelay = hostCommandWaitDelay
	err = cmd.Run()
	if probeCtx.Err() != nil {
		return false, errors.New("kernel policy-routing capability probe timed out")
	}
	if stdout.Truncated() || stderr.Truncated() {
		return false, errors.New("kernel policy-routing capability probe output exceeded the safety limit")
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		return false, errors.New("kernel policy-routing capability probe did not terminate cleanly")
	}
	if err != nil {
		return false, errors.New("kernel policy-routing capability probe failed")
	}
	return true, nil
}

// probeConfiguredCore fingerprints and runs the exact configured binary. The before/after identity
// check turns a replacement during the probe into a global probe error rather than a digest from H1
// paired with a version from H2.
func probeConfiguredCore(ctx context.Context, configured string) (CoreRunnableIdentityV1, error) {
	configured = strings.TrimSpace(configured)
	id := CoreRunnableIdentityV1{ConfiguredPath: configured, State: coreStateUnset}
	if configured == "" {
		return id, nil
	}

	located := configured
	var err error
	// LookPath intentionally rejects a non-executable file as if it were absent. For an explicit
	// configured path, resolve and stat it ourselves so the UI can distinguish missing from present
	// but not executable; only a bare command name is searched through PATH.
	if !filepath.IsAbs(configured) && !strings.ContainsRune(configured, os.PathSeparator) {
		located, err = exec.LookPath(configured)
		if err != nil {
			if errors.Is(err, exec.ErrNotFound) {
				id.State = coreStateMissing
				id.ProbeError = "configured sing-box binary was not found"
			} else {
				id.State = coreStateProbeFailed
				id.ProbeError = "configured sing-box binary lookup failed"
			}
			return id, nil
		}
	}
	abs, absErr := filepath.Abs(located)
	if absErr != nil {
		id.State = coreStateProbeFailed
		id.ProbeError = "configured sing-box path could not be normalized"
		return id, nil
	}
	located = abs
	resolved, err := filepath.EvalSymlinks(located)
	if err != nil {
		if os.IsNotExist(err) {
			id.State = coreStateMissing
			id.ProbeError = "configured sing-box binary was not found"
			return id, nil
		}
		id.State = coreStateProbeFailed
		id.ProbeError = "configured sing-box path could not be resolved"
		return id, nil
	}
	id.ResolvedPath = resolved

	before, err := os.Stat(resolved)
	if err != nil {
		if os.IsNotExist(err) {
			id.State = coreStateMissing
			id.ProbeError = "configured sing-box binary was not found"
		} else {
			id.State = coreStateProbeFailed
			id.ProbeError = "configured sing-box file metadata could not be read"
		}
		return id, nil
	}
	if !before.Mode().IsRegular() {
		id.State = coreStateMissing
		id.ProbeError = "configured sing-box binary is not a regular file"
		return id, nil
	}
	id.Present = true
	if before.Mode()&0o111 == 0 {
		id.State = coreStateNotExecutable
		id.ProbeError = "configured sing-box binary is not executable"
		return id, nil
	}

	probeCtx, cancelProbe := context.WithTimeout(ctx, coreIdentityProbeTimeout)
	defer cancelProbe()
	digest, err := sha256FileContext(probeCtx, resolved)
	if err != nil {
		id.State = coreStateProbeFailed
		id.ProbeError = "configured sing-box binary could not be fingerprinted"
		return id, nil
	}
	id.ContentSHA256 = digest

	var stdout, stderr cappedHostOutput
	cmd := exec.CommandContext(probeCtx, resolved, "version")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = hostCommandWaitDelay
	versionErr := cmd.Run()
	version := strings.TrimSpace(stdout.String() + "\n" + stderr.String())
	if stdout.Truncated() || stderr.Truncated() {
		versionErr = errors.New("configured sing-box version output exceeded the safety limit")
	}
	afterRun, statErr := os.Stat(resolved)
	if statErr != nil || !sameHostFile(before, afterRun) {
		id.State = coreStateProbeFailed
		id.ProbeError = "configured sing-box binary changed during the identity probe"
		return id, errors.New(id.ProbeError)
	}
	if versionErr != nil || !validSingBoxVersionOutput(version) {
		id.State = coreStateProbeFailed
		if versionErr != nil {
			id.ProbeError = "configured sing-box version probe failed"
		} else {
			id.ProbeError = "configured binary did not report a valid sing-box version identity"
		}
		return id, nil
	}
	// Hash again after executing `version`. Inode/size/mtime catches ordinary atomic replacement,
	// while the second digest also catches an in-place same-size rewrite whose timestamp was restored.
	// Without both checks a digest from H1 could be paired with a version emitted by H2.
	digestAfter, digestErr := sha256FileContext(probeCtx, resolved)
	final, finalStatErr := os.Stat(resolved)
	if digestErr != nil || finalStatErr != nil || !sameHostFile(afterRun, final) || digestAfter != digest {
		id.State = coreStateProbeFailed
		id.ProbeError = "configured sing-box binary changed during the identity probe"
		return id, errors.New(id.ProbeError)
	}
	id.Version = version
	id.Runnable = true
	id.State = coreStateReady
	return id, nil
}

func sameHostFile(before, after os.FileInfo) bool {
	return before != nil && after != nil && os.SameFile(before, after) &&
		before.Size() == after.Size() && before.ModTime().Equal(after.ModTime()) &&
		before.Mode() == after.Mode()
}

func validSingBoxVersionOutput(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 || fields[0] != "sing-box" || fields[1] != "version" {
			continue
		}
		token := fields[2]
		base := token
		if i := strings.IndexAny(base, "-+"); i >= 0 {
			base = base[:i]
		}
		parts := strings.Split(base, ".")
		if len(parts) != 3 {
			continue
		}
		valid := true
		for _, part := range parts {
			if part == "" {
				valid = false
				break
			}
			for i := 0; i < len(part); i++ {
				if part[i] < '0' || part[i] > '9' {
					valid = false
					break
				}
			}
		}
		if valid {
			return true
		}
	}
	return false
}

func sha256FileContext(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, readErr := f.Read(buf)
		if n > 0 {
			_, _ = h.Write(buf[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", readErr
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// cappedHostOutput consumes all child output while retaining only a bounded prefix. Returning the
// full write length avoids SIGPIPE behavior; the context deadline still terminates a child that
// floods output forever.
type cappedHostOutput struct {
	data      []byte
	truncated bool
}

func (b *cappedHostOutput) Write(p []byte) (int, error) {
	written := len(p)
	remaining := coreVersionOutputLimit - len(b.data)
	if remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		b.data = append(b.data, p[:remaining]...)
	}
	if remaining < len(p) {
		b.truncated = true
	}
	return written, nil
}

func (b *cappedHostOutput) String() string  { return string(b.data) }
func (b *cappedHostOutput) Truncated() bool { return b.truncated }

func cloneHostCapabilities(c platform.Capabilities) platform.Capabilities {
	c.Native = cloneHostBoolMap(c.Native)
	c.Installable = cloneHostStringMap(c.Installable)
	c.SingboxRequired = canonicalHostStrings(c.SingboxRequired)
	c.InstallCmds = cloneHostStringMap(c.InstallCmds)
	c.Legacy = cloneHostStringMap(c.Legacy)
	c.NetifdProtos = cloneHostBoolMap(c.NetifdProtos)
	return c
}

func cloneHostOffloadState(s platform.OffloadState) platform.OffloadState {
	s.Reasons = cloneDesiredStrings(s.Reasons)
	return s
}

func cloneHostBoolMap(in map[string]bool) map[string]bool {
	if in == nil {
		return nil
	}
	out := make(map[string]bool, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneHostStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func canonicalHostStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
