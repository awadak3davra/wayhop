package server

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

func hostTestDesired(t *testing.T) DesiredSnapshot {
	t.Helper()
	cfg := *config.Default()
	cfg.RoutingMode = "fast"
	cfg.Offload = "auto"
	cfg.SingBox.Bin = "/opt/sbin/sing-box"
	desired, err := newDesiredSnapshot(cfg, model.Profile{}, 7)
	if err != nil {
		t.Fatalf("desired snapshot: %v", err)
	}
	return desired
}

func hostTestProbe(desired DesiredSnapshot) hostProbeV1 {
	return hostProbeV1{
		Platform: "openwrt",
		RawCapabilities: platform.Capabilities{
			Platform: "openwrt",
			Native: map[string]bool{
				"wireguard": true,
				"openvpn":   true,
			},
			Installable: map[string]string{
				"amneziawg": "kmod-amneziawg",
			},
			SingboxRequired: []string{"vless", "trojan"},
			SingboxPresent:  true,
			PackageManager:  "apk",
			InstallCmds: map[string]string{
				"amneziawg": "apk add kmod-amneziawg",
			},
			Legacy: map[string]string{
				"openvpn": "legacy warning",
			},
			Accel: platform.Accel{Kind: "nft-flowtable", HW: true},
			NetifdProtos: map[string]bool{
				"wireguard": true,
			},
		},
		Core: CoreRunnableIdentityV1{
			ConfiguredPath: desired.Config.SingBox.Bin,
			ResolvedPath:   "/opt/sbin/sing-box",
			ContentSHA256:  strings.Repeat("a", 64),
			Version:        "sing-box version 1.12.0\nTags: with_quic",
			Present:        true,
			Runnable:       true,
			State:          coreStateReady,
		},
		KernelPBRAvailable: true,
		Accel:              platform.Accel{Kind: "nft-flowtable", HW: true},
		OffloadState: platform.OffloadState{
			Requested: "auto", Configured: "hw", Effective: "hw",
			UCIKnown: true, NftKnown: true, KnobsKnown: true, FlowsKnown: true,
			Flowtable: true, FlowtableHW: true, PPEEnabled: true, FastNATOn: true,
			MarkedPlane: true, FlowsTotal: 12, FlowsOffl: 8, FlowsHW: 5,
			Reasons: []string{"hardware flows observed", "requested auto resolved to hw"},
		},
		ResolvedOffload: "hw",
		OffloadReason:   "hardware flow-offload is supported",
		OffloadDevices:  []string{"wan", "br-lan"},
		NativeDNSRead:   true,
		NativeDNSWrite:  false,
		IPv6Routable:    true,
		ProbedAt:        time.Unix(1_700_000_000, 0).UTC(),
	}
}

func cloneHostTestProbe(in hostProbeV1) hostProbeV1 {
	out := in
	out.RawCapabilities = cloneHostCapabilities(in.RawCapabilities)
	out.OffloadState = cloneHostOffloadState(in.OffloadState)
	out.OffloadDevices = cloneDesiredStrings(in.OffloadDevices)
	out.NativeOperations = cloneHostBoolMap(in.NativeOperations)
	out.ProbeErrors = cloneDesiredStrings(in.ProbeErrors)
	return out
}

func TestDemoHostSnapshotIsDeterministicAndDoesNotProbeDeveloperHost(t *testing.T) {
	cfg := *config.Default()
	cfg.Demo = true
	cfg.RoutingMode = "fast"
	cfg.Offload = "auto"
	cfg.OffloadDevices = nil
	cfg.SingBox.Bin = "/definitely/missing/sing-box"
	desired, err := newDesiredSnapshot(cfg, model.Profile{}, 1)
	if err != nil {
		t.Fatalf("desired snapshot: %v", err)
	}

	server := &Server{}
	firstProbe, err := server.probeHostSnapshot(context.Background(), desired)
	if err != nil {
		t.Fatalf("first demo probe: %v", err)
	}
	secondProbe, err := server.probeHostSnapshot(context.Background(), desired)
	if err != nil {
		t.Fatalf("second demo probe: %v", err)
	}
	first, err := newHostSnapshot(desired, firstProbe, nil)
	if err != nil {
		t.Fatalf("first demo snapshot: %v", err)
	}
	second, err := newHostSnapshot(desired, secondProbe, nil)
	if err != nil {
		t.Fatalf("second demo snapshot: %v", err)
	}

	if first.ProbeError != "" || len(first.ProbeErrors) != 0 {
		t.Fatalf("demo snapshot inherited developer-host probe errors: %+v", first.ProbeErrors)
	}
	if first.Platform != string(platform.OpenWrt) || !first.Core.Present || !first.Core.Runnable ||
		first.Core.State != coreStateReady || first.Core.ResolvedPath != "demo://sing-box" {
		t.Fatalf("demo host identity is incomplete: %+v", first)
	}
	if !first.CapabilitySet.Usable(platform.CapEngineSingbox) ||
		!first.CapabilitySet.Usable(platform.CapRoutingModeFast) {
		t.Fatalf("demo capabilities are unexpectedly blocked: %+v", first.CapabilitySet.Items)
	}
	if first.ResolvedOffload != "hw" || strings.Join(first.OffloadDevices, ",") != "br-lan,wan" {
		t.Fatalf("demo offload resolution = %q %v, want hw [br-lan wan]", first.ResolvedOffload, first.OffloadDevices)
	}
	if first.CapabilitySet.Rev == "" || first.CapabilitySet.Rev != second.CapabilitySet.Rev {
		t.Fatalf("demo capability revision is not stable: %q != %q", first.CapabilitySet.Rev, second.CapabilitySet.Rev)
	}
}

func TestHostSnapshotCaptureCallsProviderOnceAndCannotMixH1H2(t *testing.T) {
	desired := hostTestDesired(t)
	h1 := hostTestProbe(desired)
	h2 := cloneHostTestProbe(h1)
	h2.Platform = "keenetic"
	h2.RawCapabilities.Platform = "keenetic"
	h2.Core.Version = "sing-box version H2"
	h2.Core.ContentSHA256 = strings.Repeat("b", 64)
	h2.KernelPBRAvailable = false
	h2.Accel = platform.Accel{Kind: "ppe", HW: true}
	h2.OffloadState.Effective = "off"
	h2.ResolvedOffload = "off"
	h2.OffloadDevices = []string{"br0"}
	h2.IPv6Routable = false

	var mu sync.Mutex
	current := h1
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	provider := hostSnapshotProviderFunc(func(_ context.Context, gotDesired DesiredSnapshot) (hostProbeV1, error) {
		if gotDesired.DesiredRev != desired.DesiredRev || gotDesired.Config.SingBox.Bin != desired.Config.SingBox.Bin {
			return hostProbeV1{}, errors.New("provider received a different desired snapshot")
		}
		calls.Add(1)
		mu.Lock()
		captured := cloneHostTestProbe(current)
		mu.Unlock()
		close(entered)
		<-release
		return captured, nil
	})

	type result struct {
		snapshot HostSnapshotV1
		err      error
	}
	done := make(chan result, 1)
	go func() {
		snapshot, err := captureHostSnapshotFrom(context.Background(), desired, provider)
		done <- result{snapshot: snapshot, err: err}
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("provider never reached the deterministic H1/H2 barrier")
	}
	mu.Lock()
	current = h2
	mu.Unlock()
	close(release)

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("capture: %v", got.err)
		}
		if calls.Load() != 1 {
			t.Fatalf("provider calls = %d, want exactly one", calls.Load())
		}
		if got.snapshot.Platform != h1.Platform || got.snapshot.RawCapabilities.Platform != h1.RawCapabilities.Platform {
			t.Fatalf("platform mixed across observations: %+v", got.snapshot)
		}
		if got.snapshot.Core.Version != h1.Core.Version || got.snapshot.Core.ContentSHA256 != h1.Core.ContentSHA256 {
			t.Fatalf("core identity mixed across observations: %+v", got.snapshot.Core)
		}
		if !got.snapshot.KernelPBRAvailable || got.snapshot.Accel.Kind != h1.Accel.Kind ||
			got.snapshot.OffloadState.Effective != h1.OffloadState.Effective || !got.snapshot.IPv6Routable {
			t.Fatalf("decision facts mixed H1/H2: %+v", got.snapshot)
		}
		if strings.Join(got.snapshot.OffloadDevices, ",") != "br-lan,wan" {
			t.Fatalf("resolved devices = %v, want canonical H1 devices", got.snapshot.OffloadDevices)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("capture did not finish after releasing the provider")
	}
}

func TestHostSnapshotRejectsIncompleteRunnableCoreIdentity(t *testing.T) {
	desired := hostTestDesired(t)
	for name, edit := range map[string]func(*CoreRunnableIdentityV1){
		"not present":     func(c *CoreRunnableIdentityV1) { c.Present = false },
		"missing version": func(c *CoreRunnableIdentityV1) { c.Version = "" },
		"invalid digest":  func(c *CoreRunnableIdentityV1) { c.ContentSHA256 = "not-a-sha256" },
		"wrong state":     func(c *CoreRunnableIdentityV1) { c.State = coreStateProbeFailed },
	} {
		t.Run(name, func(t *testing.T) {
			probe := hostTestProbe(desired)
			edit(&probe.Core)
			snapshot, err := newHostSnapshot(desired, probe, nil)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.ProbeError == "" || snapshot.CapabilitySet.ProbeError == "" {
				t.Fatalf("incomplete ready core was not failed closed: %+v", snapshot.Core)
			}
			if got := snapshot.CapabilitySet.Get(platform.CapEngineSingbox); got.State != platform.CapUnknown {
				t.Fatalf("engine capability = %q, want unknown", got.State)
			}
		})
	}
}

func TestHostSnapshotProviderErrorPoisonsCapabilitiesFailClosed(t *testing.T) {
	desired := hostTestDesired(t)
	probe := hostTestProbe(desired)
	provider := hostSnapshotProviderFunc(func(context.Context, DesiredSnapshot) (hostProbeV1, error) {
		return probe, errors.New("ndmc timed out")
	})

	failed, err := captureHostSnapshotFrom(context.Background(), desired, provider)
	if err != nil {
		t.Fatalf("provider failure must be represented in the fail-closed snapshot: %v", err)
	}
	if !strings.Contains(failed.ProbeError, "ndmc timed out") || failed.CapabilitySet.ProbeError == "" {
		t.Fatalf("probe error not carried through snapshot/evaluator: %+v", failed)
	}
	for _, id := range []string{platform.CapRoutingModeTun, platform.CapEngineSingbox, platform.CapIPv6Routing} {
		capability := failed.CapabilitySet.Get(id)
		if capability.State != platform.CapUnknown || capability.State.Usable() {
			t.Fatalf("%s = %q after probe error, want fail-closed unknown", id, capability.State)
		}
	}

	clean, err := newHostSnapshot(desired, probe, nil)
	if err != nil {
		t.Fatal(err)
	}
	if failed.CapabilitySet.Rev == clean.CapabilitySet.Rev {
		t.Fatal("probe failure did not move the capability revision")
	}
}

func TestHostSnapshotOwnsProviderMapsAndSlices(t *testing.T) {
	desired := hostTestDesired(t)
	probe := hostTestProbe(desired)
	operationID := platform.NativeOperationCapabilityID("amneziawg", platform.NativeCreate)
	probe.NativeOperations = map[string]bool{operationID: true}
	snapshot, err := newHostSnapshot(desired, probe, nil)
	if err != nil {
		t.Fatal(err)
	}

	probe.RawCapabilities.Native["wireguard"] = false
	probe.RawCapabilities.SingboxRequired[0] = "mutated"
	probe.OffloadState.Reasons[0] = "mutated"
	probe.OffloadDevices[0] = "mutated"
	probe.NativeOperations[operationID] = false
	if !snapshot.RawCapabilities.Native["wireguard"] || snapshot.RawCapabilities.SingboxRequired[0] == "mutated" {
		t.Fatal("provider capability mutation reached captured snapshot")
	}
	if snapshot.OffloadState.Reasons[0] == "mutated" || snapshot.OffloadDevices[0] == "mutated" {
		t.Fatal("provider offload mutation reached captured snapshot")
	}
	if !snapshot.RuntimeFacts.NativeOperations[operationID] {
		t.Fatal("provider native-operation mutation reached captured snapshot")
	}
}

func TestProbeConfiguredCoreUsesContentIdentityNotOnlyVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX executable script")
	}
	path := t.TempDir() + "/sing-box"
	write := func(comment string) {
		t.Helper()
		body := "#!/bin/sh\n# " + comment + "\necho 'sing-box version 1.12.0'\n"
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("binary A")
	a, err := probeConfiguredCore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	write("binary B with different content")
	b, err := probeConfiguredCore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Runnable || !b.Runnable || a.Version != b.Version {
		t.Fatalf("test binaries must be runnable with the same version: A=%+v B=%+v", a, b)
	}
	if a.ContentSHA256 == b.ContentSHA256 {
		t.Fatal("same-version binary replacement kept the same content identity")
	}
}

func TestProbeConfiguredCoreDistinguishesMissingAndNotExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test asserts POSIX executable permissions")
	}
	missing, err := probeConfiguredCore(context.Background(), t.TempDir()+"/missing")
	if err != nil {
		t.Fatal(err)
	}
	if missing.State != coreStateMissing || missing.Present || missing.Runnable {
		t.Fatalf("missing core identity = %+v", missing)
	}

	path := t.TempDir() + "/sing-box"
	if err := os.WriteFile(path, []byte("not executable"), 0o644); err != nil {
		t.Fatal(err)
	}
	nonExecutable, err := probeConfiguredCore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if nonExecutable.State != coreStateNotExecutable || !nonExecutable.Present || nonExecutable.Runnable {
		t.Fatalf("non-executable core identity = %+v", nonExecutable)
	}
}

func TestProbeConfiguredCoreSanitizesPathResolutionFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX symlink loop")
	}
	dir := t.TempDir()
	path := dir + "/do-not-leak-core-path"
	if err := os.Symlink(path, path); err != nil {
		t.Fatal(err)
	}
	identity, err := probeConfiguredCore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if identity.State != coreStateProbeFailed || identity.Runnable {
		t.Fatalf("symlink-loop core identity = %+v", identity)
	}
	if strings.Contains(identity.ProbeError, dir) || strings.Contains(identity.ProbeError, "do-not-leak") {
		t.Fatalf("core probe error leaked configured path: %q", identity.ProbeError)
	}
}

func TestProbeConfiguredCoreRejectsMutationDuringVersionProbe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX self-modifying executable script")
	}
	path := t.TempDir() + "/sing-box"
	body := "#!/bin/sh\nprintf '#!/bin/sh\\necho changed\\n' > \"$0\"\necho 'sing-box version 1.12.0'\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	identity, err := probeConfiguredCore(context.Background(), path)
	if err == nil {
		t.Fatalf("self-modifying core probe succeeded with identity %+v", identity)
	}
	if identity.State != coreStateProbeFailed || identity.Runnable {
		t.Fatalf("self-modifying core identity = %+v", identity)
	}
}

func TestProbeConfiguredCoreBoundsVersionOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX executable script")
	}
	path := t.TempDir() + "/sing-box"
	body := "#!/bin/sh\nhead -c 20000 /dev/zero | tr '\\0' x\necho 'sing-box version 1.12.0'\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	identity, err := probeConfiguredCore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if identity.State != coreStateProbeFailed || identity.Runnable {
		t.Fatalf("unbounded-output core identity = %+v", identity)
	}
}

func TestProbeConfiguredCoreRejectsNonSingBoxIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX executable script")
	}
	path := t.TempDir() + "/not-sing-box"
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho version\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	identity, err := probeConfiguredCore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if identity.State != coreStateProbeFailed || identity.Runnable {
		t.Fatalf("non-sing-box executable identity = %+v", identity)
	}
	if !validSingBoxVersionOutput("sing-box version 1.12.0-beta.3\nTags: with_quic") {
		t.Fatal("valid sing-box prerelease identity was rejected")
	}
}

func TestProbeConfiguredCoreWaitDelayBoundsInheritedPipes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX child process")
	}
	path := t.TempDir() + "/sing-box"
	body := "#!/bin/sh\n(sleep 30) &\necho 'sing-box version 1.12.0'\nexit 0\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	identity, err := probeConfiguredCore(context.Background(), path)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	if identity.State != coreStateProbeFailed || identity.Runnable {
		t.Fatalf("inherited-pipe core identity = %+v", identity)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("WaitDelay did not bound inherited pipe wait: %s", elapsed)
	}
}

func TestProbeKernelPBRFreshExecutesReadOnlyCapabilityCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX nft fixture")
	}
	dir := t.TempDir()
	nft := dir + "/nft"
	if err := os.WriteFile(nft, []byte("#!/bin/sh\nwhile IFS= read -r line; do :; done\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	s := &Server{pbrRunner: pbr.ExecRunner{}}
	available, err := probeKernelPBRFresh(context.Background(), s, string(platform.OpenWrt))
	if err != nil || !available {
		t.Fatalf("working nft check = available:%v err:%v", available, err)
	}

	if err := os.WriteFile(nft, []byte("#!/bin/sh\nwhile IFS= read -r line; do :; done\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	available, err = probeKernelPBRFresh(context.Background(), s, string(platform.OpenWrt))
	if err == nil || available {
		t.Fatalf("rejected nft transaction = available:%v err:%v", available, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	available, err = probeKernelPBRFresh(ctx, s, string(platform.OpenWrt))
	if err == nil || available {
		t.Fatalf("cancelled nft check = available:%v err:%v", available, err)
	}
}
