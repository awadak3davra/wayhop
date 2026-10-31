package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// QA-129. The hunt's repro: the kernel-PBR verdict was detected once for the daemon's lifetime, so
// following the review's own remedy (install nft) never lifted the fast-mode refusal until a restart,
// while /api/native/capabilities, which probes fresh, already reported fast usable.
func TestQA129KernelPBRVerdictFollowsTheRemedy(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	cfg := &config.Config{RoutingMode: "fast"}
	s := &Server{pbrRunner: pbr.ExecRunner{}, cfg: cfg}
	if s.kernelPBRAvailable() {
		t.Fatal("precondition: nft absent should be unavailable")
	}
	caps := platform.Capabilities{Platform: string(platform.OpenWrt), PackageManager: "opkg"}
	before := platform.Evaluate(caps, s.runtimeFacts(context.Background()))
	t.Logf("before install: routing.mode.fast usable=%v remedy=%q", before.Usable("routing.mode.fast"), before.Get(platform.CapPBRKernel).Remedy)
	name, body := "nft", []byte("#!/bin/sh\nexit 0\n")
	if runtime.GOOS == "windows" {
		name = "nft.exe"
	}
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Fatalf("fixture: nft should now resolve: %v", err)
	}
	after := platform.Evaluate(caps, s.runtimeFacts(context.Background()))
	pf := s.preflightFor(*cfg, model.Profile{}, caps, platform.OffloadState{})
	blocked := false
	for _, u := range pf {
		if u.Setting == "routing_mode" && u.Value == "fast" && u.Severity == platform.SeverityBlocked {
			blocked = true
		}
	}
	if !after.Usable(platform.CapPBRKernel) || blocked {
		t.Fatalf("STALE: nft now on PATH, but kernelPBRAvailable=%v pbr.kernel usable=%v fast-preflight-blocked=%v",
			s.kernelPBRAvailable(), after.Usable(platform.CapPBRKernel), blocked)
	}
}

// The accelerator verdict had the same lifetime: a flow-offload module installed after the daemon
// started was never compiled for. A capability probe now carries the observation to the offload
// resolver, and an observation older than capStaleAfter is not trusted.
func TestQA129AcceleratorVerdictFollowsTheProbe(t *testing.T) {
	cfg := &config.Config{RoutingMode: "fast", Offload: "auto", OffloadDevices: []string{"br-lan"}}
	s := &Server{pbrRunner: pbr.ExecRunner{}, cfg: cfg}
	// The daemon started before the flowtable module was there.
	s.noteAccel(platform.Accel{})
	if opts := s.pbrCompileOptions(s.config()); opts.Offload == "sw" || opts.Offload == "hw" {
		t.Fatalf("precondition: offload %q with no accelerator", opts.Offload)
	}
	// A later capability probe observes it.
	s.noteAccel(platform.Accel{Kind: "nft-flowtable", HW: true})
	if opts := s.pbrCompileOptions(s.config()); opts.Offload != "hw" {
		t.Fatalf("offload = %q after the accelerator was observed, want hw", opts.Offload)
	}
	// The review's ?refresh=1 probes again and replaces it (the development host has no accelerator).
	_ = s.capabilitySet(context.Background(), true)
	if got := s.accel(); got != (platform.Accel{}) {
		t.Fatalf("accel = %+v after a refreshed capability probe on a host without one", got)
	}
	// A fresh observation is kept; a stale one is probed again.
	s.noteAccel(platform.Accel{Kind: "nft-flowtable"})
	if s.accelKind() != "nft-flowtable" {
		t.Fatal("a fresh observation was not kept")
	}
	s.hostVerdicts.mu.Lock()
	s.hostVerdicts.accelAt = time.Now().Add(-2 * capStaleAfter)
	s.hostVerdicts.mu.Unlock()
	if s.accelKind() != "" {
		t.Fatal("an observation older than capStaleAfter was trusted")
	}
	// The demo stays the capable box whatever was observed.
	cfg.Demo = true
	if got := s.accel(); got != demoAccel {
		t.Fatalf("demo accel = %+v", got)
	}
}

// The kernel-PBR verdict expires like the capability set it belongs to.
func TestQA129KernelPBRVerdictExpires(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	s := &Server{pbrRunner: pbr.ExecRunner{}, cfg: &config.Config{}}
	s.hostVerdicts.pbr, s.hostVerdicts.pbrAt = true, time.Now().Add(-2*capStaleAfter)
	if s.kernelPBRAvailable() {
		t.Fatal("a kernel-PBR verdict older than capStaleAfter was trusted")
	}
	s.hostVerdicts.pbr, s.hostVerdicts.pbrAt = true, time.Now()
	if !s.kernelPBRAvailable() {
		t.Fatal("a fresh kernel-PBR verdict was not kept")
	}
}

// A stale accelerator is probed inside the request that asks, and the probe is a full capability
// detection: requests that find it stale together share one probe instead of each running its own.
func TestQA129StaleAcceleratorProbedOnceForConcurrentCallers(t *testing.T) {
	s := &Server{pbrRunner: pbr.ExecRunner{}, cfg: &config.Config{}}
	var probes atomic.Int32
	release := make(chan struct{})
	s.hostVerdicts.detectAccel = func() platform.Accel {
		probes.Add(1)
		<-release
		return platform.Accel{Kind: "nft-flowtable"}
	}
	const callers = 8
	var started, finished sync.WaitGroup
	got := make([]platform.Accel, callers)
	for i := range callers {
		started.Add(1)
		finished.Add(1)
		go func() {
			defer finished.Done()
			started.Done()
			got[i] = s.accel()
		}()
	}
	started.Wait()
	// Every caller is past its start; give the ones still to reach the cache a moment to queue on
	// the probe in flight before it answers.
	deadline := time.Now().Add(2 * time.Second)
	for probes.Load() == 0 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	finished.Wait()
	if n := probes.Load(); n != 1 {
		t.Fatalf("%d concurrent callers ran %d probes, want 1", callers, n)
	}
	for i, a := range got {
		if a.Kind != "nft-flowtable" {
			t.Fatalf("caller %d got %+v, want the shared probe's answer", i, a)
		}
	}
	// The answer is kept: a later caller does not probe.
	if s.accelKind() != "nft-flowtable" || probes.Load() != 1 {
		t.Fatalf("after the shared probe: kind %q, probes %d", s.accelKind(), probes.Load())
	}
}
