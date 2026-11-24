package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"wayhop/internal/pbr"
)

func keeneticK1Artifact(t *testing.T, failClosed bool) *executionKernelArtifactV1 {
	t.Helper()
	plan := &pbr.Plan{Mask: 0x00ff0000,
		Egresses: []pbr.Egress{{Tag: "vpn", Kind: pbr.EgressInterface, Iface: "awg2", Mark: 0x20000, Table: 151, FailClosed: failClosed}},
		Zones:    []pbr.Zone{{Name: "list_a", EgressTag: "vpn", Domains: []string{"a.example"}, Mark: 0x20000}}}
	io := keeneticPBROptions("eth3")
	io.DynamicDomainSets, io.FastDNSEnforce, io.LANIfaces = true, true, []string{"br0"}
	artifact, err := buildKeeneticKernelIpsetArtifact(plan, exactKernelOptions(), io, keeneticPBRTestTools())
	if err != nil {
		t.Fatal(err)
	}
	return &executionKernelArtifactV1{Plan: plan, Ipset: artifact}
}

// After a daemon restart a policy file on disk that is not the installed one is a forgotten
// back-out: adopted as one, so the guarded retry runs and Diagnostics fails.
func TestKeeneticFastAdoptForgottenBackout(t *testing.T) {
	s, f := useKeeneticFastFakes(t)
	k := keeneticK1Artifact(t, false)
	f.disk = keeneticPolicyFile{content: []byte("# previous policy\n"), existed: true}
	s.keeneticFastAdopt(k)
	if !s.fastDNS.backedOut || string(s.fastDNS.keenetic.backout) != "# previous policy\n" ||
		string(s.fastDNS.keenetic.installed) != string(k.Ipset.DnsmasqConf) || !strings.Contains(s.fastDNS.err, "restarted") {
		t.Fatalf("not adopted: backedOut=%v err=%q", s.fastDNS.backedOut, s.fastDNS.err)
	}
	row := s.keeneticFastCheckOf(context.Background(), healthRow{}, k)
	if row.Status != "fail" {
		t.Fatalf("Diagnostics after adoption = %+v", row)
	}
	// The same file on disk: nothing to adopt.
	s2, f2 := useKeeneticFastFakes(t)
	f2.disk = keeneticPolicyFile{content: k.Ipset.DnsmasqConf, existed: true}
	s2.keeneticFastAdopt(k)
	if s2.fastDNS.backedOut {
		t.Fatal("the installed file was taken for a back-out")
	}
}

// Dnsmasq silent for keeneticFailOpenAfter suspends the enforcement (flag + deletes of exactly
// the suspendable rules), never with a kill switch, and it comes back when dnsmasq answers.
func TestKeeneticFailOpen(t *testing.T) {
	s, f := useKeeneticFastFakes(t)
	k := keeneticK1Artifact(t, false)
	ctx := context.Background()
	s.keeneticFailOpenTick(ctx, k, false)
	if len(f.programs) != 0 {
		t.Fatal("suspended at the first silent tick")
	}
	s.fastDNS.keenetic.silentSince = time.Now().Add(-keeneticFailOpenAfter - time.Second)
	s.keeneticFailOpenTick(ctx, k, false)
	if len(f.programs) != 1 || !strings.HasPrefix(f.programs[0], ": > "+pbr.FastDNSOpenFlag) ||
		!strings.Contains(f.programs[0], "-i br0 -p udp --dport 53 -j REDIRECT") ||
		!strings.Contains(f.programs[0], "while ip6tables -D FORWARD -i br0 -p tcp --dport 853") ||
		strings.Contains(f.programs[0], "MARK") {
		t.Fatalf("suspend program = %q", f.programs)
	}
	f.suspended = true
	if row := s.keeneticFastCheckOf(ctx, healthRow{}, k); row.Status != "fail" || !strings.Contains(row.Summary, "enforcement suspended") {
		t.Fatalf("Diagnostics while suspended = %+v", row)
	}
	s.keeneticFailOpenTick(ctx, k, true)
	if len(f.programs) != 2 || !strings.HasPrefix(f.programs[1], "rm -f "+pbr.FastDNSOpenFlag) ||
		!strings.Contains(f.programs[1], "iptables -t nat -C PREROUTING -i br0 -p udp --dport 53") {
		t.Fatalf("restore program = %q", f.programs)
	}

	// Kill switch: held, said why, nothing run.
	s2, f2 := useKeeneticFastFakes(t)
	ks := keeneticK1Artifact(t, true)
	s2.fastDNS.keenetic.silentSince = time.Now().Add(-keeneticFailOpenAfter - time.Second)
	s2.keeneticFailOpenTick(ctx, ks, false)
	if len(f2.programs) != 0 || !strings.Contains(s2.fastDNS.keenetic.failOpenHeld, "kill switch") {
		t.Fatalf("kill switch: programs=%q held=%q", f2.programs, s2.fastDNS.keenetic.failOpenHeld)
	}
	if row := s2.keeneticFastCheckOf(ctx, healthRow{}, ks); row.Status != "fail" || !strings.Contains(row.Detail, "kill switch") {
		t.Fatalf("Diagnostics with the kill switch = %+v", row)
	}
}

// The program's suspendable rules are exactly fast mode's enforcement; the postcheck skips them
// while suspended.
func TestKeeneticSuspendableRules(t *testing.T) {
	k := keeneticK1Artifact(t, false)
	n := 0
	for _, r := range keeneticDNSRules(k.Ipset.Script) {
		if !r.suspendable {
			t.Errorf("not suspendable: %+v", r)
		}
		n++
	}
	if n != 6 { // 2 redirects, 1 DoT, 3 IPv6 refusals for br0
		t.Fatalf("suspendable rules = %d", n)
	}
}

// A guarded restart that fails and leaves dnsmasq silent owes the loop a restart.
// The same file with dnsmasq answering its canary is not restarted.
func TestKeeneticFastReloadK1(t *testing.T) {
	s, f := useKeeneticFastFakes(t)
	k := keeneticK1Artifact(t, false)
	pre := keeneticFastPreInstall{before: keeneticPolicyFile{content: k.Ipset.DnsmasqConf, existed: true}}
	calls := &keeneticDNSGuardFake{}
	if err := s.keeneticFastReload(context.Background(), calls.run, *k.Ipset, k.Plan, pre); err != nil || len(calls.calls) != 0 {
		t.Fatalf("unchanged file: err=%v calls=%v", err, calls.calls)
	}
	f.alive = errors.New("silent")
	pre.before = keeneticPolicyFile{content: []byte("# previous\n"), existed: true}
	if err := s.keeneticFastReload(context.Background(), calls.run, *k.Ipset, k.Plan, pre); err == nil {
		t.Fatal("a silent dnsmasq passed the guard")
	}
	if !s.fastDNS.restartOwed {
		t.Fatal("a failed guarded restart owes no restart")
	}
}

// One warm-up at a time; a new one or leaving fast mode cancels the running one.
func TestKeeneticWarmUpSingleFlight(t *testing.T) {
	s, _ := useKeeneticFastFakes(t)
	plan := &pbr.Plan{}
	s.startKeeneticWarmUp(plan)
	s.fastDNS.mu.Lock()
	first := s.fastDNS.keenetic.warmCancel
	s.fastDNS.mu.Unlock()
	ctxProbe, cancelProbe := context.WithCancel(context.Background())
	defer cancelProbe()
	s.fastDNS.mu.Lock()
	s.fastDNS.keenetic.warmCancel = func() { first(); cancelProbe() }
	s.fastDNS.mu.Unlock()
	s.startKeeneticWarmUp(plan)
	if ctxProbe.Err() == nil {
		t.Fatal("a second warm-up did not cancel the first")
	}
	s.fastDNS.mu.Lock()
	second := s.fastDNS.keenetic.warmCancel
	s.fastDNS.mu.Unlock()
	if second == nil {
		t.Fatal("no cancel kept for the running warm-up")
	}
	s.keeneticFastLeft()
	if s.fastDNS.keenetic.warmCancel != nil {
		t.Fatal("leaving fast mode kept the warm-up")
	}
}
