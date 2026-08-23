package server

import (
	"strings"
	"testing"

	"wayhop/internal/config"
)

// The kernel-plane findings only mean something in the modes that ask the kernel to route.
//
// They were generated for every mode with one wording, which put 219 findings on a Keenetic running
// `mixed` — a mode with no kernel PBR at all — each announcing that traffic nobody asked the kernel
// to carry is carried by sing-box instead.

func modeCfg(mode string) *config.Config {
	c := config.Default()
	c.RoutingMode = mode
	return c
}

// tun sends everything through the sing-box TUN and mixed runs a proxy inbound only. Neither asks
// the kernel for anything, so neither has anything to report about it.
func TestKernelPlaneFindings_ModesThatNeverAskTheKernelSayNothing(t *testing.T) {
	s := dnsSeed(t)
	prof := kernelPlaneProfile()

	// The fixture must actually produce warnings, or every case below passes for the wrong reason.
	if got := s.kernelPlaneFindings(modeCfg("hybrid"), &prof); len(got) == 0 {
		t.Skip("this build's compiler produced no warnings for the fixture; there is nothing to suppress")
	}

	for _, mode := range []string{"tun", "mixed"} {
		if got := s.kernelPlaneFindings(modeCfg(mode), &prof); len(got) != 0 {
			t.Errorf("%s produced %d kernel-plane finding(s); the kernel plane is not part of that mode, "+
				"so anything said about it is noise: %+v", mode, len(got), got[0])
		}
	}
}

// hybrid does use the kernel, and the capture-all TUN carries what it declines — so this is real,
// and belongs in the plan as ONE finding carrying the list rather than one per rule.
func TestKernelPlaneFindings_HybridReportsOnceWithTheCount(t *testing.T) {
	s := dnsSeed(t)
	prof := kernelPlaneProfile()

	got := s.kernelPlaneFindings(modeCfg("hybrid"), &prof)
	if len(got) == 0 {
		t.Skip("this build's compiler produced no warnings for the fixture")
	}
	if len(got) != 1 {
		t.Fatalf("hybrid produced %d findings, want exactly 1 aggregate", len(got))
	}
	f := got[0]
	if !strings.Contains(f.Effective, "routed by sing-box") {
		t.Errorf("Effective = %q, want it to say sing-box carries them", f.Effective)
	}
	if !strings.Contains(f.Effective, "rule(s)") {
		t.Errorf("Effective = %q, want the count an operator acts on", f.Effective)
	}
	if strings.TrimSpace(f.Detail) == "" {
		t.Error("the aggregate dropped the individual messages; the count without the list is not reviewable")
	}
}

// fast is hybrid WITHOUT the capture-all TUN. What the kernel will not route is carried by nothing,
// so the shared wording — "sing-box still carries this traffic" — was a false reassurance in exactly
// the mode where the rule is dead.
func TestKernelPlaneFindings_FastDoesNotPromiseASingBoxFallback(t *testing.T) {
	s := dnsSeed(t)
	prof := kernelPlaneProfile()

	got := s.kernelPlaneFindings(modeCfg("fast"), &prof)
	if len(got) == 0 {
		t.Skip("this build's compiler produced no warnings for the fixture")
	}
	for _, f := range got {
		if !strings.Contains(f.Effective, "not routed") {
			t.Errorf("Effective = %q, want it to say the rule is not routed at all", f.Effective)
		}
		// The remedy may mention hybrid as the mode that DOES have a fallback; what it must not do is
		// tell someone on fast that something is already carrying this.
		if strings.Contains(f.Effective, "sing-box") {
			t.Errorf("Effective = %q claims sing-box carries it; in fast mode there is no TUN underneath", f.Effective)
		}
		if strings.Contains(f.Remedy, "still carries") {
			t.Errorf("Remedy = %q reassures about a fallback this mode does not have", f.Remedy)
		}
	}
}
