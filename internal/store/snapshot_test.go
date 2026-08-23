package store

import (
	"path/filepath"
	"sync"
	"testing"

	"wayhop/internal/model"
)

// snapshot_dnsPlane builds a minimal valid DNS plane whose single server's Server address is `mark`,
// so a reader can tell which write it is looking at.
func snapshot_dnsPlane(mark string) *model.DNSSettings {
	return &model.DNSSettings{
		Enabled: true,
		Servers: []model.DNSServer{{Tag: "r", Type: "udp", Server: mark, Enabled: true}},
	}
}

// TestSnapshot_PairsPlaneWithItsOwnGen is the deterministic wiring guard: the profile Snapshot
// returns and the gen it returns come from the same published write, and SetDNSIfGen reports the
// generation it produced (not a fresh re-read). Single-threaded, so it only proves the pairing is
// wired correctly; TestSnapshot_NeverTearsProfileFromGen proves it holds under concurrency.
func TestSnapshot_PairsPlaneWithItsOwnGen(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	g0, err := s.SetDNSIfGen(snapshot_dnsPlane("1.1.1.1"), s.Gen())
	if err != nil {
		t.Fatalf("SetDNSIfGen A: %v", err)
	}
	p, rev := s.Snapshot()
	if rev != g0 {
		t.Fatalf("Snapshot rev = %d, want the gen SetDNSIfGen produced (%d)", rev, g0)
	}
	if p.DNS == nil || p.DNS.Servers[0].Server != "1.1.1.1" {
		t.Fatalf("Snapshot profile = %+v, want the plane just written (1.1.1.1)", p.DNS)
	}

	g1, err := s.SetDNSIfGen(snapshot_dnsPlane("9.9.9.9"), g0)
	if err != nil {
		t.Fatalf("SetDNSIfGen B: %v", err)
	}
	if g1 == g0 {
		t.Fatalf("second write did not advance the generation (still %d)", g0)
	}
	p, rev = s.Snapshot()
	if rev != g1 || p.DNS.Servers[0].Server != "9.9.9.9" {
		t.Fatalf("Snapshot after B = (rev %d, %q), want (rev %d, 9.9.9.9)", rev, p.DNS.Servers[0].Server, g1)
	}

	// A stale write is refused and the returned gen is the CURRENT one, so the caller can report it
	// without a separate Gen() read.
	staleGen, err := s.SetDNSIfGen(snapshot_dnsPlane("8.8.8.8"), g0) // g0 is now stale
	if err == nil {
		t.Fatal("SetDNSIfGen accepted a stale generation")
	}
	if staleGen != g1 {
		t.Fatalf("stale refusal reported gen %d, want the current %d", staleGen, g1)
	}
}

// snapshot_markFor is the marker a published pair carries at generation g: the writer below stamps
// even generations with markB and odd with markA, so a reader can tell — from g alone — which plane
// a CONSISTENT pair must hold. A torn pair (profile from one published pointer, gen from another)
// violates it whenever the two pointers straddle a parity change, which every single-step write is.
func snapshot_markFor(g uint64) string {
	if g%2 == 0 {
		return "9.9.9.9" // markB
	}
	return "1.1.1.1" // markA
}

// TestSnapshot_NeverTearsProfileFromGen is the LOOP-035 proof. It is white-box and disk-free on
// purpose: the guarantee under test — that a published {profile, gen} is indivisible — lives in the
// cur pointer, and driving cur directly lets the writer publish MILLIONS of times so the tiny window
// between two independent atomic loads is actually hit. (An earlier version drove the public write
// API; each write fsynced a file, so the writer published only a few hundred times and the torn
// window was never sampled — the test passed even against a two-load Snapshot, proving nothing.)
//
// The writer swaps cur between (markA, odd gen) and (markB, even gen); the reader hammers Snapshot()
// and checks the plane it got matches the parity of the gen it got. One atomic load always returns a
// real pair, so the count stays zero. Proven to FAIL when Snapshot is reverted to
// `return s.Profile(), s.Gen()`: the reader then pairs one pointer's plane with another's gen and
// catches the parity mismatch within the first handful of iterations.
func TestSnapshot_NeverTearsProfileFromGen(t *testing.T) {
	var s Store
	s.cur.Store(&published{p: &model.Profile{DNS: snapshot_dnsPlane(snapshot_markFor(1))}, gen: 1})

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for g := uint64(2); ; g++ {
			select {
			case <-stop:
				return
			default:
			}
			s.cur.Store(&published{p: &model.Profile{DNS: snapshot_dnsPlane(snapshot_markFor(g))}, gen: g})
		}
	}()

	torn, checked := 0, 0
	for i := 0; i < 2_000_000; i++ {
		p, g := s.Snapshot()
		if p.DNS == nil {
			continue
		}
		checked++
		if p.DNS.Servers[0].Server != snapshot_markFor(g) {
			torn++
		}
	}
	close(stop)
	wg.Wait()

	if checked == 0 {
		t.Fatal("the reader never observed a published pair — the test exercised nothing")
	}
	if torn != 0 {
		t.Fatalf("Snapshot returned %d/%d torn (profile, gen) pairs — the plane and the gen came from different published states", torn, checked)
	}
}
