package store

import (
	"errors"
	"path/filepath"
	"testing"

	"wayhop/internal/model"
)

// A DNS rev handed out before a daemon restart must not be accepted after it.
//
// The panel keeps the rev it read in memory and sends it back as If-Match, and a tab outlives the
// daemon (update, crash, power loss). Open used to start the generation at 0 every time, so the new
// process walked the same numbers again: tab A read rev 1, the daemon restarted, tab B removed a
// resolver (rev 0 -> 1), and tab A's save with If-Match 1 passed the compare-and-set. Tab B's edit
// was silently undone and both tabs got a 200, the exact case the check exists to refuse.
func TestGen_ARevFromBeforeARestartIsStaleAfterIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	plane := func(servers ...string) *model.DNSSettings {
		d := &model.DNSSettings{}
		for _, tag := range servers {
			d.Servers = append(d.Servers, model.DNSServer{Tag: tag, Type: "udp", Server: "192.0.2.53"})
		}
		return d
	}

	before, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := before.SetDNS(plane("x", "y")); err != nil {
		t.Fatalf("seed dns: %v", err)
	}
	_, tabA := before.Snapshot() // tab A loads the DNS page

	after, err := Open(path) // the daemon restarts; tab A keeps its rev
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	// Tab B loads and removes resolver x, then a few more writes follow (list edits, CIDR refresh
	// ticks). A counter that restarted walks back onto tabA within them; tab A's save must stay
	// refused at every step.
	for i := 0; i < 5; i++ {
		if _, err := after.SetDNSIfGen(plane("y"), after.Gen()); err != nil {
			t.Fatalf("tab B write %d: %v", i, err)
		}
		if _, err := after.SetDNSIfGen(plane("x", "y"), tabA); !errors.Is(err, ErrStaleGen) {
			t.Fatalf("after %d write(s) since the restart, tab A's pre-restart rev %d was not refused (err=%v): it undid tab B's edit", i+1, tabA, err)
		}
	}
	p := after.Profile()
	if p.DNS == nil || len(p.DNS.Servers) != 1 || p.DNS.Servers[0].Tag != "y" {
		t.Fatalf("tab B's edit was overwritten: %+v", p.DNS)
	}
}

// The rev reaches the panel as a JSON number, and JavaScript reads numbers as doubles: above 2^53 it
// rounds, String(rev) no longer matches the gen, and every DNS save would be refused as stale. The
// starting point must leave room for the process to keep counting inside that range.
func TestGen_StartsInsideTheRangeTheBrowserCanEchoBack(t *testing.T) {
	const jsSafe = uint64(1)<<53 - 1
	for i := 0; i < 64; i++ {
		s, err := Open(filepath.Join(t.TempDir(), "profile.json"))
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if g := s.Gen(); g > jsSafe/2 {
			t.Fatalf("start gen %d leaves less than 2^52 writes before the panel can no longer echo it", g)
		}
	}
}
