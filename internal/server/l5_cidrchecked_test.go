package server

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestCIDRCheckedIsSeparateFromRefreshed: the two stamps answer different questions and the whole
// point is that they diverge. A fetch whose result equals the cache is deliberately not written, so
// CIDRRefreshed stands still while the list is being checked every cycle. Reading the first as the
// second is what made a working refresh look broken.
func TestCIDRCheckedIsSeparateFromRefreshed(t *testing.T) {
	s := &Server{cidrChecks: newCIDRCheckState()}
	if got := s.cidrCheckedAt("a"); got != 0 {
		t.Fatalf("a list nothing has fetched reports %d, want 0", got)
	}
	s.noteCIDRChecked("a")
	if got := s.cidrCheckedAt("a"); got == 0 {
		t.Fatal("a completed fetch left no record")
	}
	if got := s.cidrCheckedAt("b"); got != 0 {
		t.Errorf("an untouched list borrowed another's stamp: %d", got)
	}
	// A nil state must not panic: the battery and the profile route both read this, and a panic in
	// either is worse than a missing number.
	var bare *Server
	if got := bare.cidrCheckedAt("a"); got != 0 {
		t.Errorf("nil server returned %d", got)
	}
	bare.noteCIDRChecked("a") // must not panic
	(&Server{}).noteCIDRChecked("a")
}

// TestLiteProfileCarriesCheckedAt: the number is useless if the page cannot see it, and it must not
// appear as a zero for lists nothing has fetched — an absent key reads as "not checked in this
// process", which is the truth after a restart.
func TestLiteProfileCarriesCheckedAt(t *testing.T) {
	p := model.Profile{RoutingLists: []model.RoutingList{
		{ID: "fetched", Name: "F", Enabled: true, Outbound: "direct", CIDRSource: "https://example.com/a.txt"},
		{ID: "never", Name: "N", Enabled: true, Outbound: "direct", CIDRSource: "https://example.com/b.txt"},
	}}
	lite := liteProfileOf(p, func(id string) int64 {
		if id == "fetched" {
			return 1700000000
		}
		return 0
	})
	b, err := json.Marshal(lite)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := string(b)
	if !strings.Contains(out, `"cidr_checked":1700000000`) {
		t.Errorf("the fetched list does not carry its check stamp: %s", out[:min(len(out), 400)])
	}
	if strings.Contains(out, `"cidr_checked":0`) {
		t.Errorf("a list nothing fetched reports a zero stamp instead of omitting it: %s", out[:min(len(out), 400)])
	}
	// And the old field must still be there: this adds a fact, it does not replace one.
	if !strings.Contains(out, "cidr_source") {
		t.Errorf("lite list lost its source: %s", out[:min(len(out), 300)])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestStampRecordedBeforeTheUnchangedShortcut witnesses WHERE the record happens, which every other
// assertion here is blind to. Recording it after fetchOne's unchanged shortcut would keep them all
// green while restoring the defect exactly: a list whose upstream never changes would report nothing
// checked, forever, which is the reading that made a working refresh look broken.
//
// Structural rather than behavioural because the fetch client refuses loopback addresses — a
// deliberate SSRF guard — so a local test server cannot be fetched. The claim being pinned is
// structural anyway: the record must precede the early return.
func TestStampRecordedBeforeTheUnchangedShortcut(t *testing.T) {
	b, err := os.ReadFile("cidrrefresh.go")
	if err != nil {
		t.Fatalf("read cidrrefresh.go: %v", err)
	}
	src := string(b)
	fn := strings.Index(src, "func (s *Server) fetchOne(")
	if fn < 0 {
		t.Fatal("fetchOne is gone; this gate is pinning nothing")
	}
	body := src[fn:]
	if end := strings.Index(body, "\n}\n"); end > 0 {
		body = body[:end]
	}
	note := strings.Index(body, "s.noteCIDRChecked(")
	shortcut := strings.Index(body, "slices.Equal(got, rl.CIDRCache)")
	if note < 0 {
		t.Fatal("fetchOne no longer records that a fetch happened")
	}
	if shortcut < 0 {
		t.Fatal("the unchanged shortcut is gone; re-read this gate before deleting it")
	}
	if note > shortcut {
		t.Error("the fetch is recorded AFTER the unchanged shortcut, so a list whose upstream never " +
			"changes reports nothing checked — the defect this change removes")
	}
}
