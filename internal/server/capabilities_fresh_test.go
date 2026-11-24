package server

import (
	"context"
	"testing"
	"time"

	"wayhop/internal/platform"
)

// Right after installing sing-box from Components, saving a connection must not be refused from a
// capability cache up to five minutes old, and the form's Retry must keep its fresh answer.
func TestCapabilityCacheFollowsInstallsAndRetry(t *testing.T) {
	s := bindTestServer(t, feedProfile(), "")
	stale := platform.CapabilitySet{ProbedAt: time.Now()}
	s.keepCapabilities(stale)
	if got := s.capabilitySet(context.Background(), false); !got.ProbedAt.Equal(stale.ProbedAt) {
		t.Fatalf("a fresh cache should be served as is")
	}
	s.forgetCapabilities()
	s.caps.mu.Lock()
	forgotten := s.caps.set.ProbedAt.IsZero()
	s.caps.mu.Unlock()
	if !forgotten {
		t.Fatal("forgetCapabilities left the evaluation in place")
	}
	retried := platform.CapabilitySet{ProbedAt: time.Now().Add(time.Second)}
	s.keepCapabilities(retried)
	if got := s.capabilitySet(context.Background(), false); !got.ProbedAt.Equal(retried.ProbedAt) {
		t.Fatalf("the save gate must read the evaluation Retry just made")
	}
}
