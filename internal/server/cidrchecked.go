package server

import (
	"sync"
	"time"
)

// The refresh loop writes a list's cache only when the fetched bytes DIFFER from what is stored —
// deliberately, because a router should not rewrite flash to store identical content, and because a
// write would also stage a re-apply for a list that did not change. CIDRRefreshed piggybacks on that
// write, so it records when a list last CHANGED.
//
// Read as "last refreshed", which is what its name and the panel suggest, that number is misleading
// on any list whose upstream is stable: the age grows without bound against the configured cycle,
// and the honest reading of the display is that refreshing is broken. It is not — the fetch runs and
// succeeds every cycle. This tracks that fetch, in memory, so both facts can be shown: when it was
// last looked at, and when it last changed.
//
// In memory on purpose. Persisting it would reintroduce the exact flash write the skip exists to
// avoid, every cycle, for every list. The cost is that it starts empty after a restart, which is a
// true statement about this process rather than a gap.

// cidrCheckState is the in-memory record. Its own lock: a page render reads it while the refresh
// ticker writes, and neither should wait on the store.
type cidrCheckState struct {
	mu sync.RWMutex
	at map[string]int64 // routing-list id -> unix seconds of the last successful fetch
}

func newCIDRCheckState() *cidrCheckState { return &cidrCheckState{at: map[string]int64{}} }

// noteCIDRChecked records that a list's feed was fetched successfully, whether or not the result
// differed from the cache. Called on the success path only: a failed fetch has not checked anything,
// and claiming it had would be the same overstatement this file exists to remove.
func (s *Server) noteCIDRChecked(id string) {
	if s == nil || s.cidrChecks == nil || id == "" {
		return
	}
	s.cidrChecks.mu.Lock()
	s.cidrChecks.at[id] = time.Now().Unix()
	s.cidrChecks.mu.Unlock()
}

// cidrCheckedAt is when the list was last fetched in this process, or 0 for "not in this process".
func (s *Server) cidrCheckedAt(id string) int64 {
	if s == nil || s.cidrChecks == nil {
		return 0
	}
	s.cidrChecks.mu.RLock()
	defer s.cidrChecks.mu.RUnlock()
	return s.cidrChecks.at[id]
}
