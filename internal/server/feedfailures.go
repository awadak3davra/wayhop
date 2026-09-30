package server

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"wayhop/internal/model"
)

// A routing list whose feed stops answering keeps the content it last got: the sites it held still
// route, the ones added upstream since do not, and only the log said so, once per failed refresh.
// This remembers, per list, how many refreshes in a row failed, since when and why, so the bot can
// name such a list. In memory, like cidrCheckState and for the same reason: after a restart nothing
// is known until the list is next due, which is a true statement about this process.

type feedFailures struct {
	mu sync.Mutex
	m  map[string]feedFailure
}

type feedFailure struct {
	fails int       // refreshes in a row that failed, counted at most once per feedFailGap
	since time.Time // the first of them
	last  time.Time // the last one counted
	seen  time.Time // the last one, counted or not
	err   string    // the last one's reason, credentials removed
	// feeds are the sources the failures were of. A list given other sources starts over: what
	// failed before says nothing about the new ones.
	feeds string
}

// feedFailGap is how far apart two failures must be to count as two. A second tap on Refresh a
// minute after the first asks the same host in the same state, and one blip must not read as two.
const feedFailGap = time.Hour

// errFeedNotTried is a list a refresh ran out of time before asking: it neither failed nor changed.
var errFeedNotTried = errors.New("not tried, the refresh ran out of time")

func feedsOf(rl model.RoutingList) string { return rl.CIDRSource + "\x00" + rl.DomainSource }

// noteFeedRefresh records how a refresh of a list's feeds went: a success clears the list's record,
// a failure extends it. Both the refresh loop and a manual refresh call it.
func (s *Server) noteFeedRefresh(rl model.RoutingList, now time.Time, err error) {
	if s == nil || rl.ID == "" {
		return
	}
	f := &s.feedFails
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		delete(f.m, rl.ID)
		return
	}
	if f.m == nil {
		f.m = map[string]feedFailure{}
	}
	cur, ok := f.m[rl.ID]
	if !ok || cur.feeds != feedsOf(rl) {
		cur = feedFailure{since: now, feeds: feedsOf(rl)}
	}
	if cur.fails == 0 || now.Sub(cur.last) >= feedFailGap {
		cur.fails++
		cur.last = now
	}
	cur.seen, cur.err = now, feedReason(rl.ID, err)
	f.m[rl.ID] = cur
}

// forgetFeeds drops the records of lists that are no longer refreshed: deleted, switched off or left
// without a feed. A list that comes back starts over.
func (s *Server) forgetFeeds(keep map[string]bool) {
	f := &s.feedFails
	f.mu.Lock()
	defer f.mu.Unlock()
	for id := range f.m {
		if !keep[id] {
			delete(f.m, id)
		}
	}
}

// feedFailuresNow is a copy of the lists whose last refresh failed.
func (s *Server) feedFailuresNow() map[string]feedFailure {
	f := &s.feedFails
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]feedFailure, len(f.m))
	for id, v := range f.m {
		out[id] = v
	}
	return out
}

// feedReason is a refresh error as a person reads it: the first failure only (a list with two feeds
// joins both), without the "refresh \"id\"" prefix the log needs and a chat does not, and with any
// credential in the feed's address removed.
func feedReason(id string, err error) string {
	msg, _, _ := strings.Cut(err.Error(), "\n")
	for _, prefix := range []string{fmt.Sprintf("refresh %q domains: ", id), fmt.Sprintf("refresh %q: ", id)} {
		msg = strings.TrimPrefix(msg, prefix)
	}
	return redactSubscriptionError(msg)
}
