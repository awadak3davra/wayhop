package store

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"slices"
	"time"

	"wayhop/internal/atomicfile"
	"wayhop/internal/model"
	"wayhop/internal/writebehind"
)

// The routing lists' feed caches (CIDRCache/DomainCache and their refresh times) are system-managed,
// re-fetchable, and were 99 % of profile.json (0.83 MB of 1.25 MB on a measured router): every feed
// refresh rewrote the whole profile on flash. They now live in the in-memory profile as before, so
// every reader (generator, pbr, the change review, the revision hash) is unchanged, but on disk they
// are kept apart in list-cache.json beside the profile, written through a writebehind.Writer:
// coalesced, hash-skipped, at most once per CacheFlushEvery (24h in production), plus on graceful
// shutdown and when Apply commits a configuration (FlushListCaches). A crash loses at most that
// window of refreshes; the refresh loop fetches them again, and boot converge does not read them
// (it installs the materialization recorded in apply-state).
//
// profile.json no longer carries the four fields. An old profile that does is read as before; the
// first write migrates it: the cache file is written durably BEFORE the profile without them, so no
// order of crashes loses a cache that was on disk.

// ListCacheFileName is the cache file beside profile.json.
const ListCacheFileName = "list-cache.json"

const listCacheSchema = 1

type listCacheEntry struct {
	ID              string   `json:"id"`
	CIDRSource      string   `json:"cidr_source,omitempty"`
	CIDRs           []string `json:"cidrs,omitempty"`
	CIDRRefreshed   int64    `json:"cidr_refreshed,omitempty"`
	DomainSource    string   `json:"domain_source,omitempty"`
	Domains         []string `json:"domains,omitempty"`
	DomainRefreshed int64    `json:"domain_refreshed,omitempty"`
}

type listCacheFile struct {
	Schema int              `json:"schema"`
	Lists  []listCacheEntry `json:"lists"`
}

// Options tunes OpenWith.
type Options struct {
	// CacheFlushEvery is the shortest gap between two writes of list-cache.json. 0 = write-through
	// (every change is written at once), which is what Open uses.
	CacheFlushEvery time.Duration
	// CacheDebounce coalesces a burst of cache changes into one write (ignored when CacheFlushEvery
	// is 0).
	CacheDebounce time.Duration
}

// hasFeedCache reports whether a list carries any system-managed feed state.
func hasFeedCache(rl *model.RoutingList) bool {
	return len(rl.CIDRCache) > 0 || len(rl.DomainCache) > 0 || rl.CIDRRefreshed != 0 || rl.DomainRefreshed != 0
}

// stripFeedCaches returns p without the feed caches, for profile.json. The routing-list slice is
// copied; nothing of p is modified.
func stripFeedCaches(p *model.Profile) *model.Profile {
	strip := false
	for i := range p.RoutingLists {
		if hasFeedCache(&p.RoutingLists[i]) {
			strip = true
			break
		}
	}
	if !strip {
		return p
	}
	out := *p
	out.RoutingLists = append([]model.RoutingList(nil), p.RoutingLists...)
	for i := range out.RoutingLists {
		rl := &out.RoutingLists[i]
		rl.CIDRCache, rl.CIDRRefreshed, rl.DomainCache, rl.DomainRefreshed = nil, 0, nil, 0
	}
	return &out
}

// renderListCache renders the cache file for p (compact: it is data, not something people edit).
func renderListCache(p *model.Profile) ([]byte, error) {
	f := listCacheFile{Schema: listCacheSchema, Lists: []listCacheEntry{}}
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if !hasFeedCache(rl) {
			continue
		}
		f.Lists = append(f.Lists, listCacheEntry{
			ID: rl.ID, CIDRSource: rl.CIDRSource, CIDRs: rl.CIDRCache, CIDRRefreshed: rl.CIDRRefreshed,
			DomainSource: rl.DomainSource, Domains: rl.DomainCache, DomainRefreshed: rl.DomainRefreshed,
		})
	}
	return json.Marshal(f)
}

// readListCache loads the cache file; a missing or unreadable one is empty (the feeds are
// re-fetched), never fatal.
func readListCache(path string) (raw []byte, entries map[string]listCacheEntry, mod time.Time) {
	entries = map[string]listCacheEntry{}
	raw, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("store: cannot read %s (%v); routing-list feeds will be fetched again", path, err)
		}
		return nil, entries, time.Time{}
	}
	var f listCacheFile
	if err := json.Unmarshal(raw, &f); err != nil || f.Schema != listCacheSchema {
		log.Printf("store: %s is unreadable (%v, schema %d); routing-list feeds will be fetched again", path, err, f.Schema)
		return nil, entries, time.Time{}
	}
	for _, e := range f.Lists {
		entries[e.ID] = e
	}
	if fi, err := os.Stat(path); err == nil {
		mod = fi.ModTime()
	}
	return raw, entries, mod
}

// mergeListCache folds the cache file into a profile read from disk. An entry applies only while its
// source still matches the list's (a re-pointed list must not get the old feed back), and only when
// it is at least as fresh as what an old-format profile carried inline.
func mergeListCache(p *model.Profile, entries map[string]listCacheEntry) {
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		e, ok := entries[rl.ID]
		if !ok {
			continue
		}
		if e.CIDRSource == rl.CIDRSource && e.CIDRRefreshed >= rl.CIDRRefreshed && (len(e.CIDRs) > 0 || len(rl.CIDRCache) == 0) {
			rl.CIDRCache, rl.CIDRRefreshed = e.CIDRs, e.CIDRRefreshed
		}
		if e.DomainSource == rl.DomainSource && e.DomainRefreshed >= rl.DomainRefreshed && (len(e.Domains) > 0 || len(rl.DomainCache) == 0) {
			rl.DomainCache, rl.DomainRefreshed = e.Domains, e.DomainRefreshed
		}
	}
}

// openListCache wires the cache writer and merges the file into p. Called from OpenWith before
// anything is published.
func (s *Store) openListCache(p *model.Profile, opt Options) {
	s.cachePath = filepath.Join(filepath.Dir(s.path), ListCacheFileName)
	atomicfile.RemoveStale(s.cachePath)
	raw, entries, mod := readListCache(s.cachePath)
	for i := range p.RoutingLists {
		if hasFeedCache(&p.RoutingLists[i]) {
			s.legacyEmbedded = true // an old-format profile.json: migrate on the first write
			break
		}
	}
	mergeListCache(p, entries)
	wo := writebehind.Options{}
	if opt.CacheFlushEvery > 0 {
		wo.MinInterval, wo.Debounce = opt.CacheFlushEvery, opt.CacheDebounce
	}
	s.cacheW = writebehind.New(s.cachePath, 0o600, wo)
	if raw != nil {
		s.cacheW.Seed(raw, mod)
	} else if empty, err := renderListCache(&model.Profile{}); err == nil {
		// No file: an empty cache needs no write; anything else does.
		s.cacheW.Seed(empty, time.Time{})
	}
}

// sameListCaches reports whether a and b carry the same feed caches, which is what list-cache.json
// renders. A copy-on-write profile shares the slices it did not change, so the common case is a pointer
// comparison.
func sameListCaches(a, b *model.Profile) bool {
	if a == nil || b == nil {
		return a == b
	}
	of := func(p *model.Profile) map[string]*model.RoutingList {
		m := map[string]*model.RoutingList{}
		for i := range p.RoutingLists {
			if hasFeedCache(&p.RoutingLists[i]) {
				m[p.RoutingLists[i].ID] = &p.RoutingLists[i]
			}
		}
		return m
	}
	ma, mb := of(a), of(b)
	if len(ma) != len(mb) {
		return false
	}
	for id, x := range ma {
		y, ok := mb[id]
		if !ok || x.CIDRSource != y.CIDRSource || x.DomainSource != y.DomainSource ||
			x.CIDRRefreshed != y.CIDRRefreshed || x.DomainRefreshed != y.DomainRefreshed ||
			!sameStrings(x.CIDRCache, y.CIDRCache) || !sameStrings(x.DomainCache, y.DomainCache) {
			return false
		}
	}
	return true
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 || &a[0] == &b[0] {
		return true
	}
	return slices.Equal(a, b)
}

// markListCache tells the cache writer the published profile may have new caches. The producer reads
// the profile current at write time, so the writer holds no copy.
func (s *Store) markListCache() {
	if s.cacheW == nil {
		return
	}
	s.cacheW.Mark(func() ([]byte, error) {
		cur := s.cur.Load()
		if cur == nil || cur.p == nil {
			return renderListCache(&model.Profile{})
		}
		return renderListCache(cur.p)
	})
}

// FlushListCaches writes pending feed caches now (graceful shutdown; a committed Apply, after which
// the caches are part of what the router runs). Skipped when the file already holds them.
func (s *Store) FlushListCaches() error {
	if s.cacheW == nil {
		return nil
	}
	return s.cacheW.Flush()
}

// Close flushes pending caches and releases the writer.
func (s *Store) Close() error {
	if s.cacheW == nil {
		return nil
	}
	return s.cacheW.Close()
}

// profileDigest is the hash publish compares to skip a profile.json write that would not change it.
func profileDigest(data []byte) [32]byte { return sha256.Sum256(data) }
