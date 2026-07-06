// Package store persists the user Profile (endpoints/groups/rules) to a JSON
// file and offers thread-safe CRUD. It is intentionally tiny: no database, a
// single atomically-written file under /opt/etc/wayhop/ (see docs/ARCHITECTURE.md).
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"wayhop/internal/atomicfile"
	"wayhop/internal/model"
)

// Store guards a Profile persisted at path using copy-on-write. The published profile is
// IMMUTABLE once installed: a writer clones it, mutates the clone, persists it, and only
// then atomically swaps the clone in — so a reader loads the current profile with no lock
// and no per-read clone, and keeps a consistent snapshot even as a writer proceeds.
type Store struct {
	path string
	// wmu serializes writers so the load-clone-mutate-persist-publish sequence is atomic
	// with respect to other writers (two concurrent writers can't lose each other's update).
	// Readers take NO lock — they atomically load cur.
	wmu sync.Mutex
	// cur is the currently-published profile. It is never mutated after being Store()d:
	// writers publish a freshly-built copy, so a lock-free reader that loaded an earlier
	// pointer holds a stable, unchanging view.
	cur atomic.Pointer[model.Profile]
	// gen bumps on every durably-published mutation. Lock-free readers that memoize a
	// profile-derived result (e.g. the native-only datapath verdict) key their cache on
	// it: same gen ⇒ the profile is byte-identical, so the cached value is still valid.
	gen atomic.Uint64
}

// Open loads the profile at path, creating an empty one if it does not exist.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	// Treat a missing OR empty/whitespace-only file identically: start from an empty
	// profile and rewrite a valid file. An existing zero-length / whitespace-only file
	// is the canonical power-loss / jffs2 / overlayfs artifact on a router; it reads as
	// (nil, nil), would otherwise reach json.Unmarshal([]byte{}) → "unexpected end of
	// JSON input" → the daemon refuses to boot. A genuinely-corrupt NON-empty file
	// still falls through to the parse error below.
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(bytes.TrimSpace(data)) == 0) {
		if err == nil {
			log.Printf("wayhop: profile %s is empty; recreating empty profile", path)
		}
		empty := model.Profile{}
		s.cur.Store(&empty)
		return s, s.persist(&empty)
	}
	if err != nil {
		return nil, fmt.Errorf("read profile %s: %w", path, err)
	}
	var p model.Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse profile %s: %w", path, err)
	}
	s.cur.Store(&p)
	return s, nil
}

// Profile returns the current profile as a value whose top-level slices share the
// published, immutable backing arrays — copy-on-write, so there is no per-read deep clone.
// The returned top-level slice headers are capped to their length (s[:n:n]) so a caller's
// append REALLOCATES instead of scribbling the shared backing that other readers alias.
//
// CONTRACT: the returned profile is a READ-ONLY snapshot. Callers must not mutate its
// elements or nested fields in place — no `p.Endpoints[i] = x`, no writing into
// Endpoint.Params / Group.Members / Rule.Domain / RoutingList.CIDRCache. Every writer
// REPLACES whole elements/fields on a private clone (cloneProfile) and publishes atomically,
// so a reader holding an older snapshot sees a consistent, unchanging view. (Verified: no
// production caller mutates the returned profile.) A writer's own in-place slice compaction
// (removeString, kept[:0]) is safe because it runs on the clone, never on a published copy.
func (s *Store) Profile() model.Profile {
	cur := s.cur.Load()
	if cur == nil { // defensive: a Store built without Open() has no published profile yet
		return model.Profile{}
	}
	p := *cur
	p.Endpoints = p.Endpoints[:len(p.Endpoints):len(p.Endpoints)]
	p.Groups = p.Groups[:len(p.Groups):len(p.Groups)]
	p.Rules = p.Rules[:len(p.Rules):len(p.Rules)]
	p.RoutingLists = p.RoutingLists[:len(p.RoutingLists):len(p.RoutingLists)]
	return p
}

// cloneProfile returns a mutable working copy of src: the top-level slices (and each
// Group.Members, which the delete paths compact in place) are cloned so a writer can
// mutate/compact/append them without touching src's — hence a published profile's — backing
// arrays. Deeper element fields (Endpoint.Params map, Rule.Domain/IPCIDR/Port, RoutingList.
// Manual/CIDRCache) are shared by reference: the mutators only ever REPLACE them wholesale
// (never write into them in place), so the shared originals stay immutable for readers.
func cloneProfile(src *model.Profile) model.Profile {
	p := *src
	p.Endpoints = append([]model.Endpoint{}, src.Endpoints...)
	p.Groups = append([]model.Group{}, src.Groups...)
	// Group.Members is compacted IN PLACE by removeString (DeleteEndpoint/DeleteGroup
	// pruning), so it must be cloned too — otherwise the writer would scribble a slice a
	// lock-free reader (generator/monitor) still aliases.
	for i := range p.Groups {
		p.Groups[i].Members = append([]string{}, src.Groups[i].Members...)
	}
	p.Rules = append([]model.Rule{}, src.Rules...)
	p.RoutingLists = append([]model.RoutingList{}, src.RoutingLists...)
	return p
}

// snapshot builds a mutable working copy of the currently-published profile. Callers hold
// s.wmu, so cur can't be swapped between this load and the eventual publish().
func (s *Store) snapshot() model.Profile {
	return cloneProfile(s.cur.Load())
}

// Replace swaps the whole profile (used by bulk import / subscription sync / backup
// restore). It VALIDATES the incoming profile first, so a bad set (dangling outbound,
// cyclic group, duplicate/empty id) can never overwrite a good, working profile and break
// the next Apply — every caller can rely on this as the store-layer gate (defense in depth).
func (s *Store) Replace(p model.Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	// Clone before publishing: the caller may retain aliases to p's slices, and a published
	// profile must be immutable, so no external writer may hold our backing arrays.
	cp := cloneProfile(&p)
	return s.publish(&cp)
}

// UpsertEndpoint inserts or replaces an endpoint by ID.
func (s *Store) UpsertEndpoint(e model.Endpoint) error {
	if e.ID == "" {
		return errors.New("endpoint id is required")
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	for i := range p.Endpoints {
		if p.Endpoints[i].ID == e.ID {
			p.Endpoints[i] = e
			return s.publish(&p)
		}
	}
	p.Endpoints = append(p.Endpoints, e)
	return s.publish(&p)
}

// DeleteEndpoint removes an endpoint, pruning it from group members. It refuses
// if a rule still targets the endpoint (the caller should repoint the rule first).
func (s *Store) DeleteEndpoint(id string) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	for _, r := range p.Rules {
		if r.Outbound == id {
			return fmt.Errorf("endpoint %q is used by rule %q; repoint it first", id, r.ID)
		}
	}
	// Refuse if this endpoint is the sole member of a group — pruning it would
	// leave a zero-member group, which fails Validate() and blocks every Apply.
	for _, g := range p.Groups {
		if onlyMember(g.Members, id) {
			return fmt.Errorf("endpoint %q is the only member of group %q; remove or repoint that group first", id, g.ID)
		}
	}
	// Refuse if a routing list routes (or downloads) via this endpoint — a dangling
	// outbound fails Validate() and blocks every Apply (same intent as the rule guard).
	for _, rl := range p.RoutingLists {
		if rl.Outbound == id || rl.DownloadVia == id {
			return fmt.Errorf("endpoint %q is used by routing list %q (route/download via); repoint it first", id, rl.ID)
		}
	}
	kept := p.Endpoints[:0]
	found := false
	for _, e := range p.Endpoints {
		if e.ID == id {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if !found {
		return fmt.Errorf("endpoint %q not found", id)
	}
	p.Endpoints = kept
	for gi := range p.Groups {
		p.Groups[gi].Members = removeString(p.Groups[gi].Members, id)
	}
	return s.publish(&p)
}

// UpsertGroup inserts or replaces a group by ID.
func (s *Store) UpsertGroup(g model.Group) error {
	if g.ID == "" {
		return errors.New("group id is required")
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	for i := range p.Groups {
		if p.Groups[i].ID == g.ID {
			p.Groups[i] = g
			return s.publish(&p)
		}
	}
	p.Groups = append(p.Groups, g)
	return s.publish(&p)
}

// DeleteGroup removes a group; refuses if a rule targets it.
func (s *Store) DeleteGroup(id string) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	for _, r := range p.Rules {
		if r.Outbound == id {
			return fmt.Errorf("group %q is used by rule %q; repoint it first", id, r.ID)
		}
	}
	// Refuse if this group is the sole member of another group (nested groups) —
	// pruning it would leave that parent empty and fail Validate().
	for _, g := range p.Groups {
		if g.ID != id && onlyMember(g.Members, id) {
			return fmt.Errorf("group %q is the only member of group %q; remove or repoint that group first", id, g.ID)
		}
	}
	// Refuse if a routing list routes (or downloads) via this group — see DeleteEndpoint.
	for _, rl := range p.RoutingLists {
		if rl.Outbound == id || rl.DownloadVia == id {
			return fmt.Errorf("group %q is used by routing list %q (route/download via); repoint it first", id, rl.ID)
		}
	}
	kept := p.Groups[:0]
	found := false
	for _, g := range p.Groups {
		if g.ID == id {
			found = true
			continue
		}
		kept = append(kept, g)
	}
	if !found {
		return fmt.Errorf("group %q not found", id)
	}
	p.Groups = kept
	// Mirror DeleteEndpoint: prune the deleted group's id from any group that
	// listed it as a nested member, so the profile stays Validate-clean.
	for gi := range p.Groups {
		p.Groups[gi].Members = removeString(p.Groups[gi].Members, id)
	}
	return s.publish(&p)
}

// onlyMember reports whether id is in members and every member equals id, so
// removing id would empty the slice.
func onlyMember(members []string, id string) bool {
	if len(members) == 0 {
		return false
	}
	for _, m := range members {
		if m != id {
			return false
		}
	}
	return true
}

// UpsertRule inserts or replaces a rule by ID.
func (s *Store) UpsertRule(r model.Rule) error {
	if r.ID == "" {
		return errors.New("rule id is required")
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	for i := range p.Rules {
		if p.Rules[i].ID == r.ID {
			p.Rules[i] = r
			return s.publish(&p)
		}
	}
	p.Rules = append(p.Rules, r)
	return s.publish(&p)
}

// DeleteRule removes a rule by ID.
func (s *Store) DeleteRule(id string) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	kept := p.Rules[:0]
	found := false
	for _, r := range p.Rules {
		if r.ID == id {
			found = true
			continue
		}
		kept = append(kept, r)
	}
	if !found {
		return fmt.Errorf("rule %q not found", id)
	}
	p.Rules = kept
	return s.publish(&p)
}

// UpsertRoutingList inserts or replaces a routing list by ID.
func (s *Store) UpsertRoutingList(rl model.RoutingList) error {
	if rl.ID == "" {
		return errors.New("routing list id is required")
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	for i := range p.RoutingLists {
		if p.RoutingLists[i].ID == rl.ID {
			// Keep the system-managed CIDRCache consistent with CIDRSource across a user
			// edit:
			//   • source CHANGED → the old cache is stale → drop it unconditionally (even
			//     if the incoming struct still carries it, e.g. a UI GET→edit→PUT round-trip
			//     that echoed back the old cidr_cache) — the refresh loop repopulates it;
			//   • source UNCHANGED but the edit omitted the cache → preserve the existing
			//     value the UI didn't send back.
			switch {
			case rl.CIDRSource != p.RoutingLists[i].CIDRSource:
				rl.CIDRCache = nil
				rl.CIDRRefreshed = 0 // stale freshness would delay the new source's first fetch
			case len(rl.CIDRCache) == 0:
				rl.CIDRCache = p.RoutingLists[i].CIDRCache
				if rl.CIDRRefreshed == 0 {
					rl.CIDRRefreshed = p.RoutingLists[i].CIDRRefreshed // system-managed, UI doesn't echo it
				}
			}
			p.RoutingLists[i] = rl
			return s.publish(&p)
		}
	}
	p.RoutingLists = append(p.RoutingLists, rl)
	return s.publish(&p)
}

// SetRoutingListCache replaces a routing list's system-managed CIDRCache (the last-good
// result of fetching its CIDRSource — see the auto-refresh loop). Atomic + persisted.
func (s *Store) SetRoutingListCache(id string, cidrs []string) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	for i := range p.RoutingLists {
		if p.RoutingLists[i].ID == id {
			p.RoutingLists[i].CIDRCache = cidrs
			p.RoutingLists[i].CIDRRefreshed = time.Now().Unix()
			return s.publish(&p)
		}
	}
	return fmt.Errorf("routing list %q not found", id)
}

// CacheUpdate is one refreshed feed result for SetRoutingListCaches. Source is the CIDRSource the
// fetch was performed AGAINST: the write is skipped when the list's source has changed since (a
// user re-pointed the list mid-fetch — writing would resurrect the OLD feed's CIDRs into the
// re-sourced list, which UpsertRoutingList deliberately cleared).
type CacheUpdate struct {
	Source string
	CIDRs  []string
}

// SetRoutingListCaches replaces the CIDRCache of MANY routing lists in ONE atomic profile write. The
// auto-refresh ticker coalesces a whole tick's changed lists here so K changed lists cost ONE
// whole-profile rewrite/fsync, not K — the flash-wear protection for the router overlay. Entries
// whose id no longer exists or whose CIDRSource no longer matches are skipped; returns how many
// lists were actually updated, and does NOT touch flash when that is zero.
func (s *Store) SetRoutingListCaches(caches map[string]CacheUpdate) (int, error) {
	if len(caches) == 0 {
		return 0, nil
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	matched := 0
	now := time.Now().Unix()
	for i := range p.RoutingLists {
		if up, ok := caches[p.RoutingLists[i].ID]; ok && p.RoutingLists[i].CIDRSource == up.Source {
			p.RoutingLists[i].CIDRCache = up.CIDRs
			p.RoutingLists[i].CIDRRefreshed = now
			matched++
		}
	}
	if matched == 0 {
		return 0, nil // every entry raced a delete/re-source — nothing changed, spend no flash write
	}
	return matched, s.publish(&p)
}

// DeleteRoutingList removes a routing list by ID.
func (s *Store) DeleteRoutingList(id string) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	kept := p.RoutingLists[:0]
	found := false
	for _, rl := range p.RoutingLists {
		if rl.ID == id {
			found = true
			continue
		}
		kept = append(kept, rl)
	}
	if !found {
		return fmt.Errorf("routing list %q not found", id)
	}
	p.RoutingLists = kept
	return s.publish(&p)
}

// SetDNS replaces the profile's DNS plane (the "DNS" section) atomically. A nil settings clears it
// (back to the no-dns-block default). Copy-on-write like the other CRUD methods; the returned live
// profile stays read-only.
func (s *Store) SetDNS(dns *model.DNSSettings) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	p.DNS = dns
	return s.publish(&p)
}

// persist atomically + durably writes p to disk.
func (s *Store) persist(p *model.Profile) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(s.path, data, 0o600)
}

// publish persists the mutated working copy and, ONLY if the durable write succeeds,
// atomically installs it as the new profile and bumps gen. On failure nothing is published:
// the previous profile stays live, so the in-memory state never diverges from disk — the
// router overlay can ENOSPC mid-edit, and a phantom in-RAM change that feeds an Apply yet
// vanishes on reboot is worse than a surfaced error. Callers must hold s.wmu, so the
// snapshot()..Store() window is atomic with respect to other writers.
func (s *Store) publish(p *model.Profile) error {
	if err := s.persist(p); err != nil {
		return err
	}
	s.cur.Store(p)
	s.gen.Add(1)
	return nil
}

// Gen returns the current profile generation: it increments on every durably-committed
// mutation and never resets while the process lives. A reader that caches a value derived
// purely from the profile can compare Gen() to skip recomputing when nothing has changed.
func (s *Store) Gen() uint64 {
	return s.gen.Load()
}

func removeString(ss []string, target string) []string {
	out := ss[:0]
	for _, s := range ss {
		if s != target {
			out = append(out, s)
		}
	}
	return out
}
