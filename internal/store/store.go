// Package store persists the user Profile (endpoints/groups/rules) to a JSON
// file and offers thread-safe CRUD. It is intentionally tiny: no database, a
// single atomically-written file under /opt/etc/wayhop/ (see docs/ARCHITECTURE.md (development repository)).
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
// published pairs the live profile with its generation so BOTH are installed in ONE
// atomic Store. Keeping them as two independent atomics let a lock-free reader interleave
// between cur.Store(p) and gen.Add(1) and observe the NEW profile with the OLD gen — a
// transient violation of the "same gen ⇒ byte-identical profile" invariant that a
// gen-memoizing reader (nativeOnlyCached) would turn into a stale cache HIT. A single
// pointer swap makes the profile and its gen indivisible.
type published struct {
	p   *model.Profile
	gen uint64
}

type Store struct {
	path string
	// wmu serializes writers so the load-clone-mutate-persist-publish sequence is atomic
	// with respect to other writers (two concurrent writers can't lose each other's update).
	// Readers take NO lock — they atomically load cur.
	wmu sync.Mutex
	// cur is the currently-published (profile, gen) pair. It is never mutated after being
	// Store()d: writers publish a freshly-built snapshot, so a lock-free reader that loaded
	// an earlier pointer holds a stable, unchanging view whose gen matches its profile.
	// gen bumps on every durably-published mutation; a lock-free reader that memoizes a
	// profile-derived result (e.g. the native-only datapath verdict) keys its cache on it.
	cur atomic.Pointer[published]
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
		s.cur.Store(&published{p: &empty})
		return s, s.persist(&empty)
	}
	if err != nil {
		return nil, fmt.Errorf("read profile %s: %w", path, err)
	}
	var p model.Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse profile %s: %w", path, err)
	}
	s.cur.Store(&published{p: &p})
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
	if cur == nil || cur.p == nil { // defensive: a Store built without Open() has no published profile yet
		return model.Profile{}
	}
	return cappedProfile(cur.p)
}

// cappedProfile returns p as a value whose top-level slice headers are capped to their length
// (s[:n:n]) so a caller's append REALLOCATES instead of scribbling the shared, immutable backing
// arrays other readers alias. Shared by Profile() and Snapshot() so the capping rule is identical
// for both — a second hand-inlined copy is exactly how the two would drift.
func cappedProfile(p *model.Profile) model.Profile {
	v := *p
	v.Endpoints = v.Endpoints[:len(v.Endpoints):len(v.Endpoints)]
	v.Groups = v.Groups[:len(v.Groups):len(v.Groups)]
	v.Rules = v.Rules[:len(v.Rules):len(v.Rules)]
	v.RoutingLists = v.RoutingLists[:len(v.RoutingLists):len(v.RoutingLists)]
	v.DeviceGroups = v.DeviceGroups[:len(v.DeviceGroups):len(v.DeviceGroups)]
	return v
}

// Snapshot returns the current profile AND its generation from ONE atomic load of the published
// pair, so the two can never disagree. Profile() and Gen() each load cur independently; a caller
// that needs a (profile, revision) pair — a DNS GET whose rev the client hands back as an If-Match,
// an Apply plan keyed to a revision — must use this instead of calling them separately. A writer
// committing between two independent loads yields the OLD profile with the NEW gen; a client that
// edits that stale profile and submits the new gen then PASSES a compare-and-set it should have
// failed, silently discarding the commit it never saw. A single load closes that window.
func (s *Store) Snapshot() (model.Profile, uint64) {
	cur := s.cur.Load()
	if cur == nil || cur.p == nil {
		return model.Profile{}, 0
	}
	return cappedProfile(cur.p), cur.gen
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
	// DeviceGroups: top-level slice cloned so DeleteDeviceGroup's kept[:0] compaction runs on the
	// writer's private copy. Members + each list's ScopeGroups are shared by reference and only ever
	// REPLACED wholesale (Upsert swaps the group; DeleteDeviceGroup assigns a fresh ScopeGroups).
	p.DeviceGroups = append([]model.DeviceGroup{}, src.DeviceGroups...)
	return p
}

// snapshot builds a mutable working copy of the currently-published profile. Callers hold
// s.wmu, so cur can't be swapped between this load and the eventual publish().
func (s *Store) snapshot() model.Profile {
	cur := s.cur.Load()
	if cur == nil || cur.p == nil {
		return model.Profile{}
	}
	return cloneProfile(cur.p)
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

// Reconcile runs fn on a mutable copy of the profile under the write lock and publishes the copy
// only when fn reports a change. It is for a writer that derives its change from the profile itself
// (the native-tunnel sync), so an edit made between its read and its write is never lost.
func (s *Store) Reconcile(fn func(p *model.Profile) bool) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	if !fn(&p) {
		return nil
	}
	return s.publish(&p)
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

// UpsertEndpoints inserts-or-replaces many endpoints by ID in a SINGLE snapshot+publish under one
// wmu hold — the batch form of UpsertEndpoint. Bulk import and subscription refresh use it so N adds
// cost ONE profile write, not N: a per-endpoint publish rewrites the whole (growing) profile and
// fsyncs each time, i.e. O(N^2) bytes and 2N fsyncs — a real multi-minute stall + flash-wear hazard
// on a router. Like UpsertEndpoint it does NOT whole-profile-validate (Apply is the validation gate),
// so it can't regress on a profile a prior unvalidated upsert left imperfect. An endpoint with an
// empty ID is skipped and its input index returned in skipped.
func (s *Store) UpsertEndpoints(eps []model.Endpoint) (skipped []int, err error) {
	if len(eps) == 0 {
		return nil, nil
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	idx := make(map[string]int, len(p.Endpoints))
	for i := range p.Endpoints {
		idx[p.Endpoints[i].ID] = i
	}
	for k := range eps {
		e := eps[k]
		if e.ID == "" {
			skipped = append(skipped, k)
			continue
		}
		if i, ok := idx[e.ID]; ok {
			p.Endpoints[i] = e
		} else {
			idx[e.ID] = len(p.Endpoints)
			p.Endpoints = append(p.Endpoints, e)
		}
	}
	return skipped, s.publish(&p)
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
	// Refuse if a DNS server detours through this endpoint — a dangling Detour fails Validate()
	// ("detour ... does not resolve") and blocks every Apply, same intent as the guards above.
	// p.DNS is an optional pointer (nil when no DNS plane is configured), so guard it.
	if p.DNS != nil {
		for _, ds := range p.DNS.Servers {
			if ds.Detour == id {
				return fmt.Errorf("endpoint %q is used by DNS server %q (detour); repoint it first", id, ds.Tag)
			}
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
	// Refuse if a DNS server detours through this group — a dangling Detour fails Validate() and
	// blocks every Apply, same intent as the guards above. p.DNS is optional (nil when unset).
	if p.DNS != nil {
		for _, ds := range p.DNS.Servers {
			if ds.Detour == id {
				return fmt.Errorf("group %q is used by DNS server %q (detour); repoint it first", id, ds.Tag)
			}
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
			// The domain feed's cache follows the identical rule, for the identical reason.
			switch {
			case rl.DomainSource != p.RoutingLists[i].DomainSource:
				rl.DomainCache = nil
				rl.DomainRefreshed = 0
			case len(rl.DomainCache) == 0:
				rl.DomainCache = p.RoutingLists[i].DomainCache
				if rl.DomainRefreshed == 0 {
					rl.DomainRefreshed = p.RoutingLists[i].DomainRefreshed
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
	// DomainSource / Domains are the same contract for a list's name feed: guarded against a
	// mid-fetch re-source the same way, and written in the same profile write so a list carrying
	// both kinds costs one flash rewrite, not two.
	DomainSource string
	Domains      []string
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
		up, ok := caches[p.RoutingLists[i].ID]
		if !ok {
			continue
		}
		hit := false
		if up.Source != "" && p.RoutingLists[i].CIDRSource == up.Source {
			p.RoutingLists[i].CIDRCache = up.CIDRs
			p.RoutingLists[i].CIDRRefreshed = now
			hit = true
		}
		if up.DomainSource != "" && p.RoutingLists[i].DomainSource == up.DomainSource {
			p.RoutingLists[i].DomainCache = up.Domains
			p.RoutingLists[i].DomainRefreshed = now
			hit = true
		}
		if hit {
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
	// Refuse if an ENABLED DNS rule still references this list via rule_sets — a dangling rule_set
	// fails validateDNS ("rule_set %q is not a routing list") and blocks EVERY subsequent Apply,
	// mirroring the endpoint/group detour delete guards. Disabled rules are skipped by validateDNS,
	// so they don't block. p.DNS is an optional pointer (nil when no DNS plane exists).
	if p.DNS != nil {
		for i := range p.DNS.Rules {
			r := &p.DNS.Rules[i]
			if r.Disabled {
				continue
			}
			for _, rs := range r.RuleSets {
				if rs == id {
					return fmt.Errorf("routing list %q is used by DNS rule %q (rule_set); remove or repoint that DNS rule first", id, r.ID)
				}
			}
		}
	}
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

// UpsertDeviceGroup adds or replaces a device group (a named MAC/IP set that RoutingLists scope to).
// Atomic + persisted, copy-on-write; the returned live profile stays read-only.
func (s *Store) UpsertDeviceGroup(g model.DeviceGroup) error {
	if g.ID == "" {
		return errors.New("device group id is required")
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	for i := range p.DeviceGroups {
		if p.DeviceGroups[i].ID == g.ID {
			p.DeviceGroups[i] = g
			return s.publish(&p)
		}
	}
	p.DeviceGroups = append(p.DeviceGroups, g)
	return s.publish(&p)
}

// DeleteDeviceGroup removes a device group and prunes its id from every RoutingList.ScopeGroups. A
// list whose scope becomes empty under "only"/"except" is reset to all-clients (ScopeMode "") so the
// profile stays valid — a scoped list can't reference zero groups. Atomic + persisted.
func (s *Store) DeleteDeviceGroup(id string) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	kept := p.DeviceGroups[:0]
	found := false
	for _, g := range p.DeviceGroups {
		if g.ID == id {
			found = true
			continue
		}
		kept = append(kept, g)
	}
	if !found {
		return fmt.Errorf("device group %q not found", id)
	}
	p.DeviceGroups = kept
	// Referential integrity: drop the deleted id from each list's scope, REPLACING the slice wholesale
	// (never mutating the shared original in place — a lock-free reader may still alias it).
	for i := range p.RoutingLists {
		sg := p.RoutingLists[i].ScopeGroups
		if len(sg) == 0 {
			continue
		}
		pruned := make([]string, 0, len(sg))
		for _, gid := range sg {
			if gid != id {
				pruned = append(pruned, gid)
			}
		}
		if len(pruned) == len(sg) {
			continue // this list didn't reference the deleted group
		}
		if len(pruned) == 0 {
			p.RoutingLists[i].ScopeMode = "" // no groups left → back to all-clients so Validate passes
			p.RoutingLists[i].ScopeGroups = nil
		} else {
			p.RoutingLists[i].ScopeGroups = pruned
		}
	}
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

// ErrStaleGen reports that a compare-and-set write was based on a profile generation that is no
// longer current: somebody else committed in between. The write is refused, not merged.
var ErrStaleGen = errors.New("profile changed since it was read")

// SetDNSIfGen replaces the DNS plane only if the profile is still at wantGen.
//
// The DNS plane has no per-object API — the whole plane is submitted on every edit, so removing one
// resolver rewrites every resolver and every rule. Without this check two editors silently lose
// each other's work and both get a 200. Reading the generation under wmu is what makes the check
// meaningful: publish() bumps the generation under the same lock, so no commit can slip between the
// comparison and the write.
// It returns the generation the write produced (on success) or the current generation (on a stale
// refusal), read under wmu so the returned number is exactly the pair for the DNS the caller now
// holds — the API response must not re-read Gen() separately, or it reopens the torn pair at the
// write boundary that Snapshot closes at the read boundary.
func (s *Store) SetDNSIfGen(dns *model.DNSSettings, wantGen uint64) (uint64, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if got := s.Gen(); got != wantGen {
		return got, fmt.Errorf("%w: expected generation %d, current is %d", ErrStaleGen, wantGen, got)
	}
	p := s.snapshot()
	p.DNS = dns
	if err := s.publish(&p); err != nil {
		return s.Gen(), err
	}
	return s.Gen(), nil // under wmu: no other writer can bump between publish and this read
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
	// A write may not switch something off while live references still point at it, nor aim a new
	// reference at something already off. The delete paths refuse exactly these references, but the
	// same break is reachable by ordinary edits that strand nothing and are answered 200 — disabling
	// an endpoint a rule targets, or pointing a rule at one that is already disabled. The stored
	// profile then fails Validate(), so EVERY later Apply fails, including applies that have nothing
	// to do with that reference, and nothing said so at the moment of the edit.
	//
	// The subject is Validate itself, not a second hand-written opinion about the same question that
	// would drift from it. Only the disabled-reference CLASS is refused: the other failures describe a
	// draft that is merely unfinished (a group whose members come next), which authoring depends on.
	//
	// Only a valid->invalid transition is refused. A profile that is ALREADY invalid keeps accepting
	// writes, or an operator could not repair one — the edit that fixes rule A would be refused
	// because rule B is still broken.
	if err := p.Validate(); err != nil {
		var dre *model.DisabledRefError
		if errors.As(err, &dre) {
			if prev := s.cur.Load(); prev != nil && prev.p.Validate() == nil {
				return fmt.Errorf("this change would leave the profile unappliable: %w", err)
			}
		}
	}
	if err := s.persist(p); err != nil {
		return err
	}
	// Install the profile and its bumped generation as ONE atomic snapshot, so a
	// lock-free reader never sees the new profile paired with the old gen. The caller
	// holds s.wmu, so reading the previous gen and computing gen+1 is race-free.
	var g uint64
	if prev := s.cur.Load(); prev != nil {
		g = prev.gen
	}
	s.cur.Store(&published{p: p, gen: g + 1})
	return nil
}

// Gen returns the current profile generation: it increments on every durably-committed
// mutation and never resets while the process lives. A reader that caches a value derived
// purely from the profile can compare Gen() to skip recomputing when nothing has changed.
func (s *Store) Gen() uint64 {
	if cur := s.cur.Load(); cur != nil {
		return cur.gen
	}
	return 0
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

// ReorderRoutingLists rewrites the routing-list order to match ids.
//
// The order is not cosmetic: the generator emits one route rule per list in slice order and sing-box
// takes the FIRST match, so moving a list changes which one wins. There is no order field — the
// slice order IS the order — so a reorder has to rewrite the slice.
//
// ids must name exactly the lists that exist, once each. A partial or padded list would silently
// drop or duplicate a routing list, and a reorder that quietly loses a rule is far worse than one
// that refuses.
func (s *Store) ReorderRoutingLists(ids []string) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()

	byID := make(map[string]int, len(p.RoutingLists))
	for i := range p.RoutingLists {
		byID[p.RoutingLists[i].ID] = i
	}
	if len(ids) != len(p.RoutingLists) {
		return fmt.Errorf("reorder must list every routing list exactly once: got %d, have %d",
			len(ids), len(p.RoutingLists))
	}
	seen := make(map[string]bool, len(ids))
	out := make([]model.RoutingList, 0, len(ids))
	for _, id := range ids {
		idx, ok := byID[id]
		if !ok {
			return fmt.Errorf("reorder names unknown routing list %q", id)
		}
		if seen[id] {
			return fmt.Errorf("reorder names routing list %q twice", id)
		}
		seen[id] = true
		out = append(out, p.RoutingLists[idx])
	}
	p.RoutingLists = out
	return s.publish(&p)
}

// EndpointDependent names one thing that routes through an endpoint, in terms the panel can show.
type EndpointDependent struct {
	Kind string `json:"kind"` // "rule" | "routing_list" | "download_via" | "dns_detour" | "group_member"
	ID   string `json:"id"`
	Name string `json:"name"`
}

// GroupDeleteBlockers lists what makes DeleteGroup refuse, in the same shape the endpoint path
// already uses.
//
// DeleteGroup answered with a sentence, so the panel could only show it raw — measured on the demo:
// pointing the default route at a group and pressing Delete produced the toast `group
// "grp-order-probe" is used by rule "default"; repoint it first`, with nothing to act on. The
// endpoint path solved this long ago by naming its dependents; groups now answer the same way.
//
// The two conditions here are exactly the two DeleteGroup refuses on, and the test beside it pins
// that: a blocker list that drifts from the refusal would promise a delete the store then rejects.
func (s *Store) GroupDeleteBlockers(id string) []EndpointDependent {
	p := s.Profile()
	var out []EndpointDependent
	for _, r := range p.Rules {
		if r.Outbound == id {
			out = append(out, EndpointDependent{Kind: "rule", ID: r.ID, Name: r.ID})
		}
	}
	for _, g := range p.Groups {
		if g.ID != id && onlyMember(g.Members, id) {
			out = append(out, EndpointDependent{Kind: "sole_member_of", ID: g.ID, Name: g.Name})
		}
	}
	// Routing lists and DNS detours refuse too. They were missing from the first cut of this list, and
	// a live DELETE on the demo answered `group "auto" is used by DNS server "dns_secure_bk" (detour)`
	// while the blockers came back empty — a list shorter than the refusal promises a delete the store
	// then rejects, which is the failure this function exists to prevent.
	for _, rl := range p.RoutingLists {
		if rl.Outbound == id || rl.DownloadVia == id {
			out = append(out, EndpointDependent{Kind: "routing_list", ID: rl.ID, Name: rl.Name})
		}
	}
	if p.DNS != nil {
		for _, ds := range p.DNS.Servers {
			if ds.Detour == id {
				out = append(out, EndpointDependent{Kind: "dns_detour", ID: ds.Tag, Name: ds.Tag})
			}
		}
	}
	return out
}

// EndpointDependents lists everything that would dangle if this endpoint were removed.
//
// Deletion used to simply refuse while naming the first blocker, which is a dead end: the operator
// is told to "repoint it first" without being told what to repoint it to, and with several
// dependents they discover them one refusal at a time. Returning the whole set lets the panel offer
// a replacement and do it in one step.
func (s *Store) EndpointDependents(id string) []EndpointDependent {
	p := s.Profile()
	var out []EndpointDependent
	for _, r := range p.Rules {
		if r.Outbound == id {
			out = append(out, EndpointDependent{Kind: "rule", ID: r.ID, Name: r.ID})
		}
	}
	for _, rl := range p.RoutingLists {
		if rl.Outbound == id {
			out = append(out, EndpointDependent{Kind: "routing_list", ID: rl.ID, Name: rl.Name})
		}
		if rl.DownloadVia == id {
			out = append(out, EndpointDependent{Kind: "download_via", ID: rl.ID, Name: rl.Name})
		}
	}
	if p.DNS != nil {
		for _, ds := range p.DNS.Servers {
			if ds.Detour == id {
				out = append(out, EndpointDependent{Kind: "dns_detour", ID: ds.Tag, Name: ds.Tag})
			}
		}
	}
	for _, g := range p.Groups {
		if onlyMember(g.Members, id) {
			out = append(out, EndpointDependent{Kind: "group_member", ID: g.ID, Name: g.Name})
		}
	}
	return out
}

// EndpointReplacements are the outbounds a dependent may be moved to when an endpoint is deleted.
//
// Groups and the two builtins are offered alongside endpoints because a routing list may target any
// of them. A group that would be left empty by this deletion is excluded: moving a list onto it
// would trade one dangling reference for another.
func (s *Store) EndpointReplacements(id string) []string {
	p := s.Profile()
	out := []string{model.OutboundDirect, model.OutboundBlock}
	for _, e := range p.Endpoints {
		if e.ID != id {
			out = append(out, e.ID)
		}
	}
	for _, g := range p.Groups {
		if !onlyMember(g.Members, id) {
			out = append(out, g.ID)
		}
	}
	return out
}

// DeleteEndpointReplacing repoints every dependent onto replacement and then deletes the endpoint,
// as one published revision so no reader ever observes a dangling outbound.
//
// replacement "" keeps the old refuse-if-referenced behaviour, so a caller that has not asked for a
// move cannot silently rewrite routing.
func (s *Store) DeleteEndpointReplacing(id, replacement string) error {
	if replacement == "" {
		return s.DeleteEndpoint(id)
	}
	if replacement == id {
		return fmt.Errorf("endpoint %q cannot replace itself", id)
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	if !outboundExists(&p, replacement) {
		return fmt.Errorf("replacement outbound %q does not exist", replacement)
	}
	// A group holds endpoints, not builtins or other groups, so a sole-member group can only be
	// repaired with another endpoint. Refusing here keeps the group valid instead of leaving one
	// that fails Validate() at the next Apply.
	replacementIsEndpoint := p.EndpointByID(replacement) != nil
	for _, g := range p.Groups {
		if onlyMember(g.Members, id) && !replacementIsEndpoint {
			return fmt.Errorf("group %q would be left with no members; choose a connection, not %q", g.ID, replacement)
		}
	}
	repointDependents(&p, id, replacement)
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
		members := removeString(p.Groups[gi].Members, id)
		if len(members) == 0 && replacementIsEndpoint {
			members = []string{replacement}
		}
		p.Groups[gi].Members = members
	}
	return s.publish(&p)
}

// repointDependents moves every rule, routing list, list download and DNS detour that points at id
// onto replacement. Deleting an endpoint and switching one off ask the same question of the same
// dependents, so they share the answer rather than each carrying its own copy of these four loops.
// Groups are NOT touched here: their membership rules differ between the two callers (a delete
// prunes the member, a disable swaps it), and that difference is the caller's to state.
func repointDependents(p *model.Profile, id, replacement string) {
	for i := range p.Rules {
		if p.Rules[i].Outbound == id {
			p.Rules[i].Outbound = replacement
		}
	}
	for i := range p.RoutingLists {
		if p.RoutingLists[i].Outbound == id {
			p.RoutingLists[i].Outbound = replacement
		}
		if p.RoutingLists[i].DownloadVia == id {
			p.RoutingLists[i].DownloadVia = replacement
		}
	}
	if p.DNS == nil {
		return
	}
	for i := range p.DNS.Servers {
		if p.DNS.Servers[i].Detour == id {
			p.DNS.Servers[i].Detour = replacement
		}
	}
}

// parkDependents is the other half of that shared answer: everything pointing at id is moved onto
// `direct` and switched off, keeping its name, scope and CIDRs while routing nothing. It cannot
// simply blank the outbound — Validate() resolves the outbound of EVERY routing list and rule,
// enabled or not, so an empty tag would block every later Apply. Disabling matters as much as the
// retarget: left enabled on `direct`, those destinations would get real ISP routes, which is a
// routing decision nobody made.
func parkDependents(p *model.Profile, id string) {
	for i := range p.Rules {
		if p.Rules[i].Outbound == id {
			p.Rules[i].Outbound = model.OutboundDirect
			p.Rules[i].Disabled = true
		}
	}
	for i := range p.RoutingLists {
		if p.RoutingLists[i].Outbound == id {
			p.RoutingLists[i].Outbound = model.OutboundDirect
			p.RoutingLists[i].Enabled = false
		}
		if p.RoutingLists[i].DownloadVia == id {
			p.RoutingLists[i].DownloadVia = ""
		}
	}
	if p.DNS == nil {
		return
	}
	for i := range p.DNS.Servers {
		if p.DNS.Servers[i].Detour == id {
			p.DNS.Servers[i].Detour = ""
		}
	}
}

// outboundExists reports whether a tag names something a dependent may point at.
func outboundExists(p *model.Profile, tag string) bool {
	switch tag {
	case model.OutboundDirect, model.OutboundBlock:
		return true
	}
	return p.EndpointByID(tag) != nil || p.GroupByID(tag) != nil
}

// DetachEndpointDependents parks everything that routes through an endpoint and then deletes it.
//
// This is the "delete it anyway, I will re-point the list later" path. It cannot simply blank the
// outbound: Validate() resolves the outbound of EVERY routing list and rule, enabled or not, so an
// empty or dangling tag would block every later Apply — the exact breakage the delete guard exists
// to prevent. Each dependent is therefore parked on `direct` and switched off, which keeps its
// CIDRs, its scope and its name intact while routing nothing until the operator chooses an exit.
//
// Disabling matters as much as the retarget: on a router where the kernel plane is live, leaving the
// list enabled on `direct` would install real ISP routes for those destinations, which is a routing
// decision nobody made.
func (s *Store) DetachEndpointDependents(id string) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	// A group with no members fails Validate(). Emptying one here would trade a dangling outbound
	// for an invalid group, so this case still needs a decision the operator has to make.
	for _, g := range p.Groups {
		if onlyMember(g.Members, id) {
			return fmt.Errorf("group %q has no other members; delete that group or pick a replacement connection", g.ID)
		}
	}
	parkDependents(&p, id)
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

// containsString reports membership; the member lists are short enough that a map would cost more
// than the scan.
func containsString(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}

// replaceString swaps old for repl in a member list, dropping the entry rather than duplicating when
// repl is already a member — a group listing the same exit twice fails no validation but weights
// urltest twice, which nobody asked for.
func replaceString(ss []string, old, repl string) []string {
	out := make([]string, 0, len(ss))
	seen := make(map[string]bool, len(ss))
	for _, s := range ss {
		if s == old {
			s = repl
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// putEndpoint writes e over the endpoint carrying the same id. The disable paths below EDIT an exit
// the profile already holds; refusing an unknown id keeps them from quietly creating one.
func putEndpoint(p *model.Profile, e model.Endpoint) error {
	for i := range p.Endpoints {
		if p.Endpoints[i].ID == e.ID {
			p.Endpoints[i] = e
			return nil
		}
	}
	return fmt.Errorf("endpoint %q not found", e.ID)
}

// EndpointDisableBlockers are the dependents that stand in the way of switching an endpoint OFF.
//
// Deleting and disabling break a reference the same way — a disabled endpoint is not emitted as an
// outbound either — so this is the delete set with one difference: EVERY group holding the endpoint
// blocks, not only a group it is the sole member of. Validate() rejects a group with a disabled
// member ("group %q: member %q is disabled"), where a delete merely prunes the membership.
func (s *Store) EndpointDisableBlockers(id string) []EndpointDependent {
	out := s.EndpointDependents(id)
	for _, g := range s.Profile().Groups {
		if containsString(g.Members, id) && !onlyMember(g.Members, id) {
			out = append(out, EndpointDependent{Kind: "group_member", ID: g.ID, Name: g.Name})
		}
	}
	return out
}

// EndpointDisableReplacements are the outbounds those blockers may be moved to. Same set a delete
// offers, minus the two builtins when a failover group holds the endpoint: a group member must be an
// endpoint or another group, so offering `direct` there would be offering a choice we then refuse.
func (s *Store) EndpointDisableReplacements(id string) []string {
	out := s.EndpointReplacements(id)
	p := s.Profile()
	inGroup := false
	for _, g := range p.Groups {
		if containsString(g.Members, id) {
			inGroup = true
			break
		}
	}
	if !inGroup {
		return out
	}
	kept := out[:0]
	for _, o := range out {
		if o == model.OutboundDirect || o == model.OutboundBlock {
			continue
		}
		kept = append(kept, o)
	}
	return kept
}

// SetEndpointDisabledReplacing switches an endpoint off and moves everything that routed through it
// onto replacement, as one published revision so no reader observes a dangling outbound.
//
// Switching an exit off was refused outright while anything still pointed at it, and the refusal
// named ids the operator never typed — `routing list "dom-test": outbound "external-nwg0"` — with no
// way forward from the switch they had just clicked. Deleting an endpoint has had the two honest
// answers to that question for a while (move the dependents, or park them); disabling one asks the
// same question of the same dependents, so it now gets the same two answers.
func (s *Store) SetEndpointDisabledReplacing(e model.Endpoint, replacement string) error {
	if e.ID == "" {
		return errors.New("endpoint id is required")
	}
	if replacement == "" {
		return errors.New("a replacement outbound is required")
	}
	if replacement == e.ID {
		return fmt.Errorf("endpoint %q cannot replace itself", e.ID)
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	if !outboundExists(&p, replacement) {
		return fmt.Errorf("replacement outbound %q does not exist", replacement)
	}
	if err := putEndpoint(&p, e); err != nil {
		return err
	}
	memberable := p.EndpointByID(replacement) != nil || p.GroupByID(replacement) != nil
	for gi := range p.Groups {
		if !containsString(p.Groups[gi].Members, e.ID) {
			continue
		}
		if !memberable {
			return fmt.Errorf("group %q holds this connection; %q cannot be a member — choose a connection or a group", p.Groups[gi].ID, replacement)
		}
		p.Groups[gi].Members = replaceString(p.Groups[gi].Members, e.ID, replacement)
	}
	repointDependents(&p, e.ID, replacement)
	return s.publish(&p)
}

// SetEndpointDisabledDetaching switches an endpoint off and parks everything that routed through it
// — the "switch it off anyway, I will re-point these later" path, and the exact counterpart of
// DetachEndpointDependents for a delete. Dependents keep their names, scopes and CIDRs; each is
// moved onto `direct` and switched off, so nothing silently starts routing over the ISP instead.
//
// A group loses the endpoint from its members rather than keeping a disabled one, which Validate()
// rejects. The dialog that offers this lists the group, so it is a choice and not a surprise.
func (s *Store) SetEndpointDisabledDetaching(e model.Endpoint) error {
	if e.ID == "" {
		return errors.New("endpoint id is required")
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	p := s.snapshot()
	for _, g := range p.Groups {
		if onlyMember(g.Members, e.ID) {
			return fmt.Errorf("group %q has no other members; delete that group or pick a replacement connection", g.ID)
		}
	}
	if err := putEndpoint(&p, e); err != nil {
		return err
	}
	parkDependents(&p, e.ID)
	for gi := range p.Groups {
		p.Groups[gi].Members = removeString(p.Groups[gi].Members, e.ID)
	}
	return s.publish(&p)
}
