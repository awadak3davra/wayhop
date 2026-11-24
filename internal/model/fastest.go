package model

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
)

// fastest.go is the model side of "fastest tunnel per routing list": a list with two or more
// candidate tunnels may choose, at runtime, the fastest working one by measurements to its own
// destinations. The runtime itself is the kernel plane's elector (internal/failover, server
// kernelelect.go); this file holds the setting, its defaults and its rules.

// FastestPolicy is a routing list's runtime choice among its candidates. Zero fields mean the
// defaults below; a nil policy on the list means the feature is off.
type FastestPolicy struct {
	Enabled bool `json:"enabled"`
	// Mode is empty for ElectionFor's list-aware default; an explicit mode always wins.
	Mode ElectionMode `json:"mode,omitempty"`
	// Targets are "host:port" destinations that stand for the list (at most 3); empty = automatic.
	Targets       []string `json:"targets,omitempty"`
	IntervalSec   int      `json:"interval_sec,omitempty"`    // 0 = 60; 30..600
	SwitchDeltaMs int      `json:"switch_delta_ms,omitempty"` // 0 = 30 ms
	// SwitchDeltaPct is 20% when zero; latency uses max(ms, %), throughput only the percentage.
	SwitchDeltaPct int `json:"switch_delta_pct,omitempty"`
	MinDwellSec    int `json:"min_dwell_sec,omitempty"` // 0 = 120
	// Pinned holds the list on one candidate until PinnedUntil (unix seconds; 0 = until unpinned).
	Pinned      string   `json:"pinned,omitempty"`
	PinnedUntil int64    `json:"pinned_until,omitempty"`
	Excluded    []string `json:"excluded,omitempty"` // candidates the choice skips
	// OnAllDown is what the list does when no candidate works: "wan" (fall through to the provider,
	// the default), "block" (drop, like a kill switch) or "keep" (stay on the last tunnel).
	OnAllDown     string `json:"on_all_down,omitempty"`
	ResetOnSwitch bool   `json:"reset_on_switch,omitempty"` // drop the list's connections on a switch
	Notify        bool   `json:"notify,omitempty"`          // tell the Telegram bot about switches
}

// Fastest-list bounds and defaults.
const (
	MaxFastestLists       = 32 // own mark + table each; the mark space holds ~250 for everything
	MaxFastestTargets     = 3
	DefaultFastestSec     = 60
	MinFastestSec         = 30
	MaxFastestSec         = 600
	DefaultSwitchDeltaMs  = 30
	DefaultSwitchDeltaPct = 20
	DefaultMinDwellSec    = 120

	OnAllDownWAN   = "wan"
	OnAllDownBlock = "block"
	OnAllDownKeep  = "keep"
)

// ListEgressPrefix tags a kernel egress owned by one fastest list rather than an endpoint or group.
const ListEgressPrefix = "list:"

// ListEgressTag is the kernel egress tag of a fastest list.
func ListEgressTag(listID string) string { return ListEgressPrefix + listID }

// ListEgressID is the list id behind a list egress tag.
func ListEgressID(tag string) (string, bool) {
	if !strings.HasPrefix(tag, ListEgressPrefix) {
		return "", false
	}
	return strings.TrimPrefix(tag, ListEgressPrefix), true
}

// ElectionFor returns the list's election mode. Media-heavy lists default to mixed (latency first,
// then throughput); an explicit mode, including latency, always wins.
func (f FastestPolicy) ElectionFor(rl RoutingList) ElectionMode {
	if f.Mode != "" {
		return f.Mode
	}
	if MediaList(rl) {
		return ElectionMixed
	}
	return ElectionLatency
}

// MediaList reports whether a list carries media traffic (Telegram, Instagram, YouTube), by its id
// and name: the lists whose users feel throughput before delay. "meta" is the catalog's name for the
// Instagram list. Whole words only: "cidr-meta" and "Telegram calls" are media lists, "Metal",
// "MetaMask" and "metacritic" are not.
func MediaList(rl RoutingList) bool {
	words := strings.FieldsFunc(strings.ToLower(rl.ID+" "+rl.Name), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	for _, w := range words {
		switch w {
		case "telegram", "instagram", "youtube", "meta":
			return true
		}
	}
	return false
}

// Interval is the measurement interval in seconds.
func (f FastestPolicy) Interval() int {
	if f.IntervalSec <= 0 {
		return DefaultFastestSec
	}
	return f.IntervalSec
}

// DeltaMs is the absolute switch threshold.
func (f FastestPolicy) DeltaMs() int {
	if f.SwitchDeltaMs <= 0 {
		return DefaultSwitchDeltaMs
	}
	return f.SwitchDeltaMs
}

// DeltaPct is the relative switch threshold.
func (f FastestPolicy) DeltaPct() int {
	if f.SwitchDeltaPct <= 0 {
		return DefaultSwitchDeltaPct
	}
	return f.SwitchDeltaPct
}

// Dwell is the minimum time on a tunnel, in seconds.
func (f FastestPolicy) Dwell() int {
	if f.MinDwellSec <= 0 {
		return DefaultMinDwellSec
	}
	return f.MinDwellSec
}

// AllDown is OnAllDown with its default.
func (f FastestPolicy) AllDown() string {
	if f.OnAllDown == "" {
		return OnAllDownWAN
	}
	return f.OnAllDown
}

// PinActive reports whether the pin holds at unix time now (seconds).
func (f FastestPolicy) PinActive(now int64) bool {
	return f.Pinned != "" && (f.PinnedUntil == 0 || now < f.PinnedUntil)
}

// ListCandidates are the endpoints a list may choose between, in order: Candidates (or Outbound
// when none are set), groups expanded recursively, duplicates and builtins dropped.
func ListCandidates(p *Profile, rl RoutingList) []string {
	src := rl.Candidates
	if len(src) == 0 {
		src = []string{rl.Outbound}
	}
	var out []string
	seen := map[string]bool{}
	var walk func(id string, visiting map[string]bool)
	walk = func(id string, visiting map[string]bool) {
		if id == "" || isBuiltin(id) || visiting[id] {
			return
		}
		if p.EndpointByID(id) != nil {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
			return
		}
		if g := p.GroupByID(id); g != nil {
			visiting[id] = true
			for _, m := range g.Members {
				walk(m, visiting)
			}
			delete(visiting, id)
		}
	}
	for _, id := range src {
		walk(id, map[string]bool{})
	}
	return out
}

// ListKillSwitch reports whether a kill switch covers the list's tunnels: one of its candidates (or
// its Outbound when it names none) is a group with KillSwitch on, directly or through nested groups.
// The list's own egress then inherits it: its traffic must never leave by the provider.
func ListKillSwitch(p *Profile, rl RoutingList) bool {
	src := rl.Candidates
	if len(src) == 0 {
		src = []string{rl.Outbound}
	}
	seen := map[string]bool{}
	var walk func(id string) bool
	walk = func(id string) bool {
		if seen[id] {
			return false
		}
		seen[id] = true
		g := p.GroupByID(id)
		if g == nil {
			return false
		}
		if g.KillSwitch {
			return true
		}
		for _, m := range g.Members {
			if walk(m) {
				return true
			}
		}
		return false
	}
	for _, id := range src {
		if walk(id) {
			return true
		}
	}
	return false
}

// EffectiveAllDown is what the list does when no candidate works, as the router runs it: the saved
// choice, except that "wan" becomes "block" under a kill switch (ListKillSwitch). "keep" stays: the
// table keeps its last tunnel, and the kill switch's blackhole catches the traffic if that tunnel's
// link goes away.
func EffectiveAllDown(p *Profile, rl RoutingList) string {
	mode := OnAllDownWAN
	if rl.Fastest != nil {
		mode = rl.Fastest.AllDown()
	}
	if mode == OnAllDownWAN && ListKillSwitch(p, rl) {
		return OnAllDownBlock
	}
	return mode
}

// FastestActive reports whether a list asks for the runtime choice and has something to choose
// between: enabled, switched on, two or more candidates.
func FastestActive(p *Profile, rl RoutingList) bool {
	return rl.Enabled && rl.Fastest != nil && rl.Fastest.Enabled && len(ListCandidates(p, rl)) >= 2
}

// NormalizeRoutingList applies the write-time rules a saved list follows: Outbound is the first
// candidate when candidates are given, and the fastest choice is switched off when there is only one
// tunnel to choose from (reported by the review, never an error).
func NormalizeRoutingList(p *Profile, rl *RoutingList) {
	if len(rl.Candidates) > 0 {
		rl.Outbound = rl.Candidates[0]
	}
	if rl.Fastest != nil && rl.Fastest.Enabled && len(ListCandidates(p, *rl)) < 2 {
		rl.Fastest.Enabled = false
	}
}

// RepointListCandidates moves every list's tunnel id onto replacement, for the paths that delete,
// switch off or replace an exit. replacement takes id's place among the tunnels when it can be one (an
// endpoint or a group of p); "" or a builtin just drops id. Outbound follows the first remaining
// tunnel. A list left with no tunnels keeps its Outbound, so the caller's own rule for Outbound
// (refuse, repoint or park) still decides it. A pin on id moves to replacement when that is an
// endpoint, else ends; an exclusion of id ends. Slices and the policy are replaced, never written in
// place: the profile they came from may be the store's published one.
func RepointListCandidates(p *Profile, id, replacement string) {
	keep := replacement != "" && !isBuiltin(replacement) && (p.EndpointByID(replacement) != nil || p.GroupByID(replacement) != nil)
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if containsID(rl.Candidates, id) {
			var next []string
			for _, c := range rl.Candidates {
				if c == id {
					if !keep {
						continue
					}
					c = replacement
				}
				if !containsID(next, c) {
					next = append(next, c)
				}
			}
			rl.Candidates = next
			if len(next) > 0 {
				rl.Outbound = next[0]
			}
		}
		if f := rl.Fastest; f != nil && (f.Pinned == id || containsID(f.Excluded, id)) {
			nf := *f
			if nf.Pinned == id {
				nf.Pinned, nf.PinnedUntil = "", 0
				if keep && p.EndpointByID(replacement) != nil {
					nf.Pinned, nf.PinnedUntil = replacement, f.PinnedUntil
				}
			}
			nf.Excluded = nil
			for _, x := range f.Excluded {
				if x != id {
					nf.Excluded = append(nf.Excluded, x)
				}
			}
			rl.Fastest = &nf
		}
	}
}

// TidyListFastest restores the rules a list's tunnels follow after an edit elsewhere changed what they
// expand to (a group lost a member, an exit was deleted or renamed): Outbound is the first tunnel, and a
// pin or an exclusion that is no longer one of the list's tunnels ends. Validate refuses both, and a
// stored profile that fails Validate fails every later Apply. Reports whether anything changed; lists
// are replaced, never written in place.
func TidyListFastest(p *Profile) bool {
	changed := false
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if len(rl.Candidates) > 0 && rl.Outbound != rl.Candidates[0] {
			rl.Outbound = rl.Candidates[0]
			changed = true
		}
		f := rl.Fastest
		if f == nil || (f.Pinned == "" && len(f.Excluded) == 0) {
			continue
		}
		cands := map[string]bool{}
		for _, c := range ListCandidates(p, *rl) {
			cands[c] = true
		}
		var ex []string
		for _, x := range f.Excluded {
			if cands[x] {
				ex = append(ex, x)
			}
		}
		pinGone := f.Pinned != "" && !cands[f.Pinned]
		if !pinGone && len(ex) == len(f.Excluded) {
			continue
		}
		nf := *f
		nf.Excluded = ex
		if pinGone {
			nf.Pinned, nf.PinnedUntil = "", 0
		}
		rl.Fastest = &nf
		changed = true
	}
	return changed
}

func containsID(ss []string, id string) bool {
	for _, s := range ss {
		if s == id {
			return true
		}
	}
	return false
}

// ValidateFastestTarget checks one "host:port" probe target: a port is required and an address may
// not be private, loopback or link-local (the measurement goes through a tunnel to the internet).
func ValidateFastestTarget(t string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(t))
	if err != nil || host == "" {
		return fmt.Errorf("target %q: want host:port", t)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("target %q: port must be 1-65535", t)
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() ||
			(a.Is4() && a.As4()[0] == 100 && a.As4()[1]&0xc0 == 64) {
			return fmt.Errorf("target %q: a private or local address says nothing about a tunnel", t)
		}
		return nil
	}
	if strings.ContainsAny(host, " \t/\\\"'`$;|&<>") {
		return fmt.Errorf("target %q: not a host name", t)
	}
	return nil
}

// validateRoutingListFastest checks the candidates and the policy of one list. ids/enabled are the
// namespace Validate built.
func validateRoutingListFastest(p *Profile, rl RoutingList, ids map[string]string, enabled map[string]bool) error {
	for _, c := range rl.Candidates {
		if isBuiltin(c) {
			return fmt.Errorf("routing list %q: candidate %q: direct and block cannot be candidates", rl.ID, c)
		}
		if _, ok := NDMPolicyName(c); ok {
			return fmt.Errorf("routing list %q: candidate %q: an access policy cannot be a candidate", rl.ID, c)
		}
		if kind := ids[c]; kind != "endpoint" && kind != "group" {
			return unresolvedRef("routing list", rl.ID, c, "routing list %q: candidate %q does not resolve", rl.ID, c)
		}
		if !enabled[c] {
			return disabledRef("routing list", rl.ID, c, "routing list %q: candidate %q targets a disabled endpoint", rl.ID, c)
		}
	}
	if len(rl.Candidates) > 0 && rl.Outbound != rl.Candidates[0] {
		return fmt.Errorf("routing list %q: outbound %q must be the first candidate %q", rl.ID, rl.Outbound, rl.Candidates[0])
	}
	f := rl.Fastest
	if f == nil {
		return nil
	}
	switch f.Mode {
	case "", ElectionLatency, ElectionThroughput, ElectionMixed:
	default:
		return fmt.Errorf("routing list %q: invalid fastest mode %q (latency|throughput|mixed)", rl.ID, f.Mode)
	}
	if len(f.Targets) > MaxFastestTargets {
		return fmt.Errorf("routing list %q: at most %d probe targets", rl.ID, MaxFastestTargets)
	}
	for _, t := range f.Targets {
		if err := ValidateFastestTarget(t); err != nil {
			return fmt.Errorf("routing list %q: %w", rl.ID, err)
		}
	}
	if f.IntervalSec != 0 && (f.IntervalSec < MinFastestSec || f.IntervalSec > MaxFastestSec) {
		return fmt.Errorf("routing list %q: interval_sec must be %d-%d", rl.ID, MinFastestSec, MaxFastestSec)
	}
	if f.SwitchDeltaMs < 0 || f.SwitchDeltaMs > 5000 || f.SwitchDeltaPct < 0 || f.SwitchDeltaPct > 500 {
		return fmt.Errorf("routing list %q: switch thresholds out of range (0-5000 ms, 0-500 %%)", rl.ID)
	}
	if f.MinDwellSec < 0 || f.MinDwellSec > 86400 {
		return fmt.Errorf("routing list %q: min_dwell_sec must be 0-86400", rl.ID)
	}
	switch f.OnAllDown {
	case "", OnAllDownWAN, OnAllDownBlock, OnAllDownKeep:
	default:
		return fmt.Errorf("routing list %q: on_all_down %q (wan|block|keep)", rl.ID, f.OnAllDown)
	}
	cands := map[string]bool{}
	for _, c := range ListCandidates(p, rl) {
		cands[c] = true
	}
	if f.Pinned != "" && !cands[f.Pinned] {
		return fmt.Errorf("routing list %q: pinned %q is not one of its tunnels", rl.ID, f.Pinned)
	}
	for _, x := range f.Excluded {
		if !cands[x] {
			return fmt.Errorf("routing list %q: excluded %q is not one of its tunnels", rl.ID, x)
		}
	}
	if f.PinnedUntil < 0 {
		return fmt.Errorf("routing list %q: pinned_until must not be negative", rl.ID)
	}
	return nil
}
