package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"wayhop/internal/pbr"
)

// listmemory.go answers "what do these lists cost this router" — in kernel memory, per list.
//
// A routing list is not free. Each one becomes an ipset the kernel holds resident, and on a router
// with 256 MB that is a budget the operator is spending without being shown the bill. Measured on
// a live box: two open feeds account for about a megabyte between them —
// wr_list_cidr_refilter_4 at 552 096 bytes for 27 115 prefixes and wr_list_cidr_antifilter_4 at
// 460 832 for 15 797 — while the other three lists together cost under 5 KB. The page listed all five
// as equals.
//
// Read from `ipset list -t`: the TERSE form prints each set's header and its "Size in memory" without
// dumping members, so asking about a 27 000-entry set costs the same as asking about an empty one. A
// full listing would stream tens of thousands of lines to answer a number the header already carries.

const listMemoryOutputLimit = 1 << 20

// listMemoryEntry is one list's kernel footprint.
type listMemoryEntry struct {
	ID    string `json:"id"`
	Bytes int64  `json:"bytes"`
	// Sets names the kernel sets counted for this list — a list has one per family, and seeing both
	// is how an operator can tell "v4 only" from "both" when the number looks small.
	Sets []string `json:"sets,omitempty"`
}

// handlePBRListMemory reports per-list kernel memory. Read-only.
//
// A list with no entry is one the kernel does not hold a set for — not a list costing zero. The page
// words those differently, so they are ABSENT here rather than reported as 0.
func (s *Server) handlePBRListMemory(w http.ResponseWriter, r *http.Request) {
	profile := s.store.Profile()
	ids := make([]string, 0, len(profile.RoutingLists))
	for i := range profile.RoutingLists {
		ids = append(ids, profile.RoutingLists[i].ID)
	}
	ctx, cancel := context.WithTimeout(r.Context(), kernelCounterTimeout)
	defer cancel()
	entries, measured := s.kernelListMemory(ctx, ids)
	writeJSON(w, http.StatusOK, map[string]any{
		"measured": measured,
		"lists":    entries,
	})
}

// kernelListMemory reads every set's size in one call and keeps the ones belonging to routing lists.
// The second return says whether the MEASUREMENT happened at all: a router with no ipset binary, or
// one where the plane is not installed, must read as "not measured" rather than as "these lists cost
// nothing", which is the same distinction the traffic counters make.
func (s *Server) kernelListMemory(ctx context.Context, listIDs []string) ([]listMemoryEntry, bool) {
	if s == nil || len(listIDs) == 0 {
		return nil, false
	}
	opts := keeneticPBROptions("")
	want := make(map[string]string, len(listIDs)*2)
	for _, id := range listIDs {
		zone := pbr.ListZoneName(id)
		want[opts.ZoneSetName(zone, "4")] = id
		want[opts.ZoneSetName(zone, "6")] = id
	}
	text, err := runHostCommandBounded(ctx, kernelCounterTimeout, listMemoryOutputLimit,
		applyHostCommandWaitDelay, "ipset", "list", "-t")
	if err != nil {
		return nil, false
	}
	byID := map[string]*listMemoryEntry{}
	for _, name := range parseIpsetSizes(text, want) {
		entry := byID[name.id]
		if entry == nil {
			entry = &listMemoryEntry{ID: name.id}
			byID[name.id] = entry
		}
		entry.Bytes += name.bytes
		entry.Sets = append(entry.Sets, name.set)
	}
	// Emitted in the profile's own order so the page can pair them with its rows without sorting.
	out := make([]listMemoryEntry, 0, len(byID))
	for _, id := range listIDs {
		if entry := byID[id]; entry != nil {
			out = append(out, *entry)
		}
	}
	return out, true
}

type ipsetSize struct {
	id, set string
	bytes   int64
}

// parseIpsetSizes walks `ipset list -t` output: a "Name:" line opens a set and the "Size in memory:"
// line that follows closes it. Sets that are not ours are skipped rather than summed — the router's
// own firmware keeps a dozen (_NDM_*), and counting those would report someone else's memory as the
// cost of a routing list.
func parseIpsetSizes(text string, want map[string]string) []ipsetSize {
	var out []ipsetSize
	name := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Name:"):
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "Size in memory:"):
			if name == "" {
				continue
			}
			id, ours := want[name]
			raw := strings.TrimSpace(strings.TrimPrefix(line, "Size in memory:"))
			bytes, err := strconv.ParseInt(strings.Fields(raw + " ")[0], 10, 64)
			if ours && err == nil {
				out = append(out, ipsetSize{id: id, set: name, bytes: bytes})
			}
			name = "" // one size per set; anything after it belongs to the next Name:
		}
	}
	return out
}
