package server

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"wayhop/internal/pbr"
	"wayhop/internal/writebehind"
)

// killswitchlearned.go persists the addresses dnsmasq added to kill-switched domain sets.
// They existed only in RAM: after a reboot the sets came back empty, the backstop mirrored the empty
// sets and released the boot hold, and a LAN device that still had an answer cached connected to an
// address in no set and no route: unmarked, main table, WAN, until it asked the resolver again.
//
// The file is in ipset restore format with each entry's remaining timeout, so the hook restores it
// into the sets at boot and the boot fill puts it into the backstop table; stale addresses age out.
// Flash: written through a writebehind.Writer, at most once an hour, only when the members changed
// (an order-independent key over set and address, not the timeouts), plus on a graceful stop and
// when an Apply is saved. Capped by count and bytes; over the cap the entries with the longest
// remaining timeout are kept, which are the ones dnsmasq added most recently.

const (
	// ksLearnedPath is beside the restore file, outside netfilter.d (NDM runs what is in there).
	ksLearnedPath       = "/opt/etc/ndm/wayhop-learned.ipset"
	ksLearnedInterval   = time.Hour
	ksLearnedMaxEntries = 16384
	ksLearnedMaxBytes   = 1 << 20
	// ksLearnedTrailer ends the file with its entry count: the fill tells a cut file from a whole one.
	// ipset restore skips it as a comment; were it refused, it is the last line, after every entry.
	ksLearnedTrailer = pbr.LearnedTrailer
	// ksLearnedMinTTL floors the timeout written for an entry: the file is rewritten only
	// when the members change, so a timeout is a snapshot from that moment, and an entry dnsmasq has
	// re-added since would come back after a reboot with seconds left while clients still hold the
	// answer. Holding a stale address an hour longer costs only that address's route.
	ksLearnedMinTTL = 3600
)

// ksLearned is the persisted copy's writer and the key of what it last wrote.
type ksLearned struct {
	mu      sync.Mutex
	w       *writebehind.Writer
	path    string
	lastKey uint64 // key of the members last written (or found in the file at start)
	hasKey  bool
	// write stands in for the durable write in tests (nil: atomicfile via writebehind).
	write func(path string, data []byte, perm os.FileMode) error
}

// ksEntry is one learned member with its remaining timeout in seconds.
type ksEntry struct {
	set string
	p   netip.Prefix
	ttl int
}

// learnedKey is an order-independent key over (set, address): no sort, no allocation per tick.
func learnedKey(sets []string, read ksMembers) (uint64, bool) {
	var key uint64
	h := fnv.New64a()
	for _, set := range sets {
		got, err := read(context.Background(), set)
		if err != nil {
			return 0, false
		}
		for _, p := range got {
			h.Reset()
			h.Write([]byte(set))
			b, _ := p.MarshalBinary()
			h.Write(b)
			key += h.Sum64()
		}
	}
	return key, true
}

func entriesKey(es []ksEntry) uint64 {
	by := map[string][]netip.Prefix{}
	var sets []string
	for _, e := range es {
		if _, ok := by[e.set]; !ok {
			sets = append(sets, e.set)
		}
		by[e.set] = append(by[e.set], e.p)
	}
	k, _ := learnedKey(sets, func(_ context.Context, s string) ([]netip.Prefix, error) { return by[s], nil })
	return k
}

// parseIpsetEntries reads `ipset list <set>` members with their timeouts, skipping static ones
// (`timeout 0`) and members without a timeout.
func parseIpsetEntries(set, out string) []ksEntry {
	var es []ksEntry
	in := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !in {
			in = line == "Members:"
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 || f[1] != "timeout" {
			continue
		}
		ttl, err := strconv.Atoi(f[2])
		if err != nil || ttl <= 0 {
			continue
		}
		if p, ok := parseSetEntry(f[0]); ok {
			es = append(es, ksEntry{set, p, ttl})
		}
	}
	return es
}

// renderLearned is the file: the drain header, the newest entries within the caps in a stable order,
// and the trailer.
func renderLearned(es []ksEntry, maxEntries, maxBytes int) []byte {
	sort.SliceStable(es, func(i, j int) bool { return es[i].ttl > es[j].ttl })
	var kept []ksEntry
	size := 0
	for _, e := range es {
		n := len(fmt.Sprintf("add %s %s timeout %d -exist\n", e.set, e.p.Addr(), e.ttl))
		if len(kept) >= maxEntries || size+n > maxBytes {
			break
		}
		kept = append(kept, e)
		size += n
	}
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].set != kept[j].set {
			return kept[i].set < kept[j].set
		}
		return kept[i].p.Addr().Less(kept[j].p.Addr())
	})
	var b strings.Builder
	for _, e := range kept {
		entry := e.p.Addr().String()
		if e.p.Bits() != e.p.Addr().BitLen() {
			entry = e.p.String()
		}
		fmt.Fprintf(&b, "add %s %s timeout %d -exist\n", e.set, entry, max(e.ttl, ksLearnedMinTTL))
	}
	fmt.Fprintf(&b, "%s%d\n", ksLearnedTrailer, len(kept))
	// Under the drain header: the key ties the hook's progress stamps to this content.
	return pbr.KeyedRestore([]byte(b.String()))
}

// errNoLearned: no plane with kill-switched domain sets to persist.
var errNoLearned = errors.New("no kill-switched domain set to persist")

// learnedWriter returns the writer, created on first use and seeded from the file on flash.
func (s *Server) learnedWriter() *writebehind.Writer {
	l := &s.ksl
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.w != nil {
		return l.w
	}
	if l.path == "" {
		l.path = ksLearnedPath
	}
	// The debounce (shorter than the mirror's 5 s tick, so a stream of changes still gets written) puts
	// the write, and its set reads, on the writer's timer: never under the tick's applyMu.
	l.w = writebehind.New(l.path, keeneticPBRConfPerm, writebehind.Options{Debounce: 2 * time.Second, MinInterval: ksLearnedInterval, Write: l.write})
	if data, err := os.ReadFile(l.path); err == nil {
		fi, _ := os.Stat(l.path)
		l.w.Seed(data, fi.ModTime())
		var es []ksEntry
		for _, line := range strings.Split(string(data), "\n") {
			if f := strings.Fields(line); len(f) >= 5 && f[0] == "add" {
				if p, ok := parseSetEntry(f[2]); ok {
					ttl, _ := strconv.Atoi(f[4])
					es = append(es, ksEntry{f[1], p, ttl})
				}
			}
		}
		l.lastKey, l.hasKey = entriesKey(es), true
	}
	return l.w
}

// produceLearned reads the kill-switched domain sets of the installed plane with their timeouts and
// renders the file. Unchanged members give back the bytes on flash, which the writer skips.
func (s *Server) produceLearned(read func(ctx context.Context, set string) ([]ksEntry, error)) func() ([]byte, error) {
	return func() ([]byte, error) {
		k := s.kernelBaseline()
		if k == nil {
			return nil, errNoLearned
		}
		bs := k.Plan.KillSwitchBackstop(keeneticKillSwitchOptions(*k.Ipset))
		sets := append(append([]string(nil), bs.Sets4...), bs.Sets6...)
		if len(sets) == 0 {
			return nil, errNoLearned
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		var es []ksEntry
		for _, set := range sets {
			got, err := read(ctx, set)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", set, err)
			}
			es = append(es, got...)
		}
		key := entriesKey(es)
		l := &s.ksl
		l.mu.Lock()
		same := l.hasKey && l.lastKey == key
		l.mu.Unlock()
		if same {
			// A file an older build left without the drain header is written again.
			if data, err := os.ReadFile(l.path); err == nil && pbr.HasDrainHeader(data) {
				return data, nil
			}
		}
		data := renderLearned(es, ksLearnedMaxEntries, ksLearnedMaxBytes)
		l.mu.Lock()
		l.lastKey, l.hasKey = key, true
		l.mu.Unlock()
		return data, nil
	}
}

// learnedReader reads a set's learned entries through the artifact's authenticated ipset.
func (s *Server) learnedReader() func(ctx context.Context, set string) ([]ksEntry, error) {
	return func(ctx context.Context, set string) ([]ksEntry, error) {
		k := s.kernelBaseline()
		if k == nil {
			return nil, errNoLearned
		}
		if s.ksb.reader != nil { // tests: the stand-in set reader, timeouts unknown (a day)
			got, err := s.ksb.reader(*k.Ipset)(ctx, set)
			es := make([]ksEntry, 0, len(got))
			for _, p := range got {
				es = append(es, ksEntry{set, p, 86400})
			}
			return es, err
		}
		adapter, err := newExactKeeneticKernelAdapter(*k.Ipset)
		if err != nil {
			return nil, err
		}
		out, err := adapter.runner.runLimit(ctx, ksSetReadLimit, "", executionToolIpset, "list", set)
		if err != nil {
			return nil, err
		}
		return parseIpsetEntries(set, out), nil
	}
}

// noteLearned is the mirror's report of the members it read this tick: a change marks the writer,
// which writes at most hourly.
func (s *Server) noteLearned(sets []string, read ksMembers) {
	if len(sets) == 0 || read == nil || s.config().Demo {
		return
	}
	key, ok := learnedKey(sets, read)
	if !ok {
		return
	}
	w := s.learnedWriter()
	l := &s.ksl
	l.mu.Lock()
	changed := !l.hasKey || l.lastKey != key
	l.mu.Unlock()
	if changed {
		w.Mark(s.produceLearned(s.learnedReader()))
	}
}

// saveLearnedNow writes the file now if the members changed (an Apply was saved).
func (s *Server) saveLearnedNow() {
	k := s.kernelBaseline()
	if k == nil || s.config().Demo || !k.Plan.KillSwitchDomains() {
		return
	}
	w := s.learnedWriter()
	w.Mark(s.produceLearned(s.learnedReader()))
	if err := w.Flush(); err != nil {
		log.Printf("kill switch: learned addresses: %v", err)
	}
}
