package atomicfile

import (
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Write accounting: how many bytes the daemon has asked the filesystem to store, per file class,
// since the process started. It exists so an operator can see flash wear from the panel (GET
// /api/diagnostics/flash) instead of guessing from a router's block counters. Only writers that go
// through this package (or report with Note) are counted; sing-box's own cache.db is not.

// WriteStat is the tally for one file class.
type WriteStat struct {
	Class        string `json:"class"`
	Writes       uint64 `json:"writes"`
	Bytes        uint64 `json:"bytes"`
	Skipped      uint64 `json:"skipped"`       // rewrites of identical content that were not performed
	SkippedBytes uint64 `json:"skipped_bytes"` // what those rewrites would have cost
	RAM          bool   `json:"ram"`           // the class lives under a registered RAM directory
}

var stats = struct {
	sync.Mutex
	started time.Time
	byClass map[string]*WriteStat
	ramDirs []string
}{started: time.Now(), byClass: map[string]*WriteStat{}}

// maxClasses bounds the table: class names are normalized (see classOf), but a bug elsewhere that
// writes ever-new names must not grow the daemon's memory without limit.
const maxClasses = 128

// SetRAMDirs registers directories that are RAM (tmpfs) so writes under them are reported apart from
// flash writes. Replaces any earlier registration.
func SetRAMDirs(dirs ...string) {
	stats.Lock()
	defer stats.Unlock()
	stats.ramDirs = stats.ramDirs[:0]
	for _, d := range dirs {
		if d != "" {
			stats.ramDirs = append(stats.ramDirs, filepath.Clean(d))
		}
	}
}

// Note records a write of n bytes to path made outside this package (a writer that needs plain
// os.WriteFile semantics), so the counter stays complete.
func Note(path string, n int) { noteWrite(path, n) }

// NoteSkip records a write of n bytes to path that a caller decided not to perform.
func NoteSkip(path string, n int) { noteSkip(path, n) }

func noteWrite(path string, n int) {
	stats.Lock()
	defer stats.Unlock()
	if st := statFor(path); st != nil {
		st.Writes++
		st.Bytes += uint64(n)
	}
}

func noteSkip(path string, n int) {
	stats.Lock()
	defer stats.Unlock()
	if st := statFor(path); st != nil {
		st.Skipped++
		st.SkippedBytes += uint64(n)
	}
}

// statFor returns the tally for path's class, creating it. Caller holds stats.
func statFor(path string) *WriteStat {
	ram := underAny(path, stats.ramDirs)
	class := classOf(path)
	key := class
	if ram {
		key = "ram:" + class
	}
	st := stats.byClass[key]
	if st == nil {
		if len(stats.byClass) >= maxClasses {
			key, class = "other", "other"
			if st = stats.byClass[key]; st != nil {
				return st
			}
		}
		st = &WriteStat{Class: class, RAM: ram}
		stats.byClass[key] = st
	}
	return st
}

func underAny(path string, dirs []string) bool {
	p := filepath.Clean(path)
	for _, d := range dirs {
		if p == d || strings.HasPrefix(p, d+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// classOf names the class of a file: its base name with the parts that vary per write (content
// hashes, timestamps, temp numbers) replaced by '*', so wayhop-backup-20261121T101010Z.json and a
// content-addressed blob each count as one class.
func classOf(path string) string {
	base := filepath.Base(path)
	var b strings.Builder
	run := 0
	flush := func(seg string) {
		if run >= 6 {
			b.WriteByte('*')
		} else {
			b.WriteString(seg)
		}
	}
	start := 0
	for i := 0; i <= len(base); i++ {
		hexish := i < len(base) && isHexDigit(base[i])
		if hexish {
			if run == 0 {
				start = i
			}
			run++
			continue
		}
		if run > 0 {
			flush(base[start:i])
			run = 0
		}
		if i < len(base) {
			b.WriteByte(base[i])
		}
	}
	return b.String()
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f'
}

// Stats returns the tallies (flash classes first, then RAM, each by bytes descending) and when
// counting started.
func Stats() ([]WriteStat, time.Time) {
	stats.Lock()
	defer stats.Unlock()
	out := make([]WriteStat, 0, len(stats.byClass))
	for _, st := range stats.byClass {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RAM != out[j].RAM {
			return !out[i].RAM
		}
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Class < out[j].Class
	})
	return out, stats.started
}

// resetStats clears the tallies (tests).
func resetStats() {
	stats.Lock()
	defer stats.Unlock()
	stats.byClass = map[string]*WriteStat{}
	stats.ramDirs = nil
	stats.started = time.Now()
}
