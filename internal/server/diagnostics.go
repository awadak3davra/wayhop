package server

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"wayhop/internal/kb"
)

// maxDiagLines caps how many log lines the analyzer processes. Pasted text is bounded only
// by the 16 MiB body cap, which at ~2 bytes/line is millions of lines; analyze() allocates
// O(lines) and re-serializes them all, so without this cap a huge paste could OOM the
// memory-constrained router daemon. A real log paste is at most a few thousand lines.
const maxDiagLines = 5000

type lineMatch struct {
	Line    string     `json:"line"`
	Error   bool       `json:"error"`
	Entries []kb.Entry `json:"entries,omitempty"`
}

// ansiSeq is the CSI escape a colourising engine writes around its level word and tags. sing-box
// colours its output whether or not a terminal is attached, so the lines the daemon reads from it
// carry the raw bytes — and they were handed to the panel untouched. Measured on a live
// Keenetic: "Load sing-box log" rendered its one line as
//
//	ESC[33mWARN ESC[0m inbound/tun[tun-in]: enable offload: set udp offload: TUNSETOFFLOAD: invalid argument
//
// on screen, escape bytes and all. Stripping here rather than in the renderer keeps every consumer
// clean — the panel, the copied report, and anything reading /api/diagnostics.
//
// Matching is unaffected either way (checked against the knowledge base with coloured and plain
// copies of the same lines: identical hits), but analysing the same text the operator is shown is
// the property worth having — a future pattern anchored on ERROR would silently miss a line
// whose ERROR is glued to an escape.
var ansiSeq = regexp.MustCompile("\x1b[[0-9;]*[a-zA-Z]")

func stripANSI(s string) string { return ansiSeq.ReplaceAllString(s, "") }

func analyze(lines []string) []lineMatch {
	out := make([]lineMatch, 0, len(lines))
	for _, raw := range lines {
		ln := stripANSI(raw)
		lm := lineMatch{Line: ln, Error: kb.IsErrorLine(ln)}
		if m := kb.Match(ln); len(m) > 0 {
			lm.Entries = m
		}
		out = append(out, lm)
	}
	return out
}

// foundCause is a distinct diagnostic cause plus how many analyzed log lines matched
// it. The count distinguishes a persistent, spamming failure (e.g. a failover tier whose
// url-test times out every probe) from a one-off blip — a much stronger signal for the
// operator than "this cause appeared at least once".
type foundCause struct {
	kb.Entry
	Count int `json:"count"`
}

func respondDiagnostics(w http.ResponseWriter, lines []string, truncated bool) {
	analyzed := analyze(lines)
	idx := map[string]int{} // entry ID -> index in found
	found := []foundCause{}
	for _, lm := range analyzed {
		for _, e := range lm.Entries {
			if i, ok := idx[e.ID]; ok {
				found[i].Count++
				continue
			}
			idx[e.ID] = len(found)
			found = append(found, foundCause{Entry: e, Count: 1})
		}
	}
	// Most-frequent cause first — a persistently-spamming failure is the strongest signal. Ties break
	// on the ID rather than on first-seen order: log order varies between runs on the same fault, and
	// a list that reorders itself while the router does the same thing reads as a change.
	sort.SliceStable(found, func(i, j int) bool {
		if found[i].Count != found[j].Count {
			return found[i].Count > found[j].Count
		}
		return found[i].ID < found[j].ID
	})
	// Events and signatures are different numbers and were reported as one. On the router a single
	// url-test timeout produced count=1, found=2, and the panel said "2 known issues" — two
	// incidents, from one line. `events` is how many log lines were explained; `signatures` is how
	// many distinct causes those lines carry.
	events := 0
	for _, lm := range analyzed {
		if len(lm.Entries) > 0 {
			events++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"lines":      analyzed,
		"found":      found,
		"count":      len(lines), // lines ANALYSED, matched or not; unchanged for existing callers
		"events":     events,     // lines that matched at least one signature
		"signatures": len(found), // distinct causes across those lines
		"truncated":  truncated,
	})
}

// handleDiagnostics analyzes the live sing-box log buffer.
func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	var lines []string
	if s.singbox != nil {
		lines = s.singbox.LogLines()
	}
	respondDiagnostics(w, lines, false) // live log is ring-buffer-bounded already
}

// handleDiagnosticsAnalyze analyzes pasted log text (works anywhere, incl. logs
// copied from the router or another device).
func (s *Server) handleDiagnosticsAnalyze(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// Stream-split with a hard line cap. Splitting the whole body up front would itself
	// allocate O(lines) string headers before any cap could apply, so walk it line by line
	// (cheap O(1) string slices) and stop at maxDiagLines.
	var lines []string
	truncated := false
	rest := body.Text
	for rest != "" {
		var ln string
		if i := strings.IndexByte(rest, '\n'); i >= 0 {
			ln, rest = rest[:i], rest[i+1:]
		} else {
			ln, rest = rest, ""
		}
		if ln = strings.TrimRight(ln, "\r"); strings.TrimSpace(ln) != "" {
			lines = append(lines, ln)
			if len(lines) >= maxDiagLines {
				truncated = rest != "" // more input remained beyond the cap
				break
			}
		}
	}
	respondDiagnostics(w, lines, truncated)
}

// handleKB returns the whole error knowledgebase for browsing.
func (s *Server) handleKB(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, kb.Entries())
}
