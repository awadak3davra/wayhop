package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"velinx/internal/kb"
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

func analyze(lines []string) []lineMatch {
	out := make([]lineMatch, 0, len(lines))
	for _, ln := range lines {
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
	// Most-frequent cause first — a persistently-spamming failure is the strongest signal.
	// Stable so equal-count causes keep first-seen order (deterministic output for tests).
	sort.SliceStable(found, func(i, j int) bool { return found[i].Count > found[j].Count })
	writeJSON(w, http.StatusOK, map[string]any{
		"lines":     analyzed,
		"found":     found,
		"count":     len(lines),
		"truncated": truncated,
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
