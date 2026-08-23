package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDiagnosticsAnalyze_LineCap guards the OOM fix: a huge pasted log is capped at
// maxDiagLines (so analyze() can't allocate O(millions) on the router), and the response
// flags the truncation. A small paste is analyzed whole and not flagged.
func TestDiagnosticsAnalyze_LineCap(t *testing.T) {
	s := &Server{} // handleDiagnosticsAnalyze reads only the request body

	var sb strings.Builder
	for i := 0; i < maxDiagLines+500; i++ {
		sb.WriteString("ERROR something failed\n")
	}
	body, _ := json.Marshal(map[string]string{"text": sb.String()})
	rec := httptest.NewRecorder()
	s.handleDiagnosticsAnalyze(rec, httptest.NewRequest("POST", "/api/diagnostics", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out struct {
		Count     int               `json:"count"`
		Truncated bool              `json:"truncated"`
		Lines     []json.RawMessage `json:"lines"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if out.Count > maxDiagLines || len(out.Lines) > maxDiagLines {
		t.Errorf("count=%d lines=%d, want both <= %d (capped)", out.Count, len(out.Lines), maxDiagLines)
	}
	if !out.Truncated {
		t.Errorf("truncated=false, want true for oversized input")
	}

	// Small input: analyzed whole, not truncated.
	body2, _ := json.Marshal(map[string]string{"text": "line a\nline b\n"})
	rec2 := httptest.NewRecorder()
	s.handleDiagnosticsAnalyze(rec2, httptest.NewRequest("POST", "/api/diagnostics", bytes.NewReader(body2)))
	var out2 struct {
		Count     int  `json:"count"`
		Truncated bool `json:"truncated"`
	}
	_ = json.Unmarshal(rec2.Body.Bytes(), &out2)
	if out2.Count != 2 || out2.Truncated {
		t.Errorf("small input: count=%d truncated=%v, want 2/false", out2.Count, out2.Truncated)
	}
}

// TestDiagnosticsFoundCounts verifies the analyzer reports per-cause frequency (so a
// persistently-spamming failure reads differently from a one-off) and sorts most-frequent
// first. Grounded in a real device state: a failover tier whose url-test times out every
// probe floods the log with the same cause.
func TestDiagnosticsFoundCounts(t *testing.T) {
	urltestLine := `outbound/urltest[group-failover]: (dial tcp 5.255.255.242:443: i/o timeout)`
	lines := []string{urltestLine, urltestLine, "operation not permitted"}
	rec := httptest.NewRecorder()
	respondDiagnostics(rec, lines, false)

	var resp struct {
		Found []struct {
			ID    string `json:"id"`
			Count int    `json:"count"`
		} `json:"found"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, f := range resp.Found {
		counts[f.ID] = f.Count
	}
	if counts["urltest-target-unreachable"] != 2 {
		t.Errorf("urltest count = %d, want 2 (found: %+v)", counts["urltest-target-unreachable"], resp.Found)
	}
	if counts["gen-permission"] != 1 {
		t.Errorf("gen-permission count = %d, want 1 (found: %+v)", counts["gen-permission"], resp.Found)
	}
	// Most-frequent first: the top cause must carry the highest count.
	if len(resp.Found) > 0 && resp.Found[0].Count < 2 {
		t.Errorf("found not sorted by count desc: first = %+v", resp.Found[0])
	}
}
