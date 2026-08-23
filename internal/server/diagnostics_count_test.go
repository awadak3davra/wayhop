package server

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// The router reported count=1, found=2 for a single url-test timeout, and the panel rendered "2
// known issues" — two incidents, from one line. Events and signatures are different numbers and were
// being reported as one.

const (
	urltestTimeout = "outbound/urltest[auto] test failed: dial tcp 203.0.113.10:443: i/o timeout"
	certUntrusted  = "tls: x509: certificate signed by unknown authority"
)

type diagResp struct {
	Found []struct {
		ID    string `json:"id"`
		Count int    `json:"count"`
	} `json:"found"`
	Count      int `json:"count"`
	Events     int `json:"events"`
	Signatures int `json:"signatures"`
}

func diag(t *testing.T, lines []string) diagResp {
	t.Helper()
	w := httptest.NewRecorder()
	respondDiagnostics(w, lines, false)
	var out diagResp
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v — body %s", err, w.Body.String())
	}
	return out
}

// The exact case from the router: one line, two patterns. The panel read the signature count as an
// incident count and said "2 known issues" over a single event.
//
// The finding offered two ways out — make the specific matcher win, or report the two numbers
// honestly. The first was tried and abandoned: the knowledgebase does not actually divide into
// specific and generic. `hy-tls-verify` is labelled hysteria2 and carries Hysteria sources, but its
// pattern matches any x509 line, and two existing tests require exactly that. Suppressing on that
// taxonomy would have attributed a plain certificate failure to Hysteria2 — trading a wrong count for
// a wrong cause. So the numbers are reported separately instead.
func TestDiagnostics_OneLineIsOneEventHoweverManyPatternsMatch(t *testing.T) {
	d := diag(t, []string{urltestTimeout})
	if d.Count != 1 {
		t.Errorf("count = %d, want 1 line analysed", d.Count)
	}
	if d.Events != 1 {
		t.Fatalf("events = %d, want 1 — one log line was explained, whatever matched it", d.Events)
	}
	if d.Signatures < 2 {
		t.Fatalf("the fixture must reproduce the overlap: signatures = %d", d.Signatures)
	}
	// Both names for the one event are kept, because either may be the one that helps.
	ids := map[string]bool{}
	for _, f := range d.Found {
		ids[f.ID] = true
	}
	if !ids["urltest-target-unreachable"] {
		t.Errorf("the specific cause is missing, got %v", ids)
	}
	// The claim the UI makes is what has to be right: one event, several signatures — never "2
	// incidents".
	if d.Events == d.Signatures {
		t.Error("events and signatures are equal here, so the row would print the misleading form")
	}
}

// A failure that repeats is one cause seen many times. The count is the signal an operator reads —
// a tier timing out on every probe is not a blip — so it must follow the lines, not the signatures.
func TestDiagnostics_RepeatedLinesAreOneCauseCountedUp(t *testing.T) {
	d := diag(t, []string{urltestTimeout, urltestTimeout, urltestTimeout})
	if d.Events != 3 {
		t.Errorf("events = %d, want 3 — three lines were explained", d.Events)
	}
	// The signature set does not grow with repetition — one line repeated is the same causes again,
	// deduplicated — while each cause's count follows the lines.
	one := diag(t, []string{urltestTimeout})
	if d.Signatures != one.Signatures {
		t.Fatalf("signatures grew from %d to %d when the same line repeated", one.Signatures, d.Signatures)
	}
	for _, f := range d.Found {
		if f.Count != 3 {
			t.Errorf("%s: count = %d, want 3 — the count must follow the lines", f.ID, f.Count)
		}
	}
}

// Two unrelated failures must stay two. The suppression is per line, and a fix that tidied the count
// by folding independent problems together would be worse than the defect.
func TestDiagnostics_IndependentProblemsAreNotFolded(t *testing.T) {
	d := diag(t, []string{urltestTimeout, certUntrusted})
	if d.Events != 2 {
		t.Errorf("events = %d, want 2", d.Events)
	}
	// Each line brings its own causes, and neither line's are lost to the other's.
	a := diag(t, []string{urltestTimeout})
	b := diag(t, []string{certUntrusted})
	if d.Signatures < a.Signatures || d.Signatures < b.Signatures {
		t.Fatalf("signatures = %d, but the lines alone give %d and %d — a cause was dropped",
			d.Signatures, a.Signatures, b.Signatures)
	}
	ids := map[string]bool{}
	for _, f := range d.Found {
		ids[f.ID] = true
	}
	// The url-test cause is named because it is the one the router reported. The certificate line is
	// asserted only to be a DIFFERENT cause: which entry explains it is the knowledgebase's business,
	// and pinning that here would fail the day a more specific matcher is added for it — which is what
	// this first run did, when the line resolved to hy-tls-verify rather than the generic entry.
	if !ids["urltest-target-unreachable"] {
		t.Errorf("the url-test cause is missing, got %v", ids)
	}
	if len(ids) < 2 {
		t.Errorf("two lines with unrelated failures must yield distinct causes, got %v", ids)
	}
}

// Lines nothing recognises are analysed but are not events. Counting them would put a number in
// front of the operator that no signature explains.
func TestDiagnostics_UnmatchedLinesAreNotEvents(t *testing.T) {
	d := diag(t, []string{"router: everything is fine", urltestTimeout})
	if d.Count != 2 {
		t.Errorf("count = %d, want 2 lines analysed", d.Count)
	}
	if d.Events != 1 {
		t.Errorf("events = %d, want 1 — only one line matched anything", d.Events)
	}
}

// Equal counts must order the same way every time. Log order varies between runs on one fault, and a
// list that reshuffles while the router does the same thing reads as a change.
func TestDiagnostics_EqualCountsOrderDeterministically(t *testing.T) {
	first := diag(t, []string{urltestTimeout, certUntrusted})
	second := diag(t, []string{certUntrusted, urltestTimeout})
	if len(first.Found) != len(second.Found) || len(first.Found) == 0 {
		t.Fatalf("the same two lines gave %d and %d causes", len(first.Found), len(second.Found))
	}
	for i := range first.Found {
		if first.Found[i].ID != second.Found[i].ID {
			t.Fatalf("ordering follows log order at %d: %s vs %s", i, first.Found[i].ID, second.Found[i].ID)
		}
	}
}
