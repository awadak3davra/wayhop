package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestDNSToolSaysItIgnoresTheExit (L5): three of the four tools in "one tool, one exit" take the
// exit; the DNS lookup does not, and said nothing.
//
// handleNetDiagStream resolves the Egress selector to an interface and hands it to ping (-I) and
// traceroute (-i). netdiag.DNSLookup takes no interface at all, so the lookup goes out the router's
// ordinary resolver path whatever the operator picked. Measured on a live Keenetic with the
// egress set to WgProvider_SiteB: "Resolve (DNS)" for rutracker.org returned the WAN resolver's
// records with nothing on screen saying the exit had been ignored — which is exactly the question
// someone selects a tunnel to ask (geo-DNS, a resolver that answers differently per region).
//
// This pins the DISCLOSURE, not the binding: the row still cannot ask through a tunnel, and it must
// not read as though it had.
func TestDNSToolSaysItIgnoresTheExit(t *testing.T) {
	s := dnsSeed(t)
	if err := s.store.UpsertEndpoint(model.Endpoint{ID: "tun", Name: "tun", Owner: "external",
		Engine: model.EngineExternal, Enabled: true, Params: map[string]any{"interface": "lo"}}); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}

	// A name that cannot resolve keeps the test off the network: the note is emitted before the
	// lookup, so it must be there whatever the lookup then answers.
	run := func(egress string) string {
		r := httptest.NewRequest(http.MethodGet,
			"/api/netdiag/stream?tool=dns&target=nothing.invalid&egress="+egress, nil)
		w := httptest.NewRecorder()
		s.handleNetDiagStream(w, r)
		return w.Body.String()
	}

	withExit := run("tun")
	if !strings.Contains(withExit, "used the router's own resolver") {
		t.Errorf("a lookup run with an exit selected must say the exit was not used:\n%s", withExit)
	}
	if !strings.Contains(withExit, "lo") {
		t.Errorf("and must name the exit it did not use:\n%s", withExit)
	}
	// And it must not claim a POSITION. The same closure runs standalone and inside the Full run,
	// where DNS is emitted first and ping/traceroute appear underneath it — measured on a live
	// Keenetic, the note read "ping and traceroute above" with nothing above it.
	if strings.Contains(withExit, "above") || strings.Contains(withExit, "below") {
		t.Errorf("the note must name the tools, not where they sit on screen:\n%s", withExit)
	}
	if !strings.Contains(withExit, "ping and traceroute") {
		t.Errorf("and it must still say which tools DO take the exit:\n%s", withExit)
	}
	// The note has to arrive before the records, or it is a footnote under an answer already read.
	if noteAt, recAt := strings.Index(withExit, "note:"), strings.Index(withExit, "error:"); recAt >= 0 && noteAt > recAt {
		t.Error("the note must precede the answer it qualifies")
	}

	// On the WAN there is nothing to disclose, and a caveat printed every time is one nobody reads.
	if direct := run("direct"); strings.Contains(direct, "used the router's own resolver") {
		t.Errorf("no exit was selected, so there is no exit to disclaim:\n%s", direct)
	}
}
