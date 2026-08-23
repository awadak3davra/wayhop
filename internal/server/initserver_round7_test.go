package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/importer"
)

// TestServerjobs_JobSnapshotNoStore is the regression for the missing Cache-Control
// on the job-snapshot endpoint. The harden-keys job stores the freshly generated
// root SSH private key in its Result, and handleServerJob serves that snapshot, so
// the response must carry no-store like every other credential-bearing response
// (backup.go / config.go / subscription.go).
func TestServerjobs_JobSnapshotNoStore(t *testing.T) {
	s := serverjobs_newServer(t)
	j := s.jobs.New("harden-keys", "192.0.2.9")

	req := httptest.NewRequest(http.MethodGet, "/api/server/job/"+j.ID(), nil)
	req.SetPathValue("id", j.ID())
	w := serverjobs_do(t, s.handleServerJob, req)
	if w.Code != http.StatusOK {
		t.Fatalf("handleServerJob: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store (job snapshot can carry the SSH private key)", cc)
	}
}

// TestSanitizeLinkErr_NoCredentialLeak is the regression for the parse-error
// redaction hole: on a client-config parse failure during provisioning, the raw
// share link (carrying the live UUID/password/host) was written verbatim into the
// job console via importer.Parse's err.Error(), bypassing redactSecrets.
// sanitizeLinkErr must surface only the scheme (a public protocol name), never the
// credential body.
func TestSanitizeLinkErr_NoCredentialLeak(t *testing.T) {
	// The leak is now closed AT THE SOURCE (LOOP-021): importer.Parse no longer embeds the raw link
	// in its error. A literal "%zz" is an invalid percent-escape, so url.Parse — and thus
	// importer.Parse — fails, and the error must carry the scheme for debuggability but NOT the
	// credential. (sanitizeLinkErr below stays as defense-in-depth on the provisioning path.)
	const secret = "SEKRETpassword"
	_, err := importer.Parse("trojan://" + secret + "%zz@vpn.hidden.example:443")
	if err == nil {
		t.Fatal("expected importer.Parse to fail on the malformed percent-escape")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("importer.Parse leaked the credential into its error (LOOP-021): %q", err.Error())
	}
	if !strings.Contains(err.Error(), "trojan") {
		t.Errorf("importer.Parse error should still name the scheme for debuggability, got %q", err.Error())
	}

	// Defense-in-depth on the provisioning path: only the scheme is surfaced, never the credential/host.
	got := sanitizeLinkErr("trojan://" + secret + "@vpn.hidden.example:443?sni=x#node")
	if strings.Contains(got, secret) || strings.Contains(got, "vpn.hidden.example") {
		t.Errorf("sanitizeLinkErr leaked credential/host: %q", got)
	}
	if !strings.Contains(got, "trojan") {
		t.Errorf("sanitizeLinkErr should name the scheme for debuggability, got %q", got)
	}

	// A schemeless blob must fall back to the generic message and never echo the blob
	// itself (which could still be a bare credential token).
	if g := sanitizeLinkErr("SECRETblobwithnoscheme"); strings.Contains(g, "SECRETblob") {
		t.Errorf("sanitizeLinkErr echoed a schemeless blob: %q", g)
	}
}
