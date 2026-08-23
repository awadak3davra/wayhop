package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSubscriptionTitle_FromHeader exercises the full fetch path: a loopback
// httptest server returns a base64 "Profile-Title" header, and subscriptionTitle
// applied to the fetched response yields the decoded human name. allowInternalFetch
// relaxes the SSRF dial guard so the loopback httptest server is reachable.
//
// (The /api/subscription handler captures resp.Header and feeds it to
// subscriptionTitle; this test verifies the helper against a real fetched
// response so the wiring is proven end-to-end without depending on the handler's
// response shape.)
func TestSubscriptionTitle_FromHeader(t *testing.T) {
	s := servererrorpaths_server(t)
	s.allowInternalFetch = true // httptest binds loopback; relax the SSRF dial guard

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Profile-Title", "TWFpbiBTZXJ2ZXJz") // base64("Main Servers")
		_, _ = w.Write([]byte("vless://x@1.2.3.4:443#x"))
	}))
	defer upstream.Close()

	req, err := http.NewRequest(http.MethodGet, upstream.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := s.subscriptionFetchClient().Do(req)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	defer resp.Body.Close()

	if got := subscriptionTitle(resp.Header); got != "Main Servers" {
		t.Errorf("subscriptionTitle = %q, want %q", got, "Main Servers")
	}
}

// TestSubscriptionTitle_ContentDispositionFallback verifies the fallback: when no
// Profile-Title is present, a Content-Disposition filename becomes the name (with
// its extension dropped).
func TestSubscriptionTitle_ContentDispositionFallback(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Disposition", `attachment; filename="My VPN Provider.txt"`)
	if got := subscriptionTitle(h); got != "My VPN Provider" {
		t.Errorf("Content-Disposition fallback = %q, want %q", got, "My VPN Provider")
	}
}

// TestSubscriptionTitle_None returns "" when neither header carries a usable name,
// so the caller keeps its own default naming.
func TestSubscriptionTitle_None(t *testing.T) {
	if got := subscriptionTitle(http.Header{}); got != "" {
		t.Errorf("no headers = %q, want empty", got)
	}
	if got := subscriptionTitle(nil); got != "" {
		t.Errorf("nil header = %q, want empty", got)
	}
}

// TestSubscriptionTitle_RawHeader confirms a provider that sends the title verbatim
// (not base64) is honored. "Tokyo Edge" contains a space, so it is never valid
// base64 and passes through unchanged.
func TestSubscriptionTitle_RawHeader(t *testing.T) {
	h := http.Header{}
	h.Set("Profile-Title", "Tokyo Edge")
	if got := subscriptionTitle(h); got != "Tokyo Edge" {
		t.Errorf("raw Profile-Title = %q, want %q", got, "Tokyo Edge")
	}
}
