package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestWebhookNotifier_SSRFGuard: the crash-restart webhook now goes through the SSRF-guarded
// subscriptionFetchClient (blockInternalDial), so an operator-supplied — or 302-redirected —
// NotifyURL pointing at a loopback/internal target is refused at dial time. The test-only
// allowInternalFetch bypass proves it is the guard (not some unrelated error) doing the blocking.
func TestWebhookNotifier_SSRFGuard(t *testing.T) {
	hit := make(chan struct{}, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit <- struct{}{}
	}))
	defer srv.Close()

	// Guarded (production) client must REFUSE the loopback target.
	guarded := (&Server{}).subscriptionFetchClient() // allowInternalFetch = false
	req, _ := http.NewRequest(http.MethodPost, srv.URL, nil)
	if resp, err := guarded.Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("SSRF-guarded webhook client must refuse a loopback NotifyURL, but the request succeeded")
	}
	select {
	case <-hit:
		t.Fatal("guarded client reached the internal target — SSRF not blocked")
	case <-time.After(200 * time.Millisecond):
	}

	// With the test-only bypass the SAME client reaches it, proving the guard is what blocked above.
	open := (&Server{allowInternalFetch: true}).subscriptionFetchClient()
	req2, _ := http.NewRequest(http.MethodPost, srv.URL, nil)
	resp, err := open.Do(req2)
	if err != nil {
		t.Fatalf("un-guarded client should reach loopback: %v", err)
	}
	resp.Body.Close()
	select {
	case <-hit:
	case <-time.After(2 * time.Second):
		t.Fatal("un-guarded client did not reach the target")
	}
}
