package cidrfeed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFetch_RefusesOversizedFeed: a feed larger than the cap must FAIL (fail closed) rather than be
// silently truncated — a truncated line-oriented CIDR feed would parse into a non-empty-but-incomplete
// set the caller accepts as complete, dropping every CIDR past the cap from the carve-out.
func TestFetch_RefusesOversizedFeed(t *testing.T) {
	big := make([]byte, maxFeedBytes+1024)
	for i := range big {
		big[i] = 'a'
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(big)
	}))
	defer ts.Close()

	if _, _, err := Fetch(context.Background(), ts.Client(), ts.URL); err == nil {
		t.Fatal("an oversized feed must be refused (fail closed), not silently truncated")
	} else if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("want an over-limit error, got %v", err)
	}
}
