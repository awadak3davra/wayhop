package iptv

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// rtFunc is a host-discriminating RoundTripper (unlike fakeRT which matches by path only), so these
// tests can make the PRIMARY iptv-org host fail while a specific MIRROR host succeeds — the exact
// DPI-fallback path that fakeRT (host-agnostic) cannot exercise.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

const oneChannel = "#EXTINF:-1 tvg-id=\"z\",Zeta\nhttp://s/z\n"

// TestFetchAllMirrorFallback: the canonical GitHub Pages host is DPI-blocked (dial error); the fetch
// must fall through to the jsDelivr mirror and still return the channels.
func TestFetchAllMirrorFallback(t *testing.T) {
	var primaryTried, mirrorTried bool
	client := &http.Client{Transport: rtFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(req.URL.Host, "iptv-org.github.io"):
			primaryTried = true
			return nil, fmt.Errorf("simulated DPI block")
		case strings.Contains(req.URL.Host, "jsdelivr"):
			mirrorTried = true
			return mkResp(http.StatusOK, oneChannel), nil
		}
		return mkResp(http.StatusNotFound, ""), nil
	})}

	chs, _, errs := fetchAll(context.Background(), client, []string{"us"}, nil, nil, nil)
	if !primaryTried || !mirrorTried {
		t.Fatalf("expected both primary and mirror to be tried (primary=%v mirror=%v)", primaryTried, mirrorTried)
	}
	if len(chs) != 1 {
		t.Fatalf("expected 1 channel via mirror, got %d", len(chs))
	}
	if len(errs) != 0 {
		t.Fatalf("mirror succeeded, expected no errors, got %v", errs)
	}
}

// TestFetchAllBlockPageFallsThrough: the primary answers 200 but with an HTML block page (parses to 0
// channels); that must be treated as unavailable and fall through to the mirror.
func TestFetchAllBlockPageFallsThrough(t *testing.T) {
	client := &http.Client{Transport: rtFunc(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Host, "iptv-org.github.io") {
			return mkResp(http.StatusOK, "<html><body>Access denied by your provider</body></html>"), nil
		}
		return mkResp(http.StatusOK, oneChannel), nil
	})}

	chs, _, errs := fetchAll(context.Background(), client, []string{"us"}, nil, nil, nil)
	if len(chs) != 1 {
		t.Fatalf("block page should fall through to the mirror; got %d channels", len(chs))
	}
	if len(errs) != 0 {
		t.Fatalf("expected no errors after mirror success, got %v", errs)
	}
}

// TestFetchAllAllMirrorsFail: when every mirror fails the country is reported unavailable exactly once.
func TestFetchAllAllMirrorsFail(t *testing.T) {
	client := &http.Client{Transport: rtFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("down")
	})}

	chs, _, errs := fetchAll(context.Background(), client, []string{"us"}, nil, nil, nil)
	if len(chs) != 0 {
		t.Fatalf("expected 0 channels, got %d", len(chs))
	}
	if len(errs) != 1 || !strings.Contains(errs[0], "unavailable") {
		t.Fatalf("expected one 'unavailable' error, got %v", errs)
	}
}

// TestFetchAllCustomSourceNoMirror: a custom provider URL is fetched as-is (no mirror expansion) and a
// dial failure surfaces as unavailable.
func TestFetchAllCustomSourceNoMirror(t *testing.T) {
	var calls int
	client := &http.Client{Transport: rtFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return nil, fmt.Errorf("down")
	})}

	_, _, errs := fetchAll(context.Background(), client, nil, nil, []string{"https://provider.example/list.m3u"}, nil)
	if calls != 1 {
		t.Fatalf("custom source must be tried exactly once (no mirror), got %d calls", calls)
	}
	if len(errs) != 1 {
		t.Fatalf("expected one error, got %v", errs)
	}
}
