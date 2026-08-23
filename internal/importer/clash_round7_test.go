package importer

import (
	"strings"
	"testing"
	"time"
)

// All servers / keys here are SYNTHETIC.

// TestParseSubscription_LeadingCommentBanner is the end-to-end regression for the
// looksLikeClash false negative: a genuine Clash config that opens with a URL
// comment banner ("# https://…") has its first "://" at byte 7 — inside the old
// fixed 12-byte reject window — so the whole config was routed to the share-link
// path and every endpoint silently dropped. With the fix (column-0 real-scheme
// check) the banner is ignored and the config imports normally.
func TestParseSubscription_LeadingCommentBanner(t *testing.T) {
	body := "proxies:\n  - {name: A, type: trojan, server: 1.2.3.4, port: 443, password: pw}\n"

	eps, errs := ParseSubscription(body)
	if len(eps) != 1 {
		t.Fatalf("baseline (no banner): got %d eps, errs=%v; want 1", len(eps), errs)
	}

	withBanner := "# https://sub.example.com/clash\n" + body
	eps2, errs2 := ParseSubscription(withBanner)
	if len(eps2) != 1 {
		t.Fatalf("with leading comment banner: got %d eps, errs=%v; want 1 (banner must not force the share-link path)", len(eps2), errs2)
	}
	if eps2[0].Name != "A" {
		t.Fatalf("endpoint name = %q, want A", eps2[0].Name)
	}
}

// TestFoldFlowMapping_DepthBound is the regression for the O(n^2) flow-mapping
// parse DoS: foldFlowMapping re-scans the whole remaining string via splitTopLevel
// at every nesting level, so a crafted deeply nested {a:{a:{a:…}}} up to the 8 MiB
// fetch cap could peg a CPU core for hours. The depth bound (maxFlowDepth) makes
// pathological nesting fail fast with an error instead of doing quadratic work.
func TestFoldFlowMapping_DepthBound(t *testing.T) {
	// Shallow nesting (well within maxFlowDepth) must still parse — real clash
	// mappings nest a couple of levels (ws-opts.headers.Host, reality-opts, …).
	// YAML flow mappings use "key: value" (colon then space).
	shallow := "{a: {b: {c: x}}}"
	pm, err := parseFlowMapping(shallow)
	if err != nil {
		t.Fatalf("shallow nesting must parse, got err: %v", err)
	}
	if pm["a.b.c"] != "x" {
		t.Fatalf("shallow parse pm = %#v, want a.b.c=x", pm)
	}

	// Pathologically deep nesting must be rejected rather than parsed (the old,
	// unbounded code would happily fold all of it, doing O(n^2) work).
	depth := maxFlowDepth + 8
	deep := strings.Repeat("{a: ", depth) + "x" + strings.Repeat("}", depth)

	done := make(chan error, 1)
	go func() { _, e := parseFlowMapping(deep); done <- e }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("deeply nested flow mapping must return an error (depth bound), got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("parseFlowMapping did not return within 5s on deep nesting — depth bound not enforced")
	}
}
