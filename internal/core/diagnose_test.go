package core

import (
	"strings"
	"testing"
)

// realFatal is the VERBATIM abort captured from a live KeeneticOS router (ANSI colour codes stripped):
// four rule-sets failed — three with a corrupt cached file, one whose download was cancelled — and the
// whole core died even though `sing-box check` had passed.
const realFatal = `FATAL[0002] start service: (initialize rule-set[3]: initial rule-set: rs-ai_openai: invalid sing-box rule-set file | initialize rule-set[1]: initial rule-set: rs-ai_anthropic: invalid sing-box rule-set file | initialize rule-set[11]: initial rule-set: rs-news_independent: Get "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/news.lst": context canceled | initialize rule-set[12]: initial rule-set: rs-ooni_blocked: invalid sing-box rule-set file)`

// A binary rule-set whose format byte is past the core's ceiling (srs.Read: "unsupported version: N")
// is intact, so re-downloading it after clearing the cache fails the same way (QA-064).
func TestClassifyStartFailure_RuleSetTooNew(t *testing.T) {
	tooNew := `FATAL[0001] start service: initialize rule-set[2]: initial rule-set: rs-ru_bundle: unsupported version: 4`
	f := ClassifyStartFailure([]string{tooNew})
	if f.Kind != "rule-set" || len(f.Items) != 1 || f.Items[0] != "rs-ru_bundle" {
		t.Fatalf("got %+v", f)
	}
	if !strings.Contains(f.Detail, "newer format") || strings.Contains(f.Detail, "corrupt") {
		t.Errorf("detail = %q, want the format cause alone", f.Detail)
	}
	if !strings.Contains(f.Remedy, "update the core") || strings.HasPrefix(f.Remedy, "clear") {
		t.Errorf("remedy = %q, want the core update first, not the cache loop", f.Remedy)
	}

	mixed := `FATAL[0001] start service: (initialize rule-set[2]: initial rule-set: rs-ru_bundle: unsupported version: 4 | initialize rule-set[3]: initial rule-set: rs-ai_openai: invalid sing-box rule-set file)`
	f = ClassifyStartFailure([]string{mixed})
	if len(f.Items) != 2 || !strings.Contains(f.Detail, "newer format") || !strings.Contains(f.Detail, "corrupt") ||
		!strings.Contains(f.Remedy, "update the core") || !strings.Contains(f.Remedy, "cache_file") {
		t.Errorf("mixed: got %+v, want both causes and both remedies", f)
	}
}

func TestClassifyStartFailure_RealRuleSetAbort(t *testing.T) {
	f := ClassifyStartFailure([]string{"INFO router: loaded", realFatal})

	if f.Kind != "rule-set" {
		t.Fatalf("Kind = %q, want rule-set", f.Kind)
	}
	// Every failing rule-set must be named so the user knows exactly what to fix.
	want := []string{"rs-ai_anthropic", "rs-ai_openai", "rs-news_independent", "rs-ooni_blocked"}
	if len(f.Items) != len(want) {
		t.Fatalf("Items = %v, want %v", f.Items, want)
	}
	for i, w := range want {
		if f.Items[i] != w {
			t.Errorf("Items[%d] = %q, want %q", i, f.Items[i], w)
		}
	}
	if f.Remedy == "" {
		t.Error("a classified failure must carry a remedy")
	}
	// The check-cannot-catch-this note matters: it explains why Apply looked fine.
	if !strings.Contains(f.Detail, "sing-box check") {
		t.Errorf("detail should note that `sing-box check` cannot catch this, got %q", f.Detail)
	}
	if s := f.Summary(); !strings.Contains(s, "rs-ai_openai") || !strings.Contains(s, "cache") {
		t.Errorf("Summary must name offenders + remedy, got %q", s)
	}
}

func TestClassifyStartFailure_OtherKinds(t *testing.T) {
	cases := []struct {
		name, line, wantKind string
	}{
		{"port in use", `FATAL[0001] start service: listen tcp 127.0.0.1:7890: bind: address already in use`, "port-in-use"},
		{"tun busy", `FATAL[0001] start service: create tun interface: device or resource busy`, "tun"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := ClassifyStartFailure([]string{c.line})
			if f.Kind != c.wantKind {
				t.Errorf("Kind = %q, want %q", f.Kind, c.wantKind)
			}
			if f.Summary() == "" {
				t.Error("classified failure must render a summary")
			}
		})
	}
}

func TestClassifyStartFailure_Unrecognized(t *testing.T) {
	// No FATAL, or an unfamiliar FATAL: return the zero value so the caller falls back to the raw tail
	// rather than inventing a wrong diagnosis.
	for _, lines := range [][]string{
		nil,
		{"INFO all good", "INFO started"},
		{"FATAL something entirely unfamiliar happened"},
	} {
		if f := ClassifyStartFailure(lines); f.Kind != "" || f.Summary() != "" {
			t.Errorf("want zero StartFailure for %v, got %+v", lines, f)
		}
	}
}
