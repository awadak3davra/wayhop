package netdiag

import (
	"context"
	"errors"
	"testing"
)

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"instagram.com":              "instagram.com",
		"https://chat.openai.com/v1": "chat.openai.com",
		"http://1.1.1.1":             "1.1.1.1",
		"1.1.1.1:443":                "1.1.1.1",
		"host/path":                  "host",
		"[2001:db8::1]:443":          "2001:db8::1",
		"  ya.ru  ":                  "ya.ru",
	}
	for in, want := range cases {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTargetURL(t *testing.T) {
	ok := map[string]string{
		"instagram.com":        "https://instagram.com",
		"http://x.com/y":       "http://x.com/y",
		"https://a.b/generate": "https://a.b/generate",
		"1.1.1.1":              "https://1.1.1.1",
		"web.telegram.org":     "https://web.telegram.org",
	}
	for in, want := range ok {
		got, valid := TargetURL(in)
		if !valid || got != want {
			t.Errorf("TargetURL(%q) = %q,%v want %q,true", in, got, valid, want)
		}
	}
	for _, bad := range []string{"", "-rf", "a b", "ftp://x.com", "http://", "has space.com/x y"} {
		if u, valid := TargetURL(bad); valid {
			t.Errorf("TargetURL(%q) = %q,true — want invalid", bad, u)
		}
	}
}

type stubDelay struct {
	ms      int
	err     error
	calls   int
	gotName string
	gotURL  string
}

func (s *stubDelay) Delay(_ context.Context, name, testURL string, _ int) (int, error) {
	s.calls++
	s.gotName, s.gotURL = name, testURL
	return s.ms, s.err
}

func TestReachVia_Success(t *testing.T) {
	d := &stubDelay{ms: 42}
	r := ReachVia(context.Background(), d, "instagram.com", "ep1", 8000)
	if !r.Reachable || r.LatencyMs != 42 {
		t.Fatalf("want reachable 42ms, got reachable=%v ms=%d err=%q", r.Reachable, r.LatencyMs, r.Err)
	}
	if d.gotName != "ep1" || d.gotURL != "https://instagram.com" {
		t.Fatalf("probe routed wrong: name=%q url=%q", d.gotName, d.gotURL)
	}
	if r.Egress != "ep1" {
		t.Fatalf("egress = %q, want ep1", r.Egress)
	}
}

func TestReachVia_Down(t *testing.T) {
	d := &stubDelay{err: errors.New("proxy delay test failed: timeout")}
	r := ReachVia(context.Background(), d, "blocked.example", "tun", 8000)
	if r.Reachable || r.LatencyMs != -1 || r.Err == "" {
		t.Fatalf("want unreachable with err, got %+v", r)
	}
}

func TestReachVia_EmptyEgressDefaultsDirect(t *testing.T) {
	d := &stubDelay{ms: 10}
	r := ReachVia(context.Background(), d, "1.1.1.1", "", 8000)
	if r.Egress != "direct" || d.gotName != "direct" {
		t.Fatalf("empty egress must default to direct, got egress=%q name=%q", r.Egress, d.gotName)
	}
}

func TestReachVia_InvalidTargetSkipsProbe(t *testing.T) {
	d := &stubDelay{ms: 10}
	r := ReachVia(context.Background(), d, "bad target", "ep1", 8000)
	if r.Reachable || r.Err == "" || d.calls != 0 {
		t.Fatalf("invalid target must not probe; got reachable=%v err=%q calls=%d", r.Reachable, r.Err, d.calls)
	}
}
