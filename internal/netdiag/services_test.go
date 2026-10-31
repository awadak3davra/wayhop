package netdiag

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Each verdict says "blocked" only on the service's own refusal and "available" only on its own
// confirmation; anything else that answered is "reachable".
func TestServiceVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name          string
		check         func(answer) (string, string)
		a             answer
		state, region string
	}{
		{"chatgpt supported", verdictChatGPT, answer{status: 200, body: []byte("{\n  \"cookie_consent_required\": false\n}")}, ServiceAvailable, ""},
		{"chatgpt unsupported", verdictChatGPT, answer{status: 200, body: []byte(`{"error":{"code":"unsupported_country"}}`)}, ServiceBlocked, ""},
		{"chatgpt bot page", verdictChatGPT, answer{status: 403, body: []byte("<html>Just a moment...</html>")}, ServiceReachable, ""},
		{"claude region page", verdictClaude, answer{finalURL: "https://www.anthropic.com/app-unavailable-in-region", status: 200}, ServiceBlocked, ""},
		{"claude challenge", verdictClaude, answer{finalURL: "https://claude.ai/", status: 403}, ServiceReachable, ""},
		{"youtube premium offered", verdictYouTubePremium, answer{status: 200, body: []byte(`..."INNERTUBE_CONTEXT_GL":"US"... Ad-free and offline ...`)}, ServiceAvailable, "US"},
		{"youtube premium refused", verdictYouTubePremium, answer{status: 200, body: []byte(`"INNERTUBE_CONTEXT_GL" : "RU" YouTube Premium is not available in your country`)}, ServiceBlocked, "RU"},
		{"youtube in china", verdictYouTubePremium, answer{status: 200, body: []byte(`<a href="https://www.google.cn/">`)}, ServiceBlocked, "CN"},
		{"youtube unknown page", verdictYouTubePremium, answer{status: 200, body: []byte(`<html>consent</html>`)}, ServiceReachable, ""},
	} {
		state, region := tc.check(tc.a)
		if state != tc.state || region != tc.region {
			t.Errorf("%s: got %s/%q, want %s/%q", tc.name, state, region, tc.state, tc.region)
		}
	}
}

func TestParseTrace(t *testing.T) {
	id := parseTrace([]byte("fl=12f\nh=www.cloudflare.com\nip=198.51.100.7\nts=1.2\ncolo=LHR\nloc=gb\nwarp=on\n"))
	if id.IP != "198.51.100.7" || id.Country != "GB" || id.Colo != "LHR" || !id.Warp || id.Err != "" {
		t.Errorf("trace = %+v", id)
	}
	if bad := parseTrace([]byte("<html>blocked</html>")); bad.Err == "" || bad.IP != "" {
		t.Errorf("a page that is not a trace must say so: %+v", bad)
	}
	if odd := parseTrace([]byte("ip=not-an-ip\nloc=USA\n")); odd.IP != "" || odd.Country != "" {
		t.Errorf("malformed values must not pass through: %+v", odd)
	}
}

// The whole check through one client: identity and every service, a dead service reported as
// unreachable without holding up the rest, a redirect followed to its final URL.
func TestCheckServices(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/cdn-cgi/trace", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ip=203.0.113.9\ncolo=AMS\nloc=NL\nwarp=off\n"))
	})
	mux.HandleFunc("/openai", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != browserUA {
			http.Error(w, "bot", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"cookie_consent_required":false}`))
	})
	mux.HandleFunc("/claude", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app-unavailable-in-region", http.StatusFound)
	})
	mux.HandleFunc("/app-unavailable-in-region", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("sorry")) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	origS, origT := services, traceURL
	t.Cleanup(func() { services, traceURL = origS, origT })
	traceURL = srv.URL + "/cdn-cgi/trace"
	services = []serviceCheck{
		{id: "chatgpt", url: srv.URL + "/openai", verdict: verdictChatGPT},
		{id: "claude", url: srv.URL + "/claude", verdict: verdictClaude},
		{id: "youtube_premium", url: deadURL + "/premium", verdict: verdictYouTubePremium},
	}
	c := srv.Client()
	c.Timeout = 5 * time.Second
	got := CheckServices(context.Background(), c)
	if got.Identity.Country != "NL" || got.Identity.IP != "203.0.113.9" {
		t.Errorf("identity = %+v", got.Identity)
	}
	want := map[string]string{"chatgpt": ServiceAvailable, "claude": ServiceBlocked, "youtube_premium": ServiceUnreachable}
	for _, v := range got.Services {
		if v.State != want[v.Service] {
			t.Errorf("%s = %+v, want %s", v.Service, v, want[v.Service])
		}
	}
	if got.Services[2].Err == "" {
		t.Error("an unreachable service must say why")
	}
}

func TestIfaceClientRefusesBadIface(t *testing.T) {
	if _, err := IfaceClient("eth0; reboot", time.Second); err == nil {
		t.Error("an interface name outside the safe set must be refused")
	}
	if _, err := IfaceClient("", time.Second); err != nil {
		t.Errorf("the unbound WAN client: %v", err)
	}
}
