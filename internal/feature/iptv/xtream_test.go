package iptv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"testing"
)

// TestFetchAllXtreamNoCredsInLog: the Xtream password must NEVER reach the daemon log — not on the
// empty-200 branch (raw URL) nor on a transport error (the *url.Error / FetchPlaylist wrap embeds the
// full get.php URL). Both log paths must be credential-stripped.
func TestFetchAllXtreamNoCredsInLog(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)
	const pass = "S3kretPass123"
	x := []XtreamSource{{URL: "http://prov.example", Username: "alice", Password: pass}}
	// empty-200 path: get.php returns 200 with a non-M3U body → 0 channels → the "no channels" log line.
	fetchAll(context.Background(), &http.Client{Transport: rtFunc(func(*http.Request) (*http.Response, error) {
		return mkResp(http.StatusOK, "<html>account expired</html>"), nil
	})}, nil, nil, nil, x)
	// transport-error path: the http.Client wraps the get.php URL (with the password) in a *url.Error,
	// which FetchPlaylist wraps again — the error text carries the credential unless scrubbed.
	fetchAll(context.Background(), &http.Client{Transport: rtFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("connection refused")
	})}, nil, nil, nil, x)
	if s := buf.String(); strings.Contains(s, pass) || strings.Contains(s, "password=") {
		t.Fatalf("Xtream credentials leaked to the daemon log:\n%s", s)
	}
}

// TestScrubErr: no credential — the Xtream password, nor a token in an absolute OR relative redirect
// Location — survives scrubErr (the relative case is the round-2 regression).
func TestScrubErr(t *testing.T) {
	raw := "http://host/get.php?username=alice&password=secretpw&type=m3u_plus&output=m3u8"
	cases := []struct {
		err error
		bad []string
	}{
		{fmt.Errorf("fetch %s: %w", raw, fmt.Errorf(`Get %q: dial tcp: no such host`, raw)), []string{"secretpw", "password="}},
		{fmt.Errorf("fetch %s: %w", raw, fmt.Errorf(`Get "http://host/live?token=ABSTOK": stopped`)), []string{"ABSTOK", "secretpw"}},
		{fmt.Errorf("fetch %s: %w", raw, fmt.Errorf(`Get "/live?token=RELTOK": stopped after 5 redirects`)), []string{"RELTOK", "secretpw"}},
	}
	for i, c := range cases {
		got := scrubErr(c.err, raw)
		for _, b := range c.bad {
			if strings.Contains(got, b) {
				t.Fatalf("case %d: scrubErr leaked %q: %s", i, b, got)
			}
		}
	}
}

// TestFetchAllCustomURLTokenNotInErrs: a credential/token in a custom source URL's query must NOT
// appear in the user-facing errs (which feed Stats.LastError → shown in the UI, and the
// "no channels fetched" build error → logged). The host/path stays so the source is still identifiable.
func TestFetchAllCustomURLTokenNotInErrs(t *testing.T) {
	client := &http.Client{Transport: rtFunc(func(*http.Request) (*http.Response, error) { return nil, fmt.Errorf("down") })}
	_, _, errs := fetchAll(context.Background(), client, nil, nil, []string{"https://prov.example/list.m3u?token=SECRETTOK&password=pw"}, nil)
	if len(errs) != 1 {
		t.Fatalf("errs = %v", errs)
	}
	if strings.Contains(errs[0], "SECRETTOK") || strings.Contains(errs[0], "token=") || strings.Contains(errs[0], "password=") {
		t.Fatalf("custom-URL credential leaked into errs (→ LastError/UI): %q", errs[0])
	}
	if !strings.Contains(errs[0], "prov.example") {
		t.Fatalf("errs should still name the failed source's host: %q", errs[0])
	}
}

// TestAggKeyNoCollision: distinct inputs must not share a preview-cache key (fmt "%v" space-joins, which
// two different source-URL sets can render identically), and the key stays order-independent.
func TestAggKeyNoCollision(t *testing.T) {
	if aggKey(nil, nil, []string{"http://a.com/x y", "http://b.com"}, false) == aggKey(nil, nil, []string{"http://a.com/x", "y http://b.com"}, false) {
		t.Fatal("aggKey collided across distinct source-URL sets")
	}
	if aggKey([]string{"us", "gb"}, nil, nil, true) != aggKey([]string{"gb", "us"}, nil, nil, true) {
		t.Fatal("aggKey must be order-independent (inputs are sorted)")
	}
}

func TestXtreamM3UURL(t *testing.T) {
	u, err := xtreamM3UURL(XtreamSource{URL: "prov.example:8080", Username: "a b", Password: "p&q"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u, "http://prov.example:8080/get.php?") { // bare host → http://, get.php path
		t.Fatalf("url = %q", u)
	}
	for _, want := range []string{"username=a+b", "password=p%26q", "type=m3u_plus", "output=m3u8"} {
		if !strings.Contains(u, want) {
			t.Fatalf("url %q missing %q", u, want)
		}
	}
	// A full URL keeps only scheme+host; any path is dropped.
	if u2, _ := xtreamM3UURL(XtreamSource{URL: "https://h.tv/portal/x", Username: "u", Password: "p"}); !strings.HasPrefix(u2, "https://h.tv/get.php?") {
		t.Fatalf("full-url form = %q", u2)
	}
	// Invalid accounts error, and the message NEVER contains the password.
	const secret = "S3kretPass"
	for _, bad := range []XtreamSource{
		{URL: "", Username: "u", Password: secret},
		{URL: "ftp://h", Username: "u", Password: secret},
		{URL: "h", Username: "", Password: secret},
		{URL: "h", Username: "u", Password: ""},
	} {
		_, err := xtreamM3UURL(bad)
		if err == nil {
			t.Fatalf("expected error for %+v", bad)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaked the password: %v", err)
		}
	}
}

func TestFetchAllXtream(t *testing.T) {
	var user, pass string
	client := &http.Client{Transport: rtFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/get.php" {
			user, pass = req.URL.Query().Get("username"), req.URL.Query().Get("password")
			return mkResp(http.StatusOK, "#EXTINF:-1 tvg-id=\"x\",X\nhttp://s/x\n"), nil
		}
		return mkResp(http.StatusNotFound, ""), nil
	})}
	chs, _, errs := fetchAll(context.Background(), client, nil, nil, nil, []XtreamSource{{URL: "http://prov.example", Username: "alice", Password: "secret"}})
	if len(chs) != 1 || len(errs) != 0 {
		t.Fatalf("xtream fetch: chs=%d errs=%v", len(chs), errs)
	}
	if user != "alice" || pass != "secret" {
		t.Fatalf("credentials not carried into get.php: %q/%q", user, pass)
	}
}

// TestFetchAllXtreamErrorHostOnly: an invalid account errors naming the HOST, never the credentials.
func TestFetchAllXtreamErrorHostOnly(t *testing.T) {
	client := &http.Client{Transport: rtFunc(func(*http.Request) (*http.Response, error) { return mkResp(http.StatusNotFound, ""), nil })}
	_, _, errs := fetchAll(context.Background(), client, nil, nil, nil, []XtreamSource{{URL: "prov.example", Username: "alice", Password: ""}})
	if len(errs) != 1 || !strings.Contains(errs[0], "prov.example") {
		t.Fatalf("expected a host-labelled error, got %v", errs)
	}
	if strings.Contains(errs[0], "alice") {
		t.Fatalf("error leaked the username: %v", errs)
	}
}

// TestCreateXtreamOnlyList: a list with ONLY an Xtream account is valid, stored, and exported.
func TestCreateXtreamOnlyList(t *testing.T) {
	enabled := true
	mux, _, _ := testDeps(t, &enabled)
	rec := do(t, mux, "POST", "/api/iptv/lists", `{"xtream_sources":[{"url":"http://prov.example:8080","username":"u","password":"p"}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create xtream-only = %d (%s)", rec.Code, rec.Body)
	}
	var l List
	if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil {
		t.Fatal(err)
	}
	if len(l.XtreamSources) != 1 || l.XtreamSources[0].Username != "u" {
		t.Fatalf("xtream not stored: %+v", l.XtreamSources)
	}
	// Export carries the account so import recreates it.
	rec = do(t, mux, "GET", "/api/iptv/lists/"+l.ID+"/export", "")
	if !strings.Contains(rec.Body.String(), `"xtream_sources"`) || !strings.Contains(rec.Body.String(), "prov.example") {
		t.Fatalf("export missing xtream: %s", rec.Body)
	}
	// A wholly-empty list (no country/url/xtream) is still rejected.
	if rec := do(t, mux, "POST", "/api/iptv/lists", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty list = %d, want 400", rec.Code)
	}
	// A malformed Xtream account (no password) is rejected without leaking anything.
	if rec := do(t, mux, "POST", "/api/iptv/lists", `{"xtream_sources":[{"url":"http://h","username":"u","password":""}]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad xtream = %d, want 400", rec.Code)
	}
}
