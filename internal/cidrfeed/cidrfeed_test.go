package cidrfeed

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestParseList(t *testing.T) {
	feed := "" +
		"# RU banks feed v3\n" +
		"77.88.0.0/16\n" +
		"  213.180.192.0/19   # Yandex market\n" + // inline comment + leading/trailing ws
		"; a semicolon comment line\n" +
		"8.8.8.8\n" + // bare IP -> /32
		"\n" + // blank
		"2001:db8::/32\n" + // v6
		"185.71.67.0/24 Russian Standard\n" + // trailing label
		"77.88.0.0/16\n" + // exact dup -> dropped
		"not-an-ip\n" + // skipped
		"999.1.1.1/24\n" + // invalid -> skipped
		"10.0.0.0/8\r\n" // CRLF

	cidrs, skipped := ParseList(feed)
	want := []string{
		"77.88.0.0/16",
		"213.180.192.0/19",
		"8.8.8.8/32",
		"2001:db8::/32",
		"185.71.67.0/24",
		"10.0.0.0/8",
	}
	if !reflect.DeepEqual(cidrs, want) {
		t.Errorf("cidrs = %v\n want %v", cidrs, want)
	}
	if skipped != 2 { // not-an-ip + 999.1.1.1/24
		t.Errorf("skipped = %d, want 2", skipped)
	}
}

func TestParseList_NormalizesAndMasks(t *testing.T) {
	// Host bits in a CIDR are masked to the network address (so identical networks written
	// with different host bits dedupe), and the order is first-seen.
	cidrs, skipped := ParseList("1.2.3.4/24\n1.2.3.200/24\n")
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0", skipped)
	}
	if !reflect.DeepEqual(cidrs, []string{"1.2.3.0/24"}) {
		t.Errorf("cidrs = %v, want [1.2.3.0/24] (masked + deduped)", cidrs)
	}
}

func TestParseList_Empty(t *testing.T) {
	for _, in := range []string{"", "\n\n", "# only comments\n; another\n", "   \n\t\n"} {
		if cidrs, skipped := ParseList(in); len(cidrs) != 0 || skipped != 0 {
			t.Errorf("ParseList(%q) = (%v, %d), want ([], 0)", in, cidrs, skipped)
		}
	}
}

func TestParseRIPEstat(t *testing.T) {
	body := []byte(`{"data":{"resource":"13238","prefixes":[
		{"prefix":"5.45.192.0/18","timelines":[]},
		{"prefix":"77.88.0.0/18"},
		{"prefix":"2a02:6b8::/32"},
		{"prefix":"5.45.192.0/18"},
		{"prefix":"bogus/33"}
	]}}`)
	cidrs, skipped, err := ParseRIPEstat(body)
	if err != nil {
		t.Fatalf("ParseRIPEstat: %v", err)
	}
	want := []string{"5.45.192.0/18", "77.88.0.0/18", "2a02:6b8::/32"}
	if !reflect.DeepEqual(cidrs, want) {
		t.Errorf("cidrs = %v, want %v", cidrs, want)
	}
	if skipped != 1 { // bogus/33
		t.Errorf("skipped = %d, want 1", skipped)
	}
	if _, _, err := ParseRIPEstat([]byte("not json")); err == nil {
		t.Error("want error on malformed json")
	}
}

func TestFetch_HTTPSFeed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "# feed\n1.2.3.0/24\n5.6.7.8\n")
	}))
	defer ts.Close()
	cidrs, _, err := Fetch(context.Background(), ts.Client(), ts.URL)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !reflect.DeepEqual(cidrs, []string{"1.2.3.0/24", "5.6.7.8/32"}) {
		t.Errorf("cidrs = %v", cidrs)
	}
}

func TestFetch_ASN_MergeDedup(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("resource"), "13238") {
			io.WriteString(w, `{"data":{"prefixes":[{"prefix":"5.45.192.0/18"},{"prefix":"77.88.0.0/18"}]}}`)
		} else {
			io.WriteString(w, `{"data":{"prefixes":[{"prefix":"77.88.0.0/18"},{"prefix":"87.240.128.0/18"}]}}`)
		}
	}))
	defer ts.Close()
	old := RIPEstatBase
	RIPEstatBase = ts.URL + "/?resource=AS"
	defer func() { RIPEstatBase = old }()

	cidrs, _, err := Fetch(context.Background(), ts.Client(), "asn:13238,47541")
	if err != nil {
		t.Fatalf("Fetch asn: %v", err)
	}
	want := []string{"5.45.192.0/18", "77.88.0.0/18", "87.240.128.0/18"} // 77.88 deduped across ASNs
	if !reflect.DeepEqual(cidrs, want) {
		t.Errorf("cidrs = %v, want %v", cidrs, want)
	}
}

func TestFetch_Errors(t *testing.T) {
	if _, _, err := Fetch(context.Background(), http.DefaultClient, "ftp://x"); err == nil {
		t.Error("want error on unsupported scheme")
	}
	if _, _, err := Fetch(context.Background(), http.DefaultClient, "asn:notanumber"); err == nil {
		t.Error("want error on non-numeric asn")
	}
	// a non-200 from the feed must error (so the caller keeps last-good, not an empty set).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	if _, _, err := Fetch(context.Background(), ts.Client(), ts.URL); err == nil {
		t.Error("want error on HTTP 500")
	}
}

// TestParseList_StripsBOM: a UTF-8 BOM (common on Windows-authored feeds) must not corrupt the first
// CIDR. The BOM isn't whitespace, so without an explicit strip TrimSpace leaves it on the first token
// and normalize rejects it — silently dropping the first (often largest) prefix.
func TestParseList_StripsBOM(t *testing.T) {
	cidrs, skipped := ParseList("\uFEFF45.10.0.0/16\n77.88.8.0/24\n")
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0 (BOM must not corrupt the first entry)", skipped)
	}
	if !reflect.DeepEqual(cidrs, []string{"45.10.0.0/16", "77.88.8.0/24"}) {
		t.Errorf("cidrs = %v, want both prefixes (first not dropped by the BOM)", cidrs)
	}
}
