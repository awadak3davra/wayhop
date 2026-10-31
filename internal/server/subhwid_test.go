package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/platform"
)

// Competitor gap 25: subscription HWID. Invented IDs only; nothing here is a real device's.
const (
	testHWID      = "Test-HWID=0123456789"
	otherTestHWID = "other-test-hwid-42"
	testGenHWID   = "0123456789abcdef"
)

// generatedHWIDPattern is the shape newHWID makes.
var generatedHWIDPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// hwidHeaderNames are every device header Remnawave reads besides user-agent.
var hwidHeaderNames = []string{"X-Hwid", "X-Device-Os", "X-Ver-Os", "X-Device-Model"}

func TestSetSubscriptionHeaders(t *testing.T) {
	// Off: the User-Agent and nothing else, so a provider without a device limit sees what it saw before.
	h := http.Header{}
	setSubscriptionHeaders(h, "", "", platform.Keenetic)
	if got := h.Get("User-Agent"); got != "wayhop" {
		t.Errorf("User-Agent = %q, want the default wayhop", got)
	}
	for _, n := range hwidHeaderNames {
		if v := h.Get(n); v != "" {
			t.Errorf("HWID off sent %s: %q", n, v)
		}
	}

	// On: x-hwid and the platform; the OS version and the model are never sent.
	for p, want := range map[platform.Platform]string{platform.Keenetic: "KeeneticOS", platform.OpenWrt: "OpenWrt", platform.Unknown: "Linux"} {
		h := http.Header{}
		setSubscriptionHeaders(h, "sing-box", testHWID, p)
		if h.Get("User-Agent") != "sing-box" || h.Get("X-Hwid") != testHWID || h.Get("X-Device-Os") != want {
			t.Errorf("%s: headers = %v, want sing-box / %s / %s", p, h, testHWID, want)
		}
		if h.Get("X-Ver-Os") != "" || h.Get("X-Device-Model") != "" {
			t.Errorf("%s: sent the OS version or the model: %v", p, h)
		}
	}
}

// The panel refuses what Remnawave would ignore (^[a-zA-Z0-9=-]{10,64}$): stored, such a value would be
// a 404 from a device-limited panel with nothing saying why.
func TestCheckHWIDRequest(t *testing.T) {
	for _, ok := range []string{"abcdefghij", strings.Repeat("A", 64), testHWID, "0123456789==--"} {
		if err := checkHWIDRequest("custom", ok); err != nil {
			t.Errorf("custom %q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "abcdefghi", strings.Repeat("a", 65), "abc_defghij", "abc defghij", "abc/defghij", "abc+defghij", "абвгдежзий", "abcdefghij\n"} {
		if err := checkHWIDRequest("custom", bad); err == nil {
			t.Errorf("custom %q accepted, want refused", bad)
		}
	}
	for _, mode := range []string{"", "off", "generate"} {
		if err := checkHWIDRequest(mode, "ignored"); err != nil {
			t.Errorf("mode %q refused: %v", mode, err)
		}
	}
	if err := checkHWIDRequest("auto", ""); err == nil {
		t.Error("unknown mode accepted")
	}
}

// fakeDeviceLimitedPanel answers like Remnawave with its HWID device limit on: 404 to a fetch without a
// usable x-hwid, the subscription otherwise. It records the headers of every fetch.
type fakeDeviceLimitedPanel struct {
	mu   sync.Mutex
	seen []http.Header
}

func (f *fakeDeviceLimitedPanel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seen = append(f.seen, r.Header.Clone())
	f.mu.Unlock()
	if !validHWID(r.Header.Get("x-hwid")) {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write([]byte("trojan://secretpass@example.com:443?security=tls&sni=example.com#T1\n"))
}

func (f *fakeDeviceLimitedPanel) last(t *testing.T) http.Header {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.seen) == 0 {
		t.Fatal("the panel was never fetched")
	}
	return f.seen[len(f.seen)-1]
}

func (f *fakeDeviceLimitedPanel) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

func hwidImport(t *testing.T, s *Server, u, mode, hwid string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"url": u, "hwid_mode": mode, "hwid": hwid})
	return servererrorpaths_post(s.handleSubscription, "/api/subscription", string(body))
}

// storedSub reads the subscription back from config.json, not from memory: "kept" means it survives a
// restart.
func storedSub(t *testing.T, s *Server) config.Subscription {
	t.Helper()
	c, err := config.Load(filepath.Join(s.config().DataDir, "config.json"))
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	return c.Subscription
}

// storedHWID is the stored HWID the stored URL is fetched with.
func storedHWID(t *testing.T, s *Server) string {
	t.Helper()
	return storedSub(t, s).HWID
}

// subServer serves the subscription to every fetch and records the x-hwid of each.
func subServer(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var got []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Header.Get("x-hwid"))
		mu.Unlock()
		_, _ = w.Write([]byte("trojan://secretpass@example.com:443?security=tls&sni=example.com#T1\n"))
	}))
	t.Cleanup(ts.Close)
	return ts, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), got...) }
}

// importedHWID is the "hwid" a successful import answers with.
func importedHWID(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("import: %d %s", w.Code, w.Body.String())
	}
	var r struct {
		HWID string `json:"hwid"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r.HWID
}

// End to end against a device-limited panel: without an HWID neither the import nor the refresh gets the
// subscription; with one both do, and both present the same device.
func TestSubscriptionHWID_DeviceLimitedPanel(t *testing.T) {
	s := servererrorpaths_server(t)
	s.allowInternalFetch = true
	s.platformOf = func() platform.Platform { return platform.OpenWrt }
	panel := &fakeDeviceLimitedPanel{}
	upstream := httptest.NewServer(panel)
	defer upstream.Close()

	// What WayHop did before: no x-hwid, so 404.
	if w := hwidImport(t, s, upstream.URL, "off", ""); w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "404") {
		t.Fatalf("import without an HWID: %d %s, want 502 naming the 404", w.Code, w.Body.String())
	}

	// Generated: fetched, and the ID is kept with the URL.
	w := hwidImport(t, s, upstream.URL, "generate", "")
	if w.Code != http.StatusOK {
		t.Fatalf("import with a generated HWID: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Endpoints []json.RawMessage `json:"endpoints"`
		HWID      string            `json:"hwid"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	id := storedHWID(t, s)
	if len(resp.Endpoints) != 1 || !generatedHWIDPattern.MatchString(id) || resp.HWID != id {
		t.Fatalf("import: %d endpoints, stored %q, answered %q; want 1 and one generated ID", len(resp.Endpoints), id, resp.HWID)
	}
	if h := panel.last(t); h.Get("x-hwid") != id || h.Get("x-device-os") != "OpenWrt" || h.Get("user-agent") != "wayhop" {
		t.Errorf("import sent %v", h)
	}

	// The scheduled refresh asks as the same device.
	added, err := s.refreshSubscriptionOnce(context.Background())
	if err != nil || added != 1 {
		t.Fatalf("refresh: added %d, err %v; want 1, nil", added, err)
	}
	if h := panel.last(t); h.Get("x-hwid") != id || h.Get("x-device-os") != "OpenWrt" {
		t.Errorf("refresh sent %v, want the stored %q", h, id)
	}

	// A custom value the panel would ignore is refused before anything is fetched or saved.
	n := panel.count()
	if w := hwidImport(t, s, upstream.URL, "custom", "too short"); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid custom HWID: %d, want 400", w.Code)
	}
	if panel.count() != n || storedHWID(t, s) != id {
		t.Error("a refused HWID still reached the provider or the config")
	}

	// Custom: used and kept; the refresh follows it.
	if w := hwidImport(t, s, upstream.URL, "custom", " "+testHWID+" "); w.Code != http.StatusOK {
		t.Fatalf("custom HWID: %d %s", w.Code, w.Body.String())
	}
	if storedHWID(t, s) != testHWID || panel.last(t).Get("x-hwid") != testHWID {
		t.Errorf("custom HWID not sent or kept (trimmed): stored %q", storedHWID(t, s))
	}
	if _, err := s.refreshSubscriptionOnce(context.Background()); err != nil || panel.last(t).Get("x-hwid") != testHWID {
		t.Errorf("refresh after custom: %v, sent %q", err, panel.last(t).Get("x-hwid"))
	}

	// Off fails against this panel, and a failed import changes nothing: the refresh keeps the last
	// working ID.
	if w := hwidImport(t, s, upstream.URL, "generate", ""); w.Code != http.StatusOK {
		t.Fatalf("re-generate: %d", w.Code)
	}
	if w := hwidImport(t, s, upstream.URL, "off", ""); w.Code != http.StatusBadGateway {
		t.Fatalf("off: %d, want the 404 as 502", w.Code)
	}
	if _, err := s.refreshSubscriptionOnce(context.Background()); err != nil {
		t.Fatalf("refresh still has the last working HWID and must succeed: %v", err)
	}
	if h := panel.last(t); h.Get("x-hwid") == "" {
		t.Error("a failed import switched the stored HWID off")
	}
}

// "Generate" makes the ID once: a later fetch reuses it, a failed fetch keeps it (the provider may have
// counted the device already), and a mode absent from the request keeps whatever is stored.
func TestSubscriptionHWID_GeneratedOnceAndKept(t *testing.T) {
	s := servererrorpaths_server(t)
	s.allowInternalFetch = true
	fail := true
	var got []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("x-hwid"))
		if fail {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("trojan://secretpass@example.com:443?security=tls&sni=example.com#T1\n"))
	}))
	defer upstream.Close()

	if w := hwidImport(t, s, upstream.URL, "generate", ""); w.Code != http.StatusBadGateway {
		t.Fatalf("failing upstream: %d", w.Code)
	}
	// Kept as the generated ID, but not yet as the one a stored URL is fetched with: nothing was stored.
	sub := storedSub(t, s)
	id := sub.GeneratedHWID
	if !generatedHWIDPattern.MatchString(id) || sub.HWID != "" || sub.URL != "" {
		t.Fatalf("after a failed fetch: generated %q, hwid %q, url %q; want a kept ID and nothing else", id, sub.HWID, sub.URL)
	}
	fail = false
	for i := 0; i < 2; i++ {
		if w := hwidImport(t, s, upstream.URL, "generate", ""); w.Code != http.StatusOK {
			t.Fatalf("generate #%d: %d", i, w.Code)
		}
	}
	if w := hwidImport(t, s, upstream.URL, "", ""); w.Code != http.StatusOK {
		t.Fatalf("no mode: %d", w.Code)
	}
	if len(got) != 4 || got[0] != id || got[1] != id || got[2] != id || got[3] != id || storedHWID(t, s) != id {
		t.Errorf("sent %q, stored %q; want %q every time", got, storedHWID(t, s), id)
	}

	// From a custom value, "generate" means the generated ID, not the custom one renamed.
	if w := hwidImport(t, s, upstream.URL, "custom", testHWID); w.Code != http.StatusOK {
		t.Fatalf("custom: %d", w.Code)
	}
	if sub := storedSub(t, s); sub.HWID != testHWID || sub.GeneratedHWID != id {
		t.Errorf("custom stored %q and left the generated %q, want %q and %q", sub.HWID, sub.GeneratedHWID, testHWID, id)
	}
	if w := hwidImport(t, s, upstream.URL, "generate", ""); w.Code != http.StatusOK {
		t.Fatalf("generate after custom: %d", w.Code)
	}
	if again := storedHWID(t, s); again != id {
		t.Errorf("generate after custom stored %q, want the generated %q", again, id)
	}

	// Off, fetched: nothing sent and no HWID for the URL, but the generated one stays.
	if w := hwidImport(t, s, upstream.URL, "off", ""); w.Code != http.StatusOK {
		t.Fatalf("off: %d", w.Code)
	}
	if sub := storedSub(t, s); got[len(got)-1] != "" || sub.HWID != "" || sub.GeneratedHWID != id {
		t.Errorf("off sent %q and stored %q (generated %q)", got[len(got)-1], sub.HWID, sub.GeneratedHWID)
	}

	// Two generated IDs differ: random, not derived from anything about the host.
	a, _ := newHWID()
	b, _ := newHWID()
	if a == b || !generatedHWIDPattern.MatchString(a) {
		t.Errorf("newHWID gave %q and %q", a, b)
	}
}

// A refresh with an HWID hand-edited into something the provider ignores fails as a configuration error
// rather than as the provider's 404.
func TestSubscriptionHWID_RefreshRefusesAnInvalidStoredValue(t *testing.T) {
	s := servererrorpaths_server(t)
	s.cfgMu.Lock()
	s.cfg.Subscription.URL = "https://provider.example/sub"
	s.cfg.Subscription.HWID = "bad hwid!"
	s.cfgMu.Unlock()
	if w := servererrorpaths_post(s.handleSubRefreshNow, "/api/subscription/refresh", "{}"); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "hwid") {
		t.Fatalf("refresh with an invalid stored HWID: %d %s, want 400 naming the hwid", w.Code, w.Body.String())
	}
}

// The config export masks the HWID unless secrets are included; an import restores it, keeps the current
// one for the mask or an absent value, and refuses an invalid one before saving anything.
func TestSubscriptionHWID_ConfigExportImport(t *testing.T) {
	s := cfgFileServer(t)
	s.cfg.Subscription.HWID = testHWID
	s.cfg.Subscription.GeneratedHWID = testGenHWID

	var red, full config.Config
	_ = json.Unmarshal(getRec(t, s.handleConfigExport, "/api/config/export").Body.Bytes(), &red)
	_ = json.Unmarshal(getRec(t, s.handleConfigExport, "/api/config/export?secrets=1").Body.Bytes(), &full)
	if red.Subscription.HWID != config.RedactedMark || full.Subscription.HWID != testHWID {
		t.Fatalf("export: redacted %q, with secrets %q", red.Subscription.HWID, full.Subscription.HWID)
	}
	if red.Subscription.GeneratedHWID != config.RedactedMark || full.Subscription.GeneratedHWID != testGenHWID {
		t.Fatalf("export: generated redacted %q, with secrets %q", red.Subscription.GeneratedHWID, full.Subscription.GeneratedHWID)
	}
	// GET /api/config shows both: the Subscription tab displays the ID it sends and the generated one.
	var shown config.Config
	_ = json.Unmarshal(getRec(t, s.handleGetConfig, "/api/config").Body.Bytes(), &shown)
	if shown.Subscription.HWID != testHWID || shown.Subscription.GeneratedHWID != testGenHWID {
		t.Errorf("GET /api/config hwid = %q, generated %q", shown.Subscription.HWID, shown.Subscription.GeneratedHWID)
	}

	imp := func(hwid, gen string) int {
		in := s.config()
		in.Subscription.HWID, in.Subscription.GeneratedHWID = hwid, gen
		body, _ := json.Marshal(in)
		return opshandlers_post(s.handleConfigImport, "/api/config/import", string(body)).Code
	}
	kept := func(hwid, gen string) bool {
		c := s.config().Subscription
		return c.HWID == hwid && c.GeneratedHWID == gen
	}
	if code := imp(config.RedactedMark, config.RedactedMark); code != http.StatusOK || !kept(testHWID, testGenHWID) {
		t.Errorf("import of a redacted export: %d, %+v", code, s.config().Subscription)
	}
	if code := imp("", ""); code != http.StatusOK || !kept(testHWID, testGenHWID) {
		t.Errorf("import without an hwid: %d, %+v", code, s.config().Subscription)
	}
	if code := imp(otherTestHWID, "fedcba9876543210"); code != http.StatusOK || !kept(otherTestHWID, "fedcba9876543210") {
		t.Errorf("import with secrets: %d, %+v", code, s.config().Subscription)
	}
	before := s.config().RoutingMode
	for _, bad := range [][2]string{{"no good", ""}, {"", "no good"}} {
		in := s.config()
		in.Subscription.HWID, in.Subscription.GeneratedHWID = bad[0], bad[1]
		in.RoutingMode = "fast"
		body, _ := json.Marshal(in)
		if code := opshandlers_post(s.handleConfigImport, "/api/config/import", string(body)).Code; code != http.StatusBadRequest {
			t.Errorf("import with an invalid hwid %q: %d, want 400", bad, code)
		}
		if c := s.config(); !kept(otherTestHWID, "fedcba9876543210") || c.RoutingMode != before {
			t.Errorf("a refused import changed the config: %+v", c.Subscription)
		}
	}
}

// The full backup carries the HWID, and a restore onto a fresh router brings it back; a bundle without
// one keeps the current one, and an invalid one refuses the restore before anything changes.
func TestSubscriptionHWID_FullBackupRestore(t *testing.T) {
	srvA, hA := backup_newServer(t)
	tsA := httptest.NewServer(hA)
	defer tsA.Close()
	if err := srvA.store.Replace(sampleProfile()); err != nil {
		t.Fatal(err)
	}
	srvA.cfgMu.Lock()
	srvA.cfg.Subscription.HWID = testHWID
	srvA.cfg.Subscription.GeneratedHWID = testGenHWID
	srvA.cfgMu.Unlock()
	_, bundle, _ := backup_get(t, tsA, "/api/backup")
	if !strings.Contains(string(bundle), `"subscription_hwid": "`+testHWID+`"`) ||
		!strings.Contains(string(bundle), `"subscription_generated_hwid": "`+testGenHWID+`"`) {
		t.Fatalf("the full backup does not carry both HWIDs: %s", bundle)
	}

	srvB, hB := backup_newServer(t)
	tsB := httptest.NewServer(hB)
	defer tsB.Close()
	if code, out := backup_post(t, tsB, "/api/backup/restore", bundle); code != http.StatusOK {
		t.Fatalf("restore: %d %s", code, out)
	}
	if got := srvB.config().Subscription; got.HWID != testHWID || got.GeneratedHWID != testGenHWID {
		t.Errorf("restored hwid = %q, generated %q; want %q, %q", got.HWID, got.GeneratedHWID, testHWID, testGenHWID)
	}

	var b map[string]any
	_ = json.Unmarshal(bundle, &b)
	delete(b, "subscription_hwid")
	delete(b, "subscription_generated_hwid")
	older, _ := json.Marshal(b)
	srvB.cfgMu.Lock()
	srvB.cfg.Subscription.HWID = otherTestHWID
	srvB.cfg.Subscription.GeneratedHWID = "fedcba9876543210"
	srvB.cfgMu.Unlock()
	if code, out := backup_post(t, tsB, "/api/backup/restore", older); code != http.StatusOK ||
		srvB.config().Subscription.HWID != otherTestHWID || srvB.config().Subscription.GeneratedHWID != "fedcba9876543210" {
		t.Errorf("restore without an hwid: %d %s, %+v (want kept)", code, out, srvB.config().Subscription)
	}

	for _, key := range []string{"subscription_hwid", "subscription_generated_hwid"} {
		b2 := map[string]any{}
		for k, v := range b {
			b2[k] = v
		}
		b2[key] = "no good"
		bad, _ := json.Marshal(b2)
		srvC, hC := backup_newServer(t)
		tsC := httptest.NewServer(hC)
		if code, _ := backup_post(t, tsC, "/api/backup/restore", bad); code != http.StatusBadRequest {
			t.Errorf("restore with an invalid %s: %d, want 400", key, code)
		}
		if c := srvC.config().Subscription; len(srvC.store.Profile().Endpoints) != 0 || c.HWID != "" || c.GeneratedHWID != "" {
			t.Errorf("a refused restore (%s) still changed the profile or the config", key)
		}
		tsC.Close()
	}
}

// Finding 1 of the gap-25 review: the generated ID is made once. Off and a custom ID used to overwrite
// the one field it lived in, so going back to Generate made a new ID, another device slot each time.
func TestSubscriptionHWID_GeneratedSurvivesOffAndCustom(t *testing.T) {
	s := servererrorpaths_server(t)
	s.allowInternalFetch = true
	upstream, sent := subServer(t)

	id := importedHWID(t, hwidImport(t, s, upstream.URL, "generate", ""))
	if !generatedHWIDPattern.MatchString(id) {
		t.Fatalf("generate answered %q", id)
	}
	for _, step := range [][2]string{{"off", ""}, {"generate", ""}, {"custom", testHWID}, {"generate", ""}, {"off", ""}, {"custom", otherTestHWID}, {"generate", ""}} {
		got := importedHWID(t, hwidImport(t, s, upstream.URL, step[0], step[1]))
		want := step[1]
		if step[0] == "generate" {
			want = id
		}
		if got != want || storedHWID(t, s) != want {
			t.Fatalf("%s: answered %q, stored %q; want %q (sent so far %q)", step[0], got, storedHWID(t, s), want, sent())
		}
	}
	for _, h := range sent() {
		if generatedHWIDPattern.MatchString(h) && h != id {
			t.Errorf("a second generated ID reached the provider: %q (sent %q)", h, sent())
		}
	}
}

// Finding 2: "generate" stored its new ID as the stored URL's HWID before the fetch, so a failed import
// (or one of another URL) changed what the stored subscription is fetched with: a new device at that
// provider, and a custom ID lost.
func TestSubscriptionHWID_FailedImportKeepsTheStoredChoice(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer failing.Close()
	for _, c := range []struct{ mode, hwid string }{{"off", ""}, {"custom", testHWID}} {
		s := servererrorpaths_server(t)
		s.allowInternalFetch = true
		providerA, sent := subServer(t)
		if got := importedHWID(t, hwidImport(t, s, providerA.URL, c.mode, c.hwid)); got != c.hwid {
			t.Fatalf("%s: import of A answered %q", c.mode, got)
		}
		if w := hwidImport(t, s, failing.URL+"/b", "generate", ""); w.Code != http.StatusBadGateway {
			t.Fatalf("%s: failed import of B: %d", c.mode, w.Code)
		}
		if sub := storedSub(t, s); sub.URL != providerA.URL || sub.HWID != c.hwid {
			t.Errorf("%s: a failed import of B left url %q hwid %q, want A's %q", c.mode, sub.URL, sub.HWID, c.hwid)
		}
		if _, err := s.refreshSubscriptionOnce(context.Background()); err != nil {
			t.Fatalf("%s: refresh of A: %v", c.mode, err)
		}
		if got := sent(); got[len(got)-1] != c.hwid {
			t.Errorf("%s: the refresh of A sent x-hwid %q, want %q", c.mode, got[len(got)-1], c.hwid)
		}
	}
}

// Finding 3: with no mode (the panel could not read the stored choice) an import of another URL sent
// provider A's ID to provider B.
func TestSubscriptionHWID_NoModeSendsNoneToAnotherURL(t *testing.T) {
	s := servererrorpaths_server(t)
	s.allowInternalFetch = true
	providerA, sentA := subServer(t)
	providerB, sentB := subServer(t)
	importedHWID(t, hwidImport(t, s, providerA.URL, "custom", testHWID))

	// The same URL with no mode keeps the stored ID.
	if got := importedHWID(t, hwidImport(t, s, providerA.URL, "", "")); got != testHWID || sentA()[1] != testHWID {
		t.Fatalf("no mode, same URL: answered %q, sent %q", got, sentA())
	}
	// Another URL with no mode gets none, and is then stored with none.
	if got := importedHWID(t, hwidImport(t, s, providerB.URL, "", "")); got != "" || sentB()[0] != "" {
		t.Errorf("no mode, another URL: answered %q, B received x-hwid %q", got, sentB()[0])
	}
	if sub := storedSub(t, s); sub.URL != providerB.URL || sub.HWID != "" {
		t.Errorf("stored url %q hwid %q, want B with none", sub.URL, sub.HWID)
	}
}

// Finding 5: an invalid custom ID refused a pasted text that fetches nothing, and an import with no mode
// sent a hand-edited invalid stored ID unchecked while the refresh refuses it.
func TestSubscriptionHWID_ValidationScope(t *testing.T) {
	s := servererrorpaths_server(t)
	s.allowInternalFetch = true
	body, _ := json.Marshal(map[string]string{"text": "trojan://secretpass@example.com:443?security=tls&sni=example.com#T1\n", "hwid_mode": "custom", "hwid": "too short"})
	w := servererrorpaths_post(s.handleSubscription, "/api/subscription", string(body))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"endpoints":[{`) {
		t.Errorf("a pasted text with an invalid custom HWID: %d %s, want parsed", w.Code, w.Body.String())
	}

	upstream, sent := subServer(t)
	s.cfgMu.Lock()
	s.cfg.Subscription.URL = upstream.URL
	s.cfg.Subscription.HWID = "bad hwid!"
	s.cfgMu.Unlock()
	if w := hwidImport(t, s, upstream.URL, "", ""); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "hwid") {
		t.Errorf("no mode with an invalid stored HWID: %d %s, want 400 naming the hwid", w.Code, w.Body.String())
	}
	if n := len(sent()); n != 0 {
		t.Errorf("the invalid stored HWID still reached the provider (%d fetches)", n)
	}
}

// Finding 6: a device-limited panel's 404 to a fetch without an HWID now says what it most likely is;
// a 404 to a fetch that sent one does not.
func TestSubscriptionHWID_404WithoutHWIDSaysWhy(t *testing.T) {
	const note = "a provider with a device limit needs an HWID"
	s := servererrorpaths_server(t)
	s.allowInternalFetch = true
	panel := httptest.NewServer(&fakeDeviceLimitedPanel{})
	defer panel.Close()
	if w := hwidImport(t, s, panel.URL, "off", ""); w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "404") || !strings.Contains(w.Body.String(), note) {
		t.Errorf("import without an HWID: %d %s, want the 404 with the note", w.Code, w.Body.String())
	}
	s.cfgMu.Lock()
	s.cfg.Subscription.URL = panel.URL
	s.cfgMu.Unlock()
	if _, err := s.refreshSubscriptionOnce(context.Background()); err == nil || !strings.Contains(err.Error(), note) {
		t.Errorf("refresh without an HWID: %v, want the note", err)
	}

	gone := httptest.NewServer(http.NotFoundHandler())
	defer gone.Close()
	if w := hwidImport(t, s, gone.URL, "custom", testHWID); w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), note) {
		t.Errorf("a 404 with an HWID sent: %d %s, want no note", w.Code, w.Body.String())
	}
}

// redirectSeen records, at the end of a redirect, the headers that reached it.
type redirectSeen struct {
	mu   sync.Mutex
	last http.Header
}

func (r *redirectSeen) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.last = req.Header.Clone()
	r.mu.Unlock()
	_, _ = w.Write([]byte("trojan://secretpass@example.com:443?security=tls&sni=example.com#T1\n"))
}

func (r *redirectSeen) get() http.Header {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}

// Finding 4 and QA-126: a redirected subscription fetch sent the subscription URL (its token) as
// Referer, and x-hwid with x-device-os to whatever host the provider redirected to. The import and the
// refresh alike: neither sends a Referer now, and the device headers go only to the host given.
func TestSubscriptionRedirect_NoRefererNoHWIDToAnotherHost(t *testing.T) {
	const token = "/sub/secret-token-123"
	final := &redirectSeen{}
	target := httptest.NewServer(final)
	defer target.Close()
	tu, _ := url.Parse(target.URL)
	for _, c := range []struct {
		name, to   string
		keepDevice bool
	}{
		// 127.0.0.1 on another port: the same host (the port is not compared).
		{"same host", target.URL + "/final", true},
		// The same server under another name: another host, without leaving loopback.
		{"another host", "http://localhost:" + tu.Port() + "/final", false},
	} {
		start := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != token {
				http.NotFound(w, r)
				return
			}
			http.Redirect(w, r, c.to, http.StatusFound)
		}))
		s := servererrorpaths_server(t)
		s.allowInternalFetch = true
		s.platformOf = func() platform.Platform { return platform.OpenWrt }

		check := func(what string) {
			t.Helper()
			h := final.get()
			if h == nil {
				t.Fatalf("%s, %s: the redirect target was never reached", c.name, what)
			}
			if ref := h.Get("Referer"); ref != "" {
				t.Errorf("%s, %s: Referer %q reached the redirect target", c.name, what, ref)
			}
			if got := h.Get("X-Hwid") != "" || h.Get("X-Device-Os") != ""; got != c.keepDevice {
				t.Errorf("%s, %s: device headers at the target = %v (x-hwid %q, x-device-os %q), want %v",
					c.name, what, got, h.Get("X-Hwid"), h.Get("X-Device-Os"), c.keepDevice)
			}
			if h.Get("User-Agent") != "wayhop" {
				t.Errorf("%s, %s: User-Agent %q", c.name, what, h.Get("User-Agent"))
			}
		}
		final.mu.Lock()
		final.last = nil
		final.mu.Unlock()
		importedHWID(t, hwidImport(t, s, start.URL+token, "custom", testHWID))
		check("import")
		final.mu.Lock()
		final.last = nil
		final.mu.Unlock()
		if _, err := s.refreshSubscriptionOnce(context.Background()); err != nil {
			t.Fatalf("%s: refresh: %v", c.name, err)
		}
		check("refresh")
		start.Close()
	}
}

// subscriptionRedirect on its own: the host compare ignores case and port, and the redirect cap holds.
func TestSubscriptionRedirectFunc(t *testing.T) {
	first, _ := http.NewRequest(http.MethodGet, "https://provider.example.com/sub/token", nil)
	hop := func(to string) http.Header {
		req, _ := http.NewRequest(http.MethodGet, to, nil)
		req.Header.Set("Referer", first.URL.String())
		req.Header.Set("X-Hwid", testHWID)
		req.Header.Set("X-Device-Os", "OpenWrt")
		if err := subscriptionRedirect(req, []*http.Request{first}); err != nil {
			t.Fatal(err)
		}
		return req.Header
	}
	if h := hop("https://PROVIDER.example.com:8443/next"); h.Get("X-Hwid") != testHWID || h.Get("X-Device-Os") != "OpenWrt" || h.Get("Referer") != "" {
		t.Errorf("same host: %v", h)
	}
	if h := hop("https://cdn.example.net/next"); h.Get("X-Hwid") != "" || h.Get("X-Device-Os") != "" || h.Get("Referer") != "" {
		t.Errorf("another host: %v", h)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://provider.example.com/6", nil)
	if err := subscriptionRedirect(req, make([]*http.Request, 5)); err == nil {
		t.Error("a sixth redirect was followed")
	}
}
