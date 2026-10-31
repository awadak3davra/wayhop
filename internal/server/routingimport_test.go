package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/importer"
	"wayhop/internal/platform"
	"wayhop/internal/store"
)

// importKeeneticConfig is a running-config with the parts the import reads, on documentation
// addresses. The private key stands for the secrets a real one carries: it must never reach the answer.
const importKeeneticConfig = `interface Wireguard0
    description VPN
    wireguard private-key do-not-leak-this-key
!
object-group fqdn domain-list7
    description Telegram
    include example.org
    include 192.0.2.0/24
    include bad name
!
object-group fqdn domain-list8
    include *.example.net
!
dns-proxy
    route object-group domain-list7 Wireguard0 auto
!
`

func routingImportServer(p platform.Platform, read keeneticConfigReadFunc) *Server {
	return &Server{cfg: &config.Config{}, platformOf: func() platform.Platform { return p }, keeneticConfigReader: read}
}

func decodeRoutingImport(t *testing.T, w *httptest.ResponseRecorder) routingImportAnswer {
	t.Helper()
	var ans routingImportAnswer
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &ans) != nil {
		t.Fatalf("want 200 with an answer, got %d %s", w.Code, w.Body.String())
	}
	return ans
}

func TestRoutingImportKeenetic_ReadsTheRouterGroups(t *testing.T) {
	reads := 0
	s := routingImportServer(platform.Keenetic, func(context.Context) (string, error) {
		reads++
		return importKeeneticConfig, nil
	})
	w := httptest.NewRecorder()
	s.handleRoutingImportKeenetic(w, httptest.NewRequest(http.MethodGet, "/api/routing/import/keenetic", nil))
	ans := decodeRoutingImport(t, w)
	if reads != 1 || ans.Source != "keenetic" || ans.Demo || len(ans.Groups) != 2 {
		t.Fatalf("reads %d, answer %+v", reads, ans)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("a live router read must not be cached")
	}
	if strings.Contains(w.Body.String(), "private-key") || strings.Contains(w.Body.String(), "do-not-leak") {
		t.Fatalf("the running-config leaked into the answer: %s", w.Body.String())
	}

	tg := ans.Groups[0]
	if tg.Name != "domain-list7" || tg.Description != "Telegram" || tg.Route != "Wireguard0" {
		t.Errorf("group header = %+v", tg)
	}
	if want := []routingImportSkip{{Entry: "bad name", Reason: importer.HydraSkipInvalid}}; !reflect.DeepEqual(tg.Skipped, want) {
		t.Errorf("skipped = %+v, want %+v", tg.Skipped, want)
	}
	// The suggestion is named by the description and carries names then prefixes.
	if want := (&routingImportList{Name: "Telegram", Manual: []string{"example.org", "192.0.2.0/24"}}); !reflect.DeepEqual(tg.Suggested, want) || tg.Refused != "" {
		t.Errorf("suggested = %+v (refused %q), want %+v", tg.Suggested, tg.Refused, want)
	}

	// Nothing usable: no suggestion, and the model's reason instead. Empty lists stay arrays.
	empty := ans.Groups[1]
	if empty.Suggested != nil || !strings.HasPrefix(empty.Refused, "needs ") || empty.Domains == nil || empty.CIDRs == nil {
		t.Errorf("an unusable group = %+v", empty)
	}
	if !strings.Contains(w.Body.String(), `"domains":[]`) || !strings.Contains(w.Body.String(), `"suggested":null`) {
		t.Errorf("empty fields must serialise as [] and null: %s", w.Body.String())
	}
}

func TestRoutingImportKeenetic_RefusalsAndDemo(t *testing.T) {
	reads := 0
	read := func(context.Context) (string, error) { reads++; return importKeeneticConfig, nil }

	// Off KeeneticOS there is no running-config to read; nothing is run.
	for _, p := range []platform.Platform{platform.OpenWrt, platform.Unknown} {
		w := httptest.NewRecorder()
		routingImportServer(p, read).handleRoutingImportKeenetic(w, httptest.NewRequest(http.MethodGet, "/api/routing/import/keenetic", nil))
		if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "KeeneticOS") {
			t.Errorf("%s: %d %s", p, w.Code, w.Body.String())
		}
	}
	if reads != 0 {
		t.Fatalf("a non-Keenetic router ran ndmc %d time(s)", reads)
	}

	// A failed read is a 503 that says what failed and nothing the command printed.
	w := httptest.NewRecorder()
	routingImportServer(platform.Keenetic, func(context.Context) (string, error) {
		return "", errors.New("ndmc: secret detail")
	}).handleRoutingImportKeenetic(w, httptest.NewRequest(http.MethodGet, "/api/routing/import/keenetic", nil))
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "secret detail") {
		t.Errorf("failed read: %d %s", w.Code, w.Body.String())
	}

	// The demo answers on any platform without running anything, and through the real parser.
	for _, p := range []platform.Platform{platform.Keenetic, platform.Unknown} {
		s := routingImportServer(p, read)
		s.cfg.Demo = true
		w := httptest.NewRecorder()
		s.handleRoutingImportKeenetic(w, httptest.NewRequest(http.MethodGet, "/api/routing/import/keenetic", nil))
		ans := decodeRoutingImport(t, w)
		if !ans.Demo || len(ans.Groups) != 3 || ans.Groups[0].Route != "Wireguard0" ||
			ans.Groups[1].Description != "Видео" || len(ans.Groups[1].Excludes) != 1 ||
			len(ans.Groups[2].Skipped) != 1 || ans.Groups[2].Suggested == nil {
			t.Errorf("%s demo answer: %s", p, w.Body.String())
		}
	}
	if reads != 0 {
		t.Fatalf("the demo ran ndmc %d time(s)", reads)
	}
}

func postHydraRoute(s *Server, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.handleRoutingImportHydraRoute(w, httptest.NewRequest(http.MethodPost, "/api/routing/import/hydraroute", strings.NewReader(body)))
	return w
}

func TestRoutingImportHydraRoute_GroupsByTarget(t *testing.T) {
	text := "## Video\nyoutube.com,geosite:google/HydraRoute\n" +
		"geosite:netflix/nwg0\n" +
		"no-target\n"
	payload, _ := json.Marshal(map[string]string{"text": text})
	w := postHydraRoute(&Server{}, string(payload))
	ans := decodeRoutingImport(t, w)
	if ans.Source != "hydraroute" || ans.Format != importer.HydraFormatDomains || len(ans.Groups) != 2 {
		t.Fatalf("answer = %s", w.Body.String())
	}
	hr := ans.Groups[0]
	if hr.Name != "HydraRoute" || hr.Route != "HydraRoute" || hr.Description != "Video" {
		t.Errorf("group = %+v", hr)
	}
	if want := (&routingImportList{Name: "Video", Manual: []string{"youtube.com"}}); !reflect.DeepEqual(hr.Suggested, want) {
		t.Errorf("suggested = %+v, want %+v", hr.Suggested, want)
	}
	if want := []routingImportSkip{{Entry: "geosite:google", Reason: importer.HydraSkipGeosite, Line: 2}}; !reflect.DeepEqual(hr.Skipped, want) {
		t.Errorf("skipped = %+v, want %+v", hr.Skipped, want)
	}
	// A target whose only rule is a geosite tag offers no list, and says why.
	if nwg := ans.Groups[1]; nwg.Name != "nwg0" || nwg.Suggested != nil || nwg.Refused == "" || len(nwg.Skipped) != 1 {
		t.Errorf("geosite-only target = %+v", nwg)
	}
	if want := []routingImportSkip{{Entry: "no-target", Reason: importer.HydraSkipInvalid, Line: 4}}; !reflect.DeepEqual(ans.Skipped, want) {
		t.Errorf("orphan lines = %+v, want %+v", ans.Skipped, want)
	}
}

func TestRoutingImportHydraRoute_BodyRefusals(t *testing.T) {
	big, _ := json.Marshal(map[string]string{"text": strings.Repeat("example.com/HydraRoute\n", routingImportMaxBody/20)})
	for name, tc := range map[string]struct {
		body string
		code int
	}{
		"over the limit": {string(big), http.StatusRequestEntityTooLarge},
		"not JSON":       {"example.com/HydraRoute", http.StatusBadRequest},
		"empty text":     {`{"text": "  \n"}`, http.StatusBadRequest},
		"no text":        {`{}`, http.StatusBadRequest},
	} {
		if w := postHydraRoute(&Server{}, tc.body); w.Code != tc.code {
			t.Errorf("%s: %d %s, want %d", name, w.Code, w.Body.String(), tc.code)
		}
	}
	// Just under the limit is read.
	fits, _ := json.Marshal(map[string]string{"text": strings.Repeat("example.com/HydraRoute\n", (routingImportMaxBody-64)/24)})
	if len(fits) > routingImportMaxBody {
		t.Fatalf("fixture is %d bytes, over the limit", len(fits))
	}
	if w := postHydraRoute(&Server{}, string(fits)); w.Code != http.StatusOK {
		t.Errorf("a body under the limit: %d", w.Code)
	}
}

// The suggestion is a POST /api/routing body short of the operator's choices: given an id and an
// exit it is accepted as it stands, and the stored list carries the entries unchanged.
func TestRoutingImportSuggestion_IsAcceptedByTheRoutingWrite(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := routingImportServer(platform.Keenetic, func(context.Context) (string, error) { return importKeeneticConfig, nil })
	s.store = st
	w := httptest.NewRecorder()
	s.handleRoutingImportKeenetic(w, httptest.NewRequest(http.MethodGet, "/api/routing/import/keenetic", nil))
	sug := decodeRoutingImport(t, w).Groups[0].Suggested

	body, _ := json.Marshal(map[string]any{"id": "rl-imported", "name": sug.Name, "manual": sug.Manual, "outbound": "direct", "enabled": true})
	w = httptest.NewRecorder()
	s.handleUpsertRoutingList(w, httptest.NewRequest(http.MethodPost, "/api/routing", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/routing refused the suggestion: %d %s", w.Code, w.Body.String())
	}
	p := st.Profile()
	if len(p.RoutingLists) != 1 || !reflect.DeepEqual(p.RoutingLists[0].Manual, sug.Manual) || p.Validate() != nil {
		t.Errorf("stored list = %+v (validate %v)", p.RoutingLists, p.Validate())
	}
}
