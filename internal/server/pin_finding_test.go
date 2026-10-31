package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

var (
	srvPinCert = sha256.Sum256([]byte("wayhop invented server certificate"))
	srvPinKey  = sha256.Sum256([]byte("wayhop invented server public key"))
)

// Certificate pins in the Apply review, by core: what a core cannot check is left out and said
// (as accepting any certificate where the link turned checks off), a whole-certificate pin the core
// checks carries the server-certificate-only condition, and a link's verify name is said where
// sing-box checks the SNI instead. None holds Apply. The connection check says the same.
func TestEndpointFindings_CertificatePins(t *testing.T) {
	s, _ := sharehandlers_server(t)
	bin := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(bin, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.cfg.SingBox.Bin = bin
	answer := "sing-box version 1.14.4\n"
	s.coreVersionOf = func(context.Context, string) (string, error) { return answer, nil }

	certHex := hex.EncodeToString(srvPinCert[:])
	keyB64 := base64.StdEncoding.EncodeToString(srvPinKey[:])
	ep := func(id string, p model.Protocol, edit func(*model.Endpoint)) model.Endpoint {
		e := model.Endpoint{ID: id, Name: id, Enabled: true, Engine: model.EngineSingBox, Protocol: p, Server: "192.0.2.60", Port: 443,
			Params: map[string]any{"password": "pw", "uuid": "00000000-0000-4000-8000-000000000060"},
			TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "cdn.example.com"}}
		edit(&e)
		return e
	}
	prof := model.Profile{Endpoints: []model.Endpoint{
		ep("hy-legacy-insecure", model.ProtoHysteria2, func(e *model.Endpoint) {
			e.TLS.Insecure, e.Params[model.ParamLegacyPin] = true, strings.ToUpper(certHex)
		}),
		// From a link's pcs= (Xray: the leaf or a CA in the chain).
		ep("tr-cert", model.ProtoTrojan, func(e *model.Endpoint) { e.TLS.PinCertSHA256, e.TLS.PinCertMayBeCA = []string{certHex}, true }),
		// Typed in the form: no condition about where it came from.
		ep("tr-typed", model.ProtoTrojan, func(e *model.Endpoint) { e.TLS.PinCertSHA256 = []string{certHex} }),
		// Hysteria's pinSHA256 with certificate checks on.
		ep("hy-checks-on", model.ProtoHysteria2, func(e *model.Endpoint) {
			e.TLS.PinCertSHA256, e.TLS.PinCertBesideChain = []string{certHex}, true
		}),
		// An older WayHop's legacy pin that is not a SHA-256 hash, checks on.
		ep("hy-bad-legacy", model.ProtoHysteria2, func(e *model.Endpoint) { e.Params[model.ParamLegacyPin] = "deadbeef" }),
		ep("tr-key", model.ProtoTrojan, func(e *model.Endpoint) { e.TLS.PinPubKeySHA256 = []string{keyB64} }),
		ep("vl-vcn", model.ProtoVLESS, func(e *model.Endpoint) { e.Params[model.ParamVerifyCertName] = "real.example.com" }),
		ep("vl-vcn-pinned", model.ProtoVLESS, func(e *model.Endpoint) {
			e.Params[model.ParamVerifyCertName], e.TLS.PinCertSHA256 = "real.example.com", []string{certHex}
		}),
		ep("vl-vcn-is-sni", model.ProtoVLESS, func(e *model.Endpoint) { e.Params[model.ParamVerifyCertName] = "cdn.example.com" }),
		ep("plain", model.ProtoTrojan, func(*model.Endpoint) {}),
		ep("reality-pins", model.ProtoVLESS, func(e *model.Endpoint) {
			e.TLS.Type, e.TLS.PublicKey, e.TLS.PinCertSHA256 = "reality", "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", []string{certHex}
		}),
	}}
	findings := func() map[string][]string {
		got := map[string][]string{}
		for _, f := range s.endpointFindings(prof, platform.CapabilitySet{}) {
			if !strings.HasPrefix(f.ID, "endpoint.tls.pin") && f.ID != "endpoint.tls.vcn" {
				continue
			}
			if f.Blocks != platform.BlocksNothing || f.Severity != platform.SeverityDegraded {
				t.Errorf("%s on %s: blocks %q severity %q, want a note", f.ID, f.Item, f.Blocks, f.Severity)
			}
			if code, title, detail, remedy := findingTemplate(f); code == "" || title == "" || detail == "" || remedy == "" ||
				strings.HasPrefix(code, "ENDPOINT") {
				t.Errorf("%s has no template: %q %q", f.ID, code, title)
			}
			got[f.Item] = append(got[f.Item], f.ID)
			sort.Strings(got[f.Item])
		}
		return got
	}
	want114 := map[string][]string{
		"hy-legacy-insecure": {"endpoint.tls.pin.unenforced"},
		"tr-cert":            {"endpoint.tls.pin.core"},
		"tr-typed":           {"endpoint.tls.pin.core"},
		"hy-checks-on":       {"endpoint.tls.pin.core"},
		"hy-bad-legacy":      {"endpoint.tls.pin.invalid"},
		"vl-vcn":             {"endpoint.tls.vcn"},
		"vl-vcn-pinned":      {"endpoint.tls.pin.core", "endpoint.tls.vcn"},
		"reality-pins":       {"endpoint.tls.pin.reality"},
	}
	if got := findings(); !sameFindingMap(got, want114) {
		t.Errorf("1.14 core: findings = %v, want %v", got, want114)
	}

	if err := s.store.UpsertEndpoint(prof.Endpoints[1]); err != nil {
		t.Fatal(err)
	}
	check := func(id string) map[string]any {
		r := httptest.NewRequest(http.MethodPost, "/api/endpoints/"+id+"/check", nil)
		r.SetPathValue("id", id)
		w := httptest.NewRecorder()
		s.handleEndpointCheck(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	if out := check("tr-cert"); out["ok"] != false || !strings.Contains(out["error"].(string), "sing-box 1.15") ||
		!strings.Contains(out["error"].(string), "chain") {
		t.Errorf("1.14 core: check = %v, want the pin named with the version it needs", out)
	}

	if err := os.WriteFile(bin, []byte("v2-longer"), 0o755); err != nil {
		t.Fatal(err)
	}
	answer = "sing-box version 1.15.0-alpha.13\n"
	// The malformed pin gets its own finding on a core that checks pins too (it was named as "needs a
	// newer core" before), and a Hysteria pin with checks on says the chain is no longer checked.
	want115 := map[string][]string{
		"tr-cert":       {"endpoint.tls.pin.leaf"},
		"hy-checks-on":  {"endpoint.tls.pin.replaces_chain"},
		"hy-bad-legacy": {"endpoint.tls.pin.invalid"},
		"vl-vcn":        {"endpoint.tls.vcn"},
		"reality-pins":  {"endpoint.tls.pin.reality"},
	}
	if got := findings(); !sameFindingMap(got, want115) {
		t.Errorf("1.15 core: findings = %v, want %v", got, want115)
	}
	if out := check("tr-cert"); out["error"] != nil && strings.Contains(out["error"].(string), "pin") {
		t.Errorf("1.15 core: check still names the pin: %v", out)
	}
}

func sameFindingMap(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if strings.Join(v, ",") != strings.Join(b[k], ",") {
			return false
		}
	}
	return true
}

// The form sends pins as typed; the save stores them in one form and refuses one that is not a
// SHA-256 hash, naming it.
func TestUpsertEndpointCanonicalisesPins(t *testing.T) {
	s, _ := sharehandlers_server(t)
	colons := strings.ToUpper(hex.EncodeToString(srvPinCert[:]))
	var parts []string
	for i := 0; i < len(colons); i += 2 {
		parts = append(parts, colons[i:i+2])
	}
	e := model.Endpoint{ID: "tr", Name: "tr", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoTrojan,
		Server: "192.0.2.61", Port: 443, Params: map[string]any{"password": "pw"},
		TLS: &model.TLS{Enabled: true, Type: "tls", SNI: "example.com", PinCertSHA256: []string{strings.Join(parts, ":"), " "},
			PinPubKeySHA256: []string{hex.EncodeToString(srvPinKey[:])}}}
	post := func(e model.Endpoint) *httptest.ResponseRecorder {
		b, _ := json.Marshal(e)
		r := httptest.NewRequest(http.MethodPost, "/api/endpoints", bytes.NewReader(b))
		w := httptest.NewRecorder()
		s.handleUpsertEndpoint(w, r)
		return w
	}
	if w := post(e); w.Code != http.StatusOK {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	prof := s.store.Profile()
	got := prof.EndpointByID("tr").TLS
	if strings.Join(got.PinCertSHA256, ",") != hex.EncodeToString(srvPinCert[:]) ||
		strings.Join(got.PinPubKeySHA256, ",") != base64.StdEncoding.EncodeToString(srvPinKey[:]) {
		t.Errorf("stored pins = %q / %q", got.PinCertSHA256, got.PinPubKeySHA256)
	}
	e.TLS.PinCertSHA256 = []string{"deadbeef"}
	if w := post(e); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "not a SHA-256 hash") {
		t.Errorf("malformed pin: %d %s", w.Code, w.Body.String())
	}
}

// The share-link export refuses a link weaker than the connection (a public-key pin it cannot carry,
// with certificate checks off), saying why, and gives the link once a whole-certificate pin is there.
func TestEndpointExportRefusesAWeakerLink(t *testing.T) {
	s, _ := sharehandlers_server(t)
	e := model.Endpoint{ID: "tk", Name: "tk", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoTrojan,
		Server: "192.0.2.62", Port: 443, Params: map[string]any{"password": "pw"},
		TLS: &model.TLS{Enabled: true, Type: "tls", SNI: "example.com", Insecure: true,
			PinPubKeySHA256: []string{base64.StdEncoding.EncodeToString(srvPinKey[:])}}}
	export := func() *httptest.ResponseRecorder {
		if err := s.store.UpsertEndpoint(e); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodGet, "/api/endpoints/tk/export", nil)
		r.SetPathValue("id", "tk")
		w := httptest.NewRecorder()
		s.handleEndpointExport(w, r)
		return w
	}
	if w := export(); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "any certificate") ||
		strings.Contains(w.Body.String(), "trojan://") {
		t.Errorf("weaker link: %d %s", w.Code, w.Body.String())
	}
	e.TLS.PinCertSHA256 = []string{hex.EncodeToString(srvPinCert[:])}
	if w := export(); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "pcs="+hex.EncodeToString(srvPinCert[:])) {
		t.Errorf("with a whole-certificate pin: %d %s", w.Code, w.Body.String())
	}
}
