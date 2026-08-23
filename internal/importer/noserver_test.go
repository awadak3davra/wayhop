package importer

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// A link with nothing usable in it used to import "successfully": Parse returned an endpoint with
// an empty Server, a DEFAULTED port and Enabled=true. model.Validate rejects that later, so nothing
// broken reached the profile — but the user was shown `endpoint "x": empty server` from the store,
// an error about the endpoint rather than about the link they pasted.
func TestParse_LinkWithNoServerIsRejectedHere(t *testing.T) {
	for _, raw := range []string{
		"vless://",
		"vless://uuid@",
		"vless://uuid@:443",
		"vless://@:443",
		"trojan://pass@",
		"hysteria2://pass@",
		"vmess://eyJ2IjoiMiJ9", // a valid-base64 vmess payload carrying no address
	} {
		ep, err := Parse(raw)
		if err == nil {
			t.Errorf("%q imported as a connection (server=%q port=%d enabled=%v) — the link has no server",
				raw, ep.Server, ep.Port, ep.Enabled)
			continue
		}
		if !strings.Contains(err.Error(), "server") {
			t.Errorf("%q: the error should name the missing server, got %q", raw, err)
		}
	}
}

// The guard must not reject links that DO carry an address, including the shapes that legitimately
// omit a port and take the protocol default.
func TestParse_LinksWithAServerStillImport(t *testing.T) {
	for _, raw := range []string{
		"vless://00000000-0000-0000-0000-000000000000@example.com:443?security=none#n",
		"vless://00000000-0000-0000-0000-000000000000@example.com#n",
		"trojan://secret@example.com:8443#n",
		"hysteria2://secret@example.com:8443#n",
	} {
		ep, err := Parse(raw)
		if err != nil {
			t.Errorf("%q is a usable link but was rejected: %v", raw, err)
			continue
		}
		if ep.Server == "" {
			t.Errorf("%q parsed with no server", raw)
		}
		if ep.Port < 1 || ep.Port > 65535 {
			t.Errorf("%q parsed with an out-of-range port %d", raw, ep.Port)
		}
	}
}

// What the guard is really protecting: anything Parse accepts must survive the validation the store
// applies, so "imported" and "usable" mean the same thing.
func TestParse_AcceptedLinksPassProfileValidation(t *testing.T) {
	for _, raw := range []string{
		"vless://00000000-0000-0000-0000-000000000000@example.com:443#n",
		"trojan://secret@example.com:8443#n",
	} {
		ep, err := Parse(raw)
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		p := model.Profile{Endpoints: []model.Endpoint{*ep}}
		if verr := p.Validate(); verr != nil {
			t.Errorf("%q imported but the store would reject it: %v", raw, verr)
		}
	}
}
