package model

import "testing"

// TestValidate_RejectsPathTraversalEndpointID: an endpoint id becomes a filesystem path component
// for native plugins (<id>.conf / <id>.yaml), so a path-separator or bare-traversal id must be
// rejected before it can make the root plugin manager write/delete outside its directory.
func TestValidate_RejectsPathTraversalEndpointID(t *testing.T) {
	mk := func(id string) *Profile {
		return &Profile{Endpoints: []Endpoint{
			{ID: id, Name: "x", Engine: EngineExternal, Server: "203.0.113.9", Enabled: true,
				Params: map[string]any{"interface": "awg9"}},
		}}
	}
	for _, bad := range []string{"../../etc/foo", "a/b", `x\y`, "..", "."} {
		if err := mk(bad).Validate(); err == nil {
			t.Errorf("id %q must be rejected (path traversal into the plugin dir), Validate passed", bad)
		}
	}
	if err := mk("proxy-a").Validate(); err != nil {
		t.Errorf("a normal slug id must validate, got %v", err)
	}
}

// TestValidate_RejectsUnsafeExternalInterface: an EngineExternal endpoint's params.interface is
// interpolated into the ROOT kernel plane (nft `oifname "x"`, `ip route ... dev x`), so a name
// carrying an nft/shell metacharacter, whitespace, newline, or a wildcard must be rejected.
func TestValidate_RejectsUnsafeExternalInterface(t *testing.T) {
	mk := func(ifc string) *Profile {
		return &Profile{Endpoints: []Endpoint{
			{ID: "x", Name: "x", Engine: EngineExternal, Enabled: true, Params: map[string]any{"interface": ifc}},
		}}
	}
	for _, bad := range []string{
		"br0\" masquerade\n\tip daddr 1.2.3.4 dnat to 5.6.7.8", // nft string-breakout + injected rule
		"eth0 via 10.0.0.1", // `ip route ... dev` argv injection
		"eth0;reboot",       // shell metacharacter
		"eth0*",             // wildcard — not a concrete egress dev
		"eth0 ",             // trailing space
		"waaaaay-too-long",  // > 15 chars (IFNAMSIZ)
	} {
		if err := mk(bad).Validate(); err == nil {
			t.Errorf("interface %q must be rejected, Validate passed", bad)
		}
	}
	if err := mk("awg0").Validate(); err != nil {
		t.Errorf("a plain interface name must validate, got %v", err)
	}
}
