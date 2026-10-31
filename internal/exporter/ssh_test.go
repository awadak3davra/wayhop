package exporter

import (
	"testing"

	"wayhop/internal/model"
)

// An SSH exit is never exported: a link could carry the user and password but not the private key or
// the pinned host keys, so it would hand over a connection that accepts any server.
func TestExportSSHIsRefused(t *testing.T) {
	e := model.Endpoint{ID: "vps", Engine: model.EngineSingBox, Protocol: model.ProtoSSH, Server: "192.0.2.50", Port: 22,
		Params: map[string]any{"user": "root", "password": "pw", "host_key": []string{"ssh-ed25519 AAAA"}}}
	if r, ok := Export(e); ok {
		t.Fatalf("exported %+v", r)
	}
	if l, ok := ShareLink(e); ok {
		t.Fatalf("share link %q", l)
	}
}
