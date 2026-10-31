package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// An SSH exit with no pinned host key accepts any server: the review says so as a privacy finding
// that holds nothing (no Apply block, no acknowledgement), with the remedy, and says nothing once a
// key is pinned or the connection is off. Algorithm limits on a pre-1.14 core are a degraded note.
func TestEndpointFindings_SSHExit(t *testing.T) {
	s, _ := sharehandlers_server(t)
	bin := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(bin, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.cfg.SingBox.Bin = bin
	answer := "sing-box version 1.13.21\n"
	s.coreVersionOf = func(context.Context, string) (string, error) { return answer, nil }
	ssh := model.Endpoint{ID: "vps", Name: "VPS over SSH", Enabled: true, Engine: model.EngineSingBox,
		Protocol: model.ProtoSSH, Server: "192.0.2.30", Port: 22,
		Params: map[string]any{"password": "pw", "cipher": []any{"aes128-ctr"}}}
	findings := func(e model.Endpoint) map[string]PlanFinding {
		out := map[string]PlanFinding{}
		for _, f := range s.endpointFindings(model.Profile{Endpoints: []model.Endpoint{e}}, platform.CapabilitySet{}) {
			out[f.ID] = f
		}
		return out
	}
	got := findings(ssh)
	hk, ok := got["endpoint.ssh.host_key"]
	if !ok || hk.Severity != platform.SeverityPrivacy || hk.Blocks != platform.BlocksNothing || hk.Item != "VPS over SSH" {
		t.Fatalf("no host key: finding = %+v (all %v)", hk, got)
	}
	folded := foldFindings([]PlanFinding{hk}, nil)
	if len(folded) != 1 || folded[0].AckRequired || folded[0].hard() || folded[0].Code != "SSH_HOST_KEY_NOT_PINNED" ||
		!strings.Contains(folded[0].Detail, "accepts whatever key") || !strings.Contains(folded[0].Remedy, "ssh-keyscan") {
		t.Fatalf("folded = %+v", folded)
	}
	// One text serves every SSH exit in the group, key logins too, so it promises the password only
	// where there is one: an impostor server cannot take a private key.
	if d := folded[0].Detail; !strings.Contains(d, "take the password if the connection logs in with one") ||
		strings.Contains(d, "take the password, and") {
		t.Fatalf("detail claims a password every login has: %q", d)
	}
	if al, ok := got["endpoint.ssh.algorithms"]; !ok || al.Severity != platform.SeverityDegraded || al.Blocks != platform.BlocksNothing {
		t.Fatalf("1.13 core with a cipher list: finding = %+v", al)
	}
	if f := foldFindings([]PlanFinding{got["endpoint.ssh.algorithms"]}, nil); f[0].AckRequired || !strings.Contains(f[0].Detail, "1.14") {
		t.Fatalf("algorithms folded = %+v", f)
	}

	pinned := ssh
	pinned.Params = map[string]any{"password": "pw",
		"host_key": "192.0.2.30 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"}
	if _, ok := findings(pinned)["endpoint.ssh.host_key"]; ok {
		t.Fatal("a pinned host key still reported")
	}
	off := ssh
	off.Enabled = false
	if f := findings(off); len(f) != 0 {
		t.Fatalf("a disabled connection reported %v", f)
	}
	// A new binary is a new probe (the cache keys on size and mtime).
	if err := os.WriteFile(bin, []byte("v2-longer"), 0o755); err != nil {
		t.Fatal(err)
	}
	answer = "sing-box version 1.14.4\n"
	if _, ok := findings(ssh)["endpoint.ssh.algorithms"]; ok {
		t.Fatal("1.14 core: the algorithm limits are carried, nothing to say")
	}
}

// The SSH exit runs on the core: its capability requirements and execution class say so.
func TestSSHExitNeedsTheCore(t *testing.T) {
	e := model.Endpoint{ID: "vps", Engine: model.EngineSingBox, Protocol: model.ProtoSSH}
	req, err := endpointCapabilityRequirements(e)
	if err != nil || strings.Join(req, ",") != platform.CapEngineSingbox+","+platform.CapProtocolPrefix+"ssh" {
		t.Fatalf("requirements = %v, %v", req, err)
	}
	if c := classifyExecutionEndpoint(model.EngineSingBox, model.ProtoSSH); c != executionEndpointCore {
		t.Fatalf("execution class = %v", c)
	}
	if protocolLabels[model.ProtoSSH] != "SSH" {
		t.Fatalf("label = %q", protocolLabels[model.ProtoSSH])
	}
}

// An SSH exit that traffic is routed to gets a degraded note that it carries TCP only, which holds
// nothing and asks no acknowledgement; one nothing is routed to gets none.
func TestEndpointFindings_SSHTCPOnly(t *testing.T) {
	s, _ := sharehandlers_server(t)
	ssh := model.Endpoint{ID: "vps", Name: "VPS over SSH", Enabled: true, Engine: model.EngineSingBox,
		Protocol: model.ProtoSSH, Server: "192.0.2.30", Port: 22, Params: map[string]any{"password": "pw"}}
	find := func(p model.Profile) (PlanFinding, bool) {
		for _, f := range s.endpointFindings(p, platform.CapabilitySet{}) {
			if f.ID == "endpoint.ssh.tcp_only" {
				return f, true
			}
		}
		return PlanFinding{}, false
	}
	if f, ok := find(model.Profile{Endpoints: []model.Endpoint{ssh}}); ok {
		t.Fatalf("nothing routed to the exit, yet %+v", f)
	}
	routed := model.Profile{Endpoints: []model.Endpoint{ssh}, Rules: []model.Rule{{ID: "all", Default: true, Outbound: "vps"}}}
	f, ok := find(routed)
	if !ok || f.Severity != platform.SeverityDegraded || f.Blocks != platform.BlocksNothing || f.Item != "VPS over SSH" {
		t.Fatalf("default route to the exit: finding = %+v, %v", f, ok)
	}
	folded := foldFindings([]PlanFinding{f}, nil)
	if len(folded) != 1 || folded[0].AckRequired || folded[0].hard() || folded[0].Code != "SSH_EXIT_TCP_ONLY" ||
		!strings.Contains(folded[0].Detail, "TCP") || !strings.Contains(folded[0].Remedy, "DNS over TLS or HTTPS") {
		t.Fatalf("folded = %+v", folded)
	}
	routed.Endpoints[0].Enabled = false
	if _, ok := find(routed); ok {
		t.Fatal("a disabled connection reported")
	}
}
