package generator

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// sshTestMaterial makes an encrypted OpenSSH client key and an Ed25519 host key line at run time, so
// no key text sits in the tree and sing-box parses real ones.
func sshTestMaterial(t *testing.T) (encKey, pass, hostLine string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pass = "fixture-passphrase"
	b, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	hostPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(hostPub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(b)), pass, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

func sshTestProfile(t *testing.T) *model.Profile {
	key, pass, host := sshTestMaterial(t)
	ep := func(id string, params map[string]any) model.Endpoint {
		return model.Endpoint{ID: id, Name: id, Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoSSH,
			Server: "192.0.2.22", Port: 2222, Params: params}
	}
	return &model.Profile{
		Endpoints: []model.Endpoint{
			ep("ssh-pw", map[string]any{"password": "pw"}),
			// ssh-keyscan's output pasted as it is: banner, host-name prefix, a blank line.
			ep("ssh-key", map[string]any{"user": "tunnel", "private_key": key, "private_key_passphrase": pass,
				"host_key":       "# 192.0.2.22:2222 SSH-2.0-OpenSSH_9.6\n[192.0.2.22]:2222 " + host + "\n\n",
				"client_version": "SSH-2.0-OpenSSH_9.6", "cipher": []any{"aes256-ctr", "aes128-ctr"},
				"mac": "hmac-sha2-256", "kex_algorithm": []string{"curve25519-sha256"}}),
		},
		Rules: []model.Rule{
			{ID: "a", DomainSuffix: []string{"a.example.com"}, Outbound: "ssh-key"},
			{ID: "def", Default: true, Outbound: "ssh-pw"},
		},
	}
}

func sshOutbounds(t *testing.T, cfg map[string]any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, ob := range cfg["outbounds"].([]map[string]any) {
		if ob["type"] == "ssh" {
			out[ob["tag"].(string)] = ob
		}
	}
	return out
}

// TestSSHOutbound renders both connections: the password one bare (root and a random client version
// left to sing-box), the key one with its pinned host key reduced to "<type> <base64>", the matching
// host_key_algorithms, and the algorithm lists only for a 1.14+ core.
func TestSSHOutbound(t *testing.T) {
	p := sshTestProfile(t)
	host := strings.Fields(p.Endpoints[1].Params["host_key"].(string))[4:6] // "<type> <base64>" after the banner and the host
	for _, ver := range []string{"", "1.12.17", "1.13.21", "1.14.4", "1.15.0-alpha.13"} {
		res, err := Generate(p, Options{MixedPort: 7890, CoreVersion: ver})
		if err != nil {
			t.Fatalf("%q: %v", ver, err)
		}
		obs := sshOutbounds(t, res.Config)
		pw := obs["ssh-pw"]
		if pw == nil || pw["server"] != "192.0.2.22" || pw["server_port"] != 2222 || pw["password"] != "pw" {
			t.Fatalf("%q: ssh-pw = %v", ver, pw)
		}
		for _, absent := range []string{"user", "private_key", "host_key", "host_key_algorithms", "client_version", "cipher"} {
			if _, ok := pw[absent]; ok {
				t.Errorf("%q: ssh-pw carries %s", ver, absent)
			}
		}
		k := obs["ssh-key"]
		if k["user"] != "tunnel" || !strings.HasPrefix(k["private_key"].(string), "-----BEGIN OPENSSH") ||
			k["private_key_passphrase"] != "fixture-passphrase" || k["client_version"] != "SSH-2.0-OpenSSH_9.6" {
			t.Errorf("%q: ssh-key = %v", ver, k)
		}
		if !reflect.DeepEqual(k["host_key"], []string{strings.Join(host, " ")}) ||
			!reflect.DeepEqual(k["host_key_algorithms"], []string{"ssh-ed25519"}) {
			t.Errorf("%q: host_key %v algorithms %v", ver, k["host_key"], k["host_key_algorithms"])
		}
		modern := coreMinor(ver) >= 14
		for key, want := range map[string][]string{"cipher": {"aes256-ctr", "aes128-ctr"},
			"mac": {"hmac-sha2-256"}, "kex_algorithm": {"curve25519-sha256"}} {
			got, ok := k[key]
			if ok != modern || (modern && !reflect.DeepEqual(got, want)) {
				t.Errorf("%q: %s = %v (present %v), want present only on 1.14+", ver, key, got, ok)
			}
		}
		if got, want := SSHAlgorithmsNeedNewerCore(&p.Endpoints[1], ver), ver == "1.12.17" || ver == "1.13.21"; got != want {
			t.Errorf("%q: SSHAlgorithmsNeedNewerCore = %v, want %v", ver, got, want)
		}
		if SSHAlgorithmsNeedNewerCore(&p.Endpoints[0], ver) {
			t.Errorf("%q: a connection with no algorithm lists needs no newer core", ver)
		}
		// The KeeneticOS fallback core builds the outbound alone, with the same gate.
		ob, err := OutboundForCore(&p.Endpoints[1], ver)
		if err != nil || ob["type"] != "ssh" {
			t.Fatalf("%q: OutboundForCore = %v, %v", ver, ob, err)
		}
		if _, ok := ob["cipher"]; ok != modern {
			t.Errorf("%q: OutboundForCore cipher present %v", ver, ok)
		}
	}
	// A passphrase left behind with no key is not written: sing-box reads it only with a key.
	stray := model.Endpoint{ID: "s", Protocol: model.ProtoSSH, Server: "192.0.2.22", Port: 22,
		Params: map[string]any{"password": "pw", "private_key_passphrase": "left-over"}}
	if ob, err := OutboundFor(&stray); err != nil || ob["private_key_passphrase"] != nil {
		t.Errorf("stray passphrase: %v, %v", ob, err)
	}
	// A host key that stopped parsing is an error, never a connection that accepts any server.
	bad := sshTestProfile(t)
	bad.Endpoints[1].Params["host_key"] = []any{"ssh-ed25519 !!!"}
	if _, err := OutboundFor(&bad.Endpoints[1]); err == nil || !strings.Contains(err.Error(), "host key") {
		t.Fatalf("malformed host key: err = %v", err)
	}
	if _, err := Generate(bad, Options{MixedPort: 7890}); err == nil {
		t.Fatal("Generate rendered a profile with a malformed host key")
	}
	// The SSH exit needs the core, like every other proxy protocol.
	if !ProtocolNeedsSingbox(model.ProtoSSH) {
		t.Error("ProtocolNeedsSingbox(ssh) = false")
	}
}

// TestSSHSingBoxCheck runs the real `sing-box check` (WR_SINGBOX) on both SSH connections, rendered
// for the binary's own version: the core parses the encrypted key with its passphrase and the pinned
// host key, and 1.12/1.13 get no 1.14 field. A deprecation warning fails it too.
func TestSSHSingBoxCheck(t *testing.T) {
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — set it to a sing-box binary for a real `check`")
	}
	ver := singboxVersionOf(t, bin)
	res, err := Generate(sshTestProfile(t), Options{MixedPort: 7890, CoreVersion: ver, CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if err != nil {
		t.Fatalf("generate for %s: %v", strings.SplitN(ver, "\n", 2)[0], err)
	}
	data, _ := json.MarshalIndent(res.Config, "", "  ")
	f := filepath.Join(t.TempDir(), "ssh.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", f).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check rejected the SSH config: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "deprecated") {
		t.Fatalf("sing-box warned about a deprecated field:\n%s", out)
	}
	// The negative control: the same key without its passphrase is what model.Validate refuses,
	// because the core cannot load it either.
	p := sshTestProfile(t)
	delete(p.Endpoints[1].Params, "private_key_passphrase")
	ob, err := OutboundFor(&p.Endpoints[1])
	if err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{"outbounds": []map[string]any{ob}}
	data, _ = json.Marshal(cfg)
	f2 := filepath.Join(t.TempDir(), "ssh-nopass.json")
	if err := os.WriteFile(f2, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", f2).CombinedOutput(); err == nil {
		t.Fatalf("sing-box accepted an encrypted key without its passphrase:\n%s", out)
	}
	if p := model.EndpointParamProblem(&p.Endpoints[1]); !strings.Contains(p, "passphrase") {
		t.Fatalf("Validate does not refuse it: %q", p)
	}
	// The second control: a pinned host key cut short, or with bytes appended, keeps its type name
	// intact; the core refuses it at load, and so does the host key check before it is saved.
	good := sshTestProfile(t)
	ob, err = OutboundFor(&good.Endpoints[1])
	if err != nil {
		t.Fatal(err)
	}
	line := ob["host_key"].([]string)[0]
	for _, bad := range []string{line[:len("ssh-ed25519 ")+40], line[:len(line)-4] + "AAAAAAAA"} {
		ob["host_key"] = []string{bad}
		data, _ = json.Marshal(map[string]any{"outbounds": []map[string]any{ob}})
		f3 := filepath.Join(t.TempDir(), "ssh-badhost.json")
		if err := os.WriteFile(f3, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bin, "check", "-c", f3).CombinedOutput(); err == nil {
			t.Fatalf("sing-box accepted host key %q:\n%s", bad, out)
		}
		if _, err := model.ParseSSHHostKey(bad); err == nil {
			t.Fatalf("ParseSSHHostKey accepted %q, which the core refuses", bad)
		}
	}
}

// Generate -> ParseSingbox -> Generate keeps an SSH outbound byte for byte, as QA-019 asks of every
// protocol WayHop writes.
func TestSSHRoundTrip(t *testing.T) {
	p := sshTestProfile(t)
	first, err := Generate(p, Options{MixedPort: 7890, CoreVersion: "1.14.4"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(first.Config)
	back, errs := importer.ParseSingbox(string(raw))
	if len(errs) > 0 {
		t.Fatalf("ParseSingbox: %v", errs)
	}
	for i := range back {
		back[i].ID, back[i].Enabled = back[i].Name, true
	}
	p2 := &model.Profile{Endpoints: back, Rules: p.Rules}
	second, err := Generate(p2, Options{MixedPort: 7890, CoreVersion: "1.14.4"})
	if err != nil {
		t.Fatalf("generate from the read-back config: %v", err)
	}
	norm := func(m map[string]map[string]any) string { b, _ := json.Marshal(m); return string(b) }
	if a, b := norm(sshOutbounds(t, first.Config)), norm(sshOutbounds(t, second.Config)); a != b {
		t.Fatalf("changed across the round-trip:\nfirst  %s\nsecond %s", a, b)
	}
}

// SSHExitGetsUDP says whether what is routed to an SSH exit can be UDP, which it cannot carry: any
// enabled rule or routing list sending traffic to it (directly or through groups, nested ones too),
// or a DNS server querying over UDP through it. A disabled rule or list, a DNS server over TLS or
// HTTPS, and a DNS plane that is off send none.
func TestSSHExitGetsUDP(t *testing.T) {
	base := func() *model.Profile {
		return &model.Profile{
			Endpoints: []model.Endpoint{{ID: "vps", Protocol: model.ProtoSSH}, {ID: "wg", Protocol: model.ProtoWireGuard}},
			Groups: []model.Group{{ID: "outer", Type: model.GroupSelector, Members: []string{"inner"}},
				{ID: "inner", Type: model.GroupURLTest, Members: []string{"wg", "vps"}},
				{ID: "loop", Type: model.GroupSelector, Members: []string{"loop"}}},
		}
	}
	dns := func(typ, detour string, on bool) *model.DNSSettings {
		return &model.DNSSettings{Enabled: on, Servers: []model.DNSServer{{Tag: "d", Type: typ, Server: "192.0.2.53", Detour: detour, Enabled: true}}}
	}
	for _, tc := range []struct {
		name string
		edit func(p *model.Profile)
		want bool
	}{
		{"nothing routed", func(p *model.Profile) {}, false},
		{"default rule", func(p *model.Profile) { p.Rules = []model.Rule{{ID: "r", Default: true, Outbound: "vps"}} }, true},
		{"disabled rule", func(p *model.Profile) { p.Rules = []model.Rule{{ID: "r", Disabled: true, Outbound: "vps"}} }, false},
		{"rule to another exit", func(p *model.Profile) { p.Rules = []model.Rule{{ID: "r", Default: true, Outbound: "wg"}} }, false},
		{"list through nested groups", func(p *model.Profile) {
			p.RoutingLists = []model.RoutingList{{ID: "l", Outbound: "outer", Enabled: true}}
		}, true},
		{"disabled list", func(p *model.Profile) { p.RoutingLists = []model.RoutingList{{ID: "l", Outbound: "vps"}} }, false},
		{"self-referencing group", func(p *model.Profile) { p.Rules = []model.Rule{{ID: "r", Outbound: "loop"}} }, false},
		{"list downloaded through it", func(p *model.Profile) {
			p.RoutingLists = []model.RoutingList{{ID: "l", Outbound: "direct", DownloadVia: "vps", Enabled: true}}
		}, false},
		{"dns over udp", func(p *model.Profile) { p.DNS = dns("udp", "vps", true) }, true},
		{"dns over quic", func(p *model.Profile) { p.DNS = dns("quic", "inner", true) }, true},
		{"dns over tls", func(p *model.Profile) { p.DNS = dns("tls", "vps", true) }, false},
		{"dns over https", func(p *model.Profile) { p.DNS = dns("https", "vps", true) }, false},
		{"dns plane off", func(p *model.Profile) { p.DNS = dns("udp", "vps", false) }, false},
	} {
		p := base()
		tc.edit(p)
		if got := SSHExitGetsUDP(p, "vps"); got != tc.want {
			t.Errorf("%s: SSHExitGetsUDP = %v, want %v", tc.name, got, tc.want)
		}
	}
}
