package importer

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

func TestParseSSHLink(t *testing.T) {
	for _, tc := range []struct {
		link, server, user, password, name string
		port                               int
	}{
		{"ssh://root:p%40ss@192.0.2.40:2222#My%20VPS", "192.0.2.40", "root", "p@ss", "My VPS", 2222},
		{"SSH://tunnel@[2001:db8::7]", "2001:db8::7", "tunnel", "", "SSH 2001:db8::7", 22},
		{"ssh://user;fingerprint=ssh-ed25519-aa-bb@vps.example.net", "vps.example.net", "user", "", "SSH vps.example.net", 22},
		{"ssh://192.0.2.42:22?ignored=1", "192.0.2.42", "", "", "SSH 192.0.2.42", 22},
	} {
		e, err := Parse(tc.link)
		if err != nil {
			t.Fatalf("%s: %v", tc.link, err)
		}
		if e.Protocol != model.ProtoSSH || e.Engine != model.EngineSingBox || e.Server != tc.server || e.Port != tc.port ||
			e.Name != tc.name || !e.Enabled || e.ID == "" {
			t.Errorf("%s: endpoint = %+v", tc.link, e)
		}
		if u, _ := e.Params["user"].(string); u != tc.user {
			t.Errorf("%s: user = %q, want %q", tc.link, u, tc.user)
		}
		if pw, _ := e.Params["password"].(string); pw != tc.password {
			t.Errorf("%s: password = %q, want %q", tc.link, pw, tc.password)
		}
		if _, ok := e.Params["user"]; !ok && tc.user != "" {
			t.Errorf("%s: no user", tc.link)
		}
	}
	// A link with no key and no password parses (the form asks for the key), and is what
	// Validate then names, so a subscription stores it disabled rather than failing every Apply.
	e, _ := Parse("ssh://tunnel@192.0.2.43")
	if p := model.EndpointParamProblem(e); !strings.Contains(p, "password or private_key") {
		t.Errorf("credential-less link: problem = %q", p)
	}
	// Errors never carry the password. A user that decodes to a control character is refused at the
	// link, not stored as a login no server has.
	for _, bad := range []string{"ssh://u:hunter2secret@:22", "ssh://u:hunter2secret@192.0.2.44:99999", "ssh://u:hunter2secret@192.0.2.44:x",
		"ssh://us%0Aer:hunter2secret@192.0.2.44", "ssh://us%09er:hunter2secret@192.0.2.44", "ssh://us%7Fer:hunter2secret@192.0.2.44"} {
		_, err := Parse(bad)
		if err == nil {
			t.Errorf("%s: accepted", bad)
			continue
		}
		if strings.Contains(err.Error(), "hunter2secret") {
			t.Errorf("%s: the error quotes the password: %v", bad, err)
		}
	}
}

// A sing-box ssh outbound reads back into the params the generator renders: the key from its
// listable lines, host keys and algorithm lists as lists, the default port, and a key file refused.
func TestParseSingboxSSH(t *testing.T) {
	cfg := `{"outbounds":[
	  {"type":"ssh","tag":"vps","server":"192.0.2.45","user":"tunnel","password":"pw",
	   "private_key":["-----BEGIN OPENSSH ","body","-----END OPENSSH "],"private_key_passphrase":"pp",
	   "host_key":"ssh-ed25519 AAAA","host_key_algorithms":["ssh-ed25519"],"client_version":"SSH-2.0-x",
	   "cipher":["aes128-ctr"],"mac":"hmac-sha2-256","kex_algorithm":[]},
	  {"type":"ssh","tag":"file","server":"192.0.2.46","server_port":2200,"private_key_path":"$HOME/.ssh/id_ed25519"}]}`
	eps, errs := ParseSingbox(cfg)
	if len(eps) != 1 || len(errs) != 1 || !strings.Contains(errs[0], "private_key_path names the file") {
		t.Fatalf("eps %v errs %v", eps, errs)
	}
	e := eps[0]
	p := e.Params
	if e.Protocol != model.ProtoSSH || e.Port != 22 || e.Name != "vps" || p["user"] != "tunnel" || p["password"] != "pw" ||
		p["private_key"] != "-----BEGIN OPENSSH \nbody\n-----END OPENSSH" || p["private_key_passphrase"] != "pp" ||
		p["client_version"] != "SSH-2.0-x" {
		t.Errorf("endpoint = %+v", e)
	}
	if hk, _ := p["host_key"].([]string); len(hk) != 1 || hk[0] != "ssh-ed25519 AAAA" {
		t.Errorf("host_key = %v", p["host_key"])
	}
	if c, _ := p["cipher"].([]string); len(c) != 1 || c[0] != "aes128-ctr" {
		t.Errorf("cipher = %v", p["cipher"])
	}
	if m, _ := p["mac"].([]string); len(m) != 1 {
		t.Errorf("mac = %v", p["mac"])
	}
	for _, absent := range []string{"kex_algorithm", "host_key_algorithms"} {
		if _, ok := p[absent]; ok {
			t.Errorf("%s kept: %v", absent, p[absent])
		}
	}
}

// Two accounts on one server are two exits, even before either has a password.
func TestContentKeySSHUser(t *testing.T) {
	a, _ := Parse("ssh://alice@192.0.2.47")
	b, _ := Parse("ssh://bob@192.0.2.47")
	if ContentKey(*a) == ContentKey(*b) {
		t.Fatal("two SSH users on one server share a content key")
	}
	c, _ := Parse("ssh://alice@192.0.2.47")
	if ContentKey(*a) != ContentKey(*c) {
		t.Fatal("the same link gives two keys")
	}
}
