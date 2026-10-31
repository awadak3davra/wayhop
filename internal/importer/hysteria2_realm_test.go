package importer

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// The realm-mode example from Hysteria's URI-scheme docs: the userinfo is the rendezvous token, the
// host the rendezvous, the path the realm name, and the Hysteria password is auth=. Its pinSHA256 is
// a placeholder ("deadbeef", 4 bytes) that no certificate can match, so the verbatim example is
// refused for it, and read with a real-shaped pin in its place.
func TestParseHysteria2Realm_UpstreamExample(t *testing.T) {
	const doc = "hysteria2+realm://mytoken@rendezvous.example.com/my-cabin-1f3a8c2e9b?auth=your_password&insecure=1&pinSHA256=deadbeef"
	if _, err := Parse(doc); err == nil || !strings.Contains(err.Error(), "pinSHA256") {
		t.Errorf("the placeholder pin: %v", err)
	}
	link := strings.Replace(doc, "deadbeef", strings.ToUpper(pinAHex), 1)
	e, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(e.TLS.PinCertSHA256) != 1 || e.TLS.PinCertSHA256[0] != pinAHex || e.Params[model.ParamLegacyPin] != nil {
		t.Errorf("pin = %q, params %v", e.TLS.PinCertSHA256, e.Params)
	}
	if e.Protocol != model.ProtoHysteria2 || e.Engine != model.EngineSingBox || e.Server != "" || e.Port != 0 || !e.Enabled {
		t.Fatalf("endpoint = %+v", e)
	}
	if e.Params["password"] != "your_password" || e.Params["realm"] != "realm://mytoken@rendezvous.example.com/my-cabin-1f3a8c2e9b" {
		t.Fatalf("params = %v", e.Params)
	}
	if _, ok := e.Params["realm_stun"]; ok {
		t.Errorf("no stun= in the link, yet realm_stun = %v", e.Params["realm_stun"])
	}
	// No sni=: unset, so the core presents the rendezvous host as Hysteria does, never "" + server.
	if e.TLS == nil || !e.TLS.Enabled || !e.TLS.Insecure || e.TLS.SNI != "" {
		t.Fatalf("tls = %+v", e.TLS)
	}
	// The realm name is the secret that keeps the server's address private on a shared rendezvous.
	if strings.Contains(e.Name, "my-cabin") || strings.Contains(e.ID, "my-cabin") {
		t.Errorf("the realm name leaked into name %q / id %q", e.Name, e.ID)
	}
	if !strings.HasPrefix(e.ID, "hysteria2-realm-rendezvous-example-com-") {
		t.Errorf("id = %q", e.ID)
	}
	// Two realms on one rendezvous are two connections, not one to be replaced by the other (QA-058);
	// the same link twice is still the same one.
	other, err := Parse("hysteria2+realm://mytoken@rendezvous.example.com/group-0a1b2c3d4e?auth=pw")
	again, err2 := Parse(link)
	if err != nil || err2 != nil || other.ID == e.ID || again.ID != e.ID {
		t.Errorf("ids: first %q, other realm %q, same link again %q (%v %v)", e.ID, other.ID, again.ID, err, err2)
	}
	if err := (&model.Profile{Endpoints: []model.Endpoint{*e}}).Validate(); err != nil {
		t.Fatalf("the imported realm connection fails Validate: %v", err)
	}
}

func TestParseHysteria2Realm_Params(t *testing.T) {
	e, err := Parse("HY2+REALM+HTTP://rendezvous.example.com:8080/lab-realm-0001?auth=pw&obfs=salamander&obfs-password=ob" +
		"&sni=hy.example.com&alpn=h3&stun=192.0.2.7:3478&stun=stun.example.com&lport=40000&mport=20000-30000#Lab")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r, err := model.Hy2RealmOf(e)
	if err != nil || r == nil || !r.HTTP || r.Token != "" || r.Port != 8080 || r.ID != "lab-realm-0001" {
		t.Fatalf("realm = %+v, %v (params %v)", r, err, e.Params)
	}
	if e.Params["realm_stun"] != "192.0.2.7:3478,stun.example.com" || e.Params["obfs"] != "salamander" ||
		e.Params["obfs_password"] != "ob" || e.Name != "Lab" {
		t.Fatalf("endpoint = %+v", e)
	}
	// lport has no sing-box equivalent, and realm mode has no port hopping.
	for _, k := range []string{"lport", "hop_ports"} {
		if _, ok := e.Params[k]; ok {
			t.Errorf("%s carried: %v", k, e.Params)
		}
	}
	if e.TLS.SNI != "hy.example.com" || len(e.TLS.ALPN) != 1 {
		t.Errorf("tls = %+v", e.TLS)
	}

	for _, bad := range []string{
		"hysteria2+realm://mytoken@rendezvous.example.com?auth=pw",       // no realm name
		"hysteria2+realm://mytoken@rendezvous.example.com/a/b?auth=pw",   // two path segments
		"hysteria2+realm://mytoken@/my-cabin?auth=pw",                    // no rendezvous
		"hysteria2+realm://mytoken@rendezvous.example.com/n1?stun=a%20b", // bad STUN server
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q: accepted", bad)
		} else if strings.Contains(err.Error(), "mytoken") {
			t.Errorf("%q: the error quotes the token: %v", bad, err)
		}
	}
}

// Two realm connections share no host or port; the realm is what tells them apart.
func TestContentKey_Hysteria2Realm(t *testing.T) {
	a, err := Parse("hysteria2+realm://t@rendezvous.example.com/realm-one?auth=pw")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse("hysteria2+realm://t@rendezvous.example.com/realm-two?auth=pw")
	if err != nil {
		t.Fatal(err)
	}
	if ContentKey(*a) == ContentKey(*b) {
		t.Fatal("two realms on one rendezvous dedupe as one connection")
	}
	plain := model.Endpoint{Protocol: model.ProtoHysteria2, Engine: model.EngineSingBox, Server: "192.0.2.4", Port: 443,
		Params: map[string]any{"password": "pw"}}
	if strings.Contains(ContentKey(plain), "realm") {
		t.Fatalf("a plain connection's key changed: %q", ContentKey(plain))
	}
}
