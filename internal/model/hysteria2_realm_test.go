package model

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseHy2Realm(t *testing.T) {
	for _, tc := range []struct {
		in        string
		want      Hy2Realm
		uri, base string
	}{
		{"realm://public@rendezvous.example.com/my-cabin-1f3a8c2e9b",
			Hy2Realm{Token: "public", Host: "rendezvous.example.com", ID: "my-cabin-1f3a8c2e9b"},
			"realm://public@rendezvous.example.com/my-cabin-1f3a8c2e9b", "https://rendezvous.example.com"},
		// Hysteria's ?stun= is read, ?lport= accepted and not carried.
		{"REALM://tok%3Aen@rendezvous.example.com:8443/node_1?stun=192.0.2.7:3478&stun=stun.example.com&lport=40000",
			Hy2Realm{Token: "tok:en", Host: "rendezvous.example.com", Port: 8443, ID: "node_1",
				STUN: []string{"192.0.2.7:3478", "stun.example.com"}},
			"realm://tok%3Aen@rendezvous.example.com:8443/node_1", "https://rendezvous.example.com:8443"},
		// sing-box takes a rendezvous without a token; plain HTTP is realm+http.
		{"realm+http://[2001:db8::5]/lab-realm",
			Hy2Realm{HTTP: true, Host: "2001:db8::5", ID: "lab-realm"},
			"realm+http://[2001:db8::5]/lab-realm", "http://[2001:db8::5]"},
	} {
		r, err := ParseHy2Realm(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if !reflect.DeepEqual(*r, tc.want) {
			t.Errorf("%s: parsed %+v, want %+v", tc.in, *r, tc.want)
		}
		if got := r.URI(); got != tc.uri {
			t.Errorf("%s: URI %q, want %q", tc.in, got, tc.uri)
		}
		if got := r.ServerURL(); got != tc.base {
			t.Errorf("%s: ServerURL %q, want %q", tc.in, got, tc.base)
		}
	}
	for _, bad := range []string{
		"https://public@rendezvous.example.com/name",       // not a realm scheme
		"realm://public@/name",                             // no host
		"realm://public@rendezvous.example.com",            // no name
		"realm://public@rendezvous.example.com/",           // empty name
		"realm://public@rendezvous.example.com/a/b",        // two segments
		"realm://public@rendezvous.example.com/a%2Fb",      // a slash smuggled into the name
		"realm://public@rendezvous.example.com:0/name",     // port out of range
		"realm://public@rendezvous.example.com/name#x",     // fragment
		"realm://public@2001:db8::5/name",                  // unbracketed IPv6
		"realm://public@rendezvous.example.com/n?stun=a b", // STUN host with a space
		"realm://public@rendezvous.example.com/n?stun=stun.example.com:99999",
	} {
		if _, err := ParseHy2Realm(bad); err == nil {
			t.Errorf("%q: accepted", bad)
		} else if strings.Contains(err.Error(), "public@") {
			t.Errorf("%q: error quotes the token: %v", bad, err)
		}
	}
}

// A realm replaces the server and port; without one a Hysteria2 connection needs both, as before.
// A malformed realm is refused by EndpointParamProblem, which the save path asks for an enabled
// connection, so it never waits for Apply.
func TestValidate_Hysteria2Realm(t *testing.T) {
	ep := func(params map[string]any) Endpoint {
		params["password"] = "pw"
		return Endpoint{ID: "hy", Name: "hy", Enabled: true, Engine: EngineSingBox, Protocol: ProtoHysteria2, Params: params}
	}
	ok := ep(map[string]any{"realm": "realm://public@rendezvous.example.com/my-cabin-1f3a8c2e9b", "realm_stun": "192.0.2.7:3478, stun.example.com"})
	if err := (&Profile{Endpoints: []Endpoint{ok}}).Validate(); err != nil {
		t.Fatalf("realm without a server: %v", err)
	}
	r, err := Hy2RealmOf(&ok)
	if err != nil || !reflect.DeepEqual(r.STUN, []string{"192.0.2.7:3478", "stun.example.com"}) {
		t.Fatalf("Hy2RealmOf = %+v, %v", r, err)
	}
	// realm_stun as a JSON list merges with the address's own ?stun=, without duplicates.
	listed := ep(map[string]any{"realm": "realm://t@realm.example.com/n1?stun=192.0.2.8", "realm_stun": []any{"192.0.2.7", "192.0.2.8"}})
	if r, err := Hy2RealmOf(&listed); err != nil || !reflect.DeepEqual(r.STUN, []string{"192.0.2.7", "192.0.2.8"}) {
		t.Fatalf("listed STUN = %+v, %v", r, err)
	}

	bad := ep(map[string]any{"realm": "realm://public@rendezvous.example.com"})
	if p := EndpointParamProblem(&bad); !strings.Contains(p, "realm name") {
		t.Fatalf("realm without a name: problem = %q", p)
	}
	if err := (&Profile{Endpoints: []Endpoint{bad}}).Validate(); err == nil {
		t.Fatal("an enabled connection with a malformed realm passed Validate")
	}
	badSTUN := ep(map[string]any{"realm": "realm://public@rendezvous.example.com/n1", "realm_stun": []any{7}})
	if EndpointParamProblem(&badSTUN) == "" {
		t.Fatal("a non-string STUN server passed")
	}
	bad.Enabled = false // a draft may be unfinished
	if err := (&Profile{Endpoints: []Endpoint{bad}}).Validate(); err != nil {
		t.Fatalf("disabled draft: %v", err)
	}

	noServer := ep(map[string]any{})
	if err := (&Profile{Endpoints: []Endpoint{noServer}}).Validate(); err == nil || !strings.Contains(err.Error(), "empty server") {
		t.Fatalf("Hysteria2 without server or realm: err = %v", err)
	}
	// Only Hysteria2 has realms: the param on another protocol exempts nothing.
	trojan := Endpoint{ID: "tr", Enabled: true, Engine: EngineSingBox, Protocol: ProtoTrojan,
		Params: map[string]any{"password": "pw", "realm": "realm://public@rendezvous.example.com/n1"}}
	if err := (&Profile{Endpoints: []Endpoint{trojan}}).Validate(); err == nil {
		t.Fatal("a trojan connection without a server passed on a realm param")
	}
}
