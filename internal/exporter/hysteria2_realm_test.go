package exporter

import (
	"reflect"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// A realm connection exports as Hysteria's realm-mode link and imports back to the same connection.
func TestExportHysteria2Realm(t *testing.T) {
	e := model.Endpoint{Name: "Cabin", Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
		Params: map[string]any{"password": "p@ss", "realm": "realm://tok@rendezvous.example.com:8443/my-cabin-1f3a8c2e9b",
			"realm_stun": "192.0.2.7:3478,stun.example.com", "obfs": "salamander", "obfs_password": "ob"},
		TLS: &model.TLS{Enabled: true, Type: "tls", SNI: "hy.example.com", Insecure: true}}
	link, ok := ShareLink(e)
	const want = "hysteria2+realm://tok@rendezvous.example.com:8443/my-cabin-1f3a8c2e9b?auth=p%40ss&insecure=1" +
		"&obfs=salamander&obfs-password=ob&sni=hy.example.com&stun=192.0.2.7%3A3478&stun=stun.example.com#Cabin"
	if !ok || link != want {
		t.Fatalf("link = %q, %v\nwant   %q", link, ok, want)
	}
	got, err := importer.Parse(link)
	if err != nil {
		t.Fatalf("re-import: %v", err)
	}
	if !reflect.DeepEqual(got.Params, e.Params) || got.Name != e.Name || got.Server != "" || got.Port != 0 ||
		got.TLS.SNI != e.TLS.SNI || !got.TLS.Insecure {
		t.Fatalf("round trip = %+v %+v", got, got.TLS)
	}

	e.Params = map[string]any{"password": "pw", "realm": "realm+http://rendezvous.example.com/lab-realm-0001"}
	e.TLS, e.Name = nil, ""
	if link, _ := ShareLink(e); link != "hysteria2+realm+http://rendezvous.example.com/lab-realm-0001?auth=pw" {
		t.Fatalf("realm+http link = %q", link)
	}

	e.Params["realm"] = "realm://tok@rendezvous.example.com" // no realm name: a draft with nothing to share
	if _, ok := Export(e); ok {
		t.Fatal("a malformed realm exported a link")
	}
}
