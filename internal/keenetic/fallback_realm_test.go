package keenetic

import (
	"testing"

	"wayhop/internal/model"
)

// The fallback core builds its outbounds with the detected core's version-gated options, as Generate
// does. Without them a Realm connection reached sing-box with no address on every core: dead even on
// 1.14, with nothing in the review to say why.
func TestSingboxFallbackCarriesARealmOnA114Core(t *testing.T) {
	realm := &model.Endpoint{ID: "hy-realm", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
		TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "hy.example.com"},
		Params: map[string]any{"password": "pw", "realm": "realm://tok@rendezvous.example.com/my-cabin-1f3a8c2e9b"}}
	outbound := func(core string) map[string]any {
		t.Helper()
		plan, err := SingboxFallback([]*model.Endpoint{realm}, FallbackOptions{CoreVersion: core})
		if err != nil {
			t.Fatal(err)
		}
		return findByTag(plan.Config["outbounds"].([]map[string]any), "hy-realm")
	}
	modern := outbound("1.14.4")
	r, _ := modern["realm"].(map[string]any)
	if r == nil || r["realm_id"] != "my-cabin-1f3a8c2e9b" || r["server_url"] != "https://rendezvous.example.com" {
		t.Fatalf("1.14.4 outbound = %v, want the realm block", modern)
	}
	if _, ok := modern["server"]; ok {
		t.Errorf("1.14.4 outbound carries a server beside the realm: %v", modern)
	}
	if old := outbound("1.13.19"); old["realm"] != nil {
		t.Errorf("1.13.19 outbound = %v: an older core has no realm option", old)
	}
}
