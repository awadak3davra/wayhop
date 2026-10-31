package keenetic

import (
	"reflect"
	"testing"

	"wayhop/internal/model"
)

// With no log block sing-box logs at trace and names every connection's destination; the fallback
// core logs warnings only, like the generated one (QA-051).
func TestSingboxFallbackLogsWarningsOnly(t *testing.T) {
	vless := &model.Endpoint{ID: "vless-nl", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "192.0.2.1", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u"}}
	plan, err := SingboxFallback([]*model.Endpoint{vless}, FallbackOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := plan.Config["log"], map[string]any{"level": "warn", "timestamp": true}; !reflect.DeepEqual(got, want) {
		t.Errorf("log = %v, want %v", got, want)
	}
}
