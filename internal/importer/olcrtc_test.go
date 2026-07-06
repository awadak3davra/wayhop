package importer

import (
	"testing"

	"wayhop/internal/model"
)

func TestParseOlcRTC(t *testing.T) {
	cfg := `mode: cnc
auth:
  provider: jitsi
room:
  id: "https://meet.example.com/MyRoom123"
crypto:
  key: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
net:
  transport: datachannel
  dns: "8.8.8.8:53"
socks:
  host: "127.0.0.1"
  port: 8808
data: data`

	e, err := Parse(cfg)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Protocol != model.ProtoOlcRTC || e.Engine != model.EngineOlcRTC {
		t.Fatalf("proto/engine = %s/%s", e.Protocol, e.Engine)
	}
	if e.Params["provider"] != "jitsi" {
		t.Fatalf("provider = %v", e.Params["provider"])
	}
	if e.Params["room"] != "https://meet.example.com/MyRoom123" {
		t.Fatalf("room = %v", e.Params["room"])
	}
	if e.Params["transport"] != "datachannel" {
		t.Fatalf("transport = %v", e.Params["transport"])
	}
	if e.Params["dns"] != "8.8.8.8:53" {
		t.Fatalf("dns = %v", e.Params["dns"])
	}
	if e.Params["key"] == "" {
		t.Fatal("key not parsed")
	}
	if e.Server != "meet.example.com" || e.Port != 443 {
		t.Fatalf("server = %s:%d (want meet.example.com:443)", e.Server, e.Port)
	}
}
